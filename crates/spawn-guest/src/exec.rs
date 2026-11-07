use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, User};
use spawn_proto::guest::v1::exec_event::Event;
use spawn_proto::guest::v1::{ExecEvent, ExecExit, ExecRequest};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tonic::Status;

pub type EventSender = mpsc::Sender<Result<ExecEvent, Status>>;

/// How long to keep reading output after the command exits. A background job
/// that inherited stdout can keep the pipe open forever.
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_millis(500);

const DEFAULT_USER: &str = "user";
const DEFAULT_CWD: &str = "/workspace";

/// The account a command runs as. Empty means `user`.
pub fn user(name: &str) -> Result<User, Status> {
    let name = if name.is_empty() { DEFAULT_USER } else { name };
    User::from_name(name)
        .map_err(|e| Status::internal(format!("look up user {name}: {e}")))?
        .ok_or_else(|| Status::invalid_argument(format!("no such user: {name}")))
}

/// bash, or `sh` in images without it.
pub fn shell() -> &'static str {
    if std::path::Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    }
}

/// The working directory of a command. Empty means /workspace.
pub fn cwd(cwd: &str) -> &str {
    if cwd.is_empty() { DEFAULT_CWD } else { cwd }
}

pub fn start(req: ExecRequest) -> Result<(Child, Instant), Status> {
    if req.cmd.is_empty() {
        return Err(Status::invalid_argument("cmd is empty"));
    }
    let user = user(&req.user)?;
    let cwd = cwd(&req.cwd);

    let mut cmd = Command::new(shell());
    cmd.arg("-lc")
        .arg(&req.cmd)
        // Also drops supplementary groups when switching away from root.
        .uid(user.uid.as_raw())
        .gid(user.gid.as_raw())
        .env("HOME", &user.dir)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .envs(&req.env)
        .current_dir(cwd)
        .stdin(if req.stdin.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group, so a timeout or disconnect kills the whole tree.
        .process_group(0)
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| Status::failed_precondition(format!("cannot start command: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        // A command that exits without reading all of it is fine.
        tokio::spawn(async move {
            let _ = stdin.write_all(&req.stdin).await;
        });
    }
    Ok((child, Instant::now()))
}

/// Streams the command's output, then its exit status, then closes the
/// stream. Output readers feed `run` through their own channel so that only
/// `run` holds `tx`: a background job that keeps the pipes open cannot keep
/// the stream open after the exit status.
pub async fn run(mut child: Child, started: Instant, timeout_ms: u32, tx: EventSender) {
    let (out_tx, mut out_rx) = mpsc::channel(16);
    if let Some(out) = child.stdout.take() {
        tokio::spawn(forward(out, out_tx.clone(), Event::Stdout));
    }
    if let Some(err) = child.stderr.take() {
        tokio::spawn(forward(err, out_tx.clone(), Event::Stderr));
    }
    drop(out_tx);

    let deadline = async {
        match timeout_ms {
            0 => std::future::pending().await,
            ms => tokio::time::sleep(Duration::from_millis(ms.into())).await,
        }
    };
    tokio::pin!(deadline);

    let mut timed_out = false;
    let mut output_open = true;
    let status = loop {
        tokio::select! {
            event = out_rx.recv(), if output_open => match event {
                Some(event) => {
                    if tx.send(Ok(ExecEvent { event: Some(event) })).await.is_err() {
                        kill_group(&child);
                        let _ = child.wait().await;
                        return;
                    }
                }
                None => output_open = false,
            },
            status = child.wait() => break status,
            () = &mut deadline => {
                timed_out = true;
                kill_group(&child);
                break child.wait().await;
            }
            () = tx.closed() => {
                kill_group(&child);
                let _ = child.wait().await;
                return;
            }
        }
    };

    // Output written just before the exit is still in the pipes. A
    // background job may hold them open forever; stop after a grace period.
    let drain = tokio::time::sleep(OUTPUT_DRAIN_GRACE);
    tokio::pin!(drain);
    while output_open {
        tokio::select! {
            event = out_rx.recv() => match event {
                Some(event) => {
                    if tx.send(Ok(ExecEvent { event: Some(event) })).await.is_err() {
                        return;
                    }
                }
                None => output_open = false,
            },
            () = &mut drain => break,
        }
    }

    let exit = match status {
        Ok(status) => ExecExit {
            exit_code: status.code(),
            signal: status.signal(),
            timed_out,
            duration_ms: started.elapsed().as_millis() as u64,
        },
        Err(error) => {
            let _ = tx
                .send(Err(Status::internal(format!("wait failed: {error}"))))
                .await;
            return;
        }
    };
    let _ = tx
        .send(Ok(ExecEvent {
            event: Some(Event::Exit(exit)),
        }))
        .await;
}

/// Reads a pipe until it closes. Once nobody listens, it keeps reading and
/// drops the output, so a background job never gets SIGPIPE for writing.
async fn forward(
    mut out: impl AsyncRead + Unpin,
    tx: mpsc::Sender<Event>,
    wrap: fn(Vec<u8>) -> Event,
) {
    let mut buf = vec![0; 64 * 1024];
    let mut tx = Some(tx);
    loop {
        match out.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if let Some(sender) = &tx
                    && sender.send(wrap(buf[..n].to_vec())).await.is_err()
                {
                    tx = None;
                }
            }
        }
    }
}

fn kill_group(child: &Child) {
    if let Some(pid) = child.id() {
        let _ = killpg(Pid::from_raw(pid as i32), Signal::SIGKILL);
    }
}
