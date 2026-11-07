//! Interactive terminals: a process on a pseudo-terminal, streamed to the
//! host.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use spawn_proto::guest::v1::pty_input::Input;
use spawn_proto::guest::v1::pty_output::Output;
use spawn_proto::guest::v1::{ExecExit, PtyInput, PtyOutput, PtySize, PtyStart};
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tonic::{Status, Streaming};

use crate::exec;

pub type OutputSender = mpsc::Sender<Result<PtyOutput, Status>>;

/// How long a hung-up process has to exit before it is killed.
const HANGUP_GRACE: Duration = Duration::from_secs(2);
/// How long to keep reading output after the process exits. A background
/// job may hold the terminal open forever.
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_millis(500);
const MAX_SIZE: u32 = 1000;

pub struct Session {
    master: Arc<AsyncFd<OwnedFd>>,
    child: Child,
    started: Instant,
}

pub fn start(req: PtyStart) -> Result<Session, Status> {
    let user = exec::user(&req.user)?;
    let size = winsize(req.cols, req.rows);
    let pty = openpty(Some(&size), None).map_err(|e| Status::internal(format!("openpty: {e}")))?;
    fcntl(&pty.master, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
        .map_err(|e| Status::internal(format!("set the terminal non-blocking: {e}")))?;
    // openpty does not set close-on-exec, so without this every later
    // process would inherit this terminal and could read or type into it.
    for fd in [&pty.master, &pty.slave] {
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|e| Status::internal(format!("set close-on-exec: {e}")))?;
    }

    let mut cmd = Command::new(crate::exec::shell());
    if req.cmd.is_empty() {
        cmd.arg("-l");
    } else {
        cmd.arg("-lc").arg(&req.cmd);
    }
    let io = |fd: &OwnedFd| -> Result<Stdio, Status> {
        fd.try_clone()
            .map(Stdio::from)
            .map_err(|e| Status::internal(format!("dup terminal: {e}")))
    };
    cmd.uid(user.uid.as_raw())
        .gid(user.gid.as_raw())
        .env("HOME", &user.dir)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("TERM", "xterm-256color")
        .envs(&req.env)
        .current_dir(exec::cwd(&req.cwd))
        .stdin(io(&pty.slave)?)
        .stdout(io(&pty.slave)?)
        .stderr(io(&pty.slave)?)
        .kill_on_drop(true);
    // SAFETY: runs in the forked child before exec and only calls
    // async-signal-safe functions (setsid, ioctl).
    unsafe {
        cmd.pre_exec(|| {
            // A new session whose controlling terminal is the PTY, so job
            // control and ^C work. Its process group id is the child's pid.
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .map_err(|e| Status::failed_precondition(format!("cannot start terminal: {e}")))?;
    // The parent must not keep the terminal's other end open, or reads
    // never see the process go away.
    drop(cmd);
    drop(pty.slave);
    // SAFETY: an OwnedFd is open until dropped and always returns the
    // same descriptor.
    let master = unsafe { AsyncFd::register(pty.master) }
        .map_err(|e| Status::internal(format!("watch terminal: {e}")))?;
    Ok(Session {
        master: Arc::new(master),
        child,
        started: Instant::now(),
    })
}

/// Streams output until the process exits, then sends its exit status.
/// Input and resizes come from `input`; when it ends, the terminal hangs up.
pub async fn run(mut session: Session, input: Streaming<PtyInput>, tx: OutputSender) {
    let (hangup_tx, mut hangup) = oneshot::channel();
    let writer = tokio::spawn(forward_input(Arc::clone(&session.master), input, hangup_tx));
    let pgid = session.child.id().map(|pid| Pid::from_raw(pid as i32));
    let mut buf = vec![0; 64 * 1024];
    let mut output_open = true;
    let mut kill_at: Option<tokio::time::Instant> = None;
    let status = loop {
        let kill = async {
            match kill_at {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            read = read(&session.master, &mut buf), if output_open => match read {
                Ok(n) if n > 0 => {
                    let data = Output::Data(buf[..n].to_vec());
                    if tx.send(Ok(PtyOutput { output: Some(data) })).await.is_err() {
                        signal(pgid, Signal::SIGKILL);
                        let _ = session.child.wait().await;
                        writer.abort();
                        return;
                    }
                }
                // EIO once every process closed the terminal.
                _ => output_open = false,
            },
            status = session.child.wait() => break status,
            _ = &mut hangup, if kill_at.is_none() => {
                signal(pgid, Signal::SIGHUP);
                kill_at = Some(tokio::time::Instant::now() + HANGUP_GRACE);
            }
            () = kill => {
                signal(pgid, Signal::SIGKILL);
                kill_at = Some(tokio::time::Instant::now() + Duration::from_secs(3600));
            }
            () = tx.closed() => {
                signal(pgid, Signal::SIGKILL);
                let _ = session.child.wait().await;
                writer.abort();
                return;
            }
        }
    };
    writer.abort();

    let drain = tokio::time::sleep(OUTPUT_DRAIN_GRACE);
    tokio::pin!(drain);
    while output_open {
        tokio::select! {
            read = read(&session.master, &mut buf) => match read {
                Ok(n) if n > 0 => {
                    let data = Output::Data(buf[..n].to_vec());
                    if tx.send(Ok(PtyOutput { output: Some(data) })).await.is_err() {
                        return;
                    }
                }
                _ => output_open = false,
            },
            () = &mut drain => break,
        }
    }
    // Background jobs of the session die with it.
    signal(pgid, Signal::SIGKILL);

    let exit = match status {
        Ok(status) => ExecExit {
            exit_code: status.code(),
            signal: status.signal(),
            timed_out: false,
            duration_ms: session.started.elapsed().as_millis() as u64,
        },
        Err(error) => {
            let _ = tx
                .send(Err(Status::internal(format!("wait failed: {error}"))))
                .await;
            return;
        }
    };
    let _ = tx
        .send(Ok(PtyOutput {
            output: Some(Output::Exit(exit)),
        }))
        .await;
}

async fn forward_input(
    master: Arc<AsyncFd<OwnedFd>>,
    mut input: Streaming<PtyInput>,
    hangup: oneshot::Sender<()>,
) {
    while let Ok(Some(message)) = input.message().await {
        match message.input {
            Some(Input::Data(data)) => {
                if write_all(&master, &data).await.is_err() {
                    break;
                }
            }
            Some(Input::Resize(PtySize { cols, rows })) => resize(&master, cols, rows),
            Some(Input::Start(_)) | None => {}
        }
    }
    let _ = hangup.send(());
}

fn winsize(cols: u32, rows: u32) -> Winsize {
    let clamp = |n: u32, default: u16| {
        if n == 0 {
            default
        } else {
            n.min(MAX_SIZE) as u16
        }
    };
    Winsize {
        ws_row: clamp(rows, 24),
        ws_col: clamp(cols, 80),
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

fn resize(master: &AsyncFd<OwnedFd>, cols: u32, rows: u32) {
    let size = winsize(cols, rows);
    // SAFETY: TIOCSWINSZ reads one `winsize` from the pointer, which is
    // valid for the call; the fd is an open terminal.
    unsafe {
        libc::ioctl(
            master.get_ref().as_raw_fd(),
            libc::TIOCSWINSZ,
            &raw const size,
        );
    }
}

fn signal(pgid: Option<Pid>, signal: Signal) {
    if let Some(pgid) = pgid {
        let _ = killpg(pgid, signal);
    }
}

async fn read(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = fd.readable().await?;
        if let Ok(result) =
            guard.try_io(|inner| nix::unistd::read(inner.get_ref(), buf).map_err(io::Error::from))
        {
            return result;
        }
    }
}

async fn write_all(fd: &AsyncFd<OwnedFd>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let mut guard = fd.writable().await?;
        if let Ok(result) =
            guard.try_io(|inner| nix::unistd::write(inner.get_ref(), data).map_err(io::Error::from))
        {
            data = &data[result?..];
        }
    }
    Ok(())
}
