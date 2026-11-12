//! Kills the server's VMs when the server process dies.
//!
//! VM processes live in cgroups under one parent cgroup, outside the
//! server's own process and service cgroup, so they outlive a server that
//! is killed with `SIGKILL`, by the OOM killer, or that aborts. A primary
//! that starts a lost host's persistent sandboxes elsewhere relies on
//! them being dead by then. So the server starts a guard: a small copy of
//! itself (`spawn-api guard`) that waits on a pipe whose write end only
//! the server holds. When the server is gone, by any means, the kernel
//! closes that end; the guard sees end of file and kills every VM cgroup.
//!
//! A server that stops cleanly has already stopped its VMs; it sends
//! [`DISARM`] first, and the guard exits without killing.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// The byte that tells the guard the server stopped cleanly.
const DISARM: u8 = b'd';
/// The guard's line on its stdout once it is ready.
const READY: &[u8] = b"ready\n";
/// Longest wait for the guard to start.
const START_WAIT: Duration = Duration::from_secs(5);
/// Longest wait for killed processes to leave their cgroups.
const KILL_WAIT: Duration = Duration::from_secs(5);

/// The server's end of the guard.
pub struct Guard {
    pid: u32,
    pipe: Mutex<Option<std::io::PipeWriter>>,
    disarmed: Arc<AtomicBool>,
}

impl Guard {
    /// Starts the guard of the VM cgroups under `cgroups`. It moves
    /// itself into the cgroup `own`, so a service manager that kills the
    /// server's cgroup does not kill it too. If the guard exits while the
    /// server runs, `fatal` makes the server kill its VMs and exit: it is
    /// unguarded. Otherwise it only warns.
    pub fn start(cgroups: &Path, own: Option<&Path>, fatal: bool) -> Result<Self> {
        Self::start_exe(&exe()?, cgroups, own, fatal)
    }

    fn start_exe(exe: &Path, cgroups: &Path, own: Option<&Path>, fatal: bool) -> Result<Self> {
        // Both ends are close-on-exec: Firecracker, the jailer and other
        // children must not hold the write end, or the guard never sees
        // the server go. The child gets the read end as its stdin.
        let (reader, writer) = std::io::pipe().context("create the guard pipe")?;
        let mut command = Command::new(exe);
        command
            .arg("guard")
            .arg("--cgroup-parent")
            .arg(cgroups)
            .stdin(Stdio::from(reader))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            // Out of the server's process group: Ctrl-C does not reach it.
            .process_group(0);
        if let Some(own) = own {
            command.arg("--own-cgroup").arg(own);
        }
        // SAFETY: only calls `signal`, which is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                // Ignored signals stay ignored across exec, so the guard
                // ignores them from its first instruction. `SIGTTOU`: it
                // may log to the terminal from a background group.
                for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGTTOU] {
                    if libc::signal(signal, libc::SIG_IGN) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("start {} guard", exe.display()))?;
        drop(command);
        let pid = child.id();
        let disarmed = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let watched = Arc::clone(&disarmed);
        let cgroups = cgroups.to_owned();
        std::thread::Builder::new()
            .name("spawnbox-guard".into())
            .spawn(move || {
                let ready = child_ready(&mut child);
                watch(ready, child, &ready_tx, &watched, &cgroups, fatal);
            })
            .context("start the guard watcher")?;
        match ready_rx.recv_timeout(START_WAIT) {
            Ok(true) => {}
            _ => {
                disarmed.store(true, Ordering::SeqCst);
                kill(pid);
                bail!("the VM guard (pid {pid}) did not start");
            }
        }
        eprintln!("VM guard running as pid {pid}");
        Ok(Self {
            pid,
            pipe: Mutex::new(Some(writer)),
            disarmed,
        })
    }

    /// Tells the guard the server stopped its VMs, so it exits without
    /// killing.
    pub fn disarm(&self) {
        self.disarmed.store(true, Ordering::SeqCst);
        let pipe = self.pipe.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(mut pipe) = pipe
            && let Err(error) = pipe.write_all(&[DISARM])
        {
            eprintln!("warning: disarm the VM guard (pid {}): {error}", self.pid);
        }
    }
}

/// This program, also if its file was replaced since it started.
fn exe() -> Result<PathBuf> {
    if cfg!(target_os = "linux") {
        return Ok(PathBuf::from("/proc/self/exe"));
    }
    std::env::current_exe().context("find this program")
}

/// Takes the guard's stdout and waits for its ready line.
fn child_ready(child: &mut Child) -> bool {
    let Some(mut out) = child.stdout.take() else {
        return false;
    };
    let mut line = [0; READY.len()];
    out.read_exact(&mut line).is_ok() && line == READY
}

fn watch(
    ready: bool,
    mut child: Child,
    ready_tx: &std::sync::mpsc::Sender<bool>,
    disarmed: &AtomicBool,
    cgroups: &Path,
    fatal: bool,
) {
    let _ = ready_tx.send(ready);
    let status = child.wait();
    if !ready || disarmed.load(Ordering::SeqCst) {
        return;
    }
    let status = status.map_or_else(|e| e.to_string(), |s| s.to_string());
    if !fatal {
        eprintln!(
            "warning: the VM guard exited ({status}); if this server dies now, its VMs keep running"
        );
        return;
    }
    // Nothing would kill the VMs if this server died now, and the fence
    // time of the fleet relies on that. Fail safe, like a lost lease.
    eprintln!("the VM guard exited ({status}); killing every VM and exiting");
    if sweep(cgroups, KILL_WAIT) > 0 {
        eprintln!("warning: processes of some sandboxes are still running");
    }
    std::process::exit(1);
}

fn kill(pid: u32) {
    if let Ok(pid) = libc::pid_t::try_from(pid) {
        // SAFETY: `kill` has no memory effects.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// `spawn-api guard`: waits until the server is gone, then kills its VMs.
pub fn run(cgroups: &Path, own: Option<&Path>) -> Result<()> {
    // Logs must not fail: stderr may be a closed terminal by then.
    let log = |line: std::fmt::Arguments| {
        let _ = writeln!(std::io::stderr(), "vm guard: {line}");
    };
    if let Some(own) = own
        && let Err(error) = enter(own)
    {
        log(format_args!(
            "warning: stays in the server's cgroup ({error:#}); stopping that cgroup also stops this guard"
        ));
    }
    std::io::stdout()
        .write_all(READY)
        .and_then(|()| std::io::stdout().flush())
        .context("report ready")?;
    let mut stdin = std::io::stdin().lock();
    let mut byte = [0];
    loop {
        match stdin.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == DISARM => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                log(format_args!("read from the server: {error}"));
                break;
            }
        }
    }
    let started = Instant::now();
    log(format_args!(
        "the server is gone; killing every VM under {}",
        cgroups.display()
    ));
    let left = sweep(cgroups, KILL_WAIT);
    if left > 0 {
        log(format_args!(
            "warning: {left} VM cgroups still have processes after {} ms",
            started.elapsed().as_millis()
        ));
        bail!("{left} VM cgroups still have processes");
    }
    log(format_args!(
        "every VM is gone after {} ms",
        started.elapsed().as_millis()
    ));
    Ok(())
}

/// Moves this process into the cgroup `dir`.
fn enter(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    std::fs::write(dir.join("cgroup.procs"), std::process::id().to_string())
        .with_context(|| format!("move into {}", dir.display()))
}

/// Kills every process in each cgroup under `parent` and waits up to
/// `wait` for them to leave. Uses `cgroup.kill`, or, on kernels without
/// it, kills each process in `cgroup.procs` again until none are left.
/// Returns how many cgroups still have processes.
pub fn sweep(parent: &Path, wait: Duration) -> usize {
    let deadline = Instant::now() + wait;
    loop {
        let mut left = 0;
        for dir in children(parent) {
            let procs = pids(&dir);
            if procs.is_empty() {
                continue;
            }
            left += 1;
            if !kill_cgroup(&dir) {
                procs.into_iter().for_each(kill);
            }
        }
        if left == 0 || Instant::now() >= deadline {
            return left;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn children(parent: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(parent)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect()
}

fn pids(dir: &Path) -> Vec<u32> {
    std::fs::read_to_string(dir.join("cgroup.procs"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|pid| pid.parse().ok())
        .collect()
}

/// Writes `cgroup.kill`, which kills the cgroup and its descendants. False
/// if the kernel has no such file.
fn kill_cgroup(dir: &Path) -> bool {
    std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("cgroup.kill"))
        .and_then(|mut file| file.write_all(b"1"))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spawnbox-guard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_sweep_writes_cgroup_kill_and_waits_for_empty_cgroups() {
        let parent = tree("kill");
        for id in ["a", "b", "idle"] {
            std::fs::create_dir(parent.join(id)).unwrap();
            std::fs::write(parent.join(id).join("cgroup.kill"), "").unwrap();
        }
        std::fs::write(parent.join("a").join("cgroup.procs"), "999999998\n").unwrap();
        std::fs::write(parent.join("b").join("cgroup.procs"), "999999999\n").unwrap();
        std::fs::write(parent.join("idle").join("cgroup.procs"), "").unwrap();
        assert_eq!(sweep(&parent, Duration::from_millis(40)), 2);
        for (id, kill) in [("a", "1"), ("b", "1"), ("idle", "")] {
            let written = std::fs::read_to_string(parent.join(id).join("cgroup.kill")).unwrap();
            assert_eq!(written, kill, "{id}");
        }
        std::fs::write(parent.join("a").join("cgroup.procs"), "").unwrap();
        std::fs::write(parent.join("b").join("cgroup.procs"), "").unwrap();
        assert_eq!(sweep(&parent, Duration::ZERO), 0);
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn without_cgroup_kill_a_sweep_kills_each_process() {
        let parent = tree("procs");
        let mut sleep = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::create_dir(parent.join("vm")).unwrap();
        std::fs::write(
            parent.join("vm").join("cgroup.procs"),
            sleep.id().to_string(),
        )
        .unwrap();
        sweep(&parent, Duration::ZERO);
        let status = sleep.wait().unwrap();
        assert!(!status.success());
        assert!(!parent.join("vm").join("cgroup.kill").exists());
        std::fs::remove_dir_all(&parent).unwrap();
    }

    /// Children the server starts later must not hold the guard's pipe,
    /// and `SIGTERM` must not stop the guard.
    #[test]
    fn the_guard_sees_the_server_go_despite_children_and_sigterm() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tree("start");
        let exe = dir.join("fake-guard");
        let done = dir.join("done");
        std::fs::write(
            &exe,
            format!(
                "#!/bin/sh\necho ready\ncat >/dev/null\necho gone > {}\n",
                done.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let guard = Guard::start_exe(&exe, &dir, None, false).unwrap();
        let mut later = Command::new("sleep").arg("30").spawn().unwrap();
        // SAFETY: `kill` has no memory effects.
        unsafe { libc::kill(libc::pid_t::try_from(guard.pid).unwrap(), libc::SIGTERM) };
        std::thread::sleep(Duration::from_millis(100));
        assert!(!done.exists());
        drop(guard);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        later.kill().unwrap();
        later.wait().unwrap();
        assert!(done.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_missing_parent_has_nothing_to_kill() {
        let parent = std::env::temp_dir().join("spawnbox-guard-none-such-dir");
        assert_eq!(sweep(&parent, Duration::ZERO), 0);
    }
}
