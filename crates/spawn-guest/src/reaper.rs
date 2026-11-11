//! Exit statuses of child processes.
//!
//! PID 1 adopts every orphaned process and must reap them all with
//! `waitpid(-1)`. That would steal the exit status of its own children, the
//! agent and the services, so one thread reaps every process and hands the
//! status of a known child to whoever started it.
//!
//! The reaper must not reap a child while it is being spawned: when a
//! spawn fails between fork and exec, std waits for that child itself and
//! panics if it is gone.

use std::collections::HashMap;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::wait::{Id, WaitPidFlag, waitid};

type Notify = Box<dyn FnOnce(ExitStatus) + Send>;

pub struct Reaper(Mode);

enum Mode {
    /// Reaps every process; calls back for the ones started here. The lock
    /// is held across each spawn, and while a process is reaped.
    Pid1(Mutex<HashMap<i32, Notify>>),
    /// Not PID 1, as in tests: a thread waits for each child.
    #[cfg(test)]
    Direct,
}

/// What a child that could not be waited for counts as.
#[cfg(test)]
const KILLED: i32 = libc::SIGKILL;

impl Reaper {
    /// Starts the thread that reaps every process. Call once, in PID 1.
    pub fn pid1() -> Arc<Self> {
        let reaper = Arc::new(Self(Mode::Pid1(Mutex::default())));
        let reaping = Arc::clone(&reaper);
        std::thread::spawn(move || reaping.reap_forever());
        reaper
    }

    #[cfg(test)]
    pub fn direct() -> Arc<Self> {
        Arc::new(Self(Mode::Direct))
    }

    /// Starts `cmd` and calls `notify` with its exit status once it ends.
    /// Returns its PID. `cmd` is dropped, so the parent's copies of its
    /// pipes close.
    pub fn spawn(
        &self,
        mut cmd: Command,
        notify: impl FnOnce(ExitStatus) + Send + 'static,
    ) -> io::Result<u32> {
        match &self.0 {
            Mode::Pid1(waiting) => {
                // Held across the spawn, so the reaper leaves the child to
                // std if the spawn fails, and finds its notify if it does
                // not.
                let mut waiting = lock(waiting);
                let child = cmd.spawn()?;
                let pid = child.id();
                waiting.insert(i32::try_from(pid).unwrap_or(-1), Box::new(notify));
                Ok(pid)
            }
            #[cfg(test)]
            Mode::Direct => {
                let mut child = cmd.spawn()?;
                let pid = child.id();
                std::thread::spawn(move || {
                    let status = child
                        .wait()
                        .unwrap_or_else(|_| ExitStatus::from_raw(KILLED));
                    notify(status);
                });
                Ok(pid)
            }
        }
    }

    fn reap_forever(&self) {
        #[cfg_attr(not(test), expect(irrefutable_let_patterns))]
        let Mode::Pid1(waiting) = &self.0 else {
            return;
        };
        loop {
            // Waits for any process to end, but leaves it unreaped.
            let pid = match waitid(Id::All, WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT) {
                Ok(status) => match status.pid() {
                    Some(pid) => pid.as_raw(),
                    None => continue,
                },
                Err(Errno::EINTR) => continue,
                // No children right now.
                Err(Errno::ECHILD) => {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                Err(error) => {
                    eprintln!("spawn-guest: waitid failed: {error}");
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };
            // Blocks while a spawn is in progress.
            let mut waiting = lock(waiting);
            let mut raw = 0;
            // SAFETY: `raw` is a valid place for the status.
            let reaped = unsafe { libc::waitpid(pid, &raw mut raw, libc::WNOHANG) };
            // Otherwise a failed spawn reaped it already.
            if reaped == pid
                && let Some(notify) = waiting.remove(&pid)
            {
                drop(waiting);
                notify(ExitStatus::from_raw(raw));
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
