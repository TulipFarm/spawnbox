//! Exit statuses of child processes.
//!
//! PID 1 adopts every orphaned process and must reap them all with
//! `waitpid(-1)`. That would steal the exit status of its own children, the
//! agent and the services, so one thread reaps every process and hands the
//! status of a known child to whoever started it.

use std::collections::HashMap;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

type Notify = Box<dyn FnOnce(ExitStatus) + Send>;

pub struct Reaper(Mode);

enum Mode {
    /// Reaps every process; calls back for the ones started here.
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
                // Held across the spawn: the reaper may see the child exit
                // before it is recorded, and then waits for this lock.
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
            let mut raw = 0;
            // SAFETY: `raw` is a valid place for the status.
            let pid = unsafe { libc::waitpid(-1, &raw mut raw, 0) };
            if pid > 0 {
                let notify = lock(waiting).remove(&pid);
                if let Some(notify) = notify {
                    notify(ExitStatus::from_raw(raw));
                }
                continue;
            }
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => {}
                // No children right now.
                Some(libc::ECHILD) => std::thread::sleep(Duration::from_millis(50)),
                _ => {
                    eprintln!(
                        "spawn-guest: waitpid failed: {}",
                        io::Error::last_os_error()
                    );
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
