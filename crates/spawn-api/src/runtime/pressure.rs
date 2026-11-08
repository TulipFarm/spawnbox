//! Pauses idle sandboxes to disk when the host runs short of memory, so the
//! kernel never has to kill a VM.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{PauseReason, Sandboxes, VmState};
use crate::events::Origin;
use crate::fleet::{memory_available_mib, memory_total_mib};
use crate::model::{ApiError, Code};

/// PSI is an average over 10 seconds: it stays high for a while after a
/// pause has helped.
const STALL_WAIT: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(super) struct State {
    pressured: AtomicBool,
    /// A pause for memory is running.
    relieving: Arc<AtomicBool>,
    last: Mutex<Option<Instant>>,
}

#[derive(Clone, Copy)]
struct Reading {
    available_mib: u64,
    total_mib: u64,
    /// Percent of the last 10 seconds some process waited for memory.
    stall_pct: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Verdict {
    Fine,
    /// Free memory is below the limit: pause at once.
    Short,
    /// Processes wait for memory: pause, but not faster than PSI can show
    /// the result.
    Stalled,
}

fn judge(reading: Reading, pct: u8) -> Verdict {
    if pct == 0 || reading.total_mib == 0 {
        return Verdict::Fine;
    }
    if reading.available_mib * 100 < reading.total_mib * u64::from(pct) {
        Verdict::Short
    } else if reading.stall_pct >= f64::from(pct) {
        Verdict::Stalled
    } else {
        Verdict::Fine
    }
}

/// `avg10` of the `some` line of `/proc/pressure/memory`.
fn parse_stall(text: &str) -> Option<f64> {
    text.lines()
        .find_map(|line| line.strip_prefix("some "))?
        .split_whitespace()
        .find_map(|field| field.strip_prefix("avg10="))?
        .parse()
        .ok()
}

fn read() -> Option<Reading> {
    let stall_pct = std::fs::read_to_string("/proc/pressure/memory")
        .ok()
        .and_then(|text| parse_stall(&text))
        .unwrap_or(0.0);
    Some(Reading {
        available_mib: memory_available_mib()?,
        total_mib: memory_total_mib()?,
        stall_pct,
    })
}

struct Relieving(Arc<AtomicBool>);

impl Drop for Relieving {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Sandboxes {
    /// Whether creates and resumes are refused because memory is short.
    pub fn under_pressure(&self) -> bool {
        self.pressure.pressured.load(Ordering::SeqCst)
    }

    pub(super) fn pressure_error() -> ApiError {
        ApiError::new(
            Code::NoCapacity,
            "this host is short of memory; idle sandboxes are being paused",
        )
    }

    /// Checks host memory. When it is short, pauses the running sandbox
    /// that has had no call for the longest, one at a time.
    pub fn relieve_pressure(&self) {
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        let pct = self.settings.memory_pressure_pct;
        let verdict = read().map_or(Verdict::Fine, |reading| judge(reading, pct));
        let was = self
            .pressure
            .pressured
            .swap(verdict != Verdict::Fine, Ordering::SeqCst);
        if was != (verdict != Verdict::Fine) {
            eprintln!(
                "host memory {}",
                if was { "is fine again" } else { "is short" }
            );
        }
        if verdict == Verdict::Fine {
            return;
        }
        let last = *self.pressure.last.lock().unwrap_or_else(|e| e.into_inner());
        if verdict == Verdict::Stalled && last.is_some_and(|at| at.elapsed() < STALL_WAIT) {
            return;
        }
        if self.pressure.relieving.swap(true, Ordering::SeqCst) {
            return;
        }
        let relieving = Relieving(Arc::clone(&self.pressure.relieving));
        let victim = self
            .inner()
            .records
            .iter()
            .filter(|(_, r)| matches!(r.vm, VmState::Running(_)) && !r.is_moving() && r.busy == 0)
            .min_by_key(|(_, r)| r.last_active)
            .map(|(id, r)| (id.clone(), Arc::clone(&r.lock)));
        let Some((id, lock)) = victim else {
            return;
        };
        let this = self.clone();
        tokio::spawn(async move {
            let _relieving = relieving;
            let Ok(_changing) = lock.try_lock() else {
                return;
            };
            if this.closing.load(Ordering::SeqCst) {
                return;
            }
            eprintln!("{id}: host memory is short; pausing");
            let _ = this
                .pause_locked(&id, PauseReason::Pressure, &Origin::system())
                .await;
            *this.pressure.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(available_mib: u64, stall_pct: f64) -> Reading {
        Reading {
            available_mib,
            total_mib: 1000,
            stall_pct,
        }
    }

    #[test]
    fn judges_free_memory_before_stalls() {
        assert_eq!(judge(reading(99, 50.0), 10), Verdict::Short);
        assert_eq!(judge(reading(100, 10.0), 10), Verdict::Stalled);
        assert_eq!(judge(reading(100, 9.9), 10), Verdict::Fine);
        assert_eq!(judge(reading(0, 100.0), 0), Verdict::Fine);
    }

    #[test]
    fn parses_psi() {
        let text = "some avg10=12.50 avg60=3.00 avg300=1.00 total=123\n\
                    full avg10=2.00 avg60=0.00 avg300=0.00 total=45\n";
        assert_eq!(parse_stall(text), Some(12.5));
        assert_eq!(parse_stall("full avg10=1.00\n"), None);
    }
}
