//! Empties workers so their machines can be stopped. A retirement stops
//! new sandboxes going to the worker, moves its sandboxes and volumes away
//! (or waits for them to end), and marks it `ready_to_terminate` only once
//! the worker itself reports that it is empty. The autoscaler's hook, or
//! the operator's own tools, then stop the machine and remove the node.
//! It runs on every primary that leads, with or without a hook, and picks
//! up retirements a previous leader started.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::migrate;
use crate::db::{NodeRow, Retirement, node_state, retire_state};
use crate::events::Origin;
use crate::model::rfc3339_ms;
use crate::runtime::now_ms;
use crate::server::{App, AppState};

const TICK: Duration = Duration::from_secs(5);
/// Calls that placed a sandbox or started a move before the retirement may
/// still finish this long after it; a new leader does not know of them.
pub const SETTLE_MS: i64 = 3 * 60_000;
/// Wait this long after a pass that left sandboxes behind before the next.
const RETRY_MS: i64 = 60_000;

/// Forwarded creates, forks and moves to each node that have not ended.
#[derive(Default)]
pub struct Busy(Mutex<HashMap<String, usize>>);

/// Held while a call may put a sandbox on a node.
pub struct BusyGuard<'a> {
    busy: &'a Busy,
    node: String,
}

impl Busy {
    pub fn hold(&self, node: &str) -> BusyGuard<'_> {
        *lock(&self.0).entry(node.to_owned()).or_default() += 1;
        BusyGuard {
            busy: self,
            node: node.to_owned(),
        }
    }

    fn count(&self, node: &str) -> usize {
        lock(&self.0).get(node).copied().unwrap_or(0)
    }
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        let mut map = lock(&self.busy.0);
        if let Some(n) = map.get_mut(&self.node) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.node);
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

enum Pass {
    Running,
    /// When it ended, and whether it moved everything.
    Done {
        at: i64,
        failed: u32,
    },
}

/// The retirer's state in this process.
#[derive(Default)]
pub struct Retirer {
    passes: Mutex<HashMap<String, Pass>>,
    /// What each open retirement still waits for, as of the last tick.
    waiting: Mutex<HashMap<String, Vec<&'static str>>>,
    wake: Notify,
}

impl Retirer {
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// What `node`'s retirement waits for; empty if unknown.
    pub fn waiting_for(&self, node: &str) -> Vec<&'static str> {
        lock(&self.waiting).get(node).cloned().unwrap_or_default()
    }
}

/// Starts the retirer on a primary.
pub fn start(app: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(error) = tick(&app) {
                eprintln!("retire: {error:#}");
            }
            let Ok(p) = super::primary::primary(&app) else {
                return;
            };
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                () = p.retirer.wake.notified() => {}
            }
        }
    })
}

/// What a retirement still waits for, in the order they usually clear.
#[derive(Default)]
struct Check {
    sandboxes: usize,
    volumes: usize,
    busy: usize,
    /// Since the retirement began.
    elapsed_ms: i64,
    /// The node's last accepted heartbeat.
    last_seen: Option<i64>,
}

impl Check {
    fn waiting_for(&self, r: &Retirement) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.sandboxes > 0 {
            out.push("sandboxes");
        }
        if self.volumes > 0 {
            out.push("volumes");
        }
        if self.busy > 0 {
            out.push("calls");
        }
        if self.elapsed_ms < SETTLE_MS {
            out.push("settle");
        }
        // The heartbeat must come after the settle time, so that it shows
        // every sandbox a late call may have made there.
        if self.last_seen.is_none_or(|t| t < r.created_at + SETTLE_MS) {
            out.push("heartbeat");
        }
        out
    }
}

fn tick(app: &AppState) -> Result<()> {
    let p = super::primary::primary(app).map_err(|e| anyhow::anyhow!(e.message))?;
    let open = app.db.retirements(true)?;
    let now = now_ms();
    let counts = app.db.node_sandbox_counts()?;
    let volumes = app.db.list_volumes(None)?;
    let mut waiting = HashMap::new();
    for r in open {
        let node = app.db.get_node(&r.node)?;
        let Some(node) = node.filter(|n| n.state != node_state::REMOVED) else {
            app.db.end_retirement_of(&r.node, now)?;
            continue;
        };
        if r.state == retire_state::READY {
            waiting.insert(r.node.clone(), Vec::new());
            continue;
        }
        let check = Check {
            sandboxes: counts.get(&r.node).copied().unwrap_or(0),
            volumes: volumes
                .iter()
                .filter(|v| v.node.as_deref() == Some(r.node.as_str()))
                .count(),
            busy: p.busy.count(&r.node),
            elapsed_ms: now - r.created_at,
            last_seen: node.last_seen,
        };
        let left = check.sandboxes + check.volumes;
        let mut failed = r.failed_moves;
        let mut blocked = false;
        if r.migrate {
            match next_pass(app, &p.retirer, &node, left, now) {
                PassState::Moving => {}
                PassState::Blocked(f) => {
                    failed = i64::from(f);
                    blocked = true;
                }
            }
        }
        let wait = check.waiting_for(&r);
        let state = if wait.is_empty() {
            retire_state::READY
        } else if blocked {
            retire_state::BLOCKED
        } else {
            retire_state::DRAINING
        };
        if state != r.state || failed != r.failed_moves {
            app.db.set_retirement(&r.node, state, failed, now)?;
            if state == retire_state::READY {
                eprintln!("retire {}: ready to terminate", r.node);
                app.sandboxes.hub.record(
                    "node.retired",
                    &Origin::system(),
                    None,
                    None,
                    json!({ "node": r.node, "id": r.id, "origin": r.origin }),
                );
                if let Some(scaler) = p.autoscaler.get() {
                    scaler.wake();
                }
            }
        }
        waiting.insert(r.node.clone(), wait);
    }
    *lock(&p.retirer.waiting) = waiting;
    Ok(())
}

enum PassState {
    Moving,
    /// The last pass ended with work left; this many moves failed.
    Blocked(u32),
}

/// Starts a pass to move `node`'s sandboxes and volumes away if none ran
/// in this process yet, or the last one left some behind a while ago.
fn next_pass(
    app: &AppState,
    retirer: &Retirer,
    node: &NodeRow,
    left: usize,
    now: i64,
) -> PassState {
    let mut passes = lock(&retirer.passes);
    match passes.get(&node.id) {
        Some(Pass::Running) => return PassState::Moving,
        Some(Pass::Done { .. }) if left == 0 => return PassState::Moving,
        Some(Pass::Done { at, failed }) if now - at < RETRY_MS => {
            return PassState::Blocked(*failed);
        }
        _ => {}
    }
    passes.insert(node.id.clone(), Pass::Running);
    let (app, id) = (Arc::clone(app), node.id.clone());
    tokio::spawn(async move {
        let result = migrate::drain(Arc::clone(&app), id.clone(), Origin::system()).await;
        if let Ok(p) = super::primary::primary(&app) {
            lock(&p.retirer.passes).insert(
                id,
                Pass::Done {
                    at: now_ms(),
                    failed: result.failed + result.volumes_failed,
                },
            );
            p.retirer.wake();
        }
    });
    PassState::Moving
}

/// Forgets passes of nodes that are no longer retiring.
pub fn forget(app: &App, node: &str) {
    if let Ok(p) = super::primary::primary(app) {
        lock(&p.retirer.passes).remove(node);
        lock(&p.retirer.waiting).remove(node);
    }
}

pub fn view(r: &Retirement, waiting_for: &[&str]) -> Value {
    json!({
        "id": r.id,
        "origin": r.origin,
        "state": r.state,
        "migrate": r.migrate,
        "reason": r.reason,
        "created_at": rfc3339_ms(r.created_at),
        "ready_at": r.ready_at.map(rfc3339_ms),
        "ended_at": r.ended_at.map(rfc3339_ms),
        "failed_moves": r.failed_moves,
        "waiting_for": waiting_for,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retirement() -> Retirement {
        Retirement {
            node: "n1".into(),
            id: "ret_1".into(),
            origin: "api".into(),
            migrate: true,
            reason: "test".into(),
            state: retire_state::DRAINING.into(),
            created_at: 1_000,
            ready_at: None,
            ended_at: None,
            failed_moves: 0,
        }
    }

    #[test]
    fn ready_only_when_empty_settled_and_reported_after() {
        let r = retirement();
        let after = r.created_at + SETTLE_MS;
        let empty = Check {
            elapsed_ms: SETTLE_MS,
            last_seen: Some(after),
            ..Check::default()
        };
        assert!(empty.waiting_for(&r).is_empty());
        let early = Check {
            elapsed_ms: SETTLE_MS - 1,
            ..empty
        };
        assert_eq!(early.waiting_for(&r), ["settle"]);
        let stale = Check {
            last_seen: Some(after - 1),
            ..empty
        };
        assert_eq!(stale.waiting_for(&r), ["heartbeat"]);
        let silent = Check {
            last_seen: None,
            ..empty
        };
        assert_eq!(silent.waiting_for(&r), ["heartbeat"]);
        let full = Check {
            sandboxes: 1,
            volumes: 1,
            busy: 1,
            ..empty
        };
        assert_eq!(full.waiting_for(&r), ["sandboxes", "volumes", "calls"]);
    }

    #[test]
    fn busy_counts_calls_until_they_end() {
        let busy = Busy::default();
        let a = busy.hold("n1");
        let b = busy.hold("n1");
        assert_eq!(busy.count("n1"), 2);
        drop(a);
        assert_eq!(busy.count("n1"), 1);
        drop(b);
        assert_eq!(busy.count("n1"), 0);
    }
}
