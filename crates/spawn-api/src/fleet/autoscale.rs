//! Adds and removes workers on its own. When the fleet is busy, the primary
//! makes a join token and runs the operator's hook (a program or a webhook),
//! which starts a machine that joins with it. When the fleet is idle, the
//! primary drains the least used worker, moves its sandboxes away, runs the
//! hook to stop the machine, and removes the node. A create that finds no
//! room asks for a worker at once.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Result, anyhow};
use axum::Json;
use axum::extract::State;
use ring::hmac;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;

use super::primary::{self, Primary};
use super::{Capacity, hex, local_capacity, migrate};
use crate::db::{NodeRow, ScaleRequest, node_kind, node_state};
use crate::events::Origin;
use crate::ids;
use crate::model::{ApiError, rfc3339_ms};
use crate::runtime::now_ms;
use crate::server::{App, AppState};

const TICK: Duration = Duration::from_secs(10);
/// A new machine has this long to boot, install and join.
const JOIN_TTL_MS: i64 = 30 * 60_000;
/// Wait this long after a hook fails before running it again.
const RETRY_MS: i64 = 5 * 60_000;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(60);
/// Most hook output lines written to the log.
const MAX_LOG_LINES: usize = 50;
pub const SIGNATURE_HEADER: &str = "x-spawnbox-signature";

const UP: &str = "scale_up";
const DOWN: &str = "scale_down";

#[derive(Debug)]
pub enum Hook {
    /// Run with the action as its argument, the request as JSON on stdin
    /// and in `SPAWNBOX_*` variables.
    Command(PathBuf),
    /// POST the request as JSON, signed with HMAC-SHA256 when there is a
    /// secret.
    Webhook { url: String, secret: Option<String> },
}

impl Hook {
    /// An absolute path to a program, or an `https://` URL. `http://` is
    /// allowed only to this host, because a scale-up holds a join token.
    pub fn parse(text: &str, secret: Option<String>) -> Result<Self, String> {
        if text.starts_with("https://") || text.starts_with("http://") {
            let url = reqwest::Url::parse(text).map_err(|e| format!("{text}: {e}"))?;
            let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if url.scheme() == "http" && !local {
                return Err("a webhook must use https://, or http:// to this host".into());
            }
            return Ok(Self::Webhook {
                url: text.to_owned(),
                secret,
            });
        }
        if secret.is_some() {
            return Err("--autoscale-secret is only for a webhook".into());
        }
        let path = PathBuf::from(text);
        if !path.is_absolute() {
            return Err("give the hook program as an absolute path, or a URL".into());
        }
        Ok(Self::Command(path))
    }

    fn describe(&self) -> String {
        match self {
            Self::Command(path) => path.display().to_string(),
            Self::Webhook { url, .. } => url.clone(),
        }
    }
}

#[derive(Debug)]
pub struct Settings {
    pub hook: Hook,
    pub min_workers: usize,
    pub max_workers: usize,
    /// Fleet load (0 to 1) at or over which a worker is added...
    pub up_ratio: f64,
    /// ...when it stays there this long.
    pub up_after_ms: i64,
    /// Fleet load at or under which a worker is removed...
    pub down_ratio: f64,
    /// ...when it stays there this long.
    pub down_after_ms: i64,
}

/// When the load went high or low and stayed there.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Trend {
    high_since: Option<i64>,
    low_since: Option<i64>,
}

impl Trend {
    fn update(&mut self, load: Option<f64>, s: &Settings, now: i64) {
        match load {
            Some(l) if l >= s.up_ratio => {
                self.high_since.get_or_insert(now);
                self.low_since = None;
            }
            Some(l) if l <= s.down_ratio => {
                self.low_since.get_or_insert(now);
                self.high_since = None;
            }
            _ => *self = Self::default(),
        }
    }
}

/// The fleet as the autoscaler sees it.
#[derive(Clone, Copy, Debug, Default)]
struct Fleet {
    load: Option<f64>,
    /// Workers that are ready and not draining.
    active: usize,
    /// Workers not removed, and the one asked for.
    total: usize,
    pending_up: bool,
    scaling_down: bool,
    /// A create found no room since the last tick.
    refused: bool,
}

#[derive(Debug, PartialEq)]
enum Decision {
    Wait,
    Up(String),
    Down(String),
    /// Let the worker being removed take sandboxes again.
    CancelDown(String),
}

/// One step at a time: no new request while a worker is still to join.
fn decide(s: &Settings, f: &Fleet, t: &Trend, now: i64) -> Decision {
    if f.pending_up {
        return Decision::Wait;
    }
    let lasted = |since: Option<i64>, after: i64| since.is_some_and(|t0| now - t0 >= after);
    let need = if f.active < s.min_workers {
        Some(format!("fewer than {} workers", s.min_workers))
    } else if f.refused {
        Some("a create found no room".to_owned())
    } else if lasted(t.high_since, s.up_after_ms) {
        Some(format!(
            "load {:.0}% for {} s",
            f.load.unwrap_or(1.0) * 100.0,
            (now - t.high_since.unwrap_or(now)) / 1000
        ))
    } else {
        None
    };
    if let Some(reason) = need {
        if f.scaling_down {
            return Decision::CancelDown(reason);
        }
        if f.total < s.max_workers {
            return Decision::Up(reason);
        }
        return Decision::Wait;
    }
    if !f.scaling_down && f.active > s.min_workers && lasted(t.low_since, s.down_after_ms) {
        return Decision::Down(format!(
            "load {:.0}% for {} s",
            f.load.unwrap_or(0.0) * 100.0,
            (now - t.low_since.unwrap_or(now)) / 1000
        ));
    }
    Decision::Wait
}

/// Part of the slots, the memory in use or the memory reserved over
/// `hosts`, whichever is more, from 0 to 1. `None` if no host reports them.
fn fleet_load(hosts: &[Capacity]) -> Option<f64> {
    let (mut used, mut slots, mut mem_used, mut mem_total) = (0u64, 0u64, 0u64, 0u64);
    let (mut reserved, mut limit) = (0u64, 0u64);
    for host in hosts {
        reserved += if host.memory_pressure {
            host.memory_limit_mib
        } else {
            host.memory_reserved_mib
        };
        limit += host.memory_limit_mib;
        let total = host.slots as u64;
        slots += total;
        used += total.saturating_sub(host.free_slots as u64);
        mem_total += host.memory_total_mib;
        mem_used += host
            .memory_total_mib
            .saturating_sub(host.memory_available_mib);
    }
    let ratio = |used: u64, total: u64| (total > 0).then(|| used as f64 / total as f64);
    [
        ratio(used, slots),
        ratio(mem_used, mem_total),
        ratio(reserved, limit),
    ]
    .into_iter()
    .flatten()
    .reduce(f64::max)
    .map(|r| r.clamp(0.0, 1.0))
}

/// What `GET /v1/nodes/autoscale` shows.
#[derive(Clone, Copy, Default)]
struct Status {
    fleet: Fleet,
    trend: Trend,
}

pub struct Autoscaler {
    settings: Settings,
    status: Mutex<Status>,
    refused: AtomicBool,
    wake: Notify,
}

impl Autoscaler {
    /// A create found no room: ask for a worker without waiting for the
    /// load to stay high.
    pub fn refused(&self) {
        self.refused.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }

    pub fn load(&self) -> Option<f64> {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .fleet
            .load
    }
}

/// What one tick leaves for the next.
#[derive(Default)]
struct Memory {
    trend: Trend,
    /// No scale-up before this time, after a failed one.
    up_not_before: i64,
    /// Scale-downs whose hook failed, and when to try again.
    retry_at: HashMap<String, i64>,
    /// Drains of scale-downs are running in this process.
    drains_resumed: bool,
}

/// Starts the autoscaler on a primary.
pub fn start(app: AppState, settings: Settings) -> Result<tokio::task::JoinHandle<()>> {
    let p = primary::primary(&app).map_err(|e| anyhow!(e.message))?;
    eprintln!(
        "autoscale: {} to {} workers; hook {}",
        settings.min_workers,
        settings.max_workers,
        settings.hook.describe()
    );
    let scaler = Arc::new(Autoscaler {
        settings,
        status: Mutex::default(),
        refused: AtomicBool::new(false),
        wake: Notify::new(),
    });
    if p.autoscaler.set(Arc::clone(&scaler)).is_err() {
        return Err(anyhow!("the autoscaler is already running"));
    }
    Ok(tokio::spawn(async move {
        let mut memory = Memory::default();
        loop {
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                () = scaler.wake.notified() => {}
            }
            if let Err(error) = tick(&app, &scaler, &mut memory).await {
                eprintln!("autoscale: {error:#}");
            }
        }
    }))
}

async fn tick(app: &AppState, scaler: &Autoscaler, memory: &mut Memory) -> Result<()> {
    let s = &scaler.settings;
    let p = primary::primary(app).map_err(|e| anyhow!(e.message))?;
    let now = now_ms();
    let nodes = app.db.list_nodes()?;
    let counts = app.db.node_sandbox_counts()?;
    let mut fleet = Fleet {
        refused: scaler.refused.swap(false, Ordering::SeqCst),
        ..Fleet::default()
    };
    let mut removing: Option<ScaleRequest> = None;
    for request in app.db.scale_requests(true, 100)? {
        match request.action.as_str() {
            UP => {
                if let Some(node) = request.node.as_deref() {
                    end(app, &request, Some(node), "joined", "autoscale.done");
                } else if request.expires_at.is_some_and(|at| at <= now) {
                    let why = "no worker joined before the join token expired";
                    end(app, &request, None, why, "autoscale.failed");
                } else {
                    fleet.pending_up = true;
                }
            }
            DOWN => {
                let id = request.node.clone().unwrap_or_default();
                match nodes.iter().find(|n| n.id == id) {
                    None => end(
                        app,
                        &request,
                        None,
                        "the worker was removed",
                        "autoscale.cancelled",
                    ),
                    Some(n) if !n.draining => end(
                        app,
                        &request,
                        None,
                        "the worker was undrained",
                        "autoscale.cancelled",
                    ),
                    Some(n) => {
                        let empty = counts.get(&n.id).copied().unwrap_or(0) == 0
                            && !homes_volumes(app, &n.id)?;
                        if !empty && !memory.drains_resumed {
                            // The primary restarted while moving its sandboxes.
                            let origin = Origin::system();
                            tokio::spawn(migrate::drain(Arc::clone(app), n.id.clone(), origin));
                        }
                        let due = memory.retry_at.get(&request.id).is_none_or(|at| now >= *at);
                        if empty && due && remove_worker(app, s, &request, n).await {
                            memory.retry_at.remove(&request.id);
                        } else {
                            if empty && due {
                                memory.retry_at.insert(request.id.clone(), now + RETRY_MS);
                            }
                            removing = Some(request);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    memory.drains_resumed = true;
    memory
        .retry_at
        .retain(|id, _| removing.as_ref().is_some_and(|r| &r.id == id));
    fleet.scaling_down = removing.is_some();

    let nodes = app.db.list_nodes()?;
    let workers: Vec<&NodeRow> = nodes
        .iter()
        .filter(|n| n.kind == node_kind::WORKER)
        .collect();
    let active: Vec<&NodeRow> = workers
        .iter()
        .copied()
        .filter(|n| n.state == node_state::READY && !n.draining)
        .collect();
    let live: HashMap<String, Capacity> = p.capacities().into_iter().collect();
    let mut hosts = vec![local_capacity(app)];
    hosts.extend(active.iter().filter_map(|n| live.get(&n.id).cloned()));
    fleet.load = fleet_load(&hosts);
    fleet.active = active.len();
    fleet.total = workers.len() + usize::from(fleet.pending_up);
    memory.trend.update(fleet.load, s, now);

    match decide(s, &fleet, &memory.trend, now) {
        Decision::Wait => {}
        Decision::Up(reason) => {
            if now >= memory.up_not_before {
                memory.trend = Trend::default();
                if scale_up(app, p, s, &reason, now).await? {
                    fleet.pending_up = true;
                } else {
                    memory.up_not_before = now + RETRY_MS;
                }
            }
        }
        Decision::Down(reason) => {
            memory.trend = Trend::default();
            let pick = active
                .iter()
                .min_by_key(|n| (counts.get(&n.id).copied().unwrap_or(0), -n.created_at));
            if let Some(node) = pick {
                scale_down(app, &node.id, &reason, now)?;
                fleet.scaling_down = true;
            }
        }
        Decision::CancelDown(reason) => {
            memory.trend = Trend::default();
            if let Some(request) = removing {
                let id = request.node.clone().unwrap_or_default();
                app.db.set_node_draining(&id, false)?;
                app.sandboxes.hub.record(
                    "node.undrained",
                    &Origin::system(),
                    None,
                    None,
                    json!({ "node": id, "migrate": false }),
                );
                let why = format!("kept the worker: {reason}");
                end(app, &request, None, &why, "autoscale.cancelled");
                fleet.scaling_down = false;
            }
        }
    }
    let trend = memory.trend;
    *scaler.status.lock().unwrap_or_else(|e| e.into_inner()) = Status { fleet, trend };
    Ok(())
}

fn homes_volumes(app: &App, node: &str) -> Result<bool> {
    Ok(app
        .db
        .list_volumes(None)?
        .iter()
        .any(|v| v.node.as_deref() == Some(node)))
}

fn end(app: &App, request: &ScaleRequest, node: Option<&str>, outcome: &str, kind: &'static str) {
    if let Err(error) = app
        .db
        .end_scale_request(&request.id, node, outcome, now_ms())
    {
        eprintln!("autoscale: end {}: {error}", request.id);
        return;
    }
    eprintln!("autoscale: {} {}: {outcome}", request.action, request.id);
    app.sandboxes.hub.record(
        kind,
        &Origin::system(),
        None,
        None,
        json!({
            "id": request.id,
            "action": request.action,
            "node": node.or(request.node.as_deref()),
            "outcome": outcome,
        }),
    );
}

fn requested(app: &App, id: &str, action: &str, node: Option<&str>, reason: &str) {
    eprintln!("autoscale: {action} {id}: {reason}");
    app.sandboxes.hub.record(
        "autoscale.requested",
        &Origin::system(),
        None,
        None,
        json!({ "id": id, "action": action, "node": node, "reason": reason }),
    );
}

/// Makes a join token and asks the hook for a machine. False if the hook
/// failed.
async fn scale_up(app: &App, p: &Primary, s: &Settings, reason: &str, now: i64) -> Result<bool> {
    let id = ids::new_id("scl")?;
    let token = primary::new_join_token().map_err(|e| anyhow!(e.message))?;
    let expires_at = now + JOIN_TTL_MS;
    let ca_sha256 = p.ca_sha256()?;
    app.db
        .insert_scale_up(&id, &ids::hash_key(&token), reason, now, expires_at)?;
    requested(app, &id, UP, None, reason);
    let body = json!({
        "action": UP,
        "id": id,
        "reason": reason,
        "join": {
            "token": token,
            "ca_sha256": ca_sha256,
            "expires_at": rfc3339_ms(expires_at),
        },
    });
    let env = [
        ("SPAWNBOX_JOIN_TOKEN", token),
        ("SPAWNBOX_PRIMARY_CA_SHA256", ca_sha256),
    ];
    let request = ScaleRequest {
        id,
        action: UP.into(),
        node: None,
        reason: reason.into(),
        created_at: now,
        expires_at: Some(expires_at),
        ended_at: None,
        outcome: None,
    };
    match call(&s.hook, UP, &request.id, &body, &env).await {
        Ok(()) => Ok(true),
        Err(error) => {
            end(
                app,
                &request,
                None,
                &format!("hook failed: {error}"),
                "autoscale.failed",
            );
            Ok(false)
        }
    }
}

/// Drains `node` and moves its sandboxes away. The node is removed on a
/// later tick, once it is empty.
fn scale_down(app: &AppState, node: &str, reason: &str, now: i64) -> Result<()> {
    let id = ids::new_id("scl")?;
    if !app.db.set_node_draining(node, true)? {
        return Ok(());
    }
    app.db.insert_scale_down(&id, node, reason, now)?;
    let origin = Origin::system();
    app.sandboxes.hub.record(
        "node.draining",
        &origin,
        None,
        None,
        json!({ "node": node, "migrate": true }),
    );
    requested(app, &id, DOWN, Some(node), reason);
    tokio::spawn(migrate::drain(Arc::clone(app), node.to_owned(), origin));
    Ok(())
}

/// Asks the hook to stop the machine of an empty, draining worker, then
/// removes the node. False if the hook failed.
async fn remove_worker(app: &App, s: &Settings, request: &ScaleRequest, node: &NodeRow) -> bool {
    let joined_for = app.db.scale_up_of(&node.id).ok().flatten();
    let body = json!({
        "action": DOWN,
        "id": request.id,
        "reason": request.reason,
        "node": { "id": node.id, "url": node.url, "scale_up": joined_for },
    });
    let env = [
        ("SPAWNBOX_NODE_ID", node.id.clone()),
        ("SPAWNBOX_NODE_URL", node.url.clone()),
        ("SPAWNBOX_NODE_SCALE_UP", joined_for.unwrap_or_default()),
    ];
    if let Err(error) = call(&s.hook, DOWN, &request.id, &body, &env).await {
        eprintln!("autoscale: {DOWN} {}: hook failed: {error}", request.id);
        app.sandboxes.hub.record(
            "autoscale.failed",
            &Origin::system(),
            None,
            None,
            json!({
                "id": request.id,
                "action": DOWN,
                "node": node.id,
                "outcome": format!("hook failed: {error}; trying again in {} s", RETRY_MS / 1000),
            }),
        );
        return false;
    }
    if let Err(error) = primary::remove(app, &node.id, &Origin::system()) {
        eprintln!("autoscale: remove {}: {}", node.id, error.message);
        return false;
    }
    end(app, request, Some(&node.id), "removed", "autoscale.done");
    true
}

async fn call(
    hook: &Hook,
    action: &str,
    id: &str,
    body: &Value,
    env: &[(&str, String)],
) -> Result<(), String> {
    let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    match hook {
        Hook::Command(path) => run_command(path, action, id, &bytes, env).await,
        Hook::Webhook { url, secret } => post(url, secret.as_deref(), &bytes).await,
    }
}

async fn run_command(
    path: &PathBuf,
    action: &str,
    id: &str,
    body: &[u8],
    env: &[(&str, String)],
) -> Result<(), String> {
    let mut child = tokio::process::Command::new(path)
        .arg(action)
        .env("SPAWNBOX_ACTION", action)
        .env("SPAWNBOX_REQUEST_ID", id)
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("start {}: {e}", path.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        // The program may not read its input.
        let _ = stdin.write_all(body).await;
    }
    let output = tokio::time::timeout(COMMAND_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("no exit after {} s", COMMAND_TIMEOUT.as_secs()))?
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stdout.lines().chain(stderr.lines()).take(MAX_LOG_LINES) {
        eprintln!("autoscale hook {id}: {line}");
    }
    if output.status.success() {
        return Ok(());
    }
    let last = stderr.lines().last().unwrap_or_default();
    Err(format!("{} {last}", output.status).trim_end().to_owned())
}

/// `sha256=` and the hex HMAC-SHA256 of `body` with `secret`.
fn signature(secret: &str, body: &[u8]) -> String {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()), body);
    format!("sha256={}", hex(tag.as_ref()))
}

async fn post(url: &str, secret: Option<&str>, body: &[u8]) -> Result<(), String> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    let client = CLIENT.get_or_init(reqwest::Client::new);
    let mut request = client
        .post(url)
        .timeout(WEBHOOK_TIMEOUT)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec());
    if let Some(secret) = secret {
        request = request.header(SIGNATURE_HEADER, signature(secret, body));
    }
    let response = request.send().await.map_err(|e| format!("{e:#}"))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", response.status()))
    }
}

fn request_view(r: &ScaleRequest) -> Value {
    json!({
        "id": r.id,
        "action": r.action,
        "node": r.node,
        "reason": r.reason,
        "created_at": rfc3339_ms(r.created_at),
        "ended_at": r.ended_at.map(rfc3339_ms),
        "outcome": r.outcome,
    })
}

/// `GET /v1/nodes/autoscale`.
pub async fn status(State(app): State<AppState>) -> Result<Json<Value>, ApiError> {
    let p = primary::primary(&app)?;
    let requests: Vec<Value> = app
        .db
        .scale_requests(false, 20)?
        .iter()
        .map(request_view)
        .collect();
    let Some(scaler) = p.autoscaler.get() else {
        return Ok(Json(json!({ "enabled": false, "requests": requests })));
    };
    let s = &scaler.settings;
    let Status { fleet, trend } = *scaler.status.lock().unwrap_or_else(|e| e.into_inner());
    Ok(Json(json!({
        "enabled": true,
        "hook": match s.hook { Hook::Command(_) => "command", Hook::Webhook { .. } => "webhook" },
        "min_workers": s.min_workers,
        "max_workers": s.max_workers,
        "up_pct": (s.up_ratio * 100.0).round(),
        "up_after_s": s.up_after_ms / 1000,
        "down_pct": (s.down_ratio * 100.0).round(),
        "down_after_s": s.down_after_ms / 1000,
        "load": fleet.load,
        "workers": fleet.active,
        "high_since": trend.high_since.map(rfc3339_ms),
        "low_since": trend.low_since.map(rfc3339_ms),
        "requests": requests,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings {
            hook: Hook::Command("/bin/true".into()),
            min_workers: 1,
            max_workers: 3,
            up_ratio: 0.7,
            up_after_ms: 120_000,
            down_ratio: 0.3,
            down_after_ms: 1_200_000,
        }
    }

    fn fleet(load: f64, active: usize) -> Fleet {
        Fleet {
            load: Some(load),
            active,
            total: active,
            ..Fleet::default()
        }
    }

    /// The decision after `load` holds from time 0 to `now`.
    fn after(s: &Settings, f: &Fleet, now: i64) -> Decision {
        let mut trend = Trend::default();
        trend.update(f.load, s, 0);
        trend.update(f.load, s, now);
        decide(s, f, &trend, now)
    }

    #[test]
    fn adds_a_worker_only_when_load_stays_high() {
        let s = settings();
        assert_eq!(after(&s, &fleet(0.8, 1), 60_000), Decision::Wait);
        assert!(matches!(
            after(&s, &fleet(0.8, 1), 120_000),
            Decision::Up(_)
        ));
        assert_eq!(after(&s, &fleet(0.5, 1), 999_000_000), Decision::Wait);
    }

    #[test]
    fn a_dip_starts_the_wait_again() {
        let s = settings();
        let mut trend = Trend::default();
        trend.update(Some(0.9), &s, 0);
        trend.update(Some(0.5), &s, 100_000);
        trend.update(Some(0.9), &s, 110_000);
        assert_eq!(decide(&s, &fleet(0.9, 1), &trend, 200_000), Decision::Wait);
    }

    #[test]
    fn keeps_within_min_and_max() {
        let s = settings();
        assert!(matches!(after(&s, &fleet(0.0, 0), 0), Decision::Up(r) if r.contains("fewer")));
        assert_eq!(after(&s, &fleet(0.9, 3), 999_000), Decision::Wait);
        assert_eq!(after(&s, &fleet(0.1, 1), 9_999_000), Decision::Wait);
        assert!(matches!(
            after(&s, &fleet(0.1, 2), 1_200_000),
            Decision::Down(_)
        ));
    }

    #[test]
    fn a_refused_create_adds_a_worker_at_once() {
        let s = settings();
        let refused = Fleet {
            refused: true,
            ..fleet(0.2, 1)
        };
        assert!(matches!(after(&s, &refused, 0), Decision::Up(r) if r.contains("no room")));
        let full = Fleet {
            refused: true,
            ..fleet(0.2, 3)
        };
        assert_eq!(after(&s, &full, 0), Decision::Wait);
    }

    #[test]
    fn one_change_at_a_time() {
        let s = settings();
        let pending = Fleet {
            pending_up: true,
            ..fleet(0.0, 0)
        };
        assert_eq!(after(&s, &pending, 999_000), Decision::Wait);
        let removing = Fleet {
            scaling_down: true,
            ..fleet(0.1, 2)
        };
        assert_eq!(after(&s, &removing, 9_999_000), Decision::Wait);
        let busy_again = Fleet {
            scaling_down: true,
            ..fleet(0.9, 2)
        };
        assert!(matches!(
            after(&s, &busy_again, 120_000),
            Decision::CancelDown(_)
        ));
    }

    #[test]
    fn load_is_the_fuller_of_slots_and_memory() {
        let host = |free_slots, available| Capacity {
            slots: 10,
            free_slots,
            memory_total_mib: 1000,
            memory_available_mib: available,
            ..Capacity::default()
        };
        assert_eq!(fleet_load(&[]), None);
        let load = fleet_load(&[host(10, 1000), host(0, 1000)]).unwrap();
        assert!((load - 0.5).abs() < 1e-9);
        let load = fleet_load(&[host(10, 100), host(10, 100)]).unwrap();
        assert!((load - 0.9).abs() < 1e-9);
        let reserved = Capacity {
            memory_reserved_mib: 1425,
            memory_limit_mib: 1500,
            ..host(10, 1000)
        };
        let load = fleet_load(&[reserved]).unwrap();
        assert!((load - 0.95).abs() < 1e-9);
        let pressured = Capacity {
            memory_reserved_mib: 0,
            memory_limit_mib: 1500,
            memory_pressure: true,
            ..host(10, 1000)
        };
        assert_eq!(fleet_load(&[pressured]), Some(1.0));
        let old = Capacity {
            free_slots: 3,
            memory_available_mib: 500,
            ..Capacity::default()
        };
        assert_eq!(fleet_load(&[old]), None);
    }

    #[test]
    fn hooks_are_absolute_programs_or_safe_urls() {
        assert!(matches!(
            Hook::parse("/usr/local/bin/scale", None),
            Ok(Hook::Command(_))
        ));
        assert!(Hook::parse("scale.sh", None).is_err());
        assert!(Hook::parse("/bin/x", Some("s".into())).is_err());
        assert!(matches!(
            Hook::parse("https://ops.example.com/scale", Some("s".into())),
            Ok(Hook::Webhook { .. })
        ));
        assert!(Hook::parse("http://127.0.0.1:9000/scale", None).is_ok());
        assert!(Hook::parse("http://ops.example.com/scale", None).is_err());
    }

    #[test]
    fn signs_webhook_bodies() {
        // Same as `printf '{}' | openssl dgst -sha256 -hmac key`.
        assert_eq!(
            signature("key", b"{}"),
            "sha256=a777724d943eb48dc69bca8a4a6d57a04db3f9ec7e1de4e581e860265bdf3032"
        );
    }

    #[tokio::test]
    async fn runs_the_program_with_the_request() {
        let dir = std::env::temp_dir().join(format!("spawnbox-hook-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("hook.sh");
        let seen = dir.join("seen");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nset -e\nprintf '%s %s ' \"$1\" \"$SPAWNBOX_JOIN_TOKEN\" > {seen}\ncat >> {seen}\n[ \"$1\" = scale_up ] || {{ echo nope >&2; exit 3; }}\n",
                seen = seen.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let hook = Hook::Command(script.clone());
        let env = [("SPAWNBOX_JOIN_TOKEN", "sbj_x".to_owned())];
        call(&hook, UP, "scl_1", &json!({ "a": 1 }), &env)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap(),
            r#"scale_up sbj_x {"a":1}"#
        );
        let error = call(&hook, DOWN, "scl_2", &json!({}), &[])
            .await
            .unwrap_err();
        assert!(error.contains("nope"), "{error}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
