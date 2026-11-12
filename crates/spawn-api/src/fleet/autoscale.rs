//! Adds and removes workers through the operator's hook (a program or a
//! webhook), so any cloud or tool can start and stop the machines. When the
//! fleet is busy, the primary makes a join token and asks the hook for a
//! machine that joins with it. If the hook fails, or a new leader does not
//! know whether it ran, the same request (same ID and token) is sent again,
//! so the hook can use the ID to start at most one machine. When the fleet
//! is idle, the primary retires the least used worker (see `retire`), and
//! once it is empty asks the hook to stop that machine. A create that finds
//! no room asks for a worker at once.

use std::collections::{BTreeMap, HashMap, HashSet};
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
use super::{Capacity, hex, local_capacity};
use crate::db::{NodeRow, ScaleRequest, node_kind, node_state, retire_origin, retire_state};
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
/// A worker down this long is taken to be gone, so it no longer counts
/// toward `max_workers`. If it comes back it counts again.
const GONE_AFTER_MS: i64 = 10 * 60_000;
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
    /// Workers not removed or retiring, and the ones asked for.
    total: usize,
    /// Scale-ups still waiting for their worker to join.
    pending_up: usize,
    scaling_down: bool,
    /// A create found no room since the last tick.
    refused: bool,
}

#[derive(Debug, PartialEq)]
enum Decision {
    Wait,
    /// Ask for this many workers.
    Up(String, usize),
    Down(String),
}

/// Below the minimum, asks for all missing workers at once. Otherwise one
/// step at a time: no new request while a worker is still to join.
fn decide(s: &Settings, f: &Fleet, t: &Trend, now: i64) -> Decision {
    let missing = s.min_workers.saturating_sub(f.active + f.pending_up);
    if missing > 0 {
        let n = missing.min(s.max_workers.saturating_sub(f.total));
        if n > 0 {
            return Decision::Up(format!("fewer than {} workers", s.min_workers), n);
        }
        return Decision::Wait;
    }
    if f.pending_up > 0 {
        return Decision::Wait;
    }
    let lasted = |since: Option<i64>, after: i64| since.is_some_and(|t0| now - t0 >= after);
    let need = if f.refused {
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
        // A retiring worker never takes sandboxes again, so a worker is
        // added even while one is being removed.
        if f.total < s.max_workers {
            return Decision::Up(reason, 1);
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

/// True if `node`'s machine may still be running.
fn may_run(node: &NodeRow, now: i64) -> bool {
    node.state != node_state::DOWN || node.last_seen.is_none_or(|seen| now - seen < GONE_AFTER_MS)
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

pub struct Autoscaler {
    settings: Settings,
    status: Mutex<Trend>,
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

    pub fn wake(&self) {
        self.wake.notify_one();
    }
}

/// What one tick leaves for the next.
#[derive(Default)]
struct Memory {
    trend: Trend,
    /// Requests whose hook failed, and when to try again.
    retry_at: HashMap<String, i64>,
    /// Scale-ups whose hook ran in this process. Others are sent again.
    sent: HashSet<String>,
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
    let mut fleet = Fleet {
        refused: scaler.refused.swap(false, Ordering::SeqCst),
        ..Fleet::default()
    };
    let open = app.db.scale_requests(true, u32::MAX)?;
    let open_ids: HashSet<String> = open.iter().map(|r| r.id.clone()).collect();
    memory.retry_at.retain(|id, _| open_ids.contains(id));
    memory.sent.retain(|id| open_ids.contains(id));
    for request in open {
        let due = memory.retry_at.get(&request.id).is_none_or(|at| now >= *at);
        match request.action.as_str() {
            UP => {
                if let Some(node) = request.node.as_deref() {
                    end(app, &request, Some(node), "joined", "autoscale.done");
                } else if request.expires_at.is_some_and(|at| at <= now) {
                    // The hook may have started a machine that never joined.
                    if due {
                        if stop_unjoined(s, &request).await {
                            let why = "no worker joined before the join token expired";
                            end(app, &request, None, why, "autoscale.failed");
                        } else {
                            memory.retry_at.insert(request.id.clone(), now + RETRY_MS);
                        }
                    }
                } else {
                    fleet.pending_up += 1;
                    if due && !memory.sent.contains(&request.id) {
                        send_up(app, p, s, &request, memory, now).await;
                    }
                }
            }
            DOWN => {
                fleet.scaling_down = true;
                let id = request.node.clone().unwrap_or_default();
                let Some(node) = nodes.iter().find(|n| n.id == id) else {
                    end(
                        app,
                        &request,
                        None,
                        "the worker was removed",
                        "autoscale.done",
                    );
                    continue;
                };
                match app.db.retirement(&id)? {
                    Some(r) if r.ended_at.is_none() && r.state == retire_state::READY => {
                        if due && !remove_worker(app, s, &request, node).await {
                            memory.retry_at.insert(request.id.clone(), now + RETRY_MS);
                        }
                    }
                    Some(r) if r.ended_at.is_none() => {}
                    // From before retirements: retire it now.
                    _ => {
                        primary::start_retirement(
                            app,
                            &id,
                            retire_origin::AUTOSCALER,
                            true,
                            &request.reason,
                            &Origin::system(),
                        )
                        .map_err(|e| anyhow!(e.message))?;
                    }
                }
            }
            _ => {}
        }
    }

    // A retirement by the autoscaler whose request was not stored, after a
    // crash or a database error, gets one so its machine is stopped.
    let open_retirements = app.db.retirements(true)?;
    let downs: HashSet<String> = app
        .db
        .scale_requests(true, u32::MAX)?
        .into_iter()
        .filter(|r| r.action == DOWN)
        .filter_map(|r| r.node)
        .collect();
    for r in &open_retirements {
        if r.origin == retire_origin::AUTOSCALER && !downs.contains(&r.node) {
            let id = ids::new_id("scl")?;
            app.db.insert_scale_down(&id, &r.node, &r.reason, now)?;
            requested(app, &id, DOWN, Some(&r.node), &r.reason);
            fleet.scaling_down = true;
        }
    }
    let nodes = app.db.list_nodes()?;
    let counts = app.db.node_sandbox_counts()?;
    let retiring: HashSet<String> = open_retirements.into_iter().map(|r| r.node).collect();
    let workers: Vec<&NodeRow> = nodes
        .iter()
        .filter(|n| n.kind == node_kind::WORKER && !retiring.contains(&n.id))
        .collect();
    let active: Vec<&NodeRow> = workers
        .iter()
        .copied()
        .filter(|n| n.state == node_state::READY && !n.draining)
        .collect();
    fleet.load = current_load(app, p)?;
    fleet.active = active.len();
    fleet.total = workers.iter().filter(|n| may_run(n, now)).count() + fleet.pending_up;
    memory.trend.update(fleet.load, s, now);

    match decide(s, &fleet, &memory.trend, now) {
        Decision::Wait => {}
        Decision::Up(reason, n) => {
            memory.trend = Trend::default();
            for _ in 0..n {
                scale_up(app, p, s, &reason, memory, now).await?;
            }
        }
        Decision::Down(reason) => {
            memory.trend = Trend::default();
            let pick = active
                .iter()
                .min_by_key(|n| (counts.get(&n.id).copied().unwrap_or(0), -n.created_at));
            if let Some(node) = pick {
                scale_down(app, &node.id, &reason, now)?;
            }
        }
    }
    *scaler.status.lock().unwrap_or_else(|e| e.into_inner()) = memory.trend;
    Ok(())
}

/// Part of the slots or memory in use over the primary and its ready
/// workers that are not draining, from 0 to 1.
pub fn current_load(app: &App, p: &Primary) -> Result<Option<f64>> {
    let live: HashMap<String, Capacity> = p.capacities().into_iter().collect();
    let mut hosts = vec![local_capacity(app)];
    for node in app.db.list_nodes()? {
        if node.kind == node_kind::WORKER
            && node.state == node_state::READY
            && !node.draining
            && let Some(capacity) = live.get(&node.id)
        {
            hosts.push(capacity.clone());
        }
    }
    Ok(fleet_load(&hosts))
}

/// Workers by state, with draining and retiring ones counted apart.
fn worker_counts(app: &App) -> Result<BTreeMap<&'static str, usize>> {
    let retiring: HashSet<String> = app
        .db
        .retirements(true)?
        .into_iter()
        .map(|r| r.node)
        .collect();
    let mut counts: BTreeMap<&'static str, usize> =
        ["ready", "suspect", "down", "draining", "retiring"]
            .into_iter()
            .map(|k| (k, 0))
            .collect();
    for node in app.db.list_nodes()? {
        if node.kind != node_kind::WORKER {
            continue;
        }
        let key = if retiring.contains(&node.id) {
            "retiring"
        } else if node.draining {
            "draining"
        } else {
            match node.state.as_str() {
                node_state::READY => "ready",
                node_state::SUSPECT => "suspect",
                _ => "down",
            }
        };
        *counts.entry(key).or_default() += 1;
    }
    Ok(counts)
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

fn token_label(id: &str) -> String {
    format!("scale_up:{id}")
}

/// Makes a join token and asks the hook for a machine.
async fn scale_up(
    app: &App,
    p: &Primary,
    s: &Settings,
    reason: &str,
    memory: &mut Memory,
    now: i64,
) -> Result<()> {
    let id = ids::new_id("scl")?;
    let token = primary::new_join_token().map_err(|e| anyhow!(e.message))?;
    let expires_at = now + JOIN_TTL_MS;
    let sealed = app
        .secrets
        .sbox()
        .seal(&token_label(&id), token.as_bytes())?;
    app.db.insert_scale_up(
        &id,
        &ids::hash_key(&token),
        &sealed,
        reason,
        now,
        expires_at,
    )?;
    requested(app, &id, UP, None, reason);
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
    send_up(app, p, s, &request, memory, now).await;
    Ok(())
}

/// Asks the hook for the machine of an open scale-up, with its token.
async fn send_up(
    app: &App,
    p: &Primary,
    s: &Settings,
    request: &ScaleRequest,
    memory: &mut Memory,
    now: i64,
) {
    let token = app
        .db
        .scale_up_token(&request.id)
        .ok()
        .flatten()
        .and_then(|sealed| app.secrets.sbox().open(&token_label(&request.id), &sealed))
        .and_then(|plain| String::from_utf8(plain).ok());
    let Some(token) = token else {
        let why = "its join token is not stored; it was made by an older version";
        end(app, request, None, why, "autoscale.failed");
        return;
    };
    let ca_sha256 = match p.ca_sha256() {
        Ok(ca) => ca,
        Err(error) => {
            eprintln!("autoscale: {UP} {}: {error:#}", request.id);
            memory.retry_at.insert(request.id.clone(), now + RETRY_MS);
            return;
        }
    };
    let expires_at = request.expires_at.unwrap_or(now);
    let body = json!({
        "action": UP,
        "id": request.id,
        "reason": request.reason,
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
    match call(&s.hook, UP, &request.id, &body, &env).await {
        Ok(()) => {
            memory.sent.insert(request.id.clone());
            memory.retry_at.remove(&request.id);
        }
        Err(error) => {
            eprintln!("autoscale: {UP} {}: hook failed: {error}", request.id);
            app.sandboxes.hub.record(
                "autoscale.failed",
                &Origin::system(),
                None,
                None,
                json!({
                    "id": request.id,
                    "action": UP,
                    "outcome": format!(
                        "hook failed: {error}; sending the same request again in {} s",
                        RETRY_MS / 1000
                    ),
                }),
            );
            memory.retry_at.insert(request.id.clone(), now + RETRY_MS);
        }
    }
}

/// Retires `node`. Its machine is stopped on a later tick, once it is
/// empty.
fn scale_down(app: &AppState, node: &str, reason: &str, now: i64) -> Result<()> {
    let retired = primary::start_retirement(
        app,
        node,
        retire_origin::AUTOSCALER,
        true,
        reason,
        &Origin::system(),
    )
    .map_err(|e| anyhow!(e.message))?;
    if retired.is_none_or(|r| r.origin != retire_origin::AUTOSCALER) {
        return Ok(());
    }
    let id = ids::new_id("scl")?;
    app.db.insert_scale_down(&id, node, reason, now)?;
    requested(app, &id, DOWN, Some(node), reason);
    Ok(())
}

/// Asks the hook to stop the machine of a worker that is ready to
/// terminate, then removes the node. False if the hook failed.
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
    // The hook stopped the machine: its persistent sandboxes can start
    // elsewhere.
    let fenced = app
        .db
        .set_node_fenced(&node.id, "autoscaler", now_ms())
        .map_err(anyhow::Error::from)
        .and_then(|_| primary::cool_fenced(app, &node.id, "autoscaler", &Origin::system()));
    if let Err(error) = fenced {
        eprintln!("autoscale: fence {}: {error:#}", node.id);
    }
    end(app, request, Some(&node.id), "removed", "autoscale.done");
    true
}

/// Asks the hook to stop the machine started for a scale-up that no worker
/// joined: a `scale_down` with only `scale_up` set.
async fn stop_unjoined(s: &Settings, request: &ScaleRequest) -> bool {
    let body = json!({
        "action": DOWN,
        "id": request.id,
        "reason": "no worker joined for this scale_up",
        "node": { "id": null, "url": null, "scale_up": request.id },
    });
    let env = [
        ("SPAWNBOX_NODE_ID", String::new()),
        ("SPAWNBOX_NODE_URL", String::new()),
        ("SPAWNBOX_NODE_SCALE_UP", request.id.clone()),
    ];
    match call(&s.hook, DOWN, &request.id, &body, &env).await {
        Ok(()) => true,
        Err(error) => {
            eprintln!("autoscale: {DOWN} for {}: hook failed: {error}", request.id);
            false
        }
    }
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

/// `GET /v1/nodes/autoscale`: the fleet's load and workers, and the
/// autoscaler's settings and requests if it runs.
pub async fn status(State(app): State<AppState>) -> Result<Json<Value>, ApiError> {
    let p = primary::primary(&app)?;
    let requests: Vec<Value> = app
        .db
        .scale_requests(false, 20)?
        .iter()
        .map(request_view)
        .collect();
    let load = current_load(&app, p).map_err(ApiError::internal)?;
    let workers = worker_counts(&app).map_err(ApiError::internal)?;
    let Some(scaler) = p.autoscaler.get() else {
        return Ok(Json(json!({
            "enabled": false,
            "policy": "none",
            "observed_at": rfc3339_ms(now_ms()),
            "load": load,
            "workers": workers,
            "requests": requests,
        })));
    };
    let s = &scaler.settings;
    let trend = *scaler.status.lock().unwrap_or_else(|e| e.into_inner());
    Ok(Json(json!({
        "enabled": true,
        "policy": "hook",
        "observed_at": rfc3339_ms(now_ms()),
        "hook": match s.hook { Hook::Command(_) => "command", Hook::Webhook { .. } => "webhook" },
        "min_workers": s.min_workers,
        "max_workers": s.max_workers,
        "up_pct": (s.up_ratio * 100.0).round(),
        "up_after_s": s.up_after_ms / 1000,
        "down_pct": (s.down_ratio * 100.0).round(),
        "down_after_s": s.down_after_ms / 1000,
        "load": load,
        "workers": workers,
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
    fn a_worker_down_for_long_stops_counting() {
        let node = |state: &str, last_seen| NodeRow {
            id: "nod_a".into(),
            url: String::new(),
            state: state.into(),
            boot: None,
            seq: 0,
            report: None,
            last_seen,
            created_at: 0,
            removed_at: None,
            draining: false,
            kind: node_kind::WORKER.into(),
        };
        let now = GONE_AFTER_MS + 1;
        assert!(may_run(&node(node_state::READY, Some(0)), now));
        assert!(may_run(&node(node_state::DOWN, Some(now - 60_000)), now));
        assert!(!may_run(&node(node_state::DOWN, Some(0)), now));
    }

    #[test]
    fn adds_a_worker_only_when_load_stays_high() {
        let s = settings();
        assert_eq!(after(&s, &fleet(0.8, 1), 60_000), Decision::Wait);
        assert!(matches!(
            after(&s, &fleet(0.8, 1), 120_000),
            Decision::Up(_, 1)
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
        assert!(matches!(after(&s, &fleet(0.0, 0), 0), Decision::Up(r, 1) if r.contains("fewer")));
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
        assert!(matches!(after(&s, &refused, 0), Decision::Up(r, 1) if r.contains("no room")));
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
            pending_up: 1,
            total: 1,
            ..fleet(0.9, 1)
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
            Decision::Up(_, 1)
        ));
    }

    #[test]
    fn asks_for_all_missing_workers_at_once() {
        let s = Settings {
            min_workers: 20,
            max_workers: 25,
            ..settings()
        };
        assert!(matches!(after(&s, &fleet(0.0, 2), 0), Decision::Up(r, 18) if r.contains("fewer")));
        let asked = Fleet {
            pending_up: 15,
            total: 17,
            ..fleet(0.0, 2)
        };
        assert!(matches!(after(&s, &asked, 0), Decision::Up(_, 3)));
        let all_asked = Fleet {
            pending_up: 18,
            total: 20,
            ..fleet(0.9, 2)
        };
        assert_eq!(after(&s, &all_asked, 999_000), Decision::Wait);
        let near_max = Fleet {
            total: 23,
            ..fleet(0.0, 2)
        };
        assert!(matches!(after(&s, &near_max, 0), Decision::Up(_, 2)));
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
