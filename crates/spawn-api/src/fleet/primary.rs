//! The primary's side of the fleet: joins, heartbeats, config for workers,
//! placing new sandboxes and forwarding calls to the worker that runs them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use anyhow::Result;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as UrlPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use opentelemetry::KeyValue;
use rustls::ClientConfig;
use serde::Deserialize;
use serde_json::{Value, json};
use spawn_egress::Policy;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

use super::autoscale::Autoscaler;
use super::forward::{self, Failure};
use super::migrate::{self, MigrateInput, Moves};
use super::pki::{FleetCa, Identity, Peer};
use super::retire::{self, Busy, Retirer};
use super::volumes::Need;
use super::{
    Capacity, ColdStart, Config, ConfigRequest, DOWN_AFTER_MS, EgressCa, EventBatch, EventReply,
    Heartbeat, HeartbeatReply, JoinReply, JoinRequest, KeyCopy, NODE_HEADER, ROUTE_HEADER, Routes,
    SUSPECT_AFTER_MS, SecretPush, SyncReply, TemplateCopy, UsageBatch, check_node_url, hex,
};
use crate::db::{
    self, NodeRow, Retirement, VolumeRef, node_kind, node_state, retire_origin, retire_state, state,
};
use crate::events::Origin;
use crate::ids;
use crate::model::{
    ApiError, BASE_TEMPLATE, Code, CreateSandbox, ForkSandbox, TemplateSpec, rfc3339_ms,
};
use crate::runtime::{COLD_START_CLAIM, MAX_FORK, now_ms};
use crate::server::{App, AppState, parse};
use crate::tenancy::{Tenant, scoped};
use crate::traces::{self, Traced};

/// How much longer than a cold start may take the primary waits for a
/// worker's, and its claim lasts.
const COLD_START_SLACK: std::time::Duration = std::time::Duration::from_secs(15);
/// Most hosts a create is tried on.
const PLACE_TRIES: usize = 3;
/// Largest body on fleet calls: heartbeats list every sandbox.
const MAX_FLEET_BODY: usize = 64 * 1024 * 1024;
/// Largest create reply read back from a worker.
const MAX_CREATE_REPLY: usize = 1024 * 1024;
const TOKEN_TTL_S: u64 = 3600;
const MAX_TOKEN_TTL_S: u64 = 7 * 86_400;
/// A mirror this young may not be in a heartbeat yet.
const MIRROR_GRACE_MS: i64 = 30_000;
/// Template use is counted over this window to order joining hosts' builds.
const USES_WINDOW_MS: i64 = 7 * 86_400_000;

/// What the last heartbeat of a worker said.
struct Live {
    capacity: Capacity,
    config_version: u64,
    /// Creates sent to it and not answered yet.
    placing: usize,
}

pub struct Primary {
    ca: FleetCa,
    identity: Identity,
    clients: Mutex<HashMap<String, Arc<ClientConfig>>>,
    /// Changes whenever tenants, keys, secrets or templates do.
    version: AtomicU64,
    live: Mutex<HashMap<String, Live>>,
    pub moves: Moves,
    /// Held to read while a create uses volumes already on one host; held
    /// to write while volumes get a home or move.
    pub volume_lock: tokio::sync::RwLock<()>,
    /// The egress CA's certificate and key, which every host uses.
    egress_ca: EgressCa,
    /// Set when the primary runs with `--autoscale-hook`.
    pub autoscaler: OnceLock<Arc<Autoscaler>>,
    /// Calls that may still put a sandbox on each node.
    pub busy: Busy,
    pub retirer: Retirer,
}

impl Primary {
    pub fn new(
        dir: &Path,
        sbox: &crate::secretbox::SecretBox,
        egress_ca: EgressCa,
    ) -> Result<Self> {
        let ca = FleetCa::load_or_create(dir, sbox)?;
        let identity = ca.primary_identity(&dir.join("primary"))?;
        Ok(Self {
            ca,
            identity,
            clients: Mutex::default(),
            version: AtomicU64::new(u64::try_from(now_ms()).unwrap_or(1)),
            live: Mutex::default(),
            moves: Moves::default(),
            volume_lock: tokio::sync::RwLock::new(()),
            egress_ca,
            autoscaler: OnceLock::new(),
            busy: Busy::default(),
            retirer: Retirer::default(),
        })
    }

    /// What each worker last reported it has room for.
    pub fn capacities(&self) -> Vec<(String, Capacity)> {
        self.live()
            .iter()
            .map(|(id, l)| (id.clone(), l.capacity.clone()))
            .collect()
    }

    /// Whether `node` may not have the newest config.
    pub fn is_stale(&self, node: &str) -> bool {
        self.live()
            .get(node)
            .is_none_or(|l| l.config_version != self.version())
    }

    /// TLS for the fleet listener. A client certificate is optional, for
    /// joins; other calls check it.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        self.identity.server_config(None)
    }

    pub fn ca_sha256(&self) -> Result<String> {
        self.ca.fingerprint()
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    /// Records a change that workers must copy.
    pub fn bump(&self) {
        self.version.fetch_add(1, Ordering::SeqCst);
    }

    fn live(&self) -> MutexGuard<'_, HashMap<String, Live>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn client(&self, node: &str) -> Result<Arc<ClientConfig>, ApiError> {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tls) = clients.get(node) {
            return Ok(Arc::clone(tls));
        }
        let tls = Arc::new(
            self.identity
                .client_config(node)
                .map_err(ApiError::internal)?,
        );
        clients.insert(node.to_owned(), Arc::clone(&tls));
        Ok(tls)
    }

    fn forget(&self, node: &str) {
        self.live().remove(node);
        self.clients
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(node);
    }
}

pub(super) fn primary(app: &App) -> Result<&Arc<Primary>, ApiError> {
    match &app.role {
        super::Role::Primary(p) => Ok(p),
        _ => Err(ApiError::new(
            Code::Conflict,
            "this server is not a fleet primary; start it with --fleet-listen",
        )),
    }
}

/// The node a call comes from: named in its header, matching its
/// certificate, of `kind`, and not removed.
fn fleet_node(
    app: &App,
    peer: &Peer,
    headers: &HeaderMap,
    kind: &str,
) -> Result<NodeRow, ApiError> {
    let forbidden = || ApiError::new(Code::Forbidden, "not a node of this fleet");
    let id = headers
        .get(NODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|id| peer.is(id))
        .ok_or_else(forbidden)?;
    app.db
        .get_node(id)?
        .filter(|n| n.state != node_state::REMOVED && n.kind == kind)
        .ok_or_else(forbidden)
}

fn worker(app: &App, peer: &Peer, headers: &HeaderMap) -> Result<NodeRow, ApiError> {
    fleet_node(app, peer, headers, node_kind::WORKER)
}

/// The fleet listener. Workers and edges call its fleet routes; edges also
/// send clients' API and preview calls, which the fallback serves.
pub fn router(app: AppState) -> Router {
    let api = crate::server::router(Arc::clone(&app));
    let preview = crate::preview::router(Arc::clone(&app));
    let edge_app = Arc::clone(&app);
    Router::new()
        .route("/fleet/v1/join", post(join))
        .route("/fleet/v1/heartbeat", post(heartbeat))
        .route("/fleet/v1/config", post(config))
        .route("/fleet/v1/events", post(events))
        .route("/fleet/v1/usage", post(usage))
        .route("/fleet/v1/egress-ca", post(egress_ca))
        .route("/fleet/v1/routes", post(routes))
        .route_layer(DefaultBodyLimit::max(MAX_FLEET_BODY))
        .fallback(move |mut req: Request| {
            let (app, api, preview) = (Arc::clone(&edge_app), api.clone(), preview.clone());
            async move {
                let peer = req
                    .extensions()
                    .get::<ConnectInfo<Peer>>()
                    .map(|c| c.0.clone())
                    .unwrap_or_default();
                if req.uri().path().starts_with("/fleet/") {
                    return ApiError::new(Code::NotFound, "no such endpoint").into_response();
                }
                if let Err(error) = fleet_node(&app, &peer, req.headers(), node_kind::EDGE) {
                    return error.into_response();
                }
                let to_preview = req
                    .headers()
                    .get(ROUTE_HEADER)
                    .is_some_and(|v| v.as_bytes() == b"preview");
                req.headers_mut().remove(ROUTE_HEADER);
                req.headers_mut().remove(NODE_HEADER);
                let router = if to_preview { preview } else { api };
                match router.oneshot(req).await {
                    Ok(resp) => resp,
                    Err(never) => match never {},
                }
            }
        })
        .with_state(app)
}

/// `POST /fleet/v1/routes`: an edge's routing table. Also counts as the
/// edge's heartbeat.
async fn routes(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
) -> Result<Json<Routes>, ApiError> {
    let p = primary(&app)?;
    let edge = fleet_node(&app, &peer, &headers, node_kind::EDGE)?;
    if !app.db.edge_seen(&edge.id, now_ms())? {
        return Err(ApiError::new(Code::Forbidden, "this edge was removed"));
    }
    if edge.state == node_state::DOWN {
        eprintln!("edge {} is back", edge.id);
        app.sandboxes.hub.record(
            "node.up",
            &Origin::system(),
            None,
            None,
            json!({ "node": edge.id }),
        );
    }
    let nodes = app
        .db
        .list_nodes()?
        .into_iter()
        .filter(|n| {
            n.kind == node_kind::WORKER
                && matches!(n.state.as_str(), node_state::READY | node_state::SUSPECT)
        })
        .map(|n| (n.id, n.url))
        .collect();
    let sandboxes = app
        .db
        .edge_routes()?
        .into_iter()
        .filter(|(id, _)| !p.moves.is_moving(id))
        .collect();
    Ok(Json(Routes { nodes, sandboxes }))
}

async fn join(State(app): State<AppState>, body: Bytes) -> Result<Json<JoinReply>, ApiError> {
    let p = primary(&app)?;
    let req: JoinRequest = parse(&body)?;
    let edge = match req.kind.as_str() {
        node_kind::WORKER => false,
        node_kind::EDGE => true,
        _ => return Err(ApiError::invalid("kind must be worker or edge")),
    };
    if !edge {
        check_node_url(&req.url).map_err(|e| ApiError::invalid(format!("url {e}")))?;
    }
    let id = ids::new_id("nod").map_err(ApiError::internal)?;
    let cert_pem =
        p.ca.sign(&req.csr_pem, &id)
            .map_err(|e| ApiError::invalid(format!("{e:#}")))?;
    let mut row = NodeRow {
        id: id.clone(),
        url: req.url.clone(),
        state: node_state::SUSPECT.into(),
        boot: None,
        seq: 0,
        report: None,
        last_seen: None,
        created_at: now_ms(),
        removed_at: None,
        draining: false,
        kind: req.kind.clone(),
    };
    if edge {
        row.url = String::new();
    }
    if !app.db.join_node(&ids::hash_key(&req.token), &row)? {
        return Err(ApiError::new(
            Code::Unauthorized,
            "the join token is unknown, used or expired",
        ));
    }
    eprintln!("{} {id} joined from {}", req.kind, row.url);
    if edge {
        // Workers learn of the new edge with their next config copy.
        p.bump();
    }
    app.sandboxes.hub.record(
        "node.joined",
        &Origin::system(),
        None,
        None,
        json!({ "node": id, "url": row.url, "kind": req.kind }),
    );
    Ok(Json(JoinReply {
        node: id,
        cert_pem,
        ca_pem: p.ca.cert_pem().to_owned(),
    }))
}

async fn heartbeat(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<HeartbeatReply>, ApiError> {
    let p = primary(&app)?;
    let node = worker(&app, &peer, &headers)?;
    let hb: Heartbeat = parse(&body)?;
    check_node_url(&hb.url).map_err(|e| ApiError::invalid(format!("url {e}")))?;
    let live_copies = || {
        hb.sandboxes
            .iter()
            .filter(|s| !matches!(s.state.as_str(), state::DELETED | state::FAILED))
    };
    // Persistent copies are checked by generation; releasing one would
    // delete its volumes.
    let copies: Vec<(&str, i64)> = live_copies()
        .filter(|s| s.persistent)
        .map(|s| (s.id.as_str(), s.generation))
        .collect();
    let reply = |app: &App| -> Result<Json<HeartbeatReply>, ApiError> {
        let reported: Vec<&str> = live_copies()
            .filter(|s| !s.persistent)
            .map(|s| s.id.as_str())
            .filter(|id| !p.moves.is_moving(id))
            .collect();
        Ok(Json(HeartbeatReply {
            config_version: p.version(),
            events_after: app.db.remote_event_cursor(&node.id)?,
            release: app.db.misplaced(&node.id, &reported)?,
            stale: app.db.stale_copies(&node.id, &copies)?,
        }))
    };
    // Calls may arrive out of order; an older report must not undo a newer.
    if node.boot.as_deref() == Some(hb.boot.as_str()) && hb.seq <= node.seq {
        return reply(&app);
    }
    let now = now_ms();
    let stale: HashSet<String> = app
        .db
        .stale_copies(&node.id, &copies)?
        .into_iter()
        .collect();
    for sandbox in &hb.sandboxes {
        if stale.contains(&sandbox.id) {
            continue;
        }
        if app.db.put_mirror(&node.id, sandbox, now)?
            && sandbox.persistent
            && sandbox.state == state::COLD
        {
            cold_event(
                &app,
                &sandbox.tenant,
                &sandbox.id,
                "node_reported",
                &node.id,
            );
        }
    }
    let states: Vec<(&str, i64, &str)> = hb
        .sandboxes
        .iter()
        .filter(|s| s.persistent && !stale.contains(&s.id))
        .map(|s| (s.id.as_str(), s.generation, s.state.as_str()))
        .collect();
    for (id, tenant) in app.db.settle_claims(&node.id, &states, now)? {
        cold_event(&app, &tenant, &id, "start_unfinished", &node.id);
    }
    let mut keep: HashSet<String> = hb.sandboxes.iter().map(|s| s.id.clone()).collect();
    // A report from before a move must not count a moved sandbox as lost.
    keep.extend(p.moves.recent(now));
    for (id, tenant) in app
        .db
        .end_mirrors(&node.id, &keep, now - MIRROR_GRACE_MS, now)?
    {
        app.sandboxes.hub.record(
            "sandbox.lost",
            &Origin::system(),
            Some(&tenant),
            Some(&id),
            json!({ "reason": "gone from node", "node": node.id }),
        );
    }
    let keep: HashSet<String> = keep.difference(&stale).cloned().collect();
    for (id, tenant) in app
        .db
        .cool_missing(&node.id, &keep, now - MIRROR_GRACE_MS)?
    {
        cold_event(&app, &tenant, &id, "gone_from_node", &node.id);
    }
    let report = json!({
        "capacity": hb.capacity,
        "config_version": hb.config_version,
        "self_fence": hb.self_fence,
        "fence_after_s": hb.fence_after_s,
    });
    let seen = NodeRow {
        url: hb.url.clone(),
        boot: Some(hb.boot.clone()),
        seq: hb.seq,
        report: Some(report.to_string()),
        last_seen: Some(now),
        ..node.clone()
    };
    if !app.db.node_seen(&seen)? {
        return Err(ApiError::new(Code::Forbidden, "this node was removed"));
    }
    if node.state == node_state::DOWN {
        eprintln!("node {} is back", node.id);
        app.sandboxes.hub.record(
            "node.up",
            &Origin::system(),
            None,
            None,
            json!({ "node": node.id }),
        );
    }
    let mut live = p.live();
    let placing = live.get(&node.id).map_or(0, |l| l.placing);
    live.insert(
        node.id.clone(),
        Live {
            capacity: hb.capacity,
            config_version: hb.config_version,
            placing,
        },
    );
    drop(live);
    reply(&app)
}

async fn config(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Config>, ApiError> {
    let p = primary(&app)?;
    worker(&app, &peer, &headers)?;
    let req: ConfigRequest = parse(&body)?;
    // Read first: a change while copying gives a newer version, so the
    // worker asks again.
    let version = p.version();
    let keys = app
        .db
        .list_key_hashes()?
        .into_iter()
        .map(|(key, hash)| KeyCopy {
            key,
            hash: hex(&hash),
        })
        .collect();
    let names: Vec<_> = app
        .db
        .list_templates()?
        .into_iter()
        .filter(|t| t.name != BASE_TEMPLATE)
        .collect();
    let mut uses: HashMap<String, u64> = HashMap::new();
    let week_ago = now_ms() - USES_WINDOW_MS;
    for (tenant, name, count) in app.db.template_uses(week_ago)? {
        let own = scoped(Some(&tenant), &name);
        let key = if names.iter().any(|t| t.name == own) {
            own
        } else {
            name
        };
        *uses.entry(key).or_default() += count;
    }
    let templates = names
        .into_iter()
        .map(|t| TemplateCopy {
            uses: uses.get(&t.name).copied().unwrap_or(0),
            key: t.name,
            spec: t.spec,
        })
        .collect();
    Ok(Json(Config {
        version,
        tenants: app.db.list_tenants()?,
        keys,
        templates,
        secrets: app.secrets.export(&req.held)?,
        session_key: app.sessions.key_hex(),
        edges: app.db.edge_ids()?,
    }))
}

async fn egress_ca(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
) -> Result<Json<EgressCa>, ApiError> {
    let p = primary(&app)?;
    worker(&app, &peer, &headers)?;
    Ok(Json(p.egress_ca.clone()))
}

async fn events(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<EventReply>, ApiError> {
    let node = worker(&app, &peer, &headers)?;
    let batch: EventBatch = parse(&body)?;
    let events_after = app.sandboxes.hub.ingest(&node.id, batch.events).await?;
    Ok(Json(EventReply { events_after }))
}

async fn usage(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<Peer>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let node = worker(&app, &peer, &headers)?;
    let batch: UsageBatch = parse(&body)?;
    app.db.merge_node_usage(&node.id, &batch.rows)?;
    Ok(Json(json!({})))
}

/// Marks nodes suspect, then down, when their heartbeats stop, and makes
/// cold the persistent sandboxes of lost nodes once their copies are
/// known to be gone. `margin` is added to a worker's fence time.
pub fn watch(app: AppState, margin: std::time::Duration) -> tokio::task::JoinHandle<()> {
    let margin_ms = i64::try_from(margin.as_millis()).unwrap_or(i64::MAX);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(super::HEARTBEAT_EVERY).await;
            if let Err(error) = check_nodes(&app) {
                eprintln!("fleet: check nodes: {error:#}");
            }
            if let Err(error) = check_fenced(&app, margin_ms) {
                eprintln!("fleet: check fenced nodes: {error:#}");
            }
        }
    })
}

/// Records that a persistent sandbox is cold again.
fn cold_event(app: &App, tenant: &str, id: &str, reason: &str, node: &str) {
    eprintln!("{id} is cold: {reason} on {node}");
    app.sandboxes.hub.record(
        "sandbox.cold",
        &Origin::system(),
        Some(tenant),
        Some(id),
        json!({ "reason": reason, "node": node }),
    );
}

/// What proves a lost node's copies are gone: an operator or the
/// autoscaler said so, or the node fences itself and has not been heard
/// from for its fence time and `margin_ms`. Being down proves nothing.
pub fn fence_proof(
    fenced_by: Option<&str>,
    report: Option<&str>,
    last_seen: i64,
    margin_ms: i64,
    now: i64,
) -> Option<String> {
    if let Some(by) = fenced_by {
        return Some(by.to_owned());
    }
    let report: Value = serde_json::from_str(report?).ok()?;
    let fence_after_s = report.get("fence_after_s")?.as_i64()?;
    let fences = report.get("self_fence")?.as_bool()? && fence_after_s > 0;
    (fences && now >= last_seen + fence_after_s * 1000 + margin_ms).then(|| "self_fence".into())
}

/// Makes cold the persistent sandboxes of a node whose copies are gone.
pub fn cool_fenced(app: &App, node: &str, proof: &str, origin: &Origin) -> Result<usize> {
    let cooled = app.db.cool_node(node)?;
    for (id, tenant) in &cooled {
        eprintln!("{id} is cold: {node} is fenced ({proof})");
        crate::metrics::inc(
            "spawnbox_fenced_cold_total",
            vec![("reason", proof.to_owned())],
        );
        app.sandboxes.hub.record(
            "sandbox.cold",
            origin,
            Some(tenant),
            Some(id),
            json!({ "reason": "fenced", "node": node, "proof": proof }),
        );
    }
    Ok(cooled.len())
}

fn check_fenced(app: &App, margin_ms: i64) -> Result<()> {
    let now = now_ms();
    for (node, fenced_by) in app.db.unfenced_nodes()? {
        let last_seen = node.last_seen.unwrap_or(node.created_at);
        let Some(proof) = fence_proof(
            fenced_by.as_deref(),
            node.report.as_deref(),
            last_seen,
            margin_ms,
            now,
        ) else {
            continue;
        };
        if fenced_by.is_none() {
            app.sandboxes.hub.record(
                "node.fenced",
                &Origin::system(),
                None,
                None,
                json!({ "node": node.id, "reason": proof }),
            );
        }
        cool_fenced(app, &node.id, &proof, &Origin::system())?;
    }
    Ok(())
}

fn check_nodes(app: &App) -> Result<()> {
    let now = now_ms();
    for node in app.db.list_nodes()? {
        let age = now - node.last_seen.unwrap_or(node.created_at);
        if age > DOWN_AFTER_MS && node.state != node_state::DOWN {
            app.db.set_node_state(&node.id, node_state::DOWN)?;
            eprintln!(
                "node {} is down: no heartbeat for {} s",
                node.id,
                age / 1000
            );
            app.sandboxes.hub.record(
                "node.down",
                &Origin::system(),
                None,
                None,
                json!({ "node": node.id }),
            );
        } else if age > SUSPECT_AFTER_MS && node.state == node_state::READY {
            app.db.set_node_state(&node.id, node_state::SUSPECT)?;
        }
    }
    Ok(())
}

/// A host a new sandbox may go to. `None` is this one.
struct Candidate {
    node: Option<NodeRow>,
    backend: String,
    score: f64,
    vcpus: u8,
    memory_mib: u32,
}

/// Hosts that can take a sandbox of template `key`, best first.
fn candidates(
    app: &App,
    p: &Primary,
    tenant: &Tenant,
    key: &str,
    network: &str,
    need: Option<&Need>,
) -> Vec<Candidate> {
    let wanted = (key != BASE_TEMPLATE)
        .then(|| app.db.get_template(key).ok().flatten())
        .flatten()
        .map(|t| super::build_hash(&t.spec));
    let spread = app.db.tenant_spread(&tenant.id).unwrap_or_default();
    let mut found: Vec<(Option<NodeRow>, Capacity, usize)> =
        vec![(None, super::local_capacity(app), 0)];
    let nodes: HashMap<String, NodeRow> = app
        .db
        .list_nodes()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n.state == node_state::READY && !n.draining)
        .map(|n| (n.id.clone(), n))
        .collect();
    for (id, live) in p.live().iter() {
        if let Some(node) = nodes.get(id) {
            found.push((Some(node.clone()), live.capacity.clone(), live.placing));
        }
    }
    let most_memory = found
        .iter()
        .map(|(_, c, _)| c.memory_available_mib)
        .max()
        .unwrap_or(0)
        .max(1);
    let mut out: Vec<Candidate> = found
        .into_iter()
        .filter_map(|(node, capacity, placing)| {
            if !tenant.isolation.allows(&capacity.backend) {
                return None;
            }
            let id = node.as_ref().map(|n| n.id.as_str());
            if let Some(need) = need
                && (need
                    .backend
                    .as_ref()
                    .is_some_and(|b| *b != capacity.backend)
                    || (need.is_simple() && !need.fits(id, &capacity.backend)))
            {
                return None;
            }
            #[expect(clippy::cast_precision_loss, reason = "a score")]
            let near = need.map_or(0.0, |need| 1000.0 * need.gib_on(id) as f64);
            let template = capacity.template(key)?;
            let current = node.is_none()
                || key == BASE_TEMPLATE
                || wanted.as_deref() == Some(template.spec_sha256.as_str());
            let warm = capacity.warm_ready(key, network) > 0;
            let room = capacity.free_slots.saturating_sub(placing) > 0;
            // A warm VM already holds its memory, but it is not reserved yet.
            let asked = u64::from(template.memory_mib);
            let memory = capacity.memory_unreserved_mib() >= asked
                && (warm || capacity.memory_available_mib >= asked);
            if !(current && (warm || room) && memory) {
                return None;
            }
            let here = spread.get(&node.as_ref().map(|n| n.id.clone())).copied();
            #[expect(clippy::cast_precision_loss, reason = "a score")]
            let score = near
                + if warm { 100.0 } else { 0.0 }
                + 30.0 * capacity.memory_available_mib as f64 / most_memory as f64
                + 10.0 / (1.0 + f64::from(here.unwrap_or(0)));
            Some(Candidate {
                node,
                backend: capacity.backend.clone(),
                score,
                vcpus: template.vcpus,
                memory_mib: template.memory_mib,
            })
        })
        .collect();
    out.sort_by(|a, b| b.score.total_cmp(&a.score));
    out.truncate(PLACE_TRIES);
    out
}

/// What a worker's create reply says, to keep a copy of the sandbox here.
#[derive(Deserialize)]
struct Created {
    id: String,
    tenant: String,
    state: String,
    template: String,
    build: Option<String>,
    labels: BTreeMap<String, String>,
    secrets: Vec<String>,
    egress: Policy,
    created_at: String,
    expires_at: Option<String>,
    idle_pause_s: u64,
}

fn unix_ms(text: &str) -> Option<i64> {
    let t = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    i64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok()
}

impl Created {
    fn mirror(self, node: &str, vcpus: u8, memory_mib: u32) -> Option<db::Sandbox> {
        let created_at = unix_ms(&self.created_at)?;
        Some(db::Sandbox {
            id: self.id,
            tenant: self.tenant,
            state: self.state,
            template: self.template,
            build: self.build,
            labels: self.labels,
            secrets: self.secrets,
            egress: self.egress,
            created_at,
            expires_at: self
                .expires_at
                .as_deref()
                .and_then(unix_ms)
                .unwrap_or(created_at),
            idle_pause_s: self.idle_pause_s,
            paused_at: None,
            node: Some(node.to_owned()),
            vcpus: u32::from(vcpus),
            memory_mib,
            volumes: Vec::new(),
            persistent: false,
            generation: 1,
            cold_starts: 0,
            last_cold_start_at: None,
        })
    }
}

/// Starts cold persistent sandbox `id` on a worker with room, under a
/// claim for the next generation, or leaves it for the call to start it
/// here: then its volumes are gathered here first. `here` keeps it on this
/// host. Fails with `volume_unavailable` while a volume's only copy is on
/// a host that is not ready.
pub async fn wake_cold(app: &App, id: &str, here: bool) -> Result<(), ApiError> {
    let p = primary(app)?;
    let gate = app.sandboxes.waking_gate(id);
    let _waking = gate.lock().await;
    let Some(sandbox) = app.db.get_sandbox(id)? else {
        return Ok(());
    };
    if !sandbox.persistent || sandbox.node.is_some() || sandbox.state != state::COLD {
        return Ok(());
    }
    let Some(start) = app.db.get_start_record(id)? else {
        return Ok(());
    };
    let Some(tenant) = app.db.get_tenant(&start.tenant)? else {
        return Ok(());
    };
    let mut need = None;
    let mut _volumes = None;
    if !start.volumes.is_empty() {
        _volumes = Some(p.volume_lock.write().await);
        let now = Need::of(app, &start.volumes)?;
        for row in &now.rows {
            if let Some(home) = &row.node
                && !app
                    .db
                    .get_node(home)?
                    .is_some_and(|n| n.state == node_state::READY)
            {
                return Err(crate::volumes::volume_unavailable(&row.name));
            }
        }
        need = Some(now);
    }
    let wanted = super::build_hash(&start.spec);
    let worker = if here {
        None
    } else {
        app.templates
            .key(Some(&tenant.id), &start.template)
            .ok()
            .and_then(|key| {
                let network = app.sandboxes.network_mode(&tenant, Some(&start.egress));
                let same_build = |node: &NodeRow| {
                    p.live()
                        .get(&node.id)
                        .and_then(|l| l.capacity.template(&key).cloned())
                        .is_some_and(|t| t.spec_sha256 == wanted)
                };
                candidates(app, p, &tenant, &key, network, need.as_ref())
                    .into_iter()
                    .find(|c| c.node.as_ref().is_none_or(same_build))
            })
            .and_then(|c| c.node)
    };
    if let Some(node) = worker {
        match start_on(app, p, &node, &tenant, sandbox, &start, need.as_ref()).await {
            Ok(()) => return Ok(()),
            // The call never reached it: start it here instead.
            Err(Failure::Unreachable(error)) => {
                eprintln!("cold start {id} on node {}: {error:#}", node.id);
            }
            Err(Failure::Broken(error)) => {
                return Err(ApiError::new(
                    Code::NodeUnreachable,
                    format!("node {}: {error:#}", node.id),
                ));
            }
        }
    }
    if let Some(need) = &need {
        need.gather(app, p, None).await?;
    }
    Ok(())
}

/// Starts cold sandbox `sandbox` on `node` at the next generation. Its
/// claim is given up only when the call surely did not start it there;
/// otherwise the node's heartbeats settle it.
async fn start_on(
    app: &App,
    p: &Primary,
    node: &NodeRow,
    tenant: &Tenant,
    sandbox: db::Sandbox,
    start: &db::StartRecord,
    need: Option<&Need>,
) -> Result<(), Failure> {
    let fail = |e: ApiError| Failure::Unreachable(anyhow::anyhow!(e.message));
    let id = sandbox.id.clone();
    let _reservation = app
        .sandboxes
        .reserve(
            &tenant.id,
            &tenant.quotas,
            u8::try_from(start.vcpus).unwrap_or(u8::MAX),
            start.memory_mib,
        )
        .map_err(fail)?;
    // Nothing started there before the claim.
    let before = |f: Failure| Failure::Unreachable(f.error());
    let tls = p.client(&node.id).map_err(fail)?;
    if p.is_stale(&node.id) {
        let _: SyncReply = forward::call(
            Arc::clone(&tls),
            &node.url,
            "/fleet/v1/sync",
            None,
            &json!({}),
        )
        .await
        .map_err(before)?;
    }
    if !start.secrets.is_empty() {
        let keys: Vec<String> = app
            .secrets
            .specs(Some(&tenant.id), &start.secrets)
            .map_err(fail)?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        let push = SecretPush {
            secrets: app.secrets.export(&keys).map_err(fail)?,
        };
        let _: Value = forward::call(
            Arc::clone(&tls),
            &node.url,
            "/fleet/v1/secrets",
            None,
            &push,
        )
        .await
        .map_err(before)?;
    }
    if let Some(need) = need {
        need.gather(app, p, Some(node)).await.map_err(fail)?;
        super::volumes::push(app, p, node, &start.volumes)
            .await
            .map_err(fail)?;
    }
    let env = app
        .secrets
        .sbox()
        .open_sandbox_env(&start.tenant, &id, &start.env)
        .ok_or_else(|| fail(ApiError::internal("the start record's env cannot be read")))?;
    let claim = ids::base32(&ids::random::<10>().map_err(|e| fail(ApiError::internal(e)))?);
    let wait = COLD_START_CLAIM + COLD_START_SLACK;
    let deadline = now_ms() + i64::try_from((wait + COLD_START_SLACK).as_millis()).unwrap_or(0);
    let Some(generation) = app
        .db
        .claim_cold(&id, Some(&node.id), &claim, deadline)
        .map_err(|e| fail(e.into()))?
    else {
        return Ok(());
    };
    let body = ColdStart {
        sandbox,
        start: db::StartRecord {
            env: Vec::new(),
            ..start.clone()
        },
        env,
        generation,
    };
    let busy = p.busy.hold(&node.id);
    let sent = tokio::time::timeout(
        wait,
        forward::call::<_, Value>(tls, &node.url, "/fleet/v1/cold-start", None, &body),
    )
    .await
    .unwrap_or_else(|_| Err(Failure::Broken(anyhow::anyhow!("the start took too long"))));
    drop(busy);
    match sent {
        Ok(_) => {
            let now = now_ms();
            if app
                .db
                .finish_cold_start(&id, Some(&node.id), generation, &claim, now)
                .map_err(|e| fail(e.into()))?
            {
                eprintln!(
                    "{id} started on node {} at generation {generation}",
                    node.id
                );
            }
            Ok(())
        }
        Err(Failure::Unreachable(error)) => {
            if let Err(e) = app
                .db
                .abandon_claim(&id, Some(&node.id), generation, &claim)
            {
                eprintln!("record {id} as cold: {e}");
            }
            Err(Failure::Unreachable(error))
        }
        Err(broken) => Err(broken),
    }
}

/// Creates a sandbox on this host or a worker.
pub async fn create(
    app: &AppState,
    tenant: Tenant,
    req: CreateSandbox,
    headers: &HeaderMap,
    body: Bytes,
    mut origin: Origin,
) -> Result<Response, ApiError> {
    let span = traces::start(
        "sandbox.place",
        &mut origin,
        vec![KeyValue::new("spawnbox.tenant", tenant.id.clone())],
    );
    let placed = place_any(app, tenant, req, headers, body, origin, &span).await;
    if let Err(error) = &placed {
        span.fail(error.message.clone());
        if error.code == Code::NoCapacity {
            crate::metrics::inc(
                "spawnbox_fleet_create_refused_total",
                vec![("reason", "no_capacity".into())],
            );
            if let Ok(p) = primary(app)
                && let Some(scaler) = p.autoscaler.get()
            {
                scaler.refused();
            }
        }
    }
    placed
}

async fn place_any(
    app: &AppState,
    tenant: Tenant,
    req: CreateSandbox,
    headers: &HeaderMap,
    body: Bytes,
    origin: Origin,
    span: &Traced,
) -> Result<Response, ApiError> {
    let p = primary(app)?;
    // The worker's create span is a child of this one.
    let mut headers = headers.clone();
    if let Some(traceparent) = span
        .traceparent()
        .and_then(|t| HeaderValue::from_str(&t).ok())
    {
        headers.insert("traceparent", traceparent);
    }
    let template = req.template.as_deref().unwrap_or(BASE_TEMPLATE);
    let key = app.templates.key(Some(&tenant.id), template)?;
    let network = app.sandboxes.network_mode(&tenant, req.egress.as_ref());
    let refs = app.volumes.resolve(&tenant.id, &req.volumes)?;
    let mut need = if refs.is_empty() {
        None
    } else {
        Some(Need::of(app, &refs)?)
    };
    let mut _volumes = None;
    if let Some(first) = &need {
        if first.is_simple() {
            let guard = p.volume_lock.read().await;
            // Read again under the lock: a copy may have moved them.
            let now = Need::of(app, &refs)?;
            if now.is_simple() {
                _volumes = Some(VolumeGuard::Read(guard));
                need = Some(now);
            } else {
                drop(guard);
            }
        }
        if _volumes.is_none() {
            _volumes = Some(VolumeGuard::Write(p.volume_lock.write().await));
            need = Some(Need::of(app, &refs)?);
        }
    }
    let mut candidates = candidates(app, p, &tenant, &key, network, need.as_ref());
    if req.persistent {
        // Persistent sandboxes stay on this host: they cannot move yet.
        candidates.retain(|c| c.node.is_none());
        if candidates.is_empty() {
            if let Some(need) = &need {
                need.gather(app, p, None).await?;
            }
            return crate::server::create_here(Arc::clone(app), tenant, req, origin).await;
        }
    }
    let mut local = Some(req);
    let mut last = None;
    for candidate in candidates {
        if let Some(need) = &need {
            need.gather(app, p, candidate.node.as_ref()).await?;
        }
        let Some(node) = candidate.node else {
            let Some(req) = local.take() else { continue };
            let (app, tenant) = (Arc::clone(app), tenant.clone());
            let origin = origin.clone();
            return crate::server::create_here(app, tenant, req, origin).await;
        };
        let reservation = app.sandboxes.reserve(
            &tenant.id,
            &tenant.quotas,
            candidate.vcpus,
            candidate.memory_mib,
        )?;
        let trying = Instant::now();
        let placed = place(app, p, &node, &tenant, &headers, body.clone(), &refs).await;
        span.step_with(
            "node",
            trying,
            Instant::now(),
            vec![KeyValue::new("spawnbox.node", node.id.clone())],
        );
        match placed {
            Ok(Placed::Done(resp, maybe)) => {
                drop(reservation);
                // A lost reply may still have made the sandbox and the file.
                if resp.status().is_success() || maybe {
                    for volume in need.iter().flat_map(|n| &n.unplaced) {
                        app.db
                            .set_volume_home(volume, Some(&node.id), &candidate.backend)?;
                    }
                }
                return Ok(resp);
            }
            Ok(Placed::Full(why)) | Err(why) => {
                eprintln!("create on node {}: {why:#}", node.id);
                last = Some(why);
            }
        }
    }
    if let Some(req) = local {
        // No host has room for sure; this one says why.
        let fits_here = need
            .as_ref()
            .is_none_or(|n| n.fits(None, app.volumes.backend().name()));
        if last.is_none() && fits_here {
            return crate::server::create_here(Arc::clone(app), tenant, req, origin).await;
        }
    }
    Err(ApiError::new(
        Code::NoCapacity,
        "no host in the fleet has room for this sandbox",
    ))
}

#[expect(dead_code, reason = "held only to keep the lock")]
enum VolumeGuard<'a> {
    Read(tokio::sync::RwLockReadGuard<'a, ()>),
    Write(tokio::sync::RwLockWriteGuard<'a, ()>),
}

enum Placed {
    /// `true`: the reply was lost, so the sandbox may exist there.
    Done(Response, bool),
    /// The node did not create it; another may.
    Full(anyhow::Error),
}

async fn place(
    app: &App,
    p: &Primary,
    node: &NodeRow,
    tenant: &Tenant,
    headers: &HeaderMap,
    body: Bytes,
    volumes: &[VolumeRef],
) -> Result<Placed, anyhow::Error> {
    let tls = p.client(&node.id).map_err(|e| anyhow::anyhow!(e.message))?;
    let stale = p
        .live()
        .get(&node.id)
        .is_none_or(|l| l.config_version != p.version());
    if stale {
        let synced: Result<SyncReply, _> = forward::call(
            Arc::clone(&tls),
            &node.url,
            "/fleet/v1/sync",
            None,
            &json!({}),
        )
        .await;
        if let Err(failure) = synced {
            return Ok(Placed::Full(failure.error()));
        }
    }
    let req: CreateSandbox = serde_json::from_slice(&body).unwrap_or_default();
    if !req.secrets.is_empty() {
        let keys: Vec<String> = app
            .secrets
            .specs(Some(&tenant.id), &req.secrets)
            .map_err(|e| anyhow::anyhow!(e.message))?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        let push = SecretPush {
            secrets: app
                .secrets
                .export(&keys)
                .map_err(|e| anyhow::anyhow!(e.message))?,
        };
        let pushed: Result<Value, _> = forward::call(
            Arc::clone(&tls),
            &node.url,
            "/fleet/v1/secrets",
            None,
            &push,
        )
        .await;
        if let Err(failure) = pushed {
            return Ok(Placed::Full(failure.error()));
        }
    }
    if let Err(error) = super::volumes::push(app, p, node, volumes).await {
        return Ok(Placed::Full(anyhow::anyhow!(error.message)));
    }
    let mut out = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/v1/sandboxes");
    for (name, value) in headers {
        if name != header::HOST && name != ROUTE_HEADER && name != header::CONTENT_LENGTH {
            out = out.header(name, value);
        }
    }
    let out = out
        .header(header::HOST, host_of(&node.url))
        .body(Body::from(body))?;
    if let Some(live) = p.live().get_mut(&node.id) {
        live.placing += 1;
    }
    let busy = p.busy.hold(&node.id);
    let sent = forward::send(tls, &node.url, out).await;
    if let Some(live) = p.live().get_mut(&node.id) {
        live.placing = live.placing.saturating_sub(1);
    }
    let resp = match sent {
        Ok(resp) => resp,
        Err(Failure::Unreachable(e)) => return Ok(Placed::Full(e)),
        Err(Failure::Broken(e)) => {
            // It may exist there; the next heartbeat brings its copy.
            return Ok(Placed::Done(
                ApiError::new(Code::Internal, format!("node {}: {e:#}", node.id))
                    .into_bad_gateway(),
                true,
            ));
        }
    };
    let status = resp.status();
    if status == StatusCode::SERVICE_UNAVAILABLE {
        return Ok(Placed::Full(anyhow::anyhow!("node {} is full", node.id)));
    }
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_CREATE_REPLY).await?;
    if status.is_success() {
        let live = p.live();
        let template = live.get(&node.id).and_then(|l| {
            let created: Created = serde_json::from_slice(&bytes).ok()?;
            let key = app
                .templates
                .key(Some(&tenant.id), &created.template)
                .ok()?;
            let t = l.capacity.template(&key)?;
            Some((created, t.vcpus, t.memory_mib))
        });
        drop(live);
        if let Some((created, vcpus, memory_mib)) = template
            && let Some(mut mirror) = created.mirror(&node.id, vcpus, memory_mib)
        {
            mirror.volumes = volumes.to_vec();
            app.db.put_mirror(&node.id, &mirror, now_ms())?;
        }
    }
    drop(busy);
    Ok(Placed::Done(
        Response::from_parts(parts, Body::from(bytes)),
        false,
    ))
}

fn host_of(url: &str) -> HeaderValue {
    HeaderValue::from_str(url.trim_start_matches("https://"))
        .unwrap_or_else(|_| HeaderValue::from_static("spawnbox-node"))
}

/// Waits while sandbox `id` moves between hosts, so the call goes to
/// where it ends up.
pub async fn wait_for_move(app: &App, id: &str) {
    if let super::Role::Primary(p) = &app.role {
        p.moves.wait(id).await;
    }
}

/// The worker that runs sandbox `id`, if it is not this host.
pub fn node_of(app: &App, id: &str) -> Option<String> {
    if !matches!(app.role, super::Role::Primary(_)) || !ids::is_valid_id("sbx", id) {
        return None;
    }
    remote_node(app.db.get_sandbox(id).ok().flatten()?)
}

/// The worker that runs `sandbox`, if it has not ended. Calls for an ended
/// one are answered here, as its node may be gone, and so are calls for a
/// persistent one that is cold or starting: this host places its start.
pub fn remote_node(sandbox: db::Sandbox) -> Option<String> {
    let ended = matches!(sandbox.state.as_str(), state::DELETED | state::FAILED);
    let waking =
        sandbox.persistent && matches!(sandbox.state.as_str(), state::COLD | state::STARTING);
    sandbox.node.filter(|_| !ended && !waking)
}

/// Sends a call for a worker's sandbox to that worker. `route` tells the
/// worker which of its routers takes it.
pub async fn forward(
    app: &App,
    node: &str,
    mut req: Request,
    route: Option<&'static str>,
) -> Response {
    let Ok(p) = primary(app) else {
        return ApiError::internal("not a primary").into_response();
    };
    let row = match app.db.get_node(node) {
        Ok(Some(row)) if row.state != node_state::REMOVED => row,
        Ok(_) => return gone(node),
        Err(error) => return ApiError::from(error).into_response(),
    };
    if row.state == node_state::DOWN {
        return gone(node);
    }
    let tls = match p.client(node) {
        Ok(tls) => tls,
        Err(error) => return error.into_response(),
    };
    let headers = req.headers_mut();
    headers.remove(ROUTE_HEADER);
    headers.remove(NODE_HEADER);
    if let Some(route) = route {
        headers.insert(ROUTE_HEADER, HeaderValue::from_static(route));
    }
    if route.is_none() {
        headers.insert(header::HOST, host_of(&row.url));
    }
    let path = req
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_owned();
    *req.uri_mut() = Uri::try_from(path).unwrap_or_default();
    match forward::send(tls, &row.url, req).await {
        Ok(resp) => resp,
        Err(Failure::Unreachable(e)) => {
            eprintln!("forward to node {node}: {e:#}");
            gone(node)
        }
        Err(Failure::Broken(e)) => {
            ApiError::new(Code::Internal, format!("node {node}: {e:#}")).into_bad_gateway()
        }
    }
}

fn gone(node: &str) -> Response {
    ApiError::new(
        Code::NodeUnreachable,
        format!("the node of this sandbox ({node}) cannot be reached; try again later"),
    )
    .into_response()
}

/// Forwards a call for a worker's sandbox and keeps the copy here up to
/// date with deletes, pauses and resumes.
pub async fn forward_api(app: &App, node: &str, id: &str, req: Request) -> Response {
    // `/v1/sandboxes/{id}` and `/v1/sandboxes/{id}:verb`.
    let exact = req
        .uri()
        .path()
        .strip_prefix("/v1/sandboxes/")
        .is_some_and(|rest| !rest.contains('/'));
    let method = req.method().clone();
    let action = req.uri().path().rsplit_once(':').map(|(_, a)| a.to_owned());
    match action.as_deref() {
        Some("fork") if exact && method == Method::POST => {
            return forward_fork(app, node, id, req)
                .await
                .unwrap_or_else(IntoResponse::into_response);
        }
        Some("snapshot") if exact && method == Method::POST => {
            return forward_snapshot(app, node, id, req).await;
        }
        _ => {}
    }
    let resp = forward(app, node, req, None).await;
    if !exact || !resp.status().is_success() {
        return resp;
    }
    if method == Method::DELETE {
        let _ = app.db.set_mirror_state(node, id, state::DELETED, now_ms());
        return resp;
    }
    if method != Method::POST {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_CREATE_REPLY).await else {
        return ApiError::new(Code::Internal, "read the node's reply").into_bad_gateway();
    };
    if let Ok(view) = serde_json::from_slice::<Value>(&bytes)
        && let Some(new) = view.get("state").and_then(Value::as_str)
    {
        let _ = app.db.set_mirror_state(node, id, new, now_ms());
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// Forwards a fork: holds quota for the copies while the worker starts
/// them, then keeps copies of them here.
async fn forward_fork(app: &App, node: &str, id: &str, req: Request) -> Result<Response, ApiError> {
    let source = app.db.get_sandbox(id)?.ok_or_else(ApiError::not_found)?;
    let quotas = app
        .db
        .get_tenant(&source.tenant)?
        .map(|t| t.quotas)
        .unwrap_or_default();
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, MAX_CREATE_REPLY)
        .await
        .map_err(|e| ApiError::invalid(format!("request body: {e}")))?;
    let fork: ForkSandbox = parse(&body)?;
    let count = fork.count.unwrap_or(1).clamp(1, MAX_FORK);
    let vcpus = u8::try_from(source.vcpus).unwrap_or(u8::MAX);
    let mut reservations = Vec::new();
    for _ in 0..count {
        reservations.push(app.sandboxes.reserve(
            &source.tenant,
            &quotas,
            vcpus,
            source.memory_mib,
        )?);
    }
    let busy = primary(app)?.busy.hold(node);
    let resp = forward(
        app,
        node,
        Request::from_parts(parts, Body::from(body)),
        None,
    )
    .await;
    if !resp.status().is_success() {
        return Ok(resp);
    }
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_CREATE_REPLY)
        .await
        .map_err(|_| ApiError::new(Code::Internal, "read the node's reply"))?;
    #[derive(Deserialize)]
    struct Forked {
        sandboxes: Vec<Created>,
    }
    if let Ok(forked) = serde_json::from_slice::<Forked>(&bytes) {
        for created in forked.sandboxes {
            if let Some(mirror) = created.mirror(node, vcpus, source.memory_mib) {
                app.db.put_mirror(node, &mirror, now_ms())?;
            }
        }
    }
    drop((reservations, busy));
    Ok(Response::from_parts(parts, Body::from(bytes)))
}

/// Forwards a snapshot, then saves the new template here so that the
/// fleet learns of it.
async fn forward_snapshot(app: &App, node: &str, id: &str, req: Request) -> Response {
    let resp = forward(app, node, req, None).await;
    if !resp.status().is_success() {
        return resp;
    }
    let (parts, body) = resp.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_CREATE_REPLY).await else {
        return ApiError::new(Code::Internal, "read the node's reply").into_bad_gateway();
    };
    let saved = (|| {
        let tenant = app
            .db
            .get_sandbox(id)?
            .map(|s| s.tenant)
            .ok_or_else(ApiError::not_found)?;
        let reply: Value = serde_json::from_slice(&bytes).map_err(ApiError::internal)?;
        let spec: TemplateSpec =
            serde_json::from_value(reply["spec"].clone()).map_err(ApiError::internal)?;
        let json = serde_json::to_string(&spec).map_err(ApiError::internal)?;
        app.templates
            .sync(&scoped(Some(&tenant), &spec.name), &json)?;
        primary(app)?.bump();
        Ok::<_, ApiError>(())
    })();
    if let Err(error) = saved {
        eprintln!("save snapshot of {id} from node {node}: {}", error.message);
    }
    Response::from_parts(parts, Body::from(bytes))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TokenInput {
    ttl_s: Option<u64>,
}

pub(super) fn new_join_token() -> Result<String, ApiError> {
    Ok(format!(
        "sbj_{}",
        ids::base32(&ids::random::<32>().map_err(ApiError::internal)?)
    ))
}

/// `POST /v1/nodes/tokens`: a one-time token a worker joins with.
pub async fn new_token(
    State(app): State<AppState>,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let p = primary(&app)?;
    let input: TokenInput = parse(&body)?;
    let ttl_s = input.ttl_s.unwrap_or(TOKEN_TTL_S);
    if !(60..=MAX_TOKEN_TTL_S).contains(&ttl_s) {
        return Err(ApiError::invalid(format!(
            "ttl_s must be 60 to {MAX_TOKEN_TTL_S}"
        )));
    }
    let token = new_join_token()?;
    let now = now_ms();
    let expires_at = now + i64::try_from(ttl_s * 1000).unwrap_or(i64::MAX);
    app.db
        .insert_join_token(&ids::hash_key(&token), now, expires_at)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "token": token,
            "expires_at": rfc3339_ms(expires_at),
            "ca_sha256": p.ca_sha256().map_err(ApiError::internal)?,
        })),
    ))
}

fn node_view(p: &Primary, node: &NodeRow, sandboxes: usize, retired: Option<&Retirement>) -> Value {
    let report: Value = node
        .report
        .as_deref()
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or(Value::Null);
    json!({
        "id": node.id,
        "kind": node.kind,
        "url": node.url,
        "state": node.state,
        "draining": node.draining,
        "created_at": rfc3339_ms(node.created_at),
        "last_seen": node.last_seen.map(rfc3339_ms),
        "capacity": report.get("capacity"),
        "config_current": report.get("config_version").and_then(Value::as_u64) == Some(p.version()),
        "sandboxes": sandboxes,
        "retirement": retired.map(|r| retire::view(r, &p.retirer.waiting_for(&r.node))),
    })
}

fn node_not_found() -> ApiError {
    ApiError::new(Code::NotFound, "node not found")
}

pub async fn list_nodes(State(app): State<AppState>) -> Result<Json<Value>, ApiError> {
    let p = primary(&app)?;
    let counts = app.db.node_sandbox_counts()?;
    let retired: HashMap<String, Retirement> = app
        .db
        .retirements(false)?
        .into_iter()
        .map(|r| (r.node.clone(), r))
        .collect();
    let nodes: Vec<Value> = app
        .db
        .list_nodes()?
        .iter()
        .map(|n| {
            let count = counts.get(&n.id).copied().unwrap_or(0);
            node_view(p, n, count, retired.get(&n.id))
        })
        .collect();
    Ok(Json(json!({ "nodes": nodes })))
}

pub async fn get_node(
    State(app): State<AppState>,
    UrlPath(id): UrlPath<String>,
) -> Result<Json<Value>, ApiError> {
    let p = primary(&app)?;
    let node = app
        .db
        .get_node(&id)?
        .filter(|n| n.state != node_state::REMOVED)
        .ok_or_else(node_not_found)?;
    Ok(Json(view_of(&app, p, &node)?))
}

/// `DELETE /v1/nodes/{id}`: the node can no longer call or be called. Its
/// sandboxes are counted as lost; stop its server to stop them.
pub async fn remove_node(
    State(app): State<AppState>,
    axum::extract::Extension(origin): axum::extract::Extension<Origin>,
    UrlPath(id): UrlPath<String>,
) -> Result<StatusCode, ApiError> {
    if !remove(&app, &id, &origin)? {
        return Err(node_not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Removes a node. False if there is no such node.
pub(super) fn remove(app: &App, id: &str, origin: &Origin) -> Result<bool, ApiError> {
    let p = primary(app)?;
    let now = now_ms();
    let edge = app
        .db
        .get_node(id)?
        .is_some_and(|n| n.kind == node_kind::EDGE);
    if !app.db.remove_node(id, now)? {
        return Ok(false);
    }
    p.forget(id);
    retire::forget(app, id);
    if edge {
        // Workers stop taking its calls with their next config copy.
        p.bump();
    }
    for (sandbox, tenant) in app.db.end_mirrors(id, &HashSet::new(), i64::MAX, now)? {
        app.sandboxes.hub.record(
            "sandbox.lost",
            &Origin::system(),
            Some(&tenant),
            Some(&sandbox),
            json!({ "reason": "node removed", "node": id }),
        );
    }
    app.sandboxes
        .hub
        .record("node.removed", origin, None, None, json!({ "node": id }));
    eprintln!("node {id} removed");
    Ok(true)
}

fn view_of(app: &App, p: &Primary, node: &NodeRow) -> Result<Value, ApiError> {
    let counts = app.db.node_sandbox_counts()?;
    let retired = app.db.retirement(&node.id)?;
    Ok(node_view(
        p,
        node,
        counts.get(&node.id).copied().unwrap_or(0),
        retired.as_ref(),
    ))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct DrainInput {
    /// Also move its sandboxes to other hosts.
    #[serde(default)]
    migrate: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetireInput {
    /// Move its sandboxes away. If false, wait for them to end.
    #[serde(default = "yes")]
    migrate: bool,
    #[serde(default)]
    reason: Option<String>,
}

fn yes() -> bool {
    true
}

/// `POST /v1/nodes/{id}:drain`, `:undrain`, `:retire` and `:fenced`. A
/// draining node gets no new sandboxes. A retiring one also never takes
/// them again: it is emptied until its machine can be stopped.
pub async fn node_action(
    State(app): State<AppState>,
    axum::extract::Extension(origin): axum::extract::Extension<Origin>,
    UrlPath(path): UrlPath<String>,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let p = primary(&app)?;
    let (id, verb) = path
        .split_once(':')
        .ok_or_else(|| ApiError::new(Code::NotFound, "no such endpoint"))?;
    let draining = match verb {
        "drain" => true,
        "undrain" => false,
        "retire" => return retire_node(&app, p, id, &body, &origin),
        "fenced" => return fenced_node(&app, p, id, &body, &origin),
        _ => return Err(ApiError::new(Code::NotFound, "no such endpoint")),
    };
    let input: DrainInput = if body.is_empty() {
        DrainInput::default()
    } else {
        parse(&body)?
    };
    if !draining && input.migrate {
        return Err(ApiError::invalid("migrate is only for :drain"));
    }
    if app
        .db
        .get_node(id)?
        .is_some_and(|n| n.kind == node_kind::EDGE)
    {
        return Err(ApiError::invalid(
            "an edge runs no sandboxes, so it cannot drain",
        ));
    }
    if !app.db.set_node_draining(id, draining)? {
        if app.db.retirement(id)?.is_some_and(|r| r.ended_at.is_none()) {
            return Err(ApiError::new(
                Code::Conflict,
                "the node is retiring; it cannot take sandboxes again",
            ));
        }
        return Err(node_not_found());
    }
    let kind = if draining {
        "node.draining"
    } else {
        "node.undrained"
    };
    app.sandboxes.hub.record(
        kind,
        &origin,
        None,
        None,
        json!({ "node": id, "migrate": input.migrate }),
    );
    eprintln!("node {id}: {kind}");
    if input.migrate {
        tokio::spawn(migrate::drain(Arc::clone(&app), id.to_owned(), origin));
    }
    let node = app.db.get_node(id)?.ok_or_else(node_not_found)?;
    let view = view_of(&app, p, &node)?;
    let status = if input.migrate {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(view)))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FencedInput {
    #[serde(default)]
    reason: Option<String>,
}

/// An operator states that a down or removed node's host is powered off,
/// so its persistent sandboxes can start elsewhere.
fn fenced_node(
    app: &App,
    p: &Primary,
    id: &str,
    body: &Bytes,
    origin: &Origin,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let input: FencedInput = if body.is_empty() {
        FencedInput::default()
    } else {
        parse(body)?
    };
    let node = app.db.get_node(id)?.ok_or_else(node_not_found)?;
    if node.kind == node_kind::EDGE {
        return Err(ApiError::invalid("an edge runs no sandboxes"));
    }
    if !app.db.set_node_fenced(id, "operator", now_ms())? {
        return Err(ApiError::new(
            Code::Conflict,
            "the node is not down or removed; only a lost host can be fenced",
        ));
    }
    app.sandboxes.hub.record(
        "node.fenced",
        origin,
        None,
        None,
        json!({ "node": id, "reason": "operator", "note": input.reason }),
    );
    let cooled = cool_fenced(app, id, "operator", origin).map_err(ApiError::internal)?;
    let mut view = view_of(app, p, &node)?;
    view["sandboxes_cold"] = json!(cooled);
    Ok((StatusCode::OK, Json(view)))
}

fn retire_node(
    app: &AppState,
    p: &Primary,
    id: &str,
    body: &Bytes,
    origin: &Origin,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let input: RetireInput = if body.is_empty() {
        parse(&Bytes::from_static(b"{}"))?
    } else {
        parse(body)?
    };
    if app
        .db
        .get_node(id)?
        .is_some_and(|n| n.kind == node_kind::EDGE)
    {
        return Err(ApiError::invalid(
            "an edge runs no sandboxes; remove it with DELETE",
        ));
    }
    let retired = start_retirement(
        app,
        id,
        retire_origin::API,
        input.migrate,
        input.reason.as_deref().unwrap_or("asked through the API"),
        origin,
    )?
    .ok_or_else(node_not_found)?;
    let node = app.db.get_node(id)?.ok_or_else(node_not_found)?;
    let counts = app.db.node_sandbox_counts()?;
    let view = node_view(
        p,
        &node,
        counts.get(id).copied().unwrap_or(0),
        Some(&retired),
    );
    Ok((StatusCode::ACCEPTED, Json(view)))
}

/// Starts retiring `node`, or returns its retirement if it already is.
/// `None` if it is not an active worker.
pub(super) fn start_retirement(
    app: &App,
    node: &str,
    by: &str,
    migrate: bool,
    reason: &str,
    origin: &Origin,
) -> Result<Option<Retirement>, ApiError> {
    let p = primary(app)?;
    let now = now_ms();
    let new = Retirement {
        node: node.to_owned(),
        id: ids::new_id("ret").map_err(ApiError::internal)?,
        origin: by.to_owned(),
        migrate,
        reason: reason.to_owned(),
        state: retire_state::DRAINING.to_owned(),
        created_at: now,
        ready_at: None,
        ended_at: None,
        failed_moves: 0,
    };
    let Some(retired) = app.db.retire_node(&new)? else {
        return Ok(None);
    };
    if retired.id == new.id {
        eprintln!("node {node}: retiring ({reason})");
        app.sandboxes.hub.record(
            "node.retiring",
            origin,
            None,
            None,
            json!({ "node": node, "id": retired.id, "origin": by, "migrate": migrate, "reason": reason }),
        );
        p.retirer.wake();
    }
    Ok(Some(retired))
}

/// `POST /v1/sandboxes/{id}:migrate`: moves a sandbox to another host.
pub async fn migrate_sandbox(
    app: &AppState,
    id: &str,
    body: &Bytes,
    origin: &Origin,
) -> Result<Json<Value>, ApiError> {
    let input: MigrateInput = if body.is_empty() {
        MigrateInput::default()
    } else {
        parse(body)?
    };
    let attrs = migrate::migrate(app, id, input, origin).await?;
    Ok(Json(json!({ "id": id, "migrated": attrs })))
}

impl ApiError {
    fn into_bad_gateway(self) -> Response {
        let mut resp = self.into_response();
        *resp.status_mut() = StatusCode::BAD_GATEWAY;
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_proof_makes_a_lost_node_fenced() {
        let report = |on: bool| json!({ "self_fence": on, "fence_after_s": 60 }).to_string();
        let on = report(true);
        let off = report(false);
        let at = |now| fence_proof(None, Some(&on), 1_000, 30_000, now);
        // Being down proves nothing, until the node's own fence time and
        // the margin have passed.
        assert_eq!(at(1_000 + 89_999), None);
        assert_eq!(at(1_000 + 90_000).as_deref(), Some("self_fence"));
        assert_eq!(fence_proof(None, Some(&off), 0, 0, i64::MAX), None);
        assert_eq!(fence_proof(None, None, 0, 0, i64::MAX), None);
        assert_eq!(fence_proof(None, Some("{}"), 0, 0, i64::MAX), None);
        assert_eq!(
            fence_proof(Some("operator"), Some(&off), 0, 0, 0).as_deref(),
            Some("operator")
        );
    }
}
