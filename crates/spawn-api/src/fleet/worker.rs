//! The worker's side of the fleet: joins once, then sends heartbeats,
//! events and usage to the primary, copies its config, and serves the
//! primary's forwarded calls on the node listener. Edges may send API and
//! preview calls there too.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use rustls::ClientConfig;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::forward::Failure;
use super::migrate;
use super::pki::{self, Identity, Peer};
use super::{
    Config, ConfigRequest, EgressCa, EventBatch, EventReply, HEARTBEAT_EVERY, Heartbeat,
    HeartbeatReply, JoinReply, JoinRequest, NODE_HEADER, REPORT_ENDED_MS, ROUTE_HEADER, SELF_NODE,
    SecretPush, SyncReply, UsageBatch, local_capacity, unhex,
};
use crate::db;
use crate::events::Filter;
use crate::ids;
use crate::metering::{HOUR_MS, hour_start};
use crate::model::ApiError;
use crate::runtime::now_ms;
use crate::server::{App, AppState, parse};

const NODE_FILE: &str = "id";
const EVENTS_EVERY: Duration = Duration::from_secs(1);
const USAGE_EVERY: Duration = Duration::from_secs(60);
const EVENT_BATCH: usize = 500;

pub struct Worker {
    pub node: String,
    primary: super::Primaries,
    /// Our URL, sent with each heartbeat.
    advertise: String,
    identity: Identity,
    tls: Arc<ClientConfig>,
    /// Changes every start, so the primary knows our sequence restarted.
    boot: String,
    seq: AtomicI64,
    /// The config version copied last.
    version: AtomicU64,
    /// The newest of our events the primary has; -1 until it says.
    events_after: AtomicI64,
    syncing: tokio::sync::Mutex<()>,
    /// Edges that may call the node listener, from the last config copy.
    edges: RwLock<HashSet<String>>,
}

/// Where a worker keeps its fleet identity.
fn dir(data: &Path) -> PathBuf {
    data.join("fleet").join("worker")
}

impl Worker {
    /// Loads this worker's identity, or joins the fleet with `token`.
    pub async fn start(
        data: &Path,
        primary: &str,
        advertise: &str,
        token: Option<&str>,
        ca_sha256: Option<&str>,
    ) -> Result<Arc<Self>> {
        let dir = dir(data);
        let id_file = dir.join(NODE_FILE);
        if !(Identity::exists(&dir) && id_file.exists()) {
            let (Some(token), Some(ca_sha256)) = (token, ca_sha256) else {
                bail!(
                    "this host has not joined the fleet; give --join-token and \
                     --primary-ca-sha256 from POST /v1/nodes/tokens on the primary"
                );
            };
            join(
                &dir,
                &super::Primaries::parse(primary).map_err(anyhow::Error::msg)?,
                advertise,
                token,
                ca_sha256,
                db::node_kind::WORKER,
            )
            .await?;
        } else if token.is_some() {
            eprintln!("already joined; --join-token is not used");
        }
        let node = std::fs::read_to_string(&id_file)
            .with_context(|| format!("read {}", id_file.display()))?
            .trim()
            .to_owned();
        let identity = Identity::load(&dir)?;
        let tls = Arc::new(identity.client_config(pki::PRIMARY)?);
        let _ = SELF_NODE.set(node.clone());
        eprintln!("fleet worker {node}; primary {primary}");
        Ok(Arc::new(Self {
            node,
            primary: super::Primaries::parse(primary).map_err(anyhow::Error::msg)?,
            advertise: advertise.to_owned(),
            identity,
            tls,
            boot: ids::new_id("boot")?,
            seq: AtomicI64::new(0),
            version: AtomicU64::new(0),
            events_after: AtomicI64::new(-1),
            syncing: tokio::sync::Mutex::new(()),
            edges: RwLock::default(),
        }))
    }

    /// TLS for the node listener: callers need a fleet certificate. The
    /// router checks whose.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        self.identity.server_config_any()
    }

    /// Whether the call comes from an edge of this fleet: it names itself
    /// in its header, matching its certificate.
    fn is_edge(&self, peer: &Peer, headers: &axum::http::HeaderMap) -> bool {
        headers
            .get(NODE_HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|id| {
                peer.is(id)
                    && self
                        .edges
                        .read()
                        .unwrap_or_else(|e| e.into_inner())
                        .contains(id)
            })
    }

    /// The primary's egress CA, which every host uses.
    pub async fn egress_ca(&self) -> Result<EgressCa> {
        self.call("/fleet/v1/egress-ca", &json!({}))
            .await
            .map_err(Failure::error)
    }

    async fn call<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, Failure> {
        self.primary
            .call(&self.tls, path, Some(&self.node), body)
            .await
    }
}

/// Joins the fleet as a `kind` node and saves the identity in `dir`.
pub(super) async fn join(
    dir: &Path,
    primary: &super::Primaries,
    advertise: &str,
    token: &str,
    ca_sha256: &str,
    kind: &str,
) -> Result<()> {
    let (key_pem, csr_pem) = pki::new_request()?;
    let tls = Arc::new(pki::join_config(ca_sha256)?);
    let req = JoinRequest {
        token: token.to_owned(),
        csr_pem,
        url: advertise.to_owned(),
        kind: kind.to_owned(),
    };
    let reply: JoinReply = primary
        .call(&tls, "/fleet/v1/join", None, &req)
        .await
        .map_err(Failure::error)
        .context("join the fleet")?;
    std::fs::create_dir_all(dir)?;
    // The ID first: the identity counts as saved once its certificate is.
    std::fs::write(dir.join(NODE_FILE), format!("{}\n", reply.node))?;
    Identity::save(dir, &reply.cert_pem, &key_pem, &reply.ca_pem)?;
    eprintln!("joined the fleet as node {}", reply.node);
    Ok(())
}

/// Copies tenants, keys, templates and our secrets from the primary.
pub async fn sync(app: &App, w: &Worker) -> Result<u64> {
    let _syncing = w.syncing.lock().await;
    let held = app.secrets.keys().map_err(|e| anyhow::anyhow!(e.message))?;
    let config: Config = w
        .call("/fleet/v1/config", &ConfigRequest { held: held.clone() })
        .await
        .map_err(Failure::error)?;
    let keys = config
        .keys
        .into_iter()
        .map(|k| {
            let hash = unhex(&k.hash).context("bad key hash")?;
            Ok((k.key, hash))
        })
        .collect::<Result<Vec<_>>>()?;
    app.db.replace_tenants_and_keys(&config.tenants, &keys)?;
    let mut templates = config.templates;
    // Builds are queued in this order, so the most used come first.
    templates.sort_by_key(|t| std::cmp::Reverse(t.uses));
    let mut keep = HashSet::new();
    for template in &templates {
        if let Err(error) = app.templates.sync(&template.key, &template.spec) {
            eprintln!("fleet: template {:?}: {}", template.key, error.message);
        }
        keep.insert(template.key.clone());
    }
    app.templates
        .remove_others(&keep)
        .map_err(|e| anyhow::anyhow!(e.message))?;
    app.secrets
        .import(&config.secrets, Some(&held))
        .map_err(|e| anyhow::anyhow!(e.message))?;
    if let Some(key) = &config.session_key {
        app.sessions.set(unhex(key).context("bad session key")?);
    }
    *w.edges.write().unwrap_or_else(|e| e.into_inner()) = config.edges.into_iter().collect();
    w.version.store(config.version, Ordering::SeqCst);
    Ok(config.version)
}

/// Logs a failing loop once per change, not on every try.
pub(super) struct Quiet(pub(super) Option<String>);

impl Quiet {
    pub(super) fn see(&mut self, what: &str, result: Result<()>) {
        match result {
            Ok(()) => {
                if self.0.take().is_some() {
                    eprintln!("fleet: {what}: working again");
                }
            }
            Err(error) => {
                let text = format!("{error:#}");
                if self.0.as_deref() != Some(&text) {
                    eprintln!("fleet: {what}: {text}");
                }
                self.0 = Some(text);
            }
        }
    }
}

async fn heartbeat(app: &App, w: &Worker) -> Result<()> {
    let now = now_ms();
    let hb = Heartbeat {
        url: w.advertise.clone(),
        boot: w.boot.clone(),
        seq: w.seq.fetch_add(1, Ordering::SeqCst) + 1,
        config_version: w.version.load(Ordering::SeqCst),
        capacity: local_capacity(app),
        sandboxes: app.db.local_report(now - REPORT_ENDED_MS)?,
    };
    let reply: HeartbeatReply = w
        .call("/fleet/v1/heartbeat", &hb)
        .await
        .map_err(Failure::error)?;
    w.events_after.store(reply.events_after, Ordering::SeqCst);
    for id in &reply.release {
        eprintln!("fleet: {id} runs on another host now; removing it here");
        if let Err(error) = app.sandboxes.forget(id, super::migrate::PRIMARY).await {
            eprintln!("fleet: release {id}: {}", error.message);
        }
    }
    if reply.config_version != w.version.load(Ordering::SeqCst) {
        sync(app, w).await?;
    }
    Ok(())
}

async fn send_events(app: &App, w: &Worker) -> Result<()> {
    let after = w.events_after.load(Ordering::SeqCst);
    if after < 0 {
        return Ok(());
    }
    let (events, _) = app.db.list_events(&Filter::default(), after, EVENT_BATCH)?;
    if events.is_empty() {
        return Ok(());
    }
    let reply: EventReply = w
        .call("/fleet/v1/events", &EventBatch { events })
        .await
        .map_err(Failure::error)?;
    w.events_after.store(reply.events_after, Ordering::SeqCst);
    Ok(())
}

async fn send_usage(app: &App, w: &Worker) -> Result<()> {
    let rows = app.db.usage_rows(hour_start(now_ms()) - HOUR_MS)?;
    if rows.is_empty() {
        return Ok(());
    }
    let _: Value = w
        .call("/fleet/v1/usage", &UsageBatch { rows })
        .await
        .map_err(Failure::error)?;
    Ok(())
}

/// Starts the loops that report to the primary.
pub fn spawn(app: AppState, w: Arc<Worker>) -> Vec<tokio::task::JoinHandle<()>> {
    let beat = {
        let (app, w) = (Arc::clone(&app), Arc::clone(&w));
        tokio::spawn(async move {
            let mut quiet = Quiet(None);
            loop {
                quiet.see("heartbeat", heartbeat(&app, &w).await);
                tokio::time::sleep(HEARTBEAT_EVERY).await;
            }
        })
    };
    let events = {
        let (app, w) = (Arc::clone(&app), Arc::clone(&w));
        tokio::spawn(async move {
            let mut quiet = Quiet(None);
            loop {
                tokio::time::sleep(EVENTS_EVERY).await;
                quiet.see("send events", send_events(&app, &w).await);
            }
        })
    };
    let usage = tokio::spawn(async move {
        let mut quiet = Quiet(None);
        loop {
            tokio::time::sleep(USAGE_EVERY).await;
            quiet.see("send usage", send_usage(&app, &w).await);
        }
    });
    vec![beat, events, usage]
}

fn peer_of(req: &Request) -> Peer {
    req.extensions()
        .get::<ConnectInfo<Peer>>()
        .map(|c| c.0.clone())
        .unwrap_or_default()
}

fn forbidden() -> Response {
    ApiError::new(
        crate::model::Code::Forbidden,
        "not allowed to call this node",
    )
    .into_response()
}

/// Fleet routes take only the primary.
async fn only_primary(req: Request, next: Next) -> Response {
    if peer_of(&req).is(pki::PRIMARY) {
        next.run(req).await
    } else {
        forbidden()
    }
}

/// The node listener: the primary's fleet calls, and API and preview calls
/// from the primary or an edge.
pub fn router(app: AppState) -> Router {
    let api = crate::server::router(Arc::clone(&app));
    let preview = crate::preview::router(Arc::clone(&app));
    let fallback_app = Arc::clone(&app);
    Router::new()
        .route("/fleet/v1/sync", post(sync_now))
        .route("/fleet/v1/secrets", post(take_secrets))
        .route("/fleet/v1/migrate/export", post(migrate::export_here))
        .route("/fleet/v1/migrate/import", post(migrate::import_here))
        .route("/fleet/v1/migrate/release", post(migrate::release_here))
        .route("/fleet/v1/migrate/abort", post(migrate::abort_here))
        .route("/fleet/v1/volumes/put", post(super::volumes::put_here))
        .route(
            "/fleet/v1/volumes/export",
            post(super::volumes::export_here),
        )
        .route(
            "/fleet/v1/volumes/import",
            post(super::volumes::import_here),
        )
        .route(
            "/fleet/v1/volumes/drop",
            post(super::volumes::drop_here_route),
        )
        .route_layer(middleware::from_fn(only_primary))
        .fallback(move |mut req: Request| {
            let peer = peer_of(&req);
            let allowed = peer.is(pki::PRIMARY)
                || worker_of(&fallback_app).is_ok_and(|w| w.is_edge(&peer, req.headers()));
            req.headers_mut().remove(NODE_HEADER);
            let to_preview = req
                .headers()
                .get(ROUTE_HEADER)
                .is_some_and(|v| v.as_bytes() == b"preview");
            let router = if to_preview {
                preview.clone()
            } else {
                api.clone()
            };
            async move {
                if !allowed {
                    return forbidden();
                }
                match router.oneshot(req).await {
                    Ok(resp) => resp,
                    Err(never) => match never {},
                }
            }
        })
        .with_state(app)
}

fn worker_of(app: &App) -> Result<&Arc<Worker>, ApiError> {
    match &app.role {
        super::Role::Worker(w) => Ok(w),
        _ => Err(ApiError::internal("not a worker")),
    }
}

async fn sync_now(State(app): State<AppState>) -> Response {
    let result = async {
        let w = worker_of(&app)?;
        sync(&app, w)
            .await
            .map_err(|e| ApiError::internal(format!("{e:#}")))
    }
    .await;
    match result {
        Ok(config_version) => Json(SyncReply { config_version }).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn take_secrets(State(app): State<AppState>, body: Bytes) -> Result<Json<Value>, ApiError> {
    let push: SecretPush = parse(&body)?;
    app.secrets.import(&push.secrets, None)?;
    Ok(Json(json!({})))
}
