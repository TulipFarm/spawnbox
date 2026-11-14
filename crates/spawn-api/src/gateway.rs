//! The forward listener, for trusted HTTP gateways in front of sandbox
//! ports.
//!
//! A gateway sends the original request with `X-Spawnbox-Key` (an API key
//! with `sandboxes:forward`) and `X-Spawnbox-Target: sbx_ID:PORT`. The
//! listener wakes the sandbox if needed, within a per-host wake limit and a
//! per-sandbox in-flight limit, and forwards the request to the port
//! through the same vsock tunnel as previews. Every `X-Spawnbox-*` header
//! is removed before the app sees the request, and replaced on the way back.
//!
//! It also keeps the drains of this host's sandboxes, and answers whether a
//! port is ready for traffic.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

use crate::db::{Db, state};
use crate::events::Origin;
use crate::fleet::Role;
use crate::model::{ApiError, Code, DrainView, rfc3339_ms};
use crate::runtime::{Published, now_ms};
use crate::server::{App, AppState};
use crate::tenancy::{Caller, DEFAULT_TENANT, Scope};
use crate::{ids, metrics};

pub const KEY: &str = "x-spawnbox-key";
pub const TARGET: &str = "x-spawnbox-target";
pub const WAKE: &str = "x-spawnbox-wake";
pub const TIMEOUT_MS: &str = "x-spawnbox-timeout-ms";
/// Set by the host that sends a request on to the worker that runs the
/// sandbox.
pub const EXPECT_GENERATION: &str = "x-spawnbox-expect-generation";
pub const ERROR: &str = "x-spawnbox-error";
pub const SANDBOX: &str = "x-spawnbox-sandbox";
pub const GENERATION: &str = "x-spawnbox-generation";
pub const ENDPOINT_GENERATION: &str = "x-spawnbox-endpoint-generation";
const PREFIX: &str = "x-spawnbox-";

/// A revoked key stops working within this time.
const KEY_TTL: Duration = Duration::from_secs(5);
const MAX_CACHED_KEYS: usize = 10_000;
/// How long a resume or a cold start may take.
const WAKE_LIMIT: Duration = Duration::from_secs(60);
const DEFAULT_RESPONSE: Duration = Duration::from_secs(60);
/// Largest request body kept to send a request a second time after
/// `stale_route`.
const REPLAY_BODY: usize = 1 << 20;
/// How long a forwarded request waits for a port to be ready after a wake.
const READY_AFTER_WAKE: Duration = Duration::from_secs(30);
pub const READY_POLL: Duration = Duration::from_millis(250);
const DRAINING: &str = "the sandbox is draining";
const NOT_PUBLISHED: &str = " is not published";

/// Whether a port that is not ready for `reason` stays so however long a
/// caller waits.
pub fn lasting(reason: &str) -> bool {
    reason == DRAINING || reason.ends_with(NOT_PUBLISHED)
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Wakes that run at once on this host.
    pub max_wakes: usize,
    /// How long a request waits for a wake slot.
    pub wake_queue: Duration,
    /// Forwarded requests and upgraded connections per sandbox.
    pub max_in_flight: u32,
    /// The longest response-header timeout a gateway may ask for.
    pub max_response: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_wakes: 8,
            wake_queue: Duration::from_secs(10),
            max_in_flight: 1024,
            max_response: Duration::from_secs(600),
        }
    }
}

/// What `X-Spawnbox-Target` names.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    Port {
        sandbox: String,
        port: u16,
    },
    /// The current target of an endpoint of the key's tenant.
    Endpoint {
        name: String,
    },
}

impl Target {
    pub fn parse(text: &str) -> Result<Self, ApiError> {
        let bad = || ApiError::invalid("X-Spawnbox-Target must be sbx_ID:PORT or endpoint:NAME");
        if let Some(name) = text.strip_prefix("endpoint:") {
            if !crate::endpoints::valid_name(name) {
                return Err(bad());
            }
            return Ok(Self::Endpoint {
                name: name.to_owned(),
            });
        }
        let (sandbox, port) = text.rsplit_once(':').ok_or_else(bad)?;
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(bad)?;
        if !ids::is_valid_id("sbx", sandbox) {
            return Err(bad());
        }
        Ok(Self::Port {
            sandbox: sandbox.to_owned(),
            port,
        })
    }
}

/// `X-Spawnbox-Wake`: which sandboxes a request may wake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Wake {
    /// Resume a paused sandbox and start a cold one.
    #[default]
    Any,
    /// Only resume a paused sandbox.
    Paused,
    /// Wake nothing.
    Never,
}

impl Wake {
    pub fn parse(text: Option<&str>) -> Result<Self, ApiError> {
        match text {
            None | Some("any") => Ok(Self::Any),
            Some("paused") => Ok(Self::Paused),
            Some("never") => Ok(Self::Never),
            Some(_) => Err(ApiError::invalid(
                "X-Spawnbox-Wake must be any, paused or never",
            )),
        }
    }

    /// Whether a sandbox in `state` needs a wake, or why it may not have
    /// one.
    pub fn admit(self, sandbox_state: &str) -> Result<bool, ApiError> {
        match sandbox_state {
            state::RUNNING => Ok(false),
            state::PAUSED if self == Self::Never => Err(ApiError::new(
                Code::SandboxPaused,
                "the sandbox is paused and the request asked not to wake it",
            )),
            state::PAUSED => Ok(true),
            state::COLD | state::STARTING if self == Self::Any => Ok(true),
            state::COLD | state::STARTING => Err(ApiError::new(
                Code::Cold,
                "the sandbox is cold and the request asked not to start it",
            )),
            _ => Err(ApiError::not_found()),
        }
    }
}

/// `X-Spawnbox-Timeout-Ms`: how long to wait for the app's response
/// headers.
pub fn response_timeout(text: Option<&str>, max: Duration) -> Result<Duration, ApiError> {
    let Some(text) = text else {
        return Ok(DEFAULT_RESPONSE.min(max));
    };
    text.parse::<u64>()
        .ok()
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .filter(|wait| *wait <= max)
        .ok_or_else(|| {
            ApiError::invalid(format!(
                "X-Spawnbox-Timeout-Ms must be 1 to {}",
                max.as_millis()
            ))
        })
}

/// Removes every `X-Spawnbox-*` header.
pub fn strip(headers: &mut HeaderMap) {
    let ours: Vec<HeaderName> = headers
        .keys()
        .filter(|name| name.as_str().starts_with(PREFIX))
        .cloned()
        .collect();
    for name in ours {
        headers.remove(name);
    }
}

/// Wake slots, in-flight counts, drains and verified keys of one host.
pub struct Gateway {
    pub settings: Settings,
    wakes: Arc<Semaphore>,
    waking: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    in_flight: Arc<Mutex<HashMap<String, u32>>>,
    keys: Mutex<HashMap<Vec<u8>, (Instant, Caller)>>,
    drains: Mutex<HashMap<String, Drain>>,
    drain_serial: std::sync::atomic::AtomicU64,
}

/// What a drain does once no request is in flight or its time is up.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Then {
    #[default]
    None,
    Pause,
    Delete,
}

impl Then {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pause => "pause",
            Self::Delete => "delete",
        }
    }
}

/// A drain of one sandbox on this host. It stays until `:undrain` or the
/// sandbox is deleted, so a drained sandbox takes no traffic after `then`.
#[derive(Clone, Copy, Debug)]
struct Drain {
    serial: u64,
    started_at: i64,
    deadline: i64,
    then: Then,
}

/// `POST /v1/sandboxes/{id}:drain`
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainRequest {
    pub timeout_s: Option<u64>,
    #[serde(default)]
    pub then: Then,
}

impl DrainRequest {
    pub fn timeout(&self) -> Result<Duration, ApiError> {
        match self.timeout_s.unwrap_or(30) {
            s @ 1..=3600 => Ok(Duration::from_secs(s)),
            _ => Err(ApiError::invalid("timeout_s must be 1 to 3600")),
        }
    }
}

/// The turn of one request to wake a sandbox. Requests for the same
/// sandbox take turns, so a burst of them uses one wake slot.
pub struct WakeTurn {
    waking: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    id: String,
    guard: Option<OwnedMutexGuard<()>>,
}

impl Drop for WakeTurn {
    fn drop(&mut self) {
        drop(self.guard.take());
        let mut waking = self.waking.lock().unwrap_or_else(|e| e.into_inner());
        if waking
            .get(&self.id)
            .is_some_and(|turns| Arc::strong_count(turns) == 1)
        {
            waking.remove(&self.id);
        }
    }
}

/// One forwarded request or upgraded connection in a sandbox.
#[derive(Debug)]
pub struct InFlight {
    counts: Arc<Mutex<HashMap<String, u32>>>,
    id: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.id);
            }
        }
    }
}

impl Gateway {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            wakes: Arc::new(Semaphore::new(settings.max_wakes)),
            waking: Arc::default(),
            in_flight: Arc::default(),
            keys: Mutex::default(),
            drains: Mutex::default(),
            drain_serial: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Forwarded and preview requests and upgraded connections in sandbox
    /// `id` now.
    pub fn in_flight(&self, id: &str) -> u32 {
        let counts = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        counts.get(id).copied().unwrap_or(0)
    }

    pub fn draining(&self, id: &str) -> bool {
        self.drains
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(id)
    }

    /// Refuses new traffic for sandbox `id` from now. Returns the drain's
    /// serial, which the task that finishes it checks.
    pub(crate) fn begin_drain(
        &self,
        id: &str,
        timeout: Duration,
        then: Then,
        now: i64,
    ) -> Result<u64, ApiError> {
        let mut drains = self.drains.lock().unwrap_or_else(|e| e.into_inner());
        if drains.contains_key(id) {
            return Err(ApiError::new(
                Code::Conflict,
                "the sandbox is already draining; call :undrain first",
            ));
        }
        let serial = 1 + self
            .drain_serial
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let timeout_ms = i64::try_from(timeout.as_millis()).unwrap_or(i64::MAX);
        drains.insert(
            id.to_owned(),
            Drain {
                serial,
                started_at: now,
                deadline: now.saturating_add(timeout_ms),
                then,
            },
        );
        Ok(serial)
    }

    /// Ends the drain of `id`. Returns whether there was one.
    pub fn undrain(&self, id: &str) -> bool {
        self.drains
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id)
            .is_some()
    }

    fn drain_is(&self, id: &str, serial: u64) -> bool {
        self.drains
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .is_some_and(|drain| drain.serial == serial)
    }

    pub fn drain_view(&self, id: &str) -> Option<DrainView> {
        let drain = *self
            .drains
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)?;
        Some(DrainView {
            started_at: rfc3339_ms(drain.started_at),
            deadline: rfc3339_ms(drain.deadline),
            in_flight: self.in_flight(id),
            then: drain.then.as_str(),
        })
    }

    /// Counts a request in sandbox `id`, unless it is draining.
    pub fn admit(&self, id: &str) -> Result<InFlight, ApiError> {
        if self.draining(id) {
            return Err(ApiError::new(
                Code::Draining,
                "the sandbox is draining and takes no new requests",
            ));
        }
        self.enter(id)
    }

    /// The caller behind `X-Spawnbox-Key`, which must hold
    /// `sandboxes:forward`.
    pub fn authenticate(
        &self,
        db: &Db,
        headers: &HeaderMap,
        now: Instant,
    ) -> Result<Caller, ApiError> {
        let unknown = || ApiError::new(Code::Unauthorized, "missing or unknown X-Spawnbox-Key");
        let key = headers
            .get(KEY)
            .and_then(|value| value.to_str().ok())
            .filter(|key| ids::bearer(&format!("Bearer {key}")) == Some(*key))
            .ok_or_else(unknown)?;
        let hash = ids::hash_key(key);
        let cached = {
            let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
            keys.get(&hash)
                .filter(|(at, _)| now.saturating_duration_since(*at) < KEY_TTL)
                .map(|(_, caller)| caller.clone())
        };
        let caller = match cached {
            Some(caller) => caller,
            None => {
                let caller = db
                    .find_key(&hash)?
                    .map(|key| Caller::from_key(&key))
                    .transpose()?
                    .ok_or_else(unknown)?;
                let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
                if keys.len() >= MAX_CACHED_KEYS {
                    keys.retain(|_, (at, _)| now.saturating_duration_since(*at) < KEY_TTL);
                }
                keys.insert(hash, (now, caller.clone()));
                caller
            }
        };
        caller.require(Scope::SandboxesForward)?;
        Ok(caller)
    }

    /// Counts a request in sandbox `id` until the guard drops.
    pub fn enter(&self, id: &str) -> Result<InFlight, ApiError> {
        let mut counts = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let count = counts.entry(id.to_owned()).or_default();
        if *count >= self.settings.max_in_flight {
            return Err(ApiError::new(
                Code::TooManyRequests,
                format!(
                    "the sandbox has {} requests in flight",
                    self.settings.max_in_flight
                ),
            ));
        }
        *count += 1;
        Ok(InFlight {
            counts: Arc::clone(&self.in_flight),
            id: id.to_owned(),
        })
    }

    /// Waits until no other request wakes sandbox `id`. The caller checks
    /// again whether the sandbox still needs a wake.
    pub async fn wake_turn(&self, id: &str) -> Result<WakeTurn, ApiError> {
        let turns = {
            let mut waking = self.waking.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(waking.entry(id.to_owned()).or_default())
        };
        let guard = tokio::time::timeout(self.settings.wake_queue + WAKE_LIMIT, turns.lock_owned())
            .await
            .map_err(|_| ApiError::new(Code::WakeBusy, "the sandbox is still waking; try again"))?;
        Ok(WakeTurn {
            waking: Arc::clone(&self.waking),
            id: id.to_owned(),
            guard: Some(guard),
        })
    }

    /// Waits for a wake slot, up to the queue time.
    pub async fn wake_slot(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        let started = Instant::now();
        let slot = tokio::time::timeout(
            self.settings.wake_queue,
            Arc::clone(&self.wakes).acquire_owned(),
        )
        .await;
        metrics::observe(
            "spawnbox_forward_wake_wait_seconds",
            vec![],
            started.elapsed().as_secs_f64(),
        );
        match slot {
            Ok(Ok(slot)) => Ok(slot),
            Ok(Err(_)) => Err(ApiError::internal("wake slots closed")),
            Err(_) => Err(ApiError::new(
                Code::WakeBusy,
                format!(
                    "{} sandboxes are waking on this host; try again",
                    self.settings.max_wakes
                ),
            )),
        }
    }
}

pub fn router(app: AppState) -> Router {
    Router::new().fallback(handle).with_state(app)
}

async fn handle(State(app): State<AppState>, req: Request) -> Response {
    let response = match serve(&app, req).await {
        Ok(response) => response,
        Err(error) => refusal(error),
    };
    let code = response
        .headers()
        .get(ERROR)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("ok")
        .to_owned();
    metrics::inc("spawnbox_forward_requests_total", vec![("code", code)]);
    response
}

/// A response that Spawnbox made, not the app.
pub fn refusal(error: ApiError) -> Response {
    let code = HeaderValue::from_static(error.code.as_str());
    let mut response = error.into_response();
    response.headers_mut().insert(ERROR, code);
    response
}

/// What the gateway asked for.
struct Ask {
    caller: Caller,
    target: Target,
    wake: Wake,
    timeout: Duration,
    expect: Option<i64>,
}

impl Ask {
    fn read(app: &App, headers: &HeaderMap) -> Result<Self, ApiError> {
        let caller = app.gateway.authenticate(&app.db, headers, Instant::now())?;
        let text = |name: &str| {
            headers
                .get(name)
                .map(|value| {
                    value
                        .to_str()
                        .map_err(|_| ApiError::invalid(format!("{name} must be ASCII")))
                })
                .transpose()
        };
        let target =
            text(TARGET)?.ok_or_else(|| ApiError::invalid("X-Spawnbox-Target is required"))?;
        let target = Target::parse(target)?;
        let expect = text(EXPECT_GENERATION)?
            .map(|n| {
                n.parse::<i64>()
                    .map_err(|_| ApiError::invalid("bad X-Spawnbox-Expect-Generation"))
            })
            .transpose()?;
        Ok(Self {
            caller,
            target,
            wake: Wake::parse(text(WAKE)?)?,
            timeout: response_timeout(text(TIMEOUT_MS)?, app.gateway.settings.max_response)?,
            expect,
        })
    }
}

async fn serve(app: &App, req: Request) -> Result<Response, ApiError> {
    let ask = Ask::read(app, req.headers())?;
    let (req, again) = replayable(req).await?;
    let first = resolve(app, &ask, req).await;
    // An endpoint may have switched away from a draining target since it
    // was read; no byte reached the app, so the request is sent again.
    let retry = is_stale(&first)
        || (matches!(ask.target, Target::Endpoint { .. }) && is_code(&first, Code::Draining));
    match again {
        Some(again) if retry => Ok(resolve(app, &ask, again).await),
        _ => Ok(first),
    }
}

/// Finds the sandbox port the request is for, and sends it there.
async fn resolve(app: &App, ask: &Ask, req: Request) -> Response {
    match &ask.target {
        Target::Port { sandbox, port } => route(app, ask, sandbox, *port, req)
            .await
            .unwrap_or_else(refusal),
        Target::Endpoint { name } => {
            let tenant = ask.caller.tenant.as_deref().unwrap_or(DEFAULT_TENANT);
            let endpoint = match app.db.get_endpoint(tenant, name) {
                Ok(Some(endpoint)) => endpoint,
                Ok(None) => {
                    return refusal(ApiError::new(
                        Code::NotFound,
                        format!("no endpoint {name:?}"),
                    ));
                }
                Err(error) => return refusal(error.into()),
            };
            let mut response = route(app, ask, &endpoint.sandbox, endpoint.port, req)
                .await
                .unwrap_or_else(refusal);
            response
                .headers_mut()
                .insert(ENDPOINT_GENERATION, HeaderValue::from(endpoint.generation));
            response
        }
    }
}

pub fn is_stale(response: &Response) -> bool {
    is_code(response, Code::StaleRoute)
}

fn is_code(response: &Response, code: Code) -> bool {
    response
        .headers()
        .get(ERROR)
        .is_some_and(|value| value.as_bytes() == code.as_str().as_bytes())
}

/// Splits a request into two copies, so it can be sent again after
/// `stale_route`. Upgrades and large or streamed bodies get no copy.
pub async fn replayable(req: Request) -> Result<(Request, Option<Request>), ApiError> {
    let headers = req.headers();
    let length = match headers.get(header::CONTENT_LENGTH) {
        Some(value) => value.to_str().ok().and_then(|v| v.parse::<usize>().ok()),
        None if headers.contains_key(header::TRANSFER_ENCODING) => None,
        None => Some(0),
    };
    if headers.contains_key(header::UPGRADE) || length.is_none_or(|n| n > REPLAY_BODY) {
        return Ok((req, None));
    }
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, REPLAY_BODY)
        .await
        .map_err(|e| ApiError::invalid(format!("read request body: {e}")))?;
    let again = Request::from_parts(parts.clone(), Body::from(bytes.clone()));
    Ok((Request::from_parts(parts, Body::from(bytes)), Some(again)))
}

/// Sends the request to the host that runs the sandbox, or serves it here.
async fn route(
    app: &App,
    ask: &Ask,
    id: &str,
    port: u16,
    req: Request,
) -> Result<Response, ApiError> {
    if matches!(app.role, Role::Worker(_)) {
        let here = app.sandboxes.generation(id);
        if here.is_none() || ask.expect.is_some_and(|n| here != Some(n)) {
            return Err(ApiError::new(
                Code::StaleRoute,
                "this host does not run that generation of the sandbox",
            ));
        }
    }
    let row = app
        .db
        .get_sandbox(id)?
        .filter(|row| ask.caller.sees(&row.tenant))
        .ok_or_else(ApiError::not_found)?;
    crate::fleet::primary::wait_for_move(app, id).await;
    if let Some(node) = crate::fleet::primary::node_of(app, id) {
        return Ok(to_worker(app, &node, id, port, row.generation, req).await);
    }
    if !published(app, id, port)? {
        return Err(ApiError::new(
            Code::NotFound,
            format!("port {port} of this sandbox is not published"),
        ));
    }
    let in_flight = app.gateway.admit(id)?;
    let origin = Origin::of_call(&ask.caller.key, None, None)?;
    let woke = ask.wake.admit(&row.state)?;
    let (mut turn, mut slot) = (None, None);
    if woke {
        turn = Some(app.gateway.wake_turn(id).await?);
        // The request that had the turn before may have woken it.
        let row = app.db.get_sandbox(id)?.ok_or_else(ApiError::not_found)?;
        if let Some(node) = crate::fleet::primary::node_of(app, id) {
            drop((turn, in_flight));
            return Ok(to_worker(app, &node, id, port, row.generation, req).await);
        }
        if ask.wake.admit(&row.state)? {
            slot = Some(app.gateway.wake_slot().await?);
            metrics::inc("spawnbox_forward_wakes_total", vec![]);
            if matches!(app.role, Role::Primary(_)) {
                within(
                    WAKE_LIMIT,
                    "wake",
                    crate::fleet::primary::wake_cold(app, id, false),
                )
                .await?;
                if let Some(node) = crate::fleet::primary::node_of(app, id) {
                    drop((slot, turn, in_flight));
                    let generation = app.db.get_sandbox(id)?.map_or(0, |row| row.generation);
                    return Ok(to_worker(app, &node, id, port, generation, req).await);
                }
            }
        }
    }
    let opened = within(WAKE_LIMIT, "wake", app.sandboxes.open(id, &origin)).await?;
    drop((slot, turn));
    if let Some(name) = app.sandboxes.service_on_port(id, port) {
        if !app.sandboxes.wait_healthy(&opened.channel, &name).await {
            return Err(ApiError::new(
                Code::NotReady,
                format!("service {name:?} on port {port} is not healthy"),
            ));
        }
    } else if woke
        && let Some(reason) = wait_ready(app, &opened.channel, id, port, READY_AFTER_WAKE).await
    {
        return Err(ApiError::new(Code::NotReady, reason));
    }
    let generation = opened.busy.generation();
    let mut req = req;
    strip(req.headers_mut());
    let forwarded =
        crate::preview::forward(opened.channel, (opened.busy, in_flight), port, req, None);
    let mut response = within(ask.timeout, "response", forwarded).await?;
    let headers = response.headers_mut();
    strip(headers);
    if let Ok(value) = HeaderValue::from_str(id) {
        headers.insert(SANDBOX, value);
    }
    headers.insert(GENERATION, HeaderValue::from(generation));
    Ok(response)
}

/// Runs `work`, or fails with `upstream_timeout` after `limit`.
async fn within<T>(
    limit: Duration,
    what: &str,
    work: impl Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
    tokio::time::timeout(limit, work).await.map_err(|_| {
        ApiError::new(
            Code::UpstreamTimeout,
            format!("no {what} within {} ms", limit.as_millis()),
        )
    })?
}

/// Whether `port` of sandbox `id` is published here, or in its start
/// record if it is cold.
fn published(app: &App, id: &str, port: u16) -> Result<bool, ApiError> {
    if app.sandboxes.published(id, port).is_some() {
        return Ok(true);
    }
    let Some(start) = app.db.get_start_record(id)? else {
        return Ok(false);
    };
    let ports: BTreeMap<u16, Published> = serde_json::from_str(&start.ports).unwrap_or_default();
    Ok(ports.contains_key(&port))
}

/// Sends the request to the worker that runs the sandbox, which checks the
/// generation before any byte reaches the app.
async fn to_worker(
    app: &App,
    node: &str,
    id: &str,
    port: u16,
    generation: i64,
    mut req: Request,
) -> Response {
    let headers = req.headers_mut();
    headers.insert(EXPECT_GENERATION, HeaderValue::from(generation));
    // The worker has no endpoints, so it gets the port they resolved to.
    if let Ok(target) = HeaderValue::from_str(&format!("{id}:{port}")) {
        headers.insert(TARGET, target);
    }
    let mut response = crate::fleet::primary::forward(app, node, req, Some("forward")).await;
    mark_fleet_error(&mut response);
    response
}

/// Marks a response that the fleet layer made, not the worker's listener,
/// as a Spawnbox error.
pub fn mark_fleet_error(response: &mut Response) {
    let headers = response.headers();
    if headers.contains_key(SANDBOX) || headers.contains_key(ERROR) {
        return;
    }
    let code = if response.status() == StatusCode::SERVICE_UNAVAILABLE {
        Code::NodeUnreachable
    } else {
        Code::Internal
    };
    response
        .headers_mut()
        .insert(ERROR, HeaderValue::from_static(code.as_str()));
}

/// `GET /v1/sandboxes/{id}/ports/{port}/ready`
#[derive(Debug, Deserialize, Serialize)]
pub struct Readiness {
    pub ready: bool,
    pub generation: i64,
    pub state: String,
    pub reason: Option<String>,
}

/// Whether `port` of sandbox `id`, which this host runs, takes traffic. A
/// zero `wait` does not wake the sandbox; a longer one wakes it and waits
/// up to `wait` for the port to be ready.
pub async fn readiness(
    app: &App,
    id: &str,
    port: u16,
    wait: Duration,
    origin: &Origin,
) -> Result<Readiness, ApiError> {
    let row = app.db.get_sandbox(id)?.ok_or_else(ApiError::not_found)?;
    let not_ready = |reason: String, generation: i64, state: String| Readiness {
        ready: false,
        generation,
        state,
        reason: Some(reason),
    };
    if !published(app, id, port)? {
        return Ok(not_ready(
            format!("port {port}{NOT_PUBLISHED}"),
            row.generation,
            row.state,
        ));
    }
    if app.gateway.draining(id) {
        return Ok(not_ready(DRAINING.into(), row.generation, row.state));
    }
    if wait.is_zero() && row.state != state::RUNNING {
        let reason = format!("the sandbox is {}", row.state);
        return Ok(not_ready(reason, row.generation, row.state));
    }
    let opened = within(WAKE_LIMIT, "wake", app.sandboxes.open(id, origin)).await?;
    let generation = opened.busy.generation();
    let reason = wait_ready(app, &opened.channel, id, port, wait).await;
    Ok(Readiness {
        ready: reason.is_none(),
        generation,
        state: state::RUNNING.into(),
        reason,
    })
}

/// Waits up to `wait` for `port` to be ready. A service port is ready when
/// its service is healthy; another port when it takes a connection.
/// Returns why it is not ready, if it is not.
async fn wait_ready(
    app: &App,
    channel: &tonic::transport::Channel,
    id: &str,
    port: u16,
    wait: Duration,
) -> Option<String> {
    if let Some(name) = app.sandboxes.service_on_port(id, port) {
        let healthy = app.sandboxes.wait_healthy_for(channel, &name, wait).await;
        return (!healthy).then(|| format!("service {name:?} on port {port} is not healthy"));
    }
    let deadline = Instant::now() + wait;
    loop {
        let reason = match crate::preview::dial(channel.clone(), port).await {
            Ok(_) => return None,
            Err(error) => error.message,
        };
        if Instant::now() + READY_POLL >= deadline {
            return Some(reason);
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

/// Starts a drain of sandbox `id`, which this host runs or keeps. New
/// forwarded and preview requests get `503 draining` at once; `then` runs
/// once no request is in flight, or at the deadline.
pub fn drain(
    app: &AppState,
    id: &str,
    req: &DrainRequest,
    origin: &Origin,
) -> Result<(), ApiError> {
    let timeout = req.timeout()?;
    let row = app.db.get_sandbox(id)?.ok_or_else(ApiError::not_found)?;
    let serial = app.gateway.begin_drain(id, timeout, req.then, now_ms())?;
    app.sandboxes.event(
        "sandbox.drain_started",
        origin,
        &row.tenant,
        id,
        json!({ "timeout_s": timeout.as_secs(), "then": req.then.as_str() }),
    );
    let (app, id, then, origin) = (Arc::clone(app), id.to_owned(), req.then, origin.clone());
    let deadline = Instant::now() + timeout;
    tokio::spawn(async move {
        loop {
            if !app.gateway.drain_is(&id, serial) {
                return;
            }
            if app.gateway.in_flight(&id) == 0 || Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let in_flight = app.gateway.in_flight(&id);
        let running = app
            .db
            .get_sandbox(&id)
            .ok()
            .flatten()
            .is_some_and(|row| row.state == state::RUNNING);
        // Stopping the VM ends what is left; with `none` it runs on.
        let (closed, done) = match then {
            Then::None => (0, Ok(())),
            Then::Pause if !running => (0, Ok(())),
            Then::Pause => (in_flight, app.sandboxes.pause(&id, &origin).await.map(drop)),
            Then::Delete => {
                let done = app.sandboxes.delete(&id, &origin).await;
                app.gateway.undrain(&id);
                (in_flight, done)
            }
        };
        let error = done.err().map(|e| e.message);
        if let Some(error) = &error {
            eprintln!("drain of {id}: {} failed: {error}", then.as_str());
        }
        app.sandboxes.event(
            "sandbox.drained",
            &origin,
            &row.tenant,
            &id,
            json!({ "in_flight": in_flight, "closed": closed, "then": then.as_str(), "error": error }),
        );
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_name_a_sandbox_and_a_port() {
        assert_eq!(
            Target::parse("sbx_0123456789abcdef:8000").unwrap(),
            Target::Port {
                sandbox: "sbx_0123456789abcdef".into(),
                port: 8000
            }
        );
        for bad in [
            "",
            "sbx_0123456789abcdef",
            "sbx_0123456789abcdef:0",
            "sbx_0123456789abcdef:65536",
            "sbx_0123456789abcdef:http",
            "tpl_0123456789abcdef:80",
            "../x:80",
        ] {
            let error = Target::parse(bad).unwrap_err();
            assert_eq!(error.code, Code::InvalidRequest, "{bad}");
        }
    }

    #[test]
    fn wake_modes_decide_which_states_wake() {
        let admit = |wake: &str, state: &str| {
            Wake::parse(Some(wake))
                .unwrap()
                .admit(state)
                .map_err(|e| e.code.as_str())
        };
        assert_eq!(admit("any", "running"), Ok(false));
        assert_eq!(admit("never", "running"), Ok(false));
        assert_eq!(admit("any", "paused"), Ok(true));
        assert_eq!(admit("paused", "paused"), Ok(true));
        assert_eq!(admit("never", "paused"), Err("sandbox_paused"));
        assert_eq!(admit("any", "cold"), Ok(true));
        assert_eq!(admit("any", "starting"), Ok(true));
        assert_eq!(admit("paused", "cold"), Err("sandbox_cold"));
        assert_eq!(admit("never", "cold"), Err("sandbox_cold"));
        assert_eq!(admit("any", "deleted"), Err("not_found"));
        assert_eq!(Wake::parse(None).unwrap(), Wake::Any);
        assert_eq!(
            Wake::parse(Some("always")).unwrap_err().code,
            Code::InvalidRequest
        );
    }

    #[test]
    fn response_timeouts_default_to_a_minute_and_stay_under_the_cap() {
        let max = Duration::from_secs(600);
        assert_eq!(
            response_timeout(None, max).unwrap(),
            Duration::from_secs(60)
        );
        assert_eq!(
            response_timeout(None, Duration::from_secs(5)).unwrap(),
            Duration::from_secs(5)
        );
        assert_eq!(
            response_timeout(Some("1500"), max).unwrap(),
            Duration::from_millis(1500)
        );
        for bad in ["0", "-1", "600001", "soon"] {
            assert_eq!(
                response_timeout(Some(bad), max).unwrap_err().code,
                Code::InvalidRequest,
                "{bad}"
            );
        }
    }

    #[test]
    fn only_spawnbox_headers_are_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(KEY, HeaderValue::from_static("sbx_org_secret"));
        headers.insert(TARGET, HeaderValue::from_static("sbx_a:80"));
        headers.insert("X-Spawnbox-Anything", HeaderValue::from_static("1"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer app"),
        );
        headers.insert(header::COOKIE, HeaderValue::from_static("session=abc"));
        headers.insert(header::HOST, HeaderValue::from_static("app.example.com"));
        strip(&mut headers);
        let mut left: Vec<_> = headers.keys().map(|k| k.as_str().to_owned()).collect();
        left.sort();
        assert_eq!(left, ["authorization", "cookie", "host"]);
    }

    fn key(db: &Db, scopes: Option<&str>) -> String {
        let key = ids::new_key(false).unwrap();
        db.insert_key(&key, None, scopes, None, 1).unwrap();
        key.secret
    }

    fn with_key(key: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(KEY, HeaderValue::from_str(key).unwrap());
        headers
    }

    #[test]
    fn only_keys_with_the_forward_scope_pass() {
        let db = Db::memory().unwrap();
        let gateway = Gateway::new(Settings::default());
        let now = Instant::now();
        let check = |headers: &HeaderMap| {
            gateway
                .authenticate(&db, headers, now)
                .map(|caller| caller.scopes)
                .map_err(|e| e.code)
        };
        assert_eq!(check(&HeaderMap::new()), Err(Code::Unauthorized));
        assert_eq!(check(&with_key("not-a-key")), Err(Code::Unauthorized));
        assert_eq!(
            check(&with_key("sbx_org_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
            Err(Code::Unauthorized)
        );
        let reader = key(&db, Some(r#"["sandboxes:read","sandboxes:write"]"#));
        assert_eq!(check(&with_key(&reader)), Err(Code::Forbidden));
        let forwarder = key(&db, Some(r#"["sandboxes:forward"]"#));
        assert_eq!(
            check(&with_key(&forwarder)),
            Ok(vec![Scope::SandboxesForward])
        );
    }

    #[test]
    fn a_forward_only_key_can_call_no_other_api() {
        let db = Db::memory().unwrap();
        let secret = key(&db, Some(r#"["sandboxes:forward"]"#));
        let caller =
            Caller::from_key(&db.find_key(&ids::hash_key(&secret)).unwrap().unwrap()).unwrap();
        for (method, path) in [
            ("GET", "/v1/sandboxes"),
            ("POST", "/v1/sandboxes"),
            ("GET", "/v1/sandboxes/sbx_a/ports"),
            ("POST", "/v1/sandboxes/sbx_a/exec"),
            ("GET", "/v1/usage"),
        ] {
            let scope = crate::tenancy::required_scope(method, path);
            assert_eq!(
                caller.require(scope).unwrap_err().code,
                Code::Forbidden,
                "{method} {path}"
            );
        }
    }

    #[test]
    fn revoked_keys_stop_working_once_the_cache_expires() {
        let db = Db::memory().unwrap();
        let gateway = Gateway::new(Settings::default());
        let secret = key(&db, Some(r#"["sandboxes:forward"]"#));
        let id = db.find_key(&ids::hash_key(&secret)).unwrap().unwrap().id;
        let start = Instant::now();
        let headers = with_key(&secret);
        assert!(gateway.authenticate(&db, &headers, start).is_ok());
        db.revoke_key(&id, 2).unwrap();
        assert!(
            gateway
                .authenticate(&db, &headers, start + Duration::from_secs(4))
                .is_ok()
        );
        assert_eq!(
            gateway
                .authenticate(&db, &headers, start + Duration::from_secs(5))
                .unwrap_err()
                .code,
            Code::Unauthorized
        );
    }

    #[test]
    fn each_sandbox_takes_a_bounded_number_of_requests() {
        let gateway = Gateway::new(Settings {
            max_in_flight: 2,
            ..Settings::default()
        });
        let first = gateway.enter("sbx_a").unwrap();
        let _second = gateway.enter("sbx_a").unwrap();
        let refused = gateway.enter("sbx_a").unwrap_err();
        assert_eq!(refused.code, Code::TooManyRequests);
        assert_eq!(refusal(refused).headers()[header::RETRY_AFTER], "1");
        assert!(gateway.enter("sbx_b").is_ok());
        drop(first);
        assert!(gateway.enter("sbx_a").is_ok());
    }

    #[tokio::test]
    async fn wakes_wait_for_a_slot_then_give_up() {
        let gateway = Gateway::new(Settings {
            max_wakes: 2,
            wake_queue: Duration::from_millis(50),
            ..Settings::default()
        });
        let first = gateway.wake_slot().await.unwrap();
        let _second = gateway.wake_slot().await.unwrap();
        let busy = gateway.wake_slot().await.unwrap_err();
        assert_eq!(busy.code, Code::WakeBusy);
        let response = refusal(busy);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[ERROR], "wake_busy");
        assert_eq!(response.headers()[header::RETRY_AFTER], "5");
        let waiting = tokio::spawn({
            let wakes = Arc::clone(&gateway.wakes);
            async move { wakes.acquire_owned().await.is_ok() }
        });
        drop(first);
        assert!(waiting.await.unwrap());
    }

    /// Wakes `id` as a forwarded request does: in its turn, and in a slot
    /// only if it still needs a wake. Returns whether it took a slot.
    async fn wake_like_a_request(
        gateway: &Gateway,
        id: &str,
        awake: &Mutex<Vec<String>>,
    ) -> Result<bool, Code> {
        let _turn = gateway.wake_turn(id).await.map_err(|e| e.code)?;
        if awake.lock().unwrap().iter().any(|a| a == id) {
            return Ok(false);
        }
        let _slot = gateway.wake_slot().await.map_err(|e| e.code)?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        awake.lock().unwrap().push(id.to_owned());
        Ok(true)
    }

    #[tokio::test]
    async fn a_burst_to_one_sandbox_takes_one_wake_slot() {
        let gateway = Arc::new(Gateway::new(Settings {
            max_wakes: 2,
            wake_queue: Duration::from_millis(50),
            ..Settings::default()
        }));
        let awake = Arc::new(Mutex::new(Vec::new()));
        let burst: Vec<_> = (0..8)
            .map(|i| {
                let (gateway, awake) = (Arc::clone(&gateway), Arc::clone(&awake));
                let id = if i == 7 { "sbx_b" } else { "sbx_a" };
                tokio::spawn(async move { wake_like_a_request(&gateway, id, &awake).await })
            })
            .collect();
        let mut slots = 0;
        for request in burst {
            slots += usize::from(request.await.unwrap().expect("no wake_busy"));
        }
        assert_eq!(slots, 2, "one wake of each sandbox");
        assert!(
            gateway.waking.lock().unwrap().is_empty(),
            "turns are cleaned up"
        );
    }

    #[tokio::test]
    async fn only_small_requests_are_kept_to_send_again() {
        let call = |headers: &[(&str, &str)], body: &'static str| {
            let mut builder = Request::builder().method("POST").uri("/upload");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            builder.body(Body::from(body)).unwrap()
        };
        let (first, again) = replayable(call(&[("content-length", "5")], "hello"))
            .await
            .unwrap();
        let read = |r: Request| async { axum::body::to_bytes(r.into_body(), 64).await.unwrap() };
        assert_eq!(read(again.expect("a copy")).await, "hello");
        assert_eq!(read(first).await, "hello");
        for headers in [
            &[("transfer-encoding", "chunked")][..],
            &[("content-length", "2000000")][..],
            &[("upgrade", "websocket")][..],
        ] {
            let (_, again) = replayable(call(headers, "")).await.unwrap();
            assert!(again.is_none(), "{headers:?}");
        }
    }

    #[test]
    fn fleet_errors_are_marked_and_app_responses_are_not() {
        let mut gone = (StatusCode::SERVICE_UNAVAILABLE, "down").into_response();
        mark_fleet_error(&mut gone);
        assert_eq!(gone.headers()[ERROR], "node_unreachable");
        let mut app = (StatusCode::SERVICE_UNAVAILABLE, "app says no").into_response();
        app.headers_mut()
            .insert(SANDBOX, HeaderValue::from_static("sbx_a"));
        mark_fleet_error(&mut app);
        assert!(!app.headers().contains_key(ERROR));
    }

    #[test]
    fn a_drain_refuses_new_requests_and_counts_the_old_ones() {
        let gateway = Gateway::new(Settings::default());
        let old = gateway.admit("sbx_a").unwrap();
        let serial = gateway
            .begin_drain("sbx_a", Duration::from_secs(30), Then::Pause, 1_000)
            .unwrap();
        assert!(gateway.draining("sbx_a"));
        assert!(gateway.drain_is("sbx_a", serial));
        assert_eq!(gateway.admit("sbx_a").unwrap_err().code, Code::Draining);
        assert!(
            gateway.admit("sbx_b").is_ok(),
            "other sandboxes take traffic"
        );
        let view = gateway.drain_view("sbx_a").unwrap();
        assert_eq!((view.in_flight, view.then), (1, "pause"));
        assert_eq!(view.deadline, rfc3339_ms(31_000));
        drop(old);
        assert_eq!(gateway.in_flight("sbx_a"), 0);
        assert_eq!(
            gateway
                .begin_drain("sbx_a", Duration::from_secs(1), Then::None, 2_000)
                .unwrap_err()
                .code,
            Code::Conflict
        );
        assert!(gateway.undrain("sbx_a"));
        assert!(!gateway.drain_is("sbx_a", serial), "the task stops");
        assert!(!gateway.undrain("sbx_a"));
        assert!(gateway.admit("sbx_a").is_ok());
        assert!(gateway.drain_view("sbx_a").is_none());
    }

    #[test]
    fn drain_requests_default_to_30_s_and_no_action() {
        let req: DrainRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(
            (req.timeout().unwrap(), req.then),
            (Duration::from_secs(30), Then::None)
        );
        let req: DrainRequest = serde_json::from_str(r#"{"timeout_s":0}"#).unwrap();
        assert_eq!(req.timeout().unwrap_err().code, Code::InvalidRequest);
        let req: DrainRequest = serde_json::from_str(r#"{"timeout_s":3601}"#).unwrap();
        assert_eq!(req.timeout().unwrap_err().code, Code::InvalidRequest);
        let req: DrainRequest = serde_json::from_str(r#"{"then":"delete"}"#).unwrap();
        assert_eq!(req.then, Then::Delete);
        assert!(serde_json::from_str::<DrainRequest>(r#"{"then":"stop"}"#).is_err());
    }

    #[test]
    fn endpoint_targets_name_a_valid_endpoint() {
        assert_eq!(
            Target::parse("endpoint:web-2").unwrap(),
            Target::Endpoint {
                name: "web-2".into()
            }
        );
        for bad in ["endpoint:", "endpoint:Web", "endpoint:a/b"] {
            assert_eq!(
                Target::parse(bad).unwrap_err().code,
                Code::InvalidRequest,
                "{bad}"
            );
        }
    }
}
