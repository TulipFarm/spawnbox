//! The forward listener, for trusted HTTP gateways in front of sandbox
//! ports.
//!
//! A gateway sends the original request with `X-Spawnbox-Key` (an API key
//! with `sandboxes:forward`) and `X-Spawnbox-Target: sbx_ID:PORT`. The
//! listener wakes the sandbox if needed, within a per-host wake limit and a
//! per-sandbox in-flight limit, and forwards the request to the port
//! through the same vsock tunnel as previews. Every `X-Spawnbox-*` header
//! is removed before the app sees the request, and replaced on the way back.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::db::{Db, state};
use crate::events::Origin;
use crate::fleet::Role;
use crate::model::{ApiError, Code};
use crate::runtime::Published;
use crate::server::{App, AppState};
use crate::tenancy::{Caller, Scope};
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
    Port { sandbox: String, port: u16 },
}

impl Target {
    pub fn parse(text: &str) -> Result<Self, ApiError> {
        let bad = || ApiError::invalid("X-Spawnbox-Target must be sbx_ID:PORT");
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

/// Wake slots, in-flight counts and verified keys of one host.
pub struct Gateway {
    pub settings: Settings,
    wakes: Arc<Semaphore>,
    in_flight: Arc<Mutex<HashMap<String, u32>>>,
    keys: Mutex<HashMap<Vec<u8>, (Instant, Caller)>>,
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
            in_flight: Arc::default(),
            keys: Mutex::default(),
        }
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
    sandbox: String,
    port: u16,
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
        let Target::Port { sandbox, port } = Target::parse(target)?;
        let expect = text(EXPECT_GENERATION)?
            .map(|n| {
                n.parse::<i64>()
                    .map_err(|_| ApiError::invalid("bad X-Spawnbox-Expect-Generation"))
            })
            .transpose()?;
        Ok(Self {
            caller,
            sandbox,
            port,
            wake: Wake::parse(text(WAKE)?)?,
            timeout: response_timeout(text(TIMEOUT_MS)?, app.gateway.settings.max_response)?,
            expect,
        })
    }
}

async fn serve(app: &App, req: Request) -> Result<Response, ApiError> {
    let ask = Ask::read(app, req.headers())?;
    let (req, again) = replayable(req).await?;
    let first = route(app, &ask, req).await?;
    match again {
        Some(again) if is_stale(&first) => route(app, &ask, again).await,
        _ => Ok(first),
    }
}

pub fn is_stale(response: &Response) -> bool {
    response
        .headers()
        .get(ERROR)
        .is_some_and(|code| code.as_bytes() == Code::StaleRoute.as_str().as_bytes())
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
async fn route(app: &App, ask: &Ask, req: Request) -> Result<Response, ApiError> {
    let id = &ask.sandbox;
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
        return Ok(to_worker(app, &node, row.generation, req).await);
    }
    if !published(app, id, ask.port)? {
        return Err(ApiError::new(
            Code::NotFound,
            format!("port {} of this sandbox is not published", ask.port),
        ));
    }
    let in_flight = app.gateway.enter(id)?;
    let origin = Origin::of_call(&ask.caller.key, None, None)?;
    let slot = if ask.wake.admit(&row.state)? {
        let slot = app.gateway.wake_slot().await?;
        metrics::inc("spawnbox_forward_wakes_total", vec![]);
        if matches!(app.role, Role::Primary(_)) {
            within(
                WAKE_LIMIT,
                "wake",
                crate::fleet::primary::wake_cold(app, id, false),
            )
            .await?;
            if let Some(node) = crate::fleet::primary::node_of(app, id) {
                drop((slot, in_flight));
                let generation = app.db.get_sandbox(id)?.map_or(0, |row| row.generation);
                return Ok(to_worker(app, &node, generation, req).await);
            }
        }
        Some(slot)
    } else {
        None
    };
    let opened = within(WAKE_LIMIT, "wake", app.sandboxes.open(id, &origin)).await?;
    drop(slot);
    if let Some(name) = app.sandboxes.service_on_port(id, ask.port)
        && !app.sandboxes.wait_healthy(&opened.channel, &name).await
    {
        return Err(ApiError::new(
            Code::NotReady,
            format!("service {name:?} on port {} is not healthy", ask.port),
        ));
    }
    let generation = opened.busy.generation();
    let mut req = req;
    strip(req.headers_mut());
    let forwarded = crate::preview::forward(
        opened.channel,
        (opened.busy, in_flight),
        ask.port,
        req,
        None,
    );
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
async fn to_worker(app: &App, node: &str, generation: i64, mut req: Request) -> Response {
    req.headers_mut()
        .insert(EXPECT_GENERATION, HeaderValue::from(generation));
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
}
