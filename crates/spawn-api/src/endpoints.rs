//! Endpoints: stable names for one sandbox port, which a caller switches to
//! a new sandbox in one compare-and-set step.
//!
//! The switch is one conditional update of the endpoint row. Forwarded
//! requests to `endpoint:NAME` read the row, so each one is served by
//! exactly one generation of the endpoint. The old target drains only after
//! `--endpoint-propagation-s`, so hosts that read the row just before the
//! switch still reach it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::db::{Db, Endpoint, state};
use crate::events::Origin;
use crate::gateway::{READY_POLL, Readiness, Then};
use crate::ids;
use crate::model::{ApiError, Code, rfc3339_ms};
use crate::runtime::now_ms;
use crate::server::{App, AppState, TenantQuery, namespace, parse};
use crate::tenancy::{Caller, DEFAULT_TENANT};

/// The longest `wait_s` of one readiness call.
const READY_CALL: u64 = 120;

/// 1 to 63 of `a-z`, `0-9` and `-`.
pub fn valid_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateEndpoint {
    pub name: String,
    pub sandbox: String,
    pub port: u16,
}

/// What happens to the old target after a switch.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Previous {
    pub drain_s: Option<u64>,
    #[serde(default = "pause")]
    pub then: Then,
}

fn pause() -> Then {
    Then::Pause
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "serde's default for a field that `null` turns off"
)]
fn default_previous() -> Option<Previous> {
    Some(Previous {
        drain_s: None,
        then: Then::Pause,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchEndpoint {
    pub sandbox: String,
    pub port: u16,
    pub if_generation: i64,
    pub ready_wait_s: Option<u64>,
    /// Missing: drain for 30 s, then pause. `null`: leave it alone.
    #[serde(default = "default_previous")]
    pub previous: Option<Previous>,
}

impl SwitchEndpoint {
    fn ready_wait(&self) -> Result<Duration, ApiError> {
        match self.ready_wait_s.unwrap_or(60) {
            s @ 0..=300 => Ok(Duration::from_secs(s)),
            _ => Err(ApiError::invalid("ready_wait_s must be 0 to 300")),
        }
    }
}

impl Previous {
    fn drain_s(&self) -> Result<u64, ApiError> {
        match self.drain_s.unwrap_or(30) {
            s @ 1..=3600 => Ok(s),
            _ => Err(ApiError::invalid("previous.drain_s must be 1 to 3600")),
        }
    }
}

fn view(app: &App, endpoint: &Endpoint) -> Value {
    let target_state = app
        .db
        .get_sandbox(&endpoint.sandbox)
        .ok()
        .flatten()
        .map_or_else(|| state::DELETED.to_owned(), |row| row.state);
    json!({
        "name": endpoint.name,
        "tenant": endpoint.tenant,
        "sandbox": endpoint.sandbox,
        "port": endpoint.port,
        "generation": endpoint.generation,
        "target_state": target_state,
        "created_at": rfc3339_ms(endpoint.created_at),
        "updated_at": rfc3339_ms(endpoint.updated_at),
    })
}

fn no_endpoint(name: &str) -> ApiError {
    ApiError::new(Code::NotFound, format!("no endpoint {name:?}"))
}

/// The sandbox a new target names, if the caller may use it in `tenant`.
fn target(
    app: &App,
    caller: &Caller,
    tenant: Option<&str>,
    sandbox: &str,
) -> Result<String, ApiError> {
    let row = ids::is_valid_id("sbx", sandbox)
        .then(|| app.db.get_sandbox(sandbox))
        .transpose()?
        .flatten()
        .filter(|row| row.state != state::DELETED && caller.sees(&row.tenant))
        .ok_or_else(|| ApiError::new(Code::NotFound, format!("no sandbox {sandbox:?}")))?;
    if tenant.is_some_and(|tenant| tenant != row.tenant) {
        return Err(ApiError::invalid(
            "the sandbox is in another tenant than the endpoint",
        ));
    }
    Ok(row.tenant)
}

fn port(port: u16) -> Result<u16, ApiError> {
    if port == 0 {
        return Err(ApiError::invalid("port must be 1 to 65535"));
    }
    Ok(port)
}

/// `POST /v1/endpoints`. The endpoint is in the tenant of its sandbox.
pub async fn create(
    State(app): State<AppState>,
    axum::Extension(caller): axum::Extension<Caller>,
    axum::Extension(origin): axum::Extension<Origin>,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let req: CreateEndpoint = parse(&body)?;
    if !valid_name(&req.name) {
        return Err(ApiError::invalid("name must be 1 to 63 of a-z, 0-9 and -"));
    }
    let tenant = target(&app, &caller, None, &req.sandbox)?;
    let now = now_ms();
    let endpoint = Endpoint {
        tenant,
        name: req.name,
        sandbox: req.sandbox,
        port: port(req.port)?,
        generation: 1,
        created_at: now,
        updated_at: now,
    };
    if !app.db.insert_endpoint(&endpoint)? {
        return Err(ApiError::new(
            Code::Conflict,
            format!("endpoint {:?} exists", endpoint.name),
        ));
    }
    app.sandboxes.hub.record(
        "endpoint.created",
        &origin,
        Some(&endpoint.tenant),
        Some(&endpoint.sandbox),
        json!({ "name": endpoint.name, "port": endpoint.port }),
    );
    Ok((StatusCode::CREATED, Json(view(&app, &endpoint))))
}

pub async fn list(
    State(app): State<AppState>,
    axum::Extension(caller): axum::Extension<Caller>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let endpoints: Vec<Value> = app
        .db
        .list_endpoints(ns.as_deref())?
        .iter()
        .map(|endpoint| view(&app, endpoint))
        .collect();
    Ok(Json(json!({ "endpoints": endpoints })))
}

pub async fn get_one(
    State(app): State<AppState>,
    axum::Extension(caller): axum::Extension<Caller>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let tenant = ns.as_deref().unwrap_or(DEFAULT_TENANT);
    let endpoint = app
        .db
        .get_endpoint(tenant, &name)?
        .ok_or_else(|| no_endpoint(&name))?;
    Ok(Json(view(&app, &endpoint)))
}

pub async fn delete(
    State(app): State<AppState>,
    axum::Extension(caller): axum::Extension<Caller>,
    axum::Extension(origin): axum::Extension<Origin>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let tenant = ns.as_deref().unwrap_or(DEFAULT_TENANT);
    if !app.db.delete_endpoint(tenant, &name)? {
        return Err(no_endpoint(&name));
    }
    app.sandboxes.hub.record(
        "endpoint.deleted",
        &origin,
        Some(tenant),
        None,
        json!({ "name": name }),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/endpoints/{name}`: waits for the new target to be ready, then
/// switches the endpoint if it is still at `if_generation`.
pub async fn switch(
    State(app): State<AppState>,
    axum::Extension(caller): axum::Extension<Caller>,
    axum::Extension(origin): axum::Extension<Origin>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let req: SwitchEndpoint = parse(&body)?;
    let ready_wait = req.ready_wait()?;
    let drain_s = req.previous.as_ref().map(Previous::drain_s).transpose()?;
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let tenant = ns.as_deref().unwrap_or(DEFAULT_TENANT);
    let current = app
        .db
        .get_endpoint(tenant, &name)?
        .ok_or_else(|| no_endpoint(&name))?;
    if current.generation != req.if_generation {
        return Err(conflict(&current));
    }
    target(&app, &caller, Some(tenant), &req.sandbox)?;
    let port = port(req.port)?;
    let hosts = ThroughRouter {
        app: Arc::clone(&app),
        headers,
    };
    let switched = match switch_to(&app.db, &hosts, &current, &req, port, ready_wait).await {
        Ok(switched) => switched,
        Err(refused) => return Ok(*refused),
    };
    app.sandboxes.hub.record(
        "endpoint.switched",
        &origin,
        Some(tenant),
        Some(&switched.sandbox),
        json!({
            "name": name,
            "port": switched.port,
            "generation": switched.generation,
            "previous": { "sandbox": current.sandbox, "port": current.port },
        }),
    );
    if let (Some(previous), Some(drain_s)) = (req.previous, drain_s)
        && current.sandbox != switched.sandbox
    {
        drain_later(
            app.db.clone(),
            hosts,
            tenant.to_owned(),
            current.sandbox.clone(),
            (drain_s, previous.then),
            app.endpoint_propagation,
        );
    }
    let mut reply = view(&app, &switched);
    reply["previous"] = json!({ "sandbox": current.sandbox, "port": current.port });
    Ok(Json(reply).into_response())
}

/// Takes any drain off the new target, waits for it to be ready and
/// switches the endpoint if it is still at `if_generation`. Returns the
/// reply to send instead, if it does not switch.
async fn switch_to(
    db: &Db,
    hosts: &impl Hosts,
    current: &Endpoint,
    req: &SwitchEndpoint,
    port: u16,
    ready_wait: Duration,
) -> Result<Endpoint, Refused> {
    // A drain stays after its `then`, so a target that an earlier switch
    // drained takes traffic again only this way.
    hosts.undrain(&req.sandbox).await?;
    if !ready_wait.is_zero() {
        wait_ready(hosts, &req.sandbox, port, ready_wait).await?;
    }
    let switched = db
        .switch_endpoint(
            &current.tenant,
            &current.name,
            &req.sandbox,
            port,
            req.if_generation,
            now_ms(),
        )
        .map_err(|e| refuse(e.into()))?;
    let Some(switched) = switched else {
        let now = db
            .get_endpoint(&current.tenant, &current.name)
            .map_err(|e| refuse(e.into()))?
            .ok_or_else(|| refuse(no_endpoint(&current.name)))?;
        return Err(refuse(conflict(&now)));
    };
    // A drain from an earlier switch may have started during the wait.
    if let Err(reply) = hosts.undrain(&req.sandbox).await {
        eprintln!(
            "undrain {} after an endpoint switch: {}",
            req.sandbox,
            reply.status()
        );
    }
    Ok(switched)
}

fn conflict(endpoint: &Endpoint) -> ApiError {
    ApiError::new(
        Code::GenerationConflict,
        format!(
            "endpoint {:?} is at generation {}, with target {}:{}",
            endpoint.name, endpoint.generation, endpoint.sandbox, endpoint.port
        ),
    )
}

/// The reply to send instead of the one asked for.
type Refused = Box<Response>;

fn refuse(error: ApiError) -> Refused {
    Box::new(error.into_response())
}

/// What a switch asks of the host that runs a sandbox.
trait Hosts: Clone + Send + Sync + 'static {
    fn ready(
        &self,
        sandbox: &str,
        port: u16,
        wait_s: u64,
    ) -> impl Future<Output = Result<Readiness, Refused>> + Send;
    fn drain(
        &self,
        sandbox: &str,
        drain_s: u64,
        then: Then,
    ) -> impl Future<Output = Result<(), Refused>> + Send;
    /// Succeeds also if the sandbox is not draining.
    fn undrain(&self, sandbox: &str) -> impl Future<Output = Result<(), Refused>> + Send;
}

/// Sends API calls for a sandbox through this server's own router, with
/// the caller's key, so they reach the host that runs the sandbox.
#[derive(Clone)]
struct ThroughRouter {
    app: AppState,
    headers: HeaderMap,
}

impl ThroughRouter {
    async fn call(&self, method: Method, uri: &str, body: Value) -> Response {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(auth) = self.headers.get(header::AUTHORIZATION) {
            req = req.header(header::AUTHORIZATION, auth);
        }
        let req = match req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
        {
            Ok(req) => req,
            Err(error) => return ApiError::internal(error.to_string()).into_response(),
        };
        match crate::server::router(Arc::clone(&self.app))
            .oneshot(req)
            .await
        {
            Ok(response) => response,
            Err(never) => match never {},
        }
    }
}

impl Hosts for ThroughRouter {
    async fn ready(&self, sandbox: &str, port: u16, wait_s: u64) -> Result<Readiness, Refused> {
        let uri = format!("/v1/sandboxes/{sandbox}/ports/{port}/ready?wait_s={wait_s}");
        let reply = self.call(Method::GET, &uri, Value::Null).await;
        if !reply.status().is_success() {
            return Err(Box::new(reply));
        }
        let bytes = axum::body::to_bytes(reply.into_body(), 64 << 10)
            .await
            .map_err(|e| refuse(ApiError::internal(format!("read the readiness reply: {e}"))))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| refuse(ApiError::internal(format!("read the readiness reply: {e}"))))
    }

    async fn drain(&self, sandbox: &str, drain_s: u64, then: Then) -> Result<(), Refused> {
        let uri = format!("/v1/sandboxes/{sandbox}:drain");
        let body = json!({ "timeout_s": drain_s, "then": then });
        let reply = self.call(Method::POST, &uri, body).await;
        if !reply.status().is_success() {
            return Err(Box::new(reply));
        }
        Ok(())
    }

    async fn undrain(&self, sandbox: &str) -> Result<(), Refused> {
        let uri = format!("/v1/sandboxes/{sandbox}:undrain");
        let reply = self.call(Method::POST, &uri, json!({})).await;
        if reply.status().is_success() || reply.status() == StatusCode::CONFLICT {
            return Ok(());
        }
        Err(Box::new(reply))
    }
}

/// Waits for `port` of `sandbox` to be ready, waking it. Returns the reply
/// to send instead of switching, if it does not get ready.
async fn wait_ready(
    hosts: &impl Hosts,
    sandbox: &str,
    port: u16,
    wait: Duration,
) -> Result<(), Refused> {
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now()).as_secs();
        let readiness = hosts
            .ready(sandbox, port, left.clamp(1, READY_CALL))
            .await?;
        if readiness.ready {
            return Ok(());
        }
        let reason = readiness.reason.unwrap_or_default();
        if crate::gateway::lasting(&reason) || Instant::now() + READY_POLL >= deadline {
            return Err(refuse(ApiError::new(
                Code::NotReady,
                format!("port {port} of {sandbox} is not ready: {reason}"),
            )));
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

/// Drains the old target once every host has read the switch, unless an
/// endpoint targets it again by then.
fn drain_later(
    db: Db,
    hosts: impl Hosts,
    tenant: String,
    sandbox: String,
    (drain_s, then): (u64, Then),
    propagation: Duration,
) -> tokio::task::JoinHandle<()> {
    // An endpoint is in the tenant of its target.
    let targeted = move |db: &Db, sandbox: &str| {
        db.list_endpoints(Some(&tenant))
            .map(|all| all.iter().any(|e| e.sandbox == sandbox))
            .unwrap_or(true)
    };
    tokio::spawn(async move {
        tokio::time::sleep(propagation).await;
        if targeted(&db, &sandbox) {
            return;
        }
        if let Err(reply) = hosts.drain(&sandbox, drain_s, then).await {
            eprintln!(
                "drain {sandbox} after an endpoint switch: {}",
                reply.status()
            );
            return;
        }
        // A switch back to it may have committed while this drain started.
        if targeted(&db, &sandbox)
            && let Err(reply) = hosts.undrain(&sandbox).await
        {
            eprintln!(
                "undrain {sandbox} after an endpoint switch: {}",
                reply.status()
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn names_are_short_lowercase_words() {
        for good in ["a", "web", "api-v2", &"x".repeat(63)] {
            assert!(valid_name(good), "{good}");
        }
        for bad in ["", "Web", "a_b", "a.b", "a/b", &"x".repeat(64)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_missing_previous_drains_and_a_null_one_does_not() {
        let missing: SwitchEndpoint =
            serde_json::from_str(r#"{"sandbox":"sbx_a","port":80,"if_generation":1}"#).unwrap();
        assert_eq!(missing.previous, default_previous());
        assert_eq!(missing.ready_wait().unwrap(), Duration::from_secs(60));
        let null: SwitchEndpoint = serde_json::from_str(
            r#"{"sandbox":"sbx_a","port":80,"if_generation":1,"previous":null,"ready_wait_s":0}"#,
        )
        .unwrap();
        assert_eq!(null.previous, None);
        assert!(null.ready_wait().unwrap().is_zero());
        let delete: SwitchEndpoint = serde_json::from_str(
            r#"{"sandbox":"sbx_a","port":80,"if_generation":1,"previous":{"drain_s":5,"then":"delete"}}"#,
        )
        .unwrap();
        let previous = delete.previous.unwrap();
        assert_eq!(
            (previous.drain_s().unwrap(), previous.then),
            (5, Then::Delete)
        );
        let long: SwitchEndpoint = serde_json::from_str(
            r#"{"sandbox":"sbx_a","port":80,"if_generation":1,"ready_wait_s":301}"#,
        )
        .unwrap();
        assert_eq!(long.ready_wait().unwrap_err().code, Code::InvalidRequest);
        assert!(
            serde_json::from_str::<SwitchEndpoint>(r#"{"sandbox":"sbx_a","port":80}"#).is_err(),
            "if_generation is required"
        );
    }

    fn endpoint(name: &str, sandbox: &str) -> Endpoint {
        Endpoint {
            tenant: "default".into(),
            name: name.into(),
            sandbox: sandbox.into(),
            port: 8000,
            generation: 1,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn two_switches_from_one_generation_let_one_win() {
        let db = Db::memory().unwrap();
        assert!(db.insert_endpoint(&endpoint("web", "sbx_old")).unwrap());
        assert!(!db.insert_endpoint(&endpoint("web", "sbx_other")).unwrap());
        let first = db
            .switch_endpoint("default", "web", "sbx_new", 9000, 1, 2)
            .unwrap()
            .unwrap();
        assert_eq!(
            (first.sandbox.as_str(), first.port, first.generation),
            ("sbx_new", 9000, 2)
        );
        assert_eq!(
            db.switch_endpoint("default", "web", "sbx_late", 9000, 1, 3)
                .unwrap(),
            None
        );
        let now = db.get_endpoint("default", "web").unwrap().unwrap();
        assert_eq!((now.sandbox.as_str(), now.generation), ("sbx_new", 2));
        assert_eq!(db.list_endpoints(Some("default")).unwrap(), vec![now]);
        assert!(db.list_endpoints(Some("other")).unwrap().is_empty());
        assert!(db.delete_endpoint("default", "web").unwrap());
        assert!(!db.delete_endpoint("default", "web").unwrap());
        assert_eq!(
            db.switch_endpoint("default", "web", "sbx_new", 9000, 2, 4)
                .unwrap(),
            None
        );
    }

    /// Hosts that keep drains in a real gateway. Every published port is
    /// ready unless the sandbox is draining or listed in `starting`.
    #[derive(Clone, Default)]
    struct Fake(Arc<FakeHost>);

    struct FakeHost {
        gateway: crate::gateway::Gateway,
        unpublished: std::sync::Mutex<Vec<String>>,
        starting: std::sync::Mutex<Vec<String>>,
        ready_calls: std::sync::atomic::AtomicUsize,
    }

    impl Default for FakeHost {
        fn default() -> Self {
            Self {
                gateway: crate::gateway::Gateway::new(crate::gateway::Settings::default()),
                unpublished: std::sync::Mutex::default(),
                starting: std::sync::Mutex::default(),
                ready_calls: std::sync::atomic::AtomicUsize::default(),
            }
        }
    }

    impl Hosts for Fake {
        async fn ready(&self, sandbox: &str, port: u16, _: u64) -> Result<Readiness, Refused> {
            self.0
                .ready_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let has = |list: &std::sync::Mutex<Vec<String>>| {
                list.lock().unwrap().iter().any(|s| s == sandbox)
            };
            let reason = if has(&self.0.unpublished) {
                Some(format!("port {port} is not published"))
            } else if self.0.gateway.draining(sandbox) {
                Some("the sandbox is draining".to_owned())
            } else if has(&self.0.starting) {
                Some(format!("connection to port {port} refused"))
            } else {
                None
            };
            Ok(Readiness {
                ready: reason.is_none(),
                generation: 1,
                state: "running".into(),
                reason,
            })
        }

        async fn drain(&self, sandbox: &str, drain_s: u64, then: Then) -> Result<(), Refused> {
            self.0
                .gateway
                .begin_drain(sandbox, Duration::from_secs(drain_s), then, 1)
                .map(drop)
                .map_err(refuse)
        }

        async fn undrain(&self, sandbox: &str) -> Result<(), Refused> {
            self.0.gateway.undrain(sandbox);
            Ok(())
        }
    }

    fn to(sandbox: &str, if_generation: i64) -> SwitchEndpoint {
        SwitchEndpoint {
            sandbox: sandbox.into(),
            port: 8000,
            if_generation,
            ready_wait_s: None,
            previous: default_previous(),
        }
    }

    async fn error_code(reply: Refused) -> String {
        let bytes = axum::body::to_bytes(reply.into_body(), 1 << 16)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        body["error"]["code"].as_str().unwrap().to_owned()
    }

    /// Switches `web` from `sbx_old` to `sbx_new`, and lets the old target
    /// drain and pause as a switch does.
    async fn switched_once(db: &Db, hosts: &Fake) -> Endpoint {
        db.insert_endpoint(&endpoint("web", "sbx_old")).unwrap();
        let current = db.get_endpoint("default", "web").unwrap().unwrap();
        let new = switch_to(
            db,
            hosts,
            &current,
            &to("sbx_new", 1),
            8000,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        drain_later(
            db.clone(),
            hosts.clone(),
            "default".into(),
            "sbx_old".into(),
            (30, Then::Pause),
            Duration::ZERO,
        )
        .await
        .unwrap();
        assert!(hosts.0.gateway.draining("sbx_old"));
        new
    }

    #[tokio::test]
    async fn switching_back_to_a_drained_target_takes_it_out_of_the_drain() {
        for wait in [Duration::from_secs(5), Duration::ZERO] {
            let (db, hosts) = (Db::memory().unwrap(), Fake::default());
            let current = switched_once(&db, &hosts).await;
            let started = Instant::now();
            let back = switch_to(&db, &hosts, &current, &to("sbx_old", 2), 8000, wait)
                .await
                .unwrap();
            assert!(started.elapsed() < Duration::from_secs(1), "{wait:?}");
            assert_eq!((back.sandbox.as_str(), back.generation), ("sbx_old", 3));
            assert!(!hosts.0.gateway.draining("sbx_old"), "{wait:?}");
        }
    }

    #[tokio::test]
    async fn a_late_drain_leaves_a_target_that_an_endpoint_switched_back_to() {
        let (db, hosts) = (Db::memory().unwrap(), Fake::default());
        db.insert_endpoint(&endpoint("web", "sbx_old")).unwrap();
        let current = db.get_endpoint("default", "web").unwrap().unwrap();
        let wait = Duration::ZERO;
        let new = switch_to(&db, &hosts, &current, &to("sbx_new", 1), 8000, wait)
            .await
            .unwrap();
        let old_drain = drain_later(
            db.clone(),
            hosts.clone(),
            "default".into(),
            "sbx_old".into(),
            (30, Then::Delete),
            Duration::from_millis(200),
        );
        switch_to(&db, &hosts, &new, &to("sbx_old", 2), 8000, wait)
            .await
            .unwrap();
        let new_drain = drain_later(
            db.clone(),
            hosts.clone(),
            "default".into(),
            "sbx_new".into(),
            (30, Then::Delete),
            Duration::from_millis(200),
        );
        old_drain.await.unwrap();
        new_drain.await.unwrap();
        assert!(!hosts.0.gateway.draining("sbx_old"));
        assert!(hosts.0.gateway.draining("sbx_new"));
    }

    #[tokio::test]
    async fn readiness_that_cannot_change_fails_at_once() {
        let hosts = Fake::default();
        hosts.0.unpublished.lock().unwrap().push("sbx_a".into());
        let started = Instant::now();
        let reply = wait_ready(&hosts, "sbx_a", 8000, Duration::from_secs(3))
            .await
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(error_code(reply).await, "not_ready");
        assert_eq!(
            hosts
                .0
                .ready_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn readiness_that_may_change_is_asked_again_after_a_pause() {
        let hosts = Fake::default();
        hosts.0.starting.lock().unwrap().push("sbx_a".into());
        let reply = wait_ready(&hosts, "sbx_a", 8000, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error_code(reply).await, "not_ready");
        let calls = hosts
            .0
            .ready_calls
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!((2..=5).contains(&calls), "{calls} calls in 1 s");
    }

    #[test]
    fn concurrent_switches_commit_exactly_once() {
        let db = Db::memory().unwrap();
        db.insert_endpoint(&endpoint("api", "sbx_old")).unwrap();
        let won: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let db = db.clone();
                    scope.spawn(move || {
                        db.switch_endpoint("default", "api", &format!("sbx_{i}"), 80, 1, 5)
                            .unwrap()
                            .is_some()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum()
        });
        assert_eq!(won, 1);
        let now = db.get_endpoint("default", "api").unwrap().unwrap();
        assert_eq!(now.generation, 2);
    }
}
