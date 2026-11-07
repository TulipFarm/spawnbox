//! Published ports: the `/ports` API and the preview listener that forwards
//! HTTP and WebSocket traffic into sandboxes.
//!
//! The preview listener routes by the first label of `Host`
//! (`3000-sbx-...`). Each request opens a stream to the guest agent over
//! vsock, which connects to the port inside the VM, so servers bound to
//! localhost work and no sandbox address is exposed.

use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, Request, State};
use axum::http::uri::PathAndQuery;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use spawn_proto::guest::v1::port_input::Input;
use spawn_proto::guest::v1::ports_client::PortsClient;
use spawn_proto::guest::v1::{PortInput, PortOpen, PortOutput};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::{Code as GrpcCode, Streaming};

use crate::events::Origin;
use crate::model::{ApiError, Code, rfc3339_ms};
use crate::ports::{self, Access, COOKIE, Publish, TOKEN_PARAM};
use crate::runtime::{Busy, Published, now_ms};
use crate::server::{App, AppState, parse};
use crate::session;
use crate::tenancy::{Caller, Scope};

const BUFFER: usize = 64 * 1024;

fn port_view(app: &AppState, id: &str, port: u16, published: &Published) -> Value {
    let mut url = ports::url(&app.preview_url, id, port);
    let mut view = json!({ "port": port, "access": published.access });
    if let Some((token, expires_at)) = &published.token {
        url = format!("{url}/?{TOKEN_PARAM}={token}");
        view["token_expires_at"] = json!(rfc3339_ms(*expires_at));
    }
    view["url"] = json!(url);
    view
}

pub async fn publish(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let req: Publish = parse(&body)?;
    let (port, published) = app.sandboxes.publish(&id, &req, &origin)?;
    Ok(Json(port_view(&app, &id, port, &published)))
}

pub async fn list(
    State(app): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let ports: Vec<Value> = app
        .sandboxes
        .ports(&id)?
        .iter()
        .map(|(port, published)| port_view(&app, &id, *port, published))
        .collect();
    Ok(Json(json!({ "ports": ports })))
}

pub async fn unpublish(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path((id, port)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let port: u16 = port
        .parse()
        .map_err(|_| ApiError::new(Code::NotFound, "no such port"))?;
    app.sandboxes.unpublish(&id, port, &origin)?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn router(app: AppState) -> Router {
    Router::new().fallback(proxy).with_state(app)
}

fn plain(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

async fn proxy(State(app): State<AppState>, mut req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .unwrap_or_default()
        .to_owned();
    let Some((id, port)) = ports::parse_host(&host) else {
        return plain(StatusCode::NOT_FOUND, "unknown preview host");
    };
    crate::fleet::primary::wait_for_move(&app, &id).await;
    if let Some(node) = crate::fleet::primary::node_of(&app, &id) {
        return crate::fleet::primary::forward(&app, &node, req, Some("preview")).await;
    }
    let Some(published) = app.sandboxes.published(&id, port) else {
        return plain(StatusCode::NOT_FOUND, "no published port at this address");
    };
    let https = app.preview_url.starts_with("https://");
    // Taken on every port, so a sandbox's apps never see a session token.
    let session_cookie = take_cookie(&mut req, session::COOKIE);
    match published.access {
        Access::Public => {}
        Access::Private => {
            if let Some(response) = private_access(&app, &mut req, &id, session_cookie, https) {
                return response;
            }
        }
        Access::Token => {
            let Some((token, expires_at)) = published.token else {
                return plain(StatusCode::INTERNAL_SERVER_ERROR, "port has no token");
            };
            if now_ms() >= expires_at {
                return plain(StatusCode::UNAUTHORIZED, "this preview link has expired");
            }
            if let Some(redirect) = trade_token(&req, &token, expires_at, https) {
                return redirect;
            }
            if !take_cookie(&mut req, COOKIE)
                .is_some_and(|given| ports::token_matches(&given, &token))
            {
                return plain(
                    StatusCode::UNAUTHORIZED,
                    "open this preview with its link, which carries a token",
                );
            }
        }
    }
    // Only now, so that requests without access cannot wake a sandbox.
    // Preview visitors have no API key, so their wakes have no actor.
    let opened = match app.sandboxes.open(&id, &Origin::default()).await {
        Ok(opened) => opened,
        Err(error) => return plain(StatusCode::BAD_GATEWAY, &error.message),
    };
    let proto = if https { "https" } else { "http" };
    forward(opened.channel, opened.busy, port, req, &host, proto)
        .await
        .unwrap_or_else(|message| plain(StatusCode::BAD_GATEWAY, &message))
}

/// A private port takes an API key with `sandboxes:read`, or a browser
/// session token for this sandbox: first as a `?spawnbox_session=` link,
/// which is traded for a cookie, then as that cookie. Returns the response
/// to send instead of forwarding, if any.
fn private_access(
    app: &App,
    req: &mut Request,
    id: &str,
    session_cookie: Option<String>,
    https: bool,
) -> Option<Response> {
    let now = now_ms();
    if let Some(query) = req.uri().query()
        && let (Some(given), rest) = ports::take_param(query, session::PREVIEW_PARAM)
    {
        let (caller, claims) = match app.sessions.caller(&app.db, &given, id, now) {
            Ok(Some(found)) => found,
            Ok(None) => {
                return Some(plain(
                    StatusCode::UNAUTHORIZED,
                    "this preview link is not valid or has expired",
                ));
            }
            Err(error) => return Some(error.into_response()),
        };
        if let Some(refused) = refused(app, &caller, id) {
            return Some(refused);
        }
        let max_age = claims.exp - now / 1000;
        return Some(
            with_cookie(req, &rest, session::COOKIE, &given, max_age, https)
                .unwrap_or_else(|| plain(StatusCode::BAD_REQUEST, "bad preview link")),
        );
    }
    let found = match crate::server::caller(&app.db, req.headers()) {
        Ok(Some(caller)) => Ok(Some(caller)),
        Ok(None) => match &session_cookie {
            Some(token) => app
                .sessions
                .caller(&app.db, token, id, now)
                .map(|found| found.map(|(caller, _)| caller)),
            None => Ok(None),
        },
        Err(error) => Err(error),
    };
    let caller = match found {
        Ok(Some(caller)) => caller,
        Ok(None) if session_cookie.is_some() => {
            return Some(plain(
                StatusCode::UNAUTHORIZED,
                "this preview session has ended; open a new link",
            ));
        }
        Ok(None) => {
            return Some(plain(
                StatusCode::UNAUTHORIZED,
                "this preview needs an API key or a session link",
            ));
        }
        Err(error) => return Some(error.into_response()),
    };
    if let Some(refused) = refused(app, &caller, id) {
        return Some(refused);
    }
    req.headers_mut().remove(header::AUTHORIZATION);
    None
}

/// Why `caller` may not see sandbox `id`'s private ports, if it may not.
fn refused(app: &App, caller: &Caller, id: &str) -> Option<Response> {
    let tenant = match app.db.get_sandbox(id) {
        Ok(sandbox) => sandbox.map(|s| s.tenant),
        Err(error) => return Some(ApiError::from(error).into_response()),
    };
    if !tenant.is_some_and(|t| caller.sees(&t)) {
        return Some(plain(
            StatusCode::NOT_FOUND,
            "no published port at this address",
        ));
    }
    if caller.require(Scope::SandboxesRead).is_err() {
        return Some(plain(
            StatusCode::FORBIDDEN,
            "this API key cannot read sandboxes",
        ));
    }
    None
}

/// A link with `?spawnbox_token=` becomes a cookie and a redirect to the
/// same URL without the token, so it does not stay in history or reach the
/// app. Returns `None` if the request carries no token.
fn trade_token(req: &Request, token: &str, expires_at: i64, https: bool) -> Option<Response> {
    let query = req.uri().query()?;
    let (given, rest) = ports::take_param(query, TOKEN_PARAM);
    let given = given?;
    if !ports::token_matches(&given, token) {
        return Some(plain(
            StatusCode::UNAUTHORIZED,
            "this preview link is not valid",
        ));
    }
    with_cookie(
        req,
        &rest,
        COOKIE,
        token,
        (expires_at - now_ms()) / 1000,
        https,
    )
}

/// A redirect to the request's path with query `rest` that sets cookie
/// `name`.
fn with_cookie(
    req: &Request,
    rest: &str,
    name: &str,
    value: &str,
    max_age: i64,
    https: bool,
) -> Option<Response> {
    let mut location = ports::same_host_path(req.uri().path());
    if !rest.is_empty() {
        location = format!("{location}?{rest}");
    }
    let secure = if https { "; Secure" } else { "" };
    let cookie =
        format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}");
    let mut response = StatusCode::FOUND.into_response();
    let headers = response.headers_mut();
    headers.insert(header::LOCATION, HeaderValue::from_str(&location).ok()?);
    headers.insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).ok()?);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Some(response)
}

/// Removes cookie `name`, so the app never sees it, and returns its value.
fn take_cookie(req: &mut Request, name: &str) -> Option<String> {
    let mut found = None;
    let mut kept = Vec::new();
    for value in req.headers().get_all(header::COOKIE) {
        let Ok(text) = value.to_str() else {
            kept.push(value.clone());
            continue;
        };
        if let Some(given) = ports::cookie(text, name) {
            found = Some(given.to_owned());
        }
        if let Some(rest) = ports::without_cookie(text, name)
            && let Ok(rest) = HeaderValue::from_str(&rest)
        {
            kept.push(rest);
        }
    }
    let headers = req.headers_mut();
    headers.remove(header::COOKIE);
    for value in kept {
        headers.append(header::COOKIE, value);
    }
    found
}

/// Sends one request to the guest port over a fresh tunnel. Upgraded
/// connections (WebSocket) are spliced through the same tunnel.
async fn forward(
    channel: Channel,
    busy: Busy,
    port: u16,
    mut req: Request,
    host: &str,
    proto: &'static str,
) -> Result<Response, String> {
    let (tx, rx) = mpsc::channel(16);
    let open = PortInput {
        input: Some(Input::Open(PortOpen {
            port: u32::from(port),
        })),
    };
    let _ = tx.send(open).await;
    let output = PortsClient::new(channel)
        .dial(ReceiverStream::new(rx))
        .await
        .map_err(|status| match status.code() {
            GrpcCode::Unavailable => format!("nothing listens on port {port}"),
            _ => format!("guest agent: {}", status.message()),
        })?
        .into_inner();
    let (ours, theirs) = tokio::io::duplex(BUFFER);
    // The tunnel, and so the sandbox, is busy until the response and any
    // upgraded connection are done.
    tokio::spawn(async move {
        let _busy = busy;
        pump(theirs, tx, output).await;
    });

    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(ours))
        .await
        .map_err(|e| format!("connect to port {port}: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let client_upgrade = req
        .headers()
        .contains_key(header::UPGRADE)
        .then(|| hyper::upgrade::on(&mut req));
    let path = req
        .uri()
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    *req.uri_mut() = path.into();
    let headers = req.headers_mut();
    if let Ok(value) = HeaderValue::from_str(host) {
        headers.insert("x-forwarded-host", value);
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static(proto));

    let mut response = sender
        .send_request(req)
        .await
        .map_err(|e| format!("port {port}: {e}"))?;
    if response.status() == StatusCode::SWITCHING_PROTOCOLS
        && let Some(client_upgrade) = client_upgrade
    {
        let upstream = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            let (Ok(client), Ok(upstream)) = (client_upgrade.await, upstream.await) else {
                return;
            };
            let _ = tokio::io::copy_bidirectional(
                &mut TokioIo::new(client),
                &mut TokioIo::new(upstream),
            )
            .await;
        });
    }
    Ok(response.map(Body::new))
}

/// Copies bytes between the local end of the tunnel and the guest stream
/// until either side closes.
async fn pump(io: DuplexStream, input: mpsc::Sender<PortInput>, mut output: Streaming<PortOutput>) {
    let (mut read, mut write) = tokio::io::split(io);
    let up = async move {
        let mut buf = vec![0; BUFFER];
        loop {
            match read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let data = Input::Data(buf[..n].to_vec());
                    if input.send(PortInput { input: Some(data) }).await.is_err() {
                        return;
                    }
                }
            }
        }
    };
    let down = async move {
        while let Ok(Some(message)) = output.message().await {
            if write.write_all(&message.data).await.is_err() {
                return;
            }
        }
        let _ = write.shutdown().await;
    };
    tokio::select! {
        () = up => {}
        () = down => {}
    }
}
