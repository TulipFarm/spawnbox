//! Calls between fleet hosts: one HTTP/1.1 request per mutual-TLS
//! connection. No connection is kept, so a removed node is cut off at once.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, header};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest JSON reply a fleet call reads.
const MAX_REPLY: usize = 64 * 1024 * 1024;
/// Fleet configs name the peer to check; this is only sent as SNI.
const SNI: &str = "spawnbox-fleet";
const HOP_BY_HOP: [&str; 6] = [
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "proxy-authorization",
];

#[derive(Debug)]
pub enum Failure {
    /// The request did not reach the node, so another one may be tried.
    Unreachable(anyhow::Error),
    /// The request may have reached the node.
    Broken(anyhow::Error),
}

impl Failure {
    pub fn error(self) -> anyhow::Error {
        match self {
            Self::Unreachable(e) | Self::Broken(e) => e,
        }
    }
}

fn authority(url: &str) -> anyhow::Result<&str> {
    url.strip_prefix("https://")
        .filter(|rest| !rest.contains('/'))
        .ok_or_else(|| anyhow!("{url} is not https://host:port"))
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
}

fn strip_hop_by_hop(headers: &mut HeaderMap, upgrade: bool) {
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    if !upgrade {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    }
}

/// Sends `req` to the host at `url`; `tls` checks who it is. WebSocket
/// upgrades are joined both ways.
pub async fn send(
    tls: Arc<ClientConfig>,
    url: &str,
    req: Request<Body>,
) -> Result<Response<Body>, Failure> {
    connect(tls, url).await?.send(req).await
}

/// A connection to a host that no request was sent on yet.
pub struct Connection {
    sender: hyper::client::conn::http1::SendRequest<Body>,
    url: String,
}

/// Connects to the host at `url`; `tls` checks who it is.
pub async fn connect(tls: Arc<ClientConfig>, url: &str) -> Result<Connection, Failure> {
    let addr = authority(url).map_err(Failure::Unreachable)?;
    let unreachable = |e: anyhow::Error| Failure::Unreachable(e.context(format!("reach {url}")));
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("connect timed out")
        .and_then(|r| r.context("connect"))
        .map_err(unreachable)?;
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(SNI).map_err(|e| unreachable(e.into()))?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TlsConnector::from(tls).connect(name, tcp))
        .await
        .context("TLS handshake timed out")
        .and_then(|r| r.context("TLS handshake"))
        .map_err(unreachable)?;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| unreachable(e.into()))?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(Connection {
        sender,
        url: url.to_owned(),
    })
}

impl Connection {
    /// Sends `req`. WebSocket upgrades are joined both ways.
    pub async fn send(self, mut req: Request<Body>) -> Result<Response<Body>, Failure> {
        let Self { mut sender, url } = self;
        let upgrade = is_upgrade(req.headers()).then(|| hyper::upgrade::on(&mut req));
        strip_hop_by_hop(req.headers_mut(), upgrade.is_some());
        let mut resp = sender
            .send_request(req)
            .await
            .map_err(|e| Failure::Broken(anyhow::Error::from(e).context(format!("call {url}"))))?;
        match upgrade {
            Some(client) if resp.status() == StatusCode::SWITCHING_PROTOCOLS => {
                let upstream = hyper::upgrade::on(&mut resp);
                tokio::spawn(async move {
                    if let (Ok(client), Ok(upstream)) = tokio::join!(client, upstream) {
                        let _ = tokio::io::copy_bidirectional(
                            &mut TokioIo::new(client),
                            &mut TokioIo::new(upstream),
                        )
                        .await;
                    }
                });
            }
            _ => strip_hop_by_hop(resp.headers_mut(), false),
        }
        Ok(resp.map(Body::new))
    }
}

/// POSTs `body` as JSON to `url` + `path` and reads a JSON reply. A reply
/// that is not 2xx is an error with its body.
pub async fn call<T: Serialize, R: DeserializeOwned>(
    tls: Arc<ClientConfig>,
    url: &str,
    path: &str,
    node: Option<&str>,
    body: &T,
) -> Result<R, Failure> {
    let host = authority(url).map_err(Failure::Unreachable)?;
    let json = serde_json::to_vec(body).map_err(|e| Failure::Unreachable(e.into()))?;
    let mut req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(node) = node {
        req = req.header(super::NODE_HEADER, node);
    }
    let req = req
        .body(Body::from(json))
        .map_err(|e| Failure::Unreachable(e.into()))?;
    let resp = send(tls, url, req).await?;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), MAX_REPLY)
        .await
        .map_err(|e| Failure::Broken(anyhow!("read reply from {url}{path}: {e}")))?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&bytes);
        return Err(Failure::Broken(anyhow!(
            "{url}{path}: {status}: {}",
            text.trim()
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| Failure::Broken(anyhow!("{url}{path}: bad reply: {e}")))
}
