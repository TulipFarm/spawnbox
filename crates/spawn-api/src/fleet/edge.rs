//! The edge: a front door for a fleet that runs no sandboxes. It joins like
//! a worker and copies the primary's routing table every second. Exec, PTY,
//! file, git clone and preview calls go straight to the worker that runs
//! the sandbox; all other calls go to the primary. So data calls to running
//! sandboxes still work while the primary is down.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rustls::ClientConfig;

use super::forward::{self, Failure};
use super::pki::{self, Identity};
use super::worker::Quiet;
use super::{NODE_HEADER, ROUTE_HEADER, Routes};
use crate::db::node_kind;
use crate::ids;
use crate::model::{ApiError, Code};
use crate::{ports, server, tls};

const POLL_EVERY: Duration = Duration::from_secs(1);
const MAX_ROUTES: usize = 64 * 1024 * 1024;
const NODE_FILE: &str = "id";

#[derive(clap::Args)]
pub struct Args {
    /// Run as an edge of the primary at this URL, which is its
    /// `--fleet-listen` address: `https://host:port`. With primaries that
    /// fail over, list each one, separated by commas.
    #[arg(long, value_parser = server::parse_primaries)]
    primary: String,
    /// One-time token from `POST /v1/nodes/tokens` on the primary. Needed
    /// only for the first start.
    #[arg(long, env = "SPAWNBOX_JOIN_TOKEN")]
    join_token: Option<String>,
    /// `ca_sha256` from the same reply. Needed only for the first start.
    #[arg(long)]
    primary_ca_sha256: Option<String>,
    /// Keeps the edge's fleet identity.
    #[arg(long, default_value = crate::DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
    /// Address clients call the API on. Without `--tls-cert`, it speaks
    /// plain HTTP.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// PEM certificate chain for HTTPS on `--listen`. Re-read when it
    /// changes, so renewals need no restart.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for `--tls-cert`.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Address for preview hosts, `<port>-<sandbox>.<domain>`.
    #[arg(long, default_value = "127.0.0.1:8081")]
    preview_listen: SocketAddr,
    /// PEM certificate chain for HTTPS on `--preview-listen`, usually a
    /// wildcard certificate.
    #[arg(long, requires = "preview_tls_key")]
    preview_tls_cert: Option<PathBuf>,
    /// PEM private key for `--preview-tls-cert`.
    #[arg(long, requires = "preview_tls_cert")]
    preview_tls_key: Option<PathBuf>,
}

/// Where each sandbox runs, as the primary said last.
#[derive(Default)]
struct Table {
    /// Node ID to URL.
    nodes: HashMap<String, String>,
    /// Sandbox ID to node ID.
    sandboxes: HashMap<String, String>,
}

struct Edge {
    node: String,
    primary: super::Primaries,
    identity: Identity,
    to_primary: Arc<ClientConfig>,
    clients: Mutex<HashMap<String, Arc<ClientConfig>>>,
    table: RwLock<Table>,
    /// The primary removed this edge.
    removed: AtomicBool,
}

type EdgeState = Arc<Edge>;

/// Where a call goes.
enum Target {
    Primary,
    Worker { node: String, url: String },
}

/// The sandbox of a call that may go straight to its worker.
fn direct_sandbox(path: &str) -> Option<&str> {
    let (id, tail) = path.strip_prefix("/v1/sandboxes/")?.split_once('/')?;
    let data = matches!(tail, "exec" | "pty" | "files" | "git:clone");
    (data && ids::is_valid_id("sbx", id)).then_some(id)
}

/// The worker that runs `sandbox`, or the primary if the table has none.
fn target(table: &Table, sandbox: Option<&str>) -> Target {
    sandbox
        .and_then(|id| table.sandboxes.get(id))
        .and_then(|node| Some((node, table.nodes.get(node)?)))
        .map_or(Target::Primary, |(node, url)| Target::Worker {
            node: node.clone(),
            url: url.clone(),
        })
}

impl Edge {
    fn target(&self, sandbox: Option<&str>) -> Target {
        target(
            &self.table.read().unwrap_or_else(|e| e.into_inner()),
            sandbox,
        )
    }

    fn client(&self, node: &str) -> Result<Arc<ClientConfig>> {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tls) = clients.get(node) {
            return Ok(Arc::clone(tls));
        }
        let tls = Arc::new(self.identity.client_config(node)?);
        clients.insert(node.to_owned(), Arc::clone(&tls));
        Ok(tls)
    }

    /// Sends a client's call on. `route` is `Some("preview")` for previews.
    async fn send(
        &self,
        target: Target,
        mut req: Request,
        route: Option<&'static str>,
    ) -> Result<Response, ApiError> {
        if self.removed.load(Ordering::SeqCst) {
            return Err(ApiError::new(
                Code::Forbidden,
                "this edge was removed from the fleet",
            ));
        }
        let (tls, url, name) = match target {
            Target::Primary => (
                Arc::clone(&self.to_primary),
                self.primary.current().to_owned(),
                "the primary".to_owned(),
            ),
            Target::Worker { node, url } => (
                self.client(&node).map_err(ApiError::internal)?,
                url,
                format!("node {node}"),
            ),
        };
        let headers = req.headers_mut();
        headers.remove(ROUTE_HEADER);
        let node = HeaderValue::from_str(&self.node).map_err(ApiError::internal)?;
        headers.insert(NODE_HEADER, node);
        match route {
            Some(route) => {
                headers.insert(ROUTE_HEADER, HeaderValue::from_static(route));
            }
            None => {
                let host = url.strip_prefix("https://").unwrap_or(&url);
                let host = HeaderValue::from_str(host).map_err(ApiError::internal)?;
                headers.insert(header::HOST, host);
            }
        }
        let path = req.uri().path_and_query().map_or("/", |p| p.as_str());
        *req.uri_mut() = Uri::try_from(path).unwrap_or_default();
        match forward::send(tls, &url, req).await {
            Ok(resp) => Ok(resp),
            Err(Failure::Unreachable(e)) => {
                eprintln!("edge: {name}: {e:#}");
                // The next call tries a standby, which may lead by then.
                self.primary.unreachable(&url);
                Err(ApiError::new(
                    Code::NodeUnreachable,
                    format!("{name} cannot be reached; try again later"),
                ))
            }
            Err(Failure::Broken(e)) => {
                let mut resp =
                    ApiError::new(Code::Internal, format!("{name}: {e:#}")).into_response();
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                Ok(resp)
            }
        }
    }

    /// Copies the routing table from the primary.
    async fn poll(&self) -> Result<()> {
        let url = self.primary.current().to_owned();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/fleet/v1/routes")
            .header(
                header::HOST,
                url.strip_prefix("https://").unwrap_or_default(),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .header(NODE_HEADER, &self.node)
            .body(Body::from("{}"))?;
        let resp = match forward::send(Arc::clone(&self.to_primary), &url, req).await {
            Ok(resp) => resp,
            Err(Failure::Unreachable(e)) => {
                self.primary.unreachable(&url);
                return Err(e);
            }
            Err(Failure::Broken(e)) => return Err(e),
        };
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), MAX_ROUTES).await?;
        if status == StatusCode::FORBIDDEN {
            let mut table = self.table.write().unwrap_or_else(|e| e.into_inner());
            *table = Table::default();
            if !self.removed.swap(true, Ordering::SeqCst) {
                eprintln!("edge: the primary removed this edge; refusing all calls");
            }
            bail!("removed from the fleet");
        }
        if !status.is_success() {
            bail!(
                "routes: {status}: {}",
                String::from_utf8_lossy(&bytes).trim()
            );
        }
        let routes: Routes = serde_json::from_slice(&bytes).context("routes: bad reply")?;
        let table = Table {
            nodes: routes.nodes.into_iter().collect(),
            sandboxes: routes.sandboxes.into_iter().collect(),
        };
        *self.table.write().unwrap_or_else(|e| e.into_inner()) = table;
        self.removed.store(false, Ordering::SeqCst);
        Ok(())
    }
}

async fn api(State(edge): State<EdgeState>, req: Request) -> Response {
    let target = edge.target(direct_sandbox(req.uri().path()));
    edge.send(target, req, None)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

async fn preview(State(edge): State<EdgeState>, req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let sandbox = ports::parse_host(host).map(|(id, _)| id);
    let target = edge.target(sandbox.as_deref());
    match edge.send(target, req, Some("preview")).await {
        Ok(resp) => resp,
        Err(error) => {
            let status =
                StatusCode::from_u16(error.code.http_status()).unwrap_or(StatusCode::BAD_GATEWAY);
            (status, format!("{}\n", error.message)).into_response()
        }
    }
}

/// Loads the edge's identity, or joins the fleet as an edge.
async fn start(args: &Args, data: &Path) -> Result<Edge> {
    let dir = data.join("fleet").join("edge");
    let id_file = dir.join(NODE_FILE);
    if !(Identity::exists(&dir) && id_file.exists()) {
        let (Some(token), Some(ca_sha256)) = (&args.join_token, &args.primary_ca_sha256) else {
            bail!(
                "this edge has not joined the fleet; give --join-token and \
                 --primary-ca-sha256 from POST /v1/nodes/tokens on the primary"
            );
        };
        let primaries = super::Primaries::parse(&args.primary).map_err(anyhow::Error::msg)?;
        super::worker::join(&dir, &primaries, "", token, ca_sha256, node_kind::EDGE).await?;
    } else if args.join_token.is_some() {
        eprintln!("already joined; --join-token is not used");
    }
    let node = std::fs::read_to_string(&id_file)
        .with_context(|| format!("read {}", id_file.display()))?
        .trim()
        .to_owned();
    let identity = Identity::load(&dir)?;
    let to_primary = Arc::new(identity.client_config(pki::PRIMARY)?);
    eprintln!("fleet edge {node}; primary {}", args.primary);
    Ok(Edge {
        node,
        primary: super::Primaries::parse(&args.primary).map_err(anyhow::Error::msg)?,
        identity,
        to_primary,
        clients: Mutex::default(),
        table: RwLock::default(),
        removed: AtomicBool::new(false),
    })
}

pub async fn run(args: Args) -> Result<()> {
    let data = crate::open_data_dir(&args.data_dir)?;
    let edge = Arc::new(start(&args, &data).await?);
    let poller = {
        let edge = Arc::clone(&edge);
        tokio::spawn(async move {
            let mut quiet = Quiet(None);
            loop {
                quiet.see("routes", edge.poll().await);
                tokio::time::sleep(POLL_EVERY).await;
            }
        })
    };
    let previews = tls::Bound::bind(
        args.preview_listen,
        server::tls_files(args.preview_tls_cert, args.preview_tls_key),
    )
    .await?;
    eprintln!("previews on {}", previews.url(args.preview_listen));
    let previews = previews.serve(
        Router::new()
            .fallback(preview)
            .with_state(Arc::clone(&edge)),
        std::future::pending(),
    );
    let previews = tokio::spawn(async move {
        if let Err(error) = previews.await {
            eprintln!("preview listener: {error}");
        }
    });
    let listener =
        tls::Bound::bind(args.listen, server::tls_files(args.tls_cert, args.tls_key)).await?;
    eprintln!("listening on {}", listener.url(args.listen));
    let routes = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .fallback(api)
        .with_state(edge);
    let served = listener.serve(routes, server::shutdown_signal()).await;
    poller.abort();
    previews.abort();
    served.map_err(|e| anyhow!(e)).context("serve HTTP")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "sbx_0123456789abcdef";

    #[test]
    fn only_data_calls_go_straight_to_workers() {
        assert!(ids::is_valid_id("sbx", ID));
        for tail in ["exec", "pty", "files", "git:clone"] {
            assert_eq!(
                direct_sandbox(&format!("/v1/sandboxes/{ID}/{tail}")),
                Some(ID)
            );
        }
        for path in [
            format!("/v1/sandboxes/{ID}"),
            format!("/v1/sandboxes/{ID}:pause"),
            format!("/v1/sandboxes/{ID}/events"),
            format!("/v1/sandboxes/{ID}/ports"),
            format!("/v1/sandboxes/{ID}/session-tokens"),
            format!("/v1/sandboxes/{ID}/files/x"),
            "/v1/sandboxes/sbx_bad/exec".to_owned(),
            "/v1/sandboxes".to_owned(),
            "/v1/templates/x/exec".to_owned(),
        ] {
            assert_eq!(direct_sandbox(&path), None, "{path}");
        }
    }

    #[test]
    fn unknown_sandboxes_go_to_the_primary() {
        let table = Table {
            nodes: HashMap::from([("nod_a".into(), "https://10.0.0.2:7444".into())]),
            sandboxes: HashMap::from([
                (ID.into(), "nod_a".into()),
                ("sbx_gone".into(), "nod_x".into()),
            ]),
        };
        let pick = |id| match target(&table, id) {
            Target::Primary => None,
            Target::Worker { node, url } => Some((node, url)),
        };
        assert_eq!(
            pick(Some(ID)),
            Some(("nod_a".into(), "https://10.0.0.2:7444".into()))
        );
        assert_eq!(pick(Some("sbx_gone")), None);
        assert_eq!(pick(Some("sbx_other")), None);
        assert_eq!(pick(None), None);
    }
}
