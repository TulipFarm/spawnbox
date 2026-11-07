//! The proxy server. nftables redirects every TCP connection a sandbox makes
//! to it; the kernel keeps the address the sandbox wanted.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use nix::sys::socket::sockopt::{Mark, OriginalDst};
use nix::sys::socket::{getsockopt, setsockopt};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::policy::{Mode, Policy, is_blocked, strictest};
use crate::secrets::{Attached, Secret, SecretStore, inject};
use crate::sniff::{MAX_SNIFF, Sniffed, request_host_is, sniff};
use crate::tls::{Ca, provider};

const SNIFF_TIMEOUT: Duration = Duration::from_secs(5);
/// With `allow_all` a client that sends nothing is passed through sooner.
const SNIFF_TIMEOUT_OPEN: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SMTP: u16 = 25;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// What the proxy did, for the API's event log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity {
    /// A connection from a sandbox was accepted. Its `Connection` follows
    /// with the same `id`.
    Opened { sandbox: String, id: u64 },
    /// A connection ended or was refused.
    Connection {
        id: u64,
        sandbox: String,
        tenant: Option<String>,
        dst: SocketAddrV4,
        host: Option<String>,
        /// `allow`, `intercept`, `deny` or `error`.
        verdict: &'static str,
        reason: String,
        up: u64,
        down: u64,
        ms: u64,
    },
    /// An HTTPS request on an intercepted connection.
    Request {
        sandbox: String,
        tenant: Option<String>,
        host: String,
        method: String,
        /// `None` if refused or the server failed.
        status: Option<u16>,
        /// Names and versions of the secrets added.
        secrets: Vec<(String, u32)>,
        /// Why it was refused, if it was.
        refused: Option<&'static str>,
    },
    /// A DNS query.
    Dns {
        sandbox: String,
        tenant: Option<String>,
        name: String,
        /// `A`, `AAAA`, ...
        qtype: String,
        /// `allow`, `deny` (the policy refused the name) or `error`.
        verdict: &'static str,
        /// `NOERROR`, `NXDOMAIN`, ...
        rcode: String,
        /// The A and AAAA addresses in the answer.
        answers: Vec<std::net::IpAddr>,
        ms: u64,
    },
}

/// Receives every `Activity`. Called on the proxy's tasks, so it must be
/// quick.
pub type Sink = Arc<dyn Fn(Activity) + Send + Sync>;

/// What one sandbox may do.
#[derive(Clone, Debug)]
pub struct Registration {
    pub sandbox: String,
    pub tenant: Option<String>,
    /// Every one must allow a connection: for example the tenant's and the
    /// sandbox's.
    pub policies: Vec<Policy>,
    pub secrets: Vec<Attached>,
}

impl Registration {
    fn mode(&self, server: Mode) -> Mode {
        self.policies
            .iter()
            .fold(server, |mode, policy| strictest(mode, policy.mode))
    }

    pub(crate) fn allows(&self, host: Option<&str>) -> bool {
        self.policies.iter().all(|policy| policy.allows(host))
    }

    fn denies_any(&self) -> bool {
        self.policies.iter().any(|policy| !policy.deny.is_empty())
    }

    fn secrets_for(&self, store: &SecretStore, host: &str) -> Vec<(Arc<Secret>, String)> {
        self.secrets
            .iter()
            .filter_map(|a| Some((store.get(&a.name)?, a.placeholder.clone())))
            .filter(|(secret, _)| secret.allows(host))
            .collect()
    }
}

struct Entry {
    registration: Arc<Registration>,
    /// Dropping it ends the sandbox's open connections.
    _cancel: watch::Sender<()>,
    cancelled: watch::Receiver<()>,
}

pub(crate) struct Inner {
    pub(crate) policy: Policy,
    mark: u32,
    ca: Arc<Ca>,
    store: SecretStore,
    client: Arc<ClientConfig>,
    sandboxes: RwLock<HashMap<Ipv4Addr, Entry>>,
    /// Tenants whose new connections are refused, for example over an
    /// egress quota.
    blocked: RwLock<HashSet<String>>,
    pub(crate) sink: Sink,
}

impl Inner {
    pub(crate) fn registration(&self, addr: Ipv4Addr) -> Option<Arc<Registration>> {
        self.sandboxes
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&addr)
            .map(|e| Arc::clone(&e.registration))
    }
}

pub struct Egress {
    inner: Arc<Inner>,
    accept: JoinHandle<()>,
    dns: std::sync::Mutex<Vec<JoinHandle<()>>>,
}

impl Egress {
    /// Listens on `port` on all addresses. The host firewall lets only
    /// sandbox interfaces reach it. Connections to servers carry the
    /// firewall mark `mark`, so the host firewall can keep them off the
    /// host's own addresses. Call inside a Tokio runtime.
    pub async fn start(
        port: u16,
        mark: u32,
        policy: Policy,
        ca: Arc<Ca>,
        store: SecretStore,
        sink: Sink,
    ) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
            .await
            .with_context(|| format!("listen for egress on port {port}"))?;
        let mut client = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let inner = Arc::new(Inner {
            policy,
            mark,
            ca,
            store,
            client: Arc::new(client),
            sandboxes: RwLock::new(HashMap::new()),
            blocked: RwLock::default(),
            sink,
        });
        let accept = tokio::spawn(accept(listener, Arc::clone(&inner)));
        Ok(Self {
            inner,
            accept,
            dns: std::sync::Mutex::default(),
        })
    }

    /// Answers sandbox DNS queries on `port` (UDP and TCP), checked against
    /// the same policies, by asking `upstream`.
    pub async fn serve_dns(&self, port: u16, upstream: Ipv4Addr) -> Result<()> {
        let tasks = crate::dns::start(Arc::clone(&self.inner), port, upstream).await?;
        self.dns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(tasks);
        Ok(())
    }

    /// Connections from `addr` belong to this sandbox from now on.
    pub fn register(&self, addr: Ipv4Addr, registration: Registration) {
        let (cancel, cancelled) = watch::channel(());
        let entry = Entry {
            registration: Arc::new(registration),
            _cancel: cancel,
            cancelled,
        };
        self.sandboxes().insert(addr, entry);
    }

    /// Refuses new connections from `addr` and ends its open ones.
    pub fn unregister(&self, addr: Ipv4Addr) {
        self.sandboxes().remove(&addr);
    }

    /// Refuses new connections of these tenants' sandboxes from now on.
    /// Open connections stay.
    pub fn block_tenants(&self, tenants: HashSet<String>) {
        *self
            .inner
            .blocked
            .write()
            .unwrap_or_else(|e| e.into_inner()) = tenants;
    }

    pub fn close(&self) {
        self.accept.abort();
        for task in self.dns.lock().unwrap_or_else(|e| e.into_inner()).drain(..) {
            task.abort();
        }
        self.sandboxes().clear();
    }

    fn sandboxes(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<Ipv4Addr, Entry>> {
        self.inner
            .sandboxes
            .write()
            .unwrap_or_else(|e| e.into_inner())
    }
}

impl Drop for Egress {
    fn drop(&mut self) {
        self.close();
    }
}

async fn accept(listener: TcpListener, inner: Arc<Inner>) {
    loop {
        match listener.accept().await {
            Ok((stream, SocketAddr::V4(peer))) => {
                tokio::spawn(handle(Arc::clone(&inner), stream, *peer.ip()));
            }
            Ok(_) => {}
            Err(err) => {
                eprintln!("egress: accept: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// The outcome of one connection, for its log line.
struct Conn {
    verdict: &'static str,
    reason: String,
    host: Option<String>,
    up: u64,
    down: u64,
    /// Bytes of an intercepted connection, which `up` and `down` miss.
    intercepted: Option<Arc<Counted>>,
}

/// Bytes read from and written to the sandbox.
#[derive(Default)]
struct Counted {
    up: AtomicU64,
    down: AtomicU64,
}

impl Conn {
    fn deny(&mut self, reason: &str) {
        self.verdict = "deny";
        self.reason = reason.to_owned();
    }
}

/// IDs that pair each `Activity::Opened` with its `Activity::Connection`.
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

async fn handle(inner: Arc<Inner>, stream: TcpStream, peer: Ipv4Addr) {
    let started = Instant::now();
    let dst = match original_dst(&stream) {
        Ok(dst) => dst,
        Err(err) => {
            eprintln!("egress: from {peer}: {err:#}");
            return;
        }
    };
    let found = {
        let sandboxes = inner.sandboxes.read().unwrap_or_else(|e| e.into_inner());
        sandboxes
            .get(&peer)
            .map(|e| (Arc::clone(&e.registration), e.cancelled.clone()))
    };
    let Some((registration, mut cancelled)) = found else {
        eprintln!("egress: from unknown address {peer} to {dst}: refused");
        return;
    };
    let id = NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed);
    (inner.sink)(Activity::Opened {
        sandbox: registration.sandbox.clone(),
        id,
    });
    let mut conn = Conn {
        verdict: "allow",
        reason: String::new(),
        host: None,
        up: 0,
        down: 0,
        intercepted: None,
    };
    tokio::select! {
        result = serve(&inner, &registration, stream, dst, &mut conn) => {
            if let Err(err) = result {
                if conn.verdict == "allow" {
                    conn.verdict = "error";
                }
                conn.reason = format!("{err:#}");
            }
        }
        _ = cancelled.changed() => conn.reason = "sandbox stopped".into(),
    }
    if let Some(counted) = &conn.intercepted {
        conn.up = counted.up.load(Ordering::Relaxed);
        conn.down = counted.down.load(Ordering::Relaxed);
    }
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    eprintln!(
        "egress: sandbox={} dst={dst} host={} verdict={} up={} down={} ms={ms}{}",
        registration.sandbox,
        conn.host.as_deref().unwrap_or("-"),
        conn.verdict,
        conn.up,
        conn.down,
        if conn.reason.is_empty() {
            String::new()
        } else {
            format!(" reason={:?}", conn.reason)
        },
    );
    (inner.sink)(Activity::Connection {
        id,
        sandbox: registration.sandbox.clone(),
        tenant: registration.tenant.clone(),
        dst,
        host: conn.host,
        verdict: conn.verdict,
        reason: conn.reason,
        up: conn.up,
        down: conn.down,
        ms,
    });
}

fn original_dst(stream: &TcpStream) -> Result<SocketAddrV4> {
    let addr = getsockopt(stream, OriginalDst).context("read the original destination")?;
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

async fn serve(
    inner: &Arc<Inner>,
    registration: &Arc<Registration>,
    mut stream: TcpStream,
    dst: SocketAddrV4,
    conn: &mut Conn,
) -> Result<()> {
    if dst.port() == SMTP || is_blocked(*dst.ip()) {
        conn.deny("blocked address");
        return Ok(());
    }
    let tenant_blocked = registration.tenant.as_ref().is_some_and(|tenant| {
        inner
            .blocked
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(tenant)
    });
    if tenant_blocked {
        conn.deny("egress quota");
        return Ok(());
    }
    let mode = registration.mode(inner.policy.mode);
    let web = matches!(dst.port(), 80 | 443);
    if mode == Mode::DenyAll {
        conn.deny("deny_all");
        return Ok(());
    }
    if mode == Mode::Allowlist && !web {
        conn.deny("allowlist allows only ports 80 and 443");
        return Ok(());
    }
    let (head, sniffed) = if web {
        let wait = match mode {
            Mode::AllowAll => SNIFF_TIMEOUT_OPEN,
            _ => SNIFF_TIMEOUT,
        };
        read_head(&mut stream, wait).await
    } else {
        (Vec::new(), Sniffed::Other)
    };
    let (tls, host) = match sniffed {
        Sniffed::Tls(host) => (true, host),
        Sniffed::Http(host) => (false, host),
        _ => (false, None),
    };
    conn.host.clone_from(&host);
    if !(inner.policy.allows(host.as_deref()) && registration.allows(host.as_deref())) {
        conn.deny(if host.is_some() {
            "host not allowed"
        } else {
            "no host name"
        });
        return Ok(());
    }
    if tls
        && let Some(host) = &host
        && !registration.secrets_for(&inner.store, host).is_empty()
    {
        conn.verdict = "intercept";
        let counted = Arc::new(Counted::default());
        conn.intercepted = Some(Arc::clone(&counted));
        let stream = Prefixed {
            head,
            pos: 0,
            inner: stream,
            counted,
        };
        return intercept(inner, registration, stream, host, dst.port()).await;
    }
    // A name the policy checked must be the name connected to, or a client
    // could send an allowed name to another server.
    let checked_name =
        mode == Mode::Allowlist || !inner.policy.deny.is_empty() || registration.denies_any();
    let mut upstream = match (&host, checked_name) {
        (Some(host), true) => connect_name(host, dst.port(), inner.mark).await?,
        _ => connect(SocketAddr::V4(dst), inner.mark).await?,
    };
    upstream.write_all(&head).await?;
    conn.up = head.len() as u64;
    let (up, down) = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    conn.up += up;
    conn.down = down;
    Ok(())
}

/// Reads until the first bytes show a host name, or the client stops.
async fn read_head(stream: &mut TcpStream, wait: Duration) -> (Vec<u8>, Sniffed) {
    let deadline = tokio::time::Instant::now() + wait;
    let mut head = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        match sniff(&head) {
            Sniffed::Incomplete => {}
            found => return (head, found),
        }
        let room = (MAX_SNIFF - head.len()).min(chunk.len());
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk[..room])).await {
            Ok(Ok(n)) if n > 0 => head.extend_from_slice(&chunk[..n]),
            _ => return (head, Sniffed::Other),
        }
    }
}

async fn connect(addr: SocketAddr, mark: u32) -> Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    setsockopt(&socket, Mark, &mark).context("mark the upstream socket")?;
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(addr))
        .await
        .map_err(|_| anyhow!("connect to {addr}: timed out"))?
        .with_context(|| format!("connect to {addr}"))?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Resolves `host` on the host and connects to an address sandboxes may
/// reach.
async fn connect_name(host: &str, port: u16, mark: u32) -> Result<TcpStream> {
    let addrs: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}"))?
        .filter(|a| matches!(a, SocketAddr::V4(v4) if !is_blocked(*v4.ip())))
        .collect();
    let mut last = anyhow!("{host} has no address sandboxes may reach");
    for addr in addrs {
        match connect(addr, mark).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last = err,
        }
    }
    Err(last)
}

/// Ends the sandbox's TLS with a certificate from the egress CA, adds the
/// secrets to each request, and sends it on over a verified TLS connection.
async fn intercept(
    inner: &Arc<Inner>,
    registration: &Arc<Registration>,
    stream: Prefixed,
    host: &str,
    port: u16,
) -> Result<()> {
    let config = inner.ca.server_config(host)?;
    let client = TlsAcceptor::from(config)
        .accept(stream)
        .await
        .context("TLS from the sandbox")?;
    let upstream = Arc::new(Mutex::new(Upstream {
        host: host.to_owned(),
        port,
        mark: inner.mark,
        client: Arc::clone(&inner.client),
        sender: None,
        task: None,
    }));
    let inner = Arc::clone(inner);
    let registration = Arc::clone(registration);
    let host = host.to_owned();
    let service = service_fn(move |req| {
        forward(
            Arc::clone(&inner),
            Arc::clone(&registration),
            Arc::clone(&upstream),
            host.clone(),
            req,
        )
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(client), service)
        .await
        .context("HTTP from the sandbox")
}

async fn forward(
    inner: Arc<Inner>,
    registration: Arc<Registration>,
    upstream: Arc<Mutex<Upstream>>,
    host: String,
    mut req: Request<Incoming>,
) -> Result<Response<Incoming>, BoxError> {
    if req.headers().contains_key(http::header::UPGRADE) {
        return Err(BoxError::from("protocol upgrades are not supported"));
    }
    if !request_host_is(req.uri(), req.headers(), &host) {
        const REASON: &str = "Host does not match the TLS name";
        eprintln!(
            "egress: sandbox={} host={host} request={} verdict=deny reason={REASON:?}",
            registration.sandbox,
            req.method(),
        );
        (inner.sink)(Activity::Request {
            sandbox: registration.sandbox.clone(),
            tenant: registration.tenant.clone(),
            host,
            method: req.method().to_string(),
            status: None,
            secrets: Vec::new(),
            refused: Some(REASON),
        });
        return Err(BoxError::from(REASON));
    }
    if !req.headers().contains_key(http::header::HOST) {
        let value = http::HeaderValue::from_str(&host).map_err(BoxError::from)?;
        req.headers_mut().insert(http::header::HOST, value);
    }
    let secrets = registration.secrets_for(&inner.store, &host);
    let pairs: Vec<_> = secrets
        .iter()
        .map(|(secret, placeholder)| (Arc::clone(secret), placeholder.as_str()))
        .collect();
    let used = inject(req.headers_mut(), &pairs);
    let method = req.method().clone();
    let mut upstream = upstream.lock().await;
    let sender = upstream.sender().await.map_err(BoxError::from)?;
    let response = sender.send_request(req).await.map_err(BoxError::from);
    let status = response.as_ref().ok().map(|r| r.status().as_u16());
    // Names and versions only, so the log shows which secret was used where.
    let names: Vec<_> = used
        .iter()
        .map(|(name, v)| format!("{name}@v{v}"))
        .collect();
    eprintln!(
        "egress: sandbox={} host={host} request={method} status={} secrets={}",
        registration.sandbox,
        status.map_or_else(|| "error".to_owned(), |s| s.to_string()),
        if names.is_empty() {
            "-".to_owned()
        } else {
            names.join(",")
        },
    );
    (inner.sink)(Activity::Request {
        sandbox: registration.sandbox.clone(),
        tenant: registration.tenant.clone(),
        host,
        method: method.to_string(),
        status,
        secrets: used,
        refused: None,
    });
    response
}

/// The verified connection to the real server, made on the first request
/// and again if the server closes it.
struct Upstream {
    host: String,
    port: u16,
    mark: u32,
    client: Arc<ClientConfig>,
    sender: Option<SendRequest<Incoming>>,
    task: Option<JoinHandle<()>>,
}

impl Upstream {
    async fn sender(&mut self) -> Result<&mut SendRequest<Incoming>> {
        if let Some(sender) = &mut self.sender
            && sender.ready().await.is_ok()
        {
            return Ok(self.sender.as_mut().expect("checked above"));
        }
        self.sender = None;
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let tcp = connect_name(&self.host, self.port, self.mark).await?;
        let name = ServerName::try_from(self.host.clone())?;
        let tls = TlsConnector::from(Arc::clone(&self.client))
            .connect(name, tcp)
            .await
            .with_context(|| format!("TLS to {}", self.host))?;
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        self.task = Some(tokio::spawn(async move {
            let _ = connection.await;
        }));
        Ok(self.sender.insert(sender))
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// A stream that first returns bytes already read from it.
struct Prefixed {
    head: Vec<u8>,
    pos: usize,
    inner: TcpStream,
    counted: Arc<Counted>,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.head.len() {
            let n = buf.remaining().min(self.head.len() - self.pos);
            let start = self.pos;
            buf.put_slice(&self.head[start..start + n]);
            self.pos += n;
            self.counted.up.fetch_add(n as u64, Ordering::Relaxed);
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let read = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        self.counted.up.fetch_add(n as u64, Ordering::Relaxed);
        read
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = written {
            self.counted.down.fetch_add(n as u64, Ordering::Relaxed);
        }
        written
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
