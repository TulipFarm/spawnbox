//! HTTP server: routes, API key check, JSON and SSE exec, files, templates,
//! and the host setup and cleanup around it.

use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::body::{Body, Bytes};
use axum::extract::DefaultBodyLimit;
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spawn_egress::{Activity, Ca, Egress, Policy, SecretStore};
use spawn_node::firecracker::Host;
use spawn_node::gvisor::Runsc;
use spawn_node::net::{self, HostNet};
use spawn_node::{Backend, Node, absolute};
use spawn_proto::guest::v1::exec_event::Event as GuestEvent;
use spawn_proto::guest::v1::files_client::FilesClient;
use spawn_proto::guest::v1::read_chunk::Chunk as ReadPart;
use spawn_proto::guest::v1::write_chunk::Chunk as WritePart;
use spawn_proto::guest::v1::{
    ExecEvent, ExecExit, FileInfo, FileKind, PathRequest, ReadChunk, RemoveRequest, WriteChunk,
    WriteHeader,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Streaming;

use crate::db::{self, Db, state};
use crate::egress::Network;
use crate::events::{Filter, Origin};
use crate::fleet::pki::Peer;
use crate::fleet::primary::{self, Primary};
use crate::fleet::worker::{self, Worker};
use crate::fleet::{self, EgressCa, Role};
use crate::hub::{ExecLog, Hub};
use crate::ids;
use crate::metering::{HOUR_MS, Meter, Totals, hour_start, month_start};
use crate::metrics;
use crate::model::{
    ApiError, Code, CreateSandbox, CreateVolume, Exec, ForkSandbox, GitClone, Resources,
    SandboxView, SecretInput, SecretView, SnapshotSandbox, TemplateSpec, Timings, VolumeMount,
    check_user, rfc3339_ms,
};
use crate::otlp::Otlp;
use crate::runtime::{Busy, Parts, Sandboxes, Settings, now_ms};
use crate::secretbox::SecretBox;
use crate::secrets::{self, Secrets};
use crate::store::BuildStore;
use crate::templates::{Inputs, Slots, Templates};
use crate::tenancy::{
    self, Caller, DEFAULT_TENANT, KeyInput, Tenant, TenantInput, Usage, tenant_not_found,
};
use crate::tls;
use crate::traces;
use crate::utf8::Utf8Stream;
use crate::volumes::Volumes;
use crate::{preview, terminal};

/// Output kept per stream for a plain JSON exec. SSE has no limit.
const MAX_JSON_OUTPUT: usize = 1024 * 1024;
const DEFAULT_PAGE: u32 = 50;
const MAX_PAGE: u32 = 200;
/// Largest piece of a file sent to the guest in one message.
const FILE_CHUNK: usize = 1024 * 1024;
/// Template specs may hold many long setup steps.
const MAX_TEMPLATE_BODY: usize = 8 * 1024 * 1024;
const DEFAULT_EVENT_PAGE: usize = 100;
/// The longest range `GET /v1/usage` answers.
const MAX_USAGE_RANGE_MS: i64 = 93 * 24 * HOUR_MS;
/// How often disks are measured and usage is written.
const METER_EVERY: Duration = Duration::from_secs(10);
const MAX_EVENT_PAGE: usize = 1000;
/// Header that tags a call with the caller's step, such as an agent's tool
/// call ID.
const STEP_HEADER: &str = "x-spawnbox-step";

/// What runs sandboxes.
#[derive(Clone, Copy, clap::ValueEnum)]
enum BackendArg {
    /// Firecracker if `/dev/kvm` can be opened, otherwise gVisor.
    Auto,
    /// Firecracker microVMs. Needs KVM.
    Firecracker,
    /// gVisor containers, for hosts without KVM. Weaker isolation.
    Gvisor,
}

#[derive(clap::Args)]
pub struct Args {
    /// What runs sandboxes.
    #[arg(long, value_enum, default_value_t = BackendArg::Auto)]
    backend: BackendArg,
    /// Path to the Firecracker binary. Needed for Firecracker.
    #[arg(long)]
    firecracker: Option<PathBuf>,
    /// Path to the jailer binary from the same Firecracker release. Needed
    /// for Firecracker.
    #[arg(long)]
    jailer: Option<PathBuf>,
    /// Path to the uncompressed guest kernel (vmlinux). Needed for
    /// Firecracker.
    #[arg(long)]
    kernel: Option<PathBuf>,
    /// Path to gVisor's runsc binary. Needed for gVisor.
    #[arg(long)]
    runsc: Option<PathBuf>,
    /// Path to the ext4 base disk with spawn-guest installed.
    #[arg(long)]
    rootfs: PathBuf,
    /// Database, template build, jails and logs.
    #[arg(long, default_value = crate::DEFAULT_DATA_DIR)]
    data_dir: PathBuf,
    /// Address to listen on. Without `--tls-cert`, it speaks plain HTTP:
    /// keep it on localhost or put a TLS proxy in front.
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    /// PEM certificate chain for HTTPS on `--listen`. Re-read when it
    /// changes, so renewals need no restart.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for `--tls-cert`.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// vCPUs of `base` and the default for other templates.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=16))]
    vcpus: u8,
    /// Memory of `base` and the default for other templates.
    #[arg(long, default_value_t = 1024, value_parser = clap::value_parser!(u32).range(256..=32_768))]
    memory_mib: u32,
    /// Logical size of each sandbox's writable disk, for `base` and as the
    /// default for other templates.
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=100))]
    upper_disk_gib: u32,
    /// Most template builds running at once. Each uses a sandbox slot.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=64))]
    max_builds: u32,
    /// DNS resolver that guest DNS requests are sent to.
    #[arg(long, default_value_t = Ipv4Addr::new(1, 1, 1, 1))]
    dns: Ipv4Addr,
    /// Most sandboxes running at once.
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..16_384))]
    max_sandboxes: u32,
    /// Largest `timeout_s` a create request may ask for.
    #[arg(long, default_value_t = 86_400)]
    max_timeout_s: u64,
    /// Pause a sandbox after this many seconds with no calls, unless its
    /// create request sets `idle_pause_s`. 0 means never.
    #[arg(long, default_value_t = 600)]
    idle_pause_s: u64,
    /// Delete paused sandboxes after this many seconds.
    #[arg(long, default_value_t = 7 * 86_400)]
    paused_retention_s: u64,
    /// Host port the egress proxy listens on. Only sandboxes can reach it.
    #[arg(long, default_value_t = 15_001)]
    egress_port: u16,
    /// Host port (UDP and TCP) the DNS forwarder listens on. Only sandboxes
    /// can reach it. It sends queries on to `--dns`.
    #[arg(long, default_value_t = 15_053)]
    dns_port: u16,
    /// Egress policy every sandbox connection must also pass, as JSON.
    /// Example: '{"mode":"allowlist","allow":["*.github.com"]}'.
    #[arg(long, default_value = r#"{"mode":"allow_all"}"#, value_parser = parse_policy)]
    egress_policy: Policy,
    /// Key that encrypts secrets at rest. Back it up: without it, stored
    /// secrets cannot be read. Default: <data-dir>/secrets.key.
    #[arg(long)]
    secrets_key_file: Option<PathBuf>,
    /// Keep state in this Postgres database instead of SQLite in the data
    /// directory: `postgres://user:password@host:5432/spawnbox`. Primaries
    /// that share it fail over: one serves, the others wait and take over
    /// about 15 s after it stops. They need the same secrets key.
    #[arg(long, env = "SPAWNBOX_DATABASE_URL", conflicts_with = "primary")]
    database_url: Option<String>,
    /// PEM CA certificates the database's TLS certificate must come from.
    /// Without it, TLS is used when the server offers it, with any
    /// certificate.
    #[arg(long, requires = "database_url")]
    database_ca_file: Option<PathBuf>,
    /// On the first start, copy this SQLite database (such as
    /// <data-dir>/spawnbox.db) into the empty `--database-url` database.
    #[arg(long, requires = "database_url")]
    import_sqlite: Option<PathBuf>,
    /// Address the preview proxy listens on. It routes by host name, so
    /// point a wildcard DNS name at it.
    #[arg(long, default_value = "127.0.0.1:8081")]
    preview_listen: SocketAddr,
    /// PEM certificate chain for HTTPS on `--preview-listen`, usually a
    /// wildcard certificate. Re-read when it changes.
    #[arg(long, requires = "preview_tls_key")]
    preview_tls_cert: Option<PathBuf>,
    /// PEM private key for `--preview-tls-cert`.
    #[arg(long, requires = "preview_tls_cert")]
    preview_tls_key: Option<PathBuf>,
    /// Preview URL of a port; `{label}` becomes `<port>-<sandbox>`. With an
    /// https:// URL, token cookies are marked Secure.
    #[arg(long, default_value = "http://{label}.localhost:8081", value_parser = parse_preview_url)]
    preview_url: String,
    /// Delete events older than this many seconds. 0 keeps them forever.
    #[arg(long, default_value_t = 7 * 86_400)]
    events_retention_s: u64,
    /// Bytes of each stream's last output kept in `exec.finished`.
    #[arg(long, default_value_t = 64 * 1024, value_parser = clap::value_parser!(u32).range(0..=1024 * 1024))]
    events_output_bytes: u32,
    /// OTLP/HTTP collector that events are also sent to as log records,
    /// and creates and execs as traces, such as http://localhost:4318. Headers come from
    /// OTEL_EXPORTER_OTLP_HEADERS.
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,
    /// Address that serves Prometheus metrics at `/metrics`, with no
    /// authentication. Off if not set. Keep it on a private network.
    #[arg(long)]
    metrics_listen: Option<SocketAddr>,
    /// Percent of host memory that running sandboxes may reserve together,
    /// by their `memory_mib`. Over 100 lets sandboxes that do not use all
    /// their memory share it. A create past it gets `503 no_capacity`.
    #[arg(long, default_value_t = 150, value_parser = clap::value_parser!(u16).range(10..=1000))]
    memory_overcommit_pct: u16,
    /// Pauses the longest-idle sandboxes to disk when free host memory
    /// drops below this percent of host memory, or when processes stall
    /// waiting for memory (PSI) for over this percent of the last 10
    /// seconds. Creates are refused meanwhile. 0 turns it off.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(0..=50))]
    memory_pressure_pct: u8,
    /// Lets the kernel merge equal memory pages across Firecracker VMs
    /// (KSM). Saves memory, but one sandbox may learn what another holds
    /// by timing; use it only when all sandboxes trust each other.
    #[arg(long)]
    ksm: bool,
    /// Percent of host memory that warm VMs may use: VMs restored ahead of
    /// time so creates are faster. 0 turns warm pools off.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(0..=50))]
    warm_pool_memory_pct: u8,
    /// Warm VMs always kept for `base` with the server's egress policy.
    /// Other templates get warm VMs when they are used.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(0..=64))]
    warm_pool_min: u32,
    /// Object store for ready builds: `s3://bucket/prefix` (endpoint,
    /// region and credentials come from the `AWS_*` environment variables)
    /// or `file:///path`. Builds are saved there and fetched instead of
    /// built again when their inputs match.
    #[arg(long, env = "SPAWNBOX_BUILD_STORE")]
    build_store: Option<String>,
    /// Disk the local builds directory may use. Past it, idle builds that
    /// are in the build store are removed locally and fetched again when
    /// used. 0 means no limit. Needs --build-store.
    #[arg(long, default_value_t = 0, requires = "build_store")]
    build_cache_gib: u64,
    /// Run as a fleet primary: workers join and report on this address,
    /// over mutual TLS. Keep it on a private network.
    #[arg(long, conflicts_with = "primary")]
    fleet_listen: Option<SocketAddr>,
    /// Run as a fleet worker of the primary at this URL, which is its
    /// `--fleet-listen` address: `https://host:port`. A worker serves only
    /// `--node-listen`; clients call the primary. With primaries that fail
    /// over, list each one, separated by commas.
    #[arg(long, requires_all = ["node_listen", "advertise"], value_parser = parse_primaries)]
    primary: Option<String>,
    /// One-time token from `POST /v1/nodes/tokens` on the primary. Needed
    /// only for the first start.
    #[arg(long, env = "SPAWNBOX_JOIN_TOKEN", requires = "primary")]
    join_token: Option<String>,
    /// `ca_sha256` from the same reply. Needed only for the first start.
    #[arg(long, requires = "primary")]
    primary_ca_sha256: Option<String>,
    /// Address a worker takes the primary's calls on, over mutual TLS.
    #[arg(long, requires = "primary")]
    node_listen: Option<SocketAddr>,
    /// URL the primary reaches `--node-listen` at: `https://host:port`.
    #[arg(long, requires = "primary", value_parser = parse_node_url)]
    advertise: Option<String>,
    /// Add and remove workers on their own. When the fleet needs a worker,
    /// or has one too many, run this program (an absolute path) or POST
    /// to this URL. Needs --fleet-listen.
    #[arg(long, requires = "fleet_listen")]
    autoscale_hook: Option<String>,
    /// Key to sign webhook calls with: `X-Spawnbox-Signature: sha256=` and
    /// the hex HMAC-SHA256 of the body.
    #[arg(long, env = "SPAWNBOX_AUTOSCALE_SECRET")]
    autoscale_secret: Option<String>,
    /// Fewest workers the autoscaler keeps, not counting the primary.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u32).range(0..=1000))]
    autoscale_min_workers: u32,
    /// Most workers the autoscaler keeps, not counting the primary.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1000))]
    autoscale_max_workers: u32,
    /// Add a worker when the fleet uses this percent of its slots or
    /// memory...
    #[arg(long, default_value_t = 70, value_parser = clap::value_parser!(u8).range(1..=100))]
    autoscale_up_pct: u8,
    /// ...for this many seconds.
    #[arg(long, default_value_t = 120)]
    autoscale_up_after_s: u32,
    /// Remove a worker when the fleet uses this percent or less...
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u8).range(0..=99))]
    autoscale_down_pct: u8,
    /// ...for this many seconds.
    #[arg(long, default_value_t = 1200)]
    autoscale_down_after_s: u32,
}

/// The autoscaler's settings, if `--autoscale-hook` is set.
fn autoscale_settings(args: &Args) -> Result<Option<fleet::autoscale::Settings>> {
    let Some(hook) = &args.autoscale_hook else {
        return Ok(None);
    };
    let hook = fleet::autoscale::Hook::parse(hook, args.autoscale_secret.clone())
        .map_err(|e| anyhow::anyhow!("--autoscale-hook: {e}"))?;
    if args.autoscale_down_pct >= args.autoscale_up_pct {
        bail!("--autoscale-down-pct must be less than --autoscale-up-pct");
    }
    if args.autoscale_min_workers > args.autoscale_max_workers {
        bail!("--autoscale-min-workers must not be more than --autoscale-max-workers");
    }
    Ok(Some(fleet::autoscale::Settings {
        hook,
        min_workers: args.autoscale_min_workers as usize,
        max_workers: args.autoscale_max_workers as usize,
        up_ratio: f64::from(args.autoscale_up_pct) / 100.0,
        up_after_ms: i64::from(args.autoscale_up_after_s) * 1000,
        down_ratio: f64::from(args.autoscale_down_pct) / 100.0,
        down_after_ms: i64::from(args.autoscale_down_after_s) * 1000,
    }))
}

/// One URL, or the leader's and standbys' URLs separated by commas.
pub fn parse_primaries(text: &str) -> Result<String, String> {
    fleet::Primaries::parse(text)?;
    Ok(text.to_owned())
}

pub fn parse_node_url(text: &str) -> Result<String, String> {
    fleet::check_node_url(text)?;
    Ok(text.to_owned())
}

fn parse_preview_url(text: &str) -> Result<String, String> {
    let ok = (text.starts_with("http://") || text.starts_with("https://"))
        && text.contains("{label}")
        && !text.ends_with('/');
    if ok {
        Ok(text.to_owned())
    } else {
        Err("must start with http:// or https://, contain {label} and not end with /".into())
    }
}

fn parse_policy(text: &str) -> Result<Policy, String> {
    let mut policy: Policy = serde_json::from_str(text).map_err(|e| e.to_string())?;
    policy.check()?;
    Ok(policy)
}

pub struct App {
    pub sandboxes: Sandboxes,
    pub(crate) templates: Arc<Templates>,
    pub(crate) secrets: Arc<Secrets>,
    pub(crate) volumes: Arc<Volumes>,
    pub db: Db,
    pub preview_url: String,
    pub role: Role,
    /// Signs and checks browser session tokens.
    pub sessions: crate::session::Sessions,
}

pub type AppState = Arc<App>;

impl App {
    /// Records a change to tenants, keys, secrets or templates.
    fn admin_event(&self, kind: &'static str, origin: &Origin, tenant: Option<&str>, attrs: Value) {
        if let Role::Primary(primary) = &self.role {
            primary.bump();
        }
        self.sandboxes.hub.record(kind, origin, tenant, None, attrs);
    }
}

/// Never the value.
fn secret_attrs(view: &SecretView) -> Value {
    json!({
        "name": view.spec.name,
        "type": view.spec.kind,
        "version": view.version,
        "allowed_hosts": view.spec.allowed_hosts,
    })
}

pub async fn serve(args: Args) -> Result<()> {
    // Checked before the host is set up.
    autoscale_settings(&args)?;
    if !nix::unistd::geteuid().is_root() {
        bail!("run as root: it creates jails, cgroups, network namespaces and firewall rules");
    }
    let data = crate::open_data_dir(&args.data_dir)?;
    let db = crate::leader::open(
        &data,
        args.database_url.as_deref(),
        args.database_ca_file.as_deref(),
    )?;
    let key_file = args
        .secrets_key_file
        .clone()
        .unwrap_or_else(|| data.join("secrets.key"));
    let sbox = SecretBox::open_or_create(&key_file).context("open secrets key")?;
    if let Some(url) = &args.database_url {
        let target = crate::leader::target(url, args.database_ca_file.as_deref())?;
        crate::leader::lead(target, crate::leader::host_id(&data)?).await?;
        if let Some(path) = &args.import_sqlite {
            match db
                .import_sqlite(path)
                .context("import the SQLite database")?
            {
                Some(rows) => eprintln!("copied {rows} rows from {}", path.display()),
                None => eprintln!(
                    "the database already has data; not importing {}",
                    path.display()
                ),
            }
        }
        crate::leader::pull_shared(&db, &data, &sbox)?;
    }
    let ca = Arc::new(secrets::egress_ca(&data, &sbox).context("load egress CA")?);
    let backend = match args.backend {
        BackendArg::Auto => Backend::detect(),
        BackendArg::Firecracker => {
            if Backend::detect() != Backend::Firecracker {
                bail!("--backend firecracker needs /dev/kvm, and it cannot be opened read-write");
            }
            Backend::Firecracker
        }
        BackendArg::Gvisor => Backend::Gvisor,
    };
    let need = |path: &Option<PathBuf>, flag: &str| {
        let path = path
            .as_deref()
            .with_context(|| format!("--{flag} is needed for {}", backend.name()))?;
        absolute(path)
    };
    let mut host = Host {
        jailer: PathBuf::new(),
        firecracker: PathBuf::new(),
        jails: data.join("jails"),
        logs: data.join("logs"),
        ksm: args.ksm,
    };
    let (runsc, inputs) = match backend {
        Backend::Firecracker => {
            host.jailer = need(&args.jailer, "jailer")?;
            host.firecracker = need(&args.firecracker, "firecracker")?;
            let inputs = Inputs {
                kernel: need(&args.kernel, "kernel")?,
                rootfs: absolute(&args.rootfs)?,
                runtime: host.firecracker.clone(),
            };
            (None, inputs)
        }
        Backend::Gvisor => {
            let runsc = Runsc {
                bin: need(&args.runsc, "runsc")?,
                dir: data.join("gvisor"),
            };
            let inputs = Inputs {
                kernel: PathBuf::new(),
                rootfs: absolute(&args.rootfs)?,
                runtime: runsc.bin.clone(),
            };
            (Some(runsc), inputs)
        }
    };
    eprintln!("sandboxes run in {}", backend.name());
    // Leftovers from a server that crashed.
    if let Some(runsc) = &runsc {
        runsc.remove_all().await;
    }
    net::remove_stale_namespaces().await?;
    host.remove_all().await;
    host.setup()?;
    if let Some(runsc) = &runsc {
        runsc.setup()?;
    }
    let ports = net::ProxyPorts {
        tcp: args.egress_port,
        dns: args.dns_port,
    };
    let host_net = HostNet::setup(args.dns, Some(ports)).await?;

    let node = Node {
        host: host.clone(),
        runsc: runsc.clone(),
        dns: args.dns,
    };
    let result = run(&args, node, inputs, db, &data, sbox, ca).await;

    if let Some(runsc) = &runsc {
        runsc.remove_all().await;
    }
    let _ = net::remove_stale_namespaces().await;
    host.remove_all().await;
    host_net.teardown().await;
    result
}

async fn run(
    args: &Args,
    node: Node,
    inputs: Inputs,
    db: Db,
    data: &std::path::Path,
    sbox: SecretBox,
    ca: Arc<Ca>,
) -> Result<()> {
    // The OTLP exporter's and the autoscale webhook's HTTPS clients use the
    // process-wide crypto provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut autoscale = autoscale_settings(args)?;
    let role = if let Some(url) = &args.primary {
        Role::Worker(
            Worker::start(
                data,
                url,
                args.advertise.as_deref().unwrap_or_default(),
                args.join_token.as_deref(),
                args.primary_ca_sha256.as_deref(),
            )
            .await?,
        )
    } else if args.fleet_listen.is_some() {
        let (cert_pem, key_pem) = secrets::egress_ca_pem(data, &sbox)?;
        Role::Primary(Arc::new(
            Primary::new(&data.join("fleet"), &sbox, EgressCa { cert_pem, key_pem })
                .context("load the fleet CA")?,
        ))
    } else {
        Role::Single
    };
    let sessions = match role {
        // Set from the primary's key at each fleet sync.
        Role::Worker(_) => crate::session::Sessions::default(),
        _ => crate::session::Sessions::load(&data.join("session.key"))
            .context("open the session key")?,
    };
    if db.is_postgres() {
        crate::leader::push_shared(&db, data, &sbox).context("store the shared files")?;
    }
    // Every host of a fleet uses the primary's egress CA, so sandboxes can
    // move between them.
    let ca = match &role {
        Role::Worker(w) => match w.egress_ca().await {
            Ok(theirs) => {
                if secrets::install_egress_ca(data, &sbox, &theirs.cert_pem, &theirs.key_pem)? {
                    eprintln!("now using the primary's egress CA; templates are built again");
                }
                Arc::new(secrets::egress_ca(data, &sbox).context("load egress CA")?)
            }
            Err(error) => {
                eprintln!("warning: cannot get the primary's egress CA: {error:#}");
                ca
            }
        },
        _ => ca,
    };
    let otlp = match &args.otlp_endpoint {
        Some(endpoint) if !endpoint.is_empty() => {
            eprintln!("sending events and traces to {endpoint}");
            traces::init(endpoint).context("start OTLP trace exporter")?;
            Some(Otlp::new(endpoint).context("start OTLP exporter")?)
        }
        _ => None,
    };
    let hub = Hub::start(db.clone(), otlp, usize::try_from(args.events_output_bytes)?);
    let meter = Arc::new(Meter::new(db.clone()));
    let lost = db.delete_unfinished(now_ms())?;
    if !lost.is_empty() {
        eprintln!(
            "marked {} sandboxes from the last run as deleted",
            lost.len()
        );
    }
    for (id, tenant) in &lost {
        hub.record(
            "sandbox.lost",
            &Origin::system(),
            Some(tenant),
            Some(id),
            json!({ "reason": "server restarted" }),
        );
    }
    let node = Arc::new(node);
    let slots = Arc::new(Slots::new(args.max_sandboxes));
    let store = SecretStore::default();
    let secrets = Arc::new(Secrets::load(db.clone(), sbox, store.clone()).context("load secrets")?);
    let network = Arc::new(Network {
        ca_pem: ca.cert_pem().to_owned(),
        proxy: Egress::start(
            args.egress_port,
            spawn_node::netplan::EGRESS_MARK,
            args.egress_policy.clone(),
            ca,
            store,
            {
                let hub = Arc::clone(&hub);
                let meter = Arc::clone(&meter);
                Arc::new(move |activity| {
                    if let Activity::Connection {
                        sandbox,
                        tenant: Some(tenant),
                        up,
                        down,
                        ..
                    } = &activity
                        // Template builds are not metered.
                        && sandbox.starts_with("sbx_")
                    {
                        meter.egress(tenant, sandbox, up.saturating_add(*down), now_ms());
                    }
                    hub.egress(activity);
                })
            },
        )
        .await
        .context("start egress proxy")?,
        policy: args.egress_policy.clone(),
    });
    network
        .proxy
        .serve_dns(args.dns_port, args.dns)
        .await
        .context("start DNS forwarder")?;
    let build_store = match &args.build_store {
        Some(url) => {
            let store = BuildStore::open(url).context("open build store")?;
            eprintln!("build store: {}", store.url());
            Some(Arc::new(store))
        }
        None => None,
    };
    let started = Instant::now();
    let templates = Templates::start(
        db.clone(),
        Arc::clone(&node),
        Arc::clone(&slots),
        Arc::clone(&network),
        Arc::clone(&secrets),
        inputs,
        data.join("builds"),
        Resources {
            vcpus: Some(u32::from(args.vcpus)),
            memory_mib: Some(args.memory_mib),
            disk_gib: Some(args.upper_disk_gib),
        },
        usize::try_from(args.max_builds)?,
        build_store,
        args.build_cache_gib.saturating_mul(1 << 30),
    )
    .await
    .context("load templates")?;
    eprintln!(
        "templates ready in {:.1} s",
        started.elapsed().as_secs_f64()
    );

    let volumes = Arc::new(
        Volumes::new(
            db.clone(),
            data.join("volumes"),
            node.backend(),
            Arc::clone(&meter),
            !matches!(role, Role::Worker(_)),
        )
        .context("open volumes")?,
    );
    let app = Arc::new(App {
        sandboxes: Sandboxes::new(
            Parts {
                node,
                db: db.clone(),
                templates: Arc::clone(&templates),
                slots,
                network: Arc::clone(&network),
                secrets: Arc::clone(&secrets),
                volumes: Arc::clone(&volumes),
                hub: Arc::clone(&hub),
                meter,
            },
            Settings {
                max_timeout_s: args.max_timeout_s,
                idle_pause_s: args.idle_pause_s,
                paused_retention_s: args.paused_retention_s,
                paused_dir: data.join("paused"),
                warm_memory_mib: host_memory_mib()? * u64::from(args.warm_pool_memory_pct) / 100,
                warm_min: usize::try_from(args.warm_pool_min)?,
                warm_reserve: usize::try_from(args.max_builds)?,
                memory_limit_mib: host_memory_mib()? * u64::from(args.memory_overcommit_pct) / 100,
                memory_pressure_pct: args.memory_pressure_pct,
            },
        ),
        templates,
        secrets,
        volumes,
        db,
        preview_url: args.preview_url.clone(),
        sessions,
        role,
    });
    let paused = app
        .sandboxes
        .load_paused()
        .context("load paused sandboxes")?;
    if paused > 0 {
        eprintln!("{paused} paused sandboxes");
    }
    let reaper = {
        let app = Arc::clone(&app);
        let retention_ms =
            i64::try_from(args.events_retention_s.saturating_mul(1000)).unwrap_or(i64::MAX);
        tokio::spawn(async move {
            let mut next_prune = Instant::now();
            let mut next_meter = Instant::now() + METER_EVERY;
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                app.sandboxes.expire();
                app.sandboxes.pause_idle();
                app.sandboxes.relieve_pressure();
                app.sandboxes.refill_warm();
                if Instant::now() >= next_meter {
                    next_meter = Instant::now() + METER_EVERY;
                    app.volumes.meter();
                    app.sandboxes.meter();
                }
                if retention_ms > 0 && Instant::now() >= next_prune {
                    next_prune = Instant::now() + Duration::from_secs(60);
                    app.sandboxes
                        .hub
                        .prune(now_ms().saturating_sub(retention_ms))
                        .await;
                }
            }
        })
    };
    let on_shutdown = Arc::clone(&app);
    let shutdown = async move {
        shutdown_signal().await;
        eprintln!("stopping all sandboxes");
        on_shutdown.templates.close();
        // Ends open exec streams, so the server can finish.
        on_shutdown.sandboxes.stop_all().await;
        // Ends event follow streams.
        on_shutdown.sandboxes.hub.stop_feeds();
    };
    let mut background = vec![reaper];
    if let Some(addr) = args.metrics_listen {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("listen on {addr}"))?;
        eprintln!("metrics on http://{addr}/metrics");
        let routes = Router::new()
            .route("/metrics", get(metrics_text))
            .with_state(Arc::clone(&app));
        let max_sandboxes = args.max_sandboxes;
        let routes = routes.layer(axum::Extension(max_sandboxes));
        background.push(tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, routes).await {
                eprintln!("metrics listener: {error}");
            }
        }));
    }
    let served = match &app.role {
        Role::Worker(w) => {
            let addr = args.node_listen.context("--node-listen is needed")?;
            let listener = tls::Listener::bind(addr, w.server_config()?).await?;
            eprintln!("node listener on https://{addr}");
            background.extend(worker::spawn(Arc::clone(&app), Arc::clone(w)));
            let service =
                worker::router(Arc::clone(&app)).into_make_service_with_connect_info::<Peer>();
            axum::serve(listener, service)
                .with_graceful_shutdown(shutdown)
                .await
        }
        Role::Primary(_) | Role::Single => {
            let preview_listener = tls::Bound::bind(
                args.preview_listen,
                tls_files(args.preview_tls_cert.clone(), args.preview_tls_key.clone()),
            )
            .await?;
            eprintln!("previews on {}", preview_listener.url(args.preview_listen));
            let previews =
                preview_listener.serve(preview::router(Arc::clone(&app)), std::future::pending());
            background.push(tokio::spawn(async move {
                if let Err(error) = previews.await {
                    eprintln!("preview listener: {error}");
                }
            }));
            if let (Role::Primary(p), Some(addr)) = (&app.role, args.fleet_listen) {
                let listener = tls::Listener::bind(addr, p.server_config()?).await?;
                eprintln!(
                    "fleet listener on https://{addr}; CA SHA-256 {}",
                    p.ca_sha256()?
                );
                let service =
                    primary::router(Arc::clone(&app)).into_make_service_with_connect_info::<Peer>();
                background.push(tokio::spawn(async move {
                    if let Err(error) = axum::serve(listener, service).await {
                        eprintln!("fleet listener: {error}");
                    }
                }));
                background.push(primary::watch(Arc::clone(&app)));
                if let Some(settings) = autoscale.take() {
                    background.push(fleet::autoscale::start(Arc::clone(&app), settings)?);
                }
            }
            let listener = tls::Bound::bind(
                args.listen,
                tls_files(args.tls_cert.clone(), args.tls_key.clone()),
            )
            .await?;
            eprintln!("listening on {}", listener.url(args.listen));
            listener.serve(router(Arc::clone(&app)), shutdown).await
        }
    };
    for task in background {
        task.abort();
    }
    app.templates.close();
    app.sandboxes.stop_all().await;
    if let Err(error) = app.sandboxes.flush_usage() {
        eprintln!("usage: write: {error}");
    }
    network.proxy.close();
    app.sandboxes.hub.close().await;
    let _ = tokio::task::spawn_blocking(traces::shutdown).await;
    served.context("serve HTTP")
}

/// The registry plus gauges read now, in the Prometheus text format.
async fn metrics_text(
    State(app): State<AppState>,
    axum::Extension(max_sandboxes): axum::Extension<u32>,
) -> Response {
    let mut samples: Vec<(&'static str, metrics::Labels, f64)> = Vec::new();
    match app.db.count_local_sandboxes() {
        Ok(counts) => {
            for (state, count) in counts {
                samples.push(("spawnbox_sandboxes", vec![("state", state)], count as f64));
            }
        }
        Err(error) => eprintln!("metrics: count sandboxes: {error}"),
    }
    let free = app.sandboxes.free_slots() as f64;
    let slots = f64::from(max_sandboxes);
    samples.push((
        "spawnbox_node_committed_ratio",
        vec![("resource", "slots".into())],
        (1.0 - free / slots).clamp(0.0, 1.0),
    ));
    if let (Ok(total), Some(available)) = (host_memory_mib(), fleet::memory_available_mib())
        && total > 0
    {
        samples.push((
            "spawnbox_node_committed_ratio",
            vec![("resource", "memory".into())],
            (1.0 - available as f64 / total as f64).clamp(0.0, 1.0),
        ));
    }
    for pool in app.sandboxes.warm_pools().2 {
        samples.push((
            "spawnbox_warm_pool_ready",
            vec![
                ("template", pool.template),
                ("build", pool.build),
                ("network", pool.network.into()),
            ],
            pool.ready as f64,
        ));
    }
    if let Role::Primary(p) = &app.role {
        if let Some(load) = p.autoscaler.get().and_then(|a| a.load()) {
            samples.push(("spawnbox_fleet_load", vec![], load));
        }
        match app.db.list_nodes() {
            Ok(nodes) => {
                let mut counts = std::collections::BTreeMap::<String, u32>::new();
                for node in nodes {
                    *counts.entry(node.state).or_default() += 1;
                }
                for (state, count) in counts {
                    samples.push(("spawnbox_fleet_nodes", vec![("state", state)], count.into()));
                }
            }
            Err(error) => eprintln!("metrics: list nodes: {error}"),
        }
    }
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics::render(&samples),
    )
        .into_response()
}

/// `MemTotal` from `/proc/meminfo`.
fn host_memory_mib() -> Result<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    parse_mem_total(&info).context("no MemTotal in /proc/meminfo")
}

fn parse_mem_total(info: &str) -> Option<u64> {
    let line = info.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024)
}

async fn warm_pools(State(app): State<AppState>) -> Json<Value> {
    let (used, budget, pools) = app.sandboxes.warm_pools();
    Json(json!({
        "memory_mib": used,
        "memory_budget_mib": budget,
        "pools": pools,
    }))
}

pub fn tls_files(cert: Option<PathBuf>, key: Option<PathBuf>) -> Option<tls::Files> {
    Some(tls::Files {
        cert: cert?,
        key: key?,
    })
}

pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(term) => term,
        Err(error) => {
            eprintln!("warning: cannot watch SIGTERM: {error}");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

pub fn router(app: AppState) -> Router {
    let v1 = Router::new()
        .route("/v1/sandboxes", post(create).get(list))
        .route(
            "/v1/sandboxes/{id}",
            get(get_one).delete(delete).post(pause_or_resume),
        )
        .route("/v1/sandboxes/{id}/exec", post(exec))
        .route("/v1/sandboxes/{id}/pty", get(terminal::open))
        .route("/v1/sandboxes/{id}/session-tokens", post(session_token))
        .route("/v1/sandboxes/{id}/git:clone", post(git_clone))
        .route(
            "/v1/sandboxes/{id}/ports",
            post(preview::publish).get(preview::list),
        )
        .route(
            "/v1/sandboxes/{id}/ports/{port}",
            axum::routing::delete(preview::unpublish),
        )
        .route(
            "/v1/sandboxes/{id}/files",
            get(read_file).put(write_file).delete(delete_file),
        )
        .route(
            "/v1/templates",
            post(put_template)
                .get(list_templates)
                .layer(DefaultBodyLimit::max(MAX_TEMPLATE_BODY)),
        )
        .route(
            "/v1/templates/{name}",
            get(get_template).delete(delete_template),
        )
        .route("/v1/templates/{name}/builds/{build_id}", get(get_build))
        .route("/v1/secrets", post(create_secret).get(list_secrets))
        .route(
            "/v1/secrets/{name}",
            get(get_secret).patch(update_secret).delete(delete_secret),
        )
        .route("/v1/volumes", post(create_volume).get(list_volumes))
        .route("/v1/volumes/{name}", get(get_volume).delete(delete_volume))
        .route("/v1/tenants", post(create_tenant).get(list_tenants))
        .route(
            "/v1/tenants/{id}",
            get(get_tenant).patch(update_tenant).delete(delete_tenant),
        )
        .route("/v1/keys", post(create_key).get(list_keys))
        .route("/v1/keys/{id}", axum::routing::delete(revoke_key))
        .route("/v1/events", get(list_events))
        .route("/v1/sandboxes/{id}/events", get(sandbox_events))
        .route("/v1/usage", get(usage))
        .route("/v1/warm-pools", get(warm_pools))
        .route("/v1/nodes", get(primary::list_nodes))
        .route("/v1/nodes/tokens", post(primary::new_token))
        .route("/v1/nodes/autoscale", get(fleet::autoscale::status))
        .route(
            "/v1/nodes/{id}",
            get(primary::get_node)
                .delete(primary::remove_node)
                .post(primary::node_action),
        )
        .route_layer(middleware::from_fn_with_state(Arc::clone(&app), auth));
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .merge(v1)
        .fallback(|| async { ApiError::new(Code::NotFound, "no such endpoint") })
        .with_state(app)
}

/// `Retry-After` of a `no_capacity` reply.
const NO_CAPACITY_RETRY_S: &str = "30";

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = ids::new_id("req").unwrap_or_default();
        metrics::inc(
            "spawnbox_api_errors_total",
            vec![("code", self.code.as_str().into())],
        );
        if self.code == Code::Internal {
            eprintln!("{request_id}: {}", self.message);
        }
        let status = StatusCode::from_u16(self.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = (status, Json(self.body(&request_id))).into_response();
        if self.code == Code::NoCapacity {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_static(NO_CAPACITY_RETRY_S),
            );
        }
        response
    }
}

/// Finds the caller's key, checks its scope, and hides other tenants'
/// sandboxes from tenant keys. Handlers get the `Caller` and the call's
/// `Origin` for events.
async fn auth(State(app): State<AppState>, mut req: Request, next: Next) -> Response {
    if let Some(id) = tenancy::sandbox_in_path(req.uri().path())
        && !req.uri().path().ends_with(":migrate")
    {
        primary::wait_for_move(&app, id).await;
    }
    let (caller, origin, remote) = match authorize(&app, &req) {
        Ok(found) => found,
        Err(error) => return error.into_response(),
    };
    if let Some((node, id)) = remote {
        return primary::forward_api(&app, &node, &id, req).await;
    }
    req.extensions_mut().insert(caller);
    req.extensions_mut().insert(origin);
    next.run(req).await
}

/// Worker node and ID of a sandbox that another host runs.
type RemoteSandbox = (String, String);

/// Also returns the sandbox the call is for, if another host runs it.
fn authorize(
    app: &App,
    req: &Request,
) -> Result<(Caller, Origin, Option<RemoteSandbox>), ApiError> {
    let caller = match caller(&app.db, req.headers())? {
        Some(caller) => Some(caller),
        None => session_caller(app, req)?,
    }
    .ok_or_else(|| ApiError::new(Code::Unauthorized, "missing or unknown API key"))?;
    let path = req.uri().path();
    caller.require(tenancy::required_scope(req.method().as_str(), path))?;
    let read = matches!(req.method().as_str(), "GET" | "HEAD");
    if matches!(app.role, Role::Worker(_)) && !read && !path.starts_with("/v1/sandboxes") {
        return Err(ApiError::new(
            Code::Conflict,
            "this server is a fleet worker; make changes on the primary",
        ));
    }
    let mut remote = None;
    if let Some(id) = tenancy::sandbox_in_path(path) {
        // Handlers see the percent-decoded ID, so an encoded one could name
        // another tenant's sandbox past this check. Real IDs never need it.
        if id.contains('%') {
            return Err(ApiError::not_found());
        }
        let row = if ids::is_valid_id("sbx", id) {
            app.db.get_sandbox(id)?
        } else {
            None
        };
        if let Some(own) = &caller.tenant
            && row.as_ref().is_some_and(|s| s.tenant != *own)
        {
            return Err(ApiError::not_found());
        }
        // Events of every host are kept here, and the primary moves
        // sandboxes.
        if !path.ends_with("/events")
            && !path.ends_with(":migrate")
            && let Some(node) = row.and_then(primary::remote_node)
        {
            remote = Some((node, id.to_owned()));
        }
    }
    let header_text = |name: &str| {
        req.headers()
            .get(name)
            .map(|value| {
                value.to_str().map_err(|_| {
                    ApiError::invalid(format!("{name} must be visible ASCII characters"))
                })
            })
            .transpose()
    };
    let origin = Origin::of_call(
        &caller.key,
        header_text(STEP_HEADER)?,
        header_text("traceparent")?,
    )?;
    Ok((caller, origin, remote))
}

/// The caller behind the request's bearer key, if it is active.
pub fn caller(db: &Db, headers: &HeaderMap) -> Result<Option<Caller>, ApiError> {
    let key = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(ids::bearer);
    let Some(key) = key else {
        return Ok(None);
    };
    db.find_key(&ids::hash_key(key))?
        .map(|key| Caller::from_key(&key))
        .transpose()
}

/// A browser session token stands in for an API key only to open that
/// sandbox's terminal. Browsers cannot set headers on a WebSocket, so it
/// may come as `?session_token=`.
fn session_caller(app: &App, req: &Request) -> Result<Option<Caller>, ApiError> {
    let path = req.uri().path();
    let Some(id) = tenancy::sandbox_in_path(path) else {
        return Ok(None);
    };
    if req.method() != axum::http::Method::GET || path != format!("/v1/sandboxes/{id}/pty") {
        return Ok(None);
    }
    let from_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim().to_owned());
    let token = from_header.or_else(|| {
        let query = req.uri().query()?;
        crate::ports::take_param(query, crate::session::PTY_PARAM).0
    });
    match token {
        Some(token) => Ok(app
            .sessions
            .caller(&app.db, &token, id, now_ms())?
            .map(|(caller, _)| caller)),
        None => Ok(None),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionTokenRequest {
    ttl_s: Option<u64>,
}

/// `POST /v1/sandboxes/{id}/session-tokens`.
async fn session_token(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let req: SessionTokenRequest = parse(&body)?;
    let max = crate::session::MAX_TTL_S;
    let ttl_s = req.ttl_s.unwrap_or(max);
    if !(1..=max).contains(&ttl_s) {
        return Err(ApiError::invalid(format!("ttl_s must be 1 to {max}")));
    }
    let sandbox = app.sandboxes.get(&id)?;
    let claims = crate::session::claims(&caller, &sandbox.tenant, &id, ttl_s, now_ms())
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let token = app.sessions.issue(&claims)?;
    let expires_at = rfc3339_ms(claims.exp * 1000);
    app.sandboxes.event(
        "sandbox.session_token_created",
        &origin,
        &sandbox.tenant,
        &id,
        json!({ "token_id": claims.jti, "expires_at": expires_at }),
    );
    Ok(Json(json!({ "token": token, "expires_at": expires_at })))
}

#[derive(Deserialize)]
struct TenantQuery {
    tenant: Option<String>,
}

/// The tenant a call works in (`None`: org-wide). Fails with 404 if it does
/// not exist or the caller may not see it.
fn namespace(
    app: &App,
    caller: &Caller,
    requested: Option<&str>,
) -> Result<Option<String>, ApiError> {
    let ns = caller.namespace(requested)?;
    if let Some(tenant) = &ns
        && (!tenancy::is_tenant_id(tenant) || app.db.get_tenant(tenant)?.is_none())
    {
        return Err(tenant_not_found());
    }
    Ok(ns)
}

/// Parses a JSON body into the spec's error format on failure. An empty body
/// counts as `{}`.
pub fn parse<T: DeserializeOwned>(body: &Bytes) -> Result<T, ApiError> {
    let body: &[u8] = if body.iter().all(u8::is_ascii_whitespace) {
        b"{}"
    } else {
        body
    };
    serde_json::from_slice(body).map_err(|e| ApiError::invalid(format!("request body: {e}")))
}

fn view(sandbox: db::Sandbox, timings_ms: Option<Timings>) -> SandboxView {
    let paused = sandbox.state == state::PAUSED;
    SandboxView {
        id: sandbox.id,
        tenant: sandbox.tenant,
        state: sandbox.state,
        template: sandbox.template,
        build: sandbox.build,
        labels: sandbox.labels,
        secrets: sandbox.secrets,
        volumes: sandbox
            .volumes
            .into_iter()
            .map(|v| VolumeMount {
                volume: v.name,
                path: v.path,
                read_only: v.read_only,
            })
            .collect(),
        egress: sandbox.egress,
        created_at: rfc3339_ms(sandbox.created_at),
        expires_at: (!paused).then(|| rfc3339_ms(sandbox.expires_at)),
        paused_at: sandbox.paused_at.filter(|_| paused).map(rfc3339_ms),
        idle_pause_s: sandbox.idle_pause_s,
        node: sandbox
            .node
            .or_else(|| fleet::self_node().map(str::to_owned)),
        started_from: timings_ms.map(|t| if t.warm { "warm_pool" } else { "build" }),
        timings_ms,
    }
}

async fn create(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let req: CreateSandbox = parse(&body)?;
    let ns = namespace(&app, &caller, req.tenant.as_deref())?;
    let tenant = app
        .db
        .get_tenant(ns.as_deref().unwrap_or(DEFAULT_TENANT))?
        .ok_or_else(tenant_not_found)?;
    if matches!(app.role, Role::Primary(_)) {
        return primary::create(&app, tenant, req, &headers, body, origin).await;
    }
    create_here(app, tenant, req, origin).await
}

/// Creates a sandbox on this host.
pub async fn create_here(
    app: AppState,
    tenant: Tenant,
    req: CreateSandbox,
    origin: Origin,
) -> Result<Response, ApiError> {
    if !tenant.isolation.allows(app.templates.backend().name()) {
        return Err(ApiError::new(
            Code::NoCapacity,
            "this tenant's sandboxes need microVM isolation, and this host runs gVisor",
        ));
    }
    let (sandbox, timings) =
        finish(async move { app.sandboxes.create(tenant, req, &origin).await }).await?;
    Ok((StatusCode::CREATED, Json(view(sandbox, Some(timings)))).into_response())
}

#[derive(Deserialize)]
struct ListQuery {
    tenant: Option<String>,
    state: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
}

async fn list(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    if let Some(s) = &query.state
        && !state::ALL.contains(&s.as_str())
    {
        return Err(ApiError::invalid(format!(
            "state must be one of {}",
            state::ALL.join(", ")
        )));
    }
    let limit = match &query.limit {
        None => DEFAULT_PAGE,
        Some(text) => text
            .parse()
            .ok()
            .filter(|n| (1..=MAX_PAGE).contains(n))
            .ok_or_else(|| ApiError::invalid(format!("limit must be 1 to {MAX_PAGE}")))?,
    };
    let after = match &query.cursor {
        None => 0,
        Some(text) => text
            .parse()
            .ok()
            .filter(|n: &i64| *n >= 0)
            .ok_or_else(|| ApiError::invalid("cursor is not valid"))?,
    };
    let (page, next) = app
        .sandboxes
        .list(ns.as_deref(), query.state.as_deref(), limit, after)?;
    let sandboxes: Vec<SandboxView> = page.into_iter().map(|s| view(s, None)).collect();
    Ok(Json(json!({
        "sandboxes": sandboxes,
        "next_cursor": next.map(|n| n.to_string()),
    })))
}

async fn get_one(
    State(app): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SandboxView>, ApiError> {
    Ok(Json(view(app.sandboxes.get(&id)?, None)))
}

async fn delete(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    finish(async move { app.sandboxes.delete(&id, &origin).await }).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Runs `work` in its own task. A client that disconnects drops the handler,
/// which would otherwise stop a create or delete halfway and leak its VM.
async fn finish<T: Send + 'static>(
    work: impl Future<Output = Result<T, ApiError>> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::spawn(work)
        .await
        .map_err(|error| ApiError::new(Code::Internal, format!("task failed: {error}")))?
}

/// `POST /v1/sandboxes/{id}:pause`, `:resume`, `:snapshot` and `:fork`.
/// The router sees the action as part of the id.
async fn pause_or_resume(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id_action): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let no_action = || ApiError::new(Code::NotFound, "no such endpoint");
    let (id, action) = id_action.split_once(':').ok_or_else(no_action)?;
    if action == "migrate" {
        return primary::migrate_sandbox(&app, id, &body, &origin)
            .await
            .map(IntoResponse::into_response);
    }
    let id = id.to_owned();
    match action {
        "snapshot" => {
            let req: SnapshotSandbox = parse(&body)?;
            let sandboxes = app.sandboxes.clone();
            let (spec, build) =
                finish(async move { sandboxes.snapshot(&id, &req.name, &origin).await }).await?;
            if let Role::Primary(primary) = &app.role {
                primary.bump();
            }
            let reply = json!({ "template": spec.name, "build": build, "spec": spec });
            return Ok((StatusCode::CREATED, Json(reply)).into_response());
        }
        "fork" => {
            let req: ForkSandbox = parse(&body)?;
            let count = req.count.unwrap_or(1);
            let sandboxes = app.sandboxes.clone();
            let started = finish(async move { sandboxes.fork(&id, count, &origin).await }).await?;
            let failed = count as usize - started.len();
            let views: Vec<SandboxView> = started.into_iter().map(|s| view(s, None)).collect();
            let reply = json!({ "sandboxes": views, "failed": failed });
            return Ok((StatusCode::CREATED, Json(reply)).into_response());
        }
        _ => {}
    }
    let (id, pause) = match action {
        "pause" => (id, true),
        "resume" => (id, false),
        _ => return Err(no_action()),
    };
    let sandbox = finish(async move {
        if pause {
            app.sandboxes.pause(&id, &origin).await
        } else {
            app.sandboxes.resume(&id, &origin).await
        }
    })
    .await?;
    Ok(Json(view(sandbox, None)).into_response())
}

async fn exec(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let req: Exec = parse(&body)?;
    let (events, busy, log) = app.sandboxes.exec(&id, req, &origin).await?;
    let wants_sse = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"));
    if wants_sse {
        Ok(stream_events(events, busy, log))
    } else {
        let result = collect(events, log).await?;
        drop(busy);
        Ok(Json(result).into_response())
    }
}

/// Clones with `git` inside the sandbox. The egress proxy adds attached
/// `git_https` secrets, so credentials never enter the VM.
async fn git_clone(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let req: GitClone = parse(&body)?;
    let (cmd, path) = req.command()?;
    let exec = Exec {
        cmd,
        cwd: None,
        env: [("GIT_TERMINAL_PROMPT".to_owned(), "0".to_owned())].into(),
        user: req.user,
        timeout_s: req.timeout_s,
        stdin: None,
    };
    let (events, busy, log) = app.sandboxes.exec(&id, exec, &origin).await?;
    let result = collect(events, log).await?;
    drop(busy);
    let text = |key: &str| result[key].as_str().unwrap_or_default().to_owned();
    if result["exit_code"] != json!(0) {
        let stderr = text("stderr");
        let tail: String = stderr
            .trim()
            .lines()
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        let why = if result["timed_out"] == json!(true) {
            "timed out".to_owned()
        } else {
            tail
        };
        return Err(ApiError::invalid(format!("git clone failed: {why}")));
    }
    let stdout = text("stdout");
    let mut lines = stdout.lines().rev();
    let branch = lines.next().unwrap_or_default().to_owned();
    let commit = lines.next().unwrap_or_default().to_owned();
    Ok(Json(json!({
        "path": path,
        "commit": commit,
        "branch": (branch != "HEAD").then_some(branch),
        "duration_ms": result["duration_ms"],
    })))
}

fn exit_json(exit: &ExecExit) -> Value {
    json!({
        "exit_code": exit.exit_code,
        "signal": exit.signal,
        "timed_out": exit.timed_out,
        "duration_ms": exit.duration_ms,
    })
}

/// Keeps up to `MAX_JSON_OUTPUT` bytes of each stream and reports the rest
/// as truncated.
async fn collect(mut events: Streaming<ExecEvent>, mut log: ExecLog) -> Result<Value, ApiError> {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let (mut stdout_cut, mut stderr_cut) = (false, false);
    let mut exit = None;
    loop {
        let event = match events.message().await {
            Ok(Some(event)) => event,
            Ok(None) => break,
            Err(status) => {
                let error = format!("guest agent: {}", status.message());
                log.failed(&error);
                return Err(ApiError::internal(error));
            }
        };
        if let Some(seen) = &event.event {
            log.see(seen);
        }
        let (buffer, cut, bytes) = match event.event {
            Some(GuestEvent::Stdout(bytes)) => (&mut stdout, &mut stdout_cut, bytes),
            Some(GuestEvent::Stderr(bytes)) => (&mut stderr, &mut stderr_cut, bytes),
            Some(GuestEvent::Exit(e)) => {
                exit = Some(e);
                continue;
            }
            None => continue,
        };
        let room = MAX_JSON_OUTPUT - buffer.len();
        if bytes.len() > room {
            *cut = true;
        }
        buffer.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }
    let Some(exit) = exit else {
        let error = "command ended without an exit status";
        log.failed(error);
        return Err(ApiError::internal(error));
    };
    let mut body = exit_json(&exit);
    body["exec_id"] = json!(log.id());
    body["stdout"] = json!(String::from_utf8_lossy(&stdout));
    body["stderr"] = json!(String::from_utf8_lossy(&stderr));
    body["stdout_truncated"] = json!(stdout_cut);
    body["stderr_truncated"] = json!(stderr_cut);
    Ok(body)
}

/// SSE events: `stdout` and `stderr` with `{"text": ...}`, then one `exit`,
/// or one `error` if the guest connection fails. Closing the connection
/// kills the command.
fn stream_events(mut events: Streaming<ExecEvent>, busy: Busy, mut log: ExecLog) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Event, Infallible>>(32);
    tokio::spawn(async move {
        let _busy = busy;
        let (mut out, mut err) = (Utf8Stream::default(), Utf8Stream::default());
        let text = |name: &str, text: String| {
            (!text.is_empty()).then(|| {
                Event::default()
                    .event(name)
                    .data(json!({ "text": text }).to_string())
            })
        };
        loop {
            let message = tokio::select! {
                message = events.message() => message,
                () = tx.closed() => return,
            };
            let mut done = false;
            if let Ok(Some(ExecEvent { event: Some(seen) })) = &message {
                log.see(seen);
            }
            let batch: Vec<Option<Event>> = match message {
                Ok(Some(event)) => match event.event {
                    Some(GuestEvent::Stdout(bytes)) => vec![text("stdout", out.push(&bytes))],
                    Some(GuestEvent::Stderr(bytes)) => vec![text("stderr", err.push(&bytes))],
                    Some(GuestEvent::Exit(exit)) => {
                        let mut data = exit_json(&exit);
                        data["exec_id"] = json!(log.id());
                        vec![
                            text("stdout", out.finish()),
                            text("stderr", err.finish()),
                            Some(Event::default().event("exit").data(data.to_string())),
                        ]
                    }
                    None => continue,
                },
                Ok(None) => {
                    log.failed("command ended without an exit status");
                    return;
                }
                Err(status) => {
                    done = true;
                    let error = ApiError::internal(format!("guest agent: {}", status.message()));
                    log.failed(&error.message);
                    let request_id = ids::new_id("req").unwrap_or_default();
                    eprintln!("{request_id}: {}", error.message);
                    vec![Some(
                        Event::default()
                            .event("error")
                            .data(error.body(&request_id).to_string()),
                    )]
                }
            };
            for event in batch.into_iter().flatten() {
                if tx.send(Ok(event)).await.is_err() {
                    return;
                }
            }
            if done {
                return;
            }
        }
    });
    Sse::new(ReceiverStream::new(rx))
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn create_secret(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    Query(query): Query<TenantQuery>,
    body: Bytes,
) -> Result<(StatusCode, Json<SecretView>), ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let input: SecretInput = parse(&body)?;
    let view = app.secrets.create(ns.as_deref(), input, now_ms())?;
    app.admin_event(
        "secret.created",
        &origin,
        ns.as_deref(),
        secret_attrs(&view),
    );
    Ok((StatusCode::CREATED, Json(view)))
}

async fn list_secrets(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    Ok(Json(json!({ "secrets": app.secrets.list(ns.as_deref())? })))
}

async fn get_secret(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
) -> Result<Json<SecretView>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    Ok(Json(app.secrets.get(ns.as_deref(), &name)?))
}

async fn update_secret(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<Json<SecretView>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let input: SecretInput = parse(&body)?;
    let kind = if input.value.is_some() {
        "secret.rotated"
    } else {
        "secret.updated"
    };
    let view = app.secrets.update(ns.as_deref(), &name, input, now_ms())?;
    app.admin_event(kind, &origin, ns.as_deref(), secret_attrs(&view));
    Ok(Json(view))
}

async fn delete_secret(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    app.secrets.delete(ns.as_deref(), &name)?;
    app.admin_event(
        "secret.deleted",
        &origin,
        ns.as_deref(),
        json!({ "name": name }),
    );
    Ok(StatusCode::NO_CONTENT)
}

fn volume_view(app: &App, volume: db::Volume) -> Result<Value, ApiError> {
    let mounts: Vec<Value> = app
        .db
        .volume_users(&volume.id)?
        .into_iter()
        .map(|user| json!({ "sandbox": user.sandbox, "read_only": user.read_only }))
        .collect();
    let node = match (&volume.node, &volume.backend) {
        (Some(node), _) => Some(node.clone()),
        (None, Some(_)) => fleet::self_node().map(str::to_owned),
        (None, None) => None,
    };
    Ok(json!({
        "id": volume.id,
        "name": volume.name,
        "tenant": volume.tenant,
        "size_gib": volume.size_gib,
        "node": node,
        "backend": volume.backend,
        "mounts": mounts,
        "created_at": rfc3339_ms(volume.created_at),
    }))
}

fn volume_attrs(volume: &db::Volume) -> Value {
    json!({ "name": volume.name, "id": volume.id, "size_gib": volume.size_gib })
}

async fn create_volume(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let req: CreateVolume = parse(&body)?;
    let ns = namespace(&app, &caller, req.tenant.as_deref())?;
    let tenant = app
        .db
        .get_tenant(ns.as_deref().unwrap_or(DEFAULT_TENANT))?
        .ok_or_else(tenant_not_found)?;
    let volume = app.volumes.create(&tenant, &req)?;
    app.sandboxes.hub.record(
        "volume.created",
        &origin,
        Some(&tenant.id),
        None,
        volume_attrs(&volume),
    );
    Ok((StatusCode::CREATED, Json(volume_view(&app, volume)?)))
}

async fn list_volumes(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let volumes = app
        .volumes
        .list(ns.as_deref())?
        .into_iter()
        .map(|volume| volume_view(&app, volume))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({ "volumes": volumes })))
}

async fn get_volume(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let volume = app
        .volumes
        .get(ns.as_deref().unwrap_or(DEFAULT_TENANT), &name)?;
    Ok(Json(volume_view(&app, volume)?))
}

async fn delete_volume(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let tenant = ns.as_deref().unwrap_or(DEFAULT_TENANT);
    let volume = crate::fleet::volumes::delete(&app, tenant, &name).await?;
    app.sandboxes.hub.record(
        "volume.deleted",
        &origin,
        Some(tenant),
        None,
        volume_attrs(&volume),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn put_template(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    Query(query): Query<TenantQuery>,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    let spec: TemplateSpec = parse(&body)?;
    let (template, build) = app.templates.put(ns.as_deref(), spec)?;
    app.admin_event(
        "template.saved",
        &origin,
        ns.as_deref(),
        json!({ "name": template.spec.name, "build_id": build.id }),
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "template": template, "build": build })),
    ))
}

async fn list_templates(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<TenantQuery>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    Ok(Json(
        json!({ "templates": app.templates.list(ns.as_deref())? }),
    ))
}

async fn get_template(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    Ok(Json(json!(app.templates.get(ns.as_deref(), &name)?)))
}

async fn delete_template(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Extension(origin): Extension<Origin>,
    Query(query): Query<TenantQuery>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    app.templates.delete(ns.as_deref(), &name)?;
    app.admin_event(
        "template.deleted",
        &origin,
        ns.as_deref(),
        json!({ "name": name }),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn get_build(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<TenantQuery>,
    Path((name, build_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let ns = namespace(&app, &caller, query.tenant.as_deref())?;
    Ok(Json(json!(app.templates.build(
        ns.as_deref(),
        &name,
        &build_id
    )?)))
}

fn tenant_json(tenant: Tenant, usage: Option<Usage>) -> Value {
    let mut body = json!({
        "id": tenant.id,
        "name": tenant.name,
        "quotas": tenant.quotas,
        "egress": tenant.egress,
        "isolation": tenant.isolation,
        "created_at": rfc3339_ms(tenant.created_at),
        "updated_at": rfc3339_ms(tenant.updated_at),
    });
    if let Some(usage) = usage {
        body["usage"] = json!(usage);
    }
    body
}

fn find_tenant(app: &App, id: &str) -> Result<Tenant, ApiError> {
    if !tenancy::is_tenant_id(id) {
        return Err(tenant_not_found());
    }
    app.db.get_tenant(id)?.ok_or_else(tenant_not_found)
}

async fn create_tenant(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let input: TenantInput = parse(&body)?;
    let tenant = input.create(now_ms())?;
    if !app.db.insert_tenant(&tenant)? {
        return Err(ApiError::new(
            Code::Conflict,
            format!("tenant {:?} already exists", tenant.id),
        ));
    }
    app.admin_event(
        "tenant.created",
        &origin,
        Some(&tenant.id),
        json!({ "name": tenant.name }),
    );
    Ok((StatusCode::CREATED, Json(tenant_json(tenant, None))))
}

async fn list_tenants(State(app): State<AppState>) -> Result<Json<Value>, ApiError> {
    let tenants: Vec<Value> = app
        .db
        .list_tenants()?
        .into_iter()
        .map(|t| tenant_json(t, None))
        .collect();
    Ok(Json(json!({ "tenants": tenants })))
}

async fn get_tenant(
    State(app): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let tenant = find_tenant(&app, &id)?;
    let usage = app.sandboxes.usage(&tenant.id);
    let month_egress = app.sandboxes.month_egress(&tenant.id)?;
    let snapshot_bytes = app.sandboxes.snapshot_bytes(&tenant.id);
    let mut body = tenant_json(tenant, Some(usage));
    body["usage"]["monthly_egress_bytes"] = json!(month_egress);
    body["usage"]["snapshot_storage_bytes"] = json!(snapshot_bytes);
    Ok(Json(body))
}

/// New quotas and egress apply to sandboxes created or resumed afterwards.
async fn update_tenant(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let input: TenantInput = parse(&body)?;
    let tenant = input.update(&find_tenant(&app, &id)?, now_ms())?;
    if !app.db.update_tenant(&tenant)? {
        return Err(tenant_not_found());
    }
    app.admin_event(
        "tenant.updated",
        &origin,
        Some(&tenant.id),
        json!({
            "quotas": tenant.quotas,
            "egress": tenant.egress,
            "isolation": tenant.isolation,
        }),
    );
    app.sandboxes.block_over_egress();
    Ok(Json(tenant_json(tenant, None)))
}

async fn delete_tenant(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if id == DEFAULT_TENANT {
        return Err(ApiError::invalid(format!(
            "{DEFAULT_TENANT:?} is built in and cannot be deleted"
        )));
    }
    if !tenancy::is_tenant_id(&id) {
        return Err(tenant_not_found());
    }
    let in_use = |what: &str, n: i64| {
        ApiError::new(
            Code::Conflict,
            format!("tenant {id:?} still has {n} {what}; delete them first"),
        )
    };
    match app.db.delete_tenant(&id, now_ms())? {
        None => Err(tenant_not_found()),
        Some(Ok(())) => {
            app.admin_event("tenant.deleted", &origin, Some(&id), json!({}));
            Ok(StatusCode::NO_CONTENT)
        }
        Some(Err(db::InUse::Sandboxes(n))) => Err(in_use("sandboxes", n)),
        Some(Err(db::InUse::Templates(n))) => Err(in_use("templates", n)),
        Some(Err(db::InUse::Secrets(n))) => Err(in_use("secrets", n)),
        Some(Err(db::InUse::Volumes(n))) => Err(in_use("volumes", n)),
    }
}

fn key_json(key: &db::Key) -> Result<Value, ApiError> {
    let caller = Caller::from_key(key)?;
    Ok(json!({
        "id": key.id,
        "tenant": key.tenant,
        "scopes": caller.scopes,
        "name": key.name,
        "created_at": rfc3339_ms(key.created_at),
        "revoked_at": key.revoked_at.map(rfc3339_ms),
    }))
}

/// The key's secret is in the response once and never again.
async fn create_key(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let mut input: KeyInput = parse(&body)?;
    input.check()?;
    if let Some(tenant) = &input.tenant {
        find_tenant(&app, tenant)
            .map_err(|_| ApiError::invalid(format!("tenant {tenant:?} does not exist")))?;
    }
    let scopes = input
        .scopes
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(ApiError::internal)?;
    let key = ids::new_key(input.tenant.is_some()).map_err(ApiError::internal)?;
    let stored = app.db.insert_key(
        &key,
        input.tenant.as_deref(),
        scopes.as_deref(),
        input.name.as_deref(),
        now_ms(),
    )?;
    let mut body = key_json(&stored)?;
    app.admin_event(
        "key.created",
        &origin,
        stored.tenant.as_deref(),
        json!({ "key_id": stored.id, "scopes": body["scopes"], "name": stored.name }),
    );
    body["key"] = json!(key.secret);
    Ok((StatusCode::CREATED, Json(body)))
}

async fn list_keys(State(app): State<AppState>) -> Result<Json<Value>, ApiError> {
    let keys = app
        .db
        .list_keys()?
        .iter()
        .map(key_json)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!({ "keys": keys })))
}

async fn revoke_key(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !app.db.revoke_key(&id, now_ms())? {
        return Err(ApiError::new(Code::NotFound, "key not found"));
    }
    app.admin_event("key.revoked", &origin, None, json!({ "key_id": id }));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct FileQuery {
    path: Option<String>,
    user: Option<String>,
    #[serde(default)]
    recursive: bool,
}

impl FileQuery {
    /// The path and user for the guest. An empty user means `user`.
    fn target(&self) -> Result<PathRequest, ApiError> {
        let path = self
            .path
            .clone()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| ApiError::invalid("the path query parameter is required"))?;
        if let Some(user) = &self.user {
            check_user(user)?;
        }
        Ok(PathRequest {
            path,
            user: self.user.clone().unwrap_or_default(),
        })
    }
}

fn guest_error(status: tonic::Status) -> ApiError {
    ApiError::from_guest(&status)
}

fn file_json(name_key: &str, info: &FileInfo) -> Value {
    let kind = match info.kind() {
        FileKind::File => "file",
        FileKind::Dir => "dir",
        FileKind::Symlink => "symlink",
        FileKind::Other | FileKind::Unspecified => "other",
    };
    json!({
        name_key: info.path,
        "kind": kind,
        "size": info.size,
        "mode": format!("{:04o}", info.mode),
        "modified_at": rfc3339_ms(info.modified_unix_ms),
    })
}

/// A file's bytes, or a JSON listing for a directory.
async fn read_file(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    Query(query): Query<FileQuery>,
) -> Result<Response, ApiError> {
    let target = query.target()?;
    let opened = app.sandboxes.open(&id, &origin).await?;
    let busy = opened.busy;
    let mut client = FilesClient::new(opened.channel);
    let info = client
        .stat(target.clone())
        .await
        .map_err(guest_error)?
        .into_inner();
    if info.kind() == FileKind::Dir {
        let list = client.list(target).await.map_err(guest_error)?.into_inner();
        let entries: Vec<Value> = list.entries.iter().map(|e| file_json("name", e)).collect();
        return Ok(Json(json!({
            "path": list.path,
            "entries": entries,
            "truncated": list.truncated,
        }))
        .into_response());
    }
    let mut stream = client.read(target).await.map_err(guest_error)?.into_inner();
    let first = stream.message().await.map_err(guest_error)?;
    let Some(ReadPart::Info(info)) = first.and_then(|c| c.chunk) else {
        return Err(ApiError::internal("guest sent no file info"));
    };
    // Busy until the whole file was sent.
    let body = stream.filter_map(move |item| match (&busy, item) {
        (
            _,
            Ok(ReadChunk {
                chunk: Some(ReadPart::Data(data)),
            }),
        ) => Some(Ok(Bytes::from(data))),
        (_, Ok(_)) => None,
        (_, Err(status)) => Some(Err(io::Error::other(status.message().to_owned()))),
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, info.size.to_string()),
        ],
        Body::from_stream(body),
    )
        .into_response())
}

/// Streams the request body into a file. The file is replaced only once the
/// whole body arrived; a broken upload leaves the old file as it was.
async fn write_file(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    Query(query): Query<FileQuery>,
    body: Body,
) -> Result<Json<Value>, ApiError> {
    let target = query.target()?;
    let opened = app.sandboxes.open(&id, &origin).await?;
    let _running = app.sandboxes.hub.begin(&id, &origin);
    let channel = opened.channel;
    let (tx, rx) = mpsc::channel(4);
    let message = |chunk| WriteChunk { chunk: Some(chunk) };
    let header = WriteHeader {
        path: target.path,
        user: target.user,
    };
    let _ = tx.send(message(WritePart::Header(header))).await;
    // Returns the hash of everything sent once it committed.
    let mut pump = tokio::spawn(async move {
        let mut hash = Sha256::new();
        let mut data = body.into_data_stream();
        while let Some(frame) = data.next().await {
            // Without a commit the guest throws the partial file away.
            let Ok(mut bytes) = frame else { return None };
            hash.update(&bytes);
            while !bytes.is_empty() {
                let part = bytes.split_to(bytes.len().min(FILE_CHUNK));
                if tx
                    .send(message(WritePart::Data(part.to_vec())))
                    .await
                    .is_err()
                {
                    return None;
                }
            }
        }
        tx.send(message(WritePart::Commit(true))).await.ok()?;
        Some(hash.finalize())
    });
    let written = FilesClient::new(channel)
        .write(ReceiverStream::new(rx))
        .await;
    let info = match written {
        Ok(info) => info.into_inner(),
        Err(status) => {
            pump.abort();
            return Err(guest_error(status));
        }
    };
    // The guest committed, so the pump has already sent everything.
    let sha256 = (&mut pump).await.ok().flatten().map(|digest| {
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });
    app.sandboxes.event(
        "file.written",
        &origin,
        &opened.tenant,
        &id,
        json!({ "path": info.path, "size": info.size, "sha256": sha256 }),
    );
    Ok(Json(file_json("path", &info)))
}

async fn delete_file(
    State(app): State<AppState>,
    Extension(origin): Extension<Origin>,
    Path(id): Path<String>,
    Query(query): Query<FileQuery>,
) -> Result<StatusCode, ApiError> {
    let target = query.target()?;
    let opened = app.sandboxes.open(&id, &origin).await?;
    let _running = app.sandboxes.hub.begin(&id, &origin);
    FilesClient::new(opened.channel)
        .remove(RemoveRequest {
            path: target.path.clone(),
            user: target.user,
            recursive: query.recursive,
        })
        .await
        .map_err(guest_error)?;
    app.sandboxes.event(
        "file.deleted",
        &origin,
        &opened.tenant,
        &id,
        json!({ "path": target.path, "recursive": query.recursive }),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct EventQuery {
    tenant: Option<String>,
    sandbox: Option<String>,
    step_id: Option<String>,
    #[serde(rename = "type")]
    types: Option<String>,
    since: Option<String>,
    until: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
    #[serde(default)]
    follow: bool,
}

/// `GET /v1/events`: stored events, oldest first, or a live SSE stream with
/// `follow=true`. Tenant keys see only their tenant's events.
async fn list_events(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Result<Response, ApiError> {
    let tenant = event_namespace(&caller, query.tenant.as_deref())?;
    let sandbox = query.sandbox.clone();
    events_response(&app, &headers, query, tenant, sandbox)
}

/// `GET /v1/sandboxes/{id}/events`, also for deleted sandboxes.
async fn sandbox_events(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Result<Response, ApiError> {
    let sandbox = ids::is_valid_id("sbx", &id)
        .then(|| app.db.get_sandbox(&id))
        .transpose()?
        .flatten()
        .filter(|s| caller.tenant.as_ref().is_none_or(|own| *own == s.tenant))
        .ok_or_else(ApiError::not_found)?;
    events_response(&app, &headers, query, None, Some(sandbox.id))
}

/// Like `namespace`, but a deleted tenant's events stay readable by org keys.
fn event_namespace(caller: &Caller, requested: Option<&str>) -> Result<Option<String>, ApiError> {
    let ns = caller.namespace(requested)?;
    if ns.as_deref().is_some_and(|t| !tenancy::is_tenant_id(t)) {
        return Err(tenant_not_found());
    }
    Ok(ns)
}

fn events_response(
    app: &App,
    headers: &HeaderMap,
    query: EventQuery,
    tenant: Option<String>,
    sandbox: Option<String>,
) -> Result<Response, ApiError> {
    let time = |name: &str, text: &Option<String>| parse_time(name, text.as_deref());
    let filter = Filter {
        tenant,
        sandbox,
        step_id: query.step_id.clone(),
        types: query
            .types
            .as_deref()
            .map(Filter::parse_types)
            .transpose()?
            .unwrap_or_default(),
        since: time("since", &query.since)?,
        until: time("until", &query.until)?,
    };
    let cursor = query
        .cursor
        .as_deref()
        .map(|text| {
            text.parse::<i64>()
                .ok()
                .filter(|n| *n >= 0)
                .ok_or_else(|| ApiError::invalid("cursor is not valid"))
        })
        .transpose()?;
    if query.follow {
        let last_seen = headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<i64>().ok());
        let after = match cursor.or(last_seen) {
            Some(after) => after,
            None if filter.since.is_some() => 0,
            None => app.sandboxes.hub.latest()?,
        };
        return Ok(Sse::new(app.sandboxes.hub.follow(filter, after))
            .keep_alive(KeepAlive::default())
            .into_response());
    }
    let limit = match &query.limit {
        None => DEFAULT_EVENT_PAGE,
        Some(text) => text
            .parse()
            .ok()
            .filter(|n| (1..=MAX_EVENT_PAGE).contains(n))
            .ok_or_else(|| ApiError::invalid(format!("limit must be 1 to {MAX_EVENT_PAGE}")))?,
    };
    let (events, has_more) = app.db.list_events(&filter, cursor.unwrap_or(0), limit)?;
    let next_cursor = events
        .last()
        .map(|e| e.id)
        .or(cursor)
        .map(|id| id.to_string());
    let events: Vec<Value> = events.iter().map(|e| e.to_json()).collect();
    Ok(Json(json!({
        "events": events,
        "next_cursor": next_cursor,
        "has_more": has_more,
    }))
    .into_response())
}

/// Unix ms of an optional RFC 3339 query parameter.
fn parse_time(name: &str, text: Option<&str>) -> Result<Option<i64>, ApiError> {
    text.map(|text| {
        OffsetDateTime::parse(text, &Rfc3339)
            .ok()
            .and_then(|t| i64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok())
            .ok_or_else(|| ApiError::invalid(format!("{name} must be an RFC 3339 time")))
    })
    .transpose()
}

#[derive(Deserialize)]
struct UsageQuery {
    tenant: Option<String>,
    from: Option<String>,
    to: Option<String>,
    group_by: Option<String>,
}

/// `GET /v1/usage`: hourly usage per tenant, or per sandbox with
/// `group_by=sandbox`. Tenant keys see only their tenant's.
async fn usage(
    State(app): State<AppState>,
    Extension(caller): Extension<Caller>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<Value>, ApiError> {
    let tenant = event_namespace(&caller, query.tenant.as_deref())?;
    let by_sandbox = match query.group_by.as_deref() {
        None => false,
        Some("sandbox") => true,
        Some(_) => return Err(ApiError::invalid("group_by must be sandbox")),
    };
    let now = now_ms();
    let from = hour_start(parse_time("from", query.from.as_deref())?.unwrap_or(month_start(now)));
    let to = parse_time("to", query.to.as_deref())?.unwrap_or(now);
    // Up to the end of the hour holding `to`, unless it starts one.
    let to = hour_start(to.saturating_add(HOUR_MS - 1));
    if to < from {
        return Err(ApiError::invalid("to must not be before from"));
    }
    if to - from > MAX_USAGE_RANGE_MS {
        return Err(ApiError::invalid(
            "from and to may be at most 93 days apart",
        ));
    }
    app.sandboxes.flush_usage()?;
    let rows = app.db.list_usage(tenant.as_deref(), from, to, by_sandbox)?;
    let mut total = Totals::default();
    let usage: Vec<Value> = rows
        .iter()
        .map(|row| {
            total.add(&row.totals);
            let mut body = totals_json(&row.totals);
            body["hour"] = json!(rfc3339_ms(row.hour));
            body["tenant"] = json!(row.tenant);
            if by_sandbox {
                body["sandbox"] = json!(row.sandbox);
            }
            body
        })
        .collect();
    Ok(Json(json!({
        "from": rfc3339_ms(from),
        "to": rfc3339_ms(to),
        "tenant": tenant,
        "usage": usage,
        "total": totals_json(&total),
    })))
}

fn totals_json(totals: &Totals) -> Value {
    let round = |n: f64| (n * 1e6).round() / 1e6;
    json!({
        "vcpu_s": round(totals.vcpu_s),
        "mem_gib_s": round(totals.mem_gib_s),
        "disk_gib_h": round(totals.disk_gib_h),
        "egress_bytes": totals.egress_bytes,
    })
}
