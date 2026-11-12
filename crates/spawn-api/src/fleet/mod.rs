//! Many hosts, one API. The primary is a normal server that also keeps the
//! fleet: it lets workers join, takes their heartbeats, sends them its
//! tenants, keys, templates and secrets, places new sandboxes, and forwards
//! calls for a worker's sandboxes to that worker over mutual TLS. Edges
//! join too, but run no sandboxes: they route clients' calls.

pub mod autoscale;
pub mod edge;
pub mod forward;
pub mod migrate;
pub mod pki;
pub mod primary;
pub mod retire;
pub mod volumes;
pub mod worker;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::db;
use crate::events::Event;
use crate::metering::{Key as UsageKey, Totals};
pub use crate::secrets::SecretCopy;
use crate::server::App;
use crate::tenancy::Tenant;

pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(5);
/// Without a heartbeat for this long, a node gets no new sandboxes.
pub const SUSPECT_AFTER_MS: i64 = 15_000;
/// Without a heartbeat for this long, a node is down.
pub const DOWN_AFTER_MS: i64 = 30_000;
/// Ended sandboxes stay in heartbeats this long, so the primary learns how
/// they ended.
pub const REPORT_ENDED_MS: i64 = 10 * 60_000;
/// A primary-only header: the request is for the preview proxy.
pub const ROUTE_HEADER: &str = "x-spawnbox-route";
/// Names the worker on its calls to the primary. Checked against its
/// certificate.
pub const NODE_HEADER: &str = "x-spawnbox-node";

/// What this server is in a fleet.
pub enum Role {
    /// No fleet.
    Single,
    Primary(Arc<primary::Primary>),
    Worker(Arc<worker::Worker>),
}

static SELF_NODE: OnceLock<String> = OnceLock::new();

/// This worker's node ID, shown in its sandbox views. `None` on the
/// primary or a single server.
pub fn self_node() -> Option<&'static str> {
    SELF_NODE.get().map(String::as_str)
}

/// A template this host can start sandboxes from now.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadyTemplate {
    /// Storage key: `name` or `tenant/name`.
    pub key: String,
    /// SHA-256 of the spec its build was made from.
    pub spec_sha256: String,
    pub vcpus: u8,
    pub memory_mib: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WarmCount {
    pub template: String,
    pub network: String,
    pub ready: usize,
}

/// What a host has room for.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Capacity {
    pub free_slots: usize,
    /// `--max-sandboxes`. 0 from hosts older than this field.
    #[serde(default)]
    pub slots: usize,
    pub memory_available_mib: u64,
    #[serde(default)]
    pub memory_total_mib: u64,
    /// Memory reserved by running sandboxes, and the most they may
    /// reserve. 0 and 0 from hosts older than these fields.
    #[serde(default)]
    pub memory_reserved_mib: u64,
    #[serde(default)]
    pub memory_limit_mib: u64,
    /// The host is short of memory and pausing idle sandboxes; it takes
    /// no new ones.
    #[serde(default)]
    pub memory_pressure: bool,
    pub templates: Vec<ReadyTemplate>,
    pub warm: Vec<WarmCount>,
    /// `Templates::fingerprint`. Sandboxes move only between hosts with
    /// equal fingerprints and CPUs.
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub cpu: String,
    /// `firecracker` or `gvisor`.
    #[serde(default)]
    pub backend: String,
}

impl Capacity {
    /// Memory that sandboxes may still reserve. No limit from older hosts.
    pub fn memory_unreserved_mib(&self) -> u64 {
        if self.memory_pressure {
            return 0;
        }
        if self.memory_limit_mib == 0 {
            return u64::MAX;
        }
        self.memory_limit_mib
            .saturating_sub(self.memory_reserved_mib)
    }

    /// Memory a new sandbox can have: free memory, and memory that is not
    /// reserved, whichever is less.
    pub fn memory_room_mib(&self) -> u64 {
        self.memory_available_mib.min(self.memory_unreserved_mib())
    }

    pub fn template(&self, key: &str) -> Option<&ReadyTemplate> {
        self.templates.iter().find(|t| t.key == key)
    }

    pub fn warm_ready(&self, template: &str, network: &str) -> usize {
        self.warm
            .iter()
            .filter(|w| w.template == template && w.network == network)
            .map(|w| w.ready)
            .sum()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Heartbeat {
    /// The worker's internal listener now.
    pub url: String,
    pub boot: String,
    pub seq: i64,
    pub config_version: u64,
    pub capacity: Capacity,
    /// Every sandbox that has not ended, and those that ended lately.
    pub sandboxes: Vec<db::Sandbox>,
    /// The worker stops its persistent sandboxes once it has not reached
    /// the primary for `fence_after_s`.
    #[serde(default)]
    pub self_fence: bool,
    #[serde(default)]
    pub fence_after_s: u64,
    /// The worker's software version. Empty from versions that did not
    /// send it.
    #[serde(default)]
    pub version: String,
}

#[derive(Serialize, Deserialize)]
pub struct HeartbeatReply {
    pub config_version: u64,
    /// The newest of this worker's events the primary has.
    pub events_after: i64,
    /// Sandboxes the worker still has that moved to another host. The
    /// worker removes them without events.
    #[serde(default)]
    pub release: Vec<String>,
    /// Copies of persistent sandboxes that are not the current
    /// generation. The worker destroys them.
    #[serde(default)]
    pub stale: Vec<String>,
}

/// The primary asks a worker to start a cold persistent sandbox at
/// `generation`, which the primary claimed for it.
#[derive(Serialize, Deserialize)]
pub struct ColdStart {
    pub sandbox: db::Sandbox,
    /// Its `env` is empty: the worker seals `env` with its own key.
    pub start: db::StartRecord,
    pub env: crate::secretbox::SandboxEnv,
    pub generation: i64,
}

/// The egress CA every host of a fleet uses, so their template
/// fingerprints match and sandboxes can move between them.
#[derive(Clone, Serialize, Deserialize)]
pub struct EgressCa {
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Serialize, Deserialize)]
pub struct JoinRequest {
    pub token: String,
    pub csr_pem: String,
    /// The worker's internal listener, `https://host:port`. Empty for an
    /// edge, which has none.
    pub url: String,
    /// `worker` or `edge`.
    #[serde(default = "worker_kind")]
    pub kind: String,
}

fn worker_kind() -> String {
    db::node_kind::WORKER.to_owned()
}

#[derive(Serialize, Deserialize)]
pub struct JoinReply {
    pub node: String,
    pub cert_pem: String,
    pub ca_pem: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigRequest {
    /// Secrets the worker keeps. The primary sends their current values.
    pub held: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyCopy {
    pub key: db::Key,
    /// Hex SHA-256 of the secret key.
    pub hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TemplateCopy {
    pub key: String,
    pub spec: String,
    /// Sandboxes made from it in the last week. Joining hosts get the most
    /// used templates first.
    #[serde(default)]
    pub uses: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub version: u64,
    pub tenants: Vec<Tenant>,
    pub keys: Vec<KeyCopy>,
    /// Every template but `base`, which each host makes itself.
    pub templates: Vec<TemplateCopy>,
    /// Current values of the held secrets that still exist and that the
    /// worker's sandboxes and templates may use.
    pub secrets: Vec<SecretCopy>,
    /// Held secrets that the primary has deleted. The worker removes only
    /// these, never a secret just left out of `secrets`.
    #[serde(default)]
    pub gone: Vec<String>,
    /// Hex key that signs browser session tokens.
    #[serde(default)]
    pub session_key: Option<String>,
    /// Edges that may send API and preview calls to workers.
    #[serde(default)]
    pub edges: Vec<String>,
}

/// An edge's routing table.
#[derive(Default, Serialize, Deserialize)]
pub struct Routes {
    /// Workers that are not down: node ID and URL.
    pub nodes: Vec<(String, String)>,
    /// Sandbox and node ID of each sandbox a worker runs. Moving sandboxes
    /// are left out, so their calls go to the primary.
    pub sandboxes: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize)]
pub struct SecretPush {
    pub secrets: Vec<SecretCopy>,
}

#[derive(Serialize, Deserialize)]
pub struct EventBatch {
    /// With the worker's IDs.
    pub events: Vec<Event>,
}

#[derive(Serialize, Deserialize)]
pub struct EventReply {
    pub events_after: i64,
}

#[derive(Serialize, Deserialize)]
pub struct UsageBatch {
    pub rows: Vec<(UsageKey, Totals)>,
}

#[derive(Serialize, Deserialize)]
pub struct SyncReply {
    pub config_version: u64,
}

/// Hash of the parts of a template spec (JSON) that a build is made from,
/// so hosts agree on a build when only `min_warm` differs.
pub fn build_hash(spec: &str) -> String {
    match serde_json::from_str::<crate::model::TemplateSpec>(spec)
        .and_then(|s| serde_json::to_string(&s.for_build()))
    {
        Ok(json) => sha256_hex(json.as_bytes()),
        Err(_) => sha256_hex(spec.as_bytes()),
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    pki::fingerprint(bytes)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// What this host has room for now.
pub fn local_capacity(app: &App) -> Capacity {
    let templates = app
        .templates
        .ready_builds()
        .into_iter()
        .filter_map(|(key, build, limits)| {
            let spec = app.db.get_build(&build).ok().flatten()?.spec;
            Some(ReadyTemplate {
                key,
                spec_sha256: build_hash(&spec),
                vcpus: limits.vcpus,
                memory_mib: limits.memory_mib,
            })
        })
        .collect();
    let (_, _, pools) = app.sandboxes.warm_pools();
    let warm = pools
        .into_iter()
        .filter(|p| p.ready > 0)
        .map(|p| WarmCount {
            template: p.template,
            network: p.network.to_owned(),
            ready: p.ready,
        })
        .collect();
    let (memory_reserved_mib, memory_limit_mib) = app.sandboxes.memory_reserved();
    Capacity {
        free_slots: app.sandboxes.free_slots(),
        slots: app.sandboxes.total_slots(),
        memory_available_mib: memory_available_mib().unwrap_or(0),
        memory_total_mib: memory_total_mib().unwrap_or(0),
        memory_reserved_mib,
        memory_limit_mib,
        memory_pressure: app.sandboxes.under_pressure(),
        templates,
        warm,
        fingerprint: app.templates.fingerprint().to_owned(),
        cpu: app.templates.cpu().to_owned(),
        backend: app.templates.backend().name().to_owned(),
    }
}

/// `MemAvailable` from `/proc/meminfo`.
pub fn memory_available_mib() -> Option<u64> {
    meminfo_mib("MemAvailable:")
}

/// `MemTotal` from `/proc/meminfo`.
pub fn memory_total_mib() -> Option<u64> {
    meminfo_mib("MemTotal:")
}

fn meminfo_mib(field: &str) -> Option<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = info.lines().find(|l| l.starts_with(field))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024)
}

/// Checks an advertised node URL: `https://host:port`, nothing more.
pub fn check_node_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("must start with https://")?;
    let (host, port) = rest.rsplit_once(':').ok_or("must have a port")?;
    let ok_host = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'[' | b']' | b':'));
    if !ok_host || port.parse::<u16>().map_or(true, |p| p == 0) {
        return Err("must be https://host:port with no path or user".into());
    }
    Ok(())
}

/// The primary's fleet URLs: the leader's and its standbys'. Standbys do
/// not listen, so calls go to the URL that answered last and move to the
/// next when it cannot be reached.
pub struct Primaries {
    urls: Vec<String>,
    current: std::sync::atomic::AtomicUsize,
}

impl Primaries {
    /// One URL, or several separated by commas.
    pub fn parse(text: &str) -> Result<Self, String> {
        let urls: Vec<String> = text.split(',').map(|u| u.trim().to_owned()).collect();
        for url in &urls {
            check_node_url(url).map_err(|e| format!("{url}: {e}"))?;
        }
        Ok(Self {
            urls,
            current: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// The URL that answered last.
    pub fn current(&self) -> &str {
        let i = self.current.load(std::sync::atomic::Ordering::Relaxed);
        &self.urls[i % self.urls.len()]
    }

    /// Moves on from `url`, which could not be reached.
    pub fn unreachable(&self, url: &str) {
        if let Some(i) = self.urls.iter().position(|u| u == url) {
            let next = (i + 1) % self.urls.len();
            let _ = self.current.compare_exchange(
                i,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    /// Tries each URL once, from the current one, until one is reached.
    pub async fn call<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        tls: &Arc<rustls::ClientConfig>,
        path: &str,
        node: Option<&str>,
        body: &T,
    ) -> Result<R, forward::Failure> {
        let mut last = None;
        for _ in 0..self.urls.len() {
            let url = self.current().to_owned();
            match forward::call(Arc::clone(tls), &url, path, node, body).await {
                Err(forward::Failure::Unreachable(error)) => {
                    self.unreachable(&url);
                    last = Some(error);
                }
                result => return result,
            }
        }
        Err(forward::Failure::Unreachable(
            last.unwrap_or_else(|| anyhow::anyhow!("no primary URL")),
        ))
    }
}

impl std::fmt::Display for Primaries {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.urls.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_heartbeat_from_an_older_worker_has_no_version() {
        let hb: Heartbeat = serde_json::from_value(serde_json::json!({
            "url": "https://10.0.0.2:7443",
            "boot": "b",
            "seq": 1,
            "config_version": 1,
            "capacity": serde_json::to_value(Capacity::default()).unwrap(),
            "sandboxes": [],
        }))
        .unwrap();
        assert_eq!(hb.version, "");
    }

    #[test]
    fn primaries_move_on_when_unreachable() {
        let p = Primaries::parse("https://a:1, https://b:2").unwrap();
        assert_eq!(p.current(), "https://a:1");
        p.unreachable("https://b:2");
        assert_eq!(p.current(), "https://a:1");
        p.unreachable("https://a:1");
        assert_eq!(p.current(), "https://b:2");
        p.unreachable("https://b:2");
        assert_eq!(p.current(), "https://a:1");
        assert!(Primaries::parse("https://a:1,http://b:2").is_err());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0xab, 0xff];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn node_urls_are_host_and_port_only() {
        assert!(check_node_url("https://10.0.0.5:8443").is_ok());
        assert!(check_node_url("https://node-2.internal:8443").is_ok());
        for bad in [
            "http://10.0.0.5:8443",
            "https://10.0.0.5",
            "https://10.0.0.5:8443/x",
            "https://user@10.0.0.5:8443",
            "https://:8443",
            "https://10.0.0.5:0",
        ] {
            assert!(check_node_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn build_hash_ignores_min_warm() {
        let plain = r#"{"name":"py","setup":["true"],"warmup":[],"env":{},"resources":{"vcpus":1,"memory_mib":512,"disk_gib":1}}"#;
        let warm = plain.replace(r#""name":"py","#, r#""name":"py","min_warm":2,"#);
        assert_eq!(build_hash(plain), build_hash(&warm));
        assert_eq!(build_hash(plain), sha256_hex(plain.as_bytes()));
        assert_ne!(
            build_hash(plain),
            build_hash(&plain.replace("true", "false"))
        );
    }
}
