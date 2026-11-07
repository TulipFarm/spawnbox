//! Sandboxes: create, exec, pause, resume, delete and expiry.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use opentelemetry::KeyValue;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use spawn_egress::{Attached, Policy};
use spawn_node::firecracker::Limits;
use spawn_node::net::NetMode;
use spawn_node::uffd::PageSource;
use spawn_node::{Backend, Vm};
use spawn_node::{Node, RestoreSteps, Restored, ResumeError, guest, new_identity};
use spawn_proto::guest::v1::{ExecEvent, ExecRequest};
use tonic::transport::Channel;
use tonic::{Code as GrpcCode, Streaming};

use crate::db::{self, Db, state};
use crate::egress::{CA_ENV, Network};
use crate::events::Origin;
use crate::hub::{ExecLog, Hub};
use crate::ids;
use crate::metering::{Meter, Rate};
use crate::metrics;
use crate::model::{ApiError, BASE_TEMPLATE, Code, CreateSandbox, Exec, Timings};
use crate::ports::{self, Access, Publish};
use crate::secrets::Secrets;
use crate::templates::{ReadyBuild, Slots, Startable, Templates};
use crate::tenancy::{Quotas, Tenant, Usage};
use crate::traces::{self, Traced};
use crate::volumes::Volumes;
use crate::warm::{self, PoolView};

mod fork;

pub use fork::MAX_FORK;

/// A VM that runs.
struct Live {
    vm: Vm,
    channel: Channel,
    index: u32,
    expires_at: i64,
    /// Whether volumes are mounted, so the guest must flush before the VM
    /// stops.
    volumes: bool,
}

enum VmState {
    Running(Box<Live>),
    /// Saved to `<paused dir>/<id>`. `remaining_ms` is what was left of
    /// its timeout.
    Paused {
        paused_at: i64,
        remaining_ms: i64,
    },
    /// Being paused. Only seen without the sandbox's lock held.
    Changing,
}

/// A sandbox that runs or is paused.
struct Record {
    tenant: String,
    vm: VmState,
    env: BTreeMap<String, String>,
    ports: BTreeMap<u16, Published>,
    egress: Policy,
    secrets: Vec<Attached>,
    volumes: Vec<db::VolumeRef>,
    limits: Limits,
    idle_pause_s: u64,
    /// How long it is kept once paused, from its tenant's quota.
    retention_ms: i64,
    /// Calls that use the VM right now. Idle pause waits for zero.
    busy: u32,
    last_active: Instant,
    /// Held while the VM changes: pause, resume, delete.
    lock: Arc<tokio::sync::Mutex<()>>,
    /// Usage is counted up to here (Unix ms).
    metered_at: i64,
    /// Bytes stored on the host when last measured: the VM's disk layer
    /// while it runs, its snapshot while it is paused.
    disk_bytes: u64,
    /// Set while it is copied to another host: since when, and whether it
    /// ran before.
    moving: Option<(Instant, bool)>,
}

/// A move that takes longer than this was abandoned.
const MOVE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

impl Record {
    fn is_moving(&self) -> bool {
        self.moving
            .is_some_and(|(since, _)| since.elapsed() < MOVE_TIMEOUT)
    }

    /// What it holds in its current state.
    fn rate(&self) -> Rate {
        match self.vm {
            VmState::Paused { .. } => Rate {
                disk_bytes: self.disk_bytes,
                ..Rate::default()
            },
            VmState::Running(_) | VmState::Changing => Rate {
                vcpus: self.limits.vcpus,
                memory_mib: self.limits.memory_mib,
                disk_bytes: self.disk_bytes,
            },
        }
    }
}

/// Why a sandbox is paused.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PauseReason {
    Api,
    /// Only if it is still idle.
    Idle,
    /// To move it to another host. Not held to the snapshot quota.
    Migrate,
}

/// A paused sandbox ready to be copied to another host.
pub struct Export {
    pub sandbox: db::Sandbox,
    /// What resuming needs, as JSON.
    pub saved: String,
    pub was_running: bool,
    /// Its snapshot files.
    pub dir: PathBuf,
    /// Its volumes' files, by slot.
    pub volumes: Vec<PathBuf>,
}

/// A port reachable through preview URLs.
#[derive(Clone, Serialize, Deserialize)]
pub struct Published {
    pub access: Access,
    /// For `token` access: the token and when it stops working (Unix ms).
    pub token: Option<(String, i64)>,
}

/// What a paused sandbox needs to resume, also after a server restart.
#[derive(Serialize, Deserialize)]
struct Saved {
    env: BTreeMap<String, String>,
    ports: BTreeMap<u16, Published>,
    /// Secret name and placeholder.
    secrets: Vec<(String, String)>,
    vcpus: u8,
    memory_mib: u32,
    remaining_ms: i64,
}

struct Inner {
    records: HashMap<String, Record>,
    /// Sandboxes being created or resumed, by ID: their tenant and size.
    /// Counted against quotas until they run.
    starting: HashMap<String, (String, Limits)>,
    /// Sandboxes being paused, by ID: their tenant and the snapshot bytes
    /// they may store. Counted against the snapshot quota until paused.
    pausing: HashMap<String, (String, u64)>,
}

impl Inner {
    fn usage(&self, tenant: &str) -> Usage {
        let mut usage = Usage::default();
        let running = self.records.values().filter(|r| {
            r.tenant == tenant && matches!(r.vm, VmState::Running(_) | VmState::Changing)
        });
        let starting = self.starting.values().filter(|(t, _)| t == tenant);
        for limits in running.map(|r| &r.limits).chain(starting.map(|(_, l)| l)) {
            usage.add(u64::from(limits.vcpus), u64::from(limits.memory_mib));
        }
        usage
    }

    /// Bytes stored for `tenant`'s paused sandboxes.
    fn snapshot_bytes(&self, tenant: &str) -> u64 {
        let paused = self
            .records
            .values()
            .filter(|r| r.tenant == tenant && matches!(r.vm, VmState::Paused { .. }))
            .map(|r| r.disk_bytes);
        let pausing = self
            .pausing
            .values()
            .filter(|(t, _)| t == tenant)
            .map(|(_, bytes)| *bytes);
        paused.chain(pausing).sum()
    }
}

/// A sandbox admitted under its tenant's quotas. Counted while it starts;
/// drop it once the sandbox runs or failed.
struct Admission {
    inner: Arc<Mutex<Inner>>,
    id: String,
}

impl Drop for Admission {
    fn drop(&mut self) {
        lock(&self.inner).starting.remove(&self.id);
    }
}

/// Quota held for a sandbox that starts on a worker.
pub struct Reservation(#[expect(dead_code, reason = "held for its drop")] Admission);

/// A VM in use. While one exists, the sandbox is not paused for being
/// idle.
pub struct Busy {
    inner: Arc<Mutex<Inner>>,
    id: String,
}

impl Drop for Busy {
    fn drop(&mut self) {
        let mut inner = lock(&self.inner);
        if let Some(record) = inner.records.get_mut(&self.id) {
            record.busy = record.busy.saturating_sub(1);
            record.last_active = Instant::now();
        }
    }
}

/// A sandbox being paused, counted against its tenant's snapshot quota
/// until it is paused or failed.
struct Pausing {
    inner: Arc<Mutex<Inner>>,
    id: String,
}

impl Drop for Pausing {
    fn drop(&mut self) {
        lock(&self.inner).pausing.remove(&self.id);
    }
}

/// A running sandbox's guest connection, for one call.
pub struct Opened {
    pub tenant: String,
    pub channel: Channel,
    pub env: BTreeMap<String, String>,
    pub busy: Busy,
}

/// A VM restored from a build with its vCPUs paused, waiting in a warm
/// pool. Its jail and network are named after `id`, the sandbox it
/// becomes.
pub struct WarmVm {
    id: String,
    vm: Vm,
    channel: Channel,
    index: u32,
}

type Warm = warm::Warm<NetMode, WarmVm, ReadyBuild>;
type WarmKey = warm::Key<NetMode>;

fn net_name(mode: &NetMode) -> &'static str {
    match mode {
        NetMode::Open => "open",
        NetMode::Restricted => "restricted",
        NetMode::Closed => "closed",
    }
}

pub struct Settings {
    pub max_timeout_s: u64,
    /// For sandboxes created without `idle_pause_s`.
    pub idle_pause_s: u64,
    pub paused_retention_s: u64,
    pub paused_dir: PathBuf,
    /// Memory all warm VMs may have together. 0 turns warm pools off.
    pub warm_memory_mib: u64,
    /// Warm VMs kept for `base` with the server's network policy.
    pub warm_min: usize,
    /// Free slots warm pools leave for template builds.
    pub warm_reserve: usize,
}

#[derive(Clone)]
pub struct Sandboxes(Arc<Shared>);

pub struct Shared {
    node: Arc<Node>,
    db: Db,
    templates: Arc<Templates>,
    slots: Arc<Slots>,
    network: Arc<Network>,
    secrets: Arc<Secrets>,
    volumes: Arc<Volumes>,
    pub hub: Arc<Hub>,
    meter: Arc<Meter>,
    settings: Settings,
    inner: Arc<Mutex<Inner>>,
    warm: Warm,
    closing: AtomicBool,
}

impl Deref for Sandboxes {
    type Target = Shared;

    fn deref(&self) -> &Shared {
        &self.0
    }
}

fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(|e| e.into_inner())
}

/// What sandboxes are built from and report to.
pub struct Parts {
    pub node: Arc<Node>,
    pub db: Db,
    pub templates: Arc<Templates>,
    pub slots: Arc<Slots>,
    pub network: Arc<Network>,
    pub secrets: Arc<Secrets>,
    pub volumes: Arc<Volumes>,
    pub hub: Arc<Hub>,
    pub meter: Arc<Meter>,
}

impl Sandboxes {
    pub fn new(parts: Parts, settings: Settings) -> Self {
        let Parts {
            node,
            db,
            templates,
            slots,
            network,
            secrets,
            volumes,
            hub,
            meter,
        } = parts;
        Self(Arc::new(Shared {
            node,
            db,
            templates,
            slots,
            network,
            secrets,
            volumes,
            hub,
            meter,
            warm: Warm::new(settings.warm_memory_mib),
            settings,
            inner: Arc::new(Mutex::new(Inner {
                records: HashMap::new(),
                starting: HashMap::new(),
                pausing: HashMap::new(),
            })),
            closing: AtomicBool::new(false),
        }))
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        lock(&self.inner)
    }

    /// Records an event about sandbox `id`.
    pub fn event(&self, kind: &'static str, origin: &Origin, tenant: &str, id: &str, attrs: Value) {
        self.hub.record(kind, origin, Some(tenant), Some(id), attrs);
    }

    /// Counts `record`'s usage up to `now`. Call before its state changes
    /// and when it is removed.
    fn settle(&self, id: &str, record: &mut Record, now: i64) {
        self.meter
            .charge(&record.tenant, id, record.metered_at, now, record.rate());
        record.metered_at = record.metered_at.max(now);
    }

    /// Counts every sandbox's usage up to now and writes what is collected.
    pub fn flush_usage(&self) -> rusqlite::Result<()> {
        {
            let now = now_ms();
            let mut inner = self.inner();
            for (id, record) in &mut inner.records {
                self.settle(id, record, now);
            }
        }
        self.meter.flush()
    }

    /// Measures disks, writes usage, and refuses new egress of tenants
    /// over their monthly egress quota. Call every few seconds.
    pub fn meter(&self) {
        let targets: Vec<(String, Option<PathBuf>, bool)> = self
            .inner()
            .records
            .iter()
            .filter_map(|(id, record)| match &record.vm {
                VmState::Running(live) => Some((id.clone(), live.vm.disk(), true)),
                VmState::Paused { .. } => Some((id.clone(), Some(self.paused_dir(id)), false)),
                VmState::Changing => None,
            })
            .collect();
        // Measured without the lock; dropped if the state changed since.
        let measured: Vec<(String, u64, bool)> = targets
            .into_iter()
            .map(|(id, path, running)| (id, path.as_deref().map_or(0, stored_bytes), running))
            .collect();
        {
            let mut inner = self.inner();
            for (id, bytes, running) in measured {
                if let Some(record) = inner.records.get_mut(&id) {
                    let still = match record.vm {
                        VmState::Running(_) => running,
                        VmState::Paused { .. } => !running,
                        VmState::Changing => false,
                    };
                    if still {
                        record.disk_bytes = bytes;
                    }
                }
            }
        }
        if let Err(error) = self.flush_usage() {
            eprintln!("usage: write: {error}");
        }
        self.block_over_egress();
    }

    /// Refuses new egress of tenants over their monthly egress quota, and
    /// allows it again for the rest.
    pub fn block_over_egress(&self) {
        let tenants = match self.db.list_tenants() {
            Ok(tenants) => tenants,
            Err(error) => {
                eprintln!("usage: read tenants: {error}");
                return;
            }
        };
        let now = now_ms();
        let blocked = tenants
            .into_iter()
            .filter(|tenant| {
                tenant.quotas.monthly_egress_bytes.is_some_and(|limit| {
                    self.meter
                        .month_egress(&tenant.id, now)
                        .is_ok_and(|used| used >= limit)
                })
            })
            .map(|tenant| tenant.id)
            .collect();
        self.network.proxy.block_tenants(blocked);
    }

    /// `tenant`'s egress bytes this UTC month.
    pub fn month_egress(&self, tenant: &str) -> rusqlite::Result<u64> {
        self.meter.month_egress(tenant, now_ms())
    }

    /// Bytes stored for `tenant`'s paused sandboxes.
    pub fn snapshot_bytes(&self, tenant: &str) -> u64 {
        self.inner().snapshot_bytes(tenant)
    }

    fn paused_dir(&self, id: &str) -> PathBuf {
        self.settings.paused_dir.join(id)
    }

    /// A new directory name for a sandbox copied from another host. Ones
    /// left by a crash are removed at start.
    pub fn staging_dir(&self) -> anyhow::Result<PathBuf> {
        let name = format!(".incoming-{}", ids::base32(&ids::random::<10>()?));
        Ok(self.settings.paused_dir.join(name))
    }

    /// Call once the slot's VM is gone.
    fn release(&self, index: u32) {
        self.network.unregister(index);
        self.slots.release(index);
    }

    /// A free slot. Stops a warm VM of a pool other than `keep` if no slot
    /// is free.
    async fn take_slot(&self, keep: Option<&WarmKey>) -> Result<u32, ApiError> {
        if let Some(index) = self.slots.try_take() {
            return Ok(index);
        }
        if let Some(vm) = self.warm.evict(keep) {
            self.stop_warm(vm).await;
        }
        self.slots.try_take().ok_or_else(Self::no_slot)
    }

    async fn stop_warm(&self, warm: WarmVm) {
        let WarmVm {
            vm, channel, index, ..
        } = warm;
        drop(channel);
        vm.stop().await;
        self.release(index);
    }

    /// Resumes a warm VM's vCPUs. Stops it on error.
    async fn wake(&self, warm: WarmVm) -> anyhow::Result<Restored> {
        let WarmVm { vm, channel, .. } = warm;
        let started = Instant::now();
        if let Err(error) = vm.thaw().await {
            drop(channel);
            vm.stop().await;
            return Err(error);
        }
        let hello = round(started.elapsed().as_secs_f64() * 1000.0);
        Ok(Restored {
            vm,
            channel,
            started,
            steps: RestoreSteps {
                hello,
                ..RestoreSteps::default()
            },
        })
    }

    /// Restores warm VMs that pools miss and stops ones they no longer
    /// need. Call every second; it returns at once.
    pub fn refill_warm(&self) {
        if !self.warm.enabled() || self.closing.load(Ordering::SeqCst) {
            return;
        }
        let mut wants = Vec::new();
        if self.settings.warm_min > 0
            && let Ok((_, base)) = self.templates.ready(None, BASE_TEMPLATE)
        {
            let key = WarmKey {
                build: base.id.clone(),
                kind: self.network.mode(&[Policy::allow_all()]),
            };
            let memory = u64::from(base.build.limits.memory_mib);
            wants.push(crate::warm::Want {
                key,
                template: BASE_TEMPLATE.to_owned(),
                source: base,
                memory_mib: memory,
                min: self.settings.warm_min,
            });
        }
        for (template, build, min) in self.templates.min_warm() {
            // A tenant's template warms with its tenant's egress policy.
            let tenant_policy = match crate::tenancy::split(&template).0 {
                Some(tenant) => self
                    .db
                    .get_tenant(tenant)
                    .ok()
                    .flatten()
                    .and_then(|t| t.egress),
                None => None,
            };
            let policies: Vec<Policy> = tenant_policy
                .into_iter()
                .chain([Policy::allow_all()])
                .collect();
            let key = WarmKey {
                build: build.id.clone(),
                kind: self.network.mode(&policies),
            };
            let memory = u64::from(build.build.limits.memory_mib);
            wants.push(crate::warm::Want {
                key,
                template,
                source: build,
                memory_mib: memory,
                min,
            });
        }
        self.warm.set_minimums(&wants);
        let free = self
            .slots
            .free_count()
            .saturating_sub(self.settings.warm_reserve);
        let plan = self.warm.plan(free, Instant::now());
        for vm in plan.stop {
            let this = self.clone();
            tokio::spawn(async move { this.stop_warm(vm).await });
        }
        for (key, build) in plan.fill {
            let this = self.clone();
            tokio::spawn(async move {
                let made = this.make_warm(&key, &build).await;
                drop(build);
                let made = match made {
                    Ok(vm) => vm,
                    Err(error) => {
                        eprintln!("warm pool {}: {error:#}", key.build);
                        None
                    }
                };
                if let Some(vm) = this.warm.filled(&key, made) {
                    this.stop_warm(vm).await;
                }
            });
        }
    }

    /// Restores one warm VM. `None` if no slot is free.
    async fn make_warm(
        &self,
        key: &WarmKey,
        build: &Arc<ReadyBuild>,
    ) -> anyhow::Result<Option<WarmVm>> {
        self.templates
            .ensure_local(build)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.message))?;
        let Some(index) = self.slots.try_take() else {
            return Ok(None);
        };
        let id = ids::new_id("sbx")?;
        let name = ids::host_name(&id);
        let restored = match self
            .node
            .restore(&build.build, &name, index, key.kind, &[])
            .await
        {
            Ok(restored) => restored,
            Err(error) => {
                self.node.remove_failed(&name, index).await;
                self.release(index);
                return Err(error);
            }
        };
        let warm = WarmVm {
            id,
            vm: restored.vm,
            channel: restored.channel,
            index,
        };
        if let Err(error) = warm.vm.freeze().await {
            self.stop_warm(warm).await;
            return Err(error);
        }
        Ok(Some(warm))
    }

    /// Warm memory in use, the budget, and each pool.
    pub fn warm_pools(&self) -> (u64, u64, Vec<PoolView>) {
        let (used, pools) = self.warm.view(net_name);
        (used, self.warm.budget_mib(), pools)
    }

    fn no_slot() -> ApiError {
        ApiError::new(
            Code::NoCapacity,
            "the sandbox limit on this host is reached",
        )
    }

    fn shutting_down() -> ApiError {
        ApiError::new(Code::NoCapacity, "server is shutting down")
    }

    /// Counts a sandbox of `limits` against `tenant`'s quotas, or fails
    /// with `quota_exceeded`.
    fn admit(
        &self,
        tenant: &str,
        quotas: &Quotas,
        id: &str,
        limits: Limits,
    ) -> Result<Admission, ApiError> {
        let mut inner = self.inner();
        let mut usage = inner.usage(tenant);
        usage.merge(self.db.mirror_usage(tenant)?);
        quotas.admit(usage, u64::from(limits.vcpus), u64::from(limits.memory_mib))?;
        inner
            .starting
            .insert(id.to_owned(), (tenant.to_owned(), limits));
        Ok(Admission {
            inner: Arc::clone(&self.inner),
            id: id.to_owned(),
        })
    }

    /// Counts a sandbox that starts on a worker against `tenant`'s quotas
    /// until the returned value drops.
    pub fn reserve(
        &self,
        tenant: &str,
        quotas: &Quotas,
        vcpus: u8,
        memory_mib: u32,
    ) -> Result<Reservation, ApiError> {
        let id = ids::new_id("res").map_err(ApiError::internal)?;
        let limits = Limits { vcpus, memory_mib };
        Ok(Reservation(self.admit(tenant, quotas, &id, limits)?))
    }

    /// Sandboxes this host can start now: free slots, and warm VMs, which
    /// give up their slots when needed.
    pub fn free_slots(&self) -> usize {
        let warm: usize = self.warm_pools().2.iter().map(|p| p.ready).sum();
        self.slots.free_count().saturating_add(warm)
    }

    /// The warm pool network (`open`, `restricted` or `closed`) a sandbox
    /// of `tenant` with `egress` gets.
    pub fn network_mode(&self, tenant: &Tenant, egress: Option<&Policy>) -> &'static str {
        let policies: Vec<Policy> = tenant
            .egress
            .iter()
            .cloned()
            .chain([egress.cloned().unwrap_or_else(Policy::allow_all)])
            .collect();
        net_name(&self.network.mode(&policies))
    }

    /// What `tenant`'s running and starting sandboxes hold now, on this
    /// host and on workers.
    pub fn usage(&self, tenant: &str) -> Usage {
        let mut usage = self.inner().usage(tenant);
        if let Ok(mirrors) = self.db.mirror_usage(tenant) {
            usage.merge(mirrors);
        }
        usage
    }

    fn retention_ms(&self, quotas: &Quotas) -> i64 {
        let seconds = quotas.paused_retention_s(self.settings.paused_retention_s);
        i64::try_from(seconds.saturating_mul(1000)).unwrap_or(i64::MAX)
    }

    /// Creates a sandbox for `tenant`.
    pub async fn create(
        &self,
        tenant: Tenant,
        req: CreateSandbox,
        origin: &Origin,
    ) -> Result<(db::Sandbox, Timings), ApiError> {
        let mut origin = origin.clone();
        let span = traces::start(
            "sandbox.create",
            &mut origin,
            vec![
                KeyValue::new("spawnbox.tenant", tenant.id.clone()),
                KeyValue::new(
                    "spawnbox.template",
                    req.template.clone().unwrap_or_else(|| BASE_TEMPLATE.into()),
                ),
                KeyValue::new("spawnbox.backend", self.volumes.backend().name()),
            ],
        );
        let created = self.create_traced(tenant, req, &origin, &span).await;
        match &created {
            Ok((sandbox, _)) => span.attr(KeyValue::new("spawnbox.sandbox", sandbox.id.clone())),
            Err(error) => span.fail(error.message.clone()),
        }
        created
    }

    async fn create_traced(
        &self,
        tenant: Tenant,
        mut req: CreateSandbox,
        origin: &Origin,
        span: &Traced,
    ) -> Result<(db::Sandbox, Timings), ApiError> {
        let timeout_s = req.check(tenant.quotas.max_timeout_s(self.settings.max_timeout_s))?;
        if self.closing.load(Ordering::SeqCst) {
            return Err(Self::shutting_down());
        }
        let idle_pause_s = req.idle_pause_s.unwrap_or(self.settings.idle_pause_s);
        let egress = req.egress.take().unwrap_or_else(Policy::allow_all);
        let volumes = self.volumes.resolve(&tenant.id, &req.volumes)?;
        let mut attached = Vec::new();
        let mut placeholders = BTreeMap::new();
        for (key, spec) in self.secrets.specs(Some(&tenant.id), &req.secrets)? {
            let placeholder = ids::placeholder().map_err(ApiError::internal)?;
            if let Some(var) = &spec.env {
                if req.env.contains_key(var) || placeholders.contains_key(var) {
                    return Err(ApiError::invalid(format!(
                        "{var} is set by both env and secret {:?}",
                        spec.name
                    )));
                }
                placeholders.insert(var.clone(), placeholder.clone());
            }
            attached.push(Attached {
                name: key,
                placeholder,
            });
        }
        let template = req.template.as_deref().unwrap_or(BASE_TEMPLATE);
        // Held until the VM is restored, so the build's files stay in place.
        let (_, ready) = self.templates.ready(Some(&tenant.id), template)?;
        let asked = Instant::now();
        let (fetched, lazy) = match self.templates.ensure_startable(&ready).await? {
            Startable::Local { fetched } => (fetched, None),
            Startable::Lazy(lazy) => (true, Some(lazy)),
        };
        if fetched {
            span.step("fetch_build", asked, Instant::now());
        }
        span.attr(KeyValue::new("spawnbox.build", ready.id.clone()));
        tenant
            .quotas
            .admit_egress(self.meter.month_egress(&tenant.id, now_ms())?)?;
        let policies: Vec<Policy> = tenant
            .egress
            .iter()
            .cloned()
            .chain([egress.clone()])
            .collect();
        let mode = self.network.mode(&policies);
        let (send, receive) = self.network.rates(&policies);
        let key = WarmKey {
            build: ready.id.clone(),
            kind: mode,
        };
        let memory = u64::from(ready.build.limits.memory_mib);
        let begin = Instant::now();
        let mounts = self.volumes.prepare(&volumes).await?;
        if !mounts.is_empty() {
            span.step("volumes", begin, Instant::now());
        }
        let claiming = Instant::now();
        let attaches: Vec<_> = mounts.iter().map(|(attach, _)| attach.clone()).collect();
        // A warm gVisor sandbox has started, and volumes are bound at start.
        let warm = if mounts.is_empty() || self.volumes.backend() == Backend::Firecracker {
            self.warm
                .claim(&key, template, &ready, memory, Instant::now())
        } else {
            None
        };
        let pool = if warm.is_some() {
            "spawnbox_warm_pool_hits_total"
        } else {
            "spawnbox_warm_pool_misses_total"
        };
        metrics::inc(pool, vec![("build", ready.id.clone())]);
        let id = match &warm {
            Some(warm) => warm.id.clone(),
            None => ids::new_id("sbx").map_err(ApiError::internal)?,
        };
        let admitted = self.admit(&tenant.id, &tenant.quotas, &id, ready.build.limits);
        let (_admission, index) = match (admitted, warm.as_ref().map(|w| w.index)) {
            (Ok(admission), Some(index)) => (admission, index),
            (Ok(admission), None) => (admission, self.take_slot(Some(&key)).await?),
            (Err(error), _) => {
                if let Some(vm) = warm.and_then(|vm| self.warm.put_back(&key, vm)) {
                    self.stop_warm(vm).await;
                }
                return Err(error);
            }
        };
        let now = now_ms();
        let mut sandbox = db::Sandbox {
            id,
            tenant: tenant.id.clone(),
            state: state::STARTING.into(),
            template: template.into(),
            build: Some(ready.id.clone()),
            labels: req.labels,
            secrets: req.secrets,
            egress: egress.clone(),
            created_at: now,
            expires_at: now.saturating_add(i64::try_from(timeout_s * 1000).unwrap_or(i64::MAX)),
            idle_pause_s,
            paused_at: None,
            node: None,
            vcpus: u32::from(ready.build.limits.vcpus),
            memory_mib: ready.build.limits.memory_mib,
            volumes,
        };
        let inserted = match self.db.insert_sandbox(&sandbox) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(name)) => Err(ApiError::new(
                Code::Conflict,
                format!("volume {name:?} is in use by another sandbox"),
            )),
            Err(error) => Err(error.into()),
        };
        if let Err(error) = inserted {
            match warm {
                Some(vm) => {
                    if let Some(vm) = self.warm.put_back(&key, vm) {
                        self.stop_warm(vm).await;
                    }
                }
                None => self.release(index),
            }
            return Err(error);
        }
        span.step_with(
            "claim",
            claiming,
            Instant::now(),
            vec![KeyValue::new("spawnbox.warm", warm.is_some())],
        );

        let name = ids::host_name(&sandbox.id);
        let from_pool = warm.is_some();
        if from_pool {
            self.refill_warm();
        }
        self.network.register(
            index,
            &sandbox.id,
            Some(&tenant.id),
            policies,
            attached.clone(),
        );
        let restoring = Instant::now();
        let started = async {
            let restored = match warm {
                Some(vm) => {
                    let restored = self.wake(vm).await?;
                    if let Err(error) = restored.vm.attach(&attaches).await {
                        restored.vm.stop().await;
                        return Err(error);
                    }
                    restored
                }
                None => match &lazy {
                    Some(lazy) => {
                        let pages: Arc<dyn PageSource> = lazy.clone();
                        self.node
                            .restore_lazy(&ready.build, &name, index, mode, &attaches, pages)
                            .await?
                    }
                    None => {
                        self.node
                            .restore(&ready.build, &name, index, mode, &attaches)
                            .await?
                    }
                },
            };
            let apply_start = restored.started.elapsed();
            let fixups = async {
                restored.vm.set_rates(send, receive).await?;
                guest::apply(&restored.channel, new_identity(&name)?).await?;
                guest::mount(&restored.channel, &mounts).await
            };
            if let Err(error) = fixups.await {
                restored.vm.stop().await;
                return Err(error);
            }
            anyhow::Ok((restored, apply_start))
        }
        .await;
        let (restored, apply_start) = match started {
            Ok(ok) => ok,
            Err(error) => {
                eprintln!("create {}: {error:#}", sandbox.id);
                self.node.remove_failed(&name, index).await;
                self.release(index);
                self.db.set_state(&sandbox.id, state::FAILED, now_ms())?;
                self.event(
                    "sandbox.lost",
                    origin,
                    &tenant.id,
                    &sandbox.id,
                    json!({ "reason": "failed to start" }),
                );
                return Err(ApiError::internal(format!(
                    "sandbox {} failed to start; see the server log",
                    sandbox.id
                )));
            }
        };
        let Restored {
            mut vm,
            channel,
            started,
            steps,
        } = restored;
        let lost = vm.take_lost();
        let applying = started + apply_start;
        span.step("restore", restoring, applying);
        span.step("fixups", applying, Instant::now());
        let mut env: BTreeMap<String, String> = CA_ENV
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        env.extend(ready.spec.env.clone());
        env.extend(req.env);
        env.extend(placeholders);
        let limits = ready.build.limits;
        drop(ready);
        let ms = |d: Duration| round(d.as_secs_f64() * 1000.0);
        let timings = Timings {
            prepare: round(steps.prepare),
            restore: round(steps.hello),
            fixups: ms(started.elapsed() - apply_start),
            total: ms(begin.elapsed()),
            warm: from_pool,
        };
        let backend = self.volumes.backend().name();
        let path = match (from_pool, fetched, lazy.is_some()) {
            (true, _, _) => "warm",
            (false, _, true) => "lazy",
            (false, true, false) => "cold",
            (false, false, false) => "cached",
        };
        span.attr(KeyValue::new("spawnbox.path", path));
        metrics::observe(
            "spawnbox_create_seconds",
            vec![("path", path.into()), ("backend", backend.into())],
            asked.elapsed().as_secs_f64(),
        );
        for (step, ms) in [
            ("prepare", timings.prepare),
            ("restore", timings.restore),
            ("fixups", timings.fixups),
        ] {
            metrics::observe(
                "spawnbox_create_step_seconds",
                vec![("step", step.into()), ("backend", backend.into())],
                ms / 1000.0,
            );
        }

        let live = Live {
            vm,
            channel,
            index,
            expires_at: sandbox.expires_at,
            volumes: !mounts.is_empty(),
        };
        if self.closing.load(Ordering::SeqCst) {
            self.stop(&sandbox.id, live, state::DELETED).await;
            return Err(Self::shutting_down());
        }
        let created = json!({
            "template": sandbox.template,
            "build": sandbox.build,
            "vcpus": limits.vcpus,
            "memory_mib": limits.memory_mib,
            "timeout_s": timeout_s,
            "idle_pause_s": idle_pause_s,
            "secrets": sandbox.secrets,
            "labels": sandbox.labels,
            "timings_ms": timings,
            "warm": from_pool,
        });
        let tenant_id = tenant.id.clone();
        let disk_bytes = disk_bytes(&live.vm);
        self.inner().records.insert(
            sandbox.id.clone(),
            Record {
                tenant: tenant.id,
                vm: VmState::Running(Box::new(live)),
                env,
                ports: BTreeMap::new(),
                egress,
                secrets: attached,
                volumes: sandbox.volumes.clone(),
                limits,
                idle_pause_s,
                retention_ms: self.retention_ms(&tenant.quotas),
                busy: 0,
                last_active: Instant::now(),
                lock: Arc::default(),
                metered_at: now_ms(),
                disk_bytes,
                moving: None,
            },
        );
        if let Err(error) = self.db.set_state(&sandbox.id, state::RUNNING, now_ms()) {
            let record = self.inner().records.remove(&sandbox.id);
            if let Some(Record {
                vm: VmState::Running(live),
                ..
            }) = record
            {
                self.stop(&sandbox.id, *live, state::FAILED).await;
            }
            return Err(error.into());
        }
        sandbox.state = state::RUNNING.into();
        self.event("sandbox.created", origin, &tenant_id, &sandbox.id, created);
        if let Some(lost) = lost {
            let (this, id, origin) = (self.clone(), sandbox.id.clone(), origin.clone());
            tokio::spawn(async move {
                // An error means the VM stopped first, as it should.
                if let Ok(why) = lost.await {
                    this.lose_memory(&id, &origin, &why).await;
                }
            });
        }
        Ok((sandbox, timings))
    }

    /// Fails a sandbox whose pager stopped it because a memory part could
    /// not be fetched.
    async fn lose_memory(&self, id: &str, origin: &Origin, why: &str) {
        eprintln!("{id}: {why}; it was stopped");
        // A pause or move may hold it for a while; it fails without memory.
        for _ in 0..600 {
            let taken = {
                let mut inner = self.inner();
                let running = match inner.records.get(id) {
                    None => return,
                    Some(record) => matches!(record.vm, VmState::Running(_)),
                };
                if running {
                    inner.records.remove(id)
                } else {
                    None
                }
            };
            if let Some(mut record) = taken {
                self.settle(id, &mut record, now_ms());
                let VmState::Running(live) = record.vm else {
                    return;
                };
                self.stop(id, *live, state::FAILED).await;
                self.event(
                    "sandbox.lost",
                    origin,
                    &record.tenant,
                    id,
                    json!({ "reason": "memory pages could not be fetched" }),
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn get(&self, id: &str) -> Result<db::Sandbox, ApiError> {
        if !ids::is_valid_id("sbx", id) {
            return Err(ApiError::not_found());
        }
        self.db.get_sandbox(id)?.ok_or_else(ApiError::not_found)
    }

    /// One tenant's sandboxes, or every tenant's.
    pub fn list(
        &self,
        tenant: Option<&str>,
        state: Option<&str>,
        limit: u32,
        after: i64,
    ) -> Result<(Vec<db::Sandbox>, Option<i64>), ApiError> {
        Ok(self.db.list_sandboxes(tenant, state, limit, after)?)
    }

    fn record_lock(&self, id: &str) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.inner().records.get(id).map(|r| Arc::clone(&r.lock))
    }

    fn not_running(&self, id: &str) -> ApiError {
        match self.get(id) {
            Ok(sandbox) => ApiError::new(
                Code::Conflict,
                format!("sandbox is {}, not running", sandbox.state),
            ),
            Err(error) => error,
        }
    }

    /// Works from any state except `starting`.
    pub async fn delete(&self, id: &str, origin: &Origin) -> Result<(), ApiError> {
        let sandbox = self.get(id)?;
        if let Some(lock) = self.record_lock(id) {
            let _changing = lock.lock().await;
            if self.inner().records.get(id).is_some_and(Record::is_moving) {
                return Err(ApiError::new(
                    Code::Conflict,
                    "sandbox is moving to another host; try again soon",
                ));
            }
            if let Some(tenant) = self.remove(id, state::DELETED).await {
                self.event("sandbox.killed", origin, &tenant, id, json!({}));
                return Ok(());
            }
        }
        let sandbox = self.get(id).unwrap_or(sandbox);
        if sandbox.state == state::STARTING {
            return Err(ApiError::new(
                Code::Conflict,
                "sandbox is starting; delete it once it is running",
            ));
        }
        if sandbox.state != state::DELETED {
            self.db.set_state(id, state::DELETED, now_ms())?;
            self.event(
                "sandbox.killed",
                origin,
                &sandbox.tenant,
                id,
                json!({ "previous_state": sandbox.state }),
            );
        }
        Ok(())
    }

    /// Stops or forgets the VM and records `final_state`. Hold the
    /// sandbox's lock. Returns its tenant, or `None` if it was not running
    /// or paused.
    async fn remove(&self, id: &str, final_state: &str) -> Option<String> {
        let mut record = self.inner().records.remove(id)?;
        self.settle(id, &mut record, now_ms());
        match record.vm {
            VmState::Running(live) => self.stop(id, *live, final_state).await,
            VmState::Paused { .. } | VmState::Changing => {
                remove_dir(&self.paused_dir(id));
                if let Err(error) = self.db.set_state(id, final_state, now_ms()) {
                    eprintln!("record {id} as {final_state}: {error}");
                }
            }
        }
        Some(record.tenant)
    }

    async fn stop(&self, id: &str, live: Live, final_state: &str) {
        let Live {
            vm,
            channel,
            index,
            volumes,
            ..
        } = live;
        if volumes {
            flush(&channel).await;
        }
        drop(channel);
        vm.stop().await;
        // Only reuse the index once its jail and network are gone.
        self.release(index);
        if let Err(error) = self.db.set_state(id, final_state, now_ms()) {
            eprintln!("record {id} as {final_state}: {error}");
        }
    }

    /// The guest connection and environment for one call. Resumes a paused
    /// sandbox first. Keep `busy` until the call is done.
    pub async fn open(&self, id: &str, origin: &Origin) -> Result<Opened, ApiError> {
        loop {
            let lock = {
                let mut inner = self.inner();
                let Some(record) = inner.records.get_mut(id) else {
                    drop(inner);
                    return Err(self.not_running(id));
                };
                if let VmState::Running(live) = &record.vm {
                    record.busy += 1;
                    record.last_active = Instant::now();
                    return Ok(Opened {
                        tenant: record.tenant.clone(),
                        channel: live.channel.clone(),
                        env: record.env.clone(),
                        busy: Busy {
                            inner: Arc::clone(&self.inner),
                            id: id.to_owned(),
                        },
                    });
                }
                Arc::clone(&record.lock)
            };
            // In its own task: a client that disconnects must not stop a
            // resume halfway.
            let this = self.clone();
            let id = id.to_owned();
            let origin = origin.clone();
            tokio::spawn(async move {
                let _changing = lock.lock().await;
                this.resume_locked(&id, &origin, "wake").await
            })
            .await
            .map_err(|error| ApiError::internal(format!("task failed: {error}")))??;
        }
    }

    /// Pauses a running sandbox. Does nothing if it is paused.
    pub async fn pause(&self, id: &str, origin: &Origin) -> Result<db::Sandbox, ApiError> {
        let lock = self.record_lock(id).ok_or_else(|| self.not_running(id))?;
        {
            let _changing = lock.lock().await;
            self.pause_locked(id, PauseReason::Api, origin).await?;
        }
        self.get(id)
    }

    /// Resumes a paused sandbox. Does nothing if it runs.
    pub async fn resume(&self, id: &str, origin: &Origin) -> Result<db::Sandbox, ApiError> {
        let lock = self.record_lock(id).ok_or_else(|| self.not_running(id))?;
        {
            let _changing = lock.lock().await;
            self.resume_locked(id, origin, "api").await?;
        }
        self.get(id)
    }

    /// Hold the sandbox's lock. For `Idle`, does nothing once a call has
    /// started.
    async fn pause_locked(
        &self,
        id: &str,
        why: PauseReason,
        origin: &Origin,
    ) -> Result<(), ApiError> {
        let only_if_idle = why == PauseReason::Idle;
        let not_running = || ApiError::new(Code::Conflict, "sandbox is not running");
        let tenant = self
            .inner()
            .records
            .get(id)
            .map(|r| r.tenant.clone())
            .ok_or_else(not_running)?;
        let quotas = self
            .db
            .get_tenant(&tenant)?
            .map(|t| t.quotas)
            .unwrap_or_default();
        let (live, tenant, _pausing) = {
            let mut inner = self.inner();
            let stored = inner.snapshot_bytes(&tenant);
            let record = inner.records.get_mut(id).ok_or_else(not_running)?;
            // Checked in the same critical section that takes the VM, so
            // `open` cannot start a call in between.
            if only_if_idle && !is_idle(record) {
                return Ok(());
            }
            // Its memory snapshot is at most its memory size.
            let asked = u64::from(record.limits.memory_mib) * (1 << 20) + record.disk_bytes;
            if let VmState::Running(_) = record.vm
                && why != PauseReason::Migrate
                && let Err(error) = quotas.admit_snapshot(stored, asked)
            {
                if !only_if_idle {
                    return Err(error);
                }
                eprintln!("{id} is idle but stays running: {}", error.message);
                // Try again after another idle period.
                record.last_active = Instant::now();
                return Ok(());
            }
            if only_if_idle {
                eprintln!("{id} is idle; pausing");
            }
            let live = match std::mem::replace(&mut record.vm, VmState::Changing) {
                VmState::Running(live) => live,
                other => {
                    record.vm = other;
                    return Ok(());
                }
            };
            let tenant = record.tenant.clone();
            inner.pausing.insert(id.to_owned(), (tenant.clone(), asked));
            let pausing = Pausing {
                inner: Arc::clone(&self.inner),
                id: id.to_owned(),
            };
            (live, tenant, pausing)
        };
        let begin = Instant::now();
        let dir = self.paused_dir(id);
        remove_dir(&dir);
        // Written now, the data survives a delete while paused.
        if live.volumes {
            flush(&live.channel).await;
        }
        let snapshot_ms = match self.node.pause(&live.vm, &dir).await {
            Ok(snapshot_ms) => snapshot_ms,
            Err(error) => {
                eprintln!("pause {id}: {error:#}");
                if error.downcast_ref::<spawn_node::Frozen>().is_some() {
                    if let Some(mut record) = self.inner().records.remove(id) {
                        self.settle(id, &mut record, now_ms());
                    }
                    self.stop(id, *live, state::FAILED).await;
                    self.event(
                        "sandbox.lost",
                        origin,
                        &tenant,
                        id,
                        json!({ "reason": "froze while pausing" }),
                    );
                } else if let Some(record) = self.inner().records.get_mut(id) {
                    record.vm = VmState::Running(live);
                    // Wait another idle period before trying again.
                    record.last_active = Instant::now();
                }
                return Err(ApiError::internal(format!(
                    "sandbox {id} could not be paused; see the server log"
                )));
            }
        };
        let saved_ms = begin.elapsed().as_millis();
        let remaining_ms = (live.expires_at - now_ms()).max(0);
        let Live {
            vm, channel, index, ..
        } = *live;
        drop(channel);
        vm.stop().await;
        self.release(index);
        let stopped_ms = begin.elapsed().as_millis();
        let snapshot_bytes = stored_bytes(&dir);
        let paused_at = now_ms();
        let saved = {
            let mut inner = self.inner();
            inner.records.get_mut(id).map(|record| {
                self.settle(id, record, paused_at);
                record.vm = VmState::Paused {
                    paused_at,
                    remaining_ms,
                };
                record.disk_bytes = snapshot_bytes;
                saved(record, remaining_ms)
            })
        };
        if let Some(saved) = saved
            && let Err(error) = self.db.set_paused(id, paused_at, &to_json(&saved))
        {
            eprintln!("record {id} as paused: {error}");
        }
        let total_ms = begin.elapsed().as_millis();
        eprintln!(
            "{id} paused in {total_ms} ms (snapshot {snapshot_ms:.0}, saved {saved_ms}, stopped {stopped_ms})"
        );
        self.event(
            "sandbox.paused",
            origin,
            &tenant,
            id,
            json!({
                "reason": match why {
                    PauseReason::Api => "api",
                    PauseReason::Idle => "idle",
                    PauseReason::Migrate => "migrate",
                },
                "duration_ms": u64::try_from(total_ms).unwrap_or(u64::MAX),
            }),
        );
        Ok(())
    }

    /// Hold the sandbox's lock. `reason` is `api`, `wake` when a call to a
    /// paused sandbox resumes it, or `migrate` on a move's target, where a
    /// failure leaves the row to the caller and records no event.
    async fn resume_locked(
        &self,
        id: &str,
        origin: &Origin,
        reason: &'static str,
    ) -> Result<(), ApiError> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(Self::shutting_down());
        }
        let (tenant, remaining_ms, limits, egress, secrets, volumes) = {
            let inner = self.inner();
            let record = inner
                .records
                .get(id)
                .ok_or_else(|| ApiError::new(Code::Conflict, "sandbox is not paused"))?;
            if record.is_moving() {
                return Err(ApiError::new(
                    Code::Conflict,
                    "sandbox is moving to another host; try again soon",
                ));
            }
            match record.vm {
                VmState::Paused { remaining_ms, .. } => (
                    record.tenant.clone(),
                    remaining_ms,
                    record.limits,
                    record.egress.clone(),
                    record.secrets.clone(),
                    record.volumes.clone(),
                ),
                VmState::Running(_) => return Ok(()),
                VmState::Changing => {
                    return Err(ApiError::internal("sandbox is being paused"));
                }
            }
        };
        // Read again: quotas and egress may have changed while it slept.
        let row = self.db.get_tenant(&tenant)?;
        let quotas = row.as_ref().map(|t| t.quotas).unwrap_or_default();
        quotas.admit_egress(self.meter.month_egress(&tenant, now_ms())?)?;
        let _admission = self.admit(&tenant, &quotas, id, limits)?;
        let policies: Vec<Policy> = row
            .and_then(|t| t.egress)
            .into_iter()
            .chain([egress])
            .collect();
        let begin = Instant::now();
        let index = self.take_slot(None).await?;
        // If the server dies while the VM runs, the next start must not
        // resume the old snapshot: it treats running sandboxes as lost.
        if let Err(error) = self.db.set_state(id, state::RUNNING, now_ms()) {
            self.slots.release(index);
            return Err(error.into());
        }
        let name = ids::host_name(id);
        let mode = self.network.mode(&policies);
        let (send, receive) = self.network.rates(&policies);
        self.network
            .register(index, id, Some(&tenant), policies, secrets);
        let dir = self.paused_dir(id);
        let attaches: Vec<_> = self
            .volumes
            .attachments(&volumes)
            .into_iter()
            .map(|(attach, _)| attach)
            .collect();
        let resumed = async {
            let restored = self
                .node
                .resume(&dir, limits, &name, index, mode, &attaches)
                .await?;
            let identity = async {
                restored.vm.set_rates(send, receive).await?;
                guest::apply(&restored.channel, new_identity(&name)?).await
            };
            if let Err(error) = identity.await {
                restored.vm.stop().await;
                return Err(ResumeError::After(error));
            }
            Ok(restored)
        }
        .await;
        let restored = match resumed {
            Ok(restored) => restored,
            Err(error) => {
                eprintln!("resume {id}: {error}");
                self.node.remove_failed(&name, index).await;
                self.release(index);
                if let ResumeError::Before(_) = error {
                    if let Err(error) = self.db.set_state(id, state::PAUSED, now_ms()) {
                        eprintln!("record {id} as paused: {error}");
                    }
                } else if reason == "migrate" {
                    if let Some(mut record) = self.inner().records.remove(id) {
                        self.settle(id, &mut record, now_ms());
                    }
                    remove_dir(&dir);
                } else {
                    if let Some(mut record) = self.inner().records.remove(id) {
                        self.settle(id, &mut record, now_ms());
                    }
                    remove_dir(&dir);
                    self.db.set_state(id, state::FAILED, now_ms())?;
                    self.event(
                        "sandbox.lost",
                        origin,
                        &tenant,
                        id,
                        json!({ "reason": "failed to resume" }),
                    );
                }
                return Err(ApiError::internal(format!(
                    "sandbox {id} could not be resumed; see the server log"
                )));
            }
        };
        let expires_at = now_ms().saturating_add(remaining_ms);
        let live = Live {
            vm: restored.vm,
            channel: restored.channel,
            index,
            expires_at,
            volumes: !volumes.is_empty(),
        };
        if let Err(error) = self.db.set_resumed(id, expires_at) {
            eprintln!("record {id} as resumed: {error}");
        }
        let disk_bytes = disk_bytes(&live.vm);
        match self.inner().records.get_mut(id) {
            Some(record) => {
                self.settle(id, record, now_ms());
                record.disk_bytes = disk_bytes;
                record.vm = VmState::Running(Box::new(live));
                record.last_active = Instant::now();
            }
            None => return Err(ApiError::internal("sandbox vanished while resuming")),
        }
        let total_ms = begin.elapsed().as_millis();
        eprintln!("{id} resumed in {total_ms} ms");
        self.event(
            "sandbox.resumed",
            origin,
            &tenant,
            id,
            json!({
                "reason": reason,
                "duration_ms": u64::try_from(total_ms).unwrap_or(u64::MAX),
            }),
        );
        Ok(())
    }

    /// Pauses running sandboxes that were idle for their `idle_pause_s`.
    pub fn pause_idle(&self) {
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        let idle: Vec<(String, Arc<tokio::sync::Mutex<()>>)> = self
            .inner()
            .records
            .iter()
            .filter(|(_, record)| is_idle(record))
            .map(|(id, record)| (id.clone(), Arc::clone(&record.lock)))
            .collect();
        for (id, lock) in idle {
            let this = self.clone();
            tokio::spawn(async move {
                let Ok(_changing) = lock.try_lock() else {
                    return;
                };
                if !this.closing.load(Ordering::SeqCst) {
                    let _ = this
                        .pause_locked(&id, PauseReason::Idle, &Origin::system())
                        .await;
                }
            });
        }
    }

    /// Publishes a port, or replaces its access and token.
    pub fn publish(
        &self,
        id: &str,
        req: &Publish,
        origin: &Origin,
    ) -> Result<(u16, Published), ApiError> {
        let (port, ttl_s) = req.check()?;
        let token = match ttl_s {
            Some(ttl) => Some((
                ports::new_token().map_err(ApiError::internal)?,
                now_ms().saturating_add(i64::try_from(ttl * 1000).unwrap_or(i64::MAX)),
            )),
            None => None,
        };
        let published = Published {
            access: req.access,
            token,
        };
        let tenant = self.with_record(id, |record| {
            record.ports.insert(port, published.clone());
            record.tenant.clone()
        })?;
        self.event(
            "port.published",
            origin,
            &tenant,
            id,
            json!({
                "port": port,
                "access": published.access,
                "token_expires_at": published.token.as_ref().map(|(_, at)| crate::model::rfc3339_ms(*at)),
            }),
        );
        Ok((port, published))
    }

    pub fn ports(&self, id: &str) -> Result<Vec<(u16, Published)>, ApiError> {
        let inner = self.inner();
        let record = inner.records.get(id);
        let Some(record) = record else {
            drop(inner);
            return Err(self.not_running(id));
        };
        Ok(record
            .ports
            .iter()
            .map(|(port, p)| (*port, p.clone()))
            .collect())
    }

    pub fn unpublish(&self, id: &str, port: u16, origin: &Origin) -> Result<(), ApiError> {
        let (removed, tenant) = self.with_record(id, |record| {
            (record.ports.remove(&port), record.tenant.clone())
        })?;
        removed.ok_or_else(|| {
            ApiError::new(Code::NotFound, format!("port {port} is not published"))
        })?;
        self.event(
            "port.unpublished",
            origin,
            &tenant,
            id,
            json!({ "port": port }),
        );
        Ok(())
    }

    /// The access of a published port, for the preview proxy.
    pub fn published(&self, id: &str, port: u16) -> Option<Published> {
        self.inner().records.get(id)?.ports.get(&port).cloned()
    }

    /// Changes a running or paused sandbox. A paused one is saved again.
    fn with_record<T>(&self, id: &str, f: impl FnOnce(&mut Record) -> T) -> Result<T, ApiError> {
        let (result, saved) = {
            let mut inner = self.inner();
            let Some(record) = inner.records.get_mut(id) else {
                drop(inner);
                return Err(self.not_running(id));
            };
            let result = f(record);
            let saved = match record.vm {
                VmState::Paused { remaining_ms, .. } => Some(saved(record, remaining_ms)),
                _ => None,
            };
            (result, saved)
        };
        if let Some(saved) = saved {
            self.db.set_saved(id, &to_json(&saved))?;
        }
        Ok(result)
    }

    /// Starts a command. Dropping the stream kills it. The log stores
    /// `exec.finished` once dropped; show it what the stream sends.
    pub async fn exec(
        &self,
        id: &str,
        req: Exec,
        origin: &Origin,
    ) -> Result<(Streaming<ExecEvent>, Busy, ExecLog), ApiError> {
        let timeout_s = req.check()?;
        let mut origin = origin.clone();
        let span = traces::start(
            "sandbox.exec",
            &mut origin,
            vec![KeyValue::new("spawnbox.sandbox", id.to_owned())],
        );
        let origin = &origin;
        let opening = Instant::now();
        let opened = self.open(id, origin).await;
        span.step("open", opening, Instant::now());
        let Opened {
            tenant,
            channel,
            mut env,
            busy,
        } = opened.inspect_err(|error| span.fail(error.message.clone()))?;
        let started = json!({
            "cmd": req.cmd,
            "cwd": req.cwd,
            "user": req.user,
            "timeout_s": timeout_s,
            "stdin_bytes": req.stdin.as_ref().map_or(0, String::len),
        });
        env.extend(req.env);
        let request = ExecRequest {
            cmd: req.cmd,
            cwd: req.cwd.unwrap_or_default(),
            env: env.into_iter().collect(),
            timeout_ms: timeout_s * 1000,
            user: req.user.unwrap_or_default(),
            stdin: req.stdin.map(String::into_bytes).unwrap_or_default(),
        };
        let starting = Instant::now();
        let events = guest::exec_stream(&channel, request)
            .await
            .map_err(|status| match status.code() {
                GrpcCode::InvalidArgument | GrpcCode::FailedPrecondition => {
                    ApiError::invalid(status.message())
                }
                _ => ApiError::internal(format!("guest agent: {}", status.message())),
            })
            .inspect_err(|error| span.fail(error.message.clone()))?;
        span.step("start", starting, Instant::now());
        let log = self.hub.exec(origin, &tenant, id, started, span);
        Ok((events, busy, log))
    }

    /// Deletes running sandboxes past their `expires_at` and paused ones
    /// past their retention.
    pub fn expire(&self) {
        let now = now_ms();
        let due: Vec<(String, Arc<tokio::sync::Mutex<()>>, &'static str)> = self
            .inner()
            .records
            .iter()
            .filter(|(_, record)| !record.is_moving())
            .filter_map(|(id, record)| {
                let reason = match &record.vm {
                    VmState::Running(live) if live.expires_at <= now => "timeout",
                    VmState::Paused { paused_at, .. }
                        if paused_at.saturating_add(record.retention_ms) <= now =>
                    {
                        "paused_retention"
                    }
                    _ => return None,
                };
                Some((id.clone(), Arc::clone(&record.lock), reason))
            })
            .collect();
        for (id, lock, reason) in due {
            let this = self.clone();
            tokio::spawn(async move {
                let Ok(_changing) = lock.try_lock() else {
                    return;
                };
                eprintln!("{id} reached its {reason}; deleting");
                if let Some(tenant) = this.remove(&id, state::DELETED).await {
                    this.event(
                        "sandbox.expired",
                        &Origin::system(),
                        &tenant,
                        &id,
                        json!({ "reason": reason }),
                    );
                }
            });
        }
    }

    /// Loads paused sandboxes saved by an earlier run, and removes snapshot
    /// files nothing owns. Call once at start.
    pub fn load_paused(&self) -> anyhow::Result<usize> {
        let mut loaded = HashSet::new();
        let files = self.templates.backend().snapshot_files();
        for (sandbox, saved) in self.db.paused_sandboxes()? {
            let dir = self.paused_dir(&sandbox.id);
            let saved: Option<Saved> = saved.and_then(|s| serde_json::from_str(&s).ok());
            let complete = files.iter().all(|name| dir.join(name).exists());
            let (Some(saved), true) = (saved, complete) else {
                eprintln!("{}: paused files are missing; marking failed", sandbox.id);
                self.db.set_state(&sandbox.id, state::FAILED, now_ms())?;
                self.event(
                    "sandbox.lost",
                    &Origin::system(),
                    &sandbox.tenant,
                    &sandbox.id,
                    json!({ "reason": "paused files are missing" }),
                );
                continue;
            };
            let id = sandbox.id.clone();
            let record = self.paused_record(sandbox, saved, &dir)?;
            loaded.insert(id.clone());
            self.inner().records.insert(id, record);
        }
        if let Ok(entries) = std::fs::read_dir(&self.settings.paused_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !loaded.contains(&name) {
                    remove_dir(&entry.path());
                }
            }
        }
        Ok(loaded.len())
    }

    fn paused_record(
        &self,
        sandbox: db::Sandbox,
        saved: Saved,
        dir: &Path,
    ) -> Result<Record, ApiError> {
        let quotas = self
            .db
            .get_tenant(&sandbox.tenant)?
            .map(|t| t.quotas)
            .unwrap_or_default();
        Ok(Record {
            retention_ms: self.retention_ms(&quotas),
            tenant: sandbox.tenant,
            vm: VmState::Paused {
                paused_at: sandbox.paused_at.unwrap_or_else(now_ms),
                remaining_ms: saved.remaining_ms,
            },
            env: saved.env,
            ports: saved.ports,
            egress: sandbox.egress,
            secrets: saved
                .secrets
                .into_iter()
                .map(|(name, placeholder)| Attached { name, placeholder })
                .collect(),
            volumes: sandbox.volumes,
            limits: Limits {
                vcpus: saved.vcpus,
                memory_mib: saved.memory_mib,
            },
            idle_pause_s: sandbox.idle_pause_s,
            busy: 0,
            last_active: Instant::now(),
            lock: Arc::default(),
            metered_at: now_ms(),
            disk_bytes: stored_bytes(dir),
            moving: None,
        })
    }

    /// Pauses a sandbox if it runs and marks it as moving, so nothing
    /// resumes, pauses or deletes it until `forget` or `abort_move`.
    pub async fn export(&self, id: &str) -> Result<Export, ApiError> {
        let lock = self.record_lock(id).ok_or_else(|| self.not_running(id))?;
        let _changing = lock.lock().await;
        let was_running = {
            let inner = self.inner();
            let record = inner.records.get(id).ok_or_else(|| self.not_running(id))?;
            if record.is_moving() {
                return Err(ApiError::new(Code::Conflict, "sandbox is already moving"));
            }
            matches!(record.vm, VmState::Running(_))
        };
        if was_running {
            self.pause_locked(id, PauseReason::Migrate, &Origin::system())
                .await?;
        }
        let saved = {
            let mut inner = self.inner();
            let record = inner
                .records
                .get_mut(id)
                .ok_or_else(|| ApiError::new(Code::Conflict, "sandbox ended while moving"))?;
            let VmState::Paused { remaining_ms, .. } = record.vm else {
                return Err(ApiError::new(Code::Conflict, "sandbox is not paused"));
            };
            record.moving = Some((Instant::now(), was_running));
            to_json(&saved(record, remaining_ms))
        };
        let sandbox = self.db.get_sandbox(id)?.ok_or_else(ApiError::not_found)?;
        let volumes = sandbox
            .volumes
            .iter()
            .map(|v| self.volumes.file(&v.volume))
            .collect();
        Ok(Export {
            sandbox,
            saved,
            was_running,
            dir: self.paused_dir(id),
            volumes,
        })
    }

    /// Makes a sandbox copied from another host one of this host's, from
    /// the snapshot files in `staged`. Resumes it if `run`. On failure,
    /// leaves nothing behind.
    pub async fn adopt(
        &self,
        sandbox: db::Sandbox,
        saved: &str,
        staged: &Path,
        run: bool,
    ) -> Result<(), ApiError> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(Self::shutting_down());
        }
        let parsed: Saved = serde_json::from_str(saved)
            .map_err(|error| ApiError::invalid(format!("saved state: {error}")))?;
        let id = sandbox.id.clone();
        let dir = self.paused_dir(&id);
        let paused_at = sandbox.paused_at.unwrap_or_else(now_ms);
        let sandbox = db::Sandbox {
            paused_at: Some(paused_at),
            ..sandbox
        };
        let here =
            |inner: &Inner| inner.records.contains_key(&id) || inner.starting.contains_key(&id);
        if here(&self.inner()) {
            return Err(ApiError::new(Code::Conflict, "sandbox is already here"));
        }
        remove_dir(&dir);
        std::fs::rename(staged, &dir)
            .map_err(|error| ApiError::internal(format!("place snapshot: {error}")))?;
        let record = match self.paused_record(sandbox.clone(), parsed, &dir) {
            Ok(record) => record,
            Err(error) => {
                remove_dir(&dir);
                return Err(error);
            }
        };
        let lock = Arc::clone(&record.lock);
        {
            let mut inner = self.inner();
            if here(&inner) {
                return Err(ApiError::new(Code::Conflict, "sandbox is already here"));
            }
            inner.records.insert(id.clone(), record);
        }
        let _changing = lock.lock().await;
        let prior = match self.db.take_over(&sandbox, paused_at, saved) {
            Ok(prior) => prior,
            Err(error) => {
                self.inner().records.remove(&id);
                remove_dir(&dir);
                return Err(error.into());
            }
        };
        if run && let Err(error) = self.resume_locked(&id, &Origin::system(), "migrate").await {
            if let Some(mut record) = self.inner().records.remove(&id) {
                self.settle(&id, &mut record, now_ms());
            }
            remove_dir(&dir);
            if let Err(error) = self.db.undo_take_over(&id, prior) {
                eprintln!("undo take over of {id}: {error}");
            }
            return Err(error);
        }
        Ok(())
    }

    /// Drops a sandbox that now runs on `node`, without events: its VM,
    /// its files, the volumes that went with it, and its claim on the row.
    pub async fn forget(&self, id: &str, node: &str) -> Result<(), ApiError> {
        if let Some(lock) = self.record_lock(id) {
            let _changing = lock.lock().await;
            let record = self.inner().records.remove(id);
            if let Some(mut record) = record {
                for volume in &record.volumes {
                    self.volumes.remove_file(&volume.volume);
                }
                self.settle(id, &mut record, now_ms());
                if let VmState::Running(live) = record.vm {
                    let Live {
                        vm, channel, index, ..
                    } = *live;
                    drop(channel);
                    vm.stop().await;
                    self.release(index);
                }
            }
        }
        remove_dir(&self.paused_dir(id));
        self.db.hand_off(id, node)?;
        Ok(())
    }

    /// Ends a move that failed: the sandbox stays here, and runs again if
    /// it ran before.
    pub async fn abort_move(&self, id: &str) -> Result<(), ApiError> {
        let lock = self.record_lock(id).ok_or_else(|| self.not_running(id))?;
        let _changing = lock.lock().await;
        let was_running = self
            .inner()
            .records
            .get_mut(id)
            .and_then(|r| r.moving.take())
            .is_some_and(|(_, was_running)| was_running);
        if was_running {
            self.resume_locked(id, &Origin::system(), "api").await?;
        }
        Ok(())
    }

    /// Stops every running VM; paused sandboxes stay paused. New creates
    /// and resumes fail from now on.
    pub async fn stop_all(&self) {
        self.closing.store(true, Ordering::SeqCst);
        for vm in self.warm.close() {
            self.stop_warm(vm).await;
        }
        let all: Vec<(String, Arc<tokio::sync::Mutex<()>>)> = self
            .inner()
            .records
            .iter()
            .map(|(id, record)| (id.clone(), Arc::clone(&record.lock)))
            .collect();
        for (id, lock) in all {
            let _changing = lock.lock().await;
            let mut record = self.inner().records.remove(&id);
            if let Some(record) = record.as_mut() {
                self.settle(&id, record, now_ms());
            }
            if let Some(Record {
                vm: VmState::Running(live),
                tenant,
                ..
            }) = record
            {
                self.stop(&id, *live, state::DELETED).await;
                self.event(
                    "sandbox.killed",
                    &Origin::system(),
                    &tenant,
                    &id,
                    json!({ "reason": "server stopped" }),
                );
            }
        }
    }
}

fn is_idle(record: &Record) -> bool {
    matches!(record.vm, VmState::Running(_))
        && !record.is_moving()
        && record.idle_pause_s > 0
        && record.busy == 0
        && record.last_active.elapsed() >= Duration::from_secs(record.idle_pause_s)
}

fn saved(record: &Record, remaining_ms: i64) -> Saved {
    Saved {
        env: record.env.clone(),
        ports: record.ports.clone(),
        secrets: record
            .secrets
            .iter()
            .map(|a| (a.name.clone(), a.placeholder.clone()))
            .collect(),
        vcpus: record.limits.vcpus,
        memory_mib: record.limits.memory_mib,
        remaining_ms,
    }
}

/// Bytes the sandbox's writable disk takes.
fn disk_bytes(vm: &Vm) -> u64 {
    vm.disk().as_deref().map_or(0, stored_bytes)
}

/// Bytes a file, or a directory's files, take on disk. Sparse holes do not
/// count. Missing is 0. Follows links: gVisor's layer is a `/proc` fd link.
fn stored_bytes(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return 0;
    };
    if meta.is_dir() {
        std::fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| stored_bytes(&entry.path()))
            .sum()
    } else {
        meta.blocks() * 512
    }
}

fn to_json(value: &impl Serialize) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn remove_dir(dir: &std::path::Path) {
    match std::fs::remove_dir_all(dir) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            eprintln!("warning: remove {}: {error}", dir.display());
        }
        _ => {}
    }
}

/// Asks the guest to write cached volume data to disk. A VM that is killed
/// loses what it has not written.
async fn flush(channel: &Channel) {
    match tokio::time::timeout(Duration::from_secs(10), guest::exec(channel, "sync")).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => eprintln!("warning: sync volumes: {error:#}"),
        Err(_) => eprintln!("warning: sync volumes: timed out"),
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn round(ms: f64) -> f64 {
    (ms * 10.0).round() / 10.0
}
