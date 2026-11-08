//! Templates and their builds: the background build worker, the build each
//! template currently uses, and the VM slots that builds and sandboxes share.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use spawn_egress::Attached;
use spawn_node::firecracker::Limits;
use spawn_node::{Backend, Build, HOT_FILE, Log, Node, Recipe, Slot};
use tokio::sync::{Notify, Semaphore};

use crate::db::{self, Db, build_state};
use crate::egress::Network;
use crate::ids;
use crate::model::{
    ApiError, BASE_TEMPLATE, BuildView, Code, Resources, TemplateSpec, TemplateView,
    is_template_name, rfc3339_ms,
};
use crate::pages::LazyMem;
use crate::runtime::now_ms;
use crate::secrets::Secrets;
use crate::store::{self, BuildStore, PagesIn};
use crate::tenancy::{scoped, split};

const LOG_FILE: &str = "build.log";
/// A Firecracker build's memory file.
const MEMORY: &str = "vm.mem";
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
const LOG_TAIL_BYTES: u64 = 64 * 1024;
/// Store objects nothing has used for this long are deleted.
const STORE_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
const MAINTAIN_EVERY: Duration = Duration::from_secs(60);
/// In `MAINTAIN_EVERY` ticks.
const COLLECT_EVERY: u64 = 24 * 60;
/// Builds used this recently stay in the local cache even past its limit.
const CACHE_GRACE_MS: i64 = 10 * 60 * 1000;
/// How long a worker keeps a snapshot template that the primary's list
/// does not have yet.
const FRESH_SNAPSHOT: Duration = Duration::from_secs(60);
/// A build claim not written again for this long belongs to a host that
/// stopped, and another host builds it instead.
const CLAIM_STALE: Duration = Duration::from_secs(180);
const CLAIM_REFRESH: Duration = Duration::from_secs(30);
const CLAIM_POLL: Duration = Duration::from_secs(5);
static CLAIMS_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

/// This host's claim on building a store key. It is written again while
/// held, and deleted when dropped.
struct ClaimGuard {
    store: Arc<BuildStore>,
    key: String,
    refresh: tokio::task::AbortHandle,
}

impl ClaimGuard {
    fn new(store: Arc<BuildStore>, key: String) -> Self {
        let (s, k) = (Arc::clone(&store), key.clone());
        let refresh = tokio::spawn(async move {
            loop {
                tokio::time::sleep(CLAIM_REFRESH).await;
                if let Err(error) = s.refresh_claim(&k).await {
                    eprintln!("warning: refresh build claim {k}: {error:#}");
                }
            }
        })
        .abort_handle();
        Self {
            store,
            key,
            refresh,
        }
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        self.refresh.abort();
        let (store, key) = (Arc::clone(&self.store), std::mem::take(&mut self.key));
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = store.release_claim(&key).await {
                    eprintln!("warning: release build claim {key}: {error:#}");
                }
            });
        }
    }
}

/// Jail and network indexes, shared by sandboxes and builds and reused
/// oldest first.
pub struct Slots {
    total: u32,
    free: Mutex<VecDeque<u32>>,
    released: Notify,
}

impl Slots {
    pub fn new(count: u32) -> Self {
        Self {
            total: count,
            free: Mutex::new((1..=count).collect()),
            released: Notify::new(),
        }
    }

    fn free(&self) -> MutexGuard<'_, VecDeque<u32>> {
        self.free.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn total(&self) -> u32 {
        self.total
    }

    /// Slots free now.
    pub fn free_count(&self) -> usize {
        self.free().len()
    }

    pub fn try_take(&self) -> Option<u32> {
        self.free().pop_front()
    }

    /// Waits until a slot is free.
    pub async fn take(&self) -> u32 {
        loop {
            if let Some(index) = self.try_take() {
                return index;
            }
            self.released.notified().await;
        }
    }

    /// Call only once the slot's jail and network are gone.
    pub fn release(&self, index: u32) {
        self.free().push_back(index);
        self.released.notify_one();
    }
}

/// A ready build that new sandboxes can start from. Once retired, its files
/// are removed when the last create using it finishes. Running sandboxes
/// keep their own links and copies, so they are not affected.
pub struct ReadyBuild {
    pub id: String,
    seq: i64,
    pub build: Build,
    pub spec: TemplateSpec,
    dir: PathBuf,
    retired: AtomicBool,
    /// Its key in the build store, if it can be kept there.
    store_key: Option<String>,
    /// False while its files are only in the build store. Held while they
    /// are fetched or removed.
    local: tokio::sync::Mutex<bool>,
    uploaded: AtomicBool,
    uploading: AtomicBool,
    last_used: AtomicI64,
    /// Set while its memory file is loaded from the build store, with
    /// sandboxes already running from it.
    lazy: Mutex<Option<Arc<LazyMem>>>,
}

/// How a create can start a sandbox from a build.
pub enum Startable {
    /// From its local files. `fetched` if they were fetched just now.
    Local { fetched: bool },
    /// With its memory read from the build store as the guest uses it.
    Lazy(Arc<LazyMem>),
}

impl ReadyBuild {
    fn new(build: &db::Build, files: Build, spec: TemplateSpec, dir: PathBuf, local: bool) -> Self {
        Self {
            id: build.id.clone(),
            seq: build.seq,
            build: files,
            spec,
            dir,
            retired: AtomicBool::new(false),
            store_key: build.store_key.clone(),
            local: tokio::sync::Mutex::new(local),
            uploaded: AtomicBool::new(build.uploaded_at.is_some()),
            uploading: AtomicBool::new(false),
            last_used: AtomicI64::new(now_ms()),
            lazy: Mutex::new(None),
        }
    }

    fn lazy(&self) -> Option<Arc<LazyMem>> {
        self.lazy.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_lazy(&self, lazy: Option<Arc<LazyMem>>) {
        *self.lazy.lock().unwrap_or_else(|e| e.into_inner()) = lazy;
    }
}

impl crate::warm::Source for ReadyBuild {
    fn is_retired(&self) -> bool {
        self.retired.load(Ordering::SeqCst)
    }
}

impl Drop for ReadyBuild {
    fn drop(&mut self) {
        if self.retired.load(Ordering::SeqCst) {
            remove_dir(&self.dir);
        }
    }
}

/// Paths to the inputs of every build.
pub struct Inputs {
    /// Empty for gVisor, which runs no guest kernel.
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    /// The Firecracker or runsc binary.
    pub runtime: PathBuf,
}

pub struct Templates {
    db: Db,
    node: Arc<Node>,
    slots: Arc<Slots>,
    network: Arc<Network>,
    secrets: Arc<Secrets>,
    inputs: Inputs,
    /// `<data-dir>/builds`, one directory per build.
    dir: PathBuf,
    fingerprint: String,
    defaults: Resources,
    builds: Semaphore,
    /// The newest ready build of each template.
    current: Mutex<HashMap<String, Arc<ReadyBuild>>>,
    closing: AtomicBool,
    store: Option<Arc<BuildStore>>,
    /// Disk the builds directory may use before idle builds that are in
    /// the store are removed locally. 0 means no limit.
    cache_bytes: u64,
    cpu: String,
    /// Snapshot templates saved here, and when.
    fresh: Mutex<HashMap<String, Instant>>,
}

impl Templates {
    /// Loads saved builds, makes sure `base` is ready, and starts queued
    /// builds in the background.
    #[expect(clippy::too_many_arguments, reason = "called once, at startup")]
    pub async fn start(
        db: Db,
        node: Arc<Node>,
        slots: Arc<Slots>,
        network: Arc<Network>,
        secrets: Arc<Secrets>,
        inputs: Inputs,
        dir: PathBuf,
        defaults: Resources,
        max_builds: usize,
        store: Option<Arc<BuildStore>>,
        cache_bytes: u64,
    ) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&dir)?;
        let fingerprint = {
            let files: Vec<PathBuf> = match node.backend() {
                Backend::Firecracker => vec![
                    inputs.kernel.clone(),
                    inputs.rootfs.clone(),
                    inputs.runtime.clone(),
                ],
                Backend::Gvisor => vec![inputs.rootfs.clone(), inputs.runtime.clone()],
            };
            let mut extra = BUILD_FORMAT.to_vec();
            extra.extend_from_slice(network.ca_pem.as_bytes());
            tokio::task::spawn_blocking(move || fingerprint(&files, &extra)).await??
        };
        let this = Arc::new(Self {
            db,
            node,
            slots,
            network,
            secrets,
            inputs,
            dir,
            fingerprint,
            defaults,
            builds: Semaphore::new(max_builds),
            current: Mutex::new(HashMap::new()),
            closing: AtomicBool::new(false),
            store,
            cache_bytes,
            cpu: store::cpu_model(),
            fresh: Mutex::new(HashMap::new()),
        });
        this.load()?;
        this.ensure_base().await?;
        for build in this.db.builds_in(&[build_state::QUEUED])? {
            this.queue(build.id);
        }
        if this.store.is_some() {
            let maintain = Arc::clone(&this);
            tokio::spawn(async move { maintain.maintain().await });
        }
        Ok(this)
    }

    /// Uploads builds the store misses, trims the local cache, and now and
    /// then deletes old objects from the store.
    async fn maintain(self: Arc<Self>) {
        let mut ticks = 0u64;
        while !self.closing.load(Ordering::SeqCst) {
            self.check_uploaded().await;
            self.upload_pending().await;
            let this = Arc::clone(&self);
            if let Err(error) = tokio::task::spawn_blocking(move || this.trim()).await {
                eprintln!("warning: trim build cache: {error}");
            }
            // The first pass waits a while, so a restart loop does not
            // delete anything.
            if ticks % COLLECT_EVERY == 10 {
                self.collect().await;
            }
            ticks += 1;
            tokio::time::sleep(MAINTAIN_EVERY).await;
        }
    }

    /// Before `trim` removes anything, makes sure the store still has the
    /// builds marked uploaded. The store can lose them, for example when it
    /// is wiped or its bucket changes; those builds are uploaded again.
    async fn check_uploaded(&self) {
        let Some(store) = &self.store else { return };
        if self.cache_bytes == 0 {
            return;
        }
        let dir = self.dir.clone();
        let used = tokio::task::spawn_blocking(move || disk_usage(&dir))
            .await
            .unwrap_or(0);
        if used <= self.cache_bytes {
            return;
        }
        let uploaded: Vec<_> = self
            .current()
            .values()
            .filter(|b| b.uploaded.load(Ordering::SeqCst))
            .cloned()
            .collect();
        for ready in uploaded {
            let Some(key) = &ready.store_key else {
                continue;
            };
            match store.has(key).await {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!("build {} is missing from the build store", ready.id);
                    ready.uploaded.store(false, Ordering::SeqCst);
                }
                Err(error) => {
                    eprintln!("build {}: check the build store: {error:#}", ready.id);
                    ready.uploaded.store(false, Ordering::SeqCst);
                }
            }
        }
    }

    /// Uploads current builds that are not in the store yet.
    async fn upload_pending(&self) {
        let Some(store) = &self.store else { return };
        let pending: Vec<_> = self
            .current()
            .values()
            .filter(|b| b.store_key.is_some() && !b.uploaded.load(Ordering::SeqCst))
            .cloned()
            .collect();
        for ready in pending {
            let Some(key) = &ready.store_key else {
                continue;
            };
            if self.closing.load(Ordering::SeqCst) || ready.uploading.swap(true, Ordering::SeqCst) {
                continue;
            }
            // Holding `ready` keeps `trim` from removing its files meanwhile.
            let local = *ready.local.lock().await;
            if local {
                self.upload(store, key, &ready).await;
            }
            ready.uploading.store(false, Ordering::SeqCst);
        }
    }

    async fn upload(&self, store: &BuildStore, key: &str, ready: &ReadyBuild) {
        let mut names: Vec<String> = ready
            .build
            .own_files()
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        // Firecracker memory goes as pages, so other hosts can load it
        // lazily.
        let pages = names.iter().position(|n| n == MEMORY).map(|at| {
            let hot = std::fs::read(ready.dir.join(HOT_FILE))
                .ok()
                .and_then(|json| serde_json::from_slice(&json).ok())
                .unwrap_or_default();
            PagesIn {
                name: names.remove(at),
                hot,
            }
        });
        let started = Instant::now();
        match store.upload(key, &ready.dir, &names, pages).await {
            Ok(()) => {
                ready.uploaded.store(true, Ordering::SeqCst);
                if let Err(error) = self.db.set_build_uploaded(&ready.id, now_ms()) {
                    eprintln!("build {}: {error}", ready.id);
                }
                eprintln!(
                    "build {} saved to the build store in {:.1} s",
                    ready.id,
                    started.elapsed().as_secs_f64()
                );
            }
            Err(error) => eprintln!("build {}: save to the build store: {error:#}", ready.id),
        }
    }

    /// Removes the files of idle builds, least recently used first, until
    /// the builds directory fits in `cache_bytes`. Only builds the store has
    /// are removed; they are fetched again when used.
    fn trim(&self) {
        if self.cache_bytes == 0 {
            return;
        }
        let mut used = disk_usage(&self.dir);
        if used <= self.cache_bytes {
            return;
        }
        let mut idle: Vec<_> = self
            .current()
            .values()
            .filter(|b| b.uploaded.load(Ordering::SeqCst))
            .cloned()
            .collect();
        idle.sort_by_key(|b| b.last_used.load(Ordering::SeqCst));
        let recent = now_ms() - CACHE_GRACE_MS;
        for ready in idle {
            if used <= self.cache_bytes || ready.last_used.load(Ordering::SeqCst) > recent {
                break;
            }
            let Ok(mut local) = ready.local.try_lock() else {
                continue;
            };
            // Checked under the lock: `ensure_local` sets `last_used` before
            // it locks, so a create that already passed it is seen here. Held
            // by `current` and `idle` only means no create or warm pool uses
            // it; a create that takes it from now on waits and fetches it.
            if !*local
                || Arc::strong_count(&ready) > 2
                || ready.last_used.load(Ordering::SeqCst) > recent
            {
                continue;
            }
            *local = false;
            let mut freed = 0;
            for path in ready.build.own_files() {
                freed += std::fs::metadata(&path).map_or(0, |m| m.blocks() * 512);
                if let Err(error) = std::fs::remove_file(&path) {
                    eprintln!("warning: remove {}: {error}", path.display());
                }
            }
            used = used.saturating_sub(freed);
            eprintln!(
                "build {} removed from the local cache; it is in the build store",
                ready.id
            );
        }
    }

    /// Deletes store objects that no build here uses and that no host has
    /// written for `STORE_MAX_AGE`.
    async fn collect(&self) {
        let Some(store) = &self.store else { return };
        let keep: HashSet<String> = self
            .current()
            .values()
            .filter_map(|b| b.store_key.clone())
            .collect();
        match store.collect(&keep, STORE_MAX_AGE).await {
            Ok((0, 0)) => {}
            Ok((builds, blobs)) => {
                eprintln!("build store: deleted {builds} old builds and {blobs} blobs");
            }
            Err(error) => eprintln!("build store: clean up: {error:#}"),
        }
    }

    /// Makes sure the build's files are on this host, fetching them from
    /// the build store if needed. If that fails, the template is built
    /// again. `true` if the files were fetched now.
    pub async fn ensure_local(self: &Arc<Self>, ready: &Arc<ReadyBuild>) -> Result<bool, ApiError> {
        ready.last_used.store(now_ms(), Ordering::SeqCst);
        let mut local = loop {
            let local = ready.local.lock().await;
            match ready.lazy() {
                // Its memory is being loaded: wait for that instead.
                Some(lazy) => {
                    drop(local);
                    lazy.wait_done().await;
                }
                None => break local,
            }
        };
        if *local {
            return Ok(false);
        }
        eprintln!("fetching build {} from the build store", ready.id);
        let started = Instant::now();
        let fetched = match (&self.store, &ready.store_key) {
            (Some(store), Some(key)) => self.fetch(store, key, &ready.dir, &ready.spec).await,
            _ => Err(anyhow::anyhow!("no build store is set")),
        };
        match fetched {
            Ok(Some(_)) => {
                *local = true;
                eprintln!(
                    "fetched build {} in {:.1} s",
                    ready.id,
                    started.elapsed().as_secs_f64()
                );
                Ok(true)
            }
            result => {
                drop(local);
                Err(self.fetch_failed(ready, result.err()))
            }
        }
    }

    fn fetch_failed(
        self: &Arc<Self>,
        ready: &ReadyBuild,
        error: Option<anyhow::Error>,
    ) -> ApiError {
        let why = match error {
            Some(error) => format!("{error:#}"),
            None => "the build store does not have it".into(),
        };
        eprintln!("build {}: fetch: {why}", ready.id);
        self.rebuild(ready);
        let message = if ready.spec.snapshot.is_some() {
            "the snapshot's files could not be fetched; save it again"
        } else {
            "the template's build could not be fetched; it is being built again"
        };
        ApiError::new(Code::Conflict, message)
    }

    /// Like `ensure_local`, but on Firecracker a build that is only in the
    /// store can start before its memory file is here: its other files are
    /// fetched, and its memory is loaded in the background, the parts a
    /// sandbox touches first.
    pub async fn ensure_startable(
        self: &Arc<Self>,
        ready: &Arc<ReadyBuild>,
    ) -> Result<Startable, ApiError> {
        let (Some(store), Some(key)) = (&self.store, &ready.store_key) else {
            let fetched = self.ensure_local(ready).await?;
            return Ok(Startable::Local { fetched });
        };
        if self.node.backend() != Backend::Firecracker {
            let fetched = self.ensure_local(ready).await?;
            return Ok(Startable::Local { fetched });
        }
        ready.last_used.store(now_ms(), Ordering::SeqCst);
        let mut local = ready.local.lock().await;
        if *local {
            return Ok(Startable::Local { fetched: false });
        }
        if let Some(lazy) = ready.lazy() {
            return Ok(Startable::Lazy(lazy));
        }
        eprintln!("fetching build {} from the build store", ready.id);
        let started = Instant::now();
        let fetched = async {
            let Some(paged) = store.download_files(key, &ready.dir).await? else {
                return Ok(None);
            };
            ready
                .build
                .link_inputs(&self.inputs.kernel, &self.inputs.rootfs)?;
            let Some(paged) = paged else {
                // An older build, with its memory as a whole file.
                ready.build.check_files(&[])?;
                return Ok(Some(None));
            };
            ready.build.check_files(&[MEMORY])?;
            let lazy = LazyMem::new(Arc::clone(store), paged, &ready.dir)?;
            anyhow::Ok(Some(Some(lazy)))
        }
        .await;
        let lazy = match fetched {
            Ok(Some(Some(lazy))) => lazy,
            Ok(Some(None)) => {
                *local = true;
                return Ok(Startable::Local { fetched: true });
            }
            result => {
                drop(local);
                return Err(self.fetch_failed(ready, result.err()));
            }
        };
        eprintln!(
            "build {}: disks fetched in {:.1} s; loading its memory while it runs",
            ready.id,
            started.elapsed().as_secs_f64()
        );
        ready.set_lazy(Some(Arc::clone(&lazy)));
        let (ready2, lazy2) = (Arc::clone(ready), Arc::clone(&lazy));
        tokio::spawn(async move {
            let result = lazy2.run().await;
            let mut local = ready2.local.lock().await;
            match result {
                Ok(()) => {
                    *local = true;
                    eprintln!(
                        "build {}: memory loaded in {:.1} s",
                        ready2.id,
                        started.elapsed().as_secs_f64()
                    );
                }
                Err(error) => eprintln!("build {}: load memory: {error:#}", ready2.id),
            }
            ready2.set_lazy(None);
            drop(local);
            lazy2.mark_done();
        });
        Ok(Startable::Lazy(lazy))
    }

    /// Downloads build `key` into `dir`. `None` if the store does not have it.
    async fn fetch(
        &self,
        store: &BuildStore,
        key: &str,
        dir: &Path,
        spec: &TemplateSpec,
    ) -> Result<Option<Build>> {
        if !store.download(key, dir).await? {
            return Ok(None);
        }
        let files = Build::adopt(
            dir,
            self.node.backend(),
            &self.inputs.kernel,
            &self.inputs.rootfs,
            limits(&spec.resources),
            spec.has_layer(),
            spec.own_rootfs(),
        )?;
        Ok(Some(files))
    }

    /// Replaces a current build whose files are lost with a new build. A
    /// snapshot cannot be built, so it is only retired.
    fn rebuild(self: &Arc<Self>, ready: &ReadyBuild) {
        let mut current = self.current();
        let Some(template) = current
            .iter()
            .find(|(_, b)| b.id == ready.id)
            .map(|(t, _)| t.clone())
        else {
            return;
        };
        if let Some(old) = current.remove(&template) {
            old.retired.store(true, Ordering::SeqCst);
        }
        drop(current);
        let queued = (|| {
            self.db
                .set_build_state(&ready.id, build_state::OUTDATED, now_ms(), None)?;
            if ready.spec.snapshot.is_some() {
                return Ok(None);
            }
            let spec = self
                .db
                .get_template(&template)?
                .context("template is gone")?
                .spec;
            anyhow::Ok(Some(
                self.new_build(&template, &spec)
                    .map_err(|e| anyhow::anyhow!("{}", e.message))?,
            ))
        })();
        match queued {
            Ok(Some(build)) => self.queue(build.id),
            Ok(None) => {}
            Err(error) => eprintln!("rebuild template {template:?}: {error:#}"),
        }
    }

    fn current(&self) -> MutexGuard<'_, HashMap<String, Arc<ReadyBuild>>> {
        self.current.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Picks up ready builds from the last run, drops ones that no longer
    /// match this host's inputs, and removes directories nothing refers to.
    fn load(&self) -> Result<()> {
        let requeued = self.db.requeue_unfinished_builds()?;
        if requeued > 0 {
            eprintln!("queued {requeued} interrupted builds again");
        }
        let now = now_ms();
        let mut keep = Vec::new();
        for build in self.db.builds_in(&[build_state::READY])? {
            let template = self.db.get_template(&build.template)?;
            let spec = serde_json::from_str::<TemplateSpec>(&build.spec);
            let ready = match (&template, spec) {
                (None, _) => Err(build_state::REMOVED),
                (Some(_), _) if build.fingerprint != self.fingerprint => Err(build_state::OUTDATED),
                (Some(_), Ok(spec)) => self.open(&build, spec).ok_or(build_state::OUTDATED),
                (Some(_), Err(_)) => Err(build_state::OUTDATED),
            };
            match ready {
                Ok(ready) => {
                    // Newer builds come later and replace older ones.
                    if let Some(old) = self.current().insert(build.template.clone(), ready) {
                        self.db
                            .set_build_state(&old.id, build_state::REMOVED, now, None)?;
                        old.retired.store(true, Ordering::SeqCst);
                    }
                }
                Err(state) => {
                    self.db.set_build_state(&build.id, state, now, None)?;
                    if state == build_state::OUTDATED
                        && let Some(template) = template
                    {
                        keep.push(template);
                    }
                }
            }
        }
        // Outdated templates are built again with their current spec.
        for template in keep {
            if template.name == BASE_TEMPLATE || self.current().contains_key(&template.name) {
                continue;
            }
            let snapshot = serde_json::from_str::<TemplateSpec>(&template.spec)
                .is_ok_and(|spec| spec.snapshot.is_some());
            if snapshot {
                eprintln!(
                    "snapshot template {:?} no longer matches this host's inputs",
                    template.name
                );
                continue;
            }
            let pending = self
                .db
                .latest_build(&template.name)?
                .is_some_and(|b| b.state == build_state::QUEUED);
            if !pending {
                eprintln!("rebuilding template {:?} for new inputs", template.name);
                self.new_build(&template.name, &template.spec)?;
            }
        }
        self.remove_unused_dirs()
    }

    /// The ready build in `build`'s directory, if all its files are there.
    fn open(&self, build: &db::Build, spec: TemplateSpec) -> Option<Arc<ReadyBuild>> {
        let dir = self.dir.join(&build.id);
        let limits = limits(&spec.resources);
        let has_layer = spec.has_layer();
        let files = Build::at(&dir, self.node.backend(), limits, has_layer)
            .with_own_rootfs(spec.own_rootfs());
        let complete = files.files().iter().all(|p| p.is_file());
        let stored =
            self.store.is_some() && build.store_key.is_some() && build.uploaded_at.is_some();
        (complete || stored).then(|| Arc::new(ReadyBuild::new(build, files, spec, dir, complete)))
    }

    fn remove_unused_dirs(&self) -> Result<()> {
        let live = |state: &str| {
            matches!(
                state,
                build_state::QUEUED | build_state::READY | build_state::FAILED
            )
        };
        for entry in std::fs::read_dir(&self.dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let used = ids::is_valid_id("bld", &name)
                && self.db.get_build(&name)?.is_some_and(|b| live(&b.state));
            if !used {
                remove_dir(&entry.path());
            }
        }
        Ok(())
    }

    /// Builds `base` now unless a ready build matches the server's flags.
    async fn ensure_base(self: &Arc<Self>) -> Result<()> {
        let spec = TemplateSpec::base(self.defaults);
        let ready = self
            .current()
            .get(BASE_TEMPLATE)
            .is_some_and(|b| b.spec == spec);
        if ready {
            return Ok(());
        }
        let json = serde_json::to_string(&spec)?;
        self.db.put_template(BASE_TEMPLATE, &json, now_ms())?;
        // An interrupted build of the same spec is picked up, not repeated.
        let build = match self.db.latest_build(BASE_TEMPLATE)? {
            Some(b) if b.state == build_state::QUEUED && self.wanted(&b)? => b,
            _ => self.new_build(BASE_TEMPLATE, &json)?,
        };
        Arc::clone(self).run(build.id.clone()).await;
        let build = self
            .db
            .get_build(&build.id)?
            .context("base build vanished")?;
        if build.state != build_state::READY {
            bail!(
                "template {BASE_TEMPLATE:?} failed to build: {}; see {}",
                build.error.unwrap_or_default(),
                self.dir.join(&build.id).join(LOG_FILE).display()
            );
        }
        Ok(())
    }

    fn new_build(&self, template: &str, spec: &str) -> Result<db::Build, ApiError> {
        let id = ids::new_id("bld").map_err(ApiError::internal)?;
        Ok(self
            .db
            .insert_build(&id, template, spec, &self.fingerprint, now_ms())?)
    }

    /// Runs a queued build in the background.
    fn queue(self: &Arc<Self>, id: String) {
        let this = Arc::clone(self);
        tokio::spawn(async move { this.run(id).await });
    }

    /// Runs a build if it is still queued and wanted, and records the result.
    async fn run(self: Arc<Self>, id: String) {
        let claim = self.wait_turn(&id).await;
        let Ok(permit) = self.builds.acquire().await else {
            return;
        };
        let result = self.try_run(&id, claim.as_ref()).await;
        drop(claim);
        drop(permit);
        let Err(error) = result else {
            if self.store.is_some() {
                let this = Arc::clone(&self);
                tokio::spawn(async move { this.upload_pending().await });
            }
            return;
        };
        let message = format!("{error:#}");
        eprintln!("build {id}: {message}");
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        // Don't leave the build looking busy forever. A published build is
        // already in `current` and keeps its files.
        let published = self.current().values().any(|b| b.id == id);
        if !published {
            remove_all_but_log(&self.dir.join(&id));
            if let Err(error) = self.db.fail_build(&id, now_ms(), &message) {
                eprintln!("build {id}: mark failed: {error}");
            }
        }
    }

    /// With a build store, waits while another host builds the same thing,
    /// so it is built once and fetched here. The claim, if this host is to
    /// build it, is held until the build is in the store.
    async fn wait_turn(&self, id: &str) -> Option<ClaimGuard> {
        let store = self.store.as_ref()?;
        let mut waited = false;
        loop {
            let build = self.db.get_build(id).ok()??;
            if build.state != build_state::QUEUED || self.closing.load(Ordering::SeqCst) {
                return None;
            }
            let (spec, _, key) = self.inputs_of(&build).ok()?;
            if spec.snapshot.is_some() {
                return None;
            }
            if store.has(&key).await.unwrap_or(false) {
                return None;
            }
            match store.claim(&key, CLAIM_STALE).await {
                Ok(store::Claim::Mine) => return Some(ClaimGuard::new(Arc::clone(store), key)),
                Ok(store::Claim::Held) => {
                    if !waited {
                        eprintln!(
                            "template {:?} ({id}) is being built on another host; waiting",
                            build.template
                        );
                        waited = true;
                    }
                }
                Ok(store::Claim::Unsupported) => {
                    if !CLAIMS_UNSUPPORTED.swap(true, Ordering::SeqCst) {
                        eprintln!(
                            "warning: the build store has no create-only writes; hosts may build the same template at once"
                        );
                    }
                    return None;
                }
                Err(error) => {
                    eprintln!("build {id}: claim in the build store: {error:#}");
                    return None;
                }
            }
            tokio::time::sleep(CLAIM_POLL).await;
        }
    }

    /// The spec, egress policies and store key of `build`.
    fn inputs_of(
        &self,
        build: &db::Build,
    ) -> Result<(TemplateSpec, Vec<spawn_egress::Policy>, String)> {
        let spec: TemplateSpec = serde_json::from_str(&build.spec)?;
        // A tenant's builds follow its egress policy.
        let policies: Vec<_> = match split(&build.template).0 {
            Some(tenant) => self.db.get_tenant(tenant)?.and_then(|t| t.egress),
            None => None,
        }
        .into_iter()
        .collect();
        let key = self.store_key(&spec, &policies)?;
        Ok((spec, policies, key))
    }

    /// True when the builds directory is full and new builds in the store
    /// should stay there until they are used.
    async fn cache_full(&self) -> bool {
        if self.cache_bytes == 0 {
            return false;
        }
        let dir = self.dir.clone();
        tokio::task::spawn_blocking(move || disk_usage(&dir))
            .await
            .is_ok_and(|used| used >= self.cache_bytes)
    }

    async fn try_run(&self, id: &str, claim: Option<&ClaimGuard>) -> Result<()> {
        let Some(mut build) = self.db.get_build(id)? else {
            return Ok(());
        };
        if build.state != build_state::QUEUED || self.closing.load(Ordering::SeqCst) {
            return Ok(());
        }
        if !self.wanted(&build)? {
            self.db
                .set_build_state(id, build_state::REMOVED, now_ms(), None)?;
            return Ok(());
        }
        let (spec, policies, key) = self.inputs_of(&build)?;
        let dir = self.dir.join(id);
        remove_dir(&dir);
        std::fs::create_dir_all(&dir)?;
        let mut log = CappedLog::create(&dir.join(LOG_FILE))?;
        if !self.begin(&build, &key)? {
            remove_dir(&dir);
            return Ok(());
        }
        build.store_key = Some(key.clone());
        let started = Instant::now();
        if let Some(store) = &self.store {
            if claim.is_none() && self.cache_full().await && store.has(&key).await.unwrap_or(false)
            {
                let _ = writeln!(log, "== in the build store; fetched when first used");
                eprintln!(
                    "template {:?} ({id}) stays in the build store until used; the cache is full",
                    build.template
                );
                build.uploaded_at = Some(now_ms());
                self.db.set_build_uploaded(id, now_ms())?;
                let files = Build::at(
                    &dir,
                    self.node.backend(),
                    limits(&spec.resources),
                    spec.has_layer(),
                )
                .with_own_rootfs(spec.own_rootfs());
                return self.publish(&build, spec, files, dir, false);
            }
            match self.fetch(store, &key, &dir, &spec).await {
                Ok(Some(files)) => {
                    let seconds = started.elapsed().as_secs_f64();
                    let _ = writeln!(log, "== fetched from the build store in {seconds:.1} s");
                    eprintln!(
                        "template {:?} ({id}) fetched from the build store in {seconds:.1} s",
                        build.template
                    );
                    build.uploaded_at = Some(now_ms());
                    self.db.set_build_uploaded(id, now_ms())?;
                    return self.publish(&build, spec, files, dir, true);
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = writeln!(log, "== could not use the build store: {error:#}");
                    eprintln!("build {id}: build store: {error:#}");
                }
            }
        }
        if spec.snapshot.is_some() {
            remove_all_but_log(&dir);
            bail!("the snapshot was saved on another host and the build store does not have it");
        }
        let index = self.slots.take().await;
        // The template may have changed or gone while this waited for a slot.
        let wanted = match self.wanted(&build) {
            Ok(wanted) => wanted,
            Err(error) => {
                self.slots.release(index);
                return Err(error);
            }
        };
        if !wanted || self.closing.load(Ordering::SeqCst) {
            self.slots.release(index);
            if !wanted {
                self.db
                    .set_build_state(id, build_state::REMOVED, now_ms(), None)?;
            }
            remove_dir(&dir);
            return Ok(());
        }
        eprintln!("building template {:?} ({id})", build.template);

        let name = ids::host_name(id);
        let slot = Slot { id: &name, index };
        let recipe = Recipe {
            setup: spec.setup.clone(),
            warmup: spec.warmup.clone(),
            env: spec.env.clone(),
            limits: limits(&spec.resources),
            disk_gib: spec.resources.disk_gib.unwrap_or(1),
            net: self.network.mode(&policies),
            ca: Some(self.network.ca_pem.clone()),
            base: spec.base.clone(),
            record_pages: self.store.is_some(),
        };
        let result = async {
            if spec.base.is_some() {
                self.unpack(&build, &spec, &policies, &recipe, &slot, &mut log)
                    .await?;
            }
            // Setup steps get no secrets.
            self.network
                .register(index, &format!("build {id}"), None, policies, Vec::new());
            self.node
                .build_template(
                    &dir,
                    &self.inputs.kernel,
                    &self.inputs.rootfs,
                    &recipe,
                    &slot,
                    &mut log,
                )
                .await
        }
        .await;
        if result.is_err() {
            self.node.remove_failed(&name, index).await;
        }
        self.network.unregister(index);
        self.slots.release(index);
        if self.closing.load(Ordering::SeqCst) {
            // Queued again on the next start.
            return Ok(());
        }
        let now = now_ms();
        match result {
            Ok((files, _)) => {
                let seconds = started.elapsed().as_secs_f64();
                let _ = writeln!(log, "== ready in {seconds:.1} s");
                eprintln!(
                    "template {:?} ({id}) ready in {seconds:.1} s",
                    build.template
                );
                self.publish(&build, spec, files, dir, true)?;
                // Other hosts wait for this upload, so it is done now.
                if let (Some(store), Some(_)) = (&self.store, claim) {
                    let ready = self.current().values().find(|b| b.id == id).cloned();
                    if let Some(ready) = ready
                        && !ready.uploading.swap(true, Ordering::SeqCst)
                    {
                        self.upload(store, &key, &ready).await;
                        ready.uploading.store(false, Ordering::SeqCst);
                    }
                }
            }
            Err(error) => {
                let message = format!("{error:#}");
                let _ = writeln!(log, "== failed: {message}");
                eprintln!("build {id} of {:?} failed: {message}", build.template);
                // Keep the log; drop the large files.
                for path in Build::at(&dir, self.node.backend(), recipe.limits, true).files() {
                    let _ = std::fs::remove_file(path);
                }
                self.db
                    .set_build_state(id, build_state::FAILED, now, Some(&message))?;
            }
        }
        Ok(())
    }

    /// Pulls the build's base image. Only the pull gets the registry
    /// secrets. Unregisters the network before it returns.
    async fn unpack(
        &self,
        build: &db::Build,
        spec: &TemplateSpec,
        policies: &[spawn_egress::Policy],
        recipe: &Recipe,
        slot: &Slot<'_>,
        log: Log<'_>,
    ) -> Result<()> {
        let tenant = split(&build.template).0;
        let attached = self
            .secrets
            .specs(tenant, &spec.registry_secrets)
            .map_err(|e| anyhow::anyhow!("{}", e.message))?
            .into_iter()
            .map(|(name, _)| {
                Ok(Attached {
                    name,
                    placeholder: ids::placeholder()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        self.network.register(
            slot.index,
            &format!("build {} image", build.id),
            tenant,
            policies.to_vec(),
            attached,
        );
        let dir = self.dir.join(&build.id);
        let unpacked = self
            .node
            .unpack_image(
                &dir,
                &self.inputs.kernel,
                &self.inputs.rootfs,
                recipe,
                slot,
                log,
            )
            .await;
        self.network.unregister(slot.index);
        let digest = unpacked?;
        let _ = writeln!(log, "== image {digest}");
        Ok(())
    }

    /// Moves a queued build to `building` and records the inputs it is
    /// built from. False when it should not run any more.
    fn begin(&self, build: &db::Build, store_key: &str) -> Result<bool> {
        if self.closing.load(Ordering::SeqCst) {
            return Ok(false);
        }
        if !self.wanted(build)? {
            self.db
                .set_build_state(&build.id, build_state::REMOVED, now_ms(), None)?;
            return Ok(false);
        }
        Ok(self
            .db
            .start_build(&build.id, &self.fingerprint, store_key, now_ms())?)
    }

    /// True while `build` matches its template's current spec.
    fn wanted(&self, build: &db::Build) -> Result<bool> {
        let Some(template) = self.db.get_template(&build.template)? else {
            return Ok(false);
        };
        let current: TemplateSpec = serde_json::from_str(&template.spec)?;
        let built: TemplateSpec = serde_json::from_str(&build.spec)?;
        Ok(current.for_build() == built.for_build())
    }

    /// Makes a finished build its template's current build, unless the
    /// template changed or a newer build is already current.
    fn publish(
        &self,
        build: &db::Build,
        spec: TemplateSpec,
        files: Build,
        dir: PathBuf,
        local: bool,
    ) -> Result<()> {
        let now = now_ms();
        let mut current = self.current();
        let newer = current
            .get(&build.template)
            .is_some_and(|c| c.seq > build.seq);
        if newer || !self.wanted(build)? {
            drop(current);
            self.db
                .set_build_state(&build.id, build_state::REMOVED, now, None)?;
            remove_dir(&dir);
            return Ok(());
        }
        self.db
            .set_build_state(&build.id, build_state::READY, now, None)?;
        let ready = Arc::new(ReadyBuild::new(build, files, spec, dir, local));
        if let Some(old) = current.insert(build.template.clone(), ready) {
            self.db
                .set_build_state(&old.id, build_state::REMOVED, now, None)?;
            old.retired.store(true, Ordering::SeqCst);
        }
        eprintln!("template {:?} is ready ({})", build.template, build.id);
        Ok(())
    }

    /// The storage key of the template a new sandbox in `ns` asks for.
    pub fn key(&self, ns: Option<&str>, template: &str) -> Result<String, ApiError> {
        self.resolve(ns, template)
            .map_err(|error| match error.code {
                Code::NotFound => {
                    ApiError::invalid(format!("template {template:?} does not exist"))
                }
                _ => error,
            })
    }

    /// The storage key and build a new sandbox in `ns` starts from.
    pub fn ready(
        &self,
        ns: Option<&str>,
        template: &str,
    ) -> Result<(String, Arc<ReadyBuild>), ApiError> {
        let key = self.key(ns, template)?;
        if let Some(build) = self.current().get(&key) {
            return Ok((key, Arc::clone(build)));
        }
        Err(ApiError::new(
            Code::Conflict,
            format!("template {template:?} has no ready build yet"),
        ))
    }

    /// Saves a template in `ns` and queues a build of it.
    pub fn put(
        self: &Arc<Self>,
        ns: Option<&str>,
        mut spec: TemplateSpec,
    ) -> Result<(TemplateView, BuildView), ApiError> {
        spec.check(self.defaults)?;
        self.secrets.specs(ns, &spec.registry_secrets)?;
        let key = scoped(ns, &spec.name);
        let json = serde_json::to_string(&spec).map_err(ApiError::internal)?;
        // Saving the same template again builds it again; a change of
        // `min_warm` alone does not.
        let only_min_warm = self
            .db
            .get_template(&key)?
            .and_then(|t| serde_json::from_str::<TemplateSpec>(&t.spec).ok())
            .is_some_and(|old| old.min_warm != spec.min_warm);
        self.db.put_template(&key, &json, now_ms())?;
        let same = if only_min_warm {
            self.same_build(&key, &spec)?
        } else {
            None
        };
        let build = match same {
            Some(build) => build,
            None => {
                let build = self.new_build(&key, &json)?;
                self.queue(build.id.clone());
                build
            }
        };
        let template = self
            .db
            .get_template(&key)?
            .ok_or_else(|| template_not_found(&spec.name))?;
        Ok((self.view(template)?, build_view(&build, None)))
    }

    pub fn get(&self, ns: Option<&str>, name: &str) -> Result<TemplateView, ApiError> {
        let key = self.resolve(ns, name)?;
        let template = self
            .db
            .get_template(&key)?
            .ok_or_else(|| template_not_found(name))?;
        self.view(template)
    }

    /// With a namespace: its own templates and the org-wide ones. Without:
    /// every template of every tenant.
    pub fn list(&self, ns: Option<&str>) -> Result<Vec<TemplateView>, ApiError> {
        self.db
            .list_templates()?
            .into_iter()
            .filter(|t| ns.is_none() || split(&t.name).0.is_none_or(|own| Some(own) == ns))
            .map(|t| self.view(t))
            .collect()
    }

    /// The namespace's own template, else the org-wide one.
    fn resolve(&self, ns: Option<&str>, name: &str) -> Result<String, ApiError> {
        if !is_template_name(name) {
            return Err(template_not_found(name));
        }
        if let Some(tenant) = ns {
            let own = scoped(Some(tenant), name);
            if self.db.get_template(&own)?.is_some() {
                return Ok(own);
            }
        }
        match self.db.get_template(name)? {
            Some(_) => Ok(name.to_owned()),
            None => Err(template_not_found(name)),
        }
    }

    fn view(&self, template: db::Template) -> Result<TemplateView, ApiError> {
        let spec = serde_json::from_str(&template.spec).map_err(ApiError::internal)?;
        let current_build = self.current().get(&template.name).map(|b| b.id.clone());
        let latest_build = self
            .db
            .latest_build(&template.name)?
            .map(|b| build_view(&b, None));
        Ok(TemplateView {
            spec,
            tenant: split(&template.name).0.map(str::to_owned),
            created_at: rfc3339_ms(template.created_at),
            updated_at: rfc3339_ms(template.updated_at),
            current_build,
            latest_build,
        })
    }

    /// Running sandboxes of the template keep running. Org-wide templates
    /// are read-only to tenants.
    pub fn delete(&self, ns: Option<&str>, name: &str) -> Result<(), ApiError> {
        if name == BASE_TEMPLATE {
            return Err(ApiError::invalid(format!(
                "{BASE_TEMPLATE:?} is built in and cannot be deleted"
            )));
        }
        let key = self.resolve(ns, name)?;
        if split(&key).0 != ns {
            return Err(ApiError::new(
                Code::Forbidden,
                format!("template {name:?} is org-wide; it is read-only to tenants"),
            ));
        }
        let mut current = self.current();
        if !self.db.delete_template(&key, now_ms())? {
            return Err(template_not_found(name));
        }
        if let Some(old) = current.remove(&key) {
            old.retired.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn build(&self, ns: Option<&str>, template: &str, id: &str) -> Result<BuildView, ApiError> {
        let key = self.resolve(ns, template)?;
        let build = ids::is_valid_id("bld", id)
            .then(|| self.db.get_build(id))
            .transpose()?
            .flatten()
            .filter(|b| b.template == key)
            .ok_or_else(|| ApiError::new(Code::NotFound, "build not found"))?;
        let log = tail(&self.dir.join(id).join(LOG_FILE)).ok();
        Ok(build_view(&build, Some(log.unwrap_or_default())))
    }

    /// Hash of the kernel, base rootfs, Firecracker or runsc, and egress
    /// CA. Hosts with equal fingerprints can run each other's snapshots.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// This host's CPU model. Snapshots need an equal one.
    pub fn cpu(&self) -> &str {
        &self.cpu
    }

    pub fn backend(&self) -> Backend {
        self.node.backend()
    }

    /// The base rootfs every sandbox disk starts from.
    pub fn base_rootfs(&self) -> &std::path::Path {
        &self.inputs.rootfs
    }

    /// Each template with a ready build: its key, build ID and limits.
    pub fn ready_builds(&self) -> Vec<(String, String, Limits)> {
        self.current()
            .iter()
            .map(|(key, ready)| (key.clone(), ready.id.clone(), ready.build.limits))
            .collect()
    }

    /// Fleet hosts: makes template `key` the primary's `spec` (its exact
    /// JSON), and builds it if that changed it. A snapshot made on another
    /// host is only fetched, so without a build store it gets no build.
    pub fn sync(self: &Arc<Self>, key: &str, spec: &str) -> Result<(), ApiError> {
        if key == BASE_TEMPLATE {
            return Ok(());
        }
        if self.db.get_template(key)?.is_some_and(|t| t.spec == spec) {
            return Ok(());
        }
        let parsed = serde_json::from_str::<TemplateSpec>(spec)
            .map_err(|e| ApiError::invalid(format!("template {key:?}: {e}")))?;
        self.db.put_template(key, spec, now_ms())?;
        if parsed.snapshot.is_some() && self.store.is_none() {
            return Ok(());
        }
        if self.same_build(key, &parsed)?.is_none() {
            let build = self.new_build(key, spec)?;
            self.queue(build.id);
        }
        Ok(())
    }

    /// The latest build of `key` if it is queued, building or ready from
    /// the same parts as `spec`, so a change of `min_warm` alone needs no
    /// new build.
    fn same_build(&self, key: &str, spec: &TemplateSpec) -> Result<Option<db::Build>, ApiError> {
        let Some(build) = self.db.latest_build(key)? else {
            return Ok(None);
        };
        let live = [
            build_state::QUEUED,
            build_state::BUILDING,
            build_state::READY,
        ];
        let same = live.contains(&build.state.as_str())
            && serde_json::from_str::<TemplateSpec>(&build.spec)
                .is_ok_and(|built| built.for_build() == spec.for_build());
        Ok(same.then_some(build))
    }

    /// Ready builds of templates that ask for warm VMs: the template key,
    /// its build and `min_warm`.
    pub fn min_warm(&self) -> Vec<(String, Arc<ReadyBuild>, usize)> {
        let Ok(templates) = self.db.list_templates() else {
            return Vec::new();
        };
        let current = self.current();
        templates
            .into_iter()
            .filter_map(|t| {
                let spec: TemplateSpec = serde_json::from_str(&t.spec).ok()?;
                let min = usize::try_from(spec.min_warm).ok().filter(|m| *m > 0)?;
                let build = Arc::clone(current.get(&t.name)?);
                Some((t.name, build, min))
            })
            .collect()
    }

    /// Fleet workers: removes every template but `base` not in `keep`.
    pub fn remove_others(&self, keep: &HashSet<String>) -> Result<(), ApiError> {
        let fresh: HashSet<String> = {
            let mut fresh = self.fresh.lock().unwrap_or_else(|e| e.into_inner());
            fresh.retain(|_, saved| saved.elapsed() < FRESH_SNAPSHOT);
            fresh.keys().cloned().collect()
        };
        for template in self.db.list_templates()? {
            let kept = keep.contains(&template.name) || fresh.contains(&template.name);
            if template.name == BASE_TEMPLATE || kept {
                continue;
            }
            let mut current = self.current();
            self.db.delete_template(&template.name, now_ms())?;
            if let Some(old) = current.remove(&template.name) {
                old.retired.store(true, Ordering::SeqCst);
            }
        }
        Ok(())
    }

    /// The build store key of a build of `spec`. A snapshot's key does not
    /// depend on egress policies: its files are not built.
    fn store_key(&self, spec: &TemplateSpec, policies: &[spawn_egress::Policy]) -> Result<String> {
        let policies = if spec.snapshot.is_some() {
            &[]
        } else {
            policies
        };
        Ok(store::key(
            &self.fingerprint,
            &self.cpu,
            &serde_json::to_string(&spec.for_build())?,
            &serde_json::to_string(policies)?,
        ))
    }

    /// Saves snapshot template `key` and starts its build. Write the files
    /// into the returned directory, then call `finish_snapshot`.
    pub fn begin_snapshot(
        &self,
        key: &str,
        spec: &TemplateSpec,
    ) -> Result<(db::Build, PathBuf), ApiError> {
        if self.db.get_template(key)?.is_some() {
            return Err(ApiError::new(
                Code::Conflict,
                format!("template {:?} already exists", spec.name),
            ));
        }
        let json = serde_json::to_string(spec).map_err(ApiError::internal)?;
        self.db.put_template(key, &json, now_ms())?;
        self.fresh
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_owned(), Instant::now());
        let build = self.new_build(key, &json)?;
        let dir = self.dir.join(&build.id);
        Ok((build, dir))
    }

    /// Makes a snapshot build current, and with a build store, uploads it
    /// so that other hosts can fetch it. On error the template is removed.
    pub async fn finish_snapshot(
        &self,
        build: &db::Build,
        spec: &TemplateSpec,
        saved: Result<()>,
    ) -> Result<(), ApiError> {
        let dir = self.dir.join(&build.id);
        let published = async {
            saved?;
            let key = self.store_key(spec, &[])?;
            if !self
                .db
                .start_build(&build.id, &self.fingerprint, &key, now_ms())?
            {
                bail!("the template changed");
            }
            let mut build = build.clone();
            build.store_key = Some(key);
            let limits = limits(&spec.resources);
            let files = Build::at(&dir, self.node.backend(), limits, spec.has_layer())
                .with_own_rootfs(spec.own_rootfs());
            self.publish(&build, spec.clone(), files, dir.clone(), true)?;
            self.current()
                .get(&build.template)
                .filter(|ready| ready.id == build.id)
                .cloned()
                .context("the template changed")
        }
        .await;
        let ready = match published {
            Ok(ready) => ready,
            Err(error) => {
                remove_dir(&dir);
                let _ = self
                    .db
                    .fail_build(&build.id, now_ms(), &format!("{error:#}"));
                self.forget(&build.template);
                return Err(ApiError::internal(format!("save the snapshot: {error:#}")));
            }
        };
        if let (Some(store), Some(key)) = (&self.store, ready.store_key.clone())
            && !ready.uploading.swap(true, Ordering::SeqCst)
        {
            self.upload(store, &key, &ready).await;
            ready.uploading.store(false, Ordering::SeqCst);
        }
        Ok(())
    }

    /// Removes template `key` after its snapshot failed.
    fn forget(&self, key: &str) {
        let mut current = self.current();
        if let Err(error) = self.db.delete_template(key, now_ms()) {
            eprintln!("remove template {key:?}: {error}");
        }
        if let Some(old) = current.remove(key) {
            old.retired.store(true, Ordering::SeqCst);
        }
        self.fresh
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    /// Running builds are queued again on the next start.
    pub fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.builds.close();
    }
}

fn template_not_found(name: &str) -> ApiError {
    ApiError::new(Code::NotFound, format!("template {name:?} not found"))
}

fn build_view(build: &db::Build, log: Option<String>) -> BuildView {
    BuildView {
        id: build.id.clone(),
        template: split(&build.template).1.to_owned(),
        state: build.state.clone(),
        created_at: rfc3339_ms(build.created_at),
        started_at: build.started_at.map(rfc3339_ms),
        finished_at: build.finished_at.map(rfc3339_ms),
        error: build.error.clone(),
        log,
    }
}

fn limits(resources: &Resources) -> Limits {
    Limits {
        vcpus: resources
            .vcpus
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(1),
        memory_mib: resources.memory_mib.unwrap_or(256),
    }
}

/// Frees a failed build's disk space but keeps its log.
fn remove_all_but_log(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name() != LOG_FILE {
            let path = entry.path();
            let removed = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            if let Err(error) = removed {
                eprintln!("warning: remove {}: {error}", path.display());
            }
        }
    }
}

/// Disk the files of each build directory under `dir` use. Links to the
/// shared inputs are not counted.
fn disk_usage(dir: &Path) -> u64 {
    let Ok(builds) = std::fs::read_dir(dir) else {
        return 0;
    };
    builds
        .flatten()
        .filter_map(|build| std::fs::read_dir(build.path()).ok())
        .flatten()
        .flatten()
        .filter(|f| !matches!(f.file_name().to_str(), Some("rootfs.ext4" | "vmlinux")))
        .filter_map(|f| f.metadata().ok())
        .map(|m| m.blocks() * 512)
        .sum()
}

fn remove_dir(dir: &Path) {
    if let Err(error) = std::fs::remove_dir_all(dir)
        && error.kind() != io::ErrorKind::NotFound
    {
        eprintln!("warning: remove {}: {error}", dir.display());
    }
}

/// Changes when spawn-node builds snapshots differently, as when VMs got
/// their volume disks, so older builds are rebuilt.
const BUILD_FORMAT: &[u8] = b"build-format-3\0";

/// SHA-256 over the files every build is made from, and `extra`.
fn fingerprint(files: &[PathBuf], extra: &[u8]) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    for path in files {
        let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        // Separates the files, so moving bytes between them changes the hash.
        hasher.update([0xff; 8]);
    }
    hasher.update(extra);
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// The last `LOG_TAIL_BYTES` of a log.
fn tail(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(LOG_TAIL_BYTES)))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// A build log that stops growing at `MAX_LOG_BYTES`.
struct CappedLog {
    file: File,
    written: u64,
}

impl CappedLog {
    fn create(path: &Path) -> io::Result<Self> {
        Ok(Self {
            file: File::create(path)?,
            written: 0,
        })
    }
}

impl Write for CappedLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.written < MAX_LOG_BYTES {
            let room = usize::try_from(MAX_LOG_BYTES - self.written).unwrap_or(usize::MAX);
            let part = &bytes[..bytes.len().min(room)];
            self.file.write_all(part)?;
            self.written += part.len() as u64;
            if self.written == MAX_LOG_BYTES {
                self.file.write_all(b"\n[log truncated]\n")?;
            }
        }
        // The rest is dropped, not an error: the build goes on.
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
