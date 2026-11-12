//! Moving a sandbox to another host: pause it, copy its snapshot, resume
//! it there. The primary runs every move; the hosts only export, import,
//! release and abort when it asks.
//!
//! The copy is one zstd stream: a u32 header length and the header JSON,
//! then for each file a u16 name length, the name and the file as a store
//! blob, then a zero name length and the SHA-256 of everything before.
//! A sandbox's volumes go with it, so it must be their only user.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedRwLockWriteGuard, RwLock, mpsc};

use super::forward::{self, Failure};
use super::{Capacity, SecretPush, SyncReply};
use crate::db::{self, NodeRow, node_state, state};
use crate::events::Origin;
use crate::model::{ApiError, Code};
use crate::runtime::now_ms;
use crate::server::{App, AppState, parse};
use crate::store::{Hashed, read_blob, write_blob};

/// Files of a paused sandbox that are copied, for both backends, then its
/// volumes by slot, then its base disk if it was unpacked from an image.
/// The shared base disk is not copied: hosts with equal fingerprints have
/// the same one.
const FILES: [&str; 12] = [
    "vm.state",
    "vm.mem",
    "upper.ext4",
    "checkpoint.img",
    "pages.img",
    "pages_meta.img",
    "layer.ext4",
    "vol0.ext4",
    "vol1.ext4",
    "vol2.ext4",
    "vol3.ext4",
    ROOTFS,
];
const ROOTFS: &str = "rootfs.ext4";
/// Where volume `slot` is in a package: after the 7 snapshot files.
fn volume_file(slot: usize) -> &'static str {
    FILES[7 + slot]
}
const MAX_HEADER: u32 = 4 * 1024 * 1024;
/// Largest file in a package.
const MAX_FILE: u64 = 1 << 40;
const ZSTD_LEVEL: i32 = 1;
const CHUNK: usize = 256 * 1024;
/// Tells the primary whether an exported sandbox ran before.
const WAS_RUNNING: &str = "x-spawnbox-was-running";
/// API calls for a moving sandbox wait this long for the move to end.
const WAIT_FOR_MOVE: Duration = Duration::from_secs(120);
/// A worker's report may be older than a move for this long.
const MOVED_GRACE_MS: i64 = 60_000;
/// The name of the primary as a move's target.
pub const PRIMARY: &str = "primary";

#[derive(Serialize, Deserialize)]
struct Header {
    sandbox: db::Sandbox,
    /// Holds env values in plain.
    saved: String,
    was_running: bool,
    fingerprint: String,
    cpu: String,
}

impl std::fmt::Debug for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header")
            .field("sandbox", &self.sandbox)
            .field("was_running", &self.was_running)
            .field("fingerprint", &self.fingerprint)
            .field("cpu", &self.cpu)
            .finish_non_exhaustive()
    }
}

/// The files of `dir` a package may hold.
fn files_in(dir: &Path) -> Vec<(&'static str, PathBuf)> {
    FILES.iter().map(|name| (*name, dir.join(name))).collect()
}

/// Writes a package of `files` that exist.
pub(super) fn write_package<H: Serialize>(
    out: impl Write,
    header: &H,
    files: &[(&str, PathBuf)],
) -> Result<()> {
    let mut encoder = zstd::Encoder::new(out, ZSTD_LEVEL)?;
    encoder.include_checksum(true)?;
    let mut out = Hashed {
        inner: encoder,
        hasher: Sha256::new(),
    };
    let json = serde_json::to_vec(header)?;
    out.write_all(&u32::try_from(json.len())?.to_le_bytes())?;
    out.write_all(&json)?;
    for (name, path) in files {
        let file = match File::open(path) {
            Ok(file) => file,
            // The reader checks that its backend's files are there.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("open {name}")),
        };
        out.write_all(&u16::try_from(name.len())?.to_le_bytes())?;
        out.write_all(name.as_bytes())?;
        write_blob(&file, &mut out)?;
    }
    out.write_all(&0u16.to_le_bytes())?;
    let Hashed { mut inner, hasher } = out;
    inner.write_all(&hasher.finalize())?;
    inner.finish()?.flush()?;
    Ok(())
}

/// Reads a package into the empty directory `dir`. `check` sees the
/// header before any file is written. Only `known` files may be in it, and
/// each of `required` must.
pub(super) fn read_package<H: serde::de::DeserializeOwned>(
    input: impl Read,
    dir: &Path,
    known: &[&'static str],
    required: &[&str],
    check: impl FnOnce(&H) -> Result<()>,
) -> Result<H> {
    let mut input = Hashed {
        inner: zstd::Decoder::new(input)?,
        hasher: Sha256::new(),
    };
    let mut len = [0; 4];
    input.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > MAX_HEADER {
        bail!("package header is too large");
    }
    let mut json = vec![0; usize::try_from(len)?];
    input.read_exact(&mut json)?;
    let header: H = serde_json::from_slice(&json).context("package header")?;
    check(&header)?;
    let mut seen = HashSet::new();
    loop {
        let mut len = [0; 2];
        input.read_exact(&mut len)?;
        let len = usize::from(u16::from_le_bytes(len));
        if len == 0 {
            break;
        }
        let mut name = vec![0; len];
        input.read_exact(&mut name)?;
        let name = known
            .iter()
            .copied()
            .find(|n| n.as_bytes() == name.as_slice())
            .context("package has an unknown file")?;
        if !seen.insert(name) {
            bail!("package has {name} twice");
        }
        let out = File::create_new(dir.join(name))?;
        read_blob(&mut input, &out, MAX_FILE).with_context(|| format!("read {name}"))?;
        out.sync_all()?;
    }
    if required.iter().any(|n| !seen.contains(n)) {
        bail!("package misses a file");
    }
    let Hashed { mut inner, hasher } = input;
    let mut sum = [0; 32];
    inner.read_exact(&mut sum)?;
    if sum[..] != hasher.finalize()[..] {
        bail!("package does not match its SHA-256");
    }
    if inner.read(&mut [0; 1])? != 0 {
        bail!("package has data after its end");
    }
    Ok(header)
}

/// Sends what a blocking task writes as a response body.
pub(super) struct ChannelWriter {
    tx: mpsc::Sender<io::Result<Bytes>>,
    buf: Vec<u8>,
}

impl Write for ChannelWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() >= CHUNK {
            self.flush()?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::take(&mut self.buf));
        self.tx
            .blocking_send(Ok(chunk))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the reader went away"))
    }
}

/// Reads a request body from a blocking task.
pub(super) struct ChannelReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    chunk: Bytes,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.chunk.is_empty() {
            match self.rx.blocking_recv() {
                Some(chunk) => self.chunk = chunk?,
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.chunk.len());
        out[..n].copy_from_slice(&self.chunk.split_to(n));
        Ok(n)
    }
}

pub(super) fn reader(body: Body) -> ChannelReader {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(io::Error::other);
            if tx.send(chunk).await.is_err() {
                break;
            }
        }
    });
    ChannelReader {
        rx,
        chunk: Bytes::new(),
    }
}

/// Pauses sandbox `id` of this host, marks it moving, and streams its
/// package.
pub async fn export(app: &App, id: &str) -> Result<Response, ApiError> {
    let export = app.sandboxes.export(id).await?;
    let header = Header {
        sandbox: export.sandbox,
        saved: export.saved,
        was_running: export.was_running,
        fingerprint: app.templates.fingerprint().to_owned(),
        cpu: app.templates.cpu().to_owned(),
    };
    let mut files = files_in(&export.dir);
    for (slot, path) in export.volumes.into_iter().enumerate() {
        let name = volume_file(slot);
        if let Some(entry) = files.iter_mut().find(|(n, _)| *n == name) {
            entry.1 = path;
        }
    }
    if !spawn_node::distinct_files(&export.dir.join(ROOTFS), app.templates.base_rootfs()) {
        files.retain(|(name, _)| *name != ROOTFS);
    }
    let what = format!("export {}", header.sandbox.id);
    let mut resp = Response::new(stream_package(what, header, files));
    resp.headers_mut().insert(
        WAS_RUNNING,
        HeaderValue::from_static(if export.was_running { "1" } else { "0" }),
    );
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    Ok(resp)
}

/// Streams a package written by a blocking task.
pub(super) fn stream_package<H: Serialize + Send + 'static>(
    what: String,
    header: H,
    files: Vec<(&'static str, PathBuf)>,
) -> Body {
    let (tx, rx) = mpsc::channel(8);
    tokio::task::spawn_blocking(move || {
        let mut out = ChannelWriter {
            tx: tx.clone(),
            buf: Vec::new(),
        };
        let written = write_package(&mut out, &header, &files).and_then(|()| Ok(out.flush()?));
        if let Err(error) = written {
            eprintln!("{what}: {error:#}");
            let _ = tx.blocking_send(Err(io::Error::other(format!("{error:#}"))));
        }
    });
    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// Makes the sandbox in a package one of this host's; resumes it if it
/// ran before.
pub async fn import(app: &AppState, body: Body) -> Result<(), ApiError> {
    let staged = app.sandboxes.staging_dir().map_err(ApiError::internal)?;
    let result = import_into(app, body, &staged).await;
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staged);
    }
    result
}

async fn import_into(app: &AppState, body: Body, staged: &Path) -> Result<(), ApiError> {
    std::fs::create_dir_all(staged).map_err(|e| ApiError::internal(format!("staging: {e}")))?;
    let input = reader(body);
    let (fingerprint, cpu) = (
        app.templates.fingerprint().to_owned(),
        app.templates.cpu().to_owned(),
    );
    let base = app.templates.base_rootfs().to_owned();
    let required = app.templates.backend().snapshot_files();
    let dir = staged.to_owned();
    let header = tokio::task::spawn_blocking(move || {
        let header = read_package(input, &dir, &FILES, required, |h: &Header| {
            if h.fingerprint != fingerprint {
                bail!("this host has another backend, kernel, base disk, Firecracker, runsc or egress CA");
            }
            if h.cpu != cpu {
                bail!("this host has another CPU model ({cpu}, not {})", h.cpu);
            }
            Ok(())
        })?;
        for slot in 0..header.sandbox.volumes.len() {
            if !dir.join(volume_file(slot)).exists() {
                bail!("package misses a volume");
            }
        }
        if !dir.join(ROOTFS).exists() {
            link_or_copy(&base, &dir.join(ROOTFS))?;
        }
        Ok::<_, anyhow::Error>(header)
    })
    .await
    .map_err(|e| ApiError::internal(format!("task failed: {e}")))?
    .map_err(|e| ApiError::invalid(format!("{e:#}")))?;
    let volumes: Vec<PathBuf> = header
        .sandbox
        .volumes
        .iter()
        .map(|v| app.volumes.file(&v.volume))
        .collect();
    for (slot, file) in volumes.iter().enumerate() {
        std::fs::rename(staged.join(volume_file(slot)), file)
            .map_err(|e| ApiError::internal(format!("place volume: {e}")))?;
    }
    let adopted = app
        .sandboxes
        .adopt(header.sandbox, &header.saved, staged, header.was_running)
        .await;
    if adopted.is_err() {
        // The source keeps its copy.
        for file in &volumes {
            let _ = std::fs::remove_file(file);
        }
    }
    adopted
}

fn link_or_copy(src: &Path, dest: &Path) -> Result<()> {
    if std::fs::hard_link(src, dest).is_err() {
        std::fs::copy(src, dest).with_context(|| format!("copy {}", src.display()))?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct One {
    id: String,
    /// For release: where it runs now.
    #[serde(default)]
    node: Option<String>,
}

/// Fleet routes on a worker. Only the primary reaches them.
pub async fn export_here(State(app): State<AppState>, body: Bytes) -> Response {
    let result = async {
        let one: One = parse(&body)?;
        export(&app, &one.id).await
    }
    .await;
    result.unwrap_or_else(IntoResponse::into_response)
}

pub async fn import_here(
    State(app): State<AppState>,
    req: Request,
) -> Result<Json<Value>, ApiError> {
    import(&app, req.into_body()).await?;
    Ok(Json(json!({})))
}

pub async fn release_here(
    State(app): State<AppState>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let one: One = parse(&body)?;
    let node = one.node.as_deref().unwrap_or(PRIMARY);
    app.sandboxes.forget(&one.id, node).await?;
    Ok(Json(json!({})))
}

pub async fn abort_here(State(app): State<AppState>, body: Bytes) -> Result<Json<Value>, ApiError> {
    let one: One = parse(&body)?;
    app.sandboxes.abort_move(&one.id).await?;
    Ok(Json(json!({})))
}

/// Sandboxes being moved, and those moved lately.
#[derive(Default)]
pub struct Moves {
    /// API calls take a read lock; a move holds the write lock.
    moving: Mutex<HashMap<String, Arc<RwLock<()>>>>,
    /// When each finished, so a heartbeat from before it ends nothing.
    moved: Mutex<HashMap<String, i64>>,
}

/// Held while a sandbox moves.
pub struct Moving<'a> {
    moves: &'a Moves,
    id: String,
    _write: OwnedRwLockWriteGuard<()>,
}

impl Drop for Moving<'_> {
    fn drop(&mut self) {
        lock(&self.moves.moving).remove(&self.id);
        lock(&self.moves.moved).insert(self.id.clone(), now_ms());
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Moves {
    fn start(&self, id: &str) -> Result<Moving<'_>, ApiError> {
        let mut moving = lock(&self.moving);
        if moving.contains_key(id) {
            return Err(ApiError::new(Code::Conflict, "sandbox is already moving"));
        }
        let rw = Arc::new(RwLock::new(()));
        let write = Arc::clone(&rw)
            .try_write_owned()
            .map_err(|_| ApiError::internal("new lock is taken"))?;
        moving.insert(id.to_owned(), rw);
        Ok(Moving {
            moves: self,
            id: id.to_owned(),
            _write: write,
        })
    }

    pub fn is_moving(&self, id: &str) -> bool {
        lock(&self.moving).contains_key(id)
    }

    /// Waits until sandbox `id` is not moving, or a while.
    pub async fn wait(&self, id: &str) {
        let rw = lock(&self.moving).get(id).cloned();
        if let Some(rw) = rw {
            let _ = tokio::time::timeout(WAIT_FOR_MOVE, rw.read()).await;
        }
    }

    /// Sandboxes that moved within the grace time; forgets older ones.
    pub fn recent(&self, now: i64) -> Vec<String> {
        let mut moved = lock(&self.moved);
        moved.retain(|_, at| now - *at < MOVED_GRACE_MS);
        let mut ids: Vec<String> = moved.keys().cloned().collect();
        ids.extend(lock(&self.moving).keys().cloned());
        ids
    }
}

/// A host a sandbox can move to or from. `None` is the primary.
struct Host {
    node: Option<NodeRow>,
    capacity: Capacity,
}

impl Host {
    fn name(&self) -> &str {
        self.node.as_ref().map_or(PRIMARY, |n| n.id.as_str())
    }
}

/// Every host that may take part in a move, with what it last reported.
fn hosts(app: &App, p: &super::primary::Primary) -> Vec<Host> {
    let mut out = vec![Host {
        node: None,
        capacity: super::local_capacity(app),
    }];
    let nodes: HashMap<String, NodeRow> = app
        .db
        .list_nodes()
        .unwrap_or_default()
        .into_iter()
        .map(|n| (n.id.clone(), n))
        .collect();
    for (id, capacity) in p.capacities() {
        if let Some(node) = nodes.get(&id) {
            out.push(Host {
                node: Some(node.clone()),
                capacity,
            });
        }
    }
    out
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MigrateInput {
    /// A node ID, or `primary`. The best host if not given.
    pub node: Option<String>,
}

/// Moves sandbox `id` to another host. Returns what the event records.
pub async fn migrate(
    app: &AppState,
    id: &str,
    input: MigrateInput,
    origin: &Origin,
) -> Result<Value, ApiError> {
    let p = super::primary::primary(app)?;
    let row = app.db.get_sandbox(id)?.ok_or_else(ApiError::not_found)?;
    if row.persistent {
        return Err(ApiError::new(
            Code::Conflict,
            "persistent sandboxes cannot move to another host yet",
        ));
    }
    if !matches!(row.state.as_str(), state::RUNNING | state::PAUSED) {
        return Err(ApiError::new(
            Code::Conflict,
            format!(
                "sandbox is {}; only running and paused ones move",
                row.state
            ),
        ));
    }
    let hosts = hosts(app, p);
    let source = hosts
        .iter()
        .find(|h| h.node.as_ref().map(|n| &n.id) == row.node.as_ref())
        .ok_or_else(|| {
            ApiError::new(
                Code::NodeUnreachable,
                "the sandbox's node has not reported; try again later",
            )
        })?;
    let running = row.state == state::RUNNING;
    let mut targets: Vec<&Host> = hosts
        .iter()
        .filter(|h| h.name() != source.name())
        .filter(|h| input.node.as_deref().is_none_or(|n| n == h.name()))
        .filter(|h| {
            h.node
                .as_ref()
                .is_none_or(|n| n.state == node_state::READY && !n.draining)
        })
        .collect();
    if targets.is_empty() {
        return Err(match input.node {
            Some(node) => ApiError::invalid(format!(
                "node {node} cannot take sandboxes: it is not ready, is draining, or runs it"
            )),
            None => ApiError::new(Code::NoCapacity, "no other host can take sandboxes"),
        });
    }
    targets.retain(|h| {
        h.capacity.fingerprint == source.capacity.fingerprint
            && h.capacity.cpu == source.capacity.cpu
    });
    if targets.is_empty() {
        return Err(ApiError::new(
            Code::NoCapacity,
            "no host has the same backend, kernel, base disk, Firecracker or runsc, egress CA and CPU model",
        ));
    }
    targets.retain(|h| {
        // A paused sandbox reserves memory only when it resumes.
        let room = if running {
            h.capacity.memory_room_mib()
        } else {
            h.capacity.memory_available_mib
        };
        room >= u64::from(row.memory_mib) && (!running || h.capacity.free_slots > 0)
    });
    targets.sort_by_key(|h| std::cmp::Reverse(h.capacity.memory_available_mib));
    let target = targets
        .first()
        .ok_or_else(|| ApiError::new(Code::NoCapacity, "no host has room for this sandbox"))?;
    let (from, to) = (source.name().to_owned(), target.name().to_owned());
    let target_node = target.node.clone();
    let source_node = source.node.clone();
    let _busy = target_node.as_ref().map(|n| p.busy.hold(&n.id));

    let _volumes = if row.volumes.is_empty() {
        None
    } else {
        Some(p.volume_lock.write().await)
    };
    for volume in &row.volumes {
        let others: Vec<String> = app
            .db
            .volume_users(&volume.volume)?
            .into_iter()
            .map(|u| u.sandbox)
            .filter(|s| s != id)
            .collect();
        if !others.is_empty() {
            return Err(ApiError::new(
                Code::Conflict,
                format!(
                    "volume {:?} is also mounted in {}; a sandbox moves only with volumes no other sandbox uses",
                    volume.name,
                    others.join(", ")
                ),
            ));
        }
    }
    let _moving = p.moves.start(id)?;
    let begin = Instant::now();
    if let Some(node) = &target_node {
        prepare(app, p, node, &row).await?;
    }
    let exported = match &source_node {
        None => export(app, id).await?,
        Some(node) => {
            let resp = p
                .send(
                    node,
                    "/fleet/v1/migrate/export",
                    json_body(&json!({ "id": id })),
                )
                .await?;
            ok_or_error(node, resp).await?
        }
    };
    let was_running = exported
        .headers()
        .get(WAS_RUNNING)
        .is_some_and(|v| v.as_bytes() == b"1");
    let imported = match &target_node {
        None => import(app, exported.into_body()).await,
        Some(node) => {
            async {
                let resp = p
                    .send(node, "/fleet/v1/migrate/import", exported.into_body())
                    .await?;
                ok_or_error(node, resp).await.map(drop)
            }
            .await
        }
    };
    if let Err(error) = imported {
        let aborted = match &source_node {
            None => app.sandboxes.abort_move(id).await,
            Some(node) => p
                .call::<_, Value>(node, "/fleet/v1/migrate/abort", &json!({ "id": id }))
                .await
                .map(drop),
        };
        if let Err(abort) = aborted {
            eprintln!("abort move of {id}: {}", abort.message);
        }
        return Err(ApiError::new(
            error.code,
            format!("could not move {id} from {from} to {to}: {}", error.message),
        ));
    }
    let new_state = if was_running {
        state::RUNNING
    } else {
        state::PAUSED
    };
    let now = now_ms();
    match (&source_node, &target_node) {
        (Some(a), Some(b)) => {
            app.db.reassign(id, &a.id, &b.id)?;
            app.db.set_mirror_state(&b.id, id, new_state, now)?;
        }
        (None, Some(b)) => {
            app.sandboxes.forget(id, &b.id).await?;
            app.db.set_mirror_state(&b.id, id, new_state, now)?;
        }
        // The import made the row this host's.
        (_, None) => {}
    }
    for volume in &row.volumes {
        if let Some(home) = app.db.get_volume_by_id(&volume.volume)?
            && let Some(backend) = &home.backend
        {
            app.db.set_volume_home(
                &volume.volume,
                target_node.as_ref().map(|n| n.id.as_str()),
                backend,
            )?;
        }
    }
    if let Some(node) = &source_node {
        let released: Result<Value, _> = p
            .call(
                node,
                "/fleet/v1/migrate/release",
                &json!({ "id": id, "node": to }),
            )
            .await;
        if let Err(error) = released {
            // Its next heartbeat is told to release it.
            eprintln!("release {id} on {}: {}", node.id, error.message);
        }
    }
    let attrs = json!({
        "from": from,
        "to": to,
        "was_running": was_running,
        "duration_ms": u64::try_from(begin.elapsed().as_millis()).unwrap_or(u64::MAX),
    });
    app.sandboxes.hub.record(
        "sandbox.migrated",
        origin,
        Some(&row.tenant),
        Some(id),
        attrs.clone(),
    );
    eprintln!("{id} moved from {from} to {to}");
    Ok(attrs)
}

/// Makes sure the target has the primary's config and the sandbox's
/// secrets and volumes.
async fn prepare(
    app: &App,
    p: &super::primary::Primary,
    node: &NodeRow,
    row: &db::Sandbox,
) -> Result<(), ApiError> {
    if p.is_stale(&node.id) {
        let _: SyncReply = p.call(node, "/fleet/v1/sync", &json!({})).await?;
    }
    if !row.secrets.is_empty() {
        let keys: Vec<String> = app
            .secrets
            .specs(Some(&row.tenant), &row.secrets)?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        let push = SecretPush {
            secrets: app.secrets.export(&keys)?,
        };
        let _: Value = p.call(node, "/fleet/v1/secrets", &push).await?;
    }
    super::volumes::push(app, p, node, &row.volumes).await
}

pub(super) fn json_body(value: &Value) -> Body {
    Body::from(value.to_string())
}

pub(super) async fn ok_or_error(node: &NodeRow, resp: Response) -> Result<Response, ApiError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let message = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.pointer("/error/message")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(&bytes).trim().to_owned());
    let code = if status == StatusCode::CONFLICT {
        Code::Conflict
    } else {
        Code::Internal
    };
    Err(ApiError::new(code, format!("node {}: {message}", node.id)))
}

impl super::primary::Primary {
    /// Sends one fleet request to `node`, streaming `body`.
    pub(super) async fn send(
        &self,
        node: &NodeRow,
        path: &str,
        body: Body,
    ) -> Result<Response, ApiError> {
        let tls = self.client(&node.id)?;
        let req = axum::http::Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::HOST, node.url.trim_start_matches("https://"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(body)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        forward::send(tls, &node.url, req)
            .await
            .map_err(|e| unreachable_or_broken(node, e))
    }

    pub(super) async fn call<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        node: &NodeRow,
        path: &str,
        body: &T,
    ) -> Result<R, ApiError> {
        let tls = self.client(&node.id)?;
        forward::call(tls, &node.url, path, None, body)
            .await
            .map_err(|e| unreachable_or_broken(node, e))
    }
}

fn unreachable_or_broken(node: &NodeRow, failure: Failure) -> ApiError {
    match failure {
        Failure::Unreachable(e) => ApiError::new(
            Code::NodeUnreachable,
            format!("node {} cannot be reached: {e:#}", node.id),
        ),
        Failure::Broken(e) => ApiError::internal(format!("node {}: {e:#}", node.id)),
    }
}

/// What one pass of `drain` could not move.
pub struct Drained {
    pub failed: u32,
    pub volumes_failed: u32,
}

/// Moves every sandbox off `node`, running ones first, until it is
/// undrained.
pub async fn drain(app: AppState, node: String, origin: Origin) -> Drained {
    let mut sandboxes = app.db.node_sandboxes(&node).unwrap_or_default();
    sandboxes.sort_by_key(|s| s.state != state::RUNNING);
    let (mut moved, mut failed) = (0u32, 0u32);
    for sandbox in sandboxes {
        let draining = app
            .db
            .get_node(&node)
            .ok()
            .flatten()
            .is_some_and(|n| n.draining && n.state != node_state::REMOVED);
        if !draining {
            eprintln!("node {node} is no longer draining; stopped moving sandboxes");
            break;
        }
        match migrate(&app, &sandbox.id, MigrateInput::default(), &origin).await {
            Ok(_) => moved += 1,
            Err(error) => {
                eprintln!("drain {node}: {}: {}", sandbox.id, error.message);
                failed += 1;
            }
        }
    }
    let draining = app
        .db
        .get_node(&node)
        .ok()
        .flatten()
        .is_some_and(|n| n.draining && n.state != node_state::REMOVED);
    let (volumes_moved, volumes_failed) = match super::primary::primary(&app) {
        Ok(p) if draining => super::volumes::evacuate(&app, p, &node).await,
        _ => (0, 0),
    };
    app.sandboxes.hub.record(
        "node.drained",
        &origin,
        None,
        None,
        json!({
            "node": node,
            "moved": moved,
            "failed": failed,
            "volumes_moved": volumes_moved,
            "volumes_failed": volumes_failed,
            "complete": failed == 0 && volumes_failed == 0,
        }),
    );
    Drained {
        failed,
        volumes_failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;

    const FC: &[&str] = &["vm.state", "vm.mem", "upper.ext4"];

    fn header() -> Header {
        Header {
            sandbox: db::Sandbox {
                id: "sbx_1".into(),
                tenant: "default".into(),
                state: state::PAUSED.into(),
                template: "base".into(),
                build: None,
                labels: Default::default(),
                secrets: Vec::new(),
                egress: spawn_egress::Policy {
                    mode: spawn_egress::Mode::Allowlist,
                    allow: Vec::new(),
                    deny: Vec::new(),
                    max_egress_mbps: None,
                    max_ingress_mbps: None,
                },
                created_at: 1,
                expires_at: 2,
                idle_pause_s: 0,
                paused_at: Some(3),
                node: None,
                vcpus: 1,
                memory_mib: 256,
                volumes: Vec::new(),
                persistent: false,
                generation: 1,
                cold_starts: 0,
                last_cold_start_at: None,
            },
            saved: "{}".into(),
            was_running: true,
            fingerprint: "fp".into(),
            cpu: "cpu".into(),
        }
    }

    fn snapshot(dir: &Path) {
        std::fs::write(dir.join("vm.state"), b"state").unwrap();
        let mem = File::create(dir.join("vm.mem")).unwrap();
        mem.write_all_at(b"head", 0).unwrap();
        mem.write_all_at(b"tail", 8 << 20).unwrap();
        File::create(dir.join("upper.ext4"))
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
    }

    #[test]
    fn packages_round_trip_sparse() {
        let tmp = tempdir("roundtrip");
        let (src, dst) = (tmp.join("src"), tmp.join("dst"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        snapshot(&src);
        let mut package = Vec::new();
        write_package(&mut package, &header(), &files_in(&src)).unwrap();
        let got = read_package(package.as_slice(), &dst, &FILES, FC, |h: &Header| {
            assert_eq!(h.fingerprint, "fp");
            Ok(())
        })
        .unwrap();
        assert!(got.was_running);
        assert_eq!(std::fs::read(dst.join("vm.state")).unwrap(), b"state");
        let mem = std::fs::read(dst.join("vm.mem")).unwrap();
        assert_eq!(mem.len(), (8 << 20) + 4);
        assert_eq!(&mem[..4], b"head");
        assert_eq!(&mem[8 << 20..], b"tail");
        let upper = std::fs::metadata(dst.join("upper.ext4")).unwrap();
        assert_eq!(upper.len(), 64 << 20);
        assert!(!dst.join("layer.ext4").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn packages_are_checked() {
        let tmp = tempdir("checked");
        let src = tmp.join("src");
        std::fs::create_dir_all(&src).unwrap();
        snapshot(&src);
        let mut package = Vec::new();
        write_package(&mut package, &header(), &files_in(&src)).unwrap();

        let refused = tmp.join("refused");
        std::fs::create_dir_all(&refused).unwrap();
        let err = read_package(package.as_slice(), &refused, &FILES, FC, |_: &Header| {
            bail!("wrong host")
        });
        assert!(err.is_err());
        assert!(std::fs::read_dir(&refused).unwrap().next().is_none());

        // Change one byte of the uncompressed stream.
        let mut plain = zstd::decode_all(package.as_slice()).unwrap();
        let name = plain.windows(8).position(|w| w == b"vm.state").unwrap() + 8;
        let at = name
            + plain[name..]
                .windows(5)
                .position(|w| w == b"state")
                .unwrap();
        plain[at] = b'S';
        let bad = zstd::encode_all(plain.as_slice(), 1).unwrap();
        let dst = tmp.join("bad");
        std::fs::create_dir_all(&dst).unwrap();
        let err = read_package(bad.as_slice(), &dst, &FILES, FC, |_: &Header| Ok(())).unwrap_err();
        assert!(format!("{err:#}").contains("SHA-256"), "{err:#}");

        // A gVisor host needs its own files.
        let gvisor = tmp.join("gvisor");
        std::fs::create_dir_all(&gvisor).unwrap();
        let gvisor_files = &["checkpoint.img", "pages.img", "pages_meta.img"];
        let err = read_package(
            package.as_slice(),
            &gvisor,
            &FILES,
            gvisor_files,
            |_: &Header| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("misses a file"), "{err:#}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn tempdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spawnbox-migrate-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
