//! The build store: ready builds kept as content-addressed blobs in an
//! object store (any S3-compatible service, or a directory), so a host can
//! fetch a build instead of building it again.
//!
//! Layout under the store's prefix:
//! - `builds/<key>.json`: a manifest. The key is a hash of everything that
//!   makes the build, so equal inputs give equal keys.
//! - `blobs/<sha256>.zst`: one file of a build, compressed with zstd. The
//!   name is the SHA-256 of the uncompressed blob, so equal files are kept
//!   once.
//!
//! - `pages/<sha256>.sbxp`: a VM's memory file, in parts that can be read
//!   one at a time, so a host can start the VM before it has all of them.
//!   The name is the SHA-256 of its header and index.
//!
//! A blob holds only the data parts of a file, not its holes, so a 20 GiB
//! disk with 100 MiB written costs about 100 MiB to read, hash and send.
//! Uncompressed, it is `MAGIC`, then records of a little-endian u64 offset,
//! a u64 length and that many bytes, in order. The last record has length
//! 0 and the file's size as its offset.
//!
//! A pages object is `PAGES_MAGIC`, the file's size (u64), the part size
//! (u32) and the part count (u32), then an index entry per part: the start
//! (u64) and length (u64) of its zstd frame in the object, and the SHA-256
//! of the uncompressed part. A part of only zeros has length 0 and no
//! frame. Then the frames. Numbers are little-endian.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path as FsPath;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{StreamExt, TryStreamExt, stream};
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, PutPayload, WriteMultipart};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::runtime::now_ms;

/// Version 2 adds `pages`. Version 1 manifests are still read.
const MANIFEST_VERSION: u32 = 2;
const MAGIC: &[u8; 8] = b"SBXBLOB1";
const PAGES_MAGIC: &[u8; 8] = b"SBXPAGE1";
/// Memory is fetched in parts of this size.
pub const PART_BYTES_MEM: u64 = 2 * 1024 * 1024;
const PAGES_HEADER: usize = 24;
const PAGES_ENTRY: usize = 48;
const ZSTD_LEVEL: i32 = 3;
const IO_BYTES: usize = 1024 * 1024;
/// S3 needs parts of at least 5 MiB, except the last.
const PART_BYTES: usize = 16 * 1024 * 1024;
const RANGE_BYTES: u64 = 8 * 1024 * 1024;
/// Parts uploaded, or ranges downloaded, at the same time.
const PARALLEL: usize = 8;
/// Zero blocks of this size become holes, so sparse disks stay sparse.
const BLOCK: usize = 4096;

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    key: String,
    files: Vec<Blob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pages: Option<PagesRef>,
}

/// A memory file kept as a pages object.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PagesRef {
    name: String,
    /// Of the object's header and index, which is also the object's name.
    sha256: String,
    size: u64,
    /// Parts to fetch first, in this order.
    #[serde(default)]
    hot: Vec<u32>,
}

/// A memory file to upload as a pages object.
pub struct PagesIn {
    pub name: String,
    pub hot: Vec<u32>,
}

/// A pages object in the store, ready to read parts from.
pub struct Paged {
    path: Path,
    pub name: String,
    pub size: u64,
    pub hot: Vec<u32>,
    parts: Vec<Part>,
}

struct Part {
    start: u64,
    len: u64,
    sha256: [u8; 32],
}

impl Paged {
    pub fn count(&self) -> u32 {
        u32::try_from(self.parts.len()).unwrap_or(u32::MAX)
    }

    /// The uncompressed length of part `i`; the last can be short.
    pub fn part_len(&self, i: u32) -> u64 {
        PART_BYTES_MEM.min(self.size - u64::from(i) * PART_BYTES_MEM)
    }

    pub fn is_zero(&self, i: u32) -> bool {
        self.parts[i as usize].len == 0
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Blob {
    name: String,
    sha256: String,
    size: u64,
}

pub struct BuildStore {
    store: Arc<dyn ObjectStore>,
    prefix: Path,
    url: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    Mine,
    /// Another host builds it.
    Held,
    /// The store has no create-only put.
    Unsupported,
}

impl BuildStore {
    /// `s3://bucket/prefix` takes the endpoint, region and credentials from
    /// the `AWS_*` environment variables. `file:///path` uses a directory.
    pub fn open(url: &str) -> Result<Self> {
        let (store, prefix): (Arc<dyn ObjectStore>, &str) =
            if let Some(rest) = url.strip_prefix("s3://") {
                let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
                if bucket.is_empty() {
                    bail!("build store {url:?} has no bucket");
                }
                let s3 = AmazonS3Builder::from_env()
                    .with_bucket_name(bucket)
                    .build()
                    .with_context(|| format!("build store {url:?}"))?;
                (Arc::new(s3), prefix)
            } else if let Some(dir) = url.strip_prefix("file://") {
                std::fs::create_dir_all(dir).with_context(|| format!("create {dir}"))?;
                (Arc::new(LocalFileSystem::new_with_prefix(dir)?), "")
            } else {
                bail!("build store {url:?} must start with s3:// or file://");
            };
        Ok(Self {
            store,
            prefix: Path::parse(prefix.trim_matches('/'))?,
            url: url.to_owned(),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn claim_path(&self, key: &str) -> Path {
        self.prefix
            .clone()
            .join("claims")
            .join(format!("{key}.json"))
    }

    /// Claims the build of `key` for this host, so other hosts wait for its
    /// upload instead of building it too. A claim not written for `stale`
    /// belongs to a host that is gone, and is taken over.
    pub async fn claim(&self, key: &str, stale: Duration) -> Result<Claim> {
        let path = self.claim_path(key);
        for _ in 0..2 {
            let body = PutPayload::from(format!("{{\"at\":{}}}", now_ms()));
            match self
                .store
                .put_opts(&path, body, PutMode::Create.into())
                .await
            {
                Ok(_) => return Ok(Claim::Mine),
                Err(object_store::Error::NotImplemented { .. }) => return Ok(Claim::Unsupported),
                Err(object_store::Error::AlreadyExists { .. }) => {}
                Err(error) => return Err(error.into()),
            }
            let written = match self.store.head(&path).await {
                Ok(meta) => meta.last_modified.timestamp_millis(),
                // Released meanwhile.
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(error) => return Err(error.into()),
            };
            if now_ms().saturating_sub(written) < i64::try_from(stale.as_millis())? {
                return Ok(Claim::Held);
            }
            self.release_claim(key).await?;
        }
        Ok(Claim::Held)
    }

    /// Writes this host's claim on `key` again, so it does not go stale.
    pub async fn refresh_claim(&self, key: &str) -> Result<()> {
        let body = PutPayload::from(format!("{{\"at\":{}}}", now_ms()));
        self.store.put(&self.claim_path(key), body).await?;
        Ok(())
    }

    pub async fn release_claim(&self, key: &str) -> Result<()> {
        match self.store.delete(&self.claim_path(key)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn manifest(&self, key: &str) -> Path {
        self.prefix
            .clone()
            .join("builds")
            .join(format!("{key}.json"))
    }

    /// Tells if the store has the manifest of build `key`.
    pub async fn has(&self, key: &str) -> Result<bool> {
        match self.store.head(&self.manifest(key)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn blob(&self, sha256: &str) -> Path {
        self.prefix
            .clone()
            .join("blobs")
            .join(format!("{sha256}.zst"))
    }

    fn pages_path(&self, sha256: &str) -> Path {
        self.prefix
            .clone()
            .join("pages")
            .join(format!("{sha256}.sbxp"))
    }

    /// Uploads the named files of `dir` under `key`, and `pages` as a pages
    /// object. Objects the store already has are not sent again. The
    /// manifest goes last, so a build is only visible once all its objects
    /// are there.
    pub async fn upload(
        &self,
        key: &str,
        dir: &FsPath,
        names: &[String],
        pages: Option<PagesIn>,
    ) -> Result<()> {
        let mut files = Vec::new();
        for name in names {
            let source = dir.join(name);
            let packed = dir.join(format!(".{name}.zst"));
            let result = async {
                let (sha256, size) = {
                    let (source, packed) = (source.clone(), packed.clone());
                    tokio::task::spawn_blocking(move || compress(&source, &packed)).await??
                };
                let blob = self.blob(&sha256);
                if self.store.head(&blob).await.is_err() {
                    self.put_file(&blob, &packed).await?;
                }
                anyhow::Ok(Blob {
                    name: name.clone(),
                    sha256,
                    size,
                })
            }
            .await;
            let _ = std::fs::remove_file(&packed);
            files.push(result.with_context(|| format!("upload {}", source.display()))?);
        }
        let pages = match pages {
            Some(pages) => Some(self.upload_pages(dir, pages).await?),
            None => None,
        };
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            key: key.to_owned(),
            files,
            pages,
        };
        let json = serde_json::to_vec(&manifest)?;
        self.store
            .put(&self.manifest(key), PutPayload::from(json))
            .await?;
        Ok(())
    }

    async fn upload_pages(&self, dir: &FsPath, pages: PagesIn) -> Result<PagesRef> {
        let source = dir.join(&pages.name);
        let packed = dir.join(format!(".{}.sbxp", pages.name));
        let result = async {
            let (sha256, size) = {
                let (source, packed) = (source.clone(), packed.clone());
                tokio::task::spawn_blocking(move || pack_pages(&source, &packed)).await??
            };
            let path = self.pages_path(&sha256);
            if self.store.head(&path).await.is_err() {
                self.put_file(&path, &packed).await?;
            }
            anyhow::Ok(PagesRef {
                name: pages.name.clone(),
                sha256,
                size,
                hot: pages.hot,
            })
        }
        .await;
        let _ = std::fs::remove_file(&packed);
        result.with_context(|| format!("upload {}", source.display()))
    }

    async fn put_file(&self, to: &Path, from: &FsPath) -> Result<()> {
        let upload = self.store.put_multipart(to).await?;
        let mut writer = WriteMultipart::new_with_chunk_size(upload, PART_BYTES);
        let sent = async {
            let mut file = tokio::fs::File::open(from).await?;
            let mut buf = vec![0; IO_BYTES];
            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    return anyhow::Ok(());
                }
                writer.wait_for_capacity(PARALLEL).await?;
                writer.write(&buf[..n]);
            }
        }
        .await;
        match sent {
            Ok(()) => {
                writer.finish().await?;
                Ok(())
            }
            Err(error) => {
                let _ = writer.abort().await;
                Err(error)
            }
        }
    }

    /// Downloads the build `key` into `dir` and checks every file against
    /// its SHA-256. False if the store does not have it.
    pub async fn download(&self, key: &str, dir: &FsPath) -> Result<bool> {
        let paged = match self.download_files(key, dir).await? {
            None => return Ok(false),
            Some(None) => return Ok(true),
            Some(Some(paged)) => paged,
        };
        let dest = dir.join(&paged.name);
        let partial = dir.join(format!(".{}.part", paged.name));
        let result = async {
            self.fetch_pages(&paged, &partial).await?;
            std::fs::rename(&partial, &dest)?;
            anyhow::Ok(())
        }
        .await;
        let _ = std::fs::remove_file(&partial);
        result?;
        Ok(true)
    }

    /// Like `download`, but leaves out the memory file if it is a pages
    /// object, and returns that object to read its parts from. `None` if
    /// the store does not have the build.
    pub async fn download_files(&self, key: &str, dir: &FsPath) -> Result<Option<Option<Paged>>> {
        let manifest: Manifest = match self.store.get(&self.manifest(key)).await {
            Ok(found) => serde_json::from_slice(&found.bytes().await?)?,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !(1..=MANIFEST_VERSION).contains(&manifest.version) || manifest.key != key {
            bail!("manifest of build {key} does not match");
        }
        std::fs::create_dir_all(dir)?;
        for blob in manifest.files {
            if !is_file_name(&blob.name) || !is_sha256(&blob.sha256) {
                bail!("manifest of build {key} has a bad entry {:?}", blob.name);
            }
            let packed = dir.join(format!(".{}.zst", blob.name));
            let partial = dir.join(format!(".{}.part", blob.name));
            let result = async {
                self.fetch(&self.blob(&blob.sha256), &packed).await?;
                let (packed, partial) = (packed.clone(), partial.clone());
                let dest = dir.join(&blob.name);
                tokio::task::spawn_blocking(move || {
                    unpack(&packed, &partial, &blob)?;
                    std::fs::rename(&partial, &dest)?;
                    anyhow::Ok(())
                })
                .await?
            }
            .await;
            let _ = std::fs::remove_file(&packed);
            let _ = std::fs::remove_file(&partial);
            result?;
        }
        match manifest.pages {
            None => Ok(Some(None)),
            Some(pages) => Ok(Some(Some(self.open_pages(key, pages).await?))),
        }
    }

    /// Reads and checks the header and index of a pages object.
    async fn open_pages(&self, key: &str, pages: PagesRef) -> Result<Paged> {
        if !is_file_name(&pages.name) || !is_sha256(&pages.sha256) {
            bail!("manifest of build {key} has a bad entry {:?}", pages.name);
        }
        let count = pages.size.div_ceil(PART_BYTES_MEM);
        if pages.hot.iter().any(|&i| u64::from(i) >= count) {
            bail!("manifest of build {key} has a bad hot list");
        }
        let path = self.pages_path(&pages.sha256);
        let len = PAGES_HEADER as u64 + count * PAGES_ENTRY as u64;
        let head = self.store.get_range(&path, 0..len).await?;
        let parts = parse_index(&head, pages.size)
            .filter(|_| hex(&Sha256::digest(&head)) == pages.sha256)
            .with_context(|| format!("{} is not a valid pages object", pages.name))?;
        Ok(Paged {
            path,
            name: pages.name,
            size: pages.size,
            hot: pages.hot,
            parts,
        })
    }

    /// Reads part `i` of `paged` and checks it. `None` for a part of only
    /// zeros.
    pub async fn read_part(&self, paged: &Paged, i: u32) -> Result<Option<Vec<u8>>> {
        let part = &paged.parts[i as usize];
        if part.len == 0 {
            return Ok(None);
        }
        let frame = self
            .store
            .get_range(&paged.path, part.start..part.start + part.len)
            .await?;
        if frame.len() as u64 != part.len {
            bail!("short read of part {i} of {}", paged.name);
        }
        let (want, sha256) = (paged.part_len(i), part.sha256);
        let bytes = tokio::task::spawn_blocking(move || {
            let bytes = zstd::bulk::decompress(&frame, usize::try_from(want)?)?;
            if bytes.len() as u64 != want || Sha256::digest(&bytes)[..] != sha256 {
                bail!("does not match its SHA-256");
            }
            anyhow::Ok(bytes)
        })
        .await?
        .with_context(|| format!("part {i} of {}", paged.name))?;
        Ok(Some(bytes))
    }

    /// Downloads every part of `paged` into a new sparse file `to`.
    async fn fetch_pages(&self, paged: &Paged, to: &FsPath) -> Result<()> {
        let file = Arc::new(File::create(to)?);
        file.set_len(paged.size)?;
        stream::iter((0..paged.count()).filter(|&i| !paged.is_zero(i)))
            .map(|i| async move { anyhow::Ok((i, self.read_part(paged, i).await?)) })
            .buffer_unordered(PARALLEL)
            .try_for_each(|(i, bytes)| {
                let file = Arc::clone(&file);
                async move {
                    let Some(bytes) = bytes else { return Ok(()) };
                    let at = u64::from(i) * PART_BYTES_MEM;
                    tokio::task::spawn_blocking(move || write_sparse(&file, at, &bytes)).await??;
                    Ok(())
                }
            })
            .await?;
        file.sync_all()?;
        Ok(())
    }

    /// Downloads one object in parallel ranges.
    async fn fetch(&self, from: &Path, to: &FsPath) -> Result<()> {
        let size = self.store.head(from).await?.size;
        // One request is enough, and some servers answer a range that
        // covers the whole object with the whole object.
        if size <= RANGE_BYTES {
            let bytes = self.store.get(from).await?.bytes().await?;
            std::fs::write(to, &bytes)?;
            return Ok(());
        }
        let file = Arc::new(File::create(to)?);
        file.set_len(size)?;
        let ranges = (0..size)
            .step_by(usize::try_from(RANGE_BYTES)?)
            .map(|start| start..size.min(start + RANGE_BYTES));
        stream::iter(ranges)
            .map(|range| async move {
                let bytes = self.store.get_range(from, range.clone()).await?;
                if bytes.len() as u64 != range.end - range.start {
                    bail!("short read of {from}");
                }
                anyhow::Ok((range.start, bytes))
            })
            .buffer_unordered(PARALLEL)
            .try_for_each(|(offset, bytes)| {
                let file = Arc::clone(&file);
                async move {
                    tokio::task::spawn_blocking(move || file.write_all_at(&bytes, offset))
                        .await??;
                    Ok(())
                }
            })
            .await
    }

    /// Deletes manifests older than `max_age` that are not in `keep`, then
    /// blobs older than `max_age` that no manifest refers to. Kept manifests
    /// are written again first, so other hosts see them as recent. Returns
    /// how many manifests and blobs were deleted.
    pub async fn collect(
        &self,
        keep: &HashSet<String>,
        max_age: Duration,
    ) -> Result<(usize, usize)> {
        for key in keep {
            let path = self.manifest(key);
            if let Ok(found) = self.store.get(&path).await {
                let bytes = found.bytes().await?;
                self.store.put(&path, PutPayload::from(bytes)).await?;
            }
        }
        let cutoff = now_ms().saturating_sub(i64::try_from(max_age.as_millis())?);
        let old = |meta: &object_store::ObjectMeta| meta.last_modified.timestamp_millis() < cutoff;

        let manifests: Vec<_> = self
            .store
            .list(Some(&self.prefix.clone().join("builds")))
            .try_collect()
            .await?;
        let mut used = HashSet::new();
        let mut deleted = (0, 0);
        for meta in manifests {
            let key = stem(&meta.location, ".json");
            if !keep.contains(key) && old(&meta) {
                self.store.delete(&meta.location).await?;
                deleted.0 += 1;
                continue;
            }
            let bytes = self.store.get(&meta.location).await?.bytes().await?;
            match serde_json::from_slice::<Manifest>(&bytes) {
                Ok(manifest) => {
                    used.extend(manifest.files.into_iter().map(|b| b.sha256));
                    used.extend(manifest.pages.map(|p| p.sha256));
                }
                // Its blobs can't be told apart, so none are deleted.
                Err(_) => return Ok(deleted),
            }
        }
        let blobs: Vec<_> = self
            .store
            .list(Some(&self.prefix.clone().join("blobs")))
            .try_collect()
            .await?;
        let pages: Vec<_> = self
            .store
            .list(Some(&self.prefix.clone().join("pages")))
            .try_collect()
            .await?;
        for meta in blobs {
            if !used.contains(stem(&meta.location, ".zst")) && old(&meta) {
                self.store.delete(&meta.location).await?;
                deleted.1 += 1;
            }
        }
        for meta in pages {
            if !used.contains(stem(&meta.location, ".sbxp")) && old(&meta) {
                self.store.delete(&meta.location).await?;
                deleted.1 += 1;
            }
        }
        // Left by hosts that stopped while building.
        let claims: Vec<_> = self
            .store
            .list(Some(&self.prefix.clone().join("claims")))
            .try_collect()
            .await?;
        for meta in claims.iter().filter(|m| old(m)) {
            self.store.delete(&meta.location).await?;
        }
        Ok(deleted)
    }
}

/// The store key of a build: the same inputs, host CPU, spec and egress
/// policy always give the same key.
pub fn key(fingerprint: &str, cpu: &str, spec: &str, egress: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [
        MANIFEST_VERSION.to_string().as_str(),
        fingerprint,
        cpu,
        spec,
        egress,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hex(&hasher.finalize())
}

/// The host CPU's model. Snapshots only restore on a matching CPU.
pub fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, model)| model.trim().to_owned())
        })
        .unwrap_or_default()
}

/// Writes `source` as a pages object to `packed`. Returns the SHA-256 of
/// its header and index, and the size of `source`.
fn pack_pages(source: &FsPath, packed: &FsPath) -> Result<(String, u64)> {
    let input = File::open(source)?;
    let size = input.metadata()?.len();
    let count = size.div_ceil(PART_BYTES_MEM);
    let header_len = PAGES_HEADER + usize::try_from(count)? * PAGES_ENTRY;
    let mut head = Vec::with_capacity(header_len);
    head.extend_from_slice(PAGES_MAGIC);
    head.extend_from_slice(&size.to_le_bytes());
    head.extend_from_slice(&u32::try_from(PART_BYTES_MEM)?.to_le_bytes());
    head.extend_from_slice(&u32::try_from(count)?.to_le_bytes());
    let out = File::create(packed)?;
    let mut at = u64::try_from(header_len)?;
    let mut buf = vec![0; usize::try_from(PART_BYTES_MEM)?];
    for i in 0..count {
        let start = i * PART_BYTES_MEM;
        let part = &mut buf[..usize::try_from(PART_BYTES_MEM.min(size - start))?];
        input.read_exact_at(part, start)?;
        let (len, sha256) = if part.iter().all(|&b| b == 0) {
            (0, [0; 32])
        } else {
            let frame = zstd::bulk::compress(part, ZSTD_LEVEL)?;
            out.write_all_at(&frame, at)?;
            (frame.len() as u64, Sha256::digest(&*part).into())
        };
        head.extend_from_slice(&(if len == 0 { 0 } else { at }).to_le_bytes());
        head.extend_from_slice(&len.to_le_bytes());
        head.extend_from_slice(&sha256);
        at += len;
    }
    out.write_all_at(&head, 0)?;
    out.sync_all()?;
    Ok((hex(&Sha256::digest(&head)), size))
}

/// The index of a pages object from its first bytes, if they are valid
/// for a file of `size`.
fn parse_index(head: &[u8], size: u64) -> Option<Vec<Part>> {
    let count = size.div_ceil(PART_BYTES_MEM);
    let header_len = PAGES_HEADER as u64 + count * PAGES_ENTRY as u64;
    let u64_at = |at: usize| Some(u64::from_le_bytes(head.get(at..at + 8)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(head.get(at..at + 4)?.try_into().ok()?));
    if head.len() as u64 != header_len
        || head.get(..8)? != PAGES_MAGIC
        || u64_at(8)? != size
        || u64::from(u32_at(16)?) != PART_BYTES_MEM
        || u64::from(u32_at(20)?) != count
    {
        return None;
    }
    // A frame is never much larger than its part.
    let max_frame = PART_BYTES_MEM + PART_BYTES_MEM / 64 + 4096;
    head[PAGES_HEADER..]
        .chunks(PAGES_ENTRY)
        .map(|entry| {
            let part = Part {
                start: u64::from_le_bytes(entry[..8].try_into().ok()?),
                len: u64::from_le_bytes(entry[8..16].try_into().ok()?),
                sha256: entry[16..].try_into().ok()?,
            };
            (part.len == 0 || (part.start >= header_len && part.len <= max_frame)).then_some(part)
        })
        .collect()
}

/// Packs the data parts of `source` into `packed`. Returns the SHA-256 of
/// the uncompressed blob and the size of `source`.
fn compress(source: &FsPath, packed: &FsPath) -> Result<(String, u64)> {
    let input = File::open(source)?;
    let encoder = zstd::Encoder::new(File::create(packed)?, ZSTD_LEVEL)?;
    let mut out = Hashed {
        inner: encoder,
        hasher: Sha256::new(),
    };
    let size = write_blob(&input, &mut out)?;
    let Hashed { inner, hasher } = out;
    inner.finish()?.sync_all()?;
    Ok((hex(&hasher.finalize()), size))
}

/// Writes `input` as a blob: `MAGIC`, its data parts, and the end record.
/// Returns its size.
pub(crate) fn write_blob(input: &File, out: &mut impl Write) -> Result<u64> {
    let size = input.metadata()?.len();
    out.write_all(MAGIC)?;
    let mut buf = vec![0; IO_BYTES];
    for (start, end) in data_ranges(input, size)? {
        out.write_all(&start.to_le_bytes())?;
        out.write_all(&(end - start).to_le_bytes())?;
        let mut at = start;
        while at < end {
            let want = usize::try_from(end - at)
                .unwrap_or(usize::MAX)
                .min(buf.len());
            input.read_exact_at(&mut buf[..want], at)?;
            out.write_all(&buf[..want])?;
            at += want as u64;
        }
    }
    out.write_all(&size.to_le_bytes())?;
    out.write_all(&0u64.to_le_bytes())?;
    Ok(size)
}

/// The parts of `file` that hold data, as `(start, end)`.
fn data_ranges(file: &File, size: u64) -> Result<Vec<(u64, u64)>> {
    use nix::unistd::{Whence, lseek};
    let mut ranges = Vec::new();
    let mut at = 0;
    while at < size {
        let start = match lseek(file, i64::try_from(at)?, Whence::SeekData) {
            Ok(start) => u64::try_from(start)?,
            // Only holes are left.
            Err(nix::errno::Errno::ENXIO) => break,
            Err(error) => return Err(error.into()),
        };
        let end = u64::try_from(lseek(file, i64::try_from(start)?, Whence::SeekHole)?)?.min(size);
        if end > start {
            ranges.push((start, end));
        }
        at = end.max(start + 1);
    }
    Ok(ranges)
}

/// Unpacks `packed` into a sparse `dest` and checks it against `blob`.
fn unpack(packed: &FsPath, dest: &FsPath, blob: &Blob) -> Result<()> {
    let mut input = Hashed {
        inner: zstd::Decoder::new(File::open(packed)?)?,
        hasher: Sha256::new(),
    };
    let out = File::create(dest)?;
    let size = read_blob(&mut input, &out, blob.size)
        .with_context(|| format!("{} is not a valid blob", blob.name))?;
    let mut rest = [0; 1];
    if input.inner.read(&mut rest)? != 0 {
        bail!("{} is not a valid blob", blob.name);
    }
    out.sync_all()?;
    if size != blob.size || hex(&input.hasher.finalize()) != blob.sha256 {
        bail!("{} does not match its SHA-256", blob.name);
    }
    Ok(())
}

/// Reads one blob from `input` into the sparse file `out`, which must be
/// empty. Fails if it is malformed or larger than `max_size`. Returns its
/// size.
pub(crate) fn read_blob(input: &mut impl Read, out: &File, max_size: u64) -> Result<u64> {
    let bad = || anyhow::anyhow!("malformed blob");
    let mut magic = [0; 8];
    input.read_exact(&mut magic).map_err(|_| bad())?;
    if &magic != MAGIC {
        return Err(bad());
    }
    let mut buf = vec![0; IO_BYTES];
    let mut last_end = 0;
    let size = loop {
        let mut header = [0; 16];
        input.read_exact(&mut header).map_err(|_| bad())?;
        let offset = u64::from_le_bytes(header[..8].try_into()?);
        let len = u64::from_le_bytes(header[8..].try_into()?);
        if len == 0 {
            break offset;
        }
        let end = offset.checked_add(len).ok_or_else(bad)?;
        if offset < last_end || end > max_size {
            return Err(bad());
        }
        let mut at = offset;
        while at < end {
            let want = usize::try_from(end - at)
                .unwrap_or(usize::MAX)
                .min(buf.len());
            input.read_exact(&mut buf[..want]).map_err(|_| bad())?;
            write_sparse(out, at, &buf[..want])?;
            at += want as u64;
        }
        last_end = end;
    };
    if size < last_end || size > max_size {
        return Err(bad());
    }
    out.set_len(size)?;
    Ok(size)
}

/// Hashes what goes through it.
pub(crate) struct Hashed<T> {
    pub inner: T,
    pub hasher: Sha256,
}

impl<W: Write> Write for Hashed<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

/// Writes `bytes` at `offset`, skipping all-zero blocks.
fn write_sparse(file: &File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    let mut run: Option<usize> = None;
    for (i, block) in bytes.chunks(BLOCK).enumerate() {
        let start = i * BLOCK;
        match (block.iter().all(|&b| b == 0), run) {
            (false, None) => run = Some(start),
            (true, Some(from)) => {
                file.write_all_at(&bytes[from..start], offset + from as u64)?;
                run = None;
            }
            _ => {}
        }
    }
    if let Some(from) = run {
        file.write_all_at(&bytes[from..], offset + from as u64)?;
    }
    Ok(())
}

fn stem<'a>(path: &'a Path, suffix: &str) -> &'a str {
    let name = path.filename().unwrap_or_default();
    name.strip_suffix(suffix).unwrap_or(name)
}

fn is_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("spawnbox-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample(dir: &FsPath) -> Vec<String> {
        std::fs::write(dir.join("vm.state"), b"state").unwrap();
        // 64 MiB of mostly holes, with data at both ends.
        let disk = File::create(dir.join("upper.ext4")).unwrap();
        disk.set_len(64 << 20).unwrap();
        disk.write_all_at(b"head", 0).unwrap();
        disk.write_all_at(b"tail", (64 << 20) - 4).unwrap();
        File::create(dir.join("holes.ext4"))
            .unwrap()
            .set_len(1 << 20)
            .unwrap();
        vec!["holes.ext4".into(), "upper.ext4".into(), "vm.state".into()]
    }

    fn count(dir: &FsPath, sub: &str) -> usize {
        std::fs::read_dir(dir.join(sub)).map_or(0, Iterator::count)
    }

    #[tokio::test]
    async fn round_trips_and_keeps_files_sparse() {
        let root = temp("trip");
        let (src, dest, bucket) = (root.join("src"), root.join("dest"), root.join("bucket"));
        std::fs::create_dir_all(&src).unwrap();
        let names = sample(&src);
        let store = BuildStore::open(&format!("file://{}", bucket.display())).unwrap();

        assert!(!store.download("k1", &dest).await.unwrap());
        store.upload("k1", &src, &names, None).await.unwrap();
        // Equal files are stored once.
        store.upload("k2", &src, &names, None).await.unwrap();
        assert_eq!(count(&bucket, "blobs"), 3);
        let stored: u64 = std::fs::read_dir(bucket.join("blobs"))
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        assert!(stored < 64 * 1024, "holes are not stored: {stored} bytes");

        assert!(store.download("k1", &dest).await.unwrap());
        for name in &names {
            let a = std::fs::read(src.join(name)).unwrap();
            assert_eq!(a, std::fs::read(dest.join(name)).unwrap(), "{name}");
        }
        let disk = std::fs::metadata(dest.join("upper.ext4")).unwrap();
        assert!(std::os::unix::fs::MetadataExt::blocks(&disk) * 512 < disk.len() / 4);
        let left: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 3, "no temporary files are left: {left:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn rejects_a_blob_that_does_not_match() {
        let root = temp("bad");
        let (src, dest, bucket) = (root.join("src"), root.join("dest"), root.join("bucket"));
        std::fs::create_dir_all(&src).unwrap();
        let names = sample(&src);
        let store = BuildStore::open(&format!("file://{}", bucket.display())).unwrap();
        store.upload("k", &src, &names, None).await.unwrap();

        let manifest: Manifest =
            serde_json::from_slice(&std::fs::read(bucket.join("builds/k.json")).unwrap()).unwrap();
        let state = &manifest
            .files
            .iter()
            .find(|b| b.name == "vm.state")
            .unwrap()
            .sha256;
        // A valid blob, of other bytes.
        let other = root.join("other");
        std::fs::write(&other, b"other").unwrap();
        let swapped = root.join("swapped.zst");
        compress(&other, &swapped).unwrap();
        std::fs::rename(swapped, bucket.join("blobs").join(format!("{state}.zst"))).unwrap();
        let error = store.download("k", &dest).await.unwrap_err();
        assert!(format!("{error:#}").contains("SHA-256"), "{error:#}");
        assert!(!dest.join("vm.state").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn claims_once_and_takes_over_a_stale_claim() {
        let root = temp("claim");
        let store = BuildStore::open(&format!("file://{}", root.display())).unwrap();
        let long = Duration::from_secs(60);
        assert_eq!(store.claim("k", long).await.unwrap(), Claim::Mine);
        assert_eq!(store.claim("k", long).await.unwrap(), Claim::Held);
        store.refresh_claim("k").await.unwrap();
        assert_eq!(store.claim("k", long).await.unwrap(), Claim::Held);
        assert_eq!(store.claim("k", Duration::ZERO).await.unwrap(), Claim::Mine);
        store.release_claim("k").await.unwrap();
        store.release_claim("k").await.unwrap();
        assert_eq!(store.claim("k", long).await.unwrap(), Claim::Mine);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn collects_what_nothing_keeps() {
        let root = temp("gc");
        let (src, bucket) = (root.join("src"), root.join("bucket"));
        std::fs::create_dir_all(&src).unwrap();
        let names = sample(&src);
        let store = BuildStore::open(&format!("file://{}", bucket.display())).unwrap();
        store.upload("kept", &src, &names[1..], None).await.unwrap();
        store.upload("old", &src, &names, None).await.unwrap();
        // `old` alone has holes.ext4.

        let keep = HashSet::from(["kept".to_owned()]);
        // Nothing is old enough yet.
        assert_eq!(
            store
                .collect(&keep, Duration::from_secs(3600))
                .await
                .unwrap(),
            (0, 0)
        );
        // Ages are compared in whole milliseconds.
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(store.collect(&keep, Duration::ZERO).await.unwrap(), (1, 1));
        assert_eq!((count(&bucket, "builds"), count(&bucket, "blobs")), (1, 2));
        let _ = std::fs::remove_dir_all(root);
    }

    /// 5 parts and a bit: data, zeros, data at both ends of a part, zeros,
    /// data, and a short last part.
    fn memory(dir: &FsPath) -> Vec<u8> {
        let part = usize::try_from(PART_BYTES_MEM).unwrap();
        let mut mem = vec![0u8; part * 5 + 4096];
        mem[..part].fill(7);
        mem[part * 2] = 1;
        mem[part * 3 - 1] = 2;
        mem[part * 4 + 100] = 3;
        mem[part * 5 + 10] = 4;
        std::fs::write(dir.join("vm.mem"), &mem).unwrap();
        mem
    }

    #[tokio::test]
    async fn round_trips_memory_as_pages() {
        let root = temp("pages");
        let (src, dest, lazy, bucket) = (
            root.join("src"),
            root.join("dest"),
            root.join("lazy"),
            root.join("bucket"),
        );
        std::fs::create_dir_all(&src).unwrap();
        let names = sample(&src);
        let mem = memory(&src);
        let store = BuildStore::open(&format!("file://{}", bucket.display())).unwrap();
        let pages = PagesIn {
            name: "vm.mem".into(),
            hot: vec![4, 0],
        };
        store.upload("k", &src, &names, Some(pages)).await.unwrap();
        assert_eq!(count(&bucket, "pages"), 1);

        assert!(store.download("k", &dest).await.unwrap());
        assert!(std::fs::read(dest.join("vm.mem")).unwrap() == mem);

        let paged = store
            .download_files("k", &lazy)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!lazy.join("vm.mem").exists());
        assert!(lazy.join("vm.state").exists());
        assert_eq!((paged.count(), paged.hot.clone()), (6, vec![4, 0]));
        assert_eq!(paged.part_len(5), 4096);
        let zero: Vec<u32> = (0..6).filter(|&i| paged.is_zero(i)).collect();
        assert_eq!(zero, [1, 3]);
        let part = usize::try_from(PART_BYTES_MEM).unwrap();
        for i in 0..6 {
            let at = i as usize * part;
            match store.read_part(&paged, i).await.unwrap() {
                Some(bytes) => assert!(bytes[..] == mem[at..(at + part).min(mem.len())]),
                None => assert!(mem[at..at + part].iter().all(|&b| b == 0)),
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn rejects_a_part_or_index_that_does_not_match() {
        let root = temp("badpages");
        let (src, dest, bucket) = (root.join("src"), root.join("dest"), root.join("bucket"));
        std::fs::create_dir_all(&src).unwrap();
        memory(&src);
        let store = BuildStore::open(&format!("file://{}", bucket.display())).unwrap();
        let pages = PagesIn {
            name: "vm.mem".into(),
            hot: vec![],
        };
        store.upload("k", &src, &[], Some(pages)).await.unwrap();
        let object = std::fs::read_dir(bucket.join("pages"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let good = std::fs::read(&object).unwrap();

        // Part 0 holds a valid frame of other bytes.
        let paged = store
            .download_files("k", &dest)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let start = paged.parts[0].start as usize;
        let len = paged.parts[0].len as usize;
        let other = zstd::bulk::compress(&vec![8u8; PART_BYTES_MEM as usize], ZSTD_LEVEL).unwrap();
        assert!(other.len() <= len);
        let mut bad = good.clone();
        bad[start..start + other.len()].copy_from_slice(&other);
        std::fs::write(&object, &bad).unwrap();
        let error = store.read_part(&paged, 0).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("part 0 of vm.mem"),
            "{error:#}"
        );

        // A changed index no longer matches the object's name.
        let mut bad = good;
        bad[PAGES_HEADER + 8] ^= 1;
        std::fs::write(&object, &bad).unwrap();
        let error = store.download("k", &dest).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("not a valid pages"),
            "{error:#}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn keys_change_with_every_input() {
        let base = key("f", "cpu", "{}", "[]");
        assert_eq!(base, key("f", "cpu", "{}", "[]"));
        for other in [
            key("g", "cpu", "{}", "[]"),
            key("f", "cpu2", "{}", "[]"),
            key("f", "cpu", "{ }", "[]"),
            key("f", "cpu", "{}", "[1]"),
            key("fc", "pu", "{}", "[]"),
        ] {
            assert_ne!(base, other);
        }
    }
}
