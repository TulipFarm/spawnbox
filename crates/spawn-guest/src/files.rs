//! The `Files` and `Image` services. File calls run on blocking threads with
//! the filesystem uid and gid of the requested user, so permissions and
//! ownership match what that user's commands would see.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::{Gid, Uid, User, setfsgid, setfsuid};
use spawn_proto::guest::v1::read_chunk::Chunk as ReadPart;
use spawn_proto::guest::v1::write_chunk::Chunk as WritePart;
use spawn_proto::guest::v1::{FileInfo, FileKind, ListResponse, ReadChunk, WriteChunk};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tonic::{Status, Streaming};

use crate::init::UPPER_MOUNT;

const DEFAULT_USER: &str = "user";
const BASE_DIR: &str = "/workspace";
pub const CHUNK: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_PATH: usize = 4096;

/// `_IOWR('X', 119, int)` from `linux/fs.h`.
const FIFREEZE: u32 = 0xC004_5877;

pub type ReadSender = mpsc::Sender<Result<ReadChunk, Status>>;

pub fn resolve(path: &str) -> Result<PathBuf, Status> {
    if path.is_empty() || path.len() > MAX_PATH || path.contains('\0') {
        return Err(Status::invalid_argument(format!(
            "path must be 1 to {MAX_PATH} bytes with no NUL"
        )));
    }
    Ok(Path::new(BASE_DIR).join(path))
}

pub fn user(name: &str) -> Result<User, Status> {
    let name = if name.is_empty() { DEFAULT_USER } else { name };
    User::from_name(name)
        .map_err(|e| Status::internal(format!("look up user {name}: {e}")))?
        .ok_or_else(|| Status::invalid_argument(format!("no such user: {name}")))
}

/// Runs `work` on a blocking thread as `user` for file permission checks.
async fn as_user<T: Send + 'static>(
    user: User,
    path: PathBuf,
    work: impl FnOnce(&Path) -> io::Result<T> + Send + 'static,
) -> Result<T, Status> {
    tokio::task::spawn_blocking(move || {
        let _reset = FsIds::switch(user.uid, user.gid);
        work(&path).map_err(|error| status(&path, &error))
    })
    .await
    .map_err(|error| Status::internal(format!("file task failed: {error}")))?
}

/// Filesystem ids of the current thread, set back to root on drop.
struct FsIds;

impl FsIds {
    fn switch(uid: Uid, gid: Gid) -> Self {
        // gid first: after giving up uid 0 the thread may not change it.
        setfsgid(gid);
        setfsuid(uid);
        Self
    }
}

impl Drop for FsIds {
    fn drop(&mut self) {
        setfsuid(Uid::from_raw(0));
        setfsgid(Gid::from_raw(0));
    }
}

fn status(path: &Path, error: &io::Error) -> Status {
    let message = format!("{}: {error}", path.display());
    match error.kind() {
        io::ErrorKind::NotFound => Status::not_found(message),
        io::ErrorKind::PermissionDenied => Status::permission_denied(message),
        io::ErrorKind::AlreadyExists
        | io::ErrorKind::IsADirectory
        | io::ErrorKind::NotADirectory
        | io::ErrorKind::DirectoryNotEmpty => Status::failed_precondition(message),
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => {
            Status::resource_exhausted(message)
        }
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidFilename => {
            Status::invalid_argument(message)
        }
        _ => Status::internal(message),
    }
}

fn info(path: String, meta: &Metadata) -> FileInfo {
    let kind = if meta.is_symlink() {
        FileKind::Symlink
    } else if meta.is_dir() {
        FileKind::Dir
    } else if meta.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    };
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    FileInfo {
        path,
        kind: kind.into(),
        size: meta.len(),
        mode: meta.mode() & 0o7777,
        modified_unix_ms: modified,
    }
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

pub async fn stat(path: &str, user_name: &str) -> Result<FileInfo, Status> {
    let (path, user) = (resolve(path)?, user(user_name)?);
    as_user(user, path, |path| {
        Ok(info(display(path), &fs::metadata(path)?))
    })
    .await
}

/// Opens a regular file and returns its info. Streaming the bytes is
/// `send_file`'s job.
pub async fn open(path: &str, user_name: &str) -> Result<(File, FileInfo), Status> {
    let (path, user) = (resolve(path)?, user(user_name)?);
    as_user(user, path, |path| {
        // Non-blocking, so opening a FIFO cannot hang the agent.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Ok((file, info(display(path), &meta)))
    })
    .await
}

/// Sends the file's info, then at most `info.size` bytes of it.
pub async fn send_file(file: File, info: FileInfo, tx: ReadSender) {
    let size = info.size;
    let path = info.path.clone();
    let chunk = |part| Ok(ReadChunk { chunk: Some(part) });
    if tx.send(chunk(ReadPart::Info(info))).await.is_err() {
        return;
    }
    let mut file = tokio::fs::File::from_std(file).take(size);
    let mut buf = vec![0; CHUNK];
    loop {
        match file.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => {
                if tx
                    .send(chunk(ReadPart::Data(buf[..n].to_vec())))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _ = tx.send(Err(status(Path::new(&path), &error))).await;
                return;
            }
        }
    }
}

/// Writes to a temporary file next to the target and renames it into place
/// once the stream commits.
pub async fn write(mut stream: Streaming<WriteChunk>) -> Result<FileInfo, Status> {
    let header = match stream.message().await?.and_then(|c| c.chunk) {
        Some(WritePart::Header(header)) => header,
        _ => return Err(Status::invalid_argument("first message must be a header")),
    };
    let (path, user) = (resolve(&header.path)?, user(&header.user)?);
    let name = path
        .file_name()
        .ok_or_else(|| Status::invalid_argument("path does not name a file"))?
        .to_string_lossy()
        .into_owned();
    let temp = path.with_file_name(format!(".{name}.spawn-{}", unique()));

    let file = {
        let temp = temp.clone();
        as_user(user.clone(), path.clone(), move |path| {
            let mode = match fs::metadata(path) {
                Ok(meta) if meta.is_dir() => {
                    return Err(io::Error::new(
                        io::ErrorKind::IsADirectory,
                        "is a directory",
                    ));
                }
                Ok(meta) => meta.mode() & 0o7777,
                Err(error) if error.kind() == io::ErrorKind::NotFound => 0o644,
                Err(error) => return Err(error),
            };
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&temp)
        })
        .await?
    };
    // Also removes the partial file when the host cancels the upload, which
    // drops this future at an await.
    let _guard = TempFile(temp.clone());

    let mut file = tokio::fs::File::from_std(file);
    let copied: Result<(), Status> = async {
        loop {
            let Some(message) = stream.message().await? else {
                return Err(Status::aborted("upload ended without a commit"));
            };
            match message.chunk {
                Some(WritePart::Data(data)) => {
                    file.write_all(&data).await.map_err(|e| status(&path, &e))?
                }
                Some(WritePart::Commit(true)) => break,
                Some(WritePart::Commit(false)) | None => {}
                Some(WritePart::Header(_)) => {
                    return Err(Status::invalid_argument(
                        "only the first message is a header",
                    ));
                }
            }
        }
        file.flush().await.map_err(|e| status(&path, &e))
    }
    .await;
    drop(file);
    copied?;
    // After the rename the guard's unlink finds nothing.
    as_user(user, path, move |path| {
        fs::rename(&temp, path)?;
        Ok(info(display(path), &fs::metadata(path)?))
    })
    .await
}

struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub async fn list(path: &str, user_name: &str) -> Result<ListResponse, Status> {
    let (path, user) = (resolve(path)?, user(user_name)?);
    as_user(user, path, |path| {
        let mut entries = Vec::new();
        let mut truncated = false;
        for entry in fs::read_dir(path)? {
            if entries.len() == MAX_ENTRIES {
                truncated = true;
                break;
            }
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // An entry removed while listing is skipped.
            if let Ok(meta) = entry.metadata() {
                entries.push(info(name, &meta));
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(ListResponse {
            path: display(path),
            entries,
            truncated,
        })
    })
    .await
}

pub async fn remove(path: &str, user_name: &str, recursive: bool) -> Result<(), Status> {
    let (path, user) = (resolve(path)?, user(user_name)?);
    as_user(user, path, move |path| {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir() {
            fs::remove_file(path)
        } else if recursive {
            fs::remove_dir_all(path)
        } else {
            fs::remove_dir(path)
        }
    })
    .await
}

/// Flushes and freezes the writable disk. Writes to it block from now on.
pub async fn seal() -> Result<(), Status> {
    tokio::task::spawn_blocking(|| {
        nix::unistd::sync();
        // Under gVisor the host unmounts the layer after the container stops.
        if crate::under_gvisor() {
            return Ok(());
        }
        let dir = File::open(UPPER_MOUNT)?;
        // SAFETY: `dir` is an open descriptor for the whole call, and
        // FIFREEZE takes no pointer argument (the third value is unused).
        let result = unsafe { libc::ioctl(dir.as_raw_fd(), FIFREEZE as libc::Ioctl, 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })
    .await
    .map_err(|error| Status::internal(format!("seal task failed: {error}")))?
    .map_err(|error| Status::internal(format!("freeze {UPPER_MOUNT}: {error}")))
}

/// Unique enough for a temporary file name; `create_new` catches the rest.
fn unique() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("{nanos:x}{:x}", COUNTER.fetch_add(1, Ordering::Relaxed))
}
