//! Persistent volumes.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::mount::{MsFlags, mount};
use spawn_proto::guest::v1::VolumeMount;
use tonic::Status;

/// The VM disk for a volume slot. The host attaches the read-write slots
/// as vdc to vdf and the read-only slots as vdg to vdj.
fn disk(slot: u32, read_only: bool) -> Option<PathBuf> {
    let first = if read_only { b'g' } else { b'c' };
    let letter = first.checked_add(u8::try_from(slot).ok().filter(|s| *s < 4)?)?;
    Some(PathBuf::from(format!("/dev/vd{}", char::from(letter))))
}

/// How long a VM waits for the host to swap a volume in.
const SWAP_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn mount_all(volumes: Vec<VolumeMount>) -> Result<(), Status> {
    let gvisor = crate::under_gvisor();
    for volume in volumes {
        let path = check_path(&volume.path)?;
        std::fs::create_dir_all(path)
            .map_err(|e| Status::internal(format!("create {}: {e}", volume.path)))?;
        if gvisor {
            bind(&volume, path)?;
        } else {
            mount_disk(&volume, path).await?;
        }
    }
    Ok(())
}

fn check_path(path: &str) -> Result<&Path, Status> {
    let p = Path::new(path);
    if !p.is_absolute() || p.parent().is_none() {
        return Err(Status::invalid_argument(format!(
            "volume path {path:?} must be absolute and not /"
        )));
    }
    Ok(p)
}

fn bind(volume: &VolumeMount, path: &Path) -> Result<(), Status> {
    let source = format!("/spawn/vol/{}", volume.slot);
    let none = None::<&str>;
    mount(Some(source.as_str()), path, none, MsFlags::MS_BIND, none)
        .map_err(|e| Status::internal(format!("bind {source} at {}: {e}", volume.path)))?;
    if volume.read_only {
        let flags = MsFlags::MS_REMOUNT
            .union(MsFlags::MS_BIND)
            .union(MsFlags::MS_RDONLY);
        mount(none, path, none, flags, none)
            .map_err(|e| Status::internal(format!("make {} read-only: {e}", volume.path)))?;
    }
    Ok(())
}

async fn mount_disk(volume: &VolumeMount, path: &Path) -> Result<(), Status> {
    let id = format!("slot {}", volume.slot);
    let disk = disk(volume.slot, volume.read_only)
        .ok_or_else(|| Status::invalid_argument(format!("no volume {id}")))?;
    let name = disk.file_name().unwrap_or_default().to_owned();
    let size = Path::new("/sys/block").join(name).join("size");
    let began = Instant::now();
    loop {
        let sectors: u64 = std::fs::read_to_string(&size)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        if sectors * 512 == volume.size_bytes {
            break;
        }
        if began.elapsed() > SWAP_TIMEOUT {
            return Err(Status::internal(format!(
                "volume {id} has {sectors} sectors, not {} bytes",
                volume.size_bytes
            )));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // A read-only disk cannot replay a journal. `noinit_itable` stops a
    // background thread from writing the whole disk, which would fill the
    // host's sparse file.
    let (flags, data) = if volume.read_only {
        (MsFlags::MS_RDONLY.union(MsFlags::MS_NOATIME), "noload")
    } else {
        (MsFlags::MS_NOATIME, "noinit_itable")
    };
    mount(Some(&disk), path, Some("ext4"), flags, Some(data))
        .map_err(|e| Status::internal(format!("mount volume {id} at {}: {e}", volume.path)))
}
