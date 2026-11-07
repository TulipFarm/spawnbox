//! Persistent volumes: ext4 files that outlive sandboxes.
//!
//! A VM always has eight volume disks after its upper disk: four read-write
//! (vdc to vdf) and four read-only (vdg to vdj). Unused ones are tiny
//! placeholder files. The host attaches a volume by pointing a disk at the
//! volume's file, so a VM restored from a snapshot can take any volume.
//!
//! A gVisor container always has four bind mounts, `/spawn/vol/<slot>`. The
//! host loop-mounts a volume on a slot's source directory before the
//! container starts.

use std::os::unix::fs::{PermissionsExt, chown};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::firecracker::{self, Jail};
use crate::sh::run;

/// Volumes per sandbox.
pub const SLOTS: u32 = 4;
/// The guest's `user`, who owns a new volume's root directory.
const GUEST_USER: &str = "1000:1000";
const PLACEHOLDER_BYTES: u64 = 1 << 20;

/// A volume to attach to a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attach {
    /// 0 to `SLOTS - 1`, unique in a sandbox.
    pub slot: u32,
    pub file: PathBuf,
    pub read_only: bool,
}

impl Attach {
    /// Firecracker's ID for the slot's disk.
    fn drive_id(&self) -> String {
        drive_id(self.slot, self.read_only)
    }

    /// The volume's link in a jail.
    fn jail_name(&self) -> String {
        format!("volume-{}.ext4", self.drive_id())
    }
}

fn drive_id(slot: u32, read_only: bool) -> String {
    if read_only {
        format!("ro{slot}")
    } else {
        format!("vol{slot}")
    }
}

/// Checks slots before anything starts.
pub fn check(volumes: &[Attach]) -> Result<()> {
    for (i, volume) in volumes.iter().enumerate() {
        if volume.slot >= SLOTS {
            bail!("volume slot {} is not below {SLOTS}", volume.slot);
        }
        if volumes[..i].iter().any(|v| v.slot == volume.slot) {
            bail!("volume slot {} is used twice", volume.slot);
        }
    }
    Ok(())
}

/// Creates an empty ext4 volume of `gib` GiB at `path`. Holes stay holes,
/// so it uses little space until written.
pub async fn create(path: &Path, gib: u32) -> Result<()> {
    let disk = path.to_str().context("volume path")?;
    run("truncate", &["-s", &format!("{gib}G"), disk]).await?;
    let made = run(
        "mkfs.ext4",
        &[
            "-q",
            "-F",
            "-m",
            "0",
            "-L",
            "volume",
            "-E",
            &format!("root_owner={GUEST_USER}"),
            disk,
        ],
    )
    .await;
    if let Err(error) = made {
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    // A read-only VM opens it as its own unprivileged user. Only jails and
    // root reach the volumes directory.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    Ok(())
}

/// The VM disks for volumes, in the guest's order: read-write, then
/// read-only. Each is `(drive ID, file in the jail, read-only)`.
pub(crate) fn vm_drives() -> impl Iterator<Item = (String, String, bool)> {
    [false, true].into_iter().flat_map(|read_only| {
        (0..SLOTS).map(move |slot| {
            let id = drive_id(slot, read_only);
            let file = format!("{id}.ext4");
            (id, file, read_only)
        })
    })
}

/// Creates the placeholder files for every volume disk in a new jail.
pub(crate) fn add_placeholders(jail: &Jail) -> Result<()> {
    for (_, name, read_only) in vm_drives() {
        let file = std::fs::File::create(jail.root().join(&name))?;
        file.set_len(PLACEHOLDER_BYTES)?;
        if !read_only {
            jail.give(&name)?;
        }
    }
    Ok(())
}

/// Puts the volumes in place of their placeholders in a new jail, for a
/// fresh boot.
pub(crate) fn link_for_boot(jail: &Jail, volumes: &[Attach]) -> Result<()> {
    check(volumes)?;
    for volume in volumes {
        let name = format!("{}.ext4", volume.drive_id());
        let dest = jail.root().join(&name);
        std::fs::remove_file(&dest)?;
        std::fs::hard_link(&volume.file, &dest)
            .with_context(|| format!("link volume {}", volume.file.display()))?;
        if !volume.read_only {
            jail.give(&name)?;
        }
    }
    Ok(())
}

/// Links the volumes into a jail, before the VM starts or while it runs.
pub(crate) fn link(root: &Path, uid: u32, volumes: &[Attach]) -> Result<()> {
    for volume in volumes {
        let dest = root.join(volume.jail_name());
        std::fs::hard_link(&volume.file, &dest)
            .with_context(|| format!("link volume {}", volume.file.display()))?;
        if !volume.read_only {
            chown(&dest, Some(uid), Some(uid))?;
        }
    }
    Ok(())
}

/// Points the volume disks of a running or loaded VM at the linked volumes.
/// The guest then sees each disk change size.
pub(crate) async fn swap_in(vm: &firecracker::Vm, volumes: &[Attach]) -> Result<()> {
    for volume in volumes {
        let id = volume.drive_id();
        vm.patch(
            &format!("/drives/{id}"),
            json!({ "drive_id": id, "path_on_host": format!("/{}", volume.jail_name()) }),
        )
        .await
        .with_context(|| format!("attach volume to {id}"))?;
    }
    Ok(())
}

/// The bundle directory that a gVisor slot binds.
pub(crate) fn bundle_dir(bundle: &Path, slot: u32) -> PathBuf {
    bundle.join(format!("vol{slot}"))
}

/// Loop-mounts volumes on their slots in a gVisor bundle.
pub(crate) async fn mount_in_bundle(bundle: &Path, volumes: &[Attach]) -> Result<()> {
    for volume in volumes {
        // A read-only volume cannot replay its journal. `noinit_itable`
        // stops the kernel from writing every inode table, which would
        // fill the sparse file.
        let options = if volume.read_only {
            "loop,ro,noload"
        } else {
            "loop,noatime,noinit_itable"
        };
        let (disk, target) = (
            volume.file.to_str().context("volume path")?,
            bundle_dir(bundle, volume.slot),
        );
        run(
            "mount",
            &[
                "-t",
                "ext4",
                "-o",
                options,
                disk,
                target.to_str().context("bundle path")?,
            ],
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attach(slot: u32) -> Attach {
        Attach {
            slot,
            file: PathBuf::from("/v"),
            read_only: false,
        }
    }

    #[test]
    fn checks_slots() {
        assert!(check(&[attach(0), attach(3)]).is_ok());
        assert!(check(&[attach(4)]).is_err());
        assert!(check(&[attach(1), attach(1)]).is_err());
    }

    #[test]
    fn vm_drive_order_matches_the_guest() {
        let ids: Vec<_> = vm_drives().map(|(id, _, _)| id).collect();
        assert_eq!(
            ids,
            ["vol0", "vol1", "vol2", "vol3", "ro0", "ro1", "ro2", "ro3"]
        );
    }
}
