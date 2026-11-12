//! Whether the disk under a directory is encrypted, from `/proc` and
//! `/sys`.

#[cfg(test)]
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::Outcome;

/// What the doctor reads of the host's `/proc`, `/sys` and `/dev`.
pub trait Host {
    fn read(&self, path: &str) -> Option<String>;
    fn list(&self, dir: &str) -> Vec<String>;
    fn link(&self, path: &str) -> Option<String>;
}

#[cfg(target_os = "linux")]
pub struct SysFs;

#[cfg(target_os = "linux")]
impl Host for SysFs {
    fn read(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn list(&self, dir: &str) -> Vec<String> {
        std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect()
    }

    fn link(&self, path: &str) -> Option<String> {
        std::fs::read_link(path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
}

/// From safest to least safe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Disk {
    Crypt(String),
    /// AWS encrypts instance store NVMe volumes in hardware.
    InstanceStore(String),
    /// Whether an EBS volume is encrypted cannot be seen from the instance.
    Ebs(String),
    Unknown(String),
    Plain(String),
}

const EBS_MODEL: &str = "Amazon Elastic Block Store";
const INSTANCE_STORE_MODEL: &str = "Amazon EC2 NVMe Instance Storage";

pub fn encryption(host: &dyn Host, mountinfo: &str, data_dir: &Path, path: &Path) -> Outcome {
    let dir = data_dir.display();
    let Some(mount) = mount_of(mountinfo, path) else {
        return Outcome::Warn(format!("cannot find the file system of {dir}"));
    };
    let name = if mount.device.starts_with("0:") {
        // Not a block device itself, as for btrfs: try its source.
        mount
            .source
            .strip_prefix("/dev/")
            .map(|_| last(&host.link(&mount.source).unwrap_or(mount.source.clone())))
    } else {
        host.link(&format!("/sys/dev/block/{}", mount.device))
            .map(|l| last(&l))
    };
    let Some(name) = name else {
        return Outcome::Warn(format!(
            "{dir} is on {} ({}), whose encryption cannot be checked",
            mount.source, mount.fstype
        ));
    };
    match classify(host, &name, 0) {
        Disk::Crypt(dev) => Outcome::Pass(format!("{dir} is on dm-crypt ({dev})")),
        Disk::InstanceStore(dev) => Outcome::Pass(format!(
            "{dir} is on AWS instance store ({dev}), which AWS encrypts in hardware"
        )),
        Disk::Ebs(dev) => Outcome::Warn(format!(
            "{dir} is on an Amazon EBS volume ({dev}); whether it is encrypted cannot be \
             seen from inside the instance. Check that EBS encryption is on for it"
        )),
        Disk::Unknown(dev) => Outcome::Warn(format!(
            "cannot tell whether {dev}, which holds {dir}, is encrypted"
        )),
        Disk::Plain(dev) => Outcome::Warn(format!(
            "{dir} is on {dev}, which is not encrypted. Paused sandboxes' memory and \
             disks are stored there in plain; put {dir} on an encrypted disk, such as \
             dm-crypt with LUKS"
        )),
    }
}

/// Prefixes cryptsetup gives the device-mapper UUIDs of the formats that
/// encrypt. Its integrity and verity devices also start with `CRYPT-` but
/// do not.
const ENCRYPTING: [&str; 5] = [
    "CRYPT-LUKS1-",
    "CRYPT-LUKS2-",
    "CRYPT-PLAIN-",
    "CRYPT-TCRYPT-",
    "CRYPT-BITLK-",
];

/// `name` is under `/sys/class/block`. Encrypted if it is a dm-crypt
/// device, or every device it is built on is encrypted.
fn classify(host: &dyn Host, name: &str, depth: u8) -> Disk {
    let dir = format!("/sys/class/block/{name}");
    if host
        .read(&format!("{dir}/dm/uuid"))
        .is_some_and(|uuid| ENCRYPTING.iter().any(|p| uuid.starts_with(p)))
    {
        return Disk::Crypt(name.to_owned());
    }
    let below = host.list(&format!("{dir}/slaves"));
    if !below.is_empty() {
        if depth > 8 {
            return Disk::Unknown(name.to_owned());
        }
        return below
            .iter()
            .map(|b| classify(host, b, depth + 1))
            .max()
            .unwrap_or_else(|| Disk::Unknown(name.to_owned()));
    }
    // A partition's model is its disk's.
    let disk = if host.read(&format!("{dir}/partition")).is_some() {
        host.link(&dir)
            .and_then(|l| l.rsplit('/').nth(1).map(str::to_owned))
            .unwrap_or_else(|| name.to_owned())
    } else {
        name.to_owned()
    };
    match host
        .read(&format!("/sys/class/block/{disk}/device/model"))
        .as_deref()
        .map(str::trim)
    {
        Some(EBS_MODEL) => Disk::Ebs(name.to_owned()),
        Some(INSTANCE_STORE_MODEL) => Disk::InstanceStore(name.to_owned()),
        _ => Disk::Plain(name.to_owned()),
    }
}

fn last(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

#[derive(Debug, PartialEq, Eq)]
struct Mount {
    point: PathBuf,
    /// `major:minor`
    device: String,
    fstype: String,
    source: String,
}

/// The mount that holds `path`: the longest mount point above it, and of
/// equal ones the last, which hides the others.
fn mount_of(mountinfo: &str, path: &Path) -> Option<Mount> {
    let mut best: Option<Mount> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(dash) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        let (Some(device), Some(point), Some(fstype), Some(source)) = (
            fields.get(2),
            fields.get(4),
            fields.get(dash + 1),
            fields.get(dash + 2),
        ) else {
            continue;
        };
        let point = PathBuf::from(unescape(point));
        if !path.starts_with(&point) {
            continue;
        }
        if best
            .as_ref()
            .is_some_and(|b| b.point.as_os_str().len() > point.as_os_str().len())
        {
            continue;
        }
        best = Some(Mount {
            point,
            device: (*device).to_owned(),
            fstype: (*fstype).to_owned(),
            source: unescape(source),
        });
    }
    best
}

/// Mount info writes space, tab, newline and backslash as octal escapes.
fn unescape(field: &str) -> String {
    let mut out = String::new();
    let mut rest = field;
    while let Some(i) = rest.find('\\') {
        out.push_str(&rest[..i]);
        let code = rest
            .get(i + 1..i + 4)
            .and_then(|o| u8::from_str_radix(o, 8).ok());
        match code {
            Some(byte) => {
                out.push(char::from(byte));
                rest = &rest[i + 4..];
            }
            None => {
                out.push('\\');
                rest = &rest[i + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A host for tests: files and links by path.
#[cfg(test)]
#[derive(Default)]
struct FakeHost {
    files: HashMap<String, String>,
    links: HashMap<String, String>,
}

#[cfg(test)]
impl Host for FakeHost {
    fn read(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }

    fn list(&self, dir: &str) -> Vec<String> {
        let prefix = format!("{dir}/");
        self.files
            .keys()
            .chain(self.links.keys())
            .filter_map(|p| p.strip_prefix(&prefix))
            .filter(|rest| !rest.contains('/'))
            .map(str::to_owned)
            .collect()
    }

    fn link(&self, path: &str) -> Option<String> {
        self.links.get(path).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p1 rw
30 22 0:25 / /proc rw - proc proc rw
40 22 253:1 / /var/lib/spawn\\040box rw,relatime shared:5 - ext4 /dev/mapper/vg-data rw
41 22 0:40 / /srv rw - btrfs /dev/mapper/secure rw
42 22 0:41 / /scratch rw - tmpfs tmpfs rw
";

    fn host(links: &[(&str, &str)], files: &[(&str, &str)]) -> FakeHost {
        FakeHost {
            files: files
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            links: links
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn check(host: &FakeHost, path: &str) -> Outcome {
        encryption(host, MOUNTINFO, Path::new(path), Path::new(path))
    }

    #[test]
    fn finds_the_mount_that_holds_a_path() {
        let mount = mount_of(MOUNTINFO, Path::new("/var/lib/spawn box/db")).unwrap();
        assert_eq!(mount.point, Path::new("/var/lib/spawn box"));
        assert_eq!(mount.device, "253:1");
        let root = mount_of(MOUNTINFO, Path::new("/var/lib/spawnbox")).unwrap();
        assert_eq!(root.device, "259:2");
    }

    #[test]
    fn passes_dm_crypt_also_below_lvm() {
        let host = host(
            &[("/sys/dev/block/253:1", "../../devices/virtual/block/dm-1")],
            &[
                ("/sys/class/block/dm-1/dm/uuid", "LVM-abc\n"),
                ("/sys/class/block/dm-1/slaves/dm-0", ""),
                ("/sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc-luks\n"),
            ],
        );
        assert_eq!(
            check(&host, "/var/lib/spawn box"),
            Outcome::Pass("/var/lib/spawn box is on dm-crypt (dm-0)".to_owned())
        );
    }

    #[test]
    fn warns_for_a_plain_disk() {
        let host = host(
            &[(
                "/sys/dev/block/259:2",
                "../../devices/pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p1",
            )],
            &[("/sys/class/block/nvme0n1/device/model", "Samsung SSD\n")],
        );
        let Outcome::Warn(detail) = check(&host, "/var/lib/spawnbox") else {
            panic!("not a warning");
        };
        assert!(
            detail.contains("nvme0n1p1, which is not encrypted"),
            "{detail}"
        );
    }

    #[test]
    fn says_ebs_encryption_cannot_be_seen() {
        let device = "../../devices/pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p1";
        let host = host(
            &[
                ("/sys/dev/block/259:2", device),
                ("/sys/class/block/nvme0n1p1", device),
            ],
            &[
                ("/sys/class/block/nvme0n1p1/partition", "1\n"),
                (
                    "/sys/class/block/nvme0n1/device/model",
                    "Amazon Elastic Block Store              \n",
                ),
            ],
        );
        let Outcome::Warn(detail) = check(&host, "/var/lib/spawnbox") else {
            panic!("not a warning");
        };
        assert!(detail.contains("cannot be seen from inside"), "{detail}");
    }

    #[test]
    fn a_mix_of_encrypted_and_plain_is_plain() {
        let host = host(
            &[("/sys/dev/block/253:1", "../dm-1")],
            &[
                ("/sys/class/block/dm-1/slaves/dm-0", ""),
                ("/sys/class/block/dm-1/slaves/sdb", ""),
                ("/sys/class/block/dm-0/dm/uuid", "CRYPT-PLAIN-x"),
            ],
        );
        let Outcome::Warn(detail) = check(&host, "/var/lib/spawn box") else {
            panic!("not a warning");
        };
        assert!(detail.contains("sdb, which is not encrypted"), "{detail}");
    }

    #[test]
    fn integrity_and_verity_devices_are_not_encryption() {
        for uuid in ["CRYPT-INTEGRITY-x", "CRYPT-VERITY-x"] {
            let plain = host(
                &[("/sys/dev/block/253:1", "../dm-1")],
                &[
                    ("/sys/class/block/dm-1/dm/uuid", uuid),
                    ("/sys/class/block/dm-1/slaves/sdb", ""),
                ],
            );
            let Outcome::Warn(detail) = check(&plain, "/var/lib/spawn box") else {
                panic!("{uuid} passed");
            };
            assert!(detail.contains("sdb, which is not encrypted"), "{detail}");
            let over_luks = host(
                &[("/sys/dev/block/253:1", "../dm-1")],
                &[
                    ("/sys/class/block/dm-1/dm/uuid", uuid),
                    ("/sys/class/block/dm-1/slaves/dm-0", ""),
                    ("/sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS1-x"),
                ],
            );
            assert_eq!(
                check(&over_luks, "/var/lib/spawn box"),
                Outcome::Pass("/var/lib/spawn box is on dm-crypt (dm-0)".to_owned())
            );
        }
    }

    #[test]
    fn follows_the_source_of_a_file_system_without_a_device() {
        let host = host(
            &[("/dev/mapper/secure", "../dm-3")],
            &[("/sys/class/block/dm-3/dm/uuid", "CRYPT-LUKS2-x")],
        );
        assert!(matches!(check(&host, "/srv/spawnbox"), Outcome::Pass(_)));
        let Outcome::Warn(detail) = check(&host, "/scratch") else {
            panic!("not a warning");
        };
        assert!(detail.contains("tmpfs"), "{detail}");
    }
}
