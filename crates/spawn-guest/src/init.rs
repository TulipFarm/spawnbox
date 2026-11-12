use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Duration;

use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::unistd::{chdir, pivot_root};

use crate::reaper::Reaper;
use crate::supervisor::{self, Supervisor};

/// Where the writable disk stays mounted after the switch to the overlay.
pub const UPPER_MOUNT: &str = "/spawn/upper";

pub const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

struct Mount {
    target: &'static str,
    fstype: &'static str,
    flags: MsFlags,
    data: &'static str,
}

const DEV: Mount = Mount {
    target: "/dev",
    fstype: "devtmpfs",
    flags: MsFlags::MS_NOSUID,
    data: "mode=0755",
};

/// Writable layer for the root filesystem. Without it the guest keeps the
/// upper layer in memory. The host attaches disks in a fixed order; see
/// `spawn_node::node::Node::boot`.
const UPPER_DISK: &str = "/dev/vdb";
/// Read-only layer from a template build, between the base disk and the
/// writable layer. Only templates with setup steps have one. It comes after
/// the volume disks.
const LAYER_DISK: &str = "/dev/vdk";

/// Mounted after the root overlay is in place.
const MOUNTS: &[Mount] = &[
    Mount {
        target: "/proc",
        fstype: "proc",
        flags: MsFlags::MS_NOSUID
            .union(MsFlags::MS_NODEV)
            .union(MsFlags::MS_NOEXEC),
        data: "",
    },
    Mount {
        target: "/sys",
        fstype: "sysfs",
        flags: MsFlags::MS_NOSUID
            .union(MsFlags::MS_NODEV)
            .union(MsFlags::MS_NOEXEC),
        data: "",
    },
    Mount {
        target: "/sys/fs/cgroup",
        fstype: "cgroup2",
        flags: MsFlags::MS_NOSUID
            .union(MsFlags::MS_NODEV)
            .union(MsFlags::MS_NOEXEC),
        data: "",
    },
    Mount {
        target: "/dev/pts",
        fstype: "devpts",
        flags: MsFlags::MS_NOSUID.union(MsFlags::MS_NOEXEC),
        data: "newinstance,ptmxmode=0666,mode=0620,gid=5",
    },
    // Chromium crashes with a small /dev/shm.
    Mount {
        target: "/dev/shm",
        fstype: "tmpfs",
        flags: MsFlags::MS_NOSUID.union(MsFlags::MS_NODEV),
        data: "mode=1777,size=1g",
    },
    Mount {
        target: "/run",
        fstype: "tmpfs",
        flags: MsFlags::MS_NOSUID.union(MsFlags::MS_NODEV),
        data: "mode=0755",
    },
    Mount {
        target: "/tmp",
        fstype: "tmpfs",
        flags: MsFlags::MS_NOSUID.union(MsFlags::MS_NODEV),
        data: "mode=1777",
    },
];

pub fn run() -> ExitCode {
    let gvisor = crate::under_gvisor();
    if !gvisor {
        prepare_vm();
    }

    // Reaps every orphan, and tells the agent's and the services' starters
    // when their children exit.
    let reaper = Reaper::pid1();
    start_supervisor(&reaper);

    loop {
        let mut agent = Command::new("/proc/self/exe");
        agent.arg(crate::AGENT_FLAG).env_clear();
        if gvisor {
            agent.env(crate::BACKEND_ENV, "gvisor");
        }
        agent
            .env("PATH", PATH)
            .env("HOME", "/root")
            .env("LANG", "C.UTF-8")
            .current_dir("/");
        let (exited, exit) = std::sync::mpsc::channel();
        if let Err(error) = reaper.spawn(agent, move |_| {
            let _ = exited.send(());
        }) {
            eprintln!("spawn-guest: cannot start agent: {error}");
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let _ = exit.recv();
        eprintln!("spawn-guest: agent exited; restarting");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Runs the services' supervisor on its own thread, so it outlives the
/// agent.
fn start_supervisor(reaper: &std::sync::Arc<Reaper>) {
    let supervisor = Supervisor::new(supervisor::Config::vm(), std::sync::Arc::clone(reaper));
    let started = std::thread::Builder::new()
        .name("services".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("spawn-guest: cannot start the services runtime: {error}");
                    return;
                }
            };
            if let Err(error) =
                runtime.block_on(supervisor::serve(supervisor, Path::new(supervisor::SOCKET)))
            {
                eprintln!("spawn-guest: services stopped: {error}");
            }
        });
    if let Err(error) = started {
        eprintln!("spawn-guest: cannot start the services thread: {error}");
    }
}

/// Mounts `/dev`, the root overlay and the rest. Under gVisor, runsc and the
/// OCI bundle do this.
fn prepare_vm() {
    if let Err(error) = mount_one(&DEV) {
        eprintln!("spawn-guest: mount /dev failed: {error}");
    }
    if let Err(error) = overlay_root() {
        eprintln!("spawn-guest: overlay root failed, root stays read-only: {error}");
    }
    for m in MOUNTS {
        if let Err(error) = mount_one(m) {
            eprintln!("spawn-guest: mount {} failed: {error}", m.target);
        }
    }
    if let Err(error) = link_dev(Path::new("/dev")) {
        eprintln!("spawn-guest: /dev links failed: {error}");
    }
}

/// devtmpfs lacks the links that udev or systemd would add. Bash process
/// substitution, `<(...)`, needs `/dev/fd`.
const DEV_LINKS: &[(&str, &str)] = &[
    ("fd", "/proc/self/fd"),
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
    ("core", "/proc/kcore"),
];

fn link_dev(dev: &Path) -> std::io::Result<()> {
    for (name, target) in DEV_LINKS {
        match std::os::unix::fs::symlink(target, dev.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            result => result?,
        }
    }
    Ok(())
}

/// Makes `/` writable: the read-only base disk is the lower layer and the
/// upper disk holds every change. Then switches the root to the overlay.
fn overlay_root() -> nix::Result<()> {
    let none = None::<&str>;
    if Path::new(UPPER_DISK).exists() {
        // `noinit_itable` stops a background thread from writing to the
        // whole disk, which would make every clone's disk copy large.
        mount(
            Some(UPPER_DISK),
            "/spawn/upper",
            Some("ext4"),
            MsFlags::MS_NOATIME,
            Some("noinit_itable"),
        )?;
    } else {
        mount(
            Some("tmpfs"),
            "/spawn/upper",
            Some("tmpfs"),
            MsFlags::empty(),
            Some("mode=0755"),
        )?;
    }
    for dir in ["/spawn/upper/root", "/spawn/upper/work"] {
        std::fs::create_dir_all(dir).map_err(io_errno)?;
    }
    // Only root may look at the raw layers once they are visible again.
    std::fs::set_permissions("/spawn/upper", std::fs::Permissions::from_mode(0o700))
        .map_err(io_errno)?;
    let mut lower = "/";
    if Path::new(LAYER_DISK).exists() {
        // The layer was frozen clean, so there is no journal to replay.
        mount(
            Some(LAYER_DISK),
            "/spawn/layer",
            Some("ext4"),
            MsFlags::MS_RDONLY.union(MsFlags::MS_NOATIME),
            Some("noload"),
        )?;
        lower = "/spawn/layer/root:/";
    }
    let options = format!("lowerdir={lower},upperdir=/spawn/upper/root,workdir=/spawn/upper/work");
    mount(
        Some("overlay"),
        "/spawn/newroot",
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    )?;
    mount(
        Some("/dev"),
        "/spawn/newroot/dev",
        none,
        MsFlags::MS_MOVE,
        none,
    )?;
    pivot_root("/spawn/newroot", "/spawn/newroot/spawn/oldroot")?;
    chdir("/")?;
    // The agent freezes the writable disk here when a template build ends.
    mount(
        Some("/spawn/oldroot/spawn/upper"),
        UPPER_MOUNT,
        none,
        MsFlags::MS_MOVE,
        none,
    )?;
    umount2("/spawn/oldroot", MntFlags::MNT_DETACH)
}

fn io_errno(error: std::io::Error) -> Errno {
    Errno::from_raw(error.raw_os_error().unwrap_or(0))
}

fn mount_one(m: &Mount) -> nix::Result<()> {
    if !Path::new(m.target).exists() {
        std::fs::create_dir_all(m.target).map_err(io_errno)?;
    }
    let data = (!m.data.is_empty()).then_some(m.data);
    match mount(Some(m.fstype), m.target, Some(m.fstype), m.flags, data) {
        // The kernel may mount devtmpfs itself.
        Err(Errno::EBUSY) => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_dev_and_keeps_existing_entries() {
        let dev = std::env::temp_dir().join(format!("spawn-init-dev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dev);
        std::fs::create_dir_all(&dev).unwrap();
        std::os::unix::fs::symlink("/elsewhere", dev.join("stdin")).unwrap();

        link_dev(&dev).unwrap();
        link_dev(&dev).unwrap();

        assert_eq!(
            std::fs::read_link(dev.join("fd")).unwrap(),
            Path::new("/proc/self/fd")
        );
        assert_eq!(
            std::fs::read_link(dev.join("stderr")).unwrap(),
            Path::new("/proc/self/fd/2")
        );
        assert_eq!(
            std::fs::read_link(dev.join("stdin")).unwrap(),
            Path::new("/elsewhere")
        );
        std::fs::remove_dir_all(&dev).unwrap();
    }
}
