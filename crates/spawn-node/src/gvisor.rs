//! Runs guests in gVisor (`runsc`) containers, for hosts without KVM.
//!
//! Each container gets a bundle directory with links to its disks. The base
//! disk and the template layer are loop-mounted read-only and joined with
//! overlayfs; gVisor keeps the guest's writes in its own overlay, which is
//! part of every checkpoint.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tokio::process::Command;

use crate::firecracker::{CGROUP_PARENT, CGROUP_ROOT, Host, Limits};
use crate::guest::Dialer;
use crate::net::Netns;
use crate::sh::run;
use crate::volume::{self, Attach};

const GUEST_INIT: &str = "/usr/local/bin/spawn-guest";
const GUEST_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// The guest has root's usual powers inside the sandbox, as in a VM.
const CAPS: &[&str] = &[
    "CAP_AUDIT_WRITE",
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_IPC_LOCK",
    "CAP_KILL",
    "CAP_LEASE",
    "CAP_MKNOD",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_RAW",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_CHROOT",
    "CAP_SYS_NICE",
    "CAP_SYS_PTRACE",
    "CAP_SYS_RESOURCE",
];

/// The `runsc` binary and its working directory.
#[derive(Clone)]
pub struct Runsc {
    pub bin: PathBuf,
    /// Container state in `state/`, bundles in `run/<id>/`.
    pub dir: PathBuf,
}

impl Runsc {
    fn state(&self) -> PathBuf {
        self.dir.join("state")
    }

    fn bundle(&self, id: &str) -> PathBuf {
        self.dir.join("run").join(id)
    }

    pub fn setup(&self) -> Result<()> {
        for dir in [self.state(), self.dir.join("run")] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .with_context(|| format!("create {}", dir.display()))?;
        }
        Ok(())
    }

    /// Deletes every container, including ones left by a crashed run, and
    /// removes their bundles.
    pub async fn remove_all(&self) {
        if self.state().exists()
            && let Ok(list) = self.cmd(&["list", "-quiet"]).await
        {
            for id in list.split_whitespace() {
                let _ = self.cmd(&["delete", "-force", id]).await;
            }
        }
        unmount_under(&self.dir).await;
        for dir in [self.state(), self.dir.join("run")] {
            if let Err(error) = std::fs::remove_dir_all(&dir)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("warning: remove {}: {error}", dir.display());
            }
        }
    }

    /// Removes the container and bundle that a failed start left for `id`.
    pub async fn remove(&self, id: &str) {
        let _ = self.cmd(&["delete", "-force", id]).await;
        remove_bundle(&self.bundle(id)).await;
        remove_cgroup(id);
    }

    /// Runs a runsc command that ends on its own.
    async fn cmd(&self, args: &[&str]) -> Result<String> {
        let state = self.state();
        let mut all = vec!["--root", state.to_str().context("state path")?];
        all.extend_from_slice(args);
        run(self.bin.to_str().context("runsc path")?, &all).await
    }
}

/// The guest's root filesystem.
pub enum Root<'a> {
    /// Read-only disks; writes go to gVisor's overlay.
    Image {
        rootfs: &'a Path,
        layer: Option<&'a Path>,
    },
    /// Writes go through to the empty disk `layer`, which becomes a
    /// template's layer.
    Setup { rootfs: &'a Path, layer: &'a Path },
}

/// How a container starts.
pub enum Start<'a> {
    /// A fresh boot. `disk_gib` limits gVisor's overlay.
    Boot { disk_gib: u32 },
    /// From the checkpoint files in `image`.
    Restore { image: &'a Path },
}

pub struct Container {
    runsc: Runsc,
    id: String,
    bundle: PathBuf,
    net: Netns,
    filestore: Option<PathBuf>,
    /// The sandbox process, if found: its PID and start time.
    process: Option<(u32, String)>,
}

impl Container {
    /// Starts container `id` in `net`. On error, call `Runsc::remove`.
    #[expect(clippy::too_many_arguments)]
    pub async fn start(
        runsc: &Runsc,
        host: &Host,
        id: &str,
        root: Root<'_>,
        start: Start<'_>,
        net: Netns,
        limits: &Limits,
        volumes: &[Attach],
    ) -> Result<Self> {
        let bundle = runsc.bundle(id);
        let setup = matches!(root, Root::Setup { .. });
        let root_dir = prepare_bundle(&bundle, root).await?;
        volume::mount_in_bundle(&bundle, volumes).await?;
        let guest_ns = net.guest_path().context("network has no guest namespace")?;
        let config = config(id, &bundle, root_dir, &guest_ns, limits);
        std::fs::write(bundle.join("config.json"), config.to_string())?;

        let overlay = bundle.join("fs");
        let overlay = overlay.to_str().context("bundle path")?;
        let overlay = match (&start, setup) {
            (_, true) => "none".to_owned(),
            (Start::Boot { disk_gib }, false) => format!("root:dir={overlay},size={disk_gib}g"),
            // The size is part of the checkpoint.
            (Start::Restore { .. }, false) => format!("root:dir={overlay}"),
        };
        let mut cmd = Command::new(&runsc.bin);
        cmd.arg("--root")
            .arg(runsc.state())
            .arg(format!("--overlay2={overlay}"));
        match start {
            Start::Boot { .. } => cmd.arg("run"),
            Start::Restore { image } => cmd.arg("restore").arg("--image-path").arg(image),
        };
        // The container keeps runsc's output files: its log.
        let log = std::fs::File::create(host.logs.join(format!("{id}.log")))?;
        let status = cmd
            .arg("--bundle")
            .arg(&bundle)
            .args(["--detach", id])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .status()
            .await
            .context("start runsc")?;
        if !status.success() {
            bail!("runsc exited with {status}; see logs/{id}.log");
        }
        let mut container = Self {
            runsc: runsc.clone(),
            id: id.to_owned(),
            bundle,
            net,
            filestore: None,
            process: None,
        };
        if let Some(pid) = container.sandbox_pid().await {
            container.process = start_time(pid).map(|started| (pid, started));
            container.filestore = container.find_filestore(pid);
        }
        Ok(container)
    }

    async fn sandbox_pid(&self) -> Option<u32> {
        let state = self.runsc.cmd(&["state", &self.id]).await.ok()?;
        let pid = serde_json::from_str::<Value>(&state).ok()?["pid"].as_u64()?;
        u32::try_from(pid).ok()
    }

    /// Whether the sandbox process ended without `stop`. A new process
    /// with the same PID has another start time.
    pub fn exited(&self) -> Option<String> {
        let (pid, started) = self.process.as_ref()?;
        (start_time(*pid).as_ref() != Some(started))
            .then(|| "the gVisor sandbox process exited".to_owned())
    }

    /// gVisor keeps the guest's writes in a deleted file in `fs/`. Its
    /// sandbox process holds it open, so `/proc/<pid>/fd/<n>` reaches it.
    fn find_filestore(&self, pid: u32) -> Option<PathBuf> {
        let prefix = self.bundle.join("fs").join("runsc-filestore-");
        let prefix = prefix.to_str()?;
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .find(|fd| {
                std::fs::read_link(fd)
                    .is_ok_and(|target| target.to_str().is_some_and(|t| t.starts_with(prefix)))
            })
    }

    /// The guest's writable layer while it runs, if found.
    pub fn filestore(&self) -> Option<&Path> {
        self.filestore.as_deref()
    }

    pub fn dialer(&self) -> Dialer {
        Dialer::Tcp(self.net.path())
    }

    pub fn host_ip(&self) -> std::net::Ipv4Addr {
        self.net.host_ip()
    }

    pub async fn set_rates(&self, send: Option<u32>, receive: Option<u32>) -> Result<()> {
        self.net.set_rates(send, receive).await
    }

    /// The container's own links to its base disk and layer.
    pub fn disks(&self) -> impl Iterator<Item = (PathBuf, &'static str)> {
        ["rootfs.ext4", "layer.ext4"]
            .into_iter()
            .map(|name| (self.bundle.join(name), name))
            .filter(|(path, _)| path.exists())
    }

    /// Saves the guest to `dir` and stops it.
    pub async fn checkpoint(&self, dir: &Path) -> Result<()> {
        let image = dir.to_str().context("checkpoint path")?;
        self.runsc
            .cmd(&["checkpoint", "--image-path", image, &self.id])
            .await?;
        Ok(())
    }

    /// Saves the guest to `dir`; it runs on.
    pub async fn checkpoint_running(&self, dir: &Path) -> Result<()> {
        let image = dir.to_str().context("checkpoint path")?;
        self.runsc
            .cmd(&[
                "checkpoint",
                "--leave-running",
                "--image-path",
                image,
                &self.id,
            ])
            .await?;
        Ok(())
    }

    pub async fn running(&self) -> bool {
        self.runsc
            .cmd(&["state", &self.id])
            .await
            .ok()
            .and_then(|out| serde_json::from_str::<Value>(&out).ok())
            .is_some_and(|state| state["status"] == "running")
    }

    /// Stops the guest's processes in memory, for a warm pool.
    pub async fn pause(&self) -> Result<()> {
        self.runsc.cmd(&["pause", &self.id]).await.map(drop)
    }

    pub async fn resume(&self) -> Result<()> {
        self.runsc.cmd(&["resume", &self.id]).await.map(drop)
    }

    /// Stops the container and removes its bundle, cgroup and network.
    pub async fn stop(self) {
        if let Err(error) = self.runsc.cmd(&["delete", "-force", &self.id]).await {
            eprintln!("warning: {error:#}");
        }
        remove_bundle(&self.bundle).await;
        remove_cgroup(&self.id);
        self.net.remove().await;
    }
}

/// Fills a new bundle: links to the disks, their mounts, and the guest's
/// root. Returns the root's directory name in the bundle.
async fn prepare_bundle(bundle: &Path, root: Root<'_>) -> Result<&'static str> {
    remove_bundle(bundle).await;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(bundle)?;
    for dir in ["base", "layer", "rootfs", "fs"] {
        std::fs::create_dir(bundle.join(dir))?;
    }
    for slot in 0..volume::SLOTS {
        std::fs::create_dir(volume::bundle_dir(bundle, slot))?;
    }
    let (rootfs, layer, writable) = match root {
        Root::Image { rootfs, layer } => (rootfs, layer, false),
        Root::Setup { rootfs, layer } => (rootfs, Some(layer), true),
    };
    // Links keep the disks while the container runs, even if a paused
    // sandbox's directory is removed after it resumes.
    link(rootfs, &bundle.join("rootfs.ext4"))?;
    mount(
        &bundle.join("rootfs.ext4"),
        &bundle.join("base"),
        "ro,noload",
    )
    .await?;
    let Some(layer) = layer else {
        return Ok("base");
    };
    link(layer, &bundle.join("layer.ext4"))?;
    let options = if writable { "noatime" } else { "ro,noload" };
    mount(&bundle.join("layer.ext4"), &bundle.join("layer"), options).await?;
    let (base, upper) = (bundle.join("base"), bundle.join("layer"));
    let overlay = if writable {
        // The same layout as the Firecracker guest's writable disk.
        for dir in ["root", "work"] {
            std::fs::create_dir_all(upper.join(dir))?;
        }
        format!(
            "lowerdir={},upperdir={}/root,workdir={}/work",
            base.display(),
            upper.display(),
            upper.display()
        )
    } else {
        format!("ro,lowerdir={}/root:{}", upper.display(), base.display())
    };
    let target = bundle.join("rootfs");
    run(
        "mount",
        &[
            "-t",
            "overlay",
            "overlay",
            "-o",
            &overlay,
            target.to_str().context("bundle path")?,
        ],
    )
    .await?;
    Ok("rootfs")
}

fn link(src: &Path, dest: &Path) -> Result<()> {
    std::fs::hard_link(src, dest)
        .with_context(|| format!("link {} to {}", src.display(), dest.display()))
}

async fn mount(disk: &Path, target: &Path, options: &str) -> Result<()> {
    let options = format!("loop,{options}");
    let (disk, target) = (
        disk.to_str().context("disk path")?,
        target.to_str().context("mount path")?,
    );
    run("mount", &["-t", "ext4", "-o", &options, disk, target])
        .await
        .map(drop)
}

/// Unmounts everything in `bundle`, which flushes a setup layer and
/// volumes, then removes it.
async fn remove_bundle(bundle: &Path) {
    if !bundle.exists() {
        return;
    }
    unmount_under(bundle).await;
    // Removing a bundle with a volume still mounted would empty the volume.
    if !mounts_under(bundle).is_empty() {
        eprintln!("warning: keep {}: it still has mounts", bundle.display());
        return;
    }
    if let Err(error) = std::fs::remove_dir_all(bundle) {
        eprintln!("warning: remove {}: {error}", bundle.display());
    }
}

/// Unmounts every mount at or below `dir`, newest first, so an overlay goes
/// before the disks under it. Loop devices are freed with their mounts.
async fn unmount_under(dir: &Path) {
    for target in mounts_under(dir).into_iter().rev() {
        if run("umount", &[&target]).await.is_err()
            && let Err(error) = run("umount", &["-l", &target]).await
        {
            eprintln!("warning: {error:#}");
        }
    }
}

/// Mount points at or below `dir`, oldest first.
fn mounts_under(dir: &Path) -> Vec<String> {
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mounts") else {
        return Vec::new();
    };
    mounts
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter(|target| Path::new(target).starts_with(dir))
        .map(str::to_owned)
        .collect()
}

/// When process `pid` started, in clock ticks since boot (field 22 of
/// `/proc/<pid>/stat`), or `None` if there is no such process.
fn start_time(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The name in field 2 may hold spaces, but not the last ')'.
    let after_name = &stat[stat.rfind(')')? + 1..];
    after_name.split_whitespace().nth(19).map(str::to_owned)
}

/// runsc removes the cgroup when the container ends; this covers a crash.
fn remove_cgroup(id: &str) {
    let _ = std::fs::remove_dir(Path::new(CGROUP_ROOT).join(CGROUP_PARENT).join(id));
}

/// The OCI runtime config: the guest agent as PID 1, its mounts, the
/// network namespace to join, and limits in the `spawnbox/<id>` cgroup.
fn config(id: &str, bundle: &Path, root: &str, netns: &Path, limits: &Limits) -> Value {
    let caps = json!(CAPS);
    // gVisor reports the cgroup limit as the guest's RAM and has no
    // limit of its own, so the cgroup is exactly the sandbox's memory.
    let memory = u64::from(limits.memory_mib) * 1024 * 1024;
    let mut mounts = vec![
        mount_entry("/proc", "proc", &[]),
        mount_entry("/dev", "tmpfs", &["nosuid", "mode=755"]),
        mount_entry(
            "/dev/pts",
            "devpts",
            &[
                "nosuid",
                "noexec",
                "newinstance",
                "ptmxmode=0666",
                "mode=0620",
                "gid=5",
            ],
        ),
        // Chromium crashes with a small /dev/shm.
        mount_entry(
            "/dev/shm",
            "tmpfs",
            &["nosuid", "nodev", "mode=1777", "size=1g"],
        ),
        mount_entry("/sys", "sysfs", &["nosuid", "noexec", "nodev", "ro"]),
        mount_entry("/run", "tmpfs", &["nosuid", "nodev", "mode=755"]),
        mount_entry("/tmp", "tmpfs", &["nosuid", "nodev", "mode=1777"]),
    ];
    // Every container has every slot, so a checkpoint restores with any
    // volumes. The guest binds them where the sandbox wants them.
    mounts.extend((0..volume::SLOTS).map(|slot| {
        json!({
            "destination": format!("/spawn/vol/{slot}"),
            "type": "bind",
            "source": volume::bundle_dir(bundle, slot),
            "options": ["rbind", "rw"],
        })
    }));
    json!({
        "ociVersion": "1.0.2",
        "process": {
            "user": { "uid": 0, "gid": 0 },
            "args": [GUEST_INIT],
            "env": [format!("PATH={GUEST_PATH}"), "SPAWN_BACKEND=gvisor"],
            "cwd": "/",
            "capabilities": {
                "bounding": caps,
                "effective": caps,
                "permitted": caps,
            },
        },
        "root": { "path": root, "readonly": false },
        "hostname": id,
        "mounts": mounts,
        "linux": {
            "namespaces": [
                { "type": "pid" },
                { "type": "ipc" },
                { "type": "uts" },
                { "type": "mount" },
                { "type": "network", "path": netns },
            ],
            "cgroupsPath": format!("/{CGROUP_PARENT}/{id}"),
            "resources": {
                "memory": { "limit": memory },
                "cpu": {
                    "quota": u64::from(limits.vcpus) * 100_000,
                    "period": 100_000,
                },
            },
        },
    })
}

fn mount_entry(destination: &str, fstype: &str, options: &[&str]) -> Value {
    json!({
        "destination": destination,
        "type": fstype,
        "source": fstype,
        "options": options,
    })
}
