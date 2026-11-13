//! Template builds and restores, shared by `spawn-api` and `spawn-bench`.

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde_json::json;
use spawn_proto::guest::v1::exec_event::Event;
use spawn_proto::guest::v1::{ApplyRequest, ExecRequest};
use tonic::transport::Channel;

use crate::backend::{Backend, Vm};
use crate::firecracker::{self, Host, Jail, Limits};
use crate::guest;
use crate::gvisor::{Container, Root, Runsc, Start};
use crate::net::{self, GuestLink, NetMode, Netns, TAP};
use crate::netplan::{GATEWAY_IP, GUEST_IP, GUEST_MAC};
use crate::sh::run as sh;
use crate::uffd::{LocalFile, PageSource, Pager};
use crate::volume::{self, Attach};

const GUEST_CID: u32 = 3;
/// Jail and network index for a build when nothing else runs, as in
/// `spawn-bench`. `spawn-api` gives builds indexes from its own pool.
pub const TEMPLATE_INDEX: u32 = 0;
/// The parts of a build's `vm.mem` that a restore touches, in order, as a
/// JSON list. Written when the recipe asks for it.
pub const HOT_FILE: &str = "vm.mem.hot";
const SETUP_STEP_TIMEOUT: Duration = Duration::from_secs(3600);
const WARMUP_STEP_TIMEOUT: Duration = Duration::from_secs(600);
const CA_PATH: &str = "/usr/local/share/ca-certificates/spawnbox-egress.crt";

const ROOTFS: &str = "rootfs.ext4";
const KERNEL: &str = "vmlinux";
const LAYER: &str = "layer.ext4";
/// The disk an image is unpacked into, before it becomes the rootfs.
const IMAGE: &str = "image.ext4";
/// Where the builder VM mounts that disk.
const IMAGE_MOUNT: &str = "/spawn/image";

/// Files shared by every sandbox restored from one template build, all in
/// `dir`. A paused sandbox's files have the same layout.
#[derive(Debug, Clone)]
pub struct Build {
    pub dir: PathBuf,
    pub backend: Backend,
    pub limits: Limits,
    /// Whether there is a read-only disk with what the setup steps changed.
    pub has_layer: bool,
    /// Whether the base disk is the build's own, unpacked from an image,
    /// instead of the shared one.
    pub own_rootfs: bool,
}

impl Build {
    /// A build in `dir`, whether or not it exists yet.
    pub fn at(dir: &Path, backend: Backend, limits: Limits, has_layer: bool) -> Self {
        Self {
            dir: dir.to_owned(),
            backend,
            limits,
            has_layer,
            own_rootfs: false,
        }
    }

    pub fn with_own_rootfs(mut self, own_rootfs: bool) -> Self {
        self.own_rootfs = own_rootfs;
        self
    }

    pub fn rootfs(&self) -> PathBuf {
        self.dir.join(ROOTFS)
    }

    pub fn kernel(&self) -> PathBuf {
        self.dir.join(KERNEL)
    }

    pub fn layer(&self) -> Option<PathBuf> {
        self.has_layer.then(|| self.dir.join(LAYER))
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// A build whose own files were fetched into `dir`: links in the shared
    /// kernel and base disk, and checks that every file is there.
    pub fn adopt(
        dir: &Path,
        backend: Backend,
        kernel: &Path,
        rootfs: &Path,
        limits: Limits,
        has_layer: bool,
        own_rootfs: bool,
    ) -> Result<Self> {
        let build = Self::at(dir, backend, limits, has_layer).with_own_rootfs(own_rootfs);
        build.link_inputs(kernel, rootfs)?;
        build.check_files(&[])?;
        Ok(build)
    }

    /// Fails if a file of the build is missing, other than `except`.
    pub fn check_files(&self, except: &[&str]) -> Result<()> {
        let missing = self.files().into_iter().find(|p| {
            let skip = p
                .file_name()
                .is_some_and(|n| except.iter().any(|e| n == *e));
            !skip && !p.is_file()
        });
        if let Some(missing) = missing {
            bail!("build file {} is missing", missing.display());
        }
        Ok(())
    }

    /// Links in the shared base disk, unless the build has its own, and
    /// the kernel if the backend uses one.
    pub fn link_inputs(&self, kernel: &Path, rootfs: &Path) -> Result<()> {
        let mut inputs = Vec::new();
        if !self.own_rootfs {
            inputs.push((rootfs, self.rootfs()));
        }
        if self.backend == Backend::Firecracker {
            inputs.push((kernel, self.kernel()));
        }
        for (src, dest) in inputs {
            let _ = std::fs::remove_file(&dest);
            link_or_copy(src, &dest)?;
        }
        Ok(())
    }

    /// The files that are the build's own, not shared inputs.
    pub fn own_files(&self) -> Vec<PathBuf> {
        let snapshot = self.backend.snapshot_files().iter().map(|n| self.file(n));
        let rootfs = self.own_rootfs.then(|| self.rootfs());
        rootfs
            .into_iter()
            .chain(snapshot)
            .chain(self.layer())
            .collect()
    }

    /// Starts an empty build in `dir` from a kernel and a base disk. Other
    /// files in `dir`, such as a log, are kept. With `own_rootfs`, the base
    /// disk is the one `unpack_image` left in `dir`.
    fn prepare(
        dir: &Path,
        backend: Backend,
        kernel: &Path,
        rootfs: &Path,
        limits: Limits,
        own_rootfs: bool,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let all = Self::at(dir, backend, limits, true);
        if own_rootfs && !all.rootfs().is_file() {
            bail!("the image was not unpacked");
        }
        for path in all.files() {
            if own_rootfs && path == all.rootfs() {
                continue;
            }
            match std::fs::remove_file(&path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error).with_context(|| format!("remove {}", path.display()));
                }
                _ => {}
            }
        }
        let build = Self::at(dir, backend, limits, false).with_own_rootfs(own_rootfs);
        build.link_inputs(kernel, rootfs)?;
        Ok(build)
    }

    /// Every file of the build.
    pub fn files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if !self.own_rootfs {
            files.push(self.rootfs());
        }
        if self.backend == Backend::Firecracker {
            files.push(self.kernel());
        }
        files.extend(self.own_files());
        files
    }
}

/// What to build on top of the base disk.
#[derive(Debug, Clone)]
pub struct Recipe {
    /// Run as root with network, in order. Their changes become a read-only
    /// layer.
    pub setup: Vec<String>,
    /// Run as `user` right before the snapshot, so their processes and
    /// memory are part of it.
    pub warmup: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub limits: Limits,
    /// Logical size of the writable disk, and of the layer.
    pub disk_gib: u32,
    /// What the build's network forwards.
    pub net: NetMode,
    /// A CA certificate (PEM) the guest trusts, added before the warmup.
    pub ca: Option<String>,
    /// An OCI image to use as the base disk instead of the shared one.
    /// `unpack_image` must run first.
    pub base: Option<String>,
    /// Restore the snapshot once and write `HOT_FILE`. Firecracker only.
    pub record_pages: bool,
}

/// Where a restored VM's memory and writable disk come from.
enum LoadFrom {
    /// A build: its disk is copied.
    Build,
    /// A paused VM's own files: the disk is moved.
    Paused,
    /// A build whose memory is served by a pager, as it arrives.
    Pages(Arc<dyn PageSource>),
}

/// Where a build runs: the jail and network names and the index, which must
/// be unique among running VMs.
pub struct Slot<'a> {
    pub id: &'a str,
    pub index: u32,
}

pub struct Node {
    pub host: Host,
    /// Set when guests run in gVisor instead of Firecracker.
    pub runsc: Option<Runsc>,
    /// Resolver that guest DNS requests are sent to.
    pub dns: Ipv4Addr,
}

pub struct TemplateInfo {
    pub agent_version: String,
    /// The guest's protocol version, `major.minor`.
    pub guest_version: String,
    pub boot_to_agent_ms: f64,
    pub snapshot_create_ms: f64,
    pub upper_disk_used_kib: Option<u64>,
}

/// Milliseconds per restore step. `prepare` and `disk_copy` count from the
/// start; `spawn`, `load` and `hello` count from starting the jailer.
#[derive(Clone, Copy, Default)]
pub struct RestoreSteps {
    pub prepare: f64,
    pub disk_copy: f64,
    pub spawn: f64,
    pub load: f64,
    pub hello: f64,
}

pub struct Restored {
    pub vm: Vm,
    pub channel: Channel,
    /// When the jailer or runsc was started.
    pub started: Instant,
    pub steps: RestoreSteps,
}

/// Build progress and command output. Write errors are ignored.
pub type Log<'a> = &'a mut (dyn Write + Send);

impl Node {
    pub fn backend(&self) -> Backend {
        if self.runsc.is_some() {
            Backend::Gvisor
        } else {
            Backend::Firecracker
        }
    }

    fn runsc(&self) -> Result<&Runsc> {
        self.runsc.as_ref().context("gVisor is not set up")
    }

    /// Builds a template into `dir`, replacing what is there. On error, call
    /// `remove_failed` for the slot.
    pub async fn build_template(
        &self,
        dir: &Path,
        kernel: &Path,
        rootfs: &Path,
        recipe: &Recipe,
        slot: &Slot<'_>,
        log: Log<'_>,
    ) -> Result<(Build, TemplateInfo)> {
        let own_rootfs = recipe.base.is_some();
        let mut build = Build::prepare(
            dir,
            self.backend(),
            kernel,
            rootfs,
            recipe.limits,
            own_rootfs,
        )?;
        if !recipe.setup.is_empty() {
            self.run_setup(&build, recipe, slot, log).await?;
            build.has_layer = true;
        }
        let info = self.snapshot(&build, recipe, slot, log).await?;
        Ok((build, info))
    }

    /// Pulls `recipe.base` into a new disk, which becomes the base disk in
    /// `dir`, ready for `build_template`. A VM booted from the shared base
    /// disk does the pull, so the registry is reached through the build's
    /// network. Returns the image's digest.
    pub async fn unpack_image(
        &self,
        dir: &Path,
        kernel: &Path,
        rootfs: &Path,
        recipe: &Recipe,
        slot: &Slot<'_>,
        log: Log<'_>,
    ) -> Result<String> {
        let reference = recipe.base.as_deref().context("the recipe has no image")?;
        let build = Build::prepare(dir, self.backend(), kernel, rootfs, recipe.limits, false)?;
        let image = dir.join(IMAGE);
        let _ = std::fs::remove_file(&image);
        new_disk(&image, recipe.disk_gib, "rootfs").await?;
        let attach = Attach {
            slot: 0,
            file: image.clone(),
            read_only: false,
        };
        note(log, &format!("== image: pulling {reference}"));
        let booted = async {
            match build.backend {
                Backend::Firecracker => {
                    let jail = self.jail(&build, slot, recipe.disk_gib).await?;
                    volume::link_for_boot(&jail, std::slice::from_ref(&attach))?;
                    let (vm, channel, _) = self.boot(jail, &build, slot, recipe.net).await?;
                    anyhow::Ok((Vm::Firecracker(vm), channel))
                }
                Backend::Gvisor => {
                    let rootfs = build.rootfs();
                    let root = Root::Image {
                        rootfs: &rootfs,
                        layer: None,
                    };
                    let volumes = std::slice::from_ref(&attach);
                    let (container, channel, _) = self
                        .boot_gvisor(&build, root, slot, recipe, volumes)
                        .await?;
                    Ok((Vm::Gvisor(container), channel))
                }
            }
        }
        .await;
        let (vm, channel) = match booted {
            Ok(booted) => booted,
            Err(error) => {
                let _ = std::fs::remove_file(&image);
                return Err(error);
            }
        };
        let result = async {
            guest::mount(&channel, &[(attach.clone(), IMAGE_MOUNT.to_owned())]).await?;
            let unpack = guest::unpack(
                &channel,
                reference,
                IMAGE_MOUNT,
                recipe.ca.as_deref(),
                &mut *log,
            );
            tokio::time::timeout(SETUP_STEP_TIMEOUT, unpack)
                .await
                .context("the image pull timed out")?
        }
        .await;
        drop(channel);
        // For gVisor, this unmounts the disk, which writes it out.
        vm.stop().await;
        let digest = match result {
            Ok(digest) => digest,
            Err(error) => {
                let _ = std::fs::remove_file(&image);
                return Err(error);
            }
        };
        note(log, "== image: shrinking the disk");
        shrink(&image).await?;
        keep(&image, &build.rootfs())?;
        Ok(digest)
    }

    /// First boot: runs the setup steps and keeps what they changed as the
    /// layer.
    async fn run_setup(
        &self,
        build: &Build,
        recipe: &Recipe,
        slot: &Slot<'_>,
        log: Log<'_>,
    ) -> Result<()> {
        note(log, "== setup: booting");
        let layer = build.dir.join(LAYER);
        let (vm, channel) = match build.backend {
            Backend::Firecracker => {
                let jail = self.jail(build, slot, recipe.disk_gib).await?;
                let (vm, channel, _) = self.boot(jail, build, slot, recipe.net).await?;
                (Vm::Firecracker(vm), channel)
            }
            Backend::Gvisor => {
                // gVisor writes through to this disk, as the setup steps run.
                new_disk(&layer, recipe.disk_gib, "upper").await?;
                let rootfs = build.rootfs();
                let root = Root::Setup {
                    rootfs: &rootfs,
                    layer: &layer,
                };
                let (container, channel, _) =
                    self.boot_gvisor(build, root, slot, recipe, &[]).await?;
                (Vm::Gvisor(container), channel)
            }
        };
        let mut env = BTreeMap::from([("DEBIAN_FRONTEND".to_owned(), "noninteractive".to_owned())]);
        env.extend(recipe.env.clone());
        let result = async {
            for cmd in &recipe.setup {
                run_step(&channel, cmd, "root", &env, SETUP_STEP_TIMEOUT, log).await?;
            }
            note(log, "== setup: sealing the layer");
            guest::seal(&channel).await?;
            match &vm {
                Vm::Firecracker(vm) => keep(&vm.root().join("upper.ext4"), &layer),
                Vm::Gvisor(_) => Ok(()),
            }
        }
        .await;
        drop(channel);
        // For gVisor, this unmounts the layer, which writes it out.
        vm.stop().await;
        result?;
        std::fs::set_permissions(&layer, std::fs::Permissions::from_mode(0o644))?;
        Ok(())
    }

    /// Last boot: runs the warmup steps and saves a full snapshot.
    async fn snapshot(
        &self,
        build: &Build,
        recipe: &Recipe,
        slot: &Slot<'_>,
        log: Log<'_>,
    ) -> Result<TemplateInfo> {
        note(log, "== snapshot: booting");
        let (vm, channel, boot_to_agent_ms) = match build.backend {
            Backend::Firecracker => {
                let jail = self.jail(build, slot, recipe.disk_gib).await?;
                if let Some(layer) = build.layer() {
                    jail.link(&layer, LAYER)?;
                }
                let (vm, channel, ms) = self.boot(jail, build, slot, recipe.net).await?;
                (Vm::Firecracker(vm), channel, ms)
            }
            Backend::Gvisor => {
                let (rootfs, layer) = (build.rootfs(), build.layer());
                let root = Root::Image {
                    rootfs: &rootfs,
                    layer: layer.as_deref(),
                };
                let (container, channel, ms) =
                    self.boot_gvisor(build, root, slot, recipe, &[]).await?;
                (Vm::Gvisor(container), channel, ms)
            }
        };
        let result = async {
            let (agent_version, guest_version) = guest::hello(&channel).await?;
            if let Some(ca) = &recipe.ca {
                note(log, "== snapshot: trusting the egress CA");
                let cmd = trust_ca(ca)?;
                run_step(
                    &channel,
                    &cmd,
                    "root",
                    &BTreeMap::new(),
                    WARMUP_STEP_TIMEOUT,
                    &mut std::io::sink(),
                )
                .await?;
            }
            for cmd in &recipe.warmup {
                run_step(&channel, cmd, "", &recipe.env, WARMUP_STEP_TIMEOUT, log).await?;
            }
            guest::exec(&channel, "true").await?;
            note(log, "== snapshot: saving");
            let snapshot_create_ms = save_template(&vm, build).await?;
            anyhow::Ok((agent_version, guest_version, snapshot_create_ms))
        }
        .await;
        drop(channel);
        vm.stop().await;
        let (agent_version, guest_version, snapshot_create_ms) = result?;
        if recipe.record_pages && build.backend == Backend::Firecracker {
            note(log, "== snapshot: recording the memory a start uses");
            if let Err(error) = self.record_hot(build, slot, recipe.net).await {
                note(log, &format!("warning: no hot memory list: {error:#}"));
            }
        }
        let upper_disk_used_kib = match build.backend {
            Backend::Firecracker => {
                let upper = build.file("upper.ext4");
                let used = sh("du", &["-k", &upper.to_string_lossy()]).await?;
                used.split_whitespace().next().and_then(|n| n.parse().ok())
            }
            // gVisor's writes are inside its checkpoint.
            Backend::Gvisor => None,
        };
        Ok(TemplateInfo {
            agent_version,
            guest_version: spawn_proto::version_string(&guest_version),
            boot_to_agent_ms,
            snapshot_create_ms,
            upper_disk_used_kib,
        })
    }

    /// Restores the build once, with a pager reading its `vm.mem`, and
    /// writes the parts the start touched to `HOT_FILE`.
    async fn record_hot(&self, build: &Build, slot: &Slot<'_>, mode: NetMode) -> Result<()> {
        let pages = Arc::new(LocalFile::open(&build.file("vm.mem"))?);
        let restored = self
            .load_vm(
                build,
                slot.id,
                slot.index,
                mode,
                LoadFrom::Pages(pages),
                &[],
            )
            .await
            .map_err(ResumeError::into_inner)?;
        let ran = guest::exec(&restored.channel, "true").await;
        let touched = match &restored.vm {
            Vm::Firecracker(vm) => vm.pager().map(Pager::touched).unwrap_or_default(),
            Vm::Gvisor(_) => Vec::new(),
        };
        drop(restored.channel);
        restored.vm.stop().await;
        ran?;
        std::fs::write(build.file(HOT_FILE), serde_json::to_vec(&touched)?)?;
        Ok(())
    }

    /// Starts a fresh gVisor container and waits for its agent. Returns
    /// the milliseconds from start to the agent's answer.
    async fn boot_gvisor(
        &self,
        build: &Build,
        root: Root<'_>,
        slot: &Slot<'_>,
        recipe: &Recipe,
        volumes: &[Attach],
    ) -> Result<(Container, Channel, f64)> {
        let runsc = self.runsc()?;
        let net = Netns::create(slot.id, slot.index, GuestLink::Veth, self.dns, recipe.net).await?;
        let boot = Instant::now();
        let start = Start::Boot {
            disk_gib: recipe.disk_gib,
        };
        let container = Container::start(
            runsc,
            &self.host,
            slot.id,
            root,
            start,
            net,
            &build.limits,
            volumes,
        )
        .await?;
        match guest::connect(&container.dialer(), Duration::from_secs(30)).await {
            Ok(channel) => Ok((container, channel, ms(boot.elapsed()))),
            Err(error) => {
                container.stop().await;
                Err(error.context(format!("guest did not answer; see logs/{}.log", slot.id)))
            }
        }
    }

    /// A jail with the kernel, the base disk and a new empty writable disk.
    async fn jail(&self, build: &Build, slot: &Slot<'_>, disk_gib: u32) -> Result<Jail> {
        let jail = Jail::new(&self.host, slot.id, slot.index)?;
        jail.link(&build.kernel(), KERNEL)?;
        jail.link(&build.rootfs(), ROOTFS)?;
        new_disk(&jail.root().join("upper.ext4"), disk_gib, "upper").await?;
        jail.give("upper.ext4")?;
        volume::add_placeholders(&jail)?;
        Ok(jail)
    }

    /// Boots a fresh VM from the disks in `jail` and waits for its agent.
    /// Returns the milliseconds from start to the agent's answer.
    async fn boot(
        &self,
        jail: Jail,
        build: &Build,
        slot: &Slot<'_>,
        mode: NetMode,
    ) -> Result<(firecracker::Vm, Channel, f64)> {
        let has_layer = jail.root().join(LAYER).exists();
        let owner = jail.uid();
        let net = Netns::create(
            slot.id,
            slot.index,
            GuestLink::Tap { owner },
            self.dns,
            mode,
        )
        .await?;
        let vm = firecracker::Vm::start(&self.host, jail, net, &build.limits).await?;

        // The kernel brings up eth0 with the fixed guest address.
        let ip = format!("ip={GUEST_IP}::{GATEWAY_IP}:255.255.255.252::eth0:off");
        let boot_args = format!(
            "console=ttyS0 reboot=k panic=1 ro {ip} ipv6.disable=1 init=/usr/local/bin/spawn-guest"
        );
        vm.put(
            "/boot-source",
            json!({ "kernel_image_path": "/vmlinux", "boot_args": boot_args }),
        )
        .await?;
        // The guest sees them as vda, vdb and so on, in this order: the
        // base disk, the writable disk, the volume disks (vdc to vdj), and
        // the layer (vdk).
        let mut drives = vec![
            ("rootfs".to_owned(), "/rootfs.ext4".to_owned(), true),
            ("upper".to_owned(), "/upper.ext4".to_owned(), false),
        ];
        drives.extend(volume::vm_drives().map(|(id, file, ro)| (id, format!("/{file}"), ro)));
        if has_layer {
            drives.push(("layer".to_owned(), "/layer.ext4".to_owned(), true));
        }
        for (id, path, read_only) in drives {
            vm.put(
                &format!("/drives/{id}"),
                json!({
                    "drive_id": id,
                    "path_on_host": path,
                    "is_root_device": id == "rootfs",
                    "is_read_only": read_only,
                }),
            )
            .await?;
        }
        vm.put(
            "/machine-config",
            json!({
                "vcpu_count": build.limits.vcpus,
                "mem_size_mib": build.limits.memory_mib,
            }),
        )
        .await?;
        vm.put(
            "/network-interfaces/eth0",
            json!({
                "iface_id": "eth0",
                "host_dev_name": TAP,
                "guest_mac": GUEST_MAC,
            }),
        )
        .await?;
        vm.put(
            "/vsock",
            json!({ "guest_cid": GUEST_CID, "uds_path": "v.sock" }),
        )
        .await?;
        // The guest hands pages it frees back to the host. Snapshots keep
        // the device, so sandboxes restored from this build do too.
        vm.put(
            "/balloon",
            json!({
                "amount_mib": 0,
                "deflate_on_oom": true,
                "stats_polling_interval_s": 0,
                "free_page_reporting": true,
            }),
        )
        .await?;

        let boot = Instant::now();
        vm.put("/actions", json!({ "action_type": "InstanceStart" }))
            .await?;
        // Firecracker makes the vCPU threads on start, so they may run on
        // each other's CPUs for a moment first.
        vm.pin_vcpus()?;
        let channel = guest::connect(&vm.dialer(), Duration::from_secs(30))
            .await
            .with_context(|| format!("guest did not answer; see logs/{}.log", slot.id))?;
        Ok((vm, channel, ms(boot.elapsed())))
    }

    /// Restores a jailed VM from a build and waits for its guest agent.
    /// `index` must be unique among running VMs. `id` may use only letters,
    /// digits and hyphens. The guest must mount `volumes` afterwards.
    pub async fn restore(
        &self,
        build: &Build,
        id: &str,
        index: u32,
        mode: NetMode,
        volumes: &[Attach],
    ) -> Result<Restored> {
        self.load(build, id, index, mode, LoadFrom::Build, volumes)
            .await
            .map_err(ResumeError::into_inner)
    }

    /// Like `restore`, but the build's `vm.mem` may be missing: guest
    /// memory is read from `pages` when the guest first touches it.
    /// Firecracker only. If a part does not come within `uffd::PART_WAIT`,
    /// the VM is stopped and `Vm::take_lost` tells why.
    pub async fn restore_lazy(
        &self,
        build: &Build,
        id: &str,
        index: u32,
        mode: NetMode,
        volumes: &[Attach],
        pages: Arc<dyn PageSource>,
    ) -> Result<Restored> {
        if build.backend != Backend::Firecracker {
            bail!("only Firecracker loads memory lazily");
        }
        self.load(build, id, index, mode, LoadFrom::Pages(pages), volumes)
            .await
            .map_err(ResumeError::into_inner)
    }

    /// Resumes a VM that `pause` saved to `dir`. On success `dir` is gone.
    /// Like `restore`, the guest needs a new identity afterwards. `volumes`
    /// must be the ones it had, which stay mounted.
    pub async fn resume(
        &self,
        dir: &Path,
        limits: Limits,
        id: &str,
        index: u32,
        mode: NetMode,
        volumes: &[Attach],
    ) -> Result<Restored, ResumeError> {
        let merge_dir = dir.to_owned();
        tokio::task::spawn_blocking(move || crate::diff::finish_paused(&merge_dir))
            .await
            .map_err(|error| ResumeError::Before(error.into()))?
            .map_err(ResumeError::Before)?;
        let has_layer = dir.join(LAYER).exists();
        let paused = Build::at(dir, self.backend(), limits, has_layer);
        let restored = self
            .load(&paused, id, index, mode, LoadFrom::Paused, volumes)
            .await?;
        if let Err(error) = std::fs::remove_dir_all(dir) {
            eprintln!("warning: remove {}: {error}", dir.display());
        }
        Ok(restored)
    }

    async fn load(
        &self,
        build: &Build,
        id: &str,
        index: u32,
        mode: NetMode,
        from: LoadFrom,
        volumes: &[Attach],
    ) -> Result<Restored, ResumeError> {
        volume::check(volumes).map_err(ResumeError::Before)?;
        match build.backend {
            Backend::Firecracker => self.load_vm(build, id, index, mode, from, volumes).await,
            // gVisor never changes the checkpoint files: no copy is needed.
            Backend::Gvisor => self.load_container(build, id, index, mode, volumes).await,
        }
    }

    async fn load_container(
        &self,
        build: &Build,
        id: &str,
        index: u32,
        mode: NetMode,
        volumes: &[Attach],
    ) -> Result<Restored, ResumeError> {
        let begin = Instant::now();
        let runsc = self.runsc().map_err(ResumeError::Before)?;
        let net = Netns::create(id, index, GuestLink::Veth, self.dns, mode)
            .await
            .map_err(ResumeError::Before)?;
        let prepare = ms(begin.elapsed());
        let started = Instant::now();
        let (rootfs, layer) = (build.rootfs(), build.layer());
        let root = Root::Image {
            rootfs: &rootfs,
            layer: layer.as_deref(),
        };
        let start = Start::Restore { image: &build.dir };
        let container = Container::start(
            runsc,
            &self.host,
            id,
            root,
            start,
            net,
            &build.limits,
            volumes,
        )
        .await
        .map_err(ResumeError::Before)?;
        let load = ms(started.elapsed());
        let channel = async {
            let channel = guest::connect(&container.dialer(), Duration::from_secs(5))
                .await
                .with_context(|| format!("guest did not answer; see logs/{id}.log"))?;
            guest::hello(&channel).await?;
            anyhow::Ok(channel)
        };
        let channel = match channel.await {
            Ok(channel) => channel,
            Err(error) => {
                container.stop().await;
                return Err(ResumeError::After(error));
            }
        };
        let hello = ms(started.elapsed());
        Ok(Restored {
            vm: Vm::Gvisor(container),
            channel,
            started,
            steps: RestoreSteps {
                prepare,
                disk_copy: 0.0,
                spawn: load,
                load,
                hello,
            },
        })
    }

    async fn load_vm(
        &self,
        build: &Build,
        id: &str,
        index: u32,
        mode: NetMode,
        from: LoadFrom,
        volumes: &[Attach],
    ) -> Result<Restored, ResumeError> {
        let begin = Instant::now();
        let own_disk = matches!(from, LoadFrom::Paused);
        let jail = Jail::new(&self.host, id, index).map_err(ResumeError::Before)?;
        let net = async {
            jail.link(&build.rootfs(), ROOTFS)?;
            if let Some(layer) = build.layer() {
                jail.link(&layer, LAYER)?;
            }
            jail.link(&build.file("vm.state"), "vm.state")?;
            if !matches!(from, LoadFrom::Pages(_)) {
                jail.link(&build.file("vm.mem"), "vm.mem")?;
            }
            volume::add_placeholders(&jail)?;
            volume::link(jail.root(), jail.uid(), volumes)?;
            let upper = build.file("upper.ext4");
            let copy = Instant::now();
            if own_disk {
                jail.link(&upper, "upper.ext4")?;
                jail.give("upper.ext4")?;
            } else {
                jail.copy_disk(&upper, "upper.ext4").await?;
            }
            let disk_copy = ms(copy.elapsed());
            let owner = jail.uid();
            let net = Netns::create(id, index, GuestLink::Tap { owner }, self.dns, mode).await?;
            anyhow::Ok((net, disk_copy))
        };
        let (net, disk_copy) = net.await.map_err(ResumeError::Before)?;
        let prepare = ms(begin.elapsed());

        let started = Instant::now();
        let mut vm = firecracker::Vm::start(&self.host, jail, net, &build.limits)
            .await
            .map_err(ResumeError::Before)?;
        let spawn = ms(started.elapsed());
        let from_file = !matches!(from, LoadFrom::Pages(_));
        let backend = match from {
            LoadFrom::Pages(pages) => {
                let sock = vm.root().join("uffd.sock");
                let pager = vm
                    .pid()
                    .context("Firecracker has exited")
                    .and_then(|pid| Pager::start(&sock, vm.uid(), pid, pages));
                match pager {
                    Ok(pager) => vm.set_pager(pager),
                    Err(error) => {
                        vm.stop().await;
                        return Err(ResumeError::Before(error));
                    }
                }
                json!({ "backend_path": "/uffd.sock", "backend_type": "Uffd" })
            }
            LoadFrom::Build | LoadFrom::Paused => {
                json!({ "backend_path": "/vm.mem", "backend_type": "File" })
            }
        };
        let pin_first = vm.pins_each_vcpu();
        let loaded = vm
            .put(
                "/snapshot/load",
                json!({
                    "snapshot_path": "/vm.state",
                    "mem_backend": backend,
                    // So a pause can write only the pages written since.
                    "track_dirty_pages": from_file,
                    "resume_vm": !pin_first,
                }),
            )
            .await;
        let loaded = match loaded {
            Ok(()) if pin_first => match vm.pin_vcpus() {
                Ok(()) => vm.patch("/vm", json!({ "state": "Resumed" })).await,
                Err(error) => Err(error),
            },
            other => other.and_then(|()| vm.pin_vcpus()),
        };
        if let Err(error) = loaded {
            vm.stop().await;
            return Err(ResumeError::Before(error));
        }
        if from_file {
            vm.set_dirty_tracked();
        }
        let load = ms(started.elapsed());
        let channel = async {
            // A paused VM's snapshot already points at its volumes.
            if !own_disk {
                volume::swap_in(&vm, volumes).await?;
            }
            let channel = guest::connect(&vm.dialer(), Duration::from_secs(5))
                .await
                .with_context(|| format!("guest did not answer; see logs/{id}.log"))?;
            guest::hello(&channel).await?;
            anyhow::Ok(channel)
        };
        let channel = match channel.await {
            Ok(channel) => channel,
            Err(error) => {
                vm.stop().await;
                return Err(ResumeError::After(error));
            }
        };
        let hello = ms(started.elapsed());
        Ok(Restored {
            vm: Vm::Firecracker(vm),
            channel,
            started,
            steps: RestoreSteps {
                prepare,
                disk_copy,
                spawn,
                load,
                hello,
            },
        })
    }

    /// Pauses a sandbox from `restore` or `resume` and saves its memory and
    /// disks to `dir`, which must not exist. Returns the milliseconds the
    /// snapshot took. On success, stop the sandbox, then call
    /// `finish_paused` in the background; on error it runs on, unless the
    /// error is `Frozen`.
    pub async fn pause(&self, vm: &Vm, dir: &Path) -> Result<f64> {
        match vm {
            Vm::Firecracker(vm) => pause_vm(vm, dir).await,
            Vm::Gvisor(container) => pause_container(container, dir).await,
        }
    }

    /// Saves a running sandbox to `dir`, which must not exist, as a build
    /// that `restore` can start copies from. The sandbox runs on, but the
    /// save closes its guest connections: use the returned channel. Returns
    /// it and the milliseconds the sandbox was stopped for. On a `Frozen`
    /// error, stop it.
    pub async fn save_running(&self, vm: &Vm, dir: &Path) -> Result<(f64, Channel)> {
        create_paused_dir(dir)?;
        let saved = match vm {
            Vm::Firecracker(vm) => snapshot_vm(vm, dir).await,
            Vm::Gvisor(container) => snapshot_container(container, dir).await,
        };
        let saved = match saved {
            Ok(ms) => guest::connect(&vm.dialer(), Duration::from_secs(5))
                .await
                .map(|channel| (ms, channel))
                .map_err(|error| anyhow::Error::new(Frozen).context(format!("{error:#}"))),
            Err(error) => Err(error),
        };
        if saved.is_err() {
            let _ = std::fs::remove_dir_all(dir);
        }
        saved
    }
}

async fn snapshot_container(container: &Container, dir: &Path) -> Result<f64> {
    let started = Instant::now();
    container.checkpoint_running(dir).await?;
    let stopped_ms = ms(started.elapsed());
    for (src, name) in container.disks() {
        std::fs::hard_link(&src, dir.join(name))
            .with_context(|| format!("link {name} to {}", dir.display()))?;
    }
    flush_later(dir.to_owned(), Backend::Gvisor.snapshot_files());
    Ok(stopped_ms)
}

async fn snapshot_vm(vm: &firecracker::Vm, dir: &Path) -> Result<f64> {
    // The snapshot resets the dirty pages, so later pauses save all memory.
    vm.take_dirty_tracked();
    let started = Instant::now();
    vm.patch("/vm", json!({ "state": "Paused" })).await?;
    // Back only once the memory file is on disk: see `lift_memory_max`.
    let lift = vm.lift_memory_max();
    let root = vm.root();
    let saved = async {
        vm.put(
            "/snapshot/create",
            json!({
                "snapshot_type": "Full",
                "snapshot_path": "/snap.state",
                "mem_file_path": "/snap.mem",
                "sync_snapshot_files": false,
            }),
        )
        .await?;
        keep(&root.join("snap.state"), &dir.join("vm.state"))?;
        keep(&root.join("snap.mem"), &dir.join("vm.mem"))?;
        // Open now: a fork removes `dir` before the flush.
        let files = [
            std::fs::File::open(dir.join("vm.state"))?,
            std::fs::File::open(dir.join("vm.mem"))?,
        ];
        for name in [ROOTFS, LAYER] {
            let src = root.join(name);
            if src.exists() {
                link_from_jail(&src, &dir.join(name))?;
            }
        }
        // While paused, so the disk matches the memory.
        let (src, dest) = (root.join("upper.ext4"), dir.join("upper.ext4"));
        sh(
            "cp",
            &[
                "--no-dereference",
                "--sparse=always",
                "--reflink=auto",
                &src.to_string_lossy(),
                &dest.to_string_lossy(),
            ],
        )
        .await?;
        own(&dest)?;
        anyhow::Ok(files)
    }
    .await;
    let _ = std::fs::remove_file(root.join("snap.state"));
    let _ = std::fs::remove_file(root.join("snap.mem"));
    let stopped_ms = ms(started.elapsed());
    if let Err(resume) = vm.patch("/vm", json!({ "state": "Resumed" })).await {
        let why = match &saved {
            Err(error) => format!("{error:#}; and resume failed: {resume:#}"),
            Ok(_) => format!("resume failed: {resume:#}"),
        };
        return Err(anyhow::Error::new(Frozen).context(why));
    }
    let files = saved?;
    tokio::task::spawn_blocking(move || {
        for file in files {
            if let Err(error) = file.sync_all() {
                eprintln!("warning: flush a saved sandbox: {error}");
            }
        }
        drop(lift);
    });
    Ok(stopped_ms)
}

/// Saves a template's snapshot files into its build directory.
async fn save_template(vm: &Vm, build: &Build) -> Result<f64> {
    match vm {
        Vm::Firecracker(vm) => {
            vm.patch("/vm", json!({ "state": "Paused" })).await?;
            let started = Instant::now();
            vm.put(
                "/snapshot/create",
                json!({
                    "snapshot_type": "Full",
                    "snapshot_path": "/vm.state",
                    "mem_file_path": "/vm.mem",
                }),
            )
            .await?;
            let snapshot_ms = ms(started.elapsed());
            for name in build.backend.snapshot_files() {
                keep(&vm.root().join(name), &build.file(name))?;
            }
            Ok(snapshot_ms)
        }
        Vm::Gvisor(container) => {
            let image = build.dir.join("checkpoint");
            let _ = std::fs::remove_dir_all(&image);
            std::fs::DirBuilder::new().mode(0o700).create(&image)?;
            let started = Instant::now();
            container.checkpoint(&image).await?;
            let snapshot_ms = ms(started.elapsed());
            for name in build.backend.snapshot_files() {
                keep(&image.join(name), &build.file(name))?;
            }
            std::fs::remove_dir(&image)?;
            Ok(snapshot_ms)
        }
    }
}

/// Creates the paused sandbox directory `dir`.
fn create_paused_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir.parent().context("paused dir has no parent")?)?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("create {}", dir.display()))
}

/// Checkpointing stops the container, unless it fails early.
async fn pause_container(container: &Container, dir: &Path) -> Result<f64> {
    let started = Instant::now();
    create_paused_dir(dir)?;
    let saved = async {
        container.checkpoint(dir).await?;
        let snapshot_ms = ms(started.elapsed());
        for (src, name) in container.disks() {
            std::fs::hard_link(&src, dir.join(name))
                .with_context(|| format!("link {name} to {}", dir.display()))?;
        }
        anyhow::Ok(snapshot_ms)
    }
    .await;
    match saved {
        Ok(snapshot_ms) => {
            flush_later(dir.to_owned(), Backend::Gvisor.snapshot_files());
            Ok(snapshot_ms)
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(dir);
            if container.running().await {
                Err(error)
            } else {
                Err(anyhow::Error::new(Frozen).context(format!("{error:#}")))
            }
        }
    }
}

async fn pause_vm(vm: &firecracker::Vm, dir: &Path) -> Result<f64> {
    let diff = vm.take_dirty_tracked() && vm.root().join("vm.mem").exists();
    let started = Instant::now();
    vm.patch("/vm", json!({ "state": "Paused" })).await?;
    // See `lift_memory_max`. The vCPUs are stopped, so the guest cannot
    // use the room. The VM stops after a pause, so the limit only comes
    // back on an error.
    let lift = vm.lift_memory_max();
    let saved = async {
        // Not vm.state and vm.mem: in the jail those are links to the
        // files the VM was restored from.
        vm.put(
            "/snapshot/create",
            json!({
                "snapshot_type": if diff { "Diff" } else { "Full" },
                "snapshot_path": "/paused.state",
                "mem_file_path": "/paused.mem",
                // Writing the memory to disk takes seconds; flush_later
                // does it after the pause returns.
                "sync_snapshot_files": false,
            }),
        )
        .await?;
        let snapshot_ms = ms(started.elapsed());
        create_paused_dir(dir)?;
        let root = vm.root();
        let moved = (|| -> Result<()> {
            keep(&root.join("paused.state"), &dir.join("vm.state"))?;
            if diff {
                keep(&root.join("paused.mem"), &dir.join(crate::diff::DIFF))?;
                link_from_jail(&root.join("vm.mem"), &dir.join(crate::diff::BASE))
                    .context("keep the memory the VM was loaded from")?;
            } else {
                keep(&root.join("paused.mem"), &dir.join("vm.mem"))?;
            }
            for name in [ROOTFS, LAYER] {
                let src = root.join(name);
                if src.exists() {
                    link_from_jail(&src, &dir.join(name))?;
                }
            }
            // Last: once the disk has moved, the pause is done.
            keep(&root.join("upper.ext4"), &dir.join("upper.ext4"))
        })();
        if moved.is_err() {
            let _ = std::fs::remove_dir_all(dir);
        }
        moved.map(|()| snapshot_ms)
    }
    .await;
    if let Err(error) = saved {
        drop(lift);
        let _ = std::fs::remove_file(vm.root().join("paused.state"));
        let _ = std::fs::remove_file(vm.root().join("paused.mem"));
        if let Err(resume) = vm.patch("/vm", json!({ "state": "Resumed" })).await {
            return Err(anyhow::Error::new(Frozen)
                .context(format!("{error:#}; and resume failed: {resume:#}")));
        }
        return Err(error);
    }
    if let Ok(lift) = lift {
        lift.keep();
    }
    // `finish_paused` flushes the memory of a diff.
    flush_later(
        dir.to_owned(),
        if diff {
            &["vm.state"]
        } else {
            &["vm.state", "vm.mem"]
        },
    );
    saved
}

/// Writes a paused sandbox's memory and state to disk in the background.
/// Until then they live in the page cache: a resume reads them from there,
/// and only a host power loss in those seconds would lose them.
fn flush_later(dir: PathBuf, names: &'static [&'static str]) {
    tokio::task::spawn_blocking(move || {
        for name in names {
            let path = dir.join(name);
            let synced = std::fs::File::open(&path).and_then(|file| file.sync_all());
            match synced {
                // Already resumed.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
                Err(error) => eprintln!("warning: flush {}: {error}", path.display()),
                Ok(()) => {}
            }
        }
        if let Err(error) = std::fs::File::open(&dir).and_then(|dir| dir.sync_all())
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("warning: flush {}: {error}", dir.display());
        }
    });
}

/// A failed `pause` could not resume the sandbox: it stays frozen, or has
/// stopped, so stop it.
#[derive(Debug)]
pub struct Frozen;

impl std::fmt::Display for Frozen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the VM stayed paused")
    }
}

impl std::error::Error for Frozen {}

/// Why `resume` failed.
#[derive(Debug)]
pub enum ResumeError {
    /// The VM did not run: the paused files are unchanged.
    Before(anyhow::Error),
    /// The VM ran, so its disk may no longer match the saved memory.
    After(anyhow::Error),
}

impl ResumeError {
    pub fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Before(error) | Self::After(error) => error,
        }
    }
}

impl std::fmt::Display for ResumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Before(error) | Self::After(error) => write!(f, "{error:#}"),
        }
    }
}

/// Runs one build step and copies its output to the log. Fails unless it
/// exits with 0.
async fn run_step(
    channel: &Channel,
    cmd: &str,
    user: &str,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    log: Log<'_>,
) -> Result<()> {
    note(log, &format!("$ {cmd}"));
    let request = ExecRequest {
        cmd: cmd.to_owned(),
        cwd: String::new(),
        env: env.clone().into_iter().collect::<HashMap<_, _>>(),
        timeout_ms: u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX),
        user: user.to_owned(),
        stdin: Vec::new(),
    };
    let mut events = guest::exec_stream(channel, request).await?;
    let mut exit = None;
    while let Some(event) = events.message().await? {
        match event.event {
            Some(Event::Stdout(bytes) | Event::Stderr(bytes)) => {
                let _ = log.write_all(&bytes);
            }
            Some(Event::Exit(e)) => {
                exit = Some(e);
                break;
            }
            None => {}
        }
    }
    let exit = exit.context("step ended without an exit status")?;
    if exit.timed_out {
        bail!("step timed out after {} s: {cmd}", timeout.as_secs());
    }
    match (exit.exit_code, exit.signal) {
        (Some(0), _) => Ok(()),
        (Some(code), _) => bail!("step exited with {code}: {cmd}"),
        (None, Some(signal)) => bail!("step was killed by signal {signal}: {cmd}"),
        (None, None) => bail!("step ended without an exit code: {cmd}"),
    }
}

/// A shell command that adds `pem` to the guest's trusted certificates.
fn trust_ca(pem: &str) -> Result<String> {
    const END: &str = "SPAWNBOX_CA_END";
    if !pem.starts_with("-----BEGIN CERTIFICATE-----") || pem.contains(END) || pem.contains('\'') {
        bail!("not a PEM certificate");
    }
    // Images without `update-ca-certificates` get the CA added to the
    // bundle their distribution reads.
    Ok(format!(
        "mkdir -p /usr/local/share/ca-certificates && cat > {CA_PATH} <<'{END}'\n{}\n{END}\n\
         if command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates >/dev/null; \
         else for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do \
         if [ -f \"$f\" ]; then cat {CA_PATH} >> \"$f\"; exit 0; fi; done; \
         mkdir -p /etc/ssl/certs && cat {CA_PATH} > /etc/ssl/certs/ca-certificates.crt; fi",
        pem.trim_end()
    ))
}

fn note(log: Log<'_>, line: &str) {
    let _ = writeln!(log, "{line}");
}

/// Moves a file out of a jail, owned by root and readable by every VM.
fn keep(src: &Path, dest: &Path) -> Result<()> {
    std::fs::rename(src, dest)
        .with_context(|| format!("move {} to {}", src.display(), dest.display()))?;
    own(dest)
}

/// Makes `path`, just taken from a jail into a directory only root can
/// change, owned by root and readable by every VM. The jailed VMM may have
/// left a symlink, a hard link or a FIFO there instead of its file: these
/// are removed and refused, never followed.
fn own(path: &Path) -> Result<()> {
    let owned = (|| {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 {
            bail!("not a regular file with one link");
        }
        fchown(&file, Some(0), Some(0))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        anyhow::Ok(())
    })();
    if owned.is_err() {
        let _ = std::fs::remove_file(path);
    }
    owned.with_context(|| format!("take {} from the jail", path.display()))
}

/// Hard-links `src`, a file in a jail, to `dest`. Fails, leaving no `dest`,
/// if `src` is not a regular file: `link` does not follow a symlink, so a
/// planted one would arrive as a symlink.
fn link_from_jail(src: &Path, dest: &Path) -> Result<()> {
    std::fs::hard_link(src, dest)
        .with_context(|| format!("link {} to {}", src.display(), dest.display()))?;
    if !std::fs::symlink_metadata(dest)?.is_file() {
        let _ = std::fs::remove_file(dest);
        bail!("{} is not a regular file", src.display());
    }
    Ok(())
}

impl Node {
    /// Removes what a failed `restore` left for `id`, so that `index` can be
    /// used again. Drop the `Vm`, if any, first.
    /// Kills every process of sandbox `id`, whatever runs it. True once
    /// none is left.
    pub async fn kill(&self, id: &str) -> bool {
        // First, as removing a container can take a while.
        let gone = self.host.kill_cgroup(id).await;
        if let Some(runsc) = &self.runsc {
            runsc.remove(id).await;
        }
        gone
    }

    pub async fn remove_failed(&self, id: &str, index: u32) {
        if let Some(runsc) = &self.runsc {
            runsc.remove(id).await;
        }
        self.host.remove_vm(id).await;
        net::remove_failed(id, index).await;
    }
}

/// Fresh clock, entropy and hostname for a restored VM.
pub fn new_identity(name: &str) -> Result<ApplyRequest> {
    let mut entropy = vec![0; 64];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(ApplyRequest {
        wall_clock_unix_nanos: i64::try_from(now.as_nanos())?,
        entropy,
        hostname: name.to_owned(),
        sandbox_id: name.to_owned(),
    })
}

/// A new empty ext4 disk of `gib` GiB at `path`.
async fn new_disk(path: &Path, gib: u32, label: &str) -> Result<()> {
    let disk = path.to_string_lossy();
    sh("truncate", &["-s", &format!("{gib}G"), &disk]).await?;
    sh("mkfs.ext4", &["-q", "-F", "-m", "0", "-L", label, &disk]).await?;
    Ok(())
}

/// Checks an unpacked image's disk and shrinks it to what it holds, as it
/// is only read from.
async fn shrink(disk: &Path) -> Result<()> {
    let path = disk.to_string_lossy();
    // 1 means errors were fixed, such as a journal the stopped VM left.
    let checked = tokio::process::Command::new("e2fsck")
        .args(["-fy", &path])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .context("start e2fsck")?;
    if !matches!(checked.code(), Some(0 | 1)) {
        bail!("e2fsck {path} failed: {checked}");
    }
    sh("resize2fs", &["-M", &path]).await?;
    let header = sh("dumpe2fs", &["-h", &path]).await?;
    let field = |name: &str| -> Result<u64> {
        header
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().parse().ok())
            .with_context(|| format!("dumpe2fs: no {name}"))
    };
    let bytes = field("Block count:")? * field("Block size:")?;
    sh("truncate", &["-s", &bytes.to_string(), &path]).await?;
    Ok(())
}

/// Whether two paths are both there and different files: not hard links
/// to one file.
pub fn distinct_files(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() != b.dev() || a.ino() != b.ino(),
        _ => false,
    }
}

/// Hard-links when on the same filesystem, otherwise copies.
fn link_or_copy(src: &Path, dest: &Path) -> Result<()> {
    let src = absolute(src)?;
    if std::fs::hard_link(&src, dest).is_err() {
        std::fs::copy(&src, dest)?;
    }
    Ok(())
}

pub fn absolute(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("{} not found", path.display()))
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("spawn-jail-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("jail")).unwrap();
        std::fs::create_dir_all(dir.join("kept")).unwrap();
        dir
    }

    fn secret(dir: &Path) -> PathBuf {
        let path = dir.join("secret");
        std::fs::write(&path, "x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn keep_refuses_links_planted_in_a_jail() {
        let dir = scratch("keep");
        let secret = secret(&dir);
        let dest = dir.join("kept/vm.state");

        symlink(&secret, dir.join("jail/paused.state")).unwrap();
        assert!(keep(&dir.join("jail/paused.state"), &dest).is_err());
        assert_eq!(mode(&secret), 0o600);
        assert!(std::fs::symlink_metadata(&dest).is_err());

        std::fs::hard_link(&secret, dir.join("jail/paused.mem")).unwrap();
        assert!(keep(&dir.join("jail/paused.mem"), &dest).is_err());
        assert_eq!(mode(&secret), 0o600);

        // Only root may give a file to root.
        if std::fs::metadata(&secret).unwrap().uid() == 0 {
            std::fs::write(dir.join("jail/ok"), "y").unwrap();
            keep(&dir.join("jail/ok"), &dest).unwrap();
            assert_eq!(mode(&dest), 0o644);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn links_from_a_jail_must_be_regular_files() {
        let dir = scratch("link");
        let secret = secret(&dir);
        let dest = dir.join("kept/rootfs.ext4");
        symlink(&secret, dir.join("jail/rootfs.ext4")).unwrap();
        assert!(link_from_jail(&dir.join("jail/rootfs.ext4"), &dest).is_err());
        assert!(std::fs::symlink_metadata(&dest).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
