//! Runs Firecracker under its jailer and talks to its API socket.

use std::os::unix::fs::chown;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

use crate::net::Netns;
use crate::sh::run;
use crate::uffd::Pager;

/// Every VM gets its own unprivileged uid and gid, counting up from here.
const UID_BASE: u32 = 200_000;
pub(crate) const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// Every VM's and gVisor container's cgroup is in here.
pub(crate) const CGROUP_PARENT: &str = "spawnbox";
/// Firecracker's (or gVisor's) own memory on top of guest memory.
pub(crate) const VMM_OVERHEAD_MIB: u64 = 256;
/// Room above `memory.high` before the kernel kills the VM. Guest disk
/// writes are dirty page cache charged to the VM; above `memory.high` the
/// writer waits for the disk instead of the VM being killed.
const WRITEBACK_MARGIN_MIB: u64 = 256;
const KSM_RUN: &str = "/sys/kernel/mm/ksm/run";
const PR_SET_MEMORY_MERGE: nix::libc::c_int = 67;

#[derive(Clone)]
pub struct Host {
    pub jailer: PathBuf,
    pub firecracker: PathBuf,
    /// Jails are built in `<jails>/firecracker/<id>/root`.
    pub jails: PathBuf,
    pub logs: PathBuf,
    /// Lets the kernel merge equal memory pages across VMs (KSM). Saves
    /// memory, but a guest can time page writes to guess what another
    /// guest holds, so use it only when all guests trust each other.
    pub ksm: bool,
    /// Keeps each vCPU on one host CPU; see `CpuPins`.
    pub pins: Option<Arc<CpuPins>>,
    /// How Firecracker does disk IO for drives it boots with. Snapshots
    /// keep the engine of the VM they were taken from.
    pub io_engine: IoEngine,
}

/// Firecracker's block device IO engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoEngine {
    /// Blocking reads and writes.
    Sync,
    /// io_uring. Needs Linux 5.10.51 or later; upstream calls it a
    /// developer preview.
    Async,
}

/// Gives each VM its own host CPUs, least used first. A VM's vCPUs share
/// one L3 cache while it has free CPUs, since vCPUs that work together
/// (for example a garbage collector's threads) are much slower across L3
/// caches. Different VMs go to the least used L3 caches, since CPUs that
/// share an L3 also share its link to memory. A vCPU that moves between
/// host CPUs loses its caches and runs slower. Under nested
/// virtualization (a cloud VM running Firecracker) a vCPU that moves
/// between host CPUs can fail to enter the guest (`KVM_EXIT_FAIL_ENTRY`)
/// once many VMs share each CPU, and Firecracker exits. A vCPU that stays
/// on one CPU does not.
pub struct CpuPins {
    used: Mutex<Vec<CpuSlot>>,
    /// The CPUs this process may run on. Firecracker's other threads, which
    /// emulate disks and the network, run on any of them.
    all: nix::sched::CpuSet,
}

struct CpuSlot {
    cpu: usize,
    /// Which L3 cache the CPU uses.
    l3: usize,
    /// How many vCPUs are pinned to it.
    vcpus: u32,
}

impl CpuPins {
    /// Over the CPUs this process may run on.
    pub fn new() -> Result<Self> {
        let allowed = nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0))
            .context("read CPU affinity")?;
        let used: Vec<_> = (0..nix::sched::CpuSet::count())
            .filter(|&cpu| allowed.is_set(cpu).unwrap_or(false))
            .map(|cpu| CpuSlot {
                cpu,
                l3: l3_of(cpu).unwrap_or(cpu),
                vcpus: 0,
            })
            .collect();
        if used.is_empty() {
            bail!("no CPUs to pin vCPUs to");
        }
        Ok(Self {
            used: Mutex::new(used),
            all: allowed,
        })
    }

    /// Whether this host is itself a virtual machine.
    pub fn nested() -> bool {
        std::fs::read_to_string("/proc/cpuinfo").is_ok_and(|info| {
            info.lines()
                .filter(|line| line.starts_with("flags"))
                .any(|line| line.split_whitespace().any(|flag| flag == "hypervisor"))
        })
    }

    /// One CPU for each of `vcpus`, distinct while there are enough.
    fn take(self: &Arc<Self>, vcpus: u8) -> CpuLease {
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        let mut cpus = Vec::new();
        for _ in 0..vcpus.max(1) {
            let mut l3_load = std::collections::HashMap::<usize, u32>::new();
            for slot in used.iter() {
                *l3_load.entry(slot.l3).or_default() += slot.vcpus;
            }
            let mine: Vec<_> = used
                .iter()
                .filter(|slot| cpus.contains(&slot.cpu))
                .map(|slot| slot.l3)
                .collect();
            let key = |slot: &CpuSlot| {
                (
                    slot.vcpus,
                    !mine.contains(&slot.l3),
                    l3_load[&slot.l3],
                    slot.cpu,
                )
            };
            let best = used
                .iter()
                .enumerate()
                .filter(|(_, slot)| !cpus.contains(&slot.cpu))
                .min_by_key(|(_, slot)| key(slot))
                .or_else(|| used.iter().enumerate().min_by_key(|(_, slot)| key(slot)))
                .map(|(i, _)| i)
                .expect("not empty");
            used[best].vcpus += 1;
            cpus.push(used[best].cpu);
        }
        CpuLease {
            pins: Arc::clone(self),
            cpus,
        }
    }
}

/// The CPUs one VM is pinned to; vCPU `n` runs on `cpus[n]`.
struct CpuLease {
    pins: Arc<CpuPins>,
    cpus: Vec<usize>,
}

impl CpuLease {
    fn set(&self) -> Result<nix::sched::CpuSet> {
        let mut set = nix::sched::CpuSet::new();
        for &cpu in &self.cpus {
            set.set(cpu)?;
        }
        Ok(set)
    }
}

impl Drop for CpuLease {
    fn drop(&mut self) {
        let mut used = self.pins.used.lock().unwrap_or_else(|e| e.into_inner());
        for cpu in &self.cpus {
            if let Some(slot) = used.iter_mut().find(|slot| slot.cpu == *cpu) {
                slot.vcpus = slot.vcpus.saturating_sub(1);
            }
        }
    }
}

/// The id of the L3 cache `cpu` uses, from sysfs.
fn l3_of(cpu: usize) -> Option<usize> {
    let caches = std::fs::read_dir(format!("/sys/devices/system/cpu/cpu{cpu}/cache")).ok()?;
    caches.flatten().find_map(|cache| {
        let level = std::fs::read_to_string(cache.path().join("level")).ok()?;
        if level.trim() != "3" {
            return None;
        }
        std::fs::read_to_string(cache.path().join("id"))
            .ok()?
            .trim()
            .parse()
            .ok()
    })
}

impl Host {
    /// Creates the parent cgroup and lets VM cgroups use the CPU, memory and
    /// process-count controllers.
    pub fn setup(&self) -> Result<()> {
        // At boot systemd may not have enabled the cpu controller at the
        // root yet; it does so lazily, for example on the first user login.
        std::fs::write(
            Path::new(CGROUP_ROOT).join("cgroup.subtree_control"),
            "+cpu +memory +pids",
        )
        .context("enable root cgroup controllers")?;
        let parent = Path::new(CGROUP_ROOT).join(CGROUP_PARENT);
        std::fs::create_dir_all(&parent)?;
        std::fs::write(parent.join("cgroup.subtree_control"), "+cpu +memory +pids")
            .context("enable cgroup controllers")?;
        if self.ksm {
            std::fs::write(KSM_RUN, "1").context("turn on KSM")?;
        }
        std::fs::create_dir_all(&self.logs)?;
        Ok(())
    }

    /// Kills every VM and gVisor process, including ones left by a crashed
    /// run, then removes all jails and cgroups. A cgroup can only be removed once
    /// its processes have exited, so this retries briefly.
    pub async fn remove_all(&self) {
        let parent = Path::new(CGROUP_ROOT).join(CGROUP_PARENT);
        let mut removed = false;
        for _ in 0..100 {
            if let Ok(entries) = std::fs::read_dir(&parent) {
                for entry in entries.flatten().filter(|e| e.path().is_dir()) {
                    let _ = std::fs::write(entry.path().join("cgroup.kill"), "1");
                    let _ = std::fs::remove_dir(entry.path());
                }
            }
            removed = std::fs::remove_dir(&parent).is_ok() || !parent.exists();
            if removed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if !removed {
            eprintln!("warning: could not remove {}", parent.display());
        }
        let _ = std::fs::remove_dir_all(&self.jails);
    }

    /// Removes the jail and cgroup that a failed start left for VM `id`.
    /// Its Firecracker process was killed when its `Vm` was dropped.
    pub async fn remove_vm(&self, id: &str) {
        let _ = std::fs::remove_dir_all(self.jails.join("firecracker").join(id));
        let cgroup = Path::new(CGROUP_ROOT).join(CGROUP_PARENT).join(id);
        let _ = std::fs::write(cgroup.join("cgroup.kill"), "1");
        for _ in 0..100 {
            if std::fs::remove_dir(&cgroup).is_ok() || !cgroup.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        eprintln!("warning: could not remove {}", cgroup.display());
    }

    /// Kills every process of VM `id`. True once its cgroup is empty.
    pub async fn kill_cgroup(&self, id: &str) -> bool {
        kill_cgroup(&Path::new(CGROUP_ROOT).join(CGROUP_PARENT).join(id), 250).await
    }
}

/// Kills every process in the cgroup at `dir`, then checks `tries` times,
/// 20 ms apart, that it is empty. True if it is, or does not exist.
pub async fn kill_cgroup(dir: &Path, tries: u32) -> bool {
    let _ = std::fs::write(dir.join("cgroup.kill"), "1");
    for _ in 0..tries {
        match std::fs::read_to_string(dir.join("cgroup.procs")) {
            Ok(procs) if procs.trim().is_empty() => return true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            _ => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    false
}

/// The cgroup that holds every VM's and gVisor container's cgroup.
pub fn cgroups() -> PathBuf {
    Path::new(CGROUP_ROOT).join(CGROUP_PARENT)
}

/// The cgroup of the process that kills the VMs if the server dies. Not
/// under [`cgroups`], and not in the server's own cgroup.
pub fn guard_cgroup() -> PathBuf {
    Path::new(CGROUP_ROOT).join(format!("{CGROUP_PARENT}-guard"))
}

/// Kills every VM and gVisor process of this server at once, without an
/// async runtime, and waits up to `wait` until they are gone. False if
/// some are left.
pub fn kill_all_now(wait: Duration) -> bool {
    kill_children(&cgroups(), wait)
}

fn kill_children(parent: &Path, wait: Duration) -> bool {
    let children = || -> Vec<PathBuf> {
        std::fs::read_dir(parent)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect()
    };
    for dir in children() {
        let _ = std::fs::write(dir.join("cgroup.kill"), "1");
    }
    let deadline = Instant::now() + wait;
    loop {
        let left = children().iter().any(|dir| {
            std::fs::read_to_string(dir.join("cgroup.procs"))
                .is_ok_and(|procs| !procs.trim().is_empty())
        });
        if !left {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A jail directory being filled before Firecracker starts.
pub struct Jail {
    id: String,
    uid: u32,
    dir: PathBuf,
    root: PathBuf,
}

impl Jail {
    pub fn new(host: &Host, id: &str, index: u32) -> Result<Self> {
        let dir = host.jails.join("firecracker").join(id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        let root = dir.join("root");
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            id: id.to_owned(),
            uid: UID_BASE + index,
            dir,
            root,
        })
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Shares a read-only file with the jail without copying it.
    pub fn link(&self, src: &Path, name: &str) -> Result<()> {
        std::fs::hard_link(src, self.root.join(name))
            .with_context(|| format!("link {} into jail {}", src.display(), self.id))
    }

    /// Gives the jail its own copy of a disk. Holes stay holes, so a mostly
    /// empty 20 GiB disk copies quickly.
    pub async fn copy_disk(&self, src: &Path, name: &str) -> Result<()> {
        let dest = self.root.join(name);
        let (src, dest_str) = (src.to_string_lossy(), dest.to_string_lossy());
        run(
            "cp",
            &["--sparse=always", "--reflink=auto", &src, &dest_str],
        )
        .await?;
        self.give(name)
    }

    /// Makes a file in the jail owned by the jailed Firecracker user.
    pub fn give(&self, name: &str) -> Result<()> {
        chown(self.root.join(name), Some(self.uid), Some(self.uid))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub vcpus: u8,
    pub memory_mib: u32,
}

pub struct Vm {
    jail: Jail,
    net: Netns,
    child: Child,
    lift: Arc<Mutex<Lift>>,
    pager: Option<Box<Pager>>,
    dirty: AtomicBool,
    lease: Option<Box<CpuLease>>,
}

#[derive(Default)]
struct Lift {
    count: u32,
    /// `memory.high` and `memory.max` as they were before the lift.
    old: [String; 2],
}

const MEMORY_FILES: [&str; 2] = ["memory.high", "memory.max"];

/// From `Vm::lift_memory_max`. Dropping it puts the limit back once no
/// other guard is left.
pub struct MemoryLift {
    cgroup: PathBuf,
    lift: Arc<Mutex<Lift>>,
}

impl MemoryLift {
    /// Never puts the limit back, for a VM that is about to stop.
    pub fn keep(self) {
        std::mem::forget(self);
    }
}

impl Drop for MemoryLift {
    fn drop(&mut self) {
        let mut lift = self.lift.lock().unwrap_or_else(|e| e.into_inner());
        lift.count -= 1;
        if lift.count == 0 {
            for (name, old) in MEMORY_FILES.iter().zip(&lift.old) {
                let file = self.cgroup.join(name);
                if let Err(error) = std::fs::write(&file, old) {
                    eprintln!("warning: write {}: {error}", file.display());
                }
            }
        }
    }
}

impl Vm {
    pub async fn start(host: &Host, jail: Jail, net: Netns, limits: &Limits) -> Result<Self> {
        let log = std::fs::File::create(host.logs.join(format!("{}.log", jail.id)))?;
        let uid = jail.uid.to_string();
        let cpu_max = format!("cpu.max={} 100000", u32::from(limits.vcpus) * 100_000);
        let high_mib = u64::from(limits.memory_mib) + VMM_OVERHEAD_MIB;
        let memory_high = format!("memory.high={}", high_mib * 1024 * 1024);
        let memory_max = format!(
            "memory.max={}",
            (high_mib + WRITEBACK_MARGIN_MIB) * 1024 * 1024
        );
        let mut command = Command::new(&host.jailer);
        if host.ksm {
            // SAFETY: prctl is async-signal-safe. The jailer and Firecracker
            // keep the setting across fork and exec (Linux 6.7 and later).
            unsafe {
                command.pre_exec(|| {
                    if nix::libc::prctl(PR_SET_MEMORY_MERGE, 1, 0, 0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let lease = host
            .pins
            .as_ref()
            .map(|pins| Box::new(pins.take(limits.vcpus)));
        if let Some(lease) = &lease {
            // Every thread starts on the VM's CPUs; `pin_vcpus` then gives
            // each vCPU thread its own and lets the other threads run on
            // any CPU.
            let set = lease.set()?;
            // SAFETY: sched_setaffinity is a plain syscall, safe after fork.
            unsafe {
                command.pre_exec(move || {
                    nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &set)
                        .map_err(std::io::Error::from)
                });
            }
        }
        let child = command
            .args(["--id", &jail.id, "--uid", &uid, "--gid", &uid])
            .arg("--exec-file")
            .arg(&host.firecracker)
            .arg("--chroot-base-dir")
            .arg(&host.jails)
            .arg("--netns")
            .arg(net.path())
            .args(["--cgroup-version", "2", "--parent-cgroup", CGROUP_PARENT])
            .args(["--cgroup", &cpu_max, "--cgroup", &memory_max])
            .args(["--cgroup", &memory_high])
            .args(["--", "--api-sock", "/api.sock"])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .context("start jailer")?;
        let mut vm = Self {
            jail,
            net,
            child,
            lift: Arc::default(),
            pager: None,
            dirty: AtomicBool::new(false),
            lease,
        };
        vm.wait_for_api().await?;
        Ok(vm)
    }

    /// How Firecracker ended, if it has: the guest crashed or was killed.
    pub fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(format!("Firecracker exited with {status}")),
            Ok(None) | Err(_) => None,
        }
    }

    /// Whether the vCPU threads must be pinned one by one once they exist:
    /// the VM has more than one vCPU and its vCPUs are pinned.
    pub fn pins_each_vcpu(&self) -> bool {
        self.lease
            .as_ref()
            .is_some_and(|lease| lease.cpus.len() > 1)
    }

    /// Moves each vCPU thread (`fc_vcpu <n>`) to its own CPU, and lets
    /// Firecracker's other threads run on any CPU, so disk and network
    /// emulation do not wait for the vCPUs. Call it once Firecracker has
    /// made the vCPU threads, before they run if possible.
    pub fn pin_vcpus(&self) -> Result<()> {
        let Some(lease) = self.lease.as_ref() else {
            return Ok(());
        };
        let pid = self.pid().context("Firecracker has exited")?;
        for task in std::fs::read_dir(format!("/proc/{pid}/task"))?.flatten() {
            let Some(tid) = task.file_name().to_str().and_then(|t| t.parse().ok()) else {
                continue;
            };
            let comm = std::fs::read_to_string(task.path().join("comm")).unwrap_or_default();
            let vcpu = comm
                .trim()
                .strip_prefix("fc_vcpu ")
                .and_then(|n| n.parse::<usize>().ok());
            let set = match vcpu {
                Some(n) => {
                    let mut set = nix::sched::CpuSet::new();
                    set.set(lease.cpus[n % lease.cpus.len()])?;
                    set
                }
                None => lease.pins.all,
            };
            nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(tid), &set)
                .with_context(|| format!("set the CPUs of thread {tid} of {}", self.jail.id))?;
        }
        Ok(())
    }

    fn api(&self) -> PathBuf {
        self.jail.root.join("api.sock")
    }

    async fn wait_for_api(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while UnixStream::connect(self.api()).await.is_err() {
            if let Some(status) = self.child.try_wait()? {
                bail!("jailer exited with {status}; see logs for {}", self.jail.id);
            }
            if Instant::now() > deadline {
                bail!("Firecracker API did not start for {}", self.jail.id);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        self.jail.root()
    }

    pub fn uid(&self) -> u32 {
        self.jail.uid()
    }

    /// Firecracker's process ID. The jailer runs it in its own process.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// The VM was loaded from the file `vm.mem` in its jail with dirty page
    /// tracking, and no snapshot was taken since: a diff snapshot over that
    /// file is complete.
    pub fn set_dirty_tracked(&self) {
        self.dirty.store(true, Ordering::SeqCst);
    }

    /// Whether a diff snapshot can be taken, and forgets it: any snapshot
    /// resets the dirty pages.
    pub fn take_dirty_tracked(&self) -> bool {
        self.dirty.swap(false, Ordering::SeqCst)
    }

    /// Serves the VM's memory with `pager` until the VM stops.
    pub fn set_pager(&mut self, pager: Pager) {
        self.pager = Some(Box::new(pager));
    }

    pub fn pager(&self) -> Option<&Pager> {
        self.pager.as_deref()
    }

    pub fn pager_mut(&mut self) -> Option<&mut Pager> {
        self.pager.as_deref_mut()
    }

    /// Removes the cgroup's memory limits until the last returned guard is
    /// dropped. A snapshot's memory file is page cache charged to the VM:
    /// at the limit every page would wait for the disk, and while the
    /// pages are dirty the kernel cannot drop them, so a running VM at its
    /// limit is killed.
    pub fn lift_memory_max(&self) -> Result<MemoryLift> {
        let cgroup = Path::new(CGROUP_ROOT)
            .join(CGROUP_PARENT)
            .join(&self.jail.id);
        let mut lift = self.lift.lock().unwrap_or_else(|e| e.into_inner());
        if lift.count == 0 {
            let mut old: [String; 2] = Default::default();
            for (name, old) in MEMORY_FILES.iter().zip(&mut old) {
                let file = cgroup.join(name);
                *old = std::fs::read_to_string(&file)
                    .with_context(|| format!("read {}", file.display()))?
                    .trim()
                    .to_owned();
            }
            for name in MEMORY_FILES {
                let file = cgroup.join(name);
                std::fs::write(&file, "max")
                    .with_context(|| format!("write {}", file.display()))?;
            }
            lift.old = old;
        }
        lift.count += 1;
        Ok(MemoryLift {
            cgroup,
            lift: self.lift.clone(),
        })
    }

    pub fn dialer(&self) -> crate::guest::Dialer {
        crate::guest::Dialer::Vsock(self.jail.root.join("v.sock"))
    }

    pub fn host_ip(&self) -> std::net::Ipv4Addr {
        self.net.host_ip()
    }

    pub async fn set_rates(&self, send: Option<u32>, receive: Option<u32>) -> Result<()> {
        self.net.set_rates(send, receive).await
    }

    pub async fn put(&self, path: &str, body: Value) -> Result<()> {
        self.call(Method::PUT, path, body).await
    }

    pub async fn patch(&self, path: &str, body: Value) -> Result<()> {
        self.call(Method::PATCH, path, body).await
    }

    async fn call(&self, method: Method, path: &str, body: Value) -> Result<()> {
        let stream = UnixStream::connect(self.api()).await?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(conn);
        let request = Request::builder()
            .method(method.clone())
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body.to_string())))?;
        let response = sender.send_request(request).await?;
        let status = response.status();
        let reply = response.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            bail!(
                "{method} {path} returned {status}: {}",
                String::from_utf8_lossy(&reply)
            );
        }
        Ok(())
    }

    /// Stops Firecracker and removes its jail, cgroup and network.
    pub async fn stop(mut self) {
        // First, so the pager does not report the VM as lost.
        drop(self.pager.take());
        // `kill` also waits for the process to exit, so its cgroup is empty.
        let _ = self.child.kill().await;
        let cgroup = Path::new(CGROUP_ROOT)
            .join(CGROUP_PARENT)
            .join(&self.jail.id);
        if let Err(error) = std::fs::remove_dir(&cgroup) {
            eprintln!("warning: remove {}: {error}", cgroup.display());
        }
        if let Err(error) = std::fs::remove_dir_all(&self.jail.dir) {
            eprintln!("warning: remove {}: {error}", self.jail.dir.display());
        }
        self.net.remove().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_child_cgroup_is_killed() {
        let parent = std::env::temp_dir().join(format!("spawnbox-cgroups-{}", std::process::id()));
        assert!(kill_children(&parent, Duration::ZERO));
        for id in ["a", "b"] {
            std::fs::create_dir_all(parent.join(id)).unwrap();
            std::fs::write(parent.join(id).join("cgroup.procs"), "").unwrap();
        }
        std::fs::write(parent.join("b").join("cgroup.procs"), "7\n").unwrap();
        assert!(!kill_children(&parent, Duration::from_millis(50)));
        for id in ["a", "b"] {
            let kill = std::fs::read_to_string(parent.join(id).join("cgroup.kill")).unwrap();
            assert_eq!(kill, "1");
        }
        std::fs::write(parent.join("b").join("cgroup.procs"), "").unwrap();
        assert!(kill_children(&parent, Duration::ZERO));
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[tokio::test]
    async fn a_cgroup_is_killed_once_it_is_empty() {
        let dir = std::env::temp_dir().join(format!("spawnbox-cgroup-{}", std::process::id()));
        assert!(kill_cgroup(&dir, 1).await);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cgroup.procs"), "42\n").unwrap();
        assert!(!kill_cgroup(&dir, 2).await);
        assert_eq!(
            std::fs::read_to_string(dir.join("cgroup.kill")).unwrap(),
            "1"
        );
        std::fs::write(dir.join("cgroup.procs"), "").unwrap();
        assert!(kill_cgroup(&dir, 1).await);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `cpus` CPUs, `per_l3` to each L3 cache.
    fn pins(cpus: usize, per_l3: usize) -> Arc<CpuPins> {
        Arc::new(CpuPins {
            used: Mutex::new(
                (0..cpus)
                    .map(|cpu| CpuSlot {
                        cpu,
                        l3: cpu / per_l3,
                        vcpus: 0,
                    })
                    .collect(),
            ),
            all: nix::sched::CpuSet::new(),
        })
    }

    #[test]
    fn vms_spread_over_the_least_used_cpus() {
        let pins = pins(4, 4);
        let a = pins.take(1);
        let b = pins.take(2);
        let c = pins.take(1);
        assert_eq!(
            (a.cpus.clone(), b.cpus.clone(), c.cpus.clone()),
            (vec![0], vec![1, 2], vec![3])
        );
        drop(b);
        assert_eq!(pins.take(2).cpus, vec![1, 2]);
    }

    #[test]
    fn a_vm_with_more_vcpus_than_cpus_shares_them() {
        let pins = pins(2, 2);
        assert_eq!(pins.take(3).cpus, vec![0, 1, 0]);
    }

    #[test]
    fn a_vm_shares_one_l3_and_vms_spread_over_the_l3s() {
        let pins = pins(8, 4);
        let leases: Vec<_> = [2, 2, 1, 1, 3].map(|n| pins.take(n)).into();
        let cpus: Vec<_> = leases.iter().map(|lease| lease.cpus.clone()).collect();
        assert_eq!(
            cpus,
            [vec![0, 1], vec![4, 5], vec![2], vec![6], vec![3, 7, 0]]
        );
    }
}
