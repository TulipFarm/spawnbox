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
    api: PathBuf,
    child: Child,
    lift: Arc<Mutex<Lift>>,
    pager: Option<Box<Pager>>,
    dirty: AtomicBool,
}

#[derive(Default)]
struct Lift {
    count: u32,
    old: String,
}

/// From `Vm::lift_memory_max`. Dropping it puts the limit back once no
/// other guard is left.
pub struct MemoryLift {
    file: PathBuf,
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
        if lift.count == 0
            && let Err(error) = std::fs::write(&self.file, &lift.old)
        {
            eprintln!("warning: write {}: {error}", self.file.display());
        }
    }
}

impl Vm {
    pub async fn start(host: &Host, jail: Jail, net: Netns, limits: &Limits) -> Result<Self> {
        let log = std::fs::File::create(host.logs.join(format!("{}.log", jail.id)))?;
        let uid = jail.uid.to_string();
        let cpu_max = format!("cpu.max={} 100000", u32::from(limits.vcpus) * 100_000);
        let memory_max = format!(
            "memory.max={}",
            (u64::from(limits.memory_mib) + VMM_OVERHEAD_MIB) * 1024 * 1024
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
            .args(["--", "--api-sock", "/api.sock"])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .context("start jailer")?;
        let api = jail.root.join("api.sock");
        let mut vm = Self {
            jail,
            net,
            api,
            child,
            lift: Arc::default(),
            pager: None,
            dirty: AtomicBool::new(false),
        };
        vm.wait_for_api().await?;
        Ok(vm)
    }

    async fn wait_for_api(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while UnixStream::connect(&self.api).await.is_err() {
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

    /// Removes the cgroup's memory limit until the last returned guard is
    /// dropped. A snapshot's memory file is page cache charged to the VM:
    /// at the limit every page would wait for the disk, and while the
    /// pages are dirty the kernel cannot drop them, so a running VM at its
    /// limit is killed.
    pub fn lift_memory_max(&self) -> Result<MemoryLift> {
        let file = Path::new(CGROUP_ROOT)
            .join(CGROUP_PARENT)
            .join(&self.jail.id)
            .join("memory.max");
        let mut lift = self.lift.lock().unwrap_or_else(|e| e.into_inner());
        if lift.count == 0 {
            let old = std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?;
            std::fs::write(&file, "max").with_context(|| format!("write {}", file.display()))?;
            lift.old = old.trim().to_owned();
        }
        lift.count += 1;
        Ok(MemoryLift {
            file,
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
        let stream = UnixStream::connect(&self.api).await?;
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
