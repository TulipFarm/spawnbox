//! The two ways to run a guest: Firecracker microVMs, or gVisor containers
//! on hosts without KVM. `Vm` hides which one runs.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde_json::json;

use crate::firecracker;
use crate::guest::Dialer;
use crate::gvisor::Container;
use crate::volume::{self, Attach};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Firecracker,
    Gvisor,
}

impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Gvisor => "gvisor",
        }
    }

    /// The snapshot files of a build or a paused sandbox.
    pub fn snapshot_files(self) -> &'static [&'static str] {
        match self {
            Self::Firecracker => &["vm.state", "vm.mem", "upper.ext4"],
            Self::Gvisor => &["checkpoint.img", "pages.img", "pages_meta.img"],
        }
    }

    /// Firecracker if this host's KVM can be opened, otherwise gVisor.
    pub fn detect() -> Self {
        let kvm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm");
        if kvm.is_ok() {
            Self::Firecracker
        } else {
            Self::Gvisor
        }
    }
}

/// A running guest.
pub enum Vm {
    Firecracker(firecracker::Vm),
    Gvisor(Container),
}

impl Vm {
    pub fn dialer(&self) -> Dialer {
        match self {
            Self::Firecracker(vm) => vm.dialer(),
            Self::Gvisor(c) => c.dialer(),
        }
    }

    pub fn host_ip(&self) -> Ipv4Addr {
        match self {
            Self::Firecracker(vm) => vm.host_ip(),
            Self::Gvisor(c) => c.host_ip(),
        }
    }

    /// Limits what the guest sends and receives, in megabits per second.
    pub async fn set_rates(&self, send: Option<u32>, receive: Option<u32>) -> Result<()> {
        match self {
            Self::Firecracker(vm) => vm.set_rates(send, receive).await,
            Self::Gvisor(c) => c.set_rates(send, receive).await,
        }
    }

    /// Whether it has a read-only layer disk from a template's setup steps.
    pub fn has_layer(&self) -> bool {
        match self {
            Self::Firecracker(vm) => vm.root().join("layer.ext4").exists(),
            Self::Gvisor(c) => c.disks().any(|(_, name)| name == "layer.ext4"),
        }
    }

    /// Whether its base disk is its build's own, not `shared`.
    pub fn owns_rootfs(&self, shared: &Path) -> bool {
        let rootfs = match self {
            Self::Firecracker(vm) => Some(vm.root().join("rootfs.ext4")),
            Self::Gvisor(c) => c
                .disks()
                .find(|(_, name)| *name == "rootfs.ext4")
                .map(|(path, _)| path),
        };
        rootfs.is_some_and(|rootfs| crate::node::distinct_files(&rootfs, shared))
    }

    /// Gets a message once if the guest's memory could not be loaded and
    /// the guest was stopped. Only for a guest restored with
    /// `Node::restore_lazy`.
    pub fn take_lost(&mut self) -> Option<tokio::sync::oneshot::Receiver<String>> {
        match self {
            Self::Firecracker(vm) => vm.pager_mut().and_then(crate::uffd::Pager::take_lost),
            Self::Gvisor(_) => None,
        }
    }

    /// Why the guest is gone, if its process ended without `stop`.
    pub fn exited(&mut self) -> Option<String> {
        match self {
            Self::Firecracker(vm) => vm.exited(),
            Self::Gvisor(c) => c.exited(),
        }
    }

    /// Stops the guest's CPUs; its memory stays. For warm pools.
    pub async fn freeze(&self) -> Result<()> {
        match self {
            Self::Firecracker(vm) => vm.patch("/vm", json!({ "state": "Paused" })).await,
            Self::Gvisor(c) => c.pause().await,
        }
    }

    pub async fn thaw(&self) -> Result<()> {
        match self {
            Self::Firecracker(vm) => vm.patch("/vm", json!({ "state": "Resumed" })).await,
            Self::Gvisor(c) => c.resume().await,
        }
    }

    /// Attaches volumes to a running VM, as one from a warm pool. The guest
    /// must mount them afterwards. A gVisor container takes volumes only
    /// when it starts.
    pub async fn attach(&self, volumes: &[Attach]) -> Result<()> {
        if volumes.is_empty() {
            return Ok(());
        }
        volume::check(volumes)?;
        match self {
            Self::Firecracker(vm) => {
                volume::link(vm.root(), vm.uid(), volumes)?;
                volume::swap_in(vm, volumes).await
            }
            Self::Gvisor(_) => bail!("a running gVisor container cannot take volumes"),
        }
    }

    /// The guest's writable disk, to measure its use. For gVisor it is a
    /// `/proc` link to a deleted file.
    pub fn disk(&self) -> Option<PathBuf> {
        match self {
            Self::Firecracker(vm) => Some(vm.root().join("upper.ext4")),
            Self::Gvisor(c) => c.filestore().map(Path::to_path_buf),
        }
    }

    pub async fn stop(self) {
        match self {
            Self::Firecracker(vm) => vm.stop().await,
            Self::Gvisor(c) => c.stop().await,
        }
    }
}
