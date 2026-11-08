//! Runs Spawnbox sandboxes on one Linux host: builds a template snapshot,
//! then restores jailed Firecracker VMs, or gVisor containers on hosts
//! without KVM, from it.

// Pure helpers are used only by the Linux code but tested on every OS.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod handshake;
pub mod netplan;

#[cfg(target_os = "linux")]
mod backend;
#[cfg(target_os = "linux")]
mod diff;
#[cfg(target_os = "linux")]
pub mod firecracker;
#[cfg(target_os = "linux")]
pub mod guest;
#[cfg(target_os = "linux")]
pub mod gvisor;
#[cfg(target_os = "linux")]
pub mod net;
#[cfg(target_os = "linux")]
mod node;
#[cfg(target_os = "linux")]
pub mod sh;
#[cfg(target_os = "linux")]
pub mod uffd;
#[cfg(target_os = "linux")]
pub mod volume;

#[cfg(target_os = "linux")]
pub use backend::{Backend, Vm};
#[cfg(target_os = "linux")]
pub use diff::finish_paused;
#[cfg(target_os = "linux")]
pub use node::{
    Build, Frozen, HOT_FILE, Log, Node, Recipe, RestoreSteps, Restored, ResumeError, Slot,
    TEMPLATE_INDEX, TemplateInfo, absolute, distinct_files, new_identity,
};
#[cfg(target_os = "linux")]
pub use volume::Attach;
