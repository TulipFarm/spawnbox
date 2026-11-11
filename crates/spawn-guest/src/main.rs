//! `spawn-guest`: the agent inside every Spawnbox VM.
//!
//! As PID 1 it prepares the system, starts itself again as the agent, keeps
//! the sandbox's services running, and reaps orphaned processes. The agent serves gRPC to the host over vsock,
//! or over TCP under gVisor.

// Portable helpers are used only by the Linux agent but tested on every OS.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod identity;

#[cfg(target_os = "linux")]
mod agent;
#[cfg(target_os = "linux")]
mod exec;
#[cfg(target_os = "linux")]
mod files;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod ports;
#[cfg(target_os = "linux")]
mod pty;
#[cfg(target_os = "linux")]
mod reaper;
#[cfg(target_os = "linux")]
mod supervisor;
#[cfg(target_os = "linux")]
mod unpack;
#[cfg(target_os = "linux")]
mod volumes;

const AGENT_FLAG: &str = "--agent";
/// Set in the container's environment when the guest runs under gVisor.
const BACKEND_ENV: &str = "SPAWN_BACKEND";

/// gVisor sets up the root filesystem, mounts, clock and entropy itself,
/// and has no vsock.
fn under_gvisor() -> bool {
    std::env::var_os(BACKEND_ENV).is_some_and(|v| v == "gvisor")
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let as_agent = std::env::args().nth(1).as_deref() == Some(AGENT_FLAG);
    if as_agent || std::process::id() != 1 {
        return agent::run();
    }
    init::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("spawn-guest runs only inside a Linux VM");
    std::process::ExitCode::FAILURE
}
