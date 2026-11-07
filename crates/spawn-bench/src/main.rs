//! Host-side checks for Spawnbox milestones. Runs Firecracker, so it needs
//! Linux with KVM.

// Pure helpers are used only by the Linux commands but tested on every OS.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod stats;

#[cfg(target_os = "linux")]
mod m0;

#[cfg(target_os = "linux")]
#[derive(clap::Parser)]
#[command(version, about)]
enum Cli {
    /// Boot a template, time snapshot restores, and check clone identity.
    M0(m0::Args),
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match <Cli as clap::Parser>::parse() {
        Cli::M0(args) => m0::run(args).await,
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("spawn-bench needs Linux with KVM");
    std::process::ExitCode::FAILURE
}
