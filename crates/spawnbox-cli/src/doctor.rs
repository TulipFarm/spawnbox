use std::path::Path;

#[cfg(any(target_os = "linux", test))]
mod disk;
use std::process::ExitCode;

struct Check {
    name: &'static str,
    result: Outcome,
}

/// A warning does not fail the run.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Pass(String),
    Warn(String),
    Fail(String),
}

impl From<Result<String, String>> for Outcome {
    fn from(result: Result<String, String>) -> Self {
        match result {
            Ok(detail) => Self::Pass(detail),
            Err(detail) => Self::Fail(detail),
        }
    }
}

pub fn run(data_dir: &Path) -> ExitCode {
    println!("Spawnbox: basic host checks\n");

    let checks = [
        Check {
            name: "Linux host",
            result: require_linux(std::env::consts::OS).into(),
        },
        Check {
            name: "x86_64 architecture",
            result: require_architecture(std::env::consts::ARCH).into(),
        },
        Check {
            name: "Sandbox backend",
            result: check_backend().into(),
        },
        Check {
            name: "cgroup v2 controllers",
            result: check_cgroups().into(),
        },
        Check {
            name: "Data directory encryption",
            result: check_encryption(data_dir),
        },
    ];

    let mut passed = true;
    for check in checks {
        match check.result {
            Outcome::Pass(detail) => println!("PASS  {}: {detail}", check.name),
            Outcome::Warn(detail) => println!("WARN  {}: {detail}", check.name),
            Outcome::Fail(detail) => {
                passed = false;
                println!("FAIL  {}: {detail}", check.name);
            }
        }
    }

    println!(
        "\nThis is a prerequisite check, not a sandbox test. \
         It does not check cgroup delegation, Firecracker or runsc installation, \
         guest images, free storage, or network setup."
    );

    if passed {
        println!("Basic prerequisites passed. A real VM boot is still required.");
        ExitCode::SUCCESS
    } else {
        println!("Basic prerequisites failed. Use a Linux x86_64 host with cgroup v2.");
        ExitCode::FAILURE
    }
}

fn require_linux(os: &str) -> Result<String, String> {
    if os == "linux" {
        Ok(os.to_owned())
    } else {
        Err(format!("found {os}; Spawnbox runs sandboxes only on Linux"))
    }
}

fn require_architecture(arch: &str) -> Result<String, String> {
    if arch == "x86_64" {
        Ok(arch.to_owned())
    } else {
        Err(format!(
            "found {arch}; Spawnbox's initial runtime target is x86_64"
        ))
    }
}

/// Firecracker with a working KVM; otherwise gVisor, which needs no KVM
/// but isolates less.
#[cfg(target_os = "linux")]
fn check_backend() -> Result<String, String> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;

    let kvm = match OpenOptions::new().read(true).write(true).open("/dev/kvm") {
        Ok(kvm) => kvm,
        Err(error) => {
            return Ok(format!(
                "gVisor: cannot open /dev/kvm read-write ({error}). For microVM \
                 isolation, enable virtualization and run as root"
            ));
        }
    };

    const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
    // SAFETY: the file descriptor is live; this KVM ioctl takes no pointer argument.
    let version = unsafe { libc::ioctl(kvm.as_raw_fd(), KVM_GET_API_VERSION) };
    if version < 0 {
        return Err(format!(
            "KVM_GET_API_VERSION failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if version != 12 {
        return Err(format!("expected KVM API version 12, found {version}"));
    }

    Ok("Firecracker: KVM read-write access, API version 12".to_owned())
}

#[cfg(not(target_os = "linux"))]
fn check_backend() -> Result<String, String> {
    Err("requires Linux; run this command on your Linux test host".to_owned())
}

#[cfg(target_os = "linux")]
fn check_cgroups() -> Result<String, String> {
    let controllers =
        std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").map_err(|error| {
            format!("cannot read cgroup v2 controllers: {error}; mount cgroup v2 on the host")
        })?;
    require_controllers(&controllers)
}

#[cfg(not(target_os = "linux"))]
fn check_cgroups() -> Result<String, String> {
    Err("requires Linux; cgroup v2 is not available on this host".to_owned())
}

#[cfg(any(target_os = "linux", test))]
fn require_controllers(controllers: &str) -> Result<String, String> {
    let available: Vec<_> = controllers.split_whitespace().collect();
    let missing: Vec<_> = ["cpu", "memory", "pids"]
        .into_iter()
        .filter(|controller| !available.contains(controller))
        .collect();

    if missing.is_empty() {
        Ok("cpu, memory, pids available; delegation not checked".to_owned())
    } else {
        Err(format!(
            "missing controllers: {}; enable them in the host kernel and cgroup hierarchy",
            missing.join(", ")
        ))
    }
}

/// Paused sandboxes' memory and disks are stored in the data directory in
/// plain, so it should be on an encrypted disk.
#[cfg(target_os = "linux")]
fn check_encryption(data_dir: &Path) -> Outcome {
    use disk::{Host, SysFs};

    // The directory may not exist yet: the disk is that of its nearest
    // parent that does.
    let Some(path) = data_dir.ancestors().find_map(|p| p.canonicalize().ok()) else {
        return Outcome::Warn(format!("cannot resolve {}", data_dir.display()));
    };
    let Some(mountinfo) = SysFs.read("/proc/self/mountinfo") else {
        return Outcome::Warn("cannot read /proc/self/mountinfo".to_owned());
    };
    disk::encryption(&SysFs, &mountinfo, data_dir, &path)
}

#[cfg(not(target_os = "linux"))]
fn check_encryption(_data_dir: &Path) -> Outcome {
    Outcome::Warn("requires Linux; disk encryption not checked".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_hosts_outside_the_initial_runtime_target() {
        assert!(require_linux("linux").is_ok());
        assert!(require_linux("macos").is_err());
        assert!(require_architecture("x86_64").is_ok());
        assert!(require_architecture("aarch64").is_err());
    }

    #[test]
    fn accepts_required_controllers_in_any_order_with_other_controllers() {
        assert!(require_controllers("pids io\nmemory cpu cpuset\n").is_ok());
    }

    #[test]
    fn reports_missing_controllers_without_matching_partial_names() {
        let error = require_controllers("cpuset memory").unwrap_err();
        assert!(error.contains("missing controllers: cpu, pids"));
    }

    #[test]
    fn rejects_an_empty_controller_list() {
        let error = require_controllers("\n").unwrap_err();
        assert!(error.contains("missing controllers: cpu, memory, pids"));
    }
}
