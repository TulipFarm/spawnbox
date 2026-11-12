//! `spawn-api guard` kills the VMs once the server's end of its pipe
//! closes, and not after the server disarms it.

use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// A fake VM cgroup without `cgroup.kill`, holding a real process.
fn vm(name: &str) -> (PathBuf, Child) {
    let parent =
        std::env::temp_dir().join(format!("spawnbox-guard-bin-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&parent);
    std::fs::create_dir_all(parent.join("vm")).unwrap();
    let process = Command::new("sleep").arg("30").spawn().unwrap();
    std::fs::write(
        parent.join("vm").join("cgroup.procs"),
        process.id().to_string(),
    )
    .unwrap();
    (parent, process)
}

fn guard(parent: &Path) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_spawn-api"))
        .arg("guard")
        .arg("--cgroup-parent")
        .arg(parent)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = [0; 6];
    let out = child.stdout.as_mut().unwrap();
    out.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready\n");
    child
}

#[test]
fn the_guard_kills_the_vms_when_the_server_is_gone() {
    let (parent, mut process) = vm("gone");
    let mut child = guard(&parent);
    drop(child.stdin.take());
    let status = process.wait().unwrap();
    assert_eq!(status.signal(), Some(9));
    // The fake cgroup still lists the process, so the guard gives up.
    assert!(!child.wait().unwrap().success());
    std::fs::remove_dir_all(&parent).unwrap();
}

#[test]
fn a_disarmed_guard_exits_without_killing() {
    let (parent, mut process) = vm("disarmed");
    let mut child = guard(&parent);
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"d").unwrap();
    assert!(child.wait().unwrap().success());
    drop(stdin);
    assert!(process.try_wait().unwrap().is_none());
    process.kill().unwrap();
    process.wait().unwrap();
    std::fs::remove_dir_all(&parent).unwrap();
}
