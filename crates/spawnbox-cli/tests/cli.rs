use std::process::Command;

fn spawnbox() -> Command {
    Command::new(env!("CARGO_BIN_EXE_spawnbox"))
}

#[test]
fn help_lists_the_client_commands() {
    let output = spawnbox().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for command in [
        "login",
        "create",
        "exec",
        "sh",
        "cp",
        "templates",
        "events",
        "doctor",
    ] {
        assert!(stdout.contains(command), "missing {command}: {stdout}");
    }
}

#[test]
fn rejects_unknown_commands_and_extra_arguments() {
    for args in [
        vec!["fork"],
        vec!["doctor", "--unknown"],
        vec!["exec", "sbx_1"],
    ] {
        let output = spawnbox().args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn explains_a_missing_key_and_an_unreachable_server() {
    let home = std::env::temp_dir().join(format!("spawnbox-cli-home-{}", std::process::id()));
    let run = |extra: &[&str]| {
        let output = spawnbox()
            .args(["--url", "http://127.0.0.1:9"])
            .args(extra)
            .arg("ls")
            .env("HOME", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("SPAWNBOX_API_KEY")
            .env_remove("SPAWNBOX_URL")
            .output()
            .unwrap();
        (
            output.status.code(),
            String::from_utf8(output.stderr).unwrap(),
        )
    };
    let (code, stderr) = run(&[]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("spawnbox login"), "{stderr}");
    let (code, stderr) = run(&["--key", "sbx_org_x"]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("cannot reach http://127.0.0.1:9"),
        "{stderr}"
    );
}

#[test]
fn doctor_reports_all_checks_and_its_limits() {
    let output = spawnbox().arg("doctor").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    for name in [
        "Linux host",
        "x86_64 architecture",
        "Sandbox backend",
        "cgroup v2 controllers",
        "not a sandbox test",
    ] {
        assert!(stdout.contains(name), "missing {name}: {stdout}");
    }
    assert_eq!(output.status.success(), !stdout.contains("FAIL"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn doctor_does_not_report_a_non_linux_host_as_ready() {
    let output = spawnbox().arg("doctor").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Spawnbox runs sandboxes only on Linux")
    );
}
