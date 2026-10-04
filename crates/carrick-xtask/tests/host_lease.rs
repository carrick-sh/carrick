use carrick_xtask::host_lease::{HostLease, HostLeaseMode};
use std::process::{Command, Stdio};

#[test]
fn nested_cli_reuses_exclusive_gate_without_deadlock_or_downgrade() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    let gate = HostLease::acquire_path(temp.path(), HostLeaseMode::Gate).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    command.args(["host-lease", "--mode", "carrick", "--", "true"]);
    gate.configure_command(&mut command).unwrap();
    // Bound a bug in inheritance: a second flock would otherwise wait an hour.
    command.stdout(Stdio::null()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "nested CLI failed: {:?}",
                child.wait_with_output().unwrap()
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("nested CLI reacquired the gate lock and deadlocked");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // An independent description must still see the original gate as exclusive.
    use std::os::fd::AsRawFd;
    // SAFETY: temp owns the valid independent descriptor.
    assert_eq!(
        unsafe { libc::flock(temp.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EWOULDBLOCK)
    );
    drop(command);
    drop(gate);
    // SAFETY: temp still owns the independent descriptor.
    assert_eq!(
        unsafe { libc::flock(temp.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
        0
    );
}

#[test]
fn cli_load_check_runs_portable_ps_before_command() {
    let temp = tempfile::NamedTempFile::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args([
            "host-lease",
            "--mode",
            "carrick",
            "--check-load",
            "--",
            "true",
        ])
        .env_remove("CARRICK_HOST_LEASE_FD")
        .env_remove("CARRICK_HOST_LEASE_MODE")
        .env("CARRICK_HOST_LEASE_PATH", temp.path())
        // This test must not depend on unrelated load elsewhere on a CI host.
        .env("CARRICK_ALLOW_LOAD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("host-load:"));
}

#[test]
fn fake_ps_refuses_load_and_override_records_parent_command() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let ps = dir.path().join("ps");
    std::fs::write(&ps, "#!/bin/sh\ncase \"$*\" in\n*comm=*) printf '10 1 bash\\n21 10 /usr/bin/yes\\n' ;;\n*) printf '10 bash -c deliberate load\\n21 yes\\n' ;;\nesac\n").unwrap();
    std::fs::set_permissions(&ps, std::fs::Permissions::from_mode(0o755)).unwrap();
    let lock = dir.path().join("lock");
    let command = |allow_load: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
        command
            .env("PATH", dir.path())
            .env("CARRICK_ALLOW_LOAD", allow_load)
            .env("CARRICK_HOST_LEASE_PATH", &lock)
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env_remove("CARRICK_HOST_LEASE_MODE");
        command
    };
    for allow in ["0", "true", ""] {
        let output = command(allow)
            .args([
                "host-lease",
                "--mode",
                "carrick",
                "--check-load",
                "--",
                "/bin/echo",
                "RAN",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            output.stdout.is_empty(),
            "refused run must never start its command"
        );
        let log = String::from_utf8_lossy(&output.stderr);
        assert!(log.contains("yes PID 21: parent PID 10 command: bash -c deliberate load"));
        assert!(log.contains("CARRICK_ALLOW_LOAD=1"));
    }
    let output = command("1")
        .args([
            "host-lease",
            "--mode",
            "carrick",
            "--check-load",
            "--",
            "/bin/echo",
            "RAN",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "RAN\n");
    let log = String::from_utf8_lossy(&output.stderr);
    assert!(log.contains("CARRICK_ALLOW_LOAD=1; load present"));
    assert!(log.contains("parent PID 10 command: bash -c deliberate load"));
    let output = command("0")
        .args(["accept", "--phase", "host"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("refusing run: host load generators present")
    );
    assert!(
        output.stdout.is_empty(),
        "accept must refuse before starting host work"
    );
}
