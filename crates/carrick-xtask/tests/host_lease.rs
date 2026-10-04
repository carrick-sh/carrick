use carrick_xtask::host_lease::{HostLease, HostLeaseMode};
use std::process::{Command, Stdio};

const FORK_FIXTURE: &str = "fork_without_exec_fixture";

#[test]
#[ignore = "isolated fork fixture, invoked by lease regression"]
fn fork_without_exec_fixture() {
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    let path = std::env::var_os("CARRICK_HOST_LEASE_PATH").unwrap();
    let path = std::ffi::CString::new(path.as_bytes()).unwrap();
    // SAFETY: stat initializes the output for a valid C pathname.
    let mut lock = unsafe { std::mem::zeroed::<libc::stat>() };
    assert_eq!(unsafe { libc::stat(path.as_ptr(), &mut lock) }, 0);
    let fds: Vec<libc::c_int> = std::fs::read_dir("/dev/fd")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    let mut control = [0; 2];
    let mut ready = [0; 2];
    let detached = std::env::var_os("CARRICK_LEASE_DETACHED").is_some();
    // SAFETY: valid pipe arrays; after fork the child uses only libc and _exit.
    unsafe {
        assert_eq!(libc::pipe(control.as_mut_ptr()), 0);
        assert_eq!(libc::pipe(ready.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::close(control[1]);
            libc::close(ready[0]);
            let mut count = 0u32;
            for &fd in &fds {
                let mut stat = std::mem::zeroed::<libc::stat>();
                if libc::fstat(fd, &mut stat) == 0
                    && stat.st_dev == lock.st_dev
                    && stat.st_ino == lock.st_ino
                {
                    count += 1;
                }
            }
            if detached && libc::setsid() < 0 {
                libc::_exit(2);
            }
            libc::write(ready[1], (&count as *const u32).cast(), 4);
            if detached {
                loop {
                    libc::pause();
                }
            }
            let mut byte = 0u8;
            libc::read(control[0], (&mut byte as *mut u8).cast(), 1);
            libc::_exit(0);
        }
        libc::close(control[0]);
        libc::close(ready[1]);
        let mut count = 0u32;
        assert_eq!(libc::read(ready[0], (&mut count as *mut u32).cast(), 4), 4);
        libc::close(ready[0]);
        std::fs::write(
            std::env::var_os("CARRICK_LEASE_READY").unwrap(),
            format!(
                "{pid} {count} {} {} {}",
                std::process::id(),
                libc::getppid(),
                std::env::var("CARRICK_LEASE_SUPERVISOR").unwrap_or_else(|_| "0".into())
            ),
        )
        .unwrap();
        // Parent keeps stdin open after killing the lease runner. EOF is the
        // cleanup handshake on both red and green, so this fixture reaps its fork.
        std::io::stdin().read_exact(&mut [0]).ok();
        libc::close(control[1]);
        assert_eq!(libc::waitpid(pid, std::ptr::null_mut(), 0), pid);
    }
}

#[test]
fn runner_death_cancels_workload_before_releasing_exclusion() {
    runner_death_preserves_exclusion(false, false);
}

#[test]
fn runner_death_cancels_nested_workload_before_releasing_exclusion() {
    runner_death_preserves_exclusion(true, false);
}

#[test]
fn runner_death_cancels_detached_nested_workload_before_releasing_exclusion() {
    runner_death_preserves_exclusion(true, true);
}

#[cfg(test)]
fn runner_death_preserves_exclusion(nested: bool, detached: bool) {
    use std::os::fd::AsRawFd;
    // Linux subreaper configuration is process-wide; serialize that fixture
    // state only, while each admitted workload still runs its fork concurrently.
    #[cfg(target_os = "linux")]
    static SUBREAPER: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(target_os = "linux")]
    let _serial = SUBREAPER.lock().unwrap_or_else(|e| e.into_inner());
    #[cfg(target_os = "linux")]
    struct Subreaper(libc::c_int);
    #[cfg(target_os = "linux")]
    impl Drop for Subreaper {
        fn drop(&mut self) {
            // SAFETY: restore this fixture's prior process-wide setting.
            unsafe {
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, self.0);
            }
        }
    }
    #[cfg(target_os = "linux")]
    let _subreaper = {
        let mut previous = 0;
        // SAFETY: valid output and a process-scoped fixture setting. Cleanup
        // waits only its exact helper PID, never another parallel test's child.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut previous), 0);
            assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1), 0);
        }
        Subreaper(previous)
    };
    struct Cleanup {
        child: std::process::Child,
        control: Option<std::process::ChildStdin>,
        helper: Option<libc::pid_t>,
        fork: Option<libc::pid_t>,
        parents: Vec<libc::pid_t>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(pid) = self.fork {
                // SAFETY: this fixture owns the fork PID and its parent's wait.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            drop(self.control.take());
            drop(self.child.stdin.take());
            let _ = self.child.kill();
            let _ = self.child.wait();
            #[cfg(target_os = "linux")]
            if let Some(pid) = self.helper {
                // SAFETY: our adopted helper exits after EOF and reaps its fork.
                unsafe {
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
            }
            #[cfg(target_os = "linux")]
            for &pid in &self.parents {
                // SAFETY: wait only fixture/adopted supervisor PIDs, never -1.
                if pid > 0 {
                    unsafe {
                        libc::waitpid(pid, std::ptr::null_mut(), 0);
                    }
                }
            }
        }
    }
    let lock = tempfile::NamedTempFile::new().unwrap();
    let ready = tempfile::NamedTempFile::new().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    command.args(["host-lease", "--mode", "gate", "--"]);
    if nested {
        command.arg(env!("CARGO_BIN_EXE_carrick-xtask")).args([
            "host-lease",
            "--mode",
            "carrick",
            "--",
        ]);
    }
    if detached {
        command.env("CARRICK_LEASE_DETACHED", "1");
    }
    let mut holder = Cleanup {
        child: command
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", FORK_FIXTURE])
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env_remove("CARRICK_HOST_LEASE_SOCKET")
            .env("CARRICK_HOST_LEASE_PATH", lock.path())
            .env("CARRICK_LEASE_READY", ready.path())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
        control: None,
        helper: None,
        fork: None,
        parents: Vec::new(),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let (pid, count) = loop {
        let data = std::fs::read_to_string(ready.path()).unwrap();
        let fields: Vec<_> = data.split_whitespace().collect();
        if fields.len() == 5 {
            holder.helper = Some(fields[2].parse().unwrap());
            holder.parents = fields[3..].iter().map(|p| p.parse().unwrap()).collect();
            break (
                fields[0].parse::<libc::pid_t>().unwrap(),
                fields[1].parse::<u32>().unwrap(),
            );
        }
        assert!(
            holder.child.try_wait().unwrap().is_none(),
            "fixture exited before fork"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "fork readiness timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    holder.fork = Some(pid);
    // SAFETY: independent flock and existence checks do not modify the child.
    unsafe {
        if detached {
            assert_eq!(
                libc::getsid(pid),
                pid,
                "fixture must leave the runner's session"
            );
        }
        assert_eq!(
            libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB),
            -1
        );
        holder.child.kill().unwrap();
        // Child::wait closes its stdin. Preserve the fixture control channel
        // until the live-child and lock-release assertions have finished.
        holder.control = holder.child.stdin.take();
        holder.child.wait().unwrap();
        assert_eq!(count, 0, "test fork inherited the raw lease descriptor");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let release = libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB);
            let alive = libc::kill(pid, 0) == 0;
            assert!(
                release != 0 || !alive,
                "exclusion released while admitted {}workload PID {pid} survives runner death",
                if nested { "nested " } else { "" }
            );
            if release == 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "workload not cancelled and reaped"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        drop(holder.control.take());
    }
}

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
    // Other parallel tests can be between fork and exec; the named production
    // acquisition bound waits for that release instead of declaring a leak.
    HostLease::acquire_path(temp.path(), HostLeaseMode::Carrick).unwrap();
}

#[test]
fn nested_admission_requires_the_supervisor_scope_writer() {
    let lock = tempfile::NamedTempFile::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["host-lease", "--mode", "gate", "--", "/bin/sh", "-c"])
        .arg("unset CARRICK_HOST_LEASE_SCOPE_FD; exec \"$1\" host-lease --mode carrick -- /bin/echo SHOULD_NOT_RUN")
        .arg("scope-fixture")
        .arg(env!("CARGO_BIN_EXE_carrick-xtask"))
        .env_remove("CARRICK_HOST_LEASE_SOCKET")
        .env_remove("CARRICK_HOST_LEASE_FD")
        .env("CARRICK_HOST_LEASE_PATH", lock.path())
        .output().unwrap();
    assert!(
        !output.status.success(),
        "nested admission succeeded without a live scope writer"
    );
    assert!(output.stdout.is_empty(), "unscoped nested command ran");
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid inherited host lease"));
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
        .env_remove("CARRICK_HOST_LEASE_SOCKET")
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
            .env_remove("CARRICK_HOST_LEASE_MODE")
            .env_remove("CARRICK_HOST_LEASE_SOCKET");
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
