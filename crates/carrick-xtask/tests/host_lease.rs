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
    let close_scope = std::env::var_os("CARRICK_LEASE_CLOSE_SCOPE").is_some();
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
            if close_scope {
                // Like close_fds=True: close every inherited duplicate, while
                // retaining only this fixture's newly created control pipes.
                for &fd in &fds {
                    if fd > 2 && fd != control[0] && fd != ready[1] {
                        libc::close(fd);
                    }
                }
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
        let mut status = 0;
        assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        assert!(
            libc::WIFEXITED(status),
            "fork did not exit normally: {status}"
        );
        assert_eq!(libc::WEXITSTATUS(status), 0, "fork exit status");
    }
}

#[test]
fn runner_death_cancels_workload_before_releasing_exclusion() {
    runner_death_preserves_exclusion(false, false, false, None);
}

#[test]
fn runner_death_cancels_nested_workload_before_releasing_exclusion() {
    runner_death_preserves_exclusion(true, false, false, None);
}

#[test]
fn runner_death_cancels_detached_nested_workload_before_releasing_exclusion() {
    runner_death_preserves_exclusion(true, true, false, None);
}

#[test]
fn worktree_runner_death_cancels_nested_workload_before_releasing_exclusion() {
    runner_death_with_admission(true, true, false, false, None);
}

#[test]
fn worktree_runner_death_cancels_detached_workload_before_releasing_exclusion() {
    runner_death_with_admission(true, true, true, false, None);
}

#[test]
#[cfg(target_os = "linux")]
fn worktree_runner_death_cancels_detached_closed_scope_workload() {
    runner_death_with_admission(true, true, true, true, None);
}

#[test]
fn supervisor_sigterm_cancels_before_releasing_exclusion() {
    runner_death_preserves_exclusion(true, false, false, Some(libc::SIGTERM));
}

#[test]
fn supervisor_sigint_cancels_before_releasing_exclusion() {
    runner_death_preserves_exclusion(true, false, false, Some(libc::SIGINT));
}

#[test]
fn supervisor_sighup_cancels_before_releasing_exclusion() {
    runner_death_preserves_exclusion(true, false, false, Some(libc::SIGHUP));
}

#[test]
#[ignore = "known exclusion limit: SIGKILL destroys the sole flock owner"]
fn supervisor_sigkill_cannot_preserve_exclusion() {
    runner_death_preserves_exclusion(true, false, false, Some(libc::SIGKILL));
}

#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "known Darwin limit: detached descendants closing the scope writer escape"
)]
fn detached_closed_scope_descendant_is_cancelled() {
    runner_death_preserves_exclusion(true, true, true, None);
}

#[cfg(test)]
fn runner_death_preserves_exclusion(
    nested: bool,
    detached: bool,
    close_scope: bool,
    supervisor_signal: Option<libc::c_int>,
) {
    runner_death_with_admission(false, nested, detached, close_scope, supervisor_signal);
}

#[cfg(test)]
fn runner_death_with_admission(
    admitted: bool,
    nested: bool,
    detached: bool,
    close_scope: bool,
    supervisor_signal: Option<libc::c_int>,
) {
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
    let repository = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    if admitted {
        for args in [
            vec!["init", "-q"],
            vec![
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "base",
            ],
        ] {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(repository.path())
                    .status()
                    .unwrap()
                    .success()
            );
        }
        command
            .arg("--root")
            .arg(repository.path())
            .args(["worktree-run", "--"])
            .arg(env!("CARGO_BIN_EXE_carrick-xtask"));
    }
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
    if close_scope {
        command.env("CARRICK_LEASE_CLOSE_SCOPE", "1");
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
    let checkout_lock = admitted.then(|| {
        let generation: serde_json::Value = serde_json::from_slice(
            &std::fs::read(repository.path().join(".git/carrick-checkout-generation")).unwrap(),
        )
        .unwrap();
        let path = repository
            .path()
            .join(".git/carrick-worktree-admission")
            .join(generation["token"].as_str().unwrap());
        std::fs::File::open(path).unwrap()
    });
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
        if let Some(checkout) = &checkout_lock {
            assert_eq!(
                libc::flock(checkout.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB),
                -1,
                "worktree admission missing before runner death"
            );
        }
        if let Some(signal) = supervisor_signal {
            // Readiness records the actual flock owner's PID, not the proxy.
            assert_eq!(libc::kill(*holder.parents.last().unwrap(), signal), 0);
        } else {
            holder.child.kill().unwrap();
        }
        // Child::wait closes its stdin. Preserve the fixture control channel
        // until the live-child and lock-release assertions have finished.
        holder.control = holder.child.stdin.take();
        holder.child.wait().unwrap();
        assert_eq!(count, 0, "test fork inherited the raw lease descriptor");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let (alive, release) = observe_exclusion(
                || is_process_alive(pid),
                || libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB),
            );
            assert!(
                release != 0 || !alive,
                "exclusion released while admitted {}workload PID {pid} survives runner death",
                if nested { "nested " } else { "" }
            );
            if let Some(checkout) = &checkout_lock {
                let (alive, released) = observe_exclusion(
                    || is_process_alive(pid),
                    || libc::flock(checkout.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB),
                );
                assert!(
                    released != 0 || !alive,
                    "checkout admission released while workload survives runner death"
                );
                if release == 0 && released == 0 {
                    break;
                }
            } else if release == 0 {
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
fn fork_fixture_rejects_abnormal_fork_exit() {
    let lock = tempfile::NamedTempFile::new().unwrap();
    let ready = tempfile::NamedTempFile::new().unwrap();
    let mut fixture = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", FORK_FIXTURE])
        .env("CARRICK_HOST_LEASE_PATH", lock.path())
        .env("CARRICK_LEASE_READY", ready.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let pid = loop {
        let data = std::fs::read_to_string(ready.path()).unwrap();
        if let Some(pid) = data.split_whitespace().next() {
            break pid.parse::<libc::pid_t>().unwrap();
        }
        if std::time::Instant::now() >= deadline {
            fixture.kill().unwrap();
            fixture.wait().unwrap();
            panic!("fork fixture readiness timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    // SAFETY: the fixture retains and reaps this exact child until stdin EOF.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    drop(fixture.stdin.take());
    let output = fixture.wait_with_output().unwrap();
    assert!(
        !output.status.success(),
        "fixture accepted a SIGKILLed fork as normal completion"
    );
    let combined_output = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined_output.contains("fork did not exit normally: 9"),
        "{combined_output}"
    );
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
fn cancellation_preserves_another_checkout_with_identical_command() {
    struct Fixture {
        runner: std::process::Child,
        control: Option<std::process::ChildStdin>,
        pids: Vec<libc::pid_t>,
    }
    impl Fixture {
        fn reap_known(&self) {
            #[cfg(target_os = "linux")]
            for &pid in self.pids.iter().skip(1) {
                // SAFETY: reap exact fixture/supervisor PIDs if adopted here.
                if pid > 0 {
                    unsafe {
                        libc::waitpid(pid, std::ptr::null_mut(), 0);
                    }
                }
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(self.control.take());
            let _ = self.runner.kill();
            let _ = self.runner.wait();
            if let Some(&fork) = self.pids.first() {
                // SAFETY: exact fixture PID recorded at its fork readiness.
                unsafe {
                    libc::kill(fork, libc::SIGKILL);
                }
            }
            self.reap_known();
        }
    }
    let lock = tempfile::NamedTempFile::new().unwrap();
    let spawn = |checkout: &std::path::Path, ready: &std::path::Path| {
        let mut runner = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["host-lease", "--mode", "carrick", "--"])
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", FORK_FIXTURE])
            .current_dir(checkout)
            .env_remove("CARRICK_HOST_LEASE_SOCKET")
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env("CARRICK_HOST_LEASE_PATH", lock.path())
            .env("CARRICK_LEASE_READY", ready)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let control = runner.stdin.take();
        let mut fixture = Fixture {
            runner,
            control,
            pids: Vec::new(),
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let data = std::fs::read_to_string(ready).unwrap();
            let fields: Vec<_> = data.split_whitespace().collect();
            if fields.len() == 5 {
                assert_eq!(fields[1], "0", "fixture inherited flock");
                fixture.pids = [fields[0], fields[2], fields[3], fields[4]]
                    .iter()
                    .map(|p| p.parse().unwrap())
                    .collect();
                return fixture;
            }
            assert!(fixture.runner.try_wait().unwrap().is_none());
            assert!(
                std::time::Instant::now() < deadline,
                "checkout fixture not ready"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    };
    let checkout_a = tempfile::tempdir().unwrap();
    let checkout_b = tempfile::tempdir().unwrap();
    let ready_a = tempfile::NamedTempFile::new().unwrap();
    let ready_b = tempfile::NamedTempFile::new().unwrap();
    // Identical executable, arguments and lease inode; only cwd/scope differ.
    let mut victim = spawn(checkout_a.path(), ready_a.path());
    let mut other = spawn(checkout_b.path(), ready_b.path());
    victim.runner.kill().unwrap();
    victim.runner.wait().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        assert!(
            is_process_alive(other.pids[0]),
            "cancellation selected another checkout's fork"
        );
        assert!(
            is_process_alive(other.pids[1]),
            "cancellation selected another checkout's test process"
        );
        if !is_process_alive(victim.pids[0]) && !is_process_alive(victim.pids[1]) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "cancelled checkout's workload survived"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    victim.reap_known();
    victim.pids.clear(); // Exit observations also prevent signalling reused IDs.
    assert!(
        other.runner.try_wait().unwrap().is_none(),
        "other checkout's runner was cancelled"
    );
    drop(other.control.take());
    assert!(other.runner.wait().unwrap().success());
    other.reap_known();
    other.pids.clear();
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

// Acquire exclusion before observing liveness: a pre-acquisition observation
// can become stale during correctly ordered cancellation and release. Each
// independent lock needs its own subsequent liveness observation.
fn observe_exclusion(alive: impl FnOnce() -> bool, flock: impl FnOnce() -> i32) -> (bool, i32) {
    let release = flock();
    (alive(), release)
}

#[test]
fn death_before_release_does_not_report_live_workload() {
    use std::os::fd::AsRawFd;
    let lock = tempfile::NamedTempFile::new().unwrap();
    let lease = HostLease::acquire_path(lock.path(), HostLeaseMode::Gate).unwrap();
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    assert!(is_process_alive(pid));
    let (alive, release) = observe_exclusion(
        || is_process_alive(pid),
        || {
            // Deterministic interleaving: death is observed before exclusion
            // is released, strictly between the two test observations.
            child.kill().unwrap();
            child.wait().unwrap();
            drop(lease);
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }
        },
    );
    assert_eq!(release, 0);
    assert!(
        !alive,
        "correct death-before-release reported as live release"
    );
}

#[test]
fn live_workload_after_release_is_detected() {
    let acquired = std::cell::Cell::new(false);
    let (alive, release) = observe_exclusion(
        || {
            assert!(acquired.get(), "liveness observed before lock acquisition");
            true
        },
        || {
            acquired.set(true);
            0
        },
    );
    assert!(alive && release == 0, "missed live workload after release");
}

#[cfg(target_os = "macos")]
fn is_process_alive(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return false;
    }
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: correctly sized proc_bsdinfo output buffer.
    // arg=1 includes zombies so we can distinguish dead zombies from live processes.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            1,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if got == size {
        let info = unsafe { info.assume_init() };
        info.pbi_status != libc::SZOMB
    } else {
        false
    }
}

#[cfg(target_os = "linux")]
fn is_process_alive(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return false;
    }
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(after_comm) = stat.rfind(')').and_then(|idx| stat.get(idx + 1..)) else {
        return false;
    };
    let Some(state) = after_comm.split_whitespace().next() else {
        return false;
    };
    state != "Z"
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn is_process_alive(pid: libc::pid_t) -> bool {
    if pid <= 0 {
        return false;
    }
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn zombie_process_is_reported_dead_by_liveness_helper() {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // Child exits immediately to become a zombie.
        unsafe { libc::_exit(0) };
    }
    // Parent does NOT waitpid yet.
    // Wait until the child has exited and entered zombie state,
    // detected by observing its status through the platform API (not by sleeping).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        #[cfg(target_os = "macos")]
        {
            let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
            let got = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTBSDINFO,
                    1,
                    info.as_mut_ptr().cast(),
                    size,
                )
            };
            if got == size && unsafe { info.assume_init() }.pbi_status == libc::SZOMB {
                break;
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                if let Some(after_comm) = stat.rfind(')').and_then(|idx| stat.get(idx + 1..)) {
                    if after_comm.split_whitespace().next() == Some("Z") {
                        break;
                    }
                }
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        break;

        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for child {pid} to enter zombie state"
        );
        std::hint::spin_loop();
    }

    // The OLD probe (kill(pid, 0) == 0) erroneously reports the zombie as alive.
    let old_probe_alive = unsafe { libc::kill(pid, 0) == 0 };
    assert!(
        old_probe_alive,
        "old kill(pid, 0) probe must report zombie process {pid} as alive"
    );

    // The NEW helper must report the zombie as dead.
    assert!(
        !is_process_alive(pid),
        "new liveness helper must report zombie process {pid} as dead"
    );

    // Finally reap it.
    let mut status = 0;
    let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(reaped, pid, "failed to reap child process {pid}");
    assert!(
        !is_process_alive(pid),
        "reaped process must be reported dead"
    );
    assert!(
        unsafe { libc::kill(pid, 0) != 0 },
        "reaped process must return ESRCH from kill(pid, 0)"
    );
}
