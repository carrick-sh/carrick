#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const XTASK: &str = env!("CARGO_BIN_EXE_carrick-xtask");

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn line(reader: &mut BufReader<impl std::io::Read + AsRawFd>) -> String {
    if reader.buffer().is_empty() {
        let mut event = libc::pollfd {
            fd: reader.get_ref().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pipe descriptor; every fixture handshake is bounded.
        assert_eq!(unsafe { libc::poll(&mut event, 1, 5000) }, 1);
    }
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(!line.is_empty(), "broker/command exited before handshake");
    line
}

fn broker(
    path: &Path,
    mode: &str,
    wait_ms: u64,
) -> (Process, BufReader<std::process::ChildStdout>) {
    let mut child = Command::new(XTASK)
        .args(["host-lease", "broker", "--lock-path"])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.as_mut().unwrap(),
        "{{\"mode\":\"{mode}\",\"wait_ms\":{wait_ms}}}"
    )
    .ok(); // A pre-fix binary can exit before reading the request.
    let output = BufReader::new(child.stdout.take().unwrap());
    (Process(child), output)
}

#[test]
fn broker_two_clients_contend_then_proceed_for_every_exclusive_pair() {
    for held in ["gate", "docker", "carrick"] {
        for requested in ["gate", "docker", "carrick"] {
            let temp = tempfile::tempdir().unwrap();
            let lock = temp.path().join("lease.lock");
            std::fs::File::create(&lock).unwrap();
            let (mut first, mut first_out) = broker(&lock, held, 5000);
            assert_eq!(line(&mut first_out), "acquired\n");
            let (second, mut second_out) = broker(&lock, requested, 5000);
            if held == "carrick" && requested == "carrick" {
                assert_eq!(line(&mut second_out), "acquired\n");
            } else {
                assert_eq!(line(&mut second_out), "waiting\n");
                drop(first.0.stdin.take());
                assert!(first.0.wait().unwrap().success());
                assert_eq!(line(&mut second_out), "acquired\n");
            }
            drop(second);
        }
    }
}

#[test]
fn broker_killed_holder_releases_to_waiting_client() {
    let temp = tempfile::tempdir().unwrap();
    let lock = temp.path().join("lease.lock");
    std::fs::File::create(&lock).unwrap();
    let (mut first, mut first_out) = broker(&lock, "gate", 5000);
    assert_eq!(line(&mut first_out), "acquired\n");
    let (_second, mut second_out) = broker(&lock, "docker", 5000);
    assert_eq!(line(&mut second_out), "waiting\n");
    first.0.kill().unwrap();
    first.0.wait().unwrap();
    assert_eq!(line(&mut second_out), "acquired\n");
}

#[test]
fn broker_contention_expires_explicitly_and_disconnected_waiter_exits() {
    let temp = tempfile::tempdir().unwrap();
    let lock = temp.path().join("lease.lock");
    std::fs::File::create(&lock).unwrap();
    let (_first, mut first_out) = broker(&lock, "gate", 5000);
    assert_eq!(line(&mut first_out), "acquired\n");
    let (mut second, mut second_out) = broker(&lock, "docker", 0);
    assert_eq!(line(&mut second_out), "waiting\n");
    assert_eq!(line(&mut second_out), "timeout\n");
    assert!(!second.0.wait().unwrap().success());
    let started = std::time::Instant::now();
    let (mut timed, mut timed_out) = broker(&lock, "docker", 100);
    assert_eq!(line(&mut timed_out), "waiting\n");
    assert_eq!(line(&mut timed_out), "timeout\n");
    assert!(!timed.0.wait().unwrap().success());
    assert!(started.elapsed() < Duration::from_secs(5));
    let (mut third, mut third_out) = broker(&lock, "carrick", 5000);
    assert_eq!(line(&mut third_out), "waiting\n");
    drop(third.0.stdin.take());
    assert!(!third.0.wait().unwrap().success());
}

struct ClientSite {
    temp: tempfile::TempDir,
}

impl ClientSite {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        std::fs::File::create(temp.path().join("host.lock")).unwrap();
        // Local stdio transport, not a broker stub: exec the production binary.
        let transport = temp.path().join("ssh");
        std::fs::write(
            &transport,
            format!(
                "#!/bin/sh\nprintf '%s\\n' $$ > '{0}/broker.pid'\necho session >> '{0}/sessions'\nexec '{XTASK}' host-lease broker --lock-path '{0}/host.lock'\n",
                temp.path().display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(transport, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            temp.path().join("client.toml"),
            "broker = 'carrick-lease@10.77.0.1'\nidentity_file = '/unused/key'\nknown_hosts_file = '/unused/known_hosts'\n",
        )
        .unwrap();
        Self { temp }
    }

    fn xtask(&self) -> Command {
        let mut command = Command::new(XTASK);
        command
            .env_remove("CARRICK_HOST_LEASE_PATH")
            .env_remove("CARRICK_HOST_LEASE_SOCKET")
            .env_remove("CARRICK_HOST_LEASE_SCOPE_FD")
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env(
                "CARRICK_HOST_LEASE_CONFIG",
                self.temp.path().join("client.toml"),
            )
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.temp.path().display()),
            );
        command
    }

    fn command(&self, mode: &str) -> Command {
        let mut command = self.xtask();
        command.args(["host-lease", "--mode", mode, "--"]);
        command
    }

    #[cfg(target_os = "linux")]
    fn sessions(&self) -> usize {
        std::fs::read_to_string(self.temp.path().join("sessions"))
            .unwrap()
            .lines()
            .count()
    }
}

#[test]
#[cfg(target_os = "linux")]
fn broker_client_nested_gate_reuses_one_session_and_shared_cannot_upgrade() {
    for (outer, inner, success) in [("gate", "carrick", true), ("carrick", "gate", false)] {
        let site = ClientSite::new();
        let output = site
            .command(outer)
            .args([
                XTASK,
                "host-lease",
                "--mode",
                inner,
                "--",
                "/bin/echo",
                "nested",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            success,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(site.sessions(), 1, "nested client opened a second session");
        assert!(site.temp.path().join("host.lock").exists());
        if success {
            assert_eq!(output.stdout, b"nested\n");
        } else {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("no lock upgrades"));
        }
    }
}

#[test]
#[cfg(target_os = "linux")]
fn broker_client_connection_loss_cancels_workload_and_fails() {
    let site = ClientSite::new();
    let mut child = site
        .command("gate")
        .args(["/bin/sh", "-c", "echo ready; read finish"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut child = Process(child);
    assert_eq!(line(&mut output), "ready\n");
    let pid: i32 = std::fs::read_to_string(site.temp.path().join("broker.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: exact, live broker PID recorded by our transport before exec.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
    assert!(!child.0.wait().unwrap().success());
}

#[test]
fn broker_client_bad_configuration_never_falls_back_to_local_lock() {
    let site = ClientSite::new();
    std::fs::write(site.temp.path().join("client.toml"), "broker = 42\n").unwrap();
    let output = site
        .command("gate")
        .args(["/bin/echo", "unsafe"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "invalid site configuration admitted work"
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn broker_rejects_invalid_mode_and_excessive_wait_limit() {
    for request in [
        "{\"mode\":\"unknown\",\"wait_ms\":0}\n",
        "{\"mode\":\"gate\",\"wait_ms\":3600001}\n",
    ] {
        let mut child = Process(
            Command::new(XTASK)
                .args(["host-lease", "broker"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        child
            .0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(request.as_bytes())
            .ok();
        drop(child.0.stdin.take());
        assert!(!child.0.wait().unwrap().success());
    }
}

#[test]
fn broker_wait_bound_is_not_extended_by_partial_request() {
    // EOF in a partial request must fail before touching a host lock.
    let temp = tempfile::tempdir().unwrap();
    let lock = temp.path().join("lock");
    let (mut child, _out) = broker(&lock, "gate", Duration::from_secs(3601).as_millis() as u64);
    drop(child.0.stdin.take());
    assert!(!child.0.wait().unwrap().success());
    assert!(!lock.exists());
}

#[test]
fn broker_requires_existing_lock_file_without_o_creat() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing.lock");
    let (mut child, _out) = broker(&missing, "gate", 0);
    assert!(!child.0.wait().unwrap().success());
    assert!(!missing.exists(), "broker created a missing lock file");
}

#[test]
fn broker_and_in_process_controller_contend_on_one_inode_without_chmod() {
    use carrick_xtask::host_lease::{HostLease, HostLeaseMode};
    let lock = tempfile::NamedTempFile::new().unwrap();
    let lease = HostLease::acquire_path(lock.path(), HostLeaseMode::Gate).unwrap();
    std::fs::set_permissions(lock.path(), std::fs::Permissions::from_mode(0o660)).unwrap();
    let (_client, mut output) = broker(lock.path(), "docker", 5000);
    assert_eq!(line(&mut output), "waiting\n");
    drop(lease);
    assert_eq!(line(&mut output), "acquired\n");
    assert_eq!(
        std::fs::metadata(lock.path()).unwrap().permissions().mode() & 0o777,
        0o660
    );
}

#[test]
#[cfg(target_os = "linux")]
fn broker_configured_gate_session_refuses_target_pruning() {
    let site = ClientSite::new();
    let mut gate = site
        .command("gate")
        .args(["/bin/sh", "-c", "echo ready; read finish"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut gate_out = BufReader::new(gate.stdout.take().unwrap());
    let _gate = Process(gate);
    assert_eq!(line(&mut gate_out), "ready\n");

    let dev = site.temp.path().join("dev");
    let target = dev.join("wt/target");
    std::fs::create_dir_all(&target).unwrap();
    let output = site
        .xtask()
        .args(["target-prune", "--protocol", "fd-v1", "--dev-root"])
        .arg(&dev)
        .arg("--target-dir")
        .arg(&target)
        .args(["--days", "2", "--apply"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("target pruning skipped: host lease is held"),
        "target pruning did not contend on broker gate session: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[cfg(target_os = "linux")]
fn broker_ssh_custody_runs_in_isolated_session() {
    let site = ClientSite::new();
    let mut child = site
        .command("gate")
        .args(["/bin/sh", "-c", "echo ready; read finish"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let _child = Process(child);
    assert_eq!(line(&mut output), "ready\n");
    let broker_pid: libc::pid_t = std::fs::read_to_string(site.temp.path().join("broker.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let broker_pgid = unsafe { libc::getpgid(broker_pid) };
    let broker_sid = unsafe { libc::getsid(broker_pid) };
    assert_eq!(
        broker_pgid, broker_pid,
        "broker ssh transport is not its own process-group leader"
    );
    assert_eq!(
        broker_sid, broker_pid,
        "broker ssh transport is not its own session leader"
    );
}
