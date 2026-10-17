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
    let (_first, mut first_out) = broker(&lock, "gate", 5000);
    assert_eq!(line(&mut first_out), "acquired\n");
    let (mut second, mut second_out) = broker(&lock, "docker", 0);
    assert_eq!(line(&mut second_out), "waiting\n");
    assert!(!second.0.wait().unwrap().success());
    let started = std::time::Instant::now();
    let (mut timed, mut timed_out) = broker(&lock, "docker", 100);
    assert_eq!(line(&mut timed_out), "waiting\n");
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

    fn command(&self, mode: &str) -> Command {
        let mut command = Command::new(XTASK);
        command
            .args(["host-lease", "--mode", mode, "--"])
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
fn controller_site_declares_the_same_host_lock_as_the_broker() {
    let site = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/ci_scaler/site.rs"
    ))
    .unwrap();
    assert!(site.contains("host_lease: Some(crate::host_lease::broker::LOCK_PATH)"));
    let controller = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/ci_scaler/live.rs"
    ))
    .unwrap();
    let admission = controller.split("fn admit_one(").nth(1).unwrap();
    assert!(
        admission.find("clone_lease.acquire()?").unwrap()
            < admission.find("ledger.reserve(").unwrap()
    );
    assert!(controller.contains("clone_lease.release_if_idle(&ledger)"));
}
