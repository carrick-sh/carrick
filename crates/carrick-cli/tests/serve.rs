// Test-only crate: `unwrap`/`panic!` in the `spawn_server` test helper (a free
// fn, so clippy.toml's `allow-unwrap-in-tests`/`allow-panic-in-tests` do not
// cover it) are fine here.
#![allow(clippy::unwrap_used, clippy::panic)]

use assert_cmd::Command;
use std::time::Duration;

/// Kills the spawned `carrick serve` child on drop, so a panicking assertion in
/// a test cannot leak the server process.
struct ServerGuard(std::process::Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn serve_help_lists_docker_api_flag() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--docker-api"));
}

/// Codesign the test binary once with the hypervisor entitlement. The server we
/// spawn shells out to ITSELF (current_exe) to boot a guest under HVF, which
/// requires the `com.apple.security.hypervisor` entitlement; an unsigned binary
/// fails with HV_DENIED. assert_cmd's `cargo_bin` path is shared across the
/// concurrently-run tests in this binary, so sign it exactly once.
fn ensure_codesigned(bin: &std::path::Path) {
    use std::sync::Once;
    static SIGNED: Once = Once::new();
    SIGNED.call_once(|| {
        let out = std::process::Command::new("codesign")
            .args(["--force", "--sign", "-", "--entitlements", "scripts/entitlements.plist"])
            .arg(bin)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
}

/// Spawn `carrick serve` on a temp socket, returning a (guard, socket_path,
/// tempdir). The guard kills the server on drop.
fn spawn_server() -> (ServerGuard, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("carrick.sock");
    let sock_str = sock.to_str().unwrap().to_string();
    let bin = assert_cmd::cargo::cargo_bin("carrick");
    ensure_codesigned(&bin);
    let mut child = std::process::Command::new(bin)
        .args(["serve", "--docker-api", "--host", &sock_str])
        .spawn()
        .unwrap();
    // Wait for the socket to appear (server bound).
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if !sock.exists() {
        let status = child.try_wait().unwrap();
        panic!("carrick serve did not create socket within 5s (child exit: {status:?})");
    }
    (ServerGuard(child), sock_str, dir)
}

#[tokio::test]
async fn ping_returns_ok() {
    let (_server, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock,
        5,
        bollard::API_DEFAULT_VERSION,
    )
    .unwrap();
    let pong = docker.ping().await.unwrap();
    assert_eq!(pong, "OK");
}

#[tokio::test]
async fn version_reports_carrick() {
    let (_server, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 5, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    let v = docker.version().await.unwrap();
    assert_eq!(v.os.as_deref(), Some("linux"));
    assert!(v.api_version.is_some());
}

#[tokio::test]
async fn create_returns_id() {
    // The container registry is a persistent on-disk store shared across runs,
    // and DELETE /containers/{id} (the bollard cleanup below) is not wired up
    // yet — so a prior run can leak the `m0create` name and make `carrick
    // create` fail with a name conflict. Pre-clean it (best-effort) so the test
    // is idempotent.
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0create"])
        .output();
    let (_server, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 5, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    // bollard 0.18 names the create body `container::Config<T>` (Docker's
    // ContainerCreate request body); there is no `ContainerCreateBody` export.
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    let created = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0create".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    assert_eq!(created.id.len(), 64);
    let _ = docker.remove_container("m0create", None).await;
}

#[tokio::test]
async fn create_then_start_runs() {
    let (_server, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock, 30, bollard::API_DEFAULT_VERSION,
    ).unwrap();
    // idempotency: the registry is persistent and DELETE isn't wired until Task 8.
    let _ = docker.remove_container("m0start", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0start"]).output();
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    docker.create_container(
        Some(bollard::container::CreateContainerOptions { name: "m0start".to_string(), ..Default::default() }),
        body,
    ).await.unwrap();
    docker.start_container("m0start", None::<bollard::container::StartContainerOptions<String>>)
        .await
        .unwrap();
    // best-effort cleanup (container runs `echo hi` and exits quickly)
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0start"]).output();
}
