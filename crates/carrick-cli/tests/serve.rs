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

/// Spawn `carrick serve` on a temp socket, returning a (guard, socket_path,
/// tempdir). The guard kills the server on drop.
fn spawn_server() -> (ServerGuard, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("carrick.sock");
    let sock_str = sock.to_str().unwrap().to_string();
    let bin = assert_cmd::cargo::cargo_bin("carrick");
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
