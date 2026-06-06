// Test-only crate: `unwrap` in the `spawn_server` test helper (a free fn, so
// clippy.toml's `allow-unwrap-in-tests` does not cover it) is fine here.
#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use std::time::Duration;

#[test]
fn serve_help_lists_docker_api_flag() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--docker-api"));
}

/// Spawn `carrick serve` on a temp socket, return (child, socket_path, tempdir).
fn spawn_server() -> (std::process::Child, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("carrick.sock");
    let sock_str = sock.to_str().unwrap().to_string();
    let bin = assert_cmd::cargo::cargo_bin("carrick");
    let child = std::process::Command::new(bin)
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
    (child, sock_str, dir)
}

#[tokio::test]
async fn ping_returns_ok() {
    let (mut child, sock, _dir) = spawn_server();
    let docker = bollard::Docker::connect_with_unix(
        &sock,
        5,
        bollard::API_DEFAULT_VERSION,
    )
    .unwrap();
    let pong = docker.ping().await.unwrap();
    assert_eq!(pong, "OK");
    let _ = child.kill();
}
