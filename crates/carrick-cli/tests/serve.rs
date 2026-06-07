// Test-only crate: `unwrap`/`panic!` in the `spawn_server` test helper (a free
// fn, so clippy.toml's `allow-unwrap-in-tests`/`allow-panic-in-tests` do not
// cover it) are fine here.
#![allow(clippy::unwrap_used, clippy::panic)]

use assert_cmd::Command;
use futures_util::stream::StreamExt;
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
            .args([
                "--force",
                "--sign",
                "-",
                "--entitlements",
                "scripts/entitlements.plist",
            ])
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
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();
    let pong = docker.ping().await.unwrap();
    assert_eq!(pong, "OK");
}

#[tokio::test]
async fn version_reports_carrick() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();
    let v = docker.version().await.unwrap();
    assert_eq!(v.os.as_deref(), Some("linux"));
    assert!(v.api_version.is_some());
}

#[tokio::test]
async fn create_returns_id() {
    // The container registry is a persistent on-disk store shared across runs;
    // pre-clean so the test is idempotent.
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0create"])
        .output();
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();
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
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    // Pre-clean: the registry is persistent across runs.
    let _ = docker.remove_container("m0start", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0start"])
        .output();
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0start".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0start",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();
    // best-effort cleanup (container runs `echo hi` and exits quickly)
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0start"])
        .output();
}

#[tokio::test]
async fn wait_returns_exit_code() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0wait"])
        .output();
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0wait".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0wait",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();
    let mut waits = docker.wait_container(
        "m0wait",
        None::<bollard::container::WaitContainerOptions<String>>,
    );
    let result = waits.next().await.unwrap().unwrap();
    assert_eq!(result.status_code, 0);
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0wait"])
        .output();
}

#[tokio::test]
async fn delete_removes_container() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0del"])
        .output();
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0del".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    docker
        .remove_container(
            "m0del",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn m0_full_lifecycle_echo_hi() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 60, bollard::API_DEFAULT_VERSION).unwrap();
    assert_eq!(docker.ping().await.unwrap(), "OK");

    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0e2e"])
        .output();

    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
        ..Default::default()
    };
    let created = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0e2e".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    assert_eq!(created.id.len(), 64);

    docker
        .start_container(
            "m0e2e",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    let mut waits = docker.wait_container(
        "m0e2e",
        None::<bollard::container::WaitContainerOptions<String>>,
    );
    let result = waits.next().await.unwrap().unwrap();
    assert_eq!(result.status_code, 0);

    docker
        .remove_container(
            "m0e2e",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
}

/// Build a tiny gzipped-tar build context (the legacy `POST /build` request
/// body): a single Dockerfile.
fn gzip_tar_context(dockerfile: &str) -> Vec<u8> {
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let bytes = dockerfile.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "Dockerfile", bytes)
            .unwrap();
        builder.finish().unwrap();
    }
    let mut gz = Vec::new();
    {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        enc.write_all(&tar_buf).unwrap();
        enc.finish().unwrap();
    }
    gz
}

/// M3: drive a real legacy `POST /build` over the socket via bollard's
/// `build_image` (non-BuildKit; bollard is built without the `buildkit`
/// feature, so it uses the legacy streaming protocol). Asserts the streamed
/// NDJSON ends in success (an `aux` ID and/or a "Successfully built" line) and
/// never an `error` frame.
///
/// IGNORED by default: this BOOTS A GUEST (kaniko under HVF) and pulls the
/// kaniko + alpine images over the network, so it is slow (~30-60s) and
/// network-dependent — too heavy/flaky for the default suite. The streaming
/// machinery, query parser, and BoxBody wiring are unit-tested in
/// `src/serve/build.rs`; the buffered endpoints' BoxBody migration is covered by
/// the other tests in this file. Run explicitly with:
///   cargo test -p carrick-cli --test serve -- --ignored streams_build
#[ignore = "boots a kaniko guest + network pull; ~30-60s, run explicitly"]
#[tokio::test]
async fn streams_build_over_socket() {
    let (_server, sock, _dir) = spawn_server();
    // Generous timeout: the build pulls images and runs kaniko as a guest.
    let docker =
        bollard::Docker::connect_with_unix(&sock, 600, bollard::API_DEFAULT_VERSION).unwrap();

    let context =
        gzip_tar_context("FROM alpine:3.20\nRUN echo hi > /b.txt\nCMD [\"cat\",\"/b.txt\"]\n");

    let options = bollard::image::BuildImageOptions {
        dockerfile: "Dockerfile".to_string(),
        t: "svctest:latest".to_string(),
        nocache: true,
        ..Default::default()
    };

    let mut stream = docker.build_image(options, None, Some(context.into()));
    let mut saw_stream = false;
    let mut saw_success = false;
    while let Some(item) = stream.next().await {
        // bollard turns an `error:` frame into a DockerStreamError; surfacing it
        // here fails the test with kaniko's captured message.
        let info = item.expect("build stream yielded an error frame");
        if let Some(s) = &info.stream {
            saw_stream = true;
            if s.contains("Successfully built") {
                saw_success = true;
            }
        }
        if info.aux.is_some() {
            saw_success = true;
        }
    }
    assert!(
        saw_stream,
        "expected at least one stream frame from the build"
    );
    assert!(
        saw_success,
        "expected a success (aux ID / Successfully built) frame"
    );
}

#[tokio::test]
async fn list_containers_shows_running() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0list"])
        .output();
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/sleep".to_string(), "10".to_string()]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0list".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0list",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    let list = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await
        .unwrap();

    let found = list.iter().any(|c| {
        c.names
            .as_ref()
            .is_some_and(|n| n.contains(&"/m0list".to_string()))
    });
    assert!(found, "expected container m0list in the list");

    // Clean up
    let _ = docker
        .remove_container(
            "m0list",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
async fn stop_and_restart_lifecycle() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0stopres"])
        .output();
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/sleep".to_string(), "30".to_string()]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0stopres".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0stopres",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    // Inspect: should be running (poll to wait for startup)
    let mut running = false;
    for _ in 0..150 {
        let inspect = docker.inspect_container("m0stopres", None).await.unwrap();
        if inspect.state.unwrap().running.unwrap() {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(running, "container should be running after start");

    // Stop it
    docker.stop_container("m0stopres", None).await.unwrap();

    // Inspect: should be stopped
    let inspect = docker.inspect_container("m0stopres", None).await.unwrap();
    assert!(!inspect.state.unwrap().running.unwrap());

    // Restart it
    docker.restart_container("m0stopres", None).await.unwrap();

    // Inspect: should be running again (poll to wait for startup)
    let mut running_again = false;
    for _ in 0..150 {
        let inspect = docker.inspect_container("m0stopres", None).await.unwrap();
        if inspect.state.unwrap().running.unwrap() {
            running_again = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(running_again, "container should be running after restart");

    // Clean up
    let _ = docker
        .remove_container(
            "m0stopres",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
async fn logs_collect_output() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0logs"])
        .output();
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec![
            "/bin/echo".to_string(),
            "hello_serve_logs".to_string(),
        ]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0logs".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0logs",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    // Wait for it to exit
    let mut waits = docker.wait_container(
        "m0logs",
        None::<bollard::container::WaitContainerOptions<String>>,
    );
    let _ = waits.next().await.unwrap().unwrap();

    // Collect logs
    let mut logs_stream = docker.logs(
        "m0logs",
        Some(bollard::container::LogsOptions::<String> {
            stdout: true,
            ..Default::default()
        }),
    );
    let mut output = String::new();
    while let Some(log) = logs_stream.next().await {
        let log = log.unwrap();
        output.push_str(&log.to_string());
    }
    assert!(
        output.contains("hello_serve_logs"),
        "logs did not contain expected output: {:?}",
        output
    );

    // Clean up
    let _ = docker
        .remove_container(
            "m0logs",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
async fn list_and_pull_and_remove_images() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();

    // Pull alpine:3.20
    let mut pull_stream = docker.create_image(
        Some(bollard::image::CreateImageOptions {
            from_image: "alpine:3.20",
            ..Default::default()
        }),
        None,
        None,
    );
    let mut saw_pull_progress = false;
    while let Some(item) = pull_stream.next().await {
        let item = item.unwrap();
        if item.status.is_some() {
            saw_pull_progress = true;
        }
    }
    assert!(saw_pull_progress, "expected pull progress frames");

    // List images: check if alpine:3.20 is present
    let images = docker
        .list_images(None::<bollard::image::ListImagesOptions<String>>)
        .await
        .unwrap();
    let found = images
        .iter()
        .any(|img| img.repo_tags.iter().any(|tag| tag.contains("alpine:3.20")));
    assert!(found, "expected alpine:3.20 image in the list");

    // Remove the image
    let _ = docker
        .remove_image("alpine:3.20", None, None)
        .await
        .unwrap();

    // List images again: check it was removed
    let images = docker
        .list_images(None::<bollard::image::ListImagesOptions<String>>)
        .await
        .unwrap();
    let found_after = images
        .iter()
        .any(|img| img.repo_tags.iter().any(|tag| tag.contains("alpine:3.20")));
    assert!(!found_after, "expected alpine:3.20 image to be removed");
}

#[tokio::test]
async fn exec_attached_collects_output() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0exec"])
        .output();

    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/sleep".to_string(), "60".to_string()]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0exec".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0exec",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    // Poll to wait for it to become running
    let mut running = false;
    for _ in 0..150 {
        let inspect = docker.inspect_container("m0exec", None).await.unwrap();
        if inspect.state.unwrap().running.unwrap() {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(running, "container should be running");

    // Create exec
    let exec_create = docker
        .create_exec(
            "m0exec",
            bollard::exec::CreateExecOptions {
                cmd: Some(vec![
                    "/bin/echo".to_string(),
                    "hello_exec_output".to_string(),
                ]),
                attach_stdout: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Start exec (attached, collecting logs)
    let start_exec_res = docker.start_exec(&exec_create.id, None).await.unwrap();
    let mut output = String::new();
    if let bollard::exec::StartExecResults::Attached {
        output: mut stream, ..
    } = start_exec_res
    {
        while let Some(log) = stream.next().await {
            let log = log.unwrap();
            output.push_str(&log.to_string());
        }
    } else {
        panic!("expected attached start_exec results");
    }

    assert!(
        output.contains("hello_exec_output"),
        "exec output was incorrect: {:?}",
        output
    );

    // Clean up
    let _ = docker
        .remove_container(
            "m0exec",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}
