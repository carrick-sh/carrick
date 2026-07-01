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

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn read_http_headers(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<String> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let read = std::io::Read::read(stream, &mut buf)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&response).to_ascii_lowercase())
}

fn docker_api_json(
    sock: &str,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let body = body.to_string();
    let mut stream = std::os::unix::net::UnixStream::connect(sock).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
Host: api.moby.localhost\r\n\
User-Agent: compose/v5.1.4\r\n\
Content-Type: application/json\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n",
        body.len()
    );
    std::io::Write::write_all(&mut stream, request.as_bytes()).unwrap();
    std::io::Write::write_all(&mut stream, body.as_bytes()).unwrap();

    let (status, response_body) = read_http_response(&mut stream).unwrap();
    let value = if response_body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&response_body).unwrap_or_else(|_| {
            panic!("expected JSON response body for {method} {path}: {response_body:?}")
        })
    };
    (status, value)
}

fn read_http_response(
    stream: &mut std::os::unix::net::UnixStream,
) -> std::io::Result<(u16, String)> {
    let mut response = Vec::new();
    let mut buf = [0_u8; 1024];
    let header_end = loop {
        let read = std::io::Read::read(stream, &mut buf)?;
        if read == 0 {
            break response.len();
        }
        response.extend_from_slice(&buf[..read]);
        if let Some(pos) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    let mut body = response[header_end..].to_vec();
    if let Some(content_length) = content_length {
        while body.len() < content_length {
            let read = std::io::Read::read(stream, &mut buf)?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&buf[..read]);
        }
        body.truncate(content_length);
    } else {
        loop {
            let read = std::io::Read::read(stream, &mut buf)?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&buf[..read]);
        }
    }
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
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
async fn create_container_honors_auto_remove_for_compose_run() {
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0autoremove"])
        .output();
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = docker.remove_network("m0_autoremove_net").await;
    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_autoremove_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    let mut endpoints = std::collections::HashMap::new();
    endpoints.insert(
        "m0_autoremove_net".to_string(),
        bollard::models::EndpointSettings {
            aliases: Some(vec!["m0autoremove".to_string()]),
            ..Default::default()
        },
    );
    let created = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0autoremove".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "unused".to_string()]),
                host_config: Some(bollard::secret::HostConfig {
                    auto_remove: Some(true),
                    network_mode: Some("m0_autoremove_net".to_string()),
                    ..Default::default()
                }),
                networking_config: Some(bollard::container::NetworkingConfig {
                    endpoints_config: endpoints,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let state = carrick_runtime::container::ContainerState::load(&created.id).unwrap();
    assert!(!state.auto_remove);
    assert!(state.api_auto_remove);

    docker
        .start_container(
            "m0autoremove",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    let mut waits = docker.wait_container(
        "m0autoremove",
        None::<bollard::container::WaitContainerOptions<String>>,
    );
    let _ = waits.next().await.unwrap().unwrap();
    let inspected = docker
        .inspect_network(
            "m0_autoremove_net",
            None::<bollard::network::InspectNetworkOptions<String>>,
        )
        .await
        .unwrap();
    assert!(
        inspected
            .containers
            .as_ref()
            .is_none_or(|containers| !containers.contains_key(&created.id)),
        "auto-remove container remained attached to network: {:?}",
        inspected.containers
    );

    let _ = docker.remove_container("m0autoremove", None).await;
    let _ = docker.remove_network("m0_autoremove_net").await;
}

#[tokio::test]
async fn network_lifecycle_supports_compose_bridge_resource() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    for (name, driver) in [("bridge", "bridge"), ("host", "host"), ("none", "null")] {
        let inspected = docker
            .inspect_network(name, None::<bollard::network::InspectNetworkOptions<&str>>)
            .await
            .unwrap();
        assert_eq!(inspected.name.as_deref(), Some(name));
        assert_eq!(inspected.driver.as_deref(), Some(driver));
    }
    let builtin_networks = docker
        .list_networks(None::<bollard::network::ListNetworksOptions<&str>>)
        .await
        .unwrap();
    for name in ["bridge", "host", "none"] {
        assert!(
            builtin_networks
                .iter()
                .any(|network| network.name.as_deref() == Some(name)),
            "predefined Docker network {name:?} missing from network list"
        );
    }
    let mut builtin_filters = std::collections::HashMap::new();
    builtin_filters.insert("type", vec!["builtin"]);
    let filtered_builtin_networks = docker
        .list_networks(Some(bollard::network::ListNetworksOptions {
            filters: builtin_filters,
        }))
        .await
        .unwrap();
    assert_eq!(filtered_builtin_networks.len(), 3);
    assert!(
        docker.remove_network("bridge").await.is_err(),
        "predefined Docker bridge network should not be removable"
    );
    assert!(
        docker
            .create_network(bollard::network::CreateNetworkOptions {
                name: "bridge",
                driver: "bridge",
                ..Default::default()
            })
            .await
            .is_err(),
        "predefined Docker bridge network name should be reserved"
    );

    let _ = docker.remove_network("m0_net").await;
    let mut labels = std::collections::HashMap::new();
    labels.insert("com.docker.compose.project", "m0");
    let created = docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_net",
            check_duplicate: true,
            driver: "bridge",
            labels,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!created.id.is_empty());
    let id_prefix = &created.id[..12];

    let inspected = docker
        .inspect_network(
            "m0_net",
            Some(bollard::network::InspectNetworkOptions::<&str> {
                verbose: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    assert_eq!(inspected.name.as_deref(), Some("m0_net"));
    assert_eq!(inspected.driver.as_deref(), Some("bridge"));
    let inspected_by_prefix = docker
        .inspect_network(
            id_prefix,
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert_eq!(inspected_by_prefix.name.as_deref(), Some("m0_net"));

    let networks = docker
        .list_networks(None::<bollard::network::ListNetworksOptions<&str>>)
        .await
        .unwrap();
    assert!(
        networks
            .iter()
            .any(|network| network.name.as_deref() == Some("m0_net"))
    );

    docker.remove_network(id_prefix).await.unwrap();
}

#[tokio::test]
async fn network_create_preserves_enable_ipv4_for_compose() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_network("m0_ipv4_disabled_net").await;
    let (status, _) = docker_api_json(
        &sock,
        "POST",
        "/v1.54/networks/create",
        serde_json::json!({
            "Name": "m0_ipv4_disabled_net",
            "Driver": "bridge",
            "EnableIPv4": false,
            "EnableIPv6": true
        }),
    );
    assert_eq!(status, 201);

    let inspected = docker
        .inspect_network(
            "m0_ipv4_disabled_net",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert_eq!(inspected.enable_ipv4, Some(false));
    assert_eq!(inspected.enable_ipv6, Some(true));

    let _ = docker.remove_network("m0_ipv4_disabled_net").await;
}

#[tokio::test]
async fn network_create_preserves_scope_for_compose() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_network("m0_scope_net").await;
    let (status, _) = docker_api_json(
        &sock,
        "POST",
        "/v1.54/networks/create",
        serde_json::json!({
            "Name": "m0_scope_net",
            "Driver": "bridge",
            "Scope": "swarm"
        }),
    );
    assert_eq!(status, 201);

    let inspected = docker
        .inspect_network(
            "m0_scope_net",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert_eq!(inspected.scope.as_deref(), Some("swarm"));

    let mut filters = std::collections::HashMap::new();
    filters.insert("scope", vec!["swarm"]);
    let filtered = docker
        .list_networks(Some(bollard::network::ListNetworksOptions { filters }))
        .await
        .unwrap();
    assert!(
        filtered
            .iter()
            .any(|network| network.name.as_deref() == Some("m0_scope_net")),
        "network list scope filter should include the created swarm-scoped network"
    );

    let _ = docker.remove_network("m0_scope_net").await;
}

#[tokio::test]
async fn network_create_preserves_config_only_and_config_from_for_compose() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_network("m0_config_from_net").await;
    let _ = docker.remove_network("m0_config_only_net").await;

    let (status, _) = docker_api_json(
        &sock,
        "POST",
        "/v1.54/networks/create",
        serde_json::json!({
            "Name": "m0_config_only_net",
            "Driver": "bridge",
            "ConfigOnly": true
        }),
    );
    assert_eq!(status, 201);

    let (status, _) = docker_api_json(
        &sock,
        "POST",
        "/v1.54/networks/create",
        serde_json::json!({
            "Name": "m0_config_from_net",
            "Driver": "bridge",
            "ConfigFrom": {
                "Network": "m0_config_only_net"
            }
        }),
    );
    assert_eq!(status, 201);

    let config_only = docker
        .inspect_network(
            "m0_config_only_net",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert_eq!(config_only.config_only, Some(true));

    let config_from = docker
        .inspect_network(
            "m0_config_from_net",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert_eq!(
        config_from
            .config_from
            .as_ref()
            .and_then(|config| config.network.as_deref()),
        Some("m0_config_only_net")
    );

    let _ = docker.remove_network("m0_config_from_net").await;
    let _ = docker.remove_network("m0_config_only_net").await;
}

#[tokio::test]
async fn volume_lifecycle_supports_compose_named_resource() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker
        .remove_volume(
            "m0_data",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await;
    let created = docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_data",
            driver: "local",
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(created.name, "m0_data");
    assert_eq!(created.driver, "local");
    assert!(!created.mountpoint.is_empty());
    let duplicate = docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_data",
            driver: "local",
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(duplicate.name, "m0_data");
    assert_eq!(duplicate.mountpoint, created.mountpoint);

    let inspected = docker.inspect_volume("m0_data").await.unwrap();
    assert_eq!(inspected.name, "m0_data");
    assert_eq!(inspected.driver, "local");

    let volumes = docker
        .list_volumes(None::<bollard::volume::ListVolumesOptions<&str>>)
        .await
        .unwrap();
    assert!(
        volumes
            .volumes
            .unwrap_or_default()
            .iter()
            .any(|volume| volume.name == "m0_data")
    );

    docker
        .remove_volume(
            "m0_data",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn remove_volume_force_matches_docker_missing_and_in_use_semantics() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0forcevoluser", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0forcevoluser"])
        .output();
    for name in ["m0_force_missing", "m0_force_used"] {
        let _ = docker
            .remove_volume(
                name,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await;
    }

    assert!(
        docker
            .remove_volume("m0_force_missing", None)
            .await
            .is_err(),
        "DELETE /volumes/{{name}} without force should report a missing volume"
    );
    docker
        .remove_volume(
            "m0_force_missing",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await
        .unwrap();

    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_force_used",
            driver: "local",
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0forcevoluser".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    mounts: Some(vec![bollard::models::Mount {
                        typ: Some(bollard::models::MountTypeEnum::VOLUME),
                        source: Some("m0_force_used".to_string()),
                        target: Some("/data".to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(
        docker
            .remove_volume(
                "m0_force_used",
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await
            .is_err(),
        "DELETE /volumes/{{name}}?force=true should still reject in-use volumes"
    );

    let _ = docker.remove_container("m0forcevoluser", None).await;
    let _ = docker
        .remove_volume(
            "m0_force_used",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await;
}

#[tokio::test]
async fn network_and_volume_lists_honor_compose_filters() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    for name in ["m0_filter_net", "m0_filter_other"] {
        let _ = docker.remove_network(name).await;
    }
    for name in ["m0_filter_data", "m0_filter_other_data"] {
        let _ = docker
            .remove_volume(
                name,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await;
    }

    let mut matching_labels = std::collections::HashMap::new();
    matching_labels.insert("com.docker.compose.project", "m0filter");
    matching_labels.insert("com.docker.compose.network", "default");
    let mut other_labels = std::collections::HashMap::new();
    other_labels.insert("com.docker.compose.project", "other");

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_filter_net",
            driver: "bridge",
            labels: matching_labels.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_filter_other",
            driver: "bridge",
            labels: other_labels.clone(),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("label", vec!["com.docker.compose.project=m0filter"]);
    network_filters.insert("name", vec!["m0_filter_net"]);
    let networks = docker
        .list_networks(Some(bollard::network::ListNetworksOptions {
            filters: network_filters,
        }))
        .await
        .unwrap();
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].name.as_deref(), Some("m0_filter_net"));

    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_filter_data",
            driver: "local",
            labels: matching_labels,
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_filter_other_data",
            driver: "other",
            labels: other_labels,
            ..Default::default()
        })
        .await
        .unwrap();

    let mut volume_filters = std::collections::HashMap::new();
    volume_filters.insert("label", vec!["com.docker.compose.project=m0filter"]);
    volume_filters.insert("name", vec!["m0_filter_data"]);
    volume_filters.insert("driver", vec!["local"]);
    let volumes = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: volume_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].name, "m0_filter_data");

    for name in ["m0_filter_net", "m0_filter_other"] {
        let _ = docker.remove_network(name).await;
    }
    for name in ["m0_filter_data", "m0_filter_other_data"] {
        let _ = docker
            .remove_volume(
                name,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await;
    }
}

#[tokio::test]
async fn volume_lists_honor_dangling_filter() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0danglinguser", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0danglinguser"])
        .output();
    for name in ["m0_dangling_used", "m0_dangling_unused"] {
        let _ = docker
            .remove_volume(
                name,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await;
    }

    let mut labels = std::collections::HashMap::new();
    labels.insert("com.docker.compose.project", "m0dangling");
    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_dangling_used",
            driver: "local",
            labels: labels.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_dangling_unused",
            driver: "local",
            labels,
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0danglinguser".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    mounts: Some(vec![bollard::models::Mount {
                        typ: Some(bollard::models::MountTypeEnum::VOLUME),
                        source: Some("m0_dangling_used".to_string()),
                        target: Some("/data".to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut used_filters = std::collections::HashMap::new();
    used_filters.insert("label", vec!["com.docker.compose.project=m0dangling"]);
    used_filters.insert("dangling", vec!["false"]);
    let used = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: used_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert_eq!(used.len(), 1);
    assert_eq!(used[0].name, "m0_dangling_used");

    let mut unused_filters = std::collections::HashMap::new();
    unused_filters.insert("label", vec!["com.docker.compose.project=m0dangling"]);
    unused_filters.insert("dangling", vec!["true"]);
    let unused = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: unused_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert_eq!(unused.len(), 1);
    assert_eq!(unused[0].name, "m0_dangling_unused");

    let _ = docker.remove_container("m0danglinguser", None).await;
    for name in ["m0_dangling_used", "m0_dangling_unused"] {
        let _ = docker
            .remove_volume(
                name,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await;
    }
}

#[tokio::test]
async fn volume_prune_requires_all_for_named_volumes_like_docker() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker
        .remove_volume(
            "m0_prune_named_requires_all",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await;

    let mut labels = std::collections::HashMap::new();
    labels.insert("com.docker.compose.project", "m0pruneall");
    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_prune_named_requires_all",
            driver: "local",
            labels,
            ..Default::default()
        })
        .await
        .unwrap();

    let mut default_filters = std::collections::HashMap::new();
    default_filters.insert("label", vec!["com.docker.compose.project=m0pruneall"]);
    let default_prune = docker
        .prune_volumes(Some(bollard::volume::PruneVolumesOptions {
            filters: default_filters,
        }))
        .await
        .unwrap();
    assert!(
        default_prune
            .volumes_deleted
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        "default volume prune should not delete named volumes"
    );
    docker
        .inspect_volume("m0_prune_named_requires_all")
        .await
        .unwrap();

    let mut all_filters = std::collections::HashMap::new();
    all_filters.insert("label", vec!["com.docker.compose.project=m0pruneall"]);
    all_filters.insert("all", vec!["true"]);
    let all_prune = docker
        .prune_volumes(Some(bollard::volume::PruneVolumesOptions {
            filters: all_filters,
        }))
        .await
        .unwrap();
    assert_eq!(
        all_prune.volumes_deleted.as_deref(),
        Some(&["m0_prune_named_requires_all".to_string()][..])
    );
}

#[tokio::test]
async fn network_and_volume_prune_honor_compose_filters() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    for name in ["m0_prune_net", "m0_prune_other"] {
        let _ = docker.remove_network(name).await;
    }
    for name in ["m0_prune_data", "m0_prune_other_data"] {
        let _ = docker
            .remove_volume(
                name,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await;
    }

    let mut prune_labels = std::collections::HashMap::new();
    prune_labels.insert("com.docker.compose.project", "m0prune");
    let mut keep_labels = std::collections::HashMap::new();
    keep_labels.insert("com.docker.compose.project", "other");

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_prune_net",
            driver: "bridge",
            labels: prune_labels.clone(),
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_prune_other",
            driver: "bridge",
            labels: keep_labels.clone(),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("label", vec!["com.docker.compose.project=m0prune"]);
    let pruned_networks = docker
        .prune_networks(Some(bollard::network::PruneNetworksOptions {
            filters: network_filters,
        }))
        .await
        .unwrap();
    assert_eq!(
        pruned_networks.networks_deleted.as_deref(),
        Some(&["m0_prune_net".to_string()][..])
    );
    docker
        .inspect_network(
            "m0_prune_other",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();

    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_prune_data",
            driver: "local",
            labels: prune_labels,
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_prune_other_data",
            driver: "local",
            labels: keep_labels,
            ..Default::default()
        })
        .await
        .unwrap();

    let mut volume_filters = std::collections::HashMap::new();
    volume_filters.insert("label", vec!["com.docker.compose.project=m0prune"]);
    volume_filters.insert("all", vec!["true"]);
    let pruned_volumes = docker
        .prune_volumes(Some(bollard::volume::PruneVolumesOptions {
            filters: volume_filters,
        }))
        .await
        .unwrap();
    assert_eq!(
        pruned_volumes.volumes_deleted.as_deref(),
        Some(&["m0_prune_data".to_string()][..])
    );
    assert_eq!(pruned_volumes.space_reclaimed, Some(0));
    docker.inspect_volume("m0_prune_other_data").await.unwrap();

    let _ = docker.remove_network("m0_prune_other").await;
    let _ = docker
        .remove_volume(
            "m0_prune_other_data",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await;
}

#[tokio::test]
#[ignore = "requires docker compose client and boots multiple HVF guests"]
async fn docker_compose_two_service_smoke() {
    if !docker_compose_available() {
        eprintln!("SKIP docker_compose_two_service_smoke: docker compose is not available");
        return;
    }

    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose.yml");
    let host_port = free_loopback_port();
    std::fs::write(
        &compose,
        format!(
            r#"
services:
  db:
    image: ubuntu:24.04
    command: ["/bin/sh", "-c", "echo db-ready; sleep 30"]
    networks:
      appnet:
        aliases:
          - database
    volumes:
      - data:/data
  web:
    image: ubuntu:24.04
    command: ["/bin/sh", "-c", "echo web-ready; sleep 30"]
    depends_on:
      - db
    ports:
      - "127.0.0.1:{host_port}:8080"
    networks:
      appnet:
        aliases:
          - api
volumes:
  data: {{}}
networks:
  appnet:
    driver: bridge
"#
        ),
    )
    .unwrap();
    let project = compose_project("twosvc");

    run_compose(&sock, &compose, &project, &["up", "-d", "--remove-orphans"]);
    let ps = run_compose_output(&sock, &compose, &project, &["ps"]);
    let ps_stdout = String::from_utf8_lossy(&ps.stdout);
    assert!(
        ps_stdout.contains("db") && ps_stdout.contains("web"),
        "compose ps did not list both services\nstdout:\n{ps_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&ps.stderr)
    );
    let logs = run_compose_output(&sock, &compose, &project, &["logs", "--no-color"]);
    let logs_stdout = String::from_utf8_lossy(&logs.stdout);
    assert!(
        logs_stdout.contains("db-ready") && logs_stdout.contains("web-ready"),
        "compose logs did not include both service outputs\nstdout:\n{logs_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&logs.stderr)
    );

    let project_filter = format!("com.docker.compose.project={project}");
    let mut container_filters = std::collections::HashMap::new();
    container_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let containers = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters: container_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(containers.len(), 2, "Compose should create db and web");

    let mut db_id = None;
    let mut web_id = None;
    for container in &containers {
        match container
            .labels
            .as_ref()
            .and_then(|labels| labels.get("com.docker.compose.service"))
            .map(String::as_str)
        {
            Some("db") => db_id = container.id.clone(),
            Some("web") => web_id = container.id.clone(),
            _ => {}
        }
    }
    let db_id = db_id.unwrap_or_else(|| panic!("db container id"));
    let web_id = web_id.unwrap_or_else(|| panic!("web container id"));
    let db = docker.inspect_container(&db_id, None).await.unwrap();
    let web = docker.inspect_container(&web_id, None).await.unwrap();
    let network_name = format!("{project}_appnet");
    let db_endpoint = db
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .and_then(|networks| networks.get(&network_name))
        .unwrap_or_else(|| panic!("db missing endpoint for {network_name}"));
    let web_endpoint = web
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .and_then(|networks| networks.get(&network_name))
        .unwrap_or_else(|| panic!("web missing endpoint for {network_name}"));
    let db_ip = db_endpoint.ip_address.as_deref().unwrap_or_default();
    let web_ip = web_endpoint.ip_address.as_deref().unwrap_or_default();
    assert!(db_ip.starts_with("172.31."), "db bridge IP: {db_ip:?}");
    assert!(web_ip.starts_with("172.31."), "web bridge IP: {web_ip:?}");
    assert_ne!(db_ip, web_ip);
    assert!(
        db_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"db".to_string()))
    );
    assert!(
        db_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"database".to_string()))
    );
    assert!(
        web_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"web".to_string()))
    );
    assert!(
        web_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"api".to_string()))
    );
    let web_ports = web
        .network_settings
        .as_ref()
        .and_then(|settings| settings.ports.as_ref())
        .unwrap();
    assert_eq!(
        web_ports
            .get("8080/tcp")
            .and_then(|bindings| bindings.as_ref())
            .and_then(|bindings| bindings.first())
            .and_then(|binding| binding.host_port.as_deref()),
        Some(host_port.to_string().as_str())
    );

    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let networks = docker
        .list_networks(Some(bollard::network::ListNetworksOptions {
            filters: network_filters,
        }))
        .await
        .unwrap();
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].name.as_deref(), Some(network_name.as_str()));

    let mut volume_filters = std::collections::HashMap::new();
    volume_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let volumes = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: volume_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].name, format!("{project}_data"));

    run_compose(
        &sock,
        &compose,
        &project,
        &["down", "-v", "--remove-orphans"],
    );

    let mut container_filters = std::collections::HashMap::new();
    container_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let containers_after_down = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters: container_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        containers_after_down.is_empty(),
        "compose down should remove project containers"
    );
    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let networks_after_down = docker
        .list_networks(Some(bollard::network::ListNetworksOptions {
            filters: network_filters,
        }))
        .await
        .unwrap();
    assert!(
        networks_after_down.is_empty(),
        "compose down should remove project networks"
    );
    let mut volume_filters = std::collections::HashMap::new();
    volume_filters.insert("label".to_string(), vec![project_filter]);
    let volumes_after_down = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: volume_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert!(
        volumes_after_down.is_empty(),
        "compose down -v should remove project volumes"
    );
}

#[tokio::test]
#[ignore = "requires docker compose client, built aarch64 probes, and boots multiple HVF guests"]
async fn docker_compose_probe_workload_smoke() {
    if !docker_compose_available() {
        eprintln!("SKIP docker_compose_probe_workload_smoke: docker compose is not available");
        return;
    }

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("workspace root"));
    let probe_target = workspace
        .join("conformance-probes")
        .join("target")
        .join("aarch64-unknown-linux-musl");
    let find_probe = |name: &str| {
        ["debug", "release"]
            .into_iter()
            .map(|profile| probe_target.join(profile).join(name))
            .find(|path| path.exists())
    };
    let Some(server_probe) = find_probe("bridge_compose_server") else {
        eprintln!(
            "SKIP docker_compose_probe_workload_smoke: server probe not built under {}",
            probe_target.display()
        );
        return;
    };
    let Some(client_probe) = find_probe("bridge_compose_client") else {
        eprintln!(
            "SKIP docker_compose_probe_workload_smoke: client probe not built under {}",
            probe_target.display()
        );
        return;
    };

    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let copied_server = tmp.path().join("bridge_compose_server");
    let copied_client = tmp.path().join("bridge_compose_client");
    std::fs::copy(&server_probe, &copied_server).unwrap();
    std::fs::copy(&client_probe, &copied_client).unwrap();

    let compose = tmp.path().join("compose.yml");
    let host_port = free_loopback_port();
    std::fs::write(
        &compose,
        format!(
            r#"
services:
  db:
    image: ubuntu:24.04
    command: ["/opt/carrick/bridge_compose_server"]
    networks:
      appnet:
        aliases:
          - database
    volumes:
      - type: bind
        source: {server}
        target: /opt/carrick/bridge_compose_server
        read_only: true
      - data:/data
  web:
    image: ubuntu:24.04
    command: ["/opt/carrick/bridge_compose_client"]
    depends_on:
      - db
    ports:
      - "127.0.0.1:{host_port}:8080"
    networks:
      appnet:
        aliases:
          - api
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/bridge_compose_client
        read_only: true
volumes:
  data: {{}}
networks:
  appnet:
    driver: bridge
"#,
            server = copied_server.display(),
            client = copied_client.display()
        ),
    )
    .unwrap();
    let project = compose_project("probe");

    run_compose(
        &sock,
        &compose,
        &project,
        &[
            "up",
            "--abort-on-container-exit",
            "--exit-code-from",
            "web",
            "--remove-orphans",
        ],
    );
    let ps = run_compose_output(&sock, &compose, &project, &["ps", "-a"]);
    let ps_stdout = String::from_utf8_lossy(&ps.stdout);
    assert!(
        ps_stdout.contains("db") && ps_stdout.contains("web"),
        "compose ps did not list both services\nstdout:\n{ps_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&ps.stderr)
    );
    let logs = run_compose_output(&sock, &compose, &project, &["logs", "--no-color"]);
    let logs_stdout = String::from_utf8_lossy(&logs.stdout);
    assert!(
        logs_stdout.contains("bridge_compose_client_response=pong"),
        "compose logs did not include client ping/pong completion\nstdout:\n{logs_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&logs.stderr)
    );
    assert!(
        logs_stdout.contains("bridge_compose_server_done=true"),
        "compose logs did not include server completion\nstdout:\n{logs_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&logs.stderr)
    );
    let run = run_compose_output(
        &sock,
        &compose,
        &project,
        &["run", "--rm", "web", "/bin/echo", "hello_compose_probe_run"],
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("hello_compose_probe_run"),
        "compose run did not return command output\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    let project_filter = format!("com.docker.compose.project={project}");
    let mut container_filters = std::collections::HashMap::new();
    container_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let containers = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters: container_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        containers.len() >= 2,
        "Compose should create at least db and web containers"
    );

    let mut db_id = None;
    let mut web_id = None;
    for container in &containers {
        match container
            .labels
            .as_ref()
            .and_then(|labels| labels.get("com.docker.compose.service"))
            .map(String::as_str)
        {
            Some("db") => db_id = container.id.clone(),
            Some("web") => web_id = container.id.clone(),
            _ => {}
        }
    }
    let db_id = db_id.unwrap_or_else(|| panic!("db container id"));
    let web_id = web_id.unwrap_or_else(|| panic!("web container id"));
    let db = docker.inspect_container(&db_id, None).await.unwrap();
    let web = docker.inspect_container(&web_id, None).await.unwrap();
    let network_name = format!("{project}_appnet");
    let db_endpoint = db
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .and_then(|networks| networks.get(&network_name))
        .unwrap_or_else(|| panic!("db missing endpoint for {network_name}"));
    let web_endpoint = web
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .and_then(|networks| networks.get(&network_name))
        .unwrap_or_else(|| panic!("web missing endpoint for {network_name}"));
    let db_ip = db_endpoint.ip_address.as_deref().unwrap_or_default();
    let web_ip = web_endpoint.ip_address.as_deref().unwrap_or_default();
    assert!(db_ip.starts_with("172.31."), "db bridge IP: {db_ip:?}");
    assert!(web_ip.starts_with("172.31."), "web bridge IP: {web_ip:?}");
    assert_ne!(db_ip, web_ip);
    assert!(
        db_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"db".to_string()))
    );
    assert!(
        db_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"database".to_string()))
    );
    assert!(
        web_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"web".to_string()))
    );
    assert!(
        web_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"api".to_string()))
    );
    let web_ports = web
        .network_settings
        .as_ref()
        .and_then(|settings| settings.ports.as_ref())
        .unwrap();
    assert_eq!(
        web_ports
            .get("8080/tcp")
            .and_then(|bindings| bindings.as_ref())
            .and_then(|bindings| bindings.first())
            .and_then(|binding| binding.host_port.as_deref()),
        Some(host_port.to_string().as_str())
    );

    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let networks = docker
        .list_networks(Some(bollard::network::ListNetworksOptions {
            filters: network_filters,
        }))
        .await
        .unwrap();
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].name.as_deref(), Some(network_name.as_str()));

    let mut volume_filters = std::collections::HashMap::new();
    volume_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let volumes = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: volume_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].name, format!("{project}_data"));

    run_compose(
        &sock,
        &compose,
        &project,
        &["down", "-v", "--remove-orphans"],
    );

    let mut container_filters = std::collections::HashMap::new();
    container_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let containers_after_down = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters: container_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        containers_after_down.is_empty(),
        "compose down should remove project containers"
    );
    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let networks_after_down = docker
        .list_networks(Some(bollard::network::ListNetworksOptions {
            filters: network_filters,
        }))
        .await
        .unwrap();
    assert!(
        networks_after_down.is_empty(),
        "compose down should remove project networks"
    );
    let mut volume_filters = std::collections::HashMap::new();
    volume_filters.insert("label".to_string(), vec![project_filter]);
    let volumes_after_down = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: volume_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert!(
        volumes_after_down.is_empty(),
        "compose down -v should remove project volumes"
    );
}

#[tokio::test]
#[ignore = "requires docker compose client, built aarch64 probes, and boots multiple HVF guests"]
async fn docker_compose_shared_network_namespace_smoke() {
    if !docker_compose_available() {
        eprintln!(
            "SKIP docker_compose_shared_network_namespace_smoke: docker compose is not available"
        );
        return;
    }

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("workspace root"));
    let probe_target = workspace
        .join("conformance-probes")
        .join("target")
        .join("aarch64-unknown-linux-musl");
    let find_probe = |name: &str| {
        ["debug", "release"]
            .into_iter()
            .map(|profile| probe_target.join(profile).join(name))
            .find(|path| path.exists())
    };
    let required_probes = [
        "sidecar_loopback_server",
        "sidecar_loopback_client",
        "sidecar_loopback_isolated_client",
        "bridge_compose_server",
        "bridge_compose_client",
    ];
    let mut probes = std::collections::HashMap::new();
    for name in required_probes {
        let Some(path) = find_probe(name) else {
            eprintln!(
                "SKIP docker_compose_shared_network_namespace_smoke: probe {name} not built under {}",
                probe_target.display()
            );
            return;
        };
        probes.insert(name, path);
    }

    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mut copied = std::collections::HashMap::new();
    for (name, source) in &probes {
        let target = tmp.path().join(name);
        std::fs::copy(source, &target).unwrap();
        copied.insert(*name, target);
    }

    let sidecar_compose = tmp.path().join("sidecar.yml");
    std::fs::write(
        &sidecar_compose,
        format!(
            r#"
services:
  db:
    image: ubuntu:24.04
    command: ["/opt/carrick/sidecar_loopback_server"]
    networks:
      appnet:
        aliases:
          - database
    volumes:
      - data:/data
      - type: bind
        source: {server}
        target: /opt/carrick/sidecar_loopback_server
        read_only: true
  sidecar:
    image: ubuntu:24.04
    command: ["/opt/carrick/sidecar_loopback_client"]
    depends_on:
      - db
    network_mode: "service:db"
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/sidecar_loopback_client
        read_only: true
  web:
    image: ubuntu:24.04
    command: ["/opt/carrick/sidecar_loopback_isolated_client"]
    depends_on:
      - db
    networks:
      appnet:
        aliases:
          - api
    volumes:
      - type: bind
        source: {isolated}
        target: /opt/carrick/sidecar_loopback_isolated_client
        read_only: true
volumes:
  data: {{}}
networks:
  appnet:
    driver: bridge
"#,
            server = copied["sidecar_loopback_server"].display(),
            client = copied["sidecar_loopback_client"].display(),
            isolated = copied["sidecar_loopback_isolated_client"].display()
        ),
    )
    .unwrap();
    let sidecar_project = compose_project("sidecarns");
    run_compose(
        &sock,
        &sidecar_compose,
        &sidecar_project,
        &["up", "-d", "--remove-orphans"],
    );
    let sidecar_logs = wait_for_compose_logs(
        &sock,
        &sidecar_compose,
        &sidecar_project,
        &[
            "sidecar_loopback_client_response=sidecar-pong",
            "sidecar_loopback_bridge_peer_isolated=true",
            "sidecar_loopback_server_done=true",
        ],
    );
    assert!(
        sidecar_logs.contains("sidecar_loopback_server_peer_loopback=true"),
        "shared namespace server did not see a loopback peer\nlogs:\n{sidecar_logs}"
    );
    // Let the loopback server finish normally so runtime drop removes its
    // fork-coherent endpoint files before the next compose graph starts.
    std::thread::sleep(std::time::Duration::from_secs(6));

    let sidecar_ps = run_compose_output(&sock, &sidecar_compose, &sidecar_project, &["ps", "-a"]);
    let sidecar_ps_stdout = String::from_utf8_lossy(&sidecar_ps.stdout);
    assert!(
        sidecar_ps_stdout.contains("db")
            && sidecar_ps_stdout.contains("sidecar")
            && sidecar_ps_stdout.contains("web"),
        "compose ps did not list db, sidecar, and web\nstdout:\n{sidecar_ps_stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&sidecar_ps.stderr)
    );

    let sidecar_filter = format!("com.docker.compose.project={sidecar_project}");
    let mut container_filters = std::collections::HashMap::new();
    container_filters.insert("label".to_string(), vec![sidecar_filter.clone()]);
    let containers = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters: container_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    let mut db_id = None;
    let mut sidecar_id = None;
    for container in &containers {
        match container
            .labels
            .as_ref()
            .and_then(|labels| labels.get("com.docker.compose.service"))
            .map(String::as_str)
        {
            Some("db") => db_id = container.id.clone(),
            Some("sidecar") => sidecar_id = container.id.clone(),
            _ => {}
        }
    }
    let db_id = db_id.unwrap_or_else(|| panic!("db container id"));
    let sidecar_id = sidecar_id.unwrap_or_else(|| panic!("sidecar container id"));
    let sidecar = docker.inspect_container(&sidecar_id, None).await.unwrap();
    let expected_network_mode = format!("container:{db_id}");
    assert_eq!(
        sidecar
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some(expected_network_mode.as_str())
    );
    assert!(
        sidecar
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .is_some_and(|networks| networks.is_empty()),
        "sidecar should report no independent network endpoint"
    );

    run_compose(
        &sock,
        &sidecar_compose,
        &sidecar_project,
        &["down", "-v", "--remove-orphans"],
    );
    let mut container_filters = std::collections::HashMap::new();
    container_filters.insert("label".to_string(), vec![sidecar_filter.clone()]);
    let containers_after_down = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters: container_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        containers_after_down.is_empty(),
        "compose down should remove shared-netns project containers"
    );
    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("label".to_string(), vec![sidecar_filter.clone()]);
    let networks_after_down = docker
        .list_networks(Some(bollard::network::ListNetworksOptions {
            filters: network_filters,
        }))
        .await
        .unwrap();
    assert!(
        networks_after_down.is_empty(),
        "compose down should remove shared-netns project networks"
    );
    let mut volume_filters = std::collections::HashMap::new();
    volume_filters.insert("label".to_string(), vec![sidecar_filter]);
    let volumes_after_down = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: volume_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert!(
        volumes_after_down.is_empty(),
        "compose down -v should remove shared-netns project volumes"
    );

    let bridge_compose = tmp.path().join("bridge.yml");
    std::fs::write(
        &bridge_compose,
        format!(
            r#"
services:
  db:
    image: ubuntu:24.04
    command: ["/opt/carrick/bridge_compose_server"]
    networks:
      appnet:
        aliases:
          - database
    volumes:
      - type: bind
        source: {server}
        target: /opt/carrick/bridge_compose_server
        read_only: true
  web:
    image: ubuntu:24.04
    command: ["/opt/carrick/bridge_compose_client"]
    depends_on:
      - db
    networks:
      appnet:
        aliases:
          - api
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/bridge_compose_client
        read_only: true
volumes:
  data: {{}}
networks:
  appnet:
    driver: bridge
"#,
            server = copied["bridge_compose_server"].display(),
            client = copied["bridge_compose_client"].display()
        ),
    )
    .unwrap();
    let bridge_project = compose_project("sidecarbridge");
    run_compose(
        &sock,
        &bridge_compose,
        &bridge_project,
        &["up", "-d", "--remove-orphans"],
    );
    let bridge_logs = wait_for_compose_logs(
        &sock,
        &bridge_compose,
        &bridge_project,
        &[
            "bridge_compose_client_response=pong",
            "bridge_compose_server_done=true",
        ],
    );
    assert!(
        bridge_logs.contains("bridge_compose_server_peer_is_bridge=true"),
        "ordinary bridge path did not preserve bridge peer identity\nlogs:\n{bridge_logs}"
    );
    run_compose(
        &sock,
        &bridge_compose,
        &bridge_project,
        &["down", "-v", "--remove-orphans"],
    );
}

#[tokio::test]
#[ignore = "requires docker compose client, built aarch64 probes, and boots multiple HVF guests"]
async fn docker_compose_multi_network_smoke() {
    if !docker_compose_available() {
        eprintln!("SKIP docker_compose_multi_network_smoke: docker compose is not available");
        return;
    }

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("workspace root"));
    let probe_target = workspace
        .join("conformance-probes")
        .join("target")
        .join("aarch64-unknown-linux-musl");
    let find_probe = |name: &str| {
        ["debug", "release"]
            .into_iter()
            .map(|profile| probe_target.join(profile).join(name))
            .find(|path| path.exists())
    };
    let required_probes = ["multi_network_server", "multi_network_client"];
    let mut probes = std::collections::HashMap::new();
    for name in required_probes {
        let Some(path) = find_probe(name) else {
            eprintln!(
                "SKIP docker_compose_multi_network_smoke: probe {name} not built under {}",
                probe_target.display()
            );
            return;
        };
        probes.insert(name, path);
    }

    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let mut copied = std::collections::HashMap::new();
    for (name, source) in &probes {
        let target = tmp.path().join(name);
        std::fs::copy(source, &target).unwrap();
        copied.insert(*name, target);
    }

    let compose = tmp.path().join("multi-network.yml");
    std::fs::write(
        &compose,
        format!(
            r#"
services:
  db:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_server"]
    environment:
      CARRICK_PROBE_LABEL: db
      CARRICK_PROBE_BRIDGE_ACCEPTS: "2"
    networks:
      backend:
        aliases:
          - database
    volumes:
      - data:/data
      - type: bind
        source: {server}
        target: /opt/carrick/multi_network_server
        read_only: true
  web:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_server"]
    depends_on:
      - db
    environment:
      CARRICK_PROBE_LABEL: web
      CARRICK_PROBE_BRIDGE_ACCEPTS: "1"
      CARRICK_PROBE_LOOPBACK_ACCEPTS: "1"
      CARRICK_PROBE_CONNECT_TARGET: db
    networks:
      frontend:
        aliases:
          - api
      backend:
        aliases:
          - app
    volumes:
      - type: bind
        source: {server}
        target: /opt/carrick/multi_network_server
        read_only: true
  cache:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_client"]
    depends_on:
      - web
    environment:
      CARRICK_PROBE_LABEL: cache_to_web
      CARRICK_PROBE_TARGET: web
      CARRICK_PROBE_EXPECT: success
    networks:
      frontend:
        aliases:
          - cache
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/multi_network_client
        read_only: true
  cache_isolated:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_client"]
    depends_on:
      - db
    environment:
      CARRICK_PROBE_LABEL: cache_to_db
      CARRICK_PROBE_TARGET: db
      CARRICK_PROBE_EXPECT: failure
    networks:
      frontend: {{}}
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/multi_network_client
        read_only: true
  sidecar_loopback:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_client"]
    depends_on:
      - web
    network_mode: "service:web"
    environment:
      CARRICK_PROBE_LABEL: sidecar_loopback
      CARRICK_PROBE_TARGET: 127.0.0.1
      CARRICK_PROBE_PORT: "15432"
      CARRICK_PROBE_EXPECT: success
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/multi_network_client
        read_only: true
  sidecar_to_db:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_client"]
    depends_on:
      - db
      - web
    network_mode: "service:web"
    environment:
      CARRICK_PROBE_LABEL: sidecar_to_db
      CARRICK_PROBE_TARGET: db
      CARRICK_PROBE_EXPECT: success
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/multi_network_client
        read_only: true
volumes:
  data: {{}}
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
"#,
            server = copied["multi_network_server"].display(),
            client = copied["multi_network_client"].display()
        ),
    )
    .unwrap();

    let project = compose_project("multinet");
    run_compose(&sock, &compose, &project, &["up", "-d", "--remove-orphans"]);
    let logs = wait_for_compose_logs(
        &sock,
        &compose,
        &project,
        &[
            "web_connect_response=pong",
            "cache_to_web_response=pong",
            "cache_to_db_isolated=true",
            "sidecar_loopback_response=pong",
            "sidecar_to_db_response=pong",
            "db_server_done=true",
            "web_server_done=true",
        ],
    );
    assert!(
        logs.contains("web_bridge_server_peer_0_loopback=false"),
        "web should see frontend bridge peer for cache\nlogs:\n{logs}"
    );
    assert!(
        logs.contains("web_loopback_server_peer_0_loopback=true"),
        "web should see loopback peer for sidecar\nlogs:\n{logs}"
    );

    let project_filter = format!("com.docker.compose.project={project}");
    let mut container_filters = std::collections::HashMap::new();
    container_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let containers = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters: container_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    let mut ids = std::collections::HashMap::new();
    for container in &containers {
        if let (Some(service), Some(id)) = (
            container
                .labels
                .as_ref()
                .and_then(|labels| labels.get("com.docker.compose.service")),
            container.id.as_ref(),
        ) {
            ids.insert(service.clone(), id.clone());
        }
    }
    let web_id = ids.get("web").unwrap_or_else(|| panic!("web id"));
    let db = docker
        .inspect_container(ids.get("db").unwrap_or_else(|| panic!("db id")), None)
        .await
        .unwrap();
    let web = docker.inspect_container(web_id, None).await.unwrap();
    let cache = docker
        .inspect_container(ids.get("cache").unwrap_or_else(|| panic!("cache id")), None)
        .await
        .unwrap();
    let sidecar = docker
        .inspect_container(
            ids.get("sidecar_loopback")
                .unwrap_or_else(|| panic!("sidecar_loopback id")),
            None,
        )
        .await
        .unwrap();
    let frontend = format!("{project}_frontend");
    let backend = format!("{project}_backend");
    assert_endpoint_networks(&db, &[backend.as_str()]);
    assert_endpoint_networks(&web, &[backend.as_str(), frontend.as_str()]);
    assert_endpoint_networks(&cache, &[frontend.as_str()]);
    assert_eq!(
        sidecar
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some(format!("container:{web_id}").as_str())
    );
    assert!(
        sidecar
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .is_some_and(|networks| networks.is_empty()),
        "sidecar should report no independent endpoint"
    );

    run_compose(
        &sock,
        &compose,
        &project,
        &["down", "-v", "--remove-orphans"],
    );
    let mut container_filters = std::collections::HashMap::new();
    container_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let containers_after_down = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters: container_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        containers_after_down.is_empty(),
        "compose down should remove multi-network project containers"
    );
    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("label".to_string(), vec![project_filter.clone()]);
    let networks_after_down = docker
        .list_networks(Some(bollard::network::ListNetworksOptions {
            filters: network_filters,
        }))
        .await
        .unwrap();
    assert!(
        networks_after_down.is_empty(),
        "compose down should remove multi-network project networks"
    );
    let mut volume_filters = std::collections::HashMap::new();
    volume_filters.insert("label".to_string(), vec![project_filter]);
    let volumes_after_down = docker
        .list_volumes(Some(bollard::volume::ListVolumesOptions {
            filters: volume_filters,
        }))
        .await
        .unwrap()
        .volumes
        .unwrap_or_default();
    assert!(
        volumes_after_down.is_empty(),
        "compose down -v should remove multi-network project volumes"
    );
}

#[tokio::test]
#[ignore = "requires docker compose client, built aarch64 probes, and boots an HVF guest"]
async fn docker_compose_host_gateway_smoke() {
    if !docker_compose_available() {
        eprintln!("SKIP docker_compose_host_gateway_smoke: docker compose is not available");
        return;
    }

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("workspace root"));
    let probe_target = workspace
        .join("conformance-probes")
        .join("target")
        .join("aarch64-unknown-linux-musl");
    let Some(probe) = ["debug", "release"]
        .into_iter()
        .map(|profile| probe_target.join(profile).join("host_gateway_client"))
        .find(|path| path.exists())
    else {
        eprintln!(
            "SKIP docker_compose_host_gateway_smoke: probe host_gateway_client not built under {}",
            probe_target.display()
        );
        return;
    };

    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let host_port = listener.local_addr().unwrap().port();
    let host_server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 18];
        std::io::Read::read_exact(&mut stream, &mut request).unwrap();
        assert_eq!(&request, b"host-gateway-ping\n");
        std::io::Write::write_all(&mut stream, b"host-gateway-pong\n").unwrap();
    });

    let (_server, sock, _dir) = spawn_server();
    let tmp = tempfile::tempdir().unwrap();
    let copied_probe = tmp.path().join("host_gateway_client");
    std::fs::copy(&probe, &copied_probe).unwrap();
    let compose = tmp.path().join("host-gateway.yml");
    std::fs::write(
        &compose,
        format!(
            r#"
services:
  client:
    image: ubuntu:24.04
    command: ["/opt/carrick/host_gateway_client"]
    environment:
      CARRICK_PROBE_LABEL: host_gateway
      CARRICK_PROBE_HOST: host.docker.internal
      CARRICK_PROBE_PORT: "{host_port}"
      CARRICK_PROBE_EXPECT_GATEWAY: 172.31.0.1
    networks:
      appnet: {{}}
    volumes:
      - type: bind
        source: {probe}
        target: /opt/carrick/host_gateway_client
        read_only: true
networks:
  appnet:
    driver: bridge
"#,
            probe = copied_probe.display()
        ),
    )
    .unwrap();

    let project = compose_project("hostgateway");
    run_compose(&sock, &compose, &project, &["up", "-d", "--remove-orphans"]);
    let logs = wait_for_compose_logs(
        &sock,
        &compose,
        &project,
        &[
            "host_gateway_resolved=172.31.0.1:",
            "host_gateway_connect_ok=true",
            "host_gateway_response=host-gateway-pong",
        ],
    );
    assert!(
        logs.contains("host_gateway_response=host-gateway-pong"),
        "host-gateway probe did not complete\nlogs:\n{logs}"
    );
    run_compose(
        &sock,
        &compose,
        &project,
        &["down", "-v", "--remove-orphans"],
    );
    host_server.join().unwrap();
}

#[tokio::test]
#[ignore = "requires docker compose client, built aarch64 probes, and boots HVF guests"]
async fn docker_compose_udp_published_port_smoke() {
    if !docker_compose_available() {
        eprintln!("SKIP docker_compose_udp_published_port_smoke: docker compose is not available");
        return;
    }

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("workspace root"));
    let probe_target = workspace
        .join("conformance-probes")
        .join("target")
        .join("aarch64-unknown-linux-musl");
    let find_probe = |name: &str| {
        ["debug", "release"]
            .into_iter()
            .map(|profile| probe_target.join(profile).join(name))
            .find(|path| path.exists())
    };
    let required_probes = ["udp_published_server", "udp_published_client"];
    let mut probes = std::collections::HashMap::new();
    for name in required_probes {
        let Some(path) = find_probe(name) else {
            eprintln!(
                "SKIP docker_compose_udp_published_port_smoke: probe {name} not built under {}",
                probe_target.display()
            );
            return;
        };
        probes.insert(name, path);
    }

    let host_port = free_loopback_port();
    let (_server, sock, _dir) = spawn_server();
    let tmp = tempfile::tempdir().unwrap();
    let mut copied = std::collections::HashMap::new();
    for (name, source) in &probes {
        let target = tmp.path().join(name);
        std::fs::copy(source, &target).unwrap();
        copied.insert(*name, target);
    }

    let compose = tmp.path().join("udp-published.yml");
    std::fs::write(
        &compose,
        format!(
            r#"
services:
  server:
    image: ubuntu:24.04
    command: ["/opt/carrick/udp_published_server"]
    environment:
      CARRICK_PROBE_LABEL: udp_server
      CARRICK_PROBE_PORT: "15555"
      CARRICK_PROBE_EXPECTS: "2"
    ports:
      - "127.0.0.1:{host_port}:15555/udp"
    networks:
      appnet: {{}}
    volumes:
      - type: bind
        source: {server}
        target: /opt/carrick/udp_published_server
        read_only: true
  client:
    image: ubuntu:24.04
    command: ["/opt/carrick/udp_published_client"]
    depends_on:
      - server
    environment:
      CARRICK_PROBE_LABEL: udp_client
      CARRICK_PROBE_TARGET: server
      CARRICK_PROBE_PORT: "15555"
    networks:
      appnet: {{}}
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/udp_published_client
        read_only: true
networks:
  appnet:
    driver: bridge
"#,
            server = copied["udp_published_server"].display(),
            client = copied["udp_published_client"].display()
        ),
    )
    .unwrap();

    let project = compose_project("udppublish");
    run_compose(&sock, &compose, &project, &["up", "-d", "--remove-orphans"]);
    let logs = wait_for_compose_logs(
        &sock,
        &compose,
        &project,
        &[
            "udp_server_ready=true",
            "udp_client_connect_ok=true",
            "udp_client_response=pong",
        ],
    );
    assert!(
        logs.contains("udp_client_response=pong"),
        "service-to-service UDP probe did not complete\nlogs:\n{logs}"
    );

    let host = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    host.send_to(b"ping\n", (std::net::Ipv4Addr::LOCALHOST, host_port))
        .unwrap();
    let mut reply = [0_u8; 128];
    let (n, _) = match host.recv_from(&mut reply) {
        Ok(received) => received,
        Err(err) => {
            let logs = run_compose_output(&sock, &compose, &project, &["logs", "--no-color"]);
            panic!(
                "host UDP published-port receive failed: {err}\nlogs:\n{}",
                String::from_utf8_lossy(&logs.stdout)
            );
        }
    };
    assert_eq!(&reply[..n], b"pong\n");

    let logs = wait_for_compose_logs(&sock, &compose, &project, &["udp_server_done=true"]);
    assert!(
        logs.contains("udp_server_request_1=ping"),
        "published UDP host packet did not reach server\nlogs:\n{logs}"
    );
    run_compose(
        &sock,
        &compose,
        &project,
        &["down", "-v", "--remove-orphans"],
    );
}

#[tokio::test]
#[ignore]
async fn docker_compose_multi_network_dns_smoke() {
    if !docker_compose_available() {
        eprintln!("SKIP docker_compose_multi_network_dns_smoke: docker compose is not available");
        return;
    }

    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("workspace root"));
    let probe_target = workspace
        .join("conformance-probes")
        .join("target")
        .join("aarch64-unknown-linux-musl");
    let Some(dns_probe) = ["debug", "release"]
        .into_iter()
        .map(|profile| probe_target.join(profile).join("multi_network_dns_client"))
        .find(|path| path.exists())
    else {
        eprintln!(
            "SKIP docker_compose_multi_network_dns_smoke: probe multi_network_dns_client not built under {}",
            probe_target.display()
        );
        return;
    };

    let (_server, sock, _dir) = spawn_server();
    let tmp = tempfile::tempdir().unwrap();
    let copied_probe = tmp.path().join("multi_network_dns_client");
    std::fs::copy(&dns_probe, &copied_probe).unwrap();
    let compose = tmp.path().join("multi-network-dns.yml");
    std::fs::write(
        &compose,
        format!(
            r#"
services:
  db:
    image: ubuntu:24.04
    command: ["/bin/sleep", "20"]
    networks:
      backend:
        aliases:
          - database
  web:
    image: ubuntu:24.04
    command: ["/bin/sleep", "20"]
    depends_on:
      - db
      - cache
    networks:
      frontend:
        aliases:
          - api
      backend:
        aliases:
          - app
  cache:
    image: ubuntu:24.04
    command: ["/bin/sleep", "20"]
    networks:
      frontend:
        aliases:
          - cache
  cache_dns_web:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_dns_client"]
    depends_on:
      - web
    environment:
      CARRICK_PROBE_LABEL: cache_dns_web
      CARRICK_PROBE_TARGET: web
      CARRICK_PROBE_EXPECT: success
    networks:
      frontend: {{}}
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/multi_network_dns_client
        read_only: true
  cache_dns_db:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_dns_client"]
    depends_on:
      - db
    environment:
      CARRICK_PROBE_LABEL: cache_dns_db
      CARRICK_PROBE_TARGET: db
      CARRICK_PROBE_EXPECT: failure
    networks:
      frontend: {{}}
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/multi_network_dns_client
        read_only: true
  web_dns_db:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_dns_client"]
    depends_on:
      - db
      - web
    network_mode: "service:web"
    environment:
      CARRICK_PROBE_LABEL: web_dns_db
      CARRICK_PROBE_TARGET: db
      CARRICK_PROBE_EXPECT: success
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/multi_network_dns_client
        read_only: true
  web_dns_cache:
    image: ubuntu:24.04
    command: ["/opt/carrick/multi_network_dns_client"]
    depends_on:
      - cache
      - web
    network_mode: "service:web"
    environment:
      CARRICK_PROBE_LABEL: web_dns_cache
      CARRICK_PROBE_TARGET: cache
      CARRICK_PROBE_EXPECT: success
    volumes:
      - type: bind
        source: {client}
        target: /opt/carrick/multi_network_dns_client
        read_only: true
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
"#,
            client = copied_probe.display()
        ),
    )
    .unwrap();

    let project = compose_project("multinetdns");
    run_compose(&sock, &compose, &project, &["up", "-d", "--remove-orphans"]);
    let logs = wait_for_compose_logs(
        &sock,
        &compose,
        &project,
        &[
            "cache_dns_web_dns_ok=true",
            "cache_dns_db_dns_isolated=true",
            "web_dns_db_dns_ok=true",
            "web_dns_cache_dns_ok=true",
        ],
    );
    assert!(
        logs.contains("cache_dns_web_dns_addrs="),
        "cache should receive a DNS A answer for web\nlogs:\n{logs}"
    );
    run_compose(
        &sock,
        &compose,
        &project,
        &["down", "-v", "--remove-orphans"],
    );
}

fn assert_endpoint_networks(
    inspected: &bollard::models::ContainerInspectResponse,
    expected: &[&str],
) {
    let networks = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .unwrap_or_else(|| panic!("inspect networks"));
    let mut actual = networks.keys().map(String::as_str).collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

fn find_aarch64_probe(name: &str) -> Option<std::path::PathBuf> {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| panic!("workspace root"));
    let probe_target = workspace
        .join("conformance-probes")
        .join("target")
        .join("aarch64-unknown-linux-musl");
    ["debug", "release"]
        .into_iter()
        .map(|profile| probe_target.join(profile).join(name))
        .find(|path| path.exists())
}

async fn wait_container_exit(docker: &bollard::Docker, name: &str) {
    let mut waits = docker.wait_container(
        name,
        None::<bollard::container::WaitContainerOptions<String>>,
    );
    let _ = waits
        .next()
        .await
        .unwrap_or_else(|| panic!("wait result"))
        .unwrap_or_else(|e| panic!("wait ok: {e}"));
}

async fn container_output(docker: &bollard::Docker, name: &str) -> String {
    let mut logs_stream = docker.logs(
        name,
        Some(bollard::container::LogsOptions::<String> {
            stdout: true,
            stderr: true,
            ..Default::default()
        }),
    );
    let mut output = String::new();
    while let Some(log) = logs_stream.next().await {
        output.push_str(&log.unwrap_or_else(|e| panic!("log chunk: {e}")).to_string());
    }
    output
}

#[tokio::test]
#[ignore = "requires built aarch64 probes and boots multiple HVF guests"]
async fn network_connect_created_container_is_runtime_visible_after_start() {
    let Some(server_probe) = find_aarch64_probe("multi_network_server") else {
        eprintln!(
            "SKIP network_connect_created_container_is_runtime_visible_after_start: probe multi_network_server not built"
        );
        return;
    };
    let Some(client_probe) = find_aarch64_probe("multi_network_client") else {
        eprintln!(
            "SKIP network_connect_created_container_is_runtime_visible_after_start: probe multi_network_client not built"
        );
        return;
    };

    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let net = "m0_runtime_connect_net";
    let server_name = "m0runtimeconnectsrv";
    let client_name = "m0runtimeconnectclient";
    let _ = docker
        .remove_container(
            server_name,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker
        .remove_container(
            client_name,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker.remove_network(net).await;

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: net,
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: server_name.to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/opt/carrick/multi_network_server".to_string()]),
                env: Some(vec![
                    "CARRICK_PROBE_LABEL=runtime_connect_server".to_string(),
                    "CARRICK_PROBE_BRIDGE_ACCEPTS=1".to_string(),
                ]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("none".to_string()),
                    binds: Some(vec![format!(
                        "{}:/opt/carrick/multi_network_server:ro",
                        server_probe.display()
                    )]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .connect_network(
            net,
            bollard::network::ConnectNetworkOptions {
                container: server_name,
                endpoint_config: bollard::models::EndpointSettings {
                    aliases: Some(vec!["runtime-web".to_string()]),
                    ..Default::default()
                },
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            server_name,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: client_name.to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/opt/carrick/multi_network_client".to_string()]),
                env: Some(vec![
                    "CARRICK_PROBE_LABEL=runtime_connect_client".to_string(),
                    "CARRICK_PROBE_TARGET=runtime-web".to_string(),
                    "CARRICK_PROBE_EXPECT=success".to_string(),
                ]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some(net.to_string()),
                    binds: Some(vec![format!(
                        "{}:/opt/carrick/multi_network_client:ro",
                        client_probe.display()
                    )]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            client_name,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();
    wait_container_exit(&docker, client_name).await;
    wait_container_exit(&docker, server_name).await;
    let client_logs = container_output(&docker, client_name).await;
    let server_logs = container_output(&docker, server_name).await;
    assert!(
        client_logs.contains("runtime_connect_client_response=pong"),
        "client did not reach connected server\nclient logs:\n{client_logs}\nserver logs:\n{server_logs}"
    );
    assert!(
        server_logs.contains("runtime_connect_server_server_done=true"),
        "server did not observe runtime-connected client\nserver logs:\n{server_logs}"
    );

    let _ = docker
        .remove_container(
            client_name,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker
        .remove_container(
            server_name,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker.remove_network(net).await;
}

#[tokio::test]
#[ignore = "requires built aarch64 probes and boots multiple HVF guests"]
async fn network_disconnect_stopped_container_is_runtime_invisible_after_restart() {
    let Some(client_probe) = find_aarch64_probe("multi_network_client") else {
        eprintln!(
            "SKIP network_disconnect_stopped_container_is_runtime_invisible_after_restart: probe multi_network_client not built"
        );
        return;
    };

    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let net = "m0_runtime_disconnect_net";
    let server_name = "m0runtimedisconnectsrv";
    let client_name = "m0runtimedisconnectclient";
    let _ = docker
        .remove_container(
            server_name,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker
        .remove_container(
            client_name,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker.remove_network(net).await;

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: net,
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    let mut endpoints = std::collections::HashMap::new();
    endpoints.insert(
        net.to_string(),
        bollard::models::EndpointSettings {
            aliases: Some(vec!["runtime-web".to_string()]),
            ..Default::default()
        },
    );
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: server_name.to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/sleep".to_string(), "20".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some(net.to_string()),
                    ..Default::default()
                }),
                networking_config: Some(bollard::container::NetworkingConfig {
                    endpoints_config: endpoints,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            server_name,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();
    docker.stop_container(server_name, None).await.unwrap();
    docker
        .disconnect_network(
            net,
            bollard::network::DisconnectNetworkOptions {
                container: server_name,
                force: true,
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            server_name,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: client_name.to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/opt/carrick/multi_network_client".to_string()]),
                env: Some(vec![
                    "CARRICK_PROBE_LABEL=runtime_disconnect_client".to_string(),
                    "CARRICK_PROBE_TARGET=runtime-web".to_string(),
                    "CARRICK_PROBE_EXPECT=failure".to_string(),
                ]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some(net.to_string()),
                    binds: Some(vec![format!(
                        "{}:/opt/carrick/multi_network_client:ro",
                        client_probe.display()
                    )]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            client_name,
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();
    wait_container_exit(&docker, client_name).await;
    let client_logs = container_output(&docker, client_name).await;
    assert!(
        client_logs.contains("runtime_disconnect_client_isolated=true"),
        "client unexpectedly reached disconnected server name\nclient logs:\n{client_logs}"
    );

    let _ = docker
        .remove_container(
            client_name,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker
        .remove_container(
            server_name,
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    let _ = docker.remove_network(net).await;
}

#[tokio::test]
#[ignore = "requires docker compose client and boots multiple HVF guests"]
async fn docker_compose_smoke_workflows() {
    if !docker_compose_available() {
        eprintln!("SKIP docker_compose_smoke_workflows: docker compose is not available");
        return;
    }

    let (_server, sock, _dir) = spawn_server();
    let tmp = tempfile::tempdir().unwrap();

    let simple = tmp.path().join("simple.yml");
    std::fs::write(
        &simple,
        r#"
services:
  app:
    image: ubuntu:24.04
    command: ["/bin/echo", "hello_compose_smoke"]
    volumes:
      - data:/data
volumes:
  data: {}
"#,
    )
    .unwrap();
    let simple_project = compose_project("simple");
    run_compose(
        &sock,
        &simple,
        &simple_project,
        &["up", "--abort-on-container-exit", "--remove-orphans"],
    );
    run_compose(
        &sock,
        &simple,
        &simple_project,
        &["down", "-v", "--remove-orphans"],
    );

    let oneoff = tmp.path().join("oneoff.yml");
    std::fs::write(
        &oneoff,
        r#"
services:
  app:
    image: ubuntu:24.04
    command: ["/bin/echo", "unused"]
"#,
    )
    .unwrap();
    let oneoff_project = compose_project("run");
    let output = run_compose_output(
        &sock,
        &oneoff,
        &oneoff_project,
        &["run", "--rm", "app", "/bin/echo", "hello_compose_run"],
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hello_compose_run"),
        "compose run output did not contain command output\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    run_compose(
        &sock,
        &oneoff,
        &oneoff_project,
        &["down", "-v", "--remove-orphans"],
    );

    let copy = tmp.path().join("copy.yml");
    std::fs::write(
        &copy,
        r#"
services:
  app:
    image: ubuntu:24.04
    command: ["/bin/sh", "-c", "printf hello_compose_cp >/tmp/cp.txt; sleep 20"]
"#,
    )
    .unwrap();
    let copy_project = compose_project("cp");
    let copied = tmp.path().join("copied.txt");
    run_compose(&sock, &copy, &copy_project, &["up", "-d"]);
    run_compose(
        &sock,
        &copy,
        &copy_project,
        &["cp", "app:/tmp/cp.txt", copied.to_str().unwrap_or_default()],
    );
    assert_eq!(
        std::fs::read_to_string(&copied).unwrap(),
        "hello_compose_cp"
    );
    let upload = tmp.path().join("upload.txt");
    std::fs::write(&upload, "hello_compose_cp_upload").unwrap();
    run_compose(
        &sock,
        &copy,
        &copy_project,
        &[
            "cp",
            upload.to_str().unwrap_or_default(),
            "app:/tmp/upload.txt",
        ],
    );
    let uploaded = run_compose_output(
        &sock,
        &copy,
        &copy_project,
        &["exec", "-T", "app", "/bin/cat", "/tmp/upload.txt"],
    );
    assert!(
        String::from_utf8_lossy(&uploaded.stdout).contains("hello_compose_cp_upload"),
        "compose cp upload output did not contain uploaded content\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&uploaded.stdout),
        String::from_utf8_lossy(&uploaded.stderr)
    );
    run_compose(
        &sock,
        &copy,
        &copy_project,
        &["down", "-v", "--remove-orphans"],
    );

    let network = tmp.path().join("network.yml");
    std::fs::write(
        &network,
        r#"
services:
  server:
    image: ubuntu:24.04
    command: ["/bin/sh", "-c", "sleep 5"]
  client:
    image: ubuntu:24.04
    command: ["/usr/bin/getent", "hosts", "server"]
    depends_on:
      - server
"#,
    )
    .unwrap();
    let network_project = compose_project("net");
    run_compose(
        &sock,
        &network,
        &network_project,
        &["up", "--abort-on-container-exit", "--remove-orphans"],
    );
    run_compose(
        &sock,
        &network,
        &network_project,
        &["down", "-v", "--remove-orphans"],
    );

    let none_network = tmp.path().join("none-network.yml");
    std::fs::write(
        &none_network,
        r#"
services:
  isolated:
    image: ubuntu:24.04
    network_mode: none
    command: ["/bin/echo", "hello_compose_none_network"]
"#,
    )
    .unwrap();
    let none_network_project = compose_project("none");
    run_compose(
        &sock,
        &none_network,
        &none_network_project,
        &["up", "--abort-on-container-exit", "--remove-orphans"],
    );
    run_compose(
        &sock,
        &none_network,
        &none_network_project,
        &["down", "-v", "--remove-orphans"],
    );

    let scale = tmp.path().join("scale.yml");
    std::fs::write(
        &scale,
        r#"
services:
  app:
    image: ubuntu:24.04
    command: ["/bin/echo", "hello_compose_scale"]
"#,
    )
    .unwrap();
    let scale_project = compose_project("scale");
    run_compose(
        &sock,
        &scale,
        &scale_project,
        &[
            "up",
            "--scale",
            "app=2",
            "--abort-on-container-exit",
            "--remove-orphans",
        ],
    );
    run_compose(
        &sock,
        &scale,
        &scale_project,
        &["down", "-v", "--remove-orphans"],
    );
}

fn docker_compose_available() -> bool {
    std::process::Command::new("docker")
        .args(["compose", "version"])
        .output()
        .is_ok_and(|out| out.status.success())
}

fn compose_project(kind: &str) -> String {
    format!("carricksmoke{kind}{}", std::process::id())
}

fn run_compose(sock: &str, file: &std::path::Path, project: &str, args: &[&str]) {
    let _ = run_compose_output(sock, file, project, args);
}

fn run_compose_output(
    sock: &str,
    file: &std::path::Path,
    project: &str,
    args: &[&str],
) -> std::process::Output {
    let output = std::process::Command::new("docker")
        .env("DOCKER_HOST", format!("unix://{sock}"))
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("-f")
        .arg(file)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "docker compose {:?} failed\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn wait_for_compose_logs(
    sock: &str,
    file: &std::path::Path,
    project: &str,
    needles: &[&str],
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut latest_stdout = String::new();
    let mut latest_stderr = String::new();
    while std::time::Instant::now() < deadline {
        let output = run_compose_output(sock, file, project, &["logs", "--no-color"]);
        latest_stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        latest_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if needles.iter().all(|needle| latest_stdout.contains(needle)) {
            return latest_stdout;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "compose logs did not contain expected lines {needles:?}\nstdout:\n{latest_stdout}\nstderr:\n{latest_stderr}"
    );
}

#[tokio::test]
async fn network_disconnect_requires_existing_endpoint_even_with_force() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0notattached", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0notattached"])
        .output();
    let _ = docker.remove_network("m0_not_attached_net").await;

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_not_attached_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0notattached".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(
        docker
            .disconnect_network(
                "m0_not_attached_net",
                bollard::network::DisconnectNetworkOptions {
                    container: "m0notattached",
                    force: true,
                },
            )
            .await
            .is_err(),
        "Docker rejects disconnecting a container that has no endpoint on the network, even with Force"
    );

    let _ = docker.remove_container("m0notattached", None).await;
    let _ = docker.remove_network("m0_not_attached_net").await;
}

#[tokio::test]
async fn network_connect_disconnect_updates_container_and_network_views() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0attach", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0attach"])
        .output();
    let _ = docker.remove_network("m0_attach_net").await;

    let network_created = docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_attach_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    let network_id_prefix = &network_created.id[..12];
    let created = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0attach".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut endpoint_driver_opts = std::collections::HashMap::new();
    endpoint_driver_opts.insert("mode".to_string(), "bridge".to_string());

    docker
        .connect_network(
            network_id_prefix,
            bollard::network::ConnectNetworkOptions {
                container: "m0attach",
                endpoint_config: bollard::models::EndpointSettings {
                    aliases: Some(vec!["worker".to_string()]),
                    ipam_config: Some(bollard::models::EndpointIpamConfig {
                        ipv4_address: Some("172.31.44.12".to_string()),
                        ipv6_address: Some("fd00:carrick::12".to_string()),
                        link_local_ips: Some(vec!["169.254.44.12".to_string()]),
                    }),
                    links: Some(vec!["db:db".to_string()]),
                    mac_address: Some("02:42:ac:1f:2c:0c".to_string()),
                    driver_opts: Some(endpoint_driver_opts),
                    ..Default::default()
                },
            },
        )
        .await
        .unwrap();

    let inspected = docker.inspect_container("m0attach", None).await.unwrap();
    let networks = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .unwrap();
    assert!(networks.contains_key("m0_attach_net"));
    assert_eq!(
        networks
            .get("m0_attach_net")
            .and_then(|endpoint| endpoint.aliases.as_ref())
            .unwrap(),
        &vec!["worker".to_string()]
    );
    let endpoint = networks.get("m0_attach_net").unwrap();
    assert_eq!(
        endpoint.network_id.as_deref(),
        Some(network_created.id.as_str())
    );
    assert!(
        endpoint
            .endpoint_id
            .as_deref()
            .is_some_and(|id| !id.is_empty())
    );
    assert_eq!(endpoint.gateway.as_deref(), Some("172.31.0.1"));
    assert_eq!(endpoint.ip_address.as_deref(), Some("172.31.44.12"));
    assert_eq!(endpoint.mac_address.as_deref(), Some("02:42:ac:1f:2c:0c"));
    assert_eq!(endpoint.ip_prefix_len, Some(16));
    assert_eq!(
        endpoint
            .ipam_config
            .as_ref()
            .and_then(|ipam| ipam.ipv4_address.as_deref()),
        Some("172.31.44.12")
    );
    assert_eq!(
        endpoint
            .ipam_config
            .as_ref()
            .and_then(|ipam| ipam.ipv6_address.as_deref()),
        Some("fd00:carrick::12")
    );
    assert_eq!(
        endpoint
            .ipam_config
            .as_ref()
            .and_then(|ipam| ipam.link_local_ips.as_ref())
            .unwrap(),
        &vec!["169.254.44.12".to_string()]
    );
    assert_eq!(
        endpoint
            .driver_opts
            .as_ref()
            .and_then(|opts| opts.get("mode"))
            .map(String::as_str),
        Some("bridge")
    );
    assert_eq!(endpoint.links.as_ref().unwrap(), &vec!["db:db".to_string()]);
    assert_eq!(endpoint.ipv6_gateway.as_deref(), Some(""));
    assert_eq!(endpoint.global_ipv6_address.as_deref(), Some(""));
    assert_eq!(endpoint.global_ipv6_prefix_len, Some(0));
    let dns_names = endpoint.dns_names.as_ref().unwrap();
    assert!(dns_names.contains(&"m0attach".to_string()));
    assert!(dns_names.contains(&"worker".to_string()));
    assert!(dns_names.contains(&created.id[..12].to_string()));
    let network = docker
        .inspect_network(
            "m0_attach_net",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert!(
        network
            .containers
            .as_ref()
            .is_none_or(std::collections::HashMap::is_empty),
        "created-but-not-started Docker endpoints should not appear in network inspect"
    );

    let mut network_filters = std::collections::HashMap::new();
    network_filters.insert("network".to_string(), vec!["m0_attach_net".to_string()]);
    let listed_by_network = docker
        .list_containers(Some(bollard::container::ListContainersOptions {
            all: true,
            filters: network_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        listed_by_network
            .iter()
            .any(|container| container.id.as_deref() == Some(&created.id)),
        "network filter should include attached container"
    );
    let mut other_network_filters = std::collections::HashMap::new();
    other_network_filters.insert("network".to_string(), vec!["not_m0_attach_net".to_string()]);
    let listed_by_other_network = docker
        .list_containers(Some(bollard::container::ListContainersOptions {
            all: true,
            filters: other_network_filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(
        listed_by_other_network
            .iter()
            .all(|container| container.id.as_deref() != Some(&created.id)),
        "network filter should exclude containers attached to other networks"
    );

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_attach_rm_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .connect_network(
            "m0_attach_rm_net",
            bollard::network::ConnectNetworkOptions {
                container: "m0attach",
                endpoint_config: bollard::models::EndpointSettings {
                    aliases: Some(vec!["remove-created".to_string()]),
                    ..Default::default()
                },
            },
        )
        .await
        .unwrap();
    docker
        .remove_network("m0_attach_rm_net")
        .await
        .unwrap_or_else(|e| {
            panic!("removing a network with only created endpoints should succeed: {e}")
        });
    docker
        .inspect_network(
            "m0_attach_net",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();

    docker
        .disconnect_network(
            network_id_prefix,
            bollard::network::DisconnectNetworkOptions {
                container: "m0attach",
                force: true,
            },
        )
        .await
        .unwrap();
    let inspected = docker.inspect_container("m0attach", None).await.unwrap();
    assert!(
        inspected
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .is_none_or(|networks| !networks.contains_key("m0_attach_net"))
    );
    let network = docker
        .inspect_network(
            "m0_attach_net",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert!(
        network
            .containers
            .as_ref()
            .is_none_or(|containers| !containers.contains_key(&created.id))
    );

    let _ = docker.remove_container("m0attach", None).await;
    let _ = docker.remove_network("m0_attach_net").await;
}

#[tokio::test]
async fn predefined_bridge_connect_disconnect_updates_container_and_network_views() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0builtinbridge", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0builtinbridge"])
        .output();
    let created = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0builtinbridge".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    docker
        .connect_network(
            "bridge",
            bollard::network::ConnectNetworkOptions {
                container: "m0builtinbridge",
                endpoint_config: bollard::models::EndpointSettings {
                    aliases: Some(vec!["builtin-worker".to_string()]),
                    ..Default::default()
                },
            },
        )
        .await
        .unwrap();

    let inspected = docker
        .inspect_container("m0builtinbridge", None)
        .await
        .unwrap();
    let networks = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .unwrap();
    assert!(networks.contains_key("bridge"));
    assert_eq!(
        networks
            .get("bridge")
            .and_then(|endpoint| endpoint.aliases.as_ref())
            .unwrap(),
        &vec!["builtin-worker".to_string()]
    );
    let bridge = docker
        .inspect_network(
            "bridge",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert!(
        bridge
            .containers
            .as_ref()
            .is_none_or(std::collections::HashMap::is_empty),
        "created-but-not-started Docker endpoints should not appear in bridge network inspect"
    );

    docker
        .disconnect_network(
            "bridge",
            bollard::network::DisconnectNetworkOptions {
                container: "m0builtinbridge",
                force: true,
            },
        )
        .await
        .unwrap();
    let inspected = docker
        .inspect_container("m0builtinbridge", None)
        .await
        .unwrap();
    assert!(
        inspected
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .is_none_or(|networks| !networks.contains_key("bridge"))
    );
    let bridge = docker
        .inspect_network(
            "bridge",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert!(
        bridge
            .containers
            .as_ref()
            .is_none_or(|containers| !containers.contains_key(&created.id))
    );

    let _ = docker.remove_container("m0builtinbridge", None).await;
}

#[tokio::test]
async fn create_container_keeps_host_config_network_mode_primary() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0primarynet", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0primarynet"])
        .output();
    let _ = docker.remove_network("m0_primary_a_net").await;
    let _ = docker.remove_network("m0_primary_z_net").await;

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_primary_a_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_primary_z_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();

    let mut endpoints = std::collections::HashMap::new();
    endpoints.insert(
        "m0_primary_a_net".to_string(),
        bollard::models::EndpointSettings {
            aliases: Some(vec!["sidecar".to_string()]),
            ..Default::default()
        },
    );
    endpoints.insert(
        "m0_primary_z_net".to_string(),
        bollard::models::EndpointSettings {
            aliases: Some(vec!["api".to_string()]),
            ..Default::default()
        },
    );

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0primarynet".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("m0_primary_z_net".to_string()),
                    ..Default::default()
                }),
                networking_config: Some(bollard::container::NetworkingConfig {
                    endpoints_config: endpoints,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let id = carrick_runtime::container::resolve("m0primarynet").unwrap();
    let state = carrick_runtime::container::ContainerState::load(&id).unwrap();
    assert_eq!(state.config.network_attachments[0].name, "m0_primary_z_net");
    assert_eq!(state.config.network_attachments[0].aliases, vec!["api"]);

    let inspected = docker
        .inspect_container("m0primarynet", None)
        .await
        .unwrap();
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some("m0_primary_z_net")
    );
    let inspected_networks = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .unwrap();
    assert!(inspected_networks.contains_key("m0_primary_a_net"));
    assert!(inspected_networks.contains_key("m0_primary_z_net"));

    let _ = docker.remove_container("m0primarynet", None).await;
    let _ = docker.remove_network("m0_primary_a_net").await;
    let _ = docker.remove_network("m0_primary_z_net").await;
}

#[tokio::test]
async fn create_container_preserves_static_ipv4_endpoint_config() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0staticip", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0staticip"])
        .output();
    let _ = docker.remove_network("m0_static_ip_net").await;

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_static_ip_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();

    let mut endpoint_driver_opts = std::collections::HashMap::new();
    endpoint_driver_opts.insert("mode".to_string(), "bridge".to_string());
    let mut endpoints = std::collections::HashMap::new();
    endpoints.insert(
        "m0_static_ip_net".to_string(),
        bollard::models::EndpointSettings {
            ipam_config: Some(bollard::models::EndpointIpamConfig {
                ipv4_address: Some("172.31.44.10".to_string()),
                ipv6_address: Some("fd00:carrick::10".to_string()),
                link_local_ips: Some(vec!["169.254.10.10".to_string()]),
            }),
            aliases: Some(vec!["api".to_string()]),
            links: Some(vec!["db:db".to_string()]),
            mac_address: Some("02:42:ac:1f:2c:0a".to_string()),
            driver_opts: Some(endpoint_driver_opts),
            ..Default::default()
        },
    );

    let created = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0staticip".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("m0_static_ip_net".to_string()),
                    ..Default::default()
                }),
                networking_config: Some(bollard::container::NetworkingConfig {
                    endpoints_config: endpoints,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let state = carrick_runtime::container::ContainerState::load(&created.id).unwrap();
    assert_eq!(state.config.network_attachments.len(), 1);
    assert_eq!(
        state.config.network_attachments[0].ipv4_address.as_deref(),
        Some("172.31.44.10")
    );

    let inspected = docker.inspect_container("m0staticip", None).await.unwrap();
    let endpoint = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .and_then(|networks| networks.get("m0_static_ip_net"))
        .unwrap();
    assert_eq!(
        endpoint
            .ipam_config
            .as_ref()
            .and_then(|ipam| ipam.ipv4_address.as_deref()),
        Some("172.31.44.10")
    );
    assert_eq!(
        endpoint
            .ipam_config
            .as_ref()
            .and_then(|ipam| ipam.ipv6_address.as_deref()),
        Some("fd00:carrick::10")
    );
    assert_eq!(
        endpoint
            .ipam_config
            .as_ref()
            .and_then(|ipam| ipam.link_local_ips.as_ref())
            .unwrap(),
        &vec!["169.254.10.10".to_string()]
    );
    assert_eq!(
        endpoint
            .driver_opts
            .as_ref()
            .and_then(|opts| opts.get("mode"))
            .map(String::as_str),
        Some("bridge")
    );
    assert_eq!(endpoint.links.as_ref().unwrap(), &vec!["db:db".to_string()]);
    assert_eq!(endpoint.mac_address.as_deref(), Some("02:42:ac:1f:2c:0a"));

    let _ = docker.remove_container("m0staticip", None).await;
    let _ = docker.remove_network("m0_static_ip_net").await;
}

#[tokio::test]
async fn create_container_preserves_endpoint_gateway_priority() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0gwcreate", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0gwcreate"])
        .output();
    let _ = docker.remove_network("m0_gw_create_net").await;

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_gw_create_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();

    let (status, _) = docker_api_json(
        &sock,
        "POST",
        "/v1.54/containers/create?name=m0gwcreate",
        serde_json::json!({
            "Image": "ubuntu:24.04",
            "Cmd": ["/bin/echo", "hi"],
            "HostConfig": {
                "NetworkMode": "m0_gw_create_net"
            },
            "NetworkingConfig": {
                "EndpointsConfig": {
                    "m0_gw_create_net": {
                        "Aliases": ["api"],
                        "GwPriority": 17
                    }
                }
            }
        }),
    );
    assert_eq!(status, 201);

    let (status, inspected) = docker_api_json(
        &sock,
        "GET",
        "/v1.54/containers/m0gwcreate/json",
        serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(
        inspected["NetworkSettings"]["Networks"]["m0_gw_create_net"]["GwPriority"],
        serde_json::json!(17)
    );

    let _ = docker.remove_container("m0gwcreate", None).await;
    let _ = docker.remove_network("m0_gw_create_net").await;
}

#[tokio::test]
async fn network_connect_preserves_endpoint_gateway_priority() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0gwconnect", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0gwconnect"])
        .output();
    let _ = docker.remove_network("m0_gw_connect_net").await;

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_gw_connect_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0gwconnect".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (status, _) = docker_api_json(
        &sock,
        "POST",
        "/v1.54/networks/m0_gw_connect_net/connect",
        serde_json::json!({
            "Container": "m0gwconnect",
            "EndpointConfig": {
                "Aliases": ["worker"],
                "GwPriority": 23
            }
        }),
    );
    assert_eq!(status, 200);

    let (status, inspected) = docker_api_json(
        &sock,
        "GET",
        "/v1.54/containers/m0gwconnect/json",
        serde_json::Value::Null,
    );
    assert_eq!(status, 200);
    assert_eq!(
        inspected["NetworkSettings"]["Networks"]["m0_gw_connect_net"]["GwPriority"],
        serde_json::json!(23)
    );

    let _ = docker.remove_container("m0gwconnect", None).await;
    let _ = docker.remove_network("m0_gw_connect_net").await;
}

#[tokio::test]
async fn create_container_lowers_compose_network_and_volume_config() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0api", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0api"])
        .output();
    let _ = docker.remove_network("m0_api_net").await;
    let _ = docker
        .remove_volume(
            "m0_api_data",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await;

    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_api_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();
    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_api_data",
            driver: "local",
            ..Default::default()
        })
        .await
        .unwrap();

    let mut endpoints = std::collections::HashMap::new();
    endpoints.insert(
        "m0_api_net".to_string(),
        bollard::models::EndpointSettings {
            aliases: Some(vec!["api".to_string()]),
            ..Default::default()
        },
    );
    let created = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0api".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("m0_api_net".to_string()),
                    extra_hosts: Some(vec!["db.local:10.12.0.7".to_string()]),
                    dns: Some(vec!["1.1.1.1".to_string()]),
                    dns_search: Some(vec!["example.test".to_string()]),
                    dns_options: Some(vec!["ndots:2".to_string()]),
                    mounts: Some(vec![bollard::models::Mount {
                        typ: Some(bollard::models::MountTypeEnum::VOLUME),
                        source: Some("m0_api_data".to_string()),
                        target: Some("/data".to_string()),
                        read_only: Some(true),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                networking_config: Some(bollard::container::NetworkingConfig {
                    endpoints_config: endpoints,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let state = carrick_runtime::container::ContainerState::load(&created.id).unwrap();
    assert_eq!(state.config.network, carrick_spec::NetworkMode::Bridge);
    assert_eq!(state.config.network_aliases, vec!["api"]);
    assert_eq!(state.config.extra_hosts, vec!["db.local:10.12.0.7"]);
    assert_eq!(state.config.dns_servers, vec!["1.1.1.1"]);
    assert_eq!(state.config.dns_search, vec!["example.test"]);
    assert_eq!(state.config.dns_options, vec!["ndots:2"]);
    assert_eq!(state.config.mounts.len(), 1);
    assert!(state.config.mounts[0].readonly);
    assert_eq!(state.config.mounts[0].target.as_str(), "/data");
    assert!(
        state.config.mounts[0]
            .source
            .as_str()
            .ends_with("/docker-api/volumes/m0_api_data/_data")
    );

    let inspected = docker.inspect_container("m0api", None).await.unwrap();
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some("m0_api_net")
    );
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.extra_hosts.as_ref())
            .unwrap(),
        &vec!["db.local:10.12.0.7".to_string()]
    );
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.dns.as_ref())
            .unwrap(),
        &vec!["1.1.1.1".to_string()]
    );
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.dns_search.as_ref())
            .unwrap(),
        &vec!["example.test".to_string()]
    );
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.dns_options.as_ref())
            .unwrap(),
        &vec!["ndots:2".to_string()]
    );
    let inspected_networks = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .unwrap();
    assert!(inspected_networks.contains_key("m0_api_net"));
    assert_eq!(
        inspected_networks
            .get("m0_api_net")
            .and_then(|endpoint| endpoint.aliases.as_ref())
            .unwrap(),
        &vec!["api".to_string()]
    );
    let inspected_mount = inspected
        .mounts
        .as_ref()
        .unwrap()
        .iter()
        .find(|mount| mount.destination.as_deref() == Some("/data"))
        .unwrap();
    assert_eq!(inspected_mount.name.as_deref(), Some("m0_api_data"));
    assert_eq!(
        inspected_mount.typ,
        Some(bollard::models::MountPointTypeEnum::VOLUME)
    );
    assert_eq!(inspected_mount.rw, Some(false));

    let list = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await
        .unwrap();
    let listed = list
        .iter()
        .find(|container| {
            container
                .names
                .as_ref()
                .is_some_and(|names| names.contains(&"/m0api".to_string()))
        })
        .unwrap();
    assert_eq!(
        listed
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some("m0_api_net")
    );
    assert!(
        listed
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .is_some_and(|networks| networks.contains_key("m0_api_net"))
    );

    assert!(
        docker
            .remove_volume(
                "m0_api_data",
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await
            .is_err(),
        "removing a volume referenced by a container should fail"
    );
    docker.inspect_volume("m0_api_data").await.unwrap();

    let _ = docker.remove_container("m0api", None).await;
    let _ = docker.remove_network("m0_api_net").await;
    let _ = docker
        .remove_volume(
            "m0_api_data",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await;
}

#[tokio::test]
async fn create_container_accepts_shared_container_network_mode() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0netbase", None).await;
    let _ = docker.remove_container("m0netsidecar", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0netbase", "m0netsidecar"])
        .output();

    let base = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0netbase".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "base".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("bridge".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let sidecar = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0netsidecar".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "sidecar".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("container:m0netbase".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let state = carrick_runtime::container::ContainerState::load(&sidecar.id).unwrap();
    assert_eq!(state.config.network, carrick_spec::NetworkMode::Bridge);
    assert_eq!(
        state.config.network_container.as_deref(),
        Some(base.id.as_str())
    );

    let inspected = docker
        .inspect_container("m0netsidecar", None)
        .await
        .unwrap();
    let expected_network_mode = format!("container:{}", base.id);
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some(expected_network_mode.as_str())
    );
    assert!(
        inspected
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .is_some_and(|networks| networks.is_empty()),
        "container-shared network mode should report no independent endpoint"
    );

    let list = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await
        .unwrap();
    let listed = list
        .iter()
        .find(|container| {
            container
                .names
                .as_ref()
                .is_some_and(|names| names.contains(&"/m0netsidecar".to_string()))
        })
        .unwrap();
    assert_eq!(
        listed
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some(expected_network_mode.as_str())
    );
    assert!(
        listed
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .is_some_and(|networks| networks.is_empty())
    );

    let _ = docker.remove_container("m0netsidecar", None).await;
    let _ = docker.remove_container("m0netbase", None).await;
}

#[tokio::test]
async fn create_container_inherits_volumes_from_another_container() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0vfromsidecar", None).await;
    let _ = docker.remove_container("m0vfrombase", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0vfromsidecar", "m0vfrombase"])
        .output();
    let _ = docker
        .remove_volume(
            "m0_vfrom_data",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await;

    docker
        .create_volume(bollard::volume::CreateVolumeOptions {
            name: "m0_vfrom_data",
            driver: "local",
            ..Default::default()
        })
        .await
        .unwrap();

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0vfrombase".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "base".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    mounts: Some(vec![bollard::models::Mount {
                        typ: Some(bollard::models::MountTypeEnum::VOLUME),
                        source: Some("m0_vfrom_data".to_string()),
                        target: Some("/shared".to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let sidecar = docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0vfromsidecar".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "sidecar".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    volumes_from: Some(vec!["m0vfrombase:ro".to_string()]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let state = carrick_runtime::container::ContainerState::load(&sidecar.id).unwrap();
    assert_eq!(state.config.volumes_from, vec!["m0vfrombase:ro"]);
    assert_eq!(state.config.mounts.len(), 1);
    assert_eq!(state.config.mounts[0].target.as_str(), "/shared");
    assert!(state.config.mounts[0].readonly);
    assert!(
        state.config.mounts[0]
            .source
            .as_str()
            .ends_with("/docker-api/volumes/m0_vfrom_data/_data")
    );

    let inspected = docker
        .inspect_container("m0vfromsidecar", None)
        .await
        .unwrap();
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.volumes_from.as_ref())
            .unwrap(),
        &vec!["m0vfrombase:ro".to_string()]
    );
    let mount = inspected
        .mounts
        .as_ref()
        .unwrap()
        .iter()
        .find(|mount| mount.destination.as_deref() == Some("/shared"))
        .unwrap();
    assert_eq!(mount.name.as_deref(), Some("m0_vfrom_data"));
    assert_eq!(mount.rw, Some(false));

    let _ = docker.remove_container("m0vfromsidecar", None).await;
    let _ = docker.remove_container("m0vfrombase", None).await;
    let _ = docker
        .remove_volume(
            "m0_vfrom_data",
            Some(bollard::volume::RemoveVolumeOptions { force: true }),
        )
        .await;
}

#[tokio::test]
async fn create_container_lowers_compose_port_bindings() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0ports", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0ports"])
        .output();

    let mut port_bindings = std::collections::HashMap::new();
    port_bindings.insert(
        "8080/tcp".to_string(),
        Some(vec![bollard::models::PortBinding {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: Some("18080".to_string()),
        }]),
    );

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0ports".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("bridge".to_string()),
                    port_bindings: Some(port_bindings),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let id = carrick_runtime::container::resolve("m0ports").unwrap();
    let state = carrick_runtime::container::ContainerState::load(&id).unwrap();
    assert_eq!(state.config.network, carrick_spec::NetworkMode::Bridge);
    assert_eq!(state.config.published_ports.len(), 1);
    assert_eq!(state.config.published_ports[0].host_port, Some(18080));
    assert_eq!(state.config.published_ports[0].container_port, 8080);

    let inspected = docker.inspect_container("m0ports", None).await.unwrap();
    let inspect_ports = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.ports.as_ref())
        .unwrap();
    assert!(inspect_ports.contains_key("8080/tcp"));
    assert_eq!(
        inspect_ports
            .get("8080/tcp")
            .and_then(|bindings| bindings.as_ref())
            .and_then(|bindings| bindings.first())
            .and_then(|binding| binding.host_port.as_deref()),
        Some("18080")
    );

    let listed = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_iter()
        .find(|container| {
            container
                .names
                .as_ref()
                .is_some_and(|names| names.contains(&"/m0ports".to_string()))
        })
        .unwrap();
    assert!(
        listed
            .ports
            .as_ref()
            .unwrap()
            .iter()
            .any(|port| port.private_port == 8080 && port.public_port == Some(18080))
    );

    let _ = docker.remove_container("m0ports", None).await;
}

#[tokio::test]
async fn compose_bridge_graph_exposes_ips_ports_and_restart_cleanup() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();

    for name in ["m0graphweb", "m0graphdb"] {
        let _ = docker.remove_container(name, None).await;
        let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
            .args(["rm", "-f", name])
            .output();
    }
    let _ = docker.remove_network("m0_graph_net").await;
    docker
        .create_network(bollard::network::CreateNetworkOptions {
            name: "m0_graph_net",
            driver: "bridge",
            ..Default::default()
        })
        .await
        .unwrap();

    let mut db_endpoints = std::collections::HashMap::new();
    db_endpoints.insert(
        "m0_graph_net".to_string(),
        bollard::models::EndpointSettings {
            aliases: Some(vec!["db".to_string()]),
            ..Default::default()
        },
    );
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0graphdb".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "db".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("m0_graph_net".to_string()),
                    ..Default::default()
                }),
                networking_config: Some(bollard::container::NetworkingConfig {
                    endpoints_config: db_endpoints,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let host_port = free_loopback_port();
    let mut port_bindings = std::collections::HashMap::new();
    port_bindings.insert(
        "8080/tcp".to_string(),
        Some(vec![bollard::models::PortBinding {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: Some(host_port.to_string()),
        }]),
    );
    let mut web_endpoints = std::collections::HashMap::new();
    web_endpoints.insert(
        "m0_graph_net".to_string(),
        bollard::models::EndpointSettings {
            aliases: Some(vec!["web".to_string()]),
            ..Default::default()
        },
    );
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0graphweb".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/sleep".to_string(), "30".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("m0_graph_net".to_string()),
                    port_bindings: Some(port_bindings),
                    ..Default::default()
                }),
                networking_config: Some(bollard::container::NetworkingConfig {
                    endpoints_config: web_endpoints,
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let db = docker.inspect_container("m0graphdb", None).await.unwrap();
    let web = docker.inspect_container("m0graphweb", None).await.unwrap();
    let db_endpoint = db
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .and_then(|networks| networks.get("m0_graph_net"))
        .unwrap();
    let web_endpoint = web
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .and_then(|networks| networks.get("m0_graph_net"))
        .unwrap();
    let db_ip = db_endpoint.ip_address.as_deref().unwrap_or_default();
    let web_ip = web_endpoint.ip_address.as_deref().unwrap_or_default();
    assert!(db_ip.starts_with("172.31."), "db bridge IP: {db_ip:?}");
    assert!(web_ip.starts_with("172.31."), "web bridge IP: {web_ip:?}");
    assert_ne!(db_ip, web_ip);
    assert!(
        db_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"db".to_string()))
    );
    assert!(
        web_endpoint
            .dns_names
            .as_ref()
            .is_some_and(|names| names.contains(&"web".to_string()))
    );
    let ports = web
        .network_settings
        .as_ref()
        .and_then(|settings| settings.ports.as_ref())
        .unwrap();
    assert_eq!(
        ports
            .get("8080/tcp")
            .and_then(|bindings| bindings.as_ref())
            .and_then(|bindings| bindings.first())
            .and_then(|binding| binding.host_port.as_deref()),
        Some(host_port.to_string().as_str())
    );

    docker
        .start_container(
            "m0graphweb",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();
    docker.stop_container("m0graphweb", None).await.unwrap();
    docker.restart_container("m0graphweb", None).await.unwrap();
    let mut running_again = false;
    for _ in 0..150 {
        let inspect = docker.inspect_container("m0graphweb", None).await.unwrap();
        if inspect.state.unwrap().running.unwrap() {
            running_again = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(running_again, "web should restart with its published port");

    for name in ["m0graphweb", "m0graphdb"] {
        let _ = docker
            .remove_container(
                name,
                Some(bollard::container::RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }
    let _ = docker.remove_network("m0_graph_net").await;
}

#[tokio::test]
async fn create_container_accepts_network_mode_none() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0none", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0none"])
        .output();

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0none".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("none".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let id = carrick_runtime::container::resolve("m0none").unwrap();
    let state = carrick_runtime::container::ContainerState::load(&id).unwrap();
    assert_eq!(state.config.network, carrick_spec::NetworkMode::None);

    let inspected = docker.inspect_container("m0none", None).await.unwrap();
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some("none")
    );
    let inspect_networks = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .unwrap();
    assert!(inspect_networks.contains_key("none"));
    let none_network = docker
        .inspect_network(
            "none",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert!(
        none_network
            .containers
            .as_ref()
            .is_none_or(std::collections::HashMap::is_empty),
        "created-but-not-started Docker endpoints should not appear in none network inspect"
    );

    let _ = docker.remove_container("m0none", None).await;
}

#[tokio::test]
async fn create_container_reports_network_mode_host_endpoint() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0hostnet", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0hostnet"])
        .output();

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0hostnet".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                host_config: Some(bollard::models::HostConfig {
                    network_mode: Some("host".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let inspected = docker.inspect_container("m0hostnet", None).await.unwrap();
    assert_eq!(
        inspected
            .host_config
            .as_ref()
            .and_then(|host| host.network_mode.as_deref()),
        Some("host")
    );
    let inspect_networks = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .unwrap();
    assert!(inspect_networks.contains_key("host"));
    let host_network = docker
        .inspect_network(
            "host",
            None::<bollard::network::InspectNetworkOptions<&str>>,
        )
        .await
        .unwrap();
    assert!(
        host_network
            .containers
            .as_ref()
            .is_none_or(std::collections::HashMap::is_empty),
        "created-but-not-started Docker endpoints should not appear in host network inspect"
    );

    let listed = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_iter()
        .find(|container| {
            container
                .names
                .as_ref()
                .is_some_and(|names| names.contains(&"/m0hostnet".to_string()))
        })
        .unwrap();
    assert!(
        listed
            .network_settings
            .as_ref()
            .and_then(|settings| settings.networks.as_ref())
            .is_some_and(|networks| networks.contains_key("host"))
    );

    let _ = docker.remove_container("m0hostnet", None).await;
}

#[tokio::test]
async fn create_container_materializes_top_level_volumes() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0anonvol", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0anonvol"])
        .output();

    let mut volumes = std::collections::HashMap::new();
    volumes.insert("/cache".to_string(), std::collections::HashMap::new());
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0anonvol".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                volumes: Some(volumes),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let id = carrick_runtime::container::resolve("m0anonvol").unwrap();
    let state = carrick_runtime::container::ContainerState::load(&id).unwrap();
    assert_eq!(state.config.mounts.len(), 1);
    assert_eq!(state.config.mounts[0].target.as_str(), "/cache");
    assert!(
        state.config.mounts[0]
            .source
            .as_str()
            .contains("/docker-api/volumes/")
    );

    let inspected = docker.inspect_container("m0anonvol", None).await.unwrap();
    let mount = inspected
        .mounts
        .as_ref()
        .unwrap()
        .iter()
        .find(|mount| mount.destination.as_deref() == Some("/cache"))
        .unwrap();
    assert_eq!(mount.typ, Some(bollard::models::MountPointTypeEnum::VOLUME));
    assert!(mount.name.as_deref().is_some_and(|name| !name.is_empty()));
    assert_eq!(mount.rw, Some(true));

    let _ = docker.remove_container("m0anonvol", None).await;
}

#[tokio::test]
async fn delete_container_with_volumes_removes_anonymous_volumes() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0anonvolrm", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0anonvolrm"])
        .output();

    let mut volumes = std::collections::HashMap::new();
    volumes.insert("/cache".to_string(), std::collections::HashMap::new());
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0anonvolrm".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                volumes: Some(volumes),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let inspected = docker.inspect_container("m0anonvolrm", None).await.unwrap();
    let volume_name = inspected
        .mounts
        .as_ref()
        .unwrap()
        .iter()
        .find(|mount| mount.destination.as_deref() == Some("/cache"))
        .and_then(|mount| mount.name.as_deref())
        .unwrap()
        .to_string();
    docker.inspect_volume(&volume_name).await.unwrap();

    docker
        .remove_container(
            "m0anonvolrm",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                v: true,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let volume_after_remove = docker.inspect_volume(&volume_name).await;
    if volume_after_remove.is_ok() {
        let _ = docker
            .remove_volume(
                &volume_name,
                Some(bollard::volume::RemoveVolumeOptions { force: true }),
            )
            .await;
    }
    assert!(
        volume_after_remove.is_err(),
        "DELETE /containers/{{id}}?v=true should remove anonymous volumes"
    );
}

#[tokio::test]
async fn container_labels_round_trip_and_filter_for_compose() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    for name in ["m0labels", "m0labels_other"] {
        let _ = docker.remove_container(name, None).await;
        let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
            .args(["rm", "-f", name])
            .output();
    }

    let mut labels = std::collections::HashMap::new();
    labels.insert(
        "com.docker.compose.project".to_string(),
        "m0labels".to_string(),
    );
    labels.insert("com.docker.compose.service".to_string(), "web".to_string());
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0labels".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                labels: Some(labels.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut other_labels = std::collections::HashMap::new();
    other_labels.insert(
        "com.docker.compose.project".to_string(),
        "other".to_string(),
    );
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0labels_other".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                labels: Some(other_labels),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let inspected = docker.inspect_container("m0labels", None).await.unwrap();
    let inspected_labels = inspected
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .unwrap();
    assert_eq!(
        inspected_labels.get("com.docker.compose.project"),
        Some(&"m0labels".to_string())
    );
    assert_eq!(
        inspected_labels.get("com.docker.compose.service"),
        Some(&"web".to_string())
    );

    let mut filters = std::collections::HashMap::new();
    filters.insert(
        "label".to_string(),
        vec!["com.docker.compose.project=m0labels".to_string()],
    );
    filters.insert("name".to_string(), vec!["m0labels".to_string()]);
    filters.insert("status".to_string(), vec!["created".to_string()]);
    let listed = docker
        .list_containers(Some(bollard::container::ListContainersOptions::<String> {
            all: true,
            filters,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    let listed = &listed[0];
    assert!(
        listed
            .names
            .as_ref()
            .is_some_and(|names| names.contains(&"/m0labels".to_string()))
    );
    assert_eq!(
        listed
            .labels
            .as_ref()
            .and_then(|labels| labels.get("com.docker.compose.service")),
        Some(&"web".to_string())
    );

    let _ = docker.remove_container("m0labels", None).await;
    let _ = docker.remove_container("m0labels_other", None).await;
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
async fn start_container_waits_until_registry_leaves_created_for_compose_ps() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = docker.remove_container("m0startsync", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0startsync"])
        .output();

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0startsync".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/sleep".to_string(), "30".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    docker
        .start_container(
            "m0startsync",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();
    let inspect = docker.inspect_container("m0startsync", None).await.unwrap();
    assert!(
        inspect.state.as_ref().and_then(|state| state.running) == Some(true),
        "start returned before the container was running: {:?}",
        inspect.state
    );

    let _ = docker
        .remove_container(
            "m0startsync",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
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
async fn delete_running_container_requires_force() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0delforce"])
        .output();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0delforce".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 120".to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0delforce",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    let mut running = false;
    for _ in 0..150 {
        let inspected = docker.inspect_container("m0delforce", None).await.unwrap();
        if inspected
            .state
            .as_ref()
            .and_then(|state| state.running)
            .unwrap_or(false)
        {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(running, "container should be running before delete");

    assert!(
        docker.remove_container("m0delforce", None).await.is_err(),
        "Docker rejects deleting a running container unless Force=true"
    );
    docker.inspect_container("m0delforce", None).await.unwrap();

    docker
        .remove_container(
            "m0delforce",
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
        let info = item.unwrap_or_else(|e| panic!("build stream yielded an error frame: {e}"));
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
async fn bridge_published_port_restarts_without_stale_socket_namespace_state() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0netrestart"])
        .output();
    let host_port = free_loopback_port();
    let mut port_bindings = std::collections::HashMap::new();
    port_bindings.insert(
        "8080/tcp".to_string(),
        Some(vec![bollard::models::PortBinding {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: Some(host_port.to_string()),
        }]),
    );
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec!["/bin/sleep".to_string(), "30".to_string()]),
        host_config: Some(bollard::models::HostConfig {
            network_mode: Some("bridge".to_string()),
            port_bindings: Some(port_bindings),
            ..Default::default()
        }),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0netrestart".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();

    docker
        .start_container(
            "m0netrestart",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();
    for _ in 0..150 {
        let inspect = docker
            .inspect_container("m0netrestart", None)
            .await
            .unwrap();
        if inspect.state.unwrap().running.unwrap() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    docker.stop_container("m0netrestart", None).await.unwrap();
    let inspect = docker
        .inspect_container("m0netrestart", None)
        .await
        .unwrap();
    assert!(!inspect.state.unwrap().running.unwrap());

    docker
        .restart_container("m0netrestart", None)
        .await
        .unwrap();
    let mut running_again = false;
    for _ in 0..150 {
        let inspect = docker
            .inspect_container("m0netrestart", None)
            .await
            .unwrap();
        if inspect.state.unwrap().running.unwrap() {
            running_again = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        running_again,
        "container should be running after bridge restart"
    );

    let inspected = docker
        .inspect_container("m0netrestart", None)
        .await
        .unwrap();
    let ports = inspected
        .network_settings
        .as_ref()
        .and_then(|settings| settings.ports.as_ref())
        .unwrap();
    assert_eq!(
        ports
            .get("8080/tcp")
            .and_then(|bindings| bindings.as_ref())
            .and_then(|bindings| bindings.first())
            .and_then(|binding| binding.host_port.as_deref()),
        Some(host_port.to_string().as_str())
    );

    let _ = docker
        .remove_container(
            "m0netrestart",
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
async fn attach_container_replays_logs_for_compose() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0attachlogs"])
        .output();
    let body = bollard::container::Config {
        image: Some("ubuntu:24.04".to_string()),
        cmd: Some(vec![
            "/bin/echo".to_string(),
            "hello_serve_attach".to_string(),
        ]),
        ..Default::default()
    };
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0attachlogs".to_string(),
                ..Default::default()
            }),
            body,
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0attachlogs",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    let mut waits = docker.wait_container(
        "m0attachlogs",
        None::<bollard::container::WaitContainerOptions<String>>,
    );
    let _ = waits.next().await.unwrap().unwrap();

    let bollard::container::AttachContainerResults {
        mut output,
        input: _,
    } = docker
        .attach_container(
            "m0attachlogs",
            Some(bollard::container::AttachContainerOptions::<String> {
                stdout: Some(true),
                stderr: Some(true),
                logs: Some(true),
                stream: Some(false),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let mut attached = String::new();
    while let Some(item) = output.next().await {
        attached.push_str(&item.unwrap().to_string());
    }
    assert!(
        attached.contains("hello_serve_attach"),
        "attach output did not contain expected output: {:?}",
        attached
    );

    let _ = docker
        .remove_container(
            "m0attachlogs",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
async fn attach_container_streams_when_opened_before_start() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0attachpre"])
        .output();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0attachpre".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec![
                    "/bin/echo".to_string(),
                    "hello_attach_before_start".to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let attach_docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let attach_task = tokio::spawn(async move {
        let bollard::container::AttachContainerResults {
            mut output,
            input: _,
        } = attach_docker
            .attach_container(
                "m0attachpre",
                Some(bollard::container::AttachContainerOptions::<String> {
                    stdout: Some(true),
                    stderr: Some(true),
                    logs: Some(false),
                    stream: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        let mut attached = String::new();
        while let Ok(next) = tokio::time::timeout(Duration::from_secs(15), output.next()).await {
            match next {
                Some(Ok(item)) => {
                    attached.push_str(&item.to_string());
                    if attached.contains("hello_attach_before_start") {
                        break;
                    }
                }
                Some(Err(e)) => {
                    attached.push_str(&format!("attach stream error: {e}"));
                    break;
                }
                None => break,
            }
        }
        attached
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    docker
        .start_container(
            "m0attachpre",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    let attached = attach_task.await.unwrap();
    assert!(
        attached.contains("hello_attach_before_start"),
        "pre-start attach output did not contain expected output: {:?}",
        attached
    );

    let _ = docker
        .remove_container(
            "m0attachpre",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
async fn attach_container_upgrade_reports_docker_stream_content_type() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0attachctype"])
        .output();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0attachctype".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "unused".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut stream = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    std::io::Write::write_all(
        &mut stream,
        b"POST /v1.54/containers/m0attachctype/attach?stderr=1&stdout=1&stream=1 HTTP/1.1\r\n\
Host: api.moby.localhost\r\n\
User-Agent: compose/v5.1.4\r\n\
Content-Length: 0\r\n\
Connection: Upgrade\r\n\
Content-Type: text/plain\r\n\
Upgrade: tcp\r\n\
\r\n",
    )
    .unwrap();

    let headers = read_http_headers(&mut stream).unwrap();
    assert!(
        headers.starts_with("http/1.1 101"),
        "attach did not upgrade: {headers:?}"
    );
    assert!(
        headers.contains("content-type: application/vnd.docker.multiplexed-stream"),
        "attach response did not advertise Docker multiplexed stream: {headers:?}"
    );

    let _ = docker
        .remove_container(
            "m0attachctype",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
async fn wait_container_sends_headers_before_exit_for_compose_run() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0waitheaders"])
        .output();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0waitheaders".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "unused".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut stream = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    std::io::Write::write_all(
        &mut stream,
        b"POST /v1.54/containers/m0waitheaders/wait?condition=next-exit HTTP/1.1\r\n\
Host: api.moby.localhost\r\n\
User-Agent: compose/v5.1.4\r\n\
Content-Length: 0\r\n\
\r\n",
    )
    .unwrap();

    let headers = read_http_headers(&mut stream);
    let _ = docker
        .remove_container(
            "m0waitheaders",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;

    let headers = headers.unwrap();
    assert!(
        headers.starts_with("http/1.1 200"),
        "wait did not send success headers before container exit: {headers:?}"
    );
    assert!(
        headers.contains("content-type: application/json"),
        "wait response did not advertise JSON: {headers:?}"
    );
}

#[tokio::test]
async fn resize_tty_endpoint_accepts_compose_resize() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0resize"])
        .output();
    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0resize".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "sleep 30".to_string(),
                ]),
                tty: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0resize",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    docker
        .resize_container_tty(
            "m0resize",
            bollard::container::ResizeContainerTtyOptions {
                width: 120,
                height: 40,
            },
        )
        .await
        .unwrap();

    let _ = docker
        .remove_container(
            "m0resize",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
async fn events_stream_reports_container_create_for_compose() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();

    let _ = docker.remove_container("m0events", None).await;
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0events"])
        .output();

    let events_docker =
        bollard::Docker::connect_with_unix(&sock, 5, bollard::API_DEFAULT_VERSION).unwrap();
    let mut filters = std::collections::HashMap::new();
    filters.insert("type".to_string(), vec!["container".to_string()]);
    filters.insert("event".to_string(), vec!["create".to_string()]);
    filters.insert("container".to_string(), vec!["m0events".to_string()]);
    let event_task = tokio::spawn(async move {
        let mut events = events_docker.events(Some(bollard::system::EventsOptions::<String> {
            filters,
            ..Default::default()
        }));
        tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0events".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/echo".to_string(), "hi".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let event = event_task.await.unwrap();
    assert_eq!(event.action.as_deref(), Some("create"));
    assert_eq!(
        event
            .actor
            .as_ref()
            .and_then(|actor| actor.attributes.as_ref())
            .and_then(|attrs| attrs.get("name")),
        Some(&"m0events".to_string())
    );

    let _ = docker.remove_container("m0events", None).await;
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

#[tokio::test]
async fn download_archive_supports_compose_cp() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0archive"])
        .output();

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0archive".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "printf hello_archive >/tmp/cp.txt; sleep 60".to_string(),
                ]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0archive",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    let mut running = false;
    for _ in 0..150 {
        let inspect = docker.inspect_container("m0archive", None).await.unwrap();
        if inspect.state.unwrap().running.unwrap() {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(running, "container should be running");

    for _ in 0..150 {
        let exec = docker
            .create_exec(
                "m0archive",
                bollard::exec::CreateExecOptions {
                    cmd: Some(vec![
                        "/usr/bin/test".to_string(),
                        "-f".to_string(),
                        "/tmp/cp.txt".to_string(),
                    ]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let _ = docker.start_exec(&exec.id, None).await.unwrap();
        let inspected = docker.inspect_exec(&exec.id).await.unwrap();
        if inspected.exit_code == Some(0) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut raw = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    std::io::Write::write_all(
        &mut raw,
        b"GET /v1.54/containers/m0archive/archive?path=%2Ftmp%2Fcp.txt HTTP/1.1\r\n\
Host: api.moby.localhost\r\n\
\r\n",
    )
    .unwrap();
    let headers = read_http_headers(&mut raw).unwrap();
    assert!(
        headers.contains("x-docker-container-path-stat:"),
        "archive response did not include Docker path stat header: {headers:?}"
    );

    let mut archive_bytes = Vec::new();
    let mut stream = docker.download_from_container(
        "m0archive",
        Some(bollard::container::DownloadFromContainerOptions {
            path: "/tmp/cp.txt".to_string(),
        }),
    );
    while let Some(chunk) = stream.next().await {
        archive_bytes.extend_from_slice(&chunk.unwrap());
    }
    let mut archive = tar::Archive::new(std::io::Cursor::new(archive_bytes));
    let mut copied = String::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().as_ref() == std::path::Path::new("cp.txt") {
            std::io::Read::read_to_string(&mut entry, &mut copied).unwrap();
            break;
        }
    }
    assert_eq!(copied, "hello_archive");

    let _ = docker
        .remove_container(
            "m0archive",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}

#[tokio::test]
async fn upload_archive_supports_compose_cp_into_container() {
    let (_server, sock, _dir) = spawn_server();
    let docker =
        bollard::Docker::connect_with_unix(&sock, 30, bollard::API_DEFAULT_VERSION).unwrap();
    let _ = std::process::Command::new(assert_cmd::cargo::cargo_bin("carrick"))
        .args(["rm", "-f", "m0uploadarchive"])
        .output();

    docker
        .create_container(
            Some(bollard::container::CreateContainerOptions {
                name: "m0uploadarchive".to_string(),
                ..Default::default()
            }),
            bollard::container::Config {
                image: Some("ubuntu:24.04".to_string()),
                cmd: Some(vec!["/bin/sleep".to_string(), "60".to_string()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    docker
        .start_container(
            "m0uploadarchive",
            None::<bollard::container::StartContainerOptions<String>>,
        )
        .await
        .unwrap();

    let mut running = false;
    for _ in 0..150 {
        let inspect = docker
            .inspect_container("m0uploadarchive", None)
            .await
            .unwrap();
        if inspect.state.unwrap().running.unwrap() {
            running = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(running, "container should be running");

    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        let data = b"hello_upload_archive";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "uploaded.txt", &data[..])
            .unwrap();
        builder.finish().unwrap();
    }

    docker
        .upload_to_container(
            "m0uploadarchive",
            Some(bollard::container::UploadToContainerOptions {
                path: "/tmp".to_string(),
                ..Default::default()
            }),
            tar_bytes.into(),
        )
        .await
        .unwrap();

    let exec_create = docker
        .create_exec(
            "m0uploadarchive",
            bollard::exec::CreateExecOptions {
                cmd: Some(vec![
                    "/bin/cat".to_string(),
                    "/tmp/uploaded.txt".to_string(),
                ]),
                attach_stdout: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let start_exec_res = docker.start_exec(&exec_create.id, None).await.unwrap();
    let mut output = String::new();
    if let bollard::exec::StartExecResults::Attached {
        output: mut stream, ..
    } = start_exec_res
    {
        while let Some(log) = stream.next().await {
            output.push_str(&log.unwrap().to_string());
        }
    } else {
        panic!("expected attached start_exec results");
    }
    assert!(
        output.contains("hello_upload_archive"),
        "uploaded archive content was not visible in container: {output:?}"
    );

    let _ = docker
        .remove_container(
            "m0uploadarchive",
            Some(bollard::container::RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
}
