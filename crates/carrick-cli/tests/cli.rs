// Test code: gzip/tar helpers are plain `fn`s (not `#[test]`/`#[cfg(test)]`), so
// clippy's allow-unwrap-in-tests heuristic does not exempt them. The no-panic gate
// targets production code, so allow unwrap/expect across this integration test file.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use carrick_test_support::gzip_tar;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn command() -> Command {
    Command::cargo_bin("carrick").expect("carrick test binary")
}

#[test]
fn exec_backend_help_lists_only_portable_values() {
    command()
        .env_remove("CARRICK_EXEC_BACKEND")
        .args(["run-elf", "--help"])
        .assert()
        .success()
        .stdout(contains("possible values: hvpatch"));
}

#[test]
fn removed_auto_exec_backend_has_migration_guidance() {
    command()
        .env_remove("CARRICK_EXEC_BACKEND")
        .args(["run-elf", "--exec-backend", "vmm", "/does/not/matter"])
        .assert()
        .code(2)
        .stderr(contains("only 'hvpatch' is supported"));
}

#[test]
fn exec_backend_hvf_environment_value_has_migration_guidance() {
    command()
        .env("CARRICK_EXEC_BACKEND", "hvf")
        .args(["run-elf", "/does/not/matter"])
        .assert()
        .code(2)
        .stderr(contains("only 'hvpatch' is supported"));
}

#[test]
fn native_code_mode_flag_is_not_public_policy() {
    let output = command()
        .args([
            "run-elf",
            "--exec-backend",
            "hvpatch",
            "--native-code-mode",
            "dsr",
            "/does/not/matter",
        ])
        .output()
        .expect("run carrick CLI parser");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unexpected argument '--native-code-mode'")
    );
}

#[test]
fn inspect_elf_command_prints_json_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf()).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["inspect-elf", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\"machine\": \"aarch64\""))
        .stdout(contains("\"entry\": 4194304"));
}

#[test]
fn plan_elf_load_command_prints_segment_plan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf_with_load_segment()).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["plan-elf-load", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\"virtual_address\": 4194304"))
        .stdout(contains("\"execute\": true"));
}

#[test]
fn rootfs_cli_lists_and_reads_composed_layers() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar.gz");
    let upper = dir.path().join("upper.tar.gz");
    std::fs::write(&base, gzip_tar([("etc/motd", b"base".as_slice())])).unwrap();
    std::fs::write(
        &upper,
        gzip_tar([
            ("etc/.wh.motd", b"".as_slice()),
            ("etc/os-release", b"NAME=upper\n".as_slice()),
        ]),
    )
    .unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "rootfs",
            "--layer",
            base.to_str().unwrap(),
            "--layer",
            upper.to_str().unwrap(),
            "ls",
            "/etc",
        ])
        .assert()
        .success()
        .stdout(contains("os-release"))
        .stdout(predicates::str::contains("motd").not());

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "rootfs",
            "--layer",
            base.to_str().unwrap(),
            "--layer",
            upper.to_str().unwrap(),
            "cat",
            "/etc/os-release",
        ])
        .assert()
        .success()
        .stdout(contains("NAME=upper"));
}

#[test]
fn dispatch_syscall_cli_exercises_write_path() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "dispatch-syscall",
            "64",
            "--args",
            "1,16384,5,0,0,0",
            "--memory-base",
            "16384",
            "--memory-text",
            "hello",
        ])
        .assert()
        .success()
        .stdout(contains("\"stdout\": \"hello\""))
        .stdout(contains("\"value\": 5"));
}

#[test]
fn load_elf_command_prints_address_space_summary() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "load-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
            "--find-text",
            "hello from carrick\n",
        ])
        .assert()
        .success()
        .stdout(contains("\"region_count\""))
        .stdout(contains("\"found_address\""));
}

#[test]
fn network_cli_manages_docker_style_resources() {
    // The Docker API resource store is rooted next to the container registry,
    // which prefers the shared /Volumes/carrick scratch volume on macOS. Skip
    // there so this CLI test never mutates the operator's real network store.
    if std::path::Path::new("/Volumes/carrick").is_dir() {
        eprintln!("SKIP network_cli: shared /Volumes/carrick volume present");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let network_name = "carrick_cli_network";
    let other_network_name = "carrick_cli_network_other";

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "network",
            "create",
            "--subnet",
            "172.29.0.0/16",
            "--gateway",
            "172.29.0.1",
            "--ip-range",
            "172.29.8.0/24",
            "--aux-address",
            "router=172.29.0.254",
            "--ipam-driver",
            "carrick-ipam",
            "--ipam-opt",
            "mode=test",
            "--scope",
            "swarm",
            "--internal",
            "--attachable",
            "--ingress",
            "--config-only",
            "--ipv4=false",
            "--opt",
            "com.docker.network.bridge.name=carrick-test0",
            network_name,
        ])
        .assert()
        .success()
        .stdout(predicates::str::is_match(r"^[0-9a-f]{64}\n$").unwrap());
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "create", other_network_name])
        .assert()
        .success();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "inspect", network_name, other_network_name])
        .assert()
        .success()
        .stdout(contains("\"Name\":\"carrick_cli_network\""))
        .stdout(contains("\"Name\":\"carrick_cli_network_other\""))
        .stdout(contains("\"Internal\":true"))
        .stdout(contains("\"Attachable\":true"))
        .stdout(contains("\"Ingress\":true"))
        .stdout(contains("\"ConfigOnly\":true"))
        .stdout(contains("\"Scope\":\"swarm\""))
        .stdout(contains("\"EnableIPv4\":false"))
        .stdout(contains("\"Subnet\":\"172.29.0.0/16\""))
        .stdout(contains("\"IPRange\":\"172.29.8.0/24\""))
        .stdout(contains("\"Gateway\":\"172.29.0.1\""))
        .stdout(contains("\"Driver\":\"carrick-ipam\""))
        .stdout(contains("\"Options\":{\"mode\":\"test\"}"))
        .stdout(contains(
            "\"AuxiliaryAddresses\":{\"router\":\"172.29.0.254\"}",
        ))
        .stdout(contains(
            "\"Options\":{\"com.docker.network.bridge.name\":\"carrick-test0\"}",
        ));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "ls"])
        .assert()
        .success()
        .stdout(contains("carrick_cli_network"));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "network",
            "create",
            "--config-from",
            network_name,
            "carrick_cli_network_from_config",
        ])
        .assert()
        .success();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "inspect", "carrick_cli_network_from_config"])
        .assert()
        .success()
        .stdout(contains(
            "\"ConfigFrom\":{\"Network\":\"carrick_cli_network\"}",
        ));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "network",
            "rm",
            network_name,
            other_network_name,
            "carrick_cli_network_from_config",
        ])
        .assert()
        .success()
        .stdout(contains("carrick_cli_network"))
        .stdout(contains("carrick_cli_network_other"))
        .stdout(contains("carrick_cli_network_from_config"));
}

#[test]
fn network_cli_connects_and_disconnects_container_resources() {
    // The Docker API resource store is rooted next to the container registry,
    // which prefers the shared /Volumes/carrick scratch volume on macOS. Skip
    // there so this CLI test never mutates the operator's real container or
    // network store.
    if std::path::Path::new("/Volumes/carrick").is_dir() {
        eprintln!("SKIP network_connect_cli: shared /Volumes/carrick volume present");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let id = "b".repeat(64);
    let cdir = home.path().join("containers").join(&id);
    std::fs::create_dir_all(&cdir).unwrap();
    let state = serde_json::json!({
        "id": id, "name": "carrick_cli_attach", "image": "img", "command": [],
        "status": "created", "supervisor_pid": 0, "init_pid": 0,
        "created_secs": 0, "exit_code": serde_json::Value::Null, "auto_remove": false,
    });
    std::fs::write(cdir.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "create", "carrick_cli_attach_net"])
        .assert()
        .success();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "network",
            "connect",
            "--alias",
            "worker",
            "--ip",
            "172.31.44.11",
            "--ip6",
            "fd00:carrick::11",
            "--link-local-ip",
            "169.254.44.11",
            "--driver-opt",
            "mode=bridge",
            "--gw-priority",
            "42",
            "carrick_cli_attach_net",
            "carrick_cli_attach",
        ])
        .assert()
        .success();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "inspect", "carrick_cli_attach_net"])
        .assert()
        .success()
        .stdout(contains(&id))
        .stdout(contains("carrick_cli_attach"))
        .stdout(contains("172.31.44.11"))
        .stdout(contains("fd00:carrick::11"))
        .stdout(contains("169.254.44.11"))
        .stdout(contains("\"GwPriority\":42"))
        .stdout(contains("\"DriverOpts\":{\"mode\":\"bridge\"}"));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "rm", "carrick_cli_attach_net"])
        .assert()
        .failure()
        .stderr(contains("active endpoints"));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "network",
            "disconnect",
            "--force",
            "carrick_cli_attach_net",
            "carrick_cli_attach",
        ])
        .assert()
        .success();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "inspect", "carrick_cli_attach_net"])
        .assert()
        .success()
        .stdout(contains(&id).not());
}

#[test]
fn network_cli_accepts_docker_resource_commands() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["network", "--help"])
        .assert()
        .success()
        .stdout(contains("create"))
        .stdout(contains("connect"))
        .stdout(contains("disconnect"))
        .stdout(contains("inspect"))
        .stdout(contains("ls"))
        .stdout(contains("prune"))
        .stdout(contains("rm"));

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["network", "create", "--help"])
        .assert()
        .success()
        .stdout(contains("--subnet"))
        .stdout(contains("--gateway"))
        .stdout(contains("--ip-range"))
        .stdout(contains("--aux-address"))
        .stdout(contains("--ipam-driver"))
        .stdout(contains("--ipam-opt"))
        .stdout(contains("--scope"))
        .stdout(contains("--internal"))
        .stdout(contains("--attachable"))
        .stdout(contains("--ingress"))
        .stdout(contains("--config-from"))
        .stdout(contains("--config-only"))
        .stdout(contains("--ipv4"))
        .stdout(contains("--opt"));

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["network", "connect", "--help"])
        .assert()
        .success()
        .stdout(contains("--ip"))
        .stdout(contains("--ip6"))
        .stdout(contains("--link-local-ip"))
        .stdout(contains("--driver-opt"))
        .stdout(contains("--gw-priority"))
        .stdout(contains("--link <LINK>"));
}

#[test]
fn volume_cli_manages_docker_style_resources() {
    // The Docker API resource store is rooted next to the container registry,
    // which prefers the shared /Volumes/carrick scratch volume on macOS. Skip
    // there so this CLI test never mutates the operator's real volume store.
    if std::path::Path::new("/Volumes/carrick").is_dir() {
        eprintln!("SKIP volume_cli: shared /Volumes/carrick volume present");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    let volume_name = "carrick_cli_volume";
    let other_volume_name = "carrick_cli_volume_other";

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "volume",
            "create",
            "--label",
            "com.docker.compose.project=clivol",
            "--opt",
            "type=none",
            "--opt",
            "device=/tmp/carrick-cli-volume",
            volume_name,
        ])
        .assert()
        .success()
        .stdout(contains("carrick_cli_volume"));
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "create", volume_name])
        .assert()
        .success()
        .stdout(contains("carrick_cli_volume"));
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "create", other_volume_name])
        .assert()
        .success()
        .stdout(contains("carrick_cli_volume_other"));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "inspect", volume_name, other_volume_name])
        .assert()
        .success()
        .stdout(contains("\"Name\":\"carrick_cli_volume\""))
        .stdout(contains("\"Name\":\"carrick_cli_volume_other\""))
        .stdout(contains(
            "\"Options\":{\"device\":\"/tmp/carrick-cli-volume\",\"type\":\"none\"}",
        ))
        .stdout(contains("\"Mountpoint\""));

    let id = "c".repeat(64);
    let cdir = home.path().join("containers").join(&id);
    std::fs::create_dir_all(&cdir).unwrap();
    let mountpoint = home
        .path()
        .join("docker-api/volumes")
        .join(volume_name)
        .join("_data");
    let state = serde_json::json!({
        "id": id, "name": "carrick_cli_volume_user", "image": "img", "command": [],
        "status": "created", "supervisor_pid": 0, "init_pid": 0,
        "created_secs": 0, "exit_code": serde_json::Value::Null, "auto_remove": false,
        "config": {
            "mounts": [{
                "source": mountpoint.to_str().unwrap(),
                "target": "/data",
                "readonly": false,
            }]
        },
    });
    std::fs::write(cdir.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "rm", volume_name])
        .assert()
        .failure()
        .stderr(contains("volume is in use"));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "rm", "-f", volume_name])
        .assert()
        .failure()
        .stderr(contains("volume is in use"));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "rm", "-f", "carrick_cli_missing_volume"])
        .assert()
        .success()
        .stdout(contains("carrick_cli_missing_volume"));

    std::fs::remove_dir_all(cdir).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "ls"])
        .assert()
        .success()
        .stdout(contains("carrick_cli_volume"));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "volume",
            "ls",
            "--quiet",
            "--filter",
            "label=com.docker.compose.project=clivol",
        ])
        .assert()
        .success()
        .stdout(contains("carrick_cli_volume"))
        .stdout(contains("DRIVER").not())
        .stdout(contains("carrick_cli_volume_other").not());

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "ls", "--format", "{{.Name}}"])
        .assert()
        .success()
        .stdout(contains("carrick_cli_volume"))
        .stdout(contains("carrick_cli_volume_other"));

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "rm", volume_name, other_volume_name])
        .assert()
        .success()
        .stdout(contains("carrick_cli_volume"))
        .stdout(contains("carrick_cli_volume_other"));
}

#[test]
fn volume_cli_accepts_docker_resource_commands() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["volume", "--help"])
        .assert()
        .success()
        .stdout(contains("create"))
        .stdout(contains("inspect"))
        .stdout(contains("ls"))
        .stdout(contains("prune"))
        .stdout(contains("rm"));

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["volume", "rm", "--help"])
        .assert()
        .success()
        .stdout(contains("--force"));

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["volume", "create", "--help"])
        .assert()
        .success()
        .stdout(contains("--opt"));

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["volume", "prune", "--help"])
        .assert()
        .success()
        .stdout(contains("--all"))
        .stdout(contains("--filter"));

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["volume", "ls", "--help"])
        .assert()
        .success()
        .stdout(contains("--filter"))
        .stdout(contains("--quiet"))
        .stdout(contains("--format"));
}

#[test]
fn resource_cli_prune_honors_filters() {
    // The Docker API resource store is rooted next to the container registry,
    // which prefers the shared /Volumes/carrick scratch volume on macOS. Skip
    // there so this CLI test never mutates the operator's real resource store.
    if std::path::Path::new("/Volumes/carrick").is_dir() {
        eprintln!("SKIP resource_prune_cli: shared /Volumes/carrick volume present");
        return;
    }
    let home = tempfile::tempdir().unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "network",
            "create",
            "--label",
            "com.docker.compose.project=cliprune",
            "carrick_cli_prune_net",
        ])
        .assert()
        .success();
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["network", "create", "carrick_cli_prune_other"])
        .assert()
        .success();
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "network",
            "prune",
            "--force",
            "--filter",
            "label=com.docker.compose.project=cliprune",
        ])
        .assert()
        .success()
        .stdout(contains("carrick_cli_prune_net"))
        .stdout(contains("carrick_cli_prune_other").not());

    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "volume",
            "create",
            "--label",
            "com.docker.compose.project=cliprune",
            "carrick_cli_prune_volume",
        ])
        .assert()
        .success();
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "create", "carrick_cli_prune_other_volume"])
        .assert()
        .success();
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "volume",
            "prune",
            "--force",
            "--filter",
            "label=com.docker.compose.project=cliprune",
        ])
        .assert()
        .success()
        .stdout(contains("carrick_cli_prune_volume").not())
        .stdout(contains("carrick_cli_prune_other_volume").not());
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["volume", "inspect", "carrick_cli_prune_volume"])
        .assert()
        .success();
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args([
            "volume",
            "prune",
            "--force",
            "--all",
            "--filter",
            "label=com.docker.compose.project=cliprune",
        ])
        .assert()
        .success()
        .stdout(contains("carrick_cli_prune_volume"))
        .stdout(contains("carrick_cli_prune_other_volume").not());
}

#[test]
fn logs_replays_captured_output_for_a_container() {
    // The registry root prefers the shared /Volumes/carrick volume when it
    // exists; only when it's absent does CARRICK_HOME redirect it. Self-skip on
    // a host with the shared volume so we never pollute (or depend on) it.
    if std::path::Path::new("/Volumes/carrick").is_dir() {
        eprintln!("SKIP logs_replays: shared /Volumes/carrick volume present");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    // registry_root == <CARRICK_HOME>/scratch/containers/<id>/
    let id = "a".repeat(64);
    let cdir = home.path().join("scratch/containers").join(&id);
    std::fs::create_dir_all(&cdir).unwrap();
    let state = serde_json::json!({
        "id": id, "name": serde_json::Value::Null, "image": "img", "command": [],
        "status": "exited", "supervisor_pid": 0, "init_pid": 0,
        "created_secs": 0, "exit_code": 0, "auto_remove": false,
    });
    std::fs::write(cdir.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();
    std::fs::write(cdir.join("output.log"), b"hello from logs\nsecond line\n").unwrap();

    // Full replay.
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["logs", &id])
        .assert()
        .success()
        .stdout(contains("hello from logs"))
        .stdout(contains("second line"));

    // `--tail 1` shows only the last line.
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["logs", "--tail", "1", &id])
        .assert()
        .success()
        .stdout(contains("second line"))
        .stdout(contains("hello from logs").not());
}

#[test]
fn logs_unknown_container_errors() {
    // A random id matches nothing in any registry → docker-style "no such
    // container". Hermetic regardless of registry location.
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["logs", "definitely-not-a-real-container-id"])
        .assert()
        .failure()
        .stderr(contains("no such container"));
}

fn minimal_aarch64_elf() -> Vec<u8> {
    let mut elf = vec![0_u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf
}

fn minimal_aarch64_elf_with_load_segment() -> Vec<u8> {
    let mut elf = vec![0_u8; 0x1004];
    elf[0..64].copy_from_slice(&minimal_aarch64_elf());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());

    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
    elf[ph + 8..ph + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[ph + 32..ph + 40].copy_from_slice(&4_u64.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[0x1000..0x1004].copy_from_slice(b"\x1f\x20\x03\xd5");
    elf
}
