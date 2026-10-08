#![allow(clippy::unwrap_used, clippy::panic)]
use carrick_conformance::lane::{Lane, LocalKvmConfig, OracleBackend};
use carrick_conformance::native::{ProbeProvenance, validate_probe_provenance};
use carrick_conformance::shard::{Shard, partition};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn native_requires_local_x86_linux() {
    let lane = Lane::KvmLocal(LocalKvmConfig { timeout_scale: 1.0 });
    assert!(
        OracleBackend::Native
            .validate_host(&lane, "linux", "x86_64")
            .is_ok()
    );
    for (lane, os, arch) in [
        (&Lane::Hvf, "linux", "x86_64"),
        (&lane, "macos", "x86_64"),
        (&lane, "linux", "aarch64"),
    ] {
        assert!(OracleBackend::Native.validate_host(lane, os, arch).is_err());
    }
}

#[test]
fn partition_is_deterministic_disjoint_and_covering() {
    let names: Vec<String> = (0..29).map(|i| format!("case-{i:02}")).collect();
    let timings = BTreeMap::from([("case-03".into(), 100_000), ("case-17".into(), 20_000)]);
    for count in 1..=8 {
        let first = partition(&names, &timings, count).unwrap();
        let mut reversed = names.clone();
        reversed.reverse();
        assert_eq!(first, partition(&reversed, &timings, count).unwrap());
        let flattened: Vec<_> = first.iter().flatten().cloned().collect();
        assert_eq!(flattened.len(), names.len());
        assert_eq!(
            flattened.into_iter().collect::<BTreeSet<_>>(),
            names.iter().cloned().collect()
        );
    }
    assert!(Shard::parse("0/2").is_err());
    assert!(Shard::parse("3/2").is_err());
}

#[test]
fn provenance_kernel_mismatch_fails_closed() {
    let provenance = ProbeProvenance::new("6.12.1-test".into(), "Debian".into());
    assert!(validate_probe_provenance(&provenance, "6.12.1-test").is_ok());
    assert!(validate_probe_provenance(&provenance, "6.12.2-test").is_err());
}

fn suite() -> carrick_conformance::manifest::Suite {
    carrick_conformance::manifest::Manifest::from_toml(
        r#"
        [[suite]]
        name = "native-demo"
        ecosystem = "ltp"
        image = "example/image:1"
        cmd = ["/opt/test", "argument"]
        verdict = "shell"
        tier = "smoke"
        weight = "light"
        timeout_s = 1
        env = [{key="SHARED", val="hello world"}]
        env_docker = [{key="ORACLE", val="a=b"}]
        env_carrick = [{key="CARRICK_ONLY", val="hidden"}]
        workdir = "/tmp"
        [suite.entrypoint]
        docker = "/oracle-entry"
        carrick = "/carrick-entry"
    "#,
    )
    .unwrap()
    .suite
    .remove(0)
}

#[test]
fn native_argv_mirrors_docker_inputs_and_uses_unshare_chroot() {
    use carrick_conformance::{argv, native};
    let s = suite();
    let rootfs = native::NativeRootfs {
        root: "/private/root with space".into(),
        env: vec!["IMAGE_ENV=present".into()],
        ..Default::default()
    };
    let docker = argv::docker_argv(&s, "demo", argv::DockerPlatform::LinuxAmd64);
    let native = argv::native_argv(&s, &rootfs).unwrap();
    for value in ["SHARED=hello world", "ORACLE=a=b", "/oracle-entry", "/tmp"] {
        assert!(docker.iter().any(|arg| arg == value));
        assert!(native.iter().any(|arg| arg == value));
    }
    assert!(
        !native
            .iter()
            .any(|arg| arg.starts_with("CARRICK_ONLY=") || arg == "/carrick-entry")
    );
    let image_index = docker.iter().position(|arg| arg == &s.image).unwrap();
    assert!(native.ends_with(&docker[image_index + 1..]));
    assert!(
        native
            .windows(2)
            .any(|pair| pair == ["/usr/sbin/chroot", "/private/root with space"])
    );
    assert!(
        native::UNSHARE_FLAGS
            .iter()
            .all(|flag| native.iter().any(|arg| arg == flag))
    );
    assert!(native.windows(2).any(|pair| pair == ["env", "-i"]));
    let mut unsupported = s.clone();
    unsupported.docker_flags = vec!["--privileged".into()];
    assert!(argv::native_argv(&unsupported, &rootfs).is_err());
    let mut bad_environment = rootfs.clone();
    bad_environment.env = vec!["/usr/bin/true".into()];
    assert!(argv::native_argv(&s, &bad_environment).is_err());
    let chroot = native
        .iter()
        .position(|arg| arg == "/usr/sbin/chroot")
        .unwrap();
    assert_eq!(&native[chroot + 2..chroot + 4], ["/bin/sh", "-c"]);
    assert!(native[chroot + 4].contains("exec 3>&-"));
    assert!(native[chroot + 4].ends_with("exec \"$@\""));
    let mut probe_root = rootfs.clone();
    probe_root.probe_binary = Some("/fixture/probe".into());
    let probe = argv::native_argv(&s, &probe_root).unwrap();
    let chroot = probe
        .iter()
        .position(|arg| arg == "/usr/sbin/chroot")
        .unwrap();
    assert!(probe[chroot + 4].contains("\"$@\"; rc=$?; exit \"$rc\""));
}

#[test]
fn empty_image_workdir_means_root_but_empty_suite_workdir_is_invalid() {
    use carrick_conformance::{argv, native};
    let mut suite = suite();
    suite.workdir = None;
    let root = native::NativeRootfs {
        root: "/private/image".into(),
        workdir: Some(String::new()),
        ..Default::default()
    };
    let args = argv::native_argv(&suite, &root).unwrap();
    assert!(!args.iter().any(|arg| arg == "native-workdir"));
    suite.workdir = Some(String::new());
    assert!(argv::native_argv(&suite, &root).is_err());
}

#[test]
fn native_cache_cannot_collide_or_write_docker_file() {
    use carrick_conformance::{argv::DockerPlatform, native, oracle::*};
    let s = suite();
    let docker = oracle_key(&s, DockerPlatform::LinuxAmd64);
    let native = oracle_key_with_identity(
        &s,
        DockerPlatform::LinuxAmd64,
        ParserProfile::Regression,
        Some(("6.12", "sha256:image")),
    );
    assert_ne!(docker, native);
    assert!(!docker.contains("oracle_backend"));
    assert!(native.contains("native-unshare-v1"));
    let dir = tempfile::tempdir().unwrap();
    let docker_path = dir.path().join("oracle-cache.jsonl");
    std::fs::write(&docker_path, "untouched").unwrap();
    let images = BTreeMap::from([(s.image.clone(), "sha256:image".into())]);
    assert!(OracleCache::load_native(&docker_path, "6.12".into(), images.clone()).is_err());
    let native_path = dir.path().join(
        OracleBackend::Native
            .cache_path()
            .rsplit('/')
            .next()
            .unwrap(),
    );
    let mut cache = OracleCache::load_native(&native_path, "6.12".into(), images.clone()).unwrap();
    let raw = carrick_conformance::parsers::Raw {
        stdout: "ok".into(),
        stderr: String::new(),
        exit_code: 0,
        timed_out: false,
    };
    let result = carrick_conformance::parsers::parse(s.verdict, &raw);
    assert!(cache.insert(&s, DockerPlatform::LinuxAmd64, result, Some(100)));
    cache.save().unwrap();
    assert_eq!(std::fs::read_to_string(&docker_path).unwrap(), "untouched");
    assert!(
        std::fs::read_to_string(&native_path)
            .unwrap()
            .contains(native::BACKEND_ID)
    );
    let loaded = OracleCache::load_native(&native_path, "6.12".into(), images.clone()).unwrap();
    assert!(loaded.get(&s, DockerPlatform::LinuxAmd64).is_some());
    let mut unknown = s.clone();
    unknown.image = "unregistered-image".into();
    assert!(!cache.insert(
        &unknown,
        DockerPlatform::LinuxAmd64,
        carrick_conformance::parsers::parse(s.verdict, &raw),
        Some(100),
    ));
    let alias = dir.path().join("alias");
    std::fs::create_dir(&alias).unwrap();
    let alias_cache = alias.join("oracle-cache.native-amd64.jsonl");
    std::os::unix::fs::symlink(&native_path, &alias_cache).unwrap();
    assert!(OracleCache::load_native(&alias_cache, "6.12".into(), images.clone()).is_err());
    let other_kernel = OracleCache::load_native(&native_path, "6.13".into(), images).unwrap();
    assert!(other_kernel.get(&s, DockerPlatform::LinuxAmd64).is_none());
}

#[test]
fn every_committed_docker_key_keeps_schema_and_prior_hits() {
    use carrick_conformance::{argv::DockerPlatform, oracle::*};
    let cache = include_str!("../../../scripts/conformance/oracle-cache.jsonl");
    let mut count = 0;
    for row in cache.lines().filter(|line| !line.trim().is_empty()) {
        let record: OracleRecord = serde_json::from_str(row).unwrap();
        let key: serde_json::Value = serde_json::from_str(&record.key).unwrap();
        let mut s = suite();
        s.image = key["image"].as_str().unwrap().into();
        s.cmd = serde_json::from_value(key["cmd"].clone()).unwrap();
        s.docker_flags = serde_json::from_value(key["docker_flags"].clone()).unwrap();
        s.bind_mounts = serde_json::from_value(key["bind_mounts"].clone()).unwrap();
        s.env = serde_json::from_value::<Vec<String>>(key["env"].clone())
            .unwrap()
            .into_iter()
            .map(|kv| {
                let (key, val) = kv.split_once('=').unwrap();
                carrick_conformance::manifest::EnvKv {
                    key: key.into(),
                    val: val.into(),
                }
            })
            .collect();
        s.env_docker.clear();
        s.workdir = serde_json::from_value(key["workdir"].clone()).unwrap();
        s.entrypoint =
            key["entrypoint"]
                .as_str()
                .map(|ep| carrick_conformance::manifest::EnginePair {
                    docker: Some(ep.into()),
                    ..Default::default()
                });
        s.verdict = serde_json::from_value(key["verdict"].clone()).unwrap();
        let platform = match key["docker_platform"].as_str().unwrap_or("linux/arm64") {
            "linux/arm64" => DockerPlatform::LinuxArm64,
            "linux/amd64" => DockerPlatform::LinuxAmd64,
            other => panic!("unknown platform {other}"),
        };
        let profile = if key["parser_profile"].is_string() {
            ParserProfile::ClosureV3
        } else {
            ParserProfile::Regression
        };
        let generated = oracle_key_for_profile(&s, platform, profile);
        let current: serde_json::Value = serde_json::from_str(&generated).unwrap();
        // Main already retains historical regrtest fingerprints that miss its
        // current parser. Preserve their exact schema bytes; do not silently
        // re-admit stale parser results or refresh Docker during this work.
        let mut historical = generated;
        if key["docker_platform"].is_null() {
            historical = historical.replacen("\"docker_platform\":\"linux/arm64\",", "", 1);
        }
        for field in ["parser", "parser_profile"] {
            if current[field] != key[field] {
                let now = format!(
                    ",\"{field}\":{}",
                    serde_json::to_string(&current[field]).unwrap()
                );
                let prior = if key[field].is_null() {
                    String::new()
                } else {
                    format!(
                        ",\"{field}\":{}",
                        serde_json::to_string(&key[field]).unwrap()
                    )
                };
                historical = historical.replace(&now, &prior);
            }
        }
        assert_eq!(historical, record.key, "{}", record.name);
        count += 1;
    }
    assert!(
        count > 2_000,
        "inventory was unexpectedly truncated: {count}"
    );
}

#[test]
fn native_cli_refuses_other_lanes_before_any_execution() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_carrick-conformance"))
        .args(["--oracle", "native", "--lane", "hvf", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires --lane kvm-local"));
}
