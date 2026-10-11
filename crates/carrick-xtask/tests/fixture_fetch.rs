#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Fixture dependency prefetch: the publisher's only network step.
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn fetch_plan_covers_every_fixture_lockfile_including_conformance_probes() {
    let root = repo();
    let plan = carrick_xtask::fixtures::fetch_plan(&root).unwrap();
    // simd-adler32 (the live offline failure) is pinned by conformance-probes.
    assert!(plan.contains(&root.join("conformance-probes/Cargo.toml")));
    for manifest in &plan {
        assert!(manifest.parent().unwrap().join("Cargo.lock").is_file());
    }
    assert!(plan.len() >= 7);
}

#[test]
fn publisher_fetches_before_the_offline_environment_is_created() {
    let source = include_str!("../src/fixtures.rs");
    let build = &source[source.find("pub fn build(").unwrap()..];
    let fetch = build.find("fetch_dependencies(root)?").unwrap();
    let environment = build.find("BuildEnvironment::new(root)?").unwrap();
    assert!(
        fetch < environment,
        "the shared cache must exist before the isolated environment links it"
    );
}

#[test]
fn serial_host_fetch_tries_offline_then_locked_network_for_each_lockfile() {
    let root = repo();
    let plan = carrick_xtask::fixtures::fetch_plan(&root).unwrap();
    let fake = tempfile::tempdir().unwrap();
    for manifest in &plan {
        let rel = manifest.parent().unwrap().strip_prefix(&root).unwrap();
        let dir = fake.path().join(rel);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]\n").unwrap();
        std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    }
    let bin = tempfile::tempdir().unwrap();
    let log = bin.path().join("log");
    let cargo = bin.path().join("cargo");
    // A cold cache: offline fails, the locked network fetch succeeds.
    std::fs::write(
        &cargo,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \" $* \" in *' --offline '*) exit 101;; esac\nexit 0\n",
            log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
    let old = std::env::var_os("PATH").unwrap();
    let mut paths = vec![bin.path().to_path_buf()];
    paths.extend(std::env::split_paths(&old));
    unsafe { std::env::set_var("PATH", std::env::join_paths(paths).unwrap()) };
    let result = carrick_xtask::fixtures::fetch_dependencies(fake.path());
    unsafe { std::env::set_var("PATH", &old) };
    assert_eq!(result.unwrap(), plan.len());
    let calls: Vec<String> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(calls.len(), plan.len() * 2);
    for pair in calls.chunks(2) {
        assert!(pair[0].starts_with("fetch --locked --offline --manifest-path "));
        assert!(pair[1].starts_with("fetch --locked --manifest-path "));
    }
    // A failing network fetch is an explicit error naming the manifest.
    std::fs::write(&cargo, "#!/bin/sh\necho 'no network' >&2\nexit 101\n").unwrap();
    let mut paths = vec![bin.path().to_path_buf()];
    paths.extend(std::env::split_paths(&old));
    unsafe { std::env::set_var("PATH", std::env::join_paths(paths).unwrap()) };
    let error = carrick_xtask::fixtures::fetch_dependencies(fake.path()).unwrap_err();
    unsafe { std::env::set_var("PATH", &old) };
    assert!(error.to_string().contains("cargo fetch --locked failed"));
    assert!(error.to_string().contains("no network"));
}
