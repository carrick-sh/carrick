#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn check(shards: &str) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("justfile"),
        format!(
            "test:\n    cargo test -p one --lib -- --skip serial_host\n    env RUST_TEST_THREADS=1 cargo test -p one --lib serial_host\n{shards}"
        ),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["--root", dir.path().to_str().unwrap(), "check-test-shards"])
        .output()
        .unwrap()
}

#[test]
fn reordered_shards_preserve_exact_commands_and_serial_environment() {
    let result = check(
        "test-shard-a:\n    env RUST_TEST_THREADS=1 cargo test -p one --lib serial_host\ntest-shard-b:\n    cargo test -p one --lib -- --skip serial_host\n",
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn missing_duplicate_filtered_or_unserialized_tests_are_rejected() {
    let parallel = "    cargo test -p one --lib -- --skip serial_host\n";
    let serial = "    env RUST_TEST_THREADS=1 cargo test -p one --lib serial_host\n";
    for body in [
        parallel.to_string(),
        format!("{parallel}{serial}{serial}"),
        format!(
            "{parallel}    env RUST_TEST_THREADS=1 cargo test -p one --lib serial_host -- --skip lost_test\n"
        ),
        format!("{parallel}    cargo test -p one --lib serial_host\n"),
        format!("{parallel}    env RUST_TEST_THREADS=2 cargo test -p one --lib serial_host\n"),
    ] {
        let result = check(&format!("test-shard-a:\n{body}"));
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("shard coverage differs"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

#[test]
fn failed_recipe_is_not_treated_as_empty_coverage() {
    let result = check("test-shard-a:\n    false\n");
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("recipe test-shard-a failed"));
}

#[test]
fn every_shard_is_required_in_hosted_ci_and_union_check_runs_on_linux() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflow = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let documents = yaml_rust2::YamlLoader::load_from_str(&workflow).unwrap();
    let jobs = &documents[0]["jobs"];
    let needs = jobs["ci-ok"]["needs"].as_vec().unwrap();
    let shards = carrick_xtask::test_shards::shard_recipes(&root).unwrap();
    for shard in &shards {
        let job = format!("macos-unit-{}", shard.strip_prefix("test-shard-").unwrap());
        assert!(
            needs.iter().any(|v| v.as_str() == Some(&job)),
            "ci-ok must require {job}"
        );
        assert_eq!(
            jobs[job.as_str()]["runs-on"].as_str(),
            Some("${{ fromJSON(needs.changes.outputs.macos_runner) }}")
        );
        let steps = jobs[job.as_str()]["steps"].as_vec().unwrap();
        assert!(
            steps
                .iter()
                .any(|s| s["run"].as_str() == Some(&format!("just ci-macos-test {shard}")))
        );
        assert!(
            steps
                .iter()
                .any(|s| s["with"]["shared-key"].as_str() == Some("${{ github.job }}-debug-v2"))
        );
    }
    assert_eq!(
        jobs.as_hash()
            .unwrap()
            .keys()
            .filter(|k| k.as_str().is_some_and(|s| s.starts_with("macos-unit")))
            .count(),
        shards.len()
    );
    // Only same-repo pull_request jobs may reach the self-hosted macOS
    // runner; forks, merge groups and cache-saving push/schedule stay hosted
    // (#650).
    let runner = jobs["changes"]["outputs"]["macos_runner"].as_str().unwrap();
    assert!(
        runner.starts_with("${{ (github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository) && ")
            && runner.contains("carrick-macos-ci")
            && runner.ends_with("|| '\"macos-15\"' }}"),
        "changes.outputs.macos_runner must route only same-repo PRs to carrick-macos-ci: {runner}"
    );
    let job = "lint-gates";
    assert!(
        jobs[job]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s["run"].as_str() == Some("just check-test-shards")),
        "{job} must check both hosts' shard unions"
    );
    assert!(
        !jobs["macos-clippy"]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s["run"].as_str() == Some("just check-test-shards"))
    );
    assert!(
        !jobs["lint-domains"]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s["run"].as_str() == Some("just check-test-shards"))
    );
    assert!(
        needs.iter().any(|v| v.as_str() == Some("lint-gates")),
        "ci-ok must require lint-gates"
    );
    assert!(
        needs.iter().any(|v| v.as_str() == Some("lint-domains")),
        "ci-ok must require lint-domains"
    );
    for job in [
        "lint-clippy",
        "macos-authority",
        "loom",
        "xtask-tests-build",
    ] {
        assert!(
            needs.iter().any(|v| v.as_str() == Some(job)),
            "ci-ok must require {job}"
        );
    }
    assert_eq!(jobs["loom"]["strategy"]["fail-fast"].as_bool(), Some(false));
    assert_eq!(
        jobs["loom"]["strategy"]["matrix"]["shard"]
            .as_vec()
            .unwrap()
            .len(),
        2
    );
    let runs = |job: &str, command: &str| {
        jobs[job]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s["run"].as_str() == Some(command))
    };
    assert!(runs("linux-doc", "just check-fuzz"));
    assert!(!runs("macos-build", "just check-fuzz"));
    assert!(
        runs("macos-build", "just doc"),
        "macOS cfg documentation must retain native coverage"
    );
    assert!(
        runs("macos-clippy", "just xtask authority-debt"),
        "PR and nightly macOS census must remain in macos-clippy"
    );
    let census = jobs["macos-clippy"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|s| s["run"].as_str() == Some("just xtask authority-debt"))
        .unwrap();
    assert_eq!(
        census["if"].as_str(),
        Some("${{ !cancelled() && github.event_name != 'merge_group' }}")
    );
    assert!(
        runs("macos-authority", "just xtask authority-debt"),
        "compiled macOS authority profiles cannot be replaced by Linux discovery"
    );
}

#[test]
fn linux_check_rejects_missing_macos_only_selection() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("justfile"),
        r#"
host := env("CARRICK_TEST_CAPTURE_HOST", os())
test:
    #!/usr/bin/env bash
    if [ "{{host}}" = "macos" ]; then
        cargo test -p macos-only --lib
    else
        cargo test -p linux-only --lib
    fi
test-shard-a:
    cargo test -p linux-only --lib
"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["--root", dir.path().to_str().unwrap(), "check-test-shards"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "macOS selections were not checked on Linux"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("shard coverage differs"));
}

#[cfg(target_os = "linux")]
#[test]
fn capture_owns_its_helper_when_a_build_replaces_the_running_binary() {
    let binary = std::path::Path::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    // A hardlink preserves this test's unlinked-running-inode scenario. Keep
    // it on the executable's filesystem so temp-directory mounts cannot EXDEV.
    let dir = tempfile::Builder::new()
        .prefix("xtask-replacement-")
        .tempdir_in(binary.parent().unwrap())
        .unwrap();
    let executable = dir.path().join("xtask");
    std::fs::hard_link(binary, &executable).unwrap();
    std::fs::write(dir.path().join("justfile"), "test:\n    rm -f \"$CARRICK_TEST_EXECUTABLE\"\n    cargo test -p one --lib\nlanes:\n    cargo test -p one --lib\ntest-shard-a:\n    cargo run -p carrick-xtask -- test-batch lanes\n").unwrap();
    let output = Command::new(&executable)
        .current_dir(dir.path())
        .args(["check-test-shards"])
        .env("CARRICK_TEST_EXECUTABLE", &executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn merging_shards_into_test_batch_with_differing_features_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("alpha/src")).unwrap();
    std::fs::create_dir_all(dir.path().join("beta/src")).unwrap();
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[workspace]\nresolver = \"2\"\nmembers = [\"alpha\", \"beta\"]\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("alpha/Cargo.toml"),
        "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[features]\ndefault = []\nhost-test = []\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("alpha/src/lib.rs"), "").unwrap();
    std::fs::write(
        dir.path().join("beta/Cargo.toml"),
        "[package]\nname = \"beta\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dev-dependencies]\nalpha = { path = \"../alpha\", features = [\"host-test\"] }\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("beta/src/lib.rs"), "").unwrap();
    std::fs::write(
        dir.path().join("justfile"),
        r#"
test:
    cargo test -p alpha --lib
    cargo test -p beta --lib

batched:
    cargo test -p alpha --lib
    cargo test -p beta --lib

test-shard-a:
    cargo run -p carrick-xtask -- test-batch batched
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["--root", dir.path().to_str().unwrap(), "check-test-shards"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "batching alpha with beta must fail when beta dev-dependencies enable alpha/host-test"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("shard per-binary feature sets differ")
            && stderr.contains("alpha/host-test"),
        "expected per-binary feature diff naming alpha/host-test, got: {stderr}"
    );
}

#[test]
fn workspace_test_and_shards_agree_including_unconditional_kernel_control() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["--root", root.to_str().unwrap(), "check-test-shards"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn workspace_capture_with_artifact_and_no_cargo_environment() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("xtask artifact");
    std::fs::copy(env!("CARGO_BIN_EXE_carrick-xtask"), &artifact).unwrap();
    let output = Command::new(&artifact)
        .args(["--root", root.to_str().unwrap(), "check-test-shards"])
        .env("CARRICK_XTASK_BIN", &artifact)
        .env_remove("CARGO")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
