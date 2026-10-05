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
fn every_shard_is_required_in_hosted_ci_and_union_check_runs_on_both_hosts() {
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
        assert_eq!(jobs[job.as_str()]["runs-on"].as_str(), Some("macos-15"));
        let steps = jobs[job.as_str()]["steps"].as_vec().unwrap();
        assert!(
            steps
                .iter()
                .any(|s| s["run"].as_str() == Some(&format!("just ci-macos-test {shard}")))
        );
        assert!(
            steps
                .iter()
                .any(|s| s["with"]["shared-key"].as_str() == Some("macos-host"))
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
    for job in ["lint", "macos-clippy"] {
        assert!(
            jobs[job]["steps"]
                .as_vec()
                .unwrap()
                .iter()
                .any(|s| s["run"].as_str() == Some("just check-test-shards")),
            "{job} must check the host's shard union"
        );
    }
}
