//! Real Linux processes cross the production exec preparation/adoption path.
//! No test binds an executable or passes one to readlink's service.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

fn run(scenario: &str) {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let source = root
        .join("crates/carrick-conformance-next/tests/fixtures/native-exe-lifecycle/src/main.rs");
    let source_hash = carrick_xtask::provision::compute_sha256(&source).unwrap();
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/native-exe-lifecycle/oracle.json")).unwrap();
    assert_eq!(
        oracle["source_sha256"].as_str(),
        Some(source_hash.as_str()),
        "stale lifecycle oracle"
    );
    // Native Linux x86_64 qualified the fixture, but cannot bless ARM/HVF.
    assert!(matches!(
        oracle["status"].as_str(),
        Some("pending-native-arm64-bless" | "blessed")
    ));
    let observations = oracle["stdout"][scenario]
        .as_str()
        .expect("scenario oracle");
    let probe = root.join(
        "target/native-exe-lifecycle/aarch64-unknown-linux-musl/release/native-exe-lifecycle",
    );
    let binary_hash = carrick_xtask::provision::compute_sha256(&probe)
        .expect("signed runner must build the native executable lifecycle fixture");
    eprintln!(
        "native_exe_lifecycle scenario={scenario} source_sha256={source_hash} binary_sha256={binary_hash}"
    );
    let command = format!("exec /tmp/native-exe-lifecycle {scenario}");
    let (result, _) = common::run_or_fail(
        TestContainer::new(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(probe.display().to_string(), "/tmp/native-exe-lifecycle")
            .run_with_audit(["/bin/sh", "-c", &command]),
    );
    result.assert_success();
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(
        result.stdout_utf8(),
        format!("fixture_source_sha256={source_hash}\n{observations}"),
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
#[ignore = "boots HVF; run via the signed conformance recipe with --include-ignored"]
fn case_native_exe_lifecycle_two_live_relative_and_symlink_exec() {
    run("populations");
}

#[test]
#[ignore = "boots HVF; run via the signed conformance recipe with --include-ignored"]
fn case_native_exe_lifecycle_real_fork_inheritance() {
    run("fork");
}

#[test]
#[ignore = "boots HVF; run via the signed conformance recipe with --include-ignored"]
fn case_native_exe_lifecycle_real_vfork_shared_mm() {
    run("vfork");
}

#[test]
#[ignore = "boots HVF; run via the signed conformance recipe with --include-ignored"]
fn case_native_exe_lifecycle_two_live_threads() {
    run("thread");
}

#[test]
#[ignore = "boots HVF; run via the signed conformance recipe with --include-ignored"]
fn case_native_exe_lifecycle_failed_exec_preserves_running_caller() {
    run("failed");
}

#[test]
#[ignore = "boots HVF; run via the signed conformance recipe with --include-ignored"]
fn case_native_exe_lifecycle_root_rename_unlink_live_holders() {
    run("mutations");
}
