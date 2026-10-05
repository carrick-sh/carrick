//! Numeric exec rejection diagnostic. The oracle is provisional until the
//! director blesses this exact source on native arm64 Linux; no Docker here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn case_elf_exec_errno() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let fixture = root.join("crates/carrick-conformance-next/tests/fixtures/elf-exec-errno");
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/elf-exec-errno/oracle.json"))
            .expect("parse ELF exec oracle");
    let source_hash = carrick_xtask::provision::compute_sha256(&fixture.join("src/main.rs"))
        .expect("hash guest fixture source");
    assert_eq!(
        oracle["source_sha256"].as_str(),
        Some(source_hash.as_str()),
        "stale ELF oracle source"
    );
    let probe =
        root.join("target/elf-exec-errno/aarch64-unknown-linux-musl/release/elf-exec-errno");
    let binary_hash = carrick_xtask::provision::compute_sha256(&probe)
        .expect("build the ELF exec fixture with the command in its README");
    eprintln!(
        "ELF_EXEC_ERRNO source_sha256={source_hash} binary_sha256={binary_hash} oracle_status={}",
        oracle["status"]
    );
    let (result, _) = common::run_or_fail(
        TestContainer::new(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(probe.display().to_string(), "/tmp/elf-exec-errno")
            .run_with_audit(["/bin/sh", "-c", "exec /tmp/elf-exec-errno"]),
    );
    result.assert_success();
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    eprintln!("ELF_EXEC_ERRNO observed:\n{}", result.stdout_utf8());
    // Linux accepts pathname bytes; the current Carrick fs API uses strings.
    // Check this explicit representation limit without claiming Linux parity.
    let expected = oracle["stdout"].as_str().unwrap();
    assert!(expected.contains("non_utf8_interp_errno=2\n"));
    let carrick_expected =
        expected.replace("non_utf8_interp_errno=2\n", "non_utf8_interp_errno=8\n");
    assert_eq!(result.stdout_utf8(), carrick_expected);
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
    // A passing provisional comparison confirms only Carrick's current
    // assumptions, never Linux conformance or accepted oracle provenance.
    assert!(matches!(
        oracle["status"].as_str(),
        Some("pending-director-bless" | "blessed")
    ));
}
