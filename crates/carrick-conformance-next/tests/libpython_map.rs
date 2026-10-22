//! Provisional Linux mmap(2) loader-layout witness; native ARM oracle pending.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn case_libpython_private_fixed_file_segments() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let fixture = root.join("crates/carrick-conformance-next/tests/fixtures/libpython-map");
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/libpython-map/oracle.json")).unwrap();
    let source_hash =
        carrick_xtask::provision::compute_sha256(&fixture.join("src/main.rs")).unwrap();
    assert_eq!(oracle["source_sha256"].as_str(), Some(source_hash.as_str()));
    let probe = root.join("target/libpython-map/aarch64-unknown-linux-musl/release/libpython-map");
    let binary_hash = carrick_xtask::provision::compute_sha256(&probe)
        .expect("build libpython-map using the fixture README command");
    eprintln!(
        "LIBPYTHON_MAP source_sha256={source_hash} binary_sha256={binary_hash} oracle_status={}",
        oracle["status"]
    );
    let (result, _) = common::run_or_fail(
        TestContainer::new("python:3.12-slim")
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(probe.display().to_string(), "/tmp/libpython-map")
            .run_with_audit([
                "/bin/sh",
                "-c",
                "exec /tmp/libpython-map /usr/local/lib/libpython3.12.so.1.0",
            ]),
    );
    eprintln!("LIBPYTHON_MAP observed:\n{}", result.stdout_utf8());
    result.assert_success();
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(
        result.stdout_utf8(),
        format!(
            "source_sha256={source_hash}\n{}",
            oracle["stdout"].as_str().unwrap()
        )
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
    assert!(matches!(
        oracle["status"].as_str(),
        Some("pending-director-bless" | "blessed")
    ));
}
