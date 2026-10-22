//! Reports the syscall/errno for Python's lower-directory listing shape.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;
use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn case_libpython_directory_copyout() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let fixture = root.join("crates/carrick-conformance-next/tests/fixtures/directory-copyout");
    let hash = carrick_xtask::provision::compute_sha256(&fixture.join("src/main.rs")).unwrap();
    let probe =
        root.join("target/directory-copyout/aarch64-unknown-linux-musl/release/directory-copyout");
    let binary = carrick_xtask::provision::compute_sha256(&probe)
        .expect("signed runner builds directory-copyout");
    eprintln!("DIRECTORY_COPYOUT source_sha256={hash} binary_sha256={binary}");
    let (result, _) = common::run_or_fail(
        TestContainer::new("python:3.12-slim")
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(probe.display().to_string(), "/tmp/directory-copyout")
            .run_with_audit([
                "/bin/sh",
                "-c",
                "exec /tmp/directory-copyout /usr/local/lib/python3.12",
            ]),
    );
    eprintln!("DIRECTORY_COPYOUT observed:\n{}", result.stdout_utf8());
    assert!(
        result
            .stdout_utf8()
            .starts_with(&format!("source_sha256={hash}\n"))
    );
    result.assert_success();
    assert!(!result.trap_limit_hit);
    assert_eq!(result.signal, None);
    assert_eq!(result.terminal_reason, None);
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
    // Acceptance requires the director's exact native ARM64 Docker output.
    // This diagnostic case deliberately remains red until that is supplied.
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/directory-copyout/oracle.json")).unwrap();
    assert_eq!(oracle["source_sha256"].as_str(), Some(hash.as_str()));
    assert_eq!(oracle["status"].as_str(), Some("blessed"));
    assert_eq!(result.stdout_utf8(), oracle["stdout"].as_str().unwrap());
}
