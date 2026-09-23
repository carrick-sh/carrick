//! Guest execution regression for the carrier's ordinary and raw destinations.
//! Native-code publication is tested separately; this runs the HVF engine.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use carrick_conformance_next::{PullPolicy, TestContainer};

#[test]
fn syscall_write_destinations_preserve_bytes_permissions_and_cow() {
    let _lock = common::guest_lock();
    let directory = tempfile::TempDir::new().unwrap();
    std::fs::write(
        directory.path().join("data"),
        b"0123456789abcdef".repeat(2048),
    )
    .unwrap();
    let script = include_str!("fixtures/syscall_write_destinations.py");
    let container = TestContainer::new("python:3.12-slim")
        .pull_policy(PullPolicy::Missing)
        .mount_readonly(directory.path().display().to_string(), "/input");
    let (result, _) =
        common::run_or_fail(container.run_with_audit(["python3", "-c", script, "/input/data"]));
    assert_eq!(
        result.exit_code,
        0,
        "stdout:\n{}\nstderr:\n{}",
        result.stdout_utf8(),
        result.stderr_utf8()
    );
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(
        result.stdout_utf8(),
        concat!(
            "readv_cross_page=ok\n",
            "preadv_offset=ok\n",
            "large_read=ok\n",
            "ordinary_copy_cross_page=ok\n",
            "readonly_efault=ok\n",
            "recvfrom_cross_page=ok\n",
            "fork_cow_isolation=ok\n",
        )
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}
