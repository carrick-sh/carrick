//! Neighboring private-file stores retain fresh bytes and fork isolation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn case_private_file_cow_lanes_preserve_file_visibility_and_fork_isolation() {
    let _guard = common::guest_lock();
    let script = include_str!("workloads/private_file_cow_lanes.py");
    let container = TestContainer::new(
        "python@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a",
    )
    .pull_policy(PullPolicy::Missing);
    let (result, _) = common::run_or_fail(container.run_with_audit(["python3", "-c", script]));
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(result.stdout_utf8(), "private_file_cow_lanes=ok\n");
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}
