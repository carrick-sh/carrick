//! Immutable lower private views preserve source, fork, and page discard isolation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn case_private_file_exec_discard_preserves_header() {
    let _guard = common::guest_lock();
    let script = include_str!("workloads/private_file_exec_discard.py");
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
    assert_eq!(result.stdout_utf8(), "private_file_exec_discard=ok\n");
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
fn case_immutable_private_file_preserves_source_fork_and_discard() {
    let _guard = common::guest_lock();
    let script = include_str!("workloads/immutable_private_file.py");
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
    assert_eq!(result.stdout_utf8(), "immutable_private_file=ok\n");
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
fn case_private_file_discard_retains_source_across_fd_close_and_remap() {
    let _guard = common::guest_lock();
    let script = include_str!("workloads/private_file_discard_lifetime.py");
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
    assert_eq!(result.stdout_utf8(), "private_file_discard_lifetime=ok\n");
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
fn case_private_file_discard_shifted_restores_clean_visibility() {
    let _guard = common::guest_lock();
    let script = include_str!("workloads/private_file_discard_shifted.py");
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
    assert_eq!(result.stdout_utf8(), "private_file_discard_shifted=ok\n");
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
fn case_private_file_discard_shifted_named_restores_clean_visibility() {
    let _guard = common::guest_lock();
    let script = include_str!("workloads/private_file_discard_shifted.py");
    let container = TestContainer::new(
        "python@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a",
    )
    .pull_policy(PullPolicy::Missing);
    let (result, _) =
        common::run_or_fail(container.run_with_audit(["python3", "-c", script, "named"]));
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(result.stdout_utf8(), "private_file_discard_shifted=ok\n");
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}

#[test]
fn case_private_file_discard_shifted_private_destination() {
    let _guard = common::guest_lock();
    let script = include_str!("workloads/private_file_discard_shifted.py");
    let container = TestContainer::new(
        "python@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a",
    )
    .pull_policy(PullPolicy::Missing);
    let (result, _) = common::run_or_fail(container.run_with_audit([
        "python3",
        "-c",
        script,
        "named",
        "private-dest",
    ]));
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(result.stdout_utf8(), "private_file_discard_shifted=ok\n");
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}
