//! In-process conformance probe for rt_sigprocmask aliasing and validation.
//!
//! Regression test for:
//! 1. Normal non-aliased rt_sigprocmask call.
//! 2. Invalid `how` with valid oldset buffer: Linux validates `how` before
//!    writing `oldset`, leaving the oldset buffer untouched.
//! 3. Aliased `set` and `oldset` buffers: Linux reads `new_set` before writing `oldset`,
//!    so the new mask reflects caller's input rather than the overwritten old mask.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn case_rt_sigprocmask_alias_and_validation() {
    let _guard = common::guest_lock();
    let script = include_str!("fixtures/sigmask_alias.py");
    let container = TestContainer::new("python:3.12-slim").pull_policy(PullPolicy::Missing);
    let (result, _) = common::run_or_fail(container.run_with_audit(["python3", "-c", script]));
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(
        result.stdout_utf8(),
        concat!(
            "normal_res=0\n",
            "normal_errno=0\n",
            "normal_oldset=0x10\n",
            "normal_mask=0x30\n",
            "invalid_how_res=-1\n",
            "invalid_how_errno=22\n",
            "invalid_how_oldset=0x12345678deadbeef\n",
            "invalid_how_mask=0x30\n",
            "aliased_res=0\n",
            "aliased_errno=0\n",
            "aliased_oldset=0x10\n",
            "aliased_mask=0x30\n",
        )
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}
