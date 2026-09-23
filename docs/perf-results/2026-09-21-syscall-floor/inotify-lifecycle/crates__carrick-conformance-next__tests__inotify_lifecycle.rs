//! Unread notification identity must survive repeated watch removal.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn case_inotify_watch_churn() {
    let _guard = common::guest_lock();
    let script = include_str!("fixtures/inotify_lifecycle.py");
    let container = TestContainer::new("localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30")
        .pull_policy(PullPolicy::Missing);
    let (result, _) =
        common::run_or_fail(container.run_with_audit(["/usr/local/bin/python3", "-c", script]));
    result.assert_success();
    result.assert_exit_code(0);
    assert_eq!(result.signal, None);
    assert!(!result.trap_limit_hit);
    assert_eq!(result.terminal_reason, None);
    assert_eq!(
        result.stdout_utf8(),
        "churn_scale_1=ok\nchurn_scale_8=ok\nchurn_scale_32=ok\nchurn_scale_128=ok\noverflow_drain_rearm=ok\nprobe_complete=1\n"
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());
}
