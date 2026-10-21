//! In-process conformance probe for sched_setaffinity and sched_getaffinity
//! mask reflection across main thread and a spawned thread.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};

#[test]
fn case_sched_affinity_threads_mask_reflection() {
    let _guard = common::guest_lock();
    let script = include_str!("fixtures/sched_affinity_threads.py");
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
            "main_setaffinity_res=0\n",
            "main_setaffinity_errno=0\n",
            "main_getaffinity_size_rule=true\n",
            "main_getaffinity_errno=0\n",
            "main_mask_reflected=true\n",
            "thread_setaffinity_res=0\n",
            "thread_setaffinity_errno=0\n",
            "thread_getaffinity_size_rule=true\n",
            "thread_getaffinity_errno=0\n",
            "thread_mask_reflected=true\n",
            "threads_independent=true\n",
            "clone_mask_inherited=true\n",
        )
    );
    let diagnostics = result.stderr_utf8();
    let raw: Vec<_> = diagnostics.lines().collect();
    assert_eq!(raw.len(), 2, "{diagnostics}");
    for (line, prefix) in raw
        .iter()
        .zip(["main_getaffinity_raw=", "thread_getaffinity_raw="])
    {
        let bytes: usize = line.strip_prefix(prefix).unwrap().parse().unwrap();
        assert!(
            bytes > 0 && bytes <= 128 && bytes.is_multiple_of(8),
            "{line}"
        );
    }
}
