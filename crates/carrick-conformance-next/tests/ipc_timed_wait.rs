//! Signed ARM binding for the SysV semaphore timeout clock and timer path.
#![allow(clippy::expect_used)]

use carrick_conformance_next::{PullPolicy, TestContainer};
use std::time::Duration;

#[test]
fn semtimedop_expires_on_arm() {
    let result = TestContainer::new(
        "localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30",
    )
    .pull_policy(PullPolicy::Missing)
    .carrier_budget(Duration::from_secs(10))
    .run([
        "/usr/local/bin/python3",
        "-c",
        include_str!("fixtures/ipc_timed_wait.py"),
    ])
    .expect("bounded signed SysV IPC timeout")
    .ensure_success()
    .expect("semtimedop must complete with EAGAIN");
    assert_eq!(result.stdout_utf8().trim(), "SEMTIMEDOP_EAGAIN_11");
}

#[test]
fn msgrcv_overflow_returns_efault_and_carrier_survives() {
    let result = TestContainer::new(
        "localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30",
    )
    .pull_policy(PullPolicy::Missing)
    .carrier_budget(Duration::from_secs(10))
    .run([
        "/usr/local/bin/python3",
        "-c",
        include_str!("fixtures/ipc_msgrcv_overflow.py"),
    ])
    .expect("bounded signed msgrcv overflow")
    .ensure_success()
    .expect("msgrcv must return EFAULT without aborting the carrier");
    assert_eq!(result.stdout_utf8().trim(), "MSGRCV_EFAULT_14");
}
