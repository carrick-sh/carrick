//! Regression for SIGKILL arriving while a compute child's vCPU lease migrates.
//! The same Python fixture hangs on the pre-fix signed CLI baseline. The HAL
//! unit test forces the lease-gap ordering deterministically.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_conformance_next::{PullPolicy, TestContainer};
use std::time::Duration;

#[test]
fn subprocess_kill_compute_child_survives_lease_migration() {
    let result = TestContainer::new(
        "localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30",
    )
    .pull_policy(PullPolicy::Missing)
    .carrier_budget(Duration::from_secs(20))
    .run([
        "/usr/local/bin/python3",
        "-c",
        include_str!("fixtures/subprocess_kill_compute.py"),
    ])
    .expect("bounded signed compute-child kill test")
    .ensure_success()
    .expect("every child must terminate after SIGKILL");
    let output = result.stdout_utf8();
    assert_eq!(
        output
            .lines()
            .filter(|line| line.starts_with("iteration "))
            .count(),
        50
    );
    assert_eq!(output.lines().last(), Some("KILL_WAIT_OK"));
}
