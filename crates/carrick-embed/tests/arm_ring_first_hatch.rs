//! Signed ARM ring-first flip allowlist and hatch witness verification.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::atomic::Ordering;

use carrick_embed::{read_el1_counters, reset_el1_counters};

#[test]
fn arm_ring_first_strict_refusal_witness() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    // Default: CARRICK_ARM_RING_FIRST is unset (strict mode on).
    unsafe {
        std::env::remove_var("CARRICK_ARM_RING_FIRST");
    }

    let result = common::run_or_fail(common::interceptor_probe_builder("identity").run_blocking());

    assert!(result.success(), "exit_code={}", result.exit_code);
    let stdout = result.stdout_utf8();
    // Non-allowlisted getuid (174) must answer -ENOSYS (errno 38)
    assert!(
        stdout.contains("uid=-1 uid_errno=38"),
        "expected non-allowlisted getuid to fail with ENOSYS (38), got stdout:\n{stdout}"
    );
    // Wire-in-ring getpid (172) succeeds
    assert!(
        stdout.contains("pid_errno=0"),
        "expected wire-in-ring getpid to succeed, got stdout:\n{stdout}"
    );
    // Forward-allowlisted clock_gettime (113) succeeds
    assert!(
        stdout.contains("clock_rc=0 clock_errno=0"),
        "expected allowlisted clock_gettime to succeed, got stdout:\n{stdout}"
    );

    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let refused_getuid = counters.refused[174].load(Ordering::Relaxed);
    assert!(
        refused_getuid >= 1,
        "expected counters.refused[174] >= 1 under strict ring-first mode, got {refused_getuid}"
    );
}

#[test]
fn arm_ring_first_hatch_disabled_forward_witness() {
    let _guard = common::guest_lock();
    reset_el1_counters();

    // CARRICK_ARM_RING_FIRST=0 restores pre-flip forwarding.
    unsafe {
        std::env::set_var("CARRICK_ARM_RING_FIRST", "0");
    }

    let result = common::run_or_fail(common::interceptor_probe_builder("identity").run_blocking());

    // Clean up environment variable
    unsafe {
        std::env::remove_var("CARRICK_ARM_RING_FIRST");
    }

    assert!(result.success(), "exit_code={}", result.exit_code);
    let stdout = result.stdout_utf8();
    // With hatch = 0, getuid is forwarded to host and succeeds with uid >= 0, errno 0
    assert!(
        stdout.contains("uid_errno=0") && !stdout.contains("uid_errno=38"),
        "expected forwarded getuid to succeed with errno 0, got stdout:\n{stdout}"
    );

    let counters = read_el1_counters().expect("EL1 counters should be populated");
    let refused_getuid = counters.refused[174].load(Ordering::Relaxed);
    assert_eq!(
        refused_getuid, 0,
        "expected counters.refused[174] == 0 when hatch is disabled, got {refused_getuid}"
    );
    let forwarded_getuid = counters.forwarded[174].load(Ordering::Relaxed);
    assert!(
        forwarded_getuid >= 1,
        "expected counters.forwarded[174] >= 1 when hatch is disabled, got {forwarded_getuid}"
    );
}
