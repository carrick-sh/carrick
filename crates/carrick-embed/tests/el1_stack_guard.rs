//! Signed witness for the EL1 ring-stack guards (#369).
//!
//! The test-control EL1 image (`allocator-test-control`, enabled for these
//! tests only) serves `SYS_CARRICK_EL1_CONTROL` op 2 by recursing with a
//! 1 KiB live record per level, far past the 16 KiB EL1 stack. With the
//! guard in place the first store below the stack faults on the unmapped
//! guard; the current-EL vector reports it through `hvc #3` without storing
//! into the guard, and the host fails the run with the typed
//! `TrapError::El1StackOverflow` naming the CPU and its stack slot. Without
//! the guard the same overflow silently overwrites the memory below the
//! stack (another CPU's stack, or the counters area for slot 0; #338): the
//! fixture returns and reports that nothing stopped it.
//!
//! Its own test binary: the run ends with a failed carrier. Signed lane
//! only (`just test-embed el1_stack_guard`).
mod common;

use std::time::Duration;

use carrick_embed::{EmbedError, PullPolicy};
use carrick_hal::TrapError;
use common::{EL1_SCHED_FIXTURE as FIXTURE, carrier_or_fail, el1_sched_vfs};

#[test]
fn el1_stack_overflow_faults_on_its_guard_with_a_typed_report() {
    let _guard = common::guest_lock();
    let carrier = carrier_or_fail();
    let watchdog = common::Watchdog::start(Duration::from_secs(120));
    let outcome = carrier
        .container(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .command(vec![FIXTURE.to_owned(), "stack-guard".to_owned()])
        .vfs_mount("/opt/carrick", Box::new(el1_sched_vfs()))
        .run_blocking();
    drop(watchdog);
    let error = match outcome {
        Ok(result) => panic!(
            "an EL1 stack overflow must fail the run with a typed report; the guest \
             finished instead: exit={} signal={:?} stdout={:?} stderr={:?}",
            result.exit_code,
            result.signal,
            result.stdout_utf8(),
            result.stderr_utf8()
        ),
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): run through scripts/test-signed.sh; \
             a bare cargo test cannot boot a guest"
        ),
        Err(error) => error,
    };
    // The typed report, wherever the carrier wrapped it.
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut report = None;
    while let Some(current) = source {
        if let Some(TrapError::El1StackOverflow(overflow)) = current.downcast_ref::<TrapError>() {
            report = Some(*overflow);
            break;
        }
        source = current.source();
    }
    let Some(report) = report else {
        panic!("expected TrapError::El1StackOverflow in the error chain, got: {error:#?}");
    };
    assert_eq!(
        report.kind,
        carrick_el1_abi::El1StackOverflowKind::GuardFault,
        "{report}"
    );
    // The overflow ran off the executing CPU's own stack into its own guard.
    let cpu = report.executing.expect("the leased CPU is named");
    assert_eq!(cpu.raw(), u32::from(report.stack.raw()), "{report}");
    assert!(
        carrick_el1_abi::is_el1_stack_guard(report.far_el1.raw()),
        "{report}"
    );
}
