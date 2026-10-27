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
//! only (`just test-embed el1_stack_overflow`).
mod common;

#[test]
fn el1_stack_overflow_faults_on_its_guard_with_a_typed_report() {
    let _guard = common::guest_lock();
    common::expect_el1_stack_overflow(common::run_stack_guard_fixture("stack-guard"));
}
