//! Signed witness (#369): an EL1 stack overflow taken while a user-copy
//! fixup is armed still fails loud as a typed stack overflow. A frame
//! allocation moves SP into the guard first, so the vector's SP test stops
//! it before any fixup lookup; `el1_stack_guard_armed_store` covers the FAR
//! test. The guarded
//! copies refuse kernel-window user pointers before arming a fixup
//! (`user_range_overlaps_el1_kernel`), so a guard fault under an armed fixup
//! can only be the kernel's own overflow; taking the fixup would resume on
//! an overflowed stack. If the vector took it, EL1 would land in the
//! witness's `hvc #3` stub instead: a generic EL1 fault, not this report.
//!
//! Its own test binary: the run ends with a failed carrier.
mod common;

#[test]
fn el1_stack_overflow_with_an_armed_fixup_still_fails_loud() {
    let _guard = common::guest_lock();
    common::expect_el1_stack_overflow(common::run_stack_guard_fixture("stack-guard-armed"));
}
