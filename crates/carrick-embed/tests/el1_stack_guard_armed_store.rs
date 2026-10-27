//! Signed witness (#369): a kernel store into this CPU's own stack guard
//! while a user-copy fixup is armed, with SP still on the stack, fails loud
//! as a typed stack overflow. The vector's SP test cannot see this shape (a
//! downward overrun, not a frame allocation); its FAR test must refuse the
//! fixup. Taking the fixup would land in the witness's `hvc #3` stub, a
//! generic EL1 fault rather than this report.
//!
//! Its own test binary: the run ends with a failed carrier.
mod common;

#[test]
fn el1_stack_overflow_store_under_an_armed_fixup_fails_loud() {
    let _guard = common::guest_lock();
    common::expect_el1_stack_overflow(common::run_stack_guard_fixture("stack-guard-armed-store"));
}
