//! Signed witness (#369): a user pointer into an EL1 stack guard is EFAULT
//! from the guarded user copy (Carrick's access_ok), as Linux returns for a
//! kernel address, never a guard fault that kills the carrier.
//!
//! Its own test binary: without the access_ok check the run ends with a
//! failed carrier.
mod common;

#[test]
fn el1_user_pointer_into_a_stack_guard_is_efault() {
    let _guard = common::guest_lock();
    let result = match common::run_stack_guard_fixture("guard-user-pointer") {
        Ok(result) => result,
        Err(error) => panic!("a user pointer into a guard must not fail the run: {error:#?}"),
    };
    assert_eq!(
        result.exit_code,
        0,
        "stdout={:?} stderr={:?}",
        result.stdout_utf8(),
        result.stderr_utf8()
    );
    assert!(
        result.stdout_utf8().contains("guard-user-pointer refused"),
        "{:?}",
        result.stdout_utf8()
    );
}
