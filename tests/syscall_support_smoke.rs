//! Smoke test proving the shared syscall-support include idiom compiles and links.
//!
//! This file exists to validate `#[path = ...] mod support;` + `use support::*;`
//! against the extracted helpers/consts/imports before the bulk test move.

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

#[test]
fn support_module_imports_consts_and_helpers_are_usable() {
    // A const re-exported from the support module.
    assert_eq!(LINUX_F_GETFL, 3);

    // A pure helper re-exported from the support module.
    let perms = rw_perms();
    assert!(perms.read && perms.write && !perms.execute);

    // A dispatcher round-trip exercising a re-exported carrick type + helper
    // (write_u64 against memory whose backing covers the target address).
    let mut memory = LinearMemory::new(0x4000, b"hello from linux\n".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(outcome, DispatchOutcome::Returned { value: 17 });
}
