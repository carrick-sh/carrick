use crate::syscall_x86_64::{SyscallRemap, X86_64_SYSCALLS};

#[test]
fn guest_lifecycle_numbers_match_the_canonical_table() {
    assert_eq!(crate::nr::WAIT4, crate::syscall::nr::WAIT4);
    assert_eq!(crate::nr::EXIT_GROUP, crate::syscall::nr::EXIT_GROUP);
    assert_eq!(
        crate::nr::CARRICK_PRIVATE_X86_FORK,
        crate::syscall::nr::CARRICK_PRIVATE_X86_FORK,
    );
}

/// The real cross-check the file's doc comment promises: for every
/// `Direct(c)` entry, prove there EXISTS an `AARCH64_SYSCALLS` entry at
/// number `c` whose name equals this x86 entry's name. This catches any
/// wrong canonical mapping (e.g. a typo'd number that lands on a different
/// canonical syscall) at test time — the const sortedness guard cannot do
/// this because it can't index `AARCH64_SYSCALLS` by name in const context.
#[test]
fn every_direct_canonical_matches_aarch64_by_name() {
    // `aarch64_table()` is the public accessor for `AARCH64_SYSCALLS`
    // (the static itself is module-private).
    let aarch64 = crate::syscall::aarch64_table();
    for e in X86_64_SYSCALLS {
        if let SyscallRemap::Direct(canonical) = e.remap {
            let found = aarch64
                .iter()
                .find(|a| a.number == canonical)
                .unwrap_or_else(|| {
                    panic!(
                        "x86_64 {}={} maps to canonical {} which is absent from AARCH64_SYSCALLS",
                        e.name, e.number, canonical
                    )
                });
            assert_eq!(
                found.name, e.name,
                "x86_64 {}={} → Direct({}) but AARCH64_SYSCALLS[{}] is named {:?}, not {:?}",
                e.name, e.number, canonical, canonical, found.name, e.name
            );
        }
    }
}
