use crate::syscall_x86_64::{SyscallRemap, X86_64_SYSCALLS};

#[test]
fn guest_lifecycle_numbers_match_the_canonical_table() {
    assert_eq!(crate::nr::WAIT4, crate::syscall::nr::WAIT4);
    assert_eq!(crate::nr::EXIT_GROUP, crate::syscall::nr::EXIT_GROUP);
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
    // The ONE documented exception: x86_64 `poll`(7) is a Direct to the
    // DIFFERENTLY-named canonical `ppoll`(73). It is a deliberate bring-up
    // convenience for the musl startup fd-probe `poll(fds,n,0)` (also listed
    // in the deferred-shim block above as needing a real timeout→timespec
    // translation). Every OTHER Direct must name-match exactly.
    for e in X86_64_SYSCALLS {
        if let SyscallRemap::Direct(canonical) = e.remap {
            let found = aarch64
                .iter()
                .find(|a| a.number == canonical.raw())
                .unwrap_or_else(|| {
                    panic!(
                        "x86_64 {}={} maps to canonical {} which is absent from AARCH64_SYSCALLS",
                        e.name,
                        e.number,
                        canonical.raw()
                    )
                });
            if e.name == "poll" && found.name == "ppoll" {
                continue; // documented bring-up exception (see comment above)
            }
            assert_eq!(
                found.name,
                e.name,
                "x86_64 {}={} → Direct({}) but AARCH64_SYSCALLS[{}] is named {:?}, not {:?}",
                e.name,
                e.number,
                canonical.raw(),
                canonical.raw(),
                found.name,
                e.name
            );
        }
    }
}
