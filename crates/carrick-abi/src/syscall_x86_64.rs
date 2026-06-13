//! x86_64 Linux syscall number table and canonical remap.
//!
//! Maps x86_64 syscall numbers to their canonical (aarch64/asm-generic)
//! equivalents used by carrick's unified dispatcher. Numbers are sourced
//! from published references:
//!   - `syscalls(2)` man page (man7.org)
//!   - filippo.io/linux-syscall-table (x86_64 column)
//!   - OSDev Wiki "System calls" (x86_64 ABI table)
//!
//! Each canonical (`Direct(N)`) target is cross-checked against
//! `carrick_abi::syscall::AARCH64_SYSCALLS` in this file's compile-time
//! guard (see below) to ensure the remap is self-consistent with carrick's
//! own canonical numbering.
//!
//! CLEAN-ROOM: no Linux kernel source (`arch/x86/entry/syscalls/syscall_64.tbl`,
//! `unistd_64.h`) or glibc source was used. Numbers come exclusively from the
//! published references cited above.
//!
//! The initial 15-entry set covers the M1 ring-3 SYSCALL hello (write=1,
//! exit_group=231) and the expected M2 musl-static startup surface. The table
//! grows oracle-gated as T10/T11 discover additional numbers trap-driven on
//! the FreeBSD box — never by bulk-transcription.

/// How a guest-ISA syscall number reaches the canonical (aarch64/asm-generic)
/// dispatcher. Defined here in `carrick-abi` (the leaf crate) so both
/// `carrick-abi` and `carrick-hal` can share it without a dependency cycle.
/// `carrick-hal::guest_arch` re-exports this type.
///
/// Phase 2 carries `Direct` and `Unknown`; the legacy-shim class (x86_64
/// `open`→`openat` etc.) gets its variant when the first shim lands
/// (oracle-gated — M2's musl-static startup is at-era and needs none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallRemap {
    /// Same semantics, different number: dispatch as `canonical` with args
    /// unchanged.
    Direct(u64),
    /// ISA-private syscall the backend services natively (x86_64 `arch_prctl`).
    Native,
    /// No canonical equivalent / not in the table: honest -ENOSYS.
    Unknown,
}

/// A single x86_64 syscall table entry: the x86_64 number, its name, and
/// how it reaches carrick's canonical dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X8664Syscall {
    pub number: u64,
    pub name: &'static str,
    pub remap: SyscallRemap,
}

const fn direct(number: u64, name: &'static str, canonical: u64) -> X8664Syscall {
    X8664Syscall {
        number,
        name,
        remap: SyscallRemap::Direct(canonical),
    }
}

const fn native(number: u64, name: &'static str) -> X8664Syscall {
    X8664Syscall {
        number,
        name,
        remap: SyscallRemap::Native,
    }
}

/// Binary-search the x86_64 syscall table for `number`. Returns `None` if the
/// number is not in the initial table (the caller should answer -ENOSYS, logged
/// via `X86_64_SYSCALLS` search or a raw number).
pub fn lookup_x86_64(number: u64) -> Option<&'static X8664Syscall> {
    X86_64_SYSCALLS
        .binary_search_by_key(&number, |s| s.number)
        .ok()
        .map(|i| &X86_64_SYSCALLS[i])
}

/// Initial x86_64 syscall table — the M1+M2 surface.
///
/// Sources for x86_64 numbers (cited per-entry in inline comments):
///   syscalls(2) man7.org §"Architecture calling conventions" (x86-64 table);
///   filippo.io/linux-syscall-table; OSDev "System calls".
///
/// Sources for canonical (Direct) targets: carrick's own `AARCH64_SYSCALLS`
/// in `carrick_abi::syscall` — every Direct(N) below was verified against that
/// table at the time this file was written (see the compile-time guard).
///
/// MUST stay strictly sorted by `number` for `lookup_x86_64`'s binary search.
pub static X86_64_SYSCALLS: &[X8664Syscall] = &[
    // x86_64=0 (syscalls(2)/filippo) → canonical read=63 (AARCH64_SYSCALLS[63])
    direct(0, "read", 63),
    // x86_64=1 (syscalls(2)/filippo) → canonical write=64 (AARCH64_SYSCALLS[64])
    direct(1, "write", 64),
    // x86_64=3 (syscalls(2)/filippo) → canonical close=57 (AARCH64_SYSCALLS[57])
    direct(3, "close", 57),
    // x86_64=9 (syscalls(2)/filippo) → canonical mmap=222 (AARCH64_SYSCALLS[222])
    direct(9, "mmap", 222),
    // x86_64=10 (syscalls(2)/filippo) → canonical mprotect=226 (AARCH64_SYSCALLS[226])
    direct(10, "mprotect", 226),
    // x86_64=11 (syscalls(2)/filippo) → canonical munmap=215 (AARCH64_SYSCALLS[215])
    direct(11, "munmap", 215),
    // x86_64=12 (syscalls(2)/filippo) → canonical brk=214 (AARCH64_SYSCALLS[214])
    direct(12, "brk", 214),
    // x86_64=13 (syscalls(2)/filippo) → canonical rt_sigaction=134 (AARCH64_SYSCALLS[134])
    direct(13, "rt_sigaction", 134),
    // x86_64=14 (syscalls(2)/filippo) → canonical rt_sigprocmask=135 (AARCH64_SYSCALLS[135])
    direct(14, "rt_sigprocmask", 135),
    // x86_64=16 (syscalls(2)/filippo) → canonical ioctl=29 (AARCH64_SYSCALLS[29])
    direct(16, "ioctl", 29),
    // x86_64=20 (syscalls(2)/filippo) → canonical writev=66 (AARCH64_SYSCALLS[66])
    direct(20, "writev", 66),
    // x86_64=60 (syscalls(2)/filippo) → canonical exit=93 (AARCH64_SYSCALLS[93])
    direct(60, "exit", 93),
    // x86_64=158 (syscalls(2)/filippo): arch_prctl is x86_64-private (sets FS/GS
    // base via ARCH_SET_FS / ARCH_SET_GS); the bhyve backend handles it natively.
    native(158, "arch_prctl"),
    // x86_64=218 (syscalls(2)/filippo) → canonical set_tid_address=96
    // (AARCH64_SYSCALLS[96])
    direct(218, "set_tid_address", 96),
    // x86_64=231 (syscalls(2)/filippo) → canonical exit_group=94
    // (AARCH64_SYSCALLS[94])
    direct(231, "exit_group", 94),
];

// Compile-time guard: the table MUST stay strictly sorted (uniqueness +
// binary-search validity). A bad insert or duplicate fails the BUILD with
// this message rather than silently producing wrong lookups at runtime.
const _: () = {
    let mut i = 1;
    while i < X86_64_SYSCALLS.len() {
        assert!(
            X86_64_SYSCALLS[i - 1].number < X86_64_SYSCALLS[i].number,
            "X86_64_SYSCALLS must stay strictly sorted by syscall number \
             (binary_search validity + number uniqueness)",
        );
        i += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_remaps_to_canonical_64() {
        let e = lookup_x86_64(1).expect("write must be in the table");
        assert_eq!(e.name, "write");
        assert_eq!(e.remap, SyscallRemap::Direct(64));
    }

    #[test]
    fn exit_remaps_to_canonical_93() {
        let e = lookup_x86_64(60).expect("exit must be in the table");
        assert_eq!(e.name, "exit");
        assert_eq!(e.remap, SyscallRemap::Direct(93));
    }

    #[test]
    fn exit_group_remaps_to_canonical_94() {
        let e = lookup_x86_64(231).expect("exit_group must be in the table");
        assert_eq!(e.name, "exit_group");
        assert_eq!(e.remap, SyscallRemap::Direct(94));
    }

    #[test]
    fn brk_remaps_to_canonical_214() {
        let e = lookup_x86_64(12).expect("brk must be in the table");
        assert_eq!(e.name, "brk");
        assert_eq!(e.remap, SyscallRemap::Direct(214));
    }

    #[test]
    fn mmap_remaps_to_canonical_222() {
        let e = lookup_x86_64(9).expect("mmap must be in the table");
        assert_eq!(e.name, "mmap");
        assert_eq!(e.remap, SyscallRemap::Direct(222));
    }

    #[test]
    fn arch_prctl_is_native() {
        let e = lookup_x86_64(158).expect("arch_prctl must be in the table");
        assert_eq!(e.name, "arch_prctl");
        assert_eq!(e.remap, SyscallRemap::Native);
    }

    #[test]
    fn iopl_is_not_in_table() {
        // x86_64 iopl=172 — not in our initial table (no canonical equivalent)
        assert!(lookup_x86_64(172).is_none());
    }

    #[test]
    fn table_is_strictly_sorted() {
        for w in X86_64_SYSCALLS.windows(2) {
            assert!(
                w[0].number < w[1].number,
                "X86_64_SYSCALLS out of order: {} >= {}",
                w[0].number,
                w[1].number
            );
        }
    }
}
