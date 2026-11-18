//! The instruction publication leaf: the only inline assembly in this
//! crate. It runs on the host CPU against this crate's own mapping and makes
//! no system call.

/// Read this host's CTR_EL0 (Arm ARM D13.2.34) to visit each cache line in
/// the publication range and select the maintenance required by this CPU.
#[cfg(target_arch = "aarch64")]
pub fn cache_type() -> u64 {
    let ctr: u64;
    // SAFETY: CTR_EL0 is readable at EL0 on Linux and macOS (the kernel sets
    // SCTLR_EL1.UCT or emulates the trap); the read touches no memory.
    unsafe {
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
    ctr
}

/// Make `len` bytes just stored at `start` visible to this host's instruction
/// fetch. x86_64 keeps instruction fetch coherent with the storing core's
/// writes (the mprotect system call that follows serializes it), so there is
/// nothing to do.
#[cfg(target_arch = "x86_64")]
pub(crate) fn publish_instructions(_start: *const u8, _len: usize) -> bool {
    true
}

/// Arm ARM DDI0487 B2.4.4 (concurrent modification and execution of
/// instructions): clean each written data-cache line to the point of
/// unification (`DC CVAU`), `DSB ISH`, invalidate each instruction-cache
/// line to the point of unification (`IC IVAU`), `DSB ISH`, then `ISB`.
/// Line sizes come from CTR_EL0 (DminLine 19:16 and IminLine 3:0, log2 of
/// the line in words); IDC (bit 28) and DIC (bit 29) say the clean or the
/// invalidation is not needed for coherence on this host.
#[cfg(target_arch = "aarch64")]
pub(crate) fn publish_instructions(start: *const u8, len: usize) -> bool {
    let ctr = cache_type();
    let begin = start as usize;
    let end = begin.saturating_add(len);
    if ctr & (1 << 28) == 0 {
        let line = 4usize << ((ctr >> 16) & 0xf);
        let mut address = begin & !(line - 1);
        while address < end {
            // SAFETY: `address` lies in a line of this owner's live mapping,
            // which is readable; DC CVAU only cleans the line.
            unsafe {
                core::arch::asm!("dc cvau, {}", in(reg) address, options(nostack, preserves_flags));
            }
            address += line;
        }
    }
    // SAFETY: a barrier with no operands; it orders the cleans before what follows.
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
    if ctr & (1 << 29) == 0 {
        let line = 4usize << (ctr & 0xf);
        let mut address = begin & !(line - 1);
        while address < end {
            // SAFETY: as for DC CVAU; IC IVAU only invalidates the line.
            unsafe {
                core::arch::asm!("ic ivau, {}", in(reg) address, options(nostack, preserves_flags));
            }
            address += line;
        }
        // SAFETY: a barrier with no operands; it completes the invalidations.
        unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
    }
    // SAFETY: a context synchronization event with no operands.
    unsafe { core::arch::asm!("isb", options(nostack, preserves_flags)) };
    true
}

/// No other host has an instruction publication sequence here yet: refuse
/// rather than return code that may run stale bytes.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn publish_instructions(_start: *const u8, _len: usize) -> bool {
    false
}
