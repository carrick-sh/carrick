//! Native guest instruction leaves selected by the image architecture.

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod x86 {
    /// No x86 slot binding has been published for the ARM stack-slot caller.
    #[cold]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub extern "C" fn carrick_x86_unbound_stack_slot() -> ! {
        // SAFETY: an unsupported guest-kernel path must fault at CPL0 rather
        // than returning an unauthenticated stack slot.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }

    /// The ARM ThreadCpu record must never be interpreted as x86 context.
    #[cold]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub extern "C" fn carrick_x86_unbound_thread_cpu() -> ! {
        // SAFETY: the invalid context path must stop before state publication.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }

    /// The ARM fixup-guarded user-word reader has no x86 binding yet.
    #[cold]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub extern "C" fn carrick_x86_unbound_user_word() -> ! {
        // SAFETY: returning a fabricated user value would breach the copy gate.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }

    /// The ARM HVC fatal transport has no CPL0 equivalent in this module.
    #[cold]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub extern "C" fn carrick_x86_unbound_entry_fatal() -> ! {
        // SAFETY: faulting in CPL0 is terminal for this unsupported path.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }

    /// No owner-authenticated x86 user translation has been bound here yet.
    #[cold]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub extern "C" fn carrick_x86_unbound_user_access() -> ! {
        // SAFETY: fail closed before reading or writing an unchecked user VA.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }

    /// ARM TTBR/TLBI records cannot describe an x86 CR3/PML4 owner.
    #[cold]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub extern "C" fn carrick_x86_unbound_mmu_owner() -> u64 {
        // SAFETY: fail closed before publishing a translation or drain receipt.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }

    /// HVC service suspension has no CPL0 transport in this kernel path yet.
    #[cold]
    #[inline(never)]
    #[unsafe(no_mangle)]
    pub extern "C" fn carrick_x86_unbound_host_yield() -> ! {
        // SAFETY: fail closed before pretending a host effect completed.
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }
}
