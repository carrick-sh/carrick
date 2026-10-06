//! Native checked user access pending the CPL0 fixup binding.

/// The ARM fixup-guarded user-word reader has no x86 binding yet.
#[cold]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_unbound_user_word() -> ! {
    // SAFETY: returning a fabricated user value would breach the copy gate.
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
