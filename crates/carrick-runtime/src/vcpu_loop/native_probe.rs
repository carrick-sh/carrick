//! Reviewed inline-assembly boundary for the native-execution memory tests.
//!
//! The activation tests need one bounded CPU access to the pinned carrier
//! bytes that is *not* a Rust load/store: the point of the contract is that
//! native code, not the Rust alias, touches the granted span. Keeping the
//! instruction sequence here, in one file that both assembly allowlists
//! name, means every test asserts the same operation and no test module
//! carries unreviewed `asm!`. This module publishes no code, performs no host
//! syscall and never re-enters the dispatcher; it is compiled for tests only.

/// Increment the little-endian `u32` at `ptr` with a native load/add/store.
///
/// # Safety
///
/// `ptr` must point to four writable bytes inside an activated carrier span
/// that no Rust reference aliases while this runs, and no other executor may
/// be dispatching on that span.
#[cfg(target_arch = "aarch64")]
pub(crate) unsafe fn increment_u32(ptr: *mut u8) {
    // SAFETY: the caller guarantees an exclusive, activated four-byte span.
    unsafe {
        std::arch::asm!(
            "ldr w9, [{ptr}]",
            "add w9, w9, #1",
            "str w9, [{ptr}]",
            ptr = in(reg) ptr,
            out("x9") _,
            options(nostack)
        );
    }
}
