//! `carrick-host-jit` — host executable memory for the soft CPUs' translated
//! blocks, shared by every ISA (moved whole from `carrick-softcpu-x86`,
//! #1236). Code is written while the mapping is RW and published RX; the
//! mapping is never writable and executable at once.

use std::ptr::NonNull;

#[doc(hidden)]
#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    pub static JIT_ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub static FAIL_SMALL_JIT: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

#[cfg(any(test, feature = "test-hooks"))]
fn inject_small_jit_failure(capacity: usize, publish: bool) -> bool {
    capacity == 4096
        && FAIL_SMALL_JIT.with(|fault| {
            if fault.get() == Some(publish) {
                fault.set(None);
                true
            } else {
                false
            }
        })
}

/// Host executable scratch buffer for translated blocks (never maps guest VAs).
pub struct JitCodeBuffer {
    ptr: NonNull<u8>,
    capacity: usize,
    cursor: usize,
    executable: bool,
}

// SAFETY: `JitCodeBuffer` owns a private `mmap` allocation not shared across threads without sync.
unsafe impl Send for JitCodeBuffer {}

impl JitCodeBuffer {
    /// Allocate a host executable scratch buffer of `capacity` bytes.
    pub fn new(capacity: usize) -> Option<Self> {
        let cap = capacity.max(4096).checked_add(4095)? & !4095;
        #[cfg(any(test, feature = "test-hooks"))]
        {
            JIT_ALLOCATIONS.with(|count| count.set(count.get() + 1));
            if inject_small_jit_failure(cap, false) {
                return None;
            }
        }
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANON;
        // SAFETY: anonymous private host allocation for translated block bytes only.
        let raw = unsafe { libc::mmap(std::ptr::null_mut(), cap, prot, flags, -1, 0) };
        if raw == libc::MAP_FAILED {
            return None;
        }
        Some(Self {
            ptr: NonNull::new(raw.cast::<u8>())?,
            capacity: cap,
            cursor: 0,
            executable: false,
        })
    }

    /// Publish under W^X, returning an RX address only after mprotect succeeds.
    /// The owner must ensure no previously published code is executing while
    /// this exclusive publication changes the mapping back to RW.
    pub fn publish(&mut self, bytes: &[u8]) -> Option<u64> {
        #[cfg(any(test, feature = "test-hooks"))]
        if inject_small_jit_failure(self.capacity, true) {
            return None;
        }
        if bytes.is_empty() || bytes.len() > self.capacity {
            return None;
        }
        if self.executable {
            // SAFETY: the exclusive owner holds the entire live mmap allocation.
            if unsafe {
                libc::mprotect(
                    self.ptr.as_ptr().cast(),
                    self.capacity,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
            {
                return None;
            }
            self.executable = false;
        }
        if self.cursor.checked_add(bytes.len())? > self.capacity {
            self.cursor = 0;
        }
        // SAFETY: `self.cursor + bytes.len() <= self.capacity`.
        let dst = unsafe { self.ptr.as_ptr().add(self.cursor) };
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
        if !publish_instructions(dst, bytes.len()) {
            return None;
        }
        self.cursor += (bytes.len() + 15) & !15;
        // SAFETY: publication is complete and no mutable pointer escapes this owner.
        if unsafe {
            libc::mprotect(
                self.ptr.as_ptr().cast(),
                self.capacity,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        } != 0
        {
            return None;
        }
        self.executable = true;
        Some(dst as u64)
    }
}

impl Drop for JitCodeBuffer {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` and `self.capacity` came from `libc::mmap` in `Self::new`.
        unsafe {
            let _ = libc::munmap(self.ptr.as_ptr().cast(), self.capacity);
        }
    }
}

/// Make `len` bytes just stored at `start` visible to this host's instruction
/// fetch. x86_64 keeps instruction fetch coherent with the storing core's
/// writes (the mprotect system call that follows serializes it), so there is
/// nothing to do.
#[cfg(target_arch = "x86_64")]
fn publish_instructions(_start: *const u8, _len: usize) -> bool {
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
fn publish_instructions(start: *const u8, len: usize) -> bool {
    let ctr: u64;
    // SAFETY: CTR_EL0 is readable at EL0 on Linux and macOS (the kernel sets
    // SCTLR_EL1.UCT or emulates the trap); the read touches no memory.
    unsafe {
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags));
    }
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
fn publish_instructions(_start: *const u8, _len: usize) -> bool {
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn publish_copies_at_aligned_cursor_and_refuses_bad_sizes() {
        let mut jit = JitCodeBuffer::new(4096).unwrap();
        let first = jit.publish(&[1, 2, 3]).unwrap();
        let second = jit.publish(&[4, 5]).unwrap();
        assert_eq!(second - first, 16);
        // SAFETY: both ranges were just published into the live RX mapping,
        // which stays readable.
        let read =
            |at: u64, n: usize| unsafe { std::slice::from_raw_parts(at as *const u8, n) }.to_vec();
        assert_eq!(read(first, 3), [1, 2, 3]);
        assert_eq!(read(second, 2), [4, 5]);
        assert_eq!(jit.publish(&[]), None);
        assert_eq!(jit.publish(&[0; 4097]), None);
        // A full-capacity image wraps the cursor to the start of the mapping.
        let whole = jit.publish(&[7; 4096]).unwrap();
        assert_eq!(jit.publish(&[9; 4096]).unwrap(), whole);
        assert_eq!(read(whole, 4096), [9; 4096]);
    }

    /// The aarch64 publication witness: run a published function, rewrite it
    /// in place with a different constant and run it again. Executes only on
    /// an arm64 host (the hosted ubuntu-24.04-arm job).
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn republished_code_at_the_same_address_runs_the_new_bytes() {
        /// MOVZ W0, #imm16 (C6.2.193, sf=0, hw=0); RET (C6.2.219).
        fn returning(value: u16) -> Vec<u8> {
            let mut image = vec![0u8; 4096];
            image[..4].copy_from_slice(&(0x5280_0000u32 | (u32::from(value) << 5)).to_le_bytes());
            image[4..8].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
            image
        }
        let mut jit = JitCodeBuffer::new(4096).unwrap();
        let call = |entry: u64| {
            // SAFETY: `entry` is a just-published RX AAPCS64 function taking
            // no arguments and returning w0; the buffer outlives the call.
            let f = unsafe { std::mem::transmute::<usize, extern "C" fn() -> u32>(entry as usize) };
            f()
        };
        let first = jit.publish(&returning(0x1234)).unwrap();
        assert_eq!(call(first), 0x1234);
        let second = jit.publish(&returning(0xbeef)).unwrap();
        assert_eq!(
            second, first,
            "the full-capacity image must reuse the address"
        );
        assert_eq!(call(second), 0xbeef);
    }
}
