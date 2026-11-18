//! `carrick-host-jit` — host executable memory for the soft CPUs' translated
//! blocks, shared by every ISA (moved whole from `carrick-softcpu-x86`,
//! #1236). Code is written while the mapping is RW and published RX; the
//! mapping is never writable and executable at once.

mod publish;

use publish::publish_instructions;
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
