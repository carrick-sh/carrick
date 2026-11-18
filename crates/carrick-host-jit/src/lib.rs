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
