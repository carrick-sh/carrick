//! Cross-process futex via the public macOS `os_sync_wait_on_address` API.
//!
//! macOS has no `futex(2)`. For a guest FUTEX on private/anon memory carrick
//! parks in-process (the parking-lot `FutexTable`), which is enough for a
//! single multi-threaded guest (e.g. Go's runtime). But a FUTEX on a genuine
//! `MAP_SHARED` file mapping is an inter-PROCESS rendezvous — LTP's
//! `tst_checkpoint` (used pervasively for parent↔child sync) does
//! `FUTEX_WAIT`/`FUTEX_WAKE` on a futex word in a shared tmpfs page. carrick
//! forks each guest process as a real macOS process, and a guest `MAP_SHARED`
//! file mapping is backed by a host `MAP_SHARED` of the real file, so the same
//! PHYSICAL page is visible across processes.
//!
//! `os_sync_wait_on_address` with `OS_SYNC_WAIT_ON_ADDRESS_SHARED` (and the
//! matching `OS_SYNC_WAKE_BY_ADDRESS_SHARED` on wake) keys on the physical page
//! rather than the per-task virtual address, so a wait in one process and a
//! wake in another rendezvous correctly — the stable, public (macOS 14.4+,
//! `<os/os_sync_wait_on_address.h>`) equivalent of the private
//! `UL_COMPARE_AND_WAIT_SHARED` `__ulock` op carrick used previously.
//!
//! Wrappers are thin and map to a `-errno`-on-error contract: `wait` returns
//! `>= 0` when woken or the value already differed (the caller re-checks the
//! word), or `-errno` (`-ETIMEDOUT`, `-EINTR`, …). `wake` returns `>= 0` on
//! success or `-errno` (e.g. `-ENOENT` when there was no waiter).

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use std::ffi::c_void;

    /// Cross-process, physical-page-keyed synchronization (the SHARED flag).
    /// Value confirmed from `<os/os_sync_wait_on_address.h>`.
    const OS_SYNC_WAIT_ON_ADDRESS_SHARED: u32 = 0x0000_0001;
    const OS_SYNC_WAKE_BY_ADDRESS_SHARED: u32 = 0x0000_0001;
    /// `os_clockid_t` for the deadline clock (`<os/clock.h>`,
    /// `OS_CLOCK_MACH_ABSOLUTE_TIME = 32`).
    const OS_CLOCK_MACH_ABSOLUTE_TIME: u32 = 32;
    /// 32-bit futex word.
    const FUTEX_WORD_SIZE: libc::size_t = 4;

    #[link(name = "System")]
    unsafe extern "C" {
        fn os_sync_wait_on_address(
            addr: *mut c_void,
            value: u64,
            size: libc::size_t,
            flags: u32,
        ) -> libc::c_int;

        fn os_sync_wait_on_address_with_timeout(
            addr: *mut c_void,
            value: u64,
            size: libc::size_t,
            flags: u32,
            clockid: u32,
            timeout_ns: u64,
        ) -> libc::c_int;

        fn os_sync_wake_by_address_any(
            addr: *mut c_void,
            size: libc::size_t,
            flags: u32,
        ) -> libc::c_int;

        fn os_sync_wake_by_address_all(
            addr: *mut c_void,
            size: libc::size_t,
            flags: u32,
        ) -> libc::c_int;
    }

    fn neg_errno() -> i64 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL);
        -(e as i64)
    }

    /// Wait while `*host_addr == value`. `timeout_us` of 0 waits indefinitely.
    /// Returns `>= 0` when woken (or the value already differed — the caller
    /// re-checks), or `-errno` (e.g. `-ETIMEDOUT`, `-EINTR`).
    pub fn wait(host_addr: usize, value: u32, timeout_us: u32) -> i64 {
        let flags = OS_SYNC_WAIT_ON_ADDRESS_SHARED;
        // SAFETY: a plain libSystem call; `host_addr` points into a live host
        // MAP_SHARED region (the caller obtained it from the memory backend)
        // and is 4-byte aligned; the kernel only reads 4 bytes for the compare.
        let rc = unsafe {
            if timeout_us == 0 {
                os_sync_wait_on_address(
                    host_addr as *mut c_void,
                    value as u64,
                    FUTEX_WORD_SIZE,
                    flags,
                )
            } else {
                os_sync_wait_on_address_with_timeout(
                    host_addr as *mut c_void,
                    value as u64,
                    FUTEX_WORD_SIZE,
                    flags,
                    OS_CLOCK_MACH_ABSOLUTE_TIME,
                    (timeout_us as u64).saturating_mul(1000),
                )
            }
        };
        if rc < 0 {
            neg_errno()
        } else {
            rc as i64
        }
    }

    /// Wake waiters on `host_addr`. Returns `>= 0` on success, `-errno`
    /// (e.g. `-ENOENT`) when there was no waiter.
    pub fn wake(host_addr: usize, all: bool) -> i64 {
        let flags = OS_SYNC_WAKE_BY_ADDRESS_SHARED;
        // SAFETY: plain libSystem call against a live shared host address.
        let rc = unsafe {
            if all {
                os_sync_wake_by_address_all(host_addr as *mut c_void, FUTEX_WORD_SIZE, flags)
            } else {
                os_sync_wake_by_address_any(host_addr as *mut c_void, FUTEX_WORD_SIZE, flags)
            }
        };
        if rc < 0 {
            neg_errno()
        } else {
            rc as i64
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod imp {
    pub fn wait(_host_addr: usize, _value: u32, _timeout_us: u32) -> i64 {
        -(libc::ENOSYS as i64)
    }
    pub fn wake(_host_addr: usize, _all: bool) -> i64 {
        -(libc::ENOSYS as i64)
    }
}

pub use imp::{wait, wake};

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::{wait, wake};
    use std::sync::atomic::AtomicU32;

    #[test]
    fn wait_times_out_with_etimedout() {
        let word = AtomicU32::new(7);
        let addr = &word as *const AtomicU32 as usize;
        // Value matches (7), so we block; 10ms timeout -> -ETIMEDOUT.
        let rc = wait(addr, 7, 10_000);
        assert_eq!(rc, -(libc::ETIMEDOUT as i64), "expected -ETIMEDOUT, got {rc}");
    }

    #[test]
    fn wait_returns_nonneg_on_value_mismatch() {
        let word = AtomicU32::new(1);
        let addr = &word as *const AtomicU32 as usize;
        // Expected 999 != actual 1 -> returns immediately, >= 0.
        let rc = wait(addr, 999, 10_000);
        assert!(rc >= 0, "value mismatch should not error, got {rc}");
    }

    #[test]
    fn wake_with_no_waiters_is_nonfatal() {
        let word = AtomicU32::new(0);
        let addr = &word as *const AtomicU32 as usize;
        // No waiter parked: os_sync returns -1/ENOENT; wrapper maps to -errno.
        let rc = wake(addr, true);
        assert!(rc < 0, "wake with no waiters should report an error, got {rc}");
    }
}
