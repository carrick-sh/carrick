//! Cross-process futex via the macOS `__ulock` primitive.
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
//! `__ulock` with `UL_COMPARE_AND_WAIT_SHARED` keys on the physical page (not
//! the per-task virtual address), so a wait in one process and a wake in
//! another rendezvous correctly — exactly the semantics Linux gives a shared
//! futex. Wrappers are thin and return `-errno` on error (via `ULF_NO_ERRNO`),
//! a positive remaining-waiter count or 0 on success.
//!
//! ABI (xnu bsd/kern/sys_ulock.c): `__ulock_wait(uint32 op, void *addr,
//! uint64 value, uint32 timeout_us)` — timeout in microseconds, 0 = forever;
//! value-mismatch returns immediately (>=0). `__ulock_wake(uint32 op,
//! void *addr, uint64 wake_value)` — 0 on success, `-ENOENT` if no waiters.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    /// Compare-and-wait against a SHARED (cross-process, physical-page-keyed)
    /// address. (`UL_COMPARE_AND_WAIT` = 1 is the per-task variant.)
    const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
    /// Wake every waiter rather than just one.
    const ULF_WAKE_ALL: u32 = 0x0000_0100;
    /// Return `-errno` from the syscall instead of setting errno + returning -1.
    const ULF_NO_ERRNO: u32 = 0x0100_0000;
    const SYS_ULOCK_WAIT: libc::c_int = 515;
    const SYS_ULOCK_WAKE: libc::c_int = 516;

    /// Wait while `*host_addr == value`. `timeout_us` of 0 waits indefinitely.
    /// Returns >= 0 when woken (or the value already differed — the caller
    /// re-checks), or `-errno` (e.g. `-EINTR`, `-ETIMEDOUT`).
    pub fn wait(host_addr: usize, value: u32, timeout_us: u32) -> i64 {
        let op = (UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO) as libc::c_uint;
        // SAFETY: a plain syscall; `host_addr` points into a live host
        // MAP_SHARED region (the caller obtained it from the memory backend),
        // and the kernel only reads 4 bytes there for the compare.
        unsafe {
            libc::syscall(
                SYS_ULOCK_WAIT,
                op,
                host_addr as *mut libc::c_void,
                value as u64,
                timeout_us as libc::c_uint,
            ) as i64
        }
    }

    /// Wake waiters on `host_addr`. Returns >= 0 on success, `-ENOENT` (and
    /// other `-errno`) when there was no waiter.
    pub fn wake(host_addr: usize, all: bool) -> i64 {
        let mut op = UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO;
        if all {
            op |= ULF_WAKE_ALL;
        }
        // SAFETY: plain syscall against a live shared host address.
        unsafe {
            libc::syscall(
                SYS_ULOCK_WAKE,
                op as libc::c_uint,
                host_addr as *mut libc::c_void,
                0u64,
            ) as i64
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
