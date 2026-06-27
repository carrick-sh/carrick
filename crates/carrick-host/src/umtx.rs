//! FreeBSD cross-process futex via `_umtx_op(2)` (UMTX_OP_WAIT_UINT / WAKE).
//! Mirrors `ulock.rs`'s `-errno` contract so BsdFutex can pick either by host OS.

#[cfg(target_os = "freebsd")]
mod imp {
    use std::ffi::c_void;

    /// From `<sys/umtx.h>`: `UMTX_OP_WAKE = 3`, `UMTX_OP_WAIT_UINT = 11`.
    const UMTX_OP_WAIT_UINT: libc::c_int = 11;
    const UMTX_OP_WAKE: libc::c_int = 3;
    /// From `<sys/_clock_id.h>`: `CLOCK_MONOTONIC = 4`.
    const CLOCK_MONOTONIC: u32 = 4;

    /// Layout mirrors `struct _umtx_time` from `<sys/_umtx.h>`:
    /// `{ struct timespec _timeout; uint32_t _flags; uint32_t _clockid; }`.
    /// `_flags = 0` means relative timeout (not `UMTX_ABSTIME`).
    #[repr(C)]
    struct UmtxTime {
        timeout: libc::timespec,
        flags: u32,
        clockid: u32,
    }

    unsafe extern "C" {
        fn _umtx_op(
            obj: *mut c_void,
            op: libc::c_int,
            val: libc::c_ulong,
            uaddr: *mut c_void,
            uaddr2: *mut c_void,
        ) -> libc::c_int;
    }

    fn neg_errno() -> i64 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL);
        -(e as i64)
    }

    /// Wait while `*host_addr == value`. `timeout_us == 0` blocks indefinitely.
    /// Returns `>= 0` when woken or the value already differed, or `-errno`
    /// (`-ETIMEDOUT`, `-EINTR`, …).
    pub fn wait(host_addr: usize, value: u32, timeout_us: u32) -> i64 {
        // Register as a parked waiter in the mirror slot's `waiters` field (the host
        // word at `host_addr` is the slot's `value`; `waiters` is the next u32, at
        // `host_addr + 4`). A concurrent shared WAKE reads this to report a Linux-
        // faithful woken count, which FreeBSD `_umtx_op(UMTX_OP_WAKE)` itself never does
        // (it returns 0 on success). Held across the wait, decremented on every return.
        // SAFETY: host_addr is the mirror slot's `value` word (bhyve always routes a
        // shared futex through a FutexMirrorSlot); `value`+4 is its `waiters` field.
        let waiters = unsafe { &*((host_addr + 4) as *const std::sync::atomic::AtomicU32) };
        waiters.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // SAFETY: host_addr is a live 4-byte-aligned host MAP_SHARED word;
        // _umtx_op reads 4 bytes for the compare.
        let rc = unsafe {
            if timeout_us == 0 {
                _umtx_op(
                    host_addr as *mut c_void,
                    UMTX_OP_WAIT_UINT,
                    value as libc::c_ulong,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } else {
                let ut = UmtxTime {
                    timeout: libc::timespec {
                        tv_sec: (timeout_us / 1_000_000) as libc::time_t,
                        tv_nsec: ((timeout_us % 1_000_000) as i64 * 1000) as libc::c_long,
                    },
                    flags: 0,
                    clockid: CLOCK_MONOTONIC,
                };
                _umtx_op(
                    host_addr as *mut c_void,
                    UMTX_OP_WAIT_UINT,
                    value as libc::c_ulong,
                    std::mem::size_of::<UmtxTime>() as *mut c_void,
                    &ut as *const UmtxTime as *mut c_void,
                )
            }
        };
        waiters.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if rc < 0 { neg_errno() } else { rc as i64 }
    }

    /// Wake waiters on `host_addr`. Returns `>= 0` on success, `-errno` otherwise.
    pub fn wake(host_addr: usize, all: bool) -> i64 {
        let n: libc::c_ulong = if all {
            libc::c_int::MAX as libc::c_ulong
        } else {
            1
        };
        // Snapshot the parked-waiter count (mirror slot `waiters` at value+4) BEFORE the
        // wake. FreeBSD UMTX_OP_WAKE returns 0 on success, but Linux FUTEX_WAKE — and
        // tst_checkpoint_wake's retry loop — expect the NUMBER of waiters woken, so
        // report min(parked, requested) instead of the umtx 0.
        // SAFETY: host_addr is the mirror slot's `value`; `value`+4 is its `waiters`.
        let waiters = unsafe {
            (*((host_addr + 4) as *const std::sync::atomic::AtomicU32))
                .load(std::sync::atomic::Ordering::SeqCst)
        };
        // SAFETY: plain libc call against a live shared host address.
        let rc = unsafe {
            _umtx_op(
                host_addr as *mut c_void,
                UMTX_OP_WAKE,
                n,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc < 0 {
            return neg_errno();
        }
        (u64::from(waiters)).min(n as u64) as i64
    }
}

#[cfg(not(target_os = "freebsd"))]
mod imp {
    pub fn wait(_host_addr: usize, _value: u32, _timeout_us: u32) -> i64 {
        -(libc::ENOSYS as i64)
    }
    pub fn wake(_host_addr: usize, _all: bool) -> i64 {
        -(libc::ENOSYS as i64)
    }
}

pub use imp::{wait, wake};

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::{wait, wake};
    use std::sync::atomic::AtomicU32;

    #[test]
    fn wait_times_out_with_etimedout() {
        let word = AtomicU32::new(7);
        let addr = &word as *const AtomicU32 as usize;
        let rc = wait(addr, 7, 10_000); // value matches -> block; 10ms -> -ETIMEDOUT
        assert_eq!(
            rc,
            -(libc::ETIMEDOUT as i64),
            "expected -ETIMEDOUT, got {rc}"
        );
    }
    #[test]
    fn wait_returns_immediately_when_value_differs() {
        let word = AtomicU32::new(1);
        let addr = &word as *const AtomicU32 as usize;
        let rc = wait(addr, 0, 0); // compared value 0 != 1 -> must not block
        assert!(rc >= 0, "value-differs must return >= 0, got {rc}");
    }
    #[test]
    fn wake_with_no_waiter_is_not_fatal() {
        let word = AtomicU32::new(0);
        let addr = &word as *const AtomicU32 as usize;
        let rc = wake(addr, true);
        assert!(rc >= 0, "wake with no waiter should be >= 0, got {rc}");
    }
}
