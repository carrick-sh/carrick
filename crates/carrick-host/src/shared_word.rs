//! Host-neutral wait/wake operations for a runtime-owned shared 32-bit word.
//!
//! Runtime kernel objects such as SysV message queues use a file-backed
//! `MAP_SHARED` word as their cross-process change notification. Keep host
//! primitive selection in this leaf crate: dispatch code must not know whether
//! the host rendezvous is Darwin `os_sync_wait_on_address`, FreeBSD `_umtx_op`,
//! Linux `futex`, or NetBSD `__futex`.

/// Wait while the shared word at `host_addr` equals `value`.
///
/// `timeout_us == 0` means no timeout. Returns `>= 0` after a wake/value change,
/// or a negative host errno.
pub fn wait(host_addr: usize, value: u32, timeout_us: u32) -> i64 {
    #[cfg(target_os = "macos")]
    {
        crate::ulock::wait(host_addr, value, timeout_us)
    }
    #[cfg(target_os = "freebsd")]
    {
        let rc = crate::umtx::wait(host_addr, None, value, timeout_us);
        // A value change between userspace inspection and kernel park is a
        // successful wake hint, not an errno for the guest syscall.
        if rc == -(libc::EAGAIN as i64) { 0 } else { rc }
    }
    #[cfg(target_os = "linux")]
    {
        let timeout = (timeout_us != 0).then_some(libc::timespec {
            tv_sec: (timeout_us / 1_000_000) as libc::time_t,
            tv_nsec: i64::from(timeout_us % 1_000_000) * 1000,
        });
        let timeout_ptr = timeout
            .as_ref()
            .map_or(std::ptr::null(), |value| value as *const libc::timespec);
        // SAFETY: `host_addr` is a live aligned MAP_SHARED word. Omitting
        // FUTEX_PRIVATE_FLAG makes the rendezvous fork/process coherent.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_futex,
                host_addr as *mut u32,
                libc::FUTEX_WAIT,
                value,
                timeout_ptr,
            )
        };
        if rc >= 0 {
            rc as i64
        } else {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL);
            if errno == libc::EAGAIN {
                0
            } else {
                -i64::from(errno)
            }
        }
    }
    #[cfg(target_os = "netbsd")]
    {
        crate::netbsd_futex::wait(host_addr, value, timeout_us)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd"
    )))]
    {
        let _ = (host_addr, value, timeout_us);
        -(libc::ENOSYS as i64)
    }
}

/// Wake one or all waiters parked on the shared word at `host_addr`.
///
/// Returns `>= 0` on success or a negative host errno.
pub fn wake(host_addr: usize, all: bool) -> i64 {
    #[cfg(target_os = "macos")]
    {
        crate::ulock::wake(host_addr, all)
    }
    #[cfg(target_os = "freebsd")]
    {
        crate::umtx::wake(host_addr, None, all)
    }
    #[cfg(target_os = "linux")]
    {
        let count = if all { libc::c_int::MAX } else { 1 };
        // SAFETY: `host_addr` is a live aligned MAP_SHARED word.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_futex,
                host_addr as *mut u32,
                libc::FUTEX_WAKE,
                count,
            )
        };
        if rc >= 0 {
            rc as i64
        } else {
            -i64::from(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL),
            )
        }
    }
    #[cfg(target_os = "netbsd")]
    {
        crate::netbsd_futex::wake(host_addr, all)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "linux",
        target_os = "netbsd"
    )))]
    {
        let _ = (host_addr, all);
        -(libc::ENOSYS as i64)
    }
}
