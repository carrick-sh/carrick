//! NetBSD cross-process futex via `__futex(2)`.
//!
//! NetBSD keys cross-process futexes through shared objects: file-backed
//! `MAP_SHARED` mappings wake across `fork`, while `MAP_SHARED|MAP_ANON` stores
//! are coherent but `FUTEX_WAKE` finds no waiter in the child. A NetBSD runtime
//! shared aperture must therefore use a file-backed shared mapping if it wants
//! this primitive for guest shared futexes.
//!
//! Mirrors `ulock.rs`/`umtx.rs`'s `-errno` contract so BSD-family callers can
//! select the host primitive without learning the raw syscall ABI.

#[cfg(target_os = "netbsd")]
mod imp {
    const SYS___FUTEX: libc::c_int = 166;

    fn neg_errno() -> i64 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL);
        -(e as i64)
    }

    /// Wait while `*host_addr == value`. `timeout_us == 0` blocks indefinitely.
    /// Returns `>= 0` when woken or the value already differed, or `-errno`.
    pub fn wait(host_addr: usize, value: u32, timeout_us: u32) -> i64 {
        let ts = (timeout_us != 0).then_some(libc::timespec {
            tv_sec: (timeout_us / 1_000_000) as libc::time_t,
            tv_nsec: ((timeout_us % 1_000_000) as i64 * 1000) as libc::c_long,
        });
        let timeout_ptr = ts
            .as_ref()
            .map_or(std::ptr::null(), |t| t as *const libc::timespec);

        // SAFETY: host_addr is a live 4-byte-aligned host MAP_SHARED word;
        // __futex(FUTEX_WAIT) reads that word and an optional relative timeout.
        let rc = unsafe {
            libc::syscall(
                SYS___FUTEX,
                host_addr as *mut libc::c_int,
                libc::FUTEX_WAIT,
                value as libc::c_int,
                timeout_ptr,
                std::ptr::null_mut::<libc::c_int>(),
                0 as libc::c_int,
                0 as libc::c_int,
            )
        };
        if rc < 0 {
            let errno = (-neg_errno()) as i32;
            if errno == libc::EAGAIN {
                0
            } else {
                -i64::from(errno)
            }
        } else {
            rc as i64
        }
    }

    /// Wake waiters on `host_addr`. Returns `>= 0` on success, `-errno` otherwise.
    pub fn wake(host_addr: usize, all: bool) -> i64 {
        let n: libc::c_int = if all { libc::c_int::MAX } else { 1 };
        // SAFETY: plain __futex(FUTEX_WAKE) against a live shared host address.
        let rc = unsafe {
            libc::syscall(
                SYS___FUTEX,
                host_addr as *mut libc::c_int,
                libc::FUTEX_WAKE,
                n,
                std::ptr::null::<libc::timespec>(),
                std::ptr::null_mut::<libc::c_int>(),
                0 as libc::c_int,
                0 as libc::c_int,
            )
        };
        if rc < 0 { neg_errno() } else { rc as i64 }
    }
}

#[cfg(not(target_os = "netbsd"))]
mod imp {
    pub fn wait(_host_addr: usize, _value: u32, _timeout_us: u32) -> i64 {
        -(libc::ENOSYS as i64)
    }
    pub fn wake(_host_addr: usize, _all: bool) -> i64 {
        -(libc::ENOSYS as i64)
    }
}

pub use imp::{wait, wake};
