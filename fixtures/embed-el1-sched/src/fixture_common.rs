//! Shared libc/syscall and bounded peer helpers for both fixture ISAs.
use std::sync::atomic::AtomicU32;
use std::time::Duration;
pub(super) const SYS_FUTEX: u64 = libc::SYS_futex as u64;
const SYS_GETTID: u64 = libc::SYS_gettid as u64;
const FUTEX_WAIT_PRIVATE: u64 = 128;
const FUTEX_WAKE_PRIVATE: u64 = 129;
#[cfg(target_arch = "aarch64")]
pub(super) unsafe fn raw6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!(
            "svc #0",
            inlateout("x0") a0 as i64 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            in("x8") nr,
            options(nostack)
        );
    }
    ret
}

/// `FUTEX_WAIT_PRIVATE` bounded by a relative timeout.
pub(super) fn futex_wait_timeout(word: &AtomicU32, expected: u32, timeout: Duration) -> i64 {
    let ts = libc::timespec {
        tv_sec: timeout.as_secs() as i64,
        tv_nsec: libc::c_long::from(timeout.subsec_nanos() as i32),
    };
    unsafe {
        raw6(
            SYS_FUTEX,
            word.as_ptr() as u64,
            FUTEX_WAIT_PRIVATE,
            u64::from(expected),
            &ts as *const libc::timespec as u64,
            0,
            0,
        )
    }
}

pub(super) fn futex_wake(word: &AtomicU32, count: u32) -> i64 {
    unsafe {
        raw6(
            SYS_FUTEX,
            word.as_ptr() as u64,
            FUTEX_WAKE_PRIVATE,
            u64::from(count),
            0,
            0,
            0,
        )
    }
}

pub(super) fn gettid() -> i32 {
    unsafe { raw6(SYS_GETTID, 0, 0, 0, 0, 0, 0) as i32 }
}

pub(super) fn poll_read_byte(fd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc <= 0 || (pfd.revents & libc::POLLIN) == 0 {
        return false;
    }
    let mut byte = 0u8;
    let n = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
    n == 1
}

pub(super) fn write_signal_byte(fd: libc::c_int, byte: u8) -> bool {
    let n = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    n == 1
}

/// Send one observed count to the peer as 8 little-endian bytes.
pub(super) fn write_count(fd: libc::c_int, count: u64) -> bool {
    let bytes = count.to_le_bytes();
    let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    n == bytes.len() as isize
}

/// Receive a count written by `write_count`, bounded by `timeout_ms`.
pub(super) fn poll_read_count(fd: libc::c_int, timeout_ms: libc::c_int) -> Option<u64> {
    let mut bytes = [0u8; 8];
    let mut have = 0;
    while have < bytes.len() {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc <= 0 || (pfd.revents & libc::POLLIN) == 0 {
            return None;
        }
        let n = unsafe { libc::read(fd, bytes[have..].as_mut_ptr().cast(), bytes.len() - have) };
        if n <= 0 {
            return None;
        }
        have += n as usize;
    }
    Some(u64::from_le_bytes(bytes))
}

pub(super) fn pipe_pair() -> (i32, i32) {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe");
    (fds[0], fds[1])
}

#[cfg(target_arch = "x86_64")]
pub(super) unsafe fn raw6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    unsafe {
        std::arch::asm!("syscall", inlateout("rax") nr as i64 => ret,
            in("rdi") a0, in("rsi") a1, in("rdx") a2,
            in("r10") a3, in("r8") a4, in("r9") a5,
            lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}
