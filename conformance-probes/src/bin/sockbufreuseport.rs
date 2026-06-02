//! Socket-option read-back conformance (audit M4, M5): the values getsockopt
//! reports must reflect what the guest SET, not carrick's host-side widening.
//! Flagged oracle-sensitive in docs/asymmetric-behavior-audit.md — this probe
//! is what validates carrick's SO_RCVBUF/SNDBUF doubling and SO_REUSEPORT
//! defaulting against the Docker linux/arm64 oracle.
//!
//! Invariants encoded (carrick must match Linux line-for-line). The buffer
//! checks assert the doubling RELATIONSHIP rather than an exact value, so they
//! stay robust to the kernel's rmem_max/wmem_max clamping (which both sides see
//! identically) while still catching a missing 2x:
//!   - setsockopt(SO_RCVBUF, 8192) → getsockopt >= 16384 (Linux doubles).
//!   - setsockopt(SO_SNDBUF, 8192) → getsockopt >= 16384.
//!   - setsockopt(SO_REUSEADDR, 1) on a UDP socket → getsockopt(SO_REUSEPORT)
//!     still reports 0 (the guest never set REUSEPORT; carrick's UDP
//!     REUSEADDR→REUSEPORT host widening must be invisible).
//!   - An explicit setsockopt(SO_REUSEPORT, 1) → getsockopt reports 1.

use conformance_probes::report;

unsafe fn getsockopt_int(fd: i32, level: i32, opt: i32) -> i32 {
    let mut val: i32 = -1;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    libc::getsockopt(fd, level, opt, &mut val as *mut i32 as *mut libc::c_void, &mut len);
    val
}

unsafe fn setsockopt_int(fd: i32, level: i32, opt: i32, val: i32) -> i32 {
    libc::setsockopt(
        fd,
        level,
        opt,
        &val as *const i32 as *const libc::c_void,
        std::mem::size_of::<i32>() as libc::socklen_t,
    )
}

fn main() {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        report!(socket_ok = fd >= 0);

        report!(rcvbuf_set_ok = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, 8192) == 0);
        report!(rcvbuf_doubled = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF) >= 16384);

        report!(sndbuf_set_ok = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, 8192) == 0);
        report!(sndbuf_doubled = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF) >= 16384);

        // SO_REUSEADDR widening must not leak into SO_REUSEPORT read-back.
        report!(reuseaddr_set_ok = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1) == 0);
        report!(
            reuseport_still_zero = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT) == 0
        );

        // An explicit SO_REUSEPORT set DOES read back.
        report!(
            reuseport_set_ok = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1) == 0
        );
        report!(reuseport_now_one = getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT) == 1);

        libc::close(fd);
    }
}
