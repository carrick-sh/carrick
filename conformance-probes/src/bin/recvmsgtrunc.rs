//! A datagram larger than the receive buffer must be truncated AND flagged:
//! Linux discards the excess, returns the byte count that fit, and sets
//! MSG_TRUNC in msghdr.msg_flags. recvmsg with no ancillary buffer also leaves
//! msg_controllen at 0. carrick's recvmsg_inner (dispatch/net.rs 2702-2846)
//! reads exactly the iovec total via a host recvfrom (which silently drops the
//! overflow) and then HARD-CODES msg_controllen=0 (msg_addr+40) AND msg_flags=0
//! (msg_addr+48) — so the MSG_TRUNC signal is lost and a guest can't tell a
//! short read from a clean one.
//!
//! AF_UNIX SOCK_DGRAM socketpair keeps message boundaries and needs no ports or
//! addresses, so the observations are fully deterministic. MSG_DONTWAIT on the
//! recvs means the probe can never hang (each datagram is already queued by the
//! preceding send on the paired fd before the recv runs).
//!
//! Linux: trunc recv returns 10, msg_flags has MSG_TRUNC, controllen 0; the
//! fitting recv returns its full length with NO MSG_TRUNC. Fixed carrick MUST
//! match all of these. macOS/XNU sets MSG_TRUNC on atomic (PR_ATOMIC) records
//! exactly like Linux, so the fix can be faithful.

use conformance_probes::report;
use std::mem::MaybeUninit;

const MSG_TRUNC_LINUX: i32 = 0x20;

/// recvmsg one datagram into a single `cap`-byte iovec with MSG_DONTWAIT.
/// Returns (rc, msg_flags, msg_controllen).
unsafe fn recv_one(fd: i32, cap: usize) -> (isize, i32, u64) {
    let mut buf = vec![0u8; cap];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: cap,
    };
    let mut mh: libc::msghdr = MaybeUninit::zeroed().assume_init();
    mh.msg_iov = &mut iov as *mut libc::iovec;
    mh.msg_iovlen = 1;
    // No ancillary buffer: controllen must come back 0 on both sides.
    mh.msg_control = std::ptr::null_mut();
    mh.msg_controllen = 0;
    mh.msg_flags = 0;
    let rc = libc::recvmsg(fd, &mut mh as *mut libc::msghdr, libc::MSG_DONTWAIT);
    (rc, mh.msg_flags, mh.msg_controllen as u64)
}

fn main() {
    unsafe {
        let mut sv = [0i32; 2];
        let rc = libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr());
        if rc != 0 {
            report!(setup_socketpair_ok = false);
            return;
        }
        let (a, b) = (sv[0], sv[1]);

        // --- Case 1: oversized datagram -> truncation expected. ---
        let big = [0x41u8; 100];
        let sent = libc::send(a, big.as_ptr() as *const libc::c_void, big.len(), 0);
        if sent != 100 {
            report!(setup_send_big_ok = false);
            return;
        }
        let (n1, flags1, clen1) = recv_one(b, 10);
        report!(
            // Linux copies exactly what fits: 10 bytes.
            trunc_recv_returned_10 = n1 == 10,
            // The discarded-overflow signal: MSG_TRUNC set in msg_flags.
            trunc_recv_msg_trunc_set = (flags1 & MSG_TRUNC_LINUX) != 0,
            // No ancillary data requested -> controllen stays 0.
            trunc_recv_controllen_zero = clen1 == 0,
        );

        // --- Case 2: datagram fits exactly the buffer -> NO truncation. ---
        let small = [0x42u8; 8];
        let sent2 = libc::send(a, small.as_ptr() as *const libc::c_void, small.len(), 0);
        if sent2 != 8 {
            report!(setup_send_small_ok = false);
            return;
        }
        let (n2, flags2, clen2) = recv_one(b, 64);
        report!(
            fit_recv_returned_8 = n2 == 8,
            // A datagram that fits MUST NOT report MSG_TRUNC.
            fit_recv_no_msg_trunc = (flags2 & MSG_TRUNC_LINUX) == 0,
            fit_recv_controllen_zero = clen2 == 0,
        );

        libc::close(a);
        libc::close(b);
    }
}