//! Conformance probe for sendmmsg(2) and recvmmsg(2) batch socket operations.
//!
//! Verifies Linux batched datagram semantics on AF_UNIX SOCK_DGRAM socketpair:
//! 1. sendmmsg sends multiple datagrams, returning total sent and per-message lengths.
//! 2. recvmmsg drains multiple datagrams in order, reporting per-message lengths.
//! 3. sendmmsg partial completion: when a later message is invalid, sendmmsg returns
//!    the count of successfully sent messages prior to failure without dropping them,
//!    and the earlier datagram is delivered to the peer.
//! 4. recvmmsg MSG_TRUNC: with MSG_TRUNC flag, recvmmsg reports the full datagram length
//!    in msg_len for a truncated buffer and sets MSG_TRUNC in msg_flags.
//! 5. recvmmsg nonblocking on empty socket returns EAGAIN.

use conformance_probes::{errno, report};
use std::mem::MaybeUninit;
use std::ptr;

const MSG_TRUNC_LINUX: i32 = 0x20;

struct SocketPair {
    tx: i32,
    rx: i32,
}

impl Drop for SocketPair {
    fn drop(&mut self) {
        unsafe {
            if self.tx >= 0 {
                libc::close(self.tx);
            }
            if self.rx >= 0 {
                libc::close(self.rx);
            }
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Mmsghdr {
    msg_hdr: libc::msghdr,
    msg_len: libc::c_uint,
}

unsafe fn raw_sendmmsg(
    fd: i32,
    msgvec: *mut Mmsghdr,
    vlen: libc::c_uint,
    flags: libc::c_int,
) -> (libc::c_long, i32) {
    let rc = libc::syscall(
        libc::SYS_sendmmsg,
        fd as libc::c_long,
        msgvec as libc::c_long,
        vlen as libc::c_long,
        flags as libc::c_long,
    );
    let err = if rc == -1 { errno() } else { 0 };
    (rc, err)
}

unsafe fn raw_recvmmsg(
    fd: i32,
    msgvec: *mut Mmsghdr,
    vlen: libc::c_uint,
    flags: libc::c_int,
    timeout: *mut libc::timespec,
) -> (libc::c_long, i32) {
    let rc = libc::syscall(
        libc::SYS_recvmmsg,
        fd as libc::c_long,
        msgvec as libc::c_long,
        vlen as libc::c_long,
        flags as libc::c_long,
        timeout as libc::c_long,
    );
    let err = if rc == -1 { errno() } else { 0 };
    (rc, err)
}

fn main() {
    unsafe {
        // 5-second probe-local alarm as a last-resort bound against hangs.
        libc::alarm(5);

        let mut sv = [0i32; 2];
        let rc = libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr());
        if rc != 0 {
            report!(setup_socketpair_ok = false);
            return;
        }
        let pair = SocketPair {
            tx: sv[0],
            rx: sv[1],
        };
        let tx = pair.tx;
        let rx = pair.rx;

        // =====================================================================
        // Test 1 & 3: sendmmsg multi-message batch + recvmmsg multi-message drain
        // =====================================================================
        let msg0 = b"alpha";
        let msg1 = b"bravo_payload";
        let msg2 = b"charlie!";

        let mut iov_send = [
            libc::iovec {
                iov_base: msg0.as_ptr() as *mut libc::c_void,
                iov_len: msg0.len(),
            },
            libc::iovec {
                iov_base: msg1.as_ptr() as *mut libc::c_void,
                iov_len: msg1.len(),
            },
            libc::iovec {
                iov_base: msg2.as_ptr() as *mut libc::c_void,
                iov_len: msg2.len(),
            },
        ];

        let mut send_vec: [Mmsghdr; 3] = MaybeUninit::zeroed().assume_init();
        for i in 0..3 {
            send_vec[i].msg_hdr.msg_iov = &mut iov_send[i] as *mut libc::iovec;
            send_vec[i].msg_hdr.msg_iovlen = 1;
        }

        let (sent_count, sent_err) = raw_sendmmsg(tx, send_vec.as_mut_ptr(), 3, 0);
        report!(
            sendmmsg_batch3_count = sent_count,
            sendmmsg_batch3_err = sent_err,
            sendmmsg_batch3_len0 = send_vec[0].msg_len,
            sendmmsg_batch3_len1 = send_vec[1].msg_len,
            sendmmsg_batch3_len2 = send_vec[2].msg_len,
        );

        let mut buf0 = [0u8; 32];
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        let mut iov_recv = [
            libc::iovec {
                iov_base: buf0.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf0.len(),
            },
            libc::iovec {
                iov_base: buf1.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf1.len(),
            },
            libc::iovec {
                iov_base: buf2.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf2.len(),
            },
        ];

        let mut recv_vec: [Mmsghdr; 3] = MaybeUninit::zeroed().assume_init();
        for i in 0..3 {
            recv_vec[i].msg_hdr.msg_iov = &mut iov_recv[i] as *mut libc::iovec;
            recv_vec[i].msg_hdr.msg_iovlen = 1;
        }

        let (recv_count, recv_err) =
            raw_recvmmsg(rx, recv_vec.as_mut_ptr(), 3, libc::MSG_DONTWAIT, ptr::null_mut());
        report!(
            recvmmsg_batch3_count = recv_count,
            recvmmsg_batch3_err = recv_err,
            recvmmsg_batch3_len0 = recv_vec[0].msg_len,
            recvmmsg_batch3_len1 = recv_vec[1].msg_len,
            recvmmsg_batch3_len2 = recv_vec[2].msg_len,
            recvmmsg_batch3_data0_ok = &buf0[..msg0.len()] == msg0,
            recvmmsg_batch3_data1_ok = &buf1[..msg1.len()] == msg1,
            recvmmsg_batch3_data2_ok = &buf2[..msg2.len()] == msg2,
        );

        // =====================================================================
        // Test 5: nonblocking / no-data returns EAGAIN
        // =====================================================================
        let mut empty_buf = [0u8; 16];
        let mut empty_iov = libc::iovec {
            iov_base: empty_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: empty_buf.len(),
        };
        let mut empty_recv_vec: [Mmsghdr; 1] = MaybeUninit::zeroed().assume_init();
        empty_recv_vec[0].msg_hdr.msg_iov = &mut empty_iov as *mut libc::iovec;
        empty_recv_vec[0].msg_hdr.msg_iovlen = 1;

        let (empty_rc, empty_err) = raw_recvmmsg(
            rx,
            empty_recv_vec.as_mut_ptr(),
            1,
            libc::MSG_DONTWAIT,
            ptr::null_mut(),
        );
        report!(
            recvmmsg_nodata_rc = empty_rc,
            recvmmsg_nodata_eagain = empty_err == libc::EAGAIN,
        );

        // =====================================================================
        // Test 2: partial-completion count on later invalid message
        // =====================================================================
        let partial_msg0 = b"valid_first_message";
        let mut iov_part0 = libc::iovec {
            iov_base: partial_msg0.as_ptr() as *mut libc::c_void,
            iov_len: partial_msg0.len(),
        };
        let mut partial_send_vec: [Mmsghdr; 2] = MaybeUninit::zeroed().assume_init();
        partial_send_vec[0].msg_hdr.msg_iov = &mut iov_part0 as *mut libc::iovec;
        partial_send_vec[0].msg_hdr.msg_iovlen = 1;
        // Second message has an invalid iovec pointer (EFAULT)
        partial_send_vec[1].msg_hdr.msg_iov = 0x1 as *mut libc::iovec;
        partial_send_vec[1].msg_hdr.msg_iovlen = 1;

        let (part_sent, part_err) = raw_sendmmsg(tx, partial_send_vec.as_mut_ptr(), 2, 0);
        report!(
            sendmmsg_partial_count = part_sent,
            sendmmsg_partial_err = part_err,
            sendmmsg_partial_len0 = partial_send_vec[0].msg_len,
        );

        // Verify the first datagram is queued and readable
        let mut part_drain_buf = [0u8; 32];
        let mut part_drain_iov = libc::iovec {
            iov_base: part_drain_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: part_drain_buf.len(),
        };
        let mut part_drain_vec: [Mmsghdr; 1] = MaybeUninit::zeroed().assume_init();
        part_drain_vec[0].msg_hdr.msg_iov = &mut part_drain_iov as *mut libc::iovec;
        part_drain_vec[0].msg_hdr.msg_iovlen = 1;

        let (part_drain_rc, part_drain_err) = raw_recvmmsg(
            rx,
            part_drain_vec.as_mut_ptr(),
            1,
            libc::MSG_DONTWAIT,
            ptr::null_mut(),
        );
        report!(
            sendmmsg_partial_drain_rc = part_drain_rc,
            sendmmsg_partial_drain_err = part_drain_err,
            sendmmsg_partial_drain_len0 = part_drain_vec[0].msg_len,
            sendmmsg_partial_drain_data_ok = &part_drain_buf[..partial_msg0.len()] == partial_msg0,
        );

        // When the FIRST message is invalid, sendmmsg must return -1 with errno (EFAULT)
        let mut invalid_first_vec: [Mmsghdr; 1] = MaybeUninit::zeroed().assume_init();
        invalid_first_vec[0].msg_hdr.msg_iov = 0x1 as *mut libc::iovec;
        invalid_first_vec[0].msg_hdr.msg_iovlen = 1;

        let (inv_first_rc, inv_first_err) = raw_sendmmsg(tx, invalid_first_vec.as_mut_ptr(), 1, 0);
        report!(
            sendmmsg_invalid_first_rc = inv_first_rc,
            sendmmsg_invalid_first_efault = inv_first_err == libc::EFAULT,
        );

        // =====================================================================
        // Test 4: MSG_TRUNC reports full datagram length for a short receive buffer
        // =====================================================================
        let trunc_msg = b"0123456789abcdefghijklmnopqrstuvwxyz"; // 36 bytes
        let mut trunc_send_iov = libc::iovec {
            iov_base: trunc_msg.as_ptr() as *mut libc::c_void,
            iov_len: trunc_msg.len(),
        };
        let mut trunc_send_vec: [Mmsghdr; 1] = MaybeUninit::zeroed().assume_init();
        trunc_send_vec[0].msg_hdr.msg_iov = &mut trunc_send_iov as *mut libc::iovec;
        trunc_send_vec[0].msg_hdr.msg_iovlen = 1;

        let (trunc_sent, _) = raw_sendmmsg(tx, trunc_send_vec.as_mut_ptr(), 1, 0);
        if trunc_sent != 1 {
            report!(setup_trunc_send_ok = false);
            return;
        }

        // Receive with MSG_TRUNC and a short 8-byte buffer
        let mut trunc_buf = [0u8; 8];
        let mut trunc_recv_iov = libc::iovec {
            iov_base: trunc_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: trunc_buf.len(),
        };
        let mut trunc_recv_vec: [Mmsghdr; 1] = MaybeUninit::zeroed().assume_init();
        trunc_recv_vec[0].msg_hdr.msg_iov = &mut trunc_recv_iov as *mut libc::iovec;
        trunc_recv_vec[0].msg_hdr.msg_iovlen = 1;

        let (trunc_recv_rc, trunc_recv_err) = raw_recvmmsg(
            rx,
            trunc_recv_vec.as_mut_ptr(),
            1,
            libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            ptr::null_mut(),
        );

        report!(
            recvmmsg_trunc_rc = trunc_recv_rc,
            recvmmsg_trunc_err = trunc_recv_err,
            recvmmsg_trunc_msg_len = trunc_recv_vec[0].msg_len,
            recvmmsg_trunc_flag_set = (trunc_recv_vec[0].msg_hdr.msg_flags & MSG_TRUNC_LINUX) != 0,
            recvmmsg_trunc_buf_prefix_ok = &trunc_buf == &trunc_msg[..8],
        );
    }
}
