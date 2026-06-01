//! connect() with an AF_UNSPEC sockaddr DISCONNECTS a UDP socket (dissolves
//! the association) and returns 0 on Linux. libuv's uv_udp_connect(NULL) relies
//! on this (udp_connect, udp_connect6).
//!
//! Carrick's read_linux_sockaddr rejected any family except AF_INET/INET6/UNIX
//! with EAFNOSUPPORT, so a connect(AF_UNSPEC) short-circuited with -97 before
//! ever reaching the host — the socket stayed connected and the wrong errno was
//! returned. The fix maps AF_UNSPEC through to the host connect (macOS also
//! disconnects on AF_UNSPEC) and treats the host's EAFNOSUPPORT/EINVAL on that
//! path as success.
//!
//!  * udp_connect_unspec_disconnects: connect to a peer, then
//!    connect(AF_UNSPEC) returns 0 and getpeername reports ENOTCONN.

use conformance_probes::report;
use std::mem::{size_of, zeroed};

fn main() {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            report!(setup_ok = false);
            return;
        }
        // Connect to a peer (no listener needed for UDP connect).
        let mut peer: libc::sockaddr_in = zeroed();
        peer.sin_family = libc::AF_INET as u16;
        peer.sin_addr.s_addr = 0x7f000001u32.to_be(); // 127.0.0.1
        peer.sin_port = 9124u16.to_be();
        let r1 = libc::connect(
            fd,
            &peer as *const libc::sockaddr_in as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as u32,
        );
        // Confirm connected.
        let mut pn: libc::sockaddr_in = zeroed();
        let mut pnlen = size_of::<libc::sockaddr_in>() as u32;
        let rp1 = libc::getpeername(
            fd,
            &mut pn as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut pnlen,
        );

        // Disconnect: a 16-byte AF_UNSPEC sockaddr.
        let mut unspec: libc::sockaddr = zeroed();
        unspec.sa_family = libc::AF_UNSPEC as u16;
        let ru = libc::connect(
            fd,
            &unspec as *const libc::sockaddr,
            size_of::<libc::sockaddr>() as u32,
        );

        // Now disconnected: getpeername must report ENOTCONN.
        let mut pn2: libc::sockaddr_in = zeroed();
        let mut pn2len = size_of::<libc::sockaddr_in>() as u32;
        let rp2 = libc::getpeername(
            fd,
            &mut pn2 as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut pn2len,
        );
        let e2 = if rp2 < 0 {
            *libc::__errno_location()
        } else {
            0
        };

        eprintln!("r1={r1} rp1={rp1} ru={ru} rp2={rp2} e2={e2}");
        report!(
            udp_connect_unspec_disconnects =
                r1 == 0 && rp1 == 0 && ru == 0 && rp2 == -1 && e2 == libc::ENOTCONN
        );
        libc::close(fd);
    }
}
