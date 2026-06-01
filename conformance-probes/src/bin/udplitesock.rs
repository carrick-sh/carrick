//! `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE)` must succeed and behave like a
//! datagram socket. The guest is LINUX Python, which (unlike native-macOS
//! Python) defines IPPROTO_UDPLITE and runs the whole test_socket UDPLITE suite
//! (~113 tests). macOS has no UDPLITE protocol, so carrick's pass-through
//! socket() returned EPROTONOSUPPORT and every UDPLITE test ERRORed at setUp.
//! macOS's closest equivalent is a plain UDP socket — UDPLITE's send/recv path
//! is UDP-identical (only the checksum-coverage sockopts differ).
//!
//!  * udplite_socket_ok:  socket(AF_INET, SOCK_DGRAM, 136) succeeds.
//!  * udplite_roundtrip:  sendto/recvfrom over it round-trips a datagram.

use conformance_probes::report;

const IPPROTO_UDPLITE: i32 = 136;

fn main() {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, IPPROTO_UDPLITE);
        let udplite_socket_ok = fd >= 0;
        let mut roundtrip = false;
        if fd >= 0 {
            // Bind to an ephemeral loopback port, then send a datagram to self.
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as u16;
            addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            addr.sin_port = 0;
            let alen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, alen) == 0 {
                let mut bound: libc::sockaddr_in = std::mem::zeroed();
                let mut blen = alen;
                libc::getsockname(fd, &mut bound as *mut _ as *mut libc::sockaddr, &mut blen);
                let msg = b"udplite";
                let sent = libc::sendto(
                    fd,
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                    &bound as *const _ as *const libc::sockaddr,
                    blen,
                );
                if sent == msg.len() as isize {
                    let mut buf = [0u8; 16];
                    let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
                    roundtrip = n == msg.len() as isize && &buf[..msg.len()] == msg;
                }
            }
            libc::close(fd);
        }
        report!(
            udplite_socket_ok = udplite_socket_ok,
            udplite_roundtrip = roundtrip
        );
    }
}
