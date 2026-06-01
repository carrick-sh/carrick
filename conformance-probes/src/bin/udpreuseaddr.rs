//! Two UDP sockets that both set SO_REUSEADDR may bind the SAME wildcard
//! address/port on Linux. This is exactly what libuv's UV_UDP_REUSEADDR relies
//! on (on Linux it sets ONLY SO_REUSEADDR, before bind), and what
//! udp_bind_reuseaddr + watcher_cross_stop exercise.
//!
//! macOS BSD semantics differ: SO_REUSEADDR alone does NOT let two UDP sockets
//! share a wildcard addr/port — that needs SO_REUSEPORT. Carrick passed the
//! guest's SO_REUSEADDR straight through, so the macOS kernel rejected the
//! second bind with EADDRINUSE (-98). The fix widens SO_REUSEADDR to also set
//! host SO_REUSEPORT for datagram sockets.
//!
//!  * both_udp_reuseaddr_binds_ok: two SOCK_DGRAM sockets, each with
//!    SO_REUSEADDR=1, both bind 0.0.0.0:<port> successfully.

use conformance_probes::report;
use std::mem::{size_of, zeroed};

fn main() {
    unsafe {
        let s1 = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        let s2 = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if s1 < 0 || s2 < 0 {
            report!(setup_ok = false);
            return;
        }
        let yes: i32 = 1;
        // libuv UV_UDP_REUSEADDR on Linux: SO_REUSEADDR only, set before bind.
        for s in [s1, s2] {
            if libc::setsockopt(
                s,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &yes as *const i32 as *const libc::c_void,
                size_of::<i32>() as u32,
            ) != 0
            {
                report!(setup_ok = false);
                return;
            }
        }
        let mut a: libc::sockaddr_in = zeroed();
        a.sin_family = libc::AF_INET as u16;
        a.sin_addr.s_addr = 0; // INADDR_ANY (0.0.0.0)
        a.sin_port = 9123u16.to_be();
        let pa = &a as *const libc::sockaddr_in as *const libc::sockaddr;
        let len = size_of::<libc::sockaddr_in>() as u32;
        let r1 = libc::bind(s1, pa, len);
        let r2 = libc::bind(s2, pa, len);

        report!(both_udp_reuseaddr_binds_ok = r1 == 0 && r2 == 0);

        libc::close(s1);
        libc::close(s2);
    }
}
