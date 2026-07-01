//! Bridge UDP unconnected sendto-unreachable semantics. Sending one datagram to
//! an unused bridge-local port succeeds and does not arm a connected-socket
//! error on the sender.

use conformance_probes::{errno, report};
use std::ffi::CStr;
use std::net::Ipv4Addr;

fn main() {
    unsafe {
        let ip = eth0_ipv4();
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        report!(socket_ok = fd >= 0);

        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 65002_u16.to_be();
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        };

        let send_rc = libc::sendto(
            fd,
            b"ping".as_ptr().cast::<libc::c_void>(),
            4,
            0,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        report!(sendto_ok = send_rc == 4);

        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        };
        let poll_rc = libc::poll(&mut pollfd, 1, 100);
        report!(poll_no_error = poll_rc == 0 && pollfd.revents == 0);

        let mut buf = [0_u8; 16];
        let recv_rc = libc::recv(
            fd,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
            libc::MSG_DONTWAIT,
        );
        report!(recv_eagain = recv_rc == -1 && errno() == libc::EAGAIN);

        libc::close(fd);
    }
}

fn eth0_ipv4() -> Ipv4Addr {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        panic!("getifaddrs failed");
    }
    let mut fallback = None;
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
            continue;
        }
        let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        if family != libc::AF_INET {
            continue;
        }
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
        let octets = sin.sin_addr.s_addr.to_ne_bytes();
        let ip = Ipv4Addr::from(octets);
        if ip.is_loopback() {
            continue;
        }
        if name == "eth0" {
            unsafe { libc::freeifaddrs(head) };
            return ip;
        }
        fallback = Some(ip);
    }
    unsafe { libc::freeifaddrs(head) };
    fallback.expect("non-loopback IPv4 address")
}
