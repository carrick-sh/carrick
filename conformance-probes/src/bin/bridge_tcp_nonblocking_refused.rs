//! Bridge TCP nonblocking refused-connect semantics. Event-loop based clients
//! expect a nonblocking connect to an unused bridge-local port to report
//! EINPROGRESS first, then become writable with SO_ERROR=ECONNREFUSED.

use conformance_probes::{errno, report};
use std::ffi::CStr;
use std::net::Ipv4Addr;

fn main() {
    unsafe {
        let ip = eth0_ipv4();
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK,
            0,
        );
        report!(socket_ok = fd >= 0);

        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = 65000_u16.to_be();
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        };

        let rc = libc::connect(
            fd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        report!(connect_initial_einprogress = rc == -1 && errno() == libc::EINPROGRESS);

        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let poll_rc = libc::poll(&mut pollfd, 1, 2000);
        report!(poll_writable = poll_rc == 1 && (pollfd.revents & libc::POLLOUT) != 0);

        let mut so_error: i32 = -1;
        let mut so_error_len = std::mem::size_of::<i32>() as libc::socklen_t;
        let got_so_error = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut so_error as *mut i32).cast::<libc::c_void>(),
            &mut so_error_len,
        ) == 0;
        report!(so_error_econnrefused = got_so_error && so_error == libc::ECONNREFUSED);

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
