//! Bridge TCP/UDP SO_REUSEADDR/SO_REUSEPORT bind semantics. Docker/Linux allows
//! duplicate bridge-local binds in different combinations, but the listener
//! rules differ by protocol and option.

use conformance_probes::report;
use std::ffi::CStr;
use std::net::Ipv4Addr;

fn main() {
    unsafe {
        let ip = eth0_ipv4();
        let tcp_reuseaddr = bind_pair(ip, libc::SOCK_STREAM, libc::SO_REUSEADDR);
        report!(
            tcp_reuseaddr_second_bind_ok = tcp_reuseaddr.second_bind_ok,
            tcp_reuseaddr_first_listen_ok = tcp_reuseaddr.first_listen_ok,
            tcp_reuseaddr_second_listen_eaddrinuse = tcp_reuseaddr.second_listen_errno
                == Some(libc::EADDRINUSE),
        );

        let tcp_reuseport = bind_pair(ip, libc::SOCK_STREAM, libc::SO_REUSEPORT);
        report!(
            tcp_reuseport_second_bind_ok = tcp_reuseport.second_bind_ok,
            tcp_reuseport_first_listen_ok = tcp_reuseport.first_listen_ok,
            tcp_reuseport_second_listen_ok = tcp_reuseport.second_listen_ok,
        );

        let udp_reuseaddr = bind_pair(ip, libc::SOCK_DGRAM, libc::SO_REUSEADDR);
        report!(udp_reuseaddr_second_bind_ok = udp_reuseaddr.second_bind_ok);

        let udp_reuseport = bind_pair(ip, libc::SOCK_DGRAM, libc::SO_REUSEPORT);
        report!(udp_reuseport_second_bind_ok = udp_reuseport.second_bind_ok);

        let udp_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        report!(udp_socket_ok = udp_fd >= 0);
        report!(
            udp_reuseaddr_set_ok = set_sockopt_int(udp_fd, libc::SO_REUSEADDR, 1) == 0,
            udp_reuseaddr_gets_one = get_sockopt_int(udp_fd, libc::SO_REUSEADDR) == 1,
            udp_reuseport_still_zero = get_sockopt_int(udp_fd, libc::SO_REUSEPORT) == 0,
            udp_reuseport_set_ok = set_sockopt_int(udp_fd, libc::SO_REUSEPORT, 1) == 0,
            udp_reuseport_gets_one = get_sockopt_int(udp_fd, libc::SO_REUSEPORT) == 1,
        );
        libc::close(udp_fd);
    }
}

#[derive(Default)]
struct BindPair {
    second_bind_ok: bool,
    first_listen_ok: bool,
    second_listen_ok: bool,
    second_listen_errno: Option<i32>,
}

unsafe fn bind_pair(ip: Ipv4Addr, socket_type: i32, optname: i32) -> BindPair {
    let s1 = libc::socket(libc::AF_INET, socket_type, 0);
    let s2 = libc::socket(libc::AF_INET, socket_type, 0);
    if s1 < 0 || s2 < 0 {
        close_if_open(s1);
        close_if_open(s2);
        return BindPair::default();
    }
    let _ = set_sockopt_int(s1, optname, 1);
    let _ = set_sockopt_int(s2, optname, 1);

    let mut first = sockaddr_in(ip, 0);
    let first_bind = libc::bind(
        s1,
        (&first as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    if first_bind != 0 {
        libc::close(s1);
        libc::close(s2);
        return BindPair::default();
    }
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let _ = libc::getsockname(
        s1,
        (&mut first as *mut libc::sockaddr_in).cast::<libc::sockaddr>(),
        &mut len,
    );

    let second = sockaddr_in(ip, u16::from_be(first.sin_port));
    let second_bind = libc::bind(
        s2,
        (&second as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );

    let mut result = BindPair {
        second_bind_ok: second_bind == 0,
        ..BindPair::default()
    };
    if socket_type == libc::SOCK_STREAM {
        result.first_listen_ok = libc::listen(s1, 16) == 0;
        if libc::listen(s2, 16) == 0 {
            result.second_listen_ok = true;
        } else {
            result.second_listen_errno = std::io::Error::last_os_error().raw_os_error();
        }
    }

    libc::close(s1);
    libc::close(s2);
    result
}

unsafe fn set_sockopt_int(fd: i32, optname: i32, value: i32) -> i32 {
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        optname,
        (&value as *const i32).cast::<libc::c_void>(),
        std::mem::size_of::<i32>() as libc::socklen_t,
    )
}

unsafe fn get_sockopt_int(fd: i32, optname: i32) -> i32 {
    let mut value = -1_i32;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    let rc = libc::getsockopt(
        fd,
        libc::SOL_SOCKET,
        optname,
        (&mut value as *mut i32).cast::<libc::c_void>(),
        &mut len,
    );
    if rc == 0 { value } else { -1 }
}

unsafe fn close_if_open(fd: i32) {
    if fd >= 0 {
        libc::close(fd);
    }
}

fn sockaddr_in(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
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
