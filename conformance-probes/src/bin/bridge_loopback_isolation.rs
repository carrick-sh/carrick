//! Bridge negative-isolation probe. A service bound to 127.0.0.1 must be
//! reachable through loopback inside the container, but not through the bridge
//! eth0 address.

use std::ffi::CStr;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn main() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 8080)).expect("bind loopback server");
    let server_listener = listener.try_clone().expect("clone listener");
    let server = thread::spawn(move || {
        let (mut stream, _) = server_listener.accept().expect("accept loopback");
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).expect("read ping");
        stream.write_all(b"ok").expect("write ok");
    });

    let mut loopback = connect_with_retry(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
    loopback.write_all(b"ping").expect("write loopback ping");
    let mut reply = [0_u8; 2];
    loopback.read_exact(&mut reply).expect("read loopback reply");
    server.join().expect("server thread");

    // Keep the listener open here: the eth0 connect must fail because the
    // service is bound to loopback, not because there is no listener.
    let eth0_target = SocketAddr::new(IpAddr::V4(eth0_ipv4()), 8080);
    let bridge_connect_refused = TcpStream::connect_timeout(&eth0_target, Duration::from_millis(300))
        .is_err();

    println!("bridge_loopback_connect_ok={}", &reply == b"ok");
    println!("bridge_eth0_loopback_isolated={bridge_connect_refused}");
}

fn connect_with_retry(target: SocketAddr) -> TcpStream {
    let mut last_error = None;
    for _ in 0..50 {
        match TcpStream::connect(target) {
            Ok(stream) => return stream,
            Err(err) => {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    panic!("connect peer: {last_error:?}");
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
