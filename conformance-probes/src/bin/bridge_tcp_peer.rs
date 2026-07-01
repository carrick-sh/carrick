//! App-level bridge TCP probe. The process listens on all container addresses,
//! discovers its Linux-visible eth0 IPv4 address, and connects back through that
//! address. Docker assigns its own bridge IP; carrick's bridge provider reports
//! 172.31.0.2. The output stays address-free and deterministic.

use std::ffi::CStr;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn main() {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8080)).expect("bind server");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut buf = [0_u8; 4];
        stream.read_exact(&mut buf).expect("read ping");
        stream.write_all(b"ok").expect("write ok");
    });

    let target = SocketAddr::new(IpAddr::V4(eth0_ipv4()), 8080);
    let mut client = connect_with_retry(target);
    client.write_all(b"ping").expect("write ping");
    let mut reply = [0_u8; 2];
    client.read_exact(&mut reply).expect("read reply");
    server.join().expect("server thread");

    println!("bridge_tcp_connect_ok=true");
    println!(
        "bridge_tcp_reply={}",
        std::str::from_utf8(&reply).expect("utf8 reply")
    );
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
