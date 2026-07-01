//! Compose-shaped bridge server probe. It listens on the container's eth0
//! address and responds like a tiny backing service.

use std::ffi::CStr;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};

fn main() {
    let ip = eth0_ipv4();
    let listener = TcpListener::bind((ip, 5432)).expect("bind service");
    println!("bridge_compose_server_ip={ip}");
    println!("bridge_compose_server_ready=true");

    let (mut stream, peer) = listener.accept().expect("accept client");
    let mut request = [0_u8; 5];
    stream.read_exact(&mut request).expect("read query");
    assert_eq!(&request, b"ping\n");
    stream.write_all(b"pong\n").expect("write response");
    let peer_is_bridge = matches!(peer.ip(), IpAddr::V4(peer_ip) if !peer_ip.is_loopback());
    println!("bridge_compose_server_peer_is_bridge={peer_is_bridge}");
    println!(
        "bridge_compose_server_peer_is_distinct={}",
        peer.ip() != IpAddr::V4(ip)
    );
    println!("bridge_compose_server_done=true");
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
