//! App-level bridge UDP probe. The process binds a UDP server on all container
//! addresses, discovers its Linux-visible eth0 IPv4 address, and sends a
//! datagram to that address with send_to.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

fn main() {
    let local_ip = eth0_ipv4();
    let server = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 8080)).expect("bind server");
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("server timeout");
    let server_thread = thread::spawn(move || {
        let mut buf = [0_u8; 4];
        let (n, peer) = server.recv_from(&mut buf).expect("server recv");
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(peer.ip(), IpAddr::V4(local_ip));
        server.send_to(b"ok", peer).expect("server reply");
    });

    let client = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind client");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    let target = SocketAddr::new(IpAddr::V4(local_ip), 8080);
    client.send_to(b"ping", target).expect("client send");
    let mut reply = [0_u8; 2];
    let (n, _) = client.recv_from(&mut reply).expect("client recv");
    server_thread.join().expect("server thread");

    println!("bridge_udp_sendto_ok=true");
    println!(
        "bridge_udp_reply={}",
        std::str::from_utf8(&reply[..n]).expect("utf8 reply")
    );
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
