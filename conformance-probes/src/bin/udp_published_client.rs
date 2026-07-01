//! UDP client for bridge and published-port Compose smoke tests.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

fn main() {
    let label = std::env::var("CARRICK_PROBE_LABEL").unwrap_or_else(|_| "udp_client".to_string());
    let target_host = std::env::var("CARRICK_PROBE_TARGET").expect("CARRICK_PROBE_TARGET");
    let target_port = env_u16("CARRICK_PROBE_PORT", 15555);
    let target = resolve_one(&target_host, target_port);
    println!("{label}_resolved={target}");

    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind UDP client");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    socket.send_to(b"ping\n", target).expect("send datagram");
    let mut buf = [0_u8; 128];
    let (n, _) = socket.recv_from(&mut buf).expect("recv response");
    let response = std::str::from_utf8(&buf[..n])
        .expect("utf8 response")
        .trim_end()
        .to_string();
    assert_eq!(response, "pong");
    println!("{label}_connect_ok=true");
    println!("{label}_response={response}");
}

fn resolve_one(host: &str, port: u16) -> SocketAddr {
    (host, port)
        .to_socket_addrs()
        .expect("resolve target")
        .find(|addr| addr.is_ipv4())
        .expect("target resolves to IPv4")
}

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
