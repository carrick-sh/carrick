//! UDP echo server for bridge and published-port Compose smoke tests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

fn main() {
    let label = std::env::var("CARRICK_PROBE_LABEL").unwrap_or_else(|_| "udp_server".to_string());
    let port = env_u16("CARRICK_PROBE_PORT", 15555);
    let expected = env_usize("CARRICK_PROBE_EXPECTS", 2);
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
        .expect("bind UDP server");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    println!("{label}_ready=true");

    let mut buf = [0_u8; 2048];
    for index in 0..expected {
        let (n, peer) = socket.recv_from(&mut buf).expect("recv datagram");
        let request = std::str::from_utf8(&buf[..n]).expect("utf8 request");
        println!("{label}_request_{index}={}", request.trim_end());
        socket.send_to(b"pong\n", peer).expect("send response");
    }
    println!("{label}_done=true");
}

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
