//! Negative shared-network-namespace probe. A normal bridge peer should not
//! reach another container's loopback-only listener by connecting to 127.0.0.1.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

fn main() {
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5432);
    let isolated = TcpStream::connect_timeout(&target, Duration::from_millis(500)).is_err();
    println!("sidecar_loopback_bridge_peer_isolated={isolated}");
    assert!(isolated, "ordinary bridge peer reached another container's loopback");
}
