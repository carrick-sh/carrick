//! Shared-network-namespace server probe. It binds only loopback, accepts one
//! sidecar request, then stays alive briefly so a separate bridge peer can prove
//! that its own loopback does not reach this listener.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::time::Duration;

fn main() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 5432)).expect("bind loopback service");
    println!("sidecar_loopback_server_bound=true");

    let (mut stream, peer) = listener.accept().expect("accept sidecar");
    let mut request = [0_u8; 13];
    stream.read_exact(&mut request).expect("read request");
    assert_eq!(&request, b"sidecar-ping\n");
    stream
        .write_all(b"sidecar-pong\n")
        .expect("write response");
    println!("sidecar_loopback_server_peer_loopback={}", peer.ip().is_loopback());
    println!("sidecar_loopback_server_done=true");

    std::thread::sleep(Duration::from_secs(5));
}
