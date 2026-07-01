//! Published bridge TCP probe. This binary listens on 0.0.0.0:8080 and waits
//! for the host-side harness to connect through carrick's published port.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};

fn main() {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 8080)).expect("bind published server");
    println!("bridge_publish_listener_ready=true");
    let (mut stream, _) = listener.accept().expect("accept host connection");
    let mut buf = [0_u8; 4];
    stream.read_exact(&mut buf).expect("read ping");
    stream.write_all(b"ok").expect("write ok");
    println!("bridge_publish_tcp_ok=true");
}
