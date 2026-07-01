//! Shared-network-namespace client probe. It expects to share the target
//! container's loopback namespace and therefore reaches the target service via
//! 127.0.0.1.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

fn main() {
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5432);
    let mut stream = connect_with_retry(target);
    stream
        .write_all(b"sidecar-ping\n")
        .expect("write sidecar request");
    let mut response = [0_u8; 13];
    stream.read_exact(&mut response).expect("read response");

    println!("sidecar_loopback_client_connect_ok=true");
    println!(
        "sidecar_loopback_client_response={}",
        std::str::from_utf8(&response)
            .expect("utf8 response")
            .trim_end()
    );
}

fn connect_with_retry(target: SocketAddr) -> TcpStream {
    let mut last_error = None;
    for _ in 0..100 {
        match TcpStream::connect(target) {
            Ok(stream) => return stream,
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    panic!("connect loopback service at {target}: {last_error:?}");
}
