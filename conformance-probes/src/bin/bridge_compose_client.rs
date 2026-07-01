//! Compose-shaped bridge client probe. It resolves the backing service by its
//! Docker Compose service name.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let target = ("db", 5432)
        .to_socket_addrs()
        .expect("resolve db service")
        .find(|addr| addr.is_ipv4())
        .expect("db resolves to IPv4");
    let mut stream = connect_with_retry(target);
    stream.write_all(b"ping\n").expect("write query");
    let mut response = [0_u8; 5];
    stream.read_exact(&mut response).expect("read response");

    println!("bridge_compose_client_connect_ok=true");
    println!(
        "bridge_compose_client_response={}",
        std::str::from_utf8(&response).expect("utf8 response").trim_end()
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
    panic!("connect service at {target}: {last_error:?}");
}
