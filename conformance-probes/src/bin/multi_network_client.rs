//! Multi-network Compose client probe. It can assert either that a target is
//! reachable or that network-scoped name/route isolation prevents connection.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let label = std::env::var("CARRICK_PROBE_LABEL").unwrap_or_else(|_| "client".to_string());
    let target_host = std::env::var("CARRICK_PROBE_TARGET").expect("CARRICK_PROBE_TARGET");
    let target_port = env_u16("CARRICK_PROBE_PORT", 5432);
    let expect = std::env::var("CARRICK_PROBE_EXPECT").unwrap_or_else(|_| "success".to_string());

    match expect.as_str() {
        "success" => {
            let target = resolve_one(&target_host, target_port);
            println!("{label}_resolved={target}");
            let mut stream = connect_with_retry(target).unwrap_or_else(|err| {
                panic!("{label}: connect {target_host}:{target_port}: {err}")
            });
            stream.write_all(b"ping\n").expect("write request");
            let mut response = [0_u8; 5];
            stream.read_exact(&mut response).expect("read response");
            let response = std::str::from_utf8(&response)
                .expect("utf8 response")
                .trim_end()
                .to_string();
            assert_eq!(response, "pong");
            println!("{label}_connect_ok=true");
            println!("{label}_response={response}");
        }
        "failure" => {
            let reachable = (target_host.as_str(), target_port)
                .to_socket_addrs()
                .ok()
                .and_then(|addrs| {
                    addrs
                        .filter(|addr| addr.is_ipv4())
                        .find(|addr| TcpStream::connect_timeout(addr, Duration::from_millis(500)).is_ok())
                })
                .is_some();
            assert!(
                !reachable,
                "{label}: unexpectedly reached {target_host}:{target_port}"
            );
            println!("{label}_isolated=true");
        }
        other => panic!("unsupported CARRICK_PROBE_EXPECT={other:?}"),
    }
}

fn resolve_one(host: &str, port: u16) -> SocketAddr {
    (host, port)
        .to_socket_addrs()
        .expect("resolve target")
        .find(|addr| addr.is_ipv4())
        .expect("target resolves to IPv4")
}

fn connect_with_retry(target: SocketAddr) -> Result<TcpStream, std::io::Error> {
    let mut last_error = None;
    for _ in 0..1000 {
        match TcpStream::connect(target) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect retry exhausted")
    }))
}

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
