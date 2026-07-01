//! Docker host-gateway probe for Carrick bridge networking.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

fn main() {
    let label = std::env::var("CARRICK_PROBE_LABEL").unwrap_or_else(|_| "host_gateway".to_string());
    let host =
        std::env::var("CARRICK_PROBE_HOST").unwrap_or_else(|_| "host.docker.internal".to_string());
    let port = env_u16("CARRICK_PROBE_PORT");
    let expected_gateway =
        std::env::var("CARRICK_PROBE_EXPECT_GATEWAY").unwrap_or_else(|_| "172.31.0.1".to_string());
    let expected_gateway: Ipv4Addr = expected_gateway.parse().expect("expected gateway IPv4");

    let resolved = resolve_one(&host, port);
    println!("{label}_resolved={resolved}");
    assert_eq!(
        resolved.ip(),
        IpAddr::V4(expected_gateway),
        "{label}: {host} should resolve to bridge gateway"
    );

    let mut stream =
        connect_with_retry(resolved).unwrap_or_else(|err| panic!("{label}: connect {host}: {err}"));
    stream
        .write_all(b"host-gateway-ping\n")
        .expect("write request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read response");
    assert_eq!(response, "host-gateway-pong\n");
    println!("{label}_connect_ok=true");
    println!("{label}_response={}", response.trim_end());
}

fn resolve_one(host: &str, port: u16) -> SocketAddr {
    (host, port)
        .to_socket_addrs()
        .expect("resolve host gateway")
        .find(|addr| addr.is_ipv4())
        .expect("host gateway resolves to IPv4")
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

fn env_u16(name: &str) -> u16 {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be a u16"))
}
