//! Multi-network Compose server probe. It binds wildcard TCP so Carrick should
//! register all bridge attachment IPs for this namespace.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::thread;
use std::time::Duration;

fn main() {
    let label = std::env::var("CARRICK_PROBE_LABEL").unwrap_or_else(|_| "server".to_string());
    let bridge_port = env_u16("CARRICK_PROBE_BRIDGE_PORT", 5432);
    let bridge_accepts = env_usize("CARRICK_PROBE_BRIDGE_ACCEPTS", 1);
    let loopback_port = env_u16("CARRICK_PROBE_LOOPBACK_PORT", 15432);
    let loopback_accepts = env_usize("CARRICK_PROBE_LOOPBACK_ACCEPTS", 0);
    let connect_target = std::env::var("CARRICK_PROBE_CONNECT_TARGET").ok();
    let connect_port = env_u16("CARRICK_PROBE_CONNECT_PORT", 5432);

    let bridge_label = label.clone();
    let bridge = thread::spawn(move || {
        run_listener(
            &bridge_label,
            "bridge",
            Ipv4Addr::UNSPECIFIED,
            bridge_port,
            bridge_accepts,
        );
    });

    let loopback = (loopback_accepts > 0).then(|| {
        let loopback_label = label.clone();
        thread::spawn(move || {
            run_listener(
                &loopback_label,
                "loopback",
                Ipv4Addr::LOCALHOST,
                loopback_port,
                loopback_accepts,
            );
        })
    });

    if let Some(target) = connect_target {
        let target_addr = resolve_one(&target, connect_port);
        let mut stream = connect_with_retry(target_addr)
            .unwrap_or_else(|err| panic!("{label}: connect {target}:{connect_port}: {err}"));
        stream.write_all(b"ping\n").expect("write request");
        let mut response = [0_u8; 5];
        stream.read_exact(&mut response).expect("read response");
        let response = std::str::from_utf8(&response)
            .expect("utf8 response")
            .trim_end()
            .to_string();
        assert_eq!(response, "pong");
        println!("{label}_connect_target={target}");
        println!("{label}_connect_response={response}");
    }

    bridge.join().expect("bridge listener thread");
    if let Some(loopback) = loopback {
        loopback.join().expect("loopback listener thread");
    }
    println!("{label}_server_done=true");
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
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "connect retry exhausted")
    }))
}

fn run_listener(label: &str, kind: &str, ip: Ipv4Addr, port: u16, accepts: usize) {
    let listener = TcpListener::bind((ip, port)).expect("bind listener");
    println!("{label}_{kind}_server_ready=true");
    let mut handled = 0;
    while handled < accepts {
        let (mut stream, peer) = listener.accept().expect("accept client");
        let mut request = [0_u8; 5];
        if stream.read_exact(&mut request).is_err() || &request != b"ping\n" {
            continue;
        }
        stream.write_all(b"pong\n").expect("write response");
        println!(
            "{label}_{kind}_server_peer_{handled}_loopback={}",
            peer.ip().is_loopback()
        );
        handled += 1;
    }
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
