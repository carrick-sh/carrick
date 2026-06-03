//! perf_net_xserver: a minimal TCP echo server for the CROSS-BOUNDARY network
//! test. The GUEST binds a port that a macOS-HOST client connects to — under
//! carrick the guest bind becomes a real Darwin host socket (directly reachable
//! at 127.0.0.1:PORT, no port-publish); under Docker the same is reached only
//! via `-p`/vpnkit NAT across the VM boundary. Binds 0.0.0.0:PORT (env `PORT`,
//! default 5555), listens, and echoes each connection until the peer closes,
//! then accepts the next. Runs until killed. Prints one readiness line so the
//! runner can detect "listening" (it also poll-connects to be sure).
use std::io::{stdout, Read, Write};
use std::net::TcpListener;

fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5555);
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    println!("xserver_listening={port}");
    let _ = stdout().flush();
    for conn in listener.incoming() {
        let Ok(mut conn) = conn else { continue };
        conn.set_nodelay(true).ok();
        let mut buf = [0u8; 65536];
        loop {
            match conn.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if conn.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    }
}
