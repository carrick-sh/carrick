//! perf_net_xclient: the macOS-HOST side of the CROSS-BOUNDARY network test.
//! Connects to 127.0.0.1:PORT (env `PORT`) — the engine-under-test's guest echo
//! server, exposed to the host (carrick: a real Darwin socket; docker: via
//! -p/vpnkit NAT) — and measures 1-byte request/response RTT and bulk echo
//! throughput across that boundary. Host-only (built native, never in a guest).
//!
//! Output (key=value): xrtt_p50_us=<f> xrtt_p95_us=<f> xstream_mbps=<f> nproc=<u>
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

const RR_WARMUP: usize = 500;
const RR_ITERS: usize = 3000;
const STREAM_SECS: f64 = 1.5;
const CHUNK: usize = 256 * 1024;

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5555);
    let addr = ("127.0.0.1", port);

    // --- RTT: 1-byte ping-pong over the cross-boundary path ---
    let mut s = TcpStream::connect(addr).expect("connect rtt");
    s.set_nodelay(true).expect("nodelay");
    let msg = [0x41u8; 1];
    let mut b = [0u8; 1];
    for _ in 0..RR_WARMUP {
        s.write_all(&msg).expect("warmup write");
        s.read_exact(&mut b).expect("warmup read");
    }
    let mut ns: Vec<u128> = Vec::with_capacity(RR_ITERS);
    for _ in 0..RR_ITERS {
        let t = Instant::now();
        s.write_all(&msg).expect("write");
        s.read_exact(&mut b).expect("read");
        ns.push(t.elapsed().as_nanos());
    }
    drop(s);
    ns.sort_unstable();
    let pct = |p: f64| -> f64 {
        let i = (((ns.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(ns.len() - 1);
        ns[i] as f64 / 1000.0
    };

    // --- STREAM: send flat-out for a fixed window; a drain thread consumes the
    // echo so the server never blocks. Measures the cross-boundary send rate. ---
    let s2 = TcpStream::connect(addr).expect("connect stream");
    s2.set_nodelay(true).ok();
    let mut sender = s2.try_clone().expect("clone");
    let mut recvr = s2;
    let stop = Arc::new(AtomicBool::new(false));
    let st = Arc::clone(&stop);
    let drain = thread::spawn(move || {
        let mut buf = vec![0u8; CHUNK];
        while !st.load(Ordering::Relaxed) {
            match recvr.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    let chunk = vec![0x5Au8; CHUNK];
    let start = Instant::now();
    let mut bytes: u64 = 0;
    while start.elapsed().as_secs_f64() < STREAM_SECS {
        if sender.write_all(&chunk).is_err() {
            break;
        }
        bytes += CHUNK as u64;
    }
    let secs = start.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    drop(sender);
    let _ = drain.join();
    let mbps = (bytes as f64) / 1.0e6 / secs;

    println!("xrtt_p50_us={:.3}", pct(0.50));
    println!("xrtt_p95_us={:.3}", pct(0.95));
    println!("xstream_mbps={:.1}", mbps);
    println!("nproc={}", nproc());
}
