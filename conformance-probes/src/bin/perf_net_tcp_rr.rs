//! Perf probe: loopback TCP request/response latency (TCP_RR), self-timed
//! in-guest. A server thread echoes 1 byte; the main thread does WARMUP+ITERS
//! round-trips over 127.0.0.1, timing each with a monotonic clock, and prints
//! its own p50/p95/min in microseconds plus the CPU count the guest sees.
//!
//! Output is `key=value` lines (parsed by tests/perf_runner.rs), NOT diffed:
//!   tcp_rr_p50_us=<f>  tcp_rr_p95_us=<f>  tcp_rr_min_us=<f>  rr_iters=<u>  nproc=<u>
//!
//! This is Topology A (server+client in one guest) — it isolates the engine's
//! loopback syscall-translation path. TCP_NODELAY is set so we measure the
//! syscall round-trip, not Nagle batching.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Instant;

const WARMUP: usize = 1000;
const ITERS: usize = 5000;

fn nproc() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
}

fn main() {
    // Bind the echo server to an ephemeral loopback port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        conn.set_nodelay(true).ok();
        let mut byte = [0u8; 1];
        // Echo until the client hangs up (read returns 0).
        loop {
            match conn.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if conn.write_all(&byte).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut client = TcpStream::connect(addr).expect("connect");
    client.set_nodelay(true).expect("nodelay");
    let msg = [0x41u8; 1];
    let mut buf = [0u8; 1];

    // Warmup (not timed): primes caches and the connection.
    for _ in 0..WARMUP {
        client.write_all(&msg).expect("warmup write");
        client.read_exact(&mut buf).expect("warmup read");
    }

    // Timed round-trips.
    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        client.write_all(&msg).expect("write");
        client.read_exact(&mut buf).expect("read");
        samples_ns.push(t0.elapsed().as_nanos());
    }

    // Close the client → server's read returns 0 → server thread exits.
    drop(client);
    server.join().ok();

    samples_ns.sort_unstable();
    let pct = |p: f64| -> f64 {
        // Nearest-rank percentile, in microseconds.
        let idx = (((samples_ns.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples_ns.len() - 1);
        samples_ns[idx] as f64 / 1000.0
    };

    println!("tcp_rr_p50_us={:.3}", pct(0.50));
    println!("tcp_rr_p95_us={:.3}", pct(0.95));
    println!("tcp_rr_min_us={:.3}", samples_ns[0] as f64 / 1000.0);
    println!("rr_iters={}", samples_ns.len());
    println!("nproc={}", nproc());
}
