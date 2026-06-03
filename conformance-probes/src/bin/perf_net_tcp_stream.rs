//! Perf probe: loopback TCP bulk throughput (TCP_STREAM), self-timed in-guest.
//! A server thread drains; the main thread sends 256 KiB chunks as fast as it
//! can for a fixed ~2s window after a short warmup, and reports the achieved
//! rate in MB/s (1 MB = 1e6 bytes). HIGHER is better. Exercises the engine's
//! bulk send/recv path — carrick's per-call bounce-buffer memcpy (net.rs) vs
//! docker's in-kernel loopback.
//!
//! Output (key=value lines, parsed by the perf gate, NOT diffed):
//!   tcp_stream_mbps=<f>  bytes=<u>  secs=<f>  nproc=<u>
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

const CHUNK: usize = 256 * 1024;
const WARMUP_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB, untimed
const WINDOW: Duration = Duration::from_secs(2);

fn nproc() -> usize {
    thread::available_parallelism().map(|n| n.get()).unwrap_or(0)
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Server: drain as fast as possible until the client hangs up.
    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept");
        let mut buf = vec![0u8; CHUNK];
        loop {
            match conn.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    let mut client = TcpStream::connect(addr).expect("connect");
    client.set_nodelay(true).ok();
    let chunk = vec![0x5Au8; CHUNK];

    // Warmup (untimed): prime socket buffers and the translation path.
    let mut warm: u64 = 0;
    while warm < WARMUP_BYTES {
        client.write_all(&chunk).expect("warmup write");
        warm += CHUNK as u64;
    }

    // Timed window: send flat-out, count bytes; TCP backpressure bounds us to
    // the effective loopback throughput.
    let start = Instant::now();
    let mut bytes: u64 = 0;
    while start.elapsed() < WINDOW {
        client.write_all(&chunk).expect("write");
        bytes += CHUNK as u64;
    }
    let secs = start.elapsed().as_secs_f64();

    drop(client);
    server.join().ok();

    let mbps = (bytes as f64) / 1.0e6 / secs;
    println!("tcp_stream_mbps={:.1}", mbps);
    println!("bytes={}", bytes);
    println!("secs={:.4}", secs);
    println!("nproc={}", nproc());
}
