//! Perf probe: the HVF trap+dispatch FLOOR. Times a raw `getpid` syscall
//! (Linux aarch64 nr 172) in a tight loop — carrick services it from cached
//! process state with ~zero host syscalls, so the measured latency is the
//! irreducible cost of one guest→host round trip: the VM exit, carrick's
//! dispatch decode, and the VM entry. This is the floor ANY guest syscall
//! (including stat) pays on top of its real work; it bounds how close a
//! syscall-side optimization can get to native. LOWER is better.
//!
//! Raw `syscall(172)` (not `getpid()`) so glibc/musl's pid cache can't elide
//! the trap. Output (key=value, parsed by the perf gate, NOT diffed):
//!   trap_p50_us=<f>  trap_p95_us=<f>  trap_min_us=<f>  iters=<u>
use std::time::Instant;

const ITERS: usize = 20000;
const WARMUP: usize = 2000;

fn main() {
    // aarch64 Linux: __NR_getpid = 172. carrick answers from cached creds.
    let getpid = || unsafe { libc::syscall(172) };

    for _ in 0..WARMUP {
        let _ = getpid();
    }
    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        let _ = getpid();
        samples_ns.push(t0.elapsed().as_nanos());
    }
    samples_ns.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = (((samples_ns.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples_ns.len() - 1);
        samples_ns[idx] as f64 / 1000.0
    };
    println!("trap_p50_us={:.3}", pct(0.50));
    println!("trap_p95_us={:.3}", pct(0.95));
    println!("trap_min_us={:.3}", samples_ns[0] as f64 / 1000.0);
    println!("iters={}", samples_ns.len());
}
