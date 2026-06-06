//! Perf probe: fresh anonymous mmap churn without touching mapped pages.
//!
//! This isolates VMA creation cost. Linux should not dirty or zero physical
//! pages for untouched private anonymous mappings; Carrick should likewise
//! avoid guest-memory zero writes on fresh low-VA anonymous mmap.
//!
//! Output is `key=value` lines parsed by the perf gate:
//!   mmap_churn_total_us=<f> mappings=<u> bytes=<u> nproc=<u>

use std::thread;
use std::time::Instant;

const CHUNK: usize = 8 * 1024 * 1024;
const ITERS: usize = 64;

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn main() {
    let mut mappings = Vec::with_capacity(ITERS);

    let start = Instant::now();
    for _ in 0..ITERS {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                CHUNK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            eprintln!("mmap failed after {} mappings", mappings.len());
            std::process::exit(1);
        }
        mappings.push(ptr);
    }
    for ptr in mappings {
        let rc = unsafe { libc::munmap(ptr, CHUNK) };
        if rc != 0 {
            eprintln!("munmap failed");
            std::process::exit(1);
        }
    }
    let total_us = start.elapsed().as_secs_f64() * 1_000_000.0;

    println!("mmap_churn_total_us={total_us:.3}");
    println!("mappings={ITERS}");
    println!("bytes={}", ITERS * CHUNK);
    println!("nproc={}", nproc());
}
