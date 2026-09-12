//! Guest workload for two-process contention and parallelism tests.
//!
//! Two modes:
//! - `busy <n> <ms>`: forks `n` children that spin on a monotonic clock for `ms` milliseconds and `_exit(0)`.
//!   The parent waits for all children and prints `wall_ms=<..> children=<n>`.
//! - `faulter <iters>`: maps a 64 MiB anonymous region, touches one page per 4 KiB in a loop `iters` times,
//!   unmapping and remapping each round, and prints `p50_us=<..> p99_us=<..>`.
//!
//! Bound every wait (5 s); no asserts.

use std::time::{Duration, Instant};

const REGION_SIZE: usize = 64 * 1024 * 1024; // 64 MiB
const PAGE_SIZE: usize = 4096; // 4 KiB

fn run_busy(n: usize, ms: u64) {
    let start = Instant::now();
    let mut children = Vec::with_capacity(n);
    let fork_deadline = Instant::now() + Duration::from_secs(5);

    for _ in 0..n {
        let mut pid = -1;
        while Instant::now() < fork_deadline {
            pid = unsafe { libc::fork() };
            if pid >= 0 {
                break;
            }
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err != libc::EAGAIN && err != libc::EINTR {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        if pid < 0 {
            eprintln!("fork failed: {}", std::io::Error::last_os_error());
            break;
        }

        if pid == 0 {
            // Child: spin on monotonic clock for ms milliseconds, then _exit(0)
            let child_start = Instant::now();
            let target = Duration::from_millis(ms);
            while child_start.elapsed() < target {
                core::hint::spin_loop();
            }
            unsafe {
                libc::_exit(0);
            }
        }

        children.push(pid);
    }

    // Wait for all children; bound every wait (5 s)
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    let mut reaped = 0;
    while reaped < children.len() {
        if Instant::now() >= wait_deadline {
            // Timeout: terminate remaining children
            for &pid in &children {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            break;
        }

        let mut status = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid > 0 {
            reaped += 1;
        } else if pid == 0 {
            std::thread::sleep(Duration::from_millis(1));
        } else {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if err == libc::ECHILD {
                break;
            }
            if err == libc::EINTR {
                continue;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    let wall_ms = start.elapsed().as_millis() as u64;
    println!("wall_ms={wall_ms} children={reaped}");
}

fn run_faulter(iters: usize) {
    let mut latencies_us = Vec::with_capacity(iters);

    for _ in 0..iters {
        let t0 = Instant::now();

        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                REGION_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            eprintln!("mmap failed: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }

        let mut offset = 0;
        while offset < REGION_SIZE {
            unsafe {
                let byte_ptr = (ptr as *mut u8).add(offset);
                core::ptr::write_volatile(byte_ptr, 1);
            }
            offset += PAGE_SIZE;
        }

        let unmap_rc = unsafe { libc::munmap(ptr, REGION_SIZE) };
        if unmap_rc != 0 {
            eprintln!("munmap failed: {}", std::io::Error::last_os_error());
            std::process::exit(1);
        }

        let round_us = t0.elapsed().as_micros() as u64;
        latencies_us.push(round_us);
    }

    if latencies_us.is_empty() {
        println!("p50_us=0 p99_us=0");
        return;
    }

    latencies_us.sort_unstable();
    let p50_idx = ((latencies_us.len() as f64) * 0.50).floor() as usize;
    let p99_idx = ((latencies_us.len() as f64) * 0.99).floor() as usize;
    let p50 = latencies_us[p50_idx.min(latencies_us.len() - 1)];
    let p99 = latencies_us[p99_idx.min(latencies_us.len() - 1)];

    println!("p50_us={p50} p99_us={p99}");
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = match args.next() {
        Some(m) => m,
        None => {
            eprintln!("usage: forkstorm busy <n> <ms> | forkstorm faulter <iters>");
            std::process::exit(1);
        }
    };

    match mode.as_str() {
        "busy" => {
            let n: usize = match args.next().and_then(|s| s.parse().ok()) {
                Some(v) => v,
                None => {
                    eprintln!("invalid or missing <n> for busy mode");
                    std::process::exit(1);
                }
            };
            let ms: u64 = match args.next().and_then(|s| s.parse().ok()) {
                Some(v) => v,
                None => {
                    eprintln!("invalid or missing <ms> for busy mode");
                    std::process::exit(1);
                }
            };
            run_busy(n, ms);
        }
        "faulter" => {
            let iters: usize = match args.next().and_then(|s| s.parse().ok()) {
                Some(v) => v,
                None => {
                    eprintln!("invalid or missing <iters> for faulter mode");
                    std::process::exit(1);
                }
            };
            run_faulter(iters);
        }
        other => {
            eprintln!("unknown mode: {other}");
            std::process::exit(1);
        }
    }
}
