//! Perf probe: how raw fork() latency SCALES with the forking process's thread
//! count and resident memory. Reads two env knobs, shapes the process, then times
//! fork()+child _exit(0)+reap (the fork primitive, no exec). LOWER is better.
//!
//!   FORK_THREADS=<n>   spawn n extra parked threads before forking (default 0)
//!   FORK_MEM_MB=<n>    allocate + touch n MiB (resident) before forking (default 0)
//!
//! Direct-launch transports (`carrick run-elf`, DTrace) cannot inject guest env
//! vars, so both knobs also accept positional argv: `perf_fork_scale [threads
//! [mem_mb]]`. Env wins over argv (same idiom as clonebasic). The timed loop is
//! knob-independent.
//!
//! POSIX fork only clones the calling thread; the child _exit(0)s immediately
//! (async-signal-safe), so forking a multithreaded / large-RSS process is valid.
//! Under carrick this exercises the fork-quiesce barrier across sibling vCPUs and
//! the child's ForkRebuild whose cost may scale with threads (vCPUs) and/or the
//! mapped guest footprint. vs docker's in-kernel COW clone. Pure POSIX/std so it
//! runs identically under carrick(Linux) / docker(Linux) / native(macOS).
//!
//! Output (key=value lines):
//!   fork_p50_us=<f>  fork_p95_us=<f>  fork_min_us=<f>  iters=<u>
//!   threads=<u>  mem_mb=<u>  nproc=<u>

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{env, thread};

const ITERS: usize = 100;
const WARMUP: usize = 15;

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn wait_for_child(pid: libc::pid_t) {
    let mut status = 0;
    loop {
        let got = unsafe { libc::waitpid(pid, &mut status, 0) };
        if got == pid {
            break;
        }
        if got < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR {
                continue;
            }
            eprintln!("waitpid failed errno={errno}");
            std::process::exit(1);
        }
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        eprintln!("child exited unexpectedly status={status}");
        std::process::exit(1);
    }
}

fn env_usize(key: &str) -> Option<usize> {
    env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
}

fn argv_usize(index: usize) -> Option<usize> {
    env::args()
        .nth(index)
        .and_then(|s| s.trim().parse::<usize>().ok())
}

fn main() {
    let n_threads = env_usize("FORK_THREADS")
        .or_else(|| argv_usize(1))
        .unwrap_or(0);
    let mem_mb = env_usize("FORK_MEM_MB")
        .or_else(|| argv_usize(2))
        .unwrap_or(0);

    // Resident memory: allocate mem_mb MiB and touch every page so it is actually
    // faulted-in (RSS), not just reserved. Kept alive across the whole loop.
    let mut mem: Vec<u8> = Vec::new();
    if mem_mb > 0 {
        mem = vec![0u8; mem_mb * 1024 * 1024];
        let mut i = 0;
        while i < mem.len() {
            mem[i] = 1;
            i += 4096;
        }
    }

    // Extra threads: spawn n_threads parked workers so the process has n_threads+1
    // live threads when it forks.
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(n_threads);
    for _ in 0..n_threads {
        let s = Arc::clone(&stop);
        handles.push(thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(5));
            }
        }));
    }

    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERS);
    for rep in 0..(WARMUP + ITERS) {
        let t0 = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        if pid < 0 {
            eprintln!("fork failed");
            std::process::exit(1);
        }
        wait_for_child(pid);
        let elapsed = t0.elapsed().as_nanos();
        if rep >= WARMUP {
            samples_ns.push(elapsed);
        }
    }

    // Keep mem resident until here so it is present during every fork.
    if !mem.is_empty() {
        std::hint::black_box(mem[0]);
    }
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    samples_ns.sort_unstable();
    let pct = |p: f64| -> f64 {
        let idx = (((samples_ns.len() as f64) * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples_ns.len() - 1);
        samples_ns[idx] as f64 / 1000.0
    };
    println!("fork_p50_us={:.3}", pct(0.50));
    println!("fork_p95_us={:.3}", pct(0.95));
    println!("fork_min_us={:.3}", samples_ns[0] as f64 / 1000.0);
    println!("iters={}", samples_ns.len());
    println!("threads={}", n_threads);
    println!("mem_mb={}", mem_mb);
    println!("nproc={}", nproc());
}
