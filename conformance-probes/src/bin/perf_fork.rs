//! Perf probe: raw fork() latency in a steady-state (already-up) guest, self-timed
//! in-guest. Each rep `fork()`s; the child `_exit(0)`s IMMEDIATELY (no execve, no
//! program, no work); the parent `waitpid`s. The timed span is fork + the child's
//! immediate exit + reap. LOWER is better. Unlike perf_fork_exec this deliberately
//! excludes exec + child-program startup ("runtime overhead") so it isolates the
//! FORK primitive cost carrick pays per guest fork (its ForkRebuild: stand up the
//! child's own VM), vs docker's in-kernel COW clone+wait. The container is already
//! up before the timed loop, so this answers "once a container is running, how long
//! does a fork take". Pure POSIX (libc) so it compiles+runs identically under
//! carrick(Linux) / docker(Linux) / native(macOS).
//!
//! Output (key=value lines, parsed by the perf gate, NOT diffed):
//!   fork_p50_us=<f>  fork_p95_us=<f>  fork_min_us=<f>  iters=<u>  nproc=<u>

use std::thread;
use std::time::Instant;
use std::{env, hint};

const ITERS: usize = 300;
const WARMUP: usize = 30;

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn env_usize(key: &str) -> usize {
    env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

fn resident_memory(mem_mb: usize) -> Vec<u8> {
    let bytes = mem_mb.saturating_mul(1024 * 1024);
    let mut mem = vec![0u8; bytes];
    let mut i = 0usize;
    while i < mem.len() {
        mem[i] = 1;
        i = i.saturating_add(4096);
    }
    mem
}

/// Reap `pid`, retrying through EINTR; abort the probe on any anomaly so a broken
/// fork can never masquerade as a fast sample.
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

fn main() {
    let mem_mb = env_usize("FORK_MEM_MB");
    let mem = resident_memory(mem_mb);
    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERS);
    for rep in 0..(WARMUP + ITERS) {
        let t0 = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: async-signal-safe path only — exit immediately, no work.
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
    println!("mem_mb={mem_mb}");
    println!("nproc={}", nproc());
    if !mem.is_empty() {
        hint::black_box(mem[0]);
    }
}
