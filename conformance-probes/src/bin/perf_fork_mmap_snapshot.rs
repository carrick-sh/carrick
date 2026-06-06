//! Perf probe: fork/wait storm after a large untouched private anonymous mmap.
//!
//! This isolates fork snapshot cost for lazy-zero VMAs. The mapping is never
//! touched, so Linux should not copy or dirty physical pages, and Carrick should
//! avoid turning the virtual reservation into page-copy work before fork.
//!
//! Output is `key=value` lines parsed by the perf gate:
//!   fork_mmap_snapshot_total_us=<f>
//!   fork_mmap_snapshot_p50_us=<f>
//!   forks=<u> bytes=<u> nproc=<u>

use std::thread;
use std::time::{Duration, Instant};

const MAPPING: usize = 512 * 1024 * 1024;
const FORKS: usize = 32;

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
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

fn main() {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            MAPPING,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        eprintln!("mmap failed");
        std::process::exit(1);
    }

    let mut samples = Vec::with_capacity(FORKS);
    let total_start = Instant::now();
    for _ in 0..FORKS {
        let start = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        if pid < 0 {
            eprintln!("fork failed");
            std::process::exit(1);
        }
        wait_for_child(pid);
        samples.push(start.elapsed());
    }
    let total_us = total_start.elapsed().as_secs_f64() * 1_000_000.0;

    let rc = unsafe { libc::munmap(ptr, MAPPING) };
    if rc != 0 {
        eprintln!("munmap failed");
        std::process::exit(1);
    }

    let mut sample_us: Vec<f64> = samples
        .into_iter()
        .map(|duration: Duration| duration.as_secs_f64() * 1_000_000.0)
        .collect();
    sample_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = pct(&sample_us, 0.50);

    println!("fork_mmap_snapshot_total_us={total_us:.3}");
    println!("fork_mmap_snapshot_p50_us={p50:.3}");
    println!("forks={FORKS}");
    println!("bytes={MAPPING}");
    println!("nproc={}", nproc());
}
