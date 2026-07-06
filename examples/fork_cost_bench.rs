//! Isolate macOS fork() cost as a function of the process's mapped footprint.
//! This bench times fork() alone (child _exits immediately, parent waitpid) with
//! 0, then N large touched mappings, to see how fork cost scales with resident
//! mapped memory. It measures ONE primitive (host libc::fork of a process
//! carrying a large address space); it is NOT the end-to-end guest process-spawn
//! cost.
//!
//! NOTE: the historical "~10.8ms per fork+exec" claim once carried here is
//! SUPERSEDED and disproven — current measurements show host fork() ~0.5ms flat,
//! full HVF VM lifecycle 0.061ms, cold vcpu entry 0.022ms. The authoritative,
//! reproducible end-to-end fork/exec process-spawn number now lives in the
//! differential perf gate: conformance-probes/src/bin/perf_fork_exec.rs
//! (workload "fork_exec", metric fork_exec_p50_us), run via `just bench`. Keep
//! this example only as a fork-primitive isolator, not a source of conclusions.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(unix)]
fn time_fork(label: &str, iters: u32) {
    use std::time::Instant;
    let mut total = std::time::Duration::ZERO;
    for _ in 0..iters {
        let t0 = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        total += t0.elapsed();
    }
    println!(
        "{label}: {:.3} ms/fork+wait (n={iters})",
        total.as_secs_f64() * 1e3 / iters as f64
    );
}

#[cfg(unix)]
fn main() {
    time_fork("baseline (small heap)", 200);

    // Touch large anonymous regions to give the process a real RSS, like the
    // guest's heap/mmap windows.
    let sizes_mb = [64usize, 256, 640];
    let mut held: Vec<Vec<u8>> = Vec::new();
    for mb in sizes_mb {
        let mut v = vec![0u8; mb * 1024 * 1024];
        // Touch every page so it's resident (COW must set up real PTEs).
        for i in (0..v.len()).step_by(4096) {
            v[i] = 1;
        }
        held.push(v);
        let total_mb: usize = sizes_mb.iter().take(held.len()).sum();
        time_fork(&format!("with ~{total_mb} MiB touched"), 100);
    }
}

#[cfg(not(unix))]
fn main() {}
