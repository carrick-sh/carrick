//! Isolate macOS fork() cost as a function of the process's mapped footprint.
//! carrick's per-fork+exec overhead (~10.8ms) is dominated by the fork-pre ->
//! fork-post window; HVF VM lifecycle is <0.2ms, so the suspect is libc::fork()
//! of a process carrying the guest address space. This bench times fork()
//! (child _exits immediately, parent waitpid) with 0, then N large touched
//! mappings, to see how fork cost scales with resident mapped memory.
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
