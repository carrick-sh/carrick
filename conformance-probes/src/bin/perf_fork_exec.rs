//! Perf probe: process-spawn latency (the fork→exec→exit→reap path), self-timed
//! in-guest. Each rep `fork()`s; the child immediately `execve`s THIS probe's own
//! binary (via current_exe(), which is /tmp/p under the gate) with a child-marker
//! arg; the re-exec'd child detects the marker and `_exit(0)`s before doing any
//! work; the parent `waitpid`s. The timed span is the FULL end-to-end spawn cycle
//! per rep. LOWER is better. This is the true cost a fork/exec-heavy guest
//! workload pays: carrick must fork the process carrying the guest address space,
//! stand up a fresh guest for the exec'd image, and reap it — vs docker's single
//! in-kernel clone+execve+wait. Pure POSIX (libc) so it compiles+runs identically
//! under carrick(Linux) / docker(Linux) / native(macOS).
//!
//! Output (key=value lines, parsed by the perf gate, NOT diffed):
//!   fork_exec_p50_us=<f>  fork_exec_p95_us=<f>  fork_exec_min_us=<f>
//!   iters=<u>  nproc=<u>

use std::ffi::CString;
use std::ptr;
use std::thread;
use std::time::Instant;
use std::{env, hint};

const ITERS: usize = 200;
const WARMUP: usize = 20;
/// argv[1] handed to every re-exec'd child; its presence means "exit now".
const CHILD_MARKER: &str = "--carrick-forkexec-child";

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
/// spawn can never masquerade as a fast sample.
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
    // Child fast path: every re-exec'd child lands here. Detect the marker and
    // _exit(0) IMMEDIATELY — before any timing, allocation, or spawning — so the
    // child contributes only genuine exec+exit cost to the parent's timed span.
    if std::env::args().any(|a| a == CHILD_MARKER) {
        unsafe { libc::_exit(0) };
    }
    let mem_mb = env_usize("FORK_MEM_MB");
    let mem = resident_memory(mem_mb);

    // Resolve our own binary once (the exec target). Under the gate this is
    // /tmp/p; native it is bench-native's release binary. Both are absolute, so
    // execve resolves them without a PATH lookup.
    let exe = std::env::current_exe().expect("current_exe");
    let exe_c =
        CString::new(exe.as_os_str().to_string_lossy().as_bytes()).expect("exe path cstring");
    let marker_c = CString::new(CHILD_MARKER).expect("marker cstring");
    // argv = [exe, marker, NULL].
    let argv: [*const libc::c_char; 3] = [exe_c.as_ptr(), marker_c.as_ptr(), ptr::null()];
    // envp = the inherited environment, rebuilt portably (libc::environ is
    // Linux-only; macOS hides it behind _NSGetEnviron). Built ONCE here so the
    // child sees a realistic env, matching a normal fork+exec. `env_c` must
    // outlive the loop to keep the pointers in `envp` valid.
    let env_c: Vec<CString> = std::env::vars()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect();
    let mut envp: Vec<*const libc::c_char> = env_c.iter().map(|c| c.as_ptr()).collect();
    envp.push(ptr::null());

    let mut samples_ns: Vec<u128> = Vec::with_capacity(ITERS);
    for rep in 0..(WARMUP + ITERS) {
        let t0 = Instant::now();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: async-signal-safe path only — execve then _exit on failure.
            unsafe {
                libc::execve(exe_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
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
    println!("fork_exec_p50_us={:.3}", pct(0.50));
    println!("fork_exec_p95_us={:.3}", pct(0.95));
    println!("fork_exec_min_us={:.3}", samples_ns[0] as f64 / 1000.0);
    println!("iters={}", samples_ns.len());
    println!("mem_mb={mem_mb}");
    println!("nproc={}", nproc());
    if !mem.is_empty() {
        hint::black_box(mem[0]);
    }
}
