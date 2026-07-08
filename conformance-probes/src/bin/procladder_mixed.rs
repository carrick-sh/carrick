//! Mixed-wait variant of `procladder_mt`: N simultaneously-alive children,
//! each TWO-threaded with DIFFERENT wait classes — a std::thread sibling
//! looping a LONG `nanosleep(3s)` (a slicing, RELEASE-SAFE park) plus the
//! main thread blocked in a pipe `read()` (an FD-BACKED park). This is the
//! standing red-first gate for the MT whole-VM residency lease's fd-backed
//! VETO: a parked fd-backed waiter must never have the process VM released
//! from under it (the fd-wait wake path has an un-root-caused wake gap when
//! the VM is released — the CPython forkserver wedge,
//! task-6-regression-attribution.md cluster B, cores cr-attr-fs.*).
//!
//! The sleeper MUST out-sleep the lease's full-slice threshold or the probe
//! is VACUOUS (re-review finding: an earlier 300 ms-loop draft never drove
//! the upgrade at all — deleting the veto kept it green). The slice-tick
//! upgrade fires only from the SECOND completed full ≥1 s parked slice, and
//! a parked slice is stretched to ≥1 s only while MORE than 1 s of guest
//! wait remains — a short sleep loop parks on 50 ms service slices forever
//! and never attempts the upgrade. With a 3 s sleep the sleeper completes a
//! full slice at ~1 s and ATTEMPTS the upgrade from its next full tick
//! (inside the parent's pre-write window), so the fd-backed main thread's
//! veto is genuinely load-bearing on every iteration.
//!
//! The parent waits past that would-be release (>2.5 s) before writing one
//! byte to every child's pipe; a child whose fd-waiter was stranded by a
//! wrongly-released VM never sees the byte. NOTE: that red manifests as a
//! HARNESS TIMEOUT (the parent's waitpid on the stranded child is
//! unbounded), not as a false boolean — acceptable, documented here. The
//! parent ignores SIGPIPE so a child that died early (closed read end)
//! degrades to clean false booleans instead of a crash-red on the wake
//! write. If/when fd-backed releases are enabled (wake gap root-caused),
//! this probe is the proof fd-waiters wake correctly.
//!
//! Invariants encoded:
//!   * ladder_forked_all — all N forks succeeded
//!   * ladder_children_ok — every child read its wake byte and exited 0
//!
//! N defaults to 8 (under the ceiling; probe gate stays green);
//! PROC_LADDER_N=160 is the over-ceiling configuration (documentation of the
//! veto's capacity cost: fd-backed children never release their VMs, so the
//! over-ceiling storm may EAGAIN-degrade or hit bounded post-fork
//! exhaustion — recorded, not gated).
//!
//! Deterministic output only — booleans, never counts/times/pids.

use conformance_probes::report;
use std::env;

fn ladder_n() -> usize {
    env::var("PROC_LADDER_N")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 1024)
}

fn child_body(read_fd: libc::c_int) -> ! {
    unsafe {
        // Slicing, release-safe sibling: a LONG 3 s nanosleep per loop
        // iteration, so it completes a full ≥1 s parked slice at ~1 s and
        // ATTEMPTS the whole-VM upgrade from its next full tick — which the
        // main thread's fd-backed read() park below must VETO. (A short
        // sleep never drives the upgrade and makes the probe vacuous — see
        // the module doc.)
        std::thread::spawn(|| loop {
            let ts = libc::timespec {
                tv_sec: 3,
                tv_nsec: 0,
            };
            libc::nanosleep(&ts, std::ptr::null_mut());
        });
        // Fd-backed main thread: block in read() until the parent's wake
        // byte arrives. EINTR is retried; EOF or an error is a failure exit.
        let mut byte = 0u8;
        loop {
            let n = libc::read(read_fd, (&raw mut byte).cast(), 1);
            if n == 1 {
                libc::_exit(0);
            }
            if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            libc::_exit(3);
        }
    }
}

fn main() {
    let n = ladder_n();
    let mut children: Vec<(i32, libc::c_int)> = Vec::with_capacity(n);
    unsafe {
        // A child that died early closes its read end; the wake write below
        // must then produce clean false booleans (EPIPE), not a SIGPIPE
        // crash-red.
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        for _ in 0..n {
            let mut fds = [-1 as libc::c_int; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                break;
            }
            let pid = libc::fork();
            if pid == 0 {
                // Child: keep only the read end.
                libc::close(fds[1]);
                child_body(fds[0]);
            }
            if pid < 0 {
                libc::close(fds[0]);
                libc::close(fds[1]);
                break;
            }
            // Parent: keep only the write end.
            libc::close(fds[0]);
            children.push((pid, fds[1]));
        }
        let forked = children.len();
        // Sit WELL past any would-be whole-VM release: the sleeper's first
        // upgrade ATTEMPT lands at its second full parked slice (~2 s), so
        // 2.6 s ensures that if the fd-backed veto were broken, the release
        // (and any stranded fd-waiter) has already happened before the wake
        // bytes go out. A stranded reader then hangs the unbounded waitpid
        // below → harness-timeout red (see the module doc).
        let ts = libc::timespec {
            tv_sec: 2,
            tv_nsec: 600_000_000,
        };
        libc::nanosleep(&ts, std::ptr::null_mut());
        for &(_, wfd) in &children {
            let b = 1u8;
            libc::write(wfd, (&raw const b).cast(), 1);
        }
        let mut exited_clean = 0usize;
        for &(pid, wfd) in &children {
            let mut status = 0i32;
            if libc::waitpid(pid, &mut status, 0) == pid
                && libc::WIFEXITED(status)
                && libc::WEXITSTATUS(status) == 0
            {
                exited_clean += 1;
            }
            libc::close(wfd);
        }
        report!(
            ladder_forked_all = forked == n,
            ladder_children_ok = exited_clean == forked,
        );
    }
}
