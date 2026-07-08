//! Mixed-wait variant of `procladder_mt`: N simultaneously-alive children,
//! each TWO-threaded with DIFFERENT wait classes — a std::thread sibling
//! looping `nanosleep(300ms)` (a slicing, RELEASE-SAFE park) plus the main
//! thread blocked in a pipe `read()` (an FD-BACKED park). This is the standing
//! red-first gate for the MT whole-VM residency lease's fd-backed VETO: a
//! parked fd-backed waiter must never have the process VM released from under
//! it (the fd-wait wake path has an un-root-caused wake gap when the VM is
//! released — the CPython forkserver wedge, task-6-regression-attribution.md
//! cluster B, cores cr-attr-fs.*). The parent waits well past any would-be
//! slice-tick release (>2.5 s — releases upgrade at the second ≥1 s parked
//! slice) before writing one byte to every child's pipe; a child whose
//! fd-waiter was stranded by a wrongly-released VM never sees the byte and
//! the probe goes red. If/when fd-backed releases are enabled (wake gap
//! root-caused), this probe is the proof they wake correctly.
//!
//! Invariants encoded:
//!   * ladder_forked_all — all N forks succeeded
//!   * ladder_children_ok — every child read its wake byte and exited 0
//!
//! N defaults to 8 (under the ceiling; probe gate stays green);
//! PROC_LADDER_N=160 is the over-ceiling configuration (documentation of the
//! veto's capacity cost: fd-backed children never release, so over-ceiling
//! forks may EAGAIN-degrade — recorded, not gated).
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
        // Slicing, release-safe sibling: a 300 ms nanosleep loop. Each sleep
        // parks (>250 ms reclaim cutoff) but never completes a full ≥1 s
        // slice, so IT never upgrades; even if it did, the main thread's
        // fd-backed read() park below must veto the whole-VM release.
        std::thread::spawn(|| {
            loop {
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 300_000_000,
                };
                libc::nanosleep(&ts, std::ptr::null_mut());
            }
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
        // Sit WELL past any would-be whole-VM release: the slice-tick
        // upgrade needs a second ≥1 s parked slice (~2 s), so 2.6 s ensures
        // that if the fd-backed veto were broken, the release (and any
        // stranded fd-waiter) has already happened before the wake bytes go
        // out.
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
