//! Multi-threaded variant of `procladder`: N simultaneously-alive children,
//! each TWO-threaded (a std::thread sibling parked in pause(2) plus the main
//! thread), all blocked. Under carrick/HVF a multi-threaded process's blocking
//! park historically destroyed only the vCPU (`reclaim_park`), keeping one HVF
//! VM alive per blocked process — so >127 such children exhaust the per-VM
//! slot budget (E4). This probe is the red-first gate for the last-unparked
//! whole-VM residency lease: green requires blocked MT processes to release
//! their VM like single-threaded ones already do.
//!
//! Each child also writes a pattern into a private mmap BEFORE blocking and
//! verifies it after waking, so a VM rebuild that loses or mis-replays
//! mappings turns a boolean false instead of a silent pass.
//!
//! Invariants encoded:
//!   * ladder_forked_all — all N forks succeeded
//!   * ladder_children_ok — every child exited 0 (pattern intact, sibling joined)
//!
//! N defaults to 8 (under the ceiling; probe gate stays green);
//! PROC_LADDER_N=160 is the over-ceiling gate configuration.
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

const PAGE: usize = 4096;
const PAT_PAGES: usize = 16;

fn child_body() -> ! {
    unsafe {
        let pat = libc::mmap(
            std::ptr::null_mut(),
            PAT_PAGES * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if pat == libc::MAP_FAILED {
            libc::_exit(3);
        }
        for i in 0..PAT_PAGES {
            *pat.cast::<u8>().add(i * PAGE) = (i as u8) ^ 0x5a;
        }
        // Sibling thread: parks in pause() until the process is SIGKILLed.
        std::thread::spawn(|| loop {
            libc::pause();
        });
        // Main thread: block in an indefinite sigtimedwait-shaped wait via
        // pause(); the parent SIGKILLs us. If a SIGCONT-style wake ever
        // returns from pause, re-verify the pattern and block again.
        loop {
            libc::pause();
            for i in 0..PAT_PAGES {
                if *pat.cast::<u8>().add(i * PAGE) != (i as u8) ^ 0x5a {
                    libc::_exit(4);
                }
            }
        }
    }
}

fn main() {
    let n = ladder_n();
    let mut pids: Vec<i32> = Vec::with_capacity(n);
    unsafe {
        for _ in 0..n {
            let pid = libc::fork();
            if pid == 0 {
                child_body();
            }
            if pid < 0 {
                break;
            }
            pids.push(pid);
        }
        let forked = pids.len();
        // Let every child reach its blocked state before the kill sweep, so
        // the probe actually exercises N simultaneously-BLOCKED MT processes.
        libc::sleep(1);
        for &pid in &pids {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut reaped_killed = 0usize;
        for &pid in &pids {
            let mut status = 0i32;
            if libc::waitpid(pid, &mut status, 0) == pid
                && libc::WIFSIGNALED(status)
                && libc::WTERMSIG(status) == libc::SIGKILL
            {
                reaped_killed += 1;
            }
        }
        report!(
            ladder_forked_all = forked == n,
            ladder_children_ok = reaped_killed == forked,
        );
    }
}
