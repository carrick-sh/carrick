//! Multi-threaded variant of `procladder`: N simultaneously-alive children,
//! each TWO-threaded (a std::thread sibling parked in pause(2) plus the main
//! thread), all blocked. Under carrick/HVF a multi-threaded process's blocking
//! park historically destroyed only the vCPU (`reclaim_park`), keeping one HVF
//! VM alive per blocked process — so >127 such children exhaust the per-VM
//! slot budget (E4). This probe is the red-first gate for the last-unparked
//! whole-VM residency lease: green requires blocked MT processes to release
//! their VM like single-threaded ones already do.
//!
//! Each child writes a pattern into a private mmap BEFORE blocking, then both
//! threads block in pause(2). The parent WAKES every child with SIGUSR1 —
//! rather than SIGKILLing them — so the probe actually exercises the
//! wake-side VM rebuild that the residency lease adds (waking >127
//! concurrently-blocked children also stresses rebuild admission). Each
//! child's main thread returns from pause() on the signal, re-verifies its
//! private-mmap pattern (a rebuild that loses or mis-replays mappings flips a
//! byte and the child calls `_exit(4)` instead of `_exit(0)`), and exits
//! cleanly. The sibling thread stays parked in pause() and is reaped with the
//! process.
//!
//! Invariants encoded:
//!   * ladder_forked_all — all N forks succeeded
//!   * ladder_children_ok — every child exited 0 (pattern intact after wake)
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

extern "C" fn on_usr1(_sig: libc::c_int) {}

fn child_body() -> ! {
    unsafe {
        // Install an empty SIGUSR1 handler FIRST so pause() returns on wake
        // instead of the default terminate action.
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_usr1 as usize;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());

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
        // Sibling thread: parks in pause() until woken/reaped with the process.
        std::thread::spawn(|| loop {
            libc::pause();
        });
        // Main thread: block until the parent's SIGUSR1 wakes us.
        libc::pause();
        // Woken: re-verify the pattern survived (a VM rebuild that loses or
        // mis-replays mappings flips a byte here).
        for i in 0..PAT_PAGES {
            if *pat.cast::<u8>().add(i * PAGE) != (i as u8) ^ 0x5a {
                libc::_exit(4);
            }
        }
        libc::_exit(0);
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
        // Let every child reach its blocked state (and finish installing its
        // SIGUSR1 handler) before the wake sweep, so the probe actually
        // exercises N simultaneously-BLOCKED MT processes and guards against
        // the signal landing before the handler exists.
        libc::sleep(1);
        for &pid in &pids {
            libc::kill(pid, libc::SIGUSR1);
        }
        let mut exited_clean = 0usize;
        for &pid in &pids {
            let mut status = 0i32;
            if libc::waitpid(pid, &mut status, 0) == pid
                && libc::WIFEXITED(status)
                && libc::WEXITSTATUS(status) == 0
            {
                exited_clean += 1;
            }
        }
        report!(
            ladder_forked_all = forked == n,
            ladder_children_ok = exited_clean == forked,
        );
    }
}
