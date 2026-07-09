//! Small-N deterministic witness for "whole-VM release THEN cross-process
//! signal wake" — the fe895f39 skip-resume stranding red.
//!
//! `procladder_mt` at N=8 stays green because the run is too short for the
//! MT whole-VM residency lease to actually release a VM before the wake sweep
//! arrives: the parent sleeps only 1 s, so children are still vCPU-only-parked
//! (never past the SECOND completed full ≥1 s parked slice ≈2 s) when the
//! SIGUSR1 lands. This probe forces the release-then-signal ordering with a
//! FIXED small N (so it is not a residency-ceiling stress test — it is a
//! wake-path correctness test) and a LONGER parent sleep, so every child has
//! provably released its whole VM and stretched its park before it is woken.
//!
//! Why 3.2 s: the MT lease upgrades to a whole-VM release only from the SECOND
//! parked full ≥1 s slice on (the first full slice merely observes ≈1 s idle;
//! the release fires on the next full-slice tick, ≈2 s in), after which the
//! parked slice STRETCHES (2 s→4 s→8 s). 3.2 s lands the wake past the release
//! (≈2 s) AND inside the first stretched (2 s) slice — exactly the window
//! where the pre-fix skip-resume inner loop never re-dispatched the syscall,
//! so it never drained the cross-process signal ring, so a `sigwait`-shaped
//! blocked thread (whose awaited SIGUSR1 is masked, so the in-wait
//! unblocked-pending peek cannot see it) stranded the ring entry forever. The
//! fix's ring-authoritative peek breaks the inner loop back out to the
//! re-dispatch, whose dispatcher drain publishes and delivers the wake.
//!
//! Each child writes a pattern into a private mmap BEFORE blocking, blocks
//! SIGUSR1 (inherited by a sibling std::thread parked in pause(2)), and
//! consumes the wake with `sigwait(3)` — atomic against a pending-or-future
//! signal, no lost-wake window, and the sibling can never steal the
//! process-directed wake because it inherits the same block mask at spawn.
//! Once woken the main thread re-verifies its private-mmap pattern (a rebuild
//! that loses or mis-replays mappings flips a byte and the child `_exit(4)`s
//! instead of `_exit(0)`), then exits.
//!
//! Invariants encoded:
//!   * ladder_forked_all — all N forks succeeded
//!   * ladder_children_ok — every child exited 0 (woken; pattern intact)
//!
//! N defaults to 4 (PROC_LADDER_N overrides, clamped 1..64) — deliberately
//! well under the residency ceiling: this witnesses the wake path, not
//! admission pressure.
//!
//! Deterministic output only — booleans, never counts/times/pids.

use conformance_probes::report;
use std::env;

fn ladder_n() -> usize {
    env::var("PROC_LADDER_N")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(4)
        .clamp(1, 64)
}

const PAGE: usize = 4096;
const PAT_PAGES: usize = 16;

fn child_body() -> ! {
    unsafe {
        // Block SIGUSR1 FIRST: the sibling thread inherits this mask at spawn
        // (it can never steal the process-directed wake), and `sigwait` below
        // atomically consumes a pending-or-future SIGUSR1 — no pause() lost-
        // wake window, no delivery-thread ambiguity.
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
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
        std::thread::spawn(|| {
            loop {
                libc::pause();
            }
        });
        let mut sig: libc::c_int = 0;
        libc::sigwait(&set, &mut sig);
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
        // Sleep PAST the whole-VM release (≈2 s: second completed full ≥1 s
        // parked slice) AND into the first stretched (2 s) parked slice, so by
        // the time the wake sweep runs every child has actually released its
        // VM and stretched its park — the exact state the pre-fix skip-resume
        // inner loop stranded (it never re-dispatched, so it never drained the
        // xsig ring for a `sigwait`-masked awaited signal). SIGUSR1 is blocked
        // (not handled) in every child from the moment it forks, so a wake is
        // never lost even if a child is slow to reach `sigwait`.
        libc::sleep(3);
        // A little past the 2 s release + into the stretched slice (~3.2 s).
        libc::usleep(200_000);
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
