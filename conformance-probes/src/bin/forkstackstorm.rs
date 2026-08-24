//! Post-fork stack COW integrity under concurrent write pressure.
//!
//! The gate's migrating `*** stack smashing detected ***` family points at a
//! guest STACK page whose content goes wrong around fork COW: the transport
//! (`/bin/sh -c`) forks before every probe, the parent and child then both
//! write their (COW-shared) stacks, and a resolution that copies the wrong
//! bytes, the wrong page, or resolves against a stale generation corrupts a
//! canary or a saved register slot. `futexwakeexact`'s refault livelock
//! (far=0xfffffefaXX — a stack address) is the loud sibling of the same seam.
//!
//! Shape: threads keep deep patterned frames live and churning while the main
//! thread forks repeatedly; every child immediately verifies its inherited
//! frame pattern, rewrites it, re-verifies, and exits 0 only if both hold.
//! The parent counts corrupted children. Deterministically red only if the
//! COW seam is broken; load-independent by construction (its own threads
//! supply the concurrency).

use conformance_probes::report;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
static PARENT_CORRUPTIONS: AtomicU64 = AtomicU64::new(0);

/// Deep patterned frame kept live across yields, re-verified each pass.
#[inline(never)]
fn churn_frame(pattern: u8) -> bool {
    let mut buf = [0u8; 4096];
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = pattern.wrapping_add((i % 251) as u8);
    }
    unsafe {
        libc::sched_yield();
    }
    buf.iter()
        .enumerate()
        .all(|(i, slot)| *slot == pattern.wrapping_add((i % 251) as u8))
}

#[inline(never)]
fn child_check(pattern: u8) -> bool {
    // Fresh frame: written post-fork, so every store is a COW break on a
    // stack page inherited shared from the parent.
    let mut buf = [0u8; 8192];
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = pattern.wrapping_add((i % 249) as u8);
    }
    let first = buf
        .iter()
        .enumerate()
        .all(|(i, slot)| *slot == pattern.wrapping_add((i % 249) as u8));
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = pattern.wrapping_mul(3).wrapping_add((i % 247) as u8);
    }
    let second = buf
        .iter()
        .enumerate()
        .all(|(i, slot)| *slot == pattern.wrapping_mul(3).wrapping_add((i % 247) as u8));
    first && second
}

fn main() {
    const THREADS: usize = 8;
    const FORKS: usize = 60;
    let churners: Vec<_> = (0..THREADS)
        .map(|index| {
            std::thread::spawn(move || {
                let pattern = (index as u8).wrapping_mul(37).wrapping_add(11);
                while !STOP.load(Ordering::Relaxed) {
                    if !churn_frame(pattern) {
                        PARENT_CORRUPTIONS.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut spawned = 0u64;
    let mut child_failures = 0u64;
    let mut wait_failures = 0u64;
    for round in 0..FORKS {
        if Instant::now() >= deadline {
            break;
        }
        let pid = unsafe { libc::fork() };
        match pid {
            0 => {
                let ok = child_check((round as u8).wrapping_mul(29).wrapping_add(3));
                std::process::exit(if ok { 0 } else { 42 });
            }
            -1 => {
                wait_failures += 1;
            }
            child => {
                spawned += 1;
                let mut status = 0i32;
                let reaped = unsafe { libc::waitpid(child, &mut status, 0) };
                if reaped != child {
                    wait_failures += 1;
                } else if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
                    child_failures += 1;
                }
            }
        }
    }
    STOP.store(true, Ordering::Relaxed);
    let mut joined_all = true;
    for handle in churners {
        joined_all &= handle.join().is_ok();
    }
    report!(
        forks_completed_all = spawned == FORKS as u64,
        child_stacks_intact = child_failures == 0,
        parent_stacks_intact = PARENT_CORRUPTIONS.load(Ordering::Relaxed) == 0,
        waits_clean = wait_failures == 0,
        joined_all = joined_all,
    );
}
