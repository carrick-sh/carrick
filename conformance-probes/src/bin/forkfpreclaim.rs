//! FP/AVX state survives M:N vCPU-slot RECLAIM under fork + futex churn (the
//! bhyve go-build killer, reduced).
//!
//! The bhyve backend caps live vCPUs at `hw.vmm.maxcpu` (8) and RECLAIMS a
//! blocked thread's vCPU slot under contention, restoring the saved state into
//! a (possibly different) slot on wake. Two shipped bugs lived in that path:
//!
//! 1. Re-binding onto a slot id that no thread spawn ever materialized on the
//!    current VM (the LIFO free list surfaces never-used high ids — e.g. right
//!    after an execve rebuilt a fresh VM): the kernel vCPU was never
//!    `VM_ACTIVATE_CPU`d, so the FP/AVX-restore stub's `vm_run` fails
//!    rc=-1/EINVAL → `bhyve reclaim: FP/AVX restore failed` → thread death →
//!    fork-quiesce drain abort (SIGABRT).
//! 2. A reclaimed thread re-acquiring a slot while a fork quiesce is in
//!    flight waited UNBOUNDED for a lease held by a fork-parked sibling
//!    (fork-parked threads keep their leases) → the forker's stop-the-world
//!    drain deadlocked against the acquire → 10 s drain deadline → SIGABRT.
//!
//! Choreography: ONE long-lived horde (spawned once — thread-stack churn is
//! not what's under test) of yield-spinners over-subscribes the 8-slot pool
//! for the whole run, so the worker threads' per-round futex block happens
//! UNDER contention (which is what makes the runtime reclaim their vCPUs) and
//! their wake re-binds happen under the same pressure. Each round the main
//! thread also forks+reaps a child mid-block (fork quiesce vs reclaim
//! interplay). Each worker parks a distinctive AVX pattern in YMM12 before
//! every block and verifies it after — a lost/garbled restore prints
//! `ymm_bad`.
//!
//! Output (deterministic):
//!   workers_ok=<ROUNDS*WORKERS> forks_reaped=<ROUNDS>
//!   FORKFPRECLAIM_DONE
//! Any `ymm_bad round=.. worker=..` line, a missing DONE line (abort/hang), or
//! lower counts is the regression.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const ROUNDS: u32 = 30;
const WORKERS: usize = 6;
/// Enough yield-spinners to keep the 8-slot pool permanently contended (main
/// + spinners hold 6 slots; the 6 workers rotate through the remaining 2 via
/// reclaim-on-block) but NOT so many that the spinners own the whole pool and
/// the workers never run at all (spinners never block, so they never release).
const SPINNERS: usize = 5;

const SYS_FUTEX: libc::c_long = libc::SYS_futex;
const FUTEX_PRIVATE_FLAG: libc::c_int = 128;
// PRIVATE on purpose: the reclaim-on-block path under test is the in-process
// (private futex table) wait, not the cross-process shared-word path.
const FUTEX_WAIT: libc::c_int = FUTEX_PRIVATE_FLAG; // op 0 | PRIVATE
const FUTEX_WAKE: libc::c_int = 1 | FUTEX_PRIVATE_FLAG;

fn futex_wait(word: &AtomicU32, val: u32, timeout: &libc::timespec) -> libc::c_long {
    // SAFETY: raw futex syscall on a live in-process word; timeout bounds it.
    unsafe {
        libc::syscall(
            SYS_FUTEX,
            word.as_ptr(),
            FUTEX_WAIT,
            val,
            timeout as *const libc::timespec,
        )
    }
}

fn futex_wake_all(word: &AtomicU32) -> libc::c_long {
    // SAFETY: raw futex syscall on a live in-process word.
    unsafe {
        libc::syscall(
            SYS_FUTEX,
            word.as_ptr(),
            FUTEX_WAKE,
            libc::c_int::MAX,
            std::ptr::null::<libc::timespec>(),
        )
    }
}

// ── The distinctive per-thread register pattern ──────────────────────────────
//
// x86_64 with AVX: park the pattern in YMM12. The probe is built with baseline
// target features (x86-64 = SSE2), so compiler-generated code between the two
// asm blocks never touches YMM registers; only a broken hypervisor-side
// save/restore can corrupt them. Elsewhere (aarch64 lanes / no AVX): fall back
// to a trivially-preserved check so the probe still builds and the reclaim /
// fork-churn choreography (bugs 1+2 above are FP-independent aborts) still
// gates.

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn ymm12_store(pat: &[u8; 32]) {
    // SAFETY (caller): AVX present. Loads the 32-byte pattern into YMM12.
    unsafe {
        core::arch::asm!(
            "vmovdqu ymm12, [{p}]",
            p = in(reg) pat.as_ptr(),
            out("ymm12") _,
            options(nostack, readonly)
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx")]
unsafe fn ymm12_load(out: &mut [u8; 32]) {
    // SAFETY (caller): AVX present and YMM12 holds the parked pattern (written
    // by `ymm12_store` on this same thread; baseline codegen in between never
    // references YMM registers).
    unsafe {
        core::arch::asm!(
            "vmovdqu [{p}], ymm12",
            p = in(reg) out.as_mut_ptr(),
            options(nostack)
        );
    }
}

fn park_pattern(pat: &[u8; 32]) {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx") {
        // SAFETY: AVX detected.
        unsafe { ymm12_store(pat) };
        return;
    }
    let _ = pat;
}

fn pattern_survived(pat: &[u8; 32]) -> bool {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx") {
        let mut got = [0u8; 32];
        // SAFETY: AVX detected; YMM12 was parked by this thread.
        unsafe { ymm12_load(&mut got) };
        return &got == pat;
    }
    let _ = pat;
    true
}

fn main() {
    let ok = Arc::new(AtomicUsize::new(0));
    let round_gate = Arc::new(AtomicU32::new(0)); // rounds completed by main
    let ready = Arc::new(AtomicU32::new(0)); // workers parked for this round
    let stop = Arc::new(AtomicBool::new(false));
    let mut forks_reaped = 0u32;

    // Long-lived yield-spinners: over-subscribe the 8-slot vCPU pool for the
    // whole run so worker blocks/wakes happen under slot contention. Yield-spin
    // (not a pure spin_loop): a syscall-free spin never leaves the guest and
    // starves carrick's page-table-edit pause into a kick storm; sched_yield
    // keeps the slot held while visiting the run-loop top constantly.
    let spinners: Vec<_> = (0..SPINNERS)
        .map(|_| {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // SAFETY: plain sched_yield.
                    unsafe { libc::sched_yield() };
                }
            })
        })
        .collect();

    // Long-lived workers: per round, park the AVX pattern, block on the round
    // gate (surrendering the vCPU slot under the spinner pressure), verify the
    // pattern after the wake re-bind.
    let workers: Vec<_> = (0..WORKERS)
        .map(|w| {
            let gate = Arc::clone(&round_gate);
            let ready = Arc::clone(&ready);
            let ok = Arc::clone(&ok);
            std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    let mut pat = [0u8; 32];
                    for (i, b) in pat.iter_mut().enumerate() {
                        *b = (round as u8) ^ ((w as u8) << 4) ^ (i as u8) ^ 0xA5;
                    }
                    park_pattern(&pat);
                    ready.fetch_add(1, Ordering::SeqCst);
                    // Block until main finishes round `round` (gate > round).
                    // Bounded (5 s) and spurious-wake tolerant.
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 200_000_000,
                    };
                    while gate.load(Ordering::SeqCst) <= round && Instant::now() < deadline {
                        let _ = futex_wait(&gate, round, &ts);
                    }
                    if pattern_survived(&pat) {
                        ok.fetch_add(1, Ordering::SeqCst);
                    } else {
                        println!("ymm_bad round={round} worker={w}");
                    }
                }
            })
        })
        .collect();

    for round in 0..ROUNDS {
        // Wait for all workers to have parked their pattern for this round.
        let deadline = Instant::now() + Duration::from_secs(5);
        while ready.load(Ordering::SeqCst) < (round + 1) * WORKERS as u32
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(2));
        }
        // Give the blocked workers a beat to be reclaimed, then fork mid-block:
        // the quiesce must coexist with slot-less workers and their re-binds.
        std::thread::sleep(Duration::from_millis(10));
        // SAFETY: fork+_exit(0) child, immediately reaped by waitpid below.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // SAFETY: forked child exits without touching the runtime.
            unsafe { libc::_exit(0) };
        }
        if pid > 0 {
            let mut status = 0;
            // SAFETY: reaping our own direct child.
            if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
                forks_reaped += 1;
            }
        }
        // Complete the round: open the gate and wake the workers (their
        // re-binds — possibly onto never-yet-materialized slot ids — happen
        // here, under the spinner pressure).
        round_gate.store(round + 1, Ordering::SeqCst);
        let _ = futex_wake_all(&round_gate);
    }

    for t in workers {
        let _ = t.join();
    }
    stop.store(true, Ordering::SeqCst);
    for t in spinners {
        let _ = t.join();
    }

    println!(
        "workers_ok={} forks_reaped={forks_reaped}",
        ok.load(Ordering::SeqCst)
    );
    println!("FORKFPRECLAIM_DONE");
}
