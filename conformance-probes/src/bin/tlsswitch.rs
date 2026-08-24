//! TLS/TPIDR_EL0 and stack integrity across executor multiplexing.
//!
//! The closure gate's load-coupled churn tail shares one dominant crash
//! signature: guest `*** stack smashing detected ***` in probes that have
//! nothing else in common (signal-family, fs-family, vdso). On aarch64 the
//! stack-protector canary compares a stack slot against a TLS-resident value
//! (TPIDR_EL0-relative), so the signature is reachable two ways: a real stack
//! overwrite, or a context switch that resumes the thread with a WRONG or
//! STALE `TPIDR_EL0`. HVPatch multiplexes many logical guest threads over a
//! bounded executor pool, so every quantum boundary is a save/restore that can
//! lose the register; load only raises the switch rate.
//!
//! This probe is the discriminating instrument: more threads than executors,
//! each looping over three independent detectors —
//!   1. `mrs TPIDR_EL0` read directly, compared to the value at thread start
//!      (catches a stale restore at the exact iteration it happens);
//!   2. a stack sentinel buffer re-verified every iteration (catches a real
//!      stack overwrite, e.g. a misplaced signal frame or COW copy);
//!   3. a TLS-resident tid compared against `gettid()` (catches resuming with
//!      another thread's TLS block).
//! Yield storms and the gettid trap per iteration maximize quantum turnover.

use conformance_probes::report;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static TPIDR_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static SENTINEL_CORRUPTIONS: AtomicU64 = AtomicU64::new(0);
static TLS_TID_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static ITERATIONS: AtomicU64 = AtomicU64::new(0);

fn gettid() -> i64 {
    unsafe { libc::syscall(libc::SYS_gettid) as i64 }
}

fn read_tpidr_el0() -> u64 {
    let value: u64;
    unsafe {
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) value, options(nomem, nostack));
    }
    value
}

thread_local! {
    static TLS_TID: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}

/// One canary-shaped frame: a stack buffer written with a thread-specific
/// pattern and re-verified before return. `inline(never)` keeps the frame
/// (and its sentinel) alive across the whole window the loop spends here.
#[inline(never)]
fn sentinel_frame(pattern: u8, spin: u32) -> bool {
    let mut buf = [0u8; 256];
    for (i, slot) in buf.iter_mut().enumerate() {
        *slot = pattern.wrapping_add(i as u8);
    }
    // Dwell with the pattern live on the stack so a corruption window has
    // something to hit; the yield invites a quantum boundary mid-frame.
    for _ in 0..spin {
        unsafe {
            libc::sched_yield();
        }
    }
    buf.iter()
        .enumerate()
        .all(|(i, slot)| *slot == pattern.wrapping_add(i as u8))
}

fn worker(index: usize, deadline: Instant) {
    let tid = gettid();
    TLS_TID.with(|cell| cell.set(tid));
    let tpidr_at_start = read_tpidr_el0();
    let pattern = (index as u8).wrapping_mul(31).wrapping_add(7);
    let mut spin = 0u32;
    while Instant::now() < deadline {
        ITERATIONS.fetch_add(1, Ordering::Relaxed);
        if read_tpidr_el0() != tpidr_at_start {
            TPIDR_MISMATCHES.fetch_add(1, Ordering::Relaxed);
        }
        if !sentinel_frame(pattern, spin % 4) {
            SENTINEL_CORRUPTIONS.fetch_add(1, Ordering::Relaxed);
        }
        if TLS_TID.with(std::cell::Cell::get) != gettid() {
            TLS_TID_MISMATCHES.fetch_add(1, Ordering::Relaxed);
        }
        spin = spin.wrapping_add(1);
    }
}

fn main() {
    // More logical threads than the executor pool (bounded ~10) so every
    // quantum is contended and save/restore churn is constant.
    const THREADS: usize = 24;
    let deadline = Instant::now() + Duration::from_secs(4);
    let workers: Vec<_> = (0..THREADS)
        .map(|index| std::thread::spawn(move || worker(index, deadline)))
        .collect();
    let mut joined_all = true;
    for handle in workers {
        joined_all &= handle.join().is_ok();
    }
    report!(
        tls_tpidr_stable = TPIDR_MISMATCHES.load(Ordering::Relaxed) == 0,
        stack_sentinel_intact = SENTINEL_CORRUPTIONS.load(Ordering::Relaxed) == 0,
        tls_tid_stable = TLS_TID_MISMATCHES.load(Ordering::Relaxed) == 0,
        joined_all = joined_all,
        iterations_nonzero = ITERATIONS.load(Ordering::Relaxed) > 0,
    );
}
