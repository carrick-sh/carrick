//! Deadlock watchdog: when the WHOLE guest process tree stops making syscall
//! progress for `CARRICK_DEADLOCK_WATCHDOG_MS`, the stuck processes self-core
//! (via `lldb process save-core`) so a deadlock can be post-mortemed at the exact
//! moment it happens — instead of racing `lldb -p` against a transient state.
//!
//! The progress counter is PROCESS-TREE-GLOBAL: a single `u64` in a `MAP_SHARED`
//! page mmap'd before the first guest fork and inherited by every host
//! descendant, so `tick()` from ANY guest process advances it. That distinguishes
//! a single process legitimately blocked (the parent waiting on a forked child —
//! the child still ticks) from a TRUE deadlock (nobody ticks). Each process arms
//! its own watchdog thread (threads don't survive fork, so the forked child
//! re-arms in the `ForkOutcome::Child` path); a watchdog reads the shared counter
//! and, if it has not advanced for the window, self-cores ONCE and stops.
//!
//! Off unless `CARRICK_DEADLOCK_WATCHDOG_MS` is set. Diagnostic only.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// PROCESS-LOCAL "has this process ever dispatched a guest syscall?" flag (NOT
/// in the shared page — each process has its own). Only a process that has
/// actually run guest syscalls holds deadlock-relevant state worth coring; the
/// ns-supervisor and the orchestrator parent merely park in `kevent`/`poll` and
/// never `tick()`, so coring them wastes the (bounded) capture. `arm()`-ed in
/// every process, but the self-core is gated on this being `true`.
static LOCAL_TICKED: AtomicBool = AtomicBool::new(false);

/// The shared progress word, in a `MAP_SHARED` page inherited across fork.
fn counter() -> &'static AtomicU64 {
    static CELL: OnceLock<usize> = OnceLock::new();
    let addr = *CELL.get_or_init(|| {
        // SAFETY: a fresh anonymous shared page owned for the process lifetime.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Box::into_raw(Box::new(AtomicU64::new(0))) as usize;
        }
        // SAFETY: `p` is a writable page; an AtomicU64 fits at its start.
        unsafe { (*(p as *mut AtomicU64)).store(0, Ordering::SeqCst) };
        p as usize
    });
    // SAFETY: `addr` is a live AtomicU64 valid for the whole process; MAP_SHARED
    // makes it the SAME word in every host-forked descendant.
    unsafe { &*(addr as *const AtomicU64) }
}

/// Advance global progress. Called on every syscall dispatch (cheap, relaxed).
pub fn tick() {
    counter().fetch_add(1, Ordering::Relaxed);
    // Mark THIS process as a real guest dispatcher (see `LOCAL_TICKED`). A single
    // relaxed store on the hot path — cheaper than a load+branch, and idempotent.
    LOCAL_TICKED.store(true, Ordering::Relaxed);
}

/// Has this process ever dispatched a guest syscall? Gates self-core eligibility.
fn local_ticked() -> bool {
    LOCAL_TICKED.load(Ordering::Relaxed)
}

/// Tree-wide cap on how many processes self-core on a single deadlock. Default 1
/// (one stuck guest is enough to start); raise via `CARRICK_DEADLOCK_WATCHDOG_MAX_CORES`
/// to capture e.g. the stuck `go` PARENT *and* its pre-exec CHILD together. The
/// cap (plus the `local_ticked` gate) is what keeps this from being the original
/// every-stuck-process-self-cores fork bomb (12 concurrent `sudo lldb`).
fn max_cores() -> u64 {
    static CELL: OnceLock<u64> = OnceLock::new();
    *CELL.get_or_init(|| {
        std::env::var("CARRICK_DEADLOCK_WATCHDOG_MAX_CORES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&k| k > 0)
            .unwrap_or(1)
    })
}

/// Bounded tree-wide core-claim counter, in the SAME shared page (offset 8), so
/// at most `max_cores()` processes in the whole tree spawn lldb on a deadlock —
/// without a cap, every stuck process self-cores at once (12 concurrent `sudo
/// lldb` was an effective fork bomb). Returns true for the first `max_cores()`
/// callers across the tree.
fn claim_core_slot() -> bool {
    // SAFETY: the shared page is 4096 bytes; a second AtomicU64 fits at +8.
    let base = counter() as *const AtomicU64 as usize;
    let latch = unsafe { &*((base + 8) as *const AtomicU64) };
    claim_below(latch, max_cores())
}

/// Pure claim arithmetic (testable without the process-global shared page):
/// the first `max` callers get `true`, the rest `false`. `fetch_add` returns the
/// PRE-increment value, so callers see 0,1,…,max-1 → true and max,… → false.
fn claim_below(latch: &AtomicU64, max: u64) -> bool {
    latch.fetch_add(1, Ordering::SeqCst) < max
}

fn window_ms() -> Option<u64> {
    static CELL: OnceLock<Option<u64>> = OnceLock::new();
    *CELL.get_or_init(|| {
        std::env::var("CARRICK_DEADLOCK_WATCHDOG_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&ms| ms > 0)
    })
}

/// Arm THIS process's watchdog thread (idempotent per process). Call at process
/// start AND in the forked child (its inherited thread is dead). No-op unless
/// `CARRICK_DEADLOCK_WATCHDOG_MS` is set.
pub fn arm() {
    let Some(ms) = window_ms() else { return };
    // Ensure the shared counter exists before the first fork.
    let _ = counter();
    std::thread::Builder::new()
        .name("carrick-deadlock-wd".into())
        .spawn(move || {
            const STEP_MS: u64 = 250;
            let mut last = counter().load(Ordering::Relaxed);
            let mut stalled: u64 = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(STEP_MS));
                let now = counter().load(Ordering::Relaxed);
                if now != last {
                    last = now;
                    stalled = 0;
                    continue;
                }
                stalled += STEP_MS;
                if stalled < ms {
                    continue;
                }
                // No global syscall progress for the window: a true deadlock.
                let pid = unsafe { libc::getpid() };
                // Eligibility gate: only a process that has actually dispatched a
                // guest syscall holds deadlock-relevant state. The ns-supervisor
                // and orchestrator parent just park in `kevent`/`poll` and never
                // `tick()` — without this gate one of THEM can win the bounded
                // claim and core its own useless parked state, leaving the truly
                // stuck go-build guests un-cored. (Observed: a core that was only
                // `namespace::supervisor::run` in `kevent`, ring `total=0`.)
                if !local_ticked() {
                    eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: tree-wide stall ({ms}ms) but this process never dispatched a guest syscall (supervisor/orchestrator) — deferring the core to a stuck guest"
                    );
                    return;
                }
                // Bounded: only the first `max_cores()` stuck GUESTS spawn lldb —
                // otherwise every stuck process self-cores at once (a fork bomb).
                if !claim_core_slot() {
                    eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: tree-wide stall ({ms}ms); core quota reached, another guest is taking it"
                    );
                    return;
                }
                let path = format!("/tmp/deadlock-{pid}.core");
                eprintln!(
                    "DEADLOCK WATCHDOG pid={pid}: no tree-wide syscall progress for {ms}ms; self-coring to {path}"
                );
                // Self-core via lldb (NOPASSWD in sudoers). A separate host
                // process attaches, dumps a core of this (deadlocked) process,
                // and detaches — guest vCPU threads are parked but this host
                // watchdog thread runs fine and can spawn it.
                let out = std::process::Command::new("sudo")
                    .args([
                        "lldb",
                        "-p",
                        &pid.to_string(),
                        "-b",
                        "-o",
                        // modified-memory: captures dirty pages (incl. the event
                        // ring + Rust statics) but not the multi-GB clean guest
                        // window, so the core stays ~100MB and the carrick_lldb
                        // `eventring` reader works (a `stack` core misses it).
                        &format!("process save-core --style modified-memory {path}"),
                        "-o",
                        "detach",
                        "-o",
                        "quit",
                    ])
                    .output();
                match out {
                    Ok(o) => {
                        eprintln!(
                            "DEADLOCK WATCHDOG pid={pid}: lldb exit={:?}\n--- lldb stdout ---\n{}\n--- lldb stderr ---\n{}",
                            o.status.code(),
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr),
                        );
                    }
                    Err(e) => eprintln!("DEADLOCK WATCHDOG pid={pid}: lldb spawn failed: {e}"),
                }
                return; // one-shot per process
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_below_grants_exactly_max_then_denies() {
        let latch = AtomicU64::new(0);
        // Default cap of 1: first claimant cores, the rest defer.
        assert!(claim_below(&latch, 1), "1st claim should win");
        assert!(!claim_below(&latch, 1), "2nd claim should be denied");
        assert!(!claim_below(&latch, 1), "3rd claim should be denied");

        // A raised cap (e.g. capture the go PARENT + a stuck CHILD) grants exactly
        // that many across the tree, then denies — bounding the lldb fan-out.
        let latch = AtomicU64::new(0);
        assert!(claim_below(&latch, 3));
        assert!(claim_below(&latch, 3));
        assert!(claim_below(&latch, 3));
        assert!(!claim_below(&latch, 3), "4th claim past cap of 3 is denied");
    }
}
