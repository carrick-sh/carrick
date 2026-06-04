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
use std::sync::atomic::{AtomicU64, Ordering};

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
}

/// Tree-wide "a core has been taken" latch, in the SAME shared page (offset 8),
/// so at most ONE process in the whole tree spawns lldb on a deadlock — without
/// it, every stuck process self-cores at once (12 concurrent `sudo lldb` was an
/// effective fork bomb). Returns true exactly once across the tree.
fn claim_core_slot() -> bool {
    // SAFETY: the shared page is 4096 bytes; a second AtomicU64 fits at +8.
    let base = counter() as *const AtomicU64 as usize;
    let latch = unsafe { &*((base + 8) as *const AtomicU64) };
    latch
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
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
                // At most ONE process in the tree spawns lldb — otherwise every
                // stuck process self-cores at once (a fork bomb).
                if !claim_core_slot() {
                    eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: tree-wide stall ({ms}ms); another process is taking the core"
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
                        &format!("process save-core {path}"),
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
