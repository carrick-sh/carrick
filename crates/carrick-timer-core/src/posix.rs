//! Platform-NEUTRAL POSIX per-process timer registry (timer_create /
//! timer_settime / timer_gettime / timer_delete / timer_getoverrun). carrick
//! previously left this whole family ENOSYS; this module owns the kernel-side
//! bookkeeping the dispatcher's handlers consume.
//!
//! Delivery uses a sleep-fire thread per arm (the same fallback approach
//! `itimer::run_fallback` uses), keyed by the timer's `generation` counter so a
//! disarm or re-arm cleanly retires the previous thread without a kqueue
//! dependency. This sidesteps allocating a unique EVFILT_TIMER ident per dynamic
//! timer and keeps the pump side untouched; we can upgrade to the pump path
//! later if profiling shows the thread overhead.
//!
//! Only SIGEV_SIGNAL-style process delivery is implemented (the LTP probes
//! exercise this). The thread SPAWN + the actual fire action (publish signal +
//! kick) live in the backend; this module owns the spec/registry/remaining math
//! plus the generation/overrun helpers the firing thread reads.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// One POSIX timer's arm spec (`timer_settime` value/interval + the signum to
/// deliver). `si_value` carries the `sigev_value` payload for the `SI_TIMER`
/// `siginfo` (default 0; not yet plumbed through the arm path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PosixTimerSpec {
    /// Linux signum to deliver on expiry (sigev_signo).
    pub signum: i32,
    /// First expiry, in ns. 0 disarms.
    pub value_ns: u64,
    /// Repeat period in ns. 0 = one-shot.
    pub interval_ns: u64,
    /// `sigev_value` payload delivered in the `SI_TIMER` siginfo. Default 0.
    pub si_value: i64,
}

pub struct PosixTimerSlot {
    pub clock_id: i32,
    /// The current arm's spec (for replay if pump path is later wired up).
    pub spec: Mutex<PosixTimerSpec>,
    /// Host monotonic timestamp (ns since `BASE_INSTANT`) the current arm
    /// was published. `0` while disarmed.
    pub armed_at_ns: AtomicU64,
    /// Bumped on every arm/disarm; the per-arm fallback thread aborts on a
    /// mismatch so a disarm reliably retires its predecessor.
    pub generation: AtomicU64,
    /// Overrun count since the last successful expiry observation. Linux
    /// returns the COUNT of MISSED extra expiries between the actual
    /// delivery and the time the handler ran; we conservatively report 0
    /// (the probe only requires non-negative).
    pub overruns: AtomicU32,
}

impl PosixTimerSlot {
    fn new(clock_id: i32, signum: i32) -> Self {
        Self {
            clock_id,
            spec: Mutex::new(PosixTimerSpec {
                signum,
                value_ns: 0,
                interval_ns: 0,
                si_value: 0,
            }),
            armed_at_ns: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            overruns: AtomicU32::new(0),
        }
    }
}

static REGISTRY: Mutex<Option<HashMap<i32, std::sync::Arc<PosixTimerSlot>>>> = Mutex::new(None);
static NEXT_ID: AtomicI32 = AtomicI32::new(1);

fn registry() -> std::sync::MutexGuard<'static, Option<HashMap<i32, std::sync::Arc<PosixTimerSlot>>>>
{
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

fn ensure_registry<'a>(
    guard: &'a mut std::sync::MutexGuard<
        'static,
        Option<HashMap<i32, std::sync::Arc<PosixTimerSlot>>>,
    >,
) -> &'a mut HashMap<i32, std::sync::Arc<PosixTimerSlot>> {
    guard.get_or_insert_with(HashMap::new)
}

/// Monotonic-ns reference. Each arm samples `Instant::now().duration_since(*BASE_INSTANT)`
/// to publish its arm timestamp; `timer_gettime` subtracts to compute remaining.
/// `armed_at == 0` is the disarmed sentinel, so this function adds 1 ns to the
/// elapsed-ns to guarantee a freshly initialised BASE_INSTANT can't masquerade
/// as "disarmed".
static BASE_INSTANT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
fn now_ns() -> u64 {
    let base = *BASE_INSTANT.get_or_init(Instant::now);
    let elapsed = Instant::now().saturating_duration_since(base);
    u64::try_from(elapsed.as_nanos())
        .unwrap_or(u64::MAX)
        .saturating_add(1)
}

/// Allocate a new timer (no arm yet). Returns the new id.
pub fn create(clock_id: i32, signum: i32) -> i32 {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.insert(
        id,
        std::sync::Arc::new(PosixTimerSlot::new(clock_id, signum)),
    );
    id
}

/// Result of a successful POSIX-timer arm: the previous spec (`timer_settime`'s
/// `old_value`) plus the bits a backend needs to spawn its firing thread.
pub struct PosixArm {
    /// The spec in effect before this arm (Linux `old_value`).
    pub old: PosixTimerSpec,
    /// Generation stamped on this arm; the firing thread bails on a mismatch.
    pub generation: u64,
    /// Signum to publish on each expiry.
    pub signum: i32,
    /// The slot, so the backend's firing thread can check `generation` /
    /// bump `overruns` without re-locking the registry.
    pub slot: std::sync::Arc<PosixTimerSlot>,
}

/// Replace the slot's spec and bump its generation. Returns `None` for an
/// unknown id. On a non-disarm arm (`value_ns != 0`) records the arm timestamp;
/// the caller is responsible for spawning the firing thread (the publish + kick
/// is backend-specific). A `value_ns == 0` disarms; the caller skips spawning.
pub fn arm(id: i32, value_ns: u64, interval_ns: u64) -> Option<PosixArm> {
    let slot = {
        let mut guard = registry();
        let map = ensure_registry(&mut guard);
        map.get(&id).cloned()
    }?;
    let old = {
        let mut spec = slot.spec.lock().unwrap_or_else(|e| e.into_inner());
        let old = *spec;
        spec.value_ns = value_ns;
        spec.interval_ns = interval_ns;
        old
    };
    slot.overruns.store(0, Ordering::SeqCst);
    let new_gen = slot
        .generation
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    if value_ns == 0 {
        slot.armed_at_ns.store(0, Ordering::SeqCst);
    } else {
        slot.armed_at_ns.store(now_ns(), Ordering::SeqCst);
    }
    Some(PosixArm {
        old,
        generation: new_gen,
        signum: old.signum, // signum doesn't change on arm; carried from create.
        slot,
    })
}

/// Whether the firing thread for `slot`/`generation` is still the live arm.
pub fn generation_matches(slot: &PosixTimerSlot, generation: u64) -> bool {
    slot.generation.load(Ordering::SeqCst) == generation
}

/// Bump a slot's overrun counter (a periodic expiry the backend's firing thread
/// observed).
pub fn record_overrun(slot: &PosixTimerSlot) {
    slot.overruns.fetch_add(1, Ordering::SeqCst);
}

/// Linux CPU-time clocks whose POSIX timers must fire off AGGREGATE GUEST CPU
/// time, not wall-clock: `CLOCK_PROCESS_CPUTIME_ID` (2) / `CLOCK_THREAD_CPUTIME_ID`
/// (3).
fn is_cpu_clock(clock_id: i32) -> bool {
    clock_id == 2 || clock_id == 3
}

/// Drive a POSIX per-process timer's expiries on a backend firing thread. SHARED
/// by every backend (KVM/bhyve/NVMM kick+futex, the HVF wall-clock fallback, and
/// the runtime's inline arm) — the THREAD SPAWN and the per-fire action
/// (`on_fire`: publish the process signal + kick) are backend-specific; only this
/// timing loop is shared. Was copied ~4× and NONE of the copies handled
/// CPU-time clocks (they all fired off wall-clock). Branches on the timer's
/// clock: a CPU-time clock drives off the aggregate guest CPU total (so the timer
/// only advances while the guest actually burns CPU); every other clock is
/// wall-clock. `value_ns` is the first expiry, `interval_ns == 0` is one-shot.
/// Retires on a generation bump (disarm/re-arm).
pub fn run_fallback(
    slot: std::sync::Arc<PosixTimerSlot>,
    generation: u64,
    value_ns: u64,
    interval_ns: u64,
    on_fire: impl Fn(),
) {
    if is_cpu_clock(slot.clock_id) {
        run_fallback_cpu(&slot, generation, value_ns, interval_ns, &on_fire);
        return;
    }
    std::thread::sleep(Duration::from_nanos(value_ns));
    if !generation_matches(&slot, generation) {
        return;
    }
    on_fire();
    if interval_ns == 0 {
        return;
    }
    loop {
        std::thread::sleep(Duration::from_nanos(interval_ns));
        if !generation_matches(&slot, generation) {
            return;
        }
        record_overrun(&slot);
        on_fire();
    }
}

/// CPU-time POSIX timer fallback: poll the aggregate guest CPU total (mirroring
/// `itimer::run_fallback_cpu`) instead of sleeping wall-clock, so a
/// `CLOCK_PROCESS_CPUTIME_ID` timer fires off real guest CPU and not while the
/// process is idle. The previous per-backend copies fired CPU-clock timers off
/// wall-clock — too early on an idle process.
fn run_fallback_cpu(
    slot: &PosixTimerSlot,
    generation: u64,
    value_ns: u64,
    interval_ns: u64,
    on_fire: &impl Fn(),
) {
    let start = carrick_host::guest_cpu::total_ns_including_active();
    let mut due = start.saturating_add(value_ns);
    let mut fired = false;
    loop {
        if !generation_matches(slot, generation) {
            return;
        }
        let now = carrick_host::guest_cpu::total_ns_including_active();
        if now < due {
            let delay = crate::itimer::cpu_timer_recheck_delay_ns(due - now);
            std::thread::sleep(Duration::from_nanos(delay));
            continue;
        }
        if fired {
            record_overrun(slot);
        }
        on_fire();
        fired = true;
        if interval_ns == 0 {
            return;
        }
        due = now.saturating_add(interval_ns);
    }
}

/// Compute the remaining value/interval for a timer. Returns `None` for an
/// unknown id (Linux `EINVAL`).
pub fn remaining(id: i32) -> Option<(u64, u64)> {
    let slot = {
        let mut guard = registry();
        let map = ensure_registry(&mut guard);
        map.get(&id).cloned()
    }?;
    let spec = *slot.spec.lock().unwrap_or_else(|e| e.into_inner());
    let armed_at = slot.armed_at_ns.load(Ordering::SeqCst);
    if armed_at == 0 || spec.value_ns == 0 {
        // Disarmed: remaining=0 (Linux convention).
        return Some((0, spec.interval_ns));
    }
    let elapsed = now_ns().saturating_sub(armed_at);
    let remaining = spec.value_ns.saturating_sub(elapsed);
    Some((remaining, spec.interval_ns))
}

/// Remove a timer. Returns whether the id existed.
pub fn delete(id: i32) -> bool {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    if let Some(slot) = map.remove(&id) {
        // Retire any in-flight fallback thread.
        slot.generation.fetch_add(1, Ordering::SeqCst);
        true
    } else {
        false
    }
}

/// Snapshot the overrun counter for `id`. Returns `None` for an unknown id
/// (Linux `EINVAL`). Carrick conservatively reports 0; the probe only
/// requires `>= 0`.
pub fn getoverrun(id: i32) -> Option<u32> {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.get(&id).map(|s| s.overruns.load(Ordering::SeqCst))
}

/// `true` if `id` is currently in the registry.
pub fn exists(id: i32) -> bool {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.contains_key(&id)
}

/// The clock a timer was created with (Linux `timer_create` clock_id). Returns
/// 0 (CLOCK_REALTIME) for an unknown id; callers (timer_settime) validate
/// existence first, so the live path never hits the fallback. Used to convert a
/// TIMER_ABSTIME deadline to a relative interval on the right clock. (audit M4)
pub fn clock_id(id: i32) -> i32 {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.get(&id).map(|s| s.clock_id).unwrap_or(0)
}

/// Clear the whole registry; called by `reinit_after_fork` so a forked
/// child doesn't inherit the parent's timer IDs (whose fallback threads
/// died with the fork anyway).
pub fn clear() {
    let mut guard = registry();
    if let Some(map) = guard.as_mut() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The REGISTRY is a process-global static; `clear_empties_registry` wipes it
    // wholesale, so serialize all tests in this module to keep them from racing
    // each other's ids (mirrors the `itimer::tests::TEST_LOCK` idiom).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn create_arm_remaining_delete_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create(0, 14); // CLOCK_MONOTONIC=0, SIGALRM=14
        assert!(exists(id));
        let _ = arm(id, 1_000_000_000, 0);
        let (rem, interval) = remaining(id).expect("known id");
        assert!(rem > 0);
        assert_eq!(interval, 0);
        assert!(delete(id));
        assert!(!exists(id));
        assert!(remaining(id).is_none());
    }

    #[test]
    fn getoverrun_starts_at_zero() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create(0, 14);
        let _ = arm(id, 50_000_000, 0);
        assert_eq!(getoverrun(id), Some(0));
        let _ = delete(id);
    }

    #[test]
    fn clear_empties_registry() {
        // Models the fork-clear path (`host_signal::reinit_after_fork` calls
        // `posix::clear()`): an inherited timer id must NOT survive the clear, so a
        // child sees the not-found result (the syscall layer maps that to EINVAL).
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create(0, 14); // CLOCK_MONOTONIC=0, SIGALRM=14
        let _ = arm(id, 1_000_000_000, 0);
        assert!(exists(id));
        assert_eq!(getoverrun(id), Some(0));
        assert!(remaining(id).is_some());

        clear();

        assert!(!exists(id));
        assert_eq!(getoverrun(id), None);
        assert!(remaining(id).is_none());
    }
}
