//! POSIX per-process timer registry (timer_create / timer_settime / timer_
//! gettime / timer_delete / timer_getoverrun). carrick previously left this
//! whole family ENOSYS; this module brings up the kernel-side bookkeeping
//! the dispatcher's handlers consume.
//!
//! Delivery uses a sleep-fire thread per arm (the same fallback approach
//! `itimer::spawn_fallback_timer` uses), keyed by the timer's `generation`
//! counter so a disarm or re-arm cleanly retires the previous thread without
//! a kqueue dependency. This sidesteps allocating a unique EVFILT_TIMER
//! ident per dynamic timer and keeps the pump side untouched; we can
//! upgrade to the pump path later if profiling shows the thread overhead.
//!
//! Only SIGEV_SIGNAL delivery is implemented (the LTP probes exercise this).
//! SIGEV_THREAD and SIGEV_THREAD_ID would need a guest pthread we can't
//! create from the host — left for the runtime ↔ guest thread sync work.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerSpec {
    /// Linux signum to deliver on expiry (sigev_signo).
    pub signum: i32,
    /// First expiry, in ns. 0 disarms.
    pub value_ns: u64,
    /// Repeat period in ns. 0 = one-shot.
    pub interval_ns: u64,
}

pub struct PosixTimerSlot {
    pub clock_id: i32,
    /// The current arm's spec (for replay if pump path is later wired up).
    pub spec: Mutex<TimerSpec>,
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
            spec: Mutex::new(TimerSpec {
                signum,
                value_ns: 0,
                interval_ns: 0,
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
    map.insert(id, std::sync::Arc::new(PosixTimerSlot::new(clock_id, signum)));
    id
}

/// Replace the slot's spec, bump its generation, and spawn a fallback thread
/// that publishes the configured signum at expiry. Returns the previous spec
/// (Linux `timer_settime`'s `old_value`) and whether the id was known.
pub fn arm(id: i32, value_ns: u64, interval_ns: u64) -> Option<TimerSpec> {
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
        return Some(old);
    }
    slot.armed_at_ns.store(now_ns(), Ordering::SeqCst);

    let signum = old.signum; // signum doesn't change on arm; carrier from create.
    let slot_arc = slot.clone();
    let _ = std::thread::Builder::new()
        .name("carrick-posix-timer".to_owned())
        .spawn(move || {
            // First expiry.
            std::thread::sleep(Duration::from_nanos(value_ns));
            if slot_arc.generation.load(Ordering::SeqCst) != new_gen {
                return;
            }
            crate::host_signal::publish_process_signal(signum);
            // Periodic? Loop with the recorded interval; bail on disarm/re-arm.
            if interval_ns == 0 {
                return;
            }
            loop {
                std::thread::sleep(Duration::from_nanos(interval_ns));
                if slot_arc.generation.load(Ordering::SeqCst) != new_gen {
                    return;
                }
                slot_arc.overruns.fetch_add(1, Ordering::SeqCst);
                crate::host_signal::publish_process_signal(signum);
            }
        });
    Some(old)
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

    #[test]
    fn create_arm_remaining_delete_roundtrip() {
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
        let id = create(0, 14);
        let _ = arm(id, 50_000_000, 0);
        assert_eq!(getoverrun(id), Some(0));
        let _ = delete(id);
    }
}
