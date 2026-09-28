//! Host POSIX per-process timer registry (timer_create / timer_settime /
//! timer_gettime / timer_delete / timer_getoverrun).
//!
//! Delivery uses a sleep-fire thread per arm, keyed by the timer's `generation`
//! counter so a disarm or re-arm cleanly retires the previous thread without a
//! kqueue dependency. This sidesteps allocating a unique EVFILT_TIMER ident per
//! dynamic timer and keeps the pump side untouched.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub use carrick_timer_core::posix::{OVERRUN_MAX, PosixTimerSpec};
use carrick_timer_core::{ClockKind, CpuNs, TimerSpecNs, WallNs};

pub struct PosixTimerSlot {
    pub clock_id: i32,
    /// Clock domain measured by this timer slot.
    pub clock_kind: ClockKind,
    /// Optional thread target (e.g. SIGEV_THREAD_ID). If set, expiries are
    /// directed to this specific guest tid rather than process-wide.
    pub target_tid: Option<i32>,
    /// The current arm's spec (for replay if pump path is later wired up).
    pub spec: Mutex<PosixTimerSpec>,
    /// Host monotonic timestamp (ns since `BASE_INSTANT`) the current arm
    /// was published. `0` while disarmed.
    pub armed_at_ns: AtomicU64,
    /// Bumped on every arm/disarm; the per-arm fallback thread aborts on a
    /// mismatch so a disarm reliably retires its predecessor.
    pub generation: AtomicU64,
    /// Overrun count since the last successful expiry observation.
    pub overruns: AtomicU32,
}

impl PosixTimerSlot {
    fn new(
        clock_id: i32,
        clock_kind: ClockKind,
        signum: i32,
        target_tid: Option<i32>,
        si_value: i64,
    ) -> Self {
        Self {
            clock_id,
            clock_kind,
            target_tid,
            spec: Mutex::new(PosixTimerSpec {
                signum,
                spec: TimerSpecNs::DISARM,
                si_value,
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

static BASE_INSTANT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
fn now_ns() -> u64 {
    let base = *BASE_INSTANT.get_or_init(Instant::now);
    let elapsed = Instant::now().saturating_duration_since(base);
    u64::try_from(elapsed.as_nanos())
        .unwrap_or(u64::MAX)
        .saturating_add(1)
}

/// Allocate a new timer (no arm yet) targeting the process. Returns the new id.
pub fn create(clock_id: i32, signum: i32) -> i32 {
    create_with_target(clock_id, signum, None)
}

/// Allocate a new timer (no arm yet) optionally targeting a specific thread `target_tid`
/// (e.g. from `SIGEV_THREAD_ID`). Returns the new id.
pub fn create_with_target(clock_id: i32, signum: i32, target_tid: Option<i32>) -> i32 {
    create_with_target_and_value(clock_id, signum, target_tid, 0)
}

/// Allocate a new timer with a target thread and a `sigev_value` payload.
pub fn create_with_target_and_value(
    clock_id: i32,
    signum: i32,
    target_tid: Option<i32>,
    si_value: i64,
) -> i32 {
    create_with_clock_kind(clock_id, ClockKind::Wall, signum, target_tid, si_value)
}

/// Allocate a new timer with an explicit [`ClockKind`], target thread, and `sigev_value` payload.
pub fn create_with_clock_kind(
    clock_id: i32,
    clock_kind: ClockKind,
    signum: i32,
    target_tid: Option<i32>,
    si_value: i64,
) -> i32 {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.insert(
        id,
        std::sync::Arc::new(PosixTimerSlot::new(
            clock_id, clock_kind, signum, target_tid, si_value,
        )),
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
    /// Optional thread target (from `SIGEV_THREAD_ID`).
    pub target_tid: Option<i32>,
    /// The `sigev_value` payload to deliver in `LinuxSiginfo::timer`.
    pub si_value: i64,
    /// The slot, so the backend's firing thread can check `generation` /
    /// bump `overruns` without re-locking the registry.
    pub slot: std::sync::Arc<PosixTimerSlot>,
}

/// Replace the slot's spec and bump its generation. Returns `None` for an
/// unknown id. On a non-disarm arm (`spec.value != 0`) records the arm
/// timestamp; the caller is responsible for spawning the firing thread.
pub fn arm(id: i32, spec: TimerSpecNs) -> Option<PosixArm> {
    let slot = {
        let mut guard = registry();
        let map = ensure_registry(&mut guard);
        map.get(&id).cloned()
    }?;
    let old = {
        let mut cur = slot.spec.lock().unwrap_or_else(|e| e.into_inner());
        let old = *cur;
        cur.spec = spec;
        old
    };
    slot.overruns.store(0, Ordering::SeqCst);
    let new_gen = slot
        .generation
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1);
    if spec.value == 0 {
        slot.armed_at_ns.store(0, Ordering::SeqCst);
    } else {
        slot.armed_at_ns.store(now_ns(), Ordering::SeqCst);
    }
    Some(PosixArm {
        old,
        generation: new_gen,
        signum: old.signum,
        target_tid: slot.target_tid,
        si_value: old.si_value,
        slot,
    })
}

/// Whether the firing thread for `slot`/`generation` is still the live arm.
pub fn generation_matches(slot: &PosixTimerSlot, generation: u64) -> bool {
    slot.generation.load(Ordering::SeqCst) == generation
}

/// Bump a slot's overrun counter (a periodic expiry the backend's firing thread
/// observed). Saturates at `OVERRUN_MAX`.
pub fn record_overrun(slot: &PosixTimerSlot) {
    let _ = slot
        .overruns
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < OVERRUN_MAX).then_some(n + 1)
        });
}

/// Seed a timer's overrun counter to at least `count` (saturated at OVERRUN_MAX).
pub fn seed_overrun(id: i32, count: u32) {
    let capped = count.min(OVERRUN_MAX);
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    if let Some(slot) = map.get(&id) {
        slot.overruns.fetch_max(capped, Ordering::SeqCst);
    }
}

/// Drive a POSIX per-process timer's expiries on a backend firing thread.
pub fn run_fallback(
    slot: std::sync::Arc<PosixTimerSlot>,
    generation: u64,
    spec: TimerSpecNs,
    on_fire: impl Fn(),
) {
    run_fallback_with_cpu(slot, generation, spec, None, on_fire);
}

/// Drive a POSIX per-process timer's expiries on a backend firing thread, optionally
/// using a custom CPU-time sampler (`cpu_now`) for CPU-time clocks.
pub fn run_fallback_with_cpu(
    slot: std::sync::Arc<PosixTimerSlot>,
    generation: u64,
    spec: TimerSpecNs,
    cpu_now: Option<std::sync::Arc<dyn Fn() -> Option<u64> + Send + Sync>>,
    on_fire: impl Fn(),
) {
    if slot.clock_kind.is_cpu() {
        run_fallback_cpu(&slot, generation, spec, cpu_now.as_ref(), &on_fire);
        return;
    }
    std::thread::sleep(Duration::from_nanos(spec.value));
    if !generation_matches(&slot, generation) {
        return;
    }
    on_fire();
    if spec.interval == 0 {
        return;
    }
    loop {
        std::thread::sleep(Duration::from_nanos(spec.interval));
        if !generation_matches(&slot, generation) {
            return;
        }
        record_overrun(&slot);
        on_fire();
    }
}

/// CPU-time POSIX timer fallback: poll the CPU clock total instead of sleeping wall-clock.
fn run_fallback_cpu(
    slot: &PosixTimerSlot,
    generation: u64,
    spec: TimerSpecNs,
    cpu_now: Option<&std::sync::Arc<dyn Fn() -> Option<u64> + Send + Sync>>,
    on_fire: &impl Fn(),
) {
    let sample = || -> Option<u64> {
        if let Some(sampler) = cpu_now {
            sampler()
        } else {
            None
        }
    };
    let Some(start) = sample() else {
        return;
    };
    let mut due = start.saturating_add(spec.value);
    let mut fired = false;
    loop {
        if !generation_matches(slot, generation) {
            return;
        }
        let Some(now) = sample() else {
            return;
        };
        if now < due {
            let remaining = CpuNs(due - now);
            let delay = if slot.clock_kind.is_thread_cpu() {
                WallNs(remaining.raw().clamp(1, 1_000_000))
            } else {
                carrick_timer_core::itimer::cpu_timer_recheck_delay_ns(remaining)
            };
            std::thread::sleep(Duration::from_nanos(delay.raw()));
            continue;
        }
        if fired {
            record_overrun(slot);
        }
        on_fire();
        fired = true;
        if spec.interval == 0 {
            return;
        }
        due = now.saturating_add(spec.interval);
    }
}

/// Compute the remaining value/interval for a timer. Returns `None` for an unknown id.
pub fn remaining(id: i32) -> Option<TimerSpecNs> {
    let slot = {
        let mut guard = registry();
        let map = ensure_registry(&mut guard);
        map.get(&id).cloned()
    }?;
    let spec = slot.spec.lock().unwrap_or_else(|e| e.into_inner()).spec;
    let armed_at = slot.armed_at_ns.load(Ordering::SeqCst);
    Some(carrick_timer_core::posix::remaining_time(
        spec,
        armed_at,
        now_ns(),
    ))
}

/// Remove a timer. Returns whether the id existed.
pub fn delete(id: i32) -> bool {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    if let Some(slot) = map.remove(&id) {
        slot.generation.fetch_add(1, Ordering::SeqCst);
        true
    } else {
        false
    }
}

/// Does a timer with `id` exist in the registry?
pub fn exists(id: i32) -> bool {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.contains_key(&id)
}

/// Snapshot the overrun counter for `id`. Returns `None` for an unknown id.
pub fn getoverrun(id: i32) -> Option<u32> {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.get(&id)
        .map(|s| s.overruns.load(Ordering::SeqCst).min(OVERRUN_MAX))
}

/// The clock a timer was created with (Linux `timer_create` clock_id).
pub fn clock_id(id: i32) -> i32 {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.get(&id).map(|s| s.clock_id).unwrap_or(0)
}

/// The clock domain a timer measures ([`ClockKind`]). Returns `None` for an unknown id.
pub fn clock_kind(id: i32) -> Option<ClockKind> {
    let mut guard = registry();
    let map = ensure_registry(&mut guard);
    map.get(&id).map(|s| s.clock_kind)
}

/// Clear the whole registry.
pub fn clear() {
    let mut guard = registry();
    if let Some(map) = guard.as_mut() {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_timer_bridge::TIMER_REGISTRY_TEST_LOCK as TEST_LOCK;

    #[test]
    fn create_arm_remaining_delete_roundtrip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create(0, 14);
        assert!(exists(id));
        let _ = arm(
            id,
            TimerSpecNs {
                value: 1_000_000_000,
                interval: 0,
            },
        );
        let rem = remaining(id).expect("armed timer has remaining");
        assert!(rem.value > 0);
        assert_eq!(rem.interval, 0);
        assert!(delete(id));
        assert!(!exists(id));
        assert_eq!(remaining(id), None);
    }

    #[test]
    fn clear_empties_registry() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create(0, 14);
        assert!(exists(id));
        clear();
        assert!(!exists(id));
    }

    #[test]
    fn getoverrun_starts_at_zero() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create(0, 14);
        assert_eq!(getoverrun(id), Some(0));
        delete(id);
    }

    #[test]
    fn create_with_target_carries_target_tid() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create_with_target(0, 14, Some(42));
        let armed = arm(
            id,
            TimerSpecNs {
                value: 1_000_000,
                interval: 0,
            },
        )
        .expect("arm");
        assert_eq!(armed.target_tid, Some(42));
        delete(id);
    }

    #[test]
    fn create_with_clock_kind_preserves_domain() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create_with_clock_kind(2, ClockKind::ProcessCpu, 14, None, 0);
        assert_eq!(clock_kind(id), Some(ClockKind::ProcessCpu));
        let armed = arm(
            id,
            TimerSpecNs {
                value: 1_000_000,
                interval: 0,
            },
        )
        .expect("arm");
        assert_eq!(armed.slot.clock_kind, ClockKind::ProcessCpu);
        delete(id);
    }
}
