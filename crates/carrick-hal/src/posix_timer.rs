//! Host POSIX per-process timer registry (timer_create / timer_settime /
//! timer_gettime / timer_delete / timer_getoverrun).
//!
//! Delivery uses a sleep-fire thread per arm, keyed by the timer's `generation`
//! counter so a disarm or re-arm cleanly retires the previous thread without a
//! kqueue dependency. This sidesteps allocating a unique EVFILT_TIMER ident per
//! dynamic timer and keeps the pump side untouched.
//!
//! Every arm (`timer_settime`, including a disarm) and `timer_delete` runs
//! under the slot's [`TransitionGate`], and a firing thread delivers only
//! through `fire_if_current`, which checks its generation, charges any
//! overrun and runs the delivery callback inside ONE gate hold. Once an arm or
//! delete returns, no firing thread of a superseded generation delivers or
//! touches the slot (Linux: no expiry of the old setting generates a signal
//! after `timer_settime`/`timer_delete` returns).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub use carrick_timer_core::posix::{OVERRUN_MAX, PosixTimerSpec};
use carrick_timer_core::{ClockKind, CpuNs, FireOutcome, TimerSpecNs, TransitionGate, WallNs};

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
    /// Serializes arm/disarm/delete with firing-thread delivery; see the
    /// module docs.
    gate: TransitionGate,
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
            gate: TransitionGate::new(),
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
///
/// Returns only after any in-flight delivery of the previous setting has
/// finished; no firing thread of the previous generation delivers afterwards.
pub fn arm(id: i32, spec: TimerSpecNs) -> Option<PosixArm> {
    let slot = {
        let mut guard = registry();
        let map = ensure_registry(&mut guard);
        map.get(&id).cloned()
    }?;
    let gate = slot.gate.hold();
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
    drop(gate);
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
/// A snapshot only: delivery must go through `fire_if_current`.
pub fn generation_matches(slot: &PosixTimerSlot, generation: u64) -> bool {
    slot.generation.load(Ordering::SeqCst) == generation
}

/// Deliver one expiry for the firing thread of arm `generation`: if that arm
/// is still live, charge `overrun` (a periodic expiry after the first) and
/// run `on_fire`, all under the slot gate, so an arm or delete that returned
/// before this call is never followed by a delivery or an overrun charge for
/// the superseded setting. Returns [`FireOutcome::Retired`] when the arm is
/// gone or `spec` was a one-shot (just delivered), else
/// [`FireOutcome::Fired`]. `on_fire` must not re-enter `arm`/`delete` for this
/// timer.
fn fire_if_current(
    slot: &PosixTimerSlot,
    generation: u64,
    spec: TimerSpecNs,
    overrun: bool,
    on_fire: &impl Fn(),
) -> FireOutcome {
    let _gate = slot.gate.hold();
    if !generation_matches(slot, generation) {
        return FireOutcome::Retired;
    }
    if overrun {
        record_overrun(slot);
    }
    on_fire();
    if spec.interval == 0 {
        FireOutcome::Retired
    } else {
        FireOutcome::Fired
    }
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
/// `cpu_now` samples the timer's CPU clock and must be `Some` for a CPU-clock
/// timer (`slot.clock_kind.is_cpu()`); a `None` or vanished sample ends the
/// timer. Wall-clock timers ignore it.
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
    let mut overrun = false;
    while fire_if_current(&slot, generation, spec, overrun, &on_fire) == FireOutcome::Fired {
        overrun = true;
        std::thread::sleep(Duration::from_nanos(spec.interval));
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
        // The sample above ran outside the gate; the generation check, the
        // overrun charge and the delivery happen in one gate hold.
        if fire_if_current(slot, generation, spec, fired, on_fire) != FireOutcome::Fired {
            return;
        }
        fired = true;
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
///
/// Returns only after any in-flight delivery has finished; no firing thread
/// of the deleted timer delivers afterwards.
pub fn delete(id: i32) -> bool {
    let removed = {
        let mut guard = registry();
        let map = ensure_registry(&mut guard);
        map.remove(&id)
    };
    // Retire under the slot gate, outside the registry lock: a firing thread
    // holds the gate across its delivery callback, which must not be able to
    // stall unrelated registry operations.
    let Some(slot) = removed else {
        return false;
    };
    let _gate = slot.gate.hold();
    slot.generation.fetch_add(1, Ordering::SeqCst);
    true
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

    /// A CPU-clock sampler for the fallback worker that replays `script`
    /// (one value per sample) and PARKS on sample `park_at` -- after the
    /// worker's generation check, before its expiry decision -- until the test
    /// has deleted or re-armed the timer. Forces the arm/delete-vs-fire
    /// interleaving deterministically instead of racing a spawned thread.
    struct ScriptedCpu {
        script: Vec<u64>,
        park_at: usize,
        next: std::sync::atomic::AtomicUsize,
        parked: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        resume: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    const PARK_BOUND: Duration = Duration::from_secs(5);

    impl ScriptedCpu {
        fn sample(&self) -> Option<u64> {
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            if index == self.park_at {
                let parked = self
                    .parked
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                let resume = self
                    .resume
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let (Some(parked), Some(resume)) = (parked, resume) {
                    parked.send(()).expect("test observes the parked worker");
                    resume
                        .recv_timeout(PARK_BOUND)
                        .expect("test resumes the parked worker");
                }
            }
            self.script.get(index).or(self.script.last()).copied()
        }
    }

    /// Spawn a CPU-clock fallback worker for `armed` whose sample `park_at`
    /// parks; returns once it is parked, with the fire counter, the resume
    /// sender and the worker handle.
    fn spawn_parked_cpu_worker(
        armed: &PosixArm,
        spec: TimerSpecNs,
        script: Vec<u64>,
        park_at: usize,
    ) -> (
        std::sync::Arc<AtomicU32>,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let (parked_tx, parked_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let sampler = std::sync::Arc::new(ScriptedCpu {
            script,
            park_at,
            next: std::sync::atomic::AtomicUsize::new(0),
            parked: Mutex::new(Some(parked_tx)),
            resume: Mutex::new(Some(resume_rx)),
        });
        let cpu_now: std::sync::Arc<dyn Fn() -> Option<u64> + Send + Sync> =
            std::sync::Arc::new(move || sampler.sample());
        let fires = std::sync::Arc::new(AtomicU32::new(0));
        let counted = std::sync::Arc::clone(&fires);
        let slot = armed.slot.clone();
        let generation = armed.generation;
        let runner = std::thread::spawn(move || {
            run_fallback_with_cpu(slot, generation, spec, Some(cpu_now), move || {
                counted.fetch_add(1, Ordering::SeqCst);
            });
        });
        parked_rx
            .recv_timeout(PARK_BOUND)
            .expect("fallback worker reaches its parking CPU sample");
        (fires, resume_tx, runner)
    }

    /// Arm a one-shot process-CPU timer, park its worker at the expiry
    /// decision with the due point reached, run `retire`, resume, and return
    /// how many expiries the worker delivered.
    fn cpu_one_shot_fires_after(retire: impl FnOnce(i32)) -> u32 {
        let id = create_with_clock_kind(2, ClockKind::ProcessCpu, 27, None, 0);
        let spec = TimerSpecNs {
            value: 1_000,
            interval: 0,
        };
        let armed = arm(id, spec).expect("arm");
        // Sample 0 is the arm's start point; sample 1 (parked) reports the
        // CPU total exactly at the due point.
        let (fires, resume, runner) = spawn_parked_cpu_worker(&armed, spec, vec![0, 1_000], 1);
        retire(id);
        resume.send(()).expect("worker still parked");
        runner.join().expect("fallback worker terminates");
        let _ = delete(id);
        fires.load(Ordering::SeqCst)
    }

    #[test]
    fn cpu_fallback_does_not_fire_after_timer_delete_returns() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let fires = cpu_one_shot_fires_after(|id| {
            assert!(delete(id));
        });
        assert_eq!(fires, 0, "a POSIX timer fired after timer_delete returned");
    }

    #[test]
    fn cpu_fallback_does_not_fire_after_disarming_settime_returns() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let fires = cpu_one_shot_fires_after(|id| {
            let _ = arm(id, TimerSpecNs::DISARM).expect("disarm");
        });
        assert_eq!(
            fires, 0,
            "a POSIX timer fired after a disarming timer_settime returned"
        );
    }

    #[test]
    fn cpu_fallback_stale_worker_leaves_replacement_arm_alone() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let id = create_with_clock_kind(2, ClockKind::ProcessCpu, 27, None, 0);
        let spec = TimerSpecNs {
            value: 1_000,
            interval: 1_000,
        };
        let armed = arm(id, spec).expect("arm");
        // Sample 0 = start, sample 1 = first expiry (delivered), sample 2
        // parks with the next periodic expiry already reached.
        let (fires, resume, runner) =
            spawn_parked_cpu_worker(&armed, spec, vec![0, 1_000, 5_000], 2);
        // timer_settime replaces the arm. The stale worker must neither
        // deliver the old setting's next expiry nor charge an overrun to the
        // replacement (whose own worker is not spawned here).
        let replacement = arm(
            id,
            TimerSpecNs {
                value: 1_000_000_000,
                interval: 1_000_000_000,
            },
        )
        .expect("re-arm");
        resume.send(()).expect("worker still parked");
        runner.join().expect("fallback worker terminates");
        assert_eq!(
            fires.load(Ordering::SeqCst),
            1,
            "a stale POSIX-timer worker delivered after timer_settime replaced its arm"
        );
        assert_eq!(
            getoverrun(id),
            Some(0),
            "a stale POSIX-timer worker charged an overrun to the replacement arm"
        );
        assert!(generation_matches(
            &replacement.slot,
            replacement.generation
        ));
        let _ = delete(id);
    }
}
