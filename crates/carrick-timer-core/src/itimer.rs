//! Platform-NEUTRAL interval-timer (`setitimer`) state, shared between the
//! `setitimer` syscall handler (writer) and whatever delivers the expiry (the
//! HVF signal pump's kqueue, or the wall-clock fallback thread). The per-`which`
//! (REAL/VIRTUAL/PROF) state lives here as process-global atomics so the pump,
//! which has no access to per-process `ProcState`, can read it. Each `which`
//! owns one stable EVFILT_TIMER ident, so arming/disarming is a single
//! EV_ADD/EV_DELETE that supersedes any prior arm.
//!
//! Linux `setitimer` is two-phase: the first expiry is after `it_value`, then
//! every `it_interval`. kqueue's `EVFILT_TIMER` expresses a single period, so:
//!
//! * `it_interval == 0` → one-shot (EV_ONESHOT, data = it_value).
//! * `it_value == it_interval` → pure periodic (EV_ADD, data = interval); the
//!   kernel repeats it and the pump never re-arms (no drift, fully race-free).
//! * `it_value != it_interval` → one-shot for it_value; the pump arms a
//!   periodic timer ONCE on that first fire (`needs_periodic`).
//!
//! Disarm clears `armed` and EV_DELETEs the ident. The pump treats a fire for a
//! `!armed` `which` as stale — it EV_DELETEs the ident and does NOT publish —
//! so a disarm that races the pump's one-time periodic re-arm self-heals after
//! at most one spurious fire instead of leaving a runaway periodic timer.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::{CpuNs, CpuSampler, TimerSpecNs, WallNs};

/// The 3 itimer `which` values (REAL=0, VIRTUAL=1, PROF=2).
pub const ITIMER_COUNT: usize = 3;

/// Base of the EVFILT_TIMER ident range for itimers. Idents are
/// `BASE + which` for `which` in 0..3. The EVFILT_TIMER ident namespace is
/// distinct from EVFILT_READ (fds) and EVFILT_USER (ident 0) on the pump kq,
/// so this only needs to be internally distinct across the 3 timers.
pub const TIMER_IDENT_BASE: usize = 0x00C1_0000;

/// Number of `setitimer` `which` slots: ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF.
const WHICH_COUNT: usize = ITIMER_COUNT;

/// Maximum wall-clock interval between CPU-timer rechecks while a CPU timer is
/// armed. Delivery still depends on process guest CPU reaching `cpu_due_ns`,
/// but bounded polling keeps timers from going late after an idle process
/// resumes or when aggregate CPU advances faster than wall time.
pub const CPU_TIMER_MAX_RECHECK_NS: u64 = 1_000_000;

/// Portable EVFILT_TIMER arm flags (matches BSD EV_ADD).
pub const TIMER_ARM_ADD: u16 = 0x0001;
/// Portable EVFILT_TIMER arm flags (matches BSD EV_ONESHOT).
pub const TIMER_ARM_ONESHOT: u16 = 0x0010;

/// Per-`which` interval-timer state shared between `setitimer` and the pump.
struct ItimerSlot {
    /// Monotonic generation bumped on every arm/disarm. Fallback timer threads
    /// use it to avoid firing after a later disarm or replacement arm.
    generation: AtomicU64,
    /// First expiry in nanoseconds. Used to replay an arm when `setitimer`
    /// races ahead of a freshly-forked signal pump publishing its kqueue.
    value_ns: AtomicU64,
    /// Repeat period in nanoseconds; 0 = no repeat (one-shot).
    interval_ns: AtomicU64,
    /// True between an arm and the matching disarm. A fire for a `!armed`
    /// `which` is stale (disarmed or resurrected by a race) and is dropped.
    armed: AtomicBool,
    /// Set when an arm used a one-shot for `it_value` but wants a periodic
    /// repeat afterwards (`it_value != it_interval`). Consumed by the pump on
    /// the first fire, which then arms the periodic timer exactly once.
    needs_periodic: AtomicBool,
    /// Guest CPU-time total at which a CPU timer should next fire. Wall-time
    /// `ITIMER_REAL` leaves this zero.
    cpu_due_ns: AtomicU64,
    /// The fresh EVFILT_TIMER ident this arm registered (see [`next_ident`]).
    /// Stored so disarm/fork-replay act on the SAME ident the arm used, not a
    /// recomputed (and possibly poisoned) base ident. 0 = never armed.
    live_ident: AtomicUsize,
}

impl ItimerSlot {
    const fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            value_ns: AtomicU64::new(0),
            interval_ns: AtomicU64::new(0),
            armed: AtomicBool::new(false),
            needs_periodic: AtomicBool::new(false),
            cpu_due_ns: AtomicU64::new(0),
            live_ident: AtomicUsize::new(0),
        }
    }
}

static SLOTS: [ItimerSlot; WHICH_COUNT] = [ItimerSlot::new(), ItimerSlot::new(), ItimerSlot::new()];

/// EVFILT_TIMER ident for a `which`.
pub fn ident_for(which: usize) -> usize {
    TIMER_IDENT_BASE + which
}

/// The `which` an EVFILT_TIMER ident belongs to, or `None` if out of range.
/// Idents are `TIMER_IDENT_BASE + epoch*WHICH_COUNT + which`, so `which` is the
/// offset mod `WHICH_COUNT`; the `epoch` term gives every arm a fresh ident (a
/// recently-fired EV_ONESHOT ident on Darwin cannot be re-armed — see
/// [`next_ident`]).
pub fn which_for_ident(ident: usize) -> Option<usize> {
    ident.checked_sub(TIMER_IDENT_BASE).map(|d| d % WHICH_COUNT)
}

/// A fresh, never-before-used EVFILT_TIMER ident for `which`. Darwin poisons an
/// ident after its EV_ONESHOT timer fires: re-`EV_ADD`ing that ident (even after
/// `EV_DELETE`) silently never counts down. Each arm therefore takes a new ident
/// from a monotonic epoch, striding by `WHICH_COUNT` so `which_for_ident` still
/// decodes `which` by modulo. The old (fired) ident is abandoned — EV_ONESHOT
/// already removed its knote, so nothing leaks.
pub fn next_ident(which: usize) -> usize {
    static EPOCH: AtomicUsize = AtomicUsize::new(0);
    let epoch = EPOCH.fetch_add(1, Ordering::Relaxed);
    TIMER_IDENT_BASE + epoch.wrapping_mul(WHICH_COUNT) + which
}

/// Whether `which` is a CPU-time timer (`ITIMER_VIRTUAL`/`ITIMER_PROF`) rather
/// than wall-time `ITIMER_REAL`. ITIMER_VIRTUAL(1) / ITIMER_PROF(2) measure
/// GUEST CPU time, not wall-clock.
pub fn is_cpu_timer(which: usize) -> bool {
    which == 1 || which == 2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTimerDecision {
    Fire,
    /// Not enough guest CPU has elapsed yet; re-check after this WALL-CLOCK
    /// sleep delay (already converted from the remaining CPU quantity by
    /// [`cpu_timer_recheck_delay_ns`]).
    Wait {
        delay_ns: WallNs,
    },
}

/// Complete EVFILT_TIMER arm state for an armed interval timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerArm {
    pub ident: usize,
    pub flags: u16,
    pub delay_ns: i64,
    /// Arm generation, stamped into the kevent `udata`. A fire whose `udata`
    /// generation no longer matches the slot's current generation is a stale
    /// late fire from a superseded arm and must be dropped — an invariant the
    /// pump asserts on every timer event (see `which_for_ident`/fresh idents).
    pub generation: u64,
}

/// The current arm generation of `which` (bumped on every arm/disarm). Used to
/// validate a fired timer's `udata` against the live arm.
pub fn generation(which: usize) -> u64 {
    SLOTS
        .get(which)
        .map_or(0, |slot| slot.generation.load(Ordering::SeqCst))
}

/// Mark `which` armed with the given `spec` (`spec.interval == 0` = one-shot)
/// and whether the pump must transition a one-shot to periodic on its first
/// fire. Called by `setitimer`. Out-of-range `which` is ignored. Returns the
/// new generation. Defaults `cpu_now_ns` to 0.
pub fn arm(which: usize, spec: TimerSpecNs, needs_periodic: bool) -> u64 {
    arm_with_cpu_now(which, spec, needs_periodic, 0)
}

/// Mark `which` armed with explicit current guest CPU time `cpu_now_ns`.
pub fn arm_with_cpu_now(
    which: usize,
    spec: TimerSpecNs,
    needs_periodic: bool,
    cpu_now_ns: u64,
) -> u64 {
    if let Some(slot) = SLOTS.get(which) {
        let generation = slot
            .generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        slot.value_ns.store(spec.value, Ordering::SeqCst);
        slot.interval_ns.store(spec.interval, Ordering::SeqCst);
        slot.needs_periodic.store(needs_periodic, Ordering::SeqCst);
        let cpu_due_ns = if is_cpu_timer(which) {
            cpu_now_ns.saturating_add(spec.value)
        } else {
            0
        };
        slot.cpu_due_ns.store(cpu_due_ns, Ordering::SeqCst);
        // Allocate a FRESH ident for this arm (Darwin poisons a fired EV_ONESHOT
        // ident — re-arming it never counts down). disarm/fork-replay read this
        // back so they act on the ident actually registered.
        slot.live_ident.store(next_ident(which), Ordering::SeqCst);
        // Publish `armed` last so a pump fire that observes `armed` also sees
        // the interval/needs_periodic + live_ident written above.
        slot.armed.store(true, Ordering::SeqCst);
        generation
    } else {
        0
    }
}

/// The EVFILT_TIMER ident the current arm of `which` registered, or the base
/// ident if `which` was never armed. disarm + fork-replay use this so they touch
/// the SAME ident the live arm registered (see [`next_ident`]).
pub fn live_ident(which: usize) -> usize {
    match SLOTS.get(which) {
        Some(slot) => {
            let stored = slot.live_ident.load(Ordering::SeqCst);
            if stored == 0 {
                ident_for(which)
            } else {
                stored
            }
        }
        None => ident_for(which),
    }
}

/// Mark `which` disarmed and clear its state. Called by `setitimer` on a zero
/// `it_value`. Out-of-range `which` is ignored.
pub fn disarm(which: usize) {
    if let Some(slot) = SLOTS.get(which) {
        slot.generation.fetch_add(1, Ordering::SeqCst);
        slot.armed.store(false, Ordering::SeqCst);
        slot.value_ns.store(0, Ordering::SeqCst);
        slot.interval_ns.store(0, Ordering::SeqCst);
        slot.needs_periodic.store(false, Ordering::SeqCst);
        slot.cpu_due_ns.store(0, Ordering::SeqCst);
        // Forget the live ident — `live_ident` falls back to the base ident when
        // disarmed. (HVF disarm reads the ident BEFORE calling disarm, so this
        // does not race the EV_DELETE.)
        slot.live_ident.store(0, Ordering::SeqCst);
    }
}

pub fn generation_matches(which: usize, generation: u64) -> bool {
    SLOTS
        .get(which)
        .is_some_and(|slot| slot.generation.load(Ordering::SeqCst) == generation)
}

/// Is `which` currently armed? The pump uses this to drop stale fires.
pub fn is_armed(which: usize) -> bool {
    SLOTS
        .get(which)
        .is_some_and(|slot| slot.armed.load(Ordering::SeqCst))
}

/// The repeat interval for `which` in nanoseconds (0 = no repeat).
pub fn interval_ns(which: usize) -> u64 {
    SLOTS
        .get(which)
        .map_or(0, |slot| slot.interval_ns.load(Ordering::SeqCst))
}

/// Mark a delivered expiry complete. One-shot timers are spent after that
/// delivery, so retire their neutral armed slot. Periodic/two-phase timers stay
/// armed for their next interval.
///
/// Returns `true` when this call retired a one-shot.
pub fn complete_fire(which: usize) -> bool {
    if interval_ns(which) == 0 {
        disarm(which);
        true
    } else {
        false
    }
}

/// For CPU timers, decide whether enough guest CPU has elapsed for this timer
/// to fire given current guest CPU time `now_ns` and `active_vcpus`.
pub fn cpu_timer_decision(which: usize, now_ns: u64, active_vcpus: u64) -> Option<CpuTimerDecision> {
    if !is_cpu_timer(which) {
        return None;
    }
    let slot = SLOTS.get(which)?;
    let due_ns = slot.cpu_due_ns.load(Ordering::SeqCst);
    if due_ns == 0 {
        return Some(CpuTimerDecision::Fire);
    }
    if now_ns < due_ns {
        return Some(CpuTimerDecision::Wait {
            delay_ns: cpu_timer_recheck_delay_with_active(CpuNs(due_ns - now_ns), active_vcpus),
        });
    }
    let interval_ns = slot.interval_ns.load(Ordering::SeqCst);
    if interval_ns > 0 {
        slot.cpu_due_ns
            .store(now_ns.saturating_add(interval_ns), Ordering::SeqCst);
    } else {
        slot.cpu_due_ns.store(0, Ordering::SeqCst);
    }
    Some(CpuTimerDecision::Fire)
}

/// Decide CPU timer expiry using a [`CpuSampler`].
pub fn cpu_timer_decision_with_sampler<S: CpuSampler>(
    which: usize,
    sampler: &S,
) -> Option<CpuTimerDecision> {
    cpu_timer_decision(which, sampler.total_cpu_ns(), sampler.active_vcpus())
}

/// Convert remaining aggregate guest CPU time into a wall-clock delay for the
/// signal pump's next CPU-timer check with a default 1 active vCPU.
pub fn cpu_timer_recheck_delay_ns(remaining_cpu_ns: CpuNs) -> WallNs {
    cpu_timer_recheck_delay_with_active(remaining_cpu_ns, 1)
}

/// Convert remaining aggregate guest CPU time into a wall-clock delay scaled by
/// the number of active vCPUs.
pub fn cpu_timer_recheck_delay_with_active(remaining_cpu_ns: CpuNs, active_vcpus: u64) -> WallNs {
    let scaled = if active_vcpus > 1 {
        remaining_cpu_ns.raw().div_ceil(active_vcpus)
    } else {
        remaining_cpu_ns.raw()
    };
    WallNs(scaled.clamp(1, CPU_TIMER_MAX_RECHECK_NS))
}

/// Current kqueue timer arm for `which`, if it is armed.
pub fn current_arm(which: usize) -> Option<TimerArm> {
    let slot = SLOTS.get(which)?;
    if !slot.armed.load(Ordering::SeqCst) {
        return None;
    }
    let value_ns = slot.value_ns.load(Ordering::SeqCst);
    let interval_ns = slot.interval_ns.load(Ordering::SeqCst);
    let needs_periodic = slot.needs_periodic.load(Ordering::SeqCst);
    if value_ns == 0 {
        return None;
    }
    let flags =
        if interval_ns != 0 && !needs_periodic && value_ns == interval_ns && !is_cpu_timer(which) {
            TIMER_ARM_ADD
        } else {
            TIMER_ARM_ADD | TIMER_ARM_ONESHOT
        };
    let delay_ns = if is_cpu_timer(which) {
        cpu_timer_recheck_delay_ns(CpuNs(value_ns))
    } else {
        WallNs(value_ns)
    };
    Some(TimerArm {
        ident: live_ident(which),
        flags,
        delay_ns: i64::try_from(delay_ns.raw()).unwrap_or(i64::MAX),
        generation: generation(which),
    })
}

pub fn current_arms() -> impl Iterator<Item = TimerArm> {
    (0..WHICH_COUNT).filter_map(current_arm)
}

/// Atomically take the `needs_periodic` flag for `which`, returning whether the
/// pump should arm the periodic timer now (and clearing it so later periodic
/// fires don't re-arm).
pub fn take_needs_periodic(which: usize) -> bool {
    SLOTS
        .get(which)
        .is_some_and(|slot| slot.needs_periodic.swap(false, Ordering::SeqCst))
}

/// Disarm every `which` (used by fork reinit so a child doesn't inherit the
/// parent's interval-timer arms).
pub fn clear() {
    for which in 0..WHICH_COUNT {
        disarm(which);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn arm_disarm_generation() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        let g0 = arm(
            0,
            TimerSpecNs {
                value: 1_000_000,
                interval: 0,
            },
            false,
        );
        assert!(is_armed(0));
        assert_eq!(interval_ns(0), 0);
        let g1 = arm(
            0,
            TimerSpecNs {
                value: 2_000_000,
                interval: 500_000,
            },
            true,
        );
        assert_ne!(g0, g1, "re-arm bumps generation");
        disarm(0);
        assert!(!is_armed(0));
    }

    #[test]
    fn cpu_due_decision_fires_when_due() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        arm(1, TimerSpecNs::DISARM, false);
        match cpu_timer_decision(1, 0, 1) {
            Some(CpuTimerDecision::Fire) => {}
            other => panic!("expected Fire, got {other:?}"),
        }
        disarm(1);
    }

    #[test]
    fn cpu_due_decision_waits_when_not_due() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        arm_with_cpu_now(
            1,
            TimerSpecNs {
                value: 10_000,
                interval: 0,
            },
            false,
            1_000,
        );
        match cpu_timer_decision(1, 5_000, 2) {
            Some(CpuTimerDecision::Wait { delay_ns }) => {
                // (11_000 - 5_000) / 2 = 3_000
                assert_eq!(delay_ns.raw(), 3_000);
            }
            other => panic!("expected Wait, got {other:?}"),
        }
        disarm(1);
    }

    #[test]
    fn one_shot_fire_retires_armed_slot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        arm(
            0,
            TimerSpecNs {
                value: 1_000_000,
                interval: 0,
            },
            false,
        );

        assert!(complete_fire(0));
        assert!(!is_armed(0));
    }

    #[test]
    fn periodic_fire_keeps_armed_slot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        arm(
            0,
            TimerSpecNs {
                value: 1_000_000,
                interval: 1_000_000,
            },
            false,
        );

        assert!(!complete_fire(0));
        assert!(is_armed(0));
    }

    #[test]
    fn ident_round_trips_for_each_which() {
        for which in 0..WHICH_COUNT {
            assert_eq!(which_for_ident(ident_for(which)), Some(which));
        }
    }

    #[test]
    fn epoch_extended_idents_decode_to_their_which() {
        for epoch in [0usize, 1, 2, 7, 1_000_000] {
            for which in 0..WHICH_COUNT {
                let ident = TIMER_IDENT_BASE + epoch * WHICH_COUNT + which;
                assert_eq!(which_for_ident(ident), Some(which));
            }
        }
    }

    #[test]
    fn out_of_range_ident_is_none() {
        assert_eq!(which_for_ident(TIMER_IDENT_BASE - 1), None);
        assert_eq!(which_for_ident(0), None);
    }

    #[test]
    fn next_ident_is_fresh_and_decodes_to_which() {
        let a = next_ident(0);
        let b = next_ident(0);
        assert_ne!(a, b, "consecutive arms must take distinct idents");
        assert_eq!(which_for_ident(a), Some(0));
        assert_eq!(which_for_ident(b), Some(0));
    }

    #[test]
    fn arm_publishes_fresh_live_ident_disarm_resets_it() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        let which = 0;
        assert_eq!(live_ident(which), ident_for(which));
        let spec = TimerSpecNs {
            value: 1_000_000,
            interval: 0,
        };
        arm(which, spec, false);
        let armed_ident = live_ident(which);
        assert!(armed_ident >= TIMER_IDENT_BASE);
        assert_eq!(which_for_ident(armed_ident), Some(which));
        arm(which, spec, false);
        assert_ne!(
            live_ident(which),
            armed_ident,
            "re-arm must use a fresh ident"
        );
        disarm(which);
        assert_eq!(live_ident(which), ident_for(which));
    }

    #[test]
    fn cpu_timer_classification_excludes_real_timer() {
        assert!(!is_cpu_timer(0));
        assert!(is_cpu_timer(1));
        assert!(is_cpu_timer(2));
        assert!(!is_cpu_timer(3));
    }

    #[test]
    fn cpu_timer_recheck_delay_is_bounded() {
        assert_eq!(cpu_timer_recheck_delay_ns(CpuNs(0)), WallNs(1));
        assert_eq!(cpu_timer_recheck_delay_ns(CpuNs(500_000)), WallNs(500_000));
        assert_eq!(
            cpu_timer_recheck_delay_ns(CpuNs(10_000_000)),
            WallNs(1_000_000)
        );
    }

    #[test]
    fn cpu_timer_recheck_delay_scales_with_active_vcpus() {
        assert_eq!(
            cpu_timer_recheck_delay_with_active(CpuNs(800_000), 2),
            WallNs(400_000)
        );
    }

    #[test]
    fn arm_disarm_round_trip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let which = 2;
        disarm(which);
        assert!(!is_armed(which));
        assert_eq!(interval_ns(which), 0);

        arm(
            which,
            TimerSpecNs {
                value: 10_000,
                interval: 5_000,
            },
            true,
        );
        assert!(is_armed(which));
        assert_eq!(interval_ns(which), 5_000);
        assert!(take_needs_periodic(which));
        assert!(!take_needs_periodic(which));

        disarm(which);
        assert!(!is_armed(which));
        assert_eq!(interval_ns(which), 0);
        assert!(!take_needs_periodic(which));
    }

    #[test]
    fn one_shot_arm_has_no_periodic_transition() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let which = 1;
        disarm(which);
        arm(
            which,
            TimerSpecNs {
                value: 5_000,
                interval: 0,
            },
            false,
        );
        assert!(is_armed(which));
        assert_eq!(interval_ns(which), 0);
        assert!(!take_needs_periodic(which));
        disarm(which);
    }

    #[test]
    fn current_arm_reconstructs_one_shot_timer() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let which = 0;
        disarm(which);
        arm(
            which,
            TimerSpecNs {
                value: 50_000_000,
                interval: 0,
            },
            false,
        );
        assert_eq!(
            current_arm(which),
            Some(TimerArm {
                ident: live_ident(which),
                flags: TIMER_ARM_ADD | TIMER_ARM_ONESHOT,
                delay_ns: 50_000_000,
                generation: generation(which),
            })
        );
        disarm(which);
    }

    #[test]
    fn current_arm_reconstructs_periodic_timer() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let which = 0;
        disarm(which);
        arm(
            which,
            TimerSpecNs {
                value: 25_000_000,
                interval: 25_000_000,
            },
            false,
        );
        assert_eq!(
            current_arm(which),
            Some(TimerArm {
                ident: live_ident(which),
                flags: TIMER_ARM_ADD,
                delay_ns: 25_000_000,
                generation: generation(which),
            })
        );
        disarm(which);
    }

    #[test]
    fn current_arm_replays_cpu_periodic_timer_as_one_shot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let which = 1;
        disarm(which);
        arm(
            which,
            TimerSpecNs {
                value: 25_000_000,
                interval: 25_000_000,
            },
            false,
        );
        assert_eq!(
            current_arm(which),
            Some(TimerArm {
                ident: live_ident(which),
                flags: TIMER_ARM_ADD | TIMER_ARM_ONESHOT,
                delay_ns: 1_000_000,
                generation: generation(which),
            })
        );
        disarm(which);
    }
}
