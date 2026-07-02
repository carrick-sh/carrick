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

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crate::{CpuNs, TimerSpecNs, WallNs};

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
const CPU_TIMER_MAX_RECHECK_NS: u64 = 1_000_000;

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
    use std::sync::atomic::AtomicUsize;
    static EPOCH: AtomicUsize = AtomicUsize::new(0);
    let epoch = EPOCH.fetch_add(1, Ordering::Relaxed);
    TIMER_IDENT_BASE + epoch.wrapping_mul(WHICH_COUNT) + which
}

/// Linux signal number delivered when `which`'s timer expires.
pub fn signum_for(which: usize) -> i32 {
    match which {
        1 => carrick_abi::LINUX_SIGVTALRM, // ITIMER_VIRTUAL
        2 => carrick_abi::LINUX_SIGPROF,   // ITIMER_PROF
        _ => carrick_abi::LINUX_SIGALRM,   // ITIMER_REAL
    }
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
/// new generation.
pub fn arm(which: usize, spec: TimerSpecNs, needs_periodic: bool) -> u64 {
    if let Some(slot) = SLOTS.get(which) {
        let generation = slot
            .generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        slot.value_ns.store(spec.value, Ordering::SeqCst);
        slot.interval_ns.store(spec.interval, Ordering::SeqCst);
        slot.needs_periodic.store(needs_periodic, Ordering::SeqCst);
        let cpu_due_ns = if is_cpu_timer(which) {
            carrick_host::guest_cpu::total_ns_including_active().saturating_add(spec.value)
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

fn generation_matches(which: usize, generation: u64) -> bool {
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
/// to fire. If not, return a wall-clock recheck delay so the pump can replay a
/// one-shot wake instead of consuming the timer while the guest is idle.
///
/// Accuracy: this is EXACT for a single-vCPU guest — `total_ns_including_active`
/// is the guest's CPU total, so `Fire` happens precisely when it crosses
/// `cpu_due_ns`. For a MULTI-vCPU guest it is BEST-EFFORT: `cpu_due_ns` is set
/// off the AGGREGATE guest CPU total (summed across vCPUs), and the recheck
/// delay is scaled by the active vCPU count (see [`cpu_timer_recheck_delay_ns`],
/// which divides the remaining CPU by `active_count`) so the bounded poll wakes
/// roughly when the aggregate is expected to reach the deadline. Per-thread CPU
/// attribution (CLOCK_THREAD_CPUTIME_ID semantics) is not modeled; ITIMER_VIRTUAL
/// / ITIMER_PROF on a multi-threaded guest fire off whole-process aggregate CPU,
/// which matches Linux's process-directed itimer semantics at the process level
/// but does not pin delivery to the exact thread that burned the CPU.
pub fn cpu_timer_decision(which: usize) -> Option<CpuTimerDecision> {
    if !is_cpu_timer(which) {
        return None;
    }
    let slot = SLOTS.get(which)?;
    let due_ns = slot.cpu_due_ns.load(Ordering::SeqCst);
    if due_ns == 0 {
        return Some(CpuTimerDecision::Fire);
    }
    let now_ns = carrick_host::guest_cpu::total_ns_including_active();
    if now_ns < due_ns {
        return Some(CpuTimerDecision::Wait {
            delay_ns: cpu_timer_recheck_delay_ns(CpuNs(due_ns - now_ns)),
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

/// Convert remaining aggregate guest CPU time into a wall-clock delay for the
/// signal pump's next CPU-timer check. This is THE sanctioned [`CpuNs`] →
/// [`WallNs`] crossing: everywhere else the two domains must not mix.
pub fn cpu_timer_recheck_delay_ns(remaining_cpu_ns: CpuNs) -> WallNs {
    let active_vcpus = carrick_host::guest_cpu::active_count() as u64;
    let scaled = if active_vcpus > 1 {
        remaining_cpu_ns.raw().div_ceil(active_vcpus)
    } else {
        remaining_cpu_ns.raw()
    };
    WallNs(scaled.clamp(1, CPU_TIMER_MAX_RECHECK_NS))
}

/// Current kqueue timer arm for `which`, if it is armed. This is used when a
/// freshly forked process starts its signal pump after `setitimer` has already
/// run; without replaying the arm, the timer state says "armed" but no kqueue
/// event can ever fire.
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
            carrick_portable::EV_ADD
        } else {
            carrick_portable::EV_ADD | carrick_portable::EV_ONESHOT
        };
    let delay_ns = if is_cpu_timer(which) {
        // `value_ns` is a guest-CPU budget here; the kqueue delay is the
        // wall-clock RECHECK, not the budget itself.
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

/// Shared fallback-timer timing loop body. Branches on the timer's nature:
///
/// * Wall-time (`ITIMER_REAL`): sleeps to the first deadline, then (if still
///   armed with this `generation`) invokes `on_fire`, repeating every
///   `spec.interval` until the timer is disarmed or re-armed (generation bump)
///   or `!is_armed`. `spec.value`/`spec.interval` of 0 sleep for zero time
///   (fire immediately / one-shot, respectively).
///
/// * CPU-time (`ITIMER_VIRTUAL`/`ITIMER_PROF`): does NOT sleep the wall-clock
///   `value`/`interval`. Instead it POLLS [`cpu_timer_decision`], which compares
///   the slot's `cpu_due_ns` against the live aggregate guest CPU total. On
///   `Fire` it invokes `on_fire` (and `cpu_timer_decision` has already re-armed
///   `cpu_due_ns` for the interval, or zeroed it for a one-shot — so a zeroed
///   `cpu_due_ns` after a fire means "stop"). On `Wait { delay_ns }` it sleeps
///   the bounded recheck delay and loops. Either way it retires on a generation
///   bump (disarm/re-arm) or `!is_armed`, exactly like the wall-clock arm. This
///   makes CPU itimers fire off REAL guest CPU time on backends with no pump
///   kqueue (KVM) and in HVF fork-child fallbacks, NOT off wall-clock.
///
/// The THREAD SPAWN and the actual `on_fire` (publish signal + kick) are
/// per-backend; only this timing loop is shared.
pub fn run_fallback(which: usize, generation: u64, spec: TimerSpecNs, on_fire: impl Fn()) {
    if is_cpu_timer(which) {
        run_fallback_cpu(which, generation, &on_fire);
        return;
    }
    std::thread::sleep(Duration::from_nanos(spec.value));
    loop {
        if !generation_matches(which, generation) || !is_armed(which) {
            break;
        }
        on_fire();
        if spec.interval == 0 {
            complete_fire(which);
            break;
        }
        std::thread::sleep(Duration::from_nanos(spec.interval));
    }
}

/// CPU-itimer fallback poll loop. Drives delivery off the aggregate guest CPU
/// total via [`cpu_timer_decision`] rather than wall-clock sleeps, so the timer
/// only advances while the guest actually burns CPU (and never while idle).
/// `cpu_timer_decision` owns the one-shot-vs-interval re-arm of `cpu_due_ns`: on
/// a `Fire` it either re-arms `cpu_due_ns` for the next interval (periodic) or
/// zeroes it (one-shot). We therefore stop after a fire iff the timer has no
/// interval — a one-shot is spent — and otherwise keep polling for the next
/// interval expiry. Retires on a generation bump (disarm/re-arm) or `!is_armed`.
fn run_fallback_cpu(which: usize, generation: u64, on_fire: &impl Fn()) {
    loop {
        if !generation_matches(which, generation) || !is_armed(which) {
            break;
        }
        match cpu_timer_decision(which) {
            Some(CpuTimerDecision::Fire) => {
                on_fire();
                if interval_ns(which) == 0 {
                    complete_fire(which);
                    break;
                }
            }
            Some(CpuTimerDecision::Wait { delay_ns }) => {
                std::thread::sleep(Duration::from_nanos(delay_ns.raw()));
            }
            None => break,
        }
    }
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
    use std::sync::{Arc, Barrier, Mutex};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    // ---- Contract tests from the task spec (adjusted to the real signatures). ----

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
        carrick_host::guest_cpu::reset();
        arm(1, TimerSpecNs::DISARM, false); // VIRTUAL, due now (value == 0 => cpu_due_ns == 0)
        match cpu_timer_decision(1) {
            Some(CpuTimerDecision::Fire) => {}
            other => panic!("expected Fire, got {other:?}"),
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
    fn run_fallback_cpu_one_shot_fires_once_when_cpu_advances() {
        use std::sync::atomic::AtomicUsize;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        carrick_host::guest_cpu::reset();
        let which = 1; // VIRTUAL, one-shot
        // Arm for a small CPU budget; cpu_due_ns = 0 + 1_000 since CPU total is 0.
        let spec = TimerSpecNs {
            value: 1_000,
            interval: 0,
        };
        let generation = arm(which, spec, false);
        // Charge enough guest CPU that the one-shot is due.
        carrick_host::guest_cpu::begin_active();
        carrick_host::guest_cpu::finish_active(10_000);
        let fires = Arc::new(AtomicUsize::new(0));
        let fires2 = Arc::clone(&fires);
        // run_fallback should Fire exactly once (one-shot) then return.
        run_fallback(which, generation, spec, move || {
            fires2.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            fires.load(Ordering::SeqCst),
            1,
            "one-shot CPU timer fires once"
        );
        disarm(which);
        carrick_host::guest_cpu::reset();
    }

    #[test]
    fn run_fallback_cpu_retires_on_generation_bump() {
        use std::sync::atomic::AtomicUsize;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        carrick_host::guest_cpu::reset();
        let which = 2; // PROF, periodic — would loop forever if not retired.
        let spec = TimerSpecNs {
            value: 1_000,
            interval: 1_000,
        };
        let stale_generation = arm(which, spec, false);
        // Bump the generation (re-arm) so the stale fallback must retire.
        let _new_generation = arm(which, spec, false);
        let fires = Arc::new(AtomicUsize::new(0));
        let fires2 = Arc::clone(&fires);
        // Even with CPU charged past due, the stale-generation loop must exit
        // immediately (generation mismatch) rather than fire/loop.
        carrick_host::guest_cpu::begin_active();
        carrick_host::guest_cpu::finish_active(1_000_000);
        run_fallback(which, stale_generation, spec, move || {
            fires2.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            fires.load(Ordering::SeqCst),
            0,
            "stale-generation CPU fallback must not fire"
        );
        disarm(which);
        carrick_host::guest_cpu::reset();
    }

    #[test]
    fn run_fallback_real_retires_on_generation_bump() {
        use std::sync::atomic::AtomicUsize;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        clear();
        let which = 0; // REAL, wall-clock periodic — would loop forever if not retired.
        let spec = TimerSpecNs {
            value: 1_000,
            interval: 1_000,
        };
        let stale_generation = arm(which, spec, false);
        // Bump the generation (re-arm) so the stale fallback must retire.
        let _new_generation = arm(which, spec, false);
        let fires = Arc::new(AtomicUsize::new(0));
        let fires2 = Arc::clone(&fires);
        // The stale-generation loop must exit at its first guard (generation
        // mismatch) and return promptly rather than fire/loop. Determinism comes
        // from the generation guard, not the 1µs sleep — even if the sleep were
        // instantaneous the guard would still break before any on_fire().
        run_fallback(which, stale_generation, spec, move || {
            fires2.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            fires.load(Ordering::SeqCst),
            0,
            "stale-generation wall-clock fallback must not fire"
        );

        // Prove the CURRENT generation still fires exactly once (one-shot).
        let one_shot = TimerSpecNs {
            value: 1_000,
            interval: 0,
        };
        let g = arm(which, one_shot, false);
        let cur = Arc::new(AtomicUsize::new(0));
        let cur2 = Arc::clone(&cur);
        run_fallback(which, g, one_shot, move || {
            cur2.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            cur.load(Ordering::SeqCst),
            1,
            "current-generation one-shot wall-clock timer fires once"
        );
        disarm(which);
    }

    // ---- Regression tests carried from carrick-vmm-hvf. ----

    #[test]
    fn ident_round_trips_for_each_which() {
        for which in 0..WHICH_COUNT {
            assert_eq!(which_for_ident(ident_for(which)), Some(which));
        }
    }

    #[test]
    fn epoch_extended_idents_decode_to_their_which() {
        // Idents are TIMER_IDENT_BASE + epoch*WHICH_COUNT + which, so every
        // epoch's ident for a `which` decodes back to that `which` by modulo.
        for epoch in [0usize, 1, 2, 7, 1_000_000] {
            for which in 0..WHICH_COUNT {
                let ident = TIMER_IDENT_BASE + epoch * WHICH_COUNT + which;
                assert_eq!(which_for_ident(ident), Some(which));
            }
        }
    }

    #[test]
    fn out_of_range_ident_is_none() {
        // Only idents BELOW the timer base are out of range; at/above the base
        // they are valid epoch-extended timer idents (decoded by modulo).
        assert_eq!(which_for_ident(TIMER_IDENT_BASE - 1), None);
        assert_eq!(which_for_ident(0), None);
    }

    #[test]
    fn next_ident_is_fresh_and_decodes_to_which() {
        // Consecutive arms must NOT reuse an ident (Darwin poisons a fired
        // EV_ONESHOT ident), yet every fresh ident still decodes to its `which`.
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
        // Disarmed (clear): live_ident falls back to the base ident.
        assert_eq!(live_ident(which), ident_for(which));
        let spec = TimerSpecNs {
            value: 1_000_000,
            interval: 0,
        };
        arm(which, spec, false);
        let armed_ident = live_ident(which);
        assert!(armed_ident >= TIMER_IDENT_BASE);
        assert_eq!(which_for_ident(armed_ident), Some(which));
        // A second arm takes a DIFFERENT (fresh) ident — never the poisoned one.
        arm(which, spec, false);
        assert_ne!(
            live_ident(which),
            armed_ident,
            "re-arm must use a fresh ident"
        );
        // Disarm forgets the live ident (back to the base fallback).
        disarm(which);
        assert_eq!(live_ident(which), ident_for(which));
    }

    #[test]
    fn signum_mapping() {
        assert_eq!(signum_for(0), carrick_abi::LINUX_SIGALRM);
        assert_eq!(signum_for(1), carrick_abi::LINUX_SIGVTALRM);
        assert_eq!(signum_for(2), carrick_abi::LINUX_SIGPROF);
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
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        carrick_host::guest_cpu::reset();
        assert_eq!(cpu_timer_recheck_delay_ns(CpuNs(0)), WallNs(1));
        assert_eq!(cpu_timer_recheck_delay_ns(CpuNs(500_000)), WallNs(500_000));
        assert_eq!(
            cpu_timer_recheck_delay_ns(CpuNs(10_000_000)),
            WallNs(1_000_000)
        );
    }

    #[test]
    fn cpu_timer_recheck_delay_scales_with_active_vcpus() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        carrick_host::guest_cpu::reset();
        let started = Arc::new(Barrier::new(3));
        let release = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let started = Arc::clone(&started);
                let release = Arc::clone(&release);
                std::thread::spawn(move || {
                    carrick_host::guest_cpu::begin_active();
                    started.wait();
                    release.wait();
                    carrick_host::guest_cpu::finish_active(0);
                })
            })
            .collect::<Vec<_>>();

        started.wait();
        assert_eq!(cpu_timer_recheck_delay_ns(CpuNs(800_000)), WallNs(400_000));
        release.wait();
        for handle in handles {
            handle
                .join()
                .expect("active vCPU test thread should finish");
        }
        carrick_host::guest_cpu::reset();
    }

    #[test]
    fn arm_disarm_round_trip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        // Use which=2 (PROF) to avoid colliding with other tests' slots.
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
        // First take consumes the flag; the second sees it cleared.
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
        let which = 1; // VIRTUAL
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
        let which = 0; // REAL
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
                flags: carrick_portable::EV_ADD | carrick_portable::EV_ONESHOT,
                delay_ns: 50_000_000,
                generation: generation(which),
            })
        );
        disarm(which);
    }

    #[test]
    fn current_arm_reconstructs_periodic_timer() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let which = 0; // REAL
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
                flags: carrick_portable::EV_ADD,
                delay_ns: 25_000_000,
                generation: generation(which),
            })
        );
        disarm(which);
    }

    #[test]
    fn current_arm_replays_cpu_periodic_timer_as_one_shot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        carrick_host::guest_cpu::reset();
        let which = 1; // VIRTUAL
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
                flags: carrick_portable::EV_ADD | carrick_portable::EV_ONESHOT,
                delay_ns: 1_000_000,
                generation: generation(which),
            })
        );
        disarm(which);
    }
}
