//! Process-global interval-timer (`setitimer`) state, shared between the
//! `setitimer` syscall handler (writer) and the signal pump (reader).
//!
//! Delivery moved off a per-arm OS thread onto `EVFILT_TIMER` events on the
//! signal pump's kqueue. The pump has no access to per-process `ProcState`, so
//! the per-`which` timer state lives here as process-global atomics. Each
//! `which` (REAL/VIRTUAL/PROF) owns one stable EVFILT_TIMER ident, so
//! arming/disarming is a single EV_ADD/EV_DELETE that supersedes any prior arm.
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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Base of the EVFILT_TIMER ident range for itimers. Idents are
/// `BASE + which` for `which` in 0..3. The EVFILT_TIMER ident namespace is
/// distinct from EVFILT_READ (fds) and EVFILT_USER (ident 0) on the pump kq,
/// so this only needs to be internally distinct across the 3 timers.
pub const TIMER_IDENT_BASE: usize = 0x00C1_0000;

/// Number of `setitimer` `which` slots: ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF.
const WHICH_COUNT: usize = 3;

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
        }
    }
}

static SLOTS: [ItimerSlot; WHICH_COUNT] = [ItimerSlot::new(), ItimerSlot::new(), ItimerSlot::new()];

/// EVFILT_TIMER ident for a `which`.
pub fn ident_for(which: usize) -> usize {
    TIMER_IDENT_BASE + which
}

/// The `which` an EVFILT_TIMER ident belongs to, or `None` if out of range.
pub fn which_for_ident(ident: usize) -> Option<usize> {
    ident
        .checked_sub(TIMER_IDENT_BASE)
        .filter(|&which| which < WHICH_COUNT)
}

/// Linux signal number delivered when `which`'s timer expires.
pub fn signum_for(which: usize) -> i32 {
    match which {
        1 => crate::linux_abi::LINUX_SIGVTALRM, // ITIMER_VIRTUAL
        2 => crate::linux_abi::LINUX_SIGPROF,   // ITIMER_PROF
        _ => crate::linux_abi::LINUX_SIGALRM,   // ITIMER_REAL
    }
}

/// Whether `which` is a CPU-time timer (`ITIMER_VIRTUAL`/`ITIMER_PROF`) rather
/// than wall-time `ITIMER_REAL`.
pub fn is_cpu_timer(which: usize) -> bool {
    which == 1 || which == 2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTimerDecision {
    Fire,
    Wait { delay_ns: u64 },
}

/// Complete EVFILT_TIMER arm state for an armed interval timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerArm {
    pub ident: usize,
    pub flags: u16,
    pub delay_ns: i64,
}

/// Mark `which` armed with the given repeat interval (0 = one-shot) and whether
/// the pump must transition a one-shot to periodic on its first fire. Called by
/// `setitimer`. Out-of-range `which` is ignored.
pub fn arm(which: usize, value_ns: u64, interval_ns: u64, needs_periodic: bool) -> u64 {
    if let Some(slot) = SLOTS.get(which) {
        let generation = slot
            .generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        slot.value_ns.store(value_ns, Ordering::SeqCst);
        slot.interval_ns.store(interval_ns, Ordering::SeqCst);
        slot.needs_periodic.store(needs_periodic, Ordering::SeqCst);
        let cpu_due_ns = if is_cpu_timer(which) {
            crate::guest_cpu::total_ns_including_active().saturating_add(value_ns)
        } else {
            0
        };
        slot.cpu_due_ns.store(cpu_due_ns, Ordering::SeqCst);
        // Publish `armed` last so a pump fire that observes `armed` also sees
        // the interval/needs_periodic written above.
        slot.armed.store(true, Ordering::SeqCst);
        generation
    } else {
        0
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

/// For CPU timers, decide whether enough guest CPU has elapsed for this timer
/// to fire. If not, return the remaining CPU interval so the pump can replay a
/// one-shot wake instead of consuming the timer while the guest is idle.
pub fn cpu_timer_decision(which: usize) -> Option<CpuTimerDecision> {
    if !is_cpu_timer(which) {
        return None;
    }
    let slot = SLOTS.get(which)?;
    let due_ns = slot.cpu_due_ns.load(Ordering::SeqCst);
    if due_ns == 0 {
        return Some(CpuTimerDecision::Fire);
    }
    let now_ns = crate::guest_cpu::total_ns_including_active();
    if now_ns < due_ns {
        return Some(CpuTimerDecision::Wait {
            delay_ns: due_ns - now_ns,
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
            libc::EV_ADD
        } else {
            libc::EV_ADD | libc::EV_ONESHOT
        };
    Some(TimerArm {
        ident: ident_for(which),
        flags,
        delay_ns: i64::try_from(value_ns).unwrap_or(i64::MAX),
    })
}

pub fn current_arms() -> impl Iterator<Item = TimerArm> {
    (0..WHICH_COUNT).filter_map(current_arm)
}

/// Fallback delivery for runtimes that do not have a signal-pump kqueue. The
/// threaded runtime uses EVFILT_TIMER so a busy-waiting vCPU can be kicked; this
/// fallback is for single-threaded fork/exec children parked in host waits, where
/// publishing to the pending pipe is sufficient to interrupt the wait.
pub fn spawn_fallback_timer(which: usize, generation: u64, value: Duration, interval: Duration) {
    let _ = std::thread::Builder::new()
        .name("carrick-itimer-fallback".to_owned())
        .spawn(move || {
            std::thread::sleep(value);
            loop {
                if !generation_matches(which, generation) || !is_armed(which) {
                    break;
                }
                let signum = signum_for(which);
                crate::probes::itimer_fire(signum, 1);
                crate::host_signal::publish_process_signal(signum);
                if interval.is_zero() {
                    break;
                }
                std::thread::sleep(interval);
            }
        });
}

/// Atomically take the `needs_periodic` flag for `which`, returning whether the
/// pump should arm the periodic timer now (and clearing it so later periodic
/// fires don't re-arm).
pub fn take_needs_periodic(which: usize) -> bool {
    SLOTS
        .get(which)
        .is_some_and(|slot| slot.needs_periodic.swap(false, Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn ident_round_trips_for_each_which() {
        for which in 0..WHICH_COUNT {
            assert_eq!(which_for_ident(ident_for(which)), Some(which));
        }
    }

    #[test]
    fn out_of_range_ident_is_none() {
        assert_eq!(which_for_ident(TIMER_IDENT_BASE - 1), None);
        assert_eq!(which_for_ident(TIMER_IDENT_BASE + WHICH_COUNT), None);
        assert_eq!(which_for_ident(0), None);
    }

    #[test]
    fn signum_mapping() {
        assert_eq!(signum_for(0), crate::linux_abi::LINUX_SIGALRM);
        assert_eq!(signum_for(1), crate::linux_abi::LINUX_SIGVTALRM);
        assert_eq!(signum_for(2), crate::linux_abi::LINUX_SIGPROF);
    }

    #[test]
    fn cpu_timer_classification_excludes_real_timer() {
        assert!(!is_cpu_timer(0));
        assert!(is_cpu_timer(1));
        assert!(is_cpu_timer(2));
        assert!(!is_cpu_timer(3));
    }

    #[test]
    fn arm_disarm_round_trip() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        // Use which=2 (PROF) to avoid colliding with other tests' slots.
        let which = 2;
        disarm(which);
        assert!(!is_armed(which));
        assert_eq!(interval_ns(which), 0);

        arm(which, 10_000, 5_000, true);
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
        arm(which, 5_000, 0, false);
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
        arm(which, 50_000_000, 0, false);
        assert_eq!(
            current_arm(which),
            Some(TimerArm {
                ident: ident_for(which),
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                delay_ns: 50_000_000,
            })
        );
        disarm(which);
    }

    #[test]
    fn current_arm_reconstructs_periodic_timer() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let which = 0; // REAL
        disarm(which);
        arm(which, 25_000_000, 25_000_000, false);
        assert_eq!(
            current_arm(which),
            Some(TimerArm {
                ident: ident_for(which),
                flags: libc::EV_ADD,
                delay_ns: 25_000_000,
            })
        );
        disarm(which);
    }

    #[test]
    fn current_arm_replays_cpu_periodic_timer_as_one_shot() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let which = 1; // VIRTUAL
        disarm(which);
        arm(which, 25_000_000, 25_000_000, false);
        assert_eq!(
            current_arm(which),
            Some(TimerArm {
                ident: ident_for(which),
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                delay_ns: 25_000_000,
            })
        );
        disarm(which);
    }
}
