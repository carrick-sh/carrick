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

/// Base of the EVFILT_TIMER ident range for itimers. Idents are
/// `BASE + which` for `which` in 0..3. The EVFILT_TIMER ident namespace is
/// distinct from EVFILT_READ (fds) and EVFILT_USER (ident 0) on the pump kq,
/// so this only needs to be internally distinct across the 3 timers.
pub const TIMER_IDENT_BASE: usize = 0x00C1_0000;

/// Number of `setitimer` `which` slots: ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF.
const WHICH_COUNT: usize = 3;

/// Per-`which` interval-timer state shared between `setitimer` and the pump.
struct ItimerSlot {
    /// Repeat period in nanoseconds; 0 = no repeat (one-shot).
    interval_ns: AtomicU64,
    /// True between an arm and the matching disarm. A fire for a `!armed`
    /// `which` is stale (disarmed or resurrected by a race) and is dropped.
    armed: AtomicBool,
    /// Set when an arm used a one-shot for `it_value` but wants a periodic
    /// repeat afterwards (`it_value != it_interval`). Consumed by the pump on
    /// the first fire, which then arms the periodic timer exactly once.
    needs_periodic: AtomicBool,
}

impl ItimerSlot {
    const fn new() -> Self {
        Self {
            interval_ns: AtomicU64::new(0),
            armed: AtomicBool::new(false),
            needs_periodic: AtomicBool::new(false),
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

/// Mark `which` armed with the given repeat interval (0 = one-shot) and whether
/// the pump must transition a one-shot to periodic on its first fire. Called by
/// `setitimer`. Out-of-range `which` is ignored.
pub fn arm(which: usize, interval_ns: u64, needs_periodic: bool) {
    if let Some(slot) = SLOTS.get(which) {
        slot.interval_ns.store(interval_ns, Ordering::SeqCst);
        slot.needs_periodic.store(needs_periodic, Ordering::SeqCst);
        // Publish `armed` last so a pump fire that observes `armed` also sees
        // the interval/needs_periodic written above.
        slot.armed.store(true, Ordering::SeqCst);
    }
}

/// Mark `which` disarmed and clear its state. Called by `setitimer` on a zero
/// `it_value`. Out-of-range `which` is ignored.
pub fn disarm(which: usize) {
    if let Some(slot) = SLOTS.get(which) {
        slot.armed.store(false, Ordering::SeqCst);
        slot.interval_ns.store(0, Ordering::SeqCst);
        slot.needs_periodic.store(false, Ordering::SeqCst);
    }
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
    fn arm_disarm_round_trip() {
        // Use which=2 (PROF) to avoid colliding with other tests' slots.
        let which = 2;
        disarm(which);
        assert!(!is_armed(which));
        assert_eq!(interval_ns(which), 0);

        arm(which, 5_000, true);
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
        let which = 1; // VIRTUAL
        disarm(which);
        arm(which, 0, false);
        assert!(is_armed(which));
        assert_eq!(interval_ns(which), 0);
        assert!(!take_needs_periodic(which));
        disarm(which);
    }
}
