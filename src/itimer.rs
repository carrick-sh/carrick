//! Process-global interval-timer (`setitimer`) state, shared between the
//! `setitimer` syscall handler (writer) and the signal pump (reader).
//!
//! Delivery moved off a per-arm OS thread onto `EVFILT_TIMER` events on the
//! signal pump's kqueue. The pump has no access to per-process `ProcState`, so
//! the re-arm interval for each `which` lives here as a process-global atomic.
//! Each `which` (REAL/VIRTUAL/PROF) owns one stable EVFILT_TIMER ident, so
//! arming/disarming is a single EV_ADD/EV_DELETE that supersedes any prior arm
//! (no generation counter needed).

use std::sync::atomic::{AtomicU64, Ordering};

/// Base of the EVFILT_TIMER ident range for itimers. Idents are
/// `BASE + which` for `which` in 0..3. The EVFILT_TIMER ident namespace is
/// distinct from EVFILT_READ (fds) and EVFILT_USER (ident 0) on the pump kq,
/// so this only needs to be internally distinct across the 3 timers.
pub const TIMER_IDENT_BASE: usize = 0x00C1_0000;

/// Number of `setitimer` `which` slots: ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF.
const WHICH_COUNT: usize = 3;

/// Re-arm interval in nanoseconds per `which`; 0 means "one-shot, no repeat".
/// Read by the pump when an EV_ONESHOT timer fires to decide whether to
/// re-register a periodic timer.
static INTERVAL_NS: [AtomicU64; WHICH_COUNT] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

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

/// Record the re-arm interval for `which` (0 = no repeat). Called by
/// `setitimer` on arm/disarm. Out-of-range `which` is ignored.
pub fn set_interval_ns(which: usize, ns: u64) {
    if let Some(slot) = INTERVAL_NS.get(which) {
        slot.store(ns, Ordering::SeqCst);
    }
}

/// The re-arm interval for `which` in nanoseconds (0 = no repeat).
pub fn interval_ns(which: usize) -> u64 {
    INTERVAL_NS.get(which).map_or(0, |slot| slot.load(Ordering::SeqCst))
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
}
