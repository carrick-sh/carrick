//! Platform-NEUTRAL interval/POSIX timer-slot bookkeeping + guest-CPU-due math,
//! shared by every backend. Delivery (kqueue EVFILT_TIMER vs the wall-clock
//! fallback thread) is the backend's `TimerDelivery`; this crate owns the slot
//! state + `cpu_timer_decision` only. Filled in by Task 4.

/// The 3 itimer `which` values (REAL=0, VIRTUAL=1, PROF=2).
pub const ITIMER_COUNT: usize = 3;

/// ITIMER_VIRTUAL(1) / ITIMER_PROF(2) measure GUEST CPU time, not wall-clock.
pub fn is_cpu_timer(which: usize) -> bool {
    which == 1 || which == 2
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_timer_classification() {
        assert!(!is_cpu_timer(0)); // REAL
        assert!(is_cpu_timer(1)); // VIRTUAL
        assert!(is_cpu_timer(2)); // PROF
    }
}
