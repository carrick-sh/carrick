//! The transition gate every timer slot (interval and POSIX) serializes its
//! arm/disarm/delete transitions and its expiry deliveries through, and the
//! [`FireOutcome`] a gated delivery attempt reports.
//!
//! A timer's slot fields are individually atomic for lock-free readers, but a
//! generation check followed by an expiry decision and a delivery is only
//! meaningful if no arm/disarm/delete can land in between. Without the gate a
//! delivery thread that had observed its generation could deliver a signal for
//! a timer the guest already disarmed, deleted or replaced: Linux serializes
//! expiry against `setitimer` / `timer_settime` / `timer_delete`, so once one
//! of those returns no expiry of the superseded setting generates a signal. A
//! delivery that wins the gate first completes before the transition proceeds
//! (Linux likewise leaves a signal generated before the call pending).
//!
//! Holders run only bounded, non-reentrant work: slot-field updates, or a
//! delivery callback (publish a signal, kick, wake, register a kevent), which
//! must never re-enter a transition of the SAME slot.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::WallNs;

/// A bounded-spin, `no_std` exclusion gate guarding one timer slot.
#[derive(Debug, Default)]
pub struct TransitionGate {
    held: AtomicBool,
}

impl TransitionGate {
    pub const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
        }
    }

    /// Acquire the gate; released when the returned hold drops.
    pub fn hold(&self) -> GateHold<'_> {
        while self
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        GateHold { gate: self }
    }

    /// Fork-child reset: release a gate that may have been copied held by a
    /// parent delivery thread caught mid-delivery. That thread does not exist
    /// in the child (fork copies only the calling thread), so nothing else
    /// would ever release it. Only sound while the caller is the child's sole
    /// thread.
    pub fn release_after_fork(&self) {
        self.held.store(false, Ordering::Release);
    }

    /// Whether the gate is currently held (tests and fork diagnostics only).
    pub fn is_held(&self) -> bool {
        self.held.load(Ordering::Acquire)
    }
}

/// Exclusive hold of a [`TransitionGate`].
#[derive(Debug)]
pub struct GateHold<'a> {
    gate: &'a TransitionGate,
}

impl Drop for GateHold<'_> {
    fn drop(&mut self) {
        self.gate.held.store(false, Ordering::Release);
    }
}

/// Outcome of one gated delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FireOutcome {
    /// The expiry was delivered and the periodic arm stays live.
    Fired,
    /// A CPU timer is not due yet; re-check after this WALL-CLOCK delay.
    Wait { delay_ns: WallNs },
    /// The caller's arm is gone: superseded, disarmed or deleted before this
    /// attempt, or a one-shot this attempt just delivered and retired. The
    /// delivery thread exits.
    Retired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hold_excludes_until_dropped() {
        let gate = TransitionGate::new();
        let hold = gate.hold();
        assert!(gate.is_held());
        drop(hold);
        assert!(!gate.is_held());
        let _again = gate.hold();
        assert!(gate.is_held());
    }

    #[test]
    fn release_after_fork_frees_an_orphaned_hold() {
        let gate = TransitionGate::new();
        core::mem::forget(gate.hold());
        assert!(gate.is_held());
        gate.release_after_fork();
        let _hold = gate.hold();
    }
}
