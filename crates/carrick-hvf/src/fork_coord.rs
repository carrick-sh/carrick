//! Coordination for Carrick-owned host state that must be quiesced around
//! real host fork operations.
//!
//! THEORY OF OPERATION
//!
//! [`crate::fork_quiesce`] handles the GUEST threads around a fork; this module
//! handles Carrick's own daemon HOST thread — the [`crate::vcpu_kick`]
//! `SignalPump`. `fork(2)` carries only the calling thread into the child, so a
//! background pump thread that is alive at the fork point becomes a dead stub in
//! the child (its kqueue/pipes inherited but unowned) and a duplicate in the
//! parent's address space. [`ForkCoordinator::prepare_host_fork`] therefore STOPS
//! and JOINS the pump before `libc::fork`, yielding a [`PreparedHostFork`] token
//! that the three post-fork paths (parent, child, error) trade back in to
//! restart a fresh pump. The pump is held behind a `Mutex<Option<SignalPump>>`
//! and `start_signal_pump` is idempotent, so a child that re-forks re-runs the
//! whole stop/restart cycle cleanly. The stop is the BOUNDED `SignalPump::stop`
//! (see [`crate::vcpu_kick`]) so a pump that can no longer be woken — the
//! forkserver-from-forkserver lost-wake case — detaches rather than hanging the
//! host fork.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::thread::FutexTable;
use crate::vcpu_kick::{SignalPump, VcpuKicker};

/// Coordinates Carrick-owned host state that must not be left mid-flight across
/// a real host `fork(2)`.
pub struct ForkCoordinator {
    signal_pump: Mutex<Option<SignalPump>>,
}

pub struct PreparedHostFork {
    had_signal_pump: bool,
    _private: (),
}

impl Default for ForkCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ForkCoordinator {
    pub fn new() -> Self {
        Self {
            signal_pump: Mutex::new(None),
        }
    }

    pub fn start_signal_pump(&self, kicker: &Arc<VcpuKicker>, futex: &Arc<FutexTable>) {
        let mut pump = self.signal_pump.lock();
        if pump.is_none() {
            *pump = Some(crate::vcpu_kick::spawn_signal_pump(
                Arc::clone(kicker),
                Arc::clone(futex),
            ));
        }
    }

    pub fn prepare_host_fork(&self) -> PreparedHostFork {
        let had_signal_pump = if let Some(pump) = self.signal_pump.lock().take() {
            pump.stop();
            true
        } else {
            false
        };
        PreparedHostFork {
            had_signal_pump,
            _private: (),
        }
    }

    pub fn restart_after_parent_fork(
        &self,
        prepared: PreparedHostFork,
        kicker: &Arc<VcpuKicker>,
        futex: &Arc<FutexTable>,
        child_exit_needs_signal_pump: bool,
    ) {
        if prepared.had_signal_pump || child_exit_needs_signal_pump {
            self.start_signal_pump(kicker, futex);
        }
    }

    pub fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        kicker: &Arc<VcpuKicker>,
        futex: &Arc<FutexTable>,
    ) {
        if prepared.had_signal_pump {
            self.start_signal_pump(kicker, futex);
        }
    }

    pub fn restart_after_fork_error(
        &self,
        prepared: PreparedHostFork,
        kicker: &Arc<VcpuKicker>,
        futex: &Arc<FutexTable>,
    ) {
        if prepared.had_signal_pump {
            self.start_signal_pump(kicker, futex);
        }
    }

    #[cfg(test)]
    fn has_signal_pump_for_tests(&self) -> bool {
        self.signal_pump.lock().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_fork_preparation_stops_and_restarts_signal_pump() {
        crate::host_signal::install_default_handlers();
        let coordinator = ForkCoordinator::new();
        let kicker = Arc::new(VcpuKicker::new());
        let futex = Arc::new(FutexTable::new());

        coordinator.start_signal_pump(&kicker, &futex);
        assert!(coordinator.has_signal_pump_for_tests());

        let prepared = coordinator.prepare_host_fork();
        assert!(
            !coordinator.has_signal_pump_for_tests(),
            "signal pump host thread must be joined before host fork"
        );

        coordinator.restart_after_parent_fork(prepared, &kicker, &futex, false);
        assert!(
            coordinator.has_signal_pump_for_tests(),
            "parent must restart the signal pump after host fork"
        );
    }

    #[test]
    fn parent_can_skip_absent_signal_pump_until_child_exit_needs_it() {
        crate::host_signal::install_default_handlers();
        let coordinator = ForkCoordinator::new();
        let kicker = Arc::new(VcpuKicker::new());
        let futex = Arc::new(FutexTable::new());

        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_parent_fork(prepared, &kicker, &futex, false);
        assert!(
            !coordinator.has_signal_pump_for_tests(),
            "parent with no preexisting pump and no async child-exit signal should stay pump-free"
        );

        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_parent_fork(prepared, &kicker, &futex, true);
        assert!(
            coordinator.has_signal_pump_for_tests(),
            "caught or blocked child-exit signals still require the parent pump"
        );
    }

    #[test]
    fn child_restarts_only_inherited_signal_pump() {
        crate::host_signal::install_default_handlers();
        let coordinator = ForkCoordinator::new();
        let kicker = Arc::new(VcpuKicker::new());
        let futex = Arc::new(FutexTable::new());

        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_child_fork(prepared, &kicker, &futex);
        assert!(
            !coordinator.has_signal_pump_for_tests(),
            "fork children should not create a pump unless the parent needed one"
        );

        coordinator.start_signal_pump(&kicker, &futex);
        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_child_fork(prepared, &kicker, &futex);
        assert!(
            coordinator.has_signal_pump_for_tests(),
            "a child inheriting caught signal state must restart its pump"
        );
    }
}
