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
//!
//! The shared threaded loop drives this through the object-safe
//! [`carrick_hal::HostForkCoordinator`] trait, so it never names the concrete
//! `ForkCoordinator` / `VcpuKicker` / `FutexTable`; the registry + futex are the
//! `Arc<dyn VcpuRegistry>` / `Arc<dyn PlatformFutex>` the loop already holds.

use std::sync::Arc;

use parking_lot::Mutex;

use carrick_hal::{HostForkCoordinator, PlatformFutex, PreparedHostFork, VcpuRegistry};

use crate::vcpu_kick::SignalPump;

/// Coordinates Carrick-owned host state that must not be left mid-flight across
/// a real host `fork(2)`.
pub struct ForkCoordinator {
    signal_pump: Mutex<Option<SignalPump>>,
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

    #[cfg(test)]
    fn has_signal_pump_for_tests(&self) -> bool {
        self.signal_pump.lock().is_some()
    }
}

impl HostForkCoordinator for ForkCoordinator {
    fn start_signal_pump(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        let mut pump = self.signal_pump.lock();
        if pump.is_none() {
            *pump = Some(crate::vcpu_kick::spawn_signal_pump(
                Arc::clone(registry),
                Arc::clone(futex),
            ));
        }
    }

    fn prepare_host_fork(&self) -> PreparedHostFork {
        let had_signal_pump = if let Some(pump) = self.signal_pump.lock().take() {
            pump.stop();
            true
        } else {
            false
        };
        PreparedHostFork { had_signal_pump }
    }

    fn restart_after_parent_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
        child_exit_needs_signal_pump: bool,
    ) {
        if prepared.had_signal_pump || child_exit_needs_signal_pump {
            self.start_signal_pump(registry, futex);
        }
    }

    fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        if prepared.had_signal_pump {
            self.start_signal_pump(registry, futex);
        }
    }

    fn restart_after_fork_error(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        if prepared.had_signal_pump {
            self.start_signal_pump(registry, futex);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thread::FutexTable;
    use crate::threaded_impl::HvfFutex;
    use crate::vcpu_kick::VcpuKicker;

    fn dyn_context() -> (Arc<dyn VcpuRegistry>, Arc<dyn PlatformFutex>) {
        let registry: Arc<dyn VcpuRegistry> = Arc::new(VcpuKicker::new());
        let futex: Arc<dyn PlatformFutex> = Arc::new(HvfFutex(Arc::new(FutexTable::new())));
        (registry, futex)
    }

    #[test]
    fn host_fork_preparation_stops_and_restarts_signal_pump() {
        let _g = crate::host_signal::pump_state_test_guard();
        crate::host_signal::install_default_handlers();
        let coordinator = ForkCoordinator::new();
        let (registry, futex) = dyn_context();

        coordinator.start_signal_pump(&registry, &futex);
        assert!(coordinator.has_signal_pump_for_tests());

        let prepared = coordinator.prepare_host_fork();
        assert!(
            !coordinator.has_signal_pump_for_tests(),
            "signal pump host thread must be joined before host fork"
        );

        coordinator.restart_after_parent_fork(prepared, &registry, &futex, false);
        assert!(
            coordinator.has_signal_pump_for_tests(),
            "parent must restart the signal pump after host fork"
        );
    }

    #[test]
    fn parent_can_skip_absent_signal_pump_until_child_exit_needs_it() {
        let _g = crate::host_signal::pump_state_test_guard();
        crate::host_signal::install_default_handlers();
        let coordinator = ForkCoordinator::new();
        let (registry, futex) = dyn_context();

        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_parent_fork(prepared, &registry, &futex, false);
        assert!(
            !coordinator.has_signal_pump_for_tests(),
            "parent with no preexisting pump and no async child-exit signal should stay pump-free"
        );

        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_parent_fork(prepared, &registry, &futex, true);
        assert!(
            coordinator.has_signal_pump_for_tests(),
            "caught or blocked child-exit signals still require the parent pump"
        );
    }

    #[test]
    fn child_restarts_only_inherited_signal_pump() {
        let _g = crate::host_signal::pump_state_test_guard();
        crate::host_signal::install_default_handlers();
        let coordinator = ForkCoordinator::new();
        let (registry, futex) = dyn_context();

        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_child_fork(prepared, &registry, &futex);
        assert!(
            !coordinator.has_signal_pump_for_tests(),
            "fork children should not create a pump unless the parent needed one"
        );

        coordinator.start_signal_pump(&registry, &futex);
        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_child_fork(prepared, &registry, &futex);
        assert!(
            coordinator.has_signal_pump_for_tests(),
            "a child inheriting caught signal state must restart its pump"
        );
    }
}
