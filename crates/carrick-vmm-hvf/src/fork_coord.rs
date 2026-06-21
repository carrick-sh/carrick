//! HVF's [`carrick_hal::HostSignalPump`]: a KQUEUE pump, paired with the shared
//! [`carrick_hal::PumpForkCoordinator`] state machine.
//!
//! THEORY OF OPERATION
//!
//! [`crate::fork_quiesce`] handles the GUEST threads around a fork; this module
//! handles Carrick's own daemon HOST thread — the [`crate::vcpu_kick`]
//! `SignalPump`. `fork(2)` carries only the calling thread into the child, so a
//! background pump thread alive at the fork point becomes a dead stub in the
//! child. [`PumpForkCoordinator`] therefore STOPS + JOINS the pump (via
//! [`KqueuePump::stop_for_fork`]) before `libc::fork`, and the post-fork paths
//! restart a fresh pump. The pump is held behind a `Mutex<Option<SignalPump>>`
//! and `start` is idempotent, so a child that re-forks re-runs the cycle cleanly.
//! The stop is the BOUNDED `SignalPump::stop` so a pump that can no longer be woken
//! (the forkserver-from-forkserver lost-wake case) detaches rather than hanging.
//!
//! HVF differs from the kick+futex backends in three ways, all expressed as
//! [`carrick_hal::HostSignalPump`] methods: (1) its pump is KQUEUE, not a self-pipe
//! (the `Mutex<Option<SignalPump>>` below); (2) it is LAZY, not always-on —
//! `installed_independent_of_stop` is `false`, so a non-interactive guest that
//! never started a pump stays pump-free across forks (the pump only exists while a
//! tty needs it); (3) the child's self-pipe reinit is owned by the RUNTIME
//! (`host_signal::reinit_after_fork`, run before the coordinator's restart), so
//! `reinit_child` only respawns the pump thread, and only `if had`.

use std::sync::Arc;

use parking_lot::Mutex;

use carrick_hal::{HostSignalPump, PlatformFutex, PumpForkCoordinator, VcpuRegistry};

use crate::vcpu_kick::SignalPump;

/// HVF's kqueue async host-signal pump primitive. Owns the lazily-spawned pump
/// thread behind a `Mutex<Option<SignalPump>>`.
#[derive(Default)]
pub struct KqueuePump {
    signal_pump: Mutex<Option<SignalPump>>,
}

impl KqueuePump {
    #[cfg(test)]
    pub fn has_signal_pump_for_tests(&self) -> bool {
        self.signal_pump.lock().is_some()
    }
}

impl HostSignalPump for KqueuePump {
    fn ensure_handler(&self) {
        // No-op: HVF's vCPU kick is `hv_vcpus_exit` (not a signal), and its
        // cross-process signal handlers are installed once via
        // `host_signal::install_default_handlers` at run start — there is no
        // per-fork kick-handler / xsig-ring install to re-assert.
    }

    fn start(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        let mut pump = self.signal_pump.lock();
        if pump.is_none() {
            *pump = Some(crate::vcpu_kick::spawn_signal_pump(
                Arc::clone(registry),
                Arc::clone(futex),
            ));
        }
    }

    fn stop_for_fork(&self) -> bool {
        if let Some(pump) = self.signal_pump.lock().take() {
            pump.stop();
            true
        } else {
            false
        }
    }

    fn installed_independent_of_stop(&self) -> bool {
        // LAZY: a stopped/absent pump means no pump (HVF only runs one while a tty
        // needs it). No always-on process-global handler to keep `had` true.
        false
    }

    // block/restore_signals_for_fork: default no-op. HVF's routed handlers poke a
    // self-pipe, so a real pthread_sigmask of the pump signal set across the fork
    // window is a tracked robustness follow-up; today (as before this fold) HVF
    // relies on the bounded stop + the guest-thread fork_quiesce barrier.

    fn reinit_child(
        &self,
        had: bool,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        // The child's self-pipe reinit is the RUNTIME's job
        // (`host_signal::reinit_after_fork`, run BEFORE this restart), so here we
        // only respawn the pump THREAD, and only if the parent had one (lazy).
        if had {
            self.start(registry, futex);
        }
    }
}

/// HVF's host-fork coordinator: the neutral [`PumpForkCoordinator`] state machine
/// over the [`KqueuePump`]. (Was a hand-rolled `ForkCoordinator` struct + the same
/// state machine the kick+futex backends also hand-rolled.)
pub type ForkCoordinator = PumpForkCoordinator<KqueuePump>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thread::FutexTable;
    use crate::threaded_impl::hvf_futex;
    use crate::vcpu_kick::VcpuKicker;
    use carrick_hal::HostForkCoordinator;

    fn dyn_context() -> (Arc<dyn VcpuRegistry>, Arc<dyn PlatformFutex>) {
        let registry: Arc<dyn VcpuRegistry> = Arc::new(VcpuKicker::new());
        let futex: Arc<dyn PlatformFutex> = Arc::new(hvf_futex(Arc::new(FutexTable::new())));
        (registry, futex)
    }

    #[test]
    fn host_fork_preparation_stops_and_restarts_signal_pump() {
        let _g = crate::host_signal::pump_state_test_guard();
        crate::host_signal::install_default_handlers();
        let coordinator = ForkCoordinator::new();
        let (registry, futex) = dyn_context();

        coordinator.start_signal_pump(&registry, &futex);
        assert!(coordinator.pump().has_signal_pump_for_tests());

        let prepared = coordinator.prepare_host_fork();
        assert!(
            !coordinator.pump().has_signal_pump_for_tests(),
            "signal pump host thread must be joined before host fork"
        );

        coordinator.restart_after_parent_fork(prepared, &registry, &futex, false);
        assert!(
            coordinator.pump().has_signal_pump_for_tests(),
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
            !coordinator.pump().has_signal_pump_for_tests(),
            "parent with no preexisting pump and no async child-exit signal should stay pump-free"
        );

        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_parent_fork(prepared, &registry, &futex, true);
        assert!(
            coordinator.pump().has_signal_pump_for_tests(),
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
            !coordinator.pump().has_signal_pump_for_tests(),
            "fork children should not create a pump unless the parent needed one"
        );

        coordinator.start_signal_pump(&registry, &futex);
        let prepared = coordinator.prepare_host_fork();
        coordinator.restart_after_child_fork(prepared, &registry, &futex);
        assert!(
            coordinator.pump().has_signal_pump_for_tests(),
            "a child inheriting caught signal state must restart its pump"
        );
    }
}
