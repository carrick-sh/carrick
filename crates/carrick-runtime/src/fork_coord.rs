//! Coordination for Carrick-owned host state that must be quiesced around
//! real host fork operations.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::thread::FutexTable;
use crate::vcpu_kick::{SignalPump, VcpuKicker};

/// Coordinates Carrick-owned host state that must not be left mid-flight across
/// a real host `fork(2)`.
pub(crate) struct ForkCoordinator {
    signal_pump: Mutex<Option<SignalPump>>,
}

pub(crate) struct PreparedHostFork {
    _private: (),
}

impl ForkCoordinator {
    pub(crate) fn new() -> Self {
        Self {
            signal_pump: Mutex::new(None),
        }
    }

    pub(crate) fn start_signal_pump(&self, kicker: &Arc<VcpuKicker>, futex: &Arc<FutexTable>) {
        let mut pump = self.signal_pump.lock();
        if pump.is_none() {
            *pump = Some(crate::vcpu_kick::spawn_signal_pump(
                Arc::clone(kicker),
                Arc::clone(futex),
            ));
        }
    }

    pub(crate) fn prepare_host_fork(&self) -> PreparedHostFork {
        if let Some(pump) = self.signal_pump.lock().take() {
            pump.stop();
        }
        PreparedHostFork { _private: () }
    }

    pub(crate) fn restart_after_parent_fork(
        &self,
        _prepared: PreparedHostFork,
        kicker: &Arc<VcpuKicker>,
        futex: &Arc<FutexTable>,
    ) {
        self.start_signal_pump(kicker, futex);
    }

    pub(crate) fn restart_after_child_fork(
        &self,
        _prepared: PreparedHostFork,
        kicker: &Arc<VcpuKicker>,
        futex: &Arc<FutexTable>,
    ) {
        self.start_signal_pump(kicker, futex);
    }

    pub(crate) fn restart_after_fork_error(
        &self,
        _prepared: PreparedHostFork,
        kicker: &Arc<VcpuKicker>,
        futex: &Arc<FutexTable>,
    ) {
        self.start_signal_pump(kicker, futex);
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

        coordinator.restart_after_parent_fork(prepared, &kicker, &futex);
        assert!(
            coordinator.has_signal_pump_for_tests(),
            "parent must restart the signal pump after host fork"
        );
    }
}
