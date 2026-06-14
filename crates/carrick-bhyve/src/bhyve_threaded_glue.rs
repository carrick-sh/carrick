//! Lean bhyve impls of the threaded-loop coordinator traits. Mirrors the KVM
//! shapes minus the async host-signal pump (deferred to Tier 3+).

use std::sync::Arc;

use carrick_hal::{
    HostForkCoordinator, PlatformFutex, PreparedHostFork, SignalArrival, VcpuRegistry,
};

use crate::bhyve_kicker::install_bhyve_kick_handler;

#[derive(Default)]
pub struct BhyveForkCoordinator;

impl BhyveForkCoordinator {
    pub fn new() -> Self {
        Self
    }
}

impl HostForkCoordinator for BhyveForkCoordinator {
    fn start_signal_pump(
        &self,
        _registry: &Arc<dyn VcpuRegistry>,
        _futex: &Arc<dyn PlatformFutex>,
    ) {
        install_bhyve_kick_handler();
    }

    fn prepare_host_fork(&self) -> PreparedHostFork {
        PreparedHostFork {
            had_signal_pump: true,
        }
    }

    fn restart_after_parent_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
        _child_exit_needs_signal_pump: bool,
    ) {
        if prepared.had_signal_pump {
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

pub struct BhyveSignalArrival {
    pub kicker: Arc<dyn VcpuRegistry>,
    pub futex: Arc<dyn PlatformFutex>,
}

impl SignalArrival for BhyveSignalArrival {
    fn wake_all_waiters(&self) {
        self.kicker.kick_all();
        self.futex.notify_signal_pending();
    }
}

pub struct BhyveTimerDelivery {
    pub kicker: Arc<dyn VcpuRegistry>,
    pub main_tid: carrick_thread::thread::ThreadId,
}

impl carrick_hal::TimerDelivery for BhyveTimerDelivery {
    fn arm_itimer(
        &self,
        _which: usize,
        _value_ns: u64,
        _interval_ns: u64,
        _needs_periodic: bool,
        _signum: i32,
    ) -> bool {
        false
    }

    fn disarm_itimer(&self, _which: usize) {}

    fn arm_posix(
        &self,
        _id: i32,
        _value_ns: u64,
        _interval_ns: u64,
    ) -> Option<carrick_hal::timer_delivery::PosixTimerSpec> {
        None
    }

    fn disarm_posix(&self, _id: i32) {}

    fn current_arm(&self, _which: usize) -> Option<carrick_hal::timer_delivery::TimerArm> {
        None
    }
}
