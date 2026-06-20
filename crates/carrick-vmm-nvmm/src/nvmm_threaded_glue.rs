//! NVMM impls of the shared threaded-loop coordinator traits.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use carrick_hal::{HostForkCoordinator, PlatformFutex, PreparedHostFork, VcpuRegistry};

use crate::nvmm_kicker::install_nvmm_kick_handler;

static SIGNAL_PUMP_INSTALLED: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
pub struct NvmmForkCoordinator;

impl NvmmForkCoordinator {
    pub fn new() -> Self {
        Self
    }

    fn ensure_handler_installed(&self) {
        install_nvmm_kick_handler();
        crate::nvmm_xsig::init_xsig();
        SIGNAL_PUMP_INSTALLED.store(true, Ordering::SeqCst);
    }
}

impl HostForkCoordinator for NvmmForkCoordinator {
    fn start_signal_pump(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        self.ensure_handler_installed();
        crate::nvmm_signal_pump::start_pump(registry, futex);
    }

    fn prepare_host_fork(&self) -> PreparedHostFork {
        let was_running = crate::nvmm_signal_pump::stop_pump_for_fork();
        let had_signal_pump = was_running || SIGNAL_PUMP_INSTALLED.load(Ordering::SeqCst);
        if had_signal_pump {
            crate::nvmm_signal_pump::block_pump_signals_for_fork();
        }
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
        crate::nvmm_signal_pump::restore_pump_signals_after_fork();
    }

    fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        if prepared.had_signal_pump {
            self.ensure_handler_installed();
        }
        crate::nvmm_signal_pump::reinit_after_fork(registry, futex);
        crate::nvmm_signal_pump::restore_pump_signals_after_fork();
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
        crate::nvmm_signal_pump::restore_pump_signals_after_fork();
    }
}

pub struct NvmmTimerDelivery {
    pub kicker: Arc<dyn VcpuRegistry>,
    pub main_tid: carrick_thread::thread::ThreadId,
}

impl carrick_hal::TimerDelivery for NvmmTimerDelivery {
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

    fn disarm_itimer(&self, which: usize) {
        carrick_timer_core::itimer::disarm(which);
    }

    fn arm_posix(
        &self,
        id: i32,
        value_ns: u64,
        interval_ns: u64,
    ) -> Option<carrick_hal::timer_delivery::PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, value_ns, interval_ns)?;
        if value_ns > 0 {
            let signum = armed.signum;
            let generation = armed.generation;
            let slot = armed.slot.clone();
            let kicker = Arc::clone(&self.kicker);
            let _ = std::thread::Builder::new()
                .name(format!("carrick-ptimer-{id}"))
                .spawn(move || {
                    std::thread::sleep(std::time::Duration::from_nanos(value_ns));
                    if !carrick_timer_core::posix::generation_matches(&slot, generation) {
                        return;
                    }
                    carrick_signal_core::publish_process_signal(signum);
                    kicker.kick_all();
                    if interval_ns == 0 {
                        return;
                    }
                    loop {
                        std::thread::sleep(std::time::Duration::from_nanos(interval_ns));
                        if !carrick_timer_core::posix::generation_matches(&slot, generation) {
                            return;
                        }
                        carrick_timer_core::posix::record_overrun(&slot);
                        carrick_signal_core::publish_process_signal(signum);
                        kicker.kick_all();
                    }
                });
        }
        Some(armed.old)
    }

    fn disarm_posix(&self, id: i32) {
        let _ = carrick_timer_core::posix::arm(id, 0, 0);
    }

    fn current_arm(&self, which: usize) -> Option<carrick_hal::timer_delivery::TimerArm> {
        carrick_timer_core::itimer::current_arm(which)
    }
}
