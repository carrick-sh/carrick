//! NVMM impls of the shared threaded-loop coordinator traits.
//!
//! `NvmmForkCoordinator` is now the shared
//! [`carrick_hal::GenericForkCoordinator`] parameterized by [`crate::NvmmGlue`]
//! (the fork/pump/xsig lifecycle was byte-identical across KVM/bhyve/NVMM).
//! `NvmmTimerDelivery` stays here (NetBSD posix/itimer arming).

use std::sync::Arc;

use carrick_hal::VcpuRegistry;

/// The NVMM host-fork coordinator: the shared generic + NVMM's glue.
pub type NvmmForkCoordinator = carrick_hal::GenericForkCoordinator<crate::NvmmGlue>;

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
            let on_fire = move || {
                carrick_signal_core::publish_process_signal(signum);
                kicker.kick_all();
            };
            let _ = std::thread::Builder::new()
                .name(format!("carrick-ptimer-{id}"))
                .spawn(move || {
                    carrick_timer_core::posix::run_fallback(
                        slot,
                        generation,
                        value_ns,
                        interval_ns,
                        on_fire,
                    );
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
