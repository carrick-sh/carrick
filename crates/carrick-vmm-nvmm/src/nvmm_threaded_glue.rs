//! NVMM impls of the shared threaded-loop coordinator traits.
//!
//! `NvmmSignalPumpControl` is the shared
//! [`carrick_hal::GenericSignalPumpControl`] parameterized by [`crate::NvmmGlue`].
//! `NvmmTimerDelivery` stays here (NetBSD posix/itimer arming).

use std::sync::Arc;

use carrick_hal::VcpuRegistry;

/// The NVMM signal-pump controller: the shared generic + NVMM's glue.
pub type NvmmSignalPumpControl = carrick_hal::GenericSignalPumpControl<crate::NvmmGlue>;

pub struct NvmmTimerDelivery {
    pub kicker: Arc<dyn VcpuRegistry>,
    pub main_tid: carrick_thread::thread::ThreadId,
}

impl carrick_hal::TimerDelivery for NvmmTimerDelivery {
    fn arm_itimer(
        &self,
        _which: usize,
        _spec: carrick_hal::timer_delivery::TimerSpecNs,
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
        spec: carrick_hal::timer_delivery::TimerSpecNs,
    ) -> Option<carrick_hal::timer_delivery::PosixTimerSpec> {
        carrick_hal::timer_delivery::arm_fallback_posix_timer(id, spec, &self.kicker)
    }

    fn disarm_posix(&self, id: i32) {
        carrick_hal::timer_delivery::disarm_fallback_posix_timer(id);
    }

    fn current_arm(&self, which: usize) -> Option<carrick_hal::timer_delivery::TimerArm> {
        carrick_timer_core::itimer::current_arm(which)
    }
}
