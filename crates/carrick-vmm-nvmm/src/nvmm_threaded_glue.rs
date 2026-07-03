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
