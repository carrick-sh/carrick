//! Lean bhyve impls of the threaded-loop coordinator traits.
//!
//! `BhyveForkCoordinator` is now the shared
//! [`carrick_hal::GenericForkCoordinator`] parameterized by [`crate::BhyveGlue`]:
//! the stop+join-the-pump-across-`libc::fork` lifecycle, the idempotent
//! kick-handler install, the xsignal-ring init, and the 5 restart paths were
//! byte-identical across KVM/bhyve/NVMM and now live in carrick-hal. bhyve supplies
//! only `BhyveGlue`. `BhyveTimerDelivery` stays here (bhyve has no kqueue itimer).

use std::sync::Arc;

use carrick_hal::VcpuRegistry;

/// The bhyve host-fork coordinator: the shared generic + bhyve's glue.
pub type BhyveForkCoordinator = carrick_hal::GenericForkCoordinator<crate::BhyveGlue>;

// `BhyveSignalArrival` was byte-identical to KVM's; both collapsed into the
// shared `carrick_hal::GenericSignalArrival` (kicker + futex wake). The bhyve run
// loop constructs that directly.

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
