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
    /// bhyve has no kqueue pump, so the dispatch arm spawns
    /// `itimer::run_fallback` (return `false`) — identical to KVM/NVMM.
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
        // Bump the slot generation so the running fallback thread retires; the
        // previous no-op leaked `armed = true` and let a disarmed itimer keep
        // firing.
        carrick_timer_core::itimer::disarm(which);
    }

    fn arm_posix(
        &self,
        id: i32,
        spec: carrick_hal::timer_delivery::TimerSpecNs,
    ) -> Option<carrick_hal::timer_delivery::PosixTimerSpec> {
        // Was a silent no-op: POSIX per-process timers did nothing on FreeBSD.
        // Spawn the shared firing thread (publish the PROCESS signal + kick every
        // vCPU), exactly like KVM/NVMM.
        let armed = carrick_timer_core::posix::arm(id, spec)?;
        if spec.value > 0 {
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
                    carrick_timer_core::posix::run_fallback(slot, generation, spec, on_fire);
                });
        }
        Some(armed.old)
    }

    fn disarm_posix(&self, id: i32) {
        let _ = carrick_timer_core::posix::arm(id, carrick_timer_core::TimerSpecNs::DISARM);
    }

    fn current_arm(&self, which: usize) -> Option<carrick_hal::timer_delivery::TimerArm> {
        carrick_timer_core::itimer::current_arm(which)
    }
}
