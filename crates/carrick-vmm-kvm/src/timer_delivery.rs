//! KVM's `TimerDelivery`. The Linux/KVM backend has no kqueue signal pump, so
//! interval-timer delivery is the SHARED wall-clock fallback thread: `arm_itimer`
//! returns `false`, and the dispatch arm spawns `carrick_timer_core::itimer::
//! run_fallback`. POSIX per-process timers DO spawn their firing thread here
//! (replicating the old runtime-inline `posix_timer::arm`): the slot mutation is
//! delegated to `carrick_timer_core::posix::arm`, then a wall-clock thread
//! publishes the signal into the per-thread pending store and KICKS the target
//! vCPU — the SAME publish+kick the runtime's `timer_delivery::deliver` performs.
use std::sync::Arc;

use carrick_hal::{PosixTimerSpec, ThreadId, TimerArm, TimerDelivery, VcpuRegistry};

pub struct KvmTimerDelivery {
    /// The live-vCPU registry used to force the target out of `KVM_RUN` on a
    /// timer expiry (the firing thread publishes pending, then kicks).
    pub kicker: Arc<dyn VcpuRegistry>,
    /// The guest's main thread id. Wall-clock interval/POSIX timer signals are
    /// PROCESS-directed and now fan out via the shared PROC_PENDING mask +
    /// `kick_all` (so a blocked main thread does not drop the timer), so this is
    /// retained only as the canonical main-thread handle for the construction
    /// site; the firing thread no longer pins delivery to it.
    pub main_tid: ThreadId,
}

impl TimerDelivery for KvmTimerDelivery {
    /// KVM has no pump kqueue → the caller spawns `run_fallback`. The neutral
    /// slot state was already written by the dispatch arm (timer-core::arm).
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

    fn arm_posix(&self, id: i32, value_ns: u64, interval_ns: u64) -> Option<PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, value_ns, interval_ns)?;
        if value_ns > 0 {
            let signum = armed.signum;
            let generation = armed.generation;
            let slot = armed.slot.clone();
            let kicker = Arc::clone(&self.kicker);
            // POSIX per-process timer signals are PROCESS-directed: publish into
            // the shared PROC_PENDING mask and kick EVERY vCPU so any unblocked
            // thread delivers it (a blocked main thread must not drop the timer).
            // The wall-clock-vs-CPU-clock timing loop is shared in timer-core.
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
        // A zero-value arm disarms (bumps generation so the firing thread
        // retires); the previous spec is discarded.
        let _ = carrick_timer_core::posix::arm(id, 0, 0);
    }

    fn current_arm(&self, which: usize) -> Option<TimerArm> {
        carrick_timer_core::itimer::current_arm(which)
    }
}
