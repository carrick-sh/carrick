//! KVM's `TimerDelivery`. The Linux/KVM backend has no kqueue signal pump, so
//! interval-timer delivery is the SHARED wall-clock fallback thread: `arm_itimer`
//! returns `false`, and the dispatch arm spawns `carrick_timer_core::itimer::
//! run_fallback`. POSIX per-process timers DO spawn their firing thread here
//! (replicating the old runtime-inline `posix_timer::arm`): the slot mutation is
//! delegated to `carrick_timer_core::posix::arm`, then a wall-clock thread
//! publishes the signal into the per-thread pending store and KICKS the target
//! vCPU — the SAME publish+kick the runtime's `timer_delivery::deliver` performs.
use std::sync::Arc;
use std::time::Duration;

use carrick_hal::{PosixTimerSpec, ThreadId, TimerArm, TimerDelivery, VcpuRegistry};

pub struct KvmTimerDelivery {
    /// The live-vCPU registry used to force the target out of `KVM_RUN` on a
    /// timer expiry (the firing thread publishes pending, then kicks).
    pub kicker: Arc<dyn VcpuRegistry>,
    /// Wall-clock interval/POSIX timers are process-directed; deliver to the
    /// main thread (the common single-threaded timer case), matching the
    /// runtime's `timer_delivery::deliver`.
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
            let main_tid = self.main_tid;
            let deliver = move |sig: i32| {
                carrick_signal_core::publish_pending_for(main_tid, sig);
                kicker.kick(main_tid);
            };
            let _ = std::thread::Builder::new()
                .name(format!("carrick-ptimer-{id}"))
                .spawn(move || {
                    std::thread::sleep(Duration::from_nanos(value_ns));
                    if !carrick_timer_core::posix::generation_matches(&slot, generation) {
                        return;
                    }
                    deliver(signum);
                    if interval_ns == 0 {
                        return;
                    }
                    loop {
                        std::thread::sleep(Duration::from_nanos(interval_ns));
                        if !carrick_timer_core::posix::generation_matches(&slot, generation) {
                            return;
                        }
                        carrick_timer_core::posix::record_overrun(&slot);
                        deliver(signum);
                    }
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

    fn clear(&self) {
        // Fork-replay: reset all inherited interval-timer slots so a child does
        // not fire a stale signal. (POSIX timers are not inherited across the
        // fork-clear path; the registry is process-local.)
        carrick_timer_core::itimer::clear();
    }
}
