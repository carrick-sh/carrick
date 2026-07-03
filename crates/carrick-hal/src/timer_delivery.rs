//! How an armed timer SLOT becomes a delivered signal — the per-backend
//! mechanism behind the neutral `carrick-timer-core` slot/registry bookkeeping.
//! HVF arms an `EVFILT_TIMER` on its kqueue signal pump (so a busy vCPU is
//! kicked on expiry); KVM has no pump, so `arm_itimer` returns `false` and the
//! caller spawns the shared wall-clock fallback thread
//! (`carrick_timer_core::itimer::run_fallback`). The trait PERMITS divergence:
//! the slot/spec/remaining math is shared verbatim (timer-core), only the
//! delivery glue differs.
//!
//! `signum`/`si_value` for a POSIX timer are captured at `timer_create` (carried
//! on the slot), NOT at arm time — so `arm_posix` takes only `id` + the
//! value/interval spec, matching `carrick_timer_core::posix::arm`.
use std::sync::Arc;

use crate::threaded::VcpuRegistry;

pub use carrick_timer_core::TimerSpecNs;
pub use carrick_timer_core::itimer::TimerArm;
pub use carrick_timer_core::posix::PosixTimerSpec;

/// Arm a POSIX per-process timer using the shared fallback firing thread.
///
/// KVM, bhyve, and NVMM all lack the HVF kqueue timer pump path, so their
/// delivery sequence is identical: mutate the neutral timer-core slot, spawn a
/// per-arm fallback thread, publish the process-directed Linux signal, and kick
/// every vCPU so any unblocked guest thread can observe it.
pub fn arm_fallback_posix_timer(
    id: i32,
    spec: TimerSpecNs,
    kicker: &Arc<dyn VcpuRegistry>,
) -> Option<PosixTimerSpec> {
    let armed = carrick_timer_core::posix::arm(id, spec)?;
    if spec.value > 0 {
        let signum = armed.signum;
        let generation = armed.generation;
        let slot = armed.slot.clone();
        let kicker = Arc::clone(kicker);
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

/// Disarm a POSIX timer driven by [`arm_fallback_posix_timer`].
///
/// `TimerSpecNs::DISARM` bumps the timer-core generation, causing any in-flight
/// fallback thread to retire before it can publish another signal.
pub fn disarm_fallback_posix_timer(id: i32) {
    let _ = carrick_timer_core::posix::arm(id, TimerSpecNs::DISARM);
}

pub trait TimerDelivery: Send + Sync {
    /// Arm interval timer `which`. The neutral slot state is written by the
    /// caller into timer-core FIRST (via `carrick_timer_core::itimer::arm`);
    /// this method initiates DELIVERY. Returns `true` if the backend OWNS
    /// delivery (HVF armed an `EVFILT_TIMER` on the pump kq); `false` → the
    /// caller spawns the shared wall-clock fallback thread (KVM, or an HVF
    /// process that has no pump kqueue yet).
    fn arm_itimer(
        &self,
        which: usize,
        spec: TimerSpecNs,
        needs_periodic: bool,
        signum: i32,
    ) -> bool;

    /// Disarm interval timer `which` (clear the slot + tear down any backend
    /// delivery, e.g. delete the `EVFILT_TIMER`).
    fn disarm_itimer(&self, which: usize);

    /// (Re-)arm POSIX per-process timer `id`. `signum`/`si_value` were captured
    /// at `timer_create` and live on the slot, so only the value/interval spec
    /// is passed here. Returns the PREVIOUS spec (`timer_settime`'s
    /// `old_value`), or `None` for an unknown id. A `spec.value == 0` disarms.
    /// Delegates slot mutation to `carrick_timer_core::posix::arm`; the backend
    /// spawns its firing mechanism (KVM/HVF: a wall-clock thread).
    fn arm_posix(&self, id: i32, spec: TimerSpecNs) -> Option<PosixTimerSpec>;

    /// Disarm POSIX timer `id` (a `spec.value == 0` arm); bumps generation so
    /// any in-flight firing thread retires.
    fn disarm_posix(&self, id: i32);

    /// Reconstruct the current arm for fork replay (HVF re-applies the
    /// `EVFILT_TIMER` on the fresh pump kq; KVM re-spawns the fallback thread).
    /// `None` if `which` is disarmed.
    fn current_arm(&self, which: usize) -> Option<TimerArm>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::{GenericVcpuRegistry, ThreadId, VcpuKickDyn};

    struct CountingKick(Arc<AtomicU64>);

    impl VcpuKickDyn for CountingKick {
        fn kick(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn fallback_posix_timer_publishes_process_signal_and_kicks_all() {
        carrick_timer_core::posix::clear();
        carrick_signal_core::clear_proc_pending();

        let kicks = Arc::new(AtomicU64::new(0));
        let registry = Arc::new(GenericVcpuRegistry::new());
        registry.register(
            ThreadId::synthetic_for_tests(1),
            Box::new(CountingKick(Arc::clone(&kicks))),
        );
        let kicker: Arc<dyn VcpuRegistry> = registry;
        let id = carrick_timer_core::posix::create(0, 14);

        let old = arm_fallback_posix_timer(
            id,
            TimerSpecNs {
                value: 1_000_000,
                interval: 0,
            },
            &kicker,
        )
        .expect("known timer id should arm");

        assert_eq!(old.signum, 14);
        let deadline = Instant::now() + Duration::from_secs(1);
        while kicks.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }

        assert_eq!(kicks.load(Ordering::SeqCst), 1);
        assert_eq!(carrick_signal_core::take_process_pending(), 14);

        disarm_fallback_posix_timer(id);
        let _ = carrick_timer_core::posix::delete(id);
        carrick_signal_core::clear_proc_pending();
    }
}
