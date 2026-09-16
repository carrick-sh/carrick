//! HVF's [`TimerDelivery`]. Interval timers are delivered by an `EVFILT_TIMER`
//! armed on the signal-pump kqueue (so a busy in-guest vCPU is kicked on
//! expiry); `arm_itimer` returns `true` when it owns delivery and `false` (no
//! pump kq yet — e.g. a fresh fork child) so the caller spawns the shared
//! wall-clock fallback thread. POSIX per-process timers delegate to the existing
//! HVF `posix_timer::arm` (its own firing thread). The neutral slot mutation is
//! the timer-core's; this struct only owns the kqueue glue.
//!
//! The registered-backend handle the dispatch arm reads
//! (`GuestTimerBridge::delivery`) is the process-global seam in
//! `carrick_hal::guest_timer_bridge` (`register_delivery` / `delivery`),
//! shared with every other lane; the run loop registers [`HvfTimerDelivery`]
//! there.
use std::sync::Arc;

use carrick_hal::{GuestTimerBridge, PosixTimerSpec, TimerArm, TimerDelivery, TimerSpecNs};
use carrick_timer_core::{CpuNs, WallNs};

pub struct HvfTimerDelivery;

/// HVF's [`GuestTimerBridge`]: the neutral timer-core registry plus this
/// lane's firing glue (`itimer::spawn_fallback_timer`, `posix_timer::arm`) and
/// the hal-wide registered-backend seam, reached by the dispatcher only
/// through the trait.
#[derive(Debug, Default, Clone, Copy)]
pub struct HvfGuestTimers;

impl GuestTimerBridge for HvfGuestTimers {
    fn itimer_arm(&self, which: usize, spec: TimerSpecNs, needs_periodic: bool) -> u64 {
        crate::itimer::arm(which, spec, needs_periodic)
    }

    fn itimer_disarm(&self, which: usize) {
        crate::itimer::disarm(which);
    }

    fn itimer_signum_for(&self, which: usize) -> i32 {
        crate::itimer::signum_for(which)
    }

    fn itimer_spawn_fallback_timer(&self, which: usize, generation: u64, spec: TimerSpecNs) {
        crate::itimer::spawn_fallback_timer(which, generation, spec);
    }

    fn posix_create_with_target_and_value(
        &self,
        clock_id: i32,
        signum: i32,
        target_tid: Option<i32>,
        si_value: i64,
    ) -> i32 {
        crate::posix_timer::create_with_target_and_value(clock_id, signum, target_tid, si_value)
    }

    fn posix_arm(&self, id: i32, spec: TimerSpecNs) -> Option<PosixTimerSpec> {
        crate::posix_timer::arm(id, spec)
    }

    fn posix_remaining(&self, id: i32) -> Option<TimerSpecNs> {
        crate::posix_timer::remaining(id)
    }

    fn posix_getoverrun(&self, id: i32) -> Option<u32> {
        crate::posix_timer::getoverrun(id)
    }

    fn posix_seed_overrun(&self, id: i32, count: u32) {
        crate::posix_timer::seed_overrun(id, count);
    }

    fn posix_exists(&self, id: i32) -> bool {
        crate::posix_timer::exists(id)
    }

    fn posix_clock_id(&self, id: i32) -> i32 {
        crate::posix_timer::clock_id(id)
    }

    fn posix_delete(&self, id: i32) -> bool {
        crate::posix_timer::delete(id)
    }

    /// Publish a process-directed signal from a host-side producer: the
    /// kqueue signal pump wakes parked waiters and kicks any in-guest vCPU.
    fn deliver(&self, signum: i32) {
        crate::host_signal::publish_process_signal(signum);
    }

    fn delivery(&self) -> Option<Arc<dyn TimerDelivery>> {
        carrick_hal::guest_timer_bridge::delivery()
    }
}

impl TimerDelivery for HvfTimerDelivery {
    /// Arm `which` as an `EVFILT_TIMER` on the pump kqueue. The neutral slot
    /// state was already written by the dispatch arm (`itimer::arm`). Mirrors
    /// the original inline `setitimer` dispatch arm: a pure-periodic timer
    /// (it_value == it_interval, non-CPU) is `EV_ADD`; everything else is a
    /// `EV_ADD | EV_ONESHOT` for the first expiry (the pump promotes a
    /// two-phase timer to periodic on its first fire via `take_needs_periodic`).
    /// CPU timers (`VIRTUAL`/`PROF`) arm a wall-clock RECHECK one-shot. Returns
    /// `true` when armed on the kq; `false` (no kq) → caller spawns the fallback.
    fn arm_itimer(
        &self,
        which: usize,
        spec: TimerSpecNs,
        _needs_periodic: bool,
        _signum: i32,
    ) -> bool {
        let kq = crate::host_signal::pump_kqueue();
        if kq < 0 {
            return false;
        }
        // The fresh ident this arm allocated (itimer::arm ran first, in the
        // setitimer dispatch). A recently-fired EV_ONESHOT ident is poisoned on
        // Darwin — re-arming it never counts down — so each arm uses a new ident.
        let ident = crate::itimer::live_ident(which);
        let cpu_timer = crate::itimer::is_cpu_timer(which);
        // CPU timers can't fire on a wall-clock deadline (spec.value is a guest
        // CPU budget there); arm a recheck one-shot so the pump re-evaluates
        // guest-CPU progress instead of consuming it.
        let kqueue_value_ns = if cpu_timer {
            crate::itimer::cpu_timer_recheck_delay_ns(CpuNs(spec.value))
        } else {
            WallNs(spec.value)
        };
        let value_i64 = i64::try_from(kqueue_value_ns.raw()).unwrap_or(i64::MAX);
        let interval_i64 = i64::try_from(spec.interval).unwrap_or(i64::MAX);
        // Pure-periodic ⇔ it_value == it_interval (and not a CPU timer): one EV_ADD
        // periodic kevent covers every expiry. Otherwise (one-shot, or two-phase
        // it_value != it_interval) arm a one-shot; the pump re-arms as needed.
        let periodic = spec.interval != 0 && spec.value == spec.interval && !cpu_timer;
        let (flags, data) = if periodic {
            (libc::EV_ADD, interval_i64)
        } else {
            (libc::EV_ADD | libc::EV_ONESHOT, value_i64)
        };
        let res = crate::darwin_kqueue::apply_changes(
            kq,
            &[crate::darwin_kqueue::Kevent::timer(ident, flags, data)
                .with_udata_u64(crate::itimer::generation(which))],
        );
        // Wake the pump so it re-registers this arm FROM ITS OWN kevent context
        // (see the pump reconcile loop). A timer EV_ADDed from this (dispatcher)
        // thread while the pump is blocked in kevent() is not reliably monitored
        // by that wait; the pump thread owns the authoritative registration. Both
        // registrations carry the same generation in udata.
        crate::host_signal::wake_signal_pump_all();
        res.is_ok()
    }

    fn disarm_itimer(&self, which: usize) {
        // Read the live ident BEFORE disarm — disarm forgets it (resets the slot
        // to the base-ident fallback), so this must run first to EV_DELETE the
        // ident the arm actually registered.
        let ident = crate::itimer::live_ident(which);
        crate::itimer::disarm(which);
        let kq = crate::host_signal::pump_kqueue();
        if kq >= 0 {
            let _ = crate::darwin_kqueue::apply_changes(
                kq,
                &[crate::darwin_kqueue::Kevent::timer(
                    ident,
                    libc::EV_DELETE,
                    0,
                )],
            );
        }
    }

    fn arm_posix(&self, id: i32, spec: TimerSpecNs) -> Option<PosixTimerSpec> {
        // The HVF posix arm already spawns its own wall-clock firing thread
        // (publish_process_signal on each expiry) and returns the previous spec.
        crate::posix_timer::arm(id, spec)
    }

    fn disarm_posix(&self, id: i32) {
        // A zero-value arm disarms (generation bump retires the firing thread).
        let _ = crate::posix_timer::arm(id, TimerSpecNs::DISARM);
    }

    fn current_arm(&self, which: usize) -> Option<TimerArm> {
        crate::itimer::current_arm(which)
    }
}
