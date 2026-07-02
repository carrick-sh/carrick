//! HVF's [`TimerDelivery`]. Interval timers are delivered by an `EVFILT_TIMER`
//! armed on the signal-pump kqueue (so a busy in-guest vCPU is kicked on
//! expiry); `arm_itimer` returns `true` when it owns delivery and `false` (no
//! pump kq yet — e.g. a fresh fork child) so the caller spawns the shared
//! wall-clock fallback thread. POSIX per-process timers delegate to the existing
//! HVF `posix_timer::arm` (its own firing thread). The neutral slot mutation is
//! the timer-core's; this struct only owns the kqueue glue.
use carrick_hal::{PosixTimerSpec, TimerArm, TimerDelivery, TimerSpecNs};
use carrick_timer_core::{CpuNs, WallNs};

pub struct HvfTimerDelivery;

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
