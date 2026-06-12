//! HVF's [`TimerDelivery`]. Interval timers are delivered by an `EVFILT_TIMER`
//! armed on the signal-pump kqueue (so a busy in-guest vCPU is kicked on
//! expiry); `arm_itimer` returns `true` when it owns delivery and `false` (no
//! pump kq yet — e.g. a fresh fork child) so the caller spawns the shared
//! wall-clock fallback thread. POSIX per-process timers delegate to the existing
//! HVF `posix_timer::arm` (its own firing thread). The neutral slot mutation is
//! the timer-core's; this struct only owns the kqueue glue.
use carrick_hal::{PosixTimerSpec, TimerArm, TimerDelivery};

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
        value_ns: u64,
        interval_ns: u64,
        _needs_periodic: bool,
        _signum: i32,
    ) -> bool {
        let kq = crate::host_signal::pump_kqueue();
        if kq < 0 {
            return false;
        }
        let ident = crate::itimer::ident_for(which);
        let cpu_timer = crate::itimer::is_cpu_timer(which);
        // CPU timers can't fire on a wall-clock deadline; arm a recheck one-shot
        // so the pump re-evaluates guest-CPU progress instead of consuming it.
        let kqueue_value_ns = if cpu_timer {
            crate::itimer::cpu_timer_recheck_delay_ns(value_ns)
        } else {
            value_ns
        };
        let value_i64 = i64::try_from(kqueue_value_ns).unwrap_or(i64::MAX);
        let interval_i64 = i64::try_from(interval_ns).unwrap_or(i64::MAX);
        // Pure-periodic ⇔ it_value == it_interval (and not a CPU timer): one EV_ADD
        // periodic kevent covers every expiry. Otherwise (one-shot, or two-phase
        // it_value != it_interval) arm a one-shot; the pump re-arms as needed.
        let periodic = interval_ns != 0 && value_ns == interval_ns && !cpu_timer;
        let (flags, data) = if periodic {
            (libc::EV_ADD, interval_i64)
        } else {
            (libc::EV_ADD | libc::EV_ONESHOT, value_i64)
        };
        crate::darwin_kqueue::apply_changes(
            kq,
            &[crate::darwin_kqueue::Kevent::timer(ident, flags, data)],
        )
        .is_ok()
    }

    fn disarm_itimer(&self, which: usize) {
        let ident = crate::itimer::ident_for(which);
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

    fn arm_posix(&self, id: i32, value_ns: u64, interval_ns: u64) -> Option<PosixTimerSpec> {
        // The HVF posix arm already spawns its own wall-clock firing thread
        // (publish_process_signal on each expiry) and returns the previous spec.
        crate::posix_timer::arm(id, value_ns, interval_ns)
    }

    fn disarm_posix(&self, id: i32) {
        // A zero-value arm disarms (generation bump retires the firing thread).
        let _ = crate::posix_timer::arm(id, 0, 0);
    }

    fn current_arm(&self, which: usize) -> Option<TimerArm> {
        crate::itimer::current_arm(which)
    }
}
