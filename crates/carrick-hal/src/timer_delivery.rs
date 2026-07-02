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
pub use carrick_timer_core::TimerSpecNs;
pub use carrick_timer_core::itimer::TimerArm;
pub use carrick_timer_core::posix::PosixTimerSpec;

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
