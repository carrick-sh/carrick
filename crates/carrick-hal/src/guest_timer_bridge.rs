//! The guest-timer seam between the backend-neutral dispatcher and the
//! execution backend that fires `setitimer`/`alarm`/`timer_settime` expiries.
//!
//! The neutral slot/spec/remaining bookkeeping is `carrick-timer-core`'s and
//! is shared verbatim by every lane; what differs per lane is how an armed
//! slot becomes a delivered signal (the HVF kqueue `EVFILT_TIMER` pump, or a
//! wall-clock fallback thread that publishes and kicks). The dispatcher
//! reaches BOTH halves only through [`GuestTimerBridge`] — the registry
//! operations as well as the firing mechanism — so an external backend that
//! keeps its own timer state implements the whole trait without
//! `carrick-timer-core`.
//!
//! Every method keeps the argument and return types of the free function it
//! replaced (`carrick_timer_core::{itimer, posix}` and the lane's
//! `spawn_fallback_timer` / `posix arm` / `timer_delivery` glue).
//!
//! Two implementations live in this crate:
//!
//! - [`KickerGuestTimers`], the shared body for every kick+futex lane (KVM,
//!   bhyve, NVMM, native BSD): no signal-pump kqueue, so a fallback timer
//!   THREAD sleeps to the deadline and then publishes the process-directed
//!   signal into the neutral pending store and kicks every vCPU. It replaces
//!   the runtime's former inline Linux `timer_delivery` / `itimer` /
//!   `posix_timer` modules. The kicker and the registered [`TimerDelivery`]
//!   backend are process-global, registered once by the run loop
//!   ([`register_kicker`](crate::guest_timer_bridge::register_kicker) /
//!   [`register_delivery`](crate::guest_timer_bridge::register_delivery)) exactly
//!   as before.
//! - [`NullGuestTimerBridge`] (feature `test-support`): the neutral timer-core
//!   registry with firing threads that publish into the neutral pending store
//!   but kick nobody and register no backend delivery.

use std::sync::{Arc, Mutex, OnceLock};

use carrick_timer_core::TimerSpecNs;

use crate::{PosixTimerSpec, ThreadId, TimerDelivery, VcpuRegistry};

/// The backend's timer registry and firing mechanism as the dispatcher
/// consumes them. `which` is the interval-timer slot (`ITIMER_REAL` /
/// `ITIMER_VIRTUAL` / `ITIMER_PROF` as `usize`); `id` a POSIX timer id.
pub trait GuestTimerBridge: Send + Sync {
    /// Write the neutral interval-timer slot for `which` and return the arm
    /// generation the fallback thread checks.
    fn itimer_arm(&self, which: usize, spec: TimerSpecNs, needs_periodic: bool) -> u64;

    /// Clear the interval-timer slot for `which` (bumps the generation so an
    /// in-flight fallback thread retires).
    fn itimer_disarm(&self, which: usize);

    /// The Linux signum interval timer `which` delivers.
    fn itimer_signum_for(&self, which: usize) -> i32;

    /// Spawn the wall-clock fallback thread for `which` when the backend's
    /// [`TimerDelivery`] does not own delivery (no pump kqueue yet, or no
    /// backend registered).
    fn itimer_spawn_fallback_timer(&self, which: usize, generation: u64, spec: TimerSpecNs);

    /// `timer_create`: allocate a POSIX timer (no arm yet) with an optional
    /// thread target and the `sigev_value` payload. Returns the new id.
    fn posix_create_with_target_and_value(
        &self,
        clock_id: i32,
        signum: i32,
        target_tid: Option<i32>,
        si_value: i64,
    ) -> i32;

    /// (Re-)arm POSIX timer `id` and start its firing mechanism. Returns the
    /// PREVIOUS spec (`timer_settime`'s `old_value`), or `None` for an
    /// unknown id. A `spec.value == 0` disarms.
    fn posix_arm(&self, id: i32, spec: TimerSpecNs) -> Option<PosixTimerSpec>;

    /// `timer_gettime`: the remaining value/interval, or `None` for an
    /// unknown id.
    fn posix_remaining(&self, id: i32) -> Option<TimerSpecNs>;

    /// `timer_getoverrun`: missed expiries since the last query, or `None` for
    /// an unknown id.
    fn posix_getoverrun(&self, id: i32) -> Option<u32>;

    /// Seed the overrun counter for a past `TIMER_ABSTIME` deadline.
    fn posix_seed_overrun(&self, id: i32, count: u32);

    /// Whether `id` names a live POSIX timer.
    fn posix_exists(&self, id: i32) -> bool;

    /// The clock `id` was created on (`0` for an unknown id).
    fn posix_clock_id(&self, id: i32) -> i32;

    /// `timer_delete`: tear the timer down; `false` for an unknown id.
    fn posix_delete(&self, id: i32) -> bool;

    /// Publish a PROCESS-directed `signum` and wake the guest so an unblocked
    /// thread delivers it — the path an asynchronous host-side producer (a
    /// timer thread, an `RLIMIT_CPU` watchdog) uses.
    fn deliver(&self, signum: i32);

    /// The backend [`TimerDelivery`] the run loop registered, or `None` if no
    /// run loop has registered one (a unit test exercising the dispatcher
    /// without a backing run loop).
    fn delivery(&self) -> Option<Arc<dyn TimerDelivery>>;
}

impl std::fmt::Debug for dyn GuestTimerBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuestTimerBridge")
    }
}

// ---------------------------------------------------------------------------
// The kick+futex lanes' process-global delivery state (moved verbatim from the
// runtime's inline Linux `timer_delivery` module).
// ---------------------------------------------------------------------------

struct Delivery {
    kicker: Arc<dyn VcpuRegistry>,
    /// Nudges the carrier's futex waiters so a parked thread re-checks pending
    /// after the publish + kick (the container-scoped futex notify on the
    /// runtime's `carrick-thread` table, supplied by the carrier because this
    /// crate sits below it).
    wake: Box<dyn Fn() + Send + Sync>,
    // Wall-clock interval/POSIX timer signals (SIGALRM/SIGVTALRM/SIGPROF) are
    // PROCESS-directed: Linux delivers them to the thread group, runnable by
    // any thread that does not block the signal. `main_tid` is retained only
    // as the kick target for the legacy single-threaded path; `deliver` now
    // publishes into the SHARED process-directed mask and kicks ALL vCPUs so
    // a blocked-main / multi-thread guest still gets the timer (matching the
    // dispatcher's process-directed routing).
    #[allow(dead_code)]
    main_tid: ThreadId,
}

fn cell() -> &'static Mutex<Option<Delivery>> {
    static C: OnceLock<Mutex<Option<Delivery>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

fn lock() -> std::sync::MutexGuard<'static, Option<Delivery>> {
    cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Install the kicker + target tid + futex wake for the kick+futex lanes'
/// wall-clock `deliver`. Called once at run-loop startup.
pub fn register_kicker(
    kicker: Arc<dyn VcpuRegistry>,
    main_tid: ThreadId,
    wake: Box<dyn Fn() + Send + Sync>,
) {
    *lock() = Some(Delivery {
        kicker,
        wake,
        main_tid,
    });
}

/// Publish a PROCESS-directed timer `signum` into the shared process-directed
/// pending mask and kick EVERY vCPU so any unblocked thread re-checks pending
/// at its safe point and delivers (a blocked main thread does not drop the
/// timer). No-op if no run loop has registered (e.g. a unit test exercising
/// arm/disarm only).
pub fn deliver(signum: i32) {
    if let Some(d) = lock().as_ref() {
        carrick_signal_core::publish_process_signal(signum);
        d.kicker.kick_all();
        (d.wake)();
    }
}

// The process-global `TimerDelivery` backend handle. This is the SAME seam as
// `register_kicker`/`deliver` above, extended so the dispatch arm can reach the
// backend's arm/disarm without a run-loop reference. The run-loop startup
// registers the concrete backend (KVM `KvmTimerDelivery`, …).
static DELIVERY: OnceLock<Arc<dyn TimerDelivery>> = OnceLock::new();

/// Install the backend [`TimerDelivery`]. Called once at run-loop startup
/// (the same site as [`register_kicker`]). Subsequent calls are ignored.
pub fn register_delivery(delivery: Arc<dyn TimerDelivery>) {
    let _ = DELIVERY.set(delivery);
}

/// The registered backend [`TimerDelivery`], or `None` if no run loop has
/// registered one.
pub fn delivery() -> Option<Arc<dyn TimerDelivery>> {
    DELIVERY.get().map(Arc::clone)
}

/// The shared [`GuestTimerBridge`] of every kick+futex lane. See the module
/// docs; the process-global kicker/delivery registration is
/// [`register_kicker`] / [`register_delivery`].
#[derive(Debug, Default, Clone, Copy)]
pub struct KickerGuestTimers;

impl GuestTimerBridge for KickerGuestTimers {
    fn itimer_arm(&self, which: usize, spec: TimerSpecNs, needs_periodic: bool) -> u64 {
        carrick_timer_core::itimer::arm(which, spec, needs_periodic)
    }

    fn itimer_disarm(&self, which: usize) {
        carrick_timer_core::itimer::disarm(which);
    }

    fn itimer_signum_for(&self, which: usize) -> i32 {
        carrick_timer_core::itimer::signum_for(which)
    }

    /// Spawn the fallback timer thread for `which`. The timing-loop body is
    /// shared (`carrick_timer_core::itimer::run_fallback`); the per-fire
    /// action delivers via [`deliver`] (publish the signal + kick the target
    /// vCPUs). For wall-time `ITIMER_REAL` the shared loop sleeps to the
    /// deadline; for CPU-time `ITIMER_VIRTUAL`/`ITIMER_PROF` it POLLS the
    /// core's `cpu_timer_decision` against the live aggregate guest CPU total
    /// — so CPU itimers fire off real guest CPU time and never while the guest
    /// is idle. At most one thread per `which` is live — a disarm/re-arm bumps
    /// the generation so the old thread exits.
    fn itimer_spawn_fallback_timer(&self, which: usize, generation: u64, spec: TimerSpecNs) {
        let signum = carrick_timer_core::itimer::signum_for(which);
        let _ = std::thread::Builder::new()
            .name(format!("carrick-itimer-{which}"))
            .spawn(move || {
                carrick_timer_core::itimer::run_fallback(which, generation, spec, || {
                    deliver(signum);
                });
            });
    }

    fn posix_create_with_target_and_value(
        &self,
        clock_id: i32,
        signum: i32,
        target_tid: Option<i32>,
        si_value: i64,
    ) -> i32 {
        carrick_timer_core::posix::create_with_target_and_value(
            clock_id, signum, target_tid, si_value,
        )
    }

    /// (Re-)arm timer `id`. Returns the PREVIOUS spec (for `timer_settime`'s
    /// old_value). A `spec.value == 0` disarms. A non-zero value spawns a
    /// firing thread (the shared timer-core loop) that delivers `signum` after
    /// `spec.value` then every `spec.interval`, until the timer is re-armed or
    /// deleted (generation bump).
    fn posix_arm(&self, id: i32, spec: TimerSpecNs) -> Option<PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, spec)?;
        if spec.value > 0 {
            let signum = armed.signum;
            let generation = armed.generation;
            let slot = armed.slot.clone();
            let on_fire = move || {
                deliver(signum);
            };
            let _ = std::thread::Builder::new()
                .name(format!("carrick-ptimer-{id}"))
                .spawn(move || {
                    carrick_timer_core::posix::run_fallback(slot, generation, spec, on_fire);
                });
        }
        Some(armed.old)
    }

    fn posix_remaining(&self, id: i32) -> Option<TimerSpecNs> {
        carrick_timer_core::posix::remaining(id)
    }

    fn posix_getoverrun(&self, id: i32) -> Option<u32> {
        carrick_timer_core::posix::getoverrun(id)
    }

    fn posix_seed_overrun(&self, id: i32, count: u32) {
        carrick_timer_core::posix::seed_overrun(id, count);
    }

    fn posix_exists(&self, id: i32) -> bool {
        carrick_timer_core::posix::exists(id)
    }

    fn posix_clock_id(&self, id: i32) -> i32 {
        carrick_timer_core::posix::clock_id(id)
    }

    fn posix_delete(&self, id: i32) -> bool {
        carrick_timer_core::posix::delete(id)
    }

    fn deliver(&self, signum: i32) {
        deliver(signum);
    }

    fn delivery(&self) -> Option<Arc<dyn TimerDelivery>> {
        delivery()
    }
}

/// The timer bridge a dispatcher boots with when no carrier has handed it one:
/// the neutral timer-core registry, with firing threads that publish the
/// expiry into the neutral pending store and wake nobody (no kick, no pump),
/// and no registered backend delivery (`delivery()` is `None`, so the
/// dispatch arm takes its fallback path exactly as a backing-loop-less unit
/// test always has).
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct NullGuestTimerBridge;

#[cfg(any(test, feature = "test-support"))]
impl GuestTimerBridge for NullGuestTimerBridge {
    fn itimer_arm(&self, which: usize, spec: TimerSpecNs, needs_periodic: bool) -> u64 {
        carrick_timer_core::itimer::arm(which, spec, needs_periodic)
    }

    fn itimer_disarm(&self, which: usize) {
        carrick_timer_core::itimer::disarm(which);
    }

    fn itimer_signum_for(&self, which: usize) -> i32 {
        carrick_timer_core::itimer::signum_for(which)
    }

    fn itimer_spawn_fallback_timer(&self, which: usize, generation: u64, spec: TimerSpecNs) {
        let signum = carrick_timer_core::itimer::signum_for(which);
        let _ = std::thread::Builder::new()
            .name(format!("carrick-itimer-{which}"))
            .spawn(move || {
                carrick_timer_core::itimer::run_fallback(which, generation, spec, || {
                    carrick_signal_core::publish_process_signal(signum);
                });
            });
    }

    fn posix_create_with_target_and_value(
        &self,
        clock_id: i32,
        signum: i32,
        target_tid: Option<i32>,
        si_value: i64,
    ) -> i32 {
        carrick_timer_core::posix::create_with_target_and_value(
            clock_id, signum, target_tid, si_value,
        )
    }

    fn posix_arm(&self, id: i32, spec: TimerSpecNs) -> Option<PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, spec)?;
        if spec.value > 0 {
            let signum = armed.signum;
            let generation = armed.generation;
            let slot = armed.slot.clone();
            let target_tid = armed.target_tid;
            let on_fire = move || {
                if let Some(tid) = target_tid {
                    carrick_signal_core::publish_pending_for(tid, signum);
                } else {
                    carrick_signal_core::publish_process_signal(signum);
                }
            };
            let _ = std::thread::Builder::new()
                .name(format!("carrick-ptimer-{id}"))
                .spawn(move || {
                    carrick_timer_core::posix::run_fallback(slot, generation, spec, on_fire);
                });
        }
        Some(armed.old)
    }

    fn posix_remaining(&self, id: i32) -> Option<TimerSpecNs> {
        carrick_timer_core::posix::remaining(id)
    }

    fn posix_getoverrun(&self, id: i32) -> Option<u32> {
        carrick_timer_core::posix::getoverrun(id)
    }

    fn posix_seed_overrun(&self, id: i32, count: u32) {
        carrick_timer_core::posix::seed_overrun(id, count);
    }

    fn posix_exists(&self, id: i32) -> bool {
        carrick_timer_core::posix::exists(id)
    }

    fn posix_clock_id(&self, id: i32) -> i32 {
        carrick_timer_core::posix::clock_id(id)
    }

    fn posix_delete(&self, id: i32) -> bool {
        carrick_timer_core::posix::delete(id)
    }

    fn deliver(&self, signum: i32) {
        carrick_signal_core::publish_process_signal(signum);
    }

    fn delivery(&self) -> Option<Arc<dyn TimerDelivery>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_bridge_has_no_backend_delivery_and_reads_the_neutral_registry() {
        let bridge = NullGuestTimerBridge;
        assert!(bridge.delivery().is_none());
        assert!(!bridge.posix_exists(i32::MAX));
        assert_eq!(bridge.posix_remaining(i32::MAX), None);
        assert_eq!(bridge.posix_getoverrun(i32::MAX), None);
        assert!(!bridge.posix_delete(i32::MAX));
        assert_eq!(bridge.itimer_signum_for(0), carrick_abi::LINUX_SIGALRM);
    }
}
