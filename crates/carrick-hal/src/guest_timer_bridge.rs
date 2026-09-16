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
//! This crate holds ONE implementation over the neutral registry,
//! [`TimerCoreBridge`], generic over the lane's [`TimerFiring`] — the only
//! part that differs between lanes — and two firings:
//!
//! - [`KickerTimerFiring`] ([`KickerGuestTimers`]), the kick+futex lanes (KVM,
//!   bhyve, NVMM, native BSD): no signal-pump kqueue, so a fallback timer
//!   THREAD sleeps to the deadline and then publishes the process-directed
//!   signal into the neutral pending store and kicks every vCPU. It replaces
//!   the runtime's former inline Linux `timer_delivery` / `itimer` /
//!   `posix_timer` modules. The kicker is process-global, registered once by
//!   the run loop ([`register_kicker`](crate::guest_timer_bridge::register_kicker))
//!   exactly as before.
//! - `NullTimerFiring` (`NullGuestTimerBridge`, feature `test-support`, so
//!   not linkable from a product docs build): fires nothing — no thread, no
//!   publication, no backend delivery.
//!
//! The registered [`TimerDelivery`] backend
//! ([`register_delivery`](crate::guest_timer_bridge::register_delivery) /
//! [`delivery`](crate::guest_timer_bridge::delivery)) is the process-global
//! seam EVERY lane's bridge reads, HVF included.

use std::marker::PhantomData;
use std::sync::{Arc, Mutex, OnceLock};

use carrick_timer_core::TimerSpecNs;
use carrick_timer_core::posix::PosixArm;

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

// The process-global `TimerDelivery` backend handle: the one seam every lane's
// bridge reads (`GuestTimerBridge::delivery`), extended from the kicker
// registration above so the dispatch arm can reach the backend's arm/disarm
// without a run-loop reference. The run-loop startup registers the concrete
// backend (HVF `HvfTimerDelivery`, KVM `KvmTimerDelivery`, ...).
static DELIVERY: OnceLock<Arc<dyn TimerDelivery>> = OnceLock::new();

/// Install the backend [`TimerDelivery`]. Called once at run-loop startup
/// (the kick+futex lanes register their kicker at the same site). Subsequent
/// calls are ignored.
pub fn register_delivery(delivery: Arc<dyn TimerDelivery>) {
    let _ = DELIVERY.set(delivery);
}

/// The registered backend [`TimerDelivery`], or `None` if no run loop has
/// registered one. Every real run-loop entry registers a backend before the
/// dispatcher can run a `setitimer`/`timer_settime`, so the `None` arm only
/// matters for a unit test exercising the dispatcher without a backing run
/// loop, where the dispatch arm falls back to the shared wall-clock timer
/// thread.
pub fn delivery() -> Option<Arc<dyn TimerDelivery>> {
    DELIVERY.get().map(Arc::clone)
}

/// The firing half of a [`TimerCoreBridge`]: how a slot the neutral
/// `carrick-timer-core` registry just armed becomes a delivered guest signal
/// on this lane. Static methods, like
/// [`HostSignalGlue`](carrick_signal_core::HostSignalGlue): the lane is a
/// type, not a value.
pub trait TimerFiring: 'static {
    /// Start the fallback thread for interval timer `which` at arm
    /// `generation`, used when the backend's [`TimerDelivery`] does not own
    /// delivery.
    fn spawn_itimer_fallback(which: usize, generation: u64, spec: TimerSpecNs);

    /// Start the firing thread for POSIX timer `id`, which
    /// `carrick_timer_core::posix::arm` just armed as `armed` with a non-zero
    /// `spec.value`.
    fn spawn_posix_firing(id: i32, armed: &PosixArm, spec: TimerSpecNs);

    /// Publish a PROCESS-directed `signum` from a host-side producer and wake
    /// the guest so an unblocked thread delivers it.
    fn deliver(signum: i32);

    /// The backend [`TimerDelivery`] the run loop registered, if any.
    fn delivery() -> Option<Arc<dyn TimerDelivery>>;
}

/// A [`GuestTimerBridge`] over the neutral `carrick-timer-core` registry —
/// the slot/spec/remaining/overrun bookkeeping every lane shares verbatim —
/// with the lane's [`TimerFiring`] supplying the only part that differs. One
/// body; the lanes are instantiations.
pub struct TimerCoreBridge<F: TimerFiring>(PhantomData<fn() -> F>);

impl<F: TimerFiring> TimerCoreBridge<F> {
    /// The bridge over firing `F`; `const` so a lane can hold one in a `static`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<F: TimerFiring> Default for TimerCoreBridge<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: TimerFiring> std::fmt::Debug for TimerCoreBridge<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TimerCoreBridge")
    }
}

impl<F: TimerFiring> GuestTimerBridge for TimerCoreBridge<F> {
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
        F::spawn_itimer_fallback(which, generation, spec);
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
    /// old_value). A `spec.value == 0` disarms (the generation bump retires
    /// any firing thread); a non-zero value hands the arm to the lane's
    /// firing.
    fn posix_arm(&self, id: i32, spec: TimerSpecNs) -> Option<PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, spec)?;
        if spec.value > 0 {
            F::spawn_posix_firing(id, &armed, spec);
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
        F::deliver(signum);
    }

    fn delivery(&self) -> Option<Arc<dyn TimerDelivery>> {
        F::delivery()
    }
}

/// The kick+futex lanes' [`TimerFiring`]: a helper thread per armed timer that
/// runs the shared timer-core timing loop and delivers each expiry through
/// the process-global [`deliver`] (publish the process-directed signal + kick
/// every vCPU + nudge the futex waiters).
#[derive(Debug, Default, Clone, Copy)]
pub struct KickerTimerFiring;

impl TimerFiring for KickerTimerFiring {
    /// Spawn the fallback timer thread for `which`. The timing-loop body is
    /// shared (`carrick_timer_core::itimer::run_fallback`); the per-fire
    /// action delivers via [`deliver`]. For wall-time `ITIMER_REAL` the shared
    /// loop sleeps to the deadline; for CPU-time `ITIMER_VIRTUAL`/`ITIMER_PROF`
    /// it POLLS the core's `cpu_timer_decision` against the live aggregate
    /// guest CPU total — so CPU itimers fire off real guest CPU time and never
    /// while the guest is idle. At most one thread per `which` is live — a
    /// disarm/re-arm bumps the generation so the old thread exits.
    fn spawn_itimer_fallback(which: usize, generation: u64, spec: TimerSpecNs) {
        let signum = carrick_timer_core::itimer::signum_for(which);
        let _ = std::thread::Builder::new()
            .name(format!("carrick-itimer-{which}"))
            .spawn(move || {
                carrick_timer_core::itimer::run_fallback(which, generation, spec, || {
                    deliver(signum);
                });
            });
    }

    /// Spawn the firing thread (the shared timer-core loop) that delivers
    /// `armed.signum` after `spec.value` then every `spec.interval`, until the
    /// timer is re-armed or deleted (generation bump). The kick+futex lanes
    /// deliver every POSIX timer process-directed: `armed.target_tid` is not
    /// consulted here (the pre-existing behaviour of these lanes, kept
    /// verbatim; HVF's own firing honours it).
    fn spawn_posix_firing(id: i32, armed: &PosixArm, spec: TimerSpecNs) {
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

    fn deliver(signum: i32) {
        deliver(signum);
    }

    fn delivery() -> Option<Arc<dyn TimerDelivery>> {
        delivery()
    }
}

/// The shared [`GuestTimerBridge`] of every kick+futex lane. See the module
/// docs; the process-global kicker/delivery registration is
/// [`register_kicker`] / [`register_delivery`].
pub type KickerGuestTimers = TimerCoreBridge<KickerTimerFiring>;

/// The [`TimerFiring`] of a lane with nothing behind the registry: an armed
/// timer never fires (no thread, no publication), `deliver` publishes nothing
/// and no backend delivery is registered (`delivery()` is `None`, so the
/// dispatch arm takes its fallback path exactly as a backing-loop-less unit
/// test always has). The registry itself is still the neutral timer-core
/// (kernel state): `timer_create`/`timer_gettime`/`timer_delete` answer
/// exactly as on a product lane.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct NullTimerFiring;

#[cfg(any(test, feature = "test-support"))]
impl TimerFiring for NullTimerFiring {
    fn spawn_itimer_fallback(_which: usize, _generation: u64, _spec: TimerSpecNs) {}

    fn spawn_posix_firing(_id: i32, _armed: &PosixArm, _spec: TimerSpecNs) {}

    fn deliver(_signum: i32) {}

    fn delivery() -> Option<Arc<dyn TimerDelivery>> {
        None
    }
}

/// The timer bridge a dispatcher boots with when no carrier has handed it
/// one: the shared [`TimerCoreBridge`] body over [`NullTimerFiring`].
#[cfg(any(test, feature = "test-support"))]
pub type NullGuestTimerBridge = TimerCoreBridge<NullTimerFiring>;

/// Crate-test-shared lock serialising every test that touches the
/// process-global `carrick-timer-core` registry or the neutral pending store
/// (`timer_delivery::tests` clears both; the tests below arm and read them).
/// Module scope, not inside `mod tests`, so sibling test modules take the SAME
/// lock; `std::sync::Mutex` so a poisoned guard is recovered, not propagated.
#[cfg(test)]
pub(crate) static TIMER_REGISTRY_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_bridge_has_no_backend_delivery_and_reads_the_neutral_registry() {
        let _serial = TIMER_REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bridge = NullGuestTimerBridge::default();
        assert!(bridge.delivery().is_none());
        assert!(!bridge.posix_exists(i32::MAX));
        assert_eq!(bridge.posix_remaining(i32::MAX), None);
        assert_eq!(bridge.posix_getoverrun(i32::MAX), None);
        assert!(!bridge.posix_delete(i32::MAX));
        assert_eq!(bridge.itimer_signum_for(0), carrick_abi::LINUX_SIGALRM);
    }

    #[test]
    fn null_firing_arms_the_registry_but_never_fires() {
        let _serial = TIMER_REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        carrick_signal_core::clear_proc_pending();
        let bridge = NullGuestTimerBridge::default();
        let id = bridge.posix_create_with_target_and_value(0, carrick_abi::LINUX_SIGALRM, None, 0);
        assert!(bridge.posix_exists(id));
        let spec = TimerSpecNs {
            value: 1,
            interval: 0,
        };
        // The arm is recorded in the neutral registry (the old value is the
        // disarmed spec) and stays queryable ...
        let old = bridge.posix_arm(id, spec).expect("known id");
        assert_eq!(old.spec, TimerSpecNs::DISARM);
        assert!(bridge.posix_remaining(id).is_some());
        // ... while nothing fires: a 1 ns deadline has long passed and the
        // neutral pending store has still not seen SIGALRM (a lane that fires
        // publishes there; `timer_delivery::tests` proves the kick+futex
        // firing does, under this same lock).
        std::thread::sleep(std::time::Duration::from_millis(5));
        bridge.deliver(carrick_abi::LINUX_SIGALRM);
        assert_eq!(
            carrick_signal_core::take_process_pending(),
            carrick_signal_core::NO_PENDING_SIGNAL
        );
        assert!(bridge.posix_delete(id));
        assert!(!bridge.posix_exists(id));
    }
}
