//! Platform-neutral startup control for a backend's async signal pump.
//!
//! HVPatch models guest processes inside one Carrick kernel and one VM carrier,
//! so this seam deliberately contains no host-fork lifecycle. Backends supply
//! only the primitive needed to install their handler and start their pump.

use std::sync::Arc;

#[cfg(test)]
use crate::threaded::SharedFutexLocation;
use crate::threaded::SignalPumpControl;
use crate::{PlatformFutex, VcpuRegistry};

/// A backend's async host-signal pump primitive. Self-pipe (KVM/bhyve/NVMM) or
/// kqueue (HVF); the controller never names the concrete pump.
///
/// `Default` so [`SignalPumpController::new`] can build the pump (every impl is
/// either a zero-sized marker or a `Mutex<Option<…>>` that defaults to empty).
pub trait HostSignalPump: Send + Sync + Default {
    /// Install the backend's kick-signal handler + cross-process xsig ring, before
    /// (re)starting the pump. No-op for a backend whose kick is not a signal (HVF
    /// kicks via `hv_vcpus_exit`).
    fn ensure_handler(&self);

    /// Start the async pump (idempotent) against this registry + futex.
    fn start(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>);
}

/// The one [`SignalPumpControl`] implementation for every backend.
pub struct SignalPumpController<P: HostSignalPump> {
    pump: P,
}

impl<P: HostSignalPump> Default for SignalPumpController<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: HostSignalPump> SignalPumpController<P> {
    pub fn new() -> Self {
        Self { pump: P::default() }
    }

    /// The backend pump, for test assertions / backend-specific accessors.
    pub fn pump(&self) -> &P {
        &self.pump
    }
}

impl<P: HostSignalPump> SignalPumpControl for SignalPumpController<P> {
    fn start_signal_pump(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        self.pump.ensure_handler();
        self.pump.start(registry, futex);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Inert backend pump that records startup delegation without touching OS state.
    #[derive(Default)]
    struct InertPump {
        handler_installs: AtomicUsize,
        starts: AtomicUsize,
    }
    impl HostSignalPump for InertPump {
        fn ensure_handler(&self) {
            self.handler_installs.fetch_add(1, Ordering::SeqCst);
        }
        fn start(&self, _r: &Arc<dyn VcpuRegistry>, _f: &Arc<dyn PlatformFutex>) {
            self.starts.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct InertRegistry {
        inner: crate::GenericVcpuRegistry,
    }

    impl VcpuRegistry for InertRegistry {
        fn register(
            &self,
            t: crate::ThreadId,
            h: Box<dyn crate::VcpuKickDyn>,
            in_guest: &crate::InGuestFlag,
        ) {
            self.inner.register(t, h, in_guest);
        }
        fn poll_lease_drain(&self, except: crate::ThreadId) -> crate::VcpuLeaseDrainPoll {
            self.inner.poll_lease_drain(except)
        }
        fn subscribe_lease_drain(
            &self,
            except: crate::ThreadId,
            callback: Arc<dyn Fn() + Send + Sync + 'static>,
        ) -> crate::VcpuLeaseDrainEnrollment {
            self.inner.subscribe_lease_drain(except, callback)
        }
        fn subscribe_register(
            &self,
            tid: crate::ThreadId,
            handle: Box<dyn crate::VcpuKickDyn>,
            in_guest: &crate::InGuestFlag,
            callback: Arc<dyn Fn() + Send + Sync + 'static>,
        ) -> crate::VcpuRegistrationEnrollment {
            self.inner
                .subscribe_register(tid, handle, in_guest, callback)
        }
        fn unregister(&self, t: crate::ThreadId) {
            self.inner.unregister(t);
        }
        fn kick(&self, t: crate::ThreadId) {
            self.inner.kick(t);
        }
        fn kick_if_in_guest(&self, t: crate::ThreadId) -> bool {
            self.inner.kick_if_in_guest(t)
        }
        fn kick_all(&self) {
            self.inner.kick_all();
        }
        fn kick_all_in_guest(&self) -> bool {
            self.inner.kick_all_in_guest()
        }
        fn kick_all_except(&self, except: crate::ThreadId) {
            self.inner.kick_all_except(except);
        }
        fn any_other_in_guest(&self, except: crate::ThreadId) -> bool {
            self.inner.any_other_in_guest(except)
        }
        fn count(&self) -> usize {
            self.inner.count()
        }
        fn debug_registered_vcpus(&self) -> Vec<(crate::ThreadId, bool)> {
            self.inner.debug_registered_vcpus()
        }
    }

    struct InertFutex;
    impl PlatformFutex for InertFutex {
        fn private_wait(
            &self,
            _a: u64,
            _v: u32,
            _t: crate::ThreadId,
            _to: Option<Duration>,
            _i: &dyn Fn() -> bool,
        ) -> crate::FutexOutcome {
            crate::FutexOutcome::Woken
        }
        fn private_wake(&self, _a: u64, _n: u32) -> u32 {
            0
        }
        fn shared_wait(
            &self,
            _location: SharedFutexLocation,
            _v: u32,
            _tid: crate::ThreadId,
            _to: Option<Duration>,
            _i: &dyn Fn() -> bool,
            _wait_enrolled: &dyn Fn(),
        ) -> i64 {
            0
        }
        fn shared_wake(&self, _location: SharedFutexLocation, _k: usize, _n: u32) -> i64 {
            0
        }
        fn requeue(&self, _f: u64, _t: u64, _w: u32, _r: u32) -> (u32, u32) {
            (0, 0)
        }
        fn notify_signal_pending(&self) {}
        fn notify_signal_pending_for(&self, _t: crate::ThreadId) {}
    }

    fn ctx() -> (Arc<dyn VcpuRegistry>, Arc<dyn PlatformFutex>) {
        (Arc::new(InertRegistry::default()), Arc::new(InertFutex))
    }

    #[test]
    fn controller_installs_handler_and_starts_pump() {
        let (r, f) = ctx();
        let controller = SignalPumpController::<InertPump>::new();

        controller.start_signal_pump(&r, &f);
        assert_eq!(controller.pump().handler_installs.load(Ordering::SeqCst), 1);
        assert_eq!(controller.pump().starts.load(Ordering::SeqCst), 1);
    }
}
