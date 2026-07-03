//! The platform-NEUTRAL fork-coordinator state machine, generic over a backend's
//! async-signal-pump primitive ([`HostSignalPump`]).
//!
//! Every backend stops + joins its host signal pump before `libc::fork` (the pump
//! holds process-global locks a fork would strand in the child) and recreates it
//! on the three post-fork paths. That state machine was written twice — the
//! kick+futex backends' `GenericForkCoordinator` (self-pipe
//! pump, always-on; `crate::fork_coord`, cfg-empty on macOS) and HVF's
//! `ForkCoordinator` (kqueue pump, lazy). They differ
//! ONLY in the pump PRIMITIVE and two policies (always-on vs lazy; whether the
//! child's pump reinit is owned by the coordinator or by the runtime), all of
//! which are exactly the [`HostSignalPump`] methods. This is the one shared
//! [`HostForkCoordinator`]; each backend supplies a `HostSignalPump`.

use std::sync::Arc;

use crate::threaded::{HostForkCoordinator, PreparedHostFork};
use crate::{PlatformFutex, VcpuRegistry};

/// A backend's async host-signal PUMP primitive — the per-backend residue of the
/// shared [`PumpForkCoordinator`] state machine. Self-pipe (KVM/bhyve/NVMM) or
/// kqueue (HVF); the coordinator never names the concrete pump.
///
/// `Default` so [`PumpForkCoordinator::new`] can build the pump (every impl is
/// either a zero-sized marker or a `Mutex<Option<…>>` that defaults to empty).
pub trait HostSignalPump: Send + Sync + Default {
    /// Install the backend's kick-signal handler + cross-process xsig ring, before
    /// (re)starting the pump. No-op for a backend whose kick is not a signal (HVF
    /// kicks via `hv_vcpus_exit`).
    fn ensure_handler(&self);

    /// Start the async pump (idempotent) against this registry + futex.
    fn start(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>);

    /// Stop + join the pump before `libc::fork`; returns whether one was running.
    fn stop_for_fork(&self) -> bool;

    /// Whether a pump is considered "installed" INDEPENDENT of
    /// [`stop_for_fork`](Self::stop_for_fork)'s return — `true` for an ALWAYS-ON
    /// backend (a process-global handler stays installed even when the pump thread
    /// is stopped), `false` for a LAZY backend (HVF: a pump exists only while a tty
    /// needs it). ORed with `stop_for_fork`'s return to decide `had_signal_pump`.
    fn installed_independent_of_stop(&self) -> bool;

    /// Block the pump's signals across the fork window (an async handler firing
    /// between stop and reinit would poke a half-rebuilt pump). Default no-op — a
    /// backend with no signal-based pump wake needs nothing here.
    fn block_signals_for_fork(&self) {}

    /// Restore the signal mask after the fork window. Default no-op.
    fn restore_signals_after_fork(&self) {}

    /// Child-side re-arm. `had` is whether the parent had a pump. An ALWAYS-ON
    /// backend rebuilds its inherited self-pipe + respawns UNCONDITIONALLY (the
    /// process-global pipe came across stale); a LAZY backend whose child self-pipe
    /// reinit is owned by the runtime respawns only `if had`.
    fn reinit_child(
        &self,
        had: bool,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    );
}

/// The one [`HostForkCoordinator`] for every backend, generic over its
/// [`HostSignalPump`]. Replaces the per-backend `GenericForkCoordinator` /
/// HVF `ForkCoordinator` copies of this state machine.
pub struct PumpForkCoordinator<P: HostSignalPump> {
    pump: P,
}

impl<P: HostSignalPump> Default for PumpForkCoordinator<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: HostSignalPump> PumpForkCoordinator<P> {
    pub fn new() -> Self {
        Self { pump: P::default() }
    }

    /// The backend pump, for test assertions / backend-specific accessors.
    pub fn pump(&self) -> &P {
        &self.pump
    }
}

impl<P: HostSignalPump> HostForkCoordinator for PumpForkCoordinator<P> {
    fn start_signal_pump(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        self.pump.ensure_handler();
        self.pump.start(registry, futex);
    }

    fn prepare_host_fork(&self) -> PreparedHostFork {
        // STOP + JOIN the pump before `libc::fork` (it holds process-global locks a
        // fork would strand). `had_signal_pump` = it was running OR an always-on
        // handler is installed; if so, block the pump's signals across the window.
        let was_running = self.pump.stop_for_fork();
        let had_signal_pump = was_running || self.pump.installed_independent_of_stop();
        if had_signal_pump {
            self.pump.block_signals_for_fork();
        }
        PreparedHostFork { had_signal_pump }
    }

    fn restart_after_parent_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
        child_exit_needs_signal_pump: bool,
    ) {
        if prepared.had_signal_pump || child_exit_needs_signal_pump {
            self.start_signal_pump(registry, futex);
        }
        self.pump.restore_signals_after_fork();
    }

    fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        if prepared.had_signal_pump {
            self.pump.ensure_handler();
        }
        self.pump
            .reinit_child(prepared.had_signal_pump, registry, futex);
        self.pump.restore_signals_after_fork();
    }

    fn restart_after_fork_error(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        if prepared.had_signal_pump {
            self.start_signal_pump(registry, futex);
        }
        self.pump.restore_signals_after_fork();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A lazy/HVF-shaped inert pump: tracks whether a pump is "running" and counts
    /// the lifecycle calls, with no real OS state. (`installed_independent_of_stop`
    /// = false → lazy semantics.)
    #[derive(Default)]
    struct InertLazyPump {
        running: Mutex<bool>,
        starts: AtomicUsize,
        reinits: AtomicUsize,
    }
    impl HostSignalPump for InertLazyPump {
        fn ensure_handler(&self) {}
        fn start(&self, _r: &Arc<dyn VcpuRegistry>, _f: &Arc<dyn PlatformFutex>) {
            *self.running.lock().unwrap() = true;
            self.starts.fetch_add(1, Ordering::SeqCst);
        }
        fn stop_for_fork(&self) -> bool {
            let mut g = self.running.lock().unwrap();
            let was = *g;
            *g = false;
            was
        }
        fn installed_independent_of_stop(&self) -> bool {
            false
        }
        fn reinit_child(&self, had: bool, r: &Arc<dyn VcpuRegistry>, f: &Arc<dyn PlatformFutex>) {
            self.reinits.fetch_add(1, Ordering::SeqCst);
            if had {
                self.start(r, f);
            }
        }
    }

    struct InertRegistry;
    impl VcpuRegistry for InertRegistry {
        fn register(&self, _t: crate::ThreadId, _h: Box<dyn crate::VcpuKickDyn>) {}
        fn register_in_guest(&self, _t: crate::ThreadId) -> Arc<AtomicBool> {
            Arc::new(AtomicBool::new(false))
        }
        fn unregister(&self, _t: crate::ThreadId) {}
        fn kick(&self, _t: crate::ThreadId) {}
        fn kick_all(&self) {}
        fn kick_all_except(&self, _e: crate::ThreadId) {}
        fn any_other_in_guest(&self, _e: crate::ThreadId) -> bool {
            false
        }
        fn set_in_guest(&self, _t: crate::ThreadId, _g: bool) {}
        fn count(&self) -> usize {
            0
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
            _k: usize,
            _v: u32,
            _to: Option<Duration>,
            _i: &dyn Fn() -> bool,
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
        (Arc::new(InertRegistry), Arc::new(InertFutex))
    }

    /// The LAZY state machine: a child with no inherited pump stays pump-free; a
    /// child that inherited one restarts; the parent restarts on `child_exit`.
    #[test]
    fn lazy_pump_state_machine() {
        let (r, f) = ctx();
        let c = PumpForkCoordinator::<InertLazyPump>::new();

        c.start_signal_pump(&r, &f);
        assert!(*c.pump().running.lock().unwrap(), "start runs the pump");

        // Fork with a live pump: prepare stops it (had=true), child restarts it.
        let prepared = c.prepare_host_fork();
        assert!(prepared.had_signal_pump, "live pump → had");
        assert!(
            !*c.pump().running.lock().unwrap(),
            "prepare stopped the pump"
        );
        c.restart_after_child_fork(prepared, &r, &f);
        assert!(
            *c.pump().running.lock().unwrap(),
            "child restarts inherited pump"
        );

        // Fork with NO pump: prepare had=false, child stays pump-free.
        c.stop_for_fork_for_test();
        let prepared = c.prepare_host_fork();
        assert!(!prepared.had_signal_pump, "no pump → !had");
        c.restart_after_child_fork(prepared, &r, &f);
        assert!(
            !*c.pump().running.lock().unwrap(),
            "lazy child with no inherited pump stays pump-free"
        );

        // Parent restarts on child-exit need even with no prior pump.
        let prepared = c.prepare_host_fork();
        c.restart_after_parent_fork(prepared, &r, &f, /* child_exit */ true);
        assert!(
            *c.pump().running.lock().unwrap(),
            "child-exit need restarts parent pump"
        );
    }

    impl PumpForkCoordinator<InertLazyPump> {
        fn stop_for_fork_for_test(&self) {
            self.pump.stop_for_fork();
        }
    }
}
