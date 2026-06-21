//! The kick+futex backends' [`crate::HostSignalPump`]: a SELF-PIPE pump (KVM,
//! bhyve, NVMM), generic over the backend's [`HostSignalGlue`]. Paired with the
//! shared [`crate::PumpForkCoordinator`] state machine it reproduces the three
//! ~identical per-backend fork coordinators — they differed ONLY in which
//! `install_*_kick_handler` / `*_xsig::init_xsig` / `*_signal_pump::*` they called,
//! all now the shared generic parameterized by `G`.
//!
//! ## Why the coordinator stops+joins this pump before `libc::fork`
//!
//! The async host-signal pump ([`crate::signal_pump`]) takes process-global locks
//! (the signal-core pending table, the child-watch table, the kicker, the futex
//! table) on every wake. A `libc::fork` landing while one is held hands the CHILD
//! a mutex with no owner — a permanent child deadlock (the go-os_exec
//! TestConcurrentExec vfork-child wedge). So [`crate::PumpForkCoordinator`] STOPS +
//! JOINS the pump thread via [`HostSignalPump::stop_for_fork`]; the restart paths
//! recreate it (parent) or re-arm a fresh one bound to the child's registry/futex
//! (child, via [`HostSignalPump::reinit_child`]).

#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use carrick_signal_core::HostSignalGlue;

use crate::pump_fork_coord::{HostSignalPump, PumpForkCoordinator};
use crate::{PlatformFutex, VcpuRegistry};

/// Process-wide "is the kick-signal handler installed" flag, shared across all
/// coordinator instances (forks create fresh coordinators but the handler is a
/// process-global disposition). There is ONE active backend `G` per process, so
/// one flag is correct. Makes the self-pipe pump ALWAYS-ON: once installed,
/// `installed_independent_of_stop` stays true even while the pump thread is down.
static SIGNAL_PUMP_INSTALLED: AtomicBool = AtomicBool::new(false);

/// The self-pipe async host-signal pump for a kick+futex backend `G`. Owns no
/// per-instance state — the pump thread + self-pipe + install flag are all
/// process-global (`crate::signal_pump` + [`SIGNAL_PUMP_INSTALLED`]); `G` is used
/// only through associated fns.
pub struct SelfPipePump<G: HostSignalGlue>(PhantomData<fn() -> G>);

impl<G: HostSignalGlue> Default for SelfPipePump<G> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<G: HostSignalGlue> HostSignalPump for SelfPipePump<G> {
    fn ensure_handler(&self) {
        // ORDERING IS LOAD-BEARING: first runs at STARTUP (pre-fork, via
        // `start_signal_pump`) so the `MAP_SHARED` xsig ring is created BEFORE
        // `libc::fork` and inherited by every child. In `reinit_child` it re-runs
        // where `init_xsig` is idempotent (no-ops on the inherited ring) and only
        // the nudge handler is re-asserted.
        G::install_kick_handler();
        carrick_signal_core::host_glue::init_xsig::<G>();
        SIGNAL_PUMP_INSTALLED.store(true, Ordering::SeqCst);
    }

    fn start(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        crate::signal_pump::start_pump::<G>(registry, futex);
    }

    fn stop_for_fork(&self) -> bool {
        crate::signal_pump::stop_pump_for_fork()
    }

    fn installed_independent_of_stop(&self) -> bool {
        SIGNAL_PUMP_INSTALLED.load(Ordering::SeqCst)
    }

    fn block_signals_for_fork(&self) {
        crate::signal_pump::block_pump_signals_for_fork();
    }

    fn restore_signals_after_fork(&self) {
        crate::signal_pump::restore_pump_signals_after_fork();
    }

    fn reinit_child(
        &self,
        _had: bool,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        // ALWAYS-ON: the child inherited the process-global self-pipe stale, so
        // rebuild it + re-arm a fresh pump UNCONDITIONALLY (the `_had` gate is for
        // lazy backends). `ensure_handler` already re-asserted the kick handler.
        crate::signal_pump::reinit_after_fork::<G>(registry, futex);
    }
}

/// The shared host-fork coordinator for a kick+futex backend `G`: the neutral
/// [`PumpForkCoordinator`] state machine over the self-pipe [`SelfPipePump`].
pub type GenericForkCoordinator<G> = PumpForkCoordinator<SelfPipePump<G>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FutexOutcome;
    use crate::threaded::HostForkCoordinator;
    use std::time::Duration;

    /// Inert backend glue: real signum identity + a no-op kick install, so the
    /// coordinator state machine runs with no real KVM/bhyve/NVMM.
    struct InertGlue;
    impl HostSignalGlue for InertGlue {
        fn kick_signal() -> i32 {
            // A fixed number the state-machine test never DELIVERS (only the nudge
            // handler's sigaction is installed); avoids colliding with the runner.
            40
        }
        fn host_to_linux(s: i32) -> i32 {
            s
        }
        fn linux_to_host(s: i32) -> i32 {
            s
        }
        fn is_claimed(_s: i32) -> bool {
            false
        }
        fn poke() {}
        fn install_kick_handler() {}
    }

    struct InertRegistry;
    impl VcpuRegistry for InertRegistry {
        fn register(&self, _tid: crate::ThreadId, _h: Box<dyn crate::VcpuKickDyn>) {}
        fn register_in_guest(&self, _tid: crate::ThreadId) -> Arc<AtomicBool> {
            Arc::new(AtomicBool::new(false))
        }
        fn unregister(&self, _tid: crate::ThreadId) {}
        fn kick(&self, _tid: crate::ThreadId) {}
        fn kick_all(&self) {}
        fn kick_all_except(&self, _except: crate::ThreadId) {}
        fn any_other_in_guest(&self, _except: crate::ThreadId) -> bool {
            false
        }
        fn set_in_guest(&self, _tid: crate::ThreadId, _in_guest: bool) {}
        fn count(&self) -> usize {
            0
        }
    }

    struct InertFutex;
    impl PlatformFutex for InertFutex {
        fn private_wait(
            &self,
            _addr: u64,
            _val: u32,
            _tid: crate::ThreadId,
            _timeout: Option<Duration>,
            _interrupted: &dyn Fn() -> bool,
        ) -> FutexOutcome {
            FutexOutcome::Woken
        }
        fn private_wake(&self, _addr: u64, _n: u32) -> u32 {
            0
        }
        fn shared_wait(
            &self,
            _host_addr: usize,
            _value: u32,
            _timeout: Option<Duration>,
            _interrupted: &dyn Fn() -> bool,
        ) -> i64 {
            0
        }
        fn shared_wake(&self, _host_addr: usize, _n: u32) -> i64 {
            0
        }
        fn requeue(&self, _from: u64, _to: u64, _wake: u32, _requeue: u32) -> (u32, u32) {
            (0, 0)
        }
        fn notify_signal_pending(&self) {}
        fn notify_signal_pending_for(&self, _tid: crate::ThreadId) {}
    }

    /// The ALWAYS-ON self-pipe wiring: `start_signal_pump` installs the handler
    /// (the process-global flag flips); `prepare_host_fork` reports it; the restart
    /// paths are idempotent no-throws. (Same state machine the per-backend
    /// coordinators were tested with, now on the shared generic over `SelfPipePump`.)
    #[test]
    fn generic_coordinator_wires_self_pipe_pump() {
        let registry: Arc<dyn VcpuRegistry> = Arc::new(InertRegistry);
        let futex: Arc<dyn PlatformFutex> = Arc::new(InertFutex);
        let coord = GenericForkCoordinator::<InertGlue>::new();

        coord.start_signal_pump(&registry, &futex);
        assert!(
            SIGNAL_PUMP_INSTALLED.load(Ordering::SeqCst),
            "start_signal_pump installs the process-global handler"
        );

        let prepared = coord.prepare_host_fork();
        assert!(
            prepared.had_signal_pump,
            "always-on: prepare reports the installed handler even after stop"
        );

        coord.restart_after_parent_fork(coord.prepare_host_fork(), &registry, &futex, false);
        coord.restart_after_child_fork(coord.prepare_host_fork(), &registry, &futex);
        coord.restart_after_fork_error(coord.prepare_host_fork(), &registry, &futex);
    }
}
