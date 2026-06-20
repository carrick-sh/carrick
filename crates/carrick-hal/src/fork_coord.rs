//! The shared [`HostForkCoordinator`] for every kick+futex backend (KVM, bhyve,
//! NVMM), generic over the backend's [`HostSignalGlue`]. This is the consolidation
//! of the three ~identical per-backend fork coordinators — they differed ONLY in
//! which `install_*_kick_handler` / `*_xsig::init_xsig` / `*_signal_pump::*` they
//! called, all of which are now the shared generic parameterized by `G`.
//!
//! ## Why it must stop+join the pump before `libc::fork`
//!
//! The async host-signal pump ([`crate::signal_pump`]) takes process-global locks
//! (the signal-core pending table, the child-watch table, the kicker, the futex
//! table) on every wake. A `libc::fork` landing while one is held hands the CHILD
//! a mutex with no owner — a permanent child deadlock (the go-os_exec
//! TestConcurrentExec vfork-child wedge). So `prepare_host_fork` STOPS+JOINS the
//! pump thread; the restart paths recreate it (parent) or re-arm a fresh one
//! bound to the child's registry/futex (child).

#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use carrick_signal_core::HostSignalGlue;

use crate::threaded::{HostForkCoordinator, PreparedHostFork};
use crate::{PlatformFutex, VcpuRegistry};

/// Process-wide "is the kick-signal handler installed" flag, shared across all
/// coordinator instances (forks create fresh coordinators but the handler is a
/// process-global disposition). There is ONE active backend `G` per process, so
/// one flag is correct.
static SIGNAL_PUMP_INSTALLED: AtomicBool = AtomicBool::new(false);

/// The shared host-fork coordinator for a kick+futex backend `G`. Owns no
/// hypervisor state — it drives the shared pump + xsig + the backend's kick
/// handler (via `G`).
pub struct GenericForkCoordinator<G: HostSignalGlue> {
    /// Whether [`Self::start_signal_pump`] has installed the handler (per-instance
    /// diagnostic; the process-global truth is [`SIGNAL_PUMP_INSTALLED`]).
    signal_pump_installed: Mutex<bool>,
    // `G` is used only through associated fns; `fn() -> G` keeps the coordinator
    // unconditionally `Send + Sync` regardless of `G`.
    _glue: PhantomData<fn() -> G>,
}

impl<G: HostSignalGlue> Default for GenericForkCoordinator<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: HostSignalGlue> GenericForkCoordinator<G> {
    pub fn new() -> Self {
        Self {
            signal_pump_installed: Mutex::new(false),
            _glue: PhantomData,
        }
    }

    /// Install the backend's kick-signal handler (idempotent) + initialise the
    /// cross-process xsignal ring and its nudge handler, and record it as live.
    ///
    /// ORDERING IS LOAD-BEARING: this first runs at STARTUP (pre-fork, via
    /// `start_signal_pump`), so the `MAP_SHARED` ring is created BEFORE `libc::fork`
    /// and inherited by every child — all carrick processes share ONE ring. It also
    /// runs in `restart_after_child_fork`, where `init_xsig` is idempotent (no-ops
    /// on the inherited ring) and only the nudge handler is re-asserted.
    fn ensure_handler_installed(&self) {
        G::install_kick_handler();
        carrick_signal_core::host_glue::init_xsig::<G>();
        *self
            .signal_pump_installed
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
        SIGNAL_PUMP_INSTALLED.store(true, Ordering::SeqCst);
    }
}

impl<G: HostSignalGlue> HostForkCoordinator for GenericForkCoordinator<G> {
    fn start_signal_pump(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        // Keep the kick-signal handler installed so a process-directed signal turns
        // an in-flight run-loop ioctl into EINTR; then start the async host-signal
        // pump (idempotent) so host SIGTERM/INT/HUP/QUIT reach the guest.
        self.ensure_handler_installed();
        crate::signal_pump::start_pump::<G>(registry, futex);
    }

    fn prepare_host_fork(&self) -> PreparedHostFork {
        // STOP + JOIN the async host-signal pump thread before `libc::fork` (see the
        // module docs): it holds process-global locks a fork would strand.
        let was_running = crate::signal_pump::stop_pump_for_fork();
        let had_signal_pump = was_running || SIGNAL_PUMP_INSTALLED.load(Ordering::SeqCst);
        if had_signal_pump {
            crate::signal_pump::block_pump_signals_for_fork();
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
        // Parent: `prepare_host_fork` stopped the pump thread; restart it if one was
        // running OR the parent now needs to observe a child exit.
        if prepared.had_signal_pump || child_exit_needs_signal_pump {
            self.start_signal_pump(registry, futex);
        }
        crate::signal_pump::restore_pump_signals_after_fork();
    }

    fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        // Child: re-assert the kick handler if the parent had one, then re-arm a
        // FRESH pump (only the forking thread survives `libc::fork`, so the parent's
        // pump thread + self-pipe did not come across).
        if prepared.had_signal_pump {
            self.ensure_handler_installed();
        }
        crate::signal_pump::reinit_after_fork::<G>(registry, futex);
        crate::signal_pump::restore_pump_signals_after_fork();
    }

    fn restart_after_fork_error(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        // Fork failed: the process is unchanged, but `prepare_host_fork` already
        // STOPPED the pump thread, so RESTART it (not just the handler) if one was
        // running — `start_signal_pump` is idempotent. (KVM previously only
        // re-asserted the handler here and relied on the loop's per-dispatch
        // pump-request to restart; restarting now is strictly more robust.)
        if prepared.had_signal_pump {
            self.start_signal_pump(registry, futex);
        }
        crate::signal_pump::restore_pump_signals_after_fork();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FutexOutcome;
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

    /// `start_signal_pump` flips `signal_pump_installed`; `prepare_host_fork`
    /// reports it; the restart paths are idempotent no-throws. (Same state machine
    /// the per-backend coordinators were tested with, now on the shared generic.)
    #[test]
    fn coordinator_state_machine() {
        let registry: Arc<dyn VcpuRegistry> = Arc::new(InertRegistry);
        let futex: Arc<dyn PlatformFutex> = Arc::new(InertFutex);
        let coord = GenericForkCoordinator::<InertGlue>::new();

        assert!(
            !*coord
                .signal_pump_installed
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            "fresh coordinator has not installed the handler"
        );

        coord.start_signal_pump(&registry, &futex);
        assert!(
            *coord
                .signal_pump_installed
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            "start_signal_pump records the handler as installed"
        );

        let prepared = coord.prepare_host_fork();
        assert!(prepared.had_signal_pump, "prepare reports the live handler");

        coord.restart_after_parent_fork(coord.prepare_host_fork(), &registry, &futex, false);
        coord.restart_after_child_fork(coord.prepare_host_fork(), &registry, &futex);
        coord.restart_after_fork_error(coord.prepare_host_fork(), &registry, &futex);

        let coord2 = GenericForkCoordinator::<InertGlue>::new();
        coord2.restart_after_parent_fork(
            PreparedHostFork {
                had_signal_pump: false,
            },
            &registry,
            &futex,
            /* child_exit_needs_signal_pump */ true,
        );
        assert!(
            *coord2
                .signal_pump_installed
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            "a child-exit-signal need installs the handler"
        );
    }
}
