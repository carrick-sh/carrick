//! `HostForkCoordinator` for the KVM backend.
//!
//! Like the HVF [`carrick_runtime::fork_coord::ForkCoordinator`], this must
//! STOP + JOIN the async host-signal pump daemon thread
//! ([`crate::kvm_signal_pump`]) before `libc::fork` and recreate it after:
//! the pump takes process-global locks (signal-core pending table, child-watch
//! table, kicker, futex table) on every wake, and a fork landing while one is
//! held hands the child a mutex with no owner — a permanent child deadlock
//! (the go-os_exec TestConcurrentExec vfork-child wedge).
//!
//! On Linux a host signal delivered to a thread blocked in `KVM_RUN` natively
//! makes the ioctl return `-EINTR` (this is exactly the cross-thread "kick"
//! mechanism — see [`crate::kvm_kicker`]). The coordinator's second job is to
//! keep the [`crate::kvm_kicker::kick_signal`] handler installed (idempotently)
//! so that a delivered kick turns into an `EINTR` rather than killing the
//! process or being silently restarted.
//!
//! `PreparedHostFork { had_signal_pump }` records whether the handler was live
//! at fork time. `libc::fork` preserves signal dispositions in BOTH the parent
//! and the child (POSIX), so the handler survives the fork — but we re-assert it
//! (idempotent `Once`-guarded install) on every restart path so the contract is
//! explicit and a future eager-teardown can't strand a child without a handler.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use carrick_hal::{HostForkCoordinator, PlatformFutex, PreparedHostFork, VcpuRegistry};
use std::sync::Arc;

use crate::kvm_kicker::install_kvm_kick_handler;

/// Process-wide "is the kick-signal handler installed" flag, shared across all
/// `KvmForkCoordinator` instances (forks create fresh coordinators but the
/// handler is a process-global disposition). Mirrors the HVF coordinator's
/// pump-installed tracking, minus the daemon thread.
static SIGNAL_PUMP_INSTALLED: AtomicBool = AtomicBool::new(false);

/// The KVM host-fork coordinator. Lean by construction — no pump thread, just
/// the idempotent kick-signal-handler install (`signal_pump_installed` records
/// whether `start_signal_pump` has run for diagnostics / the prepared-fork
/// token). See the module docs for why KVM needs no pump.
pub struct KvmForkCoordinator {
    /// Whether [`Self::start_signal_pump`] has installed the handler. A `Mutex`
    /// (not an atomic) only to match the canonical struct shape in the plan; the
    /// process-global truth is [`SIGNAL_PUMP_INSTALLED`].
    signal_pump_installed: Mutex<bool>,
}

impl Default for KvmForkCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl KvmForkCoordinator {
    pub fn new() -> Self {
        Self {
            signal_pump_installed: Mutex::new(false),
        }
    }

    /// Install the kick-signal handler (idempotent) and record it as live.
    fn ensure_handler_installed(&self) {
        install_kvm_kick_handler();
        // Also initialise the cross-process explicit-signal ring + its nudge
        // handler. ORDERING IS LOAD-BEARING: `ensure_handler_installed` first
        // runs at STARTUP (pre-fork, via `start_signal_pump`), so the
        // `MAP_SHARED` ring is created BEFORE `libc::fork` and inherited by every
        // child — all carrick processes then share ONE ring. It ALSO runs in
        // `restart_after_child_fork`, where `xsig_init` is idempotent (no-ops on
        // the inherited ring) and only the nudge handler is re-asserted in the
        // child. This single hook therefore covers both the pre-fork create and
        // the post-fork re-arm.
        crate::kvm_xsig::init_xsig();
        *self
            .signal_pump_installed
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
        SIGNAL_PUMP_INSTALLED.store(true, Ordering::SeqCst);
    }
}

impl HostForkCoordinator for KvmForkCoordinator {
    fn start_signal_pump(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        // Keep the kick-signal handler installed so a process-directed signal
        // turns an in-flight KVM_RUN into EINTR.
        self.ensure_handler_installed();
        // Start the async HOST-signal pump (idempotent): catch host-delivered
        // SIGTERM/INT/HUP/QUIT, set PROC_PENDING, and kick every vCPU so the
        // generic loop delivers the guest's handler instead of the host default
        // action terminating the process. The `Once`-guarded `start_pump` makes
        // repeated calls (startup + the loop's per-dispatch pump-request) free.
        crate::kvm_signal_pump::start_pump(registry, futex);
    }

    fn prepare_host_fork(&self) -> PreparedHostFork {
        // STOP + JOIN the async host-signal pump thread before `libc::fork`,
        // exactly like the HVF ForkCoordinator. The pump takes process-global
        // locks on every wake (the signal-core pending table, the child-watch
        // table, the kicker, the futex table); under a SIGCHLD storm (exec-heavy
        // guests — go-os_exec TestConcurrentExec) it is hot near-continuously,
        // so a fork that does not first join it routinely hands the CHILD a
        // held mutex whose owner does not exist there — the child then wedges
        // in `host_signal::reinit_after_fork` and the vfork parent rides its
        // 60s suspend timeout. (The module docs' old "KVM has no pump thread"
        // premise predates kvm_signal_pump and is no longer true.)
        let was_running = crate::kvm_signal_pump::stop_pump_for_fork();
        let had_signal_pump = was_running || SIGNAL_PUMP_INSTALLED.load(Ordering::SeqCst);
        if had_signal_pump {
            crate::kvm_signal_pump::block_pump_signals_for_fork();
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
        // Parent: `prepare_host_fork` STOPPED the pump thread, so restart it
        // (not just the handler) if one was running OR the parent now needs to
        // observe a child exit. `start_signal_pump` re-asserts the handler and
        // `start_pump`'s kick-off poke runs one immediate reap pass, covering
        // any SIGCHLD that landed during the stopped window.
        if prepared.had_signal_pump || child_exit_needs_signal_pump {
            self.start_signal_pump(registry, futex);
        }
        crate::kvm_signal_pump::restore_pump_signals_after_fork();
    }

    fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        // Child: `libc::fork` inherits the parent's signal dispositions, but the
        // child's process-global `SIGNAL_PUMP_INSTALLED` flag is a fresh copy of
        // the parent's value at fork time. Re-assert the handler if the parent
        // had one so the child's own kicks/EINTR delivery work.
        if prepared.had_signal_pump {
            self.ensure_handler_installed();
        }
        // The child also needs its OWN async host-signal pump: only the forking
        // thread survives `libc::fork`, so the parent's pump thread did not come
        // across, and the child inherited the parent's (now defunct) self-pipe +
        // a `PUMP_STARTED == true` guard. `reinit_after_fork` resets the guard,
        // closes the stale write fd, and spawns a fresh pipe + pump thread bound
        // to THIS child's registry/futex.
        crate::kvm_signal_pump::reinit_after_fork(registry, futex);
        crate::kvm_signal_pump::restore_pump_signals_after_fork();
    }

    fn restart_after_fork_error(
        &self,
        prepared: PreparedHostFork,
        _registry: &Arc<dyn VcpuRegistry>,
        _futex: &Arc<dyn PlatformFutex>,
    ) {
        // Fork failed: the process is unchanged, just re-assert the handler if it
        // was live (the prepare path never tore it down, so this is a no-op in
        // practice; kept for contract symmetry).
        if prepared.had_signal_pump {
            self.ensure_handler_installed();
        }
        crate::kvm_signal_pump::restore_pump_signals_after_fork();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::FutexOutcome;
    use std::time::Duration;

    // A do-nothing VcpuRegistry / PlatformFutex so the state-machine test needs
    // no real KVM, no pthread, no futex table.
    struct InertRegistry;
    impl VcpuRegistry for InertRegistry {
        fn register(&self, _tid: carrick_hal::ThreadId, _h: Box<dyn carrick_hal::VcpuKickDyn>) {}
        fn register_in_guest(
            &self,
            _tid: carrick_hal::ThreadId,
        ) -> Arc<std::sync::atomic::AtomicBool> {
            Arc::new(std::sync::atomic::AtomicBool::new(false))
        }
        fn unregister(&self, _tid: carrick_hal::ThreadId) {}
        fn kick(&self, _tid: carrick_hal::ThreadId) {}
        fn kick_all(&self) {}
        fn kick_all_except(&self, _except: carrick_hal::ThreadId) {}
        fn any_other_in_guest(&self, _except: carrick_hal::ThreadId) -> bool {
            false
        }
        fn set_in_guest(&self, _tid: carrick_hal::ThreadId, _in_guest: bool) {}
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
            _tid: carrick_hal::ThreadId,
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
        fn notify_signal_pending_for(&self, _tid: carrick_hal::ThreadId) {}
    }

    /// The state-machine: `start_signal_pump` flips `signal_pump_installed`;
    /// `prepare_host_fork` reports the live state; the restart paths re-assert
    /// idempotently (no real fork, no pump thread).
    #[test]
    fn coordinator_state_machine() {
        let registry: Arc<dyn VcpuRegistry> = Arc::new(InertRegistry);
        let futex: Arc<dyn PlatformFutex> = Arc::new(InertFutex);
        let coord = KvmForkCoordinator::new();

        // Fresh coordinator: its own flag starts false.
        assert!(
            !*coord
                .signal_pump_installed
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            "fresh coordinator has not installed the handler"
        );

        // start_signal_pump installs the handler and records it.
        coord.start_signal_pump(&registry, &futex);
        assert!(
            *coord
                .signal_pump_installed
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            "start_signal_pump must record the handler as installed"
        );

        // prepare_host_fork now reports a live pump (process-global).
        let prepared = coord.prepare_host_fork();
        assert!(
            prepared.had_signal_pump,
            "prepare_host_fork must report the live handler"
        );

        // All three restart paths are idempotent no-throws.
        coord.restart_after_parent_fork(
            coord.prepare_host_fork(),
            &registry,
            &futex,
            /* child_exit_needs_signal_pump */ false,
        );
        coord.restart_after_child_fork(coord.prepare_host_fork(), &registry, &futex);
        coord.restart_after_fork_error(coord.prepare_host_fork(), &registry, &futex);

        // A parent that now needs a child-exit signal installs even if it had no
        // pump before (the OR branch).
        let coord2 = KvmForkCoordinator::new();
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
            "a child-exit-signal need must install the handler"
        );
    }
}
