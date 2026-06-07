//! `HostForkCoordinator` for the KVM backend.
//!
//! Unlike the HVF [`carrick_runtime::fork_coord::ForkCoordinator`], which must
//! stop + join a kqueue/itimer signal-pump daemon thread before `libc::fork`
//! (and recreate it after), the KVM coordinator is LEAN: KVM has no pump thread.
//!
//! On Linux a host signal delivered to a thread blocked in `KVM_RUN` natively
//! makes the ioctl return `-EINTR` (this is exactly the cross-thread "kick"
//! mechanism — see [`crate::kvm_kicker`]). So an async, process-directed signal
//! interrupts the in-guest vCPU WITHOUT any pump thread polling for it. The
//! coordinator therefore spawns NO thread; its only job is to keep the
//! [`crate::kvm_kicker::kick_signal`] handler installed (idempotently) so that a
//! delivered kick turns into an `EINTR` rather than killing the process or being
//! silently restarted.
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
        *self
            .signal_pump_installed
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = true;
        SIGNAL_PUMP_INSTALLED.store(true, Ordering::SeqCst);
    }
}

impl HostForkCoordinator for KvmForkCoordinator {
    fn start_signal_pump(
        &self,
        _registry: &Arc<dyn VcpuRegistry>,
        _futex: &Arc<dyn PlatformFutex>,
    ) {
        // No pump thread on KVM. Just keep the kick-signal handler installed so a
        // process-directed signal turns an in-flight KVM_RUN into EINTR.
        self.ensure_handler_installed();
    }

    fn prepare_host_fork(&self) -> PreparedHostFork {
        // Nothing to stop/join (no pump thread). Record whether the handler was
        // live so the restart paths re-assert it.
        PreparedHostFork {
            had_signal_pump: SIGNAL_PUMP_INSTALLED.load(Ordering::SeqCst),
        }
    }

    fn restart_after_parent_fork(
        &self,
        prepared: PreparedHostFork,
        _registry: &Arc<dyn VcpuRegistry>,
        _futex: &Arc<dyn PlatformFutex>,
        child_exit_needs_signal_pump: bool,
    ) {
        // Parent: re-assert the handler if it was live OR if the parent now needs
        // to observe a child exit (child_exit_needs_signal_pump). The install is
        // idempotent, so re-asserting is cheap and never double-installs.
        if prepared.had_signal_pump || child_exit_needs_signal_pump {
            self.ensure_handler_installed();
        }
    }

    fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        _registry: &Arc<dyn VcpuRegistry>,
        _futex: &Arc<dyn PlatformFutex>,
    ) {
        // Child: `libc::fork` inherits the parent's signal dispositions, but the
        // child's process-global `SIGNAL_PUMP_INSTALLED` flag is a fresh copy of
        // the parent's value at fork time. Re-assert the handler if the parent
        // had one so the child's own kicks/EINTR delivery work.
        if prepared.had_signal_pump {
            self.ensure_handler_installed();
        }
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
