//! Lean bhyve impls of the threaded-loop coordinator traits — the FreeBSD mirror
//! of the KVM coordinator + pump lifecycle (SP4.2).
//!
//! Like the KVM [`carrick_vmm_kvm::kvm_fork_coord::KvmForkCoordinator`], the bhyve
//! coordinator must STOP + JOIN the async host-signal pump daemon thread
//! ([`crate::bhyve_signal_pump`]) before `libc::fork` and recreate it after: the
//! pump takes process-global locks (signal-core pending table, child-watch table,
//! kicker, futex table) on every wake, and a fork landing while one is held hands
//! the child a mutex with no owner — a permanent child deadlock. The coordinator's
//! second job is keeping the vCPU-kick handler installed (idempotently) and
//! initialising the cross-process xsignal ring + its nudge handler.

use std::sync::Arc;

use carrick_hal::{HostForkCoordinator, PlatformFutex, PreparedHostFork, VcpuRegistry};

use crate::bhyve_kicker::install_bhyve_kick_handler;

#[derive(Default)]
pub struct BhyveForkCoordinator;

impl BhyveForkCoordinator {
    pub fn new() -> Self {
        Self
    }

    /// Install the kick-signal handler (idempotent) AND initialise the
    /// cross-process explicit-signal ring + its nudge handler. ORDERING IS
    /// LOAD-BEARING: this first runs at STARTUP (pre-fork, via `start_signal_pump`),
    /// so the `MAP_SHARED` ring is created BEFORE `libc::fork` and inherited by every
    /// child — all carrick processes then share ONE ring. It ALSO runs post-fork,
    /// where `init_xsig` is idempotent (no-ops on the inherited ring) and only the
    /// nudge handler is re-asserted in the child.
    fn ensure_handler_installed(&self) {
        install_bhyve_kick_handler();
        crate::bhyve_xsig::init_xsig();
    }
}

impl HostForkCoordinator for BhyveForkCoordinator {
    fn start_signal_pump(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        // Keep the kick-signal handler installed + create/inherit the xsignal ring.
        self.ensure_handler_installed();
        // Start the async HOST-signal pump (idempotent): catch host-delivered
        // SIGTERM/INT/HUP/QUIT into PROC_PENDING, run the SIGCHLD child-exit reaper,
        // and kick every vCPU so the generic loop delivers the guest's handler
        // instead of the host default action terminating the process.
        crate::bhyve_signal_pump::start_pump(registry, futex);
    }

    fn prepare_host_fork(&self) -> PreparedHostFork {
        // STOP + JOIN the async host-signal pump thread before `libc::fork`, exactly
        // like the KVM/HVF coordinator (the pump takes process-global locks on every
        // wake; a fork that does not first join it can hand the child a held mutex).
        let was_running = crate::bhyve_signal_pump::stop_pump_for_fork();
        PreparedHostFork {
            had_signal_pump: was_running,
        }
    }

    fn restart_after_parent_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
        child_exit_needs_signal_pump: bool,
    ) {
        // Parent: `prepare_host_fork` STOPPED the pump thread, so restart it (not
        // just the handler) if one was running OR the parent now needs to observe a
        // child exit. `start_pump`'s kick-off poke runs one immediate reap pass.
        if prepared.had_signal_pump || child_exit_needs_signal_pump {
            self.start_signal_pump(registry, futex);
        }
    }

    fn restart_after_child_fork(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        // Child: re-assert the kick handler + ring (the child inherited the parent's
        // dispositions but needs its own per-process ring nudge handler re-asserted).
        if prepared.had_signal_pump {
            self.ensure_handler_installed();
        }
        // The child also needs its OWN async host-signal pump: only the forking
        // thread survives `libc::fork`, so the parent's pump thread did not come
        // across, and the child inherited the parent's defunct self-pipe + a
        // `PUMP_STARTED == true` guard. `reinit_after_fork` resets the guard, closes
        // the stale write fd, and spawns a fresh pipe + pump thread for this child.
        crate::bhyve_signal_pump::reinit_after_fork(registry, futex);
    }

    fn restart_after_fork_error(
        &self,
        prepared: PreparedHostFork,
        registry: &Arc<dyn VcpuRegistry>,
        futex: &Arc<dyn PlatformFutex>,
    ) {
        // Fork failed: the process is unchanged; restart the pump if it was running.
        if prepared.had_signal_pump {
            self.start_signal_pump(registry, futex);
        }
    }
}

// `BhyveSignalArrival` was byte-identical to KVM's; both collapsed into the
// shared `carrick_hal::GenericSignalArrival` (kicker + futex wake). The bhyve run
// loop constructs that directly.

pub struct BhyveTimerDelivery {
    pub kicker: Arc<dyn VcpuRegistry>,
    pub main_tid: carrick_thread::thread::ThreadId,
}

impl carrick_hal::TimerDelivery for BhyveTimerDelivery {
    fn arm_itimer(
        &self,
        _which: usize,
        _value_ns: u64,
        _interval_ns: u64,
        _needs_periodic: bool,
        _signum: i32,
    ) -> bool {
        false
    }

    fn disarm_itimer(&self, _which: usize) {}

    fn arm_posix(
        &self,
        _id: i32,
        _value_ns: u64,
        _interval_ns: u64,
    ) -> Option<carrick_hal::timer_delivery::PosixTimerSpec> {
        None
    }

    fn disarm_posix(&self, _id: i32) {}

    fn current_arm(&self, _which: usize) -> Option<carrick_hal::timer_delivery::TimerArm> {
        None
    }
}
