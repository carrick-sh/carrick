//! HVF's [`SignalArrival`]: a thin struct that DELEGATES to the existing HVF
//! host-signal glue (the kqueue pump, the self-pipe / per-thread waiter wakes,
//! the cross-process xsignal MAP_SHARED ring, and the child-exit watches). It
//! reimplements nothing — every method forwards to the `crate::host_signal`
//! function that already implements that behavior on macOS.
//!
//! `install_handlers` is intentionally a no-op: on HVF the signal pump is owned
//! by the [`crate::fork_coord::ForkCoordinator`] seam (started TTY-conditionally
//! at the run-loop construction site via `start_signal_pump`), and per-signal
//! host `sigaction`s install lazily through `host_signal::ensure_host_handler`.
//! Driving the pump from here too would double-own that lifecycle.
use std::sync::Arc;

use carrick_hal::{SignalArrival, ThreadId, VcpuRegistry};

/// HVF arrival/wake mechanism. Holds the object-safe vCPU registry so
/// `on_signal_arrived` can kick the target vCPU out of `hv_vcpu_run`.
pub struct HvfSignalArrival {
    pub kicker: Arc<dyn VcpuRegistry>,
}

impl SignalArrival for HvfSignalArrival {
    fn install_handlers(&self) {}

    fn on_signal_arrived(&self, tid: ThreadId) {
        // Force the target vCPU out of the guest so it re-checks pending at its
        // next safe point, then nudge the pump (its self-pipe channel) so a
        // parked pump observes the publish too.
        self.kicker.kick(tid);
        crate::host_signal::wake_signal_pump_pipe();
    }

    fn wake_all_waiters(&self) {
        crate::host_signal::wake_all_waiters();
    }

    fn record_sender(&self, signum: i32, host_pid: i32) {
        crate::host_signal::record_sender(signum, host_pid);
    }

    fn register_child_exit_watch(&self, child_pid: i32, parent_tid: i32, exit_signal: i32) {
        crate::host_signal::register_child_exit_watch(child_pid, parent_tid, exit_signal);
    }

    fn xsig_enqueue(
        &self,
        target_host: i32,
        signum: i32,
        sender_ns: i32,
        sender_uid: u32,
        value: i64,
    ) -> bool {
        crate::host_signal::xsig_enqueue(target_host, signum, sender_ns, sender_uid, value)
    }

    fn xsig_nudge(&self, target_host: i32) {
        crate::host_signal::xsig_nudge(target_host);
    }

    fn xsig_drain_for_self(&self) -> Vec<(i32, i32, u32, i64)> {
        crate::host_signal::xsig_drain_for_self()
    }

    fn xsig_has_pending(&self) -> bool {
        crate::host_signal::xsig_has_pending()
    }

    fn reinit_after_fork(&self) {
        crate::host_signal::reinit_after_fork();
    }
}
