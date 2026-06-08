//! How async signals physically ARRIVE and how a waiter is woken — the
//! per-backend mechanism behind the neutral carrick-signal-core pending store.
//! HVF wraps the kqueue pump / EVFILT / xsig ring; KVM uses kicker+futex, the
//! native sigaction pump (Task 7), and native rt_sigqueueinfo (Task 8). The trait
//! PERMITS divergence: HVF's xsig_* use a MAP_SHARED ring, KVM's use host syscalls.
use crate::ThreadId;

pub trait SignalArrival: Send + Sync {
    /// Install host sigaction handlers / spawn the pump. Idempotent; init + after fork.
    fn install_handlers(&self);
    /// Wake the vCPU/waiter for `tid` after a signal was published into core state.
    fn on_signal_arrived(&self, tid: ThreadId);
    /// Wake ALL parked waiters (fork/exec quiesce, process-directed arrival).
    fn wake_all_waiters(&self);
    /// Record sender host pid for the NEXT async delivery of `signum` (SI_USER si_pid).
    fn record_sender(&self, signum: i32, host_pid: i32);
    /// Watch a guest child for exit, publishing `exit_signal` to `parent_tid` (SIGCHLD).
    fn register_child_exit_watch(&self, child_pid: i32, parent_tid: i32, exit_signal: i32);
    /// Cross-process queued signal. HVF: MAP_SHARED ring; KVM: native rt_sigqueueinfo.
    fn xsig_enqueue(
        &self,
        target_host: i32,
        signum: i32,
        sender_ns: i32,
        sender_uid: u32,
        value: i64,
    ) -> bool;
    fn xsig_nudge(&self, target_host: i32);
    fn xsig_drain_for_self(&self) -> Vec<(i32, i32, u32, i64)>;
    fn xsig_has_pending(&self) -> bool;
    /// Fork/exec reset (re-create pump kq, clear inherited rings/watches).
    fn reinit_after_fork(&self);
}
