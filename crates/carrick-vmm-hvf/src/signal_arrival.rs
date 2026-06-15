//! HVF's [`SignalArrival`]: the one neutral wake hook the generic loop drives.
//! `wake_all_waiters` forwards to the existing HVF host-signal glue
//! (`crate::host_signal::wake_all_waiters`), which releases every parked waiter
//! (kqueue pump self-pipe + per-thread waiter wakes) at a fork/exec quiesce
//! point or on process-directed arrival.
//!
//! Everything else (host `sigaction` install, the cross-process xsig MAP_SHARED
//! ring, sender recording, child-exit watches, the fork reset) is owned by the
//! `crate::host_signal` free-function seam and the fork coordinator and reached
//! directly by the dispatcher — none of it flows through this trait.
use carrick_hal::SignalArrival;

/// HVF arrival/wake mechanism. Field-less: the only live hook forwards to a
/// process-global `host_signal` function and needs no per-instance state.
pub struct HvfSignalArrival;

impl SignalArrival for HvfSignalArrival {
    fn wake_all_waiters(&self) {
        crate::host_signal::wake_all_waiters();
    }
}
