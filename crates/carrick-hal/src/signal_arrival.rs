//! The one neutral signal-arrival hook the generic vCPU loop dispatches: "wake
//! all parked waiters". This is needed at fork/exec quiesce points and for
//! process-directed signal arrival, where the loop must release every thread
//! parked in a backend-specific wait without naming the concrete backend.
//!
//! All OTHER signal-arrival mechanics — host-handler install, the cross-process
//! xsig MAP_SHARED ring, sender recording (SI_USER si_pid), child-exit watch,
//! per-tid wake, and the fork reset — are delivered by the backend's
//! `host_signal::*` free-function seam and the [`crate::HostForkCoordinator`],
//! NOT through this trait. The dispatcher reaches those directly, so they never
//! needed an object-safe abstraction here.

pub trait SignalArrival: Send + Sync {
    /// Wake ALL parked waiters (fork/exec quiesce, process-directed arrival).
    fn wake_all_waiters(&self);
}

/// The one `SignalArrival` impl shared by every backend whose "wake all" is
/// "kick every live vCPU out of its run ioctl, then nudge the private futex so
/// parked threads re-check pending state." This was byte-identical across the
/// KVM (`KvmSignalArrival`) and bhyve (`BhyveSignalArrival`) copies; it is now
/// one struct any backend constructs with its kicker + futex trait objects.
///
/// (HVF's wake-all is its kqueue-pump self-pipe + per-thread waiter wakes — a
/// genuinely different mechanism — so HVF keeps its own `HvfSignalArrival`; this
/// generic is for the kick+futex hosts.)
pub struct GenericSignalArrival {
    /// The live-vCPU registry: `kick_all()` forces every guest thread out of its
    /// run ioctl so the trap loop can deliver a pending signal promptly.
    pub kicker: std::sync::Arc<dyn crate::VcpuRegistry>,
    /// The process-private futex: `notify_signal_pending()` wakes parked threads
    /// to re-check their interrupt predicate.
    pub futex: std::sync::Arc<dyn crate::PlatformFutex>,
}

impl SignalArrival for GenericSignalArrival {
    fn wake_all_waiters(&self) {
        self.kicker.kick_all();
        self.futex.notify_signal_pending();
    }
}
