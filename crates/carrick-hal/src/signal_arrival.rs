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
