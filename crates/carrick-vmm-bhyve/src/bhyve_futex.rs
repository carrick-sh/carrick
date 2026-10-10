//! bhyve's `PlatformFutex`.
//!
//! A thin alias for the shared [`FutexTableFutex`]: under the unified HVPatch
//! kernel every Linux process is a thread of one carrier, so both private and
//! `MAP_SHARED` guest futexes are in-process rendezvous. The previous
//! `_umtx_op` shim existed for the retired one-host-process-per-guest-process
//! model, where a shared page had to survive a real host `fork`.

/// The bhyve `PlatformFutex`. Re-exported from the shared BSD futex module.
pub use carrick_host_bsd::futex::{BsdFutex as BhyveFutex, make_bsd_futex as make_bhyve_futex};
