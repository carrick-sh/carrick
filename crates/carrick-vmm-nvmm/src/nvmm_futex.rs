//! NVMM's `PlatformFutex`.
//!
//! A thin alias for the shared [`FutexTableFutex`]: under the unified HVPatch
//! kernel every Linux process is a thread of one carrier, so both private and
//! `MAP_SHARED` guest futexes are in-process rendezvous. The previous NetBSD
//! `__futex` shim existed for the retired one-host-process-per-guest-process
//! model.

/// The NVMM `PlatformFutex`. Re-exported from the shared BSD futex module.
pub use carrick_host_bsd::futex::{BsdFutex as NvmmFutex, make_bsd_futex as make_nvmm_futex};
