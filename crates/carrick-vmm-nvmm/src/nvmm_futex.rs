//! NVMM's `PlatformFutex`.
//!
//! A thin alias for the shared [`FutexTableFutex`]: under the unified HVPatch
//! kernel every Linux process is a thread of one carrier, so both private and
//! `MAP_SHARED` guest futexes are in-process rendezvous. The previous NetBSD
//! `__futex` shim existed for the retired one-host-process-per-guest-process
//! model.

use std::sync::Arc;

use carrick_thread::platform_futex::FutexTableFutex;
use carrick_thread::thread::FutexTable;

/// The NVMM `PlatformFutex`. Construct with [`make_nvmm_futex`].
pub type NvmmFutex = FutexTableFutex;

/// Wrap the process-private `FutexTable`.
pub fn make_nvmm_futex(table: Arc<FutexTable>) -> NvmmFutex {
    FutexTableFutex::new(table)
}
