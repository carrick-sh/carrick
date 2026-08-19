//! `PlatformFutex` for HVF.
//!
//! A thin alias for the shared [`FutexTableFutex`]: under the HVPatch kernel
//! every Linux process is a thread of one carrier, so both private and
//! `MAP_SHARED` guest futexes are in-process rendezvous with exact wake
//! accounting — no Darwin primitive involved.
//!
//! The previous `HvfShared` shim drove `os_sync_wait_on_address` /
//! `os_sync_wake_by_address` in 20 ms slices (a host wait cannot be
//! interrupted by our kick, so every shared waiter re-checked its interrupt
//! predicate 50x a second), with a fork-shared waiter side-table reconciling
//! logical and physical wakes and handing out requeue tokens. All of that
//! existed because the retired execution model ran each guest process as a
//! real macOS process; the carrier model deleted the problem it solved.

use std::sync::Arc;

use carrick_thread::platform_futex::FutexTableFutex;
use carrick_thread::thread::FutexTable;

/// HVF's `PlatformFutex`. Construct with [`hvf_futex`].
pub type HvfFutex = FutexTableFutex;

/// Wrap the process-private `FutexTable`.
pub fn hvf_futex(table: Arc<FutexTable>) -> HvfFutex {
    FutexTableFutex::new(table)
}
