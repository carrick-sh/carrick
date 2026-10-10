//! BSD-family `PlatformFutex`.
//!
//! Under the unified HVPatch kernel, every Linux process is a thread of one carrier,
//! so both private and `MAP_SHARED` guest futexes are in-process rendezvous.
//! The shared [`FutexTableFutex`] is used across all BSD backends.

use std::sync::Arc;

use carrick_thread::platform_futex::{FutexTableFutex, SharedFutexTable};
use carrick_thread::thread::FutexTable;

/// The BSD `PlatformFutex`. Construct with [`make_bsd_futex`].
pub type BsdFutex = FutexTableFutex;

/// Wrap the process-private `FutexTable`.
pub fn make_bsd_futex(table: Arc<FutexTable>, shared: SharedFutexTable) -> BsdFutex {
    FutexTableFutex::new(table, shared)
}
