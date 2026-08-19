//! bhyve's `PlatformFutex`.
//!
//! A thin alias for the shared [`FutexTableFutex`]: under the unified HVPatch
//! kernel every Linux process is a thread of one carrier, so both private and
//! `MAP_SHARED` guest futexes are in-process rendezvous. The previous
//! `_umtx_op` shim existed for the retired one-host-process-per-guest-process
//! model, where a shared page had to survive a real host `fork`.

use std::sync::Arc;

use carrick_thread::platform_futex::FutexTableFutex;
use carrick_thread::thread::FutexTable;

/// The bhyve `PlatformFutex`. Construct with [`make_bhyve_futex`].
pub type BhyveFutex = FutexTableFutex;

/// Wrap the process-private `FutexTable`.
pub fn make_bhyve_futex(table: Arc<FutexTable>) -> BhyveFutex {
    FutexTableFutex::new(table)
}
