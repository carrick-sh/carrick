//! Cross-process futex primitive (host-VA addressed).
//!
//! macOS impl wraps `carrick-host/ulock.rs` `os_sync_wait_on_address` (14.4+);
//! FreeBSD `_umtx_op` and Linux `SYS_futex` impls are deferred to their specs.

pub trait CrossProcessFutex: Send + Sync {
    fn wait(&self, host_addr: usize, expected: u32, timeout_us: u32) -> i64;
    fn wake(&self, host_addr: usize, all: bool) -> i64;
}
