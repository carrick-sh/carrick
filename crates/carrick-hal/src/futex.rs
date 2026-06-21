//! Cross-process futex primitive (host-VA addressed).
//!
//! macOS impl wraps `carrick-host/ulock.rs` `os_sync_wait_on_address` (14.4+);
//! FreeBSD `_umtx_op` and Linux `SYS_futex` impls are deferred to their specs.

use std::time::{Duration, Instant};

use carrick_abi::{LINUX_EINTR, LINUX_ETIMEDOUT};

/// Cap on a single cross-process (`MAP_SHARED`) futex wait slice: the per-vCPU
/// kick cannot interrupt a thread blocked in the host wait primitive, so we wake
/// every ≤20 ms to re-check `interrupted()` and the deadline.
pub const SHARED_FUTEX_MAX_SLICE_NS: i64 = 20_000_000; // 20 ms

/// What one kernel wait slice resolved to, as classified by the backend's own
/// `wait_one` closure (which alone knows its host errno values). The shared
/// [`shared_wait_sliced`] loop never inspects raw errnos — it only sequences
/// slices, the deadline, and the interrupt re-check.
pub enum SharedWaitStep {
    /// Woken, or the word already differed at entry — the caller re-checks its
    /// condition; the guest-facing `FUTEX_WAIT` returns 0.
    Woken,
    /// This slice expired (`ETIMEDOUT`) or a signal nudged the wait (`EINTR`);
    /// re-check `interrupted()`/deadline at the loop top rather than returning.
    Retry,
    /// Any other terminal result, returned verbatim to the guest as a raw `i64`
    /// (`-errno`, in the value space the caller expects — Linux for the guest).
    Error(i64),
}

/// The shared cross-process-futex wait loop: slice each kernel wait to ≤20 ms so
/// a pending guest signal is observed promptly, re-check `interrupted()` and the
/// (optional, relative) `timeout` deadline between slices, and fold
/// `ETIMEDOUT`/`EINTR` slice terminations into a re-check. The single platform
/// kernel wait + its host-errno classification live in `wait_one(slice_ns)`
/// (HVF `os_sync`, KVM `SYS_futex`, bhyve `_umtx_op`); the deadline/slice/
/// interrupt control — the part that is subtle and signal-delivery-critical —
/// is shared here. Returns `0` (woken/mismatch), `-LINUX_EINTR` (interrupted),
/// `-LINUX_ETIMEDOUT` (deadline), or the closure's `Error` value.
pub fn shared_wait_sliced(
    timeout: Option<Duration>,
    interrupted: &dyn Fn() -> bool,
    wait_one: &dyn Fn(i64) -> SharedWaitStep,
) -> i64 {
    let deadline = timeout.map(|d| Instant::now() + d);
    loop {
        if interrupted() {
            return -i64::from(LINUX_EINTR);
        }
        let slice_ns: i64 = match deadline {
            Some(dl) => {
                let now = Instant::now();
                if now >= dl {
                    return -i64::from(LINUX_ETIMEDOUT);
                }
                i64::try_from((dl - now).as_nanos())
                    .unwrap_or(SHARED_FUTEX_MAX_SLICE_NS)
                    .min(SHARED_FUTEX_MAX_SLICE_NS)
            }
            None => SHARED_FUTEX_MAX_SLICE_NS,
        };
        match wait_one(slice_ns) {
            SharedWaitStep::Woken => return 0,
            SharedWaitStep::Retry => continue,
            SharedWaitStep::Error(e) => return e,
        }
    }
}
