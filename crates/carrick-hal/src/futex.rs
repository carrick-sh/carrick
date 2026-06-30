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

/// Classify one cross-process futex wait slice's raw host return into a
/// [`SharedWaitStep`], enforcing the Linux `FUTEX_WAIT` errno ABI in ONE place
/// so the three backends cannot diverge on it.
///
/// - `rc >= 0` — a wake (or an at-entry value mismatch the backend already
///   resolved): [`SharedWaitStep::Woken`] (guest `FUTEX_WAIT` returns 0).
/// - `-ETIMEDOUT` / `-EINTR` — slice termination: [`SharedWaitStep::Retry`], so
///   the shared loop re-checks the deadline / interrupt rather than returning.
/// - ANY OTHER terminal `-errno` — mapped to a SPURIOUS [`SharedWaitStep::Woken`],
///   **never leaked to the guest**. A Linux futex wait only ever surfaces
///   `0`/`EAGAIN`/`EINTR`/`ETIMEDOUT`, and glibc's nptl FATALLY aborts ("the
///   futex facility returned an unexpected error code") on anything else — so a
///   host-specific errno (a Darwin/FreeBSD/NetBSD `EINVAL` etc. with no
///   Linux-futex meaning) must surface as a harmless spurious wake: the guest
///   simply re-checks its word and re-waits. HVF already did this; bhyve and
///   NVMM returned `Error(raw_host_errno)` and could thus abort a guest's nptl.
///
/// `host_etimedout` / `host_eintr` are passed in because the numeric errno
/// values differ per host OS (Linux `ETIMEDOUT` is 110, the BSDs/macOS use 60);
/// `carrick-hal` stays host-neutral and never references `libc`.
pub fn classify_wait_slice(rc: i64, host_etimedout: i32, host_eintr: i32) -> SharedWaitStep {
    if rc >= 0 {
        return SharedWaitStep::Woken;
    }
    let host_errno = (-rc) as i32;
    if host_errno == host_etimedout || host_errno == host_eintr {
        SharedWaitStep::Retry
    } else {
        // ABI guard: a non-Linux-futex errno becomes a spurious wake, never a
        // raw error leaked across the guest boundary.
        SharedWaitStep::Woken
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Use Linux's ETIMEDOUT (110) to prove the classifier does NOT assume the
    // host's value; EINTR is 4 everywhere.
    const ETIMEDOUT: i32 = 110;
    const EINTR: i32 = 4;

    fn step_name(s: &SharedWaitStep) -> &'static str {
        match s {
            SharedWaitStep::Woken => "woken",
            SharedWaitStep::Retry => "retry",
            SharedWaitStep::Error(_) => "error",
        }
    }

    #[test]
    fn wake_and_mismatch_are_woken() {
        assert_eq!(
            step_name(&classify_wait_slice(0, ETIMEDOUT, EINTR)),
            "woken"
        );
        assert_eq!(
            step_name(&classify_wait_slice(1, ETIMEDOUT, EINTR)),
            "woken"
        );
    }

    #[test]
    fn timeout_and_eintr_retry() {
        assert_eq!(
            step_name(&classify_wait_slice(
                -i64::from(ETIMEDOUT),
                ETIMEDOUT,
                EINTR
            )),
            "retry"
        );
        assert_eq!(
            step_name(&classify_wait_slice(-i64::from(EINTR), ETIMEDOUT, EINTR)),
            "retry"
        );
    }

    #[test]
    fn unexpected_host_errno_becomes_spurious_wake_not_error() {
        // The bug this guards: bhyve/NVMM returned Error(raw_host_errno) for any
        // non-{ETIMEDOUT,EINTR} errno, which glibc's nptl FATALLY aborts on. EINVAL
        // (22), EFAULT (14), and a wholly host-specific value must all fold to a
        // harmless spurious wake — never an Error.
        for errno in [22i32, 14, 35, 60, 78] {
            let step = classify_wait_slice(-i64::from(errno), ETIMEDOUT, EINTR);
            assert_eq!(
                step_name(&step),
                "woken",
                "errno {errno} must fold to a spurious wake, not leak across the ABI"
            );
        }
    }
}
