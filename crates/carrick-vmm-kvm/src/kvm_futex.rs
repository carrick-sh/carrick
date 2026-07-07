//! KVM's shared-page futex syscall shim.
//!
//! The whole `PlatformFutex` impl is now the shared
//! [`carrick_thread::platform_futex::FutexTableFutex<S>`]; KVM supplies only the
//! one per-host divergence — the `MAP_SHARED` (cross-process) futex kernel call —
//! as a [`SharedFutexSyscall`] shim. On Linux that is the REAL host `SYS_futex`
//! (`FUTEX_WAIT`/`FUTEX_WAKE`, **no** `FUTEX_PRIVATE_FLAG`) on the shared-aperture
//! HOST address: both forked carrick processes hold the SAME `MAP_SHARED|
//! MAP_ANONYMOUS` physical page at the same host VA (the aperture is inherited,
//! not copied), so a bare `FUTEX_WAIT`/`FUTEX_WAKE` rendezvouses across the
//! process boundary, and the errno values ARE Linux's (this is Linux) so no
//! cross-OS errno translation is needed.
//!
//! `KvmFutex` is now a thin alias for `FutexTableFutex<KvmSharedFutex>`; build it
//! with [`make_kvm_futex`]. The private path, the ≤20 ms slice loop, and the
//! `notify_signal_pending` wakes all live in the shared crate.

use std::sync::Arc;

use carrick_hal::{HostVa, SharedFutexLocation, SharedWaitStep};
use carrick_thread::platform_futex::{FutexTableFutex, SharedFutexSyscall};
use carrick_thread::thread::FutexTable;

/// Wait on a cross-process futex via the host `SYS_futex(FUTEX_WAIT, ...)`.
///
/// BARE `FUTEX_WAIT` (no `FUTEX_PRIVATE_FLAG`): this is a `MAP_SHARED` word that
/// must rendezvous across processes, so the kernel must key on the physical page
/// (the private flag keys on the mm, which differs between parent and child).
///
/// `timeout_ns`, when `Some`, is a RELATIVE timeout slice (a `struct timespec`).
/// Returns `0` on success (woken or value already mismatched — both are a `0`
/// return from `FUTEX_WAIT`), or `-errno` on failure (the kernel's negated
/// errno; Linux errno values, since this IS Linux).
///
/// SAFETY: `host_addr` must be a valid, mapped, 4-byte-aligned host address of
/// the shared-aperture word; the caller only ever passes the host VA the
/// GPA→host translation produced for a `MAP_SHARED` aperture page.
fn futex_wait_on_address(host_addr: usize, val: u32, timeout_ns: Option<i64>) -> i64 {
    let ts = timeout_ns.map(|ns| libc::timespec {
        tv_sec: (ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (ns % 1_000_000_000) as libc::c_long,
    });
    // futex(uaddr, op, val, timeout, uaddr2, val3). For FUTEX_WAIT only
    // uaddr/op/val/timeout are read; uaddr2/val3 are ignored (pass 0/null).
    let timeout_ptr = ts
        .as_ref()
        .map_or(std::ptr::null(), |t| t as *const libc::timespec);
    // SAFETY: a raw FUTEX_WAIT on a host-mapped word; `timeout_ptr` is either
    // null or a valid `&timespec` that outlives the call (`ts` is a local).
    let r = unsafe {
        libc::syscall(
            libc::SYS_futex,
            host_addr as *const u32,
            libc::FUTEX_WAIT,
            val as libc::c_int,
            timeout_ptr,
            std::ptr::null::<u32>(),
            0 as libc::c_int,
        )
    };
    if r < 0 {
        // syscall(3) returns -1 and sets errno; surface -errno like the kernel.
        let e = unsafe { *libc::__errno_location() };
        -i64::from(e)
    } else {
        0
    }
}

/// Wake up to `n` waiters on a cross-process futex via the host
/// `SYS_futex(FUTEX_WAKE, ...)`. BARE `FUTEX_WAKE` (no `FUTEX_PRIVATE_FLAG`),
/// matching the bare `FUTEX_WAIT` waiter side. Returns the count woken (≥0) or
/// `-errno` on failure.
fn futex_wake_by_address(host_addr: usize, n: u32) -> i64 {
    // SAFETY: a raw FUTEX_WAKE on a host-mapped word; FUTEX_WAKE reads only
    // uaddr/op/val (the count); timeout/uaddr2/val3 are ignored.
    let r = unsafe {
        libc::syscall(
            libc::SYS_futex,
            host_addr as *const u32,
            libc::FUTEX_WAKE,
            n as libc::c_int,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0 as libc::c_int,
        )
    };
    if r < 0 {
        let e = unsafe { *libc::__errno_location() };
        -i64::from(e)
    } else {
        r as i64
    }
}

/// KVM's per-host shared-page futex shim: bare `SYS_futex`.
pub struct KvmSharedFutex;

impl SharedFutexSyscall for KvmSharedFutex {
    fn wait_one_slice(
        &self,
        location: SharedFutexLocation,
        _waiter_key: usize,
        val: u32,
        slice_ns: i64,
    ) -> SharedWaitStep {
        let host_addr = location.wait_addr().raw();
        let r = futex_wait_on_address(host_addr, val, Some(slice_ns));
        if r == 0 {
            // Woken, or the word already differed from `val`. Linux FUTEX_WAIT
            // returns 0 on a successful wake; the caller re-checks.
            return SharedWaitStep::Woken;
        }
        let host_errno = (-r) as i32;
        // EAGAIN/EWOULDBLOCK: the word != `val` at entry — the wait would not
        // have blocked; surface as 0 (the guest re-reads + re-evaluates),
        // matching Linux FUTEX_WAIT's value-mismatch semantics.
        if host_errno == libc::EAGAIN {
            return SharedWaitStep::Woken;
        }
        // ETIMEDOUT (≤20 ms slice expiry) / EINTR (signal nudge): re-check at the
        // loop top — only a real deadline or pending interrupt terminates.
        if host_errno == libc::ETIMEDOUT || host_errno == libc::EINTR {
            return SharedWaitStep::Retry;
        }
        // Any other error (e.g. EFAULT on a bad address) is returned directly.
        SharedWaitStep::Error(r)
    }

    /// Unlike macOS `os_sync_wake_by_address` (which needs a one-at-a-time +
    /// `sched_yield` workaround on a SHARED address), the Linux kernel's
    /// `FUTEX_WAKE` is atomic and correct: a single `SYS_futex(FUTEX_WAKE, addr,
    /// n)` wakes up to `n` real waiters and returns the exact count.
    fn wake(&self, location: SharedFutexLocation, _waiter_key: usize, n: u32) -> i64 {
        let host_addr = location.wait_addr().raw();
        futex_wake_by_address(host_addr, n)
    }
}

/// The KVM `PlatformFutex`: the shared `FutexTableFutex` over the bare-`SYS_futex`
/// shim. Construct with [`make_kvm_futex`].
pub type KvmFutex = FutexTableFutex<KvmSharedFutex>;

/// Pair the process-private `FutexTable` with KVM's shared-page shim.
pub fn make_kvm_futex(table: Arc<FutexTable>) -> KvmFutex {
    FutexTableFutex::new(table, KvmSharedFutex)
}

#[cfg(test)]
mod tests {
    //! Host-runnable unit tests (no `/dev/kvm`, no guest). They exercise BOTH
    //! futex paths the shared `FutexTableFutex` exposes over KVM's shim:
    //!   * the PRIVATE path delegates verbatim to the wrapped `FutexTable`
    //!     (cross-THREAD round-trip + a timeout case), and
    //!   * the SHARED path drives the REAL host `SYS_futex` on a plain
    //!     `mmap(MAP_SHARED|MAP_ANONYMOUS)` word (cross-THREAD wake round-trip, a
    //!     value-mismatch fast return, a timeout, and an interrupt case).
    use super::*;
    use carrick_abi::{LINUX_EINTR, LINUX_ETIMEDOUT};
    use carrick_hal::{FutexOutcome, PlatformFutex};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;
    use std::time::Duration;

    fn never_interrupted() -> impl Fn() -> bool {
        || false
    }

    /// PRIVATE path: a `prepare_wait`→park on one thread is woken by a
    /// `private_wake` from another thread (delegated straight to `FutexTable`).
    #[test]
    fn private_wait_woken_by_other_thread() {
        let futex = Arc::new(make_kvm_futex(Arc::new(FutexTable::new())));
        const ADDR: u64 = 0x4000;
        let f2 = Arc::clone(&futex);
        let waiter = thread::spawn(move || {
            f2.private_wait(
                ADDR,
                0,
                carrick_hal::ThreadId::synthetic_for_tests(1),
                Some(Duration::from_secs(5)),
                &|| false,
            )
        });
        thread::sleep(Duration::from_millis(50));
        let woke = futex.private_wake(ADDR, 1);
        assert_eq!(woke, 1, "private_wake must report one waiter woken");
        let outcome = waiter.join().expect("waiter thread join");
        assert_eq!(
            outcome,
            FutexOutcome::Woken,
            "private_wait must report Woken after private_wake"
        );
    }

    /// PRIVATE path: with no waker, `private_wait` returns `TimedOut`.
    #[test]
    fn private_wait_times_out() {
        let futex = make_kvm_futex(Arc::new(FutexTable::new()));
        let outcome = futex.private_wait(
            0x5000,
            0,
            carrick_hal::ThreadId::synthetic_for_tests(1),
            Some(Duration::from_millis(50)),
            &never_interrupted(),
        );
        assert_eq!(
            outcome,
            FutexOutcome::TimedOut,
            "private_wait with no waker must time out"
        );
    }

    /// PRIVATE path: a pending interrupt terminates `private_wait`.
    #[test]
    fn private_wait_interrupted() {
        let futex = make_kvm_futex(Arc::new(FutexTable::new()));
        let outcome = futex.private_wait(
            0x6000,
            0,
            carrick_hal::ThreadId::synthetic_for_tests(1),
            Some(Duration::from_secs(5)),
            &|| true,
        );
        assert_eq!(
            outcome,
            FutexOutcome::Interrupted,
            "private_wait must report Interrupted when the predicate is set"
        );
    }

    /// Allocate one `MAP_SHARED|MAP_ANONYMOUS` page (the flags the KVM shared
    /// aperture uses) and return the host address of its first word.
    fn shared_word() -> *mut AtomicU32 {
        // SAFETY: a fresh 4 KiB anonymous shared mapping; we own it.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "shared mmap failed");
        p.cast::<AtomicU32>()
    }

    fn shared_location(word: usize) -> SharedFutexLocation {
        SharedFutexLocation::Direct {
            word: HostVa(word),
            waiter_key: word,
        }
    }

    /// SHARED path: thread A `shared_wait` blocks on host `SYS_futex`; thread B
    /// stores a new value + `shared_wake` → A returns `0` (woken).
    #[test]
    fn shared_wait_woken_by_shared_wake() {
        let word = shared_word() as usize;
        let location = shared_location(word);
        let atom = unsafe { &*(word as *const AtomicU32) };
        atom.store(0, Ordering::SeqCst);

        let futex = Arc::new(make_kvm_futex(Arc::new(FutexTable::new())));
        let f2 = Arc::clone(&futex);
        let waiter = thread::spawn(move || {
            f2.shared_wait(
                location,
                word,
                0,
                Some(Duration::from_secs(5)),
                &|| false,
                &|| {},
            )
        });
        thread::sleep(Duration::from_millis(50));
        atom.store(1, Ordering::SeqCst);
        let woke = futex.shared_wake(location, word, 1);
        assert_eq!(woke, 1, "shared_wake must report one waiter woken");
        let r = waiter.join().expect("shared waiter join");
        assert_eq!(r, 0, "shared_wait must return 0 (woken) after shared_wake");
    }

    /// SHARED path value-mismatch: `*word != value` at entry → immediate EAGAIN
    /// → `0` (no block), promptly.
    #[test]
    fn shared_wait_value_mismatch_returns_immediately() {
        let word = shared_word() as usize;
        let location = shared_location(word);
        let atom = unsafe { &*(word as *const AtomicU32) };
        atom.store(42, Ordering::SeqCst);

        let futex = make_kvm_futex(Arc::new(FutexTable::new()));
        let start = std::time::Instant::now();
        let r = futex.shared_wait(
            location,
            word,
            0,
            Some(Duration::from_secs(5)),
            &never_interrupted(),
            &|| {},
        );
        let elapsed = start.elapsed();
        assert_eq!(r, 0, "value-mismatch shared_wait must return 0 (no block)");
        assert!(
            elapsed < Duration::from_secs(1),
            "value-mismatch shared_wait must return promptly, took {elapsed:?}"
        );
    }

    /// SHARED path timeout: word matches `value`, no waker → `-ETIMEDOUT`.
    #[test]
    fn shared_wait_times_out() {
        let word = shared_word() as usize;
        let location = shared_location(word);
        let atom = unsafe { &*(word as *const AtomicU32) };
        atom.store(7, Ordering::SeqCst);

        let futex = make_kvm_futex(Arc::new(FutexTable::new()));
        let r = futex.shared_wait(
            location,
            word,
            7,
            Some(Duration::from_millis(120)),
            &never_interrupted(),
            &|| {},
        );
        assert_eq!(
            r,
            LINUX_ETIMEDOUT.guest_retval(),
            "shared_wait with no waker must time out with -ETIMEDOUT"
        );
    }

    /// SHARED path interrupt: a pending `interrupted()` terminates with `-EINTR`.
    #[test]
    fn shared_wait_interrupted_returns_eintr() {
        let word = shared_word() as usize;
        let location = shared_location(word);
        let atom = unsafe { &*(word as *const AtomicU32) };
        atom.store(0, Ordering::SeqCst);

        let futex = make_kvm_futex(Arc::new(FutexTable::new()));
        let r = futex.shared_wait(
            location,
            word,
            0,
            Some(Duration::from_secs(5)),
            &|| true,
            &|| {},
        );
        assert_eq!(
            r,
            LINUX_EINTR.guest_retval(),
            "shared_wait must return -EINTR when the predicate is set"
        );
    }

    /// SHARED path wake with no waiter: returns 0 (woke nobody), not an error.
    #[test]
    fn shared_wake_no_waiter_returns_zero() {
        let word = shared_word() as usize;
        let location = shared_location(word);
        let futex = make_kvm_futex(Arc::new(FutexTable::new()));
        let woke = futex.shared_wake(location, word, 1);
        assert_eq!(woke, 0, "shared_wake with no waiter must return 0");
    }
}
