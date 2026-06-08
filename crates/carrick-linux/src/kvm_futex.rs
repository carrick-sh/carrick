//! `PlatformFutex` implementation for KVM.
//!
//! `KvmFutex` wraps the process-private `carrick_thread::thread::FutexTable`
//! (parking-lot-backed) for private-anonymous futex operations, and services
//! the `MAP_SHARED` / cross-process futex operations with the REAL host
//! `SYS_futex` syscall (`FUTEX_WAIT` / `FUTEX_WAKE`, **no** `FUTEX_PRIVATE_FLAG`)
//! on the shared-aperture HOST address.
//!
//! This is the KVM analogue of `carrick_hvf::HvfFutex`: the **private** path is
//! identical (verbatim delegation to the wrapped `FutexTable`), and only the
//! **shared** path differs — HVF routes through the macOS `os_sync` ulock API
//! keyed on the physical page, whereas KVM runs on a real Linux host whose
//! kernel `SYS_futex` keys the same `MAP_SHARED|MAP_ANONYMOUS` physical page
//! across `fork(2)` for free. Because both forked carrick processes hold the
//! SAME physical page at the same host VA (the shared aperture is inherited, not
//! copied), a bare `FUTEX_WAIT`/`FUTEX_WAKE` on that host address rendezvouses
//! across the process boundary correctly.
//!
//! As with `HvfFutex`, this file is a forwarding shim only: all private-futex
//! semantics are owned by the existing `FutexTable`; the shared path just names
//! the `carrick_hal::PlatformFutex` surface and routes each method to the right
//! `SYS_futex` call.

use std::sync::Arc;
use std::time::Duration;

// The shared_wait loop now returns these via carrick_hal::shared_wait_sliced;
// only the tests still name them (to assert the interrupt/timeout returns).
#[cfg(test)]
use carrick_abi::{LINUX_EINTR, LINUX_ETIMEDOUT};
use carrick_hal::{FutexOutcome, PlatformFutex, ThreadId};
use carrick_thread::thread::{FutexTable, FutexWaitOutcome};

// The ≤20 ms shared-futex slice cap + the deadline/slice/interrupt loop now live
// in `carrick_hal::shared_wait_sliced` (shared with HVF/bhyve); see `shared_wait`.

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
/// the shared-aperture word; the caller (`shared_wait`) only ever passes the
/// host VA the GPA→host translation produced for a `MAP_SHARED` aperture page.
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

/// The KVM `PlatformFutex` implementation.
///
/// Wraps the per-process `FutexTable` for private futex ops and services
/// `MAP_SHARED` / cross-process futex ops with the host `SYS_futex` syscall.
pub struct KvmFutex(pub Arc<FutexTable>);

impl PlatformFutex for KvmFutex {
    /// Park the calling thread on a private (anonymous) futex.
    ///
    /// VERBATIM the `HvfFutex` private path: the value-equality check was already
    /// performed by the dispatcher BEFORE it returned `DispatchOutcome::FutexWait`,
    /// so we do NOT re-check here — we `prepare_wait` (capturing the generation)
    /// then `wait_prepared_for_thread`, so a thread-directed signal (tgkill) can
    /// wake this specific parked thread via its `ParkToken(tid)`.
    fn private_wait(
        &self,
        addr: u64,
        _val: u32,
        tid: ThreadId,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexOutcome {
        let wait = self.0.prepare_wait(addr);
        match self
            .0
            .wait_prepared_for_thread(wait, timeout, tid, interrupted)
        {
            FutexWaitOutcome::Woken => FutexOutcome::Woken,
            FutexWaitOutcome::TimedOut => FutexOutcome::TimedOut,
            FutexWaitOutcome::Interrupted => FutexOutcome::Interrupted,
        }
    }

    fn private_wake(&self, addr: u64, n: u32) -> u32 {
        self.0.wake(addr, n)
    }

    /// Wait on a `MAP_SHARED` (cross-process) futex via the host `SYS_futex`.
    ///
    /// Slices each kernel `FUTEX_WAIT` to ≤20 ms, re-checks `interrupted()`
    /// between slices, and returns the raw `i64` (`-EINTR`/`-ETIMEDOUT` for the
    /// interrupt/timeout terminations, `0` on woken-or-value-mismatch, `-errno`
    /// for any other kernel error) that the run loop translates back to a Linux
    /// `FUTEX_WAIT` return. Mirrors `HvfFutex::shared_wait` exactly EXCEPT the
    /// kernel call is host `SYS_futex` instead of the macOS `os_sync` ulock —
    /// and the errno values ARE Linux's (this is Linux), so no cross-OS errno
    /// translation is needed.
    fn shared_wait(
        &self,
        host_addr: usize,
        value: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> i64 {
        // The deadline/slice/interrupt loop is shared (carrick_hal); only the
        // single kernel wait + its host-errno classification is KVM-specific.
        carrick_hal::shared_wait_sliced(timeout, interrupted, &|slice_ns| {
            let r = futex_wait_on_address(host_addr, value, Some(slice_ns));
            if r == 0 {
                // Woken, or the word already differed from `value`. Linux
                // FUTEX_WAIT returns 0 on a successful wake; the caller re-checks.
                return carrick_hal::SharedWaitStep::Woken;
            }
            let host_errno = (-r) as i32;
            // EAGAIN/EWOULDBLOCK: the word != `value` at entry — the wait would
            // not have blocked; surface as a 0 return (the guest re-reads + re-
            // evaluates), matching Linux FUTEX_WAIT's value-mismatch semantics.
            if host_errno == libc::EAGAIN {
                return carrick_hal::SharedWaitStep::Woken;
            }
            // ETIMEDOUT (≤20 ms slice expiry) / EINTR (signal nudge): re-check at
            // the loop top — only a real deadline or pending interrupt terminates.
            if host_errno == libc::ETIMEDOUT || host_errno == libc::EINTR {
                return carrick_hal::SharedWaitStep::Retry;
            }
            // Any other error (e.g. EFAULT on a bad address) is returned directly.
            carrick_hal::SharedWaitStep::Error(r)
        })
    }

    /// Wake up to `n` waiters on a `MAP_SHARED` (cross-process) futex via the
    /// host `SYS_futex(FUTEX_WAKE, ...)`.
    ///
    /// Unlike `HvfFutex::shared_wake` (which wakes ONE-AT-A-TIME with a
    /// `sched_yield` between iterations to defeat macOS `os_sync_wake_by_address`'s
    /// spurious back-to-back successes on a SHARED address), the Linux kernel's
    /// `FUTEX_WAKE` is atomic and correct: a single `SYS_futex(FUTEX_WAKE, addr,
    /// n)` wakes up to `n` real waiters and returns the exact count, with no
    /// spurious-success problem to work around. So the natural one-shot form is
    /// used. Returns the count woken (`i64`); a kernel error surfaces as `-errno`.
    fn shared_wake(&self, host_addr: usize, n: u32) -> i64 {
        futex_wake_by_address(host_addr, n)
    }

    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32) {
        self.0.requeue(from, to, wake, requeue)
    }

    #[inline]
    fn notify_signal_pending(&self) {
        self.0.notify_signal_pending();
    }

    #[inline]
    fn notify_signal_pending_for(&self, tid: ThreadId) {
        self.0.notify_signal_pending_for(tid);
    }
}

#[cfg(test)]
mod tests {
    //! Host-runnable unit tests (no `/dev/kvm`, no guest). They exercise BOTH
    //! futex paths `KvmFutex` exposes:
    //!   * the PRIVATE path delegates verbatim to the wrapped `FutexTable`
    //!     (cross-THREAD round-trip + a timeout case), and
    //!   * the SHARED path drives the REAL host `SYS_futex` on a plain
    //!     `mmap(MAP_SHARED|MAP_ANONYMOUS)` word (cross-THREAD wake round-trip, a
    //!     value-mismatch fast return, and a timeout case).
    //!
    //! These run on any Linux host (the crate is `cfg(target_os = "linux")`), so
    //! they execute on the lima L2 lane / a native aarch64 Linux host. The
    //! cross-PROCESS (fork) rendezvous and the threaded-loop integration are
    //! validated at Task 7 (see the report).
    use super::*;
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
        let futex = Arc::new(KvmFutex(Arc::new(FutexTable::new())));
        const ADDR: u64 = 0x4000;
        let f2 = Arc::clone(&futex);
        let waiter = thread::spawn(move || {
            // tid 1 is the parked thread's park-token id; any non-zero is fine.
            f2.private_wait(ADDR, 0, 1, Some(Duration::from_secs(5)), &|| false)
        });
        // Give the waiter time to park, then wake exactly one waiter.
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

    /// PRIVATE path: with no waker, `private_wait` returns `TimedOut` once its
    /// timeout elapses (delegation of the `FutexTable` timeout path).
    #[test]
    fn private_wait_times_out() {
        let futex = KvmFutex(Arc::new(FutexTable::new()));
        let outcome = futex.private_wait(
            0x5000,
            0,
            1,
            Some(Duration::from_millis(50)),
            &never_interrupted(),
        );
        assert_eq!(
            outcome,
            FutexOutcome::TimedOut,
            "private_wait with no waker must time out"
        );
    }

    /// PRIVATE path: a pending interrupt terminates `private_wait` with
    /// `Interrupted` (the `interrupted()` predicate the loop uses to surface a
    /// pending signal / fork quiesce).
    #[test]
    fn private_wait_interrupted() {
        let futex = KvmFutex(Arc::new(FutexTable::new()));
        let outcome = futex.private_wait(0x6000, 0, 1, Some(Duration::from_secs(5)), &|| true);
        assert_eq!(
            outcome,
            FutexOutcome::Interrupted,
            "private_wait must report Interrupted when the predicate is set"
        );
    }

    /// Allocate one `MAP_SHARED|MAP_ANONYMOUS` page (the same flags the KVM
    /// shared aperture uses) and return the host address of its first word. The
    /// page leaks for the test process's life (fine for a unit test).
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

    /// SHARED path: thread A `shared_wait(addr, expected)` blocks on the host
    /// `SYS_futex`; thread B stores a new value + `shared_wake(addr, 1)` → A
    /// returns `0` (woken). This is the cross-THREAD analogue of the
    /// cross-PROCESS rendezvous; both use the identical bare `SYS_futex` path, so
    /// the wake-reaches-waiter mechanism is what this asserts.
    #[test]
    fn shared_wait_woken_by_shared_wake() {
        let word = shared_word() as usize;
        // SAFETY: `word` is our mapped AtomicU32.
        let atom = unsafe { &*(word as *const AtomicU32) };
        atom.store(0, Ordering::SeqCst);

        let futex = Arc::new(KvmFutex(Arc::new(FutexTable::new())));
        let f2 = Arc::clone(&futex);
        let waiter = thread::spawn(move || {
            // Wait while *word == 0, with a generous timeout so a missed wake
            // still terminates the test (it would then return -ETIMEDOUT, failing
            // the assert below rather than hanging).
            f2.shared_wait(word, 0, Some(Duration::from_secs(5)), &|| false)
        });
        // Let the waiter block in FUTEX_WAIT, then change the word and wake it.
        thread::sleep(Duration::from_millis(50));
        atom.store(1, Ordering::SeqCst);
        let woke = futex.shared_wake(word, 1);
        assert_eq!(woke, 1, "shared_wake must report one waiter woken");
        let r = waiter.join().expect("shared waiter join");
        assert_eq!(r, 0, "shared_wait must return 0 (woken) after shared_wake");
    }

    /// SHARED path value-mismatch: if `*word != value` at entry, the kernel
    /// `FUTEX_WAIT` returns EAGAIN immediately and `shared_wait` maps that to a
    /// `0` (no blocking) so the guest re-reads + re-evaluates. The wait must
    /// return promptly (well under its 5 s timeout).
    #[test]
    fn shared_wait_value_mismatch_returns_immediately() {
        let word = shared_word() as usize;
        let atom = unsafe { &*(word as *const AtomicU32) };
        atom.store(42, Ordering::SeqCst);

        let futex = KvmFutex(Arc::new(FutexTable::new()));
        let start = std::time::Instant::now();
        // Expected value 0, but the word holds 42 → immediate EAGAIN → 0.
        let r = futex.shared_wait(word, 0, Some(Duration::from_secs(5)), &never_interrupted());
        let elapsed = start.elapsed();
        assert_eq!(r, 0, "value-mismatch shared_wait must return 0 (no block)");
        assert!(
            elapsed < Duration::from_secs(1),
            "value-mismatch shared_wait must return promptly, took {elapsed:?}"
        );
    }

    /// SHARED path timeout: with the word matching `value` and no waker, the
    /// sliced loop runs out the deadline and returns `-ETIMEDOUT`.
    #[test]
    fn shared_wait_times_out() {
        let word = shared_word() as usize;
        let atom = unsafe { &*(word as *const AtomicU32) };
        atom.store(7, Ordering::SeqCst);

        let futex = KvmFutex(Arc::new(FutexTable::new()));
        // Word matches `value` (7) so FUTEX_WAIT blocks; no waker → the ≤20 ms
        // slices accumulate until the 120 ms deadline → -ETIMEDOUT.
        let r = futex.shared_wait(
            word,
            7,
            Some(Duration::from_millis(120)),
            &never_interrupted(),
        );
        assert_eq!(
            r,
            -i64::from(LINUX_ETIMEDOUT),
            "shared_wait with no waker must time out with -ETIMEDOUT"
        );
    }

    /// SHARED path interrupt: a pending `interrupted()` terminates `shared_wait`
    /// with `-EINTR` before it blocks (the loop checks the predicate at the top).
    #[test]
    fn shared_wait_interrupted_returns_eintr() {
        let word = shared_word() as usize;
        let atom = unsafe { &*(word as *const AtomicU32) };
        atom.store(0, Ordering::SeqCst);

        let futex = KvmFutex(Arc::new(FutexTable::new()));
        let r = futex.shared_wait(word, 0, Some(Duration::from_secs(5)), &|| true);
        assert_eq!(
            r,
            -i64::from(LINUX_EINTR),
            "shared_wait must return -EINTR when the predicate is set"
        );
    }

    /// SHARED path wake with no waiter: `shared_wake` returns 0 (the kernel
    /// `FUTEX_WAKE` woke nobody) — not an error.
    #[test]
    fn shared_wake_no_waiter_returns_zero() {
        let word = shared_word() as usize;
        let futex = KvmFutex(Arc::new(FutexTable::new()));
        let woke = futex.shared_wake(word, 1);
        assert_eq!(woke, 0, "shared_wake with no waiter must return 0");
    }
}
