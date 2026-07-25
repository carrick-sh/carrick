//! This lane's `carrick_hal::PlatformFutex`.
//!
//! [`crate::futex`] is the FreeBSD cross-process futex primitive; the aarch64
//! run loop, however, does not call it directly — it consumes
//! `Arc<dyn carrick_hal::PlatformFutex>` (`native_darwin.rs`'s
//! `NativeThreadRuntime::platform_futex`), and until this module existed NO
//! type implemented that trait over the BSD primitives at all (the aarch64
//! lane scout's V4: `grep 'impl .*PlatformFutex for'` found only test doubles).
//! This is the adapter that closes that gap — the FreeBSD half of the scout's
//! task T2.
//!
//! It is deliberately NOT the shape the VMM lanes use. `carrick-vmm-bhyve`'s
//! `BhyveSharedFutex` plugs `carrick_host::umtx` into the sliced
//! [`carrick_thread::platform_futex::SharedFutexSyscall`] seam, and that seam
//! reconstructs a woken count from a `SharedFutexLocation::Mirror`'s explicit
//! `waiter_count` field — which the native lane never produces
//! (`carrick-dsr-aarch64`'s `mapped_memory::shared_futex_location` and
//! `carrick-dsr`'s `identity_memory` both return `Direct`, whose
//! `waiter_count_addr()` is `None`). Routing this lane through the VMM shim
//! would therefore report ZERO woken for every cross-process `FUTEX_WAKE` and
//! lose requeue entirely. So the lane keeps its own module — with the
//! fork-shared waiter table that reconstructs what `_umtx_op` does not report
//! — behind [`carrick_thread::platform_futex::NativeSharedFutex`], the
//! whole-wait sibling seam. See that trait's doc for why slicing this module
//! would break it.
//!
//! Arch-neutral on purpose: [`crate::futex`] has zero `target_arch` and this
//! adapter adds none, so the x86_64 native lane can adopt it when its run loop
//! merges with the aarch64 one (seams-design Phase 2) instead of keeping a
//! second call path.

use std::sync::Arc;
use std::time::Duration;

use carrick_thread::platform_futex::{FutexTableNativeFutex, NativeSharedFutex};
use carrick_thread::thread::FutexTable;

/// FreeBSD's cross-process futex: `_umtx_op(2)` plus the fork-shared
/// waiter-count table that reconstructs the woken count and the logical
/// requeue the native umtx ABI does not provide.
pub struct FreebsdSharedFutex;

impl NativeSharedFutex for FreebsdSharedFutex {
    fn shared_wait(
        &self,
        word: usize,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> i64 {
        crate::futex::shared_wait(word, waiter_key, value, timeout, interrupted)
    }

    fn shared_wake(&self, word: usize, waiter_key: usize, count: u32) -> i64 {
        crate::futex::shared_wake(word, waiter_key, count)
    }

    fn shared_requeue(
        &self,
        from_word: usize,
        from_key: usize,
        to_key: usize,
        wake: u32,
        requeue: u32,
    ) -> (u32, u32) {
        crate::futex::shared_requeue(from_word, from_key, to_key, wake, requeue)
    }

    /// The waiter table MUST be mapped before the first guest `fork`, or a
    /// descendant maps a different table and cross-process wake counts go
    /// silently wrong. `FutexTableNativeFutex::new` calls this at
    /// construction, which every lane reaches before it forks; the call is
    /// idempotent.
    fn init_shared_state(&self) {
        crate::futex::init_shared_waiter_table();
    }
}

/// The FreeBSD native lane's `PlatformFutex`: the shared process-private
/// `FutexTable` paired with [`FreebsdSharedFutex`].
pub type FreebsdNativeFutex = FutexTableNativeFutex<FreebsdSharedFutex>;

/// Pair the process-private futex table with this lane's cross-process futex.
/// Mirrors `carrick_vmm_bhyve::make_bhyve_futex` in shape so the runtime's
/// lane wiring reads the same on every backend.
pub fn make_freebsd_native_futex(table: Arc<FutexTable>) -> FreebsdNativeFutex {
    FutexTableNativeFutex::new(table, FreebsdSharedFutex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::{PlatformFutex, SharedFutexLocation};

    /// One `MAP_SHARED | MAP_ANON` page: the shape a guest `MAP_SHARED` futex
    /// word has on this lane (fork-inherited, identical host VA in every
    /// process), which is what `shared_futex_location` keys as `Direct`.
    fn shared_word_page() -> *mut u32 {
        // SAFETY: a fresh kernel-chosen shared anonymous page.
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED, "map shared futex page");
        page.cast::<u32>()
    }

    fn direct(word: *mut u32) -> SharedFutexLocation {
        SharedFutexLocation::Direct {
            word: carrick_hal::HostVa(word as usize),
            waiter_key: word as usize,
        }
    }

    /// A value mismatch at entry must NOT park — the kernel re-checks
    /// `*word == value` before it queues the waiter, which is what closes the
    /// classic set-then-wake race with a peer process. With no timeout and no
    /// waker, a parking bug here would hang the test rather than fail it.
    ///
    /// MEASURED DIVERGENCE (freebsd-arm64, and a property of `_umtx_op`, not of
    /// this adapter — the x86 native lane has always behaved this way):
    /// `_umtx_op(UMTX_OP_WAIT_UINT)` reports a mismatch as **success**, so this
    /// lane returns `0` (a spurious wake the guest re-checks) where Linux
    /// returns `-EAGAIN`. Pinned rather than papered over so the divergence is
    /// visible to whoever decides whether to close it; the NetBSD peer's
    /// `__futex` returns `-EAGAIN` like Linux.
    #[test]
    fn shared_wait_value_mismatch_does_not_park() {
        let word = shared_word_page();
        // SAFETY: the test owns this writable shared page.
        unsafe { word.write_volatile(0) };
        let futex = make_freebsd_native_futex(Arc::new(FutexTable::new()));

        assert_eq!(
            futex.shared_wait(direct(word), word as usize, 1, None, &|| false, &|| {}),
            0,
            "`_umtx_op` reports an entry mismatch as success; the guest re-checks"
        );
        // SAFETY: our own mapping, no other reference to it.
        unsafe { libc::munmap(word.cast(), 4096) };
    }

    /// An already-expired deadline returns Linux `-ETIMEDOUT` without parking.
    #[test]
    fn shared_wait_with_an_expired_timeout_is_etimedout() {
        let word = shared_word_page();
        // SAFETY: the test owns this writable shared page.
        unsafe { word.write_volatile(0) };
        let futex = make_freebsd_native_futex(Arc::new(FutexTable::new()));

        assert_eq!(
            futex.shared_wait(
                direct(word),
                word as usize,
                0,
                Some(Duration::ZERO),
                &|| false,
                &|| {}
            ),
            carrick_abi::LINUX_ETIMEDOUT.guest_retval(),
        );
        // SAFETY: our own mapping, no other reference to it.
        unsafe { libc::munmap(word.cast(), 4096) };
    }

    /// The interrupt predicate is a pre-park fast path: it must reach the host
    /// module and surface Linux `-EINTR` rather than being swallowed by the
    /// seam (the aarch64 loop re-checks quiesce/exit state on exactly this).
    #[test]
    fn shared_wait_honours_the_interrupt_predicate() {
        let word = shared_word_page();
        // SAFETY: the test owns this writable shared page.
        unsafe { word.write_volatile(0) };
        let futex = make_freebsd_native_futex(Arc::new(FutexTable::new()));

        assert_eq!(
            futex.shared_wait(direct(word), word as usize, 0, None, &|| true, &|| {}),
            carrick_abi::LINUX_EINTR.guest_retval(),
        );
        // SAFETY: our own mapping, no other reference to it.
        unsafe { libc::munmap(word.cast(), 4096) };
    }

    /// A wake on a word nothing is parked on reports 0 — Linux's answer, and
    /// the one the waiter table (not `_umtx_op`, which always returns 0 on
    /// success) is there to produce. Also proves the constructor mapped that
    /// table: without it `shared_wake` returns 0 for a DIFFERENT reason, so
    /// the parked case below is what makes this meaningful.
    #[test]
    fn shared_wake_with_no_waiters_is_zero() {
        let word = shared_word_page();
        let futex = make_freebsd_native_futex(Arc::new(FutexTable::new()));
        assert_eq!(futex.shared_wake(direct(word), word as usize, 1), 0);
        // SAFETY: our own mapping, no other reference to it.
        unsafe { libc::munmap(word.cast(), 4096) };
    }

    /// End-to-end through the adapter, across a REAL fork: the parent parks in
    /// `PlatformFutex::shared_wait`, the child wakes it through
    /// `PlatformFutex::shared_wake` and observes the Linux-faithful woken count
    /// of exactly 1 — the number `_umtx_op` itself never reports, reconstructed
    /// from the fork-shared waiter table that `make_freebsd_native_futex`
    /// mapped pre-fork.
    ///
    /// `ready` (offset 0) lets the child see that the parent is about to park
    /// before it wakes; `futex` (offset 1) is the wait word and is never
    /// mutated, so a `shared_wait` return of 0 is a genuine cross-process wake
    /// rather than a value-mismatch EAGAIN. The child retries while the parent
    /// re-parks so a scheduling hiccup cannot lose the wake.
    #[test]
    fn cross_process_wake_through_the_adapter_reports_one() {
        let page = shared_word_page();
        let ready = page;
        // SAFETY: `page` is a 4096-byte shared mapping; the offset-1 u32 is in
        // bounds.
        let word = unsafe { page.add(1) };
        // SAFETY: the test owns this writable shared page.
        unsafe {
            ready.write_volatile(0);
            word.write_volatile(0);
        }
        let futex = make_freebsd_native_futex(Arc::new(FutexTable::new()));

        // SAFETY: the child only reads shared words, calls the futex wake path
        // and `_exit`; it never unwinds or allocates.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: child-side reads of the inherited shared page.
            while unsafe { ready.read_volatile() } == 0 {
                // SAFETY: plain nanosleep, async-signal-safe.
                unsafe { libc::usleep(1_000) };
            }
            let mut woke = 0;
            for _ in 0..2_000 {
                // SAFETY: plain nanosleep, async-signal-safe.
                unsafe { libc::usleep(1_000) };
                woke = futex.shared_wake(direct(word), word as usize, 1);
                if woke > 0 {
                    break;
                }
            }
            // SAFETY: immediate child exit, no atexit/unwinding.
            unsafe { libc::_exit(if woke == 1 { 0 } else { 1 }) };
        }

        // SAFETY: parent-side store on the shared page.
        unsafe { ready.write_volatile(1) };
        let retval = futex.shared_wait(
            direct(word),
            word as usize,
            0,
            Some(Duration::from_secs(20)),
            &|| false,
            &|| {},
        );
        assert_eq!(
            retval, 0,
            "the parent must return from a real cross-process wake"
        );

        let mut status = 0;
        // SAFETY: reaping our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the child's wake must report exactly 1 woken (status {status:#x})"
        );
        // SAFETY: our own mapping, no other reference to it.
        unsafe { libc::munmap(page.cast(), 4096) };
    }
}
