//! This lane's `carrick_hal::PlatformFutex`.
//!
//! [`crate::futex`] is the NetBSD cross-process futex primitive; the aarch64
//! run loop, however, does not call it directly — it consumes
//! `Arc<dyn carrick_hal::PlatformFutex>` (`native_darwin.rs`'s
//! `NativeThreadRuntime::platform_futex`), and until this module existed NO
//! type implemented that trait over the BSD primitives at all (the aarch64
//! lane scout's V4: `grep 'impl .*PlatformFutex for'` found only test doubles).
//! This is the NetBSD half of the scout's task T2.
//!
//! It is deliberately NOT the shape the VMM lanes use. `carrick-vmm-nvmm`'s
//! `NvmmSharedFutex` plugs `carrick_host::netbsd_futex` into the sliced
//! [`carrick_thread::platform_futex::SharedFutexSyscall`] seam, whose
//! `SharedFutexSyscall::requeue` default is `(0, 0)` — i.e. no requeue at all.
//! This lane instead keeps [`crate::futex`], which uses NetBSD's NATIVE
//! `__futex(FUTEX_CMP_REQUEUE)`, behind
//! [`carrick_thread::platform_futex::NativeSharedFutex`], the whole-wait
//! sibling seam.
//!
//! The FreeBSD peer's adapter wraps a module carrying a fork-shared
//! waiter-count table and a logical requeue, because `_umtx_op` reports
//! neither a woken count nor an atomic requeue. **NetBSD needs none of that**:
//! `__futex(2)` is deliberately Linux-shaped, so `FUTEX_WAKE` returns the
//! woken count and `FUTEX_(CMP_)REQUEUE` relinks queues in the kernel. The two
//! adapters are therefore the same 4 delegations over deliberately different
//! modules, and [`NetbsdSharedFutex::init_shared_state`] is a no-op where
//! FreeBSD's maps a table.
//!
//! Arch-neutral on purpose: [`crate::futex`] has zero `target_arch` and this
//! adapter adds none, so the x86_64 native lane can adopt it when its run loop
//! merges with the aarch64 one (seams-design Phase 2) instead of keeping a
//! second call path.

use std::sync::Arc;
use std::time::Duration;

use carrick_thread::platform_futex::{FutexTableNativeFutex, NativeSharedFutex};
use carrick_thread::thread::FutexTable;

/// NetBSD's cross-process futex: `__futex(2)`, which is ABI-compatible with
/// Linux `futex(2)` — a native woken count and a native `CMP_REQUEUE`, no
/// waiter table.
pub struct NetbsdSharedFutex;

impl NativeSharedFutex for NetbsdSharedFutex {
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

    /// Nothing to allocate: NetBSD keys shared futexes by their backing uvm
    /// object, so there is no fork-shared side table to map pre-fork. Kept
    /// explicit (rather than inherited from the trait default) so the
    /// divergence from the FreeBSD peer is visible at the seam.
    fn init_shared_state(&self) {
        crate::futex::init_shared_waiter_table();
    }
}

/// The NetBSD native lane's `PlatformFutex`: the shared process-private
/// `FutexTable` paired with [`NetbsdSharedFutex`].
pub type NetbsdNativeFutex = FutexTableNativeFutex<NetbsdSharedFutex>;

/// Pair the process-private futex table with this lane's cross-process futex.
/// Mirrors `carrick_vmm_nvmm::make_nvmm_futex` in shape so the runtime's lane
/// wiring reads the same on every backend.
pub fn make_netbsd_native_futex(table: Arc<FutexTable>) -> NetbsdNativeFutex {
    FutexTableNativeFutex::new(table, NetbsdSharedFutex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::{PlatformFutex, SharedFutexLocation};

    /// One `MAP_SHARED | MAP_ANON` page: the shape a guest `MAP_SHARED` futex
    /// word has on this lane (fork-inherited, identical host VA in every
    /// process), which is what `shared_futex_location` keys as `Direct`.
    /// NetBSD wakes across `fork` on an anonymous shared page (grounding doc
    /// §3, re-proved by `futex`'s own cross-process test).
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
    /// NetBSD reports the mismatch the way Linux does, `-EAGAIN`, because
    /// `__futex(2)` is deliberately Linux-shaped — the FreeBSD peer's
    /// `_umtx_op` instead reports it as success, and that peer's test pins the
    /// divergence.
    #[test]
    fn shared_wait_value_mismatch_does_not_park() {
        let word = shared_word_page();
        // SAFETY: the test owns this writable shared page.
        unsafe { word.write_volatile(0) };
        let futex = make_netbsd_native_futex(Arc::new(FutexTable::new()));

        assert_eq!(
            futex.shared_wait(direct(word), word as usize, 1, None, &|| false, &|| {}),
            carrick_abi::LINUX_EAGAIN.guest_retval(),
            "a value mismatch at entry must be EAGAIN, and must not park"
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
        let futex = make_netbsd_native_futex(Arc::new(FutexTable::new()));

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
        let futex = make_netbsd_native_futex(Arc::new(FutexTable::new()));

        assert_eq!(
            futex.shared_wait(direct(word), word as usize, 0, None, &|| true, &|| {}),
            carrick_abi::LINUX_EINTR.guest_retval(),
        );
        // SAFETY: our own mapping, no other reference to it.
        unsafe { libc::munmap(word.cast(), 4096) };
    }

    /// A wake on a word nothing is parked on reports 0 — here that is the
    /// KERNEL's own count, not a reconstruction (the divergence from the
    /// FreeBSD peer).
    #[test]
    fn shared_wake_with_no_waiters_is_zero() {
        let word = shared_word_page();
        let futex = make_netbsd_native_futex(Arc::new(FutexTable::new()));
        assert_eq!(futex.shared_wake(direct(word), word as usize, 1), 0);
        // SAFETY: our own mapping, no other reference to it.
        unsafe { libc::munmap(word.cast(), 4096) };
    }

    /// End-to-end through the adapter, across a REAL fork: the parent parks in
    /// `PlatformFutex::shared_wait`, the child wakes it through
    /// `PlatformFutex::shared_wake` and observes a woken count of exactly 1 —
    /// straight from `__futex(FUTEX_WAKE)`.
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
        let futex = make_netbsd_native_futex(Arc::new(FutexTable::new()));

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
