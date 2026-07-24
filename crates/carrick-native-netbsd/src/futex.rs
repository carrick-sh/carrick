//! NetBSD-only cross-process shared-futex primitive for the native (DSR)
//! backend.
//!
//! The NetBSD peer of `carrick-native-freebsd::futex`, exposing the same 4-fn
//! symmetric API the shared x86 run loop (`native_freebsd.rs`) calls for the
//! `SharedFutexWait{,v}` / `SharedFutexWake` / `SharedFutexRequeue` dispatch
//! outcomes. It is MUCH simpler than the FreeBSD peer: FreeBSD's
//! `_umtx_op(UMTX_OP_WAKE)` returns 0 rather than the woken count and cannot
//! atomically requeue, so that lane carries a fork-shared waiter-count side
//! table + logical-requeue machinery. NetBSD's `__futex(2)` is deliberately
//! "ABI-compatible with the Linux futex(2) system call" (`/usr/include/
//! sys/futex.h`): `FUTEX_WAKE` returns the woken count and `FUTEX_(CMP_)REQUEUE`
//! relink queues natively, and (grounding doc §3, verified on NetBSD 10.1) a
//! `MAP_SHARED` word wakes across `fork` in both directions. So there is NO
//! waiter table — every op operates directly on the shared guest word.
//!
//! ## `__futex(2)` ABI (clean-room, from the box headers)
//!
//! - `SYS___futex = 166` (`/usr/include/sys/syscall.h:471`).
//! - Ops (`/usr/include/sys/futex.h`): `FUTEX_WAIT = 0` (:75),
//!   `FUTEX_WAKE = 1` (:76), `FUTEX_REQUEUE = 3` (:78),
//!   `FUTEX_CMP_REQUEUE = 4` (:79).
//! - The kernel entry is
//!   `do_futex(int *uaddr, int op, int val, const struct timespec *timeout,
//!   int *uaddr2, int val2, int val3, register_t *retval)`
//!   (`/usr/include/sys/futex.h:178`). Unlike Linux — which OVERLOADS the
//!   `timeout` slot as `val2` for requeue ops — NetBSD's `do_futex` types the
//!   4th argument as a `struct timespec *` and carries the requeue count in the
//!   SEPARATE 6th `val2` argument, with the compare value in the 7th `val3`.
//!   The raw userland stub is the 7-arg
//!   `syscall(166, uaddr, op, val, timeout, uaddr2, val2, val3)` (the same form
//!   `carrick-host/src/netbsd_futex.rs` already uses for wait/wake).

use std::time::Duration;

use carrick_abi::{LINUX_EAGAIN, LINUX_EINTR, LINUX_ETIMEDOUT};

// `__futex(2)` numbers, defined locally with header citations (clean-room; the
// `libc` crate does not guarantee the requeue ops on this target). See the
// module doc for the header lines.
// NetBSD's `libc::syscall` is `fn(num: c_int, ...) -> c_int` (not `c_long` like
// the other supported hosts), so the syscall number is a `c_int` and every
// `__futex` return below is a `c_int` folded to `i64`/`u32` at the boundary.
const SYS___FUTEX: libc::c_int = 166; // /usr/include/sys/syscall.h:471
const FUTEX_WAIT: libc::c_int = 0; // /usr/include/sys/futex.h:75
const FUTEX_WAKE: libc::c_int = 1; // /usr/include/sys/futex.h:76
const FUTEX_REQUEUE: libc::c_int = 3; // /usr/include/sys/futex.h:78
const FUTEX_CMP_REQUEUE: libc::c_int = 4; // /usr/include/sys/futex.h:79

/// No-op on NetBSD. FreeBSD allocates a fork-shared waiter-count table pre-fork
/// (to reconstruct a woken count its `_umtx_op` does not report); NetBSD's
/// `__futex` returns the count natively and requeues atomically, so no table is
/// needed (grounding doc §3). Kept for API symmetry with the FreeBSD peer so
/// the shared run loop's pre-fork setup call site is lane-neutral.
pub fn init_shared_waiter_table() {}

/// Cross-process shared-futex WAIT via `__futex(FUTEX_WAIT)`. `word` is a live
/// host address of the 4-byte futex word; the kernel re-checks `*word == value`
/// atomically before parking (closing the set-then-wake race with a peer
/// process), then blocks until a [`shared_wake`] on the same shared object wakes
/// it, the relative `timeout` elapses, or a signal interrupts. `waiter_key` is
/// unused (NetBSD keys shared futexes by their backing object). Returns the
/// Linux `FUTEX_WAIT` retval: `0` (woken), `-EAGAIN` (value mismatch),
/// `-ETIMEDOUT`, or `-EINTR` — matching the FreeBSD peer's convention.
///
/// Like the FreeBSD peer this parks ONCE with the full relative timeout;
/// `interrupted()` is a fast-path pre-check, and mid-park cancellation comes
/// from the run loop's non-restarting kick signal, which returns `EINTR`.
pub fn shared_wait(
    word: usize,
    _waiter_key: usize,
    value: u32,
    timeout: Option<Duration>,
    interrupted: &dyn Fn() -> bool,
) -> i64 {
    if interrupted() {
        return LINUX_EINTR.guest_retval();
    }
    let ts = match timeout {
        Some(duration) => {
            if duration.is_zero() {
                return LINUX_ETIMEDOUT.guest_retval();
            }
            // `__futex(FUTEX_WAIT)` reads a RELATIVE timeout (Linux semantics,
            // no `FUTEX_CLOCK_REALTIME`), so the guest's requested duration maps
            // straight through.
            Some(libc::timespec {
                tv_sec: duration.as_secs() as libc::time_t,
                tv_nsec: duration.subsec_nanos() as libc::c_long,
            })
        }
        None => None,
    };
    let timeout_ptr = ts
        .as_ref()
        .map_or(std::ptr::null(), |t| t as *const libc::timespec);
    // SAFETY: `word` is an identity host VA of a guest-mapped, 4-byte-aligned
    // shared futex word; `__futex(FUTEX_WAIT)` only reads it plus the optional
    // relative timeout.
    let rc = unsafe {
        libc::syscall(
            SYS___FUTEX,
            word as *mut libc::c_int,
            FUTEX_WAIT,
            value as libc::c_int,
            timeout_ptr,
            std::ptr::null_mut::<libc::c_int>(),
            0 as libc::c_int,
            0 as libc::c_int,
        )
    } as libc::c_long;
    if rc >= 0 {
        return 0;
    }
    match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) {
        libc::ETIMEDOUT => LINUX_ETIMEDOUT.guest_retval(),
        libc::EINTR => LINUX_EINTR.guest_retval(),
        // `*word != value` at entry (a peer already advanced it): Linux returns
        // EAGAIN and the guest retry loop re-reads the word.
        libc::EAGAIN => LINUX_EAGAIN.guest_retval(),
        _ => LINUX_EAGAIN.guest_retval(),
    }
}

/// Cross-process shared-futex WAKE via `__futex(FUTEX_WAKE)`: wake up to `count`
/// waiters parked (possibly in another forked process) on `word`, and return
/// how many were woken — the Linux `FUTEX_WAKE` retval. NetBSD returns that
/// count natively (unlike FreeBSD's `_umtx_op`, which is why the FreeBSD peer
/// needs a side table). Zero parked yields 0. `waiter_key` is unused.
pub fn shared_wake(word: usize, _waiter_key: usize, count: u32) -> i64 {
    let n = count.min(i32::MAX as u32) as libc::c_int;
    // SAFETY: `__futex(FUTEX_WAKE)` against a live shared host word; it neither
    // reads nor writes the word's contents.
    let rc = unsafe {
        libc::syscall(
            SYS___FUTEX,
            word as *mut libc::c_int,
            FUTEX_WAKE,
            n,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null_mut::<libc::c_int>(),
            0 as libc::c_int,
            0 as libc::c_int,
        )
    } as libc::c_long;
    // A valid shared word does not error; fold any `-errno` to 0 woken so a
    // stray failure never surfaces a negative "count" to the guest.
    if rc < 0 { 0 } else { rc as i64 }
}

/// Implement Linux `FUTEX_(CMP_)REQUEUE` across shared words via NetBSD's native
/// `__futex(FUTEX_CMP_REQUEUE)` — wake up to `wake_count` waiters on `from_word`
/// and relink up to `requeue_count` of the rest onto the destination word.
///
/// **Address mapping (studied against the FreeBSD peer).** `from_word` is the
/// source futex word address (`uaddr`). The destination word address (`uaddr2`)
/// is `to_key`: FreeBSD receives `to_key` as a side-table key only (its umtx
/// cannot relink queues, so it never hands the kernel a destination address),
/// but on NetBSD `NetbsdHost` does NOT override `shared_futex_waiter_key`, so
/// the identity model sets `waiter_key == host_addr` (identity_memory:
/// `shared_futex_waiter_key(addr).unwrap_or(addr)`) — i.e. `to_key` IS the
/// destination host word address, usable directly as `uaddr2`. `from_key` is
/// unused for the same reason.
///
/// **Compare value.** The dispatcher already performed the guest's
/// `FUTEX_CMP_REQUEUE` `*uaddr == val3` gate before emitting this outcome
/// (`dispatch`: `word != val3 -> EAGAIN`), so re-reading the current word for
/// `val3` here all but always matches; on the rare intervening write the kernel
/// returns `EAGAIN` and we fall back to the compare-free `FUTEX_REQUEUE`, so a
/// `pthread_cond_broadcast` never loses a waiter to a value race.
///
/// Returns `(total, 0)`: NetBSD's requeue is atomic and reports the Linux total
/// (woken + requeued) in one value; the run loop reports `woken + moved` to the
/// guest, so the split is not observable and the second element is 0.
pub fn shared_requeue(
    from_word: usize,
    _from_key: usize,
    to_key: usize,
    wake_count: u32,
    requeue_count: u32,
) -> (u32, u32) {
    let uaddr = from_word as *mut libc::c_int;
    // `to_key` == destination host word address on NetBSD (see the doc above).
    let uaddr2 = to_key as *mut libc::c_int;
    let wake = wake_count.min(i32::MAX as u32) as libc::c_int;
    let requeue = requeue_count.min(i32::MAX as u32) as libc::c_int;
    // SAFETY: `from_word` is a live 4-byte-aligned identity host futex word.
    let val3 = unsafe { (from_word as *const u32).read_volatile() } as libc::c_int;

    // SAFETY: `uaddr`/`uaddr2` are live identity host futex words. NetBSD carries
    // the requeue count in `val2` (6th arg) and the compare value in `val3` (7th
    // arg); the `timeout` slot is ignored for requeue ops (see the module doc's
    // `do_futex` signature). The op neither reads nor writes the words' contents
    // beyond the atomic `*uaddr == val3` compare.
    let rc = unsafe {
        libc::syscall(
            SYS___FUTEX,
            uaddr,
            FUTEX_CMP_REQUEUE,
            wake,
            std::ptr::null::<libc::timespec>(),
            uaddr2,
            requeue,
            val3,
        )
    } as libc::c_long;
    let total = if rc >= 0 {
        rc
    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
        // The word raced between the dispatcher's gate and our re-read: retry
        // without the comparison (the guest's semantic gate already passed).
        // SAFETY: as above; `FUTEX_REQUEUE` ignores `val3`.
        let rc = unsafe {
            libc::syscall(
                SYS___FUTEX,
                uaddr,
                FUTEX_REQUEUE,
                wake,
                std::ptr::null::<libc::timespec>(),
                uaddr2,
                requeue,
                0 as libc::c_int,
            )
        } as libc::c_long;
        rc.max(0)
    } else {
        0
    };
    (u32::try_from(total).unwrap_or(0), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Map one `MAP_SHARED | MAP_ANON` page so a fork parent and child share it
    /// (grounding doc §3: anon-shared cross-process wake works on NetBSD 10.1).
    fn map_shared_word() -> *mut u32 {
        // SAFETY: a fresh kernel-chosen shared anonymous page.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "map shared word page");
        p.cast::<u32>()
    }

    /// Cross-process wait/wake: the parent parks on a shared word via
    /// `shared_wait`; a fork child `shared_wake`s it and asserts the woken COUNT
    /// is exactly 1 (the decisive NetBSD divergence from FreeBSD — a native
    /// woken count, no waiter table). Mirrors the intent of the FreeBSD peer's
    /// futex tests, and a standalone box probe that confirmed anon-`MAP_SHARED`
    /// cross-process wake on NetBSD 10.1.
    ///
    /// Two words share one anonymous `MAP_SHARED` page: `ready` lets the child
    /// observe that the parent is about to park (so it never wakes before there
    /// is a waiter — the classic pre-park race), and `futex` is the wait word.
    /// `futex` is never mutated, so a `shared_wait` return of 0 is a genuine
    /// cross-process wake, not a value-mismatch EAGAIN. The child retries the
    /// wake while the parent re-parks so a scheduling hiccup cannot lose it.
    #[test]
    fn cross_process_wait_wake_reports_woken_count() {
        let page = map_shared_word();
        // `ready` at offset 0, `futex` at offset 4 (both 4-byte, non-overlapping).
        let ready = page;
        // SAFETY: `page` is a 4096-byte shared mapping; offset-1 u32 is in bounds.
        let futex = unsafe { page.add(1) };
        // SAFETY: the test owns this writable shared page.
        unsafe {
            ready.write_volatile(0);
            futex.write_volatile(0);
        }
        let ready_addr = ready as usize;
        let futex_addr = futex as usize;

        // SAFETY: the child does only async-signal-safe work (shared reads, a raw
        // futex syscall, usleep) before `_exit`; it never unwinds or allocates.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // Wait until the parent published readiness, give it a moment to
            // reach FUTEX_WAIT, then wake exactly one waiter (retrying while the
            // parent re-parks).
            while unsafe { (ready_addr as *const u32).read_volatile() } == 0 {
                unsafe { libc::usleep(1_000) };
            }
            unsafe { libc::usleep(50_000) };
            let mut n = 0i64;
            for _ in 0..200 {
                n = shared_wake(futex_addr, 0, 1);
                if n >= 1 {
                    break;
                }
                unsafe { libc::usleep(10_000) };
            }
            unsafe { libc::_exit(if n == 1 { 0 } else { 21 }) };
        }

        // Publish readiness, then park until the child's cross-process wake
        // releases us, re-parking across the bounded per-call timeout. Bounded
        // by a wall deadline so a lost wake fails the test instead of hanging.
        unsafe { ready.write_volatile(1) };
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut woken = false;
        while std::time::Instant::now() < deadline {
            let ret = shared_wait(futex_addr, 0, 0, Some(Duration::from_millis(100)), &|| {
                false
            });
            if ret == 0 {
                woken = true;
                break;
            }
        }

        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "reap child");
        assert!(
            libc::WIFEXITED(status),
            "child exited normally: {status:#x}"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child's shared_wake must report exactly 1 woken waiter (exit 21 = it did not)"
        );
        assert!(
            woken,
            "parent must be released by the child's cross-process wake"
        );

        unsafe { libc::munmap(page.cast(), 4096) };
    }

    /// `shared_wake` on a word nobody is parked on returns 0 (Linux `FUTEX_WAKE`
    /// on an empty queue), never a negative errno.
    #[test]
    fn wake_with_no_waiter_returns_zero() {
        let word = map_shared_word();
        unsafe { word.write_volatile(0) };
        assert_eq!(shared_wake(word as usize, 0, 1), 0, "no waiter => 0 woken");
        unsafe { libc::munmap(word.cast(), 4096) };
    }

    /// A relative timeout that has already elapsed (zero duration) returns
    /// `-ETIMEDOUT` without entering the kernel.
    #[test]
    fn zero_timeout_wait_times_out() {
        let word = map_shared_word();
        unsafe { word.write_volatile(7) };
        assert_eq!(
            shared_wait(word as usize, 0, 7, Some(Duration::ZERO), &|| false),
            LINUX_ETIMEDOUT.guest_retval(),
        );
        unsafe { libc::munmap(word.cast(), 4096) };
    }

    /// `shared_wait` returns `-EAGAIN` immediately when the word does not hold
    /// the expected value (a peer already advanced it).
    #[test]
    fn wait_value_mismatch_returns_eagain() {
        let word = map_shared_word();
        unsafe { word.write_volatile(9) };
        assert_eq!(
            shared_wait(
                word as usize,
                0,
                1, // expected 1, actual 9
                Some(Duration::from_millis(100)),
                &|| false,
            ),
            LINUX_EAGAIN.guest_retval(),
        );
        unsafe { libc::munmap(word.cast(), 4096) };
    }
}
