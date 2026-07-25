//! One `PlatformFutex` implementation, parameterized over the host's shared-page
//! futex syscall.
//!
//! Every backend's `PlatformFutex` impl (HVF, KVM, bhyve, NVMM) was the same
//! shape: the PRIVATE (process-anonymous) path is verbatim delegation to the
//! shared parking-lot [`crate::thread::FutexTable`], and only the SHARED (`MAP_SHARED`,
//! cross-process) path differs — by exactly one kernel call:
//!
//!   * macOS  → `os_sync_wait_on_address` / `os_sync_wake_by_address` (`__ulock`)
//!   * FreeBSD → `_umtx_op`
//!   * Linux  → bare `SYS_futex` (no `FUTEX_PRIVATE_FLAG`)
//!   * NetBSD → `__futex`  (a future arm)
//!   * illumos → `lwp_park` (a future arm)
//!
//! So the whole impl is hoisted here ONCE over [`crate::platform_futex::FutexTableFutex`], and each
//! host plugs in only its best shared-page primitive behind the tiny
//! [`crate::platform_futex::SharedFutexSyscall`] shim — NOT a lowest-common-denominator. The shared
//! deadline/slice/interrupt loop is [`carrick_hal::shared_wait_sliced`]; the
//! per-host residue is a ~15-line `SharedFutexSyscall` impl.
//!
//! HVF deliberately keeps its own `HvfFutex` (it layers carrick-trace probes
//! into the wait path); that is a per-host extra, not a divergence the shim must
//! model. KVM and bhyve use `FutexTableFutex` directly.

use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

use carrick_hal::{
    FutexOutcome, HostVa, PlatformFutex, SharedFutexLocation, SharedWaitStep, ThreadId,
    shared_wait_sliced,
};

use crate::thread::{FutexTable, FutexWaitOutcome};

/// The single per-host divergence the generic [`FutexTableFutex`] needs: the
/// host's `MAP_SHARED` (cross-process) futex kernel calls. The deadline/slice/
/// interrupt control around `wait_one_slice` lives in
/// [`carrick_hal::shared_wait_sliced`]; the host supplies only the one kernel
/// wait slice (classified into a [`SharedWaitStep`]) and the wake.
pub trait SharedFutexSyscall: Send + Sync {
    /// One ≤20 ms cross-process wait slice on the shared-page word at
    /// `host_addr`. Return [`SharedWaitStep::Woken`] for a wake or an
    /// at-entry value mismatch (the guest re-checks), [`SharedWaitStep::Retry`]
    /// for a slice timeout / signal nudge (the loop re-checks the deadline +
    /// interrupt), or [`SharedWaitStep::Error`] for any other terminal `-errno`
    /// (in the value space the guest expects).
    fn wait_one_slice(
        &self,
        location: SharedFutexLocation,
        waiter_key: usize,
        val: u32,
        slice_ns: i64,
    ) -> SharedWaitStep;

    /// Wake up to `n` waiters on the shared-page word at `location`. Returns the
    /// count woken (>=0) or `-errno`.
    fn wake(&self, location: SharedFutexLocation, waiter_key: usize, n: u32) -> i64;

    /// Optional once-before-wait hook (default no-op), run once at the top of
    /// [`FutexTableFutex::shared_wait`] before the slice loop. A host can use it
    /// for a pre-wait observability peek at the shared word (HVF emits a
    /// carrick-trace `futex_route` probe here, which is why it previously kept its
    /// own `PlatformFutex` copy — this hook lets it fold onto the shared one).
    fn pre_wait(&self, _location: SharedFutexLocation, _val: u32) {}

    /// Optional logical-wait lifetime hooks. Hosts whose wake primitive does not
    /// return a waiter count can use these to track the full guest FUTEX_WAIT
    /// lifetime rather than a single host wait slice.
    fn wait_start(&self, _waiter_key: usize) {}
    fn wait_start_requeued(&self, waiter_key: usize) -> bool {
        self.wait_start(waiter_key);
        false
    }
    /// `woken` is the guest-visible outcome of the wait being closed (`true`
    /// for FUTEX_WAIT returning 0 — a wake or the slice loop's value
    /// re-check; `false` for ETIMEDOUT/EINTR). Side-table hosts use it to
    /// keep a self-woken waiter claimable by the next wake's count (Linux
    /// keeps such a waiter queued until a FUTEX_WAKE dequeues it).
    fn wait_end(&self, _waiter_key: usize, _woken: bool) {}
    fn wait_end_requeued(
        &self,
        _location: SharedFutexLocation,
        waiter_key: usize,
        _value: u32,
    ) -> bool {
        self.wait_end(waiter_key, false);
        true
    }
    fn try_complete_requeued(&self, _waiter_key: usize) -> bool {
        false
    }
    fn take_requeue(&self, _waiter_key: usize) -> Option<(usize, usize, u32)> {
        None
    }
    fn requeue(
        &self,
        _from: SharedFutexLocation,
        _from_key: usize,
        _to: SharedFutexLocation,
        _to_key: usize,
        _wake: u32,
        _requeue: u32,
    ) -> (u32, u32) {
        (0, 0)
    }
}

/// Classify one cross-process futex wait slice's raw host return into a
/// [`SharedWaitStep`] (the Linux `FUTEX_WAIT` errno ABI guard from
/// [`carrick_hal::classify_wait_slice`]) AND record the silent fold when a
/// non-`{ETIMEDOUT,EINTR}` host errno is swallowed into a spurious wake.
///
/// This is the ONE seam every host shim (HVF `os_sync`, KVM `SYS_futex`, bhyve
/// `_umtx_op`, NVMM futex) routes its raw kernel result through, so the guard AND
/// its observability are single-sourced: the `futex-unexpected-errno` USDT probe
/// fires on every backend, not just HVF. `host_etimedout`/`host_eintr` are passed
/// in because the numeric errno values differ per host OS.
#[inline]
pub fn classify_observed_wait_slice(
    raw: i64,
    host_addr: usize,
    host_etimedout: i32,
    host_eintr: i32,
) -> SharedWaitStep {
    let step = carrick_hal::classify_wait_slice(raw, host_etimedout, host_eintr);
    // A wake is `raw >= 0`; the only way `raw < 0` yields `Woken` is the
    // unexpected-errno guard folding a non-Linux-futex errno into a spurious wake.
    if raw < 0 && matches!(step, SharedWaitStep::Woken) {
        carrick_observability::probes::futex_unexpected_errno(host_addr as u64, (-raw) as i32);
    }
    step
}

/// The one `PlatformFutex` impl: a process-private [`FutexTable`] (the private
/// path, byte-identical across every backend) paired with a host
/// [`SharedFutexSyscall`] (the shared, cross-process path). Replaces the
/// per-backend `KvmFutex`/`BhyveFutex` copies.
pub struct FutexTableFutex<S: SharedFutexSyscall> {
    table: Arc<FutexTable>,
    shared: S,
}

impl<S: SharedFutexSyscall> FutexTableFutex<S> {
    /// Pair a process-private table with the host's shared-page syscall shim.
    pub fn new(table: Arc<FutexTable>, shared: S) -> Self {
        crate::thread::set_current_futex_table(&table);
        Self { table, shared }
    }
}

impl<S: SharedFutexSyscall> PlatformFutex for FutexTableFutex<S> {
    /// Park the calling thread on a private (anonymous) futex. The value-equality
    /// check already ran in the dispatcher before it returned `FutexWait`, so we
    /// do NOT re-check — `prepare_wait` captures the generation, then
    /// `wait_prepared_for_thread` parks under the thread's `ParkToken(tid)` so a
    /// thread-directed signal (tgkill) can wake exactly this parked thread.
    fn private_wait(
        &self,
        addr: u64,
        _val: u32,
        tid: ThreadId,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexOutcome {
        let wait = self.table.prepare_wait(addr);
        match self
            .table
            .wait_prepared_for_thread(wait, timeout, tid, interrupted)
        {
            FutexWaitOutcome::Woken => FutexOutcome::Woken,
            FutexWaitOutcome::TimedOut => FutexOutcome::TimedOut,
            FutexWaitOutcome::Interrupted => FutexOutcome::Interrupted,
        }
    }

    fn private_wake(&self, addr: u64, n: u32) -> u32 {
        self.table.wake(addr, n)
    }

    /// Wait on a `MAP_SHARED` (cross-process) futex. The deadline/slice/interrupt
    /// loop is shared; only the single kernel wait slice + its host-errno
    /// classification is the host's (`SharedFutexSyscall::wait_one_slice`).
    fn shared_wait(
        &self,
        location: SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
        wait_enrolled: &dyn Fn(),
    ) -> i64 {
        let mut location = location;
        let mut waiter_key = waiter_key;
        let mut value = value;
        let mut current_requeued = false;
        loop {
            self.shared.pre_wait(location, value);
            let already_woken = if current_requeued {
                self.shared.wait_start_requeued(waiter_key)
            } else {
                self.shared.wait_start(waiter_key);
                false
            };
            wait_enrolled();
            if already_woken {
                return 0;
            }
            let completed_requeued = Cell::new(false);
            let ret = shared_wait_sliced(timeout, interrupted, &|slice_ns| {
                if current_requeued && self.shared.try_complete_requeued(waiter_key) {
                    completed_requeued.set(true);
                    return SharedWaitStep::Woken;
                }
                self.shared
                    .wait_one_slice(location, waiter_key, value, slice_ns)
            });
            if current_requeued {
                if completed_requeued.get() {
                    return 0;
                }
                let complete = self.shared.wait_end_requeued(location, waiter_key, value);
                if complete {
                    return 0;
                }
                if ret == 0 {
                    continue;
                }
                return ret;
            }
            self.shared.wait_end(waiter_key, ret == 0);
            if ret != 0 {
                return ret;
            }
            let Some((next_host, next_key, next_value)) = self.shared.take_requeue(waiter_key)
            else {
                return ret;
            };
            location = SharedFutexLocation::Direct {
                word: HostVa(next_host),
                waiter_key: next_key,
            };
            waiter_key = next_key;
            value = next_value;
            current_requeued = true;
        }
    }

    fn shared_wake(&self, location: SharedFutexLocation, waiter_key: usize, n: u32) -> i64 {
        self.shared.wake(location, waiter_key, n)
    }

    fn shared_requeue(
        &self,
        from: SharedFutexLocation,
        from_key: usize,
        to: SharedFutexLocation,
        to_key: usize,
        wake: u32,
        requeue: u32,
    ) -> (u32, u32) {
        self.shared
            .requeue(from, from_key, to, to_key, wake, requeue)
    }

    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32) {
        self.table.requeue(from, to, wake, requeue)
    }

    #[inline]
    fn notify_signal_pending(&self) {
        self.table.notify_signal_pending();
    }

    #[inline]
    fn notify_signal_pending_for(&self, tid: ThreadId) {
        self.table.notify_signal_pending_for(tid);
    }
}

/// The cross-process futex a NATIVE (DSR) lane owns end-to-end, as opposed to
/// the one-kernel-slice [`SharedFutexSyscall`] the VMM lanes plug into
/// [`shared_wait_sliced`].
///
/// The two are NOT interchangeable, and the difference is not stylistic. A
/// `SharedFutexSyscall` hands the shared loop ONE ≤20 ms wait slice and lets
/// [`FutexTableFutex`] own the deadline, the interrupt re-check and the
/// requeue continuation. A native lane's futex module instead owns the WHOLE
/// `FUTEX_WAIT` — it parks once with the guest's full relative timeout and
/// returns the Linux retval directly — because the work it does around the
/// park cannot survive being cut into slices:
///
/// * **FreeBSD** (`carrick_native_freebsd::futex`) reconstructs a woken COUNT
///   and a logical REQUEUE that `_umtx_op` does not provide, using a
///   fork-shared waiter table: a waiter is enrolled in that table for the
///   duration of its park, and a requeued waiter transparently continues on
///   the destination while RETAINING its original absolute deadline. Slicing
///   would both un-enroll the waiter between slices (so a peer's WAKE would
///   under-report, which is exactly the `futexwakecount`/`futexsharedalias`
///   contract the table exists for) and hand the requeue continuation a slice
///   deadline instead of the guest's.
/// * **NetBSD** (`carrick_native_netbsd::futex`) needs no table at all —
///   `__futex(2)` is deliberately Linux-shaped, so `FUTEX_WAKE` returns the
///   woken count natively and `FUTEX_CMP_REQUEUE` relinks queues in the
///   kernel. Its module is thin for a reason, and that reason must not be
///   flattened away by routing it through a shim built for the opposite
///   problem.
///
/// Mid-park cancellation on both hosts comes from the lane's non-restarting
/// kick signal (the park returns `EINTR`), which is why `interrupted` is a
/// pre-park fast path rather than a per-slice re-check.
///
/// All three methods speak the SAME value space as the native modules: host
/// addresses in, Linux `FUTEX_*` retvals out (0 / `-EAGAIN` / `-ETIMEDOUT` /
/// `-EINTR` for wait, a woken count for wake).
pub trait NativeSharedFutex: Send + Sync {
    /// One complete cross-process `FUTEX_WAIT` on the shared word at `word`
    /// (a live host VA), with the guest's full relative `timeout`.
    fn shared_wait(
        &self,
        word: usize,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> i64;

    /// Wake up to `count` waiters on `word`, returning how many were woken.
    fn shared_wake(&self, word: usize, waiter_key: usize, count: u32) -> i64;

    /// `FUTEX_(CMP_)REQUEUE` across shared words, returning `(woken, moved)`.
    fn shared_requeue(
        &self,
        from_word: usize,
        from_key: usize,
        to_key: usize,
        wake: u32,
        requeue: u32,
    ) -> (u32, u32);

    /// Allocate any fork-shared bookkeeping the host needs, BEFORE the first
    /// guest `fork`. Idempotent; a host that needs none leaves it a no-op.
    fn init_shared_state(&self) {}
}

/// The `PlatformFutex` a native (DSR) lane gets: the same process-private
/// [`FutexTable`] every backend shares, paired with the lane's own
/// [`NativeSharedFutex`] for the cross-process half.
///
/// This is the native-lane sibling of [`FutexTableFutex`]. It exists because
/// the aarch64 run loop consumes `Arc<dyn PlatformFutex>` while the native BSD
/// futex modules are whole-wait, not per-slice (see [`NativeSharedFutex`]);
/// without it the aarch64 BSD lanes would have to either re-home their futex
/// onto the VMM crates' slice shim — losing FreeBSD's woken count and both
/// hosts' requeue — or hand-roll the private half twice.
pub struct FutexTableNativeFutex<S: NativeSharedFutex> {
    table: Arc<FutexTable>,
    shared: S,
}

impl<S: NativeSharedFutex> FutexTableNativeFutex<S> {
    /// Pair a process-private table with the lane's cross-process futex.
    /// Runs [`NativeSharedFutex::init_shared_state`] here, at construction —
    /// the one point every lane reaches before its first guest `fork`.
    pub fn new(table: Arc<FutexTable>, shared: S) -> Self {
        crate::thread::set_current_futex_table(&table);
        shared.init_shared_state();
        Self { table, shared }
    }
}

impl<S: NativeSharedFutex> PlatformFutex for FutexTableNativeFutex<S> {
    /// Identical to [`FutexTableFutex::private_wait`]: the private path is the
    /// shared parking-lot table on every backend, native lanes included.
    fn private_wait(
        &self,
        addr: u64,
        _val: u32,
        tid: ThreadId,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
    ) -> FutexOutcome {
        let wait = self.table.prepare_wait(addr);
        match self
            .table
            .wait_prepared_for_thread(wait, timeout, tid, interrupted)
        {
            FutexWaitOutcome::Woken => FutexOutcome::Woken,
            FutexWaitOutcome::TimedOut => FutexOutcome::TimedOut,
            FutexWaitOutcome::Interrupted => FutexOutcome::Interrupted,
        }
    }

    fn private_wake(&self, addr: u64, n: u32) -> u32 {
        self.table.wake(addr, n)
    }

    /// The whole cross-process wait, delegated in one call. `wait_enrolled`
    /// fires BEFORE the park (the lane uses it to publish that this thread is
    /// about to block, so a concurrent kick finds it), exactly as the sliced
    /// impl does at the top of each park.
    fn shared_wait(
        &self,
        location: SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
        wait_enrolled: &dyn Fn(),
    ) -> i64 {
        wait_enrolled();
        self.shared.shared_wait(
            location.wait_addr().raw(),
            waiter_key,
            value,
            timeout,
            interrupted,
        )
    }

    fn shared_wake(&self, location: SharedFutexLocation, waiter_key: usize, n: u32) -> i64 {
        self.shared
            .shared_wake(location.wait_addr().raw(), waiter_key, n)
    }

    fn shared_requeue(
        &self,
        from: SharedFutexLocation,
        from_key: usize,
        _to: SharedFutexLocation,
        to_key: usize,
        wake: u32,
        requeue: u32,
    ) -> (u32, u32) {
        // `to` is deliberately unused: FreeBSD's umtx cannot relink queues and
        // keys the destination by side-table key only, while NetBSD's identity
        // model makes `to_key` BE the destination host word address (its
        // `NativeHost` does not override `shared_futex_waiter_key`). Both hosts
        // therefore take the destination as `to_key` — the same shape the x86
        // native lane's dispatch arm passes today.
        self.shared
            .shared_requeue(from.wait_addr().raw(), from_key, to_key, wake, requeue)
    }

    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32) {
        self.table.requeue(from, to, wake, requeue)
    }

    #[inline]
    fn notify_signal_pending(&self) {
        self.table.notify_signal_pending();
    }

    #[inline]
    fn notify_signal_pending_for(&self, tid: ThreadId) {
        self.table.notify_signal_pending_for(tid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::HostVa;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RecordingShared;

    impl SharedFutexSyscall for RecordingShared {
        fn wait_one_slice(
            &self,
            location: SharedFutexLocation,
            _waiter_key: usize,
            _val: u32,
            _slice_ns: i64,
        ) -> SharedWaitStep {
            assert_eq!(location.wait_addr(), HostVa(0x1000));
            assert_eq!(location.waiter_count_addr(), None);
            SharedWaitStep::Woken
        }

        fn wake(&self, location: SharedFutexLocation, _waiter_key: usize, n: u32) -> i64 {
            assert_eq!(location.wait_addr(), HostVa(0x1000));
            assert_eq!(location.waiter_count_addr(), None);
            i64::from(n)
        }
    }

    #[test]
    fn direct_shared_futex_location_does_not_expose_waiter_counter() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let futex = FutexTableFutex::new(Arc::new(FutexTable::default()), RecordingShared);
        let location = SharedFutexLocation::Direct {
            word: HostVa(0x1000),
            waiter_key: 0x1000,
        };

        assert_eq!(
            futex.shared_wait(location, 0x2000, 7, None, &|| false, &|| {}),
            0
        );
        assert_eq!(futex.shared_wake(location, 0x2000, 3), 3);
    }

    struct OrderedShared {
        state: Arc<AtomicUsize>,
    }

    impl SharedFutexSyscall for OrderedShared {
        fn wait_start(&self, _waiter_key: usize) {
            assert_eq!(
                self.state.swap(1, Ordering::SeqCst),
                0,
                "wait_start must run first"
            );
        }

        fn wait_one_slice(
            &self,
            _location: SharedFutexLocation,
            _waiter_key: usize,
            _val: u32,
            _slice_ns: i64,
        ) -> SharedWaitStep {
            assert_eq!(
                self.state.load(Ordering::SeqCst),
                2,
                "wait_enrolled callback must run before the first wait slice"
            );
            SharedWaitStep::Woken
        }

        fn wake(&self, _location: SharedFutexLocation, _waiter_key: usize, _n: u32) -> i64 {
            0
        }
    }

    #[test]
    fn shared_wait_publishes_after_waiter_enrollment() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let state = Arc::new(AtomicUsize::new(0));
        let futex = FutexTableFutex::new(
            Arc::new(FutexTable::default()),
            OrderedShared {
                state: Arc::clone(&state),
            },
        );
        let location = SharedFutexLocation::Direct {
            word: HostVa(0x1000),
            waiter_key: 0x1000,
        };
        let mark_enrolled = || {
            assert_eq!(
                state.swap(2, Ordering::SeqCst),
                1,
                "wait_enrolled must run after wait_start"
            );
        };

        assert_eq!(
            futex.shared_wait(location, 0x2000, 7, None, &|| false, &mark_enrolled),
            0
        );
    }

    // ---- FutexTableNativeFutex (the native/DSR lanes' PlatformFutex) ----

    /// Records exactly what the native seam forwards, so the tests can assert
    /// the CONTRACT that distinguishes it from the sliced VMM shim: one whole
    /// wait carrying the guest's full timeout, not N slices.
    /// `(word, waiter_key, value, timeout)` as the seam forwarded it.
    type WaitRecord = (usize, usize, u32, Option<Duration>);
    /// `(word, waiter_key, count)`.
    type WakeRecord = (usize, usize, u32);
    /// `(from_word, from_key, to_key, wake, requeue)`.
    type RequeueRecord = (usize, usize, usize, u32, u32);
    type Log<T> = Arc<parking_lot::Mutex<Vec<T>>>;

    #[derive(Default)]
    struct RecordingNative {
        waits: Log<WaitRecord>,
        wakes: Log<WakeRecord>,
        requeues: Log<RequeueRecord>,
        inits: Arc<AtomicUsize>,
        enrolled_before_wait: Arc<AtomicUsize>,
        enrollments: Arc<AtomicUsize>,
    }

    impl NativeSharedFutex for RecordingNative {
        fn shared_wait(
            &self,
            word: usize,
            waiter_key: usize,
            value: u32,
            timeout: Option<Duration>,
            interrupted: &dyn Fn() -> bool,
        ) -> i64 {
            self.enrolled_before_wait
                .store(self.enrollments.load(Ordering::SeqCst), Ordering::SeqCst);
            self.waits.lock().push((word, waiter_key, value, timeout));
            if interrupted() { -4 } else { 0 }
        }

        fn shared_wake(&self, word: usize, waiter_key: usize, count: u32) -> i64 {
            self.wakes.lock().push((word, waiter_key, count));
            i64::from(count)
        }

        fn shared_requeue(
            &self,
            from_word: usize,
            from_key: usize,
            to_key: usize,
            wake: u32,
            requeue: u32,
        ) -> (u32, u32) {
            self.requeues
                .lock()
                .push((from_word, from_key, to_key, wake, requeue));
            (wake, requeue)
        }

        fn init_shared_state(&self) {
            self.inits.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn native_location(word: usize, waiter_key: usize) -> SharedFutexLocation {
        SharedFutexLocation::Direct {
            word: HostVa(word),
            waiter_key,
        }
    }

    /// The load-bearing difference from [`FutexTableFutex`]: the native seam
    /// delegates the ENTIRE wait ONCE, with the guest's own timeout. Slicing it
    /// would un-enroll a FreeBSD waiter from the fork-shared waiter table
    /// between slices and hand a requeue continuation the wrong deadline.
    #[test]
    fn native_shared_wait_delegates_the_whole_wait_once() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let shared = RecordingNative::default();
        let waits = Arc::clone(&shared.waits);
        let futex = FutexTableNativeFutex::new(Arc::new(FutexTable::default()), shared);

        let timeout = Some(Duration::from_millis(1234));
        assert_eq!(
            futex.shared_wait(
                native_location(0x1000, 0x1000),
                0x2000,
                7,
                timeout,
                &|| false,
                &|| {}
            ),
            0
        );

        assert_eq!(
            *waits.lock(),
            vec![(0x1000, 0x2000, 7, timeout)],
            "one whole wait: host word, the EXPLICIT waiter key, value, and the \
             guest's full timeout — not a slice"
        );
    }

    /// `wait_enrolled` must fire BEFORE the park, or a kick racing the park has
    /// nothing to find.
    #[test]
    fn native_shared_wait_enrolls_before_parking() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let shared = RecordingNative::default();
        let enrollments = Arc::clone(&shared.enrollments);
        let enrolled_before_wait = Arc::clone(&shared.enrolled_before_wait);
        let futex = FutexTableNativeFutex::new(Arc::new(FutexTable::default()), shared);

        let enroll = || {
            enrollments.fetch_add(1, Ordering::SeqCst);
        };
        futex.shared_wait(
            native_location(0x1000, 0x1000),
            0x1000,
            7,
            None,
            &|| false,
            &enroll,
        );

        assert_eq!(
            enrolled_before_wait.load(Ordering::SeqCst),
            1,
            "the enrollment callback must have run before the host park"
        );
    }

    /// `interrupted` reaches the host as a pre-park fast path (both native
    /// modules return `-EINTR` from it without touching the kernel).
    #[test]
    fn native_shared_wait_forwards_the_interrupt_predicate() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let futex =
            FutexTableNativeFutex::new(Arc::new(FutexTable::default()), RecordingNative::default());
        assert_eq!(
            futex.shared_wait(
                native_location(0x1000, 0x1000),
                0x1000,
                7,
                None,
                &|| true,
                &|| {}
            ),
            -4,
            "the host module decides; the seam must not swallow the predicate"
        );
    }

    /// Wake and requeue forward the host WORD address plus the keys in the
    /// shape both native modules expect — the destination arrives as `to_key`
    /// (NetBSD uses it directly as `uaddr2`; FreeBSD as a side-table key).
    #[test]
    fn native_wake_and_requeue_forward_words_and_keys() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let shared = RecordingNative::default();
        let wakes = Arc::clone(&shared.wakes);
        let requeues = Arc::clone(&shared.requeues);
        let futex = FutexTableNativeFutex::new(Arc::new(FutexTable::default()), shared);

        assert_eq!(
            futex.shared_wake(native_location(0x1000, 0x1000), 0x2000, 3),
            3
        );
        assert_eq!(*wakes.lock(), vec![(0x1000, 0x2000, 3)]);

        assert_eq!(
            futex.shared_requeue(
                native_location(0x1000, 0x1000),
                0x1000,
                native_location(0x2000, 0x2000),
                0x2000,
                1,
                5,
            ),
            (1, 5)
        );
        assert_eq!(
            *requeues.lock(),
            vec![(0x1000, 0x1000, 0x2000, 1, 5)],
            "from WORD + from key + destination key"
        );
    }

    /// Fork-shared bookkeeping (FreeBSD's waiter table) must be allocated
    /// pre-fork; construction is the one point every lane reaches first.
    #[test]
    fn native_futex_initializes_shared_state_at_construction() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let shared = RecordingNative::default();
        let inits = Arc::clone(&shared.inits);
        let futex = FutexTableNativeFutex::new(Arc::new(FutexTable::default()), shared);
        assert_eq!(inits.load(Ordering::SeqCst), 1, "init runs exactly once");

        // And the private half is the same parking-lot table every backend
        // uses: a wake with no waiter reports zero, not an error.
        assert_eq!(futex.private_wake(0x3000, 1), 0);
    }
}
