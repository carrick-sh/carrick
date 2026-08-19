//! The `PlatformFutex` implementations.
//!
//! [`FutexTableFutex`] serves every VMM lane (HVF, KVM, bhyve, NVMM). Under the
//! unified HVPatch kernel each of those lanes runs EVERY Linux process as a
//! thread of one carrier, so both the private and the `MAP_SHARED` guest futex
//! are intra-process rendezvous: the private path parks on the per-process
//! [`crate::thread::FutexTable`], the shared path on the carrier-wide
//! [`carrier_shared_futex_table`]. No host futex primitive is involved.
//!
//! This replaces the per-host `SharedFutexSyscall` shim (macOS
//! `os_sync_wait_on_address`, Linux bare `SYS_futex`, FreeBSD `_umtx_op`),
//! whose own rationale — "carrick forks each guest process as a real macOS
//! process" — described the retired 1:1 execution model. Everything that shim
//! needed to paper over a host primitive went with it: physical-page keying,
//! the fork-shared waiter side-table, logical/physical wake reconciliation,
//! requeue tokens, and the 20 ms interrupt-polling slices.
//!
//! [`FutexTableNativeFutex`] remains for the DSR native lanes, which DO run
//! guest processes as separate host processes and therefore still need a real
//! cross-process kernel primitive.

use std::sync::Arc;
use std::time::Duration;

use carrick_hal::{FutexOutcome, PlatformFutex, SharedFutexLocation, ThreadId};

use crate::thread::{FutexTable, FutexWaitOutcome};

/// The one VMM-lane `PlatformFutex`: a process-private [`FutexTable`] for the
/// private path, the carrier-wide table for the shared path.
pub struct FutexTableFutex {
    table: Arc<FutexTable>,
}

impl FutexTableFutex {
    /// Wrap the process-private table (installed as the CURRENT table for
    /// helper-thread signal wakes, exactly as before).
    pub fn new(table: Arc<FutexTable>) -> Self {
        crate::thread::set_current_futex_table(&table);
        Self { table }
    }
}

/// THE carrier-wide wait queue for `MAP_SHARED` guest futexes.
///
/// One per carrier, deliberately NOT per guest process: HVPatch multiplexes
/// every Linux process into one carrier, and `fork` hands the child a fresh
/// per-process [`FutexTable`]. A shared futex must rendezvous ACROSS guest
/// processes, so it cannot live in a table that fork replaces — parent and
/// child would park in different tables and never meet.
pub fn carrier_shared_futex_table() -> &'static Arc<FutexTable> {
    static TABLE: std::sync::OnceLock<Arc<FutexTable>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| Arc::new(FutexTable::new()))
}

impl PlatformFutex for FutexTableFutex {
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
    /// Wait on a `MAP_SHARED` guest futex — in-process, no host primitive.
    ///
    /// Under the HVPatch kernel every Linux process is a THREAD of one carrier
    /// sharing one address space, so a "cross-process" guest futex is an
    /// ordinary intra-process rendezvous. `waiter_key` is already the
    /// carrier-stable identity of the futex word, so all guest processes
    /// naming the same word hash to the same bucket of one carrier-wide table.
    ///
    /// This replaces a Darwin `os_sync_wait_on_address` path whose own header
    /// justified itself with "carrick forks each guest process as a real macOS
    /// process" — a premise HVPatch retired. Everything that path needed to
    /// paper over a host primitive is gone with it: the physical-page keying,
    /// the shared waiter side-table, the logical/physical wake reconciliation,
    /// the requeue tokens, and above all the 20 ms slicing (a host wait cannot
    /// be interrupted by our kick, so every shared waiter had to re-check its
    /// interrupt predicate 50x a second — 50k host wakeups/s at a thousand
    /// waiters, inside ONE process).
    fn shared_wait(
        &self,
        location: SharedFutexLocation,
        value: u32,
        tid: ThreadId,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
        wait_enrolled: &dyn Fn(),
    ) -> i64 {
        let table = carrier_shared_futex_table();
        let waiter_key = location.waiter_key();
        // SAFETY: the futex word is a live, 4-byte-aligned host word for as
        // long as the guest mapping naming it is alive; the wait does not
        // outlive the syscall that named it.
        let word = location.wait_addr().raw() as *const std::sync::atomic::AtomicU32;
        // Enrolled = reachable by kicks. The value check and the park are made
        // atomic against wakes by the word validation inside the park itself,
        // so enrollment order carries no lost-wake risk here.
        wait_enrolled();
        match unsafe {
            table.wait_while_word_equals(waiter_key as u64, word, value, timeout, tid, interrupted)
        } {
            FutexWaitOutcome::Woken => 0,
            FutexWaitOutcome::TimedOut => carrick_abi::LINUX_ETIMEDOUT.guest_retval(),
            FutexWaitOutcome::Interrupted => carrick_abi::LINUX_EINTR.guest_retval(),
        }
    }

    fn shared_wake(&self, _location: SharedFutexLocation, waiter_key: usize, n: u32) -> i64 {
        // The return is Linux's contract: exactly the number of parked waiters
        // released. `FutexTable::wake` reports `unparked_threads`, and shared
        // waiters park word-validated (never generation-validated), so a wake
        // that unparks nobody genuinely woke nobody.
        i64::from(carrier_shared_futex_table().wake(waiter_key as u64, n))
    }

    /// `FUTEX_CMP_REQUEUE` on a shared futex: a real queue relink
    /// (`parking_lot_core::unpark_requeue`), the same primitive the private
    /// path uses. The host-primitive path could not relink a queue it did not
    /// own, so it emulated requeue by waking the whole batch and handing each
    /// woken waiter a token telling it whether to re-park on the destination.
    fn shared_requeue(
        &self,
        _from: SharedFutexLocation,
        from_key: usize,
        _to: SharedFutexLocation,
        to_key: usize,
        wake: u32,
        requeue: u32,
    ) -> (u32, u32) {
        carrier_shared_futex_table().requeue(from_key as u64, to_key as u64, wake, requeue)
    }

    fn requeue(&self, from: u64, to: u64, wake: u32, requeue: u32) -> (u32, u32) {
        self.table.requeue(from, to, wake, requeue)
    }

    #[inline]
    fn notify_signal_pending(&self) {
        self.table.notify_signal_pending();
        // Shared waiters park in the carrier-wide table, not the per-process
        // one — a signal that only poked `self.table` would leave a shared
        // waiter asleep until its timeout.
        carrier_shared_futex_table().notify_signal_pending();
    }

    #[inline]
    fn notify_signal_pending_for(&self, tid: ThreadId) {
        self.table.notify_signal_pending_for(tid);
        carrier_shared_futex_table().notify_signal_pending_for(tid);
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
        value: u32,
        // The DSR native lane still runs guest processes as real host
        // processes, so its shared futex genuinely crosses address spaces and
        // cannot use the carrier-wide in-process queue (or a park token that
        // only names a thread of THIS process).
        _tid: ThreadId,
        timeout: Option<Duration>,
        interrupted: &dyn Fn() -> bool,
        wait_enrolled: &dyn Fn(),
    ) -> i64 {
        wait_enrolled();
        let waiter_key = location.waiter_key();
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

    /// A shared guest futex rendezvous is now entirely in-process: one waiter
    /// parks on the carrier-wide table and a wake on the SAME `waiter_key`
    /// releases it, with no host primitive involved.
    #[test]
    fn shared_futex_rendezvous_is_in_process() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let word = Box::leak(Box::new(std::sync::atomic::AtomicU32::new(7)));
        let addr = std::ptr::from_ref(word) as usize;
        let location = SharedFutexLocation::Direct {
            word: HostVa(addr),
            waiter_key: addr,
        };
        let futex = Arc::new(FutexTableFutex::new(Arc::new(FutexTable::default())));

        let waiter = {
            let futex = Arc::clone(&futex);
            std::thread::spawn(move || {
                futex.shared_wait(location, 7, test_tid(), None, &|| false, &|| {})
            })
        };

        // Wait until the waiter is actually PARKED before waking. Waking early
        // is not a lost wake — it advances the bucket generation, so the waiter
        // returns without parking — but then the wake reports 0 and this test
        // would be asserting the wrong thing.
        while carrier_shared_futex_table().waiter_count(addr as u64) == 0 {
            std::thread::yield_now();
        }
        // The wake is keyed on `waiter_key`, which is what makes two guest
        // PROCESSES meet on one word.
        assert_eq!(
            futex.shared_wake(location, addr, 1),
            1,
            "the wake must report the waiter it released"
        );
        assert_eq!(waiter.join().unwrap(), 0, "a woken FUTEX_WAIT returns 0");
    }

    /// The value re-check happens AFTER enrollment, so a word that already
    /// moved returns 0 without parking rather than sleeping to its deadline.
    #[test]
    fn shared_wait_returns_zero_when_the_word_already_moved() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let word = Box::leak(Box::new(std::sync::atomic::AtomicU32::new(9)));
        let addr = std::ptr::from_ref(word) as usize;
        let location = SharedFutexLocation::Direct {
            word: HostVa(addr),
            waiter_key: addr,
        };
        let futex = FutexTableFutex::new(Arc::new(FutexTable::default()));
        assert_eq!(
            futex.shared_wait(location, 7, test_tid(), None, &|| false, &|| {}),
            0,
            "word is 9, the wait expected 7: no park, immediate re-check"
        );
    }

    #[test]
    fn shared_wait_publishes_after_waiter_enrollment() {
        let _guard = crate::thread::current_futex_table_test_guard();
        let state = Arc::new(AtomicUsize::new(0));
        let word = Box::leak(Box::new(std::sync::atomic::AtomicU32::new(9)));
        let addr = std::ptr::from_ref(word) as usize;
        let location = SharedFutexLocation::Direct {
            word: HostVa(addr),
            waiter_key: addr,
        };
        let futex = FutexTableFutex::new(Arc::new(FutexTable::default()));
        let mark_enrolled = || {
            state.store(1, Ordering::SeqCst);
        };

        // The word (9) already differs from the wait value (7), so this returns
        // without parking — but enrollment must still have happened first.
        assert_eq!(
            futex.shared_wait(location, 7, test_tid(), None, &|| false, &mark_enrolled),
            0
        );
        assert_eq!(
            state.load(Ordering::SeqCst),
            1,
            "wait_enrolled must run before the value re-check and the park"
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
                native_location(0x1000, 0x2000),
                7,
                test_tid(),
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

    /// A synthetic thread id for the futex tests: the park token only has to be
    /// stable within the test, never to name a live guest thread.
    fn test_tid() -> ThreadId {
        ThreadId::synthetic_for_tests(4242)
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
            7,
            test_tid(),
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
                7,
                test_tid(),
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
