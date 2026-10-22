//! Linux signal policy and host-venue pending bookkeeping, shared by every backend: the
//! UNBLOCKED async-arrival store (THREAD_PENDING + PROC_PENDING) and SENDER_PID.
//! The dispatcher's blocked-signal/queued-siginfo store is SEPARATE (see the
//! design doc's two-slot invariant).
//!
//! This crate owns the data structures and the pure operations on them, plus the
//! platform-NEUTRAL cross-process xsignal ring core (see the [`xsig`] submodule:
//! the `MAP_SHARED|MAP_ANON` ring, enqueue, drain, dirty flag). Backend-specific
//! GLUE (the macOS/HVF kqueue pump + self-pipe wakes; the KVM vCPU kicks; and the
//! xsignal NUDGE signal number + nudge handler wake) lives in the backends. Each
//! backend's `host_signal` module re-exports the neutral surface from here and
//! layers its own wake/route glue on top.
//!
//! WHY THE STORE IS BITMASKS, NOT SLOTS. Process-directed signals land in
//! `PROC_PENDING`, an `AtomicU64` BITMASK of pending signums (bit `signum-1`);
//! thread-directed signals land in `THREAD_PENDING`, a `tid -> u64 BITMASK` map.
//! Both are bitmasks (not single slots) so that distinct concurrent signums all
//! survive: a single i32 slot coalesced them and hung waiters (LTP kill10's
//! manager sending SIGUSR1/SIGUSR2/SIGQUIT; libuv's signal_multiple_loops
//! sending SIGUSR1 then SIGUSR2 to one thread). Same-signum repeats still
//! coalesce (standard-signal semantics); RT-signal queue depth lives in the
//! dispatcher, not here. `PROC_PENDING` is written from async host signal
//! handlers via a lock-free `fetch_or`, so it must stay lock-free.
//! `THREAD_PENDING` is touched only from normal dispatch context (a host handler
//! can't name a guest tid), so a plain `Mutex` is safe there.

pub mod backend;
pub mod child_watch;
pub mod fasync;
pub mod fork_reset;
pub mod host_disposition;
pub mod host_glue;
pub mod xsig;

pub use backend::HostSignalGlue;

use carrick_abi::{LINUX_SIGKILL, LINUX_SIGSTOP, SigBlockMask, SigSet};
pub use carrick_signal_core::pending_bit;
use carrick_signal_core::{PendingSet, SignalSet};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard};

#[cfg(test)]
type TestBoundary = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

#[cfg(test)]
std::thread_local! {
    static PROCESS_BOUNDARY: TestBoundary = const { std::cell::RefCell::new(None) };
    static AFTER_MASK_TAKE_HOST: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static AFTER_MASK_CLEAR_HOST: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static TIMER_PREPARED: TestBoundary = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_test_boundary(slot: &'static std::thread::LocalKey<TestBoundary>) {
    let hook = slot.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

/// "No signal pending" sentinel. Chosen as `0` because Linux's
/// `kill(pid, 0)` is documented as the null-signal probe; no real
/// delivery ever uses signum 0.
pub const NO_PENDING_SIGNAL: i32 = 0;

/// Scope survives the host bridge and must be retained by native ingress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingSignalScope {
    Process,
    Thread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingTimerInfo {
    pub id: i32,
    pub overrun: i32,
    pub value: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingSignalOrigin {
    Host,
    IntervalTimer,
    PosixTimer(PendingTimerInfo),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingSignalEvent {
    pub signum: i32,
    pub scope: PendingSignalScope,
    pub origin: PendingSignalOrigin,
}

/// `THREAD_PENDING` bit for `signum` (bit `signum-1`), or 0 if out of range.
pub fn thread_pending_bit(signum: i32) -> u64 {
    pending_bit(signum).unwrap_or(0)
}

/// Lowest pending signum in a pending set (`NO_PENDING_SIGNAL` when empty;
/// callers historically ensured non-empty).
pub fn lowest_pending_signum(mask: SigSet) -> i32 {
    SignalSet::from_bits(mask.raw())
        .lowest()
        .unwrap_or(NO_PENDING_SIGNAL)
}

/// Whether `signum` is deliverable given a temporary `block_mask`.
/// SIGKILL(9)/SIGSTOP(19) can never be blocked, so they are always deliverable
/// even if they are in `block_mask`.
pub fn signal_unblocked_by_mask(signum: i32, block_mask: SigBlockMask) -> bool {
    SignalSet::from_bits(thread_pending_bit(signum))
        .deliverable(SignalSet::from_bits(block_mask.raw()), unmaskable())
        .bits()
        != 0
}

fn set_is_deliverable(bits: u64, blocked: SigBlockMask) -> bool {
    SignalSet::from_bits(bits)
        .deliverable(SignalSet::from_bits(blocked.raw()), unmaskable())
        .bits()
        != 0
}

fn unmaskable() -> SignalSet {
    SignalSet::from_bits(thread_pending_bit(LINUX_SIGKILL) | thread_pending_bit(LINUX_SIGSTOP))
}

/// Process-directed pending signals: an `AtomicU64` BITMASK (bit `signum-1`),
/// set from an async host signal handler via a lock-free `fetch_or`. A bitmask —
/// not a single i32 slot — so distinct process-directed signums pending at once
/// all survive (a single slot dropped all but the last; LTP kill10's master,
/// counting acks sent as SIGUSR1/SIGUSR2/SIGQUIT, hung when one was clobbered).
/// Same-signum repeats still coalesce (standard-signal semantics); RT-signal
/// queue depth lives in the dispatcher's `rt_pending_counts`.
static PROC_PENDING: PendingSet = PendingSet::new();
// Only this normal-context custodian touches origins. PROC_PENDING remains
// the single authoritative mask, including while a timer prepares its payload.
// Async handlers only OR that word and never enter the custodian.
type ProcessOrigins = [PendingSignalOrigin; 64];
static PROC_CUSTODY: LazyLock<fork_reset::ForkResetBacking<Mutex<ProcessOrigins>>> =
    LazyLock::new(|| {
        fork_reset::ForkResetBacking::new(Mutex::new([PendingSignalOrigin::Host; 64]))
    });

fn lock_process_custody() -> MutexGuard<'static, ProcessOrigins> {
    PROC_CUSTODY
        .get()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Preallocated replacement for the normal process-pending custodian.
#[cfg(any(target_os = "macos", test))]
pub struct ProcessPendingForkPreparation(fork_reset::PreparedForkBacking<Mutex<ProcessOrigins>>);
/// Host-fork hold; drop before child reset. PendingSet itself is never replaced.
#[cfg(any(target_os = "macos", test))]
pub struct ProcessPendingForkGuard(
    fork_reset::ForkBackingGuard<Mutex<ProcessOrigins>, MutexGuard<'static, ProcessOrigins>>,
);

#[cfg(any(target_os = "macos", test))]
pub fn prepare_process_pending_for_fork() -> ProcessPendingForkPreparation {
    ProcessPendingForkPreparation(PROC_CUSTODY.prepare(Mutex::new([PendingSignalOrigin::Host; 64])))
}

#[cfg(any(target_os = "macos", test))]
impl ProcessPendingForkPreparation {
    pub fn hold(self) -> ProcessPendingForkGuard {
        ProcessPendingForkGuard(self.0.hold(|lock| {
            lock.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }))
    }
}

#[cfg(any(target_os = "macos", test))]
impl ProcessPendingForkGuard {
    /// Already-held reset borrows custody; it must not reacquire the lock.
    pub fn clear(&mut self) {
        clear_proc_pending_guarded(self.0.guard_mut());
    }
}

/// One process-directed bridge event interrupts one host waiter. Publication
/// still broadcasts a wake hint; the first unblocked waiter claims delivery.
static PROC_WAKE_OWNER: AtomicI32 = AtomicI32::new(0);

/// Thread-directed pending signals, keyed by guest tid. A process-directed
/// signal (host `SIGINT`, `kill(pid)`) goes into the global `PROC_PENDING` mask
/// and may be serviced by any thread; a *thread*-directed signal (guest
/// `tgkill(tid, sig)` / `tkill`) targets exactly one guest thread and is parked
/// here so only that thread delivers it. Set ONLY from guest-dispatch context
/// (never a host async handler — a host signal can't name a guest tid), so a
/// plain `Mutex` is safe; it is never locked from a signal handler. The value
/// is a per-tid BITMASK of pending signums (bit `signum-1`): distinct signals
/// targeting one thread must ALL be delivered, so a second must not overwrite a
/// first. A single i32 slot coalesced them — when libuv's signal_multiple_loops
/// routed SIGUSR1 then SIGUSR2 to the same thread, SIGUSR1 was overwritten and
/// its waiters hung. Same-signal repeats still coalesce (standard-signal
/// semantics); RT-signal queue depth lives in the dispatcher's
/// `rt_pending_counts`, not here.
static THREAD_PENDING: Mutex<Option<HashMap<i32, u64>>> = Mutex::new(None);
static THREAD_TIMER_INFO: Mutex<Option<HashMap<(i32, i32), PendingTimerInfo>>> = Mutex::new(None);

/// Lock-free MAY-HAVE-PENDING hint over `THREAD_PENDING`, bit `tid % 64`. The
/// delivery cycle runs on EVERY syscall return / kick / sigreturn of every
/// guest thread; taking the global mutex + HashMap lookup on the (overwhelming
/// majority) empty path is pure per-dispatch cost that compounds under load.
/// The hint is an EXACT MIRROR of "some tid hashing to this bit has a nonzero
/// mask": every mutation of the map happens with the mutex held and updates
/// the hint before release (publish ORs its bit in; removals recompute from
/// the surviving keys). A clear bit therefore proves no entry for that tid
/// exists — the reader skips the mutex. A set bit may be a hash collision
/// (`tid % 64`), which merely falls back to the locked path. A reader racing a
/// publisher mid-critical-section linearizes BEFORE the publish; the
/// publisher's kick (the established publish→kick contract) forces a fresh
/// delivery cycle that sees the bit.
static THREAD_PENDING_TID_HINT: AtomicU64 = AtomicU64::new(0);

/// The [`THREAD_PENDING_TID_HINT`] bit for `tid`.
fn tid_hint_bit(tid: i32) -> u64 {
    1u64 << ((tid as u32) & 63)
}

/// Recompute [`THREAD_PENDING_TID_HINT`] from the map's surviving nonzero
/// entries. MUST be called with the `THREAD_PENDING` lock held (the guard
/// argument proves it) after any removal, so the hint never keeps a stale set
/// bit alive across an emptied slot — and, critically, never LOSES a bit a
/// colliding tid still needs.
fn recompute_tid_hint(guard: &std::sync::MutexGuard<'_, Option<HashMap<i32, u64>>>) {
    let mut hint = 0u64;
    if let Some(map) = guard.as_ref() {
        for (&tid, &mask) in map {
            if mask != 0 {
                hint |= tid_hint_bit(tid);
            }
        }
    }
    THREAD_PENDING_TID_HINT.store(hint, Ordering::SeqCst);
}

/// Lock the thread-pending table, lazily initialising it, and recover the guard
/// if a panicking thread poisoned the mutex (the contents are a plain bitmask,
/// never left half-updated — and a poisoned signal table must not crash delivery).
fn lock_thread_pending() -> std::sync::MutexGuard<'static, Option<HashMap<i32, u64>>> {
    let mut guard = THREAD_PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    guard
}

fn try_lock_thread_pending() -> Option<std::sync::MutexGuard<'static, Option<HashMap<i32, u64>>>> {
    let mut guard = match THREAD_PENDING.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return None,
    };
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    Some(guard)
}

/// ATFORK-PREPARE guard over the thread-pending table (see
/// [`hold_thread_pending_for_fork`]): held by the FORKING thread across
/// `fork()` so a fork child can never inherit `THREAD_PENDING`'s mutex in a
/// LOCKED state from another thread (a backend's child-exit watcher or pump
/// mid-`publish_pending_for`) — the child's signal reinit reads/clears the
/// table and would otherwise park forever on the COW lock copy.
pub struct ThreadPendingForkGuard(
    #[allow(dead_code)] std::sync::MutexGuard<'static, Option<HashMap<i32, u64>>>,
);

/// Acquire the thread-pending mutex for an atfork-prepare hold across a host
/// `fork()`. Drop the guard IMMEDIATELY after the fork returns, in BOTH
/// processes, before any pending-table use (the mutex is not reentrant).
pub fn hold_thread_pending_for_fork() -> ThreadPendingForkGuard {
    ThreadPendingForkGuard(lock_thread_pending())
}

/// Non-blocking fork-prepare acquisition used by bounded native host-fork
/// coordinators. `None` means a publisher currently owns the table; callers
/// retry only until their explicit fork deadline.
pub fn try_hold_thread_pending_for_fork() -> Option<ThreadPendingForkGuard> {
    try_lock_thread_pending().map(ThreadPendingForkGuard)
}

/// Set the thread-directed pending `signum` bit for `tid`. This is the pure
/// store half of a thread-directed publish; backends layer their own wakeups
/// (the HVF self-pipe / per-thread pipe; the KVM vCPU kick) around the call.
pub fn publish_pending_for(tid: i32, signum: i32) {
    let bit = thread_pending_bit(signum);
    if bit != 0 {
        let mut guard = lock_thread_pending();
        let map = guard.get_or_insert_with(HashMap::new);
        *map.entry(tid).or_insert(0) |= bit;
        // Under the lock, so the hint is an exact mirror at release.
        THREAD_PENDING_TID_HINT.fetch_or(tid_hint_bit(tid), Ordering::SeqCst);
    }
}

pub fn publish_pending_timer_for(tid: i32, signum: i32, info: PendingTimerInfo) {
    let bit = thread_pending_bit(signum);
    if bit == 0 {
        return;
    }
    let mut guard = lock_thread_pending();
    let map = guard.get_or_insert_with(HashMap::new);
    let pending = map.entry(tid).or_insert(0);
    if *pending & bit != 0 {
        return;
    }
    THREAD_TIMER_INFO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert((tid, signum), info);
    *pending |= bit;
    THREAD_PENDING_TID_HINT.fetch_or(tid_hint_bit(tid), Ordering::SeqCst);
}

/// Pop the lowest pending process-directed signum from `PROC_PENDING` that is
/// also in `wait_set` (pass `SigSet::EMPTY.complement()` to accept any).
/// Returns `0` if none. `take_pending_for` can run concurrently on every vCPU
/// kicked for one process-directed signal, so draining the bit must be
/// compare/exchange based: a `load` + `compare_exchange` lets multiple threads
/// observe and deliver the same pending bit at most once total. The store is a
/// raw `AtomicU64` in wire form (bit `signum-1`); the typed set converts at the
/// atomic load/CAS boundary.
fn take_proc_pending_event_in(wait_set: SigSet) -> Option<PendingSignalEvent> {
    take_proc_pending_event_in_for(wait_set, None)
}

fn take_proc_pending_event_in_for(
    wait_set: SigSet,
    consumer: Option<i32>,
) -> Option<PendingSignalEvent> {
    // Empty observations may linearize before an arrival; publication wakes the
    // delivery path again. No normal mutex on the overwhelmingly empty path.
    if PROC_PENDING.load().bits() & wait_set.raw() == 0 {
        return None;
    }
    #[cfg(test)]
    run_test_boundary(&PROCESS_BOUNDARY);
    let mut origins = lock_process_custody();
    let owner = PROC_WAKE_OWNER.load(Ordering::SeqCst);
    if consumer.is_some_and(|tid| owner != 0 && owner != tid) {
        return None;
    }
    take_proc_pending_guarded(wait_set, &mut origins)
}

fn take_proc_pending_guarded(
    wait_set: SigSet,
    origins: &mut MutexGuard<'_, ProcessOrigins>,
) -> Option<PendingSignalEvent> {
    // PendingSet uses a whole-word strong CAS and recomputes lowest eligibility
    // after any interfering async OR; it never selects from per-slot summaries.
    let signum = PROC_PENDING.take(SignalSet::from_bits(wait_set.raw()))?;
    PROC_WAKE_OWNER.store(0, Ordering::SeqCst);
    #[cfg(test)]
    AFTER_MASK_TAKE_HOST.with(|bits| proc_pending_fetch_or(bits.replace(0)));
    let index = (signum - 1) as usize;
    let origin = std::mem::replace(&mut origins[index], PendingSignalOrigin::Host);
    Some(PendingSignalEvent {
        signum,
        scope: PendingSignalScope::Process,
        origin,
    })
}

// A caller may pause an already owned result without retaining custody. This
// seam is test-only; production has no callback inside or around the guard.
#[cfg(test)]
fn take_proc_pending_event_in_after_take(
    wait_set: SigSet,
    after_take: impl FnOnce(),
) -> Option<PendingSignalEvent> {
    let event = take_proc_pending_event_in(wait_set);
    if event.is_some() {
        after_take();
    }
    event
}

fn take_proc_pending_in(wait_set: SigSet) -> i32 {
    take_proc_pending_event_in(wait_set).map_or(NO_PENDING_SIGNAL, |event| event.signum)
}

/// Drain the signal deliverable to `tid`: a thread-directed one for this tid
/// takes priority, otherwise the process-directed mask (lowest signum first).
/// Returns `0` (`NO_PENDING_SIGNAL`) if neither is set. This is the single point
/// of consumption (called under the dispatcher lock in `deliver_pending_signal`).
pub fn take_pending_for(tid: i32) -> i32 {
    take_pending_event_for(tid).map_or(NO_PENDING_SIGNAL, |event| event.signum)
}

/// Consume one host event while preserving whether it was directed to the
/// process or the exact thread. Ingress cannot infer this from the polling
/// thread: doing so strands SIGINT when that thread blocks it or exits.
pub fn take_pending_event_for(tid: i32) -> Option<PendingSignalEvent> {
    // Lock-free empty fast path: a clear hint bit proves no THREAD_PENDING
    // entry for this tid exists (see THREAD_PENDING_TID_HINT), so the global
    // mutex + map lookup is skipped on the hot no-signal-pending path.
    if THREAD_PENDING_TID_HINT.load(Ordering::SeqCst) & tid_hint_bit(tid) != 0 {
        let mut guard = lock_thread_pending();
        if let Some(map) = guard.as_mut()
            && let Some(mask) = map.get_mut(&tid)
            && *mask != 0
        {
            let signum = lowest_pending_signum(SigSet::from_raw(*mask));
            *mask &= *mask - 1; // clear the lowest set bit
            if *mask == 0 {
                map.remove(&tid);
                recompute_tid_hint(&guard);
            }
            let timer = THREAD_TIMER_INFO
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
                .and_then(|map| map.remove(&(tid, signum)));
            return Some(PendingSignalEvent {
                signum,
                scope: PendingSignalScope::Thread,
                origin: timer.map_or(PendingSignalOrigin::Host, PendingSignalOrigin::PosixTimer),
            });
        }
    }
    take_proc_pending_event_in_for(SigSet::EMPTY.complement(), Some(tid))
}

/// Drain a signal pending for `tid` only if it intersects `wait_set`. Used by
/// `rt_sigtimedwait`: signals outside the waited set must remain pending for
/// normal delivery instead of being consumed and requeued.
pub fn take_pending_in_for(tid: i32, wait_set: SigSet) -> i32 {
    // Lock-free empty fast path (see THREAD_PENDING_TID_HINT).
    if THREAD_PENDING_TID_HINT.load(Ordering::SeqCst) & tid_hint_bit(tid) != 0 {
        // The stored per-tid mask is wire form (bit `signum-1`), the same
        // convention as `wait_set.raw()`, so a bitwise AND yields the pending
        // signums that are in the waited set; drain only the lowest, leaving
        // the rest pending for normal delivery.
        let mut guard = lock_thread_pending();
        if let Some(map) = guard.as_mut()
            && let Some(mask) = map.get_mut(&tid)
        {
            let in_set_bits = *mask & wait_set.raw();
            if in_set_bits != 0 {
                let signum = lowest_pending_signum(SigSet::from_raw(in_set_bits));
                *mask &= !thread_pending_bit(signum);
                if *mask == 0 {
                    map.remove(&tid);
                    recompute_tid_hint(&guard);
                }
                THREAD_TIMER_INFO
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_mut()
                    .and_then(|map| map.remove(&(tid, signum)));
                return signum;
            }
        }
    }
    // Process-directed: drain only the lowest pending signum that's in the
    // waited set, leaving the rest of the mask for normal delivery.
    take_proc_pending_in(wait_set)
}

/// True iff a thread-directed signal is pending for `tid` (ignores the
/// process-directed mask). Backends combine this with their own sources (the
/// HVF `PROC_PENDING`/xsignal peek) in `has_pending_for`.
pub fn thread_pending_has(tid: i32) -> bool {
    // Lock-free empty fast path (see THREAD_PENDING_TID_HINT).
    if THREAD_PENDING_TID_HINT.load(Ordering::SeqCst) & tid_hint_bit(tid) == 0 {
        return false;
    }
    let mut guard = lock_thread_pending();
    guard
        .as_mut()
        .and_then(|map| map.get(&tid))
        .is_some_and(|&mask| mask != 0)
}

fn effective_wait_block_mask(tid: i32, block_mask: SigBlockMask) -> SigBlockMask {
    let effective = carrick_signal_core::wait::wait_effective_block_mask(
        carrick_signal_core::policy::SigBlockMask::blocking_all_of(SignalSet::from_bits(
            block_mask.raw(),
        )),
        carrick_signal_core::wait::non_interrupting_for(tid),
    );
    SigBlockMask::blocking_all_of(SigSet::from_raw(effective.signals().bits()))
}

/// True iff a thread-directed signal for `tid` is pending AND deliverable given
/// `block_mask`. A blocked signal does not count, except SIGKILL/SIGSTOP which
/// can never be blocked.
pub fn thread_pending_deliverable(tid: i32, block_mask: SigBlockMask) -> bool {
    // Lock-free empty fast path (see THREAD_PENDING_TID_HINT).
    if THREAD_PENDING_TID_HINT.load(Ordering::SeqCst) & tid_hint_bit(tid) == 0 {
        return false;
    }
    let block_mask = effective_wait_block_mask(tid, block_mask);
    let mut guard = lock_thread_pending();
    guard
        .as_mut()
        .and_then(|map| map.get(&tid))
        .is_some_and(|&mask| set_is_deliverable(mask, block_mask))
}

/// Is a signal deliverable to `tid` pending? True for a thread-directed signal
/// for this tid OR any process-directed signal. The pure (no-glue) form used by
/// the KVM backend; the HVF backend wraps it to also peek its xsignal ring.
pub fn has_pending_for(tid: i32) -> bool {
    if PROC_PENDING.load().bits() != 0 {
        return true;
    }
    thread_pending_has(tid)
}

/// Pure eligibility query. A signal blocked by `block_mask` does not count;
/// querying does not reserve a process-directed signal for this thread.
pub fn has_unblocked_pending_for(tid: i32, block_mask: SigBlockMask) -> bool {
    let block_mask = effective_wait_block_mask(tid, block_mask);
    if thread_pending_deliverable(tid, block_mask) {
        return true;
    }
    let owner = PROC_WAKE_OWNER.load(Ordering::SeqCst);
    (owner == 0 || owner == tid) && set_is_deliverable(PROC_PENDING.load().bits(), block_mask)
}

/// Claim eligibility in an exact policy set, without Linux's unblockable-mask
/// normalization. Internal killable waits must be able to defer SIGSTOP.
pub fn claim_pending_in_for(tid: i32, eligible: SigSet) -> bool {
    if THREAD_PENDING_TID_HINT.load(Ordering::SeqCst) & tid_hint_bit(tid) != 0
        && lock_thread_pending()
            .as_ref()
            .and_then(|map| map.get(&tid))
            .is_some_and(|bits| bits & eligible.raw() != 0)
    {
        return true;
    }
    if PROC_PENDING.load().bits() & eligible.raw() == 0 {
        return false;
    }
    let _custody = lock_process_custody();
    if PROC_PENDING.load().bits() & eligible.raw() == 0 {
        return false;
    }
    let owner = PROC_WAKE_OWNER.load(Ordering::SeqCst);
    if owner == 0 {
        PROC_WAKE_OWNER.store(tid, Ordering::SeqCst);
    }
    owner == 0 || owner == tid
}

/// Commit one interrupted waiter to a process-directed signal. Other
/// waiters keep their continuation until this owner consumes or retires.
pub fn claim_unblocked_pending_for(tid: i32, block_mask: SigBlockMask) -> bool {
    let block_mask = effective_wait_block_mask(tid, block_mask);
    if thread_pending_deliverable(tid, block_mask) {
        return true;
    }
    if !set_is_deliverable(PROC_PENDING.load().bits(), block_mask) {
        return false;
    }
    #[cfg(test)]
    run_test_boundary(&PROCESS_BOUNDARY);
    let _custody = lock_process_custody();
    // Both eligibility and owner are read under the same normal transaction as
    // consumption/clear/retirement. The pre-lock check is only an empty hint.
    if !set_is_deliverable(PROC_PENDING.load().bits(), block_mask) {
        return false;
    }
    let owner = PROC_WAKE_OWNER.load(Ordering::SeqCst);
    if owner == 0 {
        PROC_WAKE_OWNER.store(tid, Ordering::SeqCst);
    }
    owner == 0 || owner == tid
}

/// True iff any process-directed signal is pending.
pub fn has_process_pending() -> bool {
    PROC_PENDING.load().bits() != 0
}

/// Current process-directed pending set.
pub fn proc_pending_mask() -> SigSet {
    SigSet::from_raw(PROC_PENDING.load().bits())
}

/// Atomically OR `bit` into the process-directed pending mask. Lock-free, so
/// callable from an async host signal handler. Deliberately kept in raw wire
/// form (bit `signum-1`, from [`pending_bit`]/[`thread_pending_bit`]): this is
/// the async-signal-safe whole-word OR at the atomic boundary (zero and
/// multi-bit inputs are valid). No origin metadata is touched.
pub fn proc_pending_fetch_or(bit: u64) {
    PROC_PENDING.publish(SignalSet::from_bits(bit));
}

/// Publish a process-directed `signum` into the pending mask (the pure store
/// half; the lowest pending signum is later drained by `take_pending_for`).
pub fn publish_process_signal(signum: i32) {
    let bit = thread_pending_bit(signum);
    if bit != 0 {
        proc_pending_fetch_or(bit);
    }
}

/// Timer publication keeps source and siginfo together with the pending bit.
/// Timer callbacks run in normal host context; the async host signal path
/// above remains lock-free. A previously pending standard signal wins and the
/// second publication coalesces without overwriting its metadata.
pub fn publish_process_timer_signal(signum: i32, info: Option<PendingTimerInfo>) {
    let bit = thread_pending_bit(signum);
    if bit == 0 {
        return;
    }
    let mut origins = lock_process_custody();
    if PROC_PENDING.load().bits() & bit != 0 {
        return;
    }
    origins[(signum - 1) as usize] = info.map_or(
        PendingSignalOrigin::IntervalTimer,
        PendingSignalOrigin::PosixTimer,
    );
    #[cfg(test)]
    run_test_boundary(&TIMER_PREPARED);
    PROC_PENDING.publish(SignalSet::from_bits(bit));
    // Caller wake/backend/graph work happens after this guard drops.
}

/// Take (drain) the lowest process-directed pending signum, or `0` if none.
pub fn take_process_pending() -> i32 {
    take_proc_pending_in(SigSet::EMPTY.complement())
}

/// Clear the process-directed pending mask (fork / supervisor-fork reinit).
pub fn clear_proc_pending() {
    clear_proc_pending_guarded(&mut lock_process_custody());
}

fn clear_proc_pending_guarded(origins: &mut MutexGuard<'_, ProcessOrigins>) {
    PROC_PENDING.clear();
    PROC_WAKE_OWNER.store(0, Ordering::SeqCst);
    #[cfg(test)]
    AFTER_MASK_CLEAR_HOST.with(|bits| proc_pending_fetch_or(bits.replace(0)));
    origins.fill(PendingSignalOrigin::Host);
}

/// Drop any thread-directed pending entry for `tid` (called when a guest thread
/// exits so a recycled tid never inherits a stale signal). A forked child also
/// clears the whole table via [`clear_thread_pending`].
pub fn forget_thread(tid: i32) {
    carrick_signal_core::wait::clear_non_interrupting_for(tid);
    {
        let _custody = lock_process_custody();
        let _ = PROC_WAKE_OWNER.compare_exchange(tid, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
    let mut guard = lock_thread_pending();
    if let Some(map) = guard.as_mut() {
        map.remove(&tid);
    }
    if let Some(map) = THREAD_TIMER_INFO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_mut()
    {
        map.retain(|(target, _), _| *target != tid);
    }
    recompute_tid_hint(&guard);
}

/// Clear the entire thread-directed pending table (fork reinit: the child is
/// single-threaded, so inherited sibling-directed entries are stale).
pub fn clear_thread_pending() {
    carrick_signal_core::wait::clear_all_non_interrupting();
    let mut guard = lock_thread_pending();
    if let Some(map) = guard.as_mut() {
        map.clear();
    }
    THREAD_TIMER_INFO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    recompute_tid_hint(&guard);
}

/// The guest tids that currently have a thread-directed signal pending.
pub fn pending_thread_tids() -> Vec<i32> {
    lock_thread_pending()
        .as_ref()
        .map(|map| map.keys().copied().collect())
        .unwrap_or_default()
}

/// Sender's HOST pid for the most recent pending signal of each signum (index =
/// signum-1, for 1..=64). The host handler stores it from `siginfo_t.si_pid`
/// (SI_USER/SI_QUEUE/SI_TKILL carry the sender); the delivery path reads it to
/// populate the guest siginfo's si_pid instead of synthesising 0 — which made
/// LTP kill10 loop forever on "received signal from 0". A single atomic store
/// keeps it async-signal-safe. 0 = no sender recorded (default action / timer).
static SENDER_PID: [AtomicI32; 64] = [const { AtomicI32::new(0) }; 64];

/// Record `host_pid` as the sender of `signum`. Async-signal-safe (one atomic
/// store); out-of-range signums and host deliveries with no real sender pid are
/// ignored. A zero `si_pid` must not clobber the previous real sender for a
/// coalesced standard signal under a signal flood (LTP kill10).
pub fn record_sender(signum: i32, host_pid: i32) {
    if host_pid > 0 && (1..=64).contains(&signum) {
        SENDER_PID[(signum - 1) as usize].store(host_pid, Ordering::SeqCst);
    }
}

/// The last recorded sender host pid for `signum` (0 when none ever recorded).
/// READ, not take: clearing on read raced under a signal flood — a coalesced or
/// re-delivered signal whose slot a prior delivery had already consumed read 0
/// (LTP kill10 "received unexpected signal from 0"). Leaving the slot means a
/// delivery always sees the most-recent sender.
pub fn last_sender_for(signum: i32) -> i32 {
    if (1..=64).contains(&signum) {
        SENDER_PID[(signum - 1) as usize].load(Ordering::SeqCst)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_test() -> (
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
        std::sync::MutexGuard<'static, ()>,
    ) {
        // Lock in this order for every lib.rs test. The owner-module tests
        // take only their own lock, so none can clear a seeded store while a
        // lib.rs test is using it.
        (
            TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
            child_watch::TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            host_disposition::MASK_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }

    /// The supervisor reset test and the owner-module tests all mutate these
    /// process globals. A different module's clear must stay excluded while
    /// the supervisor test holds its test guard.
    #[test]
    fn supervisor_test_guard_covers_shared_state_owners() {
        let _lock = lock_test();
        child_watch::clear();
        host_disposition::clear_all();
        child_watch::register(0x6161, 0x5757, 17);
        host_disposition::mark_installed(10);

        let (watch_open, mask_open) = std::thread::spawn(|| {
            let watch_open = match child_watch::TEST_LOCK.try_lock() {
                Ok(_owner_guard) => {
                    child_watch::clear();
                    true
                }
                Err(_) => false,
            };
            let mask_open = match host_disposition::MASK_TEST_LOCK.try_lock() {
                Ok(_owner_guard) => {
                    host_disposition::clear_all();
                    true
                }
                Err(_) => false,
            };
            (watch_open, mask_open)
        })
        .join()
        .expect("owner-lock witness thread panicked");

        let watch_survived = child_watch::is_tracked(0x6161);
        let mask_survived = host_disposition::is_installed(10);
        child_watch::clear();
        host_disposition::clear_all();
        assert_eq!((watch_open, mask_open), (false, false));
        assert!(watch_survived && mask_survived);
    }

    #[test]
    fn single_mask_claim_rechecks_after_drain() {
        let _lock = lock_test();
        clear_proc_pending();
        publish_process_signal(14);
        PROCESS_BOUNDARY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                assert_eq!(take_process_pending(), 14);
            }))
        });
        let claimed = claim_unblocked_pending_for(991, SigBlockMask::NONE);
        let owner = PROC_WAKE_OWNER.load(Ordering::SeqCst);
        let empty = take_pending_event_for(991);
        publish_process_signal(12);
        let peer = take_pending_event_for(992);
        clear_proc_pending();
        assert!(!claimed, "a completed drain leaves nothing to claim");
        assert_eq!(owner, 0, "empty claim cannot hide future events");
        assert_eq!(empty, None);
        assert_eq!(peer.map(|event| event.signum), Some(12));
    }

    #[test]
    fn single_mask_take_rechecks_late_owner() {
        let _lock = lock_test();
        clear_proc_pending();
        publish_process_signal(14);
        PROCESS_BOUNDARY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                assert!(claim_unblocked_pending_for(992, SigBlockMask::NONE));
            }))
        });
        let stolen = take_pending_event_for(991);
        let owned = take_pending_event_for(992);
        clear_proc_pending();
        assert_eq!(stolen, None, "late claimant keeps its continuation custody");
        assert_eq!(owned.map(|event| event.signum), Some(14));
    }

    #[test]
    fn single_mask_async_publication_during_timer_prepare_is_visible() {
        let _lock = lock_test();
        clear_proc_pending();
        let info = PendingTimerInfo {
            id: i32::MIN,
            overrun: i32::MAX,
            value: i64::MIN + 0x12345678,
        };
        TIMER_PREPARED.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                proc_pending_fetch_or(thread_pending_bit(14) | thread_pending_bit(12));
                assert!(has_process_pending());
                assert!(has_unblocked_pending_for(
                    991,
                    SigBlockMask::blocking_all_of(SigSet::EMPTY.with(14).complement())
                ));
                assert!(
                    proc_pending_mask().raw() & thread_pending_bit(14) != 0,
                    "filtered query must see completed async OR even during timer preparation"
                );
            }))
        });
        publish_process_timer_signal(14, Some(info));
        assert_eq!(
            take_pending_event_for(991),
            Some(PendingSignalEvent {
                signum: 12,
                scope: PendingSignalScope::Process,
                origin: PendingSignalOrigin::Host,
            })
        );
        // Timer preparation overlaps Host publication; the retained complete
        // origin admits the timer-before-Host whole-operation order.
        assert_eq!(
            take_pending_event_for(991),
            Some(PendingSignalEvent {
                signum: 14,
                scope: PendingSignalScope::Process,
                origin: PendingSignalOrigin::PosixTimer(info),
            })
        );
        assert_eq!(take_pending_event_for(991), None);
        clear_proc_pending();
    }

    #[test]
    fn single_mask_global_query_sees_async_publish_during_timer_prepare() {
        let _lock = lock_test();
        clear_proc_pending();
        let info = PendingTimerInfo {
            id: i32::MIN,
            overrun: i32::MAX,
            value: i64::MIN + 0x12345678,
        };
        TIMER_PREPARED.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                publish_process_signal(14);
                assert!(
                    has_process_pending(),
                    "completed async event cannot appear globally empty"
                );
                assert_eq!(proc_pending_mask(), SigSet::EMPTY.with(14));
            }))
        });
        publish_process_timer_signal(14, Some(info));
        // Timer preparation overlaps Host publication; the retained complete
        // origin admits the timer-before-Host whole-operation order.
        assert_eq!(
            take_pending_event_for(991),
            Some(PendingSignalEvent {
                signum: 14,
                scope: PendingSignalScope::Process,
                origin: PendingSignalOrigin::PosixTimer(info),
            })
        );
        assert_eq!(take_pending_event_for(991), None);
        clear_proc_pending();
    }

    #[test]
    fn single_mask_two_consumers_keep_full_payload_in_both_completion_orders() {
        let _lock = lock_test();
        let info = PendingTimerInfo {
            id: i32::MIN,
            overrun: i32::MAX,
            value: i64::MIN + 0x12345678,
        };
        let later = PendingTimerInfo {
            id: i32::MAX,
            overrun: i32::MIN,
            value: i64::MAX - 0x23456789,
        };
        for second_first in [false, true] {
            clear_proc_pending();
            publish_process_timer_signal(14, Some(info));
            let mut second = None;
            // Publish the NEW Host after mask removal, before origin reset.
            AFTER_MASK_TAKE_HOST.with(|bits| bits.set(thread_pending_bit(14)));
            let first = take_proc_pending_event_in_after_take(SigSet::EMPTY.complement(), || {
                // Coalescence with the NEW Host retains Host custody.
                publish_process_timer_signal(14, Some(later));
                if second_first {
                    second = take_pending_event_for(992);
                }
            })
            .unwrap();
            if !second_first {
                second = take_pending_event_for(992);
            }
            assert_eq!(
                first,
                PendingSignalEvent {
                    signum: 14,
                    scope: PendingSignalScope::Process,
                    origin: PendingSignalOrigin::PosixTimer(info),
                }
            );
            assert_eq!(
                second,
                Some(PendingSignalEvent {
                    signum: 14,
                    scope: PendingSignalScope::Process,
                    origin: PendingSignalOrigin::Host,
                })
            );
            publish_process_timer_signal(14, Some(later));
            let third = take_pending_event_for(993).unwrap();
            assert_eq!(
                third,
                PendingSignalEvent {
                    signum: 14,
                    scope: PendingSignalScope::Process,
                    origin: PendingSignalOrigin::PosixTimer(later),
                }
            );
            assert_eq!(take_process_pending(), 0);
        }
        clear_proc_pending();
    }

    #[test]
    fn single_mask_prior_14_12_order_and_masked_lowest() {
        let _lock = lock_test();
        clear_proc_pending();
        publish_process_timer_signal(14, None);
        PROCESS_BOUNDARY.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| {
                assert_eq!(proc_pending_mask(), SigSet::EMPTY.with(14));
                publish_process_signal(12);
                assert!(has_unblocked_pending_for(
                    991,
                    SigBlockMask::blocking_all_of(SigSet::EMPTY.with(14).complement())
                ));
            }))
        });
        assert_eq!(take_pending_event_for(991).unwrap().signum, 12);
        publish_process_signal(10);
        assert_eq!(take_pending_in_for(992, SigSet::EMPTY.with(14)), 14);
        assert_eq!(take_process_pending(), 10);
        clear_proc_pending();
    }

    #[test]
    fn single_mask_host_survives_clear_and_full_storage_reuse() {
        let _lock = lock_test();
        clear_proc_pending();
        for signum in 1..=64 {
            let info = PendingTimerInfo {
                id: i32::MIN + signum,
                overrun: i32::MAX - signum,
                value: i64::MIN + i64::from(signum),
            };
            publish_process_timer_signal(signum, Some(info));
            publish_process_timer_signal(signum, None); // first payload wins
        }
        assert_eq!(proc_pending_mask(), SigSet::EMPTY.complement());
        for signum in 1..=64 {
            let event = take_pending_event_for(991).unwrap();
            assert_eq!(event.signum, signum);
            assert_eq!(
                event.origin,
                PendingSignalOrigin::PosixTimer(PendingTimerInfo {
                    id: i32::MIN + signum,
                    overrun: i32::MAX - signum,
                    value: i64::MIN + i64::from(signum),
                })
            );
        }
        proc_pending_fetch_or(u64::MAX);
        for signum in 1..=64 {
            let event = take_pending_event_for(992).unwrap();
            assert_eq!(event.signum, signum);
            assert_eq!(event.origin, PendingSignalOrigin::Host);
        }
        publish_process_timer_signal(14, None);
        AFTER_MASK_CLEAR_HOST.with(|bits| bits.set(thread_pending_bit(14)));
        clear_proc_pending();
        assert_eq!(
            take_pending_event_for(991).unwrap().origin,
            PendingSignalOrigin::Host
        );
        let mut fork_hold = prepare_process_pending_for_fork().hold();
        publish_process_signal(12);
        fork_hold.clear(); // borrowed guard, no nested acquisition
        assert!(!has_process_pending());
        drop(fork_hold); // parent/failure path only; no fork
        for invalid in [i32::MIN, -1, 0, 65, i32::MAX] {
            publish_process_signal(invalid);
            publish_process_timer_signal(invalid, None);
        }
        proc_pending_fetch_or(0);
        assert!(!has_process_pending());
        clear_proc_pending();
    }

    #[test]
    fn single_mask_thread_first_masked_bypass_and_exact_retirement() {
        let _lock = lock_test();
        clear_proc_pending();
        publish_process_signal(14);
        assert!(claim_unblocked_pending_for(991, SigBlockMask::NONE));
        publish_pending_for(992, 12);
        assert!(claim_unblocked_pending_for(992, SigBlockMask::NONE));
        assert_eq!(
            take_pending_event_for(992).unwrap().scope,
            PendingSignalScope::Thread
        );
        assert_eq!(take_pending_event_for(992), None);
        forget_thread(993); // only the exact owner may retire the claim
        assert_eq!(take_pending_event_for(992), None);
        assert_eq!(take_pending_in_for(992, SigSet::EMPTY.with(14)), 14);
        assert_eq!(PROC_WAKE_OWNER.load(Ordering::SeqCst), 0);
        for signum in [LINUX_SIGKILL, LINUX_SIGSTOP] {
            publish_process_signal(signum);
            assert!(claim_unblocked_pending_for(
                991,
                SigBlockMask::blocking_all_of(SigSet::EMPTY.complement())
            ));
            assert_eq!(take_pending_for(991), signum);
        }
        clear_proc_pending();
    }

    #[test]
    fn single_mask_concurrent_owned_results_and_reentrant_wake_after_release() {
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let _lock = lock_test();
        let deadline = Duration::from_secs(5);
        for second_first in [false, true] {
            clear_proc_pending();
            let first_info = PendingTimerInfo {
                id: i32::MIN,
                overrun: i32::MAX,
                value: i64::MIN,
            };
            let second_info = PendingTimerInfo {
                id: i32::MAX,
                overrun: i32::MIN,
                value: i64::MAX,
            };
            publish_process_timer_signal(14, Some(first_info));
            let (owned_tx, owned_rx) = channel();
            let (release_tx, release_rx) = channel();
            let (first_tx, first_rx) = channel();
            let first = std::thread::spawn(move || {
                let event =
                    take_proc_pending_event_in_after_take(SigSet::EMPTY.complement(), || {
                        // This is where a normal caller can wake/reenter. Even a
                        // paused caller holds an owned copy, never origin custody.
                        assert!(PROC_CUSTODY.get().try_lock().is_ok());
                        owned_tx.send(()).unwrap();
                        release_rx.recv_timeout(deadline).unwrap();
                    });
                first_tx.send(event).unwrap();
            });
            owned_rx.recv_timeout(deadline).unwrap();
            // Real normal publication + wake callback: reenter claim/take
            // after timer publication returns, checking release explicitly.
            publish_process_timer_signal(14, Some(second_info));
            assert!(PROC_CUSTODY.get().try_lock().is_ok());
            assert!(claim_unblocked_pending_for(992, SigBlockMask::NONE));
            if !second_first {
                release_tx.send(()).unwrap();
            }
            let first_event = if !second_first {
                Some(first_rx.recv_timeout(deadline).unwrap())
            } else {
                None
            };
            let second_event = take_pending_event_for(992).unwrap();
            assert_eq!(
                second_event.origin,
                PendingSignalOrigin::PosixTimer(second_info)
            );
            if second_first {
                release_tx.send(()).unwrap();
            }
            let first_event = first_event
                .unwrap_or_else(|| first_rx.recv_timeout(deadline).unwrap())
                .unwrap();
            assert_eq!(
                first_event.origin,
                PendingSignalOrigin::PosixTimer(first_info)
            );
            first.join().unwrap();
        }
        clear_proc_pending();
    }

    #[test]
    fn single_mask_normal_timer_and_consumer_share_actual_custody() {
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let _lock = lock_test();
        let deadline = Duration::from_secs(5);
        let info = PendingTimerInfo {
            id: i32::MIN,
            overrun: i32::MAX,
            value: i64::MIN,
        };
        for timer_waiter in [false, true] {
            clear_proc_pending();
            publish_process_timer_signal(14, Some(info));
            let mut custody = lock_process_custody();
            let first =
                take_proc_pending_guarded(SigSet::EMPTY.complement(), &mut custody).unwrap();
            publish_process_signal(14); // async publication never needs custody
            let (blocked_tx, blocked_rx) = channel();
            let (done_tx, done_rx) = channel();
            let worker = std::thread::spawn(move || {
                assert!(matches!(
                    PROC_CUSTODY.get().try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                blocked_tx.send(()).unwrap();
                let event = if timer_waiter {
                    publish_process_timer_signal(14, Some(info));
                    None
                } else {
                    take_pending_event_for(992)
                };
                done_tx.send(event).unwrap();
            });
            blocked_rx.recv_timeout(deadline).unwrap();
            drop(custody);
            let result = done_rx.recv_timeout(deadline).unwrap();
            worker.join().unwrap();
            assert_eq!(first.origin, PendingSignalOrigin::PosixTimer(info));
            let host = if timer_waiter {
                take_pending_event_for(993)
            } else {
                result
            }
            .unwrap();
            assert_eq!(host.signum, 14);
            assert_eq!(host.origin, PendingSignalOrigin::Host);
        }
        clear_proc_pending();
    }

    #[test]
    fn single_mask_empty_paths_and_async_or_do_not_acquire_custody() {
        let _lock = lock_test();
        clear_proc_pending();
        let origins = lock_process_custody();
        assert_eq!(take_pending_event_for(991), None);
        assert!(!claim_unblocked_pending_for(991, SigBlockMask::NONE));
        proc_pending_fetch_or(thread_pending_bit(12) | thread_pending_bit(14));
        assert!(has_process_pending());
        assert!(has_unblocked_pending_for(992, SigBlockMask::NONE));
        assert_eq!(proc_pending_mask(), SigSet::EMPTY.with(12).with(14));
        drop(origins);
        assert_eq!(take_process_pending(), 12);
        assert_eq!(take_process_pending(), 14);
        clear_proc_pending();
    }

    #[test]
    fn pending_bit_basics() {
        let _lock = lock_test();
        assert_eq!(pending_bit(1), Some(1));
        assert_eq!(pending_bit(64), Some(1 << 63));
        assert_eq!(pending_bit(0), None);
        assert_eq!(pending_bit(65), None);
    }

    #[test]
    fn publish_take_thread_pending() {
        let _lock = lock_test();
        forget_thread(4242);
        publish_pending_for(4242, 9);
        publish_pending_for(4242, 17);
        assert!(has_pending_for(4242));
        assert_eq!(lowest_pending_signum_for(4242), 9);
        // The drainer consumes ONE signum per call (lowest-first), not the whole
        // mask at once; reconstruct the published mask from the two takes.
        let taken =
            thread_pending_bit(take_pending_for(4242)) | thread_pending_bit(take_pending_for(4242));
        assert_eq!(taken, pending_bit(9).unwrap() | pending_bit(17).unwrap());
        assert!(!has_pending_for(4242));
        forget_thread(4242);
    }

    #[test]
    fn proc_pending_is_process_global() {
        let _lock = lock_test();
        clear_proc_pending();
        publish_process_signal(15);
        assert!(has_process_pending());
        // `take_process_pending` returns the signum; map it back to its bit.
        let m = thread_pending_bit(take_process_pending());
        assert_eq!(m, pending_bit(15).unwrap());
        assert!(!has_process_pending());
    }

    #[test]
    fn process_timer_metadata_survives_bridge_dequeue_and_standard_coalescing() {
        let _lock = lock_test();
        clear_proc_pending();
        let timer = PendingTimerInfo {
            id: 7,
            overrun: 3,
            value: 0x1234,
        };
        publish_process_timer_signal(14, Some(timer));
        publish_process_signal(14); // coalesces without replacing SI_TIMER
        assert_eq!(
            take_pending_event_for(991),
            Some(PendingSignalEvent {
                signum: 14,
                scope: PendingSignalScope::Process,
                origin: PendingSignalOrigin::PosixTimer(timer),
            })
        );
        assert_eq!(take_pending_event_for(991), None);
        publish_process_timer_signal(14, None);
        assert_eq!(
            take_pending_event_for(991).unwrap().origin,
            PendingSignalOrigin::IntervalTimer
        );
        clear_proc_pending();
    }

    #[test]
    fn process_publish_during_dequeue_remains_pending() {
        let _lock = lock_test();
        clear_proc_pending();
        let timer = PendingTimerInfo {
            id: i32::MIN,
            overrun: i32::MAX,
            value: i64::MIN,
        };
        publish_process_timer_signal(10, Some(timer));
        AFTER_MASK_TAKE_HOST.with(|bits| bits.set(thread_pending_bit(10)));
        let first = take_proc_pending_event_in(SigSet::EMPTY.complement()).unwrap();
        assert_eq!(first.signum, 10);
        assert_eq!(first.origin, PendingSignalOrigin::PosixTimer(timer));
        let next = take_pending_event_for(992).unwrap();
        assert_eq!(next.signum, 10);
        assert_eq!(next.origin, PendingSignalOrigin::Host);
        assert_eq!(take_process_pending(), NO_PENDING_SIGNAL);
        clear_proc_pending();
    }

    #[test]
    fn process_wake_claim_interrupts_only_one_unblocked_waiter() {
        let _lock = lock_test();
        clear_proc_pending();
        publish_process_signal(14);
        assert!(claim_unblocked_pending_for(991, SigBlockMask::NONE));
        assert!(!claim_unblocked_pending_for(992, SigBlockMask::NONE));
        assert_eq!(take_pending_event_for(992), None);
        assert_eq!(take_pending_event_for(991).unwrap().signum, 14);
        clear_proc_pending();
    }

    #[test]
    fn non_consuming_pending_probe_cannot_withhold_process_signal() {
        let _lock = lock_test();
        clear_proc_pending();
        publish_process_signal(14);
        assert!(has_unblocked_pending_for(991, SigBlockMask::NONE));
        assert_eq!(
            take_pending_event_for(992).map(|event| event.signum),
            Some(14),
            "a query by a live non-consumer cannot reserve delivery"
        );
        clear_proc_pending();
    }

    #[test]
    fn retiring_an_interrupted_non_consumer_releases_process_claim() {
        let _lock = lock_test();
        clear_proc_pending();
        publish_process_signal(14);
        assert!(claim_unblocked_pending_for(991, SigBlockMask::NONE));
        assert!(!claim_unblocked_pending_for(992, SigBlockMask::NONE));
        forget_thread(991);
        assert!(claim_unblocked_pending_for(992, SigBlockMask::NONE));
        assert_eq!(take_pending_event_for(992).unwrap().signum, 14);
        clear_proc_pending();
    }

    #[test]
    fn thread_timer_metadata_belongs_to_exact_tid() {
        let _lock = lock_test();
        let info = PendingTimerInfo {
            id: 8,
            overrun: 0,
            value: 0x5678,
        };
        publish_pending_timer_for(987_654, 10, info);
        assert_eq!(take_pending_event_for(987_655), None);
        assert_eq!(
            take_pending_event_for(987_654).unwrap().origin,
            PendingSignalOrigin::PosixTimer(info)
        );
        clear_thread_pending();
    }

    /// The NEUTRAL clears the KVM (and HVF) `reset_after_supervisor_fork` runs in
    /// the interactive-`--tty` runtime child: publish thread-pending,
    /// process-pending, a mirrored host disposition, and a child-exit watch, then
    /// run exactly those neutral clears and assert every store is empty again — so
    /// the child does not inherit the supervisor's stale state. (The pump-guard
    /// re-arm is platform GLUE, unit-tested at its own layer.)
    #[test]
    fn supervisor_fork_neutral_clears_empty_all_state() {
        let _lock = lock_test();
        let tid = 0x5757_i32;
        // Seed each neutral store.
        publish_pending_for(tid, 10); // thread-pending (SIGUSR1)
        publish_process_signal(15); // process-pending (SIGTERM)
        host_disposition::mark_installed(10); // mirrored host disposition
        child_watch::register(0x6161, tid, 17); // a watched child-exit
        assert!(has_pending_for(tid));
        assert!(has_process_pending());
        assert!(host_disposition::is_installed(10));
        assert!(child_watch::is_tracked(0x6161));

        // The exact neutral clears reset_after_supervisor_fork performs.
        clear_thread_pending();
        clear_proc_pending();
        host_disposition::clear_all();
        child_watch::clear();

        assert!(!has_pending_for(tid), "thread-pending must be empty");
        assert!(!has_process_pending(), "process-pending must be empty");
        assert!(
            !host_disposition::is_installed(10),
            "mirrored host disposition mask must be empty"
        );
        assert!(
            !child_watch::is_tracked(0x6161),
            "child-exit watches must be empty"
        );
    }

    /// The tid-hint fast path must never hide a published signal — including
    /// across drains that empty a slot a COLLIDING tid (same `tid % 64` bit)
    /// still needs, and across publish-after-drain cycles (a sticky-clear hint
    /// would strand the re-published signal).
    #[test]
    fn tid_hint_fast_path_never_hides_published_signal() {
        let _lock = lock_test();
        let tid = 0x7a11_i32;
        let colliding = tid + 64; // same hint bit
        forget_thread(tid);
        forget_thread(colliding);

        // Publish to both colliding tids; drain one — the OTHER must survive
        // the recompute (its bit is shared).
        publish_pending_for(tid, 10);
        publish_pending_for(colliding, 12);
        assert_eq!(take_pending_for(tid), 10);
        assert!(thread_pending_has(colliding), "collision bit must survive");
        assert_eq!(take_pending_for(colliding), 12);
        assert!(!thread_pending_has(colliding));

        // Publish after a full drain: the hint must be re-set, not sticky-clear.
        publish_pending_for(tid, 14);
        assert!(thread_pending_has(tid));
        assert_eq!(take_pending_for(tid), 14);
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);

        // The set-restricted taker honours the hint the same way.
        publish_pending_for(tid, 10);
        assert_eq!(
            take_pending_in_for(tid, SigSet::EMPTY.with(10)),
            10,
            "wait-set take must see the re-published signal"
        );
        assert_eq!(
            take_pending_in_for(tid, SigSet::EMPTY.with(10)),
            NO_PENDING_SIGNAL
        );
        forget_thread(tid);
        forget_thread(colliding);
    }

    /// Concurrent publish/take stress across the hint: every published signal
    /// is eventually taken by its target (no lost delivery through the
    /// lock-free fast path). Bounded, deterministic outcome.
    #[test]
    fn tid_hint_concurrent_publish_take_loses_nothing() {
        let _lock = lock_test();
        let tid = 0x7b22_i32;
        forget_thread(tid);
        const ROUNDS: usize = 2000;
        let publisher = std::thread::spawn(move || {
            for _ in 0..ROUNDS {
                publish_pending_for(tid, 10);
                while thread_pending_has(tid) {
                    std::thread::yield_now();
                }
            }
        });
        let mut taken = 0usize;
        while taken < ROUNDS {
            if take_pending_for(tid) == 10 {
                taken += 1;
            } else {
                std::thread::yield_now();
            }
        }
        publisher.join().expect("publisher thread");
        assert_eq!(taken, ROUNDS);
        assert_eq!(take_pending_for(tid), NO_PENDING_SIGNAL);
        forget_thread(tid);
    }

    /// Test helper: the lowest pending signum for `tid` WITHOUT consuming it
    /// (the production drainers are consuming; there is no peek-by-tid in the
    /// neutral API because no backend needs one).
    fn lowest_pending_signum_for(tid: i32) -> i32 {
        let guard = lock_thread_pending();
        guard
            .as_ref()
            .and_then(|map| map.get(&tid))
            .filter(|&&mask| mask != 0)
            .map(|&mask| lowest_pending_signum(SigSet::from_raw(mask)))
            .unwrap_or(NO_PENDING_SIGNAL)
    }
}
