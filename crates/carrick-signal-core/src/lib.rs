//! Platform-NEUTRAL signal pending bookkeeping, shared by every backend: the
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
pub mod host_disposition;
pub mod host_glue;
pub mod xsig;

pub use backend::HostSignalGlue;

use carrick_abi::{SigBlockMask, SigSet};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// "No signal pending" sentinel. Chosen as `0` because Linux's
/// `kill(pid, 0)` is documented as the null-signal probe; no real
/// delivery ever uses signum 0.
pub const NO_PENDING_SIGNAL: i32 = 0;

/// Bit for `signum` in a u64 pending mask (`signum-1`), or `None` if out of 1..=64.
pub fn pending_bit(signum: i32) -> Option<u64> {
    (1..=64).contains(&signum).then(|| 1u64 << (signum - 1))
}

/// `THREAD_PENDING` bit for `signum` (bit `signum-1`), or 0 if out of range.
pub fn thread_pending_bit(signum: i32) -> u64 {
    if (1..=64).contains(&signum) {
        1u64 << (signum - 1)
    } else {
        0
    }
}

/// Lowest pending signum in a pending set (`NO_PENDING_SIGNAL` when empty;
/// callers historically ensured non-empty).
pub fn lowest_pending_signum(mask: SigSet) -> i32 {
    mask.lowest_signum().unwrap_or(NO_PENDING_SIGNAL)
}

/// Whether `signum` is deliverable given a temporary `block_mask`.
/// SIGKILL(9)/SIGSTOP(19) can never be blocked, so they are always deliverable
/// even if they are in `block_mask`.
pub fn signal_unblocked_by_mask(signum: i32, block_mask: SigBlockMask) -> bool {
    let bit = thread_pending_bit(signum);
    if bit == 0 {
        return false;
    }
    let always_deliverable = thread_pending_bit(LINUX_SIGKILL) | thread_pending_bit(LINUX_SIGSTOP);
    bit & (!block_mask.raw() | always_deliverable) != 0
}

/// Linux SIGKILL — can never be caught, blocked, or ignored.
const LINUX_SIGKILL: i32 = 9;
/// Linux SIGSTOP — can never be caught, blocked, or ignored.
const LINUX_SIGSTOP: i32 = 19;

/// Process-directed pending signals: an `AtomicU64` BITMASK (bit `signum-1`),
/// set from an async host signal handler via a lock-free `fetch_or`. A bitmask —
/// not a single i32 slot — so distinct process-directed signums pending at once
/// all survive (a single slot dropped all but the last; LTP kill10's master,
/// counting acks sent as SIGUSR1/SIGUSR2/SIGQUIT, hung when one was clobbered).
/// Same-signum repeats still coalesce (standard-signal semantics); RT-signal
/// queue depth lives in the dispatcher's `rt_pending_counts`.
static PROC_PENDING: AtomicU64 = AtomicU64::new(0);

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

/// Set the thread-directed pending `signum` bit for `tid`. This is the pure
/// store half of a thread-directed publish; backends layer their own wakeups
/// (the HVF self-pipe / per-thread pipe; the KVM vCPU kick) around the call.
pub fn publish_pending_for(tid: i32, signum: i32) {
    let bit = thread_pending_bit(signum);
    if bit != 0 {
        let mut guard = lock_thread_pending();
        let map = guard.get_or_insert_with(HashMap::new);
        *map.entry(tid).or_insert(0) |= bit;
    }
}

/// Pop the lowest pending process-directed signum from `PROC_PENDING` that is
/// also in `wait_set` (pass `SigSet::EMPTY.complement()` to accept any).
/// Returns `0` if none. `take_pending_for` can run concurrently on every vCPU
/// kicked for one process-directed signal, so draining the bit must be
/// compare/exchange based: a `load` + `compare_exchange` lets multiple threads
/// observe and deliver the same pending bit at most once total. The store is a
/// raw `AtomicU64` in wire form (bit `signum-1`); the typed set converts at the
/// atomic load/CAS boundary.
fn take_proc_pending_in(wait_set: SigSet) -> i32 {
    loop {
        let mask = PROC_PENDING.load(Ordering::SeqCst);
        let candidates = mask & wait_set.raw();
        if candidates == 0 {
            return NO_PENDING_SIGNAL;
        }
        let signum = lowest_pending_signum(SigSet::from_raw(candidates));
        let bit = thread_pending_bit(signum);
        let next = mask & !bit;
        if PROC_PENDING
            .compare_exchange(mask, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return signum;
        }
    }
}

/// Drain the signal deliverable to `tid`: a thread-directed one for this tid
/// takes priority, otherwise the process-directed mask (lowest signum first).
/// Returns `0` (`NO_PENDING_SIGNAL`) if neither is set. This is the single point
/// of consumption (called under the dispatcher lock in `deliver_pending_signal`).
pub fn take_pending_for(tid: i32) -> i32 {
    {
        let mut guard = lock_thread_pending();
        if let Some(map) = guard.as_mut()
            && let Some(mask) = map.get_mut(&tid)
            && *mask != 0
        {
            let signum = lowest_pending_signum(SigSet::from_raw(*mask));
            *mask &= *mask - 1; // clear the lowest set bit
            if *mask == 0 {
                map.remove(&tid);
            }
            return signum;
        }
    }
    take_proc_pending_in(SigSet::EMPTY.complement())
}

/// Drain a signal pending for `tid` only if it intersects `wait_set`. Used by
/// `rt_sigtimedwait`: signals outside the waited set must remain pending for
/// normal delivery instead of being consumed and requeued.
pub fn take_pending_in_for(tid: i32, wait_set: SigSet) -> i32 {
    {
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
                }
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
    let mut guard = lock_thread_pending();
    guard
        .as_mut()
        .and_then(|map| map.get(&tid))
        .is_some_and(|&mask| mask != 0)
}

/// True iff a thread-directed signal for `tid` is pending AND deliverable given
/// `block_mask`. A blocked signal does not count, except SIGKILL/SIGSTOP which
/// can never be blocked.
pub fn thread_pending_deliverable(tid: i32, block_mask: SigBlockMask) -> bool {
    let always_deliverable = thread_pending_bit(LINUX_SIGKILL) | thread_pending_bit(LINUX_SIGSTOP);
    let mut guard = lock_thread_pending();
    guard
        .as_mut()
        .and_then(|map| map.get(&tid))
        .is_some_and(|&mask| mask & (!block_mask.raw() | always_deliverable) != 0)
}

/// Is a signal deliverable to `tid` pending? True for a thread-directed signal
/// for this tid OR any process-directed signal. The pure (no-glue) form used by
/// the KVM backend; the HVF backend wraps it to also peek its xsignal ring.
pub fn has_pending_for(tid: i32) -> bool {
    if PROC_PENDING.load(Ordering::SeqCst) != 0 {
        return true;
    }
    thread_pending_has(tid)
}

/// Like [`has_pending_for`], but a signal blocked by `block_mask` does NOT
/// count as deliverable-for-waking. SIGKILL/SIGSTOP can't be blocked, matching
/// the kernel. The pure (no-glue) form used by the KVM backend; the HVF backend
/// wraps it to also peek its xsignal ring.
pub fn has_unblocked_pending_for(tid: i32, block_mask: SigBlockMask) -> bool {
    let always_deliverable = thread_pending_bit(LINUX_SIGKILL) | thread_pending_bit(LINUX_SIGSTOP);
    let deliverable = |mask: u64| mask & (!block_mask.raw() | always_deliverable) != 0;
    if deliverable(PROC_PENDING.load(Ordering::SeqCst)) {
        return true;
    }
    thread_pending_deliverable(tid, block_mask)
}

/// True iff any process-directed signal is pending.
pub fn has_process_pending() -> bool {
    PROC_PENDING.load(Ordering::SeqCst) != 0
}

/// Current process-directed pending set.
pub fn proc_pending_mask() -> SigSet {
    SigSet::from_raw(PROC_PENDING.load(Ordering::SeqCst))
}

/// Atomically OR `bit` into the process-directed pending mask. Lock-free, so
/// callable from an async host signal handler. Deliberately kept in raw wire
/// form (bit `signum-1`, from [`pending_bit`]/[`thread_pending_bit`]): this is
/// the async-signal-safe single-bit store op at the atomic boundary.
pub fn proc_pending_fetch_or(bit: u64) {
    PROC_PENDING.fetch_or(bit, Ordering::SeqCst);
}

/// Publish a process-directed `signum` into the pending mask (the pure store
/// half; the lowest pending signum is later drained by `take_pending_for`).
pub fn publish_process_signal(signum: i32) {
    let bit = thread_pending_bit(signum);
    if bit != 0 {
        PROC_PENDING.fetch_or(bit, Ordering::SeqCst);
    }
}

/// Take (drain) the lowest process-directed pending signum, or `0` if none.
pub fn take_process_pending() -> i32 {
    take_proc_pending_in(SigSet::EMPTY.complement())
}

/// Clear the process-directed pending mask (fork / supervisor-fork reinit).
pub fn clear_proc_pending() {
    PROC_PENDING.store(0, Ordering::SeqCst);
}

/// Drop any thread-directed pending entry for `tid` (called when a guest thread
/// exits so a recycled tid never inherits a stale signal). A forked child also
/// clears the whole table via [`clear_thread_pending`].
pub fn forget_thread(tid: i32) {
    if let Some(map) = lock_thread_pending().as_mut() {
        map.remove(&tid);
    }
}

/// Clear the entire thread-directed pending table (fork reinit: the child is
/// single-threaded, so inherited sibling-directed entries are stale).
pub fn clear_thread_pending() {
    if let Some(map) = lock_thread_pending().as_mut() {
        map.clear();
    }
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
    #[test]
    fn pending_bit_basics() {
        assert_eq!(pending_bit(1), Some(1));
        assert_eq!(pending_bit(64), Some(1 << 63));
        assert_eq!(pending_bit(0), None);
        assert_eq!(pending_bit(65), None);
    }

    #[test]
    fn publish_take_thread_pending() {
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
        clear_proc_pending();
        publish_process_signal(15);
        assert!(has_process_pending());
        // `take_process_pending` returns the signum; map it back to its bit.
        let m = thread_pending_bit(take_process_pending());
        assert_eq!(m, pending_bit(15).unwrap());
        assert!(!has_process_pending());
    }

    /// The NEUTRAL clears the KVM (and HVF) `reset_after_supervisor_fork` runs in
    /// the interactive-`--tty` runtime child: publish thread-pending,
    /// process-pending, a mirrored host disposition, and a child-exit watch, then
    /// run exactly those neutral clears and assert every store is empty again — so
    /// the child does not inherit the supervisor's stale state. (The pump-guard
    /// re-arm is platform GLUE, unit-tested at its own layer.)
    #[test]
    fn supervisor_fork_neutral_clears_empty_all_state() {
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
