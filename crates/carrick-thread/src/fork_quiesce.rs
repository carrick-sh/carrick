//! Stop-the-world barriers for mutating shared guest/VM state while sibling
//! vCPU threads run.
//!
//! THEORY OF OPERATION
//!
//! `fork(2)` and guest page-table edits share one hard problem: a single host
//! thread must mutate state that every other guest vCPU thread can observe, and
//! POSIX `fork` only carries the calling thread into the child. This module
//! provides two distinct Pause-Modify-Resume barriers for the two cases. The
//! shared mechanic: the acting thread raises a `quiescing` flag, every OTHER
//! thread checks it at a LOCK-SAFE point at the top of its run loop and parks,
//! the acting thread waits until the others have parked (or left guest), does
//! its mutation, then lowers the flag and releases them. Blocking waits
//! ([`crate::thread`] futex, `crate::io_wait`) OR [`is_quiescing`] into their
//! wake predicate so a parked thread returns (a spurious EINTR) and reaches the
//! run-loop-top barrier rather than re-parking and missing the quiesce.
//!
//! The two barriers differ in WHAT they do to siblings:
//!
//!   * [`QuiesceBarrier`] (fork): the child must inherit NO carrick lock held by
//!     a thread that won't exist in it, and NO HVF VM topology mid-mutation. So
//!     siblings fully quiesce (release their vCPUs) before `libc::fork`, and the
//!     VM is torn down and rebuilt around the fork. The count it waits on comes
//!     from the `crate::vcpu_kick` kicker's LIVE-vCPU count, NOT the thread
//!     registry: a thread that has a tid but hasn't built its vCPU yet must not
//!     be awaited (it would never reach the barrier). `try_begin_fork`
//!     serializes forks via a CAS flag (not a held guard) so the flag survives
//!     `libc::fork` cleanly and the child clears it. [`topology_lock`] separately
//!     serializes a sibling building its vCPU against a fork destroying the VM,
//!     so a vCPU is never created in the `hv_vm_destroy` window (which would be
//!     HV_BUSY) — and a being-born thread holding it is NOT yet kicker-registered,
//!     so the fork's quiesce never waits on it: no deadlock.
//!
//!   * [`PtQuiesce`] (page-table edits): carrick edits the guest's stage-1 tables
//!     from the HOST while sibling vCPUs run (`mprotect`/`PROT_NONE`/`munmap`); a
//!     sibling walking a block mid-structural-change can fault. Here siblings
//!     KEEP their vCPUs and merely park out-of-guest. The editor waits until no
//!     sibling is in-guest — tracked by the kicker's per-vCPU `in_guest` flags,
//!     not a count — then edits, then resumes. [`PtQuiesce::pause_guard`] mints an
//!     RAII guard so the resume fires on every exit path of the editing syscall,
//!     including `?`-propagated errors.
// INVARIANT: every `.unwrap()` in this module is on a std::sync Mutex/Condvar
// guard. `lock()`/`wait()` only return `Err` on poisoning — a thread panicking
// while holding the guard — which cannot occur in this no-panic codebase. The
// allow is module-scoped because every lock site shares the identical
// invariant; a per-line allow would be pure noise.
#![allow(clippy::unwrap_used)]
use std::cell::Cell;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, TryLockError};
use std::time::{Duration, Instant};

// No-op USDT probe stubs. The real probes live in carrick-vmm-hvf's probes module;
// carrick-thread must not depend on that crate. These probe calls are
// observability-only (they do not gate behavior): replacing them with no-ops
// changes nothing except traceability.
mod probes {
    pub fn pt_pause_end(_tid: i32) {}
}

/// Process-wide barrier (one HVF VM per process). Reachable from the run loop,
/// `handle_fork`, AND the blocking-wait predicates (futex / io_wait) so a parked
/// thread returns to its run-loop top when a quiesce begins.
pub fn barrier() -> &'static QuiesceBarrier {
    static B: OnceLock<QuiesceBarrier> = OnceLock::new();
    B.get_or_init(QuiesceBarrier::new)
}

/// True while a fork quiesce is in progress. Blocking waits OR this into their
/// wake predicate so they return (spurious EINTR) and reach the run-loop-top
/// barrier instead of re-parking.
pub fn is_quiescing() -> bool {
    barrier().is_quiescing()
}

/// Serializes HVF VM-topology mutations: a sibling thread building its vCPU vs.
/// a fork tearing the VM down and rebuilding it. Both hold this for the
/// duration of their critical section, so a vCPU can never be created in the
/// window where the forker calls `hv_vm_destroy` (which would be HV_BUSY), and
/// a thread born during a fork waits and then builds in the *rebuilt* VM. A
/// being-born thread holding this lock is NOT yet in the vCPU kicker, so the
/// fork's quiesce (which waits only on kicker-registered vCPUs) never waits on
/// it — no deadlock.
pub fn topology_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

thread_local! {
    /// How many topology-lock guards THIS thread currently holds.
    ///
    /// The lock excludes *threads*, so a thread that already owns it has by
    /// definition already established the invariant it protects and must be
    /// allowed to re-enter. Before this counter existed, re-entry blocked on a
    /// non-reentrant `Mutex` and wedged the carrier forever at 0% CPU: a failed
    /// alias install under `AliasMap` (held across the whole install by the
    /// vCPU loop) ran a cleanup path that re-acquired the same lock as
    /// `AliasUnmap`. That turned a recoverable `ENOMEM` into an unkillable
    /// hang, which is the worst possible failure mode.
    static TOPOLOGY_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// True while the calling thread already owns the topology lock.
fn topology_held_by_current_thread() -> bool {
    TOPOLOGY_DEPTH.with(|depth| depth.get() > 0)
}

/// Fail-closed executor-boundary observation for the current owner pthread.
///
/// A persistent executor may be reused only after every topology guard has
/// unwound. This is intentionally an observation rather than a reset: clearing
/// a live guard would sever the depth from the mutex authority it describes.
pub fn topology_depth_is_zero_for_executor_boundary() -> bool {
    TOPOLOGY_DEPTH.with(|depth| depth.get() == 0)
}

fn enter_topology_depth() {
    TOPOLOGY_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
}

/// RAII topology-lock guard that emits a typed release event on every exit
/// path. The guard is `None` for a re-entrant acquisition, which owns a depth
/// count but not the mutex, so only the OUTERMOST guard releases it. The
/// additional fields are observability-only.
pub struct TopologyLockGuard {
    _guard: Option<MutexGuard<'static, ()>>,
    operation: carrick_observability::probes::HvpatchTopologyOperation,
    guest_pid: i32,
    guest_tid: i32,
    acquired_at: Instant,
}

fn topology_elapsed_ns(started: Instant) -> u64 {
    started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
}

fn emit_topology_lock(
    operation: carrick_observability::probes::HvpatchTopologyOperation,
    phase: carrick_observability::probes::HvpatchTopologyPhase,
    guest_pid: i32,
    guest_tid: i32,
    elapsed_ns: u64,
) {
    carrick_observability::probes::hvpatch_topology_lock(
        carrick_observability::probes::HvpatchTopologyLock::new(
            operation, phase, guest_pid, guest_tid, elapsed_ns,
        ),
    );
}

impl Drop for TopologyLockGuard {
    fn drop(&mut self) {
        // Drop the depth before `_guard` releases the mutex, so the counter is
        // never observed as held by a thread that no longer owns it.
        TOPOLOGY_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        emit_topology_lock(
            self.operation,
            carrick_observability::probes::HvpatchTopologyPhase::Released,
            self.guest_pid,
            self.guest_tid,
            topology_elapsed_ns(self.acquired_at),
        );
    }
}

/// Acquire the process-wide topology mutex and emit request/wait/release
/// records carrying the Linux guest identity responsible for the mutation.
pub fn acquire_topology_lock(
    operation: carrick_observability::probes::HvpatchTopologyOperation,
    guest_pid: i32,
    guest_tid: i32,
) -> TopologyLockGuard {
    let requested_at = Instant::now();
    emit_topology_lock(
        operation,
        carrick_observability::probes::HvpatchTopologyPhase::Requested,
        guest_pid,
        guest_tid,
        0,
    );
    // A thread that already owns the lock re-enters without touching the mutex;
    // blocking on it here would deadlock the carrier against itself.
    let guard = if topology_held_by_current_thread() {
        None
    } else {
        Some(
            topology_lock()
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        )
    };
    enter_topology_depth();
    emit_topology_lock(
        operation,
        carrick_observability::probes::HvpatchTopologyPhase::Acquired,
        guest_pid,
        guest_tid,
        topology_elapsed_ns(requested_at),
    );
    TopologyLockGuard {
        _guard: guard,
        operation,
        guest_pid,
        guest_tid,
        acquired_at: Instant::now(),
    }
}

/// Try the process-wide topology mutex without blocking. A contended attempt
/// emits `TryMiss` and returns `None`; a successful attempt returns the same
/// release-reporting guard as [`acquire_topology_lock`].
pub fn try_acquire_topology_lock(
    operation: carrick_observability::probes::HvpatchTopologyOperation,
    guest_pid: i32,
    guest_tid: i32,
) -> Option<TopologyLockGuard> {
    let requested_at = Instant::now();
    emit_topology_lock(
        operation,
        carrick_observability::probes::HvpatchTopologyPhase::Requested,
        guest_pid,
        guest_tid,
        0,
    );
    let guard = if topology_held_by_current_thread() {
        None
    } else {
        match topology_lock().try_lock() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                emit_topology_lock(
                    operation,
                    carrick_observability::probes::HvpatchTopologyPhase::TryMiss,
                    guest_pid,
                    guest_tid,
                    topology_elapsed_ns(requested_at),
                );
                return None;
            }
        }
    };
    enter_topology_depth();
    emit_topology_lock(
        operation,
        carrick_observability::probes::HvpatchTopologyPhase::Acquired,
        guest_pid,
        guest_tid,
        topology_elapsed_ns(requested_at),
    );
    Some(TopologyLockGuard {
        _guard: guard,
        operation,
        guest_pid,
        guest_tid,
        acquired_at: Instant::now(),
    })
}

#[cfg(test)]
mod topology_probe_tests {
    use super::*;
    use carrick_observability::probes::HvpatchTopologyOperation;

    /// True iff a FRESH thread cannot take the process-wide topology mutex.
    fn excluded_from_another_thread() -> bool {
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    try_acquire_topology_lock(HvpatchTopologyOperation::VmRelease, 41, 43).is_none()
                })
                .join()
                .expect("probe thread")
        })
    }

    // One test, because every case here contends for the SAME process-wide
    // mutex; splitting them lets the harness run them concurrently and they
    // then observe each other's guards rather than their own.
    #[test]
    fn topology_guard_excludes_other_threads_and_re_enters_on_the_owning_one() {
        let guard = acquire_topology_lock(HvpatchTopologyOperation::InProcessFork, 41, 42);
        // The lock excludes THREADS, so contention must be observed from a
        // different thread — asking on the owning thread is re-entry, not
        // contention.
        assert!(
            excluded_from_another_thread(),
            "try acquisition must report contention while a typed guard is live"
        );
        drop(guard);
        assert!(
            !excluded_from_another_thread(),
            "typed guard drop must release the shared topology mutex"
        );

        // A failed alias install re-enters this lock from its cleanup path
        // while the vCPU loop still holds it for the enclosing AliasMap. When
        // re-entry blocked, the carrier wedged forever at 0% CPU instead of
        // lowering the failure to a guest ENOMEM.
        let outer = acquire_topology_lock(HvpatchTopologyOperation::AliasMap, 7, 7);
        let inner = acquire_topology_lock(HvpatchTopologyOperation::AliasUnmap, 7, 7);
        let reentrant_try = try_acquire_topology_lock(HvpatchTopologyOperation::VmRelease, 7, 7);
        assert!(
            reentrant_try.is_some(),
            "re-entry must also be granted through the non-blocking door"
        );
        drop(reentrant_try);
        drop(inner);
        assert!(
            excluded_from_another_thread(),
            "an inner guard drop must NOT release the mutex the outer guard owns"
        );
        drop(outer);
        assert!(
            !excluded_from_another_thread(),
            "the outermost guard drop must release the mutex process-wide"
        );
    }
}

fn exec_owner() -> &'static AtomicI32 {
    static OWNER: AtomicI32 = AtomicI32::new(0);
    &OWNER
}

/// Count of threads currently running a POST-UNREGISTER exit cleanup
/// (`handle_thread_exit` and the sibling-bootstrap failure paths). The fork
/// quiesce CANNOT see these threads: an exiting thread never parks at the
/// barrier — it drops out of the kicker so the forker stops waiting on it —
/// but it then mutates process-global state (the host-signal pending table,
/// the dispatcher's signal-state map) AFTER the forker's count is satisfied.
/// If `libc::fork` lands inside that window the CHILD inherits a HELD mutex
/// whose owner does not exist in it and deadlocks on first touch (observed:
/// the vfork child wedged forever in `migrate_thread_signal_state` →
/// `parking_lot lock_slow` under go-os_exec TestConcurrentExec on KVM).
/// The forker waits for this count to reach 0 (bounded) just before forking.
static EXIT_CLEANUPS: AtomicI32 = AtomicI32::new(0);

/// RAII token covering a thread's post-unregister exit cleanup. Acquire BEFORE
/// `kicker.unregister` (so there is no instant where the thread is invisible
/// to both the quiesce count and this gate) and hold until every touch of
/// process-global state is done. Acquisition is a plain atomic increment — it
/// NEVER blocks, so an exiting thread can never deadlock against a forker
/// that holds the topology lock or the quiesce barrier.
pub struct ExitCleanupGuard(());

impl Drop for ExitCleanupGuard {
    fn drop(&mut self) {
        EXIT_CLEANUPS.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn begin_exit_cleanup() -> ExitCleanupGuard {
    EXIT_CLEANUPS.fetch_add(1, Ordering::SeqCst);
    ExitCleanupGuard(())
}

/// Number of in-flight exit cleanups (the forker's pre-fork wait predicate).
pub fn exit_cleanups_in_flight() -> i32 {
    EXIT_CLEANUPS.load(Ordering::SeqCst)
}

/// Mark that `owner_tid` is replacing the thread group via execve(2).
///
/// Unlike fork quiesce, sibling threads do not park and rebuild: Linux exec
/// terminates every other task in the thread group. Low-level wait paths use
/// this marker as an interrupt predicate so they can return to the run-loop top
/// and exit cooperatively before the execing thread destroys the HVF VM.
pub fn begin_exec_replacement(owner_tid: carrick_hal::ThreadId) {
    exec_owner().store(owner_tid.raw(), Ordering::SeqCst);
}

/// CAS-claim the exec-replacement marker. The native exec teardown raises it
/// BEFORE serializing on the fork token: exec must WIN against a token holder
/// that cannot make progress on its own — a vfork-suspended leader (Linux
/// kills a vfork-waiting thread during a sibling's execve) or a forker
/// mid-quiesce (its drain aborts on this flag). Returns false when another
/// thread's execve already owns the group; the caller retires. The HVF path
/// keeps the plain [`begin_exec_replacement`], serialized by its topology
/// lock.
pub fn try_begin_exec_replacement(owner_tid: carrick_hal::ThreadId) -> bool {
    exec_owner()
        .compare_exchange(0, owner_tid.raw(), Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub fn end_exec_replacement() {
    exec_owner().store(0, Ordering::SeqCst);
}

pub fn exec_replacing_other_thread(tid: carrick_hal::ThreadId) -> bool {
    let owner = exec_owner().load(Ordering::SeqCst);
    owner != 0 && owner != tid.raw()
}

#[derive(Debug)]
pub struct QuiesceBarrier {
    quiescing: AtomicBool,
    forking: AtomicBool,
    paused: Mutex<usize>,
    cv: Condvar,
}

impl Default for QuiesceBarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl QuiesceBarrier {
    pub fn new() -> Self {
        Self {
            quiescing: AtomicBool::new(false),
            forking: AtomicBool::new(false),
            paused: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    /// Serialize forks: at most one quiesce/fork at a time. Returns false if
    /// another fork is in progress (caller returns EAGAIN; the guest retries,
    /// and meanwhile this thread parks at the barrier the other fork raised).
    /// CAS-based (not a held guard) so the flag survives `libc::fork` cleanly —
    /// the child clears it via `end_fork`.
    pub fn try_begin_fork(&self) -> bool {
        self.forking
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Release the fork serialization (every handle_fork exit path).
    pub fn end_fork(&self) {
        self.forking.store(false, Ordering::SeqCst);
    }

    /// Step 1 (forking thread): raise the quiesce flag. The caller then wakes
    /// the other threads (kick in-guest vCPUs + notify blocked waiters) and
    /// calls `wait_quiesced`. Split from the wait so the wakes happen between —
    /// a thread woken by the kick/notify must observe `is_quiescing()==true` at
    /// the run-loop top, so the flag MUST be raised before the wakes.
    pub fn set_quiescing(&self) {
        self.quiescing.store(true, Ordering::SeqCst);
    }

    /// Step 2 (forking thread): wait until `others` threads have parked at the
    /// barrier, or `timeout`. Returns false on timeout (caller aborts the fork
    /// with EAGAIN and calls `end_quiesce`).
    pub fn wait_quiesced(&self, others: usize, timeout: Duration) -> bool {
        if others == 0 {
            return true;
        }
        let deadline = Instant::now() + timeout;
        let mut paused = self.paused.lock().unwrap();
        while *paused < others {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (g, res) = self.cv.wait_timeout(paused, deadline - now).unwrap();
            paused = g;
            if res.timed_out() && *paused < others {
                return false;
            }
        }
        true
    }

    /// Is a quiesce in progress? Cheap; checked at the run-loop top.
    pub fn is_quiescing(&self) -> bool {
        self.quiescing.load(Ordering::SeqCst)
    }

    /// Number of threads currently parked at the barrier (diagnostic).
    pub fn paused_count(&self) -> usize {
        *self.paused.lock().unwrap()
    }

    /// Called by every OTHER thread at the lock-safe run-loop top. If a quiesce
    /// is in progress, register as paused and block until it ends.
    pub fn park_if_quiescing(&self) {
        if !self.is_quiescing() {
            return;
        }
        let mut paused = self.paused.lock().unwrap();
        *paused += 1;
        self.cv.notify_all(); // wake the forking thread's count-wait
        while self.quiescing.load(Ordering::SeqCst) {
            paused = self.cv.wait(paused).unwrap();
        }
        *paused -= 1;
    }

    /// Called by the forking thread (parent path, child path, or timeout abort)
    /// to lower the flag and release the parked threads.
    pub fn end_quiesce(&self) {
        self.quiescing.store(false, Ordering::SeqCst);
        let _g = self.paused.lock().unwrap();
        self.cv.notify_all();
    }

    /// Hold the barrier's internal mutex ACROSS `libc::fork`.
    ///
    /// A sibling that parks for a fork drops out of the kicker count FIRST
    /// (`release_and_park_vcpu_for_fork` unregisters, then parks), so the
    /// forker can observe "all quiesced" while a sibling is still INSIDE
    /// [`Self::park_if_quiescing`]'s lock-increment-wait window — HOLDING this
    /// mutex. If `libc::fork` lands in that window, the child inherits the
    /// mutex locked by a thread that does not exist in it and deadlocks at its
    /// own `end_quiesce` (captured live: a KVM vfork child of go-os_exec wedged
    /// forever in `QuiesceBarrier::end_quiesce` → `Mutex::lock_contended`).
    /// Holding the mutex across the fork excludes that window by mutual
    /// exclusion: at the fork instant the FORKING thread owns it, and the
    /// forking thread is the one thread that survives into the child, so both
    /// sides can (and must) release it. Callers drop the guard immediately
    /// after the fork returns, BEFORE touching the barrier again.
    pub fn lock_paused_across_fork(&self) -> std::sync::MutexGuard<'_, usize> {
        self.paused.lock().unwrap()
    }

    /// CHILD-side post-fork reset of the parked-thread count. The count the
    /// child inherits belongs to PARENT threads parked at the parent's barrier;
    /// none of them exists in the child, and nothing will ever decrement it —
    /// so a child that later goes multithreaded and forks would see
    /// `wait_quiesced` satisfied by phantom parkers and fork UNQUIESCED.
    /// Call after `end_quiesce`/`end_fork` in the child arm. Safe to lock here
    /// because `lock_paused_across_fork` made the child's copy of the mutex
    /// consistent (owned by the forking thread, released on guard drop).
    pub fn reset_paused_for_child(&self) {
        *self.paused.lock().unwrap() = 0;
    }
}

/// Process-wide Pause-Modify-Resume barrier for runtime guest stage-1
/// page-table edits (mprotect / PROT_NONE / munmap). Carrick (the VMM) edits
/// the guest's stage-1 tables from the HOST while sibling vCPUs run; a sibling
/// walking a block mid-structural-change can fault. The editing thread becomes
/// the sole coordinator, raises `quiescing` so every OTHER vCPU parks (KEEPING
/// its vCPU) at its run-loop top before re-entering guest, waits until no
/// sibling is in-guest (via the kicker's in_guest flags — not a count), edits,
/// then resumes. Distinct from fork's quiesce (which tears vCPUs down).
pub fn pt_barrier() -> &'static PtQuiesce {
    static B: OnceLock<PtQuiesce> = OnceLock::new();
    B.get_or_init(PtQuiesce::new)
}

#[derive(Debug)]
pub struct PtQuiesce {
    coordinator: AtomicBool,
    quiescing: AtomicBool,
    lock: Mutex<()>,
    cv: Condvar,
}

impl Default for PtQuiesce {
    fn default() -> Self {
        Self::new()
    }
}

impl PtQuiesce {
    pub fn new() -> Self {
        Self {
            coordinator: AtomicBool::new(false),
            quiescing: AtomicBool::new(false),
            lock: Mutex::new(()),
            cv: Condvar::new(),
        }
    }

    pub fn is_quiescing(&self) -> bool {
        self.quiescing.load(Ordering::SeqCst)
    }

    /// Try to become the sole pausing editor (loser parks + retries).
    pub fn try_become_coordinator(&self) -> bool {
        self.coordinator
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn set_quiescing(&self) {
        self.quiescing.store(true, Ordering::SeqCst);
    }

    /// OTHER thread (or a coordinator-CAS loser) parks here until the pause
    /// ends, keeping its vCPU. Called at the lock-safe run-loop top.
    pub fn park(&self) {
        let mut g = self.lock.lock().unwrap();
        while self.quiescing.load(Ordering::SeqCst) {
            g = self.cv.wait(g).unwrap();
        }
    }

    /// Bounded `park`, for a caller that may hold ANOTHER process-wide
    /// serializer. Returns `false` if `deadline` passed with the pause still in
    /// force.
    ///
    /// The unbounded `park` above is right for a sibling at the run-loop top:
    /// it holds nothing, so waiting forever is just yielding to the editor. A
    /// coordinator-election loser is a different animal — it can already own
    /// the dispatcher's host-alias phase, and then an unbounded wait is not
    /// contention but the second half of a deadlock. Bounding it downgrades a
    /// silent carrier-wide stop to a typed, probed, guest-visible failure.
    pub fn park_until(&self, deadline: Instant) -> bool {
        let mut g = self.lock.lock().unwrap();
        loop {
            if !self.quiescing.load(Ordering::SeqCst) {
                return true;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            if remaining.is_zero() {
                return false;
            }
            let (next, _timed_out) = self.cv.wait_timeout(g, remaining).unwrap();
            g = next;
        }
    }

    /// Coordinator: end the pause, wake parked threads, drop coordinator.
    pub fn end(&self) {
        let _g = self.lock.lock().unwrap();
        self.quiescing.store(false, Ordering::SeqCst);
        self.coordinator.store(false, Ordering::SeqCst);
        self.cv.notify_all();
    }

    /// Mint the RAII resume-guard. The caller MUST already be the coordinator
    /// (won `try_become_coordinator`), have raised `set_quiescing`, and waited
    /// for siblings to leave guest. Dropping the guard calls `end`, so the pause
    /// is released on EVERY exit path of the editing syscall (incl. `?`-errors).
    /// `tid` is the editor, recorded so the drop can fire `pt-pause-end`.
    pub fn pause_guard(&'static self, tid: carrick_hal::ThreadId) -> PtPauseGuard {
        PtPauseGuard { barrier: self, tid }
    }
}

/// RAII handle that ends a page-table-edit pause (resuming sibling vCPUs) when
/// dropped. Held for the duration of the table-editing syscall.
pub struct PtPauseGuard {
    barrier: &'static PtQuiesce,
    tid: carrick_hal::ThreadId,
}

impl Drop for PtPauseGuard {
    fn drop(&mut self) {
        self.barrier.end();
        probes::pt_pause_end(self.tid.raw());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn quiesce_waits_for_all_others_then_releases() {
        let barrier = Arc::new(QuiesceBarrier::new());
        let resumed = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let n = 3;
        let mut handles = Vec::new();
        for _ in 0..n {
            let b = Arc::clone(&barrier);
            let r = Arc::clone(&resumed);
            let s = Arc::clone(&stop);
            handles.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    b.park_if_quiescing();
                    std::thread::yield_now();
                }
                r.fetch_add(1, Ordering::SeqCst);
            }));
        }
        std::thread::sleep(Duration::from_millis(20));
        barrier.set_quiescing();
        assert!(
            barrier.wait_quiesced(n, Duration::from_secs(5)),
            "all others should quiesce"
        );
        barrier.end_quiesce();
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(resumed.load(Ordering::SeqCst), n);
    }

    #[test]
    fn wait_quiesced_times_out_when_a_thread_never_parks() {
        let barrier = QuiesceBarrier::new();
        barrier.set_quiescing();
        assert!(!barrier.wait_quiesced(1, Duration::from_millis(100)));
        barrier.end_quiesce();
    }

    /// Hermetic stress of the REAL fork-quiesce protocol — the coordination that
    /// stranded every vCPU thread in `park_if_quiescing` under concurrent
    /// fork()/os-exec (the Go deadlock; sample: all siblings parked in
    /// `release_and_park_vcpu_for_fork -> park_if_quiescing -> pthread_cond_wait`,
    /// never released, one thread spinning). It mirrors the runtime EXACTLY:
    ///   * a fake kicker COUNT (vcpu_loop drains `kicker.count()` to 1, not the
    ///     `paused` count — so a `paused`-only stress would miss the skew);
    ///   * each sibling, on seeing `is_quiescing()`, UNREGISTERS from the count
    ///     THEN parks (the order `release_and_park_vcpu_for_fork` uses), and
    ///     re-registers on resume;
    ///   * a forker that loses `try_begin_fork` also unregisters+parks at the
    ///     in-flight barrier (vcpu_loop.rs:1501-1506) before retrying;
    ///   * the winner `set_quiescing`, spins the drain until only it remains
    ///     (mirrors the unbounded drain at vcpu_loop.rs:1528-1565), holds
    ///     `lock_paused_across_fork` across a no-op "fork", then
    ///     `end_quiesce`/`end_fork`.
    ///
    /// A lost `end_quiesce` wake (the flag is lowered OUTSIDE the `paused` lock)
    /// would leave a parker in `cv.wait` forever; a watchdog deadline turns that
    /// eternal hang into a test failure. RED if the coordination loses a wake;
    /// GREEN proves the barrier coordination is sound (so a real hang lives in a
    /// vcpu-loop wait arm that omits `is_quiescing()`, not here).
    fn fork_quiesce_stress(forkers: usize) {
        use std::sync::mpsc;
        const SIBLINGS: usize = 8;
        const ROUNDS: usize = 20_000;

        let barrier = Arc::new(QuiesceBarrier::new());
        // Registered-thread count: the forkers + the live siblings. A thread
        // unregisters before parking and re-registers on resume — exactly the
        // kicker count the runtime drains to 1.
        let kicker = Arc::new(AtomicUsize::new(forkers + SIBLINGS));
        let stop = Arc::new(AtomicBool::new(false));
        let rounds = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..SIBLINGS {
            let (b, k, s) = (Arc::clone(&barrier), Arc::clone(&kicker), Arc::clone(&stop));
            handles.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    if b.is_quiescing() {
                        k.fetch_sub(1, Ordering::SeqCst);
                        b.park_if_quiescing();
                        k.fetch_add(1, Ordering::SeqCst);
                    }
                    std::thread::yield_now();
                }
            }));
        }

        for _ in 0..forkers {
            let (b, k, s, r) = (
                Arc::clone(&barrier),
                Arc::clone(&kicker),
                Arc::clone(&stop),
                Arc::clone(&rounds),
            );
            handles.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) && r.load(Ordering::Relaxed) < ROUNDS {
                    if !b.try_begin_fork() {
                        // Lost the token: park at the in-flight barrier (like the
                        // runtime) so the winner can count us as quiesced.
                        if b.is_quiescing() {
                            k.fetch_sub(1, Ordering::SeqCst);
                            b.park_if_quiescing();
                            k.fetch_add(1, Ordering::SeqCst);
                        }
                        std::thread::yield_now();
                        continue;
                    }
                    b.set_quiescing();
                    // Drain until only this winner remains registered.
                    while k.load(Ordering::SeqCst) > 1 && !s.load(Ordering::Relaxed) {
                        std::thread::yield_now();
                    }
                    {
                        let _g = b.lock_paused_across_fork(); // no-op "fork" window
                    }
                    b.end_quiesce();
                    b.end_fork();
                    r.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        // Watchdog: the workload runs on the spawned threads; this thread fails
        // the test if ROUNDS don't complete within a hard wall-clock deadline.
        let (tx, rx) = mpsc::channel();
        {
            let (r, s) = (Arc::clone(&rounds), Arc::clone(&stop));
            std::thread::spawn(move || {
                while r.load(Ordering::Relaxed) < ROUNDS && !s.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = tx.send(());
            });
        }
        let ok = rx.recv_timeout(Duration::from_secs(30)).is_ok();

        // Tear down cleanly even on the deadlock path: stop everyone, then lower
        // the flag so any parked sibling wakes and exits, so join() returns.
        stop.store(true, Ordering::Relaxed);
        for _ in 0..4 {
            barrier.end_fork();
            barrier.end_quiesce();
            std::thread::sleep(Duration::from_millis(2));
        }
        for h in handles {
            let _ = h.join();
        }

        assert!(
            ok,
            "fork-quiesce deadlocked with {forkers} forker(s): a parker stuck in \
             park_if_quiescing or a forker spinning the drain (only {}/{ROUNDS} \
             rounds completed)",
            rounds.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn exec_replacement_claim_is_exclusive_until_ended() {
        // No lock needed: this is the only test in this binary that touches
        // the process-global exec owner (the fork-quiesce stress tests use
        // their own LOCAL barriers, never the static exec owner).
        let a = carrick_hal::ThreadId::synthetic_for_tests(701);
        let b = carrick_hal::ThreadId::synthetic_for_tests(702);
        assert!(try_begin_exec_replacement(a), "first claim wins");
        assert!(
            !try_begin_exec_replacement(b),
            "second concurrent execve must lose the claim and retire"
        );
        assert!(exec_replacing_other_thread(b));
        assert!(!exec_replacing_other_thread(a));
        end_exec_replacement();
        assert!(
            try_begin_exec_replacement(b),
            "the claim is reusable after end_exec_replacement"
        );
        end_exec_replacement();
    }

    #[test]
    fn fork_quiesce_no_lost_wakeup_single_forker() {
        fork_quiesce_stress(1);
    }

    #[test]
    fn fork_quiesce_no_lost_wakeup_concurrent_forkers() {
        fork_quiesce_stress(2);
    }
}
