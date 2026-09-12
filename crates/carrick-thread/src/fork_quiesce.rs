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
//!     `libc::fork` cleanly and the child clears it. [`topology_lock`] serializes
//!     carrier topology mutations (publication and alias containers); in HVPatch
//!     the VM is never torn down or rebuilt during fork.
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
// while holding the guard — which cannot occur in this no-panic codebase.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, TryLockError, Weak};
use std::time::{Duration, Instant};

use carrick_fatal::carrick_fatal;

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

thread_local! {
    static CURRENT_MM_QUIESCE: std::cell::RefCell<Option<Arc<PtQuiesce>>> = const { std::cell::RefCell::new(None) };
}

/// RAII token that binds the current thread's MM-scoped stage-1 quiesce barrier.
pub struct CurrentMmQuiesceGuard {
    prev: Option<Arc<PtQuiesce>>,
}

impl Drop for CurrentMmQuiesceGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        CURRENT_MM_QUIESCE.with(|cell| {
            *cell.borrow_mut() = prev;
        });
    }
}

/// Bind the current thread's MM-scoped stage-1 page table quiesce barrier.
pub fn bind_current_mm_quiesce(barrier: Arc<PtQuiesce>) -> CurrentMmQuiesceGuard {
    let prev = CURRENT_MM_QUIESCE.with(|cell| cell.borrow_mut().replace(barrier));
    CurrentMmQuiesceGuard { prev }
}

/// Returns the current thread's bound MM-scoped stage-1 quiesce barrier, if any.
pub fn current_mm_quiesce() -> Option<Arc<PtQuiesce>> {
    CURRENT_MM_QUIESCE.with(|cell| cell.borrow().clone())
}

/// Returns true if the current thread's MM is currently quiescing for a stage-1 edit.
pub fn is_current_mm_quiescing() -> bool {
    CURRENT_MM_QUIESCE.with(|cell| cell.borrow().as_ref().is_some_and(|pt| pt.is_quiescing()))
}

/// True while a fork quiesce is in progress, or the current thread's MM is
/// quiescing for a stage-1 page-table edit. Blocking waits OR this into their
/// wake predicate so they return (spurious EINTR) and reach the run-loop-top
/// barrier instead of re-parking.
pub fn is_quiescing() -> bool {
    barrier().is_quiescing() || is_current_mm_quiescing()
}

/// Serializes carrier-wide topology mutations: shared-frame publication and
/// carrier-global alias/replay/version containers.
///
/// Historical note: in legacy execution this lock serialized a sibling creating
/// its vCPU against a fork destroying and rebuilding the VM. In HVPatch, the VM
/// is never torn down or rebuilt during fork.
pub fn topology_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

struct TopologyReleaseListener {
    expected_generation: u64,
    callback: Arc<dyn Fn(u64) + Send + Sync + 'static>,
}

#[derive(Default)]
struct TopologyReleasePublication {
    generation: u64,
    listeners: BTreeMap<u64, TopologyReleaseListener>,
}

fn topology_release_publication() -> &'static Mutex<TopologyReleasePublication> {
    static PUBLICATION: OnceLock<Mutex<TopologyReleasePublication>> = OnceLock::new();
    PUBLICATION.get_or_init(|| Mutex::new(TopologyReleasePublication::default()))
}

static NEXT_TOPOLOGY_LISTENER: AtomicU64 = AtomicU64::new(1);

pub struct TopologyReleaseSubscription {
    id: u64,
    expected_generation: u64,
}

impl Drop for TopologyReleaseSubscription {
    fn drop(&mut self) {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut publication = topology_release_publication().lock().unwrap();
        if publication
            .listeners
            .get(&self.id)
            .is_some_and(|listener| listener.expected_generation == self.expected_generation)
        {
            publication.listeners.remove(&self.id);
        }
    }
}

pub enum TopologyReleaseEnrollment {
    Ready(u64),
    Subscribed(TopologyReleaseSubscription),
}

pub fn topology_release_generation() -> u64 {
    #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
    topology_release_publication().lock().unwrap().generation
}

pub fn subscribe_topology_release(
    expected_generation: u64,
    callback: Arc<dyn Fn(u64) + Send + Sync + 'static>,
) -> TopologyReleaseEnrollment {
    #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
    let mut publication = topology_release_publication().lock().unwrap();
    if publication.generation != expected_generation {
        return TopologyReleaseEnrollment::Ready(publication.generation);
    }
    let id = NEXT_TOPOLOGY_LISTENER.fetch_add(1, Ordering::Relaxed);
    if id == 0 || id == u64::MAX {
        carrick_fatal!(
            "thread::topology",
            "topology listener id exhausted or wrapped: id={id}"
        );
    }
    publication.listeners.insert(
        id,
        TopologyReleaseListener {
            expected_generation,
            callback,
        },
    );
    TopologyReleaseEnrollment::Subscribed(TopologyReleaseSubscription {
        id,
        expected_generation,
    })
}

fn publish_topology_release() {
    let (generation, callbacks) = {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut publication = topology_release_publication().lock().unwrap();
        publication.generation = publication.generation.checked_add(1).unwrap_or_else(|| {
            carrick_fatal!("thread::topology", "topology release generation overflow");
        });
        let generation = publication.generation;
        let callbacks = std::mem::take(&mut publication.listeners)
            .into_values()
            .map(|listener| listener.callback)
            .collect::<Vec<_>>();
        (generation, callbacks)
    };
    for callback in callbacks {
        callback(generation);
    }
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

/// Current topology depth held by the calling host pthread.
pub fn topology_depth() -> u32 {
    TOPOLOGY_DEPTH.with(|depth| depth.get())
}

fn enter_topology_depth() {
    TOPOLOGY_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
}

fn exit_topology_depth() {
    TOPOLOGY_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
}

/// RAII token tracking live topology depth for the current host pthread.
pub struct TopologyDepth {
    _private: (),
}

impl TopologyDepth {
    pub fn acquire() -> Self {
        enter_topology_depth();
        Self { _private: () }
    }
}

impl Drop for TopologyDepth {
    fn drop(&mut self) {
        exit_topology_depth();
    }
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
        drop(self._guard.take());
        publish_topology_release();
    }
}

/// Leaf critical section for the carrier-wide shared-frame registry: staging
/// and publishing frames another process may install next. Never held across
/// a guest write, a wait, or another lock.
pub struct FrameRegistryGuard<'r> {
    _guard: parking_lot::MutexGuard<'r, ()>,
}

impl<'r> FrameRegistryGuard<'r> {
    pub fn new(guard: parking_lot::MutexGuard<'r, ()>) -> Self {
        Self { _guard: guard }
    }
}

/// Carrier-wide leaf mutex for shared-frame registration and publication.
///
/// Never held across a guest write, a wait, or another lock.
pub fn frame_registry_lock() -> &'static parking_lot::Mutex<()> {
    static LOCK: OnceLock<parking_lot::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| parking_lot::Mutex::new(()))
}

/// Acquire the carrier-wide topology mutex and emit request/wait/release
/// records carrying the Linux guest identity responsible for the mutation.
///
/// Protects carrier-wide frame publication and alias containers until
/// superseded by per-MM transaction authority and [`FrameRegistryGuard`].
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

/// Try the carrier-wide topology mutex without blocking. A contended attempt
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
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_observability::probes::HvpatchTopologyOperation;

    static TOPOLOGY_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

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
        let _test_lock = TOPOLOGY_TEST_LOCK.lock();
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

    #[test]
    fn topology_try_miss_subscribes_to_exact_release_without_blocking() {
        let _test_lock = TOPOLOGY_TEST_LOCK.lock();
        let outer = acquire_topology_lock(HvpatchTopologyOperation::InProcessFork, 51, 52);
        let observed = topology_release_generation();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            assert!(
                try_acquire_topology_lock(HvpatchTopologyOperation::InProcessFork, 53, 54)
                    .is_none()
            );
            match subscribe_topology_release(
                observed,
                Arc::new(move |generation| {
                    let _ = tx.send(generation);
                }),
            ) {
                TopologyReleaseEnrollment::Subscribed(subscription) => subscription,
                TopologyReleaseEnrollment::Ready(_) => panic!("release raced test enrollment"),
            }
        });
        let subscription = waiter.join().unwrap();
        assert!(rx.try_recv().is_err());
        drop(outer);
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap() > observed);
        drop(subscription);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuiesceEventKind {
    Raised,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuiesceEvent {
    pub generation: u64,
    pub kind: QuiesceEventKind,
}

pub type QuiesceCallback = Arc<dyn Fn(QuiesceEvent) + Send + Sync + 'static>;

struct QuiesceListener {
    expected_generation: u64,
    callback: QuiesceCallback,
}

struct QuiescePublication {
    generation: u64,
    kind: QuiesceEventKind,
    listeners: BTreeMap<u64, QuiesceListener>,
}

pub struct QuiesceSubscription {
    barrier: Weak<QuiesceBarrier>,
    id: u64,
    expected_generation: u64,
}

pub type QuiesceProgressCallback = Arc<dyn Fn(u64) + Send + Sync + 'static>;

struct QuiesceProgressListener {
    expected_generation: u64,
    callback: QuiesceProgressCallback,
}

#[derive(Default)]
struct QuiesceProgressPublication {
    generation: u64,
    listeners: BTreeMap<u64, QuiesceProgressListener>,
}

pub struct QuiesceProgressSubscription {
    barrier: Weak<QuiesceBarrier>,
    id: u64,
    expected_generation: u64,
}

impl Drop for QuiesceProgressSubscription {
    fn drop(&mut self) {
        let Some(barrier) = self.barrier.upgrade() else {
            return;
        };
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut progress = barrier.progress.lock().unwrap();
        if progress
            .listeners
            .get(&self.id)
            .is_some_and(|listener| listener.expected_generation == self.expected_generation)
        {
            progress.listeners.remove(&self.id);
        }
    }
}

pub enum QuiesceProgressEnrollment {
    Ready(u64),
    Subscribed(QuiesceProgressSubscription),
}

impl Drop for QuiesceSubscription {
    fn drop(&mut self) {
        let Some(barrier) = self.barrier.upgrade() else {
            return;
        };
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut publication = barrier.publication.lock().unwrap();
        if publication
            .listeners
            .get(&self.id)
            .is_some_and(|listener| listener.expected_generation == self.expected_generation)
        {
            publication.listeners.remove(&self.id);
        }
    }
}

pub enum QuiesceEnrollment {
    Ready(QuiesceEvent),
    Subscribed(QuiesceSubscription),
}

pub struct QuiesceBarrier {
    quiescing: AtomicBool,
    forking: AtomicBool,
    paused: Mutex<usize>,
    cv: Condvar,
    publication: Mutex<QuiescePublication>,
    progress: Mutex<QuiesceProgressPublication>,
    next_listener: AtomicU64,
}

impl std::fmt::Debug for QuiesceBarrier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuiesceBarrier")
            .field("quiescing", &self.is_quiescing())
            .field("paused", &self.paused_count())
            .field("generation", &self.publication_generation())
            .finish_non_exhaustive()
    }
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
            publication: Mutex::new(QuiescePublication {
                generation: 0,
                kind: QuiesceEventKind::Released,
                listeners: BTreeMap::new(),
            }),
            progress: Mutex::new(QuiesceProgressPublication::default()),
            next_listener: AtomicU64::new(1),
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
        self.publish_quiesce_event(QuiesceEventKind::Released);
    }

    /// Step 1 (forking thread): raise the quiesce flag. The caller then wakes
    /// the other threads (kick in-guest vCPUs + notify blocked waiters) and
    /// calls `wait_quiesced`. Split from the wait so the wakes happen between —
    /// a thread woken by the kick/notify must observe `is_quiescing()==true` at
    /// the run-loop top, so the flag MUST be raised before the wakes.
    pub fn set_quiescing(&self) {
        self.quiescing.store(true, Ordering::SeqCst);
        self.publish_quiesce_event(QuiesceEventKind::Raised);
    }

    /// Step 2 (forking thread): wait until `others` threads have parked at the
    /// barrier, or `timeout`. Returns false on timeout (caller aborts the fork
    /// with EAGAIN and calls `end_quiesce`).
    pub fn wait_quiesced(&self, others: usize, timeout: Duration) -> bool {
        if others == 0 {
            return true;
        }
        let deadline = Instant::now() + timeout;
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut paused = self.paused.lock().unwrap();
        while *paused < others {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
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
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        *self.paused.lock().unwrap()
    }

    /// Called by every OTHER thread at the lock-safe run-loop top. If a quiesce
    /// is in progress, register as paused and block until it ends.
    pub fn park_if_quiescing(&self) {
        if !self.is_quiescing() {
            return;
        }
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut paused = self.paused.lock().unwrap();
        *paused += 1;
        self.cv.notify_all(); // wake the forking thread's count-wait
        while self.quiescing.load(Ordering::SeqCst) {
            #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
            let next = self.cv.wait(paused).unwrap();
            paused = next;
        }
        *paused -= 1;
    }

    /// Called by the forking thread (parent path, child path, or timeout abort)
    /// to lower the flag and release the parked threads.
    pub fn end_quiesce(&self) {
        self.quiescing.store(false, Ordering::SeqCst);
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let _g = self.paused.lock().unwrap();
        self.cv.notify_all();
        self.publish_quiesce_event(QuiesceEventKind::Released);
    }

    /// Publish exact progress after a logical sibling has detached its worker
    /// during process-fork quiesce. The coordinator subscribes instead of
    /// polling a vCPU count while occupying a worker.
    pub fn notify_quiesced_progress(&self) {
        let (generation, callbacks) = {
            #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
            let mut progress = self.progress.lock().unwrap();
            progress.generation = progress.generation.checked_add(1).unwrap_or_else(|| {
                carrick_fatal!(
                    "thread::fork_quiesce",
                    "quiesced progress generation overflow"
                );
            });
            let generation = progress.generation;
            let callbacks = std::mem::take(&mut progress.listeners)
                .into_values()
                .map(|listener| listener.callback)
                .collect::<Vec<_>>();
            (generation, callbacks)
        };
        for callback in callbacks {
            callback(generation);
        }
    }

    pub fn progress_generation(&self) -> u64 {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        self.progress.lock().unwrap().generation
    }

    pub fn subscribe_quiesced_progress(
        self: &Arc<Self>,
        expected_generation: u64,
        callback: QuiesceProgressCallback,
    ) -> QuiesceProgressEnrollment {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut progress = self.progress.lock().unwrap();
        if progress.generation != expected_generation {
            return QuiesceProgressEnrollment::Ready(progress.generation);
        }
        let id = self.next_listener.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id == u64::MAX {
            carrick_fatal!(
                "thread::fork_quiesce",
                "quiesced progress listener id exhausted or wrapped: id={id}"
            );
        }
        progress.listeners.insert(
            id,
            QuiesceProgressListener {
                expected_generation,
                callback,
            },
        );
        QuiesceProgressEnrollment::Subscribed(QuiesceProgressSubscription {
            barrier: Arc::downgrade(self),
            id,
            expected_generation,
        })
    }

    pub fn publication_generation(&self) -> u64 {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        self.publication.lock().unwrap().generation
    }

    pub fn subscribe_quiesce(
        self: &Arc<Self>,
        expected_generation: u64,
        callback: QuiesceCallback,
    ) -> QuiesceEnrollment {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut publication = self.publication.lock().unwrap();
        if publication.generation != expected_generation {
            return QuiesceEnrollment::Ready(QuiesceEvent {
                generation: publication.generation,
                kind: publication.kind,
            });
        }
        let id = self.next_listener.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id == u64::MAX {
            carrick_fatal!(
                "thread::fork_quiesce",
                "quiesce listener id exhausted or wrapped: id={id}"
            );
        }
        publication.listeners.insert(
            id,
            QuiesceListener {
                expected_generation,
                callback,
            },
        );
        QuiesceEnrollment::Subscribed(QuiesceSubscription {
            barrier: Arc::downgrade(self),
            id,
            expected_generation,
        })
    }

    fn publish_quiesce_event(&self, kind: QuiesceEventKind) {
        let (event, callbacks) = {
            #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
            let mut publication = self.publication.lock().unwrap();
            publication.generation = publication.generation.checked_add(1).unwrap_or_else(|| {
                carrick_fatal!("thread::fork_quiesce", "quiesce event generation overflow");
            });
            publication.kind = kind;
            let event = QuiesceEvent {
                generation: publication.generation,
                kind,
            };
            let callbacks = std::mem::take(&mut publication.listeners)
                .into_values()
                .map(|listener| listener.callback)
                .collect::<Vec<_>>();
            (event, callbacks)
        };
        for callback in callbacks {
            callback(event);
        }
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
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
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
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut guard = self.paused.lock().unwrap();
        *guard = 0;
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
pub fn pt_barrier() -> &'static Arc<PtQuiesce> {
    static B: OnceLock<Arc<PtQuiesce>> = OnceLock::new();
    B.get_or_init(|| Arc::new(PtQuiesce::new()))
}

#[derive(Debug)]
pub struct PtQuiesce {
    coordinator: AtomicBool,
    quiescing: AtomicBool,
    lock: Mutex<PtQuiesceState>,
    cv: Condvar,
}

#[derive(Debug, Default)]
struct PtQuiesceState {
    next_invalidation: u64,
    invalidation: Option<PtInvalidationState>,
}

#[derive(Debug)]
struct PtInvalidationState {
    phase: PtInvalidationPhase,
    request: PtInvalidationRequest,
    expected: BTreeSet<PtInvalidationParticipant>,
    acknowledged: BTreeSet<PtInvalidationParticipant>,
    failed: BTreeSet<PtInvalidationParticipant>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PtInvalidationParticipant {
    stage1: carrick_hal::ForeignStage1Identity,
    tid: carrick_hal::ThreadId,
}

/// Data-only exact-ASID request published after a quiesced stage-1 edit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtInvalidationRequest {
    identity: carrick_hal::ForeignCowInvalidationIdentity,
}

impl PtInvalidationRequest {
    pub const fn identity(self) -> carrick_hal::ForeignCowInvalidationIdentity {
        self.identity
    }
}

/// Opaque identity of one invalidation phase within a held pause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtInvalidationPhase(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PtInvalidationError {
    PauseNotActive,
    AlreadyPublished,
    StalePhase,
    ServiceFailed(carrick_hal::ThreadId),
    TimedOut(carrick_hal::ThreadId),
}

impl std::fmt::Display for PtInvalidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PauseNotActive => formatter.write_str("page-table pause is not active"),
            Self::AlreadyPublished => {
                formatter.write_str("another exact-ASID invalidation phase is already active")
            }
            Self::StalePhase => formatter.write_str("exact-ASID invalidation phase is stale"),
            Self::ServiceFailed(tid) => {
                write!(formatter, "executor {tid:?} failed exact-ASID invalidation")
            }
            Self::TimedOut(tid) => write!(
                formatter,
                "timed out waiting for executor {tid:?} to invalidate the exact ASID"
            ),
        }
    }
}

impl std::error::Error for PtInvalidationError {}

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
            lock: Mutex::new(PtQuiesceState::default()),
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
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut g = self.lock.lock().unwrap();
        while self.quiescing.load(Ordering::SeqCst) {
            #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
            let next = self.cv.wait(g).unwrap();
            g = next;
        }
    }

    /// Park an out-of-guest owner vCPU, servicing at most the exact phase that
    /// names this logical executor. The callback runs without the barrier lock
    /// and the executor remains parked after acknowledgement until the pause
    /// guard drops.
    pub fn park_servicing_exact_invalidation(
        &self,
        stage1: carrick_hal::ForeignStage1Identity,
        tid: carrick_hal::ThreadId,
        mut service: impl FnMut(PtInvalidationRequest) -> Result<(), ()>,
    ) {
        let participant = PtInvalidationParticipant { stage1, tid };
        let mut serviced_phase = 0;
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut g = self.lock.lock().unwrap();
        while self.quiescing.load(Ordering::SeqCst) {
            let work = g.invalidation.as_ref().and_then(|state| {
                (state.phase.0 > serviced_phase && state.expected.contains(&participant))
                    .then_some((state.phase, state.request))
            });
            if let Some((phase, request)) = work {
                drop(g);
                let result = service(request);
                #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
                let acquired = self.lock.lock().unwrap();
                g = acquired;
                serviced_phase = phase.0;
                if let Some(state) = g
                    .invalidation
                    .as_mut()
                    .filter(|state| state.phase == phase && state.expected.contains(&participant))
                {
                    match result {
                        Ok(()) => {
                            state.acknowledged.insert(participant);
                        }
                        Err(()) => {
                            state.failed.insert(participant);
                        }
                    }
                    self.cv.notify_all();
                }
                continue;
            }
            #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
            let next = self.cv.wait(g).unwrap();
            g = next;
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
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
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
            #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
            let (next, _timed_out) = self.cv.wait_timeout(g, remaining).unwrap();
            g = next;
        }
    }

    /// Coordinator: end the pause, wake parked threads, drop coordinator.
    pub fn end(&self) {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut g = self.lock.lock().unwrap();
        g.invalidation = None;
        self.quiescing.store(false, Ordering::SeqCst);
        self.coordinator.store(false, Ordering::SeqCst);
        self.cv.notify_all();
    }

    /// Mint the RAII resume-guard. The caller MUST already be the coordinator
    /// (won `try_become_coordinator`), have raised `set_quiescing`, and waited
    /// for siblings to leave guest. Dropping the guard calls `end`, so the pause
    /// is released on EVERY exit path of the editing syscall (incl. `?`-errors).
    /// `tid` is the editor, recorded so the drop can fire `pt-pause-end`.
    pub fn pause_guard(self: &Arc<Self>, tid: carrick_hal::ThreadId) -> PtPauseGuard {
        PtPauseGuard {
            barrier: Arc::clone(self),
            tid,
        }
    }
}

/// RAII handle that ends a page-table-edit pause (resuming sibling vCPUs) when
/// dropped. Held for the duration of the table-editing syscall.
pub struct PtPauseGuard {
    barrier: Arc<PtQuiesce>,
    tid: carrick_hal::ThreadId,
}

impl Drop for PtPauseGuard {
    fn drop(&mut self) {
        self.barrier.end();
        probes::pt_pause_end(self.tid.raw());
    }
}

impl PtPauseGuard {
    pub fn publish_exact_invalidation(
        &self,
        identity: carrick_hal::ForeignCowInvalidationIdentity,
        expected: impl IntoIterator<Item = carrick_hal::ThreadId>,
    ) -> Result<PtInvalidationPhase, PtInvalidationError> {
        if !self.barrier.quiescing.load(Ordering::SeqCst) {
            return Err(PtInvalidationError::PauseNotActive);
        }
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut state = self.barrier.lock.lock().unwrap();
        if state.invalidation.is_some() {
            return Err(PtInvalidationError::AlreadyPublished);
        }
        state.next_invalidation = state.next_invalidation.checked_add(1).unwrap_or_else(|| {
            carrick_fatal!(
                "thread::fork_quiesce",
                "page table next invalidation phase overflow"
            );
        });
        let phase = PtInvalidationPhase(state.next_invalidation);
        state.invalidation = Some(PtInvalidationState {
            phase,
            request: PtInvalidationRequest { identity },
            expected: expected
                .into_iter()
                .map(|tid| PtInvalidationParticipant {
                    stage1: identity.stage1(),
                    tid,
                })
                .collect(),
            acknowledged: BTreeSet::new(),
            failed: BTreeSet::new(),
        });
        self.barrier.cv.notify_all();
        Ok(phase)
    }

    pub fn wait_invalidation(
        &self,
        phase: &PtInvalidationPhase,
        deadline: Instant,
    ) -> Result<(), PtInvalidationError> {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut guard = self.barrier.lock.lock().unwrap();
        loop {
            let state = guard
                .invalidation
                .as_ref()
                .filter(|state| state.phase == *phase)
                .ok_or(PtInvalidationError::StalePhase)?;
            if let Some(participant) = state.failed.iter().next().copied() {
                return Err(PtInvalidationError::ServiceFailed(participant.tid));
            }
            if state.acknowledged == state.expected {
                return Ok(());
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                let missing = state
                    .expected
                    .difference(&state.acknowledged)
                    .next()
                    .copied()
                    .ok_or(PtInvalidationError::StalePhase)?;
                return Err(PtInvalidationError::TimedOut(missing.tid));
            };
            #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
            let (next, _) = self.barrier.cv.wait_timeout(guard, remaining).unwrap();
            guard = next;
        }
    }

    /// Retire one completed or failed phase while keeping the admission
    /// barrier raised. This permits rollback to publish a second exact-ASID
    /// generation to the same parked owners before the pause guard releases.
    pub fn finish_invalidation(
        &self,
        phase: &PtInvalidationPhase,
    ) -> Result<(), PtInvalidationError> {
        #[allow(clippy::unwrap_used)] // poisoned lock = correct to die
        let mut guard = self.barrier.lock.lock().unwrap();
        match guard.invalidation.as_ref() {
            Some(state) if state.phase == *phase => {
                guard.invalidation = None;
                self.barrier.cv.notify_all();
                Ok(())
            }
            _ => Err(PtInvalidationError::StalePhase),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    fn invalidation_identity(
        mm: u64,
        asid: u16,
        asid_generation: u64,
        root: u64,
        cow_generation: u64,
    ) -> carrick_hal::ForeignCowInvalidationIdentity {
        use std::num::{NonZeroU16, NonZeroU64};

        let mm = carrick_hal::ForeignMmId::from_kernel_allocation(NonZeroU64::new(mm).unwrap());
        let asid = carrick_hal::ForeignAsid::from_kernel_allocation(NonZeroU16::new(asid).unwrap());
        let binding = carrick_hal::ForeignMmBinding::for_aarch64_root_raw(asid, root);
        let stage1 = carrick_hal::ForeignStage1Identity::new(
            mm,
            binding,
            carrick_hal::ForeignAsidGeneration::from_runtime_binding(
                asid,
                NonZeroU64::new(asid_generation).unwrap(),
            ),
        )
        .unwrap();
        carrick_hal::ForeignCowInvalidationIdentity::new(
            stage1,
            carrick_hal::ForeignCowInvalidationGeneration::from_runtime_publication(
                NonZeroU64::new(cow_generation).unwrap(),
            ),
        )
    }

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

    #[test]
    fn quiesce_subscription_is_exact_durable_and_one_shot_for_raise_and_release() {
        let barrier = Arc::new(QuiesceBarrier::new());
        let observed = barrier.publication_generation();
        barrier.set_quiescing();
        let event_before = match barrier.subscribe_quiesce(observed, Arc::new(|_| {})) {
            QuiesceEnrollment::Ready(event) => event,
            QuiesceEnrollment::Subscribed(_) => panic!("raise-before-enrollment was lost"),
        };
        assert_eq!(event_before.kind, QuiesceEventKind::Raised);

        let callbacks = Arc::new(Mutex::new(Vec::new()));
        let callback_events = Arc::clone(&callbacks);
        let subscription = match barrier.subscribe_quiesce(
            event_before.generation,
            Arc::new(move |event| callback_events.lock().unwrap().push(event)),
        ) {
            QuiesceEnrollment::Subscribed(subscription) => subscription,
            QuiesceEnrollment::Ready(_) => panic!("stable generation must subscribe"),
        };
        barrier.end_quiesce();
        assert_eq!(
            callbacks.lock().unwrap().as_slice(),
            &[QuiesceEvent {
                generation: event_before.generation + 1,
                kind: QuiesceEventKind::Released,
            }]
        );
        barrier.set_quiescing();
        assert_eq!(callbacks.lock().unwrap().len(), 1, "one-shot callback");
        drop(subscription);
        barrier.end_quiesce();
    }

    #[test]
    fn dropped_quiesce_subscription_cannot_observe_reused_generation() {
        let barrier = Arc::new(QuiesceBarrier::new());
        let callbacks = Arc::new(AtomicUsize::new(0));
        let callback_count = Arc::clone(&callbacks);
        let subscription = match barrier.subscribe_quiesce(
            barrier.publication_generation(),
            Arc::new(move |_| {
                callback_count.fetch_add(1, Ordering::SeqCst);
            }),
        ) {
            QuiesceEnrollment::Subscribed(subscription) => subscription,
            QuiesceEnrollment::Ready(_) => panic!("stable generation must subscribe"),
        };
        drop(subscription);
        barrier.set_quiescing();
        barrier.end_quiesce();
        assert_eq!(callbacks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn logical_progress_wakes_coordinator_without_consuming_sibling_release() {
        let barrier = Arc::new(QuiesceBarrier::new());
        barrier.set_quiescing();
        let release_events = Arc::new(Mutex::new(Vec::new()));
        let release_capture = Arc::clone(&release_events);
        let release = match barrier.subscribe_quiesce(
            barrier.publication_generation(),
            Arc::new(move |event| release_capture.lock().unwrap().push(event)),
        ) {
            QuiesceEnrollment::Subscribed(subscription) => subscription,
            QuiesceEnrollment::Ready(_) => panic!("stable release generation"),
        };
        let progress_events = Arc::new(Mutex::new(Vec::new()));
        let progress_capture = Arc::clone(&progress_events);
        let progress = match barrier.subscribe_quiesced_progress(
            barrier.progress_generation(),
            Arc::new(move |generation| progress_capture.lock().unwrap().push(generation)),
        ) {
            QuiesceProgressEnrollment::Subscribed(subscription) => subscription,
            QuiesceProgressEnrollment::Ready(_) => panic!("stable progress generation"),
        };
        barrier.notify_quiesced_progress();
        assert_eq!(progress_events.lock().unwrap().as_slice(), &[1]);
        assert!(release_events.lock().unwrap().is_empty());
        barrier.end_quiesce();
        assert_eq!(release_events.lock().unwrap().len(), 1);
        drop((progress, release));
    }

    /// Hermetic stress of the REAL fork-quiesce protocol — the coordination that
    /// stranded every vCPU thread in `park_if_quiescing` under concurrent
    /// fork()/os-exec (the Go deadlock; sample: all siblings parked in
    /// `release_and_park_vcpu_for_fork -> park_if_quiescing -> pthread_cond_wait`,
    /// never released, one thread spinning). It mirrors the runtime EXACTLY:
    ///   * a fake identity registry (the runtime drains every identity other
    ///     than the exact fork owner, so a `paused`-only stress misses skew);
    ///   * each sibling, on seeing `is_quiescing()`, UNREGISTERS its identity
    ///     THEN parks (the order `release_and_park_vcpu_for_fork` uses), and
    ///     re-registers only after the owner's freeze thaws;
    ///   * a forker that loses `try_begin_fork` also unregisters+parks at the
    ///     in-flight barrier (vcpu_loop.rs:1501-1506) before retrying;
    ///   * the winner `set_quiescing`, atomically freezes once no different
    ///     identity remains, holds `lock_paused_across_fork` across a no-op
    ///     "fork", then lowers both barriers before thawing registration.
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

        #[derive(Default)]
        struct IdentityLeases {
            members: BTreeSet<carrick_hal::ThreadId>,
            freeze_owner: Option<carrick_hal::ThreadId>,
        }

        impl IdentityLeases {
            fn unregister(&mut self, tid: carrick_hal::ThreadId) {
                assert!(self.members.remove(&tid), "identity must be registered");
            }

            fn try_register(&mut self, tid: carrick_hal::ThreadId) -> bool {
                if self.freeze_owner.is_some_and(|owner| owner != tid) {
                    return false;
                }
                assert!(self.members.insert(tid), "identity must be absent");
                true
            }

            fn try_freeze(&mut self, owner: carrick_hal::ThreadId) -> bool {
                if self.freeze_owner.is_some() || self.members.iter().any(|member| *member != owner)
                {
                    return false;
                }
                self.freeze_owner = Some(owner);
                true
            }

            fn thaw(&mut self, owner: carrick_hal::ThreadId) {
                assert_eq!(self.freeze_owner, Some(owner));
                self.freeze_owner = None;
            }
        }

        let barrier = Arc::new(QuiesceBarrier::new());
        let sibling_tids: Vec<_> = (0..SIBLINGS)
            .map(|index| carrick_hal::ThreadId::synthetic_for_tests(10_000 + index as i32))
            .collect();
        let forker_tids: Vec<_> = (0..forkers)
            .map(|index| carrick_hal::ThreadId::synthetic_for_tests(20_000 + index as i32))
            .collect();
        let mut initial_members = BTreeSet::new();
        initial_members.extend(sibling_tids.iter().copied());
        initial_members.extend(forker_tids.iter().copied());
        let leases = Arc::new(Mutex::new(IdentityLeases {
            members: initial_members,
            freeze_owner: None,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let rounds = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for tid in sibling_tids {
            let (b, leases, s) = (Arc::clone(&barrier), Arc::clone(&leases), Arc::clone(&stop));
            handles.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) {
                    if b.is_quiescing() {
                        leases.lock().unwrap().unregister(tid);
                        b.park_if_quiescing();
                        while !leases.lock().unwrap().try_register(tid)
                            && !s.load(Ordering::Relaxed)
                        {
                            std::thread::yield_now();
                        }
                    }
                    std::thread::yield_now();
                }
            }));
        }

        for tid in forker_tids {
            let (b, leases, s, r) = (
                Arc::clone(&barrier),
                Arc::clone(&leases),
                Arc::clone(&stop),
                Arc::clone(&rounds),
            );
            handles.push(std::thread::spawn(move || {
                while !s.load(Ordering::Relaxed) && r.load(Ordering::Relaxed) < ROUNDS {
                    if !b.try_begin_fork() {
                        // Lost the token: park at the in-flight barrier (like the
                        // runtime) so the winner can count us as quiesced.
                        if b.is_quiescing() {
                            leases.lock().unwrap().unregister(tid);
                            b.park_if_quiescing();
                            while !leases.lock().unwrap().try_register(tid)
                                && !s.load(Ordering::Relaxed)
                            {
                                std::thread::yield_now();
                            }
                        }
                        std::thread::yield_now();
                        continue;
                    }
                    b.set_quiescing();
                    // Observation and registration closure are one locked
                    // transaction: only the exact owner remains, then a unique
                    // freeze blocks every non-owner publication.
                    let frozen = loop {
                        if leases.lock().unwrap().try_freeze(tid) {
                            break true;
                        }
                        if s.load(Ordering::Relaxed) {
                            break false;
                        }
                        std::thread::yield_now();
                    };
                    if !frozen {
                        b.end_quiesce();
                        b.end_fork();
                        break;
                    }
                    {
                        let _g = b.lock_paused_across_fork(); // no-op "fork" window
                    }
                    b.end_quiesce();
                    b.end_fork();
                    leases.lock().unwrap().thaw(tid);
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
    fn pt_pause_publishes_exact_invalidation_and_waits_for_owner_ack() {
        let barrier = Arc::new(PtQuiesce::new());
        let tid = carrick_hal::ThreadId::synthetic_for_tests(801);
        assert!(barrier.try_become_coordinator());
        barrier.set_quiescing();
        let guard = barrier.pause_guard(carrick_hal::ThreadId::synthetic_for_tests(800));
        let serviced = Arc::new(AtomicBool::new(false));
        let worker_serviced = Arc::clone(&serviced);
        let identity = invalidation_identity(13, 17, 23, 0x8000, 29);
        let worker_barrier = Arc::clone(&barrier);
        let worker = std::thread::spawn(move || {
            worker_barrier.park_servicing_exact_invalidation(identity.stage1(), tid, |request| {
                assert_eq!(request.identity(), identity);
                worker_serviced.store(true, Ordering::SeqCst);
                Ok(())
            })
        });

        let phase = guard
            .publish_exact_invalidation(identity, [tid])
            .expect("publish exact-ASID invalidation phase");
        guard
            .wait_invalidation(&phase, Instant::now() + Duration::from_secs(1))
            .expect("owner vCPU acknowledgement");
        assert!(serviced.load(Ordering::SeqCst));
        assert!(
            !worker.is_finished(),
            "owner remains excluded through commit"
        );
        drop(guard);
        worker.join().expect("parked owner resumes");
    }

    #[test]
    fn pt_pause_invalidation_fails_closed_on_owner_failure_or_timeout() {
        let failed_barrier = Arc::new(PtQuiesce::new());
        let failed_tid = carrick_hal::ThreadId::synthetic_for_tests(811);
        assert!(failed_barrier.try_become_coordinator());
        failed_barrier.set_quiescing();
        let failed_guard =
            failed_barrier.pause_guard(carrick_hal::ThreadId::synthetic_for_tests(810));
        let service_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_calls = Arc::clone(&service_calls);
        let failed_identity = invalidation_identity(15, 19, 29, 0xa000, 31);
        let worker_barrier = Arc::clone(&failed_barrier);
        let worker = std::thread::spawn(move || {
            worker_barrier.park_servicing_exact_invalidation(
                failed_identity.stage1(),
                failed_tid,
                |_| {
                    (worker_calls.fetch_add(1, Ordering::SeqCst) != 0)
                        .then_some(())
                        .ok_or(())
                },
            )
        });
        let phase = failed_guard
            .publish_exact_invalidation(failed_identity, [failed_tid])
            .expect("publish failure phase");
        assert_eq!(
            failed_guard.wait_invalidation(&phase, Instant::now() + Duration::from_secs(1)),
            Err(PtInvalidationError::ServiceFailed(failed_tid))
        );
        failed_guard
            .finish_invalidation(&phase)
            .expect("retire failed publication while pause remains held");
        let rollback_identity = invalidation_identity(15, 19, 29, 0xa000, 32);
        let rollback = failed_guard
            .publish_exact_invalidation(rollback_identity, [failed_tid])
            .expect("publish rollback invalidation");
        failed_guard
            .wait_invalidation(&rollback, Instant::now() + Duration::from_secs(1))
            .expect("parked owner services rollback generation");
        failed_guard
            .finish_invalidation(&rollback)
            .expect("retire rollback publication");
        assert_eq!(service_calls.load(Ordering::SeqCst), 2);
        drop(failed_guard);
        worker.join().expect("failed worker resumes after rollback");

        let timeout_barrier = Arc::new(PtQuiesce::new());
        let missing_tid = carrick_hal::ThreadId::synthetic_for_tests(821);
        assert!(timeout_barrier.try_become_coordinator());
        timeout_barrier.set_quiescing();
        let timeout_guard =
            timeout_barrier.pause_guard(carrick_hal::ThreadId::synthetic_for_tests(820));
        let timeout_identity = invalidation_identity(17, 31, 37, 0xc000, 41);
        let phase = timeout_guard
            .publish_exact_invalidation(timeout_identity, [missing_tid])
            .expect("publish timeout phase");
        assert_eq!(
            timeout_guard.wait_invalidation(&phase, Instant::now() + Duration::from_millis(10)),
            Err(PtInvalidationError::TimedOut(missing_tid))
        );
        drop(timeout_guard);
    }

    #[test]
    fn pt_pause_exact_identity_does_not_accept_recycled_asid_with_new_root() {
        use std::num::{NonZeroU16, NonZeroU64};

        let mm = carrick_hal::ForeignMmId::from_kernel_allocation(NonZeroU64::new(91).unwrap());
        let asid = carrick_hal::ForeignAsid::from_kernel_allocation(NonZeroU16::new(17).unwrap());
        let old_binding = carrick_hal::ForeignMmBinding::for_aarch64_root_raw(asid, 0x8000);
        let new_binding = carrick_hal::ForeignMmBinding::for_aarch64_root_raw(asid, 0x9000);
        let old_stage1 = carrick_hal::ForeignStage1Identity::new(
            mm,
            old_binding,
            carrick_hal::ForeignAsidGeneration::from_runtime_binding(
                asid,
                NonZeroU64::new(23).unwrap(),
            ),
        )
        .unwrap();
        let recycled_stage1 = carrick_hal::ForeignStage1Identity::new(
            mm,
            new_binding,
            carrick_hal::ForeignAsidGeneration::from_runtime_binding(
                asid,
                NonZeroU64::new(24).unwrap(),
            ),
        )
        .unwrap();
        let request = carrick_hal::ForeignCowInvalidationIdentity::new(
            old_stage1,
            carrick_hal::ForeignCowInvalidationGeneration::from_runtime_publication(
                NonZeroU64::new(29).unwrap(),
            ),
        );
        let barrier = Arc::new(PtQuiesce::new());
        let tid = carrick_hal::ThreadId::synthetic_for_tests(831);
        assert!(barrier.try_become_coordinator());
        barrier.set_quiescing();
        let guard = barrier.pause_guard(carrick_hal::ThreadId::synthetic_for_tests(830));
        let wrong_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wrong_worker_calls = Arc::clone(&wrong_calls);
        let worker_barrier1 = Arc::clone(&barrier);
        let wrong_worker = std::thread::spawn(move || {
            worker_barrier1.park_servicing_exact_invalidation(recycled_stage1, tid, |_| {
                wrong_worker_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });
        let right_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let right_worker_calls = Arc::clone(&right_calls);
        let worker_barrier2 = Arc::clone(&barrier);
        let right_worker = std::thread::spawn(move || {
            worker_barrier2.park_servicing_exact_invalidation(old_stage1, tid, |observed| {
                assert_eq!(observed.identity(), request);
                right_worker_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        let phase = guard
            .publish_exact_invalidation(request, [tid])
            .expect("publish typed exact-stage1 invalidation");
        guard
            .wait_invalidation(&phase, Instant::now() + Duration::from_secs(1))
            .expect("only exact old identity acknowledges");
        assert_eq!(right_calls.load(Ordering::SeqCst), 1);
        assert_eq!(wrong_calls.load(Ordering::SeqCst), 0);
        drop(guard);
        right_worker.join().unwrap();
        wrong_worker.join().unwrap();
    }

    #[test]
    fn fork_quiesce_stress_no_lost_wakeup_single_forker() {
        fork_quiesce_stress(1);
    }

    #[test]
    fn fork_quiesce_stress_no_lost_wakeup_concurrent_forkers() {
        fork_quiesce_stress(2);
    }

    #[test]
    fn topology_depth_tracks_executor_boundary() {
        assert_eq!(topology_depth(), 0);
        assert!(topology_depth_is_zero_for_executor_boundary());
        {
            let _depth = TopologyDepth::acquire();
            assert_eq!(topology_depth(), 1);
            assert!(!topology_depth_is_zero_for_executor_boundary());
        }
        assert_eq!(topology_depth(), 0);
        assert!(topology_depth_is_zero_for_executor_boundary());
    }

    #[test]
    fn frame_registry_guard_is_a_leaf() {
        let sources = [include_str!("fork_quiesce.rs")];
        for source in sources {
            let mut parts = source.split("frame_registry_lock().lock()");
            let _first = parts.next();
            for part in parts {
                let critical_section = part.split("drop(").next().unwrap_or(part);
                assert!(
                    !critical_section.contains("acquire_topology_lock"),
                    "frame_registry_lock held across acquire_topology_lock"
                );
                assert!(
                    !critical_section.contains(".lock()"),
                    "frame_registry_lock held across another .lock() call"
                );
            }
        }
    }
}
