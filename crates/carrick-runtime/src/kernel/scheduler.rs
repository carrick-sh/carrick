//! Exact-generation runnable authority for the HVPatch executor migration.
//!
//! The thread execution record is always transitioned before queue state is
//! acquired. Host wake edges and executor slots remain consequences of that
//! state, never authority for it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::{Condvar, Mutex};

pub use carrick_hal::{
    CpuAffinity, CpuLoad, CpuQueueView, GuestCpuId, GuestCpuPolicy, PreemptOrContinue,
    SchedulingPolicy, TaskKey, TaskPlacement,
};

use super::Kernel;
use super::objects::{
    BlockedReason, ExecutionGeneration, ExecutorId, Thread, ThreadExecutionError,
    ThreadExecutionLease, ThreadExecutionState, ThreadKey, ThreadSchedulerAction,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct QueueKey {
    pub(crate) thread: ThreadKey,
    pub(crate) generation: ExecutionGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeDisposition {
    Queued,
    Coalesced,
    Kicked,
    Pending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RunQueueError {
    #[error("run queue is closed")]
    Closed,
    #[error("new root submissions are rejected while the run queue is closing")]
    SubmissionRejected,
    /// A submission-authority counter would overflow. Distinct from a closing
    /// queue for the same reason: an exhaustion is not a shutdown.
    #[error("concurrent submission authorities are exhausted")]
    AuthoritiesExhausted,
    /// A generation observer already holds the exact successor binding.
    #[error("generation observer already holds the successor binding")]
    DuplicateObserverBinding,
    /// A second generation observer was installed over a live one.
    #[error("a generation observer is already installed")]
    ObserverAlreadyInstalled,
    #[error("run queue publication authority does not match the submitted generation")]
    AuthorityMismatch,
    #[error("generation observer has no binding record for the predecessor generation")]
    ObserverBindingMissing,
    #[error("generation observer outlived its scheduler")]
    ObserverSchedulerGone,
    #[error("executor identifiers are exhausted")]
    ExecutorIdExhausted,
    #[error("executor is already running another exact generation")]
    ExecutorBusy,
    #[error("executor registration is stale")]
    StaleExecutor,
    #[error("exact runnable generation is not queued")]
    QueueEmpty,
    #[error("executor was poked for owner-thread control work")]
    ControlPoked,
}

#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("exact thread generation is not live")]
    UnknownThread,
    #[error(transparent)]
    Thread(#[from] ThreadExecutionError),
    #[error(transparent)]
    Queue(#[from] RunQueueError),
}

pub trait ExecutorKick: Send + Sync + std::fmt::Debug {
    /// Atomically install an exact loaded generation at the destination.
    fn try_bind(&self, binding: ExecutorBinding) -> bool;

    /// Clear only the still-matching destination binding.
    fn unbind(&self, binding: ExecutorBinding);

    /// Atomically replace one exact loaded task with its exec successor on
    /// the same physical executor.
    fn rebind_exact_with(
        &self,
        predecessor: ExecutorBinding,
        successor: ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool;

    /// Revalidate and consume the exact token at the destination. The host
    /// nudge may occur only inside the successful exact-binding branch.
    fn deliver_exact(&self, token: ExecutorKickToken) -> bool;

    /// Debug view of the kick's need_resched flag; `None` when the
    /// implementation exposes none. Observability only.
    fn debug_need_resched(&self) -> Option<bool> {
        None
    }

    /// Debug view of whether an exact hardware kick is published for the
    /// bound quantum; `None` when not exposed. Observability only.
    fn debug_hardware_kick_published(&self) -> Option<bool> {
        None
    }

    fn current_binding(&self) -> Option<ExecutorBinding>;
}

pub(crate) trait DiscardRecorder: Send + Sync {
    fn record_discard(
        &self,
        executor: ExecutorId,
        thread: ThreadKey,
        row_generation: ExecutionGeneration,
        observed_state: String,
        reason: String,
    );
}

pub(crate) trait SchedulerGenerationObserver: Send + Sync {
    fn transition(
        &self,
        thread: ThreadKey,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
        kind: SchedulerGenerationTransition,
    ) -> Result<(), RunQueueError>;

    /// The scheduler classified the rejection this observer just returned as
    /// [`TransitionRejection::TargetReaped`]: the exact thread is gone from
    /// the kernel graph, so no successor will ever be published for
    /// `predecessor` and nothing will ever resolve that record again.
    ///
    /// An observer that keeps per-generation state — the HVPatch binding
    /// directory keeps the task binding AND its `SubmissionAuthority` — must
    /// retire the predecessor record here. Only the scheduler can make this
    /// call: the observer sees a rejected rollover, which is also what a live
    /// target under a racing generation looks like, and retiring THAT would
    /// drop a reachable authority. Liveness is the scheduler's fact.
    fn retire_reaped(&self, _thread: ThreadKey, _predecessor: ExecutionGeneration) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchedulerGenerationTransition {
    Runnable,
    Blocked,
    Terminal,
}

/// What the generation observer did with one exact transition, as its callers
/// see it.
///
/// An OUTCOME, not an error. "The observer refused" has two completely
/// different meanings and only one of them is survivable, so returning
/// `Result` let a caller write `if let Err(_)` and treat both as the benign
/// one — the round-2 swallow. There is nothing to swallow: each meaning is a
/// distinct variant every caller must branch on exhaustively. Round 4 kept the
/// fatal one out of the type by calling `std::process::abort()` inside
/// `observe_generation_transition`; it is a variant now, because the abort
/// goes through lane B's post-mortem sink and the transaction that observed it
/// still has to finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationTransitionOutcome {
    /// The observer recorded the successor. It is reachable and publishable.
    Recorded,
    /// The observer rejected the transition while the kernel graph still calls
    /// the target REACHABLE. The carrier is being aborted through the
    /// post-mortem sink, and this transaction still finishes so the capture
    /// describes a settled graph; the successor is withheld exactly as it is
    /// for a reaped target, but NOTHING is retired -- a reachable generation's
    /// authority is not this side's to drop.
    LostExactTransition,
    /// The target was REAPED while this transition was in flight. The
    /// successor generation is unreachable by construction — nothing can
    /// resolve the thread again — so it strands nothing, and Linux answers a
    /// wake of an exited task with a no-op rather than a fault. The caller
    /// must still finish whatever transaction it is in; it must not publish
    /// the successor.
    TargetReaped,
}

/// The two meanings of one observer REJECTION, before the fatal one is acted
/// on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionRejection {
    /// Benign: the target left the kernel graph under the transition.
    TargetReaped,
    /// Fatal: the thread IS still live, so the observer and the Kernel
    /// disagree about a REACHABLE generation. The Kernel execution state has
    /// already advanced, so an ordinary error would strand the successor
    /// outside the combined binding/authority directory and bypass logical
    /// completion.
    LostExactTransition,
}

/// What the kernel graph says about the target of one rejected transition.
///
/// Registry PRESENCE is not the question, and answering it was the round-4
/// defect. A thread can be missing from the exact scheduler registry for
/// reasons that have nothing to do with having exited — a reap that is still
/// in flight, an exec replacement mid-swap — and calling that "reaped"
/// withheld a FINISHED `go_types` process job's result: the settlement
/// published nothing, the job's `HvpatchLoopResult` was never filled, and
/// eighteen executors parked forever on an empty queue while the guest had
/// already printed PASS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerTargetLiveness {
    /// The exact thread's own execution state is terminal: `Exited` or
    /// `Failed`. Nothing will resolve this generation again.
    Terminal,
    /// The kernel graph still calls this generation reachable: the thread's
    /// execution state is not terminal, it is in no retirement record, and its
    /// task is not a zombie.
    Reachable,
}

/// Classify one observer rejection from the single fact that separates the two
/// meanings.
///
/// Split out as a pure function so BOTH arms are unit-testable.
const fn classify_transition_rejection(liveness: SchedulerTargetLiveness) -> TransitionRejection {
    match liveness {
        SchedulerTargetLiveness::Reachable => TransitionRejection::LostExactTransition,
        SchedulerTargetLiveness::Terminal => TransitionRejection::TargetReaped,
    }
}

/// What one settlement did about the thread's NEXT generation.
///
/// A settlement used to answer only "did it error", which cannot express the
/// case the exit wedge lives in: the transaction succeeded, no successor
/// exists, and the thread's process job therefore has no publisher left.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementDisposition {
    /// The successor is recorded; the thread is reachable again.
    Settled,
    /// The target was REAPED in flight. No successor exists and none ever
    /// will, so nothing will run this thread again and nothing else will fill
    /// its process job: the caller must publish the job's terminal result
    /// here. "A settled job with an unpublished result is unrepresentable"
    /// applies to this path too.
    TargetReaped,
    /// The observer and the kernel graph disagreed about a REACHABLE
    /// generation. The carrier is being aborted through the post-mortem sink,
    /// which answers the job wait; the settlement itself still finishes.
    LostExactTransition,
}

impl SettlementDisposition {
    const fn from_outcome(outcome: GenerationTransitionOutcome) -> Self {
        match outcome {
            GenerationTransitionOutcome::Recorded => Self::Settled,
            GenerationTransitionOutcome::TargetReaped => Self::TargetReaped,
            GenerationTransitionOutcome::LostExactTransition => Self::LostExactTransition,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorKickToken {
    executor: ExecutorId,
    executor_epoch: u64,
    thread: ThreadKey,
    generation: ExecutionGeneration,
}

impl ExecutorKickToken {
    pub const fn executor(self) -> ExecutorId {
        self.executor
    }

    pub const fn executor_epoch(self) -> u64 {
        self.executor_epoch
    }

    pub const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub const fn generation(self) -> ExecutionGeneration {
        self.generation
    }

    pub(crate) const fn binding(self) -> ExecutorBinding {
        ExecutorBinding {
            executor: self.executor,
            executor_epoch: self.executor_epoch,
            thread: self.thread,
            generation: self.generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorBinding {
    executor: ExecutorId,
    executor_epoch: u64,
    thread: ThreadKey,
    generation: ExecutionGeneration,
}

impl ExecutorBinding {
    pub const fn executor(self) -> ExecutorId {
        self.executor
    }

    pub const fn executor_epoch(self) -> u64 {
        self.executor_epoch
    }

    pub const fn thread(self) -> ThreadKey {
        self.thread
    }

    pub const fn generation(self) -> ExecutionGeneration {
        self.generation
    }

    const fn token(self) -> ExecutorKickToken {
        ExecutorKickToken {
            executor: self.executor,
            executor_epoch: self.executor_epoch,
            thread: self.thread,
            generation: self.generation,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecutorRegistration {
    id: ExecutorId,
    bound_cpu: Option<GuestCpuId>,
    is_spare: bool,
    close_observation_epoch: Arc<AtomicU64>,
    control_observation_epoch: Arc<AtomicU64>,
}

impl ExecutorRegistration {
    pub const fn id(&self) -> ExecutorId {
        self.id
    }

    pub const fn bound_cpu(&self) -> Option<GuestCpuId> {
        self.bound_cpu
    }

    pub const fn is_spare(&self) -> bool {
        self.is_spare
    }
}

#[derive(Debug)]
struct ExecutorEntry {
    kick: Arc<dyn ExecutorKick>,
    bound_cpu: Option<GuestCpuId>,
    close_observation_epoch: Arc<AtomicU64>,
    control_observation_epoch: Arc<AtomicU64>,
}

#[derive(Debug)]
struct ExecutorDirectoryState {
    next_id: u32,
    /// Round-robin cursor for binding the next executor to a guest CPU. Every
    /// non-spare executor IS one guest CPU's `M`; there is no unbound
    /// executor, so a carrier with fewer executors than CPUs simply leaves the
    /// surplus CPUs offline rather than stranding work on a CPU nothing runs.
    next_cpu: usize,
    entries: BTreeMap<ExecutorId, ExecutorEntry>,
}

impl Default for ExecutorDirectoryState {
    fn default() -> Self {
        Self {
            next_id: 1,
            next_cpu: 0,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Default)]
struct ExecutorDirectory {
    state: Mutex<ExecutorDirectoryState>,
}

impl ExecutorDirectory {
    fn register(
        &self,
        kick: Arc<dyn ExecutorKick>,
        requested_cpu: Option<GuestCpuId>,
        is_spare: bool,
        cpu_count: usize,
    ) -> Result<ExecutorRegistration, RunQueueError> {
        let mut state = self.state.lock();
        let bound_cpu = if is_spare {
            None
        } else {
            Some(requested_cpu.unwrap_or_else(|| {
                let index = state.next_cpu % cpu_count.max(1);
                state.next_cpu = state.next_cpu.wrapping_add(1);
                GuestCpuId::new(index as u32)
            }))
        };
        let raw = state.next_id;
        if raw == 0 {
            return Err(RunQueueError::ExecutorIdExhausted);
        }
        state.next_id = raw
            .checked_add(1)
            .ok_or(RunQueueError::ExecutorIdExhausted)?;
        let id = ExecutorId::from_scheduler(raw);
        let close_observation_epoch = Arc::new(AtomicU64::new(0));
        let control_observation_epoch = Arc::new(AtomicU64::new(0));
        state.entries.insert(
            id,
            ExecutorEntry {
                kick,
                bound_cpu,
                close_observation_epoch: Arc::clone(&close_observation_epoch),
                control_observation_epoch: Arc::clone(&control_observation_epoch),
            },
        );
        Ok(ExecutorRegistration {
            id,
            bound_cpu,
            is_spare,
            close_observation_epoch,
            control_observation_epoch,
        })
    }

    fn bind(
        &self,
        registration: &ExecutorRegistration,
        binding: ExecutorBinding,
    ) -> Result<(), RunQueueError> {
        let kick = self
            .state
            .lock()
            .entries
            .get(&registration.id)
            .map(|entry| Arc::clone(&entry.kick))
            .ok_or(RunQueueError::StaleExecutor)?;
        if !kick.try_bind(binding) {
            return Err(RunQueueError::ExecutorBusy);
        }
        Ok(())
    }

    fn unregister(&self, registration: &ExecutorRegistration) -> Result<(), RunQueueError> {
        let mut state = self.state.lock();
        let entry = state
            .entries
            .get(&registration.id)
            .ok_or(RunQueueError::StaleExecutor)?;
        if let Some(binding) = entry.kick.current_binding() {
            entry.kick.unbind(binding);
        }
        state.entries.remove(&registration.id);
        Ok(())
    }

    fn clear_binding(&self, registration: &ExecutorRegistration) -> Result<(), RunQueueError> {
        let kick = self
            .state
            .lock()
            .entries
            .get(&registration.id)
            .map(|entry| Arc::clone(&entry.kick))
            .ok_or(RunQueueError::StaleExecutor)?;
        if let Some(binding) = kick.current_binding() {
            kick.unbind(binding);
        }
        Ok(())
    }

    fn unbind(&self, binding: ExecutorBinding) {
        let kick = self
            .state
            .lock()
            .entries
            .get(&binding.executor)
            .map(|entry| Arc::clone(&entry.kick));
        let Some(kick) = kick else {
            return;
        };
        kick.unbind(binding);
    }

    fn rebind_exact_with(
        &self,
        predecessor: ExecutorBinding,
        successor: ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let kick = self
            .state
            .lock()
            .entries
            .get(&predecessor.executor)
            .map(|entry| Arc::clone(&entry.kick));
        kick.is_some_and(|kick| kick.rebind_exact_with(predecessor, successor, publish))
    }

    fn binding_for_thread(&self, thread: ThreadKey) -> Option<ExecutorBinding> {
        let kicks: Vec<_> = self
            .state
            .lock()
            .entries
            .values()
            .map(|entry| Arc::clone(&entry.kick))
            .collect();
        kicks
            .into_iter()
            .filter_map(|kick| kick.current_binding())
            .find(|binding| binding.thread == thread)
    }

    fn has_running(&self) -> bool {
        let kicks: Vec<_> = self
            .state
            .lock()
            .entries
            .values()
            .map(|entry| Arc::clone(&entry.kick))
            .collect();
        kicks
            .into_iter()
            .any(|kick| kick.current_binding().is_some())
    }

    fn current_tokens(&self) -> Vec<ExecutorKickToken> {
        let kicks: Vec<_> = self
            .state
            .lock()
            .entries
            .values()
            .map(|entry| Arc::clone(&entry.kick))
            .collect();
        kicks
            .into_iter()
            .filter_map(|kick| kick.current_binding().map(ExecutorBinding::token))
            .collect()
    }

    fn deliver(&self, token: ExecutorKickToken) -> bool {
        let kick = self
            .state
            .lock()
            .entries
            .get(&token.executor)
            .map(|entry| Arc::clone(&entry.kick));
        kick.is_some_and(|kick| kick.deliver_exact(token))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
enum QueueLifecycle {
    #[default]
    Open = 0,
    Closing = 1,
    Closed = 2,
}

impl QueueLifecycle {
    const fn from_raw(raw: u8) -> Self {
        match raw {
            0 => Self::Open,
            1 => Self::Closing,
            _ => Self::Closed,
        }
    }
}

#[derive(Debug)]
pub(crate) struct QueueRow {
    pub(crate) key: QueueKey,
    pub(crate) thread: Arc<Thread>,
    pub(crate) closing_authorized: bool,
}

/// One guest CPU's local run queue and parking bookkeeping, behind that CPU's
/// OWN mutex. The carrier-wide [`RunQueueInner::state`] lock is reserved for
/// lifecycle (close/drain) and is never taken to enqueue or claim.
#[derive(Debug, Default)]
struct GuestCpuLocalState {
    rows: VecDeque<QueueRow>,
    /// Executors parked on this CPU's condvar. Exact: incremented and
    /// decremented under this lock, so `close` can snapshot it.
    waiters: usize,
    /// Bumped by any publisher that wants this CPU to re-run its scan.
    ///
    /// A CPU samples the ticket BEFORE it announces itself idle and re-reads
    /// it under this lock immediately before parking, so a publication that
    /// lands on ANOTHER CPU in that window (which this CPU could only have
    /// found by stealing, and which therefore cannot be re-checked under this
    /// lock) is never lost: either the publisher saw the idle flag and bumped
    /// the ticket, or it did not, in which case the flag was stored after the
    /// publisher's load and this CPU's steal scan runs after the publication.
    wake_ticket: u64,
}

/// A guest CPU — `P` in Go's G/M/P. The unit of guest parallelism: it owns a
/// local run queue, the current task, an idle condvar for the executor bound
/// to it, and the identity the guest observes through `sched_getcpu`,
/// `getcpu(2)`, `sched_getaffinity` and `/proc/<pid>/stat` field 39.
#[derive(Debug)]
pub struct GuestCpu {
    id: GuestCpuId,
    state: Mutex<GuestCpuLocalState>,
    idle_condvar: Condvar,
    /// `rows.len()` published for lock-free load reads on the placement path.
    depth: AtomicUsize,
    /// Executors bound to this CPU that are parked, or have announced
    /// idleness and are about to park. COUNTED, not a flag: several `M`s may
    /// share one `P`, and a bool made a CPU with one executor running and two
    /// parked read "busy" to every placement and wake decision — the round-1
    /// defect that serialized a fork burst behind the parent's CPU.
    ///
    /// Incremented `SeqCst` before the final steal scan; see `wake_ticket`.
    idle: AtomicUsize,
    current_task: Mutex<Option<ThreadKey>>,
}

impl GuestCpu {
    fn new(id: GuestCpuId) -> Self {
        Self {
            id,
            state: Mutex::new(GuestCpuLocalState::default()),
            idle_condvar: Condvar::new(),
            depth: AtomicUsize::new(0),
            idle: AtomicUsize::new(0),
            current_task: Mutex::new(None),
        }
    }

    pub const fn id(&self) -> GuestCpuId {
        self.id
    }

    /// Queue depth. Lock-free; a placement decision reads every CPU's depth.
    pub fn queue_len(&self) -> usize {
        self.depth.load(Ordering::Acquire)
    }

    /// Executors here that are parked or about to park. Lock-free; this is
    /// the availability half of the placement signal.
    pub fn idle_executors(&self) -> usize {
        self.idle.load(Ordering::SeqCst)
    }

    pub fn current_task(&self) -> Option<ThreadKey> {
        *self.current_task.lock()
    }

    pub(crate) fn set_current_task(&self, task: Option<ThreadKey>) {
        *self.current_task.lock() = task;
    }

    /// Signal this CPU so a parked (or about-to-park) executor re-runs its
    /// scan. Takes the CPU lock so the bump cannot slip into the window
    /// between an executor's pre-park re-check and its `wait`.
    fn nudge(&self) {
        {
            let mut local = self.state.lock();
            local.wake_ticket = local.wake_ticket.wrapping_add(1);
        }
        self.idle_condvar.notify_all();
    }
}

/// One executor's idle announcement on one guest CPU.
///
/// A guard rather than two bare stores: `take_row` leaves the idle state
/// through six different returns, and a counted announcement that is dropped
/// on any of them would credit the CPU with a phantom free executor forever —
/// placement would keep aiming rows at a CPU that will never take them. The
/// count is exact because releasing is the destructor.
struct IdleAnnouncement<'a> {
    cpu: &'a GuestCpu,
    held: bool,
}

impl<'a> IdleAnnouncement<'a> {
    fn new(cpu: &'a GuestCpu) -> Self {
        Self { cpu, held: false }
    }

    /// Announce BEFORE the final scan, so a publisher either sees this
    /// executor and bumps the ticket, or stored its row first and the scan
    /// finds it. Idempotent within one loop iteration.
    fn announce(&mut self) {
        if !self.held {
            self.cpu.idle.fetch_add(1, Ordering::SeqCst);
            self.held = true;
        }
    }

    fn is_held(&self) -> bool {
        self.held
    }

    fn release(&mut self) {
        if self.held {
            if self.cpu.idle.fetch_sub(1, Ordering::SeqCst) == 0 {
                // An idle count that went negative means an executor released
                // an announcement it never took: placement and wake targeting
                // would both be reading a fiction from here on.
                std::process::abort();
            }
            self.held = false;
        }
    }
}

impl Drop for IdleAnnouncement<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// One shard of the carrier-wide exact-key directory.
///
/// A key may be queued on only one guest CPU at a time; stealing moves the
/// row, not the membership, so membership, the unpublished gate and the row
/// deferred behind that gate all live here rather than on a CPU.
#[derive(Debug, Default)]
struct QueueKeyShard {
    /// Exact keys that own a queue slot: a claimable row on some CPU, or a
    /// row held in `deferred`.
    queued: BTreeSet<QueueKey>,
    /// Exact keys whose submission authority has been admitted but not yet
    /// published. A wake for such a key is durable and coalescing, but its
    /// row is held in `deferred` instead of becoming claimable: the task's
    /// binding is still dormant, so a claim could only fail it.
    unpublished: BTreeSet<QueueKey>,
    /// Exact keys reserved BEFORE their thread was published to the Kernel as
    /// `Runnable`, by [`Scheduler::publish_initial_task_state_gated`].
    ///
    /// Distinct from `unpublished` because it has a different lifetime. An
    /// admission gate belongs to one authority and dies with it; a
    /// pre-publication reservation belongs to the THREAD's first generation
    /// and must outlive every authority that fails over it, because the clone
    /// rollback's `drop(dormant)` releases the authority while the child is
    /// still Kernel-runnable and still wakeable. It is retired only by that
    /// generation's first publication or its terminal retirement, both of
    /// which are bounded, so it cannot strand a long-lived thread's rows the
    /// way a lifetime-wide gate did (measured on the pre-per-CPU queue: a
    /// `go build` regression of 5 aborts in 46 runs, 0 in 46 on main).
    prepublication: BTreeSet<QueueKey>,
    /// The one row a wake enqueued for a gated key, held until that key is
    /// published (or, for an admission gate, until its authority is released).
    deferred: BTreeMap<QueueKey, QueueRow>,
}

impl QueueKeyShard {
    /// Whether any gate currently denies claimability for this exact key.
    fn gated(&self, key: QueueKey) -> bool {
        self.unpublished.contains(&key) || self.prepublication.contains(&key)
    }
}

#[derive(Debug, Default)]
struct RunQueueState {
    lifecycle: QueueLifecycle,
    /// Spare executors parked on `changed`. Per-CPU waiters live in each
    /// [`GuestCpuLocalState`]; `close` snapshots both.
    spare_waiters: usize,
    close_epoch: u64,
    close_waiters_expected: usize,
    closed_waiter_observations: usize,
}

/// Parked executors right now, or the reason the census could not be taken.
///
/// A non-blocking reader that cannot get a run-queue lock must say so. An
/// `Option`/`0` would let "nobody is parked" and "I could not look" share one
/// value, which is precisely the confusion an abort sink cannot afford.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaiterCensus {
    /// Every run-queue lock was uncontended; this is the exact count.
    Exact(usize),
    /// A run-queue lock was held elsewhere. The reader reported it instead of
    /// joining the queue behind a holder that may itself be stuck.
    RunQueueLocked,
}

impl WaiterCensus {
    /// The count when it is exact, `None` when a lock was contended.
    pub fn exact(self) -> Option<usize> {
        match self {
            Self::Exact(count) => Some(count),
            Self::RunQueueLocked => None,
        }
    }

    /// Whether the census lost to a contended run-queue lock.
    pub fn is_run_queue_locked(self) -> bool {
        matches!(self, Self::RunQueueLocked)
    }
}

/// The run-queue picture the kernel-debug endpoint and the post-mortem sink
/// read. Every field is either published atomically or read with `try_lock`,
/// so building one never blocks.
#[derive(Clone, Debug)]
pub struct SchedulerSummary {
    pub lifecycle: String,
    pub queued_len: usize,
    pub claimed: usize,
    pub waiters: WaiterCensus,
    pub control_epoch: u64,
    pub need_resched: bool,
    pub snapshot_count: u64,
}

/// What a queue insertion did with one exact row. A bare `bool` said only
/// "queued or coalesced", which cannot express the third case the pre-
/// activation window needs: durably queued but deliberately NOT claimable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnqueueOutcome {
    /// The row is queued and an executor may claim it now.
    Claimable,
    /// The row is queued and held until its submission is published.
    Deferred,
    /// An exact row for this key was already queued.
    Coalesced,
}

impl EnqueueOutcome {
    /// Whether this insertion took ownership of the wake edge. A deferred row
    /// is queued exactly as a claimable one is -- `Scheduler::wake` reports
    /// `Queued` for it and a second wake coalesces onto it.
    const fn queued(self) -> bool {
        !matches!(self, Self::Coalesced)
    }
}

#[derive(Debug)]
struct RunQueueInner {
    /// Lifecycle ONLY. Never taken to enqueue, claim, finish a claim or
    /// release an authority while the queue is open — that carrier-wide
    /// convoy is what this design exists to remove.
    state: Mutex<RunQueueState>,
    /// Lifecycle waiters: parked spare executors and `wait_closed`.
    changed: Condvar,
    /// Lock-free mirror of `state.lifecycle`, `SeqCst` so that a decrementer
    /// that misses the close and a `close` that misses the decrement cannot
    /// both happen (Dekker): one of the two always runs `maybe_finish_close`.
    lifecycle: AtomicU8,
    wake_admissions: AtomicU64,
    control_epoch: AtomicU64,
    claimed: AtomicUsize,
    /// Monotone count of claim BOUNDARIES crossed: one per claim taken and one
    /// per claim finished.
    ///
    /// `claimed` is a level, not an edge. Two executors handing work back and
    /// forth hold it at a constant 1 while the carrier plainly progresses, and
    /// the liveness census judges "nothing moved" by comparing two censuses
    /// for EQUALITY -- so the level alone cannot tell a carrier that is
    /// working from one that is stranded. This counter is the edge term that
    /// makes an unchanged census mean exactly "no claim boundary crossed".
    claim_boundaries: AtomicU64,
    total_queued: AtomicUsize,
    active_authorities: AtomicUsize,
    close_epoch: AtomicU64,
    /// Carrier-wide exact-key dedup, sharded so a wake never contends with an
    /// unrelated wake. A key may be queued on only one CPU at a time; work
    /// stealing moves the row, not the membership.
    keys: Vec<Mutex<QueueKeyShard>>,
    cpus: Vec<Arc<GuestCpu>>,
    /// How many executors are bound to each CPU. A CPU with none is OFFLINE:
    /// nothing runs there, so placement must never target it or the task
    /// starves until an idle CPU steals it. Stealing still drains an offline
    /// CPU, so an executor that retires never strands its queue.
    online: Vec<AtomicUsize>,
    policy: Arc<dyn SchedulingPolicy>,
    #[cfg(test)]
    close_observation_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(test)]
    root_admission_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(test)]
    close_started_gate: Mutex<Option<Arc<std::sync::Barrier>>>,
    #[cfg(test)]
    pre_park_gate: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

impl RunQueueInner {
    const CLOSING_BIT: u64 = 1 << 63;
    const QUEUED_SHARDS: usize = 64;

    fn shard_index(&self, key: QueueKey) -> usize {
        (key.thread.serial.raw() as usize) % self.keys.len()
    }

    fn shard(&self, key: QueueKey) -> &Mutex<QueueKeyShard> {
        &self.keys[self.shard_index(key)]
    }

    /// Mark one admitted-but-unpublished exact key. The gate lives in the same
    /// shard the key's queue membership does, so a wake for the key and its
    /// publication are ordered against each other by one lock even though the
    /// row itself lands on a per-CPU queue.
    fn mark_unpublished(&self, key: QueueKey) {
        self.shard(key).lock().unpublished.insert(key);
    }

    /// Drop an exact key's unpublished gate and any row held behind it. The
    /// wake edge is discarded with the row because the submission it named is
    /// gone; nothing can claim that generation again. A deferred row was never
    /// on a CPU queue, so `total_queued` never counted it and does not change.
    fn clear_unpublished(&self, key: QueueKey) {
        let mut shard = self.shard(key).lock();
        // The ADMISSION gate dies with its authority, as it did in 119f07e97.
        // What must NOT die with it is the thread's pre-publication
        // reservation: the clone rollback's `drop(dormant)` releases this
        // authority while the child is still Kernel-runnable and wakeable, and
        // a claim there is the abort the reservation exists to stop.
        shard.unpublished.remove(&key);
        if shard.deferred.remove(&key).is_some() {
            shard.queued.remove(&key);
        }
    }

    /// Reserve one exact key ahead of its thread's Kernel publication, so the
    /// key is unclaimable from the instant a producer can wake it.
    fn reserve_prepublication(&self, key: QueueKey) {
        self.shard(key).lock().prepublication.insert(key);
    }

    /// Retire every gate on one exact key, and the row held behind it. Only
    /// the terminal retirement of that exact generation may do this: after
    /// `fail_runnable_exact` / `fail_blocked_exact` the Kernel refuses to
    /// queue the generation at all, so a gate has nothing left to guard and
    /// keeping it would leak one entry per failed submission.
    fn retire_gates(shard: &mut QueueKeyShard, key: QueueKey) {
        shard.unpublished.remove(&key);
        shard.prepublication.remove(&key);
    }

    /// Move an unpublished gate (and the row deferred behind it) from one
    /// exact key to another. The two keys may hash to different shards, so
    /// both are taken in index order.
    fn retarget_unpublished_gate(&self, from: QueueKey, to: QueueKey) {
        if from == to {
            return;
        }
        let (source_index, target_index) = (self.shard_index(from), self.shard_index(to));
        if source_index == target_index {
            let mut shard = self.keys[source_index].lock();
            if shard.unpublished.remove(&from) {
                shard.unpublished.insert(to);
            }
            if let Some(mut held) = shard.deferred.remove(&from) {
                shard.queued.remove(&from);
                held.key = to;
                shard.queued.insert(to);
                shard.deferred.insert(to, held);
            }
            return;
        }
        let (low, high) = if source_index < target_index {
            (source_index, target_index)
        } else {
            (target_index, source_index)
        };
        let mut low_shard = self.keys[low].lock();
        let mut high_shard = self.keys[high].lock();
        let (source, target) = if source_index < target_index {
            (&mut *low_shard, &mut *high_shard)
        } else {
            (&mut *high_shard, &mut *low_shard)
        };
        if source.unpublished.remove(&from) {
            target.unpublished.insert(to);
        }
        if let Some(mut held) = source.deferred.remove(&from) {
            source.queued.remove(&from);
            held.key = to;
            target.queued.insert(to);
            target.deferred.insert(to, held);
        }
    }

    fn lifecycle(&self) -> QueueLifecycle {
        QueueLifecycle::from_raw(self.lifecycle.load(Ordering::SeqCst))
    }

    fn publish_lifecycle(&self, state: &mut RunQueueState, next: QueueLifecycle) {
        state.lifecycle = next;
        self.lifecycle.store(next as u8, Ordering::SeqCst);
    }

    fn poke_control(&self) {
        if self.control_epoch.fetch_add(1, Ordering::AcqRel) == u64::MAX {
            std::process::abort();
        }
        self.nudge_all_cpus();
        self.changed.notify_all();
    }

    fn nudge_all_cpus(&self) {
        for cpu in &self.cpus {
            cpu.nudge();
        }
    }

    fn try_admit_wake(self: &Arc<Self>) -> Result<WakeAdmission, RunQueueError> {
        let mut observed = self.wake_admissions.load(Ordering::Acquire);
        loop {
            if observed & Self::CLOSING_BIT != 0 {
                return Err(RunQueueError::Closed);
            }
            let count = observed & !Self::CLOSING_BIT;
            let next = count
                .checked_add(1)
                .filter(|next| *next < Self::CLOSING_BIT)
                .ok_or(RunQueueError::AuthoritiesExhausted)?;
            match self.wake_admissions.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(WakeAdmission {
                        queue: Arc::downgrade(self),
                        active: true,
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn begin_close(&self) {
        self.wake_admissions
            .fetch_or(Self::CLOSING_BIT, Ordering::AcqRel);
    }

    fn active_wake_admissions(&self) -> u64 {
        self.wake_admissions.load(Ordering::Acquire) & !Self::CLOSING_BIT
    }

    fn release_wake_admission(&self) {
        let previous = self.wake_admissions.fetch_sub(1, Ordering::SeqCst);
        if previous & !Self::CLOSING_BIT == 0 {
            std::process::abort();
        }
        self.settle_close_if_closing();
    }

    /// The one place a drain-relevant decrement pays for the carrier lock —
    /// and only once the queue is closing. While open this is a single
    /// `SeqCst` load, which is the whole point of the per-CPU design.
    fn settle_close_if_closing(&self) {
        if self.lifecycle() == QueueLifecycle::Open {
            return;
        }
        {
            let mut state = self.state.lock();
            self.maybe_finish_close(&mut state);
            self.changed.notify_all();
        }
        self.nudge_all_cpus();
    }

    /// Per-CPU executor availability and backlog, for the placement policy.
    /// Lock-free: a placement is taken on every wake.
    fn cpu_loads(&self, loads: &mut [CpuLoad; carrick_hal::MAX_GUEST_CPUS]) -> usize {
        for (index, (slot, cpu)) in loads.iter_mut().zip(self.cpus.iter()).enumerate() {
            *slot = CpuLoad {
                queued: cpu.queue_len(),
                idle: cpu.idle_executors(),
                bound: self
                    .online
                    .get(index)
                    .map(|slot| slot.load(Ordering::Acquire))
                    .unwrap_or(0),
            };
        }
        self.cpus.len()
    }

    fn set_executor_online(&self, cpu: GuestCpuId, online: bool) {
        let Some(slot) = self.online.get(cpu.as_usize()) else {
            return;
        };
        if online {
            slot.fetch_add(1, Ordering::AcqRel);
        } else if slot.fetch_sub(1, Ordering::AcqRel) == 0 {
            std::process::abort();
        }
    }

    /// The CPUs that currently have an executor. Empty only before the pool
    /// starts, where any CPU is as good as another.
    fn online_mask(&self) -> Option<CpuAffinity> {
        let mut words = [0u64; carrick_hal::MAX_GUEST_CPUS.div_ceil(64)];
        let mut any = false;
        for (index, slot) in self.online.iter().enumerate() {
            if slot.load(Ordering::Acquire) > 0 {
                words[index / 64] |= 1u64 << (index % 64);
                any = true;
            }
        }
        any.then(|| CpuAffinity::from_words(&words))
    }

    fn select_cpu(&self, thread: &Thread) -> GuestCpuId {
        let mut loads = [CpuLoad::default(); carrick_hal::MAX_GUEST_CPUS];
        let ncpu = self.cpu_loads(&mut loads);
        let declared = thread.affinity();
        // The guest's mask says where the task MAY run; the online set says
        // where anything runs at all. A policy is only ever offered CPUs that
        // satisfy both, so it cannot place a task onto a CPU with no `M`.
        let affinity = match self.online_mask() {
            Some(online) if !declared.intersect(&online).is_empty() => declared.intersect(&online),
            _ => declared,
        };
        let placement = TaskPlacement {
            task: TaskKey::new(thread.task_key().serial.raw()),
            last_cpu: thread.last_cpu(),
            affinity,
            cpus: &loads[..ncpu],
        };
        let chosen = self.policy.select_cpu(&placement);
        // The mechanism, not the policy, owns the affinity guarantee: a policy
        // that answers out of range or outside the mask does not get to place
        // a task where the guest was promised it cannot run.
        if chosen.as_usize() < ncpu && affinity.is_allowed(chosen) {
            return chosen;
        }
        affinity
            .first_allowed(ncpu)
            .unwrap_or_else(|| GuestCpuId::new(0))
    }

    fn drain_ready(&self) -> bool {
        self.total_queued.load(Ordering::SeqCst) == 0
            && self.active_authorities.load(Ordering::SeqCst) == 0
            && self.claimed.load(Ordering::SeqCst) == 0
            && self.active_wake_admissions() == 0
    }

    fn maybe_finish_close(&self, state: &mut RunQueueState) {
        if state.lifecycle != QueueLifecycle::Closing || !self.drain_ready() {
            return;
        }
        if state.closed_waiter_observations >= state.close_waiters_expected {
            self.publish_lifecycle(state, QueueLifecycle::Closed);
        }
        self.changed.notify_all();
    }

    fn enqueue(
        &self,
        row: QueueRow,
        closing_authorized: bool,
        target_cpu: Option<GuestCpuId>,
    ) -> Result<EnqueueOutcome, RunQueueError> {
        match self.lifecycle() {
            QueueLifecycle::Closed => return Err(RunQueueError::Closed),
            QueueLifecycle::Closing if !closing_authorized => {
                return Err(RunQueueError::SubmissionRejected);
            }
            _ => {}
        }
        let affinity = row.thread.affinity();
        let target = target_cpu
            .filter(|cpu| cpu.as_usize() < self.cpus.len() && affinity.is_allowed(*cpu))
            .unwrap_or_else(|| self.select_cpu(&row.thread));
        let index = target.as_usize().min(self.cpus.len().saturating_sub(1));
        let cpu = &self.cpus[index];
        let key = row.key;
        let task = TaskKey::new(row.thread.task_key().serial.raw());

        let waiter_present = {
            let mut local = cpu.state.lock();
            let mut shard = self.shard(key).lock();
            if shard.queued.contains(&key) {
                return Ok(EnqueueOutcome::Coalesced);
            }
            shard.queued.insert(key);
            if shard.gated(key) {
                // The submission that owns this exact generation is admitted
                // but still dormant, or the thread was reserved ahead of its
                // Kernel publication and owns no submission at all. Either way
                // no binding is resolvable for the key yet.
                //
                // Own the wake edge -- it must not be lost
                // -- and hold the row off every CPU queue until publication
                // makes the binding resolvable. A deferred row is invisible to
                // a claim, a steal and a nudge alike, which is the whole point:
                // on the per-CPU representation "not claimable" also has to
                // mean "not stealable".
                shard.deferred.insert(key, row);
                return Ok(EnqueueOutcome::Deferred);
            }
            drop(shard);
            local.rows.push_back(row);
            cpu.depth.store(local.rows.len(), Ordering::Release);
            self.total_queued.fetch_add(1, Ordering::SeqCst);
            local.wake_ticket = local.wake_ticket.wrapping_add(1);
            local.waiters > 0
        };
        cpu.idle_condvar.notify_one();
        if !waiter_present {
            // Nobody is parked on the target CPU, so its executor is busy with
            // a task and this row would wait behind it. Go's `wakep`: hand it
            // to an idle CPU that can steal it.
            self.wake_idle_cpu(cpu.id);
        }
        self.policy.on_runnable(task, cpu.id);
        Ok(EnqueueOutcome::Claimable)
    }

    /// Publish the exact row an activated submission owns, releasing any row
    /// a wake queued for it while it was dormant.
    ///
    /// This is the ONLY transition that clears a key's unpublished mark, and
    /// it is the same critical section that moves the row onto a CPU queue, so
    /// a row can never be claimed (or stolen) before its submission is active.
    fn publish(&self, row: QueueRow) -> Result<EnqueueOutcome, RunQueueError> {
        if self.lifecycle() == QueueLifecycle::Closed {
            return Err(RunQueueError::Closed);
        }
        let key = row.key;
        let affinity = row.thread.affinity();
        let target = self.select_cpu(&row.thread);
        let index = target.as_usize().min(self.cpus.len().saturating_sub(1));
        let index = if affinity.is_allowed(GuestCpuId::new(index as u32)) {
            index
        } else {
            0
        };
        let cpu = &self.cpus[index];
        let task = TaskKey::new(row.thread.task_key().serial.raw());

        let waiter_present = {
            let mut local = cpu.state.lock();
            let mut shard = self.shard(key).lock();
            // Publication is the ordinary lift for BOTH gates: the admission
            // gate of the submission being published, and the thread's
            // pre-publication reservation, whose first generation this is.
            Self::retire_gates(&mut shard, key);
            let publishable = if let Some(held) = shard.deferred.remove(&key) {
                // The membership a deferred wake took stays; only the row moves.
                held
            } else if shard.queued.contains(&key) {
                return Ok(EnqueueOutcome::Coalesced);
            } else {
                shard.queued.insert(key);
                row
            };
            drop(shard);
            local.rows.push_back(publishable);
            cpu.depth.store(local.rows.len(), Ordering::Release);
            self.total_queued.fetch_add(1, Ordering::SeqCst);
            local.wake_ticket = local.wake_ticket.wrapping_add(1);
            local.waiters > 0
        };
        cpu.idle_condvar.notify_one();
        if !waiter_present {
            self.wake_idle_cpu(cpu.id);
        }
        self.policy.on_runnable(task, cpu.id);
        Ok(EnqueueOutcome::Claimable)
    }

    /// Nudge one idle CPU other than `origin` so it re-runs its steal scan —
    /// Go's `wakep`. Exactly one, never a herd: the woken executor continues
    /// the chain itself (`propagate_wake`) if work is still queued when it
    /// takes a row, so the wake spreads until either the queues are empty or
    /// no CPU is idle.
    ///
    /// The scan starts after `origin` and wraps, so a burst does not pile
    /// every nudge onto the lowest-numbered idle CPU.
    fn wake_idle_cpu(&self, origin: GuestCpuId) {
        let ncpu = self.cpus.len();
        if ncpu == 0 {
            return;
        }
        let start = (origin.as_usize() + 1) % ncpu;
        for step in 0..ncpu {
            let index = (start + step) % ncpu;
            let cpu = &self.cpus[index];
            if cpu.id != origin && cpu.idle_executors() > 0 {
                cpu.nudge();
                return;
            }
        }
    }

    /// The next link in the wake chain: an executor that was woken to scan and
    /// FOUND work hands the remaining backlog to the next idle CPU before it
    /// starts running.
    ///
    /// Without this, `enqueue`'s single nudge is lossy — the woken executor
    /// may take a different row than the one that nudged it, and that row then
    /// waits until its own CPU's running task blocks. With it, "a runnable row
    /// exists while an executor is parked" is only ever transient.
    fn propagate_wake(&self, stealer: GuestCpuId) {
        if self.total_queued.load(Ordering::SeqCst) > 0 {
            self.wake_idle_cpu(stealer);
        }
    }

    /// Pop `cpu`'s FIFO head (or the policy's choice), accounting the claim.
    fn pop_local(&self, cpu: &GuestCpu) -> Option<QueueRow> {
        let mut local = cpu.state.lock();
        if local.rows.is_empty() {
            return None;
        }
        let position = self.policy_pick(cpu.id, &local).unwrap_or(0);
        let row = local.rows.remove(position)?;
        self.finish_removal(&mut local, cpu, row.key);
        Some(row)
    }

    /// Consult `pick_next` only for a policy that asked to see the queues.
    fn policy_pick(&self, cpu: GuestCpuId, local: &GuestCpuLocalState) -> Option<usize> {
        if !self.policy.inspects_queues() {
            return None;
        }
        let queued: Vec<TaskKey> = local
            .rows
            .iter()
            .map(|row| TaskKey::new(row.thread.task_key().serial.raw()))
            .collect();
        let chosen = self.policy.pick_next(&CpuQueueView {
            cpu,
            queued: &queued,
        })?;
        queued.iter().position(|task| *task == chosen)
    }

    /// Common bookkeeping for taking a row out of a CPU queue: the claim is
    /// accounted BEFORE the queue depth drops, so a concurrent `drain_ready`
    /// can never observe a moment where the row is in neither count.
    fn finish_removal(&self, local: &mut GuestCpuLocalState, cpu: &GuestCpu, key: QueueKey) {
        self.claimed.fetch_add(1, Ordering::SeqCst);
        self.claim_boundaries.fetch_add(1, Ordering::SeqCst);
        self.shard(key).lock().queued.remove(&key);
        cpu.depth.store(local.rows.len(), Ordering::Release);
        self.total_queued.fetch_sub(1, Ordering::SeqCst);
    }

    /// `findrunnable`'s steal: an idle CPU takes work from the longest queue,
    /// honouring the stolen task's affinity mask.
    fn try_steal(&self, stealer: GuestCpuId) -> Option<QueueRow> {
        if self.policy.inspects_queues()
            && let Some(row) = self.policy_steal(stealer)
        {
            return Some(row);
        }
        let mut victims: Vec<(usize, usize)> = self
            .cpus
            .iter()
            .enumerate()
            .filter(|(index, cpu)| *index != stealer.as_usize() && cpu.queue_len() > 0)
            .map(|(index, cpu)| (index, cpu.queue_len()))
            .collect();
        victims.sort_by_key(|(_, depth)| std::cmp::Reverse(*depth));
        for (index, _) in victims {
            let victim = &self.cpus[index];
            let mut local = victim.state.lock();
            // Steal from the TAIL: the head is the oldest row and the most
            // likely to still be warm on its owner.
            let Some(position) = local
                .rows
                .iter()
                .rposition(|row| row.thread.affinity().is_allowed(stealer))
            else {
                continue;
            };
            let row = local.rows.remove(position)?;
            self.finish_removal(&mut local, victim, row.key);
            return Some(row);
        }
        None
    }

    fn policy_steal(&self, stealer: GuestCpuId) -> Option<QueueRow> {
        let snapshots: Vec<(GuestCpuId, Vec<TaskKey>)> = self
            .cpus
            .iter()
            .filter(|cpu| cpu.id != stealer)
            .map(|cpu| {
                let local = cpu.state.lock();
                (
                    cpu.id,
                    local
                        .rows
                        .iter()
                        .map(|row| TaskKey::new(row.thread.task_key().serial.raw()))
                        .collect(),
                )
            })
            .collect();
        let views: Vec<CpuQueueView<'_>> = snapshots
            .iter()
            .map(|(cpu, queued)| CpuQueueView {
                cpu: *cpu,
                queued: queued.as_slice(),
            })
            .collect();
        let (victim_id, task) = self.policy.steal(stealer, &views)?;
        if victim_id == stealer {
            return None;
        }
        let victim = self.cpus.get(victim_id.as_usize())?;
        let mut local = victim.state.lock();
        let position = local.rows.iter().position(|row| {
            row.thread.task_key().serial.raw() == task.as_u64()
                && row.thread.affinity().is_allowed(stealer)
        })?;
        let row = local.rows.remove(position)?;
        self.finish_removal(&mut local, victim, row.key);
        Some(row)
    }

    fn finish_claim(&self) {
        if self.claimed.fetch_sub(1, Ordering::SeqCst) == 0 {
            std::process::abort();
        }
        self.claim_boundaries.fetch_add(1, Ordering::SeqCst);
        self.settle_close_if_closing();
    }

    fn release_authority(&self, key: QueueKey) {
        // Clear the gate BEFORE the count drops: once the count reaches zero a
        // close may finish, and a gate (or a row deferred behind one) outliving
        // its authority would be reachable by nothing.
        self.clear_unpublished(key);
        if self.active_authorities.fetch_sub(1, Ordering::SeqCst) == 0 {
            std::process::abort();
        }
        self.settle_close_if_closing();
    }

    /// Admit one authority. The lifecycle check and the increment are one
    /// transaction under the carrier lock, so a `close` can never observe a
    /// drained queue while an admission is in flight.
    fn admit_authority(&self) -> Result<(), RunQueueError> {
        let state = self.state.lock();
        if state.lifecycle == QueueLifecycle::Closed {
            return Err(RunQueueError::Closed);
        }
        if self
            .active_authorities
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            })
            .is_err()
        {
            return Err(RunQueueError::SubmissionRejected);
        }
        drop(state);
        Ok(())
    }

    /// Admit one authority whose exact key is not published yet. Marking the
    /// gate is part of the admission, so an admitted authority never exists
    /// without it.
    fn admit_unpublished_authority(&self, key: QueueKey) -> Result<(), RunQueueError> {
        self.admit_authority()?;
        self.mark_unpublished(key);
        Ok(())
    }
}

#[derive(Debug)]
struct WakeAdmission {
    queue: Weak<RunQueueInner>,
    active: bool,
}

impl Drop for WakeAdmission {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(queue) = self.queue.upgrade() {
            queue.release_wake_admission();
        }
        self.active = false;
    }
}

/// Queue authority retained by an exact active generation. New roots may be
/// admitted only while open; descendants of this retained authority may be
/// admitted while closing so recursive fork publication cannot be stranded.
#[derive(Debug)]
pub(crate) struct SubmissionAuthority {
    queue: Weak<RunQueueInner>,
    kernel: Weak<Kernel>,
    key: QueueKey,
    active: bool,
}

impl SubmissionAuthority {
    pub(crate) const fn thread_key(&self) -> ThreadKey {
        self.key.thread
    }

    pub(crate) const fn generation(&self) -> ExecutionGeneration {
        self.key.generation
    }

    pub(crate) const fn is_active(&self) -> bool {
        self.active
    }

    pub(crate) fn rollover_exact(
        mut self,
        scheduler: &Scheduler,
        predecessor_thread: ThreadKey,
        predecessor_generation: ExecutionGeneration,
        successor_thread: ThreadKey,
        successor_generation: ExecutionGeneration,
    ) -> Result<Self, (RunQueueError, Self)> {
        let exact_successor = predecessor_generation
            .raw()
            .checked_add(1)
            .is_some_and(|next| next == successor_generation.raw());
        if !self.active
            || self.key.thread != predecessor_thread
            || self.key.generation != predecessor_generation
            || predecessor_thread != successor_thread
            || !exact_successor
        {
            return Err((RunQueueError::AuthorityMismatch, self));
        }
        let Some(queue) = self.queue.upgrade() else {
            return Err((RunQueueError::Closed, self));
        };
        let Some(kernel) = self.kernel.upgrade() else {
            return Err((RunQueueError::Closed, self));
        };
        if !Arc::ptr_eq(&queue, &scheduler.queue.inner)
            || !Arc::ptr_eq(&kernel, &scheduler.kernel)
            || kernel
                .with_live_active_scheduler_thread(successor_thread, successor_generation, || ())
                .is_none()
        {
            return Err((RunQueueError::AuthorityMismatch, self));
        }
        self.retarget_unpublished_gate(&queue, successor_thread, successor_generation);
        self.key = QueueKey {
            thread: successor_thread,
            generation: successor_generation,
        };
        Ok(self)
    }

    /// Move an unpublished gate onto the successor key. A submission that has
    /// never been published owns no claimable row, and that stays true across
    /// a generation rollover or an exec replacement: the gate travels with the
    /// key rather than being silently left on the retired one.
    fn retarget_unpublished_gate(
        &self,
        queue: &Arc<RunQueueInner>,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) {
        queue.retarget_unpublished_gate(self.key, QueueKey { thread, generation });
    }

    pub(crate) fn park_exact(
        self,
        scheduler: &Scheduler,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
    ) -> Result<Self, (RunQueueError, Self)> {
        let thread = self.thread_key();
        let mut authority =
            self.rollover_exact(scheduler, thread, predecessor, thread, successor)?;
        if let Some(queue) = authority.queue.upgrade() {
            queue.release_authority(authority.key);
        }
        authority.active = false;
        Ok(authority)
    }

    pub(crate) fn replace_exec_exact(
        mut self,
        scheduler: &Scheduler,
        predecessor_thread: ThreadKey,
        predecessor_generation: ExecutionGeneration,
        successor_thread: ThreadKey,
        successor_generation: ExecutionGeneration,
    ) -> Result<Self, (RunQueueError, Self)> {
        if !self.active
            || self.key.thread != predecessor_thread
            || self.key.generation != predecessor_generation
        {
            return Err((RunQueueError::AuthorityMismatch, self));
        }
        let Some(queue) = self.queue.upgrade() else {
            return Err((RunQueueError::Closed, self));
        };
        let Some(kernel) = self.kernel.upgrade() else {
            return Err((RunQueueError::Closed, self));
        };
        if !Arc::ptr_eq(&queue, &scheduler.queue.inner)
            || !Arc::ptr_eq(&kernel, &scheduler.kernel)
            || kernel
                .with_live_active_scheduler_thread(successor_thread, successor_generation, || ())
                .is_none()
        {
            return Err((RunQueueError::AuthorityMismatch, self));
        }
        self.retarget_unpublished_gate(&queue, successor_thread, successor_generation);
        self.key = QueueKey {
            thread: successor_thread,
            generation: successor_generation,
        };
        Ok(self)
    }

    pub(crate) fn reactivate_exact(
        mut self,
        scheduler: &Scheduler,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
    ) -> Result<Self, (RunQueueError, Self)> {
        if self.active
            || self.generation() != predecessor
            || predecessor.raw().checked_add(1) != Some(successor.raw())
        {
            return Err((RunQueueError::AuthorityMismatch, self));
        }
        let Some(queue) = self.queue.upgrade() else {
            return Err((RunQueueError::Closed, self));
        };
        let Some(kernel) = self.kernel.upgrade() else {
            return Err((RunQueueError::Closed, self));
        };
        if !Arc::ptr_eq(&queue, &scheduler.queue.inner)
            || !Arc::ptr_eq(&kernel, &scheduler.kernel)
            || kernel
                .with_live_active_scheduler_thread(self.thread_key(), successor, || ())
                .is_none()
        {
            return Err((RunQueueError::AuthorityMismatch, self));
        }
        if let Err(error) = queue.admit_authority() {
            return Err((error, self));
        }
        self.key.generation = successor;
        self.active = true;
        Ok(self)
    }

    pub(crate) fn admit_descendant(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Self, RunQueueError> {
        if !self.active {
            return Err(RunQueueError::AuthorityMismatch);
        }
        let kernel = self.kernel.upgrade().ok_or(RunQueueError::Closed)?;
        let queue = self.queue.upgrade().ok_or(RunQueueError::Closed)?;
        kernel
            .with_live_scheduler_descendant(
                self.key.thread,
                self.key.generation,
                thread,
                generation,
                || {
                    let key = QueueKey { thread, generation };
                    queue.admit_unpublished_authority(key)?;
                    Ok(Self {
                        queue: Arc::downgrade(&queue),
                        kernel: Arc::downgrade(&kernel),
                        key,
                        active: true,
                    })
                },
            )
            .unwrap_or(Err(RunQueueError::AuthorityMismatch))
    }

    pub(crate) fn admit_same_task_sibling(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Self, RunQueueError> {
        self.admit_related(thread, generation, |kernel, commit| {
            kernel.with_live_scheduler_same_task_sibling(
                self.key.thread,
                self.key.generation,
                thread,
                generation,
                commit,
            )
        })
    }

    pub(crate) fn admit_peer_root(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Self, RunQueueError> {
        self.admit_related(thread, generation, |kernel, commit| {
            kernel.with_live_scheduler_peer_root(
                self.key.thread,
                self.key.generation,
                thread,
                generation,
                commit,
            )
        })
    }

    fn admit_related(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
        validate: impl FnOnce(
            &Kernel,
            &mut dyn FnMut() -> Result<Self, RunQueueError>,
        ) -> Option<Result<Self, RunQueueError>>,
    ) -> Result<Self, RunQueueError> {
        if !self.active {
            return Err(RunQueueError::AuthorityMismatch);
        }
        let kernel = self.kernel.upgrade().ok_or(RunQueueError::Closed)?;
        let queue = self.queue.upgrade().ok_or(RunQueueError::Closed)?;
        let mut commit = || {
            let key = QueueKey { thread, generation };
            queue.admit_unpublished_authority(key)?;
            Ok(Self {
                queue: Arc::downgrade(&queue),
                kernel: Arc::downgrade(&kernel),
                key,
                active: true,
            })
        };
        validate(&kernel, &mut commit).unwrap_or(Err(RunQueueError::AuthorityMismatch))
    }

    #[cfg(test)]
    pub(crate) fn publish(
        &self,
        scheduler: &Scheduler,
        thread: Arc<Thread>,
    ) -> Result<(), SchedulerError> {
        self.publish_row(scheduler, thread).map(|_| ())
    }

    #[cfg(test)]
    fn publish_row(
        &self,
        scheduler: &Scheduler,
        thread: Arc<Thread>,
    ) -> Result<bool, SchedulerError> {
        self.publication_handle().publish_row(scheduler, thread)
    }

    /// A non-owning publication view of this authority: the exact queue and
    /// key it admitted, detached from the authority's admission lifetime so a
    /// holder can release the lock guarding the authority before it enters
    /// the scheduler. Publication takes the run-queue lock and consults every
    /// executor kick, which nest INSIDE the exec-retarget lock order; the
    /// handle exists so no caller has to publish from under an outer lock.
    pub(crate) fn publication_handle(&self) -> SubmissionPublication {
        SubmissionPublication {
            queue: Weak::clone(&self.queue),
            key: self.key,
        }
    }
}

/// See [`SubmissionAuthority::publication_handle`].
pub(crate) struct SubmissionPublication {
    queue: Weak<RunQueueInner>,
    key: QueueKey,
}

impl SubmissionPublication {
    /// Publish the exact `(thread, generation)` row this authority admitted.
    ///
    /// The run queue is keyed by that exact pair and coalesces by it, so a
    /// row that is already queued IS this publication's row: a wake and an
    /// activation assert the same fact about the same generation, and
    /// `Scheduler::wake` has always reported the second one as
    /// `WakeDisposition::Coalesced` rather than an error. Publication says
    /// the same thing.
    ///
    /// This used to reject a coalesce. The child (or exec successor) is
    /// published to the Kernel as runnable BEFORE its dormant submission is
    /// activated, so any real producer that wakes it in that window queues
    /// the row first; the activation then found "its own" row and failed,
    /// and every production caller lowers an activation failure into a
    /// guest-fatal `TrapError`. That killed a live `cpython-importlib`
    /// guest process mid-run with exit `127`.
    pub(crate) fn publish(
        &self,
        scheduler: &Scheduler,
        thread: Arc<Thread>,
    ) -> Result<(), SchedulerError> {
        self.publish_row(scheduler, thread).map(|_| ())
    }

    fn publish_row(
        &self,
        scheduler: &Scheduler,
        thread: Arc<Thread>,
    ) -> Result<bool, SchedulerError> {
        let queue = self.queue.upgrade().ok_or(RunQueueError::Closed)?;
        let exact = scheduler
            .kernel
            .exact_thread_for_scheduler(self.key.thread)
            .ok_or(SchedulerError::UnknownThread)?;
        if !Arc::ptr_eq(&queue, &scheduler.queue.inner)
            || !Arc::ptr_eq(&exact, &thread)
            || thread.key() != self.key.thread
            || thread.execution_state().generation() != Some(self.key.generation)
        {
            return Err(RunQueueError::AuthorityMismatch.into());
        }
        scheduler
            .publish_exact(thread, self.key)
            .map_err(Into::into)
    }
}

impl Drop for SubmissionAuthority {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(queue) = self.queue.upgrade() {
            queue.release_authority(self.key);
        }
        self.active = false;
    }
}

/// The guest CPU count the carrier's INSTALLED scheduling policy schedules
/// onto, published when its run queue is built.
///
/// `0` = no run queue exists yet, in which case the default policy's answer
/// stands. Publication is once per process because HVPatch runs one carrier
/// per process and the guest may already have read `nproc`; a second, DIFFERENT
/// answer would mean two `sched_getaffinity` truths in one guest, so it fails
/// closed.
static EXPOSED_GUEST_CPUS: AtomicUsize = AtomicUsize::new(0);

/// The number of guest CPUs (`P`s) this carrier schedules onto — and the ONE
/// authority for every guest-visible CPU surface: `nproc`,
/// `sched_getaffinity`, `/proc/cpuinfo`, `/proc/stat`, `/sys/devices/system/
/// cpu/*` and `perf_event_open`'s CPU range.
///
/// It is the installed [`SchedulingPolicy`]'s `cpu_count()`, so an embedder
/// that installs a policy with `ContainerBuilder::scheduler` moves the whole
/// surface together and cannot end up telling the guest about CPUs the
/// scheduler will never place a task on. With no policy installed this is
/// still the default policy's answer, which is `host_facts::logical_cpu_count()`
/// (on macOS the performance-core count) clamped to the run queue's fixed
/// per-CPU lane width — so the shipped behaviour is unchanged.
pub fn guest_cpu_count() -> usize {
    match EXPOSED_GUEST_CPUS.load(Ordering::Acquire) {
        0 => default_guest_cpu_count(),
        published => published,
    }
}

/// The default policy's CPU count, used until a run queue publishes one.
pub fn default_guest_cpu_count() -> usize {
    crate::host_facts::logical_cpu_count().clamp(1, carrick_hal::MAX_GUEST_CPUS)
}

/// Publish the count the guest will see.
///
/// Called ONLY where a carrier builds its scheduler — not from `RunQueue::new`,
/// which every in-crate reference-model kernel and unit test also drives with
/// its own CPU count. Idempotent for the same answer; aborts on a second,
/// different one, because a guest cannot be told two different truths about
/// how many CPUs it has and there is no correct value to continue from.
pub(crate) fn publish_guest_cpu_count(ncpu: usize) {
    let ncpu = ncpu.clamp(1, carrick_hal::MAX_GUEST_CPUS);
    match EXPOSED_GUEST_CPUS.compare_exchange(0, ncpu, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {}
        Err(published) if published == ncpu => {}
        Err(_published) => std::process::abort(),
    }
}

#[derive(Debug)]
pub struct RunQueue {
    inner: Arc<RunQueueInner>,
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::new(Arc::new(GuestCpuPolicy::new(guest_cpu_count())))
    }
}

impl RunQueue {
    pub(crate) fn new(policy: Arc<dyn SchedulingPolicy>) -> Self {
        let ncpu = policy.cpu_count().clamp(1, carrick_hal::MAX_GUEST_CPUS);
        let cpus: Vec<Arc<GuestCpu>> = (0..ncpu)
            .map(|index| Arc::new(GuestCpu::new(GuestCpuId::new(index as u32))))
            .collect();
        let keys = (0..RunQueueInner::QUEUED_SHARDS)
            .map(|_| Mutex::new(QueueKeyShard::default()))
            .collect();
        Self {
            inner: Arc::new(RunQueueInner {
                state: Mutex::new(RunQueueState::default()),
                changed: Condvar::new(),
                lifecycle: AtomicU8::new(QueueLifecycle::Open as u8),
                wake_admissions: AtomicU64::new(0),
                control_epoch: AtomicU64::new(0),
                claimed: AtomicUsize::new(0),
                claim_boundaries: AtomicU64::new(0),
                total_queued: AtomicUsize::new(0),
                active_authorities: AtomicUsize::new(0),
                close_epoch: AtomicU64::new(0),
                keys,
                online: (0..ncpu).map(|_| AtomicUsize::new(0)).collect(),
                cpus,
                policy,
                #[cfg(test)]
                close_observation_gate: Mutex::new(None),
                #[cfg(test)]
                root_admission_gate: Mutex::new(None),
                #[cfg(test)]
                close_started_gate: Mutex::new(None),
                #[cfg(test)]
                pre_park_gate: Mutex::new(None),
            }),
        }
    }

    /// Remove one exact row because its generation has been terminally
    /// retired. This is also the only place a gate is lifted without a
    /// publication: the Kernel will refuse to queue the generation again, so
    /// neither the admission gate nor the pre-publication reservation has
    /// anything left to guard, and leaving them would leak one entry per
    /// failed submission.
    fn remove_exact(&self, key: QueueKey) -> bool {
        for cpu in &self.inner.cpus {
            let mut local = cpu.state.lock();
            let Some(index) = local.rows.iter().position(|row| row.key == key) else {
                continue;
            };
            local.rows.remove(index);
            {
                let mut shard = self.inner.shard(key).lock();
                shard.queued.remove(&key);
                RunQueueInner::retire_gates(&mut shard, key);
            }
            cpu.depth.store(local.rows.len(), Ordering::Release);
            self.inner.total_queued.fetch_sub(1, Ordering::SeqCst);
            drop(local);
            self.inner.settle_close_if_closing();
            return true;
        }
        // A row deferred behind a gate is on no CPU queue and was never
        // counted, so removing it touches only the shard.
        let mut shard = self.inner.shard(key).lock();
        let held = shard.deferred.remove(&key).is_some();
        if held {
            shard.queued.remove(&key);
        }
        RunQueueInner::retire_gates(&mut shard, key);
        drop(shard);
        if held {
            self.inner.settle_close_if_closing();
        }
        held
    }

    fn admit_root(
        &self,
        kernel: &Arc<Kernel>,
        key: QueueKey,
    ) -> Result<SubmissionAuthority, RunQueueError> {
        #[cfg(test)]
        if let Some(gate) = {
            let configured = self.inner.root_admission_gate.lock();
            configured.clone()
        } {
            gate.wait();
            gate.wait();
        }
        let state = self.inner.state.lock();
        if state.lifecycle != QueueLifecycle::Open
            || self.inner.wake_admissions.load(Ordering::Acquire) & RunQueueInner::CLOSING_BIT != 0
        {
            return Err(RunQueueError::SubmissionRejected);
        }
        self.inner
            .active_authorities
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            })
            .map_err(|_| RunQueueError::SubmissionRejected)?;
        drop(state);
        self.inner.mark_unpublished(key);
        Ok(SubmissionAuthority {
            queue: Arc::downgrade(&self.inner),
            kernel: Arc::downgrade(kernel),
            key,
            active: true,
        })
    }

    /// Claim one row for `executor`.
    ///
    /// A bound executor is an `M` running one `P` for the carrier's life: it
    /// serves its own CPU's queue, steals from the longest other queue when
    /// its own is empty, and otherwise parks on ITS OWN condvar. No carrier
    /// mutex is taken while the queue is open, and a wake signals exactly one
    /// CPU, so there is no herd.
    fn take_row(
        &self,
        executor: &ExecutorRegistration,
        auditors: Option<&crate::observe::AuditorChain>,
    ) -> Result<QueueRow, RunQueueError> {
        if executor.is_spare {
            return self.park_spare(executor);
        }
        let index = executor
            .bound_cpu
            .map(|cpu| cpu.as_usize())
            .unwrap_or(0)
            .min(self.inner.cpus.len().saturating_sub(1));
        let cpu = Arc::clone(&self.inner.cpus[index]);
        // Exactly one announcement per executor, released by the guard on
        // every path out of the idle state including the early returns.
        let mut idle = IdleAnnouncement::new(&cpu);
        loop {
            let control_epoch = self.inner.control_epoch.load(Ordering::Acquire);
            if executor
                .control_observation_epoch
                .swap(control_epoch, Ordering::AcqRel)
                != control_epoch
            {
                return Err(RunQueueError::ControlPoked);
            }

            if let Some(row) = self.inner.pop_local(&cpu) {
                return Ok(self.claim_taken(&mut idle, cpu.id, row));
            }
            if let Some(row) = self.inner.try_steal(cpu.id) {
                return Ok(self.claim_taken(&mut idle, cpu.id, row));
            }

            if self.inner.lifecycle() != QueueLifecycle::Open
                && let Some(error) = self.observe_close(executor)
            {
                return Err(error);
            }

            // Announce idleness BEFORE the last scan, so a publisher that
            // posts to another CPU either sees this executor (and bumps the
            // ticket, which the pre-park re-check below observes) or stored
            // its row before the announcement was visible (and the scan finds
            // it).
            let ticket = {
                let local = cpu.state.lock();
                local.wake_ticket
            };
            idle.announce();
            if let Some(row) = self
                .inner
                .pop_local(&cpu)
                .or_else(|| self.inner.try_steal(cpu.id))
            {
                return Ok(self.claim_taken(&mut idle, cpu.id, row));
            }

            #[cfg(test)]
            if let Some((arrived, resume)) = self.inner.pre_park_gate.lock().take() {
                arrived.wait();
                resume.wait();
            }

            let mut local = cpu.state.lock();
            if !local.rows.is_empty() || local.wake_ticket != ticket {
                drop(local);
                // Stay announced: this executor is going straight back round
                // the scan, and dropping the announcement here would make the
                // CPU look busy to a placement taken in that window.
                continue;
            }
            local.waiters = local
                .waiters
                .checked_add(1)
                .unwrap_or_else(|| std::process::abort());
            let close_epoch = self.inner.close_epoch.load(Ordering::Acquire);
            // The executor is about to sleep with no row: report the park on
            // the REAL guest CPU it serves, so an auditor reading the pair
            // (claimed, parked) sees the same CPU identity the guest does.
            if let Some(auditors) = auditors {
                auditors.executor_parked(executor.id, cpu.id, None);
            }
            while local.rows.is_empty()
                && local.wake_ticket == ticket
                && self.inner.lifecycle() == QueueLifecycle::Open
            {
                cpu.idle_condvar.wait(&mut local);
            }
            local.waiters = local
                .waiters
                .checked_sub(1)
                .unwrap_or_else(|| std::process::abort());
            drop(local);
            let observed_close_epoch = self.inner.close_epoch.load(Ordering::Acquire);
            if observed_close_epoch != close_epoch {
                executor
                    .close_observation_epoch
                    .store(observed_close_epoch, Ordering::Release);
            }
        }
    }

    /// Leave the idle state with a row in hand, continuing the wake chain.
    ///
    /// An executor that was woken (or had announced itself idle) consumed a
    /// nudge. If it takes a row and work is still queued anywhere, the nudge
    /// it consumed has to be replaced or that work waits for an unrelated
    /// event — so it hands one on to the next idle CPU before it runs.
    fn claim_taken(
        &self,
        idle: &mut IdleAnnouncement<'_>,
        cpu: GuestCpuId,
        row: QueueRow,
    ) -> QueueRow {
        if idle.is_held() {
            // Release BEFORE reading the queue total. The two are `SeqCst`
            // and so is `enqueue`'s (`total_queued` add, then idle load):
            // either the publisher still sees this executor idle and nudges
            // it, or this executor already sees the publisher's row and hands
            // the nudge on. One of the two always fires, so a row cannot be
            // left runnable with every other executor parked.
            idle.release();
            self.inner.propagate_wake(cpu);
        }
        row
    }

    /// The closing arm of a claim: pay this executor's close observation once
    /// the queue has drained, or report the queue closed. `None` means the
    /// queue is closing but not drained, so the caller parks normally and is
    /// nudged again by whichever decrement drains it.
    fn observe_close(&self, executor: &ExecutorRegistration) -> Option<RunQueueError> {
        let mut state = self.inner.state.lock();
        self.inner.maybe_finish_close(&mut state);
        if state.lifecycle == QueueLifecycle::Closed {
            return Some(RunQueueError::Closed);
        }
        if state.lifecycle == QueueLifecycle::Closing && self.inner.drain_ready() {
            if executor.close_observation_epoch.swap(0, Ordering::AcqRel) != 0 {
                #[cfg(test)]
                let observation_gate = {
                    let configured = self.inner.close_observation_gate.lock();
                    configured.clone()
                };
                #[cfg(test)]
                if let Some(gate) = observation_gate {
                    drop(state);
                    gate.wait();
                    state = self.inner.state.lock();
                }
                state.closed_waiter_observations = state
                    .closed_waiter_observations
                    .checked_add(1)
                    .unwrap_or_else(|| std::process::abort());
                self.inner.maybe_finish_close(&mut state);
            }
            return Some(RunQueueError::Closed);
        }
        None
    }

    /// A spare `M`. It holds no `P`, so it never claims a row in this phase:
    /// it parks on the lifecycle condvar until a control poke or the close.
    /// Phase 3 (`handoffp`) is what will hand it a `P` to run.
    fn park_spare(&self, executor: &ExecutorRegistration) -> Result<QueueRow, RunQueueError> {
        let mut state = self.inner.state.lock();
        loop {
            let control_epoch = self.inner.control_epoch.load(Ordering::Acquire);
            if executor
                .control_observation_epoch
                .swap(control_epoch, Ordering::AcqRel)
                != control_epoch
            {
                return Err(RunQueueError::ControlPoked);
            }
            self.inner.maybe_finish_close(&mut state);
            if state.lifecycle == QueueLifecycle::Closed {
                return Err(RunQueueError::Closed);
            }
            if state.lifecycle == QueueLifecycle::Closing && self.inner.drain_ready() {
                if executor.close_observation_epoch.swap(0, Ordering::AcqRel) != 0 {
                    state.closed_waiter_observations = state
                        .closed_waiter_observations
                        .checked_add(1)
                        .unwrap_or_else(|| std::process::abort());
                    self.inner.maybe_finish_close(&mut state);
                }
                return Err(RunQueueError::Closed);
            }
            state.spare_waiters = state
                .spare_waiters
                .checked_add(1)
                .unwrap_or_else(|| std::process::abort());
            let close_epoch = state.close_epoch;
            self.inner.changed.wait(&mut state);
            state.spare_waiters = state
                .spare_waiters
                .checked_sub(1)
                .unwrap_or_else(|| std::process::abort());
            if state.close_epoch != close_epoch {
                executor
                    .close_observation_epoch
                    .store(state.close_epoch, Ordering::Release);
            }
        }
    }

    pub(crate) fn take(
        &self,
        executor: &ExecutorRegistration,
        recorder: Option<&dyn DiscardRecorder>,
        auditors: Option<&crate::observe::AuditorChain>,
    ) -> Result<QueueClaim, RunQueueError> {
        loop {
            let row = self.take_row(executor, auditors)?;
            let observed_state = row.thread.execution_diagnostic();
            if row.thread.key() != row.key.thread
                || row.thread.execution_state().generation() != Some(row.key.generation)
                || !matches!(
                    row.thread.execution_state(),
                    super::objects::ThreadExecutionState::Runnable { .. }
                )
            {
                if let Some(recorder) = recorder {
                    recorder.record_discard(
                        executor.id,
                        row.key.thread,
                        row.key.generation,
                        observed_state,
                        "stale_row_generation_or_state_mismatch".to_owned(),
                    );
                }
                // A discarded row is a wake that never reaches its target, so
                // it is reported on the SAME auditor surface as a rejected
                // wake. The `DiscardRecorder` stays: it is the diagnostic
                // transcript, while this is the invariant surface.
                if let Some(auditors) = auditors {
                    auditors.wake_rejected(
                        row.thread.task_key(),
                        crate::observe::WakeRejectionReason::StaleGeneration,
                    );
                }
                self.inner.finish_claim();
                continue;
            }
            let lease = match row.thread.claim_runnable(executor.id) {
                Ok(lease) if lease.generation() == row.key.generation => lease,
                Ok(lease) => {
                    let lease_generation = lease.generation();
                    if let Some(recorder) = recorder {
                        recorder.record_discard(
                            executor.id,
                            row.key.thread,
                            row.key.generation,
                            observed_state,
                            format!("lease_generation_mismatch (lease={lease_generation:?})"),
                        );
                    }
                    drop(lease);
                    if let Some(auditors) = auditors {
                        auditors.wake_rejected(
                            row.thread.task_key(),
                            crate::observe::WakeRejectionReason::StaleGeneration,
                        );
                    }
                    self.inner.finish_claim();
                    continue;
                }
                Err(error) => {
                    if let Some(recorder) = recorder {
                        recorder.record_discard(
                            executor.id,
                            row.key.thread,
                            row.key.generation,
                            observed_state,
                            format!("claim_error: {error}"),
                        );
                    }
                    self.inner.finish_claim();
                    continue;
                }
            };
            return Ok(QueueClaim { row, lease });
        }
    }

    pub fn close(&self) {
        self.inner.begin_close();
        let mut state = self.inner.state.lock();
        if state.lifecycle == QueueLifecycle::Open {
            self.inner
                .publish_lifecycle(&mut state, QueueLifecycle::Closing);
            state.close_epoch = state
                .close_epoch
                .checked_add(1)
                .unwrap_or_else(|| std::process::abort());
            // Exactly the executors parked RIGHT NOW owe a close observation.
            // Per-CPU waiters are counted under each CPU's own lock while this
            // carrier lock is held, so an executor is either already parked
            // (counted, and woken by the nudge below) or has not yet parked
            // and will see the published lifecycle before it does.
            state.close_waiters_expected = self.waiter_count_locked(&state);
            self.inner
                .close_epoch
                .store(state.close_epoch, Ordering::Release);
        }
        #[cfg(test)]
        let close_started_gate = self.inner.close_started_gate.lock().clone();
        self.inner.maybe_finish_close(&mut state);
        self.inner.changed.notify_all();
        drop(state);
        self.inner.nudge_all_cpus();
        #[cfg(test)]
        if let Some(gate) = close_started_gate {
            gate.wait();
        }
    }

    pub fn wait_closed(&self) {
        let mut state = self.inner.state.lock();
        while state.lifecycle != QueueLifecycle::Closed {
            self.inner.changed.wait(&mut state);
        }
    }

    fn retire_executor(&self, executor: &ExecutorRegistration) {
        if executor.close_observation_epoch.swap(0, Ordering::AcqRel) == 0 {
            return;
        }
        let mut state = self.inner.state.lock();
        state.closed_waiter_observations = state
            .closed_waiter_observations
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        self.inner.maybe_finish_close(&mut state);
        self.inner.changed.notify_all();
    }

    fn len(&self) -> usize {
        self.inner.total_queued.load(Ordering::SeqCst)
    }

    /// Executors parked right now, across every CPU plus the spare pool,
    /// counted from a state guard the CALLER already holds.
    ///
    /// The count needs `spare_waiters`, which lives in the run-queue state, so
    /// it takes the guard as an argument instead of locking. Locking here was
    /// only ever safe for a caller that did not already hold the state, and
    /// that rule lived in prose: `close` obeyed it by open-coding the sum,
    /// while `scheduler_summary` locked the state and then called this, re-
    /// entering a non-reentrant `parking_lot::Mutex` and deadlocking its own
    /// thread while holding the lock the whole carrier drains through. Taking
    /// `&RunQueueState` makes that call unwritable.
    fn waiter_count_locked(&self, state: &RunQueueState) -> usize {
        let cpu_waiters: usize = self
            .inner
            .cpus
            .iter()
            .map(|cpu| cpu.state.lock().waiters)
            .sum();
        cpu_waiters + state.spare_waiters
    }

    /// The same census for a reader that must never block: the kernel-debug
    /// endpoint and the post-mortem abort sink.
    ///
    /// Those two exist to describe a carrier that is already stuck, so joining
    /// the queue behind whoever holds a run-queue lock turns the instrument
    /// into a second casualty — measured on `test_compile`, where the abort
    /// sink could not fire at all. Every lock is taken with `try_lock` and a
    /// contended read is reported as [`WaiterCensus::RunQueueLocked`], never
    /// waited on and never a silent zero.
    fn try_waiter_census(&self) -> WaiterCensus {
        let mut total = 0usize;
        for cpu in &self.inner.cpus {
            let Some(local) = cpu.state.try_lock() else {
                return WaiterCensus::RunQueueLocked;
            };
            total += local.waiters;
        }
        let Some(state) = self.inner.state.try_lock() else {
            return WaiterCensus::RunQueueLocked;
        };
        WaiterCensus::Exact(total + state.spare_waiters)
    }

    #[cfg(test)]
    fn closed_waiter_observations(&self) -> usize {
        self.inner.state.lock().closed_waiter_observations
    }

    #[cfg(test)]
    fn active_authority_count(&self) -> usize {
        self.inner.active_authorities.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn drain_ready_for_test(&self) -> bool {
        self.inner.drain_ready()
    }

    #[cfg(test)]
    fn install_pre_park_gate(
        &self,
        arrived: Arc<std::sync::Barrier>,
        resume: Arc<std::sync::Barrier>,
    ) {
        *self.inner.pre_park_gate.lock() = Some((arrived, resume));
    }

    #[cfg(test)]
    fn install_close_observation_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.inner.close_observation_gate.lock() = Some(gate);
    }

    #[cfg(test)]
    fn install_root_admission_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.inner.root_admission_gate.lock() = Some(gate);
    }

    #[cfg(test)]
    fn install_close_started_gate(&self, gate: Arc<std::sync::Barrier>) {
        *self.inner.close_started_gate.lock() = Some(gate);
    }
}

pub(crate) struct QueueClaim {
    row: QueueRow,
    lease: ThreadExecutionLease,
}

pub struct RunnableThread {
    thread: Arc<Thread>,
    key: QueueKey,
    binding: ExecutorBinding,
    lease: Option<ThreadExecutionLease>,
    queue: Weak<RunQueueInner>,
    active_claim: bool,
    /// The guest CPU this claim runs on. This is the SAME value published to
    /// the thread's `last_cpu` and read back by the guest through
    /// `sched_getcpu`, so an observer that reports it is reporting the guest's
    /// own answer rather than a host executor index.
    guest_cpu: GuestCpuId,
}

impl std::fmt::Debug for RunnableThread {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunnableThread")
            .field("key", &self.key)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl RunnableThread {
    pub const fn thread_key(&self) -> ThreadKey {
        self.key.thread
    }

    pub const fn generation(&self) -> ExecutionGeneration {
        self.key.generation
    }

    pub const fn executor(&self) -> ExecutorId {
        self.binding.executor
    }

    /// The guest CPU this claim runs on — the guest's own answer, not a host
    /// executor index.
    pub const fn guest_cpu(&self) -> GuestCpuId {
        self.guest_cpu
    }

    pub const fn executor_epoch(&self) -> u64 {
        self.binding.executor_epoch
    }

    pub fn lease(&self) -> &ThreadExecutionLease {
        self.lease.as_ref().unwrap_or_else(|| std::process::abort())
    }

    #[cfg(test)]
    pub(crate) fn lease_mut(&mut self) -> &mut ThreadExecutionLease {
        self.lease.as_mut().unwrap_or_else(|| std::process::abort())
    }

    pub(crate) fn thread(&self) -> &Arc<Thread> {
        &self.thread
    }

    pub(crate) fn take_lease(&mut self) -> ThreadExecutionLease {
        self.lease.take().unwrap_or_else(|| std::process::abort())
    }

    pub(crate) fn restore_lease(
        &mut self,
        lease: ThreadExecutionLease,
    ) -> Result<(), (ThreadExecutionError, ThreadExecutionLease)> {
        if self.lease.is_some()
            || lease.generation() != self.key.generation
            || lease.executor() != self.binding.executor
            || lease.executor_epoch() != self.binding.executor_epoch
        {
            return Err((
                ThreadExecutionError::StaleLease {
                    generation: lease.generation(),
                    executor: lease.executor(),
                    executor_epoch: lease.executor_epoch(),
                },
                lease,
            ));
        }
        self.lease = Some(lease);
        Ok(())
    }

    fn finish_claim(&mut self) {
        if !self.active_claim {
            return;
        }
        if let Some(queue) = self.queue.upgrade() {
            queue.finish_claim();
        }
        self.active_claim = false;
    }
}

/// The `HVPSETTLE` sub-step code for a thread execution state, offset into the
/// `claim-dropped-unsettled/<state>` range.
fn stranded_claim_state_code(state: ThreadExecutionState) -> i32 {
    9 + match state {
        ThreadExecutionState::Runnable { .. } => 1,
        ThreadExecutionState::Blocked {
            reason: BlockedReason::ChildState,
            ..
        } => 2,
        ThreadExecutionState::Blocked {
            reason: BlockedReason::HostWait,
            ..
        } => 3,
        ThreadExecutionState::Exited { .. } => 4,
        ThreadExecutionState::Failed { .. } => 5,
        ThreadExecutionState::Running { .. } => 6,
        ThreadExecutionState::SwitchingOut { .. } => 7,
        ThreadExecutionState::Uninitialized => 8,
    }
}

impl Drop for RunnableThread {
    fn drop(&mut self) {
        // A claim released here rather than by a settlement is the stranded
        // shape: nothing publishes the thread's process job and nothing
        // re-queues it, so the graph goes quiet with the row frozen in
        // whatever state `begin_switch_out` last wrote. Record it before the
        // count drops so a post-mortem names the strand instead of showing an
        // unexplained gap after `HVPEXEC_BOUNDARY`.
        if self.active_claim {
            crate::event_ring::rec_hvpatch_settle_step(
                self.key.thread.tid.raw(),
                self.key.generation.raw(),
                stranded_claim_state_code(self.thread.execution_state()),
            );
        }
        self.finish_claim();
    }
}

#[derive(Debug)]
enum WakeAction {
    Queue {
        thread: Arc<Thread>,
        key: QueueKey,
        closing_authorized: bool,
    },
    Kick(ExecutorKickToken),
    Pending,
}

#[derive(Debug)]
struct PendingWake {
    action: WakeAction,
    _admission: WakeAdmission,
}

pub struct Scheduler {
    kernel: Arc<Kernel>,
    queue: RunQueue,
    executors: ExecutorDirectory,
    need_resched: AtomicBool,
    snapshot_count: AtomicU64,
    generation_transition: Mutex<()>,
    generation_observer: Mutex<Option<Arc<dyn SchedulerGenerationObserver>>>,
    discard_recorder: Mutex<Option<Arc<dyn DiscardRecorder>>>,
    #[cfg(test)]
    continuation_settlement_barriers:
        Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Scheduler")
            .field("queued", &self.queue.len())
            .field("need_resched", &self.need_resched.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl Scheduler {
    pub fn new(kernel: Arc<Kernel>) -> Self {
        Self::new_with_policy(kernel, Arc::new(GuestCpuPolicy::new(guest_cpu_count())))
    }

    pub fn new_with_policy(kernel: Arc<Kernel>, policy: Arc<dyn SchedulingPolicy>) -> Self {
        Self {
            kernel,
            queue: RunQueue::new(policy),
            executors: ExecutorDirectory::default(),
            need_resched: AtomicBool::new(false),
            snapshot_count: AtomicU64::new(0),
            generation_transition: Mutex::new(()),
            generation_observer: Mutex::new(None),
            discard_recorder: Mutex::new(None),
            #[cfg(test)]
            continuation_settlement_barriers: Mutex::new(None),
        }
    }

    pub fn policy(&self) -> &Arc<dyn SchedulingPolicy> {
        &self.queue.inner.policy
    }

    pub fn guest_cpus(&self) -> &[Arc<GuestCpu>] {
        &self.queue.inner.cpus
    }

    pub fn guest_cpu(&self, id: GuestCpuId) -> Option<Arc<GuestCpu>> {
        self.queue.inner.cpus.get(id.as_usize()).cloned()
    }

    pub(crate) fn install_discard_recorder(&self, recorder: Arc<dyn DiscardRecorder>) {
        *self.discard_recorder.lock() = Some(recorder);
    }

    pub(crate) fn install_generation_observer(
        &self,
        observer: Arc<dyn SchedulerGenerationObserver>,
    ) -> Result<(), RunQueueError> {
        let mut slot = self.generation_observer.lock();
        if slot.is_some() {
            return Err(RunQueueError::ObserverAlreadyInstalled);
        }
        *slot = Some(observer);
        Ok(())
    }

    /// `target` is the exact thread object the caller already holds. It is
    /// passed in rather than looked up because the LOOKUP is what round 4 got
    /// wrong: a registry miss answers "is this key resolvable right now",
    /// which is not the same question as "will this generation ever run
    /// again", and the thread object carries the kernel graph's own answer.
    fn observe_generation_transition(
        &self,
        target: &Thread,
        thread: ThreadKey,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
        kind: SchedulerGenerationTransition,
    ) -> GenerationTransitionOutcome {
        let observer = self.generation_observer.lock().clone();
        if let Some(observer) = observer
            && let Err(error) = observer.transition(thread, predecessor, successor, kind)
        {
            let kernel_view = self.kernel.scheduler_thread_execution_diagnostic(thread);
            let execution_state = target.execution_state();
            let liveness = self.kernel.scheduler_target_liveness(thread, target);
            return match classify_transition_rejection(liveness) {
                TransitionRejection::TargetReaped => {
                    // Captured live on 2026-09-07 under eight CPU hogs as
                    // `thread=ThreadKey { tid: LinuxTid(1864), serial:
                    // ThreadSerial(225511) } predecessor=84 successor=85
                    // kind=Runnable error=AuthorityMismatch kernel_view=thread
                    // absent from registry` — a carrier abort for a wake Linux
                    // would have discarded
                    // (`docs/conformance-campaigns/2026-09-04-ecosystem.md`).
                    tracing::debug!(?thread, ?predecessor, ?successor, ?kind, %error, %kernel_view, "scheduler transition target was reaped; publication rejected");
                    // Withholding the successor is only half of it. The
                    // observer put its predecessor record BACK when the
                    // rollover failed (correct for a live target), and for a
                    // reaped one nothing will ever take it out again: no
                    // successor is published, no executor runs that
                    // generation, and no exit or exec path names it. The
                    // `SubmissionAuthority` inside that record keeps
                    // `active_authorities` non-zero, which is one of
                    // `drain_ready`'s four terms — so the container's close
                    // never finishes. Liveness is this side's fact, so the
                    // retirement has to be ordered from here.
                    observer.retire_reaped(thread, predecessor);
                    GenerationTransitionOutcome::TargetReaped
                }
                TransitionRejection::LostExactTransition => {
                    // Round 4 called `std::process::abort()` here: a signal,
                    // no evidence, and — because the abort happened INSIDE the
                    // scheduler — no chance for the container's job wait to
                    // report anything at all. Lane B's sink turns it into a
                    // named `RuntimeError::KernelAborted` carrying a
                    // post-mortem of this exact graph, which the container job
                    // group picks up at its next poll. The settlement below
                    // still finishes, so the capture describes a settled
                    // graph rather than one frozen mid-transaction.
                    tracing::error!(?thread, ?predecessor, ?successor, ?kind, %error, ?execution_state, %kernel_view, "scheduler generation observer lost exact transition");
                    crate::kernel::debug::request_abort(
                        crate::kernel::debug::AbortReason::LostExactTransition {
                            tid: thread.tid.raw(),
                            serial: thread.serial.raw(),
                            predecessor: predecessor.raw(),
                            successor: successor.raw(),
                            transition: format!("{kind:?}"),
                            execution_state: format!("{execution_state:?}"),
                            kernel_view,
                        },
                    );
                    GenerationTransitionOutcome::LostExactTransition
                }
            };
        }
        GenerationTransitionOutcome::Recorded
    }

    /// Register an `M` and bind it to the next guest CPU round-robin.
    pub fn register_executor(
        &self,
        kick: Arc<dyn ExecutorKick>,
    ) -> Result<ExecutorRegistration, RunQueueError> {
        self.register_executor_bound(kick, None, false)
    }

    /// Register an `M`. A spare holds no `P` and parks until phase 3's
    /// `handoffp` gives it one; every other executor owns exactly one guest
    /// CPU for the carrier's life.
    pub fn register_executor_bound(
        &self,
        kick: Arc<dyn ExecutorKick>,
        bound_cpu: Option<GuestCpuId>,
        is_spare: bool,
    ) -> Result<ExecutorRegistration, RunQueueError> {
        let registration =
            self.executors
                .register(kick, bound_cpu, is_spare, self.queue.inner.cpus.len())?;
        if let Some(cpu) = registration.bound_cpu {
            self.queue.inner.set_executor_online(cpu, true);
        }
        Ok(registration)
    }

    pub(crate) fn unregister_executor(
        &self,
        registration: &ExecutorRegistration,
    ) -> Result<(), RunQueueError> {
        self.queue.retire_executor(registration);
        let result = self.executors.unregister(registration);
        if result.is_ok()
            && let Some(cpu) = registration.bound_cpu
        {
            self.queue.inner.set_executor_online(cpu, false);
            // Whatever is still queued on a CPU that just lost its `M` is
            // reachable only by stealing; nudge the others so it does not wait
            // for the next unrelated wake.
            self.queue.inner.nudge_all_cpus();
        }
        result
    }

    #[cfg(test)]
    pub(crate) fn registered_executor_count(&self) -> usize {
        self.executors.state.lock().entries.len()
    }

    pub(crate) fn clear_executor_binding(
        &self,
        registration: &ExecutorRegistration,
    ) -> Result<(), RunQueueError> {
        self.executors.clear_binding(registration)
    }

    #[cfg(test)]
    pub(crate) fn admit_root(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<SubmissionAuthority, SchedulerError> {
        self.kernel
            .with_live_active_scheduler_thread(thread, generation, || {
                self.queue
                    .admit_root(&self.kernel, QueueKey { thread, generation })
            })
            .unwrap_or(Err(RunQueueError::AuthorityMismatch))
            .map_err(Into::into)
    }

    pub(crate) fn admit_process_root(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<SubmissionAuthority, SchedulerError> {
        self.kernel
            .with_live_scheduler_process_root(thread, generation, || {
                self.queue
                    .admit_root(&self.kernel, QueueKey { thread, generation })
            })
            .unwrap_or(Err(RunQueueError::AuthorityMismatch))
            .map_err(Into::into)
    }

    pub fn make_runnable(&self, thread: ThreadKey) -> Result<WakeDisposition, SchedulerError> {
        self.wake(thread)
    }

    /// Publish a brand-new thread's initial task state with its claimability
    /// gate already standing.
    ///
    /// The gate `admit_*` raises is not early enough on its own. A clone or
    /// fork child becomes `Runnable { INITIAL }` in the Kernel graph hundreds
    /// of lines before `prepare_submission` admits the submission that owns
    /// it -- the carrier backend, the COW token, the logical job and the start
    /// gate all come first -- and in that window the key is not marked, so a
    /// producer's wake (a futex on the tid the clone already copied out, a
    /// group signal) enqueued a CLAIMABLE row for a generation with no binding
    /// record at all. An executor claimed it, `resolve` reported "missing
    /// exact HVPatch task binding", the task settled `SnapshotRestoreFailed`
    /// and the carrier died -- `cpython-threading` `test_reinit_tls_after_fork`,
    /// reproduced in ~13 s at host load 9-15.
    ///
    /// Reserving the gate BEFORE the Kernel publication removes the window
    /// entirely: the key is unclaimable from the instant it can be woken until
    /// the submission that owns it publishes. The reservation is deliberately
    /// NOT the admission gate -- it belongs to the thread's first generation,
    /// not to any one authority, so it survives the `drop(dormant)` every
    /// clone-rollback arm performs. A failed publication takes its reservation
    /// with it, since nothing can ever be woken for a generation that does not
    /// exist.
    pub(crate) fn publish_initial_task_state_gated(
        &self,
        thread: &Arc<Thread>,
        state: super::objects::MigratableTaskState,
    ) -> Result<ExecutionGeneration, ThreadExecutionError> {
        let key = QueueKey {
            thread: thread.key(),
            generation: ExecutionGeneration::INITIAL,
        };
        self.queue.inner.reserve_prepublication(key);
        match thread.publish_initial_task_state(state) {
            Ok(generation) => {
                debug_assert_eq!(generation, ExecutionGeneration::INITIAL);
                Ok(generation)
            }
            Err(error) => {
                let mut shard = self.queue.inner.shard(key).lock();
                RunQueueInner::retire_gates(&mut shard, key);
                Err(error)
            }
        }
    }

    pub(crate) fn fail_runnable_exact(
        &self,
        key: ThreadKey,
        generation: ExecutionGeneration,
        reason: super::objects::ExecutionFailure,
    ) -> Result<(), SchedulerError> {
        let thread = self
            .kernel
            .exact_thread_for_scheduler(key)
            .ok_or(SchedulerError::UnknownThread)?;
        thread.fail_runnable_generation(generation, reason)?;
        self.queue.remove_exact(QueueKey {
            thread: key,
            generation,
        });
        if self.queue.len() == 0 {
            self.need_resched.store(false, Ordering::Release);
        }
        Ok(())
    }

    /// Cancel one exact dormant blocked generation without manufacturing a
    /// lease. The combined binding/authority observer is retired in the same
    /// serialized generation transaction before callers publish completion.
    pub(crate) fn fail_blocked_exact(
        &self,
        key: ThreadKey,
        generation: ExecutionGeneration,
        reason: super::objects::ExecutionFailure,
    ) -> Result<bool, SchedulerError> {
        let _transition = self.generation_transition.lock();
        let Some(thread) = self.kernel.exact_thread_for_scheduler(key) else {
            return Ok(false);
        };
        if !matches!(
            thread.execution_state(),
            super::objects::ThreadExecutionState::Blocked {
                generation: current,
                ..
            } if current == generation
        ) {
            return Ok(false);
        }
        let successor = match thread.fail_blocked_generation(generation, reason) {
            Ok(successor) => successor,
            Err(super::objects::ThreadExecutionError::InvalidTransition { .. }) => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        // A terminal transition publishes nothing, so a reaped target changes
        // nothing here: the cancellation already happened in the Kernel.
        let _ = self.observe_generation_transition(
            &thread,
            key,
            generation,
            successor,
            SchedulerGenerationTransition::Terminal,
        );
        // Terminal retirement of the exact generation: a gate a dormant
        // admission or a pre-publication reservation left behind has nothing
        // to guard once the Kernel refuses to queue this generation again.
        self.queue.remove_exact(QueueKey {
            thread: key,
            generation,
        });
        Ok(true)
    }

    pub fn wake(&self, thread: ThreadKey) -> Result<WakeDisposition, SchedulerError> {
        let _transition = self.generation_transition.lock();
        let pending = match self.begin_wake(thread) {
            Ok(pending) => pending,
            Err(err) => {
                self.audit_wake_rejection(thread, &err);
                return Err(err);
            }
        };
        match self.commit_wake(pending) {
            Ok(disposition) => Ok(disposition),
            Err(err) => {
                self.audit_wake_rejection(thread, &err);
                Err(err)
            }
        }
    }

    /// Classify a rejected wake for the auditors.
    ///
    /// The verdict is read from the TYPED execution state and from exact key
    /// ownership in the graph, never from which list the target happened to
    /// be found in. The distinction that matters is `Exited` (the identity is
    /// still owned by the graph and simply cannot run -- an ordinary lost
    /// race) versus `Reaped` (nothing owns the identity any more -- the waker
    /// holds a stale authority). Reading list membership instead labelled a
    /// zombie `Reaped`, which is backwards: a zombie is exited-but-not-yet-
    /// waited-for, so its identity is still the parent's to consume.
    fn audit_wake_rejection(&self, thread: ThreadKey, err: &SchedulerError) {
        let state = self.kernel.registry().state.read();
        let mut target = None;
        let mut reason = None;

        // A live task still owning the thread: its typed execution state is
        // the authority. A terminal state means an exit beat this wake.
        for record in state.tasks.values() {
            if let Some(t) = record.task.thread(thread.tid) {
                if t.key() == thread {
                    target = Some(record.task.key());
                    reason = Some(match t.execution_state() {
                        super::objects::ThreadExecutionState::Exited { .. }
                        | super::objects::ThreadExecutionState::Failed { .. } => {
                            crate::observe::WakeRejectionReason::Exited
                        }
                        _ => match err {
                            SchedulerError::Queue(RunQueueError::Closed) => {
                                crate::observe::WakeRejectionReason::Closed
                            }
                            SchedulerError::Queue(RunQueueError::AuthorityMismatch) => {
                                crate::observe::WakeRejectionReason::StaleGeneration
                            }
                            SchedulerError::Thread(
                                super::objects::ThreadExecutionError::SchedulerThreadMismatch {
                                    ..
                                },
                            ) => crate::observe::WakeRejectionReason::StaleGeneration,
                            _ => crate::observe::WakeRejectionReason::Other(err.to_string()),
                        },
                    });
                    break;
                }
            }
        }

        // The thread retired out of its task. Whether that is an exit or a
        // stale identity is a question about the TASK, answered by exact key:
        // a task id can be reallocated, so `contains_key` alone would call a
        // successor's liveness this thread's own.
        if target.is_none() {
            for retired in &state.retired_threads {
                if retired._key == thread {
                    target = Some(retired._task);
                    let owned = state
                        .tasks
                        .get(&retired._task.id)
                        .is_some_and(|record| record.task.key() == retired._task)
                        || state
                            .zombies
                            .get(&retired._task.id)
                            .is_some_and(|record| record.zombie.key == retired._task);
                    reason = Some(if owned {
                        crate::observe::WakeRejectionReason::Exited
                    } else {
                        crate::observe::WakeRejectionReason::Reaped
                    });
                    break;
                }
            }
        }

        // A zombie leader: exited, and its identity is still the parent's to
        // consume with `wait`. Delivering a wake to it is a no-op, not a use
        // of a reaped identity.
        if target.is_none() {
            for zombie_rec in state.zombies.values() {
                if super::ids::LinuxTid::for_task_leader(zombie_rec.zombie.key.id) == thread.tid {
                    target = Some(zombie_rec.zombie.key);
                    reason = Some(crate::observe::WakeRejectionReason::Exited);
                    break;
                }
            }
        }

        let Some(target) = target else {
            return;
        };
        let reason = reason.unwrap_or_else(|| match err {
            SchedulerError::UnknownThread => crate::observe::WakeRejectionReason::UnknownThread,
            SchedulerError::Queue(RunQueueError::Closed) => {
                crate::observe::WakeRejectionReason::Closed
            }
            SchedulerError::Queue(RunQueueError::AuthorityMismatch) => {
                crate::observe::WakeRejectionReason::StaleGeneration
            }
            SchedulerError::Thread(
                super::objects::ThreadExecutionError::SchedulerThreadMismatch { .. },
            ) => crate::observe::WakeRejectionReason::StaleGeneration,
            _ => crate::observe::WakeRejectionReason::Other(err.to_string()),
        });

        drop(state);
        self.kernel.auditors().wake_rejected(target, reason);
    }

    /// Schedule an owner-thread control quantum without completing the
    /// thread's guest-visible blocked continuation. This is intentionally a
    /// separate authority from `wake`: sleep, poll, and futex readiness may
    /// only be published by their real producers.
    pub(crate) fn wake_control(
        &self,
        thread: ThreadKey,
    ) -> Result<WakeDisposition, SchedulerError> {
        let _transition = self.generation_transition.lock();
        let admission = self.queue.inner.try_admit_wake()?;
        let action = self.decide_control_wake(thread)?;
        self.commit_wake(PendingWake {
            action,
            _admission: admission,
        })
    }

    fn begin_wake(&self, thread: ThreadKey) -> Result<PendingWake, SchedulerError> {
        let admission = self.queue.inner.try_admit_wake()?;
        let action = self.decide_wake(thread)?;
        Ok(PendingWake {
            action,
            _admission: admission,
        })
    }

    fn commit_wake(&self, pending: PendingWake) -> Result<WakeDisposition, SchedulerError> {
        let PendingWake { action, _admission } = pending;
        let result = match action {
            WakeAction::Queue { thread, key, .. } => {
                Ok(if self.enqueue_exact(thread, key, true)? {
                    WakeDisposition::Queued
                } else {
                    WakeDisposition::Coalesced
                })
            }
            action => self.deliver_wake(action),
        };
        drop(_admission);
        result
    }

    fn decide_wake(&self, key: ThreadKey) -> Result<WakeAction, SchedulerError> {
        let thread = self
            .kernel
            .exact_thread_for_scheduler(key)
            .ok_or(SchedulerError::UnknownThread)?;
        let action = thread.scheduler_wake(key)?;
        Ok(match action {
            ThreadSchedulerAction::Queue {
                key,
                predecessor,
                generation,
                closing_authorized,
            } => {
                // `TargetReaped` is the ONLY outcome that is not `Recorded`
                // here (a live disagreement aborts inside the observer, and
                // the match is exhaustive, so this cannot widen into "any
                // error is benign"). Linux answers a wake of an exited task
                // with a no-op, so this is a no-op wake — NOT an error for the
                // waker to carry. Round 1 stopped at "reject instead of abort"
                // and left the rejection to propagate, which killed the
                // executor that raised it ("executor worker died error=exact
                // thread generation is not live", `conf-35614-c00`) and
                // cascaded into a carrier FATAL: no better than the abort it
                // replaced.
                if let Some(predecessor) = predecessor {
                    match self.observe_generation_transition(
                        &thread,
                        key,
                        predecessor,
                        generation,
                        SchedulerGenerationTransition::Runnable,
                    ) {
                        GenerationTransitionOutcome::Recorded => {}
                        GenerationTransitionOutcome::TargetReaped => {
                            tracing::debug!(?key, "wake of a reaped task is a no-op");
                            return Ok(WakeAction::Pending);
                        }
                        // The carrier is already being aborted; a wake that
                        // would publish a generation the observer refused must
                        // not also strand it.
                        GenerationTransitionOutcome::LostExactTransition => {
                            return Ok(WakeAction::Pending);
                        }
                    }
                }
                WakeAction::Queue {
                    thread,
                    key: QueueKey {
                        thread: key,
                        generation,
                    },
                    closing_authorized,
                }
            }
            ThreadSchedulerAction::Kick {
                executor,
                executor_epoch,
                key,
                generation,
            } => WakeAction::Kick(ExecutorKickToken {
                executor,
                executor_epoch,
                thread: key,
                generation,
            }),
            ThreadSchedulerAction::None => WakeAction::Pending,
        })
    }

    fn decide_control_wake(&self, key: ThreadKey) -> Result<WakeAction, SchedulerError> {
        let thread = self
            .kernel
            .exact_thread_for_scheduler(key)
            .ok_or(SchedulerError::UnknownThread)?;
        let action = thread.scheduler_control_wake(key)?;
        Ok(match action {
            ThreadSchedulerAction::Queue {
                key,
                predecessor,
                generation,
                closing_authorized,
            } => {
                // `TargetReaped` is the ONLY outcome that is not `Recorded`
                // here (a live disagreement aborts inside the observer, and
                // the match is exhaustive, so this cannot widen into "any
                // error is benign"). Linux answers a wake of an exited task
                // with a no-op, so this is a no-op wake — NOT an error for the
                // waker to carry. Round 1 stopped at "reject instead of abort"
                // and left the rejection to propagate, which killed the
                // executor that raised it ("executor worker died error=exact
                // thread generation is not live", `conf-35614-c00`) and
                // cascaded into a carrier FATAL: no better than the abort it
                // replaced.
                if let Some(predecessor) = predecessor {
                    match self.observe_generation_transition(
                        &thread,
                        key,
                        predecessor,
                        generation,
                        SchedulerGenerationTransition::Runnable,
                    ) {
                        GenerationTransitionOutcome::Recorded => {}
                        GenerationTransitionOutcome::TargetReaped => {
                            tracing::debug!(?key, "wake of a reaped task is a no-op");
                            return Ok(WakeAction::Pending);
                        }
                        // The carrier is already being aborted; a wake that
                        // would publish a generation the observer refused must
                        // not also strand it.
                        GenerationTransitionOutcome::LostExactTransition => {
                            return Ok(WakeAction::Pending);
                        }
                    }
                }
                WakeAction::Queue {
                    thread,
                    key: QueueKey {
                        thread: key,
                        generation,
                    },
                    closing_authorized,
                }
            }
            ThreadSchedulerAction::Kick {
                executor,
                executor_epoch,
                key,
                generation,
            } => WakeAction::Kick(ExecutorKickToken {
                executor,
                executor_epoch,
                thread: key,
                generation,
            }),
            ThreadSchedulerAction::None => WakeAction::Pending,
        })
    }

    fn deliver_wake(&self, action: WakeAction) -> Result<WakeDisposition, SchedulerError> {
        match action {
            WakeAction::Queue {
                thread,
                key,
                closing_authorized,
                ..
            } => Ok(if self.enqueue_exact(thread, key, closing_authorized)? {
                WakeDisposition::Queued
            } else {
                WakeDisposition::Coalesced
            }),
            WakeAction::Kick(token) => {
                if self.executors.deliver(token) {
                    Ok(WakeDisposition::Kicked)
                } else {
                    Ok(WakeDisposition::Pending)
                }
            }
            WakeAction::Pending => Ok(WakeDisposition::Pending),
        }
    }

    fn enqueue_exact(
        &self,
        thread: Arc<Thread>,
        key: QueueKey,
        closing_authorized: bool,
    ) -> Result<bool, RunQueueError> {
        self.enqueue_exact_on(thread, key, closing_authorized, None)
    }

    fn enqueue_exact_on(
        &self,
        thread: Arc<Thread>,
        key: QueueKey,
        closing_authorized: bool,
        target_cpu: Option<GuestCpuId>,
    ) -> Result<bool, RunQueueError> {
        let outcome = self.queue.inner.enqueue(
            QueueRow {
                key,
                thread,
                closing_authorized,
            },
            closing_authorized,
            target_cpu,
        )?;
        self.after_insertion(outcome);
        Ok(outcome.queued())
    }

    /// Publish the exact row of a submission whose activation has just made
    /// its binding resolvable. Distinct from `enqueue_exact` because this is
    /// the transition that lifts the key's unpublished gate.
    fn publish_exact(&self, thread: Arc<Thread>, key: QueueKey) -> Result<bool, RunQueueError> {
        let outcome = self.queue.inner.publish(QueueRow {
            key,
            thread,
            closing_authorized: true,
        })?;
        self.after_insertion(outcome);
        Ok(outcome.queued())
    }

    /// Only a claimable row is work an executor can be sent looking for.
    fn after_insertion(&self, outcome: EnqueueOutcome) {
        if outcome == EnqueueOutcome::Claimable && self.executors.has_running() {
            self.need_resched.store(true, Ordering::Release);
        }
    }

    pub fn take(&self, executor: &ExecutorRegistration) -> Result<RunnableThread, RunQueueError> {
        let recorder = self.discard_recorder.lock().clone();
        let auditors = self.kernel.auditors();
        let QueueClaim { row, lease } =
            self.queue
                .take(executor, recorder.as_deref(), Some(&auditors))?;
        let binding = ExecutorBinding {
            executor: executor.id,
            executor_epoch: lease.executor_epoch(),
            thread: row.key.thread,
            generation: row.key.generation,
        };
        if let Err(error) = self.executors.bind(executor, binding) {
            drop(lease);
            self.queue.inner.finish_claim();
            return Err(error);
        }
        let bound_cpu = executor.bound_cpu.unwrap_or(GuestCpuId::new(0));
        row.thread.set_last_cpu(bound_cpu);
        if let Some(guest_cpu) = self.queue.inner.cpus.get(bound_cpu.as_usize()) {
            guest_cpu.set_current_task(Some(row.thread.key()));
        }
        self.need_resched
            .store(self.queue.len() != 0, Ordering::Release);
        Ok(RunnableThread {
            thread: row.thread,
            key: row.key,
            binding,
            lease: Some(lease),
            queue: Arc::downgrade(&self.queue.inner),
            active_claim: true,
            guest_cpu: bound_cpu,
        })
    }

    pub(crate) fn poke_executor_control(&self) {
        self.queue.inner.poke_control();
    }

    pub fn settle_blocked(
        &self,
        mut running: RunnableThread,
        reason: BlockedReason,
    ) -> Result<SettlementDisposition, SchedulerError> {
        let _transition = self.generation_transition.lock();
        let predecessor = running.generation();
        let lease = running.take_lease();
        let action = running
            .thread
            .scheduler_park_from_executor(lease, reason)
            .map_err(|(error, _lease)| error)?;
        let successor = running
            .thread
            .execution_state()
            .generation()
            .ok_or(RunQueueError::AuthorityMismatch)?;
        let kind = if matches!(
            running.thread.execution_state(),
            super::objects::ThreadExecutionState::Blocked { .. }
        ) {
            SchedulerGenerationTransition::Blocked
        } else {
            SchedulerGenerationTransition::Runnable
        };
        // A reaped target does NOT abandon this transaction. Returning early
        // here left the executor bound, the claim unfinished and the lease
        // already taken, and the pool then failed the terminal ASID retirement
        // and dropped a published MM authority — the `conf-60360-c00` /
        // `conf-76099-c00` carrier FATAL. Settle exactly as usual; only the
        // successor publication below is withheld.
        let observed = self.observe_generation_transition(
            &running.thread,
            running.thread_key(),
            predecessor,
            successor,
            kind,
        );
        self.executors.unbind(running.binding);
        let bound_cpu = self
            .executors
            .state
            .lock()
            .entries
            .get(&running.binding.executor)
            .and_then(|e| e.bound_cpu)
            .unwrap_or(GuestCpuId::new(0));
        if let Some(guest_cpu) = self.queue.inner.cpus.get(bound_cpu.as_usize()) {
            guest_cpu.set_current_task(None);
        }
        let task_key = TaskKey::new(running.thread.task_key().serial.raw());
        self.queue.inner.policy.on_block(task_key, bound_cpu);
        drop(_transition);
        if observed == GenerationTransitionOutcome::Recorded {
            self.apply_settlement_action(
                Some(running.binding.executor),
                &running.thread,
                action,
                None,
            )?;
        }
        running.finish_claim();
        Ok(SettlementDisposition::from_outcome(observed))
    }

    pub fn settle_blocked_continuation(
        &self,
        mut running: RunnableThread,
        mut continuation: crate::vcpu_loop::continuation::BlockedContinuation,
        registration: crate::vcpu_loop::continuation::ContinuationRegistration,
    ) -> Result<SettlementDisposition, SchedulerError> {
        let _transition = self.generation_transition.lock();
        let predecessor = running.generation();
        if continuation.authority().thread() != running.thread_key()
            || continuation.authority().execution_generation() != running.generation()
        {
            return Err(RunQueueError::AuthorityMismatch.into());
        }
        continuation
            .attach_registration(registration)
            .map_err(|_| RunQueueError::AuthorityMismatch)?;
        let lease = running.take_lease();
        let action = running
            .thread
            .scheduler_park_continuation_from_executor(lease, BlockedReason::HostWait, continuation)
            .map_err(|(error, _lease)| error)?;
        let successor = running
            .thread
            .execution_state()
            .generation()
            .ok_or(RunQueueError::AuthorityMismatch)?;
        let kind = if matches!(
            running.thread.execution_state(),
            super::objects::ThreadExecutionState::Blocked { .. }
        ) {
            SchedulerGenerationTransition::Blocked
        } else {
            SchedulerGenerationTransition::Runnable
        };
        // A reaped target does NOT abandon this transaction. Returning early
        // here left the executor bound, the claim unfinished and the lease
        // already taken, and the pool then failed the terminal ASID retirement
        // and dropped a published MM authority — the `conf-60360-c00` /
        // `conf-76099-c00` carrier FATAL. Settle exactly as usual; only the
        // successor publication below is withheld.
        let observed = self.observe_generation_transition(
            &running.thread,
            running.thread_key(),
            predecessor,
            successor,
            kind,
        );
        self.executors.unbind(running.binding);
        let bound_cpu = self
            .executors
            .state
            .lock()
            .entries
            .get(&running.binding.executor)
            .and_then(|e| e.bound_cpu)
            .unwrap_or(GuestCpuId::new(0));
        if let Some(guest_cpu) = self.queue.inner.cpus.get(bound_cpu.as_usize()) {
            guest_cpu.set_current_task(None);
        }
        let task_key = TaskKey::new(running.thread.task_key().serial.raw());
        self.queue.inner.policy.on_block(task_key, bound_cpu);
        drop(_transition);
        #[cfg(test)]
        if let Some((at_clear, release)) = self.continuation_settlement_barriers.lock().clone() {
            at_clear.wait();
            release.wait();
        }
        if observed == GenerationTransitionOutcome::Recorded {
            self.apply_settlement_action(
                Some(running.binding.executor),
                &running.thread,
                action,
                None,
            )?;
        }
        running.finish_claim();
        Ok(SettlementDisposition::from_outcome(observed))
    }

    pub(crate) fn begin_switch_out(&self, running: &RunnableThread) -> Result<(), SchedulerError> {
        running.thread.begin_switch_out(running.lease())?;
        Ok(())
    }

    pub(crate) fn restore_saved_lease(
        &self,
        running: &mut RunnableThread,
        lease: ThreadExecutionLease,
    ) -> Result<(), (SchedulerError, ThreadExecutionLease)> {
        running
            .restore_lease(lease)
            .map_err(|(error, lease)| (error.into(), lease))
    }

    /// Transfer the current non-cloneable worker claim to an already-published
    /// exec replacement. The caller's publication closure swaps the combined
    /// binding/submission-authority record while this generation mutex is
    /// held; only then does the exact kick token become the successor.
    pub(crate) fn retarget_running_exec<T>(
        &self,
        running: &mut RunnableThread,
        committed: super::exec::CommittedExecTransition,
        lease: ThreadExecutionLease,
        publish: impl FnOnce(&super::exec::CommittedExecSchedulerParts) -> Result<T, String>,
    ) -> Result<T, String> {
        let generation_transition = self.generation_transition.lock();
        let committed = committed
            .into_scheduler_parts()
            .map_err(|error| error.to_string())?;
        let replacement = Arc::clone(committed.context.thread());
        let lease_identity = lease
            .task_state_authority()
            .map_err(|error| error.to_string())?;
        if running.lease.is_some()
            || lease.executor() != running.binding.executor
            || lease.thread_key() != replacement.key()
            || running.thread_key() != committed.predecessor_thread
            || running.thread.task_key() != committed.task
            || replacement.task_key() != committed.task
            || replacement.key() != committed.successor_thread
            || committed.context.shared().mm().id() != committed.successor_mm
            || committed.predecessor_mm == committed.successor_mm
            || lease_identity != (committed.successor_mm, committed.successor_asid_generation)
        {
            return Err(RunQueueError::AuthorityMismatch.to_string());
        }
        replacement
            .validate_running_execution_lease(&lease)
            .map_err(|error| error.to_string())?;
        let successor = ExecutorBinding {
            executor: lease.executor(),
            executor_epoch: lease.executor_epoch(),
            thread: replacement.key(),
            generation: lease.generation(),
        };
        let mut published = None;
        let mut publication_error = None;
        let mut publish = Some(publish);
        let mut publish_once =
            || match publish.take().unwrap_or_else(|| std::process::abort())(&committed) {
                Ok(value) => {
                    published = Some(value);
                    true
                }
                Err(error) => {
                    publication_error = Some(error);
                    false
                }
            };
        if !self
            .executors
            .rebind_exact_with(running.binding, successor, &mut publish_once)
        {
            if let Some(error) = publication_error {
                return Err(error);
            }
            // The Kernel replacement and combined record are already visible;
            // continuing without the matching kick token would split worker
            // authority. There is no safe predecessor rollback here.
            std::process::abort();
        }
        let published = published.unwrap_or_else(|| std::process::abort());
        running.thread = replacement;
        running.key = QueueKey {
            thread: successor.thread,
            generation: successor.generation,
        };
        running.binding = successor;
        running.lease = Some(lease);
        drop(generation_transition);
        self.kernel
            .release_vfork_after_exec_publication(committed.publication_receipt)
            .map_err(|error| error.to_string())?;
        Ok(published)
    }

    pub(crate) fn settle_failed(
        &self,
        mut running: RunnableThread,
        reason: super::objects::ExecutionFailure,
    ) -> Result<(), SchedulerError> {
        let _transition = self.generation_transition.lock();
        let predecessor = running.generation();
        let failure = if let Some(lease) = running.lease.take() {
            running
                .thread
                .fail_from_executor(lease, reason)
                .map(|()| {
                    running
                        .thread
                        .execution_state()
                        .generation()
                        .unwrap_or_else(|| std::process::abort())
                })
                .map_err(|(error, lease)| (error, Some(lease)))
        } else {
            running
                .thread
                .fail_claimed_execution(
                    predecessor,
                    running.binding.executor,
                    running.binding.executor_epoch,
                    reason,
                )
                .map_err(|error| (error, None))
        };
        match failure {
            Ok(successor) => {
                // Terminal: nothing is published either way, and a reaped
                // target must not abandon the retirement transaction.
                let _ = self.observe_generation_transition(
                    &running.thread,
                    running.thread_key(),
                    predecessor,
                    successor,
                    SchedulerGenerationTransition::Terminal,
                );
                self.executors.unbind(running.binding);
                let bound_cpu = self
                    .executors
                    .state
                    .lock()
                    .entries
                    .get(&running.binding.executor)
                    .and_then(|e| e.bound_cpu)
                    .unwrap_or(GuestCpuId::new(0));
                if let Some(guest_cpu) = self.queue.inner.cpus.get(bound_cpu.as_usize()) {
                    guest_cpu.set_current_task(None);
                }
                drop(_transition);
                running.finish_claim();
                Ok(())
            }
            Err((error, lease)) => {
                if let Some(lease) = lease
                    && let Err((_restore_error, lease)) = running.restore_lease(lease)
                {
                    drop(lease);
                }
                Err(error.into())
            }
        }
    }

    pub fn settle_runnable(&self, running: RunnableThread) -> Result<(), SchedulerError> {
        self.settle_runnable_successor(running).map(|_| ())
    }

    pub(crate) fn settle_runnable_successor(
        &self,
        mut running: RunnableThread,
    ) -> Result<SettlementDisposition, SchedulerError> {
        let _transition = self.generation_transition.lock();
        let predecessor = running.generation();
        let lease = running.take_lease();
        let action = running
            .thread
            .scheduler_yield_from_executor(lease)
            .map_err(|(error, _lease)| error)?;
        let successor = match action {
            ThreadSchedulerAction::Queue {
                key, generation, ..
            } if key == running.key.thread => Some(generation),
            ThreadSchedulerAction::Queue { .. }
            | ThreadSchedulerAction::Kick { .. }
            | ThreadSchedulerAction::None => None,
        };
        // A yield whose target was reaped in flight still settles: the same
        // early return that abandoned `settle_blocked` abandoned this one, and
        // an abandoned yield is what the executor loop reported as "executor
        // worker died error=exact thread generation is not live" before the
        // pool cascaded into a carrier FATAL.
        let observed = match successor {
            Some(successor) => self.observe_generation_transition(
                &running.thread,
                running.thread_key(),
                predecessor,
                successor,
                SchedulerGenerationTransition::Runnable,
            ),
            None => GenerationTransitionOutcome::Recorded,
        };
        self.executors.unbind(running.binding);
        let bound_cpu = self
            .executors
            .state
            .lock()
            .entries
            .get(&running.binding.executor)
            .and_then(|e| e.bound_cpu)
            .unwrap_or(GuestCpuId::new(0));
        if let Some(guest_cpu) = self.queue.inner.cpus.get(bound_cpu.as_usize()) {
            guest_cpu.set_current_task(None);
        }
        drop(_transition);
        self.snapshot_count.fetch_add(1, Ordering::Relaxed);
        let target_cpu = running.thread.last_cpu();
        if observed == GenerationTransitionOutcome::Recorded {
            self.apply_settlement_action(
                Some(running.binding.executor),
                &running.thread,
                action,
                target_cpu,
            )?;
        }
        running.finish_claim();
        // A reaped target has no reachable successor to report. Its process
        // job's terminal result is published by the CALLER, which owns the
        // job; reporting the disposition is how it learns it must.
        let _ = successor;
        Ok(SettlementDisposition::from_outcome(observed))
    }

    pub fn settle_exited(&self, mut running: RunnableThread) -> Result<(), SchedulerError> {
        let settle_tid = running.thread_key().tid.raw();
        let settle_generation = running.generation().raw();
        crate::event_ring::rec_hvpatch_settle_step(settle_tid, settle_generation, 1);
        let _transition = self.generation_transition.lock();
        let predecessor = running.generation();
        let lease = running.take_lease();
        running
            .thread
            .exit_from_executor(lease)
            .map_err(|(error, _lease)| error)?;
        crate::event_ring::rec_hvpatch_settle_step(settle_tid, settle_generation, 2);
        let successor = running
            .thread
            .execution_state()
            .generation()
            .ok_or(RunQueueError::AuthorityMismatch)?;
        // Terminal: nothing is published either way, and a reaped target must
        // not abandon the exit transaction.
        let _ = self.observe_generation_transition(
            &running.thread,
            running.thread_key(),
            predecessor,
            successor,
            SchedulerGenerationTransition::Terminal,
        );
        self.executors.unbind(running.binding);
        let bound_cpu = self
            .executors
            .state
            .lock()
            .entries
            .get(&running.binding.executor)
            .and_then(|e| e.bound_cpu)
            .unwrap_or(GuestCpuId::new(0));
        if let Some(guest_cpu) = self.queue.inner.cpus.get(bound_cpu.as_usize()) {
            guest_cpu.set_current_task(None);
        }
        let task_key = TaskKey::new(running.thread.task_key().serial.raw());
        self.queue.inner.policy.on_exit(task_key, bound_cpu);
        crate::event_ring::rec_hvpatch_settle_step(settle_tid, settle_generation, 3);
        drop(_transition);
        running.finish_claim();
        crate::event_ring::rec_hvpatch_settle_step(settle_tid, settle_generation, 4);
        Ok(())
    }

    fn apply_settlement_action(
        &self,
        executor: Option<ExecutorId>,
        thread: &Arc<Thread>,
        action: ThreadSchedulerAction,
        target_cpu: Option<GuestCpuId>,
    ) -> Result<(), SchedulerError> {
        match action {
            ThreadSchedulerAction::Queue {
                key,
                predecessor: _,
                generation,
                closing_authorized,
            } => {
                if let Err(error) = self.enqueue_exact_on(
                    Arc::clone(thread),
                    QueueKey {
                        thread: key,
                        generation,
                    },
                    closing_authorized,
                    target_cpu,
                ) {
                    if let Some(recorder) = self.discard_recorder.lock().as_ref() {
                        let exec_id = executor.unwrap_or_else(|| ExecutorId::from_scheduler(1));
                        recorder.record_discard(
                            exec_id,
                            key,
                            generation,
                            thread.execution_diagnostic(),
                            format!("enqueue_error: {error}"),
                        );
                    }
                    return Err(error.into());
                }
            }
            ThreadSchedulerAction::Kick { .. } | ThreadSchedulerAction::None => {}
        }
        Ok(())
    }

    pub fn kernel(&self) -> &Arc<Kernel> {
        &self.kernel
    }

    /// What the kernel-debug endpoint and the abort sink read about the run
    /// queue, produced WITHOUT ever blocking on a run-queue lock.
    ///
    /// The lifecycle is taken from the atomic `RunQueueInner` publishes it to,
    /// the totals are atomics already, and the parked-executor census is a
    /// `try_lock` that reports [`WaiterCensus::RunQueueLocked`] rather than
    /// waiting. This reader has to be able to speak in exactly the state it
    /// exists to describe.
    pub fn scheduler_summary(&self) -> SchedulerSummary {
        let lifecycle = match self.queue.inner.lifecycle() {
            QueueLifecycle::Open => "open",
            QueueLifecycle::Closing => "closing",
            QueueLifecycle::Closed => "closed",
        }
        .to_owned();
        SchedulerSummary {
            lifecycle,
            queued_len: self.queue.inner.total_queued.load(Ordering::Acquire),
            claimed: self.queue.inner.claimed.load(Ordering::Acquire),
            waiters: self.queue.try_waiter_census(),
            control_epoch: self.queue.inner.control_epoch.load(Ordering::Acquire),
            need_resched: self.need_resched(),
            snapshot_count: self.snapshot_count(),
        }
    }

    pub fn snapshot_run_queue_rows(&self) -> Vec<(ThreadKey, ExecutionGeneration, bool)> {
        let mut rows = Vec::new();
        for cpu in &self.queue.inner.cpus {
            let state = cpu.state.lock();
            for row in &state.rows {
                rows.push((row.key.thread, row.key.generation, row.closing_authorized));
            }
        }
        rows
    }

    #[allow(clippy::type_complexity)]
    pub fn snapshot_executor_entries(
        &self,
    ) -> Vec<(
        ExecutorId,
        Option<ExecutorBinding>,
        u64,
        u64,
        Option<bool>,
        Option<bool>,
    )> {
        let state = self.executors.state.lock();
        state
            .entries
            .iter()
            .map(|(id, entry)| {
                (
                    *id,
                    entry.kick.current_binding(),
                    entry.control_observation_epoch.load(Ordering::Acquire),
                    entry.close_observation_epoch.load(Ordering::Acquire),
                    entry.kick.debug_need_resched(),
                    entry.kick.debug_hardware_kick_published(),
                )
            })
            .collect()
    }

    pub fn binding_for_thread(&self, thread: ThreadKey) -> Option<ExecutorBinding> {
        self.executors.binding_for_thread(thread)
    }

    /// Guest CPUs this scheduler places onto: the installed policy's
    /// `cpu_count()`, which is also the guest's `nproc`.
    pub fn cpu_count(&self) -> usize {
        self.queue.inner.cpus.len()
    }

    pub fn queued_len(&self) -> usize {
        self.queue.len()
    }

    /// Threads currently CLAIMED by an executor.
    ///
    /// A claimed thread is neither a registry task nor a queued row, so it is
    /// invisible to both of the other liveness signals -- and a claim is
    /// exactly the state a thread is in from its quantum's exit boundary,
    /// through terminal address-space retirement, until `settle_exited` calls
    /// `finish_claim`. A carrier holding one is still working.
    pub fn claimed(&self) -> usize {
        self.queue.inner.claimed.load(Ordering::Acquire)
    }

    /// Claim boundaries this carrier has crossed: the ACTIVITY fingerprint
    /// that turns a claim from an unconditional liveness signal into a bounded
    /// one. See `RunQueueInner::claim_boundaries`.
    pub fn claim_boundaries(&self) -> u64 {
        self.queue.inner.claim_boundaries.load(Ordering::Acquire)
    }

    pub fn need_resched(&self) -> bool {
        self.need_resched.load(Ordering::Acquire)
    }

    pub fn snapshot_count(&self) -> u64 {
        self.snapshot_count.load(Ordering::Relaxed)
    }

    /// Carrier-timer policy hook. It emits only exact tokens captured from the
    /// current executor directory and every delivery revalidates the complete
    /// binding, so an epoch successor cannot consume a late preemption.
    pub fn request_preemption(&self) -> usize {
        if !self.need_resched() {
            return 0;
        }
        self.executors
            .current_tokens()
            .into_iter()
            .filter(|token| self.executors.deliver(*token))
            .count()
    }

    pub fn tick_preemption(&self) -> usize {
        let mut count = 0;
        let entries: Vec<_> = {
            let state = self.executors.state.lock();
            state
                .entries
                .values()
                .filter_map(|entry| {
                    let cpu = entry.bound_cpu?;
                    let binding = entry.kick.current_binding()?;
                    Some((cpu, binding.token()))
                })
                .collect()
        };
        for (cpu, token) in entries {
            if self.queue.inner.policy.on_tick(cpu) == PreemptOrContinue::Preempt
                && self.executors.deliver(token)
            {
                count += 1;
            }
        }
        count
    }

    pub fn note_syscall_boundary(&self, _running: &RunnableThread) {
        if self.queue.len() == 0 {
            self.need_resched.store(false, Ordering::Release);
        }
    }

    pub fn close(&self) {
        self.queue.close();
    }

    pub fn wait_closed(&self) {
        self.queue.wait_closed();
    }

    #[cfg(test)]
    pub(crate) fn install_close_started_gate(&self, gate: Arc<std::sync::Barrier>) {
        self.queue.install_close_started_gate(gate);
    }

    #[cfg(test)]
    pub(crate) fn install_continuation_settlement_barriers(
        &self,
        at_clear: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) {
        *self.continuation_settlement_barriers.lock() = Some((at_clear, release));
    }

    #[cfg(test)]
    fn is_closing(&self) -> bool {
        self.queue.inner.wake_admissions.load(Ordering::Acquire) & RunQueueInner::CLOSING_BIT != 0
    }

    #[cfg(test)]
    fn waiter_count(&self) -> usize {
        let state = self.queue.inner.state.lock();
        self.queue.waiter_count_locked(&state)
    }

    #[cfg(test)]
    fn closed_waiter_observations(&self) -> usize {
        self.queue.closed_waiter_observations()
    }

    #[cfg(test)]
    fn install_close_observation_gate(&self, gate: Arc<std::sync::Barrier>) {
        self.queue.install_close_observation_gate(gate);
    }

    #[cfg(test)]
    fn install_root_admission_gate(&self, gate: Arc<std::sync::Barrier>) {
        self.queue.install_root_admission_gate(gate);
    }

    #[cfg(test)]
    pub(crate) fn install_pre_park_gate(
        &self,
        arrived: Arc<std::sync::Barrier>,
        resume: Arc<std::sync::Barrier>,
    ) {
        self.queue.install_pre_park_gate(arrived, resume);
    }

    /// Non-destructive `findrunnable` steal probe: run the steal scan `cpu`
    /// would run, then put the row straight back. Exists so a test can assert
    /// what IS and IS NOT stealable without blocking in `take`.
    #[cfg(test)]
    pub(crate) fn steal_probe(&self, cpu: GuestCpuId) -> Option<ThreadKey> {
        let row = self.queue.inner.try_steal(cpu)?;
        let key = row.key;
        let closing_authorized = row.closing_authorized;
        let thread = Arc::clone(&row.thread);
        drop(row);
        self.queue
            .inner
            .enqueue(
                QueueRow {
                    key,
                    thread,
                    closing_authorized,
                },
                closing_authorized,
                None,
            )
            .expect("restore the probed row");
        self.queue.inner.finish_claim();
        Some(key.thread)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    use carrick_abi::LinuxCloneFlags;
    /// Pin every placement to guest CPU 0.
    ///
    /// The wake-chain tests need a burst that placement CANNOT spread, and
    /// after the claimability gate the way to get a row onto a queue is
    /// publication — which places through the policy. Forcing the CPU is
    /// therefore the policy's job, not a second enqueue entry point.
    #[derive(Debug)]
    struct PinToCpuZero(usize);

    impl carrick_hal::SchedulingPolicy for PinToCpuZero {
        fn cpu_count(&self) -> usize {
            self.0
        }

        fn select_cpu(&self, _placement: &carrick_hal::TaskPlacement<'_>) -> GuestCpuId {
            GuestCpuId::new(0)
        }
    }

    use carrick_hal::ThreadId;
    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};

    use super::{
        CpuAffinity, ExecutorBinding, ExecutorKick, ExecutorKickToken, GuestCpuId, GuestCpuPolicy,
        QueueKey, RunQueueError, Scheduler, WakeDisposition,
    };
    use crate::compat::SyscallArgs;
    use crate::dispatch::SyscallRequest;
    use crate::kernel::objects::{BlockedReason, MigratableTaskState, ThreadExecutionState};
    use crate::kernel::{ClonePlan, Kernel, KernelContext, LinuxWaitStatus, RootBootstrap};
    use crate::vcpu_loop::continuation::{
        BlockedContinuation, CarrierWaitService, ContinuationBackend, ContinuationCapture,
        RestartClass,
    };

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "scheduler test".to_owned(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    fn sibling(kernel: &Arc<Kernel>, parent: &KernelContext, host_tid: i32) -> KernelContext {
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        kernel
            .reserve_thread_clone(parent, plan, None)
            .expect("reserve sibling")
            .prepare(ThreadId::synthetic_for_tests(host_tid))
            .expect("prepare sibling")
            .commit()
            .expect("publish sibling")
            .start_thread()
            .expect("start sibling")
            .into_context()
    }

    fn process_child(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        host_tid: i32,
        name: &str,
    ) -> KernelContext {
        kernel
            .fork_task(
                parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("process fork plan"),
                ThreadId::synthetic_for_tests(host_tid),
                name.to_owned(),
                None,
            )
            .expect("fork process child")
    }

    fn task_state(context: &KernelContext, marker: u64) -> MigratableTaskState {
        let mm = context.shared().mm().id();
        MigratableTaskState {
            cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
                gprs: std::array::from_fn(|index| marker + index as u64),
                pc: marker + 0x1000,
                pstate: marker + 0x2000,
                trap_pc: marker + 0x2100,
                trap_pstate: marker + 0x2200,
                sp_el0: marker + 0x3000,
                elr_el1: marker + 0x3100,
                spsr_el1: marker + 0x3200,
                ttbr0: marker + 0x4000,
                ttbr1: marker + 0x5000,
                tcr: marker + 0x6000,
                sctlr_el1: marker + 0x6100,
                mair_el1: marker + 0x6200,
                vbar_el1: marker + 0x6300,
                cpacr_el1: marker + 0x6400,
                cntkctl_el1: marker + 0x6500,
                tpidr_el1: marker + 0x6600,
                actlr_el1: marker + 0x7000,
                tpidr_el0: marker + 0x8000,
                tpidrro_el0: marker + 0x9000,
                contextidr_el1: marker + 0xa000,
                vregs: std::array::from_fn(|index| marker as u128 + index as u128),
                fpsr: marker as u32,
                fpcr: marker as u32 + 1,
                pending_resume_pc: Some(marker + 0xb000),
                last_syscall_nr: Some(marker),
                last_syscall_orig_x0: marker + 2,
                last_fault_esr: marker + 3,
                last_exit_class: marker,
                is_forked_child: false,
                syscall_continuation: None,
                mm_generation: mm.raw(),
                asid_generation: mm.raw(),
            }),
            mm,
            asid_generation: mm.raw(),
        }
    }

    fn publish(context: &KernelContext, marker: u64) {
        context
            .thread()
            .publish_initial_task_state(task_state(context, marker))
            .expect("publish task state");
    }

    /// Records every wake rejection the scheduler classifies, so a test can
    /// assert the REASON and not merely that a wake failed.
    #[derive(Debug, Default)]
    struct RecordingWakeAuditor {
        rejections: parking_lot::Mutex<
            Vec<(
                crate::kernel::objects::TaskKey,
                crate::observe::WakeRejectionReason,
            )>,
        >,
    }

    impl crate::observe::KernelAuditor for RecordingWakeAuditor {
        fn wake_rejected(
            &self,
            target: crate::kernel::objects::TaskKey,
            reason: crate::observe::WakeRejectionReason,
        ) -> crate::observe::AuditVerdict {
            self.rejections.lock().push((target, reason));
            crate::observe::AuditVerdict::Continue
        }
    }

    /// A wake aimed at a task that has exited but not yet been waited for is
    /// `Exited`, never `Reaped`.
    ///
    /// The classification used to read LIST MEMBERSHIP: a target found among
    /// `state.retired_threads` or `state.zombies` was reported as `Reaped`.
    /// Both are backwards. A retired thread's task may still be live, and a
    /// zombie is exited-but-not-yet-waited-for, so in both cases the identity
    /// is still owned by the graph -- nothing has been reaped, and the wake is
    /// the ordinary lost race Linux drops on the floor. `NoWakeOfReapedTask`
    /// aborts on `Reaped`, so under load this ended carriers whose guest
    /// output matched the Docker oracle line for line (`mqnotifycrossproc`).
    ///
    /// This exercises the RETIRED-THREAD arm, the one the probe hit: exiting
    /// the child retires its leader thread and leaves the task a zombie, so
    /// the wake resolves through `state.retired_threads` and the verdict turns
    /// on whether anything still owns `retired._task`.
    #[test]
    fn a_wake_of_a_zombie_is_classified_exited_not_reaped() {
        let (kernel, root) = bootstrap(12_461);
        let child = process_child(&kernel, &root, 9_461, "wake-audit-target");
        let child_thread = child.thread().key();
        let child_task = child.task().key();

        let recorder = Arc::new(RecordingWakeAuditor::default());
        kernel.set_auditors(Arc::new(crate::observe::auditor::AuditorChain::new(vec![
            Arc::clone(&recorder) as Arc<dyn crate::observe::KernelAuditor>,
        ])));

        drop(child);
        kernel
            .exit_task_key_eventually(child_task, LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit the child");
        assert!(!kernel.task_is_live(child_task.id), "the child is a zombie");
        assert!(kernel.task_exists(child_task.id), "not yet waited for");

        let scheduler = Scheduler::new(Arc::clone(&kernel));
        assert!(
            scheduler.wake(child_thread).is_err(),
            "a zombie's thread cannot be made runnable"
        );
        assert_eq!(
            *recorder.rejections.lock(),
            vec![(child_task, crate::observe::WakeRejectionReason::Exited)]
        );
    }

    #[derive(Debug, Default)]
    struct RecordingKick {
        binding: parking_lot::Mutex<Option<super::ExecutorBinding>>,
        tokens: parking_lot::Mutex<Vec<ExecutorKickToken>>,
    }

    impl ExecutorKick for RecordingKick {
        fn try_bind(&self, binding: super::ExecutorBinding) -> bool {
            let mut current = self.binding.lock();
            if current.is_some() {
                return false;
            }
            *current = Some(binding);
            true
        }

        fn unbind(&self, binding: super::ExecutorBinding) {
            let mut current = self.binding.lock();
            if *current == Some(binding) {
                *current = None;
            }
        }

        fn rebind_exact_with(
            &self,
            predecessor: super::ExecutorBinding,
            successor: super::ExecutorBinding,
            publish: &mut dyn FnMut() -> bool,
        ) -> bool {
            let mut current = self.binding.lock();
            if *current != Some(predecessor) {
                return false;
            }
            if !publish() {
                return false;
            }
            *current = Some(successor);
            true
        }

        fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
            let current = self.binding.lock();
            if (*current).map(super::ExecutorBinding::token) != Some(token) {
                return false;
            }
            self.tokens.lock().push(token);
            true
        }

        fn current_binding(&self) -> Option<super::ExecutorBinding> {
            *self.binding.lock()
        }
    }

    #[derive(Debug)]
    struct BarrierKick {
        entered: Arc<Barrier>,
        resume: Arc<Barrier>,
        binding: parking_lot::Mutex<Option<super::ExecutorBinding>>,
        tokens: parking_lot::Mutex<Vec<ExecutorKickToken>>,
    }

    impl ExecutorKick for BarrierKick {
        fn try_bind(&self, binding: super::ExecutorBinding) -> bool {
            let mut current = self.binding.lock();
            if current.is_some() {
                return false;
            }
            *current = Some(binding);
            true
        }

        fn unbind(&self, binding: super::ExecutorBinding) {
            let mut current = self.binding.lock();
            if *current == Some(binding) {
                *current = None;
            }
        }

        fn rebind_exact_with(
            &self,
            predecessor: super::ExecutorBinding,
            successor: super::ExecutorBinding,
            publish: &mut dyn FnMut() -> bool,
        ) -> bool {
            let mut current = self.binding.lock();
            if *current != Some(predecessor) {
                return false;
            }
            if !publish() {
                return false;
            }
            *current = Some(successor);
            true
        }

        fn deliver_exact(&self, token: ExecutorKickToken) -> bool {
            self.entered.wait();
            self.resume.wait();
            let current = self.binding.lock();
            if (*current).map(super::ExecutorBinding::token) != Some(token) {
                return false;
            }
            self.tokens.lock().push(token);
            true
        }

        fn current_binding(&self) -> Option<super::ExecutorBinding> {
            *self.binding.lock()
        }
    }

    #[test]
    fn blocked_wake_queues_exactly_one_row_for_the_next_generation() {
        let (kernel, context) = bootstrap(12_100);
        publish(&context, 1);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        assert_eq!(
            scheduler.make_runnable(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        let running = scheduler.take(&executor).unwrap();
        let first = running.generation();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        assert_eq!(scheduler.queued_len(), 1);
        let next = scheduler.take(&executor).unwrap();
        assert_eq!(next.generation().raw(), first.raw() + 2);
        scheduler.settle_exited(next).unwrap();
    }

    #[test]
    fn control_wake_during_guest_retry_does_not_invent_a_blocked_continuation() {
        let (kernel, context) = bootstrap(12_101);
        publish(&context, 1);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::ChildState)
            .unwrap();

        assert_eq!(
            scheduler.wake_control(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        let retry_attempt = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(retry_attempt, BlockedReason::HostWait)
            .unwrap();
        assert_eq!(
            scheduler.queued_len(),
            0,
            "an active control quantum must park until the fork retry subscription fires"
        );
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Blocked {
                reason: BlockedReason::HostWait,
                ..
            }
        ));

        assert_eq!(
            scheduler.wake_control(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        let completed_retry = scheduler.take(&executor).unwrap();
        let quantum = context
            .thread()
            .finish_scheduler_control_quantum(context.thread().key())
            .expect("finish retried control quantum");
        assert_eq!(
            quantum.blocked_reason, None,
            "a fork/clone retry owns its phase state and has no deferred blocked continuation"
        );
        scheduler.settle_exited(completed_retry).unwrap();
    }

    #[test]
    fn close_between_blocked_transition_and_enqueue_cannot_strand_runnable_generation() {
        let (kernel, context) = bootstrap(12_115);
        publish(&context, 20);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        let pending = scheduler
            .begin_wake(context.thread().key())
            .expect("wake admission precedes thread transition");
        let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
        let close_scheduler = Arc::clone(&scheduler);
        let close = thread::spawn(move || {
            close_scheduler.close();
            close_scheduler.wait_closed();
            closed_tx.send(()).unwrap();
        });
        while !scheduler.is_closing() {
            thread::yield_now();
        }
        assert!(matches!(
            closed_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        assert_eq!(
            scheduler.commit_wake(pending).unwrap(),
            WakeDisposition::Queued
        );
        let resumed = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(resumed).unwrap();
        closed_rx.recv().unwrap();
        close.join().unwrap();
    }

    #[test]
    fn post_close_blocked_wake_is_rejected_without_changing_blocked_state() {
        let (kernel, context) = bootstrap(12_116);
        publish(&context, 21);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        let blocked = context.thread().execution_state();
        scheduler.close();
        scheduler.wait_closed();

        assert!(scheduler.wake(context.thread().key()).is_err());
        assert_eq!(context.thread().execution_state(), blocked);
        assert_eq!(scheduler.queued_len(), 0);
    }

    #[test]
    fn wake_racing_switch_out_is_durable_and_settles_runnable_once() {
        let (kernel, context) = bootstrap(12_101);
        publish(&context, 2);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        context.thread().begin_switch_out(running.lease()).unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let wake_scheduler = Arc::clone(&scheduler);
        let wake_key = context.thread().key();
        let wake_barrier = Arc::clone(&barrier);
        let wake = thread::spawn(move || {
            wake_barrier.wait();
            wake_scheduler.wake(wake_key)
        });
        let settle_scheduler = Arc::clone(&scheduler);
        let settle_barrier = Arc::clone(&barrier);
        let settle = thread::spawn(move || {
            settle_barrier.wait();
            settle_scheduler.settle_blocked(running, BlockedReason::HostWait)
        });
        barrier.wait();
        wake.join().unwrap().unwrap();
        settle.join().unwrap().unwrap();

        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(scheduler.queued_len(), 1);
        let resumed = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(resumed).unwrap();
    }

    #[test]
    fn two_concurrent_wakes_coalesce_to_one_exact_row() {
        let (kernel, context) = bootstrap(12_102);
        publish(&context, 3);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let mut wakes = Vec::new();
        for _ in 0..2 {
            let scheduler = Arc::clone(&scheduler);
            let barrier = Arc::clone(&barrier);
            let key = context.thread().key();
            wakes.push(thread::spawn(move || {
                barrier.wait();
                scheduler.wake(key)
            }));
        }
        barrier.wait();
        for wake in wakes {
            wake.join().unwrap().unwrap();
        }

        assert_eq!(scheduler.queued_len(), 1);
        let resumed = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(resumed).unwrap();
    }

    #[test]
    fn runnable_wake_is_idempotent_and_never_duplicates_the_row() {
        let (kernel, context) = bootstrap(12_103);
        publish(&context, 4);
        let scheduler = Scheduler::new(kernel);
        assert_eq!(
            scheduler.make_runnable(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Coalesced
        );
        assert_eq!(scheduler.queued_len(), 1);
    }

    #[test]
    fn a_duplicate_exact_publication_coalesces_onto_the_queued_row() {
        // Publication of an exact `(thread, generation)` row is idempotent for
        // the same reason `wake` is: the run queue is keyed by that pair and
        // holds at most one row for it. Rejecting the second publication made
        // a wake that beat an activation into the queue kill the guest
        // process, and it did so wearing the `SubmissionRejected` message
        // "new root submissions are rejected while the run queue is closing"
        // on a run whose run queue was demonstrably `open`.
        let (kernel, context) = bootstrap(12_113);
        publish(&context, 21);
        let scheduler = Scheduler::new(kernel);
        let generation = context.thread().execution_state().generation().unwrap();
        let authority = scheduler
            .admit_root(context.thread().key(), generation)
            .expect("admit the exact root authority");
        authority
            .publication_handle()
            .publish(&scheduler, Arc::clone(context.thread()))
            .expect("first publication of the exact row");
        authority
            .publication_handle()
            .publish(&scheduler, Arc::clone(context.thread()))
            .expect("a second publication of the same exact row coalesces");
        assert_eq!(scheduler.queued_len(), 1);
    }

    #[test]
    fn stale_thread_key_and_tid_reuse_lookalike_are_rejected() {
        let (kernel, context) = bootstrap(12_104);
        let other = sibling(&kernel, &context, 22_104);
        publish(&context, 5);
        publish(&other, 6);
        let scheduler = Scheduler::new(kernel);
        let key = context.thread().key();
        let lookalike = crate::kernel::ThreadKey {
            tid: key.tid,
            serial: other.thread().key().serial,
        };

        assert!(scheduler.wake(lookalike).is_err());
        assert!(
            scheduler
                .admit_root(
                    lookalike,
                    context.thread().execution_state().generation().unwrap()
                )
                .is_err()
        );
        assert_eq!(scheduler.queued_len(), 0);
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
    }

    #[test]
    fn current_exited_generation_cannot_admit_root_authority() {
        let (kernel, context) = bootstrap(12_120);
        publish(&context, 28);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(running).unwrap();
        let exited_generation = context.thread().execution_state().generation().unwrap();

        assert!(
            scheduler
                .admit_root(context.thread().key(), exited_generation)
                .is_err()
        );
    }

    #[test]
    fn current_failed_generation_cannot_admit_root_authority() {
        let (kernel, context) = bootstrap(12_121);
        publish(&context, 29);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let mut running = scheduler.take(&executor).unwrap();
        let lease = running.take_lease();
        context
            .thread()
            .fail_from_executor(
                lease,
                crate::kernel::objects::ExecutionFailure::SnapshotRestoreFailed,
            )
            .unwrap();
        scheduler.executors.unbind(running.binding);
        running.finish_claim();
        let failed_generation = context.thread().execution_state().generation().unwrap();

        assert!(
            scheduler
                .admit_root(context.thread().key(), failed_generation)
                .is_err()
        );
    }

    #[test]
    fn close_winning_root_admission_race_publishes_no_stale_authority() {
        let (kernel, context) = bootstrap(12_122);
        publish(&context, 30);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        let generation = running.generation();
        let gate = Arc::new(Barrier::new(2));
        scheduler.install_root_admission_gate(Arc::clone(&gate));
        let admission_scheduler = Arc::clone(&scheduler);
        let key = context.thread().key();
        let admission = thread::spawn(move || admission_scheduler.admit_root(key, generation));

        gate.wait();
        let exit_scheduler = Arc::clone(&scheduler);
        let exit = thread::spawn(move || exit_scheduler.settle_exited(running));
        scheduler.close();
        assert!(scheduler.is_closing());
        gate.wait();

        assert!(admission.join().unwrap().is_err());
        exit.join().unwrap().unwrap();
        scheduler.wait_closed();
    }

    #[test]
    fn running_wake_emits_one_exact_kick_after_the_transition_unlocks() {
        let (kernel, context) = bootstrap(12_105);
        publish(&context, 7);
        let scheduler = Scheduler::new(kernel);
        let kicks = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();

        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Kicked
        );
        let tokens = kicks.tokens.lock();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].thread(), context.thread().key());
        assert_eq!(tokens[0].generation(), running.generation());
        assert_eq!(tokens[0].executor(), running.executor());
        assert_eq!(tokens[0].executor_epoch(), running.executor_epoch());
        drop(tokens);
        scheduler.settle_exited(running).unwrap();
    }

    #[test]
    fn switching_out_wake_never_kicks_old_executor_and_forces_runnable_settlement() {
        let (kernel, context) = bootstrap(12_106);
        publish(&context, 8);
        let scheduler = Scheduler::new(kernel);
        let kicks = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        context.thread().begin_switch_out(running.lease()).unwrap();

        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Pending
        );
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        assert!(kicks.tokens.lock().is_empty());
        assert_eq!(scheduler.queued_len(), 1);
        let resumed = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(resumed).unwrap();
    }

    #[test]
    fn late_kick_token_cannot_affect_the_executor_epoch_successor() {
        let (kernel, context) = bootstrap(12_107);
        publish(&context, 9);
        let scheduler = Scheduler::new(kernel);
        let kicks = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let first = scheduler.take(&executor).unwrap();
        let delayed = scheduler.decide_wake(context.thread().key()).unwrap();
        scheduler.settle_runnable(first).unwrap();
        let successor = scheduler.take(&executor).unwrap();

        assert_eq!(
            scheduler.deliver_wake(delayed).unwrap(),
            WakeDisposition::Pending
        );
        assert!(kicks.tokens.lock().is_empty());
        scheduler.settle_exited(successor).unwrap();
    }

    #[test]
    fn exec_rebind_rejects_old_full_token_and_accepts_successor_token() {
        let (kernel, first) = bootstrap(11_074);
        publish(&first, 74);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let kick = Arc::new(RecordingKick::default());
        let registration = scheduler.register_executor(kick.clone()).unwrap();
        scheduler.make_runnable(first.thread().key()).unwrap();
        let mut running = scheduler.take(&registration).unwrap();
        let predecessor = running.binding;
        let old_token = predecessor.token();
        let prepared = kernel
            .prepare_exec_with_registry_id(&first, ThreadId::synthetic_for_tests(21_074), None)
            .unwrap();
        let old_lease = running.take_lease();
        first.thread().exit_from_executor(old_lease).unwrap();
        let committed = kernel.commit_exec_transition(prepared, None).unwrap();
        let replacement = committed.context().retain_exact();
        let replacement_mm = replacement.shared().mm().id();
        let committed = committed
            .attach_successor_asid_generation(replacement_mm, replacement_mm.raw())
            .unwrap();
        replacement
            .thread()
            .publish_initial_task_state(task_state(&replacement, 75))
            .unwrap();
        let replacement_lease = replacement
            .thread()
            .claim_runnable(registration.id())
            .unwrap();
        scheduler
            .retarget_running_exec(&mut running, committed, replacement_lease, |_| {
                Ok::<_, String>(())
            })
            .unwrap();
        let successor = running.binding;
        let successor_token = successor.token();

        assert_ne!(predecessor.thread, successor.thread);
        assert!(!kick.deliver_exact(old_token));
        assert!(kick.deliver_exact(successor_token));
        assert_eq!(kick.tokens.lock().as_slice(), &[successor_token]);
        scheduler.settle_exited(running).unwrap();
        scheduler.unregister_executor(&registration).unwrap();
    }

    #[test]
    fn vfork_exec_release_follows_exact_scheduler_retarget() {
        let (kernel, parent) = bootstrap(11_075);
        let published = kernel
            .reserve_fork(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM)
                    .expect("vfork plan"),
                "scheduler vfork exec".to_owned(),
                None,
            )
            .expect("reserve vfork")
            .prepare_reference(ThreadId::synthetic_for_tests(21_075))
            .expect("prepare vfork")
            .commit()
            .expect("publish vfork");
        let (first, wait) = published.into_parts().expect("start vfork child");
        let wait = wait.expect("vfork parent wait");
        publish(&first, 75);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let kick = Arc::new(RecordingKick::default());
        let registration = scheduler.register_executor(kick).unwrap();
        scheduler.make_runnable(first.thread().key()).unwrap();
        let mut running = scheduler.take(&registration).unwrap();
        let prepared = kernel
            .prepare_exec_with_registry_id(&first, ThreadId::synthetic_for_tests(31_075), None)
            .unwrap();
        let old_lease = running.take_lease();
        first.thread().exit_from_executor(old_lease).unwrap();
        let committed = kernel.commit_exec_transition(prepared, None).unwrap();
        let replacement = committed.context().retain_exact();
        let replacement_mm = replacement.shared().mm().id();
        let committed = committed
            .attach_successor_asid_generation(replacement_mm, replacement_mm.raw())
            .unwrap();
        assert_eq!(
            wait.released_reason(),
            None,
            "Kernel exec publication is not the HVPatch successor publication"
        );
        replacement
            .thread()
            .publish_initial_task_state(task_state(&replacement, 76))
            .unwrap();
        let replacement_lease = replacement
            .thread()
            .claim_runnable(registration.id())
            .unwrap();

        scheduler
            .retarget_running_exec(&mut running, committed, replacement_lease, |_| {
                Ok::<_, String>(())
            })
            .unwrap();

        assert_eq!(
            wait.released_reason(),
            Some(crate::kernel::VforkReleaseReason::Exec)
        );
        scheduler.settle_exited(running).unwrap();
        scheduler.unregister_executor(&registration).unwrap();
    }

    #[test]
    fn exec_retarget_rejects_lease_asid_identity_not_minted_by_transition() {
        let (kernel, parent) = bootstrap(11_076);
        let published = kernel
            .reserve_fork(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM)
                    .expect("vfork plan"),
                "scheduler wrong-ASID vfork exec".to_owned(),
                None,
            )
            .expect("reserve vfork")
            .prepare_reference(ThreadId::synthetic_for_tests(21_076))
            .expect("prepare vfork")
            .commit()
            .expect("publish vfork");
        let (first, wait) = published.into_parts().expect("start vfork child");
        let wait = wait.expect("vfork parent wait");
        publish(&first, 75);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let kick = Arc::new(RecordingKick::default());
        let registration = scheduler.register_executor(kick).unwrap();
        scheduler.make_runnable(first.thread().key()).unwrap();
        let mut running = scheduler.take(&registration).unwrap();
        let prepared = kernel
            .prepare_exec_with_registry_id(&first, ThreadId::synthetic_for_tests(21_075), None)
            .unwrap();
        let old_lease = running.take_lease();
        first.thread().exit_from_executor(old_lease).unwrap();
        let committed = kernel.commit_exec_transition(prepared, None).unwrap();
        let replacement = committed.context().retain_exact();
        let replacement_mm = replacement.shared().mm().id();
        let wrong_asid = replacement_mm.raw().checked_add(1).unwrap();
        let committed = committed
            .attach_successor_asid_generation(replacement_mm, wrong_asid)
            .unwrap();
        replacement
            .thread()
            .publish_initial_task_state(task_state(&replacement, 76))
            .unwrap();
        let replacement_lease = replacement
            .thread()
            .claim_runnable(registration.id())
            .unwrap();

        assert!(
            scheduler
                .retarget_running_exec(&mut running, committed, replacement_lease, |_| Ok::<
                    _,
                    String,
                >(
                    ()
                ),)
                .is_err(),
            "replacement lease MM/ASID/CPU identity must match the Kernel token"
        );
        assert!(matches!(
            replacement.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert_eq!(
            wait.released_reason(),
            None,
            "failed retarget must leave the vfork parent blocked"
        );
        kernel
            .exit_task(
                first.task().key().id,
                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("exit exact committed child");
        assert_eq!(
            wait.released_reason(),
            Some(crate::kernel::VforkReleaseReason::Exit)
        );
        scheduler.unregister_executor(&registration).unwrap();
    }

    #[test]
    fn executor_rebind_between_directory_validation_and_delivery_never_interrupts_successor() {
        let (kernel, context) = bootstrap(12_117);
        publish(&context, 22);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let kicks = Arc::new(BarrierKick {
            entered: Arc::clone(&entered),
            resume: Arc::clone(&resume),
            binding: parking_lot::Mutex::new(None),
            tokens: parking_lot::Mutex::new(Vec::new()),
        });
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let first = scheduler.take(&executor).unwrap();
        let delayed = scheduler.decide_wake(context.thread().key()).unwrap();
        let delivery_scheduler = Arc::clone(&scheduler);
        let delivery = thread::spawn(move || delivery_scheduler.deliver_wake(delayed));

        entered.wait();
        scheduler.settle_runnable(first).unwrap();
        let successor = scheduler.take(&executor).unwrap();
        resume.wait();
        assert_eq!(delivery.join().unwrap().unwrap(), WakeDisposition::Pending);
        assert!(kicks.tokens.lock().is_empty());
        scheduler.settle_exited(successor).unwrap();
    }

    #[test]
    fn take_discards_stale_rows_and_claims_only_the_exact_current_generation() {
        let (kernel, context) = bootstrap(12_108);
        publish(&context, 10);
        let scheduler = Scheduler::new(kernel);
        scheduler.make_runnable(context.thread().key()).unwrap();

        let bypass = context
            .thread()
            .claim_runnable(crate::kernel::objects::ExecutorId::synthetic_for_tests(99))
            .unwrap();
        context.thread().yield_from_executor(bypass).unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        let claimed = scheduler.take(&executor).unwrap();

        assert_eq!(claimed.generation().raw(), 2);
        assert_eq!(scheduler.queued_len(), 0);
        scheduler.settle_exited(claimed).unwrap();
    }

    #[test]
    fn blocked_state_has_no_executor_binding() {
        let (kernel, context) = bootstrap(12_109);
        publish(&context, 11);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        assert!(
            scheduler
                .binding_for_thread(context.thread().key())
                .is_none()
        );
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Blocked { .. }
        ));
    }

    #[test]
    fn generic_wake_racing_vfork_settlement_cannot_resume_parent() {
        let (kernel, parent) = bootstrap(12_122);
        publish(&parent, 30);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let wait_service = CarrierWaitService::new(Arc::clone(&scheduler));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(parent.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();

        let published = kernel
            .reserve_fork(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM)
                    .expect("vfork plan"),
                "scheduler vfork wake race".to_owned(),
                None,
            )
            .expect("reserve vfork")
            .prepare_reference(ThreadId::synthetic_for_tests(22_122))
            .expect("prepare vfork")
            .commit()
            .expect("publish vfork");
        let (child, wait) = published.into_parts().expect("start vfork child");
        let current = parent
            .task_binding()
            .capture(parent.thread().key().tid)
            .expect("recapture vfork parent");
        let continuation = BlockedContinuation::from_vfork_parent(
            ContinuationCapture::from_lease(
                &current,
                running.lease(),
                SyscallRequest::new(220, SyscallArgs([0; 6])),
                RestartClass::RestartSyscall,
                ContinuationBackend::Hvpatch,
            )
            .expect("capture running vfork parent"),
            child.task().key(),
            wait.expect("vfork parent wait"),
        )
        .expect("vfork continuation");
        let mut registration = wait_service.prepare_registration(&continuation);
        wait_service
            .enroll(&mut registration)
            .expect("enroll vfork continuation");

        scheduler
            .wake(parent.thread().key())
            .expect("generic wake races vfork switch-out");
        scheduler
            .settle_blocked_continuation(running, continuation, registration)
            .expect("settle vfork parent");

        assert!(
            matches!(
                parent.thread().execution_state(),
                ThreadExecutionState::Blocked { .. }
            ),
            "generic wake_pending must not resume a vfork parent before exact child release",
        );
        assert_eq!(scheduler.queued_len(), 0);

        assert_eq!(
            scheduler
                .wake(parent.thread().key())
                .expect("generic wake of blocked vfork parent"),
            WakeDisposition::Pending,
        );
        assert!(matches!(
            parent.thread().execution_state(),
            ThreadExecutionState::Blocked { .. }
        ));
        assert_eq!(scheduler.queued_len(), 0);

        kernel
            .exit_task(
                child.task().key().id,
                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("publish exact vfork child release");
        assert!(matches!(
            parent.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(scheduler.queued_len(), 1);
        let released = scheduler
            .take(&executor)
            .expect("take released vfork parent");
        assert_eq!(
            released
                .lease()
                .blocked_continuation()
                .expect("released vfork continuation")
                .ready_event()
                .expect("exact release event"),
            crate::vcpu_loop::continuation::ContinuationEvent::Ready,
        );
        scheduler.settle_exited(released).unwrap();
    }

    /// `ltp-pause01`: the previous child's `exit_group` posts SIGCHLD to the
    /// parent while the parent is switching out into a shared `FUTEX_WAIT`
    /// on the LTP checkpoint word. That generic scheduler wake is not a
    /// futex wake; publishing `Ready` for it returns 0 from `futex(2)` with
    /// no counted producer, so the next child's `FUTEX_WAKE` finds nobody
    /// and `tst_checkpoint_wake` spins to ETIMEDOUT.
    #[test]
    fn generic_wake_racing_shared_futex_settlement_cannot_fabricate_wake() {
        use carrick_guest_mem::{HostVa, SharedFutexLocation};
        use carrick_thread::platform_futex::carrier_shared_futex_table;

        let (kernel, waiter) = bootstrap(12_123);
        publish(&waiter, 31);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let wait_service = CarrierWaitService::new(Arc::clone(&scheduler));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(waiter.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();

        let word = Box::new(std::sync::atomic::AtomicU32::new(0));
        let waiter_key = word.as_ptr() as usize;
        let current = waiter
            .task_binding()
            .capture(waiter.thread().key().tid)
            .expect("recapture futex waiter");
        let continuation = BlockedContinuation::from_dispatch_outcome(
            crate::dispatch::DispatchOutcome::SharedFutexWait {
                location: SharedFutexLocation::Direct {
                    word: HostVa(waiter_key),
                    waiter_key,
                },
                waiter_key,
                generation: carrier_shared_futex_table().prepare_wait(waiter_key as u64),
                value: 0,
                timeout: None,
            },
            ContinuationCapture::from_lease(
                &current,
                running.lease(),
                SyscallRequest::new(98, SyscallArgs([0; 6])),
                RestartClass::RestartSyscall,
                ContinuationBackend::Hvpatch,
            )
            .expect("capture running futex waiter"),
        )
        .expect("shared futex continuation");
        let mut registration = wait_service.prepare_registration(&continuation);
        wait_service
            .enroll(&mut registration)
            .expect("enroll shared futex continuation");

        scheduler
            .wake(waiter.thread().key())
            .expect("generic wake races futex switch-out");
        scheduler
            .settle_blocked_continuation(running, continuation, registration)
            .expect("settle futex waiter");

        assert!(
            matches!(
                waiter.thread().execution_state(),
                ThreadExecutionState::Blocked { .. }
            ),
            "generic wake_pending must not fabricate a futex wake",
        );
        assert_eq!(scheduler.queued_len(), 0);

        assert_eq!(
            scheduler
                .wake(waiter.thread().key())
                .expect("generic wake of blocked futex waiter"),
            WakeDisposition::Pending,
        );
        assert!(matches!(
            waiter.thread().execution_state(),
            ThreadExecutionState::Blocked { .. }
        ));
        assert_eq!(scheduler.queued_len(), 0);

        assert_eq!(
            carrier_shared_futex_table().wake(waiter_key as u64, 1),
            1,
            "the exact futex wake must still find the parked waiter",
        );
        assert!(matches!(
            waiter.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(scheduler.queued_len(), 1);
        let released = scheduler.take(&executor).expect("take woken futex waiter");
        assert_eq!(
            released
                .lease()
                .blocked_continuation()
                .expect("woken futex continuation")
                .ready_event()
                .expect("exact futex wake event"),
            crate::vcpu_loop::continuation::ContinuationEvent::Ready,
        );
        scheduler.settle_exited(released).unwrap();
        drop(word);
    }

    /// The wake chain, as an invariant: a burst of rows placed on ONE guest
    /// CPU while every other CPU sits parked must end with every executor
    /// running a row and nothing queued.
    ///
    /// Round 1 nudged at most one idle CPU per `enqueue`, and only when the
    /// target had no parked waiter. A nudged executor that took a DIFFERENT
    /// row consumed the wake, and the row it left behind then waited beside
    /// parked executors until an unrelated event moved the queue. Go's answer
    /// is `wakep` plus the spinning-`M` handoff: an executor woken to scan
    /// that finds work nudges the next idle CPU before it runs.
    #[test]
    fn a_burst_onto_one_cpu_wakes_every_parked_executor_through_the_chain() {
        const CPUS: usize = 4;
        let (kernel, root) = bootstrap(12_400);
        publish(&root, 40);
        let children: Vec<KernelContext> = (0..CPUS)
            .map(|index| {
                let child = process_child(
                    &kernel,
                    &root,
                    22_400 + index as i32,
                    "scheduler chain child",
                );
                publish(&child, 41 + index as u64);
                child
            })
            .collect();
        let scheduler = Arc::new(Scheduler::new_with_policy(
            Arc::clone(&kernel),
            Arc::new(PinToCpuZero(CPUS)),
        ));
        let root_authority = scheduler
            .admit_root(
                root.thread().key(),
                root.thread().execution_state().generation().unwrap(),
            )
            .unwrap();

        // One `M` per `P`. Each takes exactly ONE row and then HOLDS it, so a
        // row can only start on an executor the chain actually woke — no
        // executor is available to pick up a second row.
        let ready = Arc::new(Barrier::new(CPUS + 1));
        let hold = Arc::new(Barrier::new(CPUS + 1));
        let taken = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for index in 0..CPUS {
            let scheduler = Arc::clone(&scheduler);
            let ready = Arc::clone(&ready);
            let hold = Arc::clone(&hold);
            let taken = Arc::clone(&taken);
            workers.push(thread::spawn(move || {
                let executor = scheduler
                    .register_executor_bound(
                        Arc::new(RecordingKick::default()),
                        Some(GuestCpuId::new(index as u32)),
                        false,
                    )
                    .unwrap();
                ready.wait();
                let running = scheduler
                    .take(&executor)
                    .expect("every executor is reached by the wake chain");
                taken.fetch_add(1, Ordering::SeqCst);
                hold.wait();
                scheduler.settle_exited(running).unwrap();
                scheduler.unregister_executor(&executor).unwrap();
            }));
        }
        ready.wait();
        while scheduler.waiter_count() != CPUS {
            thread::yield_now();
        }

        // The burst. Every row is FORCED onto guest CPU 0, so placement
        // cannot spread it and only the chain can start the other three.
        let _authorities: Vec<super::SubmissionAuthority> = children
            .iter()
            .map(|child| {
                let authority = root_authority
                    .admit_descendant(
                        child.thread().key(),
                        child.thread().execution_state().generation().unwrap(),
                    )
                    .unwrap();
                // Activation IS publication: an admitted key's row is
                // deferred until its submission publishes, so the burst has to
                // arrive the way the shipped path makes rows claimable.
                authority
                    .publish(&scheduler, Arc::clone(child.thread()))
                    .unwrap();
                authority
            })
            .collect();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while taken.load(Ordering::SeqCst) < CPUS {
            assert!(
                std::time::Instant::now() < deadline,
                "the wake chain stalled: {} of {CPUS} rows started, {} still queued, {} executors parked",
                taken.load(Ordering::SeqCst),
                scheduler.queued_len(),
                scheduler.waiter_count(),
            );
            thread::yield_now();
        }

        // The invariant: nothing runnable is left beside a parked executor.
        assert_eq!(scheduler.queued_len(), 0, "a row outlived the chain");
        assert_eq!(
            scheduler.waiter_count(),
            0,
            "an executor parked while a row was runnable",
        );
        for index in 0..CPUS {
            assert_eq!(
                scheduler.queue.inner.cpus[index].idle_executors(),
                0,
                "cpu#{index} kept a phantom idle announcement",
            );
        }

        hold.wait();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    /// The counted announcement is exact across a claim: an executor that
    /// takes a row leaves no idle credit behind, and one that parks is
    /// counted once — the placement policy reads this as "a free executor
    /// lives here".
    #[test]
    fn an_idle_announcement_is_counted_per_executor_not_per_cpu() {
        let (kernel, root) = bootstrap(12_450);
        publish(&root, 50);
        let child = process_child(&kernel, &root, 22_450, "scheduler idle-count child");
        publish(&child, 51);
        let scheduler = Arc::new(Scheduler::new_with_policy(
            Arc::clone(&kernel),
            Arc::new(PinToCpuZero(2)),
        ));
        let cpu0 = Arc::clone(&scheduler.queue.inner.cpus[0]);
        // Two `M`s share guest CPU 0, which is what a bool could not express.
        let ready = Arc::new(Barrier::new(3));
        let hold = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let scheduler = Arc::clone(&scheduler);
            let ready = Arc::clone(&ready);
            let hold = Arc::clone(&hold);
            workers.push(thread::spawn(move || {
                let executor = scheduler
                    .register_executor_bound(
                        Arc::new(RecordingKick::default()),
                        Some(GuestCpuId::new(0)),
                        false,
                    )
                    .unwrap();
                ready.wait();
                match scheduler.take(&executor) {
                    Ok(running) => {
                        hold.wait();
                        scheduler.settle_exited(running).unwrap();
                    }
                    Err(RunQueueError::Closed) => {}
                    Err(error) => panic!("unexpected take error: {error:?}"),
                }
                scheduler.unregister_executor(&executor).unwrap();
            }));
        }
        ready.wait();
        while scheduler.waiter_count() != 2 {
            thread::yield_now();
        }
        assert_eq!(
            cpu0.idle_executors(),
            2,
            "both `M`s bound to cpu#0 must be counted idle, not collapsed to one flag",
        );

        let root_authority = scheduler
            .admit_root(
                root.thread().key(),
                root.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        let authority = root_authority
            .admit_descendant(
                child.thread().key(),
                child.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        // Activation IS publication: an admitted key's row is deferred until
        // its submission publishes, so the row arrives the shipped way.
        authority
            .publish(&scheduler, Arc::clone(child.thread()))
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while cpu0.idle_executors() != 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "one `M` took the row, so cpu#0 must be left with exactly one idle executor (saw {})",
                cpu0.idle_executors(),
            );
            thread::yield_now();
        }
        hold.wait();
        // Both authorities must go before the close: `drain_ready` counts
        // them, so a live authority keeps the queue Closing forever and the
        // second `M` never observes the close.
        drop(authority);
        drop(root_authority);
        scheduler.close();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(cpu0.idle_executors(), 0);
    }

    #[test]
    fn close_wakes_all_waiters_rejects_new_roots_and_drains_recursive_publication() {
        let (kernel, root) = bootstrap(12_110);
        let child = process_child(&kernel, &root, 22_110, "scheduler child");
        let grandchild = process_child(&kernel, &child, 22_111, "scheduler grandchild");
        publish(&root, 12);
        publish(&child, 13);
        publish(&grandchild, 14);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let root_generation = root.thread().execution_state().generation().unwrap();
        let root_authority = scheduler
            .admit_root(root.thread().key(), root_generation)
            .unwrap();
        let claimed = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(3));
        let mut waiters = Vec::new();
        for _ in 0..2 {
            let scheduler = Arc::clone(&scheduler);
            let claimed = Arc::clone(&claimed);
            let closed = Arc::clone(&closed);
            let barrier = Arc::clone(&barrier);
            waiters.push(thread::spawn(move || {
                let executor = scheduler
                    .register_executor(Arc::new(RecordingKick::default()))
                    .unwrap();
                barrier.wait();
                loop {
                    match scheduler.take(&executor) {
                        Ok(running) => {
                            claimed.fetch_add(1, Ordering::SeqCst);
                            scheduler.settle_exited(running).unwrap();
                        }
                        Err(RunQueueError::Closed) => {
                            closed.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        Err(error) => panic!("unexpected take error: {error:?}"),
                    }
                }
            }));
        }
        barrier.wait();
        while scheduler.waiter_count() != 2 {
            thread::yield_now();
        }

        let observation_gate = Arc::new(Barrier::new(3));
        scheduler.install_close_observation_gate(Arc::clone(&observation_gate));
        scheduler.close();
        let (closed_tx, closed_rx) = std::sync::mpsc::sync_channel(1);
        let close_scheduler = Arc::clone(&scheduler);
        let close_wait = thread::spawn(move || {
            close_scheduler.wait_closed();
            closed_tx.send(()).unwrap();
        });
        assert!(scheduler.make_runnable(child.thread().key()).is_err());
        assert!(
            scheduler
                .admit_root(
                    child.thread().key(),
                    child.thread().execution_state().generation().unwrap()
                )
                .is_err()
        );
        let child_authority = root_authority
            .admit_descendant(
                child.thread().key(),
                child.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        let grandchild_authority = child_authority
            .admit_descendant(
                grandchild.thread().key(),
                grandchild.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        child_authority
            .publish(&scheduler, Arc::clone(child.thread()))
            .unwrap();
        grandchild_authority
            .publish(&scheduler, Arc::clone(grandchild.thread()))
            .unwrap();
        drop(grandchild_authority);
        drop(child_authority);
        drop(root_authority);
        assert!(matches!(
            closed_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        observation_gate.wait();
        closed_rx.recv().unwrap();
        close_wait.join().unwrap();
        for waiter in waiters {
            waiter.join().unwrap();
        }

        assert_eq!(claimed.load(Ordering::SeqCst), 2);
        assert_eq!(closed.load(Ordering::SeqCst), 2);
        assert_eq!(scheduler.closed_waiter_observations(), 2);
    }

    #[test]
    fn a_wake_for_an_admitted_unpublished_key_is_durable_but_not_claimable() {
        // The run queue is the single authority for claimability. An admitted
        // submission has no resolvable binding until it publishes, so a wake
        // in that window owns the edge (it must not be lost, and a second
        // wake must coalesce onto it) without ever handing an executor a row
        // it can only fail.
        let (kernel, context) = bootstrap(12_130);
        publish(&context, 30);
        let generation = context.thread().execution_state().generation().unwrap();
        let scheduler = Scheduler::new(kernel);
        let authority = scheduler
            .admit_root(context.thread().key(), generation)
            .unwrap();

        assert_eq!(
            scheduler.make_runnable(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        assert_eq!(scheduler.queued_len(), 0, "held, not claimable");
        assert_eq!(
            scheduler.wake(context.thread().key()).unwrap(),
            WakeDisposition::Coalesced,
            "a held row still owns the exact key"
        );
        assert_eq!(scheduler.queued_len(), 0);

        // Publication is the transition that releases it, exactly once.
        authority
            .publish(&scheduler, Arc::clone(context.thread()))
            .unwrap();
        assert_eq!(scheduler.queued_len(), 1);
        authority
            .publish(&scheduler, Arc::clone(context.thread()))
            .unwrap();
        assert_eq!(scheduler.queued_len(), 1);
    }

    #[test]
    fn releasing_an_unpublished_authority_drops_the_row_it_was_holding() {
        // An admitted submission that dies before activating takes its held
        // row with it: nothing is left queued under a key no binding can
        // resolve, and the queue can still drain to closed.
        let (kernel, context) = bootstrap(12_131);
        publish(&context, 31);
        let generation = context.thread().execution_state().generation().unwrap();
        let scheduler = Scheduler::new(kernel);
        let authority = scheduler
            .admit_root(context.thread().key(), generation)
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        assert_eq!(scheduler.queued_len(), 0);

        drop(authority);
        // The held row went with it: the exact key is unqueued (a fresh wake
        // reports `Queued`, not `Coalesced`) and, with the ADMISSION gate
        // gone, that wake is claimable immediately. This fixture admits
        // directly, so it carries no pre-publication reservation; the
        // production shape -- where the thread was published to the Kernel
        // through `publish_initial_task_state_gated` and the reservation
        // outlives the authority -- is covered by
        // `a_dropped_dormant_submission_leaves_no_claimable_row_for_its_generation`.
        assert_eq!(
            scheduler.make_runnable(context.thread().key()).unwrap(),
            WakeDisposition::Queued
        );
        assert_eq!(scheduler.queued_len(), 1);

        // And the queue still drains once that row is settled.
        scheduler
            .fail_runnable_exact(
                context.thread().key(),
                generation,
                crate::kernel::objects::ExecutionFailure::SnapshotRestoreFailed,
            )
            .unwrap();
        assert_eq!(scheduler.queued_len(), 0);
        scheduler.close();
        scheduler.wait_closed();
    }

    #[test]
    fn exited_grant_cannot_authorize_a_descendant_during_close() {
        let (kernel, root) = bootstrap(12_118);
        let child = process_child(&kernel, &root, 22_118, "exited grant child");
        publish(&root, 23);
        publish(&child, 24);
        let scheduler = Scheduler::new(kernel);
        let authority = scheduler
            .admit_root(
                root.thread().key(),
                root.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        // Publish before waking: an admitted submission's row is not
        // claimable until its authority publishes, which is the order every
        // production path takes (`prepare_submission` then `activate`).
        authority
            .publish(&scheduler, Arc::clone(root.thread()))
            .unwrap();
        scheduler.make_runnable(root.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(running).unwrap();
        scheduler.close();

        assert!(
            authority
                .admit_descendant(
                    child.thread().key(),
                    child.thread().execution_state().generation().unwrap(),
                )
                .is_err()
        );
        drop(authority);
        scheduler.wait_closed();
    }

    #[test]
    fn authority_rollover_rejects_stale_or_wrong_successor_without_loss_or_duplication() {
        let (kernel, context) = bootstrap(12_119);
        let wrong = sibling(&kernel, &context, 22_119);
        publish(&context, 23);
        let generation = context
            .thread()
            .execution_state()
            .generation()
            .expect("published root generation");
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        let authority = scheduler
            .admit_root(context.thread().key(), generation)
            .unwrap();
        authority
            .publish(&scheduler, Arc::clone(context.thread()))
            .unwrap();
        assert_eq!(scheduler.queue.active_authority_count(), 1);
        let running = scheduler.take(&executor).unwrap();
        scheduler.settle_runnable(running).unwrap();
        let successor = context
            .thread()
            .execution_state()
            .generation()
            .expect("runnable successor generation");

        let authority = match authority.rollover_exact(
            &scheduler,
            context.thread().key(),
            successor,
            context.thread().key(),
            successor,
        ) {
            Err((RunQueueError::AuthorityMismatch, authority)) => authority,
            other => panic!("stale predecessor rollover must reject: {other:?}"),
        };
        assert_eq!(scheduler.queue.active_authority_count(), 1);
        let authority = match authority.rollover_exact(
            &scheduler,
            context.thread().key(),
            generation,
            wrong.thread().key(),
            successor,
        ) {
            Err((RunQueueError::AuthorityMismatch, authority)) => authority,
            other => panic!("wrong-thread rollover must reject: {other:?}"),
        };
        assert_eq!(scheduler.queue.active_authority_count(), 1);
        let authority = match authority.rollover_exact(
            &scheduler,
            context.thread().key(),
            generation,
            context.thread().key(),
            generation,
        ) {
            Err((RunQueueError::AuthorityMismatch, authority)) => authority,
            other => panic!("wrong successor generation must reject: {other:?}"),
        };
        assert_eq!(scheduler.queue.active_authority_count(), 1);
        let authority = authority
            .rollover_exact(
                &scheduler,
                context.thread().key(),
                generation,
                context.thread().key(),
                successor,
            )
            .expect("exact successor rollover");
        assert_eq!(authority.thread_key(), context.thread().key());
        assert_eq!(authority.generation(), successor);
        assert_eq!(scheduler.queue.active_authority_count(), 1);
        drop(authority);
        assert_eq!(scheduler.queue.active_authority_count(), 0);

        let successor_running = scheduler.take(&executor).unwrap();
        scheduler.settle_exited(successor_running).unwrap();
        scheduler.close();
        scheduler.wait_closed();
    }

    #[test]
    fn live_unrelated_process_cannot_be_admitted_as_a_descendant() {
        let (kernel, root) = bootstrap(12_119);
        let grant = process_child(&kernel, &root, 22_119, "grant child");
        let unrelated = process_child(&kernel, &root, 22_120, "unrelated child");
        publish(&root, 25);
        publish(&grant, 26);
        publish(&unrelated, 27);
        let scheduler = Scheduler::new(kernel);
        let authority = scheduler
            .admit_root(
                grant.thread().key(),
                grant.thread().execution_state().generation().unwrap(),
            )
            .unwrap();
        scheduler.close();

        assert!(
            authority
                .admit_descendant(
                    unrelated.thread().key(),
                    unrelated.thread().execution_state().generation().unwrap(),
                )
                .is_err()
        );
        drop(authority);
        scheduler.wait_closed();
    }

    #[test]
    fn proc_state_helper_renders_runnable_and_running_as_r_and_blocked_as_s() {
        let (kernel, context) = bootstrap(12_111);
        publish(&context, 14);
        let scheduler = Scheduler::new(kernel);
        assert_eq!(context.thread().linux_run_state(), Some('R'));
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        assert_eq!(context.thread().linux_run_state(), Some('R'));
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        assert_eq!(context.thread().linux_run_state(), Some('S'));
    }

    #[test]
    fn lone_task_thousands_of_syscalls_never_arm_resched_or_snapshot() {
        let (kernel, context) = bootstrap(12_112);
        publish(&context, 15);
        let scheduler = Scheduler::new(kernel);
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();
        scheduler.make_runnable(context.thread().key()).unwrap();
        let running = scheduler.take(&executor).unwrap();
        for _ in 0..10_000 {
            scheduler.note_syscall_boundary(&running);
        }

        assert!(!scheduler.need_resched());
        assert_eq!(scheduler.snapshot_count(), 0);
        scheduler.settle_exited(running).unwrap();
    }

    #[test]
    fn one_executor_preempts_two_compute_generations_and_signal_wake_is_prompt() {
        let (kernel, first) = bootstrap(12_113);
        let second = sibling(&kernel, &first, 22_113);
        publish(&first, 16);
        publish(&second, 17);
        let scheduler = Scheduler::new(kernel);
        let kicks = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kicks.clone()).unwrap();
        scheduler.make_runnable(first.thread().key()).unwrap();
        scheduler.make_runnable(second.thread().key()).unwrap();
        let mut progress = BTreeMap::new();

        for _ in 0..8 {
            let running = scheduler.take(&executor).unwrap();
            *progress.entry(running.thread_key()).or_insert(0_u32) += 1;
            assert!(scheduler.need_resched());
            if progress.values().sum::<u32>() == 1 {
                assert_eq!(scheduler.request_preemption(), 1);
                assert_eq!(kicks.tokens.lock().as_slice(), &[running.binding.token()]);
            }
            scheduler.settle_runnable(running).unwrap();
        }
        assert!(progress[&first.thread().key()] > 0);
        assert!(progress[&second.thread().key()] > 0);
        assert!(scheduler.snapshot_count() >= 8);

        let running = scheduler.take(&executor).unwrap();
        let running_key = running.thread_key();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        assert_eq!(
            scheduler.wake(running_key).unwrap(),
            WakeDisposition::Queued
        );
        assert!(scheduler.queued_len() >= 2);
    }

    #[test]
    fn unregister_clears_live_binding_and_preemption_authority() {
        let (kernel, context) = bootstrap(12_121);
        publish(&context, 29);
        let scheduler = Scheduler::new(kernel);
        for _ in 0..256 {
            let executor = scheduler
                .register_executor(Arc::new(RecordingKick::default()))
                .unwrap();
            let generation = context.thread().execution_state().generation().unwrap();
            scheduler
                .executors
                .bind(
                    &executor,
                    ExecutorBinding {
                        executor: executor.id(),
                        executor_epoch: 1,
                        thread: context.thread().key(),
                        generation,
                    },
                )
                .unwrap();
            assert!(scheduler.executors.has_running());
            scheduler.unregister_executor(&executor).unwrap();
            assert!(!scheduler.executors.has_running());
            assert_eq!(scheduler.request_preemption(), 0);
            assert_eq!(scheduler.registered_executor_count(), 0);
        }
    }

    #[test]
    fn queue_key_static_shape_contains_only_thread_key_and_execution_generation() {
        fn exact_shape(key: QueueKey) -> (crate::kernel::ThreadKey, u64) {
            let QueueKey { thread, generation } = key;
            (thread, generation.raw())
        }

        let (kernel, context) = bootstrap(12_114);
        publish(&context, 18);
        let generation = context.thread().execution_state().generation().unwrap();
        assert_eq!(
            exact_shape(QueueKey {
                thread: context.thread().key(),
                generation,
            }),
            (context.thread().key(), 1)
        );
        drop(kernel);
    }

    #[test]
    fn stale_or_mismatched_row_records_discard_receipt() {
        let (kernel, context) = bootstrap(12_115);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        publish(&context, 19);
        let generation = context.thread().execution_state().generation().unwrap();
        let key = QueueKey {
            thread: context.thread().key(),
            generation,
        };

        type DiscardRecord = (
            crate::kernel::objects::ExecutorId,
            crate::kernel::objects::ThreadKey,
            crate::kernel::objects::ExecutionGeneration,
            String,
            String,
        );
        struct TestDiscardRecorder(parking_lot::Mutex<Vec<DiscardRecord>>);
        impl super::DiscardRecorder for TestDiscardRecorder {
            fn record_discard(
                &self,
                executor: crate::kernel::objects::ExecutorId,
                thread: crate::kernel::objects::ThreadKey,
                row_generation: crate::kernel::objects::ExecutionGeneration,
                observed_state: String,
                reason: String,
            ) {
                self.0
                    .lock()
                    .push((executor, thread, row_generation, observed_state, reason));
            }
        }

        let recorder = Arc::new(TestDiscardRecorder(parking_lot::Mutex::new(Vec::new())));
        scheduler
            .install_discard_recorder(Arc::clone(&recorder) as Arc<dyn super::DiscardRecorder>);

        // Enqueue row
        scheduler
            .enqueue_exact(Arc::clone(context.thread()), key, false)
            .unwrap();
        // Transition thread to blocked (so generation/state in row becomes stale)
        let lease = context
            .thread()
            .claim_runnable(crate::kernel::objects::ExecutorId::from_scheduler(1))
            .unwrap();
        context
            .thread()
            .scheduler_park_from_executor(lease, BlockedReason::HostWait)
            .unwrap();

        // Register executor
        let kick = Arc::new(RecordingKick::default());
        let executor = scheduler.register_executor(kick).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let sched_clone = Arc::new(scheduler);
        let exec_clone = executor.clone();
        let s = Arc::clone(&sched_clone);
        let thread = std::thread::spawn(move || {
            let res = s.take(&exec_clone);
            tx.send(res.is_ok()).unwrap();
        });

        // Wait briefly for take to process stale row and block waiting on queue
        std::thread::sleep(std::time::Duration::from_millis(50));
        let discards = recorder.0.lock().clone();
        assert_eq!(discards.len(), 1);
        assert_eq!(discards[0].1, context.thread().key());
        assert_eq!(discards[0].2, generation);
        assert_eq!(discards[0].4, "stale_row_generation_or_state_mismatch");

        // Now wake thread so take can finish
        sched_clone.wake(context.thread().key()).unwrap();
        assert!(rx.recv().unwrap());
        thread.join().unwrap();
    }
    // ---- Guest CPUs (design phase 2) --------------------------------------
    //
    // These exercise the `P` layer directly rather than through the pool, so a
    // CPU count is fixed by the policy instead of inherited from the host.

    fn scheduler_with_cpus(kernel: Arc<Kernel>, cpus: usize) -> Arc<Scheduler> {
        Arc::new(Scheduler::new_with_policy(
            kernel,
            Arc::new(GuestCpuPolicy::new(cpus)),
        ))
    }

    /// One bound executor per guest CPU, so every CPU is online and placement
    /// is free to use all of them.
    fn bind_one_executor_per_cpu(
        scheduler: &Scheduler,
        cpus: usize,
    ) -> Vec<super::ExecutorRegistration> {
        (0..cpus)
            .map(|index| {
                let registration = scheduler
                    .register_executor(Arc::new(RecordingKick::default()))
                    .expect("register executor");
                assert_eq!(
                    registration.bound_cpu(),
                    Some(GuestCpuId::new(index as u32)),
                    "executors bind to guest CPUs round-robin",
                );
                registration
            })
            .collect()
    }

    fn occupied_cpus(scheduler: &Scheduler) -> Vec<GuestCpuId> {
        scheduler
            .guest_cpus()
            .iter()
            .filter(|cpu| cpu.queue_len() > 0)
            .map(|cpu| cpu.id())
            .collect()
    }

    #[test]
    fn a_wake_lands_on_exactly_one_guest_cpu() {
        let (kernel, root) = bootstrap(12_401);
        let sibling = sibling(&kernel, &root, 22_401);
        publish(&root, 41);
        publish(&sibling, 42);
        let scheduler = scheduler_with_cpus(kernel, 4);
        let _executors = bind_one_executor_per_cpu(&scheduler, 4);

        scheduler.make_runnable(root.thread().key()).unwrap();
        assert_eq!(occupied_cpus(&scheduler).len(), 1);
        assert_eq!(scheduler.queued_len(), 1);

        // A second runnable task goes to a DIFFERENT idle CPU: placement is
        // least-loaded once the first CPU is no longer empty.
        scheduler.make_runnable(sibling.thread().key()).unwrap();
        let occupied = occupied_cpus(&scheduler);
        assert_eq!(occupied.len(), 2, "two wakes, two distinct guest CPUs");
        assert_eq!(scheduler.queued_len(), 2);
        for cpu in scheduler.guest_cpus() {
            assert!(cpu.queue_len() <= 1);
        }
    }

    #[test]
    fn a_woken_task_returns_to_the_cpu_it_last_ran_on() {
        let (kernel, root) = bootstrap(12_402);
        publish(&root, 43);
        let scheduler = scheduler_with_cpus(kernel, 4);
        let executors = bind_one_executor_per_cpu(&scheduler, 4);
        let key = root.thread().key();

        scheduler.make_runnable(key).unwrap();
        let placed = occupied_cpus(&scheduler)[0];
        let running = scheduler.take(&executors[placed.as_usize()]).unwrap();
        assert_eq!(root.thread().last_cpu(), Some(placed));
        assert_eq!(
            scheduler.guest_cpus()[placed.as_usize()].current_task(),
            Some(key),
        );
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        assert_eq!(scheduler.queued_len(), 0);
        assert_eq!(
            scheduler.guest_cpus()[placed.as_usize()].current_task(),
            None,
        );

        scheduler.wake(key).unwrap();
        assert_eq!(
            occupied_cpus(&scheduler),
            vec![placed],
            "an idle last_cpu keeps the task's warm ASID and TLB",
        );
    }

    #[test]
    fn an_executor_serves_its_own_cpu_before_it_steals() {
        let (kernel, root) = bootstrap(12_403);
        let other = sibling(&kernel, &root, 22_403);
        publish(&root, 44);
        publish(&other, 45);
        let scheduler = scheduler_with_cpus(kernel, 2);
        let executors = bind_one_executor_per_cpu(&scheduler, 2);
        root.thread()
            .set_affinity(CpuAffinity::single(GuestCpuId::new(0)));
        other
            .thread()
            .set_affinity(CpuAffinity::single(GuestCpuId::new(1)));

        scheduler.make_runnable(root.thread().key()).unwrap();
        scheduler.make_runnable(other.thread().key()).unwrap();
        assert_eq!(scheduler.guest_cpus()[0].queue_len(), 1);
        assert_eq!(scheduler.guest_cpus()[1].queue_len(), 1);

        // CPU 1's executor has local work, so it never reaches for CPU 0's.
        let running = scheduler.take(&executors[1]).unwrap();
        assert_eq!(running.thread_key(), other.thread().key());
        assert_eq!(scheduler.guest_cpus()[0].queue_len(), 1);
        scheduler.settle_exited(running).unwrap();

        // Now CPU 1 is empty and CPU 0 still holds a row, but that row is
        // pinned to CPU 0: an affinity mask of one CPU is not stealable.
        assert_eq!(scheduler.steal_probe(GuestCpuId::new(1)), None);
        assert_eq!(scheduler.guest_cpus()[0].queue_len(), 1);

        // Widen the mask and the same row becomes stealable, because CPU 0's
        // executor is busy with it and CPU 1 has nothing of its own.
        root.thread().set_affinity(CpuAffinity::all(2));
        assert_eq!(
            scheduler.steal_probe(GuestCpuId::new(1)),
            Some(root.thread().key()),
        );
    }

    #[test]
    fn an_affinity_mask_of_one_cpu_pins_every_placement() {
        let (kernel, root) = bootstrap(12_404);
        publish(&root, 46);
        let scheduler = scheduler_with_cpus(kernel, 4);
        let executors = bind_one_executor_per_cpu(&scheduler, 4);
        let pinned = GuestCpuId::new(3);
        root.thread().set_affinity(CpuAffinity::single(pinned));
        let key = root.thread().key();

        scheduler.make_runnable(key).unwrap();
        assert_eq!(occupied_cpus(&scheduler), vec![pinned]);

        // A yield requeues on the same P, still the pinned one.
        let running = scheduler.take(&executors[pinned.as_usize()]).unwrap();
        assert_eq!(root.thread().last_cpu(), Some(pinned));
        scheduler.settle_runnable(running).unwrap();
        assert_eq!(occupied_cpus(&scheduler), vec![pinned]);

        // And a block/wake round trip does not launder it onto another CPU.
        let running = scheduler.take(&executors[pinned.as_usize()]).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();
        scheduler.wake(key).unwrap();
        assert_eq!(occupied_cpus(&scheduler), vec![pinned]);
    }

    #[test]
    fn placement_never_targets_a_cpu_with_no_executor() {
        let (kernel, root) = bootstrap(12_405);
        let other = sibling(&kernel, &root, 22_405);
        publish(&root, 47);
        publish(&other, 48);
        let scheduler = scheduler_with_cpus(kernel, 4);
        // Only two of the four guest CPUs have an `M`.
        let _executors = bind_one_executor_per_cpu(&scheduler, 2);

        scheduler.make_runnable(root.thread().key()).unwrap();
        scheduler.make_runnable(other.thread().key()).unwrap();
        for cpu in scheduler.guest_cpus().iter().skip(2) {
            assert_eq!(
                cpu.queue_len(),
                0,
                "an offline CPU would strand the task until something stole it",
            );
        }
        assert_eq!(scheduler.queued_len(), 2);
    }

    #[test]
    fn a_cross_cpu_wake_in_the_pre_park_window_is_not_lost() {
        let (kernel, root) = bootstrap(12_406);
        publish(&root, 49);
        let scheduler = scheduler_with_cpus(kernel, 2);
        let executors = bind_one_executor_per_cpu(&scheduler, 2);
        let key = root.thread().key();

        // The row will be published on CPU 0 while CPU 1's executor is inside
        // its pre-park window — after its own queue and its steal scan came up
        // empty. Without the idle flag plus the wake-ticket re-check, the
        // notification lands before the park and is lost forever.
        let arrived = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        scheduler.install_pre_park_gate(Arc::clone(&arrived), Arc::clone(&resume));

        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let worker_scheduler = Arc::clone(&scheduler);
        let worker_executor = executors[1].clone();
        let worker = thread::spawn(move || {
            let outcome = worker_scheduler
                .take(&worker_executor)
                .map(|running| (running.thread_key(), running));
            let key = outcome.as_ref().map(|(key, _)| *key).ok();
            tx.send(key).ok();
            if let Ok((_, running)) = outcome {
                worker_scheduler.settle_exited(running).unwrap();
            }
        });

        arrived.wait();
        root.thread()
            .set_affinity(CpuAffinity::single(GuestCpuId::new(0)));
        scheduler.make_runnable(key).unwrap();
        assert_eq!(scheduler.guest_cpus()[0].queue_len(), 1);
        // Widen the mask so CPU 1 is allowed to steal what CPU 0 was handed.
        root.thread().set_affinity(CpuAffinity::all(2));
        resume.wait();

        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Some(claimed)) => assert_eq!(claimed, key),
            Ok(None) => panic!("the parked executor reported no claim"),
            Err(_) => {
                // Release the parked executor so the suite does not wedge, then
                // fail: a lost wakeup is the defect this test exists for.
                scheduler.close();
                worker.join().ok();
                panic!("cross-CPU wake was lost: the executor parked and never woke");
            }
        }
        worker.join().unwrap();
    }

    #[test]
    fn close_drains_with_spare_executors_parked() {
        let (kernel, root) = bootstrap(12_407);
        publish(&root, 50);
        let scheduler = scheduler_with_cpus(kernel, 2);
        let closed = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(5));
        let mut workers = Vec::new();
        for index in 0..4 {
            // Two bound `M`s and two spares, exactly the shape the pool starts.
            let is_spare = index >= 2;
            let scheduler = Arc::clone(&scheduler);
            let closed = Arc::clone(&closed);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                let executor = scheduler
                    .register_executor_bound(Arc::new(RecordingKick::default()), None, is_spare)
                    .unwrap();
                assert_eq!(executor.is_spare(), is_spare);
                assert_eq!(executor.bound_cpu().is_none(), is_spare);
                barrier.wait();
                loop {
                    match scheduler.take(&executor) {
                        Ok(running) => scheduler.settle_exited(running).unwrap(),
                        Err(RunQueueError::Closed) => {
                            closed.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        Err(RunQueueError::ControlPoked) => continue,
                        Err(error) => panic!("unexpected take error: {error:?}"),
                    }
                }
            }));
        }
        barrier.wait();
        while scheduler.waiter_count() != 4 {
            thread::yield_now();
        }

        scheduler.close();
        scheduler.wait_closed();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(closed.load(Ordering::SeqCst), 4, "spares observe the close");
    }
    /// The `SchedulerGenerationObserver` a reap races: it removes the target's
    /// registry record and THEN reports the mismatch, which is exactly what
    /// `SubmissionAuthority::rollover_exact` does when its
    /// `with_live_active_scheduler_thread` liveness check finds nothing.
    #[derive(Debug)]
    struct ReapingObserver {
        kernel: Arc<Kernel>,
        task: crate::kernel::ids::TaskId,
        /// Which transition kind the reap races. Real reaps race whichever
        /// transition the target happened to be taking, so every settlement
        /// kind has to survive one, not just `Runnable`.
        on_kind: super::SchedulerGenerationTransition,
        fired: AtomicUsize,
    }

    impl ReapingObserver {
        fn on(
            kernel: &Arc<Kernel>,
            context: &KernelContext,
            on_kind: super::SchedulerGenerationTransition,
        ) -> Arc<Self> {
            Arc::new(Self {
                kernel: Arc::clone(kernel),
                task: context.thread().task_key().id,
                on_kind,
                fired: AtomicUsize::new(0),
            })
        }

        fn install(self: &Arc<Self>, scheduler: &Scheduler) {
            scheduler
                .install_generation_observer(
                    Arc::clone(self) as Arc<dyn super::SchedulerGenerationObserver>
                )
                .unwrap();
        }
    }

    impl super::SchedulerGenerationObserver for ReapingObserver {
        fn transition(
            &self,
            _thread: crate::kernel::objects::ThreadKey,
            _predecessor: crate::kernel::objects::ExecutionGeneration,
            _successor: crate::kernel::objects::ExecutionGeneration,
            kind: super::SchedulerGenerationTransition,
        ) -> Result<(), RunQueueError> {
            if kind != self.on_kind {
                return Ok(());
            }
            self.fired.fetch_add(1, Ordering::SeqCst);
            assert!(self.kernel.reap_task_record_for_test(self.task));
            Err(RunQueueError::AuthorityMismatch)
        }
    }

    /// The observer shape the real `HvpatchTaskBindingDirectory` has: it holds
    /// the target's `SubmissionAuthority` inside its binding record, and when
    /// its rollover fails it RE-INSERTS that record under the PREDECESSOR key
    /// (`crates/carrick-runtime/src/vcpu_loop/executor.rs`,
    /// `SchedulerGenerationObserver::transition`).
    ///
    /// That re-insert is correct for a live target — the next attempt resolves
    /// it — and a leak for a reaped one: no successor is ever published, no
    /// executor ever runs that generation, so no exit or exec path retires the
    /// record. The authority it holds keeps `active_authorities` above zero,
    /// which is one of `drain_ready`'s four terms, so container teardown never
    /// finishes closing.
    #[derive(Debug)]
    struct AuthorityHoldingReapingObserver {
        kernel: Arc<Kernel>,
        task: crate::kernel::ids::TaskId,
        on_kind: super::SchedulerGenerationTransition,
        held: parking_lot::Mutex<
            BTreeMap<
                (
                    crate::kernel::objects::ThreadKey,
                    crate::kernel::objects::ExecutionGeneration,
                ),
                super::SubmissionAuthority,
            >,
        >,
        fired: AtomicUsize,
        retired: parking_lot::Mutex<
            Vec<(
                crate::kernel::objects::ThreadKey,
                crate::kernel::objects::ExecutionGeneration,
            )>,
        >,
    }

    impl super::SchedulerGenerationObserver for AuthorityHoldingReapingObserver {
        fn transition(
            &self,
            thread: crate::kernel::objects::ThreadKey,
            predecessor: crate::kernel::objects::ExecutionGeneration,
            successor: crate::kernel::objects::ExecutionGeneration,
            kind: super::SchedulerGenerationTransition,
        ) -> Result<(), RunQueueError> {
            let mut held = self.held.lock();
            let Some(record) = held.remove(&(thread, predecessor)) else {
                return Ok(());
            };
            if kind != self.on_kind {
                held.insert((thread, successor), record);
                return Ok(());
            }
            self.fired.fetch_add(1, Ordering::SeqCst);
            assert!(self.kernel.reap_task_record_for_test(self.task));
            // The rollover the real directory attempts fails against a reaped
            // target, and it puts the record back where it came from.
            held.insert((thread, predecessor), record);
            Err(RunQueueError::AuthorityMismatch)
        }

        fn retire_reaped(
            &self,
            thread: crate::kernel::objects::ThreadKey,
            predecessor: crate::kernel::objects::ExecutionGeneration,
        ) {
            self.retired.lock().push((thread, predecessor));
            self.held.lock().remove(&(thread, predecessor));
        }
    }

    /// An observer whose transition drops the task's registry record and
    /// records NOTHING else: the thread is in no live task, no zombie and no
    /// retirement, so the kernel graph cannot prove that generation terminal.
    #[derive(Debug)]
    struct RecordDroppingObserver {
        kernel: Arc<Kernel>,
        task: crate::kernel::ids::TaskId,
        on_kind: super::SchedulerGenerationTransition,
        held: parking_lot::Mutex<
            BTreeMap<
                (
                    crate::kernel::objects::ThreadKey,
                    crate::kernel::objects::ExecutionGeneration,
                ),
                super::SubmissionAuthority,
            >,
        >,
        retired: parking_lot::Mutex<
            Vec<(
                crate::kernel::objects::ThreadKey,
                crate::kernel::objects::ExecutionGeneration,
            )>,
        >,
    }

    impl super::SchedulerGenerationObserver for RecordDroppingObserver {
        fn transition(
            &self,
            thread: crate::kernel::objects::ThreadKey,
            predecessor: crate::kernel::objects::ExecutionGeneration,
            successor: crate::kernel::objects::ExecutionGeneration,
            kind: super::SchedulerGenerationTransition,
        ) -> Result<(), RunQueueError> {
            let mut held = self.held.lock();
            let Some(record) = held.remove(&(thread, predecessor)) else {
                return Ok(());
            };
            if kind != self.on_kind {
                held.insert((thread, successor), record);
                return Ok(());
            }
            assert!(self.kernel.drop_task_record_for_test(self.task));
            held.insert((thread, predecessor), record);
            Err(RunQueueError::AuthorityMismatch)
        }

        fn retire_reaped(
            &self,
            thread: crate::kernel::objects::ThreadKey,
            predecessor: crate::kernel::objects::ExecutionGeneration,
        ) {
            self.retired.lock().push((thread, predecessor));
            self.held.lock().remove(&(thread, predecessor));
        }
    }

    /// A thread that is merely ABSENT from the exact scheduler registry is not
    /// a reaped thread: the kernel graph has no zombie and no retirement for
    /// it, so nothing proves that generation will never run again. Round 4
    /// called that shape a reap, retired a reachable authority and published
    /// nothing — RED here as `retired = [(thread, generation)]` and no abort
    /// request. It is now a lost exact transition, which ends the carrier
    /// through lane B's sink with a post-mortem that names the thread, both
    /// generations and both kernel views.
    #[test]
    fn an_absent_but_non_terminal_target_is_a_lost_transition_not_a_reap() {
        let (kernel, root) = bootstrap(12_413);
        publish(&root, 83);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let key = root.thread().key();
        let generation = root
            .thread()
            .execution_state()
            .generation()
            .expect("published root generation");
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()) as Arc<dyn ExecutorKick>)
            .unwrap();
        let authority = scheduler.admit_root(key, generation).unwrap();
        scheduler.make_runnable(key).unwrap();
        authority
            .publish(&scheduler, Arc::clone(root.thread()))
            .expect("activation publishes the admitted row");
        let running = scheduler.take(&executor).unwrap();
        let claimed_generation = running.generation();

        let observer = Arc::new(RecordDroppingObserver {
            kernel: Arc::clone(&kernel),
            task: root.thread().task_key().id,
            on_kind: super::SchedulerGenerationTransition::Runnable,
            held: parking_lot::Mutex::new(BTreeMap::from([((key, claimed_generation), authority)])),
            retired: parking_lot::Mutex::new(Vec::new()),
        });
        scheduler
            .install_generation_observer(
                Arc::clone(&observer) as Arc<dyn super::SchedulerGenerationObserver>
            )
            .unwrap();

        // The settlement still FINISHES: an abandoned transaction leaves the
        // executor bound with the claim unfinished, which is a second failure
        // on top of the first.
        let disposition = scheduler
            .settle_runnable_successor(running)
            .expect("the settlement itself always finishes");
        assert_eq!(
            disposition,
            super::SettlementDisposition::LostExactTransition
        );

        assert!(
            observer.retired.lock().is_empty(),
            "a reachable generation's authority is not the scheduler's to retire"
        );
        let reason = crate::kernel::debug::take_abort_request()
            .expect("a lost exact transition ends the carrier through the post-mortem sink");
        match reason {
            crate::kernel::debug::AbortReason::LostExactTransition {
                tid,
                serial,
                predecessor,
                successor,
                ..
            } => {
                assert_eq!(tid, key.tid.raw());
                assert_eq!(serial, key.serial.raw());
                assert_eq!(predecessor, claimed_generation.raw());
                assert_eq!(successor, claimed_generation.raw() + 1);
            }
            other => panic!("wrong abort reason: {other:?}"),
        }
    }

    /// A wake whose target is reaped in flight must leave NOTHING holding the
    /// queue open. `reap_task_record_for_test` retires the task's threads the
    /// way a real reap does, so the kernel graph can still prove the target
    /// terminal after its live record is gone — which is what separates this
    /// from the lost-transition case above.
    ///
    /// Round 3 stopped the reaped rejection from killing the executor and from
    /// publishing an unreachable successor, which is what the two settlement
    /// tests above assert. It did not close the other half: the observer still
    /// holds the predecessor's `SubmissionAuthority`, and `drain_ready()`
    /// counts it. Red against round 3 with `active authorities left = 1` and a
    /// queue that never reports drained.
    #[test]
    fn a_wake_whose_target_was_reaped_retires_the_authority_it_stranded() {
        let (kernel, root) = bootstrap(12_411);
        publish(&root, 81);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let key = root.thread().key();
        let generation = root
            .thread()
            .execution_state()
            .generation()
            .expect("published root generation");
        let kick = Arc::new(RecordingKick::default());
        let executor = scheduler
            .register_executor(Arc::clone(&kick) as Arc<dyn ExecutorKick>)
            .unwrap();

        let authority = scheduler.admit_root(key, generation).unwrap();
        assert_eq!(
            scheduler.queue.active_authority_count(),
            1,
            "the root authority is live before the reap"
        );

        scheduler.make_runnable(key).unwrap();
        // The wake above owns the edge but its row is held: an admitted
        // submission has no resolvable binding until it publishes. Publish it,
        // exactly as activation does, so there is a claimable row to take.
        authority
            .publish(&scheduler, Arc::clone(root.thread()))
            .expect("activation publishes the admitted row");
        let running = scheduler.take(&executor).unwrap();
        let claimed_generation = running.generation();

        let observer = Arc::new(AuthorityHoldingReapingObserver {
            kernel: Arc::clone(&kernel),
            task: root.thread().task_key().id,
            on_kind: super::SchedulerGenerationTransition::Runnable,
            held: parking_lot::Mutex::new(BTreeMap::from([((key, claimed_generation), authority)])),
            fired: AtomicUsize::new(0),
            retired: parking_lot::Mutex::new(Vec::new()),
        });
        scheduler
            .install_generation_observer(
                Arc::clone(&observer) as Arc<dyn super::SchedulerGenerationObserver>
            )
            .unwrap();

        let successor = scheduler
            .settle_runnable_successor(running)
            .expect("a yield whose target was reaped settles; it never fails the executor");
        assert_eq!(observer.fired.load(Ordering::SeqCst), 1);
        assert_eq!(successor, super::SettlementDisposition::TargetReaped);

        assert_eq!(
            scheduler.queue.active_authority_count(),
            0,
            "a reaped target strands no submission authority"
        );
        assert_eq!(
            observer.retired.lock().as_slice(),
            &[(key, claimed_generation)],
            "the scheduler names the exact predecessor record it stranded"
        );
        assert!(
            scheduler.queue.drain_ready_for_test(),
            "the queue can finish closing after a reaped wake"
        );
    }

    /// Both directions of the rejection classification, which is the whole
    /// width of the swallow. Only the reaped direction may become a no-op; a
    /// rejection naming a thread that is STILL LIVE is a lost exact transition
    /// and is fatal, and round 2's `if let Err(_)` could not tell them apart.
    #[test]
    fn a_transition_rejection_is_fatal_unless_the_target_left_the_graph() {
        assert_eq!(
            super::classify_transition_rejection(super::SchedulerTargetLiveness::Terminal),
            super::TransitionRejection::TargetReaped,
        );
        assert_eq!(
            super::classify_transition_rejection(super::SchedulerTargetLiveness::Reachable),
            super::TransitionRejection::LostExactTransition,
        );
    }

    /// A yield/preempt settlement whose target is reaped in flight must still
    /// unbind the executor and finish the claim.
    ///
    /// Round 2 left `observe_generation_transition`'s rejection propagating
    /// out of every `settle_*`, and each of them returns BEFORE
    /// `executors.unbind` and `running.finish_claim()`. The executor loop
    /// stringifies that settlement error directly, which is the captured
    /// `executor worker died index=5 error=exact thread generation is not
    /// live` in `target/conformance/raw/conf-60360-c00.err`; the abandoned
    /// binding then failed the terminal ASID retirement and dropped a
    /// published HVPatch MM authority — `carrick: FATAL: ... published HVPatch
    /// inventory dropped before exact retirement`.
    #[test]
    fn a_yield_whose_target_was_reaped_settles_instead_of_killing_the_executor() {
        let (kernel, root) = bootstrap(12_409);
        publish(&root, 61);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let key = root.thread().key();
        let kick = Arc::new(RecordingKick::default());
        let executor = scheduler
            .register_executor(Arc::clone(&kick) as Arc<dyn ExecutorKick>)
            .unwrap();

        scheduler.make_runnable(key).unwrap();
        let running = scheduler.take(&executor).unwrap();

        let observer = ReapingObserver::on(
            &kernel,
            &root,
            super::SchedulerGenerationTransition::Runnable,
        );
        observer.install(&scheduler);

        let successor = scheduler
            .settle_runnable_successor(running)
            .expect("a yield whose target was reaped settles; it never fails the executor");
        assert_eq!(observer.fired.load(Ordering::SeqCst), 1);
        assert_eq!(
            successor,
            super::SettlementDisposition::TargetReaped,
            "a reaped target has no reachable successor to report"
        );
        assert!(
            kick.current_binding().is_none(),
            "the executor is unbound, so its next claim is not refused as busy"
        );
        assert_eq!(
            scheduler.queued_len(),
            0,
            "the unreachable successor is never published as a run-queue row"
        );
    }

    /// The same abandonment on the blocking path: a task that parks while its
    /// task record is reaped must still release the executor.
    #[test]
    fn a_block_whose_target_was_reaped_settles_instead_of_killing_the_executor() {
        let (kernel, root) = bootstrap(12_410);
        publish(&root, 71);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let key = root.thread().key();
        let kick = Arc::new(RecordingKick::default());
        let executor = scheduler
            .register_executor(Arc::clone(&kick) as Arc<dyn ExecutorKick>)
            .unwrap();

        scheduler.make_runnable(key).unwrap();
        let running = scheduler.take(&executor).unwrap();

        let observer = ReapingObserver::on(
            &kernel,
            &root,
            super::SchedulerGenerationTransition::Blocked,
        );
        observer.install(&scheduler);

        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .expect("a park whose target was reaped settles; it never fails the executor");
        assert_eq!(observer.fired.load(Ordering::SeqCst), 1);
        assert!(
            kick.current_binding().is_none(),
            "the executor is unbound, so its next claim is not refused as busy"
        );
        assert_eq!(scheduler.queued_len(), 0);
    }

    #[test]
    fn a_wake_whose_target_was_reaped_is_rejected_not_fatal() {
        let (kernel, root) = bootstrap(12_408);
        publish(&root, 51);
        let scheduler = Scheduler::new(Arc::clone(&kernel));
        let key = root.thread().key();
        let executor = scheduler
            .register_executor(Arc::new(RecordingKick::default()))
            .unwrap();

        // Put the thread in the state a producer wakes from.
        scheduler.make_runnable(key).unwrap();
        let running = scheduler.take(&executor).unwrap();
        scheduler
            .settle_blocked(running, BlockedReason::HostWait)
            .unwrap();

        let observer = ReapingObserver::on(
            &kernel,
            &root,
            super::SchedulerGenerationTransition::Runnable,
        );
        observer.install(&scheduler);

        // Linux answers a wake of a task that has already been reaped with a
        // no-op — not an abort, and not an error for the waker to carry.
        // This aborted the whole carrier before the rejection landed
        // ("scheduler generation observer lost exact transition ...
        // kernel_view=thread absent from registry"), and then FAILED the
        // waker, which for an executor means "executor worker died
        // error=exact thread generation is not live" and a cascade into a
        // carrier FATAL (`conf-35614-c00`, go_types under load).
        let disposition = scheduler
            .wake(key)
            .expect("a wake whose target was reaped is a no-op, never an error");
        assert_eq!(disposition, WakeDisposition::Pending);
        assert_eq!(observer.fired.load(Ordering::SeqCst), 1);
        assert_eq!(scheduler.queued_len(), 0, "nothing was published");
    }

    /// `scheduler_summary` must return. It is the only reader the kernel-debug
    /// endpoint and the post-mortem sink have, and it took the run-queue state
    /// mutex and then called `waiter_count`, which takes the SAME mutex — a
    /// non-reentrant `parking_lot::Mutex`, so every call self-deadlocked the
    /// calling thread while holding the lock the whole carrier drains through.
    /// Measured on `test_compile` (target/perf/wedges/cmp-sched-1/bt-all.txt):
    /// thread #1 blocked at `waiter_count` scheduler.rs:2272 holding
    /// `0x13a752ec8` acquired at `scheduler_summary` scheduler.rs:3579.
    #[test]
    fn scheduler_summary_returns_and_does_not_self_deadlock() {
        let (kernel, context) = bootstrap(12_600);
        publish(&context, 1);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let probe = Arc::clone(&scheduler);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let summary = probe.scheduler_summary();
            let _ = tx.send(summary);
        });
        let summary = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("scheduler_summary must return; it deadlocked on its own state mutex");
        worker.join().expect("summary probe thread");
        assert_eq!(summary.lifecycle, "open");
        assert_eq!(
            summary.waiters,
            super::WaiterCensus::Exact(0),
            "nothing else held a run-queue lock, so the census is exact"
        );
    }

    /// The liveness/post-mortem sink has to be able to speak in exactly the
    /// wedged state it exists to describe, so its scheduler reader must never
    /// block on the run-queue state mutex: it reports `run_queue_locked`
    /// instead of joining the queue behind whoever holds it.
    #[test]
    fn scheduler_summary_reports_run_queue_locked_instead_of_blocking() {
        let (kernel, context) = bootstrap(12_601);
        publish(&context, 1);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let held = scheduler.queue.inner.state.lock();
        let probe = Arc::clone(&scheduler);
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = tx.send(probe.scheduler_summary());
        });
        let summary = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the sink must judge while another thread holds the run-queue state mutex");
        assert_eq!(
            summary.waiters,
            super::WaiterCensus::RunQueueLocked,
            "the contended read is a named finding, not a silent zero"
        );
        assert_eq!(
            summary.lifecycle, "open",
            "lifecycle is published atomically and stays readable"
        );
        drop(held);
        worker.join().expect("summary probe thread");
    }
}
