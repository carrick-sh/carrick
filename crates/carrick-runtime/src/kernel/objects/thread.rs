//! Logical guest thread execution, vCPU state, and runner coordination.
//!
//! Encapsulates thread execution states, scheduler actions, execution leases,
//! crash safe-point participation, CPU accounting, and backend runner gates.

use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use parking_lot::{Condvar, Mutex, RwLock};

use carrick_abi::LinuxGuestAbi;
use carrick_abi::keyring::KeySerial;
use carrick_fatal::carrick_fatal;
use carrick_hal::threaded::GuestCpuState;
use carrick_hal::{CpuAffinity, ThreadId};

use crate::kernel::crash_capture::{CrashCaptureGeneration, CrashRegisterVote};
use crate::kernel::ids::{LinuxSignal, LinuxTid, MmId, ThreadSerial};
use crate::kernel::objects::signal::ThreadSignalState;
use crate::kernel::objects::{
    ObjectGraphError, ObjectRevision, SYSTEM_CHARGE_WINDOW, SystemChargeWindow, Task, TaskKey,
    TaskRef, ThreadResources, close_system_charge_window,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadKey {
    pub tid: LinuxTid,
    pub serial: ThreadSerial,
}

impl std::fmt::Display for ThreadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "thread#{}:{}", self.tid.raw(), self.serial.raw())
    }
}

pub type ThreadRef = Arc<Thread>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerDirective {
    Continue,
    Resumed,
    Terminate,
}

#[derive(Debug)]
struct RunnerGateState {
    owner: ThreadKey,
    bound: bool,
    stop_requested: bool,
    parked: bool,
    terminate_requested: bool,
}

#[derive(Debug)]
pub(in crate::kernel) struct RunnerGate {
    state: Mutex<RunnerGateState>,
    changed: Condvar,
}

impl RunnerGate {
    fn new(owner: ThreadKey) -> Self {
        Self {
            state: Mutex::new(RunnerGateState {
                owner,
                bound: false,
                stop_requested: false,
                parked: false,
                terminate_requested: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn bind(
        self: &Arc<Self>,
        key: ThreadKey,
        thread: ThreadRef,
    ) -> Result<ThreadRunner, ObjectGraphError> {
        let mut state = self.state.lock();
        if state.owner != key {
            return Err(ObjectGraphError::RunnerOwnershipChanged(key));
        }
        if state.bound {
            return Err(ObjectGraphError::RunnerAlreadyBound(key));
        }
        if state.stop_requested || state.terminate_requested {
            return Err(ObjectGraphError::RunnerDraining(key));
        }
        state.bound = true;
        Ok(ThreadRunner {
            key,
            gate: Arc::clone(self),
            _thread: thread,
        })
    }

    fn transfer_owner(&self, from: ThreadKey, to: ThreadKey) {
        let mut state = self.state.lock();
        debug_assert_eq!(state.owner, from);
        state.owner = to;
    }

    fn request_stop(&self) {
        let mut state = self.state.lock();
        state.stop_requested = true;
        self.changed.notify_all();
    }

    fn wait_until_parked_or_detached(&self) {
        let mut state = self.state.lock();
        while state.bound && !state.parked {
            self.changed.wait(&mut state);
        }
    }

    fn resume_and_wait(&self) {
        let mut state = self.state.lock();
        state.stop_requested = false;
        self.changed.notify_all();
        while state.bound && state.parked {
            self.changed.wait(&mut state);
        }
    }

    fn terminate_and_wait(&self) {
        let mut state = self.state.lock();
        state.terminate_requested = true;
        state.stop_requested = false;
        self.changed.notify_all();
        while state.bound {
            self.changed.wait(&mut state);
        }
    }
}

#[derive(Debug)]
pub struct ThreadRunner {
    key: ThreadKey,
    gate: Arc<RunnerGate>,
    _thread: ThreadRef,
}

impl ThreadRunner {
    pub const fn key(&self) -> ThreadKey {
        self.key
    }

    pub fn adopt_thread(&mut self, replacement: &ThreadRef) -> Result<(), ObjectGraphError> {
        if !Arc::ptr_eq(&self.gate, &replacement.runner_gate) {
            return Err(ObjectGraphError::RunnerGateMismatch(replacement.key));
        }
        if self.gate.state.lock().owner != replacement.key {
            return Err(ObjectGraphError::RunnerOwnershipChanged(replacement.key));
        }
        self.key = replacement.key;
        self._thread = Arc::clone(replacement);
        Ok(())
    }

    /// Backend runners call this at their operation boundary. A stop request
    /// parks inside this method; only the runner can publish the parked state.
    pub fn checkpoint(&self) -> RunnerDirective {
        let mut state = self.gate.state.lock();
        let resumed = state.stop_requested;
        if resumed {
            state.parked = true;
            self.gate.changed.notify_all();
            while state.stop_requested && !state.terminate_requested {
                self.gate.changed.wait(&mut state);
            }
            state.parked = false;
            self.gate.changed.notify_all();
        }
        if state.terminate_requested {
            RunnerDirective::Terminate
        } else if resumed {
            RunnerDirective::Resumed
        } else {
            RunnerDirective::Continue
        }
    }
}

impl Drop for ThreadRunner {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        state.bound = false;
        state.parked = false;
        self.gate.changed.notify_all();
    }
}

pub(in crate::kernel) struct ExecDrain {
    gates: Vec<Arc<RunnerGate>>,
    resolved: bool,
}

impl ExecDrain {
    pub(in crate::kernel) fn new(gates: Vec<Arc<RunnerGate>>) -> Self {
        for gate in &gates {
            gate.request_stop();
        }
        for gate in &gates {
            gate.wait_until_parked_or_detached();
        }
        Self {
            gates,
            resolved: false,
        }
    }

    pub(in crate::kernel) fn resume_and_wait(mut self) {
        for gate in &self.gates {
            gate.resume_and_wait();
        }
        self.resolved = true;
    }

    pub(in crate::kernel) fn terminate_and_wait(mut self) {
        for gate in &self.gates {
            gate.terminate_and_wait();
        }
        self.resolved = true;
    }
}

impl Drop for ExecDrain {
    fn drop(&mut self) {
        if self.resolved {
            return;
        }
        for gate in &self.gates {
            gate.resume_and_wait();
        }
    }
}

/// Version of one published Kernel-owned task CPU snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionGeneration(u64);

impl ExecutionGeneration {
    pub const INITIAL: Self = Self(1);

    pub(crate) const fn initial_for_prepared_publication() -> Self {
        Self::INITIAL
    }

    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Stable identity of a persistent execution slot.
///
/// Production construction arrives with the executor pool in a later task;
/// Task 1 exposes only an explicitly synthetic constructor for state-machine
/// tests, rather than a general raw-ID escape hatch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutorId(u32);

impl ExecutorId {
    pub(in crate::kernel) const fn from_scheduler(raw: u32) -> Self {
        debug_assert!(raw != 0);
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    pub(crate) const fn raw_for_probe(self) -> u32 {
        self.0
    }

    /// Transitional exact owner for the current welded-thread scheduler. Task 4
    /// replaces this with persistent executor-pool IDs; no raw constructor is
    /// exposed.
    pub fn for_transitional_thread(thread: ThreadId) -> Result<Self, ThreadExecutionError> {
        let raw = u32::try_from(thread.raw())
            .map_err(|_| ThreadExecutionError::InvalidTransitionalExecutor(thread))?;
        if raw == 0 {
            return Err(ThreadExecutionError::InvalidTransitionalExecutor(thread));
        }
        Ok(Self(raw))
    }

    #[cfg(test)]
    pub(crate) fn synthetic_for_tests(raw: u32) -> Self {
        Self(raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedReason {
    ChildState,
    HostWait,
}

/// Scheduler-owned task authority. `MmId` is the existing never-reused Kernel
/// identity; no parallel pointer or numeric MM domain is introduced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigratableTaskState {
    pub cpu: GuestCpuState,
    pub mm: MmId,
    pub asid_generation: u64,
}

impl MigratableTaskState {
    fn validate_identity(&self) -> Result<(), ThreadExecutionError> {
        let (cpu_mm_generation, cpu_asid_generation) = self.cpu.task_identity();
        if cpu_mm_generation != self.mm.raw() || cpu_asid_generation != self.asid_generation {
            return Err(ThreadExecutionError::SnapshotCpuIdentityMismatch {
                expected_mm_generation: self.mm.raw(),
                actual_mm_generation: cpu_mm_generation,
                expected_asid_generation: self.asid_generation,
                actual_asid_generation: cpu_asid_generation,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionFailure {
    UnsettledLeaseDropped {
        executor: ExecutorId,
        executor_epoch: u64,
    },
    SnapshotSaveFailed,
    SnapshotRestoreFailed,
    SnapshotGenerationMismatch,
    /// The thread's address space was retired out from under its load: another
    /// thread in the group called `execve`, or the process exited. Linux
    /// terminates every other thread in the group at that point, so this thread
    /// never runs again -- it is a normal end, not a broken executor.
    AddressSpaceRetired,
}

/// Public observation of a thread's scheduler-owned execution state.
///
/// The architectural snapshot is intentionally absent. It remains private in
/// [`ThreadExecutionRecord`] or moves into the exact non-cloneable lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadExecutionState {
    Uninitialized,
    Runnable {
        generation: ExecutionGeneration,
    },
    Running {
        generation: ExecutionGeneration,
        executor: ExecutorId,
        executor_epoch: u64,
        wake_pending: bool,
    },
    SwitchingOut {
        generation: ExecutionGeneration,
        executor: ExecutorId,
        executor_epoch: u64,
        wake_pending: bool,
    },
    Blocked {
        generation: ExecutionGeneration,
        reason: BlockedReason,
        continuation: Option<crate::vcpu_loop::continuation::ContinuationId>,
    },
    Exited {
        generation: ExecutionGeneration,
    },
    Failed {
        generation: ExecutionGeneration,
        reason: ExecutionFailure,
    },
}

impl ThreadExecutionState {
    /// Stable probe ordinal for `hvpatch-scheduler-wake` `arg2`.
    pub(crate) const fn probe_kind(self) -> crate::probes::HvpatchThreadExecutionStateKind {
        use crate::probes::HvpatchThreadExecutionStateKind as Kind;
        match self {
            Self::Uninitialized => Kind::Uninitialized,
            Self::Runnable { .. } => Kind::Runnable,
            Self::Running { .. } => Kind::Running,
            Self::SwitchingOut { .. } => Kind::SwitchingOut,
            Self::Blocked { .. } => Kind::Blocked,
            Self::Exited { .. } => Kind::Exited,
            Self::Failed { .. } => Kind::Failed,
        }
    }

    pub const fn generation(self) -> Option<ExecutionGeneration> {
        match self {
            Self::Uninitialized => None,
            Self::Runnable { generation }
            | Self::Running { generation, .. }
            | Self::SwitchingOut { generation, .. }
            | Self::Blocked { generation, .. }
            | Self::Exited { generation }
            | Self::Failed { generation, .. } => Some(generation),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ThreadExecutionError {
    #[error("thread {0} cannot identify a transitional executor")]
    InvalidTransitionalExecutor(ThreadId),
    #[error("thread execution generation overflowed")]
    GenerationExhausted,
    #[error("scheduler expected thread {expected:?}, got {actual:?}")]
    SchedulerThreadMismatch {
        expected: ThreadKey,
        actual: ThreadKey,
    },
    #[error("a scheduler wake is pending; settlement must publish through the scheduler")]
    SchedulerSettlementRequired,
    #[error("thread execution transition {operation} is invalid from {state:?}")]
    InvalidTransition {
        operation: &'static str,
        state: ThreadExecutionState,
    },
    #[error("execution lease belongs to {actual:?}, not {expected:?}")]
    LeaseOwnerMismatch {
        expected: ThreadKey,
        actual: ThreadKey,
    },
    #[error(
        "execution lease for generation {generation:?}, executor {executor:?}, epoch \
         {executor_epoch} is stale"
    )]
    StaleLease {
        generation: ExecutionGeneration,
        executor: ExecutorId,
        executor_epoch: u64,
    },
    #[error("snapshot architecture mismatch: expected {expected:?}, got {actual:?}")]
    SnapshotArchitectureMismatch {
        expected: LinuxGuestAbi,
        actual: LinuxGuestAbi,
    },
    #[error("snapshot version mismatch: expected {expected}, got {actual}")]
    SnapshotVersionMismatch { expected: u16, actual: u16 },
    #[error("execution lease for generation {generation:?} carries no CPU snapshot")]
    MissingCpuState { generation: ExecutionGeneration },
    #[error("snapshot MM mismatch: expected {expected:?}, got {actual:?}")]
    SnapshotMmMismatch { expected: MmId, actual: MmId },
    #[error("snapshot ASID generation mismatch: expected {expected}, got {actual}")]
    SnapshotAsidGenerationMismatch { expected: u64, actual: u64 },
    #[error(
        "CPU snapshot identity mismatch: expected MM/ASID {expected_mm_generation}/{expected_asid_generation}, got {actual_mm_generation}/{actual_asid_generation}"
    )]
    SnapshotCpuIdentityMismatch {
        expected_mm_generation: u64,
        actual_mm_generation: u64,
        expected_asid_generation: u64,
        actual_asid_generation: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ThreadSchedulerAction {
    Queue {
        key: ThreadKey,
        predecessor: Option<ExecutionGeneration>,
        generation: ExecutionGeneration,
        closing_authorized: bool,
    },
    Kick {
        executor: ExecutorId,
        executor_epoch: u64,
        key: ThreadKey,
        generation: ExecutionGeneration,
    },
    None,
}

impl ThreadSchedulerAction {
    /// The generation a wake queued or kicked, zero when it produced no
    /// scheduler action (`hvpatch-scheduler-wake` `arg4`).
    const fn probe_generation(&self) -> u64 {
        match self {
            Self::Queue { generation, .. } | Self::Kick { generation, .. } => generation.raw(),
            Self::None => 0,
        }
    }
}

#[derive(Debug)]
struct ThreadExecutionRecord {
    state: ThreadExecutionState,
    task_state: Option<Box<MigratableTaskState>>,
    blocked_continuation: Option<Box<crate::vcpu_loop::continuation::BlockedContinuation>>,
    next_executor_epoch: u64,
    exec_invalidation_pending: bool,
    control_quantum: Option<SchedulerControlQuantum>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerControlQuantum {
    pub(crate) blocked_reason: Option<BlockedReason>,
    requeue_pending: bool,
}

fn cancel_continuation_slot(
    slot: &mut Option<Box<crate::vcpu_loop::continuation::BlockedContinuation>>,
    cause: crate::vcpu_loop::continuation::CancellationCause,
) {
    if let Some(continuation) = slot.take() {
        let _ = continuation.cancel(cause);
    }
}

impl ThreadExecutionRecord {
    const fn uninitialized() -> Self {
        Self {
            state: ThreadExecutionState::Uninitialized,
            task_state: None,
            blocked_continuation: None,
            next_executor_epoch: 1,
            exec_invalidation_pending: false,
            control_quantum: None,
        }
    }
}

/// Exact authority to run one thread generation on one executor binding.
///
/// The lease is deliberately non-cloneable. Dropping it before a successful
/// settle operation fails the still-matching thread generation closed.
pub struct ThreadExecutionLease {
    owner: Weak<Thread>,
    owner_key: ThreadKey,
    generation: ExecutionGeneration,
    executor: ExecutorId,
    executor_epoch: u64,
    task_state: Option<Box<MigratableTaskState>>,
    blocked_continuation: Option<Box<crate::vcpu_loop::continuation::BlockedContinuation>>,
    settled: bool,
}

/// A settlement either consumes the exact lease successfully or returns that
/// same still-live authority with the typed rejection. Callers may retry the
/// returned lease against its true owner; discarding it still invokes the
/// fail-closed unsettled-lease policy.
pub type ThreadExecutionSettlementResult = Result<(), (ThreadExecutionError, ThreadExecutionLease)>;

impl std::fmt::Debug for ThreadExecutionLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ThreadExecutionLease")
            .field("owner_key", &self.owner_key)
            .field("generation", &self.generation)
            .field("executor", &self.executor)
            .field("executor_epoch", &self.executor_epoch)
            .field("settled", &self.settled)
            .finish_non_exhaustive()
    }
}

impl ThreadExecutionLease {
    pub const fn thread_key(&self) -> ThreadKey {
        self.owner_key
    }

    pub const fn generation(&self) -> ExecutionGeneration {
        self.generation
    }

    pub const fn executor(&self) -> ExecutorId {
        self.executor
    }

    pub const fn executor_epoch(&self) -> u64 {
        self.executor_epoch
    }

    /// Exact address-space authority carried by the architectural snapshot.
    ///
    /// Continuations must derive MM and ASID generations from this non-cloneable
    /// lease, not from a caller-supplied context or from the accidental numeric
    /// equality some backends currently use for their initial ASID.
    pub(crate) fn task_state_authority(&self) -> Result<(MmId, u64), ThreadExecutionError> {
        let state = self
            .task_state
            .as_ref()
            .ok_or(ThreadExecutionError::MissingCpuState {
                generation: self.generation,
            })?;
        state.validate_identity()?;
        Ok((state.mm, state.asid_generation))
    }

    /// Return the typed snapshot only when the restoring backend names the
    /// exact architecture and version it implements.
    pub fn task_state_for_restore(
        &self,
        expected_abi: LinuxGuestAbi,
        expected_version: u16,
        expected_mm: MmId,
        expected_asid_generation: u64,
    ) -> Result<&MigratableTaskState, ThreadExecutionError> {
        let Some(state) = self.task_state.as_ref() else {
            return Err(ThreadExecutionError::MissingCpuState {
                generation: self.generation,
            });
        };
        let actual_abi = state.cpu.guest_abi();
        if actual_abi != expected_abi {
            return Err(ThreadExecutionError::SnapshotArchitectureMismatch {
                expected: expected_abi,
                actual: actual_abi,
            });
        }
        let actual_version = state.cpu.version();
        if actual_version != expected_version {
            return Err(ThreadExecutionError::SnapshotVersionMismatch {
                expected: expected_version,
                actual: actual_version,
            });
        }
        if state.mm != expected_mm {
            return Err(ThreadExecutionError::SnapshotMmMismatch {
                expected: expected_mm,
                actual: state.mm,
            });
        }
        if state.asid_generation != expected_asid_generation {
            return Err(ThreadExecutionError::SnapshotAsidGenerationMismatch {
                expected: expected_asid_generation,
                actual: state.asid_generation,
            });
        }
        Ok(state)
    }

    /// Replace the lease's pre-run image with the exact state captured at the
    /// switch-out boundary. Architecture and version may not drift while one
    /// execution generation is running.
    pub fn replace_task_state(
        &mut self,
        replacement: MigratableTaskState,
    ) -> Result<(), ThreadExecutionError> {
        replacement.validate_identity()?;
        let Some(current) = self.task_state.as_ref() else {
            return Err(ThreadExecutionError::MissingCpuState {
                generation: self.generation,
            });
        };
        if current.cpu.guest_abi() != replacement.cpu.guest_abi() {
            return Err(ThreadExecutionError::SnapshotArchitectureMismatch {
                expected: current.cpu.guest_abi(),
                actual: replacement.cpu.guest_abi(),
            });
        }
        if current.cpu.version() != replacement.cpu.version() {
            return Err(ThreadExecutionError::SnapshotVersionMismatch {
                expected: current.cpu.version(),
                actual: replacement.cpu.version(),
            });
        }
        if current.mm != replacement.mm {
            return Err(ThreadExecutionError::SnapshotMmMismatch {
                expected: current.mm,
                actual: replacement.mm,
            });
        }
        if current.asid_generation != replacement.asid_generation {
            return Err(ThreadExecutionError::SnapshotAsidGenerationMismatch {
                expected: current.asid_generation,
                actual: replacement.asid_generation,
            });
        }
        self.task_state = Some(Box::new(replacement));
        Ok(())
    }

    pub fn blocked_continuation(
        &self,
    ) -> Option<&crate::vcpu_loop::continuation::BlockedContinuation> {
        self.blocked_continuation.as_deref()
    }

    pub(crate) fn take_blocked_continuation(
        &mut self,
    ) -> Option<crate::vcpu_loop::continuation::BlockedContinuation> {
        self.blocked_continuation
            .take()
            .map(|continuation| *continuation)
    }
}

#[derive(Debug)]
enum ExecutionSettlement {
    Runnable,
    Blocked(BlockedReason),
    BlockedContinuation(
        BlockedReason,
        Box<crate::vcpu_loop::continuation::BlockedContinuation>,
    ),
    Exited,
}

impl Drop for ThreadExecutionLease {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Some(owner) = self.owner.upgrade() {
            let _ = owner.fail_unsettled_execution_lease(self);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CrashSafePointParticipationId(NonZeroU64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CrashSafePointParticipationError {
    #[error("thread {thread:?} already participates in a crash safe point")]
    AlreadyActive { thread: ThreadKey },
    #[error("thread {thread:?} exhausted crash safe-point participation identities")]
    IdentityExhausted { thread: ThreadKey },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashSafePointRelease {
    Released,
    AlreadyRevoked,
    Superseded,
}

pub(crate) struct CrashSafePointParticipation {
    thread: Arc<Thread>,
    id: CrashSafePointParticipationId,
}

impl CrashSafePointParticipation {
    #[cfg(test)]
    fn id_for_test(&self) -> CrashSafePointParticipationId {
        self.id
    }
}

impl Drop for CrashSafePointParticipation {
    fn drop(&mut self) {
        match self.thread.release_crash_safe_point_participation(self.id) {
            CrashSafePointRelease::Released | CrashSafePointRelease::AlreadyRevoked => {}
            CrashSafePointRelease::Superseded => {
                carrick_fatal!(
                    "kernel::crash_safe_point_participation",
                    "crash safe point participation superseded"
                );
            }
        }
    }
}

#[derive(Debug)]
pub struct Thread {
    pub(super) key: ThreadKey,
    registry_id: ThreadId,
    pub(super) task_key: TaskKey,
    task: Weak<Task>,
    resources: ArcSwap<ThreadResources>,
    pub(in crate::kernel) signal_state: Mutex<ThreadSignalState>,
    signal_pending_hint: AtomicU64,
    pub(in crate::kernel) revision: ObjectRevision,
    runner_gate: Arc<RunnerGate>,
    start_gate_open: AtomicBool,
    start_gate_proof_generation: AtomicU64,
    execution: Mutex<ThreadExecutionRecord>,
    /// Guest USER time charged directly to this exact logical thread across
    /// every host execution interval. Executor slots are never identities.
    cpu_accounting: Arc<ThreadCpuAccounting>,
    /// Guest SYSTEM time for this thread, in nanoseconds: the CPU carrick has
    /// burned servicing THIS thread's syscalls.
    ///
    /// Service time happens on the host thread outside guest execution, and is
    /// measured on that host thread's own `CLOCK_THREAD_CPUTIME_ID`, so a
    /// BLOCKED syscall — `wait4`, `epoll_wait` — contributes nothing, exactly
    /// as on Linux.
    ///
    /// The measurement window is one EXECUTOR RESIDENCY, not one syscall: it
    /// opens at the first dispatch boundary after the executor loads this
    /// thread (`Thread::open_system_charge_window`), closes when the executor
    /// stops running it (`close_system_charge_window`), and is flushed by every
    /// read so the thread's own `getrusage` sees the residency it is inside.
    /// Reading the clock IS a host syscall on Darwin (`thread_selfusage`), so a
    /// per-syscall bracket spent exactly two host syscalls on every guest
    /// syscall of every kind. A residency covers many syscalls and the host
    /// thread runs nothing but this logical thread's service for its whole
    /// length, so the wider window is both cheaper and more complete: it also
    /// charges the trap-decode and vCPU-loop CPU that the per-syscall bracket
    /// excluded and that Linux charges to system time. Guest EXECUTION is IN
    /// the raw window — `hv_vcpu_run` accrues to the host thread's own CPU
    /// clock — and is subtracted from it; see [`SystemChargeWindow`].
    /// This thread's answer to one task-local crash-capture generation: exact
    /// architectural state read at a safe point, or an explicit withdrawal
    /// from a park it cannot publish from. The generation prevents a delayed
    /// sibling from contaminating a later capture attempt.
    crash_vote: Mutex<Option<(CrashCaptureGeneration, CrashRegisterVote)>>,
    /// Exact architectural registers stashed when this thread parks / blocks /
    /// suspends. Collected for core publication if a sibling crashes while
    /// this thread is not on an active vCPU lease.
    parked_registers: Mutex<Option<carrick_hal::Aarch64CoreRegisters>>,
    /// Non-zero generation owned by the exact live executor quantum that can
    /// still reach a crash safe point. Retirement may revoke it to zero; a
    /// stale guard may never clear a successor's different generation.
    crash_safe_point_participant: AtomicU64,
    /// Next never-reused crash-safe-point participation generation.
    next_crash_safe_point_participation: AtomicU64,
    /// `KEY_SPEC_THREAD_KEYRING`, materialised on demand.
    ///
    /// Per-THREAD, keyed by this object's exact [`ThreadKey`] rather than by a
    /// host tid: under HVPatch a guest thread is a host pthread of one carrier,
    /// so a tid-keyed table would alias across guest processes and would go
    /// stale the moment a tid was reused. `keyrings(7)` makes this the one
    /// keyring a `fork` child does NOT inherit, which every constructor here
    /// gets for free by starting it at `None`.
    thread_keyring: Mutex<Option<KeySerial>>,
    last_cpu: AtomicU32,
    affinity: RwLock<carrick_hal::CpuAffinity>,
}

#[derive(Debug, Default)]
struct ThreadCpuAccounting {
    user_ns: AtomicU64,
    system_ns: AtomicU64,
    /// `guest_run_clock_ns()` at which this thread entered guest execution, or
    /// 0 while it is not executing guest code. A vCPU commits its run into
    /// `user_ns` only when it traps back to the runtime, and a guest that
    /// spins never traps — so a reader that must see the CPU the guest is
    /// burning RIGHT NOW (the `RLIMIT_CPU` watchdog, a CPU itimer) adds the
    /// open interval instead of waiting for a trap that will not come.
    active_since_ns: AtomicU64,
}
/// One thread's guest user CPU at an instant: see
/// [`Thread::sample_cpu_including_active`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadCpuSample {
    /// Committed user CPU plus the open guest run, if any.
    pub cpu_ns: u64,
    /// Whether the thread is inside a guest run right now.
    pub running_guest: bool,
}

/// One task's guest user CPU at an instant: see
/// [`Task::sample_cpu_including_active`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskCpuSample {
    /// Every live thread's [`ThreadCpuSample::cpu_ns`] plus exited threads'.
    pub cpu_ns: u64,
    /// How many threads are inside a guest run right now — the number of
    /// host CPUs this figure can be growing on.
    pub running_guest_threads: u64,
}

/// Monotonic host clock for the open guest-run interval, in nanoseconds.
/// Only differences between two readings are ever used; the time source is
/// the host's to own, so this holds no state of its own.
fn guest_run_clock_ns() -> u64 {
    carrick_host::clock::host_clock_uptime_ns()
}

#[derive(Debug)]
pub(crate) struct OpenedStartGate {
    thread: ThreadKey,
    generation: ExecutionGeneration,
}

impl OpenedStartGate {
    pub(crate) const fn thread(&self) -> ThreadKey {
        self.thread
    }

    pub(crate) const fn generation(&self) -> ExecutionGeneration {
        self.generation
    }
}

impl Thread {
    pub fn last_cpu(&self) -> Option<carrick_hal::GuestCpuId> {
        let raw = self.last_cpu.load(Ordering::Relaxed);
        if raw == u32::MAX {
            None
        } else {
            Some(carrick_hal::GuestCpuId::new(raw))
        }
    }

    pub fn last_cpu_raw(&self) -> u32 {
        self.last_cpu.load(Ordering::Relaxed)
    }

    pub fn set_last_cpu(&self, cpu: carrick_hal::GuestCpuId) {
        self.last_cpu.store(cpu.as_u32(), Ordering::Relaxed);
    }

    /// The guest CPUs this thread may be placed on. `Copy`, so the placement
    /// path reads it without allocating.
    pub fn affinity(&self) -> carrick_hal::CpuAffinity {
        *self.affinity.read()
    }

    pub fn set_affinity(&self, affinity: carrick_hal::CpuAffinity) {
        *self.affinity.write() = affinity;
    }

    pub(in crate::kernel) fn open_start_gate(&self) {
        self.start_gate_open.store(true, Ordering::Release);
    }

    pub(crate) fn take_opened_start_gate(
        &self,
        generation: ExecutionGeneration,
    ) -> Option<OpenedStartGate> {
        let execution = self.execution.lock();
        if !self.start_gate_open.load(Ordering::Acquire)
            || execution.state.generation() != Some(generation)
            || self
                .start_gate_proof_generation
                .compare_exchange(0, generation.raw(), Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return None;
        }
        Some(OpenedStartGate {
            thread: self.key,
            generation,
        })
    }

    pub(crate) fn parked_task_state_authority(
        &self,
        generation: ExecutionGeneration,
    ) -> Option<(MmId, u64)> {
        let execution = self.execution.lock();
        (execution.state.generation() == Some(generation))
            .then(|| execution.task_state.as_ref())
            .flatten()
            .map(|state| (state.mm, state.asid_generation))
    }

    /// Authenticate one exact live execution lease before exposing the MM
    /// identity carried by its architectural task snapshot.
    pub(crate) fn authenticate_task_state_authority(
        &self,
        lease: &ThreadExecutionLease,
    ) -> Result<(MmId, u64), ThreadExecutionError> {
        self.validate_execution_lease_owner(lease)?;
        let execution = self.execution.lock();
        if !Self::execution_state_matches_lease(execution.state, lease) {
            return Err(Self::stale_lease_error(lease));
        }
        drop(execution);
        lease.task_state_authority()
    }

    pub const fn key(&self) -> ThreadKey {
        self.key
    }

    /// Diagnostic rendering for the debug snapshot: the execution state plus
    /// the two slot-presence facts a scheduler-freeze diagnosis needs (a
    /// Runnable thread without task_state is UNCLAIMABLE — claim_runnable
    /// fails `claim_runnable_without_cpu_state` and the queue row is shredded).
    pub fn execution_diagnostic(&self) -> String {
        let execution = self.execution.lock();
        format!(
            "{:?} task_state={} continuation={} control_quantum={:?}",
            execution.state,
            execution.task_state.is_some(),
            execution.blocked_continuation.is_some(),
            execution.control_quantum
        )
    }

    /// What the parked continuation on this thread is actually waiting on.
    ///
    /// `execution_diagnostic` reports only that a continuation is present.
    /// A lost wake needs the next question answered — which family, which
    /// probe, and whether the wait service still holds a registration a
    /// producer can publish into — and a watchdog wedge snapshot is normally
    /// the only evidence available. See
    /// [`BlockedContinuation::diagnostic`](crate::vcpu_loop::continuation::BlockedContinuation::diagnostic).
    pub fn continuation_diagnostic(
        &self,
    ) -> Option<crate::vcpu_loop::continuation::ContinuationDiagnostic> {
        let execution = self.execution.lock();
        let diagnostic = execution
            .blocked_continuation
            .as_ref()
            .map(|c| c.diagnostic());
        drop(execution);
        diagnostic
    }

    pub fn execution_state(&self) -> ThreadExecutionState {
        self.execution.lock().state
    }

    pub fn exec_invalidation_pending(&self) -> bool {
        self.execution.lock().exec_invalidation_pending
    }

    /// Hold this exact execution generation stable while a scheduler commits
    /// dependent authority. The callback may acquire run-queue state; callers
    /// must never call it from a queue-held path.
    /// Diagnostic rendering of the execution state (variant name and its
    /// generation) for the generation-observer abort path.
    pub(crate) fn execution_state_diagnostic(&self) -> String {
        let execution = self.execution.lock();
        format!("{:?}", execution.state)
    }

    pub(crate) fn with_active_execution_generation<R>(
        &self,
        generation: ExecutionGeneration,
        commit: impl FnOnce() -> R,
    ) -> Option<R> {
        let execution = self.execution.lock();
        matches!(
            execution.state,
            ThreadExecutionState::Runnable {
                generation: active
            } | ThreadExecutionState::Running {
                generation: active,
                ..
            } | ThreadExecutionState::SwitchingOut {
                generation: active,
                ..
            } | ThreadExecutionState::Blocked {
                generation: active,
                ..
            } if active == generation
        )
        .then(commit)
    }

    /// Minimal Linux run-state projection consumed by `/proc` wiring in a
    /// later task. Executor identity is deliberately absent from the answer.
    pub const fn linux_run_state_from_execution(state: ThreadExecutionState) -> Option<char> {
        match state {
            ThreadExecutionState::Runnable { .. } | ThreadExecutionState::Running { .. } => {
                Some('R')
            }
            ThreadExecutionState::Blocked { .. } => Some('S'),
            ThreadExecutionState::Uninitialized
            | ThreadExecutionState::SwitchingOut { .. }
            | ThreadExecutionState::Exited { .. }
            | ThreadExecutionState::Failed { .. } => None,
        }
    }

    pub fn linux_run_state(&self) -> Option<char> {
        Self::linux_run_state_from_execution(self.execution_state())
    }

    /// Decide one exact scheduler wake while holding only this thread's
    /// execution record. Queue insertion and kick delivery are returned as
    /// typed actions and must happen after this method releases the lock.
    pub(crate) fn scheduler_wake(
        &self,
        expected: ThreadKey,
    ) -> Result<ThreadSchedulerAction, ThreadExecutionError> {
        if expected != self.key {
            return Err(ThreadExecutionError::SchedulerThreadMismatch {
                expected,
                actual: self.key,
            });
        }
        let mut execution = self.execution.lock();
        let found = execution.state;
        let action = match execution.state {
            ThreadExecutionState::Blocked {
                generation: predecessor,
                ..
            } => {
                if execution
                    .blocked_continuation
                    .as_ref()
                    .is_some_and(|continuation| !continuation.accepts_scheduler_wake_now())
                {
                    ThreadSchedulerAction::None
                } else {
                    let generation = predecessor
                        .next()
                        .ok_or(ThreadExecutionError::GenerationExhausted)?;
                    if let Some(continuation) = execution.blocked_continuation.as_ref() {
                        continuation.publish_ready_event(
                            crate::vcpu_loop::continuation::ContinuationEvent::Ready,
                        );
                    }
                    execution.state = ThreadExecutionState::Runnable { generation };
                    ThreadSchedulerAction::Queue {
                        key: self.key,
                        predecessor: Some(predecessor),
                        generation,
                        closing_authorized: true,
                    }
                }
            }
            ThreadExecutionState::Runnable { generation } => {
                // Runnable normally implies the producer edge was already
                // consumed. A control-only quantum is the exception: it made
                // the task runnable without guest readiness, so a racing real
                // producer must still publish into the preserved continuation.
                if execution.control_quantum.is_some()
                    && let Some(continuation) = execution.blocked_continuation.as_ref()
                    && continuation.accepts_scheduler_wake_now()
                {
                    continuation.publish_ready_event(
                        crate::vcpu_loop::continuation::ContinuationEvent::Ready,
                    );
                }
                ThreadSchedulerAction::Queue {
                    key: self.key,
                    predecessor: None,
                    generation,
                    closing_authorized: false,
                }
            }
            ThreadExecutionState::Running {
                generation,
                executor,
                executor_epoch,
                ..
            } => {
                execution.state = ThreadExecutionState::Running {
                    generation,
                    executor,
                    executor_epoch,
                    wake_pending: true,
                };
                ThreadSchedulerAction::Kick {
                    executor,
                    executor_epoch,
                    key: self.key,
                    generation,
                }
            }
            ThreadExecutionState::SwitchingOut {
                generation,
                executor,
                executor_epoch,
                ..
            } => {
                execution.state = ThreadExecutionState::SwitchingOut {
                    generation,
                    executor,
                    executor_epoch,
                    wake_pending: true,
                };
                ThreadSchedulerAction::None
            }
            state => {
                return Err(ThreadExecutionError::InvalidTransition {
                    operation: "scheduler_wake",
                    state,
                });
            }
        };
        drop(execution);
        self.revision.publish();
        crate::probes::hvpatch_scheduler_wake(
            self.key.serial.raw(),
            crate::probes::HvpatchSchedulerWakeKind::Wake,
            found.probe_kind(),
            found.generation().map_or(0, ExecutionGeneration::raw),
            action.probe_generation(),
        );
        Ok(action)
    }

    /// Schedule owner-thread control work without manufacturing readiness for
    /// the guest continuation. A real producer wake may still arrive while the
    /// control quantum runs; that independent edge uses `wake_pending` and
    /// publishes `ContinuationEvent::Ready` during settlement as usual.
    pub(crate) fn scheduler_control_wake(
        &self,
        expected: ThreadKey,
    ) -> Result<ThreadSchedulerAction, ThreadExecutionError> {
        if expected != self.key {
            return Err(ThreadExecutionError::SchedulerThreadMismatch {
                expected,
                actual: self.key,
            });
        }
        let mut execution = self.execution.lock();
        let found = execution.state;
        // A retry may temporarily park the same quantum as HostWait. Preserve
        // a blocked reason only when there is an actual continuation token to
        // displace and later restore. Fork/clone/job-control retry phases also
        // park as Blocked, but own their state in the production phase rather
        // than in `blocked_continuation`; treating their reason as restorable
        // would manufacture an impossible deferred-continuation obligation.
        if execution.control_quantum.is_none() {
            let blocked_reason = match (execution.state, execution.blocked_continuation.is_some()) {
                (ThreadExecutionState::Blocked { reason, .. }, true) => Some(reason),
                _ => None,
            };
            execution.control_quantum = Some(SchedulerControlQuantum {
                blocked_reason,
                requeue_pending: matches!(
                    execution.state,
                    ThreadExecutionState::Running { .. }
                        | ThreadExecutionState::SwitchingOut { .. }
                ),
            });
        } else if matches!(
            execution.state,
            ThreadExecutionState::Running { .. } | ThreadExecutionState::SwitchingOut { .. }
        ) && let Some(quantum) = execution.control_quantum.as_mut()
        {
            quantum.requeue_pending = true;
        }
        let action = match execution.state {
            ThreadExecutionState::Blocked {
                generation: predecessor,
                ..
            } => {
                let generation = predecessor
                    .next()
                    .ok_or(ThreadExecutionError::GenerationExhausted)?;
                execution.state = ThreadExecutionState::Runnable { generation };
                ThreadSchedulerAction::Queue {
                    key: self.key,
                    predecessor: Some(predecessor),
                    generation,
                    closing_authorized: true,
                }
            }
            ThreadExecutionState::Runnable { generation } => ThreadSchedulerAction::Queue {
                key: self.key,
                predecessor: None,
                generation,
                closing_authorized: false,
            },
            ThreadExecutionState::Running {
                generation,
                executor,
                executor_epoch,
                ..
            } => ThreadSchedulerAction::Kick {
                executor,
                executor_epoch,
                key: self.key,
                generation,
            },
            ThreadExecutionState::SwitchingOut { .. } => ThreadSchedulerAction::None,
            state => {
                execution.control_quantum = None;
                return Err(ThreadExecutionError::InvalidTransition {
                    operation: "scheduler_control_wake",
                    state,
                });
            }
        };
        drop(execution);
        self.revision.publish();
        crate::probes::hvpatch_scheduler_wake(
            self.key.serial.raw(),
            crate::probes::HvpatchSchedulerWakeKind::Control,
            found.probe_kind(),
            found.generation().map_or(0, ExecutionGeneration::raw),
            action.probe_generation(),
        );
        Ok(action)
    }

    pub(crate) fn finish_scheduler_control_quantum(
        &self,
        expected: ThreadKey,
    ) -> Result<SchedulerControlQuantum, ThreadExecutionError> {
        if expected != self.key {
            return Err(ThreadExecutionError::SchedulerThreadMismatch {
                expected,
                actual: self.key,
            });
        }
        let mut execution = self.execution.lock();
        let quantum =
            execution
                .control_quantum
                .take()
                .ok_or(ThreadExecutionError::InvalidTransition {
                    operation: "finish_scheduler_control_quantum",
                    state: execution.state,
                })?;
        drop(execution);
        self.revision.publish();
        Ok(quantum)
    }

    pub(crate) fn scheduler_control_quantum(
        &self,
        expected: ThreadKey,
    ) -> Result<Option<SchedulerControlQuantum>, ThreadExecutionError> {
        if expected != self.key {
            return Err(ThreadExecutionError::SchedulerThreadMismatch {
                expected,
                actual: self.key,
            });
        }
        Ok(self.execution.lock().control_quantum)
    }

    pub(crate) fn restore_scheduler_control_quantum(
        &self,
        expected: ThreadKey,
        quantum: SchedulerControlQuantum,
    ) -> Result<(), ThreadExecutionError> {
        if expected != self.key {
            return Err(ThreadExecutionError::SchedulerThreadMismatch {
                expected,
                actual: self.key,
            });
        }
        let mut execution = self.execution.lock();
        if !matches!(
            execution.state,
            ThreadExecutionState::Runnable { .. }
                | ThreadExecutionState::Running { .. }
                | ThreadExecutionState::SwitchingOut { .. }
        ) {
            return Err(ThreadExecutionError::InvalidTransition {
                operation: "restore_scheduler_control_quantum",
                state: execution.state,
            });
        }
        match execution.control_quantum {
            None
            | Some(SchedulerControlQuantum {
                blocked_reason: None,
                ..
            }) => {
                execution.control_quantum = Some(SchedulerControlQuantum {
                    requeue_pending: false,
                    ..quantum
                });
            }
            Some(existing) if existing.blocked_reason == quantum.blocked_reason => {
                execution.control_quantum = Some(SchedulerControlQuantum {
                    requeue_pending: false,
                    ..quantum
                });
            }
            Some(_) => {
                return Err(ThreadExecutionError::InvalidTransition {
                    operation: "restore_scheduler_control_quantum",
                    state: execution.state,
                });
            }
        }
        drop(execution);
        self.revision.publish();
        Ok(())
    }

    /// Seed the first complete task snapshot after backend materialization.
    /// New, fork, clone, and exec-replacement objects all begin uninitialized,
    /// and no other state accepts this publication.
    pub fn publish_initial_task_state(
        &self,
        state: MigratableTaskState,
    ) -> Result<ExecutionGeneration, ThreadExecutionError> {
        state.validate_identity()?;
        let mut execution = self.execution.lock();
        if execution.state != ThreadExecutionState::Uninitialized {
            return Err(ThreadExecutionError::InvalidTransition {
                operation: "publish_initial_task_state",
                state: execution.state,
            });
        }
        let generation = ExecutionGeneration::INITIAL;
        execution.task_state = Some(Box::new(state));
        execution.blocked_continuation = None;
        execution.exec_invalidation_pending = false;
        execution.state = ThreadExecutionState::Runnable { generation };
        drop(execution);
        self.revision.publish();
        Ok(generation)
    }

    /// Atomically move the exact Runnable snapshot into one executor lease.
    pub fn claim_runnable(
        self: &Arc<Self>,
        executor: ExecutorId,
    ) -> Result<ThreadExecutionLease, ThreadExecutionError> {
        let mut execution = self.execution.lock();
        let generation = match execution.state {
            ThreadExecutionState::Runnable { generation } => generation,
            state => {
                return Err(ThreadExecutionError::InvalidTransition {
                    operation: "claim_runnable",
                    state,
                });
            }
        };
        let executor_epoch = execution.next_executor_epoch;
        let next_executor_epoch = executor_epoch
            .checked_add(1)
            .ok_or(ThreadExecutionError::GenerationExhausted)?;
        let Some(task_state) = execution.task_state.take() else {
            return Err(ThreadExecutionError::InvalidTransition {
                operation: "claim_runnable_without_cpu_state",
                state: execution.state,
            });
        };
        let blocked_continuation = execution.blocked_continuation.take();
        execution.next_executor_epoch = next_executor_epoch;
        if let Some(quantum) = execution.control_quantum.as_mut() {
            quantum.requeue_pending = false;
        }
        execution.state = ThreadExecutionState::Running {
            generation,
            executor,
            executor_epoch,
            wake_pending: false,
        };
        drop(execution);
        self.revision.publish();
        Ok(ThreadExecutionLease {
            owner: Arc::downgrade(self),
            owner_key: self.key,
            generation,
            executor,
            executor_epoch,
            task_state: Some(task_state),
            blocked_continuation,
            settled: false,
        })
    }

    /// Transitional welded-thread wake path used until Task 3 installs the run
    /// queue. It claims only the exact blocked generation and never infers
    /// authority from a wake edge or host-thread slot.
    pub fn claim_blocked_for_transitional_executor(
        self: &Arc<Self>,
        executor: ExecutorId,
    ) -> Result<ThreadExecutionLease, ThreadExecutionError> {
        let mut execution = self.execution.lock();
        let generation = match execution.state {
            ThreadExecutionState::Blocked { generation, .. } => generation,
            state => {
                return Err(ThreadExecutionError::InvalidTransition {
                    operation: "claim_blocked_for_transitional_executor",
                    state,
                });
            }
        };
        let executor_epoch = execution.next_executor_epoch;
        execution.next_executor_epoch = executor_epoch
            .checked_add(1)
            .ok_or(ThreadExecutionError::GenerationExhausted)?;
        let Some(task_state) = execution.task_state.take() else {
            return Err(ThreadExecutionError::InvalidTransition {
                operation: "claim_blocked_without_cpu_state",
                state: execution.state,
            });
        };
        let blocked_continuation = execution.blocked_continuation.take();
        execution.state = ThreadExecutionState::Running {
            generation,
            executor,
            executor_epoch,
            wake_pending: false,
        };
        drop(execution);
        self.revision.publish();
        Ok(ThreadExecutionLease {
            owner: Arc::downgrade(self),
            owner_key: self.key,
            generation,
            executor,
            executor_epoch,
            task_state: Some(task_state),
            blocked_continuation,
            settled: false,
        })
    }

    /// Publish that the executor has begun saving the leased task state.
    pub fn begin_switch_out(
        &self,
        lease: &ThreadExecutionLease,
    ) -> Result<(), ThreadExecutionError> {
        self.validate_execution_lease_owner(lease)?;
        let mut execution = self.execution.lock();
        match execution.state {
            ThreadExecutionState::Running {
                generation,
                executor,
                executor_epoch,
                wake_pending,
            } if generation == lease.generation
                && executor == lease.executor
                && executor_epoch == lease.executor_epoch =>
            {
                execution.state = ThreadExecutionState::SwitchingOut {
                    generation,
                    executor,
                    executor_epoch,
                    wake_pending,
                };
            }
            _ => return Err(Self::stale_lease_error(lease)),
        }
        drop(execution);
        self.revision.publish();
        Ok(())
    }

    /// Authenticate that `lease` is the exact currently running generation
    /// before a backend crosses a destructive save boundary.
    pub fn validate_running_execution_lease(
        &self,
        lease: &ThreadExecutionLease,
    ) -> Result<(), ThreadExecutionError> {
        self.validate_execution_lease_owner(lease)?;
        let execution = self.execution.lock();
        if matches!(
            execution.state,
            ThreadExecutionState::Running {
                generation,
                executor,
                executor_epoch,
                ..
            } if generation == lease.generation
                && executor == lease.executor
                && executor_epoch == lease.executor_epoch
        ) {
            Ok(())
        } else {
            Err(Self::stale_lease_error(lease))
        }
    }

    pub fn yield_from_executor(
        &self,
        lease: ThreadExecutionLease,
    ) -> ThreadExecutionSettlementResult {
        self.settle_execution_lease(lease, ExecutionSettlement::Runnable, false)
            .map(|_| ())
    }

    pub fn park_from_executor(
        &self,
        lease: ThreadExecutionLease,
        reason: BlockedReason,
    ) -> ThreadExecutionSettlementResult {
        self.settle_execution_lease(lease, ExecutionSettlement::Blocked(reason), false)
            .map(|_| ())
    }

    pub fn exit_from_executor(
        &self,
        lease: ThreadExecutionLease,
    ) -> ThreadExecutionSettlementResult {
        self.settle_execution_lease(lease, ExecutionSettlement::Exited, false)
            .map(|_| ())
    }

    pub(in crate::kernel) fn cancel_kernel_owned_continuation(
        &self,
        cause: crate::vcpu_loop::continuation::CancellationCause,
    ) -> Option<crate::vcpu_loop::continuation::CancellationReceipt> {
        let mut execution = self.execution.lock();
        let continuation = execution.blocked_continuation.take()?;
        let receipt = continuation.cancel(cause);
        if let ThreadExecutionState::Blocked {
            generation, reason, ..
        } = execution.state
        {
            execution.state = ThreadExecutionState::Blocked {
                generation,
                reason,
                continuation: None,
            };
        }
        drop(execution);
        self.revision.publish();
        Some(receipt)
    }

    pub(crate) fn scheduler_yield_from_executor(
        &self,
        lease: ThreadExecutionLease,
    ) -> Result<ThreadSchedulerAction, (ThreadExecutionError, ThreadExecutionLease)> {
        self.settle_execution_lease(lease, ExecutionSettlement::Runnable, true)
    }

    pub(crate) fn scheduler_park_from_executor(
        &self,
        lease: ThreadExecutionLease,
        reason: BlockedReason,
    ) -> Result<ThreadSchedulerAction, (ThreadExecutionError, ThreadExecutionLease)> {
        self.settle_execution_lease(lease, ExecutionSettlement::Blocked(reason), true)
    }

    pub(crate) fn scheduler_park_continuation_from_executor(
        &self,
        lease: ThreadExecutionLease,
        reason: BlockedReason,
        continuation: crate::vcpu_loop::continuation::BlockedContinuation,
    ) -> Result<ThreadSchedulerAction, (ThreadExecutionError, ThreadExecutionLease)> {
        self.settle_execution_lease(
            lease,
            ExecutionSettlement::BlockedContinuation(reason, Box::new(continuation)),
            true,
        )
    }

    pub fn fail_from_executor(
        &self,
        mut lease: ThreadExecutionLease,
        reason: ExecutionFailure,
    ) -> ThreadExecutionSettlementResult {
        if let Err(error) = self.validate_execution_lease_owner(&lease) {
            return Err((error, lease));
        }
        let mut execution = self.execution.lock();
        if !Self::execution_state_matches_lease(execution.state, &lease) {
            let error = Self::stale_lease_error(&lease);
            return Err((error, lease));
        }
        let Some(generation) = lease.generation.next() else {
            return Err((ThreadExecutionError::GenerationExhausted, lease));
        };
        execution.task_state = None;
        let _ = lease.task_state.take();
        cancel_continuation_slot(
            &mut execution.blocked_continuation,
            crate::vcpu_loop::continuation::CancellationCause::ServiceShutdown,
        );
        cancel_continuation_slot(
            &mut lease.blocked_continuation,
            crate::vcpu_loop::continuation::CancellationCause::ServiceShutdown,
        );
        execution.exec_invalidation_pending = false;
        execution.control_quantum = None;
        execution.state = ThreadExecutionState::Failed { generation, reason };
        lease.settled = true;
        drop(execution);
        self.revision.publish();
        Ok(())
    }

    /// Fail the exact scheduler claim when a backend violated the scoped
    /// lease-return contract. The non-cloneable `RunnableThread` claim is the
    /// authority; no replacement lease is fabricated.
    pub(crate) fn fail_claimed_execution(
        &self,
        generation: ExecutionGeneration,
        executor: ExecutorId,
        executor_epoch: u64,
        reason: ExecutionFailure,
    ) -> Result<ExecutionGeneration, ThreadExecutionError> {
        let mut execution = self.execution.lock();
        if !matches!(
            execution.state,
            ThreadExecutionState::Running {
                generation: current,
                executor: current_executor,
                executor_epoch: current_epoch,
                ..
            } | ThreadExecutionState::SwitchingOut {
                generation: current,
                executor: current_executor,
                executor_epoch: current_epoch,
                ..
            } if current == generation
                && current_executor == executor
                && current_epoch == executor_epoch
        ) {
            return Err(ThreadExecutionError::InvalidTransition {
                operation: "fail_claimed_execution",
                state: execution.state,
            });
        }
        let successor = generation
            .next()
            .ok_or(ThreadExecutionError::GenerationExhausted)?;
        execution.task_state = None;
        cancel_continuation_slot(
            &mut execution.blocked_continuation,
            crate::vcpu_loop::continuation::CancellationCause::ServiceShutdown,
        );
        execution.exec_invalidation_pending = false;
        execution.control_quantum = None;
        execution.state = ThreadExecutionState::Failed {
            generation: successor,
            reason,
        };
        drop(execution);
        self.revision.publish();
        Ok(successor)
    }

    /// Fail a task whose first backend snapshot could not be captured before a
    /// lease existed. No guessed or empty state is published.
    pub fn fail_uninitialized_snapshot(&self, reason: ExecutionFailure) {
        let mut execution = self.execution.lock();
        if execution.state != ThreadExecutionState::Uninitialized {
            return;
        }
        execution.task_state = None;
        execution.blocked_continuation = None;
        execution.exec_invalidation_pending = false;
        execution.control_quantum = None;
        execution.state = ThreadExecutionState::Failed {
            generation: ExecutionGeneration::INITIAL,
            reason,
        };
        drop(execution);
        self.revision.publish();
    }

    /// Fail the exact initial Runnable generation when bootstrap ownership
    /// cannot be transferred to a runner. This path has no executor lease and
    /// is valid only before scheduler publication.
    pub fn fail_runnable_generation(
        &self,
        expected: ExecutionGeneration,
        reason: ExecutionFailure,
    ) -> Result<(), ThreadExecutionError> {
        let mut execution = self.execution.lock();
        if !matches!(
            execution.state,
            ThreadExecutionState::Runnable { generation } if generation == expected
        ) {
            return Err(ThreadExecutionError::InvalidTransition {
                operation: "fail_runnable_generation",
                state: execution.state,
            });
        }
        execution.task_state = None;
        cancel_continuation_slot(
            &mut execution.blocked_continuation,
            crate::vcpu_loop::continuation::CancellationCause::ServiceShutdown,
        );
        execution.exec_invalidation_pending = false;
        execution.control_quantum = None;
        execution.state = ThreadExecutionState::Failed {
            generation: expected,
            reason,
        };
        drop(execution);
        self.revision.publish();
        Ok(())
    }

    /// Fail an exact dormant scheduler generation during carrier shutdown.
    /// A blocked task owns no executor lease, so this is the only typed path
    /// that can consume its saved task state and continuation without
    /// fabricating executor authority.
    pub(crate) fn fail_blocked_generation(
        &self,
        expected: ExecutionGeneration,
        reason: ExecutionFailure,
    ) -> Result<ExecutionGeneration, ThreadExecutionError> {
        let mut execution = self.execution.lock();
        if !matches!(
            execution.state,
            ThreadExecutionState::Blocked { generation, .. } if generation == expected
        ) {
            return Err(ThreadExecutionError::InvalidTransition {
                operation: "fail_blocked_generation",
                state: execution.state,
            });
        }
        let generation = expected
            .next()
            .ok_or(ThreadExecutionError::GenerationExhausted)?;
        execution.task_state = None;
        cancel_continuation_slot(
            &mut execution.blocked_continuation,
            crate::vcpu_loop::continuation::CancellationCause::ServiceShutdown,
        );
        execution.exec_invalidation_pending = false;
        execution.control_quantum = None;
        execution.state = ThreadExecutionState::Failed { generation, reason };
        drop(execution);
        self.revision.publish();
        Ok(generation)
    }

    fn settle_execution_lease(
        &self,
        mut lease: ThreadExecutionLease,
        settlement: ExecutionSettlement,
        scheduler_owned: bool,
    ) -> Result<ThreadSchedulerAction, (ThreadExecutionError, ThreadExecutionLease)> {
        if let Err(error) = self.validate_execution_lease_owner(&lease) {
            return Err((error, lease));
        }
        let mut execution = self.execution.lock();
        if !Self::execution_state_matches_lease(execution.state, &lease) {
            let error = Self::stale_lease_error(&lease);
            return Err((error, lease));
        }
        let Some(generation) = lease.generation.next() else {
            return Err((ThreadExecutionError::GenerationExhausted, lease));
        };
        let wake_pending = matches!(
            execution.state,
            ThreadExecutionState::Running {
                wake_pending: true,
                ..
            } | ThreadExecutionState::SwitchingOut {
                wake_pending: true,
                ..
            }
        );
        let control_pending = execution
            .control_quantum
            .is_some_and(|quantum| quantum.requeue_pending);
        if wake_pending && !scheduler_owned && !matches!(settlement, ExecutionSettlement::Exited) {
            return Err((ThreadExecutionError::SchedulerSettlementRequired, lease));
        }
        let mut action = ThreadSchedulerAction::None;
        let mut settle_kind = match settlement {
            ExecutionSettlement::Runnable => crate::probes::HvpatchLeaseSettlementKind::Runnable,
            ExecutionSettlement::Blocked(_) => crate::probes::HvpatchLeaseSettlementKind::Blocked,
            ExecutionSettlement::BlockedContinuation(..) => {
                crate::probes::HvpatchLeaseSettlementKind::BlockedContinuation
            }
            ExecutionSettlement::Exited => crate::probes::HvpatchLeaseSettlementKind::Exited,
        };
        let mut settle_flags = 0_u32;
        if wake_pending {
            settle_flags |= crate::probes::HvpatchLeaseSettleFlag::WakePending.raw();
        }
        if control_pending {
            settle_flags |= crate::probes::HvpatchLeaseSettleFlag::ControlPending.raw();
        }
        if execution.exec_invalidation_pending {
            settle_kind = crate::probes::HvpatchLeaseSettlementKind::ExecInvalidated;
            execution.task_state = None;
            let _ = lease.task_state.take();
            cancel_continuation_slot(
                &mut execution.blocked_continuation,
                crate::vcpu_loop::continuation::CancellationCause::Exec,
            );
            cancel_continuation_slot(
                &mut lease.blocked_continuation,
                crate::vcpu_loop::continuation::CancellationCause::Exec,
            );
            execution.state = ThreadExecutionState::Exited { generation };
            execution.exec_invalidation_pending = false;
            execution.control_quantum = None;
        } else {
            match settlement {
                ExecutionSettlement::Runnable => {
                    execution.task_state = lease.task_state.take();
                    execution.blocked_continuation =
                        Self::carry_continuation_through_lease(&mut lease);
                    execution.state = ThreadExecutionState::Runnable { generation };
                    if scheduler_owned {
                        action = ThreadSchedulerAction::Queue {
                            key: self.key,
                            predecessor: Some(lease.generation),
                            generation,
                            closing_authorized: true,
                        };
                    }
                }
                ExecutionSettlement::Blocked(reason) => {
                    execution.task_state = lease.task_state.take();
                    execution.blocked_continuation =
                        Self::carry_continuation_through_lease(&mut lease);
                    let generic_wake_ready = wake_pending
                        && execution
                            .blocked_continuation
                            .as_ref()
                            .is_none_or(|continuation| continuation.accepts_scheduler_wake_now());
                    if generic_wake_ready || control_pending {
                        if let Some(continuation) = execution.blocked_continuation.as_ref() {
                            if generic_wake_ready {
                                continuation.publish_ready_event(
                                    crate::vcpu_loop::continuation::ContinuationEvent::Ready,
                                );
                                settle_flags |=
                                    crate::probes::HvpatchLeaseSettleFlag::ContinuationReady.raw();
                            }
                        }
                        execution.state = ThreadExecutionState::Runnable { generation };
                        action = ThreadSchedulerAction::Queue {
                            key: self.key,
                            predecessor: Some(lease.generation),
                            generation,
                            closing_authorized: true,
                        };
                    } else {
                        execution.state = ThreadExecutionState::Blocked {
                            generation,
                            reason,
                            continuation: execution
                                .blocked_continuation
                                .as_deref()
                                .map(crate::vcpu_loop::continuation::BlockedContinuation::id),
                        };
                    }
                }
                ExecutionSettlement::BlockedContinuation(reason, continuation) => {
                    execution.task_state = lease.task_state.take();
                    let continuation_id = continuation.id();
                    let generic_wake_ready =
                        wake_pending && continuation.accepts_scheduler_wake_now();
                    if generic_wake_ready || control_pending {
                        if generic_wake_ready {
                            continuation.publish_ready_event(
                                crate::vcpu_loop::continuation::ContinuationEvent::Ready,
                            );
                            settle_flags |=
                                crate::probes::HvpatchLeaseSettleFlag::ContinuationReady.raw();
                        }
                        execution.state = ThreadExecutionState::Runnable { generation };
                        action = ThreadSchedulerAction::Queue {
                            key: self.key,
                            predecessor: Some(lease.generation),
                            generation,
                            closing_authorized: true,
                        };
                    } else {
                        execution.state = ThreadExecutionState::Blocked {
                            generation,
                            reason,
                            continuation: Some(continuation_id),
                        };
                    }
                    execution.blocked_continuation = Some(continuation);
                    let _ = lease.blocked_continuation.take();
                }
                ExecutionSettlement::Exited => {
                    execution.task_state = None;
                    let _ = lease.task_state.take();
                    cancel_continuation_slot(
                        &mut execution.blocked_continuation,
                        crate::vcpu_loop::continuation::CancellationCause::ThreadExit,
                    );
                    cancel_continuation_slot(
                        &mut lease.blocked_continuation,
                        crate::vcpu_loop::continuation::CancellationCause::ThreadExit,
                    );
                    execution.state = ThreadExecutionState::Exited { generation };
                    execution.control_quantum = None;
                }
            }
        }
        lease.settled = true;
        drop(execution);
        self.revision.publish();
        crate::probes::hvpatch_lease_settle(
            self.key.serial.raw(),
            settle_kind,
            settle_flags,
            lease.generation.raw(),
            generation.raw(),
        );
        Ok(action)
    }

    /// Move an unconsumed continuation out of a settling lease, re-stamping
    /// its authority to that lease so the succession `resume_continuation`
    /// checks counts from the lease that actually held it.
    fn carry_continuation_through_lease(
        lease: &mut ThreadExecutionLease,
    ) -> Option<Box<crate::vcpu_loop::continuation::BlockedContinuation>> {
        let mut continuation = lease.blocked_continuation.take()?;
        continuation.carry_through_lease(lease.generation);
        Some(continuation)
    }

    fn validate_execution_lease_owner(
        &self,
        lease: &ThreadExecutionLease,
    ) -> Result<(), ThreadExecutionError> {
        let exact_owner = lease
            .owner
            .upgrade()
            .is_some_and(|owner| std::ptr::eq(self, owner.as_ref()));
        if lease.owner_key != self.key || !exact_owner {
            return Err(ThreadExecutionError::LeaseOwnerMismatch {
                expected: self.key,
                actual: lease.owner_key,
            });
        }
        Ok(())
    }

    fn execution_state_matches_lease(
        state: ThreadExecutionState,
        lease: &ThreadExecutionLease,
    ) -> bool {
        matches!(
            state,
            ThreadExecutionState::Running {
                generation,
                executor,
                executor_epoch,
                ..
            } | ThreadExecutionState::SwitchingOut {
                generation,
                executor,
                executor_epoch,
                ..
            } if generation == lease.generation
                && executor == lease.executor
                && executor_epoch == lease.executor_epoch
        )
    }

    const fn stale_lease_error(lease: &ThreadExecutionLease) -> ThreadExecutionError {
        ThreadExecutionError::StaleLease {
            generation: lease.generation,
            executor: lease.executor,
            executor_epoch: lease.executor_epoch,
        }
    }

    fn fail_unsettled_execution_lease(
        &self,
        lease: &ThreadExecutionLease,
    ) -> Result<(), ThreadExecutionError> {
        let mut execution = self.execution.lock();
        if !Self::execution_state_matches_lease(execution.state, lease) {
            // FAIL LOUD instead of silently skipping: an unsettled lease
            // whose thread no longer matches leaves the thread PERMANENTLY
            // in its current transient state with no owner — the frozen
            // futexforkrequeue guests show exactly ten SwitchingOut
            // task_state=false threads, one per executor, created by this
            // silent return. Name the pair so the abandoning path is
            // attributable.
            eprintln!(
                "carrick: WARN: unsettled execution lease dropped for thread                  {:?} but state {:?} does not match lease (executor={:?}                  epoch={} generation={:?}) — thread left unowned",
                self.key, execution.state, lease.executor, lease.executor_epoch, lease.generation
            );
            return Ok(());
        }
        let Some(generation) = lease.generation.next() else {
            return Err(ThreadExecutionError::GenerationExhausted);
        };
        execution.task_state = None;
        cancel_continuation_slot(
            &mut execution.blocked_continuation,
            crate::vcpu_loop::continuation::CancellationCause::ServiceShutdown,
        );
        execution.exec_invalidation_pending = false;
        execution.control_quantum = None;
        execution.state = ThreadExecutionState::Failed {
            generation,
            reason: ExecutionFailure::UnsettledLeaseDropped {
                executor: lease.executor,
                executor_epoch: lease.executor_epoch,
            },
        };
        drop(execution);
        self.revision.publish();
        Ok(())
    }

    /// Invalidate the old image at exec publication. The replacement starts
    /// independently at `Uninitialized` and must receive freshly materialized
    /// entry state before it can be claimed.
    pub(in crate::kernel) fn invalidate_execution_for_exec(
        &self,
    ) -> Result<(), ThreadExecutionError> {
        let mut execution = self.execution.lock();
        if matches!(execution.state, ThreadExecutionState::SwitchingOut { .. }) {
            execution.exec_invalidation_pending = true;
            drop(execution);
            self.revision.publish();
            return Ok(());
        }
        let Some(generation) = execution
            .state
            .generation()
            .unwrap_or(ExecutionGeneration::INITIAL)
            .next()
        else {
            return Err(ThreadExecutionError::GenerationExhausted);
        };
        execution.task_state = None;
        cancel_continuation_slot(
            &mut execution.blocked_continuation,
            crate::vcpu_loop::continuation::CancellationCause::Exec,
        );
        execution.exec_invalidation_pending = false;
        execution.control_quantum = None;
        execution.state = ThreadExecutionState::Exited { generation };
        drop(execution);
        self.revision.publish();
        Ok(())
    }

    /// This thread's `KEY_SPEC_THREAD_KEYRING`, or `None` if it has never
    /// needed one.
    pub fn thread_keyring(&self) -> Option<KeySerial> {
        *self.thread_keyring.lock()
    }

    /// Materialise-or-read this thread's keyring under the thread lock, so two
    /// racing `KEYCTL_GET_KEYRING_ID(KEY_SPEC_THREAD_KEYRING, 1)` calls cannot
    /// leave the thread with two keyrings and leak the first — the shape
    /// `keyctl04` (CVE-2017-7472) checks for.
    pub fn with_thread_keyring<R>(&self, f: impl FnOnce(&mut Option<KeySerial>) -> R) -> R {
        f(&mut self.thread_keyring.lock())
    }

    /// Answer `generation` with this thread's exact architectural state. Only
    /// the thread itself may call this, from a safe point where its register
    /// file is readable.
    pub(crate) fn publish_crash_registers(
        &self,
        generation: CrashCaptureGeneration,
        registers: carrick_hal::Aarch64CoreRegisters,
    ) {
        *self.crash_vote.lock() = Some((
            generation,
            CrashRegisterVote::Published(Box::new(registers)),
        ));
        self.revision.publish();
    }

    /// Answer `generation` with "I cannot publish".
    ///
    /// Used by the park paths that reach the task-local quiesce barrier
    /// WITHOUT a readable register file — a thread waiting for a vCPU lease,
    /// or one parked while a sibling materialises. It will not resume before
    /// the barrier drops, so it can never publish for this generation, and a
    /// collector that kept waiting for it would time out and publish no core
    /// at all. An already-published vote wins: publishing then parking must
    /// not retract the register file.
    pub(crate) fn withdraw_from_crash_capture(&self, generation: CrashCaptureGeneration) {
        let mut vote = self.crash_vote.lock();
        if matches!(vote.as_ref(), Some((published, _)) if *published == generation) {
            return;
        }
        *vote = Some((generation, CrashRegisterVote::Withdrawn));
        self.revision.publish();
    }

    /// This thread's vote for `generation`, or `None` if it has not answered.
    pub(crate) fn crash_vote(
        &self,
        generation: CrashCaptureGeneration,
    ) -> Option<CrashRegisterVote> {
        self.crash_vote
            .lock()
            .as_ref()
            .filter(|(voted, _)| *voted == generation)
            .map(|(_, vote)| vote.clone())
    }

    /// Stash exact architectural registers when parking/suspending.
    pub(crate) fn stash_parked_registers(&self, registers: carrick_hal::Aarch64CoreRegisters) {
        *self.parked_registers.lock() = Some(registers);
    }

    /// Read stashed parked registers if present.
    pub(crate) fn parked_registers(&self) -> Option<carrick_hal::Aarch64CoreRegisters> {
        *self.parked_registers.lock()
    }

    /// Mint the exact generation owned by this live executor quantum.
    pub(super) fn enter_crash_safe_point_participation_raw(
        self: &Arc<Self>,
    ) -> Result<CrashSafePointParticipation, CrashSafePointParticipationError> {
        let raw = self
            .next_crash_safe_point_participation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                next.checked_add(1)
            })
            .map_err(|_| CrashSafePointParticipationError::IdentityExhausted {
                thread: self.key,
            })?;
        let id = CrashSafePointParticipationId(
            NonZeroU64::new(raw)
                .ok_or(CrashSafePointParticipationError::IdentityExhausted { thread: self.key })?,
        );
        self.crash_safe_point_participant
            .compare_exchange(0, id.0.get(), Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CrashSafePointParticipationError::AlreadyActive { thread: self.key })?;
        Ok(CrashSafePointParticipation {
            thread: Arc::clone(self),
            id,
        })
    }

    fn release_crash_safe_point_participation(
        &self,
        id: CrashSafePointParticipationId,
    ) -> CrashSafePointRelease {
        match self.crash_safe_point_participant.compare_exchange(
            id.0.get(),
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => CrashSafePointRelease::Released,
            Err(0) => CrashSafePointRelease::AlreadyRevoked,
            Err(_) => CrashSafePointRelease::Superseded,
        }
    }

    /// Revoke participation as the exact thread leaves the task graph. Its
    /// eventual stale guard observes zero and cannot affect a successor.
    pub(super) fn revoke_crash_safe_point_participation(&self) {
        self.crash_safe_point_participant.swap(0, Ordering::AcqRel);
    }

    /// Can this thread still reach a crash safe point?
    pub(crate) fn is_crash_safe_point_participant(&self) -> bool {
        self.crash_safe_point_participant.load(Ordering::Acquire) != 0
    }

    /// Guest USER CPU (µs) accumulated across every execution interval.
    pub fn cpu_us(&self) -> u64 {
        self.cpu_accounting.user_ns.load(Ordering::Acquire) / 1000
    }

    /// Mark this thread as executing guest code from now until its next
    /// [`Self::charge_user_ns`], which commits the run and closes the interval.
    pub fn begin_guest_run(&self) {
        self.cpu_accounting
            .active_since_ns
            .store(guest_run_clock_ns().max(1), Ordering::Release);
    }

    /// Charge guest execution CPU directly to this logical thread and close
    /// any open guest-run interval. Executor slots are intentionally not
    /// accounting identities.
    pub fn charge_user_ns(&self, delta_ns: u64) {
        if delta_ns != 0 {
            self.cpu_accounting
                .user_ns
                .fetch_add(delta_ns, Ordering::AcqRel);
        }
        self.cpu_accounting
            .active_since_ns
            .store(0, Ordering::Release);
    }

    /// Guest USER CPU (ns) including the guest run this thread is inside right
    /// now, if any. The committed total alone lags a spinning guest by the
    /// whole of its current run.
    pub fn cpu_ns_including_active(&self) -> u64 {
        self.sample_cpu_including_active().cpu_ns
    }

    /// [`Self::cpu_ns_including_active`] plus whether the thread is inside a
    /// guest run right now (so the figure is still growing).
    pub fn sample_cpu_including_active(&self) -> ThreadCpuSample {
        let committed = self.cpu_accounting.user_ns.load(Ordering::Acquire);
        let since = self.cpu_accounting.active_since_ns.load(Ordering::Acquire);
        if since == 0 {
            ThreadCpuSample {
                cpu_ns: committed,
                running_guest: false,
            }
        } else {
            ThreadCpuSample {
                cpu_ns: committed.saturating_add(guest_run_clock_ns().saturating_sub(since)),
                running_guest: true,
            }
        }
    }

    /// Guest SYSTEM CPU (µs) this thread has accumulated — carrick's own CPU
    /// spent servicing this thread's syscalls. See `system_ns`.
    pub fn system_cpu_us(&self) -> u64 {
        self.flush_open_system_charge();
        self.cpu_accounting.system_ns.load(Ordering::Acquire) / 1000
    }

    /// Guest SYSTEM CPU (ns) this thread has accumulated.
    pub fn system_cpu_ns(&self) -> u64 {
        self.flush_open_system_charge();
        self.cpu_accounting.system_ns.load(Ordering::Acquire)
    }

    /// Open — or keep open — this host thread's system-CPU charge window for
    /// this logical thread.
    ///
    /// Called at the outermost dispatch scope of every guest syscall. When the
    /// window already belongs to this exact thread (the overwhelmingly common
    /// case: an executor residency services many syscalls for one logical
    /// thread) this is a pointer comparison and costs NO host syscall. It
    /// samples the host CPU clock only when the charged identity changes,
    /// committing the departing thread's accrual first — an `execve` that
    /// replaces the thread object mid-residency lands on that path.
    pub fn open_system_charge_window(self: &ThreadRef) {
        let already_current = SYSTEM_CHARGE_WINDOW.with(|window| {
            window
                .borrow()
                .as_ref()
                .and_then(SystemChargeWindow::live)
                .is_some_and(|live| Arc::ptr_eq(&live, self))
        });
        if already_current {
            return;
        }
        // The charged identity is changing, so the departing window has to be
        // settled before the clock reading is reused as the new baseline.
        close_system_charge_window();
        let opened = SystemChargeWindow {
            thread: Arc::downgrade(self),
            opened_at_host_cpu_ns: carrick_host::guest_cpu::this_thread_cpu_ns(),
            opened_at_wall_ns: guest_run_clock_ns(),
            opened_at_user_ns: self.cpu_ns_including_active(),
            charged_ns: 0,
        };
        SYSTEM_CHARGE_WINDOW.with(|window| *window.borrow_mut() = Some(opened));
    }

    /// Commit what this host thread has burned so far in an open charge window
    /// that belongs to THIS logical thread, and restart the window from now.
    ///
    /// Every read of the counter goes through here, so a guest asking for its
    /// own `getrusage`/`times`/`CLOCK_THREAD_CPUTIME_ID` sees the service time
    /// of the residency it is inside rather than only what earlier residencies
    /// committed. A read from any OTHER host thread cannot sample this thread's
    /// CPU clock and so still reports the committed total — the same lag a
    /// peer read has always had while a syscall is in flight.
    fn flush_open_system_charge(&self) {
        let delta_ns = SYSTEM_CHARGE_WINDOW.with(|window| {
            let mut window = window.borrow_mut();
            let Some(open) = window.as_mut() else {
                return 0;
            };
            let Some(live) = open.live() else {
                return 0;
            };
            if !std::ptr::eq(Arc::as_ptr(&live), self as *const Self) {
                return 0;
            }
            let (uncommitted_ns, accrued_ns) = open.pending(&live);
            open.charged_ns = accrued_ns;
            uncommitted_ns
        });
        self.charge_system_ns(delta_ns);
    }

    /// Guest USER + SYSTEM CPU (ns) including any active guest run.
    pub fn total_cpu_ns_including_active(&self) -> u64 {
        self.cpu_ns_including_active()
            .saturating_add(self.system_cpu_ns())
    }

    /// Commit `delta_ns` of syscall-service CPU to this thread.
    ///
    /// The delta is measured on the host thread's own CPU clock, so time a
    /// syscall spends BLOCKED contributes nothing, exactly as on Linux. The
    /// callers are the charge window (`open_system_charge_window`,
    /// `flush_open_system_charge`, `close_system_charge_window`) and any
    /// backend whose executor returns a non-zero `ExecutorCpuReceipt`.
    pub fn charge_system_ns(&self, delta_ns: u64) {
        if delta_ns != 0 {
            self.cpu_accounting
                .system_ns
                .fetch_add(delta_ns, Ordering::AcqRel);
        }
    }

    pub const fn registry_id(&self) -> ThreadId {
        self.registry_id
    }

    pub const fn task_key(&self) -> TaskKey {
        self.task_key
    }

    pub fn signal_state(&self) -> ThreadSignalState {
        self.signal_state.lock().clone()
    }

    pub fn may_have_pending_signals(&self) -> bool {
        self.signal_pending_hint.load(Ordering::Acquire) != 0
    }

    pub fn replace_signal_state(&self, replacement: ThreadSignalState) {
        let mut state = self.signal_state.lock();
        self.signal_pending_hint
            .store(replacement.pending().raw(), Ordering::Release);
        *state = replacement;
        self.revision.publish();
    }

    pub(crate) fn update_signal_state<R>(
        &self,
        operation: impl FnOnce(&mut ThreadSignalState) -> R,
    ) -> R {
        let mut state = self.signal_state.lock();
        let result = operation(&mut state);
        self.publish_signal_state(&state);
        result
    }

    pub(in crate::kernel) fn publish_signal_state(&self, state: &ThreadSignalState) {
        self.signal_pending_hint
            .store(state.pending().raw(), Ordering::Release);
        self.revision.publish();
        debug_assert_eq!(
            self.signal_pending_hint.load(Ordering::Relaxed),
            state.pending().raw()
        );
    }

    pub fn bind_runner(self: &Arc<Self>) -> Result<ThreadRunner, ObjectGraphError> {
        self.runner_gate.bind(self.key, Arc::clone(self))
    }

    pub(in crate::kernel) fn transfer_runner_to(
        &self,
        replacement: &ThreadRef,
    ) -> Result<(), ThreadExecutionError> {
        debug_assert!(Arc::ptr_eq(&self.runner_gate, &replacement.runner_gate));
        self.invalidate_execution_for_exec()?;
        self.runner_gate.transfer_owner(self.key, replacement.key);
        Ok(())
    }

    pub fn task(&self) -> Option<TaskRef> {
        self.task.upgrade()
    }

    pub(in crate::kernel) fn resources(&self) -> Arc<ThreadResources> {
        self.resources.load_full()
    }

    pub(in crate::kernel) fn snapshot_signal_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, ThreadSignalState)> {
        let state = self.signal_state.try_lock_until(deadline)?;
        Some((self.revision.load(), state.clone()))
    }

    pub(in crate::kernel) fn revision(&self) -> u64 {
        self.revision.load()
    }

    pub(in crate::kernel) fn replace_resources(
        &self,
        replacement: Arc<ThreadResources>,
    ) -> Arc<ThreadResources> {
        let previous = self.resources.swap(replacement);
        self.revision.publish();
        previous
    }

    pub(in crate::kernel) fn runner_gate(&self) -> Arc<RunnerGate> {
        Arc::clone(&self.runner_gate)
    }

    pub(in crate::kernel) fn accepts_unhandled_signal(&self, signal: LinuxSignal) -> bool {
        if self.signal_state.lock().blocked().contains(signal.raw()) {
            return true;
        }
        if let Some(continuation) = self.execution.lock().blocked_continuation.as_ref() {
            if continuation.is_waiting_for_signal(signal) {
                return true;
            }
        }
        false
    }

    pub(in crate::kernel) fn prepare(
        task: &Arc<Task>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
    ) -> ThreadRef {
        Arc::new(Thread {
            key,
            registry_id,
            task_key: task.key(),
            task: Arc::downgrade(task),
            resources: ArcSwap::new(resources),
            signal_state: Mutex::new(ThreadSignalState::default()),
            signal_pending_hint: AtomicU64::new(0),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
            start_gate_open: AtomicBool::new(true),
            start_gate_proof_generation: AtomicU64::new(0),
            execution: Mutex::new(ThreadExecutionRecord::uninitialized()),
            cpu_accounting: Arc::new(ThreadCpuAccounting::default()),
            crash_vote: Mutex::new(None),
            parked_registers: Mutex::new(None),
            crash_safe_point_participant: AtomicU64::new(0),
            next_crash_safe_point_participation: AtomicU64::new(1),
            thread_keyring: Mutex::new(None),
            last_cpu: AtomicU32::new(u32::MAX),
            affinity: RwLock::new(CpuAffinity::all(crate::kernel::scheduler::guest_cpu_count())),
        })
    }

    pub(in crate::kernel) fn prepare_clone(
        task: &Arc<Task>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller_signal_state: ThreadSignalState,
        caller_affinity: CpuAffinity,
    ) -> ThreadRef {
        Arc::new(Thread {
            key,
            registry_id,
            task_key: task.key(),
            task: Arc::downgrade(task),
            resources: ArcSwap::new(resources),
            signal_state: Mutex::new(ThreadSignalState::for_clone_thread(&caller_signal_state)),
            signal_pending_hint: AtomicU64::new(0),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
            start_gate_open: AtomicBool::new(false),
            start_gate_proof_generation: AtomicU64::new(0),
            execution: Mutex::new(ThreadExecutionRecord::uninitialized()),
            cpu_accounting: Arc::new(ThreadCpuAccounting::default()),
            crash_vote: Mutex::new(None),
            parked_registers: Mutex::new(None),
            crash_safe_point_participant: AtomicU64::new(0),
            next_crash_safe_point_participation: AtomicU64::new(1),
            thread_keyring: Mutex::new(None),
            last_cpu: AtomicU32::new(u32::MAX),
            affinity: RwLock::new(caller_affinity),
        })
    }

    pub(in crate::kernel) fn prepare_fork(
        task: &Arc<Task>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller_signal_state: ThreadSignalState,
        caller_affinity: CpuAffinity,
    ) -> ThreadRef {
        Arc::new(Thread {
            key,
            registry_id,
            task_key: task.key(),
            task: Arc::downgrade(task),
            resources: ArcSwap::new(resources),
            signal_state: Mutex::new(ThreadSignalState::for_fork(&caller_signal_state)),
            signal_pending_hint: AtomicU64::new(0),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
            start_gate_open: AtomicBool::new(false),
            start_gate_proof_generation: AtomicU64::new(0),
            execution: Mutex::new(ThreadExecutionRecord::uninitialized()),
            cpu_accounting: Arc::new(ThreadCpuAccounting::default()),
            crash_vote: Mutex::new(None),
            parked_registers: Mutex::new(None),
            crash_safe_point_participant: AtomicU64::new(0),
            next_crash_safe_point_participation: AtomicU64::new(1),
            thread_keyring: Mutex::new(None),
            last_cpu: AtomicU32::new(u32::MAX),
            affinity: RwLock::new(caller_affinity),
        })
    }

    pub(in crate::kernel) fn prepare_exec(
        task: &Arc<Task>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller: &ThreadRef,
    ) -> ThreadRef {
        Arc::new(Thread {
            key,
            registry_id,
            task_key: task.key(),
            task: Arc::downgrade(task),
            resources: ArcSwap::new(resources),
            signal_state: Mutex::new(ThreadSignalState::for_exec(&caller.signal_state())),
            signal_pending_hint: AtomicU64::new(caller.signal_pending_hint.load(Ordering::Acquire)),
            revision: ObjectRevision::new(),
            runner_gate: Arc::clone(&caller.runner_gate),
            start_gate_open: AtomicBool::new(true),
            start_gate_proof_generation: AtomicU64::new(0),
            execution: Mutex::new(ThreadExecutionRecord::uninitialized()),
            cpu_accounting: Arc::clone(&caller.cpu_accounting),
            crash_vote: Mutex::new(None),
            parked_registers: Mutex::new(None),
            crash_safe_point_participant: AtomicU64::new(0),
            next_crash_safe_point_participation: AtomicU64::new(1),
            thread_keyring: Mutex::new(None),
            last_cpu: AtomicU32::new(u32::MAX),
            affinity: RwLock::new(caller.affinity()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::container::{Container, LaunchContext, RunId};
    use crate::kernel::ids::{ChildExitSignal, ObjectIdRegistry, TaskId};
    use crate::kernel::objects::process::Mm;
    use crate::kernel::objects::signal::Sighand;
    use crate::kernel::objects::{Credentials, FileTable, FsContext, TaskIdentity};

    struct Fixture {
        _ids: ObjectIdRegistry,
        _task: TaskRef,
        leader: ThreadRef,
    }

    impl Fixture {
        fn new() -> Self {
            let ids = ObjectIdRegistry::new();
            let task_id = TaskId::for_root_bootstrap(100).expect("task ID");
            let key = TaskKey {
                id: task_id,
                serial: ids.task_serial().expect("task serial"),
            };
            let mm = Arc::new(Mm::new_reference(ids.mm_id().expect("mm ID")));
            let sighand = Arc::new(Sighand::new(ids.sighand_id().expect("sighand ID")));
            let shared = Arc::new(crate::kernel::objects::TaskShared::new(mm, sighand));
            let resources = Arc::new(ThreadResources::new(
                Arc::new(FileTable::new(ids.file_table_id().expect("files ID"))),
                Arc::new(FsContext::new(ids.fs_context_id().expect("fs ID"))),
                Arc::new(Credentials::root(
                    ids.credentials_id().expect("credentials ID"),
                )),
            ));
            let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
                "objects-fixture",
            ))));
            let task = Arc::new(Task::new(
                key,
                None,
                TaskIdentity::led_by(task_id),
                shared,
                resources.credentials(),
                container,
                ChildExitSignal::SIGCHLD,
            ));
            let leader = task
                .attach_thread(
                    ThreadKey {
                        tid: LinuxTid::for_task_leader(task_id),
                        serial: ids.thread_serial().expect("thread serial"),
                    },
                    ThreadId::synthetic_for_tests(100),
                    resources,
                )
                .expect("leader thread");
            Self {
                _ids: ids,
                _task: task,
                leader,
            }
        }
    }

    #[test]
    fn stale_crash_participation_release_cannot_clear_a_successor() {
        let fixture = Fixture::new();
        let first = Arc::clone(&fixture.leader)
            .enter_crash_safe_point_participation()
            .expect("first participation");
        let first_id = first.id_for_test();

        fixture.leader.revoke_crash_safe_point_participation();
        let second = Arc::clone(&fixture.leader)
            .enter_crash_safe_point_participation()
            .expect("successor participation");

        assert_eq!(
            fixture
                .leader
                .release_crash_safe_point_participation(first_id),
            CrashSafePointRelease::Superseded
        );
        assert!(fixture.leader.is_crash_safe_point_participant());

        std::mem::forget(first);
        drop(second);
        assert!(!fixture.leader.is_crash_safe_point_participant());
    }

    #[test]
    fn thread_invalidate_execution_for_exec_exhausted_generation() {
        let fixture = Fixture::new();
        {
            let mut exec = fixture.leader.execution.lock();
            exec.state = ThreadExecutionState::Runnable {
                generation: ExecutionGeneration::from_raw(u64::MAX),
            };
        }
        let res = fixture.leader.invalidate_execution_for_exec();
        assert_eq!(res, Err(ThreadExecutionError::GenerationExhausted));
    }

    #[test]
    fn thread_fail_unsettled_execution_lease_exhausted_generation() {
        let fixture = Fixture::new();
        let executor = ExecutorId::synthetic_for_tests(77);
        let generation = ExecutionGeneration::from_raw(u64::MAX);
        {
            let mut exec = fixture.leader.execution.lock();
            exec.state = ThreadExecutionState::Running {
                generation,
                executor,
                executor_epoch: 1,
                wake_pending: false,
            };
        }
        let lease = ThreadExecutionLease {
            owner: Arc::downgrade(&fixture.leader),
            owner_key: fixture.leader.key(),
            generation,
            executor,
            executor_epoch: 1,
            task_state: None,
            blocked_continuation: None,
            settled: true,
        };
        let res = fixture.leader.fail_unsettled_execution_lease(&lease);
        assert_eq!(res, Err(ThreadExecutionError::GenerationExhausted));
    }
}
