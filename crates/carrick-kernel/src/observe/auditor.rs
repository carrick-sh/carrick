//! Kernel auditor surface and lifecycle judgement.
//!
//! Kernel auditors observe internal kernel-graph lifecycle events and evaluate
//! structural invariants. Implementations are pure judgement: they return
//! [`AuditVerdict::Continue`] or [`AuditVerdict::Abort`] with a typed [`AuditReason`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use crate::kernel::objects::{ExecutionGeneration, ExecutorId, LinuxWaitStatus, TaskKey};

// The guest CPU the auditor surface names is the SAME identity the scheduler
// places tasks on and the guest reads back through `sched_getcpu`. There is one
// definition of it, in `carrick-hal`; a second copy compiled into this crate
// would make `crate::observe::GuestCpuId` a different type from the one the run
// queue hands out and force a placeholder at every emit site.
pub use carrick_hal::scheduler::GuestCpuId;

/// The kind of process or thread creation admitted by the kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ForkKind {
    Fork,
    Vfork,
    Thread,
}

impl fmt::Display for ForkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fork => write!(f, "fork"),
            Self::Vfork => write!(f, "vfork"),
            Self::Thread => write!(f, "thread"),
        }
    }
}

/// The entity claiming or owning an exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExitOwner {
    Nobody,
    Task(TaskKey),
}

impl From<Option<TaskKey>> for ExitOwner {
    fn from(opt: Option<TaskKey>) -> Self {
        match opt {
            Some(key) => Self::Task(key),
            None => Self::Nobody,
        }
    }
}

impl fmt::Display for ExitOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nobody => write!(f, "nobody"),
            Self::Task(key) => write!(f, "task({key})"),
        }
    }
}

/// Who the kernel recorded as able to reap a zombie at its publication.
///
/// An observer cannot derive this from the [`TaskKey`] alone. `TaskKey::id` is
/// a carrier-global allocation, NOT an ns-pid, so "is this pid 1" is not a test
/// an auditor can perform: in a carrier running two containers the second
/// container's init has an id far above 1, and in a nested pid namespace the
/// numeric identity an observer sees is not the one the guest sees. The kernel
/// therefore states the answer rather than inviting every auditor to guess it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ZombieReaper {
    /// A live parent task, which will observe the exit through `wait(2)`.
    Parent(TaskKey),
    /// The zombie has no parent, and no live pid-namespace init could have
    /// adopted it — it either IS its container's init, or its init exited
    /// first and left it behind. Carrick's container retirement is the reaper
    /// of last resort for both, so the zombie is still consumed, exactly once.
    ContainerRetirement,
    /// The zombie has no parent even though its pid-namespace init was live
    /// and should have adopted it: a dropped reparent edge, which no waiter and
    /// no retirement path will ever consume.
    Unreapable,
}

impl std::fmt::Display for ZombieReaper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parent(key) => write!(f, "parent({key})"),
            Self::ContainerRetirement => write!(f, "container-retirement"),
            Self::Unreapable => write!(f, "unreapable"),
        }
    }
}

/// Why a scheduler wake attempt was rejected.
///
/// `Exited` and `Reaped` are the whole point of this type. A wake that loses
/// a race with its target's exit is ORDINARY -- Linux drops a signal, an mq
/// notification or a futex wake aimed at a task that has just left, and so
/// does carrick. A wake aimed at an identity the graph no longer owns is a
/// DEFECT: the waker is holding an authority that outlived the thing it
/// names, and the next allocation of that identity would receive the wake.
/// Collapsing the two made [`crate::observe::KernelAuditor::wake_rejected`]
/// unable to state which one it saw.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum WakeRejectionReason {
    /// The target is still in the kernel graph but can never run again: its
    /// thread's typed execution state is terminal, its thread has retired
    /// while its task lives, or its task is a zombie awaiting a `wait`. A
    /// no-op, not a defect.
    Exited,
    /// The target identity is gone from the graph entirely -- no live task,
    /// no zombie, no retired thread owns it. The waker's authority is stale.
    Reaped,
    Closed,
    StaleGeneration,
    UnknownThread,
    Other(String),
}

impl fmt::Display for WakeRejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited => write!(f, "exited"),
            Self::Reaped => write!(f, "reaped"),
            Self::Closed => write!(f, "closed"),
            Self::StaleGeneration => write!(f, "stale_generation"),
            Self::UnknownThread => write!(f, "unknown_thread"),
            Self::Other(msg) => write!(f, "other({msg})"),
        }
    }
}

/// Re-export the typed first-touch delivery reason.
pub use carrick_observability::probes::HvpatchFirstTouchDeliverReason as FirstTouchDeliverReason;

/// Typed rationale for an auditor abort.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditReason {
    OrphanZombie {
        task: TaskKey,
    },
    ProcessGraphEmptyWithUnpublishedJobs {
        unpublished_jobs: usize,
    },
    WakeOfReapedTask {
        target: TaskKey,
    },
    FirstTouchRefused {
        task: TaskKey,
        addr: u64,
    },
    ChildNeverRan {
        child: TaskKey,
        within: std::time::Duration,
    },
    ExitBudgetExceeded {
        task: TaskKey,
        within: std::time::Duration,
    },
    Custom(String),
}

impl fmt::Display for AuditReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrphanZombie { task } => {
                write!(
                    f,
                    "orphan zombie {task} has no reaper: no parent, and its pid-namespace init was still live"
                )
            }
            Self::ProcessGraphEmptyWithUnpublishedJobs { unpublished_jobs } => {
                write!(
                    f,
                    "process graph empty while {unpublished_jobs} unpublished jobs remain"
                )
            }
            Self::WakeOfReapedTask { target } => {
                write!(f, "wake rejected because task {target} was already reaped")
            }
            Self::FirstTouchRefused { task, addr } => {
                write!(
                    f,
                    "first-touch publication refused lowered to SIGSEGV: task={task}, addr=0x{addr:x}"
                )
            }
            Self::ChildNeverRan { child, within } => {
                write!(f, "child {child} never reached first run within {within:?}")
            }
            Self::ExitBudgetExceeded { task, within } => {
                write!(f, "task {task} exceeded exit budget of {within:?}")
            }
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<String> for AuditReason {
    fn from(msg: String) -> Self {
        Self::Custom(msg)
    }
}

impl From<&str> for AuditReason {
    fn from(msg: &str) -> Self {
        Self::Custom(msg.to_owned())
    }
}

/// The verdict returned by a [`KernelAuditor`] callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditVerdict {
    Continue,
    Abort(AuditReason),
}

impl AuditVerdict {
    pub const fn is_continue(&self) -> bool {
        matches!(self, Self::Continue)
    }

    pub const fn is_abort(&self) -> bool {
        matches!(self, Self::Abort(_))
    }
}

/// Trait for observing and judging kernel-graph lifecycle transitions.
///
/// Implementors only override the events they care about; all methods default to
/// no-ops returning [`AuditVerdict::Continue`].
pub trait KernelAuditor: Send + Sync {
    fn fork_admitted(&self, _parent: TaskKey, _child: TaskKey, _kind: ForkKind) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn child_first_run(
        &self,
        _child: TaskKey,
        _executor: ExecutorId,
        _cpu: GuestCpuId,
    ) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn exec_committed(
        &self,
        _task: TaskKey,
        _generation_before: ExecutionGeneration,
        _generation_after: ExecutionGeneration,
    ) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn exit_settled(
        &self,
        _task: TaskKey,
        _status: LinuxWaitStatus,
        _owner: ExitOwner,
    ) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn zombie_created(&self, _task: TaskKey, _reaper: ZombieReaper) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn reaped(&self, _parent: TaskKey, _child: TaskKey) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn wake_rejected(&self, _target: TaskKey, _reason: WakeRejectionReason) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn executor_parked(
        &self,
        _executor: ExecutorId,
        _cpu: GuestCpuId,
        _task: Option<TaskKey>,
    ) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn executor_claimed(
        &self,
        _executor: ExecutorId,
        _cpu: GuestCpuId,
        _task: TaskKey,
    ) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn first_touch_delivered(
        &self,
        _task: TaskKey,
        _addr: u64,
        _reason: FirstTouchDeliverReason,
    ) -> AuditVerdict {
        AuditVerdict::Continue
    }
    fn process_graph_empty(&self, _unpublished_jobs: usize) -> AuditVerdict {
        AuditVerdict::Continue
    }
}

/// An ordered chain of [`KernelAuditor`]s.
#[derive(Clone, Default)]
pub struct AuditorChain {
    auditors: Vec<Arc<dyn KernelAuditor>>,
    abort_reason: Arc<Mutex<Option<AuditReason>>>,
}

impl fmt::Debug for AuditorChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditorChain")
            .field("auditors_len", &self.auditors.len())
            .field("abort_reason", &self.abort_reason.lock())
            .finish()
    }
}

impl AuditorChain {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(auditors: Vec<Arc<dyn KernelAuditor>>) -> Self {
        Self {
            auditors,
            abort_reason: Arc::new(Mutex::new(None)),
        }
    }

    pub fn push(&mut self, auditor: Arc<dyn KernelAuditor>) {
        self.auditors.push(auditor);
    }

    pub fn is_empty(&self) -> bool {
        self.auditors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.auditors.len()
    }

    pub fn abort_reason(&self) -> Option<AuditReason> {
        self.abort_reason.lock().clone()
    }

    pub fn abort_reason_slot(&self) -> &Arc<Mutex<Option<AuditReason>>> {
        &self.abort_reason
    }

    pub fn record_abort(&self, reason: AuditReason) {
        let mut guard = self.abort_reason.lock();
        if guard.is_none() {
            *guard = Some(reason);
        }
    }

    fn check_or_record(&self, verdict: AuditVerdict) -> AuditVerdict {
        if let AuditVerdict::Abort(ref reason) = verdict {
            self.record_abort(reason.clone());
        }
        verdict
    }

    pub fn fork_admitted(&self, parent: TaskKey, child: TaskKey, kind: ForkKind) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.fork_admitted(parent, child, kind);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn child_first_run(
        &self,
        child: TaskKey,
        executor: ExecutorId,
        cpu: GuestCpuId,
    ) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.child_first_run(child, executor, cpu);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn exec_committed(
        &self,
        task: TaskKey,
        generation_before: ExecutionGeneration,
        generation_after: ExecutionGeneration,
    ) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.exec_committed(task, generation_before, generation_after);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn exit_settled(
        &self,
        task: TaskKey,
        status: LinuxWaitStatus,
        owner: ExitOwner,
    ) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.exit_settled(task, status, owner);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn zombie_created(&self, task: TaskKey, reaper: ZombieReaper) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.zombie_created(task, reaper);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn reaped(&self, parent: TaskKey, child: TaskKey) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.reaped(parent, child);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn wake_rejected(&self, target: TaskKey, reason: WakeRejectionReason) -> AuditVerdict {
        if let Some(reason_prior) = self.abort_reason() {
            return AuditVerdict::Abort(reason_prior);
        }
        for auditor in &self.auditors {
            let verdict = auditor.wake_rejected(target, reason.clone());
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn executor_parked(
        &self,
        executor: ExecutorId,
        cpu: GuestCpuId,
        task: Option<TaskKey>,
    ) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.executor_parked(executor, cpu, task);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn executor_claimed(
        &self,
        executor: ExecutorId,
        cpu: GuestCpuId,
        task: TaskKey,
    ) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.executor_claimed(executor, cpu, task);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn first_touch_delivered(
        &self,
        task: TaskKey,
        addr: u64,
        reason: FirstTouchDeliverReason,
    ) -> AuditVerdict {
        if let Some(reason_prior) = self.abort_reason() {
            return AuditVerdict::Abort(reason_prior);
        }
        for auditor in &self.auditors {
            let verdict = auditor.first_touch_delivered(task, addr, reason);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }

    pub fn process_graph_empty(&self, unpublished_jobs: usize) -> AuditVerdict {
        if let Some(reason) = self.abort_reason() {
            return AuditVerdict::Abort(reason);
        }
        for auditor in &self.auditors {
            let verdict = auditor.process_graph_empty(unpublished_jobs);
            if !verdict.is_continue() {
                return self.check_or_record(verdict);
            }
        }
        AuditVerdict::Continue
    }
}

static CONTAINER_AUDITORS: RwLock<Option<BTreeMap<carrick_hal::ContainerId, Arc<AuditorChain>>>> =
    RwLock::new(None);

pub fn register_container_auditors(
    container_id: carrick_hal::ContainerId,
    chain: Arc<AuditorChain>,
) {
    let mut guard = CONTAINER_AUDITORS.write();
    guard
        .get_or_insert_with(BTreeMap::new)
        .insert(container_id, chain);
}

pub fn unregister_container_auditors(container_id: carrick_hal::ContainerId) {
    if let Some(map) = CONTAINER_AUDITORS.write().as_mut() {
        map.remove(&container_id);
    }
}

pub fn get_container_auditors(container_id: carrick_hal::ContainerId) -> Arc<AuditorChain> {
    CONTAINER_AUDITORS
        .read()
        .as_ref()
        .and_then(|map| map.get(&container_id).cloned())
        .unwrap_or_else(|| Arc::new(AuditorChain::empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::ids::{TaskId, TaskSerial};
    use crate::kernel::objects::{ExecutionGeneration, ExecutorId, LinuxWaitStatus, TaskKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestAuditor {
        fork_admitted_count: AtomicUsize,
        child_first_run_count: AtomicUsize,
        exec_committed_count: AtomicUsize,
        exit_settled_count: AtomicUsize,
        zombie_created_count: AtomicUsize,
        reaped_count: AtomicUsize,
        wake_rejected_count: AtomicUsize,
        executor_parked_count: AtomicUsize,
        executor_claimed_count: AtomicUsize,
        first_touch_count: AtomicUsize,
        graph_empty_count: AtomicUsize,
        abort_on_zombie: bool,
    }

    impl TestAuditor {
        fn new(abort_on_zombie: bool) -> Self {
            Self {
                fork_admitted_count: AtomicUsize::new(0),
                child_first_run_count: AtomicUsize::new(0),
                exec_committed_count: AtomicUsize::new(0),
                exit_settled_count: AtomicUsize::new(0),
                zombie_created_count: AtomicUsize::new(0),
                reaped_count: AtomicUsize::new(0),
                wake_rejected_count: AtomicUsize::new(0),
                executor_parked_count: AtomicUsize::new(0),
                executor_claimed_count: AtomicUsize::new(0),
                first_touch_count: AtomicUsize::new(0),
                graph_empty_count: AtomicUsize::new(0),
                abort_on_zombie,
            }
        }
    }

    impl KernelAuditor for TestAuditor {
        fn fork_admitted(
            &self,
            _parent: TaskKey,
            _child: TaskKey,
            _kind: ForkKind,
        ) -> AuditVerdict {
            self.fork_admitted_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn child_first_run(
            &self,
            _child: TaskKey,
            _executor: ExecutorId,
            _cpu: GuestCpuId,
        ) -> AuditVerdict {
            self.child_first_run_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn exec_committed(
            &self,
            _task: TaskKey,
            _gen_before: ExecutionGeneration,
            _gen_after: ExecutionGeneration,
        ) -> AuditVerdict {
            self.exec_committed_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn exit_settled(
            &self,
            _task: TaskKey,
            _status: LinuxWaitStatus,
            _owner: ExitOwner,
        ) -> AuditVerdict {
            self.exit_settled_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn zombie_created(&self, task: TaskKey, _reaper: ZombieReaper) -> AuditVerdict {
            self.zombie_created_count.fetch_add(1, Ordering::SeqCst);
            if self.abort_on_zombie {
                AuditVerdict::Abort(AuditReason::OrphanZombie { task })
            } else {
                AuditVerdict::Continue
            }
        }

        fn reaped(&self, _parent: TaskKey, _child: TaskKey) -> AuditVerdict {
            self.reaped_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn wake_rejected(&self, _target: TaskKey, _reason: WakeRejectionReason) -> AuditVerdict {
            self.wake_rejected_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn executor_parked(
            &self,
            _executor: ExecutorId,
            _cpu: GuestCpuId,
            _task: Option<TaskKey>,
        ) -> AuditVerdict {
            self.executor_parked_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn executor_claimed(
            &self,
            _executor: ExecutorId,
            _cpu: GuestCpuId,
            _task: TaskKey,
        ) -> AuditVerdict {
            self.executor_claimed_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn first_touch_delivered(
            &self,
            _task: TaskKey,
            _addr: u64,
            _reason: FirstTouchDeliverReason,
        ) -> AuditVerdict {
            self.first_touch_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }

        fn process_graph_empty(&self, _unpublished_jobs: usize) -> AuditVerdict {
            self.graph_empty_count.fetch_add(1, Ordering::SeqCst);
            AuditVerdict::Continue
        }
    }

    fn sample_task_key(pid: i32, serial: u64) -> TaskKey {
        TaskKey {
            id: TaskId::from_abi_positive(pid).unwrap(),
            serial: TaskSerial::from_raw_u64(serial).unwrap(),
        }
    }

    #[test]
    fn test_auditor_chain_all_ten_events_dispatch() {
        let auditor = Arc::new(TestAuditor::new(false));
        let chain = AuditorChain::new(vec![Arc::clone(&auditor) as Arc<dyn KernelAuditor>]);

        let parent = sample_task_key(10, 100);
        let child = sample_task_key(11, 101);
        let exec_id = ExecutorId::synthetic_for_tests(1);
        let cpu = GuestCpuId::new(0);

        assert!(
            chain
                .fork_admitted(parent, child, ForkKind::Fork)
                .is_continue()
        );
        assert_eq!(auditor.fork_admitted_count.load(Ordering::SeqCst), 1);

        assert!(chain.child_first_run(child, exec_id, cpu).is_continue());
        assert_eq!(auditor.child_first_run_count.load(Ordering::SeqCst), 1);

        assert!(
            chain
                .exec_committed(
                    child,
                    ExecutionGeneration::INITIAL,
                    ExecutionGeneration::INITIAL
                )
                .is_continue()
        );
        assert_eq!(auditor.exec_committed_count.load(Ordering::SeqCst), 1);

        assert!(chain.executor_claimed(exec_id, cpu, child).is_continue());
        assert_eq!(auditor.executor_claimed_count.load(Ordering::SeqCst), 1);

        assert!(chain.executor_parked(exec_id, cpu, None).is_continue());
        assert_eq!(auditor.executor_parked_count.load(Ordering::SeqCst), 1);

        assert!(
            chain
                .first_touch_delivered(child, 0x1000, FirstTouchDeliverReason::BackendRefused)
                .is_continue()
        );
        assert_eq!(auditor.first_touch_count.load(Ordering::SeqCst), 1);

        assert!(
            chain
                .zombie_created(child, ZombieReaper::Parent(parent))
                .is_continue()
        );
        assert_eq!(auditor.zombie_created_count.load(Ordering::SeqCst), 1);

        let wait_status = LinuxWaitStatus::from_wait_encoding(0);
        assert!(
            chain
                .exit_settled(child, wait_status, ExitOwner::Task(parent))
                .is_continue()
        );
        assert_eq!(auditor.exit_settled_count.load(Ordering::SeqCst), 1);

        assert!(chain.reaped(parent, child).is_continue());
        assert_eq!(auditor.reaped_count.load(Ordering::SeqCst), 1);

        assert!(
            chain
                .wake_rejected(child, WakeRejectionReason::Reaped)
                .is_continue()
        );
        assert_eq!(auditor.wake_rejected_count.load(Ordering::SeqCst), 1);

        assert!(chain.process_graph_empty(0).is_continue());
        assert_eq!(auditor.graph_empty_count.load(Ordering::SeqCst), 1);

        assert!(chain.abort_reason().is_none());
    }

    #[test]
    fn test_auditor_chain_abort_propagation() {
        let auditor = Arc::new(TestAuditor::new(true));
        let chain = AuditorChain::new(vec![Arc::clone(&auditor) as Arc<dyn KernelAuditor>]);

        let parent = sample_task_key(10, 100);
        let child = sample_task_key(11, 101);

        assert!(
            chain
                .fork_admitted(parent, child, ForkKind::Fork)
                .is_continue()
        );

        // zombie_created returns Abort
        let verdict = chain.zombie_created(child, ZombieReaper::Unreapable);
        assert_eq!(
            verdict,
            AuditVerdict::Abort(AuditReason::OrphanZombie { task: child })
        );
        assert_eq!(
            chain.abort_reason(),
            Some(AuditReason::OrphanZombie { task: child })
        );

        // Subsequent callbacks immediately short-circuit with the recorded Abort
        let follow_up = chain.fork_admitted(parent, child, ForkKind::Fork);
        assert_eq!(
            follow_up,
            AuditVerdict::Abort(AuditReason::OrphanZombie { task: child })
        );
        // auditor callback was not called again for fork_admitted
        assert_eq!(auditor.fork_admitted_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_container_auditors_registry() {
        let cid = carrick_hal::ContainerId::allocate();
        let chain = Arc::new(AuditorChain::empty());

        register_container_auditors(cid, Arc::clone(&chain));
        let retrieved = get_container_auditors(cid);
        assert_eq!(retrieved.len(), 0);

        unregister_container_auditors(cid);
        let default_chain = get_container_auditors(cid);
        assert_eq!(default_chain.len(), 0);
    }

    #[test]
    fn test_displays() {
        let parent = sample_task_key(1, 10);
        assert_eq!(ForkKind::Fork.to_string(), "fork");
        assert_eq!(ForkKind::Vfork.to_string(), "vfork");
        assert_eq!(ForkKind::Thread.to_string(), "thread");

        assert_eq!(ExitOwner::Nobody.to_string(), "nobody");
        assert_eq!(
            ExitOwner::Task(parent).to_string(),
            format!("task({parent})")
        );

        assert_eq!(WakeRejectionReason::Exited.to_string(), "exited");
        assert_eq!(WakeRejectionReason::Reaped.to_string(), "reaped");
        assert_eq!(WakeRejectionReason::Closed.to_string(), "closed");
        assert_eq!(
            WakeRejectionReason::StaleGeneration.to_string(),
            "stale_generation"
        );
        assert_eq!(
            WakeRejectionReason::UnknownThread.to_string(),
            "unknown_thread"
        );

        let reason = AuditReason::OrphanZombie { task: parent };
        let rendered = reason.to_string();
        assert!(rendered.contains("orphan zombie"));
        // The reason names WHY it is orphaned. "not pid 1" used to appear
        // here and was wrong: `TaskKey::id` is a carrier-global allocation,
        // never an ns-pid.
        assert!(rendered.contains("pid-namespace init was still live"));
        assert!(!rendered.contains("pid 1"));
    }
}
