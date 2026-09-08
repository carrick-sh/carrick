//! Built-in kernel invariants for testing and embedded container execution.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use carrick_runtime::kernel::objects::{ExecutionGeneration, ExecutorId, TaskKey};
use carrick_runtime::observe::{
    AuditReason, AuditVerdict, ExitOwner, FirstTouchDeliverReason, ForkKind, GuestCpuId,
    KernelAuditor, WakeRejectionReason,
};
use parking_lot::Mutex;

/// Identifies a built-in kernel invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum InvariantKind {
    NoOrphanZombie,
    ProcessGraphLiveness,
    NoWakeOfReapedTask,
    FirstTouchNeverDelivered,
    EveryChildRuns,
    ExitBudget,
}

/// Invariant: A zombie must have a parent unless it is PID 1.
#[derive(Clone, Debug, Default)]
pub struct NoOrphanZombie;

impl KernelAuditor for NoOrphanZombie {
    fn zombie_created(&self, task: TaskKey, parent: Option<TaskKey>) -> AuditVerdict {
        if parent.is_none() && task.id.raw() != 1 {
            AuditVerdict::Abort(AuditReason::OrphanZombie { task })
        } else {
            AuditVerdict::Continue
        }
    }
}

/// Invariant: When the process graph empties, no unpublished jobs may remain.
#[derive(Clone, Debug, Default)]
pub struct ProcessGraphLiveness;

impl KernelAuditor for ProcessGraphLiveness {
    fn process_graph_empty(&self, unpublished_jobs: usize) -> AuditVerdict {
        if unpublished_jobs > 0 {
            AuditVerdict::Abort(AuditReason::ProcessGraphEmptyWithUnpublishedJobs {
                unpublished_jobs,
            })
        } else {
            AuditVerdict::Continue
        }
    }
}

/// Invariant: Reaped tasks must never have scheduler wakeups attempted.
#[derive(Clone, Debug, Default)]
pub struct NoWakeOfReapedTask;

impl KernelAuditor for NoWakeOfReapedTask {
    fn wake_rejected(&self, target: TaskKey, reason: WakeRejectionReason) -> AuditVerdict {
        if reason == WakeRejectionReason::Reaped {
            AuditVerdict::Abort(AuditReason::WakeOfReapedTask { target })
        } else {
            AuditVerdict::Continue
        }
    }
}

/// Invariant: First-touch memory access must never be refused by backend publication.
#[derive(Clone, Debug, Default)]
pub struct FirstTouchNeverDelivered;

impl KernelAuditor for FirstTouchNeverDelivered {
    fn first_touch_delivered(
        &self,
        task: TaskKey,
        addr: u64,
        reason: FirstTouchDeliverReason,
    ) -> AuditVerdict {
        if reason == FirstTouchDeliverReason::BackendRefused {
            AuditVerdict::Abort(AuditReason::FirstTouchRefused { task, addr })
        } else {
            AuditVerdict::Continue
        }
    }
}

/// Invariant: Every admitted child process must be scheduled and run within a bound.
#[derive(Clone, Debug)]
pub struct EveryChildRuns {
    within: Duration,
    pending: Arc<Mutex<HashMap<TaskKey, mpsc::Sender<()>>>>,
    aborted: Arc<Mutex<Option<AuditReason>>>,
}

impl EveryChildRuns {
    pub fn new(within: Duration) -> Self {
        Self {
            within,
            pending: Arc::new(Mutex::new(HashMap::new())),
            aborted: Arc::new(Mutex::new(None)),
        }
    }

    pub fn within(&self) -> Duration {
        self.within
    }
}

impl Drop for EveryChildRuns {
    fn drop(&mut self) {
        let mut p = self.pending.lock();
        for tx in p.values() {
            let _ = tx.send(());
        }
        p.clear();
    }
}

impl KernelAuditor for EveryChildRuns {
    fn fork_admitted(&self, _parent: TaskKey, child: TaskKey, _kind: ForkKind) -> AuditVerdict {
        if let Some(reason) = self.aborted.lock().clone() {
            return AuditVerdict::Abort(reason);
        }
        let (tx, rx) = mpsc::channel();
        self.pending.lock().insert(child, tx);
        let within = self.within;
        let aborted = Arc::clone(&self.aborted);
        let pending = Arc::clone(&self.pending);
        std::thread::Builder::new()
            .name(format!("every-child-runs-{}", child.id.raw()))
            .spawn(move || {
                if rx.recv_timeout(within).is_err() {
                    let mut p = pending.lock();
                    if p.remove(&child).is_some() {
                        let mut a = aborted.lock();
                        if a.is_none() {
                            *a = Some(AuditReason::ChildNeverRan { child, within });
                        }
                    }
                }
            })
            .ok();
        AuditVerdict::Continue
    }

    fn child_first_run(
        &self,
        child: TaskKey,
        _executor: ExecutorId,
        _cpu: GuestCpuId,
    ) -> AuditVerdict {
        if let Some(tx) = self.pending.lock().remove(&child) {
            let _ = tx.send(());
        }
        if let Some(reason) = self.aborted.lock().clone() {
            AuditVerdict::Abort(reason)
        } else {
            AuditVerdict::Continue
        }
    }

    fn exit_settled(
        &self,
        child: TaskKey,
        _status: carrick_runtime::kernel::LinuxWaitStatus,
        _owner: ExitOwner,
    ) -> AuditVerdict {
        if let Some(tx) = self.pending.lock().remove(&child) {
            let _ = tx.send(());
        }
        if let Some(reason) = self.aborted.lock().clone() {
            AuditVerdict::Abort(reason)
        } else {
            AuditVerdict::Continue
        }
    }
}

/// Criterion for selecting tasks to apply an exit budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitBudgetMatcher {
    Any,
    Pid(u32),
    ChildrenOf(TaskKey),
    Exec(String),
}

/// Invariant: Process execution must complete and settle within an assigned duration.
#[derive(Clone, Debug)]
pub struct ExitBudget {
    select: ExitBudgetMatcher,
    within: Duration,
    pending: Arc<Mutex<HashMap<TaskKey, mpsc::Sender<()>>>>,
    aborted: Arc<Mutex<Option<AuditReason>>>,
}

impl ExitBudget {
    pub fn new(select: ExitBudgetMatcher, within: Duration) -> Self {
        Self {
            select,
            within,
            pending: Arc::new(Mutex::new(HashMap::new())),
            aborted: Arc::new(Mutex::new(None)),
        }
    }

    pub fn select(&self) -> &ExitBudgetMatcher {
        &self.select
    }

    pub fn within(&self) -> Duration {
        self.within
    }

    pub fn arm_task(&self, task: TaskKey, within: Duration) {
        let (tx, rx) = mpsc::channel();
        self.pending.lock().insert(task, tx);
        let aborted = Arc::clone(&self.aborted);
        let pending = Arc::clone(&self.pending);
        std::thread::Builder::new()
            .name(format!("exit-budget-{}", task.id.raw()))
            .spawn(move || {
                if rx.recv_timeout(within).is_err() {
                    let mut p = pending.lock();
                    if p.remove(&task).is_some() {
                        let mut a = aborted.lock();
                        if a.is_none() {
                            *a = Some(AuditReason::ExitBudgetExceeded { task, within });
                        }
                    }
                }
            })
            .ok();
    }
}

impl Drop for ExitBudget {
    fn drop(&mut self) {
        let mut p = self.pending.lock();
        for tx in p.values() {
            let _ = tx.send(());
        }
        p.clear();
    }
}

impl KernelAuditor for ExitBudget {
    fn fork_admitted(&self, parent: TaskKey, child: TaskKey, _kind: ForkKind) -> AuditVerdict {
        if let Some(reason) = self.aborted.lock().clone() {
            return AuditVerdict::Abort(reason);
        }
        let matches = match &self.select {
            ExitBudgetMatcher::Any => true,
            ExitBudgetMatcher::Pid(pid) => child.id.raw() == *pid as i32,
            ExitBudgetMatcher::ChildrenOf(p) => parent == *p,
            ExitBudgetMatcher::Exec(_) => false,
        };
        if matches {
            self.arm_task(child, self.within);
        }
        AuditVerdict::Continue
    }

    fn exec_committed(
        &self,
        task: TaskKey,
        _generation_before: ExecutionGeneration,
        _generation_after: ExecutionGeneration,
    ) -> AuditVerdict {
        if let Some(reason) = self.aborted.lock().clone() {
            return AuditVerdict::Abort(reason);
        }
        let matches = match &self.select {
            ExitBudgetMatcher::Any => true,
            ExitBudgetMatcher::Pid(pid) => task.id.raw() == *pid as i32,
            ExitBudgetMatcher::ChildrenOf(_) => false,
            ExitBudgetMatcher::Exec(_) => true,
        };
        if matches {
            self.arm_task(task, self.within);
        }
        AuditVerdict::Continue
    }

    fn exit_settled(
        &self,
        task: TaskKey,
        _status: carrick_runtime::kernel::LinuxWaitStatus,
        _owner: ExitOwner,
    ) -> AuditVerdict {
        if let Some(tx) = self.pending.lock().remove(&task) {
            let _ = tx.send(());
        }
        if let Some(reason) = self.aborted.lock().clone() {
            AuditVerdict::Abort(reason)
        } else {
            AuditVerdict::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::ThreadId;
    use carrick_runtime::kernel::ids::TaskId;
    use carrick_runtime::kernel::{LinuxWaitStatus, ObjectIdRegistry};

    fn sample_task_key(pid: i32) -> TaskKey {
        let registry = ObjectIdRegistry::new();
        TaskKey {
            id: TaskId::from_abi_positive(pid).unwrap(),
            serial: registry.task_serial().unwrap(),
        }
    }

    #[test]
    fn test_no_orphan_zombie() {
        let auditor = NoOrphanZombie;
        let pid1 = sample_task_key(1);
        let child = sample_task_key(2);
        let parent = sample_task_key(3);

        // PID 1 orphan is allowed
        assert_eq!(auditor.zombie_created(pid1, None), AuditVerdict::Continue);

        // Child with parent is allowed
        assert_eq!(
            auditor.zombie_created(child, Some(parent)),
            AuditVerdict::Continue
        );

        // Non-PID 1 orphan is aborted
        assert_eq!(
            auditor.zombie_created(child, None),
            AuditVerdict::Abort(AuditReason::OrphanZombie { task: child })
        );
    }

    #[test]
    fn test_process_graph_liveness() {
        let auditor = ProcessGraphLiveness;
        assert_eq!(auditor.process_graph_empty(0), AuditVerdict::Continue);
        assert_eq!(
            auditor.process_graph_empty(3),
            AuditVerdict::Abort(AuditReason::ProcessGraphEmptyWithUnpublishedJobs {
                unpublished_jobs: 3,
            })
        );
    }

    #[test]
    fn test_no_wake_of_reaped_task() {
        let auditor = NoWakeOfReapedTask;
        let task = sample_task_key(10);

        assert_eq!(
            auditor.wake_rejected(task, WakeRejectionReason::Closed),
            AuditVerdict::Continue
        );
        assert_eq!(
            auditor.wake_rejected(task, WakeRejectionReason::StaleGeneration),
            AuditVerdict::Continue
        );
        assert_eq!(
            auditor.wake_rejected(task, WakeRejectionReason::Reaped),
            AuditVerdict::Abort(AuditReason::WakeOfReapedTask { target: task })
        );
    }

    #[test]
    fn test_first_touch_never_delivered() {
        let auditor = FirstTouchNeverDelivered;
        let task = sample_task_key(10);

        assert_eq!(
            auditor.first_touch_delivered(task, 0x1000, FirstTouchDeliverReason::NotTracked),
            AuditVerdict::Continue
        );
        assert_eq!(
            auditor.first_touch_delivered(task, 0x1000, FirstTouchDeliverReason::BackendRefused),
            AuditVerdict::Abort(AuditReason::FirstTouchRefused { task, addr: 0x1000 })
        );
    }

    #[test]
    fn test_every_child_runs_success_and_timeout() {
        let auditor = EveryChildRuns::new(Duration::from_millis(50));
        let parent = sample_task_key(10);
        let child1 = sample_task_key(11);
        let child2 = sample_task_key(12);
        let exec =
            ExecutorId::for_transitional_thread(ThreadId::from_guest_supplied_tid(1)).unwrap();
        let cpu = GuestCpuId::new(0);

        // child1 runs promptly
        assert_eq!(
            auditor.fork_admitted(parent, child1, ForkKind::Fork),
            AuditVerdict::Continue
        );
        assert_eq!(
            auditor.child_first_run(child1, exec, cpu),
            AuditVerdict::Continue
        );

        // child2 is admitted but does not run within timeout
        assert_eq!(
            auditor.fork_admitted(parent, child2, ForkKind::Fork),
            AuditVerdict::Continue
        );
        std::thread::sleep(Duration::from_millis(100));

        let verdict = auditor.child_first_run(child2, exec, cpu);
        assert_eq!(
            verdict,
            AuditVerdict::Abort(AuditReason::ChildNeverRan {
                child: child2,
                within: Duration::from_millis(50),
            })
        );
    }

    #[test]
    fn test_exit_budget_success_and_timeout() {
        let auditor = ExitBudget::new(ExitBudgetMatcher::Any, Duration::from_millis(50));
        let parent = sample_task_key(10);
        let child1 = sample_task_key(11);
        let child2 = sample_task_key(12);
        let wait_status = LinuxWaitStatus::from_wait_encoding(0);

        // child1 exits promptly within budget
        assert_eq!(
            auditor.fork_admitted(parent, child1, ForkKind::Fork),
            AuditVerdict::Continue
        );
        assert_eq!(
            auditor.exit_settled(child1, wait_status, ExitOwner::Task(parent)),
            AuditVerdict::Continue
        );

        // child2 exceeds budget
        assert_eq!(
            auditor.fork_admitted(parent, child2, ForkKind::Fork),
            AuditVerdict::Continue
        );
        std::thread::sleep(Duration::from_millis(100));

        let verdict = auditor.exit_settled(child2, wait_status, ExitOwner::Task(parent));
        assert_eq!(
            verdict,
            AuditVerdict::Abort(AuditReason::ExitBudgetExceeded {
                task: child2,
                within: Duration::from_millis(50),
            })
        );
    }
}
