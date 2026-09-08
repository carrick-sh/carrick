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
