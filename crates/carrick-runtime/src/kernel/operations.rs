use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use carrick_abi::LinuxSiginfo;
use carrick_hal::{KernelTransactionId, ThreadId};
use parking_lot::{Condvar, Mutex};

use super::address::MmBackend;
use super::clone_plan::{
    CloneObjectMode, ClonePlan, CloneTaskMode, ForkParentMode, ForkPidfdMode, VforkMode,
};
use super::core::{
    Kernel, KernelContext, KernelDomain, ProcessGroupRecord, RegistryState, SessionRecord,
    TaskExitSubscriber, TaskRecord, TaskRevision, VforkChildRelease, VforkParentWait,
    VforkReleaseReason, ZombieRecord,
};
use super::ids::{LinuxSignal, LinuxTid, MmId, ObjectIdError, ProcessGroupId, SessionId, TaskId};
use super::objects::{
    Credentials, FileTable, LinuxWaitStatus, Mm, ObjectGraphError, ProcessGroup, Session, Task,
    TaskJobControlEvent, TaskKey, TaskLifecycle, TaskRef, TaskShared, TaskSharedCloneError,
    ThreadKey, ThreadRef, ThreadResources, Zombie,
};
use super::registry::{IdError, TaskReservation, ThreadClaim, ThreadReservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelFailpoint {
    AfterReserve,
    AfterObjects,
    AfterBackendPrepare,
    BeforePublish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitMode {
    Observe,
    Consume,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct WaitJobControl {
    stopped: bool,
    continued: bool,
}

impl WaitJobControl {
    const NONE: Self = Self {
        stopped: false,
        continued: false,
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    Exited(Zombie),
    Stopped { task: TaskId, signal: LinuxSignal },
    Continued { task: TaskId },
    StillRunning,
    NoChild,
}

/// Result of resolving one Linux signal target against the authoritative
/// kernel identity, credential, session, and sighand graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalTargetAuthorization {
    Allowed,
    DropProtectedInit,
    Denied,
    Missing,
}

/// An authorization result bound to the exact task/thread objects that were
/// inspected. The allowed ticket's fields stay private so a bare numeric PID
/// cannot be substituted between policy and enqueue.
#[derive(Debug)]
pub(crate) enum ExactSignalTargetAuthorization {
    Allowed(AuthorizedSignalTarget),
    DropProtectedInit,
    Denied,
    Missing,
}

#[derive(Debug)]
pub(crate) struct AuthorizedSignalTarget {
    domain: Arc<KernelDomain>,
    task: Weak<Task>,
    thread: Option<Weak<super::objects::Thread>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Observable identity of one exact task generation.
///
/// Keys, not bare numbers. A Linux TGID is reused within a run and an ASID is
/// recycled on exit, so `(pid, asid)` cannot distinguish two generations that
/// share a number — the ambiguity K1's observability contract forbids. The
/// `TaskSerial` inside each key is never reused by one Kernel, so a consumer
/// joining lifecycle records can always tell "the same task again" from "a
/// different task wearing the same pid".
pub struct TaskIdentity {
    pub task: TaskKey,
    pub parent: Option<TaskKey>,
    pub mm: MmId,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
}

#[derive(Clone, Debug)]
pub struct ReservedPidfdSubscription {
    domain: Arc<KernelDomain>,
    task: TaskKey,
}

impl ReservedPidfdSubscription {
    pub const fn task(&self) -> TaskKey {
        self.task
    }

    pub const fn task_id(&self) -> TaskId {
        self.task.id
    }

    pub fn belongs_to(&self, kernel: &Arc<Kernel>) -> bool {
        Arc::ptr_eq(&self.domain, kernel.domain())
    }
}

struct ReservedExitSubscriber(Arc<dyn TaskExitSubscriber>);

impl std::fmt::Debug for ReservedExitSubscriber {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ReservedExitSubscriber(<dyn TaskExitSubscriber>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildStartOutcome {
    Started,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildStartState {
    Waiting,
    Started,
    Cancelled,
}

#[derive(Debug)]
struct ChildStartShared {
    state: Mutex<ChildStartState>,
    changed: Condvar,
}

/// Child-thread-owned permission to wait until fork publication completes.
/// This handle is deliberately non-cloneable: exactly one materialized child
/// consumes the start decision.
#[derive(Debug)]
pub struct ChildStartWait {
    shared: Arc<ChildStartShared>,
}

impl ChildStartWait {
    fn pair() -> (Self, ChildStartRelease) {
        let shared = Arc::new(ChildStartShared {
            state: Mutex::new(ChildStartState::Waiting),
            changed: Condvar::new(),
        });
        (
            Self {
                shared: Arc::clone(&shared),
            },
            ChildStartRelease {
                shared,
                active: true,
            },
        )
    }

    pub fn wait(self) -> ChildStartOutcome {
        let mut state = self.shared.state.lock();
        loop {
            match *state {
                ChildStartState::Started => return ChildStartOutcome::Started,
                ChildStartState::Cancelled => return ChildStartOutcome::Cancelled,
                ChildStartState::Waiting => self.shared.changed.wait(&mut state),
            }
        }
    }
}

#[derive(Debug)]
struct ChildStartRelease {
    shared: Arc<ChildStartShared>,
    active: bool,
}

impl ChildStartRelease {
    fn start(&mut self) {
        if !self.active {
            return;
        }
        *self.shared.state.lock() = ChildStartState::Started;
        self.active = false;
        self.shared.changed.notify_all();
    }
}

impl Drop for ChildStartRelease {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        *self.shared.state.lock() = ChildStartState::Cancelled;
        self.active = false;
        self.shared.changed.notify_all();
    }
}

#[derive(Debug)]
pub struct StartedFork {
    context: KernelContext,
    vfork_parent_wait: Option<VforkParentWait>,
}

impl StartedFork {
    pub fn context(&self) -> &KernelContext {
        &self.context
    }

    pub fn vfork_parent_wait(&self) -> Option<&VforkParentWait> {
        self.vfork_parent_wait.as_ref()
    }

    pub fn into_parts(self) -> (KernelContext, Option<VforkParentWait>) {
        (self.context, self.vfork_parent_wait)
    }
}

/// Registry-published child whose execution gate is still closed.
///
/// Dropping this token opens the gate as a fail-safe: after publication there
/// is no rollback to an undiscoverable child, so cancellation would leak a live
/// task and could strand a vfork parent. The vfork wait handle is intentionally
/// unavailable until `start_child` returns `StartedFork`.
#[derive(Debug)]
#[must_use = "a published child must be started or explicitly retired"]
pub struct PublishedFork {
    started: Option<StartedFork>,
    start_wait: Option<ChildStartWait>,
    start_release: ChildStartRelease,
}

impl PublishedFork {
    pub fn context(&self) -> Option<&KernelContext> {
        self.started.as_ref().map(StartedFork::context)
    }

    pub fn start_child(mut self) -> Result<StartedFork, KernelOperationError> {
        self.start_release.start();
        drop(self.start_wait.take());
        self.started
            .take()
            .ok_or(KernelOperationError::PublishedForkConsumed)
    }

    pub fn into_parts(
        self,
    ) -> Result<(KernelContext, Option<VforkParentWait>), KernelOperationError> {
        Ok(self.start_child()?.into_parts())
    }
}

impl Drop for PublishedFork {
    fn drop(&mut self) {
        self.start_release.start();
        drop(self.start_wait.take());
    }
}

/// Non-cloneable ownership of one registry transaction across an exact task
/// set. External/backend preparation may run only while this guard is live;
/// dropping it releases every identity still owned by this transaction.
#[derive(Debug)]
struct TaskSetReservation {
    kernel: Arc<Kernel>,
    task_ids: Vec<TaskId>,
    transaction: KernelTransactionId,
    active: bool,
}

impl TaskSetReservation {
    fn acquired(
        kernel: &Arc<Kernel>,
        state: &mut RegistryState,
        mut task_ids: Vec<TaskId>,
        transaction: KernelTransactionId,
    ) -> Result<Self, KernelOperationError> {
        task_ids.sort_unstable();
        task_ids.dedup();
        for task_id in &task_ids {
            ensure_task_unreserved(state, *task_id)?;
        }
        for task_id in &task_ids {
            state.reservations.insert(*task_id, transaction);
        }
        Ok(Self {
            kernel: Arc::clone(kernel),
            task_ids,
            transaction,
            active: true,
        })
    }

    fn validate(&self, state: &RegistryState) -> Result<(), KernelOperationError> {
        if self
            .task_ids
            .iter()
            .all(|task_id| state.reservations.get(task_id) == Some(&self.transaction))
        {
            Ok(())
        } else {
            Err(KernelOperationError::StaleReservation)
        }
    }

    fn commit(&mut self, state: &mut RegistryState) -> Result<(), KernelOperationError> {
        self.validate(state)?;
        for task_id in &self.task_ids {
            state.reservations.remove(task_id);
        }
        self.active = false;
        self.kernel.publish_reservation_change();
        Ok(())
    }
}

impl Drop for TaskSetReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.kernel.registry().state.write();
        let mut changed = false;
        for task_id in &self.task_ids {
            if state.reservations.get(task_id) == Some(&self.transaction) {
                state.reservations.remove(task_id);
                changed = true;
            }
        }
        drop(state);
        if changed {
            self.kernel.publish_reservation_change();
        }
    }
}

/// Exit publication token whose fallible topology and revision checks have
/// completed. Dropping it leaves the task graph unchanged and releases every
/// affected identity reservation.
#[derive(Debug)]
pub struct PreparedTaskExit {
    reservation: TaskSetReservation,
    task: TaskKey,
    task_revision: TaskRevision,
    children: Vec<TaskKey>,
    affected_revisions: BTreeMap<TaskId, (TaskRevision, TaskRevision)>,
    adopter: Option<TaskKey>,
    prepared_adopter_children: Option<BTreeSet<TaskKey>>,
    registry_zombie: Zombie,
    result_zombie: Zombie,
}

impl PreparedTaskExit {
    pub const fn task(&self) -> TaskKey {
        self.task
    }

    pub const fn transaction(&self) -> KernelTransactionId {
        self.reservation.transaction
    }

    pub fn commit(self) -> Result<Zombie, KernelOperationError> {
        let kernel = Arc::clone(&self.reservation.kernel);
        kernel.commit_task_exit(self)
    }

    pub fn commit_notifying(
        self,
        notify_parent: impl FnOnce(Option<TaskKey>),
    ) -> Result<Zombie, KernelOperationError> {
        let kernel = Arc::clone(&self.reservation.kernel);
        kernel.commit_task_exit_notifying(self, notify_parent)
    }
}

/// Typed permission to prepare work against one exact task topology revision.
#[derive(Debug)]
pub struct TaskOperationReservation {
    domain: Arc<KernelDomain>,
    task: TaskKey,
    revision: TaskRevision,
}

impl TaskOperationReservation {
    pub const fn task(&self) -> TaskKey {
        self.task
    }

    pub const fn revision(&self) -> TaskRevision {
        self.revision
    }
}

/// Reserved child identity that remains undiscoverable until backend
/// preparation completes and `PreparedFork::commit` publishes it.
#[derive(Debug)]
pub struct ForkReservation {
    kernel: Arc<Kernel>,
    operation: TaskSetReservation,
    caller_task: TaskRef,
    caller_thread: ThreadRef,
    caller_shared: Arc<TaskShared>,
    caller_resources: Arc<ThreadResources>,
    caller_revision: TaskRevision,
    child_parent_task: TaskRef,
    child_parent_revision: TaskRevision,
    plan: ClonePlan,
    child_id: TaskId,
    task_reservation: TaskReservation,
    leader_claim: ThreadClaim,
    diagnostic_name: String,
    vfork_relationship: Option<(VforkParentWait, VforkChildRelease)>,
    failpoint: Option<KernelFailpoint>,
}

impl ForkReservation {
    pub const fn child_id(&self) -> TaskId {
        self.child_id
    }

    pub fn prepare_with_mm_backend(
        self,
        backend: Arc<dyn MmBackend>,
        child_registry_id: ThreadId,
    ) -> Result<PreparedFork, KernelOperationError> {
        if self.plan.mm() != CloneObjectMode::Copy {
            return Err(KernelOperationError::UnexpectedForkMmBackend);
        }
        let file_table_freeze = self.freeze_files_for_copied_state()?;
        let parent_mm = self.caller_shared.mm();
        let mm = Arc::new(Mm::with_backend_for_fork(
            self.kernel.object_ids().mm_id()?,
            backend,
            &parent_mm,
        ));
        self.prepare(Some(mm), child_registry_id, file_table_freeze)
    }

    pub fn prepare_shared_mm(
        self,
        child_registry_id: ThreadId,
    ) -> Result<PreparedFork, KernelOperationError> {
        if self.plan.mm() != CloneObjectMode::Share {
            return Err(KernelOperationError::MissingForkMmBackend);
        }
        self.prepare(None, child_registry_id, None)
    }

    #[cfg(test)]
    pub(crate) fn prepare_reference(
        self,
        child_registry_id: ThreadId,
    ) -> Result<PreparedFork, KernelOperationError> {
        let file_table_freeze = self.freeze_files_for_copied_state()?;
        let copied_mm = (self.plan.mm() == CloneObjectMode::Copy)
            .then(|| {
                self.kernel
                    .object_ids()
                    .mm_id()
                    .map(|id| Mm::new_reference_for_fork(id, &self.caller_shared.mm()))
                    .map(Arc::new)
            })
            .transpose()?;
        self.prepare(copied_mm, child_registry_id, file_table_freeze)
    }

    fn freeze_files_for_copied_state(
        &self,
    ) -> Result<Option<super::objects::FileTableExecFreeze>, KernelOperationError> {
        if self.plan.mm() == CloneObjectMode::Copy || self.plan.files() == CloneObjectMode::Copy {
            self.caller_resources
                .files()
                .freeze_for_exec()
                .map(Some)
                .ok_or(KernelOperationError::FileTableDraining)
        } else {
            Ok(None)
        }
    }

    fn prepare(
        self,
        copied_mm: Option<Arc<Mm>>,
        child_registry_id: ThreadId,
        mut file_table_freeze: Option<super::objects::FileTableExecFreeze>,
    ) -> Result<PreparedFork, KernelOperationError> {
        if file_table_freeze.is_none() {
            file_table_freeze = self.freeze_files_for_copied_state()?;
        }
        let child_shared = Arc::new(TaskShared::for_new_task_with_mm(
            &self.caller_shared,
            self.plan,
            self.kernel.object_ids(),
            copied_mm,
        )?);
        let child_resources = Arc::new(ThreadResources::for_clone(
            &self.caller_resources,
            self.plan,
            self.kernel.object_ids(),
        )?);
        drop(file_table_freeze);
        let child_key = TaskKey {
            id: self.child_id,
            serial: self.kernel.object_ids().task_serial()?,
        };
        let child = Arc::new(Task::new(
            child_key,
            Some(self.child_parent_task.key()),
            self.caller_task.process_group(),
            self.caller_task.session(),
            Arc::clone(&child_shared),
            child_resources.credentials(),
        ));
        let leader_tid = LinuxTid::for_task_leader(self.child_id);
        let leader = child.attach_fork_thread(
            ThreadKey {
                tid: leader_tid,
                serial: self.kernel.object_ids().thread_serial()?,
            },
            child_registry_id,
            Arc::clone(&child_resources),
            self.caller_thread.signal_state(),
        )?;
        check_failpoint(self.failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(self.failpoint, KernelFailpoint::AfterBackendPrepare)?;
        let (start_wait, start_release) = ChildStartWait::pair();
        Ok(PreparedFork {
            reservation: self,
            child,
            leader,
            child_shared,
            child_resources,
            pidfd_subscriber: None,
            start_wait: Some(start_wait),
            start_release,
        })
    }
}

#[derive(Debug)]
pub struct PreparedFork {
    reservation: ForkReservation,
    child: TaskRef,
    leader: ThreadRef,
    child_shared: Arc<TaskShared>,
    child_resources: Arc<ThreadResources>,
    pidfd_subscriber: Option<ReservedExitSubscriber>,
    start_wait: Option<ChildStartWait>,
    start_release: ChildStartRelease,
}

impl PreparedFork {
    pub const fn child_id(&self) -> TaskId {
        self.reservation.child_id
    }

    /// Exact address-space identity already selected by Kernel preparation.
    /// Runtime/backend publication must route child mappings to this ID rather
    /// than allocating or reconstructing one from backend process state.
    pub fn child_mm_id(&self) -> MmId {
        self.child_shared.mm().id()
    }

    pub fn child_key(&self) -> TaskKey {
        self.child.key()
    }

    /// Transfer the unique wait handle to a materialized child before commit.
    /// Dropping this preparation wakes it with `Cancelled`; a published child
    /// remains blocked until `PublishedFork::start_child`.
    pub fn take_child_start_wait(&mut self) -> Result<ChildStartWait, KernelOperationError> {
        self.start_wait
            .take()
            .ok_or(KernelOperationError::ChildStartWaitTaken)
    }

    pub fn reserve_pidfd_subscription<T>(
        &mut self,
        subscriber: &Arc<T>,
    ) -> Result<ReservedPidfdSubscription, KernelOperationError>
    where
        T: TaskExitSubscriber + 'static,
    {
        if self.reservation.plan.pidfd() != ForkPidfdMode::Requested {
            return Err(KernelOperationError::UnexpectedPidfdSubscription);
        }
        if self.pidfd_subscriber.is_some() {
            return Err(KernelOperationError::PidfdSubscriptionExists);
        }
        let subscriber: Arc<dyn TaskExitSubscriber> = subscriber.clone();
        self.pidfd_subscriber = Some(ReservedExitSubscriber(subscriber));
        Ok(ReservedPidfdSubscription {
            domain: Arc::clone(self.reservation.kernel.domain()),
            task: self.child.key(),
        })
    }

    pub fn commit(self) -> Result<PublishedFork, KernelOperationError> {
        let Self {
            reservation,
            child,
            leader,
            child_shared,
            child_resources,
            pidfd_subscriber,
            start_wait,
            start_release,
        } = self;
        if reservation.plan.pidfd() == ForkPidfdMode::Requested && pidfd_subscriber.is_none() {
            return Err(KernelOperationError::MissingPidfdSubscription);
        }
        let ForkReservation {
            kernel,
            mut operation,
            caller_task,
            caller_thread: _,
            caller_shared: _,
            caller_resources: _,
            caller_revision,
            child_parent_task,
            child_parent_revision,
            plan: _,
            child_id,
            task_reservation,
            leader_claim,
            diagnostic_name,
            vfork_relationship,
            failpoint,
        } = reservation;
        let child_key = child.key();
        let leader_tid = LinuxTid::for_task_leader(child_id);
        let (vfork_parent_wait, vfork_release) = match vfork_relationship {
            Some((parent_wait, child_release)) => (Some(parent_wait), Some(child_release)),
            None => (None, None),
        };
        {
            let mut state = kernel.registry().state.write();
            operation.validate(&state)?;
            let Some(caller_record) = state.tasks.get(&caller_task.key().id) else {
                return Err(KernelOperationError::ParentExited);
            };
            if caller_record.task.key() != caller_task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            if caller_record.revision != caller_revision {
                return Err(KernelOperationError::StaleContext);
            }
            let Some(child_parent_record) = state.tasks.get(&child_parent_task.key().id) else {
                return Err(KernelOperationError::ForkParentExited);
            };
            if child_parent_record.task.key() != child_parent_task.key() {
                return Err(KernelOperationError::ForkParentExited);
            }
            if child_parent_record.revision != child_parent_revision {
                return Err(KernelOperationError::ForkParentChanged);
            }
            let next_child_parent_revision = next_revision(child_parent_record.revision)?;
            let process_group = child.process_group();
            let session = child.session();
            if !state.process_groups.contains_key(&process_group)
                || !state.sessions.contains_key(&session)
            {
                return Err(KernelOperationError::IdentityObjectMissing);
            }
            check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

            let task_claim = task_reservation.commit();
            child_parent_task.add_child(child_key);
            if let Some(group) = state.process_groups.get_mut(&process_group) {
                group.members.insert(child_key);
            }
            state.tasks.insert(
                child_id,
                TaskRecord {
                    task: Arc::clone(&child),
                    revision: TaskRevision::INITIAL,
                    task_claim,
                    thread_claims: std::collections::BTreeMap::from([(leader_tid, leader_claim)]),
                    dead_leader: None,
                    vfork_release,
                    has_execed: false,
                    diagnostic_name,
                },
            );
            kernel.observe_task_publication(
                &child,
                &leader,
                &child_shared,
                &child_resources,
                TaskRevision::INITIAL,
            );
            if let Some(subscriber) = pidfd_subscriber {
                kernel
                    .exit_subscribers
                    .register_erased(child_key, &subscriber.0);
            }
            if let Some(parent_record) = state.tasks.get_mut(&child_parent_task.key().id) {
                parent_record.revision = next_child_parent_revision;
            }
            operation.commit(&mut state)?;
        }

        Ok(PublishedFork {
            started: Some(StartedFork {
                context: KernelContext::from_parts(
                    kernel,
                    child,
                    leader,
                    child_shared,
                    child_resources,
                    TaskRevision::INITIAL,
                ),
                vfork_parent_wait,
            }),
            start_wait,
            start_release,
        })
    }
}

#[derive(Debug)]
pub struct StartedThreadClone {
    context: KernelContext,
}

impl StartedThreadClone {
    pub fn context(&self) -> &KernelContext {
        &self.context
    }

    pub fn into_context(self) -> KernelContext {
        self.context
    }
}

/// Registry-published thread whose backend start gate is still closed.
/// Dropping it fail-safe starts the thread because publication cannot roll back.
#[derive(Debug)]
#[must_use = "a published thread must be started or explicitly retired"]
pub struct PublishedThreadClone {
    started: Option<StartedThreadClone>,
    start_wait: Option<ChildStartWait>,
    start_release: ChildStartRelease,
}

impl PublishedThreadClone {
    pub fn context(&self) -> Option<&KernelContext> {
        self.started.as_ref().map(StartedThreadClone::context)
    }

    pub fn start_thread(mut self) -> Result<StartedThreadClone, KernelOperationError> {
        self.start_release.start();
        drop(self.start_wait.take());
        self.started
            .take()
            .ok_or(KernelOperationError::PublishedThreadCloneConsumed)
    }

    pub fn into_context(self) -> Result<KernelContext, KernelOperationError> {
        Ok(self.start_thread()?.into_context())
    }
}

impl Drop for PublishedThreadClone {
    fn drop(&mut self) {
        self.start_release.start();
        drop(self.start_wait.take());
    }
}

#[derive(Debug)]
pub struct ThreadCloneReservation {
    kernel: Arc<Kernel>,
    task: TaskRef,
    caller: ThreadRef,
    shared: Arc<TaskShared>,
    parent_resources: Arc<ThreadResources>,
    plan: ClonePlan,
    tid: LinuxTid,
    reservation: ThreadReservation,
    failpoint: Option<KernelFailpoint>,
}

impl ThreadCloneReservation {
    pub const fn tid(&self) -> LinuxTid {
        self.tid
    }

    pub fn prepare(
        self,
        registry_id: ThreadId,
    ) -> Result<PreparedThreadClone, KernelOperationError> {
        let resources = Arc::new(ThreadResources::for_clone(
            &self.parent_resources,
            self.plan,
            self.kernel.object_ids(),
        )?);
        let thread = self.task.prepare_clone_thread(
            ThreadKey {
                tid: self.tid,
                serial: self.kernel.object_ids().thread_serial()?,
            },
            registry_id,
            Arc::clone(&resources),
            self.caller.signal_state(),
        );
        check_failpoint(self.failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(self.failpoint, KernelFailpoint::AfterBackendPrepare)?;
        let (start_wait, start_release) = ChildStartWait::pair();
        Ok(PreparedThreadClone {
            reservation: self,
            thread,
            resources,
            publication: None,
            start_wait: Some(start_wait),
            start_release,
        })
    }
}

#[derive(Debug)]
pub struct PreparedThreadClone {
    reservation: ThreadCloneReservation,
    thread: ThreadRef,
    resources: Arc<ThreadResources>,
    publication: Option<TaskSetReservation>,
    start_wait: Option<ChildStartWait>,
    start_release: ChildStartRelease,
}

impl PreparedThreadClone {
    pub const fn tid(&self) -> LinuxTid {
        self.reservation.tid
    }

    pub fn take_child_start_wait(&mut self) -> Result<ChildStartWait, KernelOperationError> {
        self.start_wait
            .take()
            .ok_or(KernelOperationError::ChildStartWaitTaken)
    }

    /// Reserve the task's publication slot before backend materialization takes
    /// the HVPatch topology lock. This establishes one lock order:
    /// task operation → topology → registry publication.
    pub fn reserve_publication_eventually(mut self) -> Result<Self, KernelOperationError> {
        let kernel = Arc::clone(&self.reservation.kernel);
        let task = self.reservation.task.key();
        let task_id = task.id;
        let transaction = kernel.object_ids().transaction_id()?;
        loop {
            let observed = kernel.reservation_epoch();
            let mut state = kernel.registry().state.write();
            if state
                .tasks
                .get(&task_id)
                .is_none_or(|record| record.task.key() != task)
            {
                return Err(KernelOperationError::ParentExited);
            }
            match TaskSetReservation::acquired(&kernel, &mut state, vec![task_id], transaction) {
                Ok(publication) => {
                    drop(state);
                    self.publication = Some(publication);
                    return Ok(self);
                }
                Err(KernelOperationError::TaskBusy(_)) => {
                    drop(state);
                    kernel.wait_for_reservation_change(observed);
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn commit(self) -> Result<PublishedThreadClone, KernelOperationError> {
        let Self {
            reservation,
            thread,
            resources,
            mut publication,
            start_wait,
            start_release,
        } = self;
        let ThreadCloneReservation {
            kernel,
            task,
            caller,
            shared,
            parent_resources,
            plan: _,
            tid,
            reservation,
            failpoint,
        } = reservation;
        let published_revision = {
            let mut state = kernel.registry().state.write();
            if let Some(publication) = publication.as_ref() {
                publication.validate(&state)?;
            } else {
                ensure_task_unreserved(&state, task.key().id)?;
            }
            let Some(record) = state.tasks.get_mut(&task.key().id) else {
                return Err(KernelOperationError::ParentExited);
            };
            if record.task.key() != task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            let current_shared = task.shared();
            let current_caller = task
                .thread(caller.key().tid)
                .ok_or(KernelOperationError::StaleContext)?;
            if !Arc::ptr_eq(&current_shared, &shared)
                || current_caller.key() != caller.key()
                || !Arc::ptr_eq(&current_caller, &caller)
                || !Arc::ptr_eq(&current_caller.resources(), &parent_resources)
            {
                return Err(KernelOperationError::StaleContext);
            }
            let published_revision = next_revision(record.revision)?;
            check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;
            let claim = reservation.commit();
            task.publish_thread(Arc::clone(&thread))?;
            record.thread_claims.insert(tid, claim);
            record.revision = published_revision;
            kernel.observe_thread_publication(&thread, &resources, published_revision);
            if let Some(publication) = publication.as_mut() {
                publication.commit(&mut state)?;
            }
            published_revision
        };
        Ok(PublishedThreadClone {
            started: Some(StartedThreadClone {
                context: KernelContext::from_parts(
                    kernel,
                    task,
                    thread,
                    shared,
                    resources,
                    published_revision,
                ),
            }),
            start_wait,
            start_release,
        })
    }
}

impl Kernel {
    pub fn task_identity(&self, task_id: TaskId) -> Result<TaskIdentity, KernelOperationError> {
        let state = self.registry().state.read();
        let record = state
            .tasks
            .get(&task_id)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        Ok(TaskIdentity {
            task: record.task.key(),
            parent: record.task.parent(),
            mm: record.task.shared().mm().id(),
            process_group: record.task.process_group(),
            session: record.task.session(),
        })
    }

    /// Resolve the authoritative current parent of one exact task generation.
    /// Runtime notification routing uses this immediately before exit
    /// publication so CLONE_PARENT and orphan reparenting cannot target a stale
    /// creator captured at fork time.
    pub fn task_parent_key(&self, task: TaskKey) -> Result<Option<TaskKey>, KernelOperationError> {
        let state = self.registry().state.read();
        let record = state
            .tasks
            .get(&task.id)
            .ok_or(KernelOperationError::UnknownTask(task.id))?;
        if record.task.key() != task {
            return Err(KernelOperationError::StaleTaskGeneration(task.id));
        }
        Ok(record.task.parent())
    }

    pub fn task_is_live(&self, task_id: TaskId) -> bool {
        self.registry().state.read().tasks.contains_key(&task_id)
    }

    pub(crate) fn live_task_key(&self, task_id: TaskId) -> Option<TaskKey> {
        let state = self.registry().state.read();
        state.tasks.get(&task_id).and_then(|record| {
            (record.task.lifecycle() == TaskLifecycle::Live).then(|| record.task.key())
        })
    }

    /// Resolve a task's exact parent at the moment a waitable state change has
    /// already been published. The registry lock is released before callers
    /// invoke the lane waker.
    fn current_parent_task(&self, task: &Task) -> Option<TaskRef> {
        let state = self.registry().state.read();
        task.parent()
            .and_then(|key| state.tasks.get(&key.id).map(|record| (key, record)))
            .filter(|(key, record)| record.task.key() == *key)
            .map(|(_, record)| Arc::clone(&record.task))
    }

    /// Authorize a process- or thread-directed Linux signal without consulting
    /// host process identity. `target_thread == None` uses the task's retained
    /// leader credential authority; thread-directed calls name the exact target
    /// thread.
    pub fn authorize_signal_target(
        &self,
        caller: &KernelContext,
        target_task: TaskId,
        target_thread: Option<LinuxTid>,
        signal: Option<LinuxSignal>,
    ) -> SignalTargetAuthorization {
        let target = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target_task) else {
                return SignalTargetAuthorization::Missing;
            };
            let thread = match target_thread {
                Some(tid) => {
                    let Some(thread) = record.task.thread(tid) else {
                        return SignalTargetAuthorization::Missing;
                    };
                    Some(thread.key())
                }
                None => None,
            };
            (record.task.key(), thread)
        };
        match self.authorize_signal_target_exact(caller, target.0, target.1, signal) {
            ExactSignalTargetAuthorization::Allowed(_) => SignalTargetAuthorization::Allowed,
            ExactSignalTargetAuthorization::DropProtectedInit => {
                SignalTargetAuthorization::DropProtectedInit
            }
            ExactSignalTargetAuthorization::Denied => SignalTargetAuthorization::Denied,
            ExactSignalTargetAuthorization::Missing => SignalTargetAuthorization::Missing,
        }
    }

    /// Resolve signal policy to one unforgeable task/thread generation. The
    /// returned ticket weakly binds the exact objects inspected here; posting
    /// through it fails if that generation exits and can never follow a reused
    /// numeric PID/TID to a different process.
    pub(crate) fn authorize_signal_target_exact(
        &self,
        caller: &KernelContext,
        target_task: TaskKey,
        target_thread: Option<ThreadKey>,
        signal: Option<LinuxSignal>,
    ) -> ExactSignalTargetAuthorization {
        if !std::ptr::eq(self, caller.kernel().as_ref()) {
            return ExactSignalTargetAuthorization::Missing;
        }
        let (target, thread, target_credentials, target_session, target_sighand) = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target_task.id) else {
                return ExactSignalTargetAuthorization::Missing;
            };
            if record.task.key() != target_task || record.task.lifecycle() != TaskLifecycle::Live {
                return ExactSignalTargetAuthorization::Missing;
            }
            let (credentials, thread) = match target_thread {
                Some(key) => {
                    let Some(thread) = record.task.thread(key.tid) else {
                        return ExactSignalTargetAuthorization::Missing;
                    };
                    if thread.key() != key {
                        return ExactSignalTargetAuthorization::Missing;
                    }
                    (thread.resources().credentials(), Some(thread))
                }
                None => (record.task.process_credentials(), None),
            };
            (
                Arc::clone(&record.task),
                thread,
                credentials,
                record.task.session(),
                record.task.shared().sighand(),
            )
        };
        let caller_credentials = caller.resources().credentials();
        let caller_is_privileged = caller_credentials.is_privileged();
        let uid_match = [caller_credentials.ruid(), caller_credentials.euid()]
            .into_iter()
            .any(|caller_uid| {
                caller_uid == target_credentials.ruid() || caller_uid == target_credentials.suid()
            });
        let same_session_sigcont = signal.is_some_and(|signal| {
            signal.raw() == carrick_abi::LINUX_SIGCONT && caller.task().session() == target_session
        });
        if !caller_is_privileged && !uid_match && !same_session_sigcont {
            return ExactSignalTargetAuthorization::Denied;
        }

        let init = TaskId::from_abi_positive(carrick_abi::LINUX_BOOTSTRAP_PID as i32).ok();
        if Some(target_task.id) == init
            && signal.is_some_and(|signal| {
                (crate::namespace::pid::is_init_protected_default_signal(signal.raw())
                    || matches!(
                        signal.raw(),
                        carrick_abi::LINUX_SIGTSTP
                            | carrick_abi::LINUX_SIGTTIN
                            | carrick_abi::LINUX_SIGTTOU
                    ))
                    && target_sighand.disposition(signal)
                        == super::objects::SignalDisposition::Default
            })
        {
            return ExactSignalTargetAuthorization::DropProtectedInit;
        }
        ExactSignalTargetAuthorization::Allowed(AuthorizedSignalTarget {
            domain: Arc::clone(self.domain()),
            task: Arc::downgrade(&target),
            thread: thread.as_ref().map(Arc::downgrade),
        })
    }

    /// Apply a default-stop action to one live Linux task without signaling
    /// the host carrier process. The target's vCPU threads and its parent wait
    /// vehicle are woken only after the task-scoped state is published.
    pub(crate) fn stop_task_for_job_control(
        &self,
        target: TaskId,
        signal: LinuxSignal,
        action_generation: Option<super::objects::JobControlStopInvalidationGeneration>,
    ) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        let generation = task.lock_signal_generation();
        if !task.stop_for_job_control(signal, action_generation) {
            return false;
        }
        drop(generation);
        let parent = self.current_parent_task(&task);
        task.wake();
        if let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    /// Resume one stopped Linux task. Returning false means the task was live
    /// but already running (or absent); SIGCONT delivery itself may still
    /// succeed and may still invoke a caught handler.
    pub fn continue_task_from_job_control(&self, target: TaskId) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        let generation = task.lock_signal_generation();
        if !task.continue_from_job_control() {
            return false;
        }
        drop(generation);
        let parent = self.current_parent_task(&task);
        task.wake();
        if let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    pub fn task_is_job_control_stopped(&self, target: TaskId) -> bool {
        self.registry()
            .state
            .read()
            .tasks
            .get(&target)
            .is_some_and(|record| record.task.is_job_control_stopped())
    }

    /// Every LIVE task in `group`, lowest id first.
    ///
    /// This is the authority a `killpg(2)` must use. The HOST's process groups
    /// describe carrick itself, not the guest — on the kernel lane every Linux
    /// process is a thread of one host process, so they are all in the same
    /// host group and a guest pgid means nothing to `libc::kill`. Worse, a
    /// guest pgid of 1 negates to `kill(-1, …)`, the host BROADCAST sentinel.
    ///
    /// Sorted so delivery order is deterministic; Linux does not specify one,
    /// but a differential oracle needs carrick's to be stable.
    pub fn tasks_in_process_group(&self, group: ProcessGroupId) -> Vec<TaskId> {
        self.task_keys_in_process_group(group)
            .into_iter()
            .map(|key| key.id)
            .collect()
    }

    pub(crate) fn task_keys_in_process_group(&self, group: ProcessGroupId) -> Vec<TaskKey> {
        let state = self.registry().state.read();
        let mut keys: Vec<TaskKey> = state
            .tasks
            .iter()
            .filter(|(_, record)| {
                record.task.lifecycle() == TaskLifecycle::Live
                    && record.task.process_group() == group
            })
            .map(|(_, record)| record.task.key())
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Every LIVE task a broadcast `kill(-1, …)` may target: all of them except
    /// the caller and init, lowest id first.
    ///
    /// Linux sends `kill(-1)` to every process the caller has permission to
    /// signal, excluding itself and pid 1. Excluding init is what stops a
    /// guest's own `kill(-1, SIGKILL)` from taking down the container's init
    /// along with everything else.
    pub fn tasks_for_broadcast(&self, caller: TaskId) -> Vec<TaskId> {
        self.task_keys_for_broadcast(caller)
            .into_iter()
            .map(|key| key.id)
            .collect()
    }

    pub(crate) fn task_keys_for_broadcast(&self, caller: TaskId) -> Vec<TaskKey> {
        let init = TaskId::from_abi_positive(carrick_abi::LINUX_BOOTSTRAP_PID as i32).ok();
        let state = self.registry().state.read();
        let mut keys: Vec<TaskKey> = state
            .tasks
            .iter()
            .filter(|(id, record)| {
                **id != caller
                    && Some(**id) != init
                    && record.task.lifecycle() == TaskLifecycle::Live
            })
            .map(|(_, record)| record.task.key())
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Enqueue through an exact-generation authorization ticket. The ticket
    /// upgrades only the weak task/thread references selected by policy, so an
    /// exit/reap/PID-reuse race can only make this fail; it cannot redirect
    /// delivery to the new occupant of the same numeric id.
    pub(crate) fn post_signal_to_authorized_target(
        &self,
        target: &AuthorizedSignalTarget,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        if !Arc::ptr_eq(self.domain(), &target.domain) {
            return false;
        }
        let Some(task) = target.task.upgrade() else {
            return false;
        };
        let thread = match &target.thread {
            Some(thread) => {
                let Some(thread) = thread.upgrade() else {
                    return false;
                };
                Some(thread)
            }
            None => None,
        };
        let generation = task.lock_signal_generation();
        if task.lifecycle() != TaskLifecycle::Live {
            return false;
        }
        if let Some(thread) = &thread
            && task
                .thread(thread.key().tid)
                .is_none_or(|current| !Arc::ptr_eq(&current, thread))
        {
            return false;
        }
        task.discard_opposing_job_control_signals(signal);
        task.record_job_control_signal_generation(signal);
        if let Some(thread) = &thread {
            thread.update_signal_state(|pending| {
                if signal.is_realtime() {
                    pending.enqueue_realtime(signal, siginfo);
                } else {
                    pending.enqueue_standard(signal, siginfo);
                }
            });
        } else {
            let pending = task.shared().pending_signals();
            if signal.is_realtime() {
                pending.enqueue_realtime(signal, siginfo);
            } else {
                pending.enqueue_standard(signal, siginfo);
            }
        }
        let continued = if signal.raw() == carrick_abi::LINUX_SIGCONT {
            task.continue_from_job_control()
        } else if signal.raw() == carrick_abi::LINUX_SIGKILL {
            task.resume_from_job_control_for_fatal_signal();
            false
        } else {
            false
        };
        drop(generation);
        // WCONTINUED belongs to the parent CURRENT at publication, not the
        // parent observed when authorization began. Resolve the exact current
        // TaskKey after publishing the event, then release the registry lock
        // before calling the lane waker.
        let parent = if continued {
            self.current_parent_task(&task)
        } else {
            None
        };
        task.wake();
        if let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    /// Post `signal` into `target`'s process-directed pending queue and report
    /// whether a live task took it.
    ///
    /// This is the delivery half of kernel-internal cross-process signalling:
    /// on the kernel lane a Linux process is a THREAD of one host process, so
    /// there is no host pid to `kill(2)` and the signal has to land in the
    /// kernel's own queue — the same queue [`take_lowest_in`] drains, so a
    /// signal posted here is indistinguishable from one the task raised on
    /// itself.
    ///
    /// Returns `false` for an unknown or exiting task, which is a `kill(2)`
    /// `ESRCH` for a specific target and simply "not a member" for a group
    /// fan-out. The liveness test closes a real race: a task that has begun
    /// exiting still has a registry entry (it becomes a zombie only once
    /// reaped), and enqueuing onto it would strand the signal in a queue no
    /// one will drain.
    ///
    /// [`take_lowest_in`]: super::objects::TaskPendingSignals::take_lowest_in
    ///
    /// The signal is made pending and then the target is WOKEN through its
    /// lane-supplied [`TaskWaker`](super::objects::TaskWaker), because enqueuing
    /// alone reaches only a task that gets back to a syscall or trap boundary —
    /// one parked in a host wait watches pipes, futexes and kqueues, none of
    /// which observe the kernel's queues. A task with no waker published is not an error: it still notices
    /// at its next boundary, just not while parked.
    ///
    /// The wake happens strictly AFTER the enqueue and outside the registry
    /// lock. After, so the woken task cannot look, find an empty queue, and go
    /// back to sleep having consumed its wake; outside, so a waker that blocks
    /// or re-enters the kernel cannot deadlock against the registry.
    #[cfg(test)]
    pub fn post_signal_to_task(
        &self,
        target: TaskId,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        let target = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            record.task.key()
        };
        self.post_signal_to_task_key(target, signal, siginfo)
    }

    /// Publish one process-directed signal to an exact live task generation.
    /// Runtime-owned asynchronous sources (HVPatch process-local timers) use
    /// this after their syscall context has returned, when no caller context is
    /// available to authorize a fresh pid lookup. A recycled numeric pid can
    /// never receive the late event because the complete [`TaskKey`] must
    /// still match under the registry lock.
    pub(crate) fn post_signal_to_task_key(
        &self,
        target: TaskKey,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        let (task, parent) = {
            let state = self.registry().state.read();
            let Some(record) = state
                .tasks
                .get(&target.id)
                .filter(|record| record.task.key() == target)
            else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            let parent = record
                .task
                .parent()
                .and_then(|key| state.tasks.get(&key.id).map(|record| (key, record)))
                .filter(|(key, record)| record.task.key() == *key)
                .map(|(_, record)| Arc::clone(&record.task));
            (Arc::clone(&record.task), parent)
        };
        let generation = task.lock_signal_generation();
        if task.lifecycle() != TaskLifecycle::Live {
            return false;
        }
        task.discard_opposing_job_control_signals(signal);
        task.record_job_control_signal_generation(signal);
        let pending = task.shared().pending_signals();
        if signal.is_realtime() {
            pending.enqueue_realtime(signal, siginfo);
        } else {
            pending.enqueue_standard(signal, siginfo);
        }
        // Queue before resume. A stopped task cannot consume the signal yet,
        // and once SIGCONT/SIGKILL releases it the pending action must already
        // be visible so delivery cannot race behind guest execution or exit.
        let continued = if signal.raw() == carrick_abi::LINUX_SIGCONT {
            task.continue_from_job_control()
        } else if signal.raw() == carrick_abi::LINUX_SIGKILL {
            task.resume_from_job_control_for_fatal_signal();
            false
        } else {
            false
        };
        drop(generation);
        task.wake();
        if continued && let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    /// Resolve one live Linux tid to its owning task, optionally requiring an
    /// exact tgid. Kernel-lane `tkill` uses the global form; `tgkill` supplies
    /// the tgid so a live tid from a different thread group is still ESRCH.
    pub fn live_task_for_thread(
        &self,
        required_task: Option<TaskId>,
        tid: LinuxTid,
    ) -> Option<TaskId> {
        self.live_keys_for_thread(required_task, tid)
            .map(|(task, _)| task.id)
    }

    pub(crate) fn live_keys_for_thread(
        &self,
        required_task: Option<TaskId>,
        tid: LinuxTid,
    ) -> Option<(TaskKey, ThreadKey)> {
        let state = self.registry().state.read();
        if let Some(task_id) = required_task {
            let record = state.tasks.get(&task_id)?;
            let thread = record.task.thread(tid)?;
            return (record.task.lifecycle() == TaskLifecycle::Live)
                .then_some((record.task.key(), thread.key()));
        }
        state.tasks.values().find_map(|record| {
            let thread = record.task.thread(tid)?;
            (record.task.lifecycle() == TaskLifecycle::Live)
                .then_some((record.task.key(), thread.key()))
        })
    }

    /// Post one thread-directed signal to an exact live `(tgid, tid)` pair.
    /// The pending queue is published before the task wake, matching the
    /// process-directed ordering in [`Self::post_signal_to_task`].
    #[cfg(test)]
    pub fn post_signal_to_thread(
        &self,
        target_task: TaskId,
        target_tid: LinuxTid,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        let (thread, task, parent) = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target_task) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            let Some(thread) = record.task.thread(target_tid) else {
                return false;
            };
            let parent = record
                .task
                .parent()
                .and_then(|key| state.tasks.get(&key.id).map(|record| (key, record)))
                .filter(|(key, record)| record.task.key() == *key)
                .map(|(_, record)| Arc::clone(&record.task));
            (thread, Arc::clone(&record.task), parent)
        };
        let generation = task.lock_signal_generation();
        if task.lifecycle() != TaskLifecycle::Live
            || task
                .thread(target_tid)
                .is_none_or(|current| !Arc::ptr_eq(&current, &thread))
        {
            return false;
        }
        task.discard_opposing_job_control_signals(signal);
        task.record_job_control_signal_generation(signal);
        thread.update_signal_state(|pending| {
            if signal.is_realtime() {
                pending.enqueue_realtime(signal, siginfo);
            } else {
                pending.enqueue_standard(signal, siginfo);
            }
        });
        let continued = if signal.raw() == carrick_abi::LINUX_SIGCONT {
            task.continue_from_job_control()
        } else if signal.raw() == carrick_abi::LINUX_SIGKILL {
            task.resume_from_job_control_for_fatal_signal();
            false
        } else {
            false
        };
        drop(generation);
        task.wake();
        if continued && let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    pub(super) fn retire_mm_io_state_if_unreferenced(&self, target: &Arc<Mm>) {
        let live = self
            .registry()
            .state
            .read()
            .tasks
            .values()
            .any(|record| Arc::ptr_eq(&record.task.shared().mm(), target));
        if !live {
            target.clear_io_uring_mappings();
        }
    }

    pub(crate) fn file_table_is_live_exact(&self, target: &Arc<FileTable>) -> bool {
        let state = self.registry().state.read();
        state.tasks.values().any(|record| {
            record.task.thread_keys().into_iter().any(|thread_key| {
                record
                    .task
                    .thread(thread_key.tid)
                    .is_some_and(|thread| Arc::ptr_eq(&thread.resources().files(), target))
            })
        })
    }

    pub(crate) fn retire_file_table_if_unreferenced(&self, target: &Arc<FileTable>) {
        self.retire_file_table_generation(target, None);
    }

    pub(super) fn retire_file_table_after_exec(
        &self,
        target: &Arc<FileTable>,
        successor: &Arc<FileTable>,
    ) {
        self.retire_file_table_generation(target, Some(successor));
    }

    fn retire_file_table_generation(
        &self,
        target: &Arc<FileTable>,
        successor: Option<&Arc<FileTable>>,
    ) {
        if self.file_table_is_live_exact(target) {
            return;
        }
        let events = target.drain_functional_refs();
        if events.is_empty() {
            return;
        }
        let successor_slots = successor.map(|table| table.read_open_files());
        self.pending_file_closes
            .lock()
            .extend(events.into_iter().map(|(fd, slot)| {
                let disposition = successor_slots
                    .as_ref()
                    .and_then(|slots| slots.get(&fd))
                    .filter(|survivor| Arc::ptr_eq(&survivor.description, &slot.description))
                    .map_or(super::core::FileCloseDisposition::Closed, |_| {
                        super::core::FileCloseDisposition::Transferred
                    });
                super::core::FileCloseEvent {
                    table: target.id(),
                    fd,
                    slot,
                    disposition,
                }
            }));
    }

    pub(crate) fn take_file_close_events(
        &self,
        table: super::ids::FileTableId,
    ) -> Vec<super::core::FileCloseEvent> {
        let mut pending = self.pending_file_closes.lock();
        let mut selected = Vec::new();
        let mut index = 0;
        while index < pending.len() {
            if pending[index].table == table {
                selected.push(pending.swap_remove(index));
            } else {
                index += 1;
            }
        }
        selected
    }

    pub fn task_key_is_live(&self, task: TaskKey) -> bool {
        self.registry()
            .state
            .read()
            .tasks
            .get(&task.id)
            .is_some_and(|record| record.task.key() == task)
    }

    pub fn task_exists(&self, task_id: TaskId) -> bool {
        let state = self.registry().state.read();
        state.tasks.contains_key(&task_id) || state.zombies.contains_key(&task_id)
    }

    pub fn register_task_exit_subscriber<T>(
        &self,
        task_id: TaskId,
        subscriber: &Arc<T>,
    ) -> Option<TaskKey>
    where
        T: super::core::TaskExitSubscriber + 'static,
    {
        let state = self.registry().state.read();
        if let Some(record) = state.tasks.get(&task_id) {
            let task = record.task.key();
            self.exit_subscribers.register(task, subscriber);
            return Some(task);
        }
        let exited = state.zombies.get(&task_id).map(|record| record.zombie.key);
        drop(state);
        if exited.is_some() {
            subscriber.publish_exit();
        }
        exited
    }

    pub fn reserve_fork(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
        diagnostic_name: String,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<ForkReservation, KernelOperationError> {
        self.sweep_retired_threads();
        if !Arc::ptr_eq(self, &parent.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        if plan.task() != CloneTaskMode::NewTask {
            return Err(KernelOperationError::ExpectedNewTask);
        }
        let transaction = self.object_ids().transaction_id()?;
        let (caller_revision, child_parent_task, child_parent_revision, operation) = {
            let mut state = self.registry().state.write();
            let caller_record = state
                .tasks
                .get(&parent.task.key().id)
                .ok_or(KernelOperationError::ParentExited)?;
            if caller_record.task.key() != parent.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            // Compare the PARENT ASSOCIATION, not the revision.
            //
            // A task's revision advances whenever any thread publishes a
            // child, so requiring equality here made two threads of one Linux
            // process unable to fork concurrently: the first commit advanced
            // the shared parent's revision and the sibling was refused with
            // `StaleContext`, which the guest sees as `EAGAIN`. Linux has no
            // such rule, and the Go toolchain forks concurrently from several
            // threads — that is why a cold `go build` reported
            // "fork/exec ...: resource temporarily unavailable".
            //
            // Reparenting matters only to CLONE_PARENT, because that operation
            // inherits the caller's parent association.  An ordinary fork
            // attaches its child to the exact caller task and remains valid if
            // the caller itself was reparented while a blocking backend
            // transaction quiesced its siblings.  Keep rejecting a stale
            // CLONE_PARENT context rather than silently selecting a different
            // parent generation. Thread/resource/shared identity is still
            // proven by the pointer checks below for every plan.
            if plan.fork_parent() == ForkParentMode::InheritCallerParent
                && caller_record.task.parent() != parent.parent_at_capture
            {
                return Err(KernelOperationError::StaleContext);
            }
            let caller_thread = caller_record
                .task
                .thread(parent.thread.key().tid)
                .ok_or(KernelOperationError::UnknownThread(parent.thread.key().tid))?;
            if !Arc::ptr_eq(&caller_thread, &parent.thread)
                || !Arc::ptr_eq(&caller_thread.resources(), &parent.resources)
                || !Arc::ptr_eq(&caller_record.task.shared(), &parent.shared)
            {
                return Err(KernelOperationError::StaleContext);
            }
            let caller_revision = caller_record.revision;
            let (child_parent_task, child_parent_revision) = match plan.fork_parent() {
                ForkParentMode::Caller => (Arc::clone(&parent.task), caller_revision),
                ForkParentMode::InheritCallerParent => {
                    let parent_key = parent.task.parent().ok_or(
                        KernelOperationError::CloneParentUnavailable(parent.task.key().id),
                    )?;
                    let parent_record = state
                        .tasks
                        .get(&parent_key.id)
                        .ok_or(KernelOperationError::ForkParentExited)?;
                    if parent_record.task.key() != parent_key {
                        return Err(KernelOperationError::ForkParentExited);
                    }
                    (Arc::clone(&parent_record.task), parent_record.revision)
                }
            };
            let operation = TaskSetReservation::acquired(
                self,
                &mut state,
                vec![parent.task.key().id, child_parent_task.key().id],
                transaction,
            )?;
            (
                caller_revision,
                child_parent_task,
                child_parent_revision,
                operation,
            )
        };
        let (child_id, task_reservation) = self.ids().reserve_task()?;
        let leader_claim = self.ids().claim_task_leader_thread(child_id)?;
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        let vfork_relationship =
            (plan.vfork() == VforkMode::SuspendParent).then(VforkChildRelease::pair);
        Ok(ForkReservation {
            kernel: self.clone(),
            operation,
            caller_task: Arc::clone(&parent.task),
            caller_thread: Arc::clone(&parent.thread),
            caller_shared: Arc::clone(&parent.shared),
            caller_resources: Arc::clone(&parent.resources),
            caller_revision,
            child_parent_task,
            child_parent_revision,
            plan,
            child_id,
            task_reservation,
            leader_claim,
            diagnostic_name,
            vfork_relationship,
            failpoint,
        })
    }

    #[cfg(test)]
    pub(super) fn fork_task(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
        child_registry_id: ThreadId,
        diagnostic_name: String,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<KernelContext, KernelOperationError> {
        if plan.vfork() == VforkMode::SuspendParent {
            return Err(KernelOperationError::VforkParentWaitRequired);
        }
        let published = self
            .reserve_fork(parent, plan, diagnostic_name, failpoint)?
            .prepare_reference(child_registry_id)?
            .commit()?;
        let (context, vfork_parent_wait) = published.into_parts()?;
        if vfork_parent_wait.is_some() {
            return Err(KernelOperationError::VforkParentWaitRequired);
        }
        Ok(context)
    }

    /// Reserve a Linux TID while keeping the thread undiscoverable. The
    /// execution adapter prepares its host registry/vCPU state from the typed
    /// TID, then supplies the distinct registry identity to `prepare`.
    pub fn reserve_thread_clone(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<ThreadCloneReservation, KernelOperationError> {
        self.sweep_retired_threads();
        if !Arc::ptr_eq(self, &parent.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        if plan.task() != CloneTaskMode::JoinThreadGroup {
            return Err(KernelOperationError::ExpectedThreadGroup);
        }
        {
            let state = self.registry().state.read();
            ensure_task_unreserved(&state, parent.task.key().id)?;
            let record = state
                .tasks
                .get(&parent.task.key().id)
                .ok_or(KernelOperationError::ParentExited)?;
            if record.task.key() != parent.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            let current_shared = record.task.shared();
            let current_caller = record
                .task
                .thread(parent.thread.key().tid)
                .ok_or(KernelOperationError::StaleContext)?;
            if !Arc::ptr_eq(&current_shared, &parent.shared)
                || current_caller.key() != parent.thread.key()
                || !Arc::ptr_eq(&current_caller, &parent.thread)
                || !Arc::ptr_eq(&current_caller.resources(), &parent.resources)
            {
                return Err(KernelOperationError::StaleContext);
            }
        }
        let (tid, reservation) = self.ids().reserve_thread()?;
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        Ok(ThreadCloneReservation {
            kernel: self.clone(),
            task: Arc::clone(&parent.task),
            caller: Arc::clone(&parent.thread),
            shared: Arc::clone(&parent.shared),
            parent_resources: Arc::clone(&parent.resources),
            plan,
            tid,
            reservation,
            failpoint,
        })
    }

    /// Reserve a thread identity after any overlapping task transaction
    /// completes. Callers must invoke this before taking backend topology locks.
    pub fn reserve_thread_clone_eventually(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
    ) -> Result<ThreadCloneReservation, KernelOperationError> {
        loop {
            let observed = self.reservation_epoch();
            match self.reserve_thread_clone(parent, plan, None) {
                Ok(reservation) => return Ok(reservation),
                Err(KernelOperationError::TaskBusy(_)) => {
                    self.wait_for_reservation_change(observed);
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(test)]
    pub(super) fn clone_thread(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
        registry_id: ThreadId,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<KernelContext, KernelOperationError> {
        self.reserve_thread_clone(parent, plan, failpoint)?
            .prepare(registry_id)?
            .commit()?
            .into_context()
    }

    /// Retire one non-final thread from the authoritative task graph. The TID
    /// claim drains only after every captured context releases its thread Arc.
    pub fn exit_thread(
        self: &Arc<Self>,
        context: &KernelContext,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<TaskRevision, KernelOperationError> {
        self.sweep_retired_threads();
        if !Arc::ptr_eq(self, &context.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        let files = context.resources.files();
        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, context.task.key().id)?;
        let record = state
            .tasks
            .get(&context.task.key().id)
            .ok_or(KernelOperationError::ParentExited)?;
        if record.task.key() != context.task.key() {
            return Err(KernelOperationError::ParentExited);
        }
        if context.task.live_thread_count() <= 1 {
            return Err(KernelOperationError::LastThreadRequiresTaskExit(
                context.thread.key().tid,
            ));
        }
        let tid = context.thread.key().tid;
        if context.task.thread(tid).is_none_or(|thread| {
            thread.key() != context.thread.key() || !Arc::ptr_eq(&thread, &context.thread)
        }) || !record.thread_claims.contains_key(&tid)
        {
            return Err(KernelOperationError::UnknownThread(tid));
        }
        let next = next_revision(record.revision)?;
        state
            .retired_threads
            .try_reserve_exact(1)
            .map_err(|_| KernelOperationError::RetiredThreadCapacity(1))?;
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

        let thread = context
            .task
            .retire_thread(context.thread.key())
            .ok_or(KernelOperationError::UnknownThread(tid))?;
        let record = state
            .tasks
            .get_mut(&context.task.key().id)
            .ok_or(KernelOperationError::ParentExited)?;
        let claim = record
            .thread_claims
            .remove(&tid)
            .ok_or(KernelOperationError::UnknownThread(tid))?;
        record.revision = next;
        if tid == LinuxTid::for_task_leader(context.task.key().id) {
            record.dead_leader = Some(super::core::RetiredThreadRecord {
                _key: thread.key(),
                _task: thread.task_key(),
                thread: Arc::downgrade(&thread),
                _claim: claim,
            });
        } else {
            state
                .retired_threads
                .push(super::core::RetiredThreadRecord {
                    _key: thread.key(),
                    _task: thread.task_key(),
                    thread: Arc::downgrade(&thread),
                    _claim: claim,
                });
        }
        drop(state);
        self.retire_file_table_if_unreferenced(&files);
        Ok(next)
    }

    /// Replace the fresh one-task adapter's empty table with an exact value
    /// copy of the inherited host-fork table. The new host process owns an
    /// independent fd namespace while every slot keeps the same open-description
    /// identity and host-fd backing inherited by `fork(2)`.
    pub fn copy_file_table_for_host_fork(
        self: &Arc<Self>,
        context: &KernelContext,
        inherited: &Arc<FileTable>,
    ) -> Result<KernelContext, KernelOperationError> {
        if !Arc::ptr_eq(self, &context.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        let task_id = context.task.key().id;
        loop {
            let observed = self.reservation_epoch();
            let state = self.registry().state.write();
            if let Err(KernelOperationError::TaskBusy(_)) = ensure_task_unreserved(&state, task_id)
            {
                drop(state);
                self.wait_for_reservation_change(observed);
                continue;
            }
            ensure_task_unreserved(&state, task_id)?;
            let record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::ParentExited)?;
            let thread = record.task.thread(context.thread.key().tid).ok_or(
                KernelOperationError::UnknownThread(context.thread.key().tid),
            )?;
            if record.task.key() != context.task.key()
                || thread.key() != context.thread.key()
                || !Arc::ptr_eq(&thread, &context.thread)
                || !Arc::ptr_eq(&thread.resources(), &context.resources)
            {
                return Err(KernelOperationError::StaleContext);
            }

            let old_files = context.resources.files();
            let files = Arc::new(FileTable::for_fork_copy(
                self.object_ids().file_table_id()?,
                inherited,
            ));
            let resources = Arc::new(context.resources.with_files(files));
            let revision = record.revision;
            let task = Arc::clone(&record.task);
            thread.replace_resources(Arc::clone(&resources));
            self.observe_thread_publication(&thread, &resources, revision);
            drop(state);
            self.retire_file_table_if_unreferenced(&old_files);
            return Ok(KernelContext::from_parts(
                self.clone(),
                task,
                thread,
                Arc::clone(&context.shared),
                resources,
                revision,
            ));
        }
    }

    /// Publish an immutable credential COW for exactly the calling thread.
    ///
    /// The captured resource bundle is validated under the registry write lock,
    /// then replaced with one `ArcSwap` publication. Sibling threads retain
    /// their prior credentials and in-flight syscalls retain their captured
    /// coherent bundle.
    pub fn update_credentials(
        self: &Arc<Self>,
        context: &KernelContext,
        update: impl FnOnce(&mut Credentials),
    ) -> Result<KernelContext, KernelOperationError> {
        if !Arc::ptr_eq(self, &context.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        let task_id = context.task.key().id;
        let mut update = Some(update);
        loop {
            let observed = self.reservation_epoch();
            let state = self.registry().state.write();
            if let Err(KernelOperationError::TaskBusy(_)) = ensure_task_unreserved(&state, task_id)
            {
                drop(state);
                self.wait_for_reservation_change(observed);
                continue;
            }
            ensure_task_unreserved(&state, task_id)?;
            let record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::ParentExited)?;
            if record.task.key() != context.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            let thread = record.task.thread(context.thread.key().tid).ok_or(
                KernelOperationError::UnknownThread(context.thread.key().tid),
            )?;
            if thread.key() != context.thread.key()
                || !Arc::ptr_eq(&thread, &context.thread)
                || !Arc::ptr_eq(&thread.resources(), &context.resources)
            {
                return Err(KernelOperationError::StaleContext);
            }

            let mut credentials = Credentials::for_copy(
                self.object_ids().credentials_id()?,
                &context.resources.credentials(),
            );
            update.take().ok_or(KernelOperationError::StaleContext)?(&mut credentials);
            let resources = Arc::new(context.resources.with_credentials(Arc::new(credentials)));
            // `TaskRevision` protects task topology and shared process state.
            // A thread-local credential COW changes neither; the exact
            // `ThreadResources` pointer and stable credential identity are the
            // publication generation for this association.
            let revision = record.revision;
            let task = Arc::clone(&record.task);
            thread.replace_resources(Arc::clone(&resources));
            if thread.key().tid == LinuxTid::for_task_leader(task_id) {
                task.replace_process_credentials(resources.credentials());
            }
            self.observe_thread_publication(&thread, &resources, revision);
            return Ok(KernelContext::from_parts(
                self.clone(),
                task,
                thread,
                Arc::clone(&context.shared),
                resources,
                revision,
            ));
        }
    }

    /// Publish one Linux umask change across every live thread that shares the
    /// caller's exact `FsContext`. Umask remains a typed `Credentials` value,
    /// but `CLONE_FS` defines its sharing domain; each affected thread receives
    /// a fresh credential register file preserving that thread's independent
    /// uid/gid state.
    pub fn update_fs_umask(
        self: &Arc<Self>,
        context: &KernelContext,
        umask: u32,
    ) -> Result<(KernelContext, u32), KernelOperationError> {
        if !Arc::ptr_eq(self, &context.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        let task_id = context.task.key().id;
        loop {
            let observed = self.reservation_epoch();
            let state = self.registry().state.write();
            match ensure_task_unreserved(&state, task_id) {
                Ok(()) => {}
                Err(KernelOperationError::TaskBusy(_)) => {
                    drop(state);
                    self.wait_for_reservation_change(observed);
                    continue;
                }
                Err(error) => return Err(error),
            }
            let caller_record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::ParentExited)?;
            if caller_record.task.key() != context.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            let caller_thread = caller_record.task.thread(context.thread.key().tid).ok_or(
                KernelOperationError::UnknownThread(context.thread.key().tid),
            )?;
            if caller_thread.key() != context.thread.key()
                || !Arc::ptr_eq(&caller_thread, &context.thread)
            {
                return Err(KernelOperationError::StaleContext);
            }

            // A concurrent CLONE_FS peer may have published a newer resource
            // generation after syscall entry. Retry from that authoritative
            // generation while the registry is locked, but only while the
            // exact caller still belongs to the captured FS domain. Copying
            // each thread's current credentials below preserves unrelated
            // concurrent credential changes rather than overwriting them.
            let fs_context = context.resources.fs_context();
            let caller_resources = caller_thread.resources();
            if !Arc::ptr_eq(&caller_resources.fs_context(), &fs_context) {
                return Err(KernelOperationError::StaleContext);
            }
            let previous_umask = caller_resources.credentials().umask();
            let mut affected = Vec::new();
            for record in state.tasks.values() {
                if record.task.lifecycle() != TaskLifecycle::Live {
                    continue;
                }
                for thread in record.task.threads() {
                    let resources = thread.resources();
                    if Arc::ptr_eq(&resources.fs_context(), &fs_context) {
                        affected.push((
                            record.task.key().id,
                            record.revision,
                            Arc::clone(&record.task),
                            thread,
                            resources,
                        ));
                    }
                }
            }

            if let Some(busy) = affected.iter().find_map(|(affected_task, ..)| {
                ensure_task_unreserved(&state, *affected_task).err()
            }) {
                if matches!(busy, KernelOperationError::TaskBusy(_)) {
                    drop(state);
                    self.wait_for_reservation_change(observed);
                    continue;
                }
                return Err(busy);
            }

            let mut prepared = Vec::with_capacity(affected.len());
            for (_, revision, task, thread, resources) in affected {
                let mut credentials = Credentials::for_copy(
                    self.object_ids().credentials_id()?,
                    &resources.credentials(),
                );
                credentials.set_umask(umask);
                let replacement = Arc::new(resources.with_credentials(Arc::new(credentials)));
                prepared.push((revision, task, thread, replacement));
            }

            if !prepared
                .iter()
                .any(|(_, _, thread, _)| thread.key() == context.thread.key())
            {
                return Err(KernelOperationError::StaleContext);
            }
            let mut caller_publication = None;
            for (revision, task, thread, replacement) in prepared {
                thread.replace_resources(Arc::clone(&replacement));
                self.observe_thread_publication(&thread, &replacement, revision);
                if thread.key() == context.thread.key() {
                    caller_publication = Some((revision, task, thread, replacement));
                }
            }
            let Some((revision, task, thread, resources)) = caller_publication else {
                tracing::error!("umask publication lost its already-validated caller");
                std::process::abort();
            };
            return Ok((
                KernelContext::from_parts(
                    self.clone(),
                    task,
                    thread,
                    Arc::clone(&context.shared),
                    resources,
                    revision,
                ),
                previous_umask,
            ));
        }
    }

    /// Test registry-locked association publication without invoking the exec
    /// backend stop/drain protocol.
    #[cfg(test)]
    pub(super) fn publish_task_associations(
        &self,
        task_id: TaskId,
        tid: LinuxTid,
        shared: Arc<TaskShared>,
        resources: Arc<ThreadResources>,
    ) -> Result<TaskRevision, KernelOperationError> {
        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let record = state
            .tasks
            .get_mut(&task_id)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        let thread = record
            .task
            .thread(tid)
            .ok_or(KernelOperationError::UnknownThread(tid))?;
        let revision = next_revision(record.revision)?;

        record.task.replace_shared(Arc::clone(&shared));
        thread.replace_resources(Arc::clone(&resources));
        record.revision = revision;
        self.observe_exec_publication(record.task.key(), &thread, &shared, &resources, revision);
        Ok(revision)
    }

    pub fn reserve_task_operation(
        &self,
        task_id: TaskId,
    ) -> Result<TaskOperationReservation, KernelOperationError> {
        self.sweep_retired_threads();
        let state = self.registry().state.read();
        ensure_task_unreserved(&state, task_id)?;
        let record = state
            .tasks
            .get(&task_id)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        Ok(TaskOperationReservation {
            domain: Arc::clone(self.domain()),
            task: record.task.key(),
            revision: record.revision,
        })
    }

    pub fn set_process_group(
        &self,
        caller_id: TaskId,
        target_id: Option<TaskId>,
        requested_group: Option<ProcessGroupId>,
    ) -> Result<(), KernelOperationError> {
        self.sweep_retired_threads();
        let target_id = target_id.unwrap_or(caller_id);
        let target_group =
            requested_group.unwrap_or_else(|| ProcessGroupId::from_leader(target_id));

        let prospective_claim = if target_group == ProcessGroupId::from_leader(target_id) {
            match self.ids().claim_process_group(target_group) {
                Ok(claim) => Some(claim),
                Err(IdError::UnknownNamespaceId(_)) => {
                    return Err(KernelOperationError::UnknownTask(target_id));
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };

        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, target_id)?;
        let caller = state
            .tasks
            .get(&caller_id)
            .map(|record| Arc::clone(&record.task))
            .ok_or(KernelOperationError::UnknownTask(caller_id))?;
        let (target, target_revision, target_has_execed) = state
            .tasks
            .get(&target_id)
            .map(|record| (Arc::clone(&record.task), record.revision, record.has_execed))
            .ok_or(KernelOperationError::UnknownTask(target_id))?;
        if target_id != caller_id {
            if target.parent().map(|parent| parent.id) != Some(caller_id) {
                return Err(KernelOperationError::UnknownTask(target_id));
            }
            if target_has_execed {
                return Err(KernelOperationError::ChildExeced(target_id));
            }
        }
        if target.session() != caller.session()
            || SessionId::from_leader(target_id) == target.session()
        {
            return Err(KernelOperationError::IdentityPermission);
        }
        if target.process_group() == target_group {
            return Ok(());
        }

        let group_exists = match state.process_groups.get(&target_group) {
            Some(group) if group.object.session() == caller.session() => true,
            Some(_) => return Err(KernelOperationError::IdentityPermission),
            None => false,
        };
        if !group_exists && target_group != ProcessGroupId::from_leader(target_id) {
            return Err(KernelOperationError::IdentityPermission);
        }

        let published_revision = next_revision(target_revision)?;
        if !group_exists {
            if !state.sessions.contains_key(&caller.session()) {
                return Err(KernelOperationError::IdentityObjectMissing);
            }
            let claim = prospective_claim.ok_or(KernelOperationError::IdentityPermission)?;
            let object = Arc::new(ProcessGroup::new(
                target_group,
                caller.session(),
                self.ids(),
                claim,
            )?);
            state
                .sessions
                .get_mut(&caller.session())
                .ok_or(KernelOperationError::IdentityObjectMissing)?
                .process_groups
                .insert(target_group);
            state.process_groups.insert(
                target_group,
                ProcessGroupRecord {
                    object,
                    members: std::collections::BTreeSet::new(),
                },
            );
        }

        let old_group = target.process_group();
        let session = target.session();
        remove_group_member(&mut state, old_group, session, target.key());
        let group = state
            .process_groups
            .get_mut(&target_group)
            .ok_or(KernelOperationError::IdentityObjectMissing)?;
        group.members.insert(target.key());
        target.replace_identity(target_group, session);
        if let Some(record) = state.tasks.get_mut(&target_id) {
            record.revision = published_revision;
        }
        Ok(())
    }

    pub fn join_process_group(
        &self,
        task_id: TaskId,
        target_group: ProcessGroupId,
    ) -> Result<(), KernelOperationError> {
        self.sweep_retired_threads();
        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some((task, revision)) = state
            .tasks
            .get(&task_id)
            .map(|record| (Arc::clone(&record.task), record.revision))
        else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        let old_group = task.process_group();
        let session = task.session();
        if old_group == target_group {
            return Ok(());
        }
        let Some(target) = state.process_groups.get(&target_group) else {
            return Err(KernelOperationError::UnknownProcessGroup(target_group));
        };
        if target.object.session() != session {
            return Err(KernelOperationError::CrossSessionProcessGroup);
        }
        let published_revision = next_revision(revision)?;

        remove_group_member(&mut state, old_group, session, task.key());
        if let Some(target) = state.process_groups.get_mut(&target_group) {
            target.members.insert(task.key());
        }
        task.replace_identity(target_group, session);
        if let Some(record) = state.tasks.get_mut(&task_id) {
            record.revision = published_revision;
        }
        Ok(())
    }

    pub fn create_process_group(
        &self,
        task_id: TaskId,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<ProcessGroupId, KernelOperationError> {
        let reservation = self.reserve_task_operation(task_id)?;
        self.create_process_group_reserved(reservation, failpoint)
    }

    pub fn create_process_group_reserved(
        &self,
        reservation: TaskOperationReservation,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<ProcessGroupId, KernelOperationError> {
        if !Arc::ptr_eq(&reservation.domain, self.domain()) {
            return Err(KernelOperationError::ForeignReservation);
        }
        let task_id = reservation.task.id;
        let task = {
            let state = self.registry().state.read();
            ensure_task_unreserved(&state, task_id)?;
            let record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::UnknownTask(task_id))?;
            if record.task.key() != reservation.task || record.revision != reservation.revision {
                return Err(KernelOperationError::StaleReservation);
            }
            Arc::clone(&record.task)
        };
        let session = task.session();
        let group_id = ProcessGroupId::from_leader(task_id);
        let claim = self.ids().claim_process_group(group_id)?;
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        let object = Arc::new(ProcessGroup::new(group_id, session, self.ids(), claim)?);
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some(current) = state
            .tasks
            .get(&task_id)
            .map(|record| Arc::clone(&record.task))
        else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        let current_revision = state
            .tasks
            .get(&task_id)
            .map(|record| record.revision)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        if current.key() != task.key()
            || current.key() != reservation.task
            || current.session() != session
            || current_revision != reservation.revision
        {
            return Err(KernelOperationError::TaskChangedBeforeCommit);
        }
        let published_revision = next_revision(current_revision)?;
        if state.process_groups.contains_key(&group_id) {
            return Err(KernelOperationError::ProcessGroupExists(group_id));
        }
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

        let old_group = current.process_group();
        state.process_groups.insert(
            group_id,
            ProcessGroupRecord {
                object,
                members: std::collections::BTreeSet::from([current.key()]),
            },
        );
        if let Some(session_record) = state.sessions.get_mut(&session) {
            session_record.process_groups.insert(group_id);
        }
        remove_group_member(&mut state, old_group, session, current.key());
        current.replace_identity(group_id, session);
        if let Some(record) = state.tasks.get_mut(&task_id) {
            record.revision = published_revision;
        }
        Ok(group_id)
    }

    pub fn create_session(
        &self,
        task_id: TaskId,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<SessionId, KernelOperationError> {
        let reservation = self.reserve_task_operation(task_id)?;
        self.create_session_reserved(reservation, failpoint)
    }

    pub fn create_session_reserved(
        &self,
        reservation: TaskOperationReservation,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<SessionId, KernelOperationError> {
        if !Arc::ptr_eq(&reservation.domain, self.domain()) {
            return Err(KernelOperationError::ForeignReservation);
        }
        let task_id = reservation.task.id;
        let task = {
            let state = self.registry().state.read();
            ensure_task_unreserved(&state, task_id)?;
            let record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::UnknownTask(task_id))?;
            if record.task.key() != reservation.task || record.revision != reservation.revision {
                return Err(KernelOperationError::StaleReservation);
            }
            Arc::clone(&record.task)
        };
        let old_group = task.process_group();
        let old_session = task.session();
        let group_id = ProcessGroupId::from_leader(task_id);
        let session_id = SessionId::from_leader(task_id);
        if old_group == group_id {
            return Err(KernelOperationError::AlreadyProcessGroupLeader);
        }
        let group_claim = self.ids().claim_process_group(group_id)?;
        let session_claim = self.ids().claim_session(session_id)?;
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        let group = Arc::new(ProcessGroup::new(
            group_id,
            session_id,
            self.ids(),
            group_claim,
        )?);
        let session = Arc::new(Session::new(session_id, self.ids(), session_claim)?);
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some(current) = state
            .tasks
            .get(&task_id)
            .map(|record| Arc::clone(&record.task))
        else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        let current_revision = state
            .tasks
            .get(&task_id)
            .map(|record| record.revision)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        if current.key() != task.key()
            || current.key() != reservation.task
            || current.process_group() != old_group
            || current.session() != old_session
            || current_revision != reservation.revision
        {
            return Err(KernelOperationError::TaskChangedBeforeCommit);
        }
        let published_revision = next_revision(current_revision)?;
        if state.process_groups.contains_key(&group_id) || state.sessions.contains_key(&session_id)
        {
            return Err(KernelOperationError::IdentityObjectExists);
        }
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

        remove_group_member(&mut state, old_group, old_session, current.key());
        state.process_groups.insert(
            group_id,
            ProcessGroupRecord {
                object: group,
                members: std::collections::BTreeSet::from([current.key()]),
            },
        );
        state.sessions.insert(
            session_id,
            SessionRecord {
                object: session,
                process_groups: std::collections::BTreeSet::from([group_id]),
            },
        );
        current.replace_identity(group_id, session_id);
        if let Some(record) = state.tasks.get_mut(&task_id) {
            record.revision = published_revision;
        }
        Ok(session_id)
    }

    /// Reserve every task identity and revision touched by exit publication.
    /// The backend may stop the task's vCPUs after this succeeds, but irreversible
    /// address-space/ASID retirement follows `PreparedTaskExit::commit`: a rare
    /// allocator abort must never leave a discoverable task without its backend.
    /// Dropping the token restores mutator access without changing task lifecycle
    /// or graph membership.
    pub fn prepare_task_exit(
        self: &Arc<Self>,
        task_id: TaskId,
        status: LinuxWaitStatus,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedTaskExit, KernelOperationError> {
        let task = self
            .registry()
            .state
            .read()
            .tasks
            .get(&task_id)
            .map(|record| record.task.key())
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        self.prepare_task_exit_key(task, status, failpoint)
    }

    pub fn prepare_task_exit_key(
        self: &Arc<Self>,
        task_key: TaskKey,
        status: LinuxWaitStatus,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedTaskExit, KernelOperationError> {
        self.prepare_task_exit_key_for_adopter(task_key, status, None, failpoint)
    }

    /// Reserve an exit that reparents the task's children to one exact live
    /// ancestor instead of the run root. Linux child subreapers use this path:
    /// the dispatcher supplies the nearest inherited subreaper as a generation-
    /// authenticated [`TaskKey`], and the same topology transaction reserves it
    /// with the exiting task and every child.
    pub fn prepare_task_exit_key_with_adopter(
        self: &Arc<Self>,
        task_key: TaskKey,
        status: LinuxWaitStatus,
        adopter: TaskKey,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedTaskExit, KernelOperationError> {
        self.prepare_task_exit_key_for_adopter(task_key, status, Some(adopter), failpoint)
    }

    fn prepare_task_exit_key_for_adopter(
        self: &Arc<Self>,
        task_key: TaskKey,
        status: LinuxWaitStatus,
        explicit_adopter: Option<TaskKey>,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedTaskExit, KernelOperationError> {
        self.sweep_retired_threads();
        let task_id = task_key.id;
        let transaction = self.object_ids().transaction_id()?;
        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some(task_record) = state.tasks.get(&task_id) else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        if task_record.task.key() != task_key {
            return Err(KernelOperationError::StaleTaskGeneration(task_id));
        }
        if task_record.task.lifecycle() == TaskLifecycle::Exiting {
            return Err(KernelOperationError::AlreadyExiting(task_id));
        }
        if state.zombies.contains_key(&task_id) {
            return Err(KernelOperationError::ExitTopologyChanged(task_id));
        }

        let task = Arc::clone(&task_record.task);
        let task_revision = task_record.revision;
        let diagnostic_name = task_record.diagnostic_name.clone();
        // The run's root task is the reparenting authority only while that
        // exact generation is live. HVPatch process threads are joined by the
        // outer runtime after individual process finalizers, so root teardown
        // can race a descendant's final Kernel publication. Once root has
        // already become a zombie, the descendant is an orphan with no live
        // adopter; targeting the retired root would make terminal cleanup fail
        // closed after the guest process has already exited.
        let adopter = if let Some(adopter_key) = explicit_adopter {
            let adopter_record = state
                .tasks
                .get(&adopter_key.id)
                .ok_or(KernelOperationError::UnknownTask(adopter_key.id))?;
            if adopter_record.task.key() != adopter_key {
                return Err(KernelOperationError::StaleTaskGeneration(adopter_key.id));
            }
            if adopter_record.task.lifecycle() != TaskLifecycle::Live {
                return Err(KernelOperationError::UnknownTask(adopter_key.id));
            }

            // An adopter must already be in the exiting task's authoritative
            // ancestry. This rejects accidental child/self adoption, which
            // would introduce a cycle when the children are published below.
            let mut ancestor = task.parent();
            let mut authenticated = false;
            while let Some(ancestor_key) = ancestor {
                if ancestor_key == adopter_key {
                    authenticated = true;
                    break;
                }
                let ancestor_record = state
                    .tasks
                    .get(&ancestor_key.id)
                    .filter(|record| record.task.key() == ancestor_key)
                    .ok_or(KernelOperationError::ExitTopologyChanged(ancestor_key.id))?;
                ancestor = ancestor_record.task.parent();
            }
            if !authenticated {
                return Err(KernelOperationError::ExitTopologyChanged(adopter_key.id));
            }
            Some(adopter_key)
        } else {
            (task_key != state.root)
                .then(|| {
                    state
                        .tasks
                        .get(&state.root.id)
                        .filter(|record| {
                            record.task.key() == state.root
                                && record.task.lifecycle() == TaskLifecycle::Live
                        })
                        .map(|record| record.task.key())
                })
                .flatten()
        };
        let mut children = task.children();
        children.sort_by_key(|child| child.serial);

        let mut reserved_ids = BTreeSet::from([task_id]);
        let mut affected_revisions = BTreeMap::new();
        for child_key in &children {
            reserved_ids.insert(child_key.id);
            if let Some(child) = state.tasks.get(&child_key.id) {
                if child.task.key() != *child_key {
                    return Err(KernelOperationError::ExitTopologyChanged(child_key.id));
                }
                affected_revisions.insert(
                    child_key.id,
                    (child.revision, next_revision(child.revision)?),
                );
            } else if state
                .zombies
                .get(&child_key.id)
                .is_none_or(|child| child.zombie.key != *child_key)
            {
                return Err(KernelOperationError::ExitTopologyChanged(child_key.id));
            }
        }

        let prepared_adopter_children = if let Some(adopter_key) = adopter {
            reserved_ids.insert(adopter_key.id);
            let adopter_record = state
                .tasks
                .get(&adopter_key.id)
                .filter(|record| record.task.key() == adopter_key)
                .ok_or(KernelOperationError::ExitTopologyChanged(adopter_key.id))?;
            affected_revisions.insert(
                adopter_key.id,
                (
                    adopter_record.revision,
                    next_revision(adopter_record.revision)?,
                ),
            );
            let mut prepared = adopter_record.task.children_set();
            prepared.extend(children.iter().copied());
            Some(prepared)
        } else {
            None
        };

        let registry_zombie = Zombie::from_task(&task, status, diagnostic_name);
        let result_zombie = registry_zombie.clone();
        let task_ids: Vec<_> = reserved_ids.into_iter().collect();
        let reservation = TaskSetReservation::acquired(self, &mut state, task_ids, transaction)?;
        drop(state);
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;
        Ok(PreparedTaskExit {
            reservation,
            task: task_key,
            task_revision,
            children,
            affected_revisions,
            adopter,
            prepared_adopter_children,
            registry_zombie,
            result_zombie,
        })
    }

    /// Publish a prepared task exit after vCPU drain and before irreversible
    /// backend retirement. All expected operational failure is resolved by
    /// `prepare_task_exit`; errors here denote an internal breach of the
    /// reservation contract, not a guest-visible retry condition.
    fn commit_task_exit(&self, prepared: PreparedTaskExit) -> Result<Zombie, KernelOperationError> {
        self.commit_task_exit_notifying(prepared, |_| {})
    }

    fn commit_task_exit_notifying(
        &self,
        mut prepared: PreparedTaskExit,
        notify_parent: impl FnOnce(Option<TaskKey>),
    ) -> Result<Zombie, KernelOperationError> {
        let mut state = self.registry().state.write();
        prepared.reservation.validate(&state)?;
        let Some(exiting_record) = state.tasks.get(&prepared.task.id) else {
            return Err(KernelOperationError::ExitTopologyChanged(prepared.task.id));
        };
        if exiting_record.task.key() != prepared.task
            || exiting_record.revision != prepared.task_revision
            || exiting_record.task.lifecycle() != TaskLifecycle::Live
        {
            return Err(KernelOperationError::ExitTopologyChanged(prepared.task.id));
        }
        for (affected_id, (expected, _)) in &prepared.affected_revisions {
            let Some(affected) = state.tasks.get(affected_id) else {
                return Err(KernelOperationError::ExitTopologyChanged(*affected_id));
            };
            if affected.revision != *expected {
                return Err(KernelOperationError::ExitTopologyChanged(*affected_id));
            }
        }
        for child_key in &prepared.children {
            let live_matches = state
                .tasks
                .get(&child_key.id)
                .is_some_and(|record| record.task.key() == *child_key);
            let zombie_matches = state
                .zombies
                .get(&child_key.id)
                .is_some_and(|record| record.zombie.key == *child_key);
            if !live_matches && !zombie_matches {
                return Err(KernelOperationError::ExitTopologyChanged(child_key.id));
            }
        }
        if !exiting_record.task.begin_exit() {
            return Err(KernelOperationError::AlreadyExiting(prepared.task.id));
        }
        let mut exiting_file_tables = Vec::new();
        for thread_key in exiting_record.task.thread_keys() {
            if let Some(thread) = exiting_record.task.thread(thread_key.tid) {
                let files = thread.resources().files();
                if !exiting_file_tables
                    .iter()
                    .any(|observed| Arc::ptr_eq(observed, &files))
                {
                    exiting_file_tables.push(files);
                }
            }
        }

        let record = state
            .tasks
            .remove(&prepared.task.id)
            .ok_or(KernelOperationError::ExitTopologyChanged(prepared.task.id))?;
        let TaskRecord {
            task,
            revision: _,
            task_claim,
            thread_claims,
            dead_leader,
            vfork_release,
            has_execed: _,
            diagnostic_name: _,
        } = record;
        for (tid, claim) in thread_claims {
            if let Some(thread) = task.thread(tid) {
                state
                    .retired_threads
                    .push(super::core::RetiredThreadRecord {
                        _key: thread.key(),
                        _task: thread.task_key(),
                        thread: Arc::downgrade(&thread),
                        _claim: claim,
                    });
            }
        }
        if let Some(dead_leader) = dead_leader {
            state.retired_threads.push(dead_leader);
        }

        for child_key in &prepared.children {
            if let Some(child) = state.tasks.get(&child_key.id) {
                child.task.reparent(prepared.adopter);
            } else if let Some(child) = state.zombies.get_mut(&child_key.id) {
                child.zombie.parent = prepared.adopter;
            }
        }
        if let (Some(adopter_key), Some(children)) =
            (prepared.adopter, prepared.prepared_adopter_children.take())
            && let Some(adopter_record) = state.tasks.get(&adopter_key.id)
        {
            adopter_record.task.publish_prepared_children(children);
        }
        for (affected_id, (_, published)) in &prepared.affected_revisions {
            if let Some(affected) = state.tasks.get_mut(affected_id) {
                affected.revision = *published;
            }
        }

        let process_group = task.process_group();
        let session = task.session();
        remove_group_member(&mut state, process_group, session, prepared.task);
        state.zombies.insert(
            prepared.task.id,
            ZombieRecord {
                zombie: prepared.registry_zombie,
                _task_claim: task_claim,
            },
        );
        // Detach this exact task generation's watchers before the zombie can
        // be consumed and its numeric claim eventually reused. Callbacks stay
        // outside the registry lock, but a later generation can no longer be
        // mistaken for this exit.
        let subscribers = self.exit_subscribers.take(prepared.task);
        drop(state);
        // Queue the parent's exit notification while every affected task is
        // still reserved. A consuming wait sees the durable zombie above but
        // gets TaskBusy until the signal is pending; this matches Linux's
        // observable ordering for a SIGCHLD handler immediately after waitpid.
        notify_parent(prepared.result_zombie.parent);
        let mut state = self.registry().state.write();
        prepared.reservation.commit(&mut state)?;
        drop(state);
        for files in &exiting_file_tables {
            self.retire_file_table_if_unreferenced(files);
        }
        if let Some(release) = vfork_release {
            release.release(VforkReleaseReason::Exit);
        }
        for subscriber in subscribers
            .into_iter()
            .filter_map(|subscriber| subscriber.upgrade())
        {
            subscriber.publish_exit();
        }
        Ok(prepared.result_zombie)
    }

    /// Convenience path for model callers without an external backend teardown.
    pub fn exit_task(
        self: &Arc<Self>,
        task_id: TaskId,
        status: LinuxWaitStatus,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<Zombie, KernelOperationError> {
        self.prepare_task_exit(task_id, status, failpoint)?.commit()
    }

    /// Publish terminal state for one exact task generation, waiting on the
    /// Kernel's reservation-change event for transient fork/exec/exit overlap.
    /// Re-observation of the same exact zombie is idempotent; a reused numeric
    /// PID with another serial is never mutated.
    pub fn exit_task_key_eventually(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
    ) -> Result<Zombie, KernelOperationError> {
        self.exit_task_key_eventually_for_adopter(task, status, None)
    }

    /// Publish terminal state and reparent children to one exact live ancestor,
    /// waiting through overlapping topology reservations just like the default
    /// run-root adoption path.
    pub fn exit_task_key_eventually_with_adopter(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        adopter: TaskKey,
    ) -> Result<Zombie, KernelOperationError> {
        self.exit_task_key_eventually_for_adopter(task, status, Some(adopter))
    }

    fn exit_task_key_eventually_for_adopter(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        adopter: Option<TaskKey>,
    ) -> Result<Zombie, KernelOperationError> {
        self.exit_task_key_eventually_for_adopter_notifying(task, status, adopter, |_| {})
    }

    /// Publish terminal state while queueing the exact parent's notification
    /// before releasing waiters on the exit reservation.
    pub fn exit_task_key_eventually_notifying(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        adopter: Option<TaskKey>,
        notify_parent: impl FnOnce(Option<TaskKey>),
    ) -> Result<Zombie, KernelOperationError> {
        self.exit_task_key_eventually_for_adopter_notifying(task, status, adopter, notify_parent)
    }

    fn exit_task_key_eventually_for_adopter_notifying(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        adopter: Option<TaskKey>,
        notify_parent: impl FnOnce(Option<TaskKey>),
    ) -> Result<Zombie, KernelOperationError> {
        let mut notify_parent = Some(notify_parent);
        loop {
            let observed = self.reservation_epoch();
            match self.prepare_task_exit_key_for_adopter(task, status, adopter, None) {
                Ok(prepared) => {
                    let Some(notify_parent) = notify_parent.take() else {
                        return Err(KernelOperationError::StaleReservation);
                    };
                    return prepared.commit_notifying(notify_parent);
                }
                Err(KernelOperationError::TaskBusy(_)) => {
                    self.wait_for_reservation_change(observed);
                }
                Err(KernelOperationError::UnknownTask(_)) => {
                    let state = self.registry().state.read();
                    if let Some(zombie) = state
                        .zombies
                        .get(&task.id)
                        .filter(|record| record.zombie.key == task)
                    {
                        return Ok(zombie.zombie.clone());
                    }
                    if state
                        .tasks
                        .get(&task.id)
                        .is_some_and(|record| record.task.key() != task)
                        || state
                            .zombies
                            .get(&task.id)
                            .is_some_and(|record| record.zombie.key != task)
                    {
                        return Err(KernelOperationError::StaleTaskGeneration(task.id));
                    }
                    return Err(KernelOperationError::UnknownTask(task.id));
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn wait_child(
        &self,
        parent_id: TaskId,
        target: Option<TaskId>,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(parent_id, target, None, None, WaitJobControl::NONE, mode)
    }

    pub fn wait_child_with_job_control(
        &self,
        parent_id: TaskId,
        target: Option<TaskId>,
        include_stopped: bool,
        include_continued: bool,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            target,
            None,
            None,
            WaitJobControl {
                stopped: include_stopped,
                continued: include_continued,
            },
            mode,
        )
    }

    pub fn wait_child_key(
        &self,
        parent_id: TaskId,
        target: TaskKey,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            Some(target.id),
            Some(target),
            None,
            WaitJobControl::NONE,
            mode,
        )
    }

    pub fn wait_child_in_process_group(
        &self,
        parent_id: TaskId,
        process_group: ProcessGroupId,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            None,
            None,
            Some(process_group),
            WaitJobControl::NONE,
            mode,
        )
    }

    pub fn wait_child_in_process_group_with_job_control(
        &self,
        parent_id: TaskId,
        process_group: ProcessGroupId,
        include_stopped: bool,
        include_continued: bool,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(
            parent_id,
            None,
            None,
            Some(process_group),
            WaitJobControl {
                stopped: include_stopped,
                continued: include_continued,
            },
            mode,
        )
    }

    fn wait_child_matching(
        &self,
        parent_id: TaskId,
        target: Option<TaskId>,
        exact_target: Option<TaskKey>,
        process_group: Option<ProcessGroupId>,
        job_control: WaitJobControl,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.sweep_retired_threads();
        let mut state = self.registry().state.write();
        if mode == WaitMode::Consume {
            ensure_task_unreserved(&state, parent_id)?;
        }
        let Some(parent) = state.tasks.get(&parent_id).map(|record| record.task.key()) else {
            return Err(KernelOperationError::UnknownTask(parent_id));
        };
        let exited = state
            .zombies
            .iter()
            .find(|(id, record)| {
                record.zombie.parent == Some(parent)
                    && process_group.is_none_or(|group| record.zombie.process_group == group)
                    && exact_target.map_or_else(
                        || target.is_none_or(|target| target == **id),
                        |target| target == record.zombie.key,
                    )
            })
            .map(|(id, record)| (*id, record.zombie.clone()));
        if let Some((id, zombie)) = exited {
            if mode == WaitMode::Consume {
                ensure_task_unreserved(&state, id)?;
                let parent_revision = state
                    .tasks
                    .get(&parent_id)
                    .map(|record| next_revision(record.revision))
                    .transpose()?
                    .ok_or(KernelOperationError::UnknownTask(parent_id))?;
                state.zombies.remove(&id);
                if let Some(parent_record) = state.tasks.get_mut(&parent_id) {
                    parent_record.task.remove_child(zombie.key);
                    // Reaping is the moment Linux moves a child's CPU into the
                    // parent's CHILDREN ledger — the child's own time plus what
                    // it had already reaped from its own children. Doing it here
                    // means only a CONSUMING wait charges it, so a WNOHANG poll
                    // or a WNOWAIT peek cannot double-count.
                    parent_record
                        .task
                        .charge_reaped_child(zombie.total_charge_to_reaper());
                    parent_record.revision = parent_revision;
                }
            }
            return Ok(WaitOutcome::Exited(zombie));
        }

        if job_control.stopped || job_control.continued {
            let state_change = state.tasks.iter().find_map(|(id, record)| {
                (record.task.parent() == Some(parent)
                    && process_group.is_none_or(|group| record.task.process_group() == group)
                    && exact_target.map_or_else(
                        || target.is_none_or(|target| target == *id),
                        |target| target == record.task.key(),
                    ))
                .then(|| {
                    record
                        .task
                        .waitable_job_control_event(
                            job_control.stopped,
                            job_control.continued,
                            mode == WaitMode::Consume,
                        )
                        .map(|event| match event {
                            TaskJobControlEvent::Stopped(signal) => {
                                WaitOutcome::Stopped { task: *id, signal }
                            }
                            TaskJobControlEvent::Continued => WaitOutcome::Continued { task: *id },
                        })
                })
                .flatten()
            });
            if let Some(state_change) = state_change {
                return Ok(state_change);
            }
        }

        let live_child = state.tasks.iter().any(|(id, record)| {
            record.task.parent() == Some(parent)
                && process_group.is_none_or(|group| record.task.process_group() == group)
                && exact_target.map_or_else(
                    || target.is_none_or(|target| target == *id),
                    |target| target == record.task.key(),
                )
        });
        Ok(if live_child {
            WaitOutcome::StillRunning
        } else {
            WaitOutcome::NoChild
        })
    }
}

fn next_revision(revision: TaskRevision) -> Result<TaskRevision, KernelOperationError> {
    revision
        .next()
        .ok_or(KernelOperationError::RevisionExhausted)
}

fn remove_group_member(
    state: &mut RegistryState,
    group_id: ProcessGroupId,
    session_id: SessionId,
    task: TaskKey,
) {
    let remove_group = if let Some(group) = state.process_groups.get_mut(&group_id) {
        group.members.remove(&task);
        group.members.is_empty()
    } else {
        false
    };
    if !remove_group {
        return;
    }
    state.process_groups.remove(&group_id);
    let remove_session = if let Some(session) = state.sessions.get_mut(&session_id) {
        session.process_groups.remove(&group_id);
        session.process_groups.is_empty()
    } else {
        false
    };
    if remove_session {
        state.sessions.remove(&session_id);
    }
}

fn ensure_task_unreserved(
    state: &RegistryState,
    task_id: TaskId,
) -> Result<(), KernelOperationError> {
    if state.reservations.contains_key(&task_id) {
        return Err(KernelOperationError::TaskBusy(task_id));
    }
    Ok(())
}

fn check_failpoint(
    selected: Option<KernelFailpoint>,
    point: KernelFailpoint,
) -> Result<(), KernelOperationError> {
    if selected == Some(point) {
        return Err(KernelOperationError::Injected(point));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum KernelOperationError {
    #[error(transparent)]
    ClonePlan(#[from] crate::kernel::ClonePlanError),
    #[error(transparent)]
    Id(#[from] IdError),
    #[error(transparent)]
    ObjectId(#[from] ObjectIdError),
    #[error(transparent)]
    ObjectGraph(#[from] ObjectGraphError),
    #[error(transparent)]
    TaskSharedClone(#[from] TaskSharedCloneError),
    #[error("kernel context belongs to another Kernel")]
    ForeignContext,
    #[error("clone plan creates a thread, not a new task")]
    ExpectedNewTask,
    #[error("clone plan creates a task, not a thread-group member")]
    ExpectedThreadGroup,
    #[error("copied-mm fork requires a prepared backend")]
    MissingForkMmBackend,
    #[error("fork caller's file table is already draining")]
    FileTableDraining,
    #[error("shared-mm fork cannot accept a replacement backend")]
    UnexpectedForkMmBackend,
    #[error("task {0:?} has no parent to inherit for CLONE_PARENT")]
    CloneParentUnavailable(TaskId),
    #[error("selected fork parent exited before commit")]
    ForkParentExited,
    #[error("selected fork parent changed before commit")]
    ForkParentChanged,
    #[error("fork does not request a pidfd subscription")]
    UnexpectedPidfdSubscription,
    #[error("fork already has a reserved pidfd subscription")]
    PidfdSubscriptionExists,
    #[error("fork child start wait handle was already transferred")]
    ChildStartWaitTaken,
    #[error("published fork start state was already consumed")]
    PublishedForkConsumed,
    #[error("published thread-clone start state was already consumed")]
    PublishedThreadCloneConsumed,
    #[error("vfork publication must retain its parent wait handle")]
    VforkParentWaitRequired,
    #[error("CLONE_PIDFD fork has no reserved exit subscription")]
    MissingPidfdSubscription,
    #[error("parent task exited before commit")]
    ParentExited,
    #[error("kernel context revision is stale")]
    StaleContext,
    #[error("kernel operation reservation is stale")]
    StaleReservation,
    #[error("kernel operation reservation belongs to another Kernel")]
    ForeignReservation,
    #[error("task {0:?} changed after exit preparation")]
    ExitTopologyChanged(TaskId),
    #[error("task revision space is exhausted")]
    RevisionExhausted,
    #[error("could not reserve {0} retired-thread records")]
    RetiredThreadCapacity(usize),
    #[error("task's process-group or session object disappeared before commit")]
    IdentityObjectMissing,
    #[error("kernel task {0:?} is not live")]
    UnknownTask(TaskId),
    #[error("kernel task {0:?} belongs to another generation")]
    StaleTaskGeneration(TaskId),
    #[error("kernel task {0:?} has a preparing operation")]
    TaskBusy(TaskId),
    #[error("kernel thread {0:?} is not live")]
    UnknownThread(LinuxTid),
    #[error("final thread {0:?} must retire through task exit")]
    LastThreadRequiresTaskExit(LinuxTid),
    #[error("kernel task {0:?} is already exiting")]
    AlreadyExiting(TaskId),
    #[error("process group {0:?} does not exist")]
    UnknownProcessGroup(ProcessGroupId),
    #[error("process group {0:?} already exists")]
    ProcessGroupExists(ProcessGroupId),
    #[error("task and target process group belong to different sessions")]
    CrossSessionProcessGroup,
    #[error("task identity changed before the operation committed")]
    TaskChangedBeforeCommit,
    #[error("process-group or session identity already exists")]
    IdentityObjectExists,
    #[error("child task {0:?} has completed exec")]
    ChildExeced(TaskId),
    #[error("process-group identity change is not permitted")]
    IdentityPermission,
    #[error("a process-group leader cannot create a session")]
    AlreadyProcessGroupLeader,
    #[error("injected kernel operation failure at {0:?}")]
    Injected(KernelFailpoint),
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use carrick_abi::{LinuxCloneFlags, LinuxSigaction, SigSet};
    use carrick_guest_mem::Gpa;
    use proptest::prelude::*;

    use super::*;
    use crate::kernel::{
        Asid, Credentials, FileDescription, FileSlotNumber, FileTable, FsContext, LinuxSignal, Mm,
        MmBackendSnapshot, MmBinding, RootBootstrap, Sighand, SignalDisposition, SnapshotError,
        Stage1Root, ThreadSignalState,
    };

    #[derive(Debug, Default)]
    struct CountingExitSubscriber(AtomicUsize);

    impl super::super::core::TaskExitSubscriber for CountingExitSubscriber {
        fn publish_exit(&self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }

    #[derive(Debug)]
    struct TestMmBackend(MmBinding);

    impl MmBackend for TestMmBackend {
        fn snapshot(
            &self,
            _deadline: std::time::Instant,
        ) -> Result<MmBackendSnapshot, SnapshotError> {
            Ok(MmBackendSnapshot {
                revision: 1,
                binding: self.0,
                vmas: Vec::new(),
                vma_revision: None,
                mapping_ids: Vec::new(),
                frame_inventory_revision: None,
            })
        }

        fn revision(&self) -> u64 {
            1
        }
    }

    fn test_binding() -> MmBinding {
        let asid = Asid::from_registry_allocation(NonZeroU16::new(7).expect("nonzero ASID"));
        let root = Stage1Root::for_aarch64_4k(Gpa(0x8000)).expect("aligned root");
        MmBinding::for_aarch64(asid, root)
    }

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "root".to_string(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    #[test]
    fn task_exit_subscribers_observe_live_zombie_and_unknown_targets() {
        let (kernel, root) = bootstrap(75);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_075),
                "child".to_string(),
                None,
            )
            .expect("child");
        let child_id = child.task.key().id;
        let live = Arc::new(CountingExitSubscriber::default());
        assert!(kernel.task_is_live(child_id));
        assert!(kernel.task_exists(child_id));
        assert_eq!(
            kernel.register_task_exit_subscriber(child_id, &live),
            Some(child.task.key())
        );
        assert_eq!(live.0.load(Ordering::Acquire), 0);

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("child exit");
        assert!(!kernel.task_is_live(child_id));
        assert!(kernel.task_exists(child_id));
        assert_eq!(live.0.load(Ordering::Acquire), 1);

        let zombie = Arc::new(CountingExitSubscriber::default());
        assert_eq!(
            kernel.register_task_exit_subscriber(child_id, &zombie),
            Some(child.task.key())
        );
        assert_eq!(zombie.0.load(Ordering::Acquire), 1);
        let unknown = Arc::new(CountingExitSubscriber::default());
        let unknown_id = TaskId::for_root_bootstrap(9_999).expect("unknown task");
        assert_eq!(
            kernel.register_task_exit_subscriber(unknown_id, &unknown),
            None
        );
        assert_eq!(unknown.0.load(Ordering::Acquire), 0);
    }

    #[test]
    fn exact_pidfd_generation_never_follows_a_reused_numeric_pid() {
        let (kernel, root) = bootstrap(76);
        let root_binding = root.task_binding();
        let root_tid = root.thread().key().tid;
        let child_a = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_076),
                "child-a".to_string(),
                None,
            )
            .expect("child A");
        let child_a_key = child_a.task().key();
        let pidfd_watch = Arc::new(CountingExitSubscriber::default());
        assert_eq!(
            kernel.register_task_exit_subscriber(child_a_key.id, &pidfd_watch),
            Some(child_a_key)
        );
        kernel
            .exit_task_key_eventually(child_a_key, LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit child A");
        assert_eq!(pidfd_watch.0.load(Ordering::Acquire), 1);
        drop(child_a);
        assert!(matches!(
            kernel.wait_child(
                root.task().key().id,
                Some(child_a_key.id),
                WaitMode::Consume
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        kernel.ids().set_next_for_tests(child_a_key.id.raw());

        let fresh_root = root_binding.capture(root_tid).expect("fresh root context");
        let child_b = kernel
            .fork_task(
                &fresh_root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_077),
                "child-b".to_string(),
                None,
            )
            .expect("child B");
        assert_eq!(child_b.task().key().id, child_a_key.id);
        assert_ne!(child_b.task().key(), child_a_key);
        assert!(!kernel.task_key_is_live(child_a_key));
        assert!(kernel.task_key_is_live(child_b.task().key()));
        assert_eq!(
            kernel
                .wait_child_key(root.task().key().id, child_a_key, WaitMode::Observe)
                .expect("exact old-generation wait"),
            WaitOutcome::NoChild
        );

        kernel
            .exit_task_key_eventually(child_b.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit child B");
        assert_eq!(pidfd_watch.0.load(Ordering::Acquire), 1);
    }

    #[test]
    fn authorized_signal_never_follows_a_reused_numeric_pid() {
        let (kernel, root) = bootstrap(78);
        let root_binding = root.task_binding();
        let root_tid = root.thread().key().tid;
        let child_a = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_078),
                "signal-child-a".to_string(),
                None,
            )
            .expect("child A");
        let child_a_key = child_a.task().key();
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let ticket =
            match kernel.authorize_signal_target_exact(&root, child_a_key, None, Some(sigusr1)) {
                ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
                other => panic!("child A should authorize before exit: {other:?}"),
            };

        kernel
            .exit_task_key_eventually(child_a_key, LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit child A");
        drop(child_a);
        assert!(matches!(
            kernel.wait_child(
                root.task().key().id,
                Some(child_a_key.id),
                WaitMode::Consume
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        kernel.ids().set_next_for_tests(child_a_key.id.raw());

        let fresh_root = root_binding.capture(root_tid).expect("fresh root context");
        let child_b = kernel
            .fork_task(
                &fresh_root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_079),
                "signal-child-b".to_string(),
                None,
            )
            .expect("child B");
        assert_eq!(child_b.task().key().id, child_a_key.id);
        assert_ne!(child_b.task().key(), child_a_key);

        assert!(
            !kernel.post_signal_to_authorized_target(&ticket, sigusr1, None),
            "the old-generation authorization ticket must fail closed",
        );
        assert!(
            !child_b
                .task()
                .shared()
                .pending_signals()
                .present()
                .contains(sigusr1.raw()),
            "the reused PID must not receive child A's authorized signal",
        );
    }

    #[test]
    fn exact_authorized_self_signals_preserve_process_and_thread_queue_ownership() {
        let (kernel, root) = bootstrap(80);
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let sigusr2 = LinuxSignal::for_signal_number(12).expect("SIGUSR2");
        let process_ticket = match kernel.authorize_signal_target_exact(
            &root,
            root.task().key(),
            None,
            Some(sigusr1),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("self process target must authorize: {other:?}"),
        };
        let thread_ticket = match kernel.authorize_signal_target_exact(
            &root,
            root.task().key(),
            Some(root.thread().key()),
            Some(sigusr2),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("self thread target must authorize: {other:?}"),
        };

        assert!(kernel.post_signal_to_authorized_target(&process_ticket, sigusr1, None));
        assert!(kernel.post_signal_to_authorized_target(&thread_ticket, sigusr2, None));
        assert!(
            root.task()
                .shared()
                .pending_signals()
                .present()
                .contains(sigusr1.raw())
        );
        let thread_pending = root.thread().signal_state().pending();
        assert!(thread_pending.contains(sigusr2.raw()));
        assert!(!thread_pending.contains(sigusr1.raw()));
    }

    #[test]
    fn child_exit_receipt_uses_parent_committed_during_reservation_wait() {
        let (kernel, root) = bootstrap(77);
        let parent = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_078),
                "parent".to_string(),
                None,
            )
            .expect("parent");
        let child = kernel
            .fork_task(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_079),
                "child".to_string(),
                None,
            )
            .expect("child");
        let prepared_parent = kernel
            .prepare_task_exit_key(
                parent.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare parent exit");
        let exiting_kernel = Arc::clone(&kernel);
        let child_key = child.task().key();
        let child_exit = std::thread::spawn(move || {
            exiting_kernel
                .exit_task_key_eventually(child_key, LinuxWaitStatus::from_wait_encoding(0))
        });
        prepared_parent.commit().expect("commit parent exit");
        let zombie = child_exit
            .join()
            .expect("child exit thread")
            .expect("child exit");
        assert_eq!(zombie.parent, Some(root.task().key()));
        assert_ne!(zombie.parent, Some(parent.task().key()));
    }

    #[test]
    fn explicit_subreaper_adopts_orphans_at_exit_publication() {
        let (kernel, root) = bootstrap(78);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let subreaper = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(9_080),
                "subreaper".to_string(),
                None,
            )
            .expect("subreaper");
        let parent = kernel
            .fork_task(
                &subreaper,
                fork_plan,
                ThreadId::synthetic_for_tests(9_081),
                "parent".to_string(),
                None,
            )
            .expect("parent");
        let child = kernel
            .fork_task(
                &parent,
                fork_plan,
                ThreadId::synthetic_for_tests(9_082),
                "orphan".to_string(),
                None,
            )
            .expect("orphan");

        let zombie = kernel
            .exit_task_key_eventually_with_adopter(
                parent.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                subreaper.task().key(),
            )
            .expect("parent exit through exact subreaper");

        assert_eq!(zombie.parent, Some(subreaper.task().key()));
        assert_eq!(child.task().parent(), Some(subreaper.task().key()));
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn exit_notification_precedes_reservation_release() {
        let (kernel, root) = bootstrap(79);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_083),
                "signal-before-wait".to_string(),
                None,
            )
            .expect("child");
        let hook_epoch = std::sync::atomic::AtomicU64::new(0);

        kernel
            .exit_task_key_eventually_notifying(
                child.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
                |parent| {
                    assert_eq!(parent, Some(root.task().key()));
                    hook_epoch.store(kernel.reservation_epoch(), Ordering::Release);
                },
            )
            .expect("child exit");

        assert_ne!(hook_epoch.load(Ordering::Acquire), 0);
        assert!(
            kernel.reservation_epoch() > hook_epoch.load(Ordering::Acquire),
            "waiters must be released only after the parent notification hook",
        );
    }

    #[test]
    fn root_exit_before_descendant_exit_allows_orphan_teardown() {
        let (kernel, root) = bootstrap(78);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_080),
                "root-orphan".to_string(),
                None,
            )
            .expect("child");

        let root_zombie = kernel
            .exit_task_key_eventually(root.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("root exit");
        assert_eq!(root_zombie.parent, None);
        assert_eq!(child.task().parent(), None);

        let child_zombie = kernel
            .exit_task_key_eventually(child.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("orphan exit after root");
        assert_eq!(child_zombie.parent, None);
    }

    #[test]
    fn umask_updates_every_live_clone_fs_peer_without_sharing_identity() {
        let (kernel, root) = bootstrap(79);
        let shared = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::FS).expect("CLONE_FS plan"),
                ThreadId::synthetic_for_tests(9_081),
                "shared-fs".to_string(),
                None,
            )
            .expect("shared-FS child");
        let root_after_shared_fork = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("root after shared-FS fork");
        let private = kernel
            .fork_task(
                &root_after_shared_fork,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_082),
                "private-fs".to_string(),
                None,
            )
            .expect("private-FS child");
        let shared = kernel
            .update_credentials(&shared, |credentials| {
                credentials.seed_identity(1001, 2001);
            })
            .expect("independent child identity");
        let root_context = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("fresh root context");
        let (_, previous) = kernel
            .update_fs_umask(&root_context, 0o077)
            .expect("publish shared umask");
        assert_eq!(previous, 0o022);
        // The exact syscall-entry context is now a stale resource generation.
        // A serialized CLONE_FS peer update must retry against the current
        // authoritative generation and return that generation's previous mask.
        let (_, previous) = kernel
            .update_fs_umask(&root_context, 0o027)
            .expect("retry stale shared-FS generation");
        assert_eq!(previous, 0o077);

        let root_after = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("root after umask");
        let shared_after = shared
            .task_binding()
            .capture(shared.thread().key().tid)
            .expect("shared peer after umask");
        let private_after = private
            .task_binding()
            .capture(private.thread().key().tid)
            .expect("private peer after umask");
        assert_eq!(root_after.resources().credentials().umask(), 0o027);
        assert_eq!(shared_after.resources().credentials().umask(), 0o027);
        assert_eq!(shared_after.resources().credentials().euid(), 1001);
        assert_eq!(private_after.resources().credentials().umask(), 0o022);
    }

    #[test]
    fn fork_publishes_task_and_independently_selected_resources() {
        let (kernel, root) = bootstrap(100);
        let ignored = LinuxSignal::for_signal_number(2).expect("ignored signal");
        let caught = LinuxSignal::for_signal_number(3).expect("caught signal");
        let mut ignored_action = LinuxSigaction::empty();
        ignored_action.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        root.shared
            .sighand()
            .install_action(ignored, ignored_action);
        let mut caught_action = LinuxSigaction::empty();
        caught_action.sa_handler = 0x3000;
        root.shared.sighand().install_action(caught, caught_action);
        let parent_signals =
            ThreadSignalState::new(SigSet::EMPTY.with(4), SigSet::EMPTY.with(5), true, 2);
        root.thread.replace_signal_state(parent_signals.clone());
        let slot = FileSlotNumber::for_open_fd(3).expect("file slot");
        let description = Arc::new(FileDescription::regular(
            kernel
                .object_ids()
                .file_description_id()
                .expect("description"),
        ));
        assert!(
            root.resources
                .files()
                .install(slot, Arc::clone(&description), false)
                .is_none()
        );
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let child = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(101),
                "child".to_string(),
                None,
            )
            .expect("fork");

        assert_eq!(kernel.registry().task_count(), 2);
        assert_eq!(child.task.parent(), Some(root.task.key()));
        assert_eq!(
            kernel
                .task_identity(child.task.key().id)
                .expect("child identity"),
            TaskIdentity {
                task: child.task.key(),
                parent: Some(root.task.key()),
                mm: child.shared.mm().id(),
                process_group: root.task.process_group(),
                session: root.task.session(),
            }
        );
        assert!(!Arc::ptr_eq(&root.shared.mm(), &child.shared.mm()));
        assert_ne!(root.shared.mm().id(), child.shared.mm().id());
        assert!(!Arc::ptr_eq(
            &root.resources.files(),
            &child.resources.files()
        ));
        assert_ne!(root.resources.files().id(), child.resources.files().id());
        assert_ne!(
            root.resources.fs_context().id(),
            child.resources.fs_context().id()
        );
        assert_ne!(root.shared.sighand().id(), child.shared.sighand().id());
        assert_eq!(
            child.shared.sighand().disposition(ignored),
            SignalDisposition::Ignore
        );
        assert_eq!(
            child.shared.sighand().disposition(caught),
            SignalDisposition::Caught
        );
        let child_signals = child.thread.signal_state();
        assert_eq!(child_signals.blocked(), parent_signals.blocked());
        assert!(child_signals.pending().is_empty());
        assert!(child_signals.altstack_enabled());
        assert_eq!(child_signals.handler_frame_depth(), 2);
        let child_slot = child
            .resources
            .files()
            .slot(slot)
            .expect("fork copies file slot");
        assert!(Arc::ptr_eq(&child_slot.description(), &description));
    }

    #[test]
    fn child_start_gate_opens_only_after_fork_publication() {
        let (kernel, root) = bootstrap(149);
        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "gated child".to_owned(),
                None,
            )
            .expect("reserve fork");
        let child_id = reservation.child_id();
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(150))
            .expect("prepare fork");
        let prepared_child_mm = prepared.child_mm_id();
        let wait = prepared.take_child_start_wait().expect("unique child wait");
        assert!(matches!(
            prepared.take_child_start_wait(),
            Err(KernelOperationError::ChildStartWaitTaken)
        ));
        let (waiting_tx, waiting_rx) = std::sync::mpsc::sync_channel(1);
        let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            waiting_tx.send(()).expect("report waiting");
            outcome_tx.send(wait.wait()).expect("report outcome");
        });
        waiting_rx.recv().expect("child reached gate");
        assert!(!kernel.task_is_live(child_id));
        assert!(matches!(
            outcome_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        let published = prepared.commit().expect("publish fork");
        assert!(kernel.task_is_live(child_id));
        assert!(matches!(
            outcome_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        let started = published.start_child().expect("start published child");
        assert_eq!(
            outcome_rx.recv().expect("started outcome"),
            ChildStartOutcome::Started
        );
        waiter.join().expect("join child waiter");
        let (child, _) = started.into_parts();
        assert_eq!(child.task.key().id, child_id);
        assert_eq!(child.shared.mm().id(), prepared_child_mm);
    }

    #[test]
    fn dropped_fork_preparation_cancels_materialized_child_gate() {
        let (kernel, root) = bootstrap(151);
        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "cancelled child".to_owned(),
                None,
            )
            .expect("reserve fork");
        let child_id = reservation.child_id();
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(152))
            .expect("prepare fork");
        let wait = prepared.take_child_start_wait().expect("unique child wait");
        let waiter = std::thread::spawn(move || wait.wait());

        drop(prepared);
        assert_eq!(
            waiter.join().expect("join cancelled child"),
            ChildStartOutcome::Cancelled
        );
        assert!(!kernel.task_is_live(child_id));
        assert_eq!(kernel.registry().task_count(), 1);
    }

    /// `killpg` must resolve its members from the KERNEL, not the host. On the
    /// kernel lane every Linux process is a thread of one host process, so they
    /// share one host process group and a guest pgid means nothing to
    /// `libc::kill` — and a guest pgid of 1 negates to the host BROADCAST
    /// sentinel.
    #[test]
    fn process_group_membership_comes_from_the_kernel() {
        let (kernel, root) = bootstrap(7);
        let root_id = root.task().key().id;
        let group = root.task().process_group();

        // A lone root is its own group.
        assert_eq!(kernel.tasks_in_process_group(group), vec![root_id]);

        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "group child".to_owned(),
                None,
            )
            .expect("reserve fork");
        let child_id = reservation.child_id();
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(701))
            .expect("prepare fork");
        let wait = prepared.take_child_start_wait().expect("child wait");
        let waiter = std::thread::spawn(move || wait.wait());
        let published = prepared.commit().expect("publish fork");
        drop(published);
        waiter.join().expect("join child");

        // A fork inherits its parent's group, so both are members and the order
        // is deterministic.
        assert_eq!(
            kernel.tasks_in_process_group(group),
            vec![root_id, child_id],
            "a forked child inherits its parent's process group"
        );

        // Exiting removes it: a killpg must never target a zombie.
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
        assert_eq!(kernel.tasks_in_process_group(group), vec![root_id]);
    }

    #[test]
    fn signal_authorization_uses_kernel_credentials_sessions_and_init_sighand() {
        let (kernel, root) = bootstrap(1);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(703),
                "signal authorization child".to_owned(),
                None,
            )
            .expect("fork child");
        let root = kernel
            .update_credentials(&root, |credentials| credentials.seed_identity(1000, 1000))
            .expect("set caller credentials");
        let child = kernel
            .update_credentials(&child, |credentials| credentials.seed_identity(2000, 2000))
            .expect("set target credentials");
        let child_id = child.task().key().id;
        let child_tid = child.thread().key().tid;
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, None, Some(sigusr1)),
            SignalTargetAuthorization::Denied,
            "process-directed delivery must compare authoritative kernel credentials",
        );
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, Some(child_tid), None),
            SignalTargetAuthorization::Denied,
            "thread-directed signal zero must enforce the target thread credentials",
        );
        assert_eq!(
            kernel.tasks_for_broadcast(root.task().key().id),
            vec![child_id]
        );
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, None, None),
            SignalTargetAuthorization::Denied,
            "broadcast signal zero must filter a member with forbidden credentials",
        );
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, Some(child_tid), Some(sigcont)),
            SignalTargetAuthorization::Allowed,
            "SIGCONT is permitted within the same authoritative guest session",
        );

        let (kernel, init) = bootstrap(1);
        let sender = kernel
            .fork_task(
                &init,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(704),
                "init signal sender".to_owned(),
                None,
            )
            .expect("fork sender");
        let init_id = init.task().key().id;
        let sigterm = LinuxSignal::for_signal_number(15).expect("SIGTERM");
        assert_eq!(
            kernel.authorize_signal_target(&sender, init_id, None, Some(sigterm)),
            SignalTargetAuthorization::DropProtectedInit,
            "an unhandled default-lethal signal to guest init is accepted but dropped",
        );
        for signum in [
            carrick_abi::LINUX_SIGTSTP,
            carrick_abi::LINUX_SIGTTIN,
            carrick_abi::LINUX_SIGTTOU,
        ] {
            let signal = LinuxSignal::for_signal_number(signum).expect("terminal stop signal");
            assert_eq!(
                kernel.authorize_signal_target(&sender, init_id, None, Some(signal)),
                SignalTargetAuthorization::DropProtectedInit,
                "default terminal-stop signal {signum} must not stop guest init",
            );
        }
        let mut caught = carrick_abi::LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        init.shared().sighand().install_action(sigterm, caught);
        assert_eq!(
            kernel.authorize_signal_target(&sender, init_id, None, Some(sigterm)),
            SignalTargetAuthorization::Allowed,
            "guest init may receive a signal for which it installed a handler",
        );
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        init.shared().sighand().install_action(sigtstp, caught);
        assert_eq!(
            kernel.authorize_signal_target(&sender, init_id, None, Some(sigtstp)),
            SignalTargetAuthorization::Allowed,
            "guest init may catch a terminal-stop signal",
        );
        for signum in [carrick_abi::LINUX_SIGKILL, carrick_abi::LINUX_SIGSTOP] {
            let signal = LinuxSignal::for_signal_number(signum).expect("uncatchable signal");
            assert_eq!(
                kernel.authorize_signal_target(&sender, init_id, None, Some(signal)),
                SignalTargetAuthorization::Allowed,
                "signal {signum} must not take default-action init immunity",
            );
        }
    }

    #[test]
    fn signal_target_enumeration_excludes_tasks_that_have_begun_exit() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "exiting signal target", 705);
        let group = root.task().process_group();
        {
            let state = kernel.registry().state.read();
            let child = &state.tasks.get(&child_id).expect("live child").task;
            assert!(child.begin_exit());
        }

        assert_eq!(
            kernel.tasks_in_process_group(group),
            vec![root.task().key().id]
        );
        assert!(kernel.tasks_for_broadcast(root.task().key().id).is_empty());
    }

    #[test]
    fn process_signal_authority_survives_leader_thread_exit() {
        let (kernel, root) = bootstrap(1);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(706),
                "leader-exit signal target".to_owned(),
                None,
            )
            .expect("fork target");
        let sibling = kernel
            .clone_thread(
                &child,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(707),
                None,
            )
            .expect("clone sibling");
        let child_id = child.task().key().id;
        let root = kernel
            .update_credentials(&root, |credentials| credentials.seed_identity(2000, 2000))
            .expect("set non-root caller credentials");
        let child = kernel
            .update_credentials(&child, |credentials| credentials.seed_identity(2000, 2000))
            .expect("set leader credentials");
        kernel
            .exit_thread(&child, None)
            .expect("retire non-final leader");

        assert!(sibling.exact_thread_is_live());
        assert!(
            kernel
                .tasks_in_process_group(sibling.task().process_group())
                .contains(&child_id),
            "group signal enumeration retains a task whose leader retired",
        );
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, None, None),
            SignalTargetAuthorization::Allowed,
            "positive/group signal-zero uses the retained task credential authority",
        );
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, None, Some(sigusr1)),
            SignalTargetAuthorization::Allowed,
            "positive/group nonzero signals use the retained task credential authority",
        );
        assert!(kernel.post_signal_to_task(child_id, sigusr1, None));
        assert!(
            sibling
                .task()
                .shared()
                .pending_signals()
                .take_lowest_in(SigSet::EMPTY.with(sigusr1.raw()))
                .is_some()
        );
    }

    #[test]
    fn job_control_stop_and_continue_are_task_scoped_and_waitable() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "job-control child", 708);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.task_is_job_control_stopped(child_id));
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root.task().key().id,
                    Some(child_id),
                    true,
                    false,
                    WaitMode::Consume,
                )
                .expect("wait stopped child"),
            WaitOutcome::Stopped {
                task: child_id,
                signal: sigstop,
            }
        );

        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root.task().key().id,
                    Some(child_id),
                    false,
                    true,
                    WaitMode::Consume,
                )
                .expect("wait continued child"),
            WaitOutcome::Continued { task: child_id }
        );
    }

    #[test]
    fn sigcont_generation_discards_pending_stop_signals_task_wide() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "continued child", 719);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigtstp, None));
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));

        let child = {
            let state = kernel.registry().state.read();
            Arc::clone(&state.tasks.get(&child_id).expect("child task").task)
        };
        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert!(
            !pending_of(&kernel, child_id)
                .present()
                .contains(sigstop.raw())
        );
        assert!(
            pending_of(&kernel, child_id)
                .present()
                .contains(sigcont.raw())
        );
        let thread_pending = child
            .thread(child_tid)
            .expect("child leader")
            .signal_state();
        assert!(!thread_pending.pending().contains(sigtstp.raw()));
    }

    #[test]
    fn stop_generation_discards_pending_sigcont_task_wide() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "stopped child", 720);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigcont, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigstop, None));

        let child = {
            let state = kernel.registry().state.read();
            Arc::clone(&state.tasks.get(&child_id).expect("child task").task)
        };
        assert!(
            !pending_of(&kernel, child_id)
                .present()
                .contains(sigcont.raw())
        );
        let thread_pending = child
            .thread(child_tid)
            .expect("child leader")
            .signal_state();
        assert!(!thread_pending.pending().contains(sigcont.raw()));
        assert!(thread_pending.pending().contains(sigstop.raw()));
    }

    #[test]
    fn sigcont_cancels_a_stop_dequeued_before_its_default_action() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "dequeue race child", 721);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(
            pending_of(&kernel, child_id)
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some(),
            "model a vCPU that dequeued STOP before applying its default action",
        );
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "the later SIGCONT generation must cancel the stale default-stop action",
        );
    }

    #[test]
    fn sigcont_cancels_every_stop_dequeued_before_its_default_action() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "two dequeue race child", 722);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigtstp, None));
        let child = {
            let state = kernel.registry().state.read();
            Arc::clone(&state.tasks.get(&child_id).expect("child task").task)
        };
        assert!(
            pending_of(&kernel, child_id)
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some(),
            "model one vCPU dequeuing the process-directed STOP",
        );
        assert!(
            child
                .thread(child_tid)
                .expect("child leader")
                .update_signal_state(|state| {
                    state
                        .take_lowest_in(SigSet::EMPTY.with(sigtstp.raw()))
                        .is_some()
                }),
            "model another vCPU dequeuing the thread-directed TSTP",
        );

        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.stop_task_for_job_control(child_id, sigtstp, None));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "SIGCONT must invalidate every earlier dequeued default-stop action",
        );

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(
            pending_of(&kernel, child_id)
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some()
        );
        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(
            kernel.task_is_job_control_stopped(child_id),
            "a stop generated after SIGCONT must replace the cancellation generation",
        );
    }

    #[test]
    fn stale_stop_action_cannot_borrow_a_newer_stop_generation() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "epoch-bound stop child", 724);
        let child_context = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        let stale = child_context
            .signal_authority()
            .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()));
        assert!(
            stale.is_some(),
            "model default-stop A dequeued before its action",
        );
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(kernel.post_signal_to_task(child_id, sigtstp, None));

        assert!(kernel.stop_task_for_job_control(
            child_id,
            sigstop,
            stale.and_then(|dequeue| dequeue.job_control_generation),
        ));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "stale A must not run under the newer stop B generation",
        );

        let current = child_context
            .signal_authority()
            .take_lowest_in(SigSet::EMPTY.with(sigtstp.raw()))
            .expect("dequeue new stop B");
        assert!(kernel.stop_task_for_job_control(
            child_id,
            sigtstp,
            current.job_control_generation,
        ));
        assert!(
            kernel.task_is_job_control_stopped(child_id),
            "the new stop generation must still apply its own default action",
        );
    }

    #[test]
    fn newer_stop_without_sigcont_does_not_cancel_dequeued_stop() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "same continue epoch child", 725);
        let child_context = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        let first = child_context
            .signal_authority()
            .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
            .expect("dequeue first stop");
        assert!(kernel.post_signal_to_task(child_id, sigtstp, None));

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, first.job_control_generation,));
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root.task().key().id,
                    Some(child_id),
                    true,
                    false,
                    WaitMode::Consume,
                )
                .expect("wait first stop"),
            WaitOutcome::Stopped {
                task: child_id,
                signal: sigstop,
            },
            "only an intervening SIGCONT invalidates dequeued stop work",
        );
    }

    #[test]
    fn sigkill_invalidates_a_stop_dequeued_before_fatal_delivery() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "kill dequeue race child", 726);
        let child_context = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigkill = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGKILL).expect("SIGKILL");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        let stale = child_context
            .signal_authority()
            .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
            .expect("dequeue stop before fatal signal generation");
        let ticket = match kernel.authorize_signal_target_exact(
            &root,
            child_context.task().key(),
            None,
            Some(sigkill),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("SIGKILL must authorize: {other:?}"),
        };
        assert!(kernel.post_signal_to_authorized_target(&ticket, sigkill, None));

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, stale.job_control_generation,));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "fatal delivery must invalidate every earlier dequeued stop action",
        );
        assert!(
            pending_of(&kernel, child_id)
                .present()
                .contains(sigkill.raw()),
            "the fatal signal must remain queued for the resumed vCPU",
        );
    }

    #[test]
    fn sigkill_resumes_a_stopped_task_without_wcontinued() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "kill stopped child", 727);
        let child_context = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigkill = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGKILL).expect("SIGKILL");

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.task_is_job_control_stopped(child_id));
        let ticket = match kernel.authorize_signal_target_exact(
            &root,
            child_context.task().key(),
            None,
            Some(sigkill),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("SIGKILL must authorize: {other:?}"),
        };
        assert!(kernel.post_signal_to_authorized_target(&ticket, sigkill, None));

        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root.task().key().id,
                    Some(child_id),
                    false,
                    true,
                    WaitMode::Consume,
                )
                .expect("wait after fatal resume"),
            WaitOutcome::StillRunning,
            "SIGKILL must not manufacture a WCONTINUED transition",
        );
    }

    #[test]
    fn sigcont_cancels_a_second_dequeued_stop_after_the_first_stops_the_task() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "split dequeue race child", 723);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigtstp, None));
        let child = {
            let state = kernel.registry().state.read();
            Arc::clone(&state.tasks.get(&child_id).expect("child task").task)
        };
        assert!(
            pending_of(&kernel, child_id)
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some()
        );
        assert!(
            child
                .thread(child_tid)
                .expect("child leader")
                .update_signal_state(|state| state
                    .take_lowest_in(SigSet::EMPTY.with(sigtstp.raw()))
                    .is_some())
        );

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.task_is_job_control_stopped(child_id));
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert!(kernel.stop_task_for_job_control(child_id, sigtstp, None));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "SIGCONT must invalidate another stop dequeued before the first group stop",
        );
    }

    #[test]
    fn wait_child_can_select_an_authoritative_guest_process_group() {
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;
        let child_id = fork_child(&kernel, &root, "wait group child", 702);
        let group = kernel
            .create_process_group(child_id, None)
            .expect("child process group");
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");

        let outcome = kernel
            .wait_child_in_process_group(root_id, group, WaitMode::Consume)
            .expect("wait child group");
        assert!(
            matches!(outcome, WaitOutcome::Exited(ref zombie) if zombie.key.id == child_id),
            "wait must select the child from its guest process group: {outcome:?}",
        );
    }

    /// The pending queue of `id`, read the way the task's own drain reads it.
    fn pending_of(
        kernel: &Arc<Kernel>,
        id: TaskId,
    ) -> Arc<super::super::objects::TaskPendingSignals> {
        let state = kernel.registry().state.read();
        state
            .tasks
            .get(&id)
            .expect("task is registered")
            .task
            .shared()
            .pending_signals()
    }

    /// Fork `parent` and return the child's id, with its start handshake
    /// completed so the child is a fully published, live task.
    fn fork_child(kernel: &Arc<Kernel>, parent: &KernelContext, name: &str, tid: i32) -> TaskId {
        let reservation = kernel
            .reserve_fork(
                parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                name.to_owned(),
                None,
            )
            .expect("reserve fork");
        let child_id = reservation.child_id();
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(tid))
            .expect("prepare fork");
        let wait = prepared.take_child_start_wait().expect("child wait");
        let waiter = std::thread::spawn(move || wait.wait());
        let published = prepared.commit().expect("publish fork");
        drop(published);
        waiter.join().expect("join child");
        child_id
    }

    /// The delivery half. A signal posted to another task must land in THAT
    /// task's pending queue and nowhere else: posting into the sender's queue
    /// instead is the shape of bug where `killpg` appears to work — the call
    /// succeeds — while the intended target never sees the signal and the
    /// SENDER dies of it.
    #[test]
    fn a_posted_signal_lands_in_the_target_queue_only() {
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;
        let child_id = fork_child(&kernel, &root, "signal target", 711);

        let sigterm = LinuxSignal::for_signal_number(15).expect("SIGTERM");
        assert!(
            kernel.post_signal_to_task(child_id, sigterm, None),
            "a live task accepts the signal"
        );

        assert!(
            pending_of(&kernel, child_id).present().contains(15),
            "the signal is pending on the target"
        );
        assert!(
            !pending_of(&kernel, root_id).present().contains(15),
            "the sender must not have signalled itself"
        );

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
    }

    #[test]
    fn a_thread_directed_signal_requires_exact_task_membership_and_lands_on_that_thread() {
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;
        let child_id = fork_child(&kernel, &root, "thread signal target", 714);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");

        assert_eq!(kernel.live_task_for_thread(None, child_tid), Some(child_id));
        assert_eq!(
            kernel.live_task_for_thread(Some(root_id), child_tid),
            None,
            "tgkill must reject a tid from another thread group",
        );
        assert!(kernel.post_signal_to_thread(
            child_id,
            child_tid,
            sigusr1,
            Some(LinuxSiginfo::kill(10, carrick_abi::LINUX_SI_TKILL, 1, 0)),
        ));

        let child = {
            let state = kernel.registry().state.read();
            state.tasks.get(&child_id).unwrap().task.clone()
        };
        assert!(
            child
                .thread(child_tid)
                .unwrap()
                .signal_state()
                .pending()
                .contains(10),
            "thread-directed delivery must not fall into the task-wide queue",
        );
        assert!(!pending_of(&kernel, child_id).present().contains(10));

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
    }

    /// Standard signals collapse to a single pending bit however many times
    /// they are sent; realtime signals QUEUE, one delivery per send. The queue
    /// picks between the two off `LinuxSignal::is_realtime`, so getting it
    /// backwards silently drops realtime deliveries (or duplicates standard
    /// ones) with no error anywhere.
    #[test]
    fn realtime_signals_queue_and_standard_signals_collapse() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "queue target", 712);

        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        assert!(!sigusr1.is_realtime());
        for _ in 0..3 {
            assert!(kernel.post_signal_to_task(child_id, sigusr1, None));
        }
        assert_eq!(
            pending_of(&kernel, child_id).pending_count(),
            1,
            "three sends of a standard signal collapse to one pending delivery"
        );

        let sigrt = LinuxSignal::for_signal_number(34).expect("SIGRTMIN+2");
        assert!(sigrt.is_realtime());
        for _ in 0..3 {
            assert!(kernel.post_signal_to_task(child_id, sigrt, None));
        }
        assert_eq!(
            pending_of(&kernel, child_id).pending_count(),
            4,
            "each realtime send queues its own delivery, alongside the standard one"
        );

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
    }

    /// A task that is parked in a host wait must be WOKEN, and it must be woken
    /// only once the signal is already pending — otherwise it wakes, looks at
    /// an empty queue, and parks again having spent its wake. This waker
    /// records what the queue held at the moment it was kicked, which is the
    /// ordering the lost-wakeup bug would violate.
    #[derive(Debug)]
    struct RecordingWaker {
        wakes: AtomicUsize,
        /// The target's REAL queue, so the wake observes exactly what a woken
        /// guest would observe rather than anything the test staged.
        queue: Arc<super::super::objects::TaskPendingSignals>,
        pending_when_woken: AtomicUsize,
    }

    impl super::super::objects::TaskWaker for RecordingWaker {
        fn wake_task(&self) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            self.pending_when_woken
                .store(self.queue.pending_count(), Ordering::SeqCst);
        }
    }

    /// Delivery must WAKE the target, not merely enqueue. A guest parked in a
    /// blocking read or a futex watches host pipes and futexes; none of them
    /// observe the kernel's pending queue, so without this a `killpg` to a
    /// sleeping process is silently deferred until it happens to trap.
    #[test]
    fn delivery_wakes_the_target_after_the_signal_is_pending() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "parked target", 714);
        let waker = Arc::new(RecordingWaker {
            wakes: AtomicUsize::new(0),
            queue: pending_of(&kernel, child_id),
            pending_when_woken: AtomicUsize::new(0),
        });

        {
            let state = kernel.registry().state.read();
            let task = &state.tasks.get(&child_id).expect("child").task;
            task.set_waker(Arc::clone(&waker) as Arc<dyn super::super::objects::TaskWaker>);
        }

        let pending = pending_of(&kernel, child_id);
        assert_eq!(waker.wakes.load(Ordering::SeqCst), 0);

        let sigterm = LinuxSignal::for_signal_number(15).expect("SIGTERM");
        assert!(kernel.post_signal_to_task(child_id, sigterm, None));

        assert_eq!(
            waker.wakes.load(Ordering::SeqCst),
            1,
            "the target is woken exactly once per delivery"
        );
        assert_eq!(
            pending.pending_count(),
            1,
            "and the signal is pending for it to find"
        );
        assert_eq!(
            waker.pending_when_woken.load(Ordering::SeqCst),
            1,
            "the signal was ALREADY pending when the wake fired — waking first \
             lets the target look, find nothing, and park again having spent \
             its wake"
        );

        // A task with NO waker is not an error: it still notices at its next
        // syscall boundary, so delivery reports success.
        let bare_id = fork_child(&kernel, &root, "unwoken target", 715);
        assert!(kernel.post_signal_to_task(bare_id, sigterm, None));
        assert!(pending_of(&kernel, bare_id).present().contains(15));

        for id in [child_id, bare_id] {
            kernel
                .exit_task(id, LinuxWaitStatus::from_wait_encoding(0), None)
                .expect("retire child");
        }
    }

    #[test]
    fn authorized_sigcont_wakes_the_parent_current_at_publication() {
        let (kernel, root) = bootstrap(1);
        let parent = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_150),
                "old signal parent".to_string(),
                None,
            )
            .expect("old parent");
        let target = kernel
            .fork_task(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_151),
                "reparented signal target".to_string(),
                None,
            )
            .expect("target");
        let parent_id = parent.task().key().id;
        let target_key = target.task().key();
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");
        assert!(kernel.stop_task_for_job_control(target_key.id, sigstop, None));
        let ticket =
            match kernel.authorize_signal_target_exact(&root, target_key, None, Some(sigcont)) {
                ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
                other => panic!("SIGCONT must authorize before reparenting: {other:?}"),
            };

        let root_waker = Arc::new(RecordingWaker {
            wakes: AtomicUsize::new(0),
            queue: root.shared().pending_signals(),
            pending_when_woken: AtomicUsize::new(0),
        });
        let old_parent_waker = Arc::new(RecordingWaker {
            wakes: AtomicUsize::new(0),
            queue: parent.shared().pending_signals(),
            pending_when_woken: AtomicUsize::new(0),
        });
        root.task()
            .set_waker(Arc::clone(&root_waker) as Arc<dyn super::super::objects::TaskWaker>);
        parent
            .task()
            .set_waker(Arc::clone(&old_parent_waker) as Arc<dyn super::super::objects::TaskWaker>);

        kernel
            .exit_task(parent_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("exit old parent");
        assert_eq!(target.task().parent(), Some(root.task().key()));
        let root_wakes_before = root_waker.wakes.load(Ordering::SeqCst);
        let old_parent_wakes_before = old_parent_waker.wakes.load(Ordering::SeqCst);

        assert!(kernel.post_signal_to_authorized_target(&ticket, sigcont, None));
        assert_eq!(
            root_waker.wakes.load(Ordering::SeqCst),
            root_wakes_before + 1,
            "WCONTINUED publication must wake the target's current parent",
        );
        assert_eq!(
            old_parent_waker.wakes.load(Ordering::SeqCst),
            old_parent_wakes_before,
            "a stale authorization-time parent must not receive the wait wake",
        );
    }

    /// An unknown or already-exiting task reports no delivery. For a specific
    /// target that is `kill(2)`'s ESRCH; for a group fan-out it is simply "not
    /// a member". Enqueuing onto an exiting task would strand the signal in a
    /// queue nobody will drain.
    #[test]
    fn posting_to_an_unknown_or_exiting_task_reports_no_delivery() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "exiting target", 713);
        let sigterm = LinuxSignal::for_signal_number(15).expect("SIGTERM");

        let absent = TaskId::from_abi_positive(9_999).expect("unused id");
        assert!(
            !kernel.post_signal_to_task(absent, sigterm, None),
            "a task that does not exist takes no signal"
        );

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
        assert!(
            !kernel.post_signal_to_task(child_id, sigterm, None),
            "a retired task takes no signal"
        );
    }

    /// `kill(-1)` targets every process the caller may signal EXCEPT itself and
    /// init. Excluding init is what stops a guest's own broadcast from killing
    /// the container's init along with everything else.
    #[test]
    fn broadcast_excludes_the_caller_and_init() {
        // Bootstrap AT pid 1 so the root IS init, which is the shape the kernel
        // lane will have once its id space is seeded at 1.
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;

        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "broadcast child".to_owned(),
                None,
            )
            .expect("reserve fork");
        let child_id = reservation.child_id();
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(702))
            .expect("prepare fork");
        let wait = prepared.take_child_start_wait().expect("child wait");
        let waiter = std::thread::spawn(move || wait.wait());
        let published = prepared.commit().expect("publish fork");
        drop(published);
        waiter.join().expect("join child");

        // From init: the child, and NOT init itself.
        assert_eq!(kernel.tasks_for_broadcast(root_id), vec![child_id]);
        // From the child: init is excluded as init, the child as the caller —
        // so a lone child broadcasting reaches nobody.
        assert!(kernel.tasks_for_broadcast(child_id).is_empty());

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
    }

    #[test]
    fn dropped_published_fork_fail_safe_starts_instead_of_leaking_task() {
        let (kernel, root) = bootstrap(153);
        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "fail-safe child".to_owned(),
                None,
            )
            .expect("reserve fork");
        let child_id = reservation.child_id();
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(154))
            .expect("prepare fork");
        let wait = prepared.take_child_start_wait().expect("unique child wait");
        let waiter = std::thread::spawn(move || wait.wait());
        let published = prepared.commit().expect("publish fork");

        drop(published);
        assert_eq!(
            waiter.join().expect("join fail-safe child"),
            ChildStartOutcome::Started
        );
        assert!(kernel.task_is_live(child_id));
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire fail-safe child");
    }

    #[test]
    fn copied_mm_fork_freezes_dispatch_before_capturing_ring_attachments() {
        let (kernel, root) = bootstrap(149);
        let files = root.resources().files();
        let active_dispatch = files
            .acquire_functional_lease()
            .expect("active dispatch lease");
        let backing =
            crate::dispatch::ioring::IoUringBacking::create(8, 4096).expect("ring backing");
        let description =
            Arc::new(FileDescription::concrete(backing).expect("ring description identity"));
        let parent_mm = root.shared().mm();
        parent_mm.replace_io_uring_mappings(
            0x1000,
            0x1000,
            Some(crate::dispatch::ioring::IoUringMapping {
                description: Arc::clone(&description),
                region: crate::dispatch::ioring::IoUringRegion::SqCq,
                start: 0x1000,
                end: 0x2000,
                backing_offset: 0,
            }),
        );
        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "ring-race child".to_owned(),
                None,
            )
            .expect("fork reservation");
        let prepare = std::thread::spawn(move || {
            reservation.prepare_reference(ThreadId::synthetic_for_tests(1491))
        });
        for _ in 0..100_000 {
            if files.functional_gate_is_frozen() {
                break;
            }
            std::thread::yield_now();
        }
        assert!(
            files.functional_gate_is_frozen(),
            "fork did not freeze dispatch before copying mm state"
        );

        parent_mm.replace_io_uring_mappings(0x1000, 0x1000, None);
        parent_mm.replace_io_uring_mappings(
            0x3000,
            0x1000,
            Some(crate::dispatch::ioring::IoUringMapping {
                description,
                region: crate::dispatch::ioring::IoUringRegion::Sqes,
                start: 0x3000,
                end: 0x4000,
                backing_offset: 0x1000,
            }),
        );
        drop(active_dispatch);
        let prepared = prepare
            .join()
            .expect("join fork preparation")
            .expect("prepare fork");
        let child_mm = prepared.child_shared.mm();
        let child_mappings = child_mm.read_io_uring_mappings();
        assert_eq!(child_mappings.len(), 1);
        assert_eq!(
            (child_mappings[0].start, child_mappings[0].end),
            (0x3000, 0x4000)
        );
    }

    #[test]
    fn fork_reservation_stays_undiscoverable_until_backend_commit() {
        let (kernel, root) = bootstrap(150);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let before = kernel.ids().counts();
        let reservation = kernel
            .reserve_fork(&root, plan, "child".to_string(), None)
            .expect("reserve fork");
        let child_id = reservation.child_id();
        assert!(
            kernel
                .context(child_id, LinuxTid::for_task_leader(child_id))
                .is_err()
        );

        let child_registry_id = ThreadId::synthetic_for_tests(9_999);
        let prepared = reservation
            .prepare_with_mm_backend(Arc::new(TestMmBackend(test_binding())), child_registry_id)
            .expect("prepare backend");
        assert!(
            kernel
                .context(child_id, LinuxTid::for_task_leader(child_id))
                .is_err()
        );
        let child = prepared.commit().expect("publish child");

        assert_eq!(
            child
                .context()
                .expect("published child context")
                .thread()
                .registry_id(),
            child_registry_id
        );
        assert_eq!(
            child
                .context()
                .expect("published child context")
                .shared()
                .mm()
                .backend()
                .expect("production backend")
                .snapshot(std::time::Instant::now() + std::time::Duration::from_secs(1))
                .expect("backend snapshot")
                .binding,
            test_binding()
        );
        assert_ne!(kernel.ids().counts(), before);
    }

    #[test]
    fn legacy_aio_authority_follows_mm_sharing_not_file_table_sharing() {
        let (kernel, root) = bootstrap(159);
        let aio = crate::dispatch::LegacyAioContextId::allocated_from(
            root.shared().mm().allocate_legacy_aio_context(),
        );
        root.shared().mm().write_legacy_aio_contexts().insert(aio);

        let copied = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::FILES).expect("copied-mm plan"),
                ThreadId::synthetic_for_tests(1591),
                "copied-mm child".to_owned(),
                None,
            )
            .expect("copied-mm fork");
        assert!(!Arc::ptr_eq(&copied.shared().mm(), &root.shared().mm()));
        assert!(copied.shared().mm().read_legacy_aio_contexts().is_empty());
        assert!(Arc::ptr_eq(
            &copied.resources().files(),
            &root.resources().files()
        ));

        let current_root = kernel
            .context(root.task().key().id, root.thread().key().tid)
            .expect("current root after copied-mm fork");
        let shared = kernel
            .fork_task(
                &current_root,
                ClonePlan::from_flags(LinuxCloneFlags::VM).expect("shared-mm plan"),
                ThreadId::synthetic_for_tests(1592),
                "shared-mm child".to_owned(),
                None,
            )
            .expect("shared-mm fork");
        assert!(Arc::ptr_eq(&shared.shared().mm(), &root.shared().mm()));
        assert!(
            shared
                .shared()
                .mm()
                .read_legacy_aio_contexts()
                .contains(&aio)
        );
    }

    #[test]
    fn fork_parent_selection_and_failpoint_preserve_exact_parentage() {
        let (kernel, root) = bootstrap(160);
        let caller = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("caller plan"),
                ThreadId::synthetic_for_tests(161),
                "caller".to_string(),
                None,
            )
            .expect("caller");
        let clone_parent_plan =
            ClonePlan::from_flags(LinuxCloneFlags::PARENT).expect("CLONE_PARENT plan");
        let sibling = kernel
            .fork_task(
                &caller,
                clone_parent_plan,
                ThreadId::synthetic_for_tests(162),
                "sibling".to_string(),
                None,
            )
            .expect("CLONE_PARENT child");

        assert_eq!(sibling.task.parent(), Some(root.task.key()));
        assert!(root.task.children().contains(&sibling.task.key()));
        assert!(!caller.task.children().contains(&sibling.task.key()));

        let before = root.task.children();
        let prepared = kernel
            .reserve_fork(
                &caller,
                clone_parent_plan,
                "rolled back sibling".to_string(),
                Some(KernelFailpoint::BeforePublish),
            )
            .expect("reserve rolled back fork")
            .prepare_reference(ThreadId::synthetic_for_tests(163))
            .expect("prepare rolled back fork");
        assert!(matches!(
            prepared.commit(),
            Err(KernelOperationError::Injected(
                KernelFailpoint::BeforePublish
            ))
        ));
        assert_eq!(root.task.children(), before);

        let current_root = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("current selected parent");
        let stale_parent = kernel
            .reserve_fork(
                &caller,
                clone_parent_plan,
                "stale selected parent".to_string(),
                None,
            )
            .expect("reserve against selected parent")
            .prepare_reference(ThreadId::synthetic_for_tests(164))
            .expect("prepare against selected parent");
        assert!(matches!(
            kernel.reserve_fork(
                &current_root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("concurrent fork plan"),
                "blocked root child".to_string(),
                None,
            ),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        drop(stale_parent);
        kernel
            .fork_task(
                &current_root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("unlocked fork plan"),
                ThreadId::synthetic_for_tests(165),
                "unlocked root child".to_string(),
                None,
            )
            .expect("dropped operation unlocks selected parent");
    }

    #[test]
    fn vfork_parent_gate_releases_once_on_exec_or_exit() {
        let (kernel, root) = bootstrap(170);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM)
            .expect("vfork plan");
        let published = kernel
            .reserve_fork(&root, plan, "vfork exec".to_string(), None)
            .expect("reserve vfork")
            .prepare_reference(ThreadId::synthetic_for_tests(171))
            .expect("prepare vfork")
            .commit()
            .expect("publish vfork");
        let (child, wait) = published.into_parts().expect("start vfork child");
        let wait = wait.expect("vfork parent wait");
        assert_eq!(wait.released_reason(), None);
        assert_eq!(wait.wait_for_release(std::time::Duration::ZERO), None);

        let failed_exec = kernel
            .prepare_exec(&child, None)
            .expect("prepare failed child exec");
        assert!(matches!(
            kernel.commit_exec(failed_exec, Some(KernelFailpoint::BeforePublish)),
            Err(crate::kernel::ExecError::Injected(
                KernelFailpoint::BeforePublish
            ))
        ));
        assert_eq!(wait.released_reason(), None);

        let prepared_exec = kernel
            .prepare_exec(&child, None)
            .expect("prepare child exec");
        kernel
            .commit_exec(prepared_exec, None)
            .expect("commit child exec");
        assert_eq!(wait.released_reason(), Some(VforkReleaseReason::Exec));
        assert_eq!(
            wait.wait_for_release(std::time::Duration::ZERO),
            Some(VforkReleaseReason::Exec)
        );
        kernel
            .exit_task(
                child.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("exit execed child");
        assert_eq!(wait.released_reason(), Some(VforkReleaseReason::Exec));

        let refreshed_root = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refreshed root");
        let exited = kernel
            .reserve_fork(&refreshed_root, plan, "vfork exit".to_string(), None)
            .expect("reserve exiting vfork")
            .prepare_reference(ThreadId::synthetic_for_tests(172))
            .expect("prepare exiting vfork")
            .commit()
            .expect("publish exiting vfork");
        let (exiting_child, exit_wait) = exited.into_parts().expect("start exiting vfork child");
        let exit_wait = exit_wait.expect("exit vfork parent wait");
        let blocking_wait = exit_wait.clone();
        let waiter = std::thread::spawn(move || blocking_wait.wait());
        kernel
            .exit_task(
                exiting_child.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("exit vfork child");
        assert_eq!(exit_wait.released_reason(), Some(VforkReleaseReason::Exit));
        assert_eq!(
            waiter.join().expect("vfork waiter"),
            VforkReleaseReason::Exit
        );
    }

    #[test]
    fn reserved_pidfd_subscription_arms_only_with_fork_commit() {
        let (kernel, root) = bootstrap(180);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::PIDFD).expect("pidfd plan");
        let missing = kernel
            .reserve_fork(&root, plan, "missing pidfd".to_string(), None)
            .expect("reserve missing pidfd")
            .prepare_reference(ThreadId::synthetic_for_tests(180))
            .expect("prepare missing pidfd");
        assert!(matches!(
            missing.commit(),
            Err(KernelOperationError::MissingPidfdSubscription)
        ));

        let subscriber = Arc::new(CountingExitSubscriber::default());
        let mut prepared = kernel
            .reserve_fork(&root, plan, "pidfd child".to_string(), None)
            .expect("reserve pidfd fork")
            .prepare_reference(ThreadId::synthetic_for_tests(181))
            .expect("prepare pidfd fork");
        let target = prepared
            .reserve_pidfd_subscription(&subscriber)
            .expect("reserve pidfd subscription");
        assert!(target.belongs_to(&kernel));
        assert_eq!(target.task_id(), prepared.child_id());
        assert_eq!(subscriber.0.load(Ordering::Acquire), 0);
        assert!(!kernel.task_exists(target.task_id()));

        let child = prepared
            .commit()
            .expect("publish pidfd child")
            .start_child()
            .expect("start pidfd child");
        assert_eq!(subscriber.0.load(Ordering::Acquire), 0);
        kernel
            .exit_task(
                child.context().task().key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("exit pidfd child");
        assert_eq!(subscriber.0.load(Ordering::Acquire), 1);

        let refreshed_root = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refreshed root");
        let rollback_subscriber = Arc::new(CountingExitSubscriber::default());
        let mut rolled_back = kernel
            .reserve_fork(
                &refreshed_root,
                plan,
                "rolled back pidfd".to_string(),
                Some(KernelFailpoint::BeforePublish),
            )
            .expect("reserve rolled back pidfd")
            .prepare_reference(ThreadId::synthetic_for_tests(182))
            .expect("prepare rolled back pidfd");
        let rolled_back_target = rolled_back
            .reserve_pidfd_subscription(&rollback_subscriber)
            .expect("reserve rolled back subscription");
        assert!(matches!(
            rolled_back.commit(),
            Err(KernelOperationError::Injected(
                KernelFailpoint::BeforePublish
            ))
        ));
        assert_eq!(rollback_subscriber.0.load(Ordering::Acquire), 0);
        assert!(!kernel.task_exists(rolled_back_target.task_id()));
    }

    #[test]
    fn dropped_fork_reservation_restores_identity_claim_counts() {
        let (kernel, root) = bootstrap(175);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let before = kernel.ids().counts();
        let reservation = kernel
            .reserve_fork(&root, plan, "child".to_string(), None)
            .expect("reserve fork");
        let child_id = reservation.child_id();
        drop(reservation);

        assert_eq!(kernel.ids().counts(), before);
        assert!(
            kernel
                .context(child_id, LinuxTid::for_task_leader(child_id))
                .is_err()
        );
        assert_eq!(kernel.registry().task_count(), 1);
    }

    #[test]
    fn thread_clone_reservation_keeps_tid_private_until_commit() {
        let (kernel, root) = bootstrap(190);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let reservation = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve thread");
        let tid = reservation.tid();
        assert!(root.task.thread(tid).is_none());

        let registry_id = ThreadId::synthetic_for_tests(8_888);
        let prepared = reservation.prepare(registry_id).expect("prepare thread");
        assert_eq!(prepared.tid(), tid);
        assert!(root.task.thread(tid).is_none());
        let published = prepared.commit().expect("publish thread");

        assert_eq!(
            published
                .context()
                .expect("published thread context")
                .thread
                .key()
                .tid,
            tid
        );
        assert!(root.task.thread(tid).is_some());
        let child = published.start_thread().expect("start thread");
        assert_eq!(child.context().thread.registry_id(), registry_id);
    }

    #[test]
    fn concurrent_thread_preparations_publish_against_the_latest_revision() {
        let (kernel, root) = bootstrap(194);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve first thread")
            .prepare(ThreadId::synthetic_for_tests(8_894))
            .expect("prepare first thread");
        let second = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve concurrent thread")
            .prepare(ThreadId::synthetic_for_tests(8_895))
            .expect("prepare concurrent thread");
        let first_tid = first.tid();
        let second_tid = second.tid();

        let commit_barrier = Arc::new(std::sync::Barrier::new(3));
        let first_barrier = Arc::clone(&commit_barrier);
        let first_handle = std::thread::spawn(move || {
            first_barrier.wait();
            first
                .commit()
                .expect("publish first thread")
                .start_thread()
                .expect("start first thread")
                .context()
                .task()
                .key()
        });
        let second_barrier = Arc::clone(&commit_barrier);
        let second_handle = std::thread::spawn(move || {
            second_barrier.wait();
            second
                .commit()
                .expect("publish concurrent thread after revision advance")
                .start_thread()
                .expect("start concurrent thread")
                .context()
                .task()
                .key()
        });
        commit_barrier.wait();
        let first_task = first_handle.join().expect("first commit thread");
        let second_task = second_handle.join().expect("second commit thread");

        assert_ne!(first_tid, second_tid);
        assert_eq!(first_task, root.task().key());
        assert_eq!(second_task, root.task().key());
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn sibling_publication_does_not_stale_thread_exit() {
        let (kernel, root) = bootstrap(195);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_896), None)
            .expect("first thread");
        let _second = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_897), None)
            .expect("second thread advances task revision");

        kernel
            .exit_thread(&first, None)
            .expect("thread identity remains valid across sibling publication");

        assert!(root.task().thread(first.thread().key().tid).is_none());
        assert_eq!(root.task().live_thread_count(), 2);
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn thread_start_gate_opens_only_after_clone_publication() {
        let (kernel, root) = bootstrap(191);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let reservation = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve thread");
        let tid = reservation.tid();
        let mut prepared = reservation
            .prepare(ThreadId::synthetic_for_tests(8_889))
            .expect("prepare thread");
        let wait = prepared
            .take_child_start_wait()
            .expect("unique thread wait");
        assert!(matches!(
            prepared.take_child_start_wait(),
            Err(KernelOperationError::ChildStartWaitTaken)
        ));
        let (waiting_tx, waiting_rx) = std::sync::mpsc::sync_channel(1);
        let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            waiting_tx.send(()).expect("report waiting");
            outcome_tx.send(wait.wait()).expect("report outcome");
        });
        waiting_rx.recv().expect("thread reached gate");
        assert!(root.task.thread(tid).is_none());

        let published = prepared.commit().expect("publish thread");
        assert!(root.task.thread(tid).is_some());
        assert!(matches!(
            outcome_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        let started = published.start_thread().expect("start thread");
        assert_eq!(started.context().thread.key().tid, tid);
        assert_eq!(
            outcome_rx.recv().expect("started outcome"),
            ChildStartOutcome::Started
        );
        waiter.join().expect("join thread waiter");
    }

    #[test]
    fn thread_clone_drop_cancels_before_publish_and_starts_after_publish() {
        let (kernel, root) = bootstrap(192);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let reservation = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve cancelled thread");
        let cancelled_tid = reservation.tid();
        let mut prepared = reservation
            .prepare(ThreadId::synthetic_for_tests(8_890))
            .expect("prepare cancelled thread");
        let wait = prepared.take_child_start_wait().expect("cancel wait");
        let cancelled = std::thread::spawn(move || wait.wait());
        drop(prepared);
        assert_eq!(
            cancelled.join().expect("join cancelled thread"),
            ChildStartOutcome::Cancelled
        );
        assert!(root.task.thread(cancelled_tid).is_none());

        let refreshed = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refreshed root");
        let reservation = kernel
            .reserve_thread_clone(&refreshed, plan, None)
            .expect("reserve fail-safe thread");
        let started_tid = reservation.tid();
        let mut prepared = reservation
            .prepare(ThreadId::synthetic_for_tests(8_891))
            .expect("prepare fail-safe thread");
        let wait = prepared.take_child_start_wait().expect("fail-safe wait");
        let started = std::thread::spawn(move || wait.wait());
        let published = prepared.commit().expect("publish fail-safe thread");
        drop(published);
        assert_eq!(
            started.join().expect("join fail-safe thread"),
            ChildStartOutcome::Started
        );
        let started_context = kernel
            .context(root.task.key().id, started_tid)
            .expect("started thread context");
        kernel
            .exit_thread(&started_context, None)
            .expect("retire fail-safe thread");
    }

    #[test]
    fn thread_exit_unpublishes_before_draining_its_tid_claim() {
        let (kernel, root) = bootstrap(195);
        let root_counts = kernel.ids().counts();
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let child = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(9_195), None)
            .expect("thread clone");
        let tid = child.thread.key().tid;
        let live_counts = kernel.ids().counts();

        kernel.exit_thread(&child, None).expect("thread exit");
        assert!(root.task.thread(tid).is_none());
        assert!(kernel.context(root.task.key().id, tid).is_err());
        assert_eq!(kernel.sweep_retired_threads(), 0);
        assert_eq!(kernel.ids().counts(), live_counts);

        drop(child);
        assert_eq!(kernel.sweep_retired_threads(), 1);
        assert_eq!(kernel.ids().counts(), root_counts);
        let refreshed = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refresh root");
        assert!(matches!(
            kernel.exit_thread(&refreshed, None),
            Err(KernelOperationError::LastThreadRequiresTaskExit(id)) if id == root.thread.key().tid
        ));
    }

    #[test]
    fn dead_leader_claim_survives_task_exit_and_zombie_reap_until_context_drain() {
        let (kernel, root) = bootstrap(196);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_196),
                "child".to_string(),
                None,
            )
            .expect("child task");
        let child_id = child.task.key().id;
        let sibling = kernel
            .clone_thread(
                &child,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(9_197),
                None,
            )
            .expect("child sibling");
        let dead_leader = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("current child leader");
        kernel
            .exit_thread(&dead_leader, None)
            .expect("leader thread exit");
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("task exit");

        drop(child);
        drop(sibling);
        assert_eq!(kernel.sweep_retired_threads(), 0);
        assert_eq!(kernel.registry().retired_thread_count(), 2);
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Consume),
            Ok(WaitOutcome::Exited(_))
        ));
        assert_eq!(kernel.ids().counts().thread_claims, 3);

        drop(dead_leader);
        assert_eq!(kernel.sweep_retired_threads(), 2);
        assert_eq!(kernel.ids().counts().thread_claims, 1);
    }

    #[test]
    fn every_thread_exit_failpoint_preserves_the_live_thread() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, root) = bootstrap(197);
            let plan = ClonePlan::from_flags(
                LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
            )
            .expect("thread plan");
            let child = kernel
                .clone_thread(&root, plan, ThreadId::synthetic_for_tests(9_197), None)
                .expect("thread clone");
            let tid = child.thread.key().tid;
            let counts = kernel.ids().counts();

            assert!(matches!(
                kernel.exit_thread(&child, Some(point)),
                Err(KernelOperationError::Injected(injected)) if injected == point
            ));
            assert!(child.task.thread(tid).is_some());
            assert_eq!(kernel.ids().counts(), counts);
            assert!(kernel.validate_invariants().is_ok());
        }
    }

    #[test]
    fn thread_clone_keeps_task_shared_but_can_copy_files_and_fs() {
        let (kernel, root) = bootstrap(200);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let child = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(201), None)
            .expect("thread clone");

        assert!(Arc::ptr_eq(&root.task, &child.task));
        assert!(Arc::ptr_eq(&root.shared, &child.shared));
        assert!(!Arc::ptr_eq(
            &root.resources.files(),
            &child.resources.files()
        ));
        assert!(!Arc::ptr_eq(
            &root.resources.fs_context(),
            &child.resources.fs_context()
        ));
        assert_eq!(root.task.live_thread_count(), 2);
    }

    #[test]
    fn context_capture_never_mixes_association_generations() {
        let (kernel, root) = bootstrap(250);
        let first_shared = Arc::clone(&root.shared);
        let first_resources = Arc::clone(&root.resources);
        let second_shared = Arc::new(TaskShared::new(
            Arc::new(Mm::new_reference(
                kernel.object_ids().mm_id().expect("second mm"),
            )),
            Arc::new(Sighand::new(
                kernel.object_ids().sighand_id().expect("second sighand"),
            )),
        ));
        let second_resources = Arc::new(ThreadResources::new(
            Arc::new(FileTable::new(
                kernel.object_ids().file_table_id().expect("second files"),
            )),
            Arc::new(FsContext::new(
                kernel.object_ids().fs_context_id().expect("second fs"),
            )),
            Arc::new(Credentials::root(
                kernel
                    .object_ids()
                    .credentials_id()
                    .expect("second credentials"),
            )),
        ));
        let task_id = root.task.key().id;
        let tid = root.thread.key().tid;
        let writer_kernel = Arc::clone(&kernel);
        let writer_first_shared = Arc::clone(&first_shared);
        let writer_first_resources = Arc::clone(&first_resources);
        let writer_second_shared = Arc::clone(&second_shared);
        let writer_second_resources = Arc::clone(&second_resources);
        let writer = std::thread::spawn(move || {
            for iteration in 0..2_000 {
                let (shared, resources) = if iteration % 2 == 0 {
                    (
                        Arc::clone(&writer_second_shared),
                        Arc::clone(&writer_second_resources),
                    )
                } else {
                    (
                        Arc::clone(&writer_first_shared),
                        Arc::clone(&writer_first_resources),
                    )
                };
                writer_kernel
                    .publish_task_associations(task_id, tid, shared, resources)
                    .expect("publish generation");
            }
        });

        for _ in 0..2_000 {
            let context = kernel.context(task_id, tid).expect("context");
            let first = Arc::ptr_eq(&context.shared, &first_shared)
                && Arc::ptr_eq(&context.resources, &first_resources);
            let second = Arc::ptr_eq(&context.shared, &second_shared)
                && Arc::ptr_eq(&context.resources, &second_resources);
            assert!(first || second, "context mixed association generations");
        }
        writer.join().expect("writer thread");
    }

    /// Two threads of one Linux process must both be able to fork.
    ///
    /// This replaces an earlier `stale_context_cannot_commit_a_fork`, which
    /// asserted the opposite: that a second fork from the same captured
    /// context is refused as `StaleContext`. That contract is not Linux's.
    /// Committing a child advances the PARENT's revision (it gains a child),
    /// so any sibling holding a context captured beforehand was refused and
    /// the guest received `EAGAIN`. The Go toolchain forks concurrently from
    /// several threads, which is why a cold `go build` under HVPatch failed
    /// with "fork/exec ...: resource temporarily unavailable".
    ///
    /// The invariant that check was really protecting — a context captured
    /// before the task was REPARENTED must not fork — is now enforced
    /// directly against the parent association and is covered by
    /// `exiting_parent_reparents_live_and_zombie_children_to_root`.
    #[test]
    fn sibling_publication_does_not_stale_a_fork_context() {
        let (kernel, root) = bootstrap(275);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let first = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(276),
                "first child".to_string(),
                None,
            )
            .expect("first fork");
        let second = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(277),
                "sibling child".to_string(),
                None,
            )
            .expect("a sibling fork must not be staled by the first child's publication");

        assert_ne!(first.task.key(), second.task.key());
        assert_eq!(first.task.parent(), Some(root.task.key()));
        assert_eq!(second.task.parent(), Some(root.task.key()));
        assert_eq!(kernel.registry().task_count(), 3);
    }

    #[test]
    fn sibling_publication_does_not_stale_a_thread_clone_context() {
        let (kernel, root) = bootstrap(285);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(286), None)
            .expect("first thread");
        drop(first);
        let second = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(287), None)
            .expect("sibling-only revision advance remains compatible");

        assert_eq!(second.task().key(), root.task().key());
        assert_eq!(root.task.live_thread_count(), 3);
    }

    #[test]
    fn stale_identity_reservations_cannot_commit() {
        let (kernel, root) = bootstrap(290);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(291),
                "child".to_string(),
                None,
            )
            .expect("child");
        let group_reservation = kernel
            .reserve_task_operation(child.task.key().id)
            .expect("group reservation");
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first_thread = kernel
            .clone_thread(
                &child,
                thread_plan,
                ThreadId::synthetic_for_tests(292),
                None,
            )
            .expect("first thread");
        assert!(matches!(
            kernel.create_process_group_reserved(group_reservation, None),
            Err(KernelOperationError::StaleReservation)
        ));

        let session_reservation = kernel
            .reserve_task_operation(child.task.key().id)
            .expect("session reservation");
        let second_thread = kernel
            .clone_thread(
                &first_thread,
                thread_plan,
                ThreadId::synthetic_for_tests(293),
                None,
            )
            .expect("second thread");
        drop(second_thread);
        assert!(matches!(
            kernel.create_session_reserved(session_reservation, None),
            Err(KernelOperationError::StaleReservation)
        ));
    }

    #[test]
    fn reservation_cannot_cross_kernel_identity() {
        let (first, first_root) = bootstrap(295);
        let (second, second_root) = bootstrap(295);
        assert_eq!(first_root.task.key(), second_root.task.key());
        assert_eq!(first_root.revision, second_root.revision);
        let reservation = first
            .reserve_task_operation(first_root.task.key().id)
            .expect("reservation");

        assert!(matches!(
            second.create_process_group_reserved(reservation, None),
            Err(KernelOperationError::ForeignReservation)
        ));
    }

    #[test]
    fn every_prepare_failpoint_leaves_registry_unchanged() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, root) = bootstrap(300);
            let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
            let counts = kernel.ids().counts();
            let credentials = root.resources.credentials();
            let credential_refs = Arc::strong_count(&credentials);
            let result = kernel.fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(301),
                "child".to_string(),
                Some(point),
            );

            assert!(matches!(result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.registry().task_count(), 1);
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(Arc::strong_count(&credentials), credential_refs);
            assert_eq!(root.task.children(), Vec::<TaskKey>::new());
        }
    }

    #[test]
    fn every_thread_failpoint_restores_claims_and_resource_references() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, root) = bootstrap(325);
            let counts = kernel.ids().counts();
            let files = root.resources.files();
            let credentials = root.resources.credentials();
            let file_refs = Arc::strong_count(&files);
            let credential_refs = Arc::strong_count(&credentials);
            let result = kernel.clone_thread(
                &root,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD
                        | LinuxCloneFlags::SIGHAND
                        | LinuxCloneFlags::VM
                        | LinuxCloneFlags::FILES,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(326),
                Some(point),
            );

            assert!(matches!(result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(Arc::strong_count(&files), file_refs);
            assert_eq!(Arc::strong_count(&credentials), credential_refs);
            assert_eq!(root.task.live_thread_count(), 1);
        }
    }

    #[test]
    fn every_identity_and_exit_failpoint_restores_registry_state() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, root) = bootstrap(335);
            let child = kernel
                .fork_task(
                    &root,
                    ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                    ThreadId::synthetic_for_tests(336),
                    "child".to_string(),
                    None,
                )
                .expect("child");
            let child_id = child.task.key().id;
            let counts = kernel.ids().counts();
            let task_count = kernel.registry().task_count();
            let group_count = kernel.registry().process_group_count();
            let session_count = kernel.registry().session_count();
            let child_shared_refs = Arc::strong_count(&child.shared);
            let child_resource_refs = Arc::strong_count(&child.resources);

            let group_result = kernel.create_process_group(child_id, Some(point));
            assert!(matches!(group_result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(kernel.registry().process_group_count(), group_count);
            assert_eq!(child.task.process_group(), root.task.process_group());

            let session_result = kernel.create_session(child_id, Some(point));
            assert!(matches!(session_result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(kernel.registry().process_group_count(), group_count);
            assert_eq!(kernel.registry().session_count(), session_count);
            assert_eq!(child.task.session(), root.task.session());

            let exit_result = kernel.exit_task(
                child_id,
                LinuxWaitStatus::from_wait_encoding(0),
                Some(point),
            );
            assert!(matches!(exit_result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(kernel.registry().task_count(), task_count);
            assert_eq!(kernel.registry().zombie_count(), 0);
            assert_eq!(Arc::strong_count(&child.shared), child_shared_refs);
            assert_eq!(Arc::strong_count(&child.resources), child_resource_refs);
            assert!(!matches!(
                kernel.create_process_group(child_id, None),
                Err(KernelOperationError::TaskBusy(_))
            ));
        }
    }

    #[test]
    fn operation_lifetime_reservations_allow_thread_prepare_but_serialize_publication() {
        let (kernel, root) = bootstrap(335);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");

        let prepared_fork = kernel
            .reserve_fork(&root, fork_plan, "prepared child".to_owned(), None)
            .expect("reserve fork")
            .prepare_reference(ThreadId::synthetic_for_tests(336))
            .expect("prepare fork backend");
        assert!(matches!(
            kernel.prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            ),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        drop(prepared_fork);

        let prepared_thread = kernel
            .reserve_thread_clone(&root, thread_plan, None)
            .expect("reserve thread")
            .prepare(ThreadId::synthetic_for_tests(337))
            .expect("prepare thread backend");
        let prepared_exit_while_thread_prepares = kernel
            .prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("thread preparation does not reserve the task");
        assert!(matches!(
            prepared_thread.commit(),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        drop(prepared_exit_while_thread_prepares);

        let prepared_exit = kernel
            .prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare exit");
        assert!(matches!(
            kernel.reserve_fork(&root, fork_plan, "blocked child".to_owned(), None),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        assert!(matches!(
            kernel.reserve_thread_clone(&root, thread_plan, None),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        drop(prepared_exit);

        let fork_after_drop = kernel
            .reserve_fork(&root, fork_plan, "unblocked child".to_owned(), None)
            .expect("exit drop unlocks fork");
        drop(fork_after_drop);
        let thread_after_drop = kernel
            .reserve_thread_clone(&root, thread_plan, None)
            .expect("fork drop unlocks thread");
        drop(thread_after_drop);
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn thread_reservation_waits_for_an_overlapping_task_transaction() {
        let (kernel, root) = bootstrap(336);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let prepared_fork = kernel
            .reserve_fork(&root, fork_plan, "prepared child".to_owned(), None)
            .expect("reserve fork")
            .prepare_reference(ThreadId::synthetic_for_tests(337))
            .expect("prepare fork backend");
        let waiter_kernel = Arc::clone(&kernel);
        let root_task = root.task().key().id;
        let root_tid = root.thread().key().tid;
        let waiter = std::thread::spawn(move || {
            let waiter_root = waiter_kernel
                .context(root_task, root_tid)
                .expect("capture reservation waiter context");
            waiter_kernel.reserve_thread_clone_eventually(&waiter_root, thread_plan)
        });
        kernel.wait_for_reservation_waiter_for_tests();
        drop(prepared_fork);
        let reservation = waiter
            .join()
            .expect("thread reservation waiter")
            .expect("reserve after transaction release");
        drop(reservation);
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn prepared_thread_publication_waits_for_an_overlapping_task_transaction() {
        let (kernel, root) = bootstrap(338);
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let prepared_thread = kernel
            .reserve_thread_clone(&root, thread_plan, None)
            .expect("reserve thread")
            .prepare(ThreadId::synthetic_for_tests(339))
            .expect("prepare thread backend");
        let prepared_exit = kernel
            .prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("reserve overlapping exit");

        let publisher =
            std::thread::spawn(move || prepared_thread.reserve_publication_eventually()?.commit());
        kernel.wait_for_reservation_waiter_for_tests();
        drop(prepared_exit);
        let published = publisher
            .join()
            .expect("thread publisher")
            .expect("publish after transaction release");
        assert_eq!(
            published
                .context()
                .expect("published thread context")
                .task()
                .live_thread_count(),
            2
        );
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn exact_generation_exit_waits_for_reservation_release_and_is_idempotent() {
        let (kernel, root) = bootstrap(336);
        let task = root.task().key();
        let prepared_fork = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
                "reservation holder".to_owned(),
                None,
            )
            .unwrap()
            .prepare_reference(ThreadId::synthetic_for_tests(337))
            .unwrap();

        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let exiting = Arc::clone(&kernel);
        let handle = std::thread::spawn(move || {
            let result = exiting
                .exit_task_key_eventually(task, LinuxWaitStatus::from_wait_encoding(17 << 8));
            done_tx.send(result).unwrap();
        });
        kernel.wait_for_reservation_waiter_for_tests();
        assert!(matches!(
            done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        drop(prepared_fork);
        let zombie = done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("reservation release wakes terminal retry")
            .expect("exact-generation exit succeeds");
        handle.join().unwrap();
        assert_eq!(zombie.key, task);
        assert_eq!(zombie.status.raw(), 17 << 8);

        let repeated = kernel
            .exit_task_key_eventually(task, LinuxWaitStatus::from_wait_encoding(99 << 8))
            .expect("exact zombie makes repeated cleanup idempotent");
        assert_eq!(repeated.key, task);
        assert_eq!(repeated.status.raw(), 17 << 8);
    }

    #[test]
    fn prepared_task_exit_reserves_affected_graph_and_drop_unlocks_it() {
        let (kernel, root) = bootstrap(340);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let parent = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(341),
                "parent".to_owned(),
                None,
            )
            .expect("parent");
        let live_child = kernel
            .fork_task(
                &parent,
                plan,
                ThreadId::synthetic_for_tests(342),
                "live child".to_owned(),
                None,
            )
            .expect("live child");
        let refreshed_parent = kernel
            .context(parent.task.key().id, parent.thread.key().tid)
            .expect("refreshed parent");
        let zombie_child = kernel
            .fork_task(
                &refreshed_parent,
                plan,
                ThreadId::synthetic_for_tests(343),
                "zombie child".to_owned(),
                None,
            )
            .expect("zombie child");
        kernel
            .exit_task(
                zombie_child.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("zombie child exit");

        let prepared = kernel
            .prepare_task_exit(
                parent.task.key().id,
                LinuxWaitStatus::from_wait_encoding(7 << 8),
                None,
            )
            .expect("prepare parent exit");
        assert_eq!(kernel.validate_invariants(), Ok(()));
        for reserved in [
            root.task.key().id,
            parent.task.key().id,
            live_child.task.key().id,
            zombie_child.task.key().id,
        ] {
            assert!(matches!(
                kernel.create_process_group(reserved, None),
                Err(KernelOperationError::TaskBusy(id)) if id == reserved
            ));
        }
        assert!(matches!(
            kernel.wait_child(
                parent.task.key().id,
                Some(zombie_child.task.key().id),
                WaitMode::Consume,
            ),
            Err(KernelOperationError::TaskBusy(id)) if id == parent.task.key().id
        ));

        drop(prepared);
        assert!(matches!(
            kernel.wait_child(
                parent.task.key().id,
                Some(zombie_child.task.key().id),
                WaitMode::Consume,
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        assert!(!matches!(
            kernel.create_process_group(live_child.task.key().id, None),
            Err(KernelOperationError::TaskBusy(_))
        ));
    }

    #[test]
    fn prepared_task_exit_publishes_reparenting_and_subscriber_once() {
        let (kernel, root) = bootstrap(345);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let parent = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(346),
                "parent".to_owned(),
                None,
            )
            .expect("parent");
        let child = kernel
            .fork_task(
                &parent,
                plan,
                ThreadId::synthetic_for_tests(347),
                "child".to_owned(),
                None,
            )
            .expect("child");
        let subscriber = Arc::new(CountingExitSubscriber::default());
        assert_eq!(
            kernel.register_task_exit_subscriber(parent.task.key().id, &subscriber),
            Some(parent.task.key())
        );

        let prepared = kernel
            .prepare_task_exit(
                parent.task.key().id,
                LinuxWaitStatus::from_wait_encoding(9 << 8),
                None,
            )
            .expect("prepare parent exit");
        assert!(kernel.task_is_live(parent.task.key().id));
        assert_eq!(subscriber.0.load(Ordering::Acquire), 0);
        let zombie = prepared.commit().expect("commit parent exit");

        assert_eq!(zombie.status, LinuxWaitStatus::from_wait_encoding(9 << 8));
        assert_eq!(subscriber.0.load(Ordering::Acquire), 1);
        assert!(!kernel.task_is_live(parent.task.key().id));
        assert_eq!(
            kernel
                .task_identity(child.task.key().id)
                .expect("reparented child")
                .parent,
            Some(root.task.key())
        );
        assert!(matches!(
            kernel.wait_child(
                root.task.key().id,
                Some(parent.task.key().id),
                WaitMode::Observe,
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        let after_exit = Arc::new(CountingExitSubscriber::default());
        assert_eq!(
            kernel.register_task_exit_subscriber(parent.task.key().id, &after_exit),
            Some(parent.task.key())
        );
        assert_eq!(after_exit.0.load(Ordering::Acquire), 1);
        assert_eq!(subscriber.0.load(Ordering::Acquire), 1);
    }

    #[test]
    fn registry_serializes_process_group_membership_transitions() {
        let (kernel, root) = bootstrap(350);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let first = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(351),
                "first".to_string(),
                None,
            )
            .expect("first child");
        let refreshed_root = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refreshed root context");
        let second = kernel
            .fork_task(
                &refreshed_root,
                fork_plan,
                ThreadId::synthetic_for_tests(352),
                "second".to_string(),
                None,
            )
            .expect("second child");
        let group = kernel
            .create_process_group(first.task.key().id, None)
            .expect("new process group");

        kernel
            .join_process_group(second.task.key().id, group)
            .expect("join group");

        assert_eq!(first.task.process_group(), group);
        assert_eq!(second.task.process_group(), group);
        assert_eq!(
            kernel.registry().process_group_members(group),
            vec![first.task.key(), second.task.key()]
        );
        assert_eq!(first.task.session(), root.task.session());
    }

    #[test]
    fn set_process_group_enforces_parent_session_and_group_policy_atomically() {
        let (kernel, root) = bootstrap(360);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let first = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(361),
                "first".to_string(),
                None,
            )
            .expect("first child");
        let refreshed_root = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refreshed root context");
        let second = kernel
            .fork_task(
                &refreshed_root,
                fork_plan,
                ThreadId::synthetic_for_tests(362),
                "second".to_string(),
                None,
            )
            .expect("second child");
        let first_group = ProcessGroupId::from_leader(first.task.key().id);

        kernel
            .set_process_group(root.task.key().id, Some(first.task.key().id), None)
            .expect("create child's group");
        kernel
            .set_process_group(
                root.task.key().id,
                Some(second.task.key().id),
                Some(first_group),
            )
            .expect("join sibling's group");
        assert_eq!(first.task.process_group(), first_group);
        assert_eq!(second.task.process_group(), first_group);
        assert_eq!(
            kernel.registry().process_group_members(first_group),
            vec![first.task.key(), second.task.key()]
        );

        let first_context = kernel
            .context(first.task.key().id, first.thread.key().tid)
            .expect("first child context");
        let grandchild = kernel
            .fork_task(
                &first_context,
                fork_plan,
                ThreadId::synthetic_for_tests(363),
                "grandchild".to_string(),
                None,
            )
            .expect("grandchild");
        assert!(matches!(
            kernel.set_process_group(
                root.task.key().id,
                Some(grandchild.task.key().id),
                None,
            ),
            Err(KernelOperationError::UnknownTask(task_id)) if task_id == grandchild.task.key().id
        ));
        assert!(matches!(
            kernel.set_process_group(
                root.task.key().id,
                Some(second.task.key().id),
                Some(ProcessGroupId::from_leader(grandchild.task.key().id)),
            ),
            Err(KernelOperationError::IdentityPermission)
        ));
        assert!(matches!(
            kernel.set_process_group(root.task.key().id, None, None),
            Err(KernelOperationError::IdentityPermission)
        ));
    }

    #[test]
    fn parent_cannot_change_process_group_after_child_exec() {
        let (kernel, root) = bootstrap(370);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(371),
                "child".to_string(),
                None,
            )
            .expect("child");
        let prepared = kernel.prepare_exec(&child, None).expect("prepare exec");
        kernel.commit_exec(prepared, None).expect("commit exec");

        assert!(matches!(
            kernel.set_process_group(root.task.key().id, Some(child.task.key().id), None),
            Err(KernelOperationError::ChildExeced(task_id)) if task_id == child.task.key().id
        ));
    }

    #[test]
    fn registry_publishes_new_session_and_group_together() {
        let (kernel, root) = bootstrap(375);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(376),
                "session child".to_string(),
                None,
            )
            .expect("child");
        let session = kernel
            .create_session(child.task.key().id, None)
            .expect("new session");
        let group = ProcessGroupId::from_leader(child.task.key().id);

        assert_eq!(child.task.session(), session);
        assert_eq!(child.task.process_group(), group);
        assert_eq!(
            kernel.registry().session_process_groups(session),
            vec![group]
        );
        assert_eq!(
            kernel.registry().process_group_members(group),
            vec![child.task.key()]
        );
    }

    #[test]
    fn identity_failpoint_does_not_publish_partial_group() {
        let (kernel, root) = bootstrap(390);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(391),
                "child".to_string(),
                None,
            )
            .expect("child");
        let original_group = child.task.process_group();
        let result =
            kernel.create_process_group(child.task.key().id, Some(KernelFailpoint::BeforePublish));

        assert!(matches!(
            result,
            Err(KernelOperationError::Injected(
                KernelFailpoint::BeforePublish
            ))
        ));
        assert_eq!(child.task.process_group(), original_group);
        assert!(
            kernel
                .registry()
                .process_group(ProcessGroupId::from_leader(child.task.key().id))
                .is_none()
        );
    }

    #[test]
    fn exiting_parent_reparents_live_and_zombie_children_to_root() {
        let (kernel, root) = bootstrap(395);
        let parent = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(396),
                "parent".to_string(),
                None,
            )
            .expect("parent");
        let grandchild = kernel
            .fork_task(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(397),
                "grandchild".to_string(),
                None,
            )
            .expect("grandchild");
        let grandchild_id = grandchild.task.key().id;
        let refreshed_parent = kernel
            .context(parent.task.key().id, parent.thread.key().tid)
            .expect("refreshed parent");
        let live_grandchild = kernel
            .fork_task(
                &refreshed_parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(398),
                "live grandchild".to_string(),
                None,
            )
            .expect("live grandchild");
        let parent_id = parent.task.key().id;
        drop(grandchild);

        kernel
            .exit_task(grandchild_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("grandchild exit");
        kernel
            .exit_task(parent_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("parent exit");

        let zombie = kernel
            .registry()
            .zombie(grandchild_id)
            .expect("reparented zombie");
        assert_eq!(zombie.parent, Some(root.task.key()));
        assert_eq!(live_grandchild.task.parent(), Some(root.task.key()));
        let descendant = kernel
            .fork_task(
                &live_grandchild,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(399),
                "reparented descendant".to_string(),
                None,
            )
            .expect("ordinary fork does not inherit the caller's parent association");
        assert_eq!(descendant.task.parent(), Some(live_grandchild.task.key()));
        assert!(matches!(
            kernel.fork_task(
                &live_grandchild,
                ClonePlan::from_flags(LinuxCloneFlags::PARENT).expect("CLONE_PARENT plan"),
                ThreadId::synthetic_for_tests(400),
                "stale CLONE_PARENT descendant".to_string(),
                None,
            ),
            Err(KernelOperationError::StaleContext)
        ));
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(grandchild_id), WaitMode::Consume),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        assert!(!kernel.ids().is_reserved_number(grandchild_id.raw()));
    }

    proptest! {
        #[test]
        fn bounded_operation_sequences_preserve_registry_invariants(
            actions in proptest::collection::vec(any::<u8>(), 1..80)
        ) {
            let (kernel, root) = bootstrap(500);
            let root_id = root.task.key().id;
            for (step, action) in actions.into_iter().enumerate() {
                let tasks = kernel.registry().task_ids();
                if tasks.is_empty() {
                    break;
                }
                let selected = tasks[usize::from(action) % tasks.len()];
                match action % 7 {
                    0 if tasks.len() < 12 => {
                        if let Ok(context) = kernel.context(
                            selected,
                            LinuxTid::for_task_leader(selected),
                        ) {
                            let _ = kernel.fork_task(
                                &context,
                                ClonePlan::from_flags(LinuxCloneFlags::empty())
                                    .expect("fork plan"),
                                ThreadId::synthetic_for_tests(1_000 + step as i32),
                                format!("task-{step}"),
                                None,
                            );
                        }
                    }
                    1 => {
                        if let Ok(context) = kernel.context(
                            selected,
                            LinuxTid::for_task_leader(selected),
                        ) {
                            let _ = kernel.clone_thread(
                                &context,
                                ClonePlan::from_flags(
                                    LinuxCloneFlags::THREAD
                                        | LinuxCloneFlags::SIGHAND
                                        | LinuxCloneFlags::VM,
                                )
                                .expect("thread plan"),
                                ThreadId::synthetic_for_tests(2_000 + step as i32),
                                None,
                            );
                        }
                    }
                    2 if selected != root_id => {
                        let _ = kernel.exit_task(
                            selected,
                            LinuxWaitStatus::from_wait_encoding(0),
                            None,
                        );
                    }
                    3 => {
                        let _ = kernel.wait_child(root_id, None, WaitMode::Consume);
                    }
                    4 => {
                        let _ = kernel.create_process_group(selected, None);
                    }
                    5 if selected != root_id => {
                        let _ = kernel.create_session(selected, None);
                    }
                    6 => {
                        let groups = kernel.registry().process_group_ids();
                        if let Some(group) = groups.get(usize::from(action) % groups.len().max(1)) {
                            let _ = kernel.join_process_group(selected, *group);
                        }
                    }
                    _ => {}
                }
                prop_assert_eq!(kernel.validate_invariants(), Ok(()));
            }
        }
    }

    #[test]
    fn zombie_holds_numeric_claim_until_consuming_wait() {
        let (kernel, root) = bootstrap(400);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(401),
                "child".to_string(),
                None,
            )
            .expect("fork");
        let child_id = child.task.key().id;
        drop(child);

        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Observe),
            Ok(WaitOutcome::StillRunning)
        ));
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(7 << 8), None)
            .expect("exit");
        assert!(kernel.ids().is_reserved_number(child_id.raw()));
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Observe),
            Ok(WaitOutcome::Exited(_))
        ));
        assert!(kernel.ids().is_reserved_number(child_id.raw()));
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Consume),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        assert!(!kernel.ids().is_reserved_number(child_id.raw()));
        assert_eq!(kernel.registry().zombie_count(), 0);
    }
}

#[cfg(test)]
mod credential_authority_tests {
    use super::*;
    use crate::kernel::{ClonePlan, Kernel, RootBootstrap};
    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;
    use std::sync::Arc;

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        Kernel::bootstrap_root(
            RootBootstrap::for_reference_model(
                pid,
                ThreadId::synthetic_for_tests(pid),
                "credential-authority-test".to_owned(),
            )
            .expect("bootstrap input"),
        )
        .expect("bootstrap")
    }

    #[test]
    fn sibling_thread_credential_cow_diverges_only_calling_thread() {
        let (kernel, root) = bootstrap(8_100);
        let root = kernel
            .update_credentials(&root, |credentials| credentials.seed_identity(1000, 1000))
            .expect("seed root credentials");
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::VM
                | LinuxCloneFlags::SIGHAND
                | LinuxCloneFlags::THREAD
                | LinuxCloneFlags::FILES
                | LinuxCloneFlags::FS,
        )
        .expect("thread clone plan");
        let sibling = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_101), None)
            .expect("clone thread");
        assert_ne!(
            root.resources().credentials().id(),
            sibling.resources().credentials().id()
        );

        let sibling = kernel
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(2000);
                credentials.set_supplementary_groups(vec![7, 11]);
            })
            .expect("publish sibling credentials");
        assert_eq!(root.resources().credentials().fsuid(), 1000);
        assert_eq!(
            root.resources()
                .credentials()
                .supplementary_groups_override(),
            None
        );
        assert_eq!(sibling.resources().credentials().fsuid(), 2000);
        assert_eq!(
            sibling
                .resources()
                .credentials()
                .supplementary_groups_override(),
            Some([7, 11].as_slice())
        );
        let fresh_root = kernel
            .context(root.task().key().id, root.thread().key().tid)
            .expect("fresh root context");
        assert_eq!(fresh_root.resources().credentials().fsuid(), 1000);
    }

    #[test]
    fn fork_copies_values_with_distinct_credential_identity() {
        let (kernel, root) = bootstrap(8_200);
        let root = kernel
            .update_credentials(&root, |credentials| {
                credentials.seed_identity(123, 456);
                credentials.set_fsuid(321);
                credentials.set_fsgid(654);
                credentials.set_umask(0o077);
                credentials.set_supplementary_groups(vec![2, 4, 8]);
            })
            .expect("seed parent credentials");
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(8_201),
                "credential-child".to_owned(),
                None,
            )
            .expect("fork task");
        let parent = root.resources().credentials();
        let child = child.resources().credentials();
        assert_ne!(parent.id(), child.id());
        assert_eq!(
            parent.supplementary_groups_override(),
            child.supplementary_groups_override()
        );
        assert_eq!(
            child.supplementary_groups_override(),
            Some([2, 4, 8].as_slice())
        );
        assert_eq!(
            (
                parent.ruid(),
                parent.egid(),
                parent.fsuid(),
                parent.fsgid(),
                parent.umask()
            ),
            (
                child.ruid(),
                child.egid(),
                child.fsuid(),
                child.fsgid(),
                child.umask()
            )
        );
    }

    #[test]
    fn fork_from_nonleader_copies_the_callers_divergent_credentials() {
        let (kernel, root) = bootstrap(8_250);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::VM
                | LinuxCloneFlags::SIGHAND
                | LinuxCloneFlags::THREAD
                | LinuxCloneFlags::FILES
                | LinuxCloneFlags::FS,
        )
        .expect("thread clone plan");
        let sibling = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_251), None)
            .expect("clone sibling");
        let sibling = kernel
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(9250);
                credentials.set_supplementary_groups(vec![25, 26]);
            })
            .expect("diverge sibling credentials");

        let child = kernel
            .fork_task(
                &sibling,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(8_252),
                "nonleader-credential-child".to_owned(),
                None,
            )
            .expect("fork from sibling");

        assert_eq!(root.resources().credentials().fsuid(), 0);
        assert_eq!(child.resources().credentials().fsuid(), 9250);
        assert_eq!(
            child
                .resources()
                .credentials()
                .supplementary_groups_override(),
            Some([25, 26].as_slice())
        );
    }

    #[test]
    fn sibling_credential_publication_does_not_stale_exact_fork_caller() {
        let (kernel, root) = bootstrap(8_275);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::VM
                | LinuxCloneFlags::SIGHAND
                | LinuxCloneFlags::THREAD
                | LinuxCloneFlags::FILES
                | LinuxCloneFlags::FS,
        )
        .expect("thread clone plan");
        let sibling = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_276), None)
            .expect("clone sibling");
        let root = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("refresh root after thread clone");
        kernel
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(9275);
            })
            .expect("diverge sibling credentials");

        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(8_277),
                "exact-root-credential-child".to_owned(),
                None,
            )
            .expect("fork exact root after sibling publication");

        assert_eq!(child.resources().credentials().fsuid(), 0);
    }

    #[test]
    fn exec_retains_callers_credential_object() {
        let (kernel, root) = bootstrap(8_300);
        let root = kernel
            .update_credentials(&root, |credentials| {
                credentials.seed_identity(77, 88);
                credentials.set_supplementary_groups(Vec::new());
            })
            .expect("seed credentials");
        let before = root.resources().credentials();
        let committed = kernel
            .commit_exec(
                kernel.prepare_exec(&root, None).expect("prepare exec"),
                None,
            )
            .expect("commit exec");
        let after = committed.resources().credentials();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!((after.ruid(), after.rgid()), (77, 88));
        assert_eq!(after.supplementary_groups_override(), Some([].as_slice()));
    }

    #[test]
    fn replaced_callers_resources_reject_stale_exec_context() {
        let (kernel, root) = bootstrap(8_315);
        kernel
            .update_credentials(&root, |credentials| {
                credentials.set_fsuid(9315);
            })
            .expect("replace caller credentials");

        assert!(matches!(
            kernel.prepare_exec(&root, None),
            Err(crate::kernel::ExecError::ForeignContext)
        ));
    }

    #[test]
    fn sibling_credential_publication_does_not_stale_exact_exec_caller() {
        let (kernel, root) = bootstrap(8_325);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::VM
                | LinuxCloneFlags::SIGHAND
                | LinuxCloneFlags::THREAD
                | LinuxCloneFlags::FILES
                | LinuxCloneFlags::FS,
        )
        .expect("thread clone plan");
        let sibling = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_326), None)
            .expect("clone sibling");
        let root = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("refresh root after thread clone");
        kernel
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(9325);
            })
            .expect("diverge sibling credentials");

        let prepared = kernel
            .prepare_exec(&root, None)
            .expect("prepare exec from exact root after sibling publication");
        let exec = kernel.commit_exec(prepared, None).expect("commit exec");

        assert_eq!(exec.resources().credentials().fsuid(), 0);
    }

    #[test]
    fn credential_publication_waits_for_task_reservation_without_recapture() {
        let (kernel, root) = bootstrap(8_350);
        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "credential-reservation-child".to_owned(),
                None,
            )
            .expect("hold task reservation");
        let exact = root.retain_exact();
        let updating = Arc::clone(&kernel);
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = updating.update_credentials(&exact, |credentials| {
                credentials.set_fsuid(8350);
            });
            sent.send(result).unwrap();
        });

        assert!(matches!(
            received.recv_timeout(std::time::Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(reservation);
        let updated = received
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("credential publication wakes")
            .expect("credential publication succeeds");
        worker.join().unwrap();
        assert_eq!(updated.resources().credentials().fsuid(), 8350);
    }

    #[test]
    fn stale_context_cannot_publish_credentials() {
        let (kernel, original) = bootstrap(8_400);
        let current = kernel
            .update_credentials(&original, |credentials| credentials.set_fsuid(42))
            .expect("publish current credentials");

        assert!(matches!(
            kernel.update_credentials(&original, |credentials| credentials.set_fsuid(99)),
            Err(KernelOperationError::StaleContext)
        ));
        assert_eq!(current.resources().credentials().fsuid(), 42);
        let fresh = kernel
            .context(current.task().key().id, current.thread().key().tid)
            .expect("fresh context");
        assert_eq!(fresh.resources().credentials().fsuid(), 42);
    }
}
