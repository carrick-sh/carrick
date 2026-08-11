use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
use super::ids::{LinuxTid, MmId, ObjectIdError, ProcessGroupId, SessionId, TaskId};
use super::objects::{
    LinuxWaitStatus, Mm, ObjectGraphError, ProcessGroup, Session, Task, TaskKey, TaskLifecycle,
    TaskRef, TaskRusage, TaskShared, TaskSharedCloneError, ThreadKey, ThreadRef, ThreadResources,
    Zombie,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    Exited(Zombie),
    StillRunning,
    NoChild,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskIdentity {
    pub task_id: TaskId,
    pub parent: Option<TaskId>,
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
        let mm = Arc::new(Mm::with_backend(self.kernel.object_ids().mm_id()?, backend));
        self.prepare(Some(mm), child_registry_id)
    }

    pub fn prepare_shared_mm(
        self,
        child_registry_id: ThreadId,
    ) -> Result<PreparedFork, KernelOperationError> {
        if self.plan.mm() != CloneObjectMode::Share {
            return Err(KernelOperationError::MissingForkMmBackend);
        }
        self.prepare(None, child_registry_id)
    }

    #[cfg(test)]
    fn prepare_reference(
        self,
        child_registry_id: ThreadId,
    ) -> Result<PreparedFork, KernelOperationError> {
        let copied_mm = (self.plan.mm() == CloneObjectMode::Copy)
            .then(|| {
                self.kernel
                    .object_ids()
                    .mm_id()
                    .map(Mm::new_reference)
                    .map(Arc::new)
            })
            .transpose()?;
        self.prepare(copied_mm, child_registry_id)
    }

    fn prepare(
        self,
        copied_mm: Option<Arc<Mm>>,
        child_registry_id: ThreadId,
    ) -> Result<PreparedFork, KernelOperationError> {
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
            task_id,
            parent: record.task.parent().map(|parent| parent.id),
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
        let (child_parent_task, child_parent_revision, operation) = {
            let mut state = self.registry().state.write();
            let caller_record = state
                .tasks
                .get(&parent.task.key().id)
                .ok_or(KernelOperationError::ParentExited)?;
            if caller_record.task.key() != parent.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            if caller_record.revision != parent.revision {
                return Err(KernelOperationError::StaleContext);
            }
            let (child_parent_task, child_parent_revision) = match plan.fork_parent() {
                ForkParentMode::Caller => (Arc::clone(&parent.task), parent.revision),
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
            (child_parent_task, child_parent_revision, operation)
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
            caller_revision: parent.revision,
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
        Ok(next)
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
        rusage: TaskRusage,
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
        self.prepare_task_exit_key(task, status, rusage, failpoint)
    }

    pub fn prepare_task_exit_key(
        self: &Arc<Self>,
        task_key: TaskKey,
        status: LinuxWaitStatus,
        rusage: TaskRusage,
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
        let adopter = (task_key != state.root).then_some(state.root);
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

        let registry_zombie = Zombie::from_task(&task, status, rusage, diagnostic_name);
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
    fn commit_task_exit(
        &self,
        mut prepared: PreparedTaskExit,
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
        prepared.reservation.commit(&mut state)?;
        // Detach this exact task generation's watchers before the zombie can
        // be consumed and its numeric claim eventually reused. Callbacks stay
        // outside the registry lock, but a later generation can no longer be
        // mistaken for this exit.
        let subscribers = self.exit_subscribers.take(prepared.task);
        drop(state);
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
        rusage: TaskRusage,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<Zombie, KernelOperationError> {
        self.prepare_task_exit(task_id, status, rusage, failpoint)?
            .commit()
    }

    /// Publish terminal state for one exact task generation, waiting on the
    /// Kernel's reservation-change event for transient fork/exec/exit overlap.
    /// Re-observation of the same exact zombie is idempotent; a reused numeric
    /// PID with another serial is never mutated.
    pub fn exit_task_key_eventually(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        rusage: TaskRusage,
    ) -> Result<Zombie, KernelOperationError> {
        loop {
            let observed = self.reservation_epoch();
            match self.prepare_task_exit_key(task, status, rusage, None) {
                Ok(prepared) => return prepared.commit(),
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
        self.wait_child_matching(parent_id, target, None, mode)
    }

    pub fn wait_child_key(
        &self,
        parent_id: TaskId,
        target: TaskKey,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.wait_child_matching(parent_id, Some(target.id), Some(target), mode)
    }

    fn wait_child_matching(
        &self,
        parent_id: TaskId,
        target: Option<TaskId>,
        exact_target: Option<TaskKey>,
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
                    parent_record.revision = parent_revision;
                }
            }
            return Ok(WaitOutcome::Exited(zombie));
        }

        let live_child = state.tasks.iter().any(|(id, record)| {
            record.task.parent() == Some(parent)
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

    use carrick_abi::{LinuxCloneFlags, SigSet};
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
            .exit_task(
                child_id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            )
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
            .exit_task_key_eventually(
                child_a_key,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
            )
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
            .exit_task_key_eventually(
                child_b.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
            )
            .expect("exit child B");
        assert_eq!(pidfd_watch.0.load(Ordering::Acquire), 1);
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
                TaskRusage::default(),
                None,
            )
            .expect("prepare parent exit");
        let exiting_kernel = Arc::clone(&kernel);
        let child_key = child.task().key();
        let child_exit = std::thread::spawn(move || {
            exiting_kernel.exit_task_key_eventually(
                child_key,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
            )
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
    fn fork_publishes_task_and_independently_selected_resources() {
        let (kernel, root) = bootstrap(100);
        let ignored = LinuxSignal::for_signal_number(2).expect("ignored signal");
        let caught = LinuxSignal::for_signal_number(3).expect("caught signal");
        root.shared
            .sighand()
            .set_disposition(ignored, SignalDisposition::Ignore);
        root.shared
            .sighand()
            .set_disposition(caught, SignalDisposition::Caught);
        let parent_signals =
            ThreadSignalState::new(SigSet::EMPTY.with(4), SigSet::EMPTY.with(5), true, 2);
        root.thread.replace_signal_state(parent_signals);
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
                task_id: child.task.key().id,
                parent: Some(root.task.key().id),
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
            .exit_task(
                child_id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            )
            .expect("retire fail-safe child");
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
                TaskRusage::default(),
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
                TaskRusage::default(),
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
                TaskRusage::default(),
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
            .exit_task(
                child_id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            )
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
            Arc::new(Credentials::new()),
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

    #[test]
    fn stale_context_cannot_commit_a_fork() {
        let (kernel, root) = bootstrap(275);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(276),
                "first child".to_string(),
                None,
            )
            .expect("first fork");
        drop(child);
        let result = kernel.fork_task(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
            ThreadId::synthetic_for_tests(277),
            "stale child".to_string(),
            None,
        );

        assert!(matches!(result, Err(KernelOperationError::StaleContext)));
        assert_eq!(kernel.registry().task_count(), 2);
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
                TaskRusage::default(),
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
                TaskRusage::default(),
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
                TaskRusage::default(),
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
                TaskRusage::default(),
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
                TaskRusage::default(),
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
            let result = exiting.exit_task_key_eventually(
                task,
                LinuxWaitStatus::from_wait_encoding(17 << 8),
                TaskRusage::default(),
            );
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
            .exit_task_key_eventually(
                task,
                LinuxWaitStatus::from_wait_encoding(99 << 8),
                TaskRusage::default(),
            )
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
                TaskRusage::default(),
                None,
            )
            .expect("zombie child exit");

        let prepared = kernel
            .prepare_task_exit(
                parent.task.key().id,
                LinuxWaitStatus::from_wait_encoding(7 << 8),
                TaskRusage::default(),
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
                TaskRusage::default(),
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
            Some(root.task.key().id)
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
            .exit_task(
                grandchild_id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            )
            .expect("grandchild exit");
        kernel
            .exit_task(
                parent_id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            )
            .expect("parent exit");

        let zombie = kernel
            .registry()
            .zombie(grandchild_id)
            .expect("reparented zombie");
        assert_eq!(zombie.parent, Some(root.task.key()));
        assert_eq!(live_grandchild.task.parent(), Some(root.task.key()));
        assert!(matches!(
            kernel.fork_task(
                &live_grandchild,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(399),
                "stale descendant".to_string(),
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
                            TaskRusage::default(),
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
            .exit_task(
                child_id,
                LinuxWaitStatus::from_wait_encoding(7 << 8),
                TaskRusage::default(),
                None,
            )
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
