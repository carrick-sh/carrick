use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use carrick_fatal::carrick_fatal;

use carrick_abi::NsUid;
use carrick_hal::{KernelTransactionId, ThreadId};
use parking_lot::{Condvar, Mutex};

use super::address::MmBackend;
use super::clone_plan::{
    CloneObjectMode, ClonePlan, CloneTaskMode, ForkParentMode, ForkPidfdMode, VforkMode,
};
use super::core::{
    Kernel, KernelContext, KernelDomain, RegistryState, TaskExitSubscriber, TaskRecord,
    TaskRevision, VforkChildRelease, VforkParentWait, VforkReleaseReason, ZombieRecord,
};
use super::ids::{LinuxSignal, LinuxTid, MmId, ObjectIdError, ProcessGroupId, TaskId};
use super::objects::{
    FileTable, LinuxWaitStatus, Mm, ObjectGraphError, Task, TaskKey, TaskLifecycle,
    TaskParticipantError, TaskRef, TaskShared, TaskSharedCloneError, ThreadKey, ThreadRef,
    ThreadResources, Zombie,
};
use super::registry::{IdError, TaskReservation, ThreadClaim};

pub mod identity;
pub mod session;
pub mod wait;
pub(super) use identity::namespace_visible_task_id;

pub mod signal;
pub use identity::{ProcessIdentity, ProcessState, TaskIdentity};
pub(crate) use session::TtyControlError;
use session::remove_group_member;
pub use signal::SignalTargetAuthorization;
pub(crate) use signal::{
    CarrierControlSignalPost, ExactSignalTargetAuthorization, ExactThreadSignalPost,
};
pub use wait::{ChildWaitPrecheck, WaitChildClass, WaitMode, WaitOutcome};
pub mod thread;
pub use thread::{
    PreparedThreadClone, PublishedThreadClone, StartedThreadClone, ThreadCloneReservation,
    ThreadPublicationReservationAttempt,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelFailpoint {
    AfterReserve,
    AfterObjects,
    AfterBackendPrepare,
    BeforePublish,
}

/// Result of splitting one calling thread's `CLONE_FILES` file table for
/// `close_range`. The caller must consume `old_file_table` through its exact
/// dispatcher close path before using `context`: when this was the final table
/// owner, the old slots are transferred to the successor rather than simply
/// discarded.
pub(crate) struct CloseRangeUnshare {
    context: KernelContext,
    old_files: Arc<FileTable>,
}

impl CloseRangeUnshare {
    pub(crate) fn context(&self) -> &KernelContext {
        &self.context
    }

    pub(crate) fn old_file_table(&self) -> &Arc<FileTable> {
        &self.old_files
    }
}

/// Result of resolving one Linux signal target against the authoritative
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
    pub(super) fn pair() -> (Self, ChildStartRelease) {
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
pub(super) struct ChildStartRelease {
    shared: Arc<ChildStartShared>,
    active: bool,
}

impl ChildStartRelease {
    pub(super) fn start(&mut self) {
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
    visible_child_id: i32,
    start_wait: Option<ChildStartWait>,
    start_release: ChildStartRelease,
}

impl PublishedFork {
    pub const fn visible_child_id(&self) -> i32 {
        self.visible_child_id
    }

    pub fn context(&self) -> Option<&KernelContext> {
        self.started.as_ref().map(StartedFork::context)
    }

    pub fn start_child(mut self) -> Result<StartedFork, KernelOperationError> {
        if let Some(started) = self.started.as_ref() {
            started.context.thread().open_start_gate();
        }
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
        if let Some(started) = self.started.as_ref() {
            started.context.thread().open_start_gate();
        }
        self.start_release.start();
        drop(self.start_wait.take());
    }
}

/// Non-cloneable ownership of one registry transaction across an exact task
/// set. External/backend preparation may run only while this guard is live;
/// dropping it releases every identity still owned by this transaction.
#[derive(Debug)]
pub(super) struct TaskSetReservation {
    kernel: Arc<Kernel>,
    task_ids: Vec<TaskId>,
    transaction: KernelTransactionId,
    active: bool,
}

impl TaskSetReservation {
    pub(super) fn acquired(
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

    pub(super) fn validate(&self, state: &RegistryState) -> Result<(), KernelOperationError> {
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

    pub(super) fn commit(
        &mut self,
        state: &mut RegistryState,
    ) -> Result<PendingReservationPublication, KernelOperationError> {
        self.validate(state)?;
        for task_id in &self.task_ids {
            state.reservations.remove(task_id);
        }
        self.active = false;
        // Publication is DEFERRED to the returned token: reservation-change
        // subscribers run synchronously in `publish_reservation_change`, and
        // a subscriber's wake path takes the registry lock shared
        // (`Scheduler::wake` -> `exact_thread_for_scheduler`). Publishing
        // here — under the caller's registry WRITE guard — self-deadlocked
        // the carrier once a subscriber existed for the committing task
        // (executor-8 sampled in `lock_shared_slow` inside its own clone
        // commit). The `Drop` arm below always had the correct order:
        // release the lock, then publish.
        Ok(PendingReservationPublication {
            kernel: Arc::clone(&self.kernel),
        })
    }
}

/// Deferred `publish_reservation_change` handed out by
/// [`TaskSetReservation::commit`]. Consume it with [`Self::publish`] AFTER
/// the registry write guard is released — subscriber callbacks may re-enter
/// the registry lock.
#[must_use = "reservation-change subscribers are not notified until publish() runs after the registry guard drops"]
pub(crate) struct PendingReservationPublication {
    kernel: Arc<Kernel>,
}

impl PendingReservationPublication {
    pub(crate) fn publish(self) {
        self.kernel.publish_reservation_change();
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
    /// The container's pid-namespace init as of this transaction, when it is
    /// still LIVE (the exiting task itself counts: it is live until this exit
    /// commits). `None` means the init has already become a zombie, so nothing
    /// inside the namespace can adopt anyone any more and container retirement
    /// is the reaper of last resort. Recorded here rather than re-read at
    /// commit so the judgement comes from the same reserved snapshot that
    /// chose `adopter`.
    namespace_init: Option<TaskKey>,
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

    /// Who will consume the zombie this exit publishes.
    ///
    /// A parentless zombie is NOT by itself a defect: a container's
    /// pid-namespace init has no parent inside its namespace, and a task its
    /// init left behind when it exited has none either — `retire_container`
    /// reaps both. The defect is a parentless zombie published while the
    /// namespace init was still live and should have adopted it.
    fn zombie_reaper(&self) -> crate::observe::ZombieReaper {
        match self.result_zombie.parent {
            Some(parent) => crate::observe::ZombieReaper::Parent(parent),
            None => match self.namespace_init {
                Some(init) if init != self.task => crate::observe::ZombieReaper::Unreapable,
                _ => crate::observe::ZombieReaper::ContainerRetirement,
            },
        }
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
    pid_identity: Option<crate::namespace::pid::PreparedNamespaceIdentity>,
    diagnostic_name: String,
    vfork_relationship: Option<(VforkParentWait, VforkChildRelease)>,
    failpoint: Option<KernelFailpoint>,
    external_peer_root: bool,
}

impl ForkReservation {
    pub const fn child_id(&self) -> TaskId {
        self.child_id
    }

    pub fn visible_child_id(&self) -> i32 {
        self.pid_identity
            .as_ref()
            .map_or(self.child_id.raw(), |identity| identity.visible_id() as i32)
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
            (!self.external_peer_root).then(|| self.child_parent_task.key()),
            self.caller_task.identity(),
            Arc::clone(&child_shared),
            child_resources.credentials(),
            self.caller_task.container(),
            self.plan.exit_signal(),
        ));
        // oom_score_adj, nice, the inherited keyrings and the capability/userns
        // copy — see `Task::inherit_fork_attributes_from`, which the host-fork
        // adapter shares so the two fork paths cannot drift apart again.
        child.inherit_fork_attributes_from(&self.caller_task);
        let leader_tid = LinuxTid::for_task_leader(self.child_id);
        let leader = child.attach_fork_thread(
            ThreadKey {
                tid: leader_tid,
                serial: self.kernel.object_ids().thread_serial()?,
            },
            child_registry_id,
            Arc::clone(&child_resources),
            self.caller_thread.signal_state(),
            self.caller_thread.affinity(),
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

    pub fn visible_child_id(&self) -> i32 {
        self.reservation.visible_child_id()
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

    pub(crate) fn retain_stdio_only(&mut self) -> Result<(), KernelOperationError> {
        let old_files = self.child_resources.files();
        let files = Arc::new(FileTable::for_external_exec(
            self.reservation.kernel.object_ids().file_table_id()?,
        ));
        let resources = Arc::new(self.child_resources.with_files(files));
        self.leader.replace_resources(Arc::clone(&resources));
        self.child_resources = resources;
        self.reservation
            .kernel
            .retire_file_table_if_unreferenced(&old_files);
        Ok(())
    }

    pub(crate) fn prepared_execution_identity(
        &self,
    ) -> (
        TaskKey,
        ThreadKey,
        MmId,
        super::objects::ExecutionGeneration,
    ) {
        (
            self.child.key(),
            self.leader.key(),
            self.child_shared.mm().id(),
            super::objects::ExecutionGeneration::initial_for_prepared_publication(),
        )
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
            pid_identity,
            diagnostic_name,
            vfork_relationship,
            failpoint,
            external_peer_root,
        } = reservation;
        let child_key = child.key();
        let visible_child_id = pid_identity
            .as_ref()
            .map_or(child_id.raw(), |identity| identity.visible_id() as i32);
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

            if pid_identity.is_some_and(|identity| !identity.commit()) {
                return Err(KernelOperationError::PidNamespaceMembership(child_id));
            }

            let task_claim = task_reservation.commit();
            if !external_peer_root {
                child_parent_task.add_child(child_key);
            }
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
            if !external_peer_root
                && let Some(parent_record) = state.tasks.get_mut(&child_parent_task.key().id)
            {
                parent_record.revision = next_child_parent_revision;
            }
            operation.commit(&mut state)?
        }
        .publish();

        let fork_kind = if vfork_parent_wait.is_some() {
            crate::observe::ForkKind::Vfork
        } else {
            crate::observe::ForkKind::Fork
        };
        kernel
            .auditors()
            .fork_admitted(child_parent_task.key(), child_key, fork_kind);

        // The child inherited its parent's RLIMIT_CPU; a finite one must be
        // watched from the moment the child is visible.
        kernel.cpu_limit_watch().ensure_watching(&kernel, &child);

        if let Some(budget) = child.container().budget() {
            let _ = budget.check_process_creation();
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
            visible_child_id,
            start_wait,
            start_release,
        })
    }
}

impl Kernel {
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

    /// Whether any registered thread outside `excluded` still holds `target`
    /// as its file table. The exclusion lets a process-terminal path retire
    /// its own table while its last thread is still registered — Linux
    /// `exit_files` runs before `exit_notify` — so that fd teardown never
    /// waits behind the exit publication or anything it serialises with.
    fn file_table_is_live_excluding(
        &self,
        target: &Arc<FileTable>,
        excluded: Option<TaskKey>,
    ) -> bool {
        let state = self.registry().state.read();
        state
            .tasks
            .values()
            .filter(|record| excluded.is_none_or(|excluded| record.task.key() != excluded))
            .any(|record| {
                record.task.thread_keys().into_iter().any(|thread_key| {
                    record
                        .task
                        .thread(thread_key.tid)
                        .is_some_and(|thread| Arc::ptr_eq(&thread.resources().files(), target))
                })
            })
    }

    /// Current FileTable generations of one exact live task. Exec/CLONE_FILES
    /// lifecycle glue uses this to authenticate a notification's owner-local
    /// alias after an old shared table changes concurrently with exec.
    pub(crate) fn task_file_tables_exact(&self, target: TaskKey) -> Vec<Arc<FileTable>> {
        let state = self.registry().state.read();
        let Some(task) = state
            .tasks
            .get(&target.id)
            .map(|record| &record.task)
            .filter(|task| task.key() == target && task.lifecycle() == TaskLifecycle::Live)
        else {
            return Vec::new();
        };
        let mut tables = Vec::new();
        for thread_key in task.thread_keys() {
            let Some(thread) = task.thread(thread_key.tid) else {
                continue;
            };
            let files = thread.resources().files();
            if !tables.iter().any(|observed| Arc::ptr_eq(observed, &files)) {
                tables.push(files);
            }
        }
        tables
    }

    pub(crate) fn retire_file_table_if_unreferenced(&self, target: &Arc<FileTable>) {
        self.retire_file_table_generation(target, None, None);
    }

    /// Retire `target` on behalf of `exiting`, whose last thread may still be
    /// registered: the process-terminal path closes the process's fds BEFORE
    /// it takes the retirement topology lock and publishes the exit, so the
    /// exiting task itself must not count as a live holder. Every other task
    /// sharing the table (`CLONE_FILES` without `CLONE_THREAD`) still keeps
    /// it alive. Idempotent: a second call finds the generation drained.
    pub(crate) fn retire_file_table_for_exiting_task(
        &self,
        target: &Arc<FileTable>,
        exiting: TaskKey,
    ) {
        self.retire_file_table_generation(target, None, Some(exiting));
    }

    pub(super) fn retire_file_table_after_exec(
        &self,
        target: &Arc<FileTable>,
        successor: &Arc<FileTable>,
    ) {
        self.retire_file_table_generation(target, Some(successor), None);
    }

    fn retire_file_table_generation(
        &self,
        target: &Arc<FileTable>,
        successor: Option<&Arc<FileTable>>,
        exiting: Option<TaskKey>,
    ) {
        if self.file_table_is_live_excluding(target, exiting) {
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
        self.sweep_retired_threads_for_process(Some(parent.task.key().id));
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
            if !caller_record.task.container().accepts_new_tasks() {
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
            enforce_rlimit_nproc(&state, parent)?;
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
        let pid_identity = match parent.task().pid_ns_region() {
            Some(region) => {
                let child = u32::try_from(child_id.raw())
                    .map_err(|_| KernelOperationError::PidNamespaceMembership(child_id))?;
                let parent_id = u32::try_from(parent.task().key().id.raw())
                    .map_err(|_| KernelOperationError::PidNamespaceMembership(child_id))?;
                Some(
                    region
                        .reserve_identity(child, parent_id)
                        .ok_or(KernelOperationError::PidNamespaceMembership(child_id))?,
                )
            }
            None => None,
        };
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
            pid_identity,
            diagnostic_name,
            vfork_relationship,
            failpoint,
            external_peer_root: false,
        })
    }

    pub(crate) fn reserve_external_peer_root(
        self: &Arc<Self>,
        source: &KernelContext,
        plan: ClonePlan,
        diagnostic_name: String,
    ) -> Result<ForkReservation, KernelOperationError> {
        if plan.fork_parent() != ForkParentMode::Caller
            || plan.vfork() != VforkMode::None
            || plan.pidfd() != ForkPidfdMode::None
        {
            return Err(KernelOperationError::InvalidExternalPeerRootPlan);
        }
        let mut reservation = self.reserve_fork(source, plan, diagnostic_name, None)?;
        reservation.external_peer_root = true;
        Ok(reservation)
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
        let exit_participants = context
            .task
            .thread_exit_participants(context.thread.key())
            .map_err(|TaskParticipantError::UnknownThread { .. }| {
                KernelOperationError::UnknownThread(context.thread.key().tid)
            })?;
        if !exit_participants.permits_nonfinal_exit() {
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
        if tid != LinuxTid::for_task_leader(context.task.key().id)
            && let Some(region) = context.task.pid_ns_region()
        {
            let internal = u32::try_from(tid.raw()).unwrap_or_else(|_| {
                carrick_fatal!(
                    "kernel::thread_retirement",
                    "tid exceeds u32 in exit_thread"
                );
            });
            if !region.unregister_reaped(internal) {
                carrick_fatal!(
                    "kernel::thread_retirement",
                    "failed to unregister reaped thread in exit_thread"
                );
            }
        }
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

    /// Perform the `close_range(CLOSE_RANGE_UNSHARE)` file-table split for
    /// exactly the calling thread. This is intentionally not the host-fork
    /// copy operation: it copies the current captured table, publishes the
    /// replacement only to this thread, and preserves the old generation for
    /// the dispatcher to retire with successor-aware close semantics.
    pub(crate) fn unshare_file_table_for_close_range(
        self: &Arc<Self>,
        context: &KernelContext,
    ) -> Result<CloseRangeUnshare, KernelOperationError> {
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
                &old_files,
            ));
            let resources = Arc::new(context.resources.with_files(Arc::clone(&files)));
            let revision = record.revision;
            let task = Arc::clone(&record.task);
            thread.replace_resources(Arc::clone(&resources));
            self.observe_thread_publication(&thread, &resources, revision);
            drop(state);
            self.retire_file_table_generation(&old_files, Some(&files), None);
            return Ok(CloseRangeUnshare {
                context: KernelContext::from_parts(
                    self.clone(),
                    task,
                    thread,
                    Arc::clone(&context.shared),
                    resources,
                    revision,
                ),
                old_files,
            });
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
            let init = state.container_inits.get(&task.container().id()).copied();
            init.filter(|init| *init != task_key).and_then(|init| {
                state.tasks.get(&init.id).and_then(|record| {
                    (record.task.key() == init && record.task.lifecycle() == TaskLifecycle::Live)
                        .then(|| record.task.key())
                })
            })
        };
        // The namespace's reparenting authority, independent of whether THIS
        // exit has anything to reparent. `adopter` below is additionally
        // filtered to "not self" and "has children", which makes it useless as
        // an answer to "could anything in this namespace still have adopted an
        // orphan?" — the question a zombie's reaper depends on.
        let namespace_init = state
            .container_inits
            .get(&task.container().id())
            .copied()
            .filter(|init| {
                *init == task_key
                    || state.tasks.get(&init.id).is_some_and(|record| {
                        record.task.key() == *init && record.task.lifecycle() == TaskLifecycle::Live
                    })
            });
        let mut children = task.children();
        children.sort_by_key(|child| child.serial);
        // The adopter is only a participant when there is something to
        // reparent. A childless exit changes no parent edge on it, so it is
        // neither reserved nor revision-bumped: otherwise every leaf exit in
        // the VM contends with the run root's own in-flight fork/exec
        // reservations, and a concurrent `reserve_fork` on root observes
        // `TaskBusy` for an exit that never touches it. The adopter above was
        // still validated so a stale explicit adopter fails closed.
        let adopter = adopter.filter(|_| !children.is_empty());

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

        let namespace_process_group = state
            .process_groups
            .get(&task.process_group())
            .filter(|group| group.container == task.container().id())
            .map(|group| group.namespace_id)
            .ok_or(KernelOperationError::ExitTopologyChanged(task_id))?;
        let namespace_session = state
            .sessions
            .get(&task.session())
            .filter(|session| session.container == task.container().id())
            .map(|session| session.namespace_id)
            .ok_or(KernelOperationError::ExitTopologyChanged(task_id))?;
        let registry_zombie = Zombie::from_task(
            &task,
            status,
            diagnostic_name,
            namespace_process_group,
            namespace_session,
        );
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
            namespace_init,
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
        // Read before the zombie is moved into the registry below: the auditor
        // is told who will consume it, and that judgement belongs to the same
        // reserved snapshot that chose the adopter.
        let zombie_reaper = prepared.zombie_reaper();
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
        // ptrace(2): a tracer's exit detaches every tracee it still owns, and
        // a detached stopped tracee resumes. Capture the tracer key before
        // `begin_exit` clears this task's own tracee-side record so the tracer
        // can drop its index entry and re-evaluate a wait on this task.
        let own_tracer = exiting_record.task.ptrace_tracer();
        if !exiting_record.task.begin_exit() {
            return Err(KernelOperationError::AlreadyExiting(prepared.task.id));
        }
        let mut released_tracees = Vec::new();
        for tracee_key in exiting_record.task.take_ptrace_tracees() {
            if let Some(tracee) = state
                .tasks
                .get(&tracee_key.id)
                .filter(|record| record.task.key() == tracee_key)
                .map(|record| Arc::clone(&record.task))
                && tracee.detach_from_ptrace(prepared.task)
            {
                released_tracees.push(tracee);
            }
        }
        let own_tracer = own_tracer.and_then(|key| {
            state
                .tasks
                .get(&key.id)
                .filter(|record| record.task.key() == key)
                .map(|record| Arc::clone(&record.task))
        });
        if let Some(tracer) = &own_tracer {
            tracer.remove_ptrace_tracee(prepared.task);
        }
        let mut exiting_threads = Vec::new();
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
                exiting_threads.push(thread);
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
        let leader_tid = LinuxTid::for_task_leader(task.key().id);
        let pid_region = task.pid_ns_region();
        let mut retired_secondary_namespace_tids = Vec::new();
        for (tid, claim) in thread_claims {
            if tid != leader_tid {
                retired_secondary_namespace_tids.push(u32::try_from(tid.raw()).unwrap_or_else(
                    |_| {
                        carrick_fatal!(
                            "kernel::task_exit_identity",
                            "secondary tid exceeds u32 in commit_task_exit_notifying"
                        );
                    },
                ));
            }
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
        let mut state = self.registry().state.write();
        let pending_publication = prepared.reservation.commit(&mut state)?;
        drop(state);
        pending_publication.publish();
        self.auditors().zombie_created(prepared.task, zombie_reaper);
        if self.registry().state.read().tasks.is_empty() {
            self.auditors().process_graph_empty(self.unpublished_jobs());
        }
        if let Some(region) = pid_region {
            for tid in retired_secondary_namespace_tids {
                if !region.unregister_reaped(tid) {
                    carrick_fatal!(
                        "kernel::task_exit_identity",
                        "failed to unregister reaped secondary thread"
                    );
                }
            }
        }
        // Cancellation can wake a host waiter, whose callback may re-enter the
        // registry. Never invoke it while holding the topology write lock.
        for thread in exiting_threads {
            let _ = thread.cancel_kernel_owned_continuation(
                crate::vcpu_loop::continuation::CancellationCause::ProcessExit,
            );
        }
        // Queue the parent's exit notification after the exit reservation is
        // committed. If notify_parent ran before commit, a parent that woke
        // immediately would see TaskBusy in wait_child_matching and park in
        // BlockedContinuation having already consumed this exit's wake edge,
        // wedging forever.
        notify_parent(prepared.result_zombie.parent);
        for tracee in released_tracees {
            tracee.wake();
        }
        if let Some(tracer) = own_tracer {
            tracer.wake();
        }
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
    /// after committing the exit reservation.
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
}

pub(super) fn next_revision(revision: TaskRevision) -> Result<TaskRevision, KernelOperationError> {
    revision
        .next()
        .ok_or(KernelOperationError::RevisionExhausted)
}

/// `RLIMIT_NPROC` at fork reservation — setrlimit(2): while the number of
/// extant threads for the caller's REAL user ID is greater than or equal to
/// the soft limit, `fork(2)` fails with `EAGAIN`.
///
/// Two exemptions, both measured against the native-arm64 Docker oracle on
/// 2026-08-26 rather than assumed from the man page (which documents only the
/// capability one):
///
/// - **real uid 0 is exempt outright.** A container running as root with
///   Docker's DEFAULT capability set — `CapEff: 00000000a80425fb`, which
///   contains neither `CAP_SYS_ADMIN` (21) nor `CAP_SYS_RESOURCE` (24) — and a
///   soft limit of 3 forked 12 live children with no `EAGAIN`. Exempting only
///   by capability would therefore refuse forks that Linux allows, in the
///   configuration every default carrick guest runs in.
/// - effective `CAP_SYS_ADMIN` or `CAP_SYS_RESOURCE` exempts any uid, per
///   setrlimit(2).
///
/// The same oracle pins the counting rule for the enforced case: as uid 1000
/// with a soft limit of 3, exactly 2 live children were created before the
/// third `fork(2)` returned `EAGAIN` — so the count INCLUDES the caller, and
/// the comparison is `count >= limit`.
///
/// Reservation, not `PreparedFork::commit`, is the enforcement point: by the
/// time `commit` runs, the frame inventory and the parent's backend
/// transaction have already committed and `vcpu_loop/quiesce.rs` aborts the
/// carrier on a commit error. Every reservation error still lowers to guest
/// `EAGAIN` there, and this runs under the same registry write lock `commit`
/// validates under.
///
/// Counting rule (Linux counts threads, not thread-group leaders): every live
/// thread claim of every live task in the registry whose thread's own real
/// uid equals the caller's — credentials are per thread. Zombies, retired
/// threads and in-flight reservations are NOT counted, so two forks racing
/// exactly at the limit can both win by one; `clone_thread` is not gated.
/// Both are deliberate approximations.
fn enforce_rlimit_nproc(
    state: &RegistryState,
    caller: &KernelContext,
) -> Result<(), KernelOperationError> {
    let ruid = caller.resources.credentials().ruid();
    if let Some(budget) = caller.task().container().budget() {
        if let Some(max_proc) = budget.max_processes_limit() {
            let current = budget.raw_counters().processes();
            if current >= max_proc {
                return Err(KernelOperationError::ProcessLimitExceeded {
                    uid: ruid,
                    count: current as usize,
                    limit: max_proc,
                });
            }
        }
    }
    if ruid == NsUid::ROOT {
        return Ok(());
    }
    let limit = caller
        .task()
        .rlimit(carrick_abi::LinuxResource::Nproc)
        .rlim_cur;
    if limit == carrick_abi::LINUX_RLIM_INFINITY {
        return Ok(());
    }
    let caps = caller.task().caps();
    if caps.has_effective(crate::namespace::process::CAP_SYS_ADMIN)
        || caps.has_effective(crate::namespace::process::CAP_SYS_RESOURCE)
    {
        return Ok(());
    }
    // Fast path for the default (8192): fewer live threads in the whole
    // kernel graph than the limit means no uid can be at it — the ordinary
    // fork reads no per-thread credentials.
    let total_threads: usize = state
        .tasks
        .values()
        .map(|record| record.thread_claims.len())
        .sum();
    if u64::try_from(total_threads).is_ok_and(|total| total < limit) {
        return Ok(());
    }
    let count = state
        .tasks
        .values()
        .flat_map(|record| {
            record
                .thread_claims
                .keys()
                .filter_map(|tid| record.task.thread(*tid))
        })
        .filter(|thread| thread.resources().credentials().ruid() == ruid)
        .count();
    if u64::try_from(count).is_ok_and(|count| count < limit) {
        return Ok(());
    }
    Err(KernelOperationError::ProcessLimitExceeded {
        uid: ruid,
        count,
        limit,
    })
}

pub(super) fn ensure_task_unreserved(
    state: &RegistryState,
    task_id: TaskId,
) -> Result<(), KernelOperationError> {
    if state.reservations.contains_key(&task_id) {
        return Err(KernelOperationError::TaskBusy(task_id));
    }
    Ok(())
}

pub(super) fn check_failpoint(
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
    #[error("external peer-root admission requires a plain copied task without vfork or pidfd")]
    InvalidExternalPeerRootPlan,
    #[error("task {0:?} has no parent to inherit for CLONE_PARENT")]
    CloneParentUnavailable(TaskId),
    #[error("selected fork parent exited before commit")]
    ForkParentExited,
    #[error("selected fork parent changed before commit")]
    ForkParentChanged,
    #[error("RLIMIT_NPROC reached for real uid {uid:?}: {count} live threads, soft limit {limit}")]
    ProcessLimitExceeded {
        uid: NsUid,
        count: usize,
        limit: u64,
    },
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
    #[error("kernel task {0:?} could not join its container PID namespace")]
    PidNamespaceMembership(TaskId),
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
    #[error("a live process group or session is already named by the caller's pid")]
    IdentityInUseByCallerPid,
    #[error("child task {0:?} has completed exec")]
    ChildExeced(TaskId),
    #[error("process-group identity change is not permitted")]
    IdentityPermission,
    #[error("a process-group leader cannot create a session")]
    AlreadyProcessGroupLeader,
    #[error("standard signal {0:?} entered real-time queue")]
    StandardSignalInRealtimeQueue(LinuxSignal),
    #[error("real-time signal {0:?} entered standard queue")]
    RealtimeSignalInStandardQueue(LinuxSignal),
    #[error("injected kernel operation failure at {0:?}")]
    Injected(KernelFailpoint),
}

#[cfg(test)]
pub(super) mod tests {
    use std::num::NonZeroU16;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use carrick_abi::{LinuxCloneFlags, LinuxSigaction, SigSet};
    use carrick_guest_mem::Gpa;
    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
    use proptest::prelude::*;

    use super::*;
    use crate::kernel::{
        Asid, FileDescription, FileSlotNumber, LinuxSignal, MmBackendSnapshot, MmBinding,
        MmRelation, RootBootstrap, SignalDisposition, SnapshotError, Stage1Root,
        TaskParticipantError, ThreadSignalState,
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

    #[derive(Debug)]
    struct RelationOnlyForeignTransport;

    #[derive(Debug)]
    struct RelationOnlyForeignLease;

    impl carrick_hal::ForeignMmTransport for RelationOnlyForeignTransport {
        fn retain(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _snapshot: &dyn carrick_hal::ForeignMmSnapshot,
            _deadline: std::time::Instant,
        ) -> Result<Arc<dyn carrick_hal::ForeignMmReadLease>, carrick_hal::ForeignMmTransportError>
        {
            Ok(Arc::new(RelationOnlyForeignLease))
        }
    }

    impl carrick_hal::ForeignMmReadLease for RelationOnlyForeignLease {
        fn read(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _authority: &dyn carrick_hal::ForeignMmLiveAuthority,
            _snapshot: &dyn carrick_hal::ForeignMmSnapshot,
            _va: carrick_guest_mem::GuestVa,
            _dst: &mut [u8],
            _deadline: std::time::Instant,
        ) -> Result<Box<dyn carrick_hal::ForeignMmReadReceipt>, carrick_hal::ForeignMmTransportError>
        {
            Err(carrick_hal::ForeignMmTransportError::AuthorityUnavailable)
        }
    }

    impl MmBackend for TestMmBackend {
        fn snapshot(
            &self,
            _deadline: std::time::Instant,
        ) -> Result<MmBackendSnapshot, SnapshotError> {
            Ok(MmBackendSnapshot {
                revision: 1,
                binding: self.0,
                vmas: Vec::new(),
                vma_revision: Some(crate::kernel::VmaRevision::from_authority_raw(1)),
                mapping_ids: Vec::new(),
                frame_inventory_revision: Some(1),
            })
        }

        fn revision(&self) -> u64 {
            1
        }

        fn vma_revision(
            &self,
            _deadline: std::time::Instant,
        ) -> Result<Option<crate::kernel::VmaRevision>, SnapshotError> {
            Ok(Some(crate::kernel::VmaRevision::from_authority_raw(1)))
        }
    }

    fn test_binding() -> MmBinding {
        let asid = Asid::from_registry_allocation(NonZeroU16::new(7).expect("nonzero ASID"));
        let root = Stage1Root::for_aarch64_4k(Gpa(0x8000)).expect("aligned root");
        MmBinding::for_aarch64(asid, root)
    }

    pub(super) fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "root".to_string(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    /// Fork `parent` and return the child's id, with its start handshake
    /// completed so the child is a fully published, live task.
    pub(super) fn fork_child(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        name: &str,
        tid: i32,
    ) -> TaskId {
        fork_child_with_plan(
            kernel,
            parent,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
            name,
            tid,
        )
    }

    pub(super) fn fork_child_with_plan(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        plan: ClonePlan,
        name: &str,
        tid: i32,
    ) -> TaskId {
        let reservation = kernel
            .reserve_fork(parent, plan, name.to_owned(), None)
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

    fn bootstrap_with_mm_backend(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::with_mm_backend(
            pid,
            ThreadId::synthetic_for_tests(pid),
            Arc::new(TestMmBackend(test_binding())),
            "root".to_string(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    fn mm_authority_execution_lease(
        context: &KernelContext,
    ) -> crate::kernel::objects::ThreadExecutionLease {
        let mm = context.shared().mm().id();
        context
            .thread()
            .publish_initial_task_state(crate::kernel::objects::MigratableTaskState {
                cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
                    gprs: [400; 31],
                    pc: 400,
                    pstate: 400,
                    trap_pc: 400,
                    trap_pstate: 400,
                    sp_el0: 400,
                    elr_el1: 400,
                    spsr_el1: 400,
                    ttbr0: 400,
                    ttbr1: 400,
                    tcr: 400,
                    sctlr_el1: 400,
                    mair_el1: 400,
                    vbar_el1: 400,
                    cpacr_el1: 400,
                    cntkctl_el1: 400,
                    tpidr_el1: 400,
                    actlr_el1: 400,
                    tpidr_el0: 400,
                    tpidrro_el0: 400,
                    contextidr_el1: 400,
                    vregs: [400; 32],
                    fpsr: 400,
                    fpcr: 400,
                    pending_resume_pc: None,
                    last_syscall_nr: None,
                    last_syscall_orig_x0: 400,
                    last_fault_esr: 400,
                    last_exit_class: 400,
                    is_forked_child: false,
                    syscall_continuation: None,
                    mm_generation: mm.raw(),
                    asid_generation: mm.raw(),
                }),
                mm,
                asid_generation: mm.raw(),
            })
            .expect("publish exact root scheduler authority");
        context
            .thread()
            .claim_runnable(crate::kernel::objects::ExecutorId::synthetic_for_tests(400))
            .expect("claim exact root execution authority")
    }

    fn fork_with_mm_backend(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        registry_id: i32,
        diagnostic_name: &str,
    ) -> KernelContext {
        kernel
            .reserve_fork(
                parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                diagnostic_name.to_owned(),
                None,
            )
            .expect("reserve fork")
            .prepare_with_mm_backend(
                Arc::new(TestMmBackend(test_binding())),
                ThreadId::synthetic_for_tests(registry_id),
            )
            .expect("prepare fork mm")
            .commit()
            .expect("publish fork")
            .into_parts()
            .expect("start child")
            .0
    }

    #[test]
    fn mm_authority_relation_distinguishes_copied_and_shared_clone_vm_tasks() {
        let (kernel, root) = bootstrap_with_mm_backend(19_400);
        let execution = mm_authority_execution_lease(&root);

        let current = root.current_mm(&execution).expect("current MM authority");
        assert_eq!(current.mm_id(), root.shared().mm().id());

        let copied = fork_with_mm_backend(&kernel, &root, 19_401, "copied-mm child");
        copied.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(RelationOnlyForeignTransport)),
        );
        let foreign = kernel
            .foreign_mm(&root, &execution, copied.task().key())
            .expect("foreign MM authority");
        assert!(matches!(foreign, MmRelation::Foreign(_)));

        let shared = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::VM).expect("shared-mm fork plan"),
                "shared-mm child".to_owned(),
                None,
            )
            .expect("reserve shared-mm fork")
            .prepare_shared_mm(ThreadId::synthetic_for_tests(19_402))
            .expect("prepare shared-mm fork")
            .commit()
            .expect("publish shared-mm fork")
            .into_parts()
            .expect("start shared-mm child")
            .0;
        assert_ne!(shared.task().key(), root.task().key());
        let relation = kernel
            .foreign_mm(&root, &execution, shared.task().key())
            .expect("shared MM authority");
        assert!(matches!(relation, MmRelation::Current(_)));
    }

    fn clone_sibling(
        kernel: &Arc<Kernel>,
        leader: &KernelContext,
        registry_id: i32,
    ) -> KernelContext {
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        kernel
            .clone_thread(
                leader,
                plan,
                ThreadId::synthetic_for_tests(registry_id),
                None,
            )
            .expect("clone sibling")
    }

    #[test]
    fn task_mints_distinct_fork_and_crash_sibling_witnesses() {
        let (kernel, leader) = bootstrap(19_410);
        let sibling = clone_sibling(&kernel, &leader, 19_411);
        let second_sibling = clone_sibling(&kernel, &leader, 19_412);

        let fork = leader
            .task()
            .fork_barrier_participants(leader.thread().key())
            .expect("exact fork owner");
        let crash = leader
            .task()
            .crash_barrier_participants(leader.thread().key())
            .expect("exact crash owner");

        assert!(fork.requires_quiesce());
        assert!(fork.contains_sibling(sibling.thread().key()));
        assert!(fork.contains_sibling(second_sibling.thread().key()));
        assert_eq!(fork.initial_sibling_count_for_probe(), 2);
        assert!(crash.requires_quiesce());
        assert!(crash.contains_sibling(sibling.thread().key()));
        assert!(crash.contains_sibling(second_sibling.thread().key()));
        assert_eq!(
            leader
                .task()
                .core_note_participants()
                .required_note_count_for_probe(),
            3
        );
    }

    #[test]
    fn task_participant_witness_rejects_a_stale_exact_owner() {
        let (kernel, leader) = bootstrap(19_420);
        let sibling = clone_sibling(&kernel, &leader, 19_421);
        kernel.exit_thread(&sibling, None).expect("retire sibling");

        assert!(matches!(
            leader
                .task()
                .fork_barrier_participants(sibling.thread().key()),
            Err(TaskParticipantError::UnknownThread { .. })
        ));
    }

    #[test]
    fn thread_exit_participants_require_an_exact_survivor() {
        let (kernel, leader) = bootstrap(19_430);
        let sibling = clone_sibling(&kernel, &leader, 19_431);
        let witness = leader
            .task()
            .thread_exit_participants(leader.thread().key())
            .expect("exact exit owner");

        assert!(witness.permits_nonfinal_exit());
        assert!(witness.contains_survivor(sibling.thread().key()));

        let (_sole_kernel, sole) = bootstrap(19_432);
        let sole_witness = sole
            .task()
            .thread_exit_participants(sole.thread().key())
            .expect("exact sole owner");
        assert!(!sole_witness.permits_nonfinal_exit());
    }

    /// `RLIMIT_NPROC` is counted per REAL uid over live threads and refused at
    /// fork RESERVATION — the last point whose error still lowers to guest
    /// `EAGAIN` (`vcpu_loop/quiesce.rs` aborts the carrier on a `commit`
    /// failure). It needs TWO live tasks to mean anything: a single task can
    /// never be at a limit of two.
    #[test]
    fn fork_reservation_enforces_rlimit_nproc_per_real_uid() {
        use carrick_abi::{LinuxResource, LinuxRlimit};
        use std::convert::Infallible;

        let (kernel, root) = bootstrap(9_300);
        let user = kernel
            .update_credentials(&root, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(1000))
            })
            .expect("seed unprivileged credentials");
        let fork_plan = || ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let set_nproc = |soft: u64| {
            user.task()
                .replace_rlimit(LinuxResource::Nproc, |_| {
                    Ok::<_, Infallible>(LinuxRlimit::new(soft, 8_192))
                })
                .expect("set RLIMIT_NPROC");
        };

        // One live thread for uid 1000 and a soft limit of one: refused.
        set_nproc(1);
        assert!(matches!(
            kernel.reserve_fork(&user, fork_plan(), "refused-at-one".to_owned(), None),
            Err(KernelOperationError::ProcessLimitExceeded { uid, count: 1, limit: 1 })
                if uid == carrick_abi::NsUid::new(1000)
        ));

        // Limit two: the first fork publishes; the second is refused because
        // the child's leader thread carries the same real uid.
        set_nproc(2);
        let reservation = kernel
            .reserve_fork(&user, fork_plan(), "first child".to_owned(), None)
            .expect("reserve first child");
        let child_id = reservation.child_id();
        let published = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(9_301))
            .expect("prepare first child")
            .commit()
            .expect("publish first child");
        drop(published);
        assert!(kernel.task_is_live(child_id));
        assert!(matches!(
            kernel.reserve_fork(&user, fork_plan(), "refused-at-two".to_owned(), None),
            Err(KernelOperationError::ProcessLimitExceeded {
                count: 2,
                limit: 2,
                ..
            })
        ));

        // CAP_SYS_RESOURCE exempts the caller even at the limit.
        user.task().with_caps(|caps| {
            caps.effective |= 1u64 << crate::namespace::process::CAP_SYS_RESOURCE;
        });
        let exempt = kernel
            .reserve_fork(&user, fork_plan(), "cap-exempt".to_owned(), None)
            .expect("CAP_SYS_RESOURCE exempts RLIMIT_NPROC")
            .prepare_reference(ThreadId::synthetic_for_tests(9_302))
            .expect("prepare exempt child")
            .commit()
            .expect("publish exempt child");
        drop(exempt);

        // Real uid 0 is exempt: a limit of one with one live thread still forks.
        let (kernel, root) = bootstrap(9_400);
        root.task()
            .replace_rlimit(LinuxResource::Nproc, |_| {
                Ok::<_, Infallible>(LinuxRlimit::new(1, 1))
            })
            .expect("set RLIMIT_NPROC on root");
        let root_child = kernel
            .reserve_fork(&root, fork_plan(), "root-exempt".to_owned(), None)
            .expect("real uid 0 is exempt from RLIMIT_NPROC")
            .prepare_reference(ThreadId::synthetic_for_tests(9_401))
            .expect("prepare root child")
            .commit()
            .expect("publish root child");
        drop(root_child);

        // Real uid 0 stays exempt even with BOTH exempting capabilities
        // dropped. Measured against the native-arm64 Docker oracle on
        // 2026-08-26: container root with `CapEff: 00000000a80425fb` (neither
        // CAP_SYS_ADMIN nor CAP_SYS_RESOURCE) and a soft limit of 3 forked 12
        // LIVE children with no EAGAIN, while uid 1000 under the identical
        // capability set and limit got EAGAIN on its third fork. That is the
        // configuration every default carrick guest runs in, so exempting
        // only by capability would refuse forks Linux allows.
        root.task().with_caps(|caps| {
            caps.effective &= !(1u64 << crate::namespace::process::CAP_SYS_RESOURCE);
            caps.effective &= !(1u64 << crate::namespace::process::CAP_SYS_ADMIN);
        });
        let root_uncapped = kernel
            .reserve_fork(&root, fork_plan(), "root-uncapped-exempt".to_owned(), None)
            .expect("real uid 0 is exempt regardless of capabilities (Docker oracle)")
            .prepare_reference(ThreadId::synthetic_for_tests(9_402))
            .expect("prepare uncapped root child")
            .commit()
            .expect("publish uncapped root child");
        drop(root_uncapped);
    }

    /// `nice` is inherited at fork and independent thereafter — and, crucially,
    /// belongs to ONE Linux process rather than to the runtime.
    ///
    /// It used to live in a `static NICE_VALUE: AtomicI32` in
    /// `dispatch/creds.rs`, justified by a comment claiming "a process-global
    /// static is correct … carrick's fork creates a fresh address space". That
    /// was true under the retired one-host-process-per-guest-process model and
    /// is false under HVPatch, where many logical Linux processes share one
    /// carrier: a dead child's nice leaked into every later process.
    ///
    /// This case needs THREE live tasks to see it. Every single-process
    /// assertion (set 5, read back 5) passes identically against a shared cell,
    /// which is exactly the blind spot `docs/identity-and-scope-domains.md`
    /// describes — so a test that never creates a second task proves nothing
    /// about scope.
    #[test]
    fn nice_is_per_process_inherited_at_fork_and_independent_thereafter() {
        let (kernel, root) = bootstrap(151);
        root.task().set_nice(7);

        let fork = |tid: i32, name: &str| {
            kernel
                .fork_task(
                    &root,
                    ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                    ThreadId::synthetic_for_tests(tid),
                    name.to_string(),
                    None,
                )
                .expect("fork child")
        };

        // Child A inherits 7, then raises itself to 19 and exits.
        let child_a = fork(9_151, "child-a");
        assert_eq!(child_a.task.nice(), 7, "child A inherits the parent's nice");
        child_a.task.set_nice(19);
        kernel
            .exit_task(
                child_a.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("child A exit");

        // A's write must not have reached its parent...
        assert_eq!(root.task().nice(), 7, "child A's nice must not touch root");

        // ...nor an unrelated later process. A runtime-global cell reports 19.
        let child_b = fork(9_152, "child-b");
        assert_eq!(
            child_b.task.nice(),
            7,
            "child B inherits root's nice, not the dead child A's"
        );

        // And B is independent of A's already-recorded value in both directions.
        child_b.task.set_nice(-3);
        assert_eq!(child_b.task.nice(), -3);
        assert_eq!(root.task().nice(), 7, "child B's nice must not touch root");
    }

    /// I/O priority is the exact same shape as [`nice`], and had the exact same
    /// defect: a `static IOPRIO_VALUE` in `dispatch/proc.rs` shared by every
    /// logical Linux process in the carrier.
    #[test]
    fn ioprio_is_per_process_inherited_at_fork_and_independent_thereafter() {
        let (kernel, root) = bootstrap(152);
        assert_eq!(
            root.task().ioprio(),
            Task::DEFAULT_IOPRIO,
            "a process that never called ioprio_set reports IOPRIO_CLASS_BE level 4"
        );
        // IOPRIO_CLASS_RT(1) level 2.
        let rt2 = (1 << 13) | 2;
        root.task().set_ioprio(rt2);

        let fork = |tid: i32, name: &str| {
            kernel
                .fork_task(
                    &root,
                    ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                    ThreadId::synthetic_for_tests(tid),
                    name.to_string(),
                    None,
                )
                .expect("fork child")
        };

        let child_a = fork(9_251, "child-a");
        assert_eq!(child_a.task.ioprio(), rt2, "inherited at fork");
        // IOPRIO_CLASS_IDLE(3).
        child_a.task.set_ioprio(3 << 13);
        kernel
            .exit_task(
                child_a.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("child A exit");
        assert_eq!(root.task().ioprio(), rt2, "child A must not touch root");

        let child_b = fork(9_252, "child-b");
        assert_eq!(
            child_b.task.ioprio(),
            rt2,
            "child B inherits root's ioprio, not the dead child A's"
        );
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
                .wait_child_key(
                    root.task().key().id,
                    child_a_key,
                    WaitChildClass::Sigchld,
                    WaitMode::Observe,
                )
                .expect("exact old-generation wait"),
            WaitOutcome::NoChild
        );

        kernel
            .exit_task_key_eventually(child_b.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit child B");
        assert_eq!(pidfd_watch.0.load(Ordering::Acquire), 1);
    }

    #[test]
    fn external_peer_root_has_no_init_wait_edge_and_retains_only_stdio_files() {
        let (kernel, root) = bootstrap(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
        let sentinel = FileSlotNumber::for_open_fd(91).expect("sentinel fd");
        let description = Arc::new(FileDescription::regular(
            kernel
                .object_ids()
                .file_description_id()
                .expect("sentinel description"),
        ));
        assert!(
            root.resources()
                .files()
                .install(sentinel, description, false)
                .is_none()
        );
        root.resources().files().lock_closed_stdio()[1] = true;
        let rebound_stdout = FileSlotNumber::for_open_fd(1).expect("stdout fd");
        let rebound_description = Arc::new(FileDescription::regular(
            kernel
                .object_ids()
                .file_description_id()
                .expect("stdout description"),
        ));
        assert!(
            root.resources()
                .files()
                .install(rebound_stdout, rebound_description, false)
                .is_none()
        );
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("plain peer plan");
        let reservation = kernel
            .reserve_external_peer_root(&root, plan, "external-peer".to_owned())
            .expect("reserve peer root");
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(9_191))
            .expect("prepare peer root");
        prepared.retain_stdio_only().expect("select exec files");
        let child = prepared
            .commit()
            .expect("publish peer root")
            .start_child()
            .expect("start peer root")
            .into_parts()
            .0;

        assert_eq!(child.task().parent(), None);
        assert!(!child.resources().files().lock_closed_stdio()[1]);
        assert!(
            child
                .resources()
                .files()
                .capture_slot_authority(rebound_stdout)
                .is_none(),
            "external exec stdout must be a fresh capture endpoint",
        );
        assert!(
            child
                .resources()
                .files()
                .capture_slot_authority(sentinel)
                .is_none(),
            "external exec must not inherit an init-open sentinel fd",
        );
        kernel
            .exit_task(
                child.task().key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("exit peer root");
        assert_eq!(
            kernel
                .wait_child(
                    root.task().key().id,
                    Some(child.task().key().id),
                    WaitMode::Observe
                )
                .expect("init wait query"),
            WaitOutcome::NoChild,
        );
        assert!(
            !root
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGCHLD),
        );
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

    /// `pidnsorphanreap` in miniature, in the kernel graph alone.
    ///
    /// init(root) -> probe -> child -> grandchild. The child exits first, so
    /// the grandchild reparents to init; init then exits while the grandchild
    /// is still live, which orphans it (the contract
    /// `root_exit_before_descendant_exit_allows_orphan_teardown` pins). The
    /// grandchild's own exit therefore publishes a PARENTLESS zombie — and that
    /// is not a dropped edge: `retire_container` reaps the namespace's remains.
    /// The `NoOrphanZombie` invariant read this as a kernel defect because it
    /// tested `TaskKey::id != 1`, a carrier-global allocation, as a stand-in for
    /// "is this the namespace init".
    #[test]
    fn a_zombie_left_behind_by_its_namespace_init_names_container_retirement() {
        let (kernel, root) = bootstrap(501);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let probe = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(9_501),
                "probe".to_string(),
                None,
            )
            .expect("probe");
        let child = kernel
            .fork_task(
                &probe,
                fork_plan,
                ThreadId::synthetic_for_tests(9_502),
                "child".to_string(),
                None,
            )
            .expect("child");
        let grandchild = kernel
            .fork_task(
                &child,
                fork_plan,
                ThreadId::synthetic_for_tests(9_503),
                "grandchild".to_string(),
                None,
            )
            .expect("grandchild");

        // The child exits first: the grandchild reparents to the namespace
        // init, which is exactly what Linux does and what the probe expects.
        let child_zombie = kernel
            .exit_task_key_eventually(child.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("child exit");
        assert_eq!(child_zombie.parent, Some(probe.task().key()));
        assert_eq!(grandchild.task().parent(), Some(root.task().key()));

        // A live namespace init adopting an orphan is the reapable case.
        let prepared_probe = kernel
            .prepare_task_exit_key(
                probe.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare probe exit");
        assert_eq!(
            prepared_probe.zombie_reaper(),
            crate::observe::ZombieReaper::Parent(root.task().key())
        );
        prepared_probe.commit().expect("commit probe exit");

        // The namespace init itself has no parent, and nothing inside the
        // namespace could ever have adopted it.
        let prepared_init = kernel
            .prepare_task_exit_key(
                root.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare init exit");
        assert_eq!(
            prepared_init.zombie_reaper(),
            crate::observe::ZombieReaper::ContainerRetirement
        );
        prepared_init.commit().expect("commit init exit");

        // The grandchild outlived the init, so it is parentless too — and is
        // reaped by container retirement, not stranded.
        assert_eq!(grandchild.task().parent(), None);
        let prepared_grandchild = kernel
            .prepare_task_exit_key(
                grandchild.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare grandchild exit");
        assert_eq!(
            prepared_grandchild.zombie_reaper(),
            crate::observe::ZombieReaper::ContainerRetirement
        );
        let grandchild_zombie = prepared_grandchild
            .commit()
            .expect("commit grandchild exit");
        assert_eq!(grandchild_zombie.parent, None);
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
    fn exit_notification_runs_after_reservation_release() {
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
        assert_eq!(
            kernel.reservation_epoch(),
            hook_epoch.load(Ordering::Acquire),
            "parent notification hook must run after the exit reservation is committed",
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
        let description = Arc::new(
            FileDescription::concrete_with_status_flags(backing, carrick_abi::LINUX_O_RDWR)
                .expect("ring description identity"),
        );
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
            assert_eq!(root.task.thread_count_for_test(), 1);
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

    /// A childless task's exit reparents nothing, so it must not reserve the
    /// run root as adopter. Before this held, EVERY child exit in the VM
    /// serialized against root's own operations: a Go `os/exec` helper
    /// exiting while the root forked its next helper made `reserve_fork`
    /// observe `TaskBusy(root)`, which the guest saw as `fork(2) = EAGAIN`
    /// (`forkabort-E4`, 2026-09-02). A task WITH children still reserves the
    /// adopter, because their parent edges really do change.
    #[test]
    fn childless_exit_does_not_reserve_the_root_adopter() {
        let (kernel, root) = bootstrap(339);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let leaf = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(3391),
                "leaf".to_string(),
                None,
            )
            .expect("leaf child");
        let middle = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(3392),
                "middle".to_string(),
                None,
            )
            .expect("middle child");
        let _grandchild = kernel
            .fork_task(
                &middle,
                plan,
                ThreadId::synthetic_for_tests(3393),
                "grandchild".to_string(),
                None,
            )
            .expect("grandchild");

        // Root is mid-fork: its task is reserved by the in-flight operation.
        let in_flight = kernel
            .reserve_fork(&root, plan, "in-flight root fork".to_string(), None)
            .expect("root fork reservation");

        let leaf_exit = kernel
            .prepare_task_exit_key(
                leaf.task.key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("a childless exit needs no adopter and must not wait on root");
        drop(leaf_exit);

        assert!(
            matches!(
                kernel.prepare_task_exit_key(
                    middle.task.key(),
                    LinuxWaitStatus::from_wait_encoding(0),
                    None,
                ),
                Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
            ),
            "an exit that reparents children still reserves the adopter"
        );
        drop(in_flight);
    }

    /// `capabilities(7)` / `user_namespaces(7)`: the capability sets and the
    /// user-namespace view are per-process. A `fork` child gets a COPY of the
    /// parent's, and each side's later change is invisible to the other.
    ///
    /// This is the fast, Docker-free guard for the property the
    /// `capbsetisolation`/`usernsisolation` conformance probes prove
    /// end-to-end. It is a real regression test: before the state moved onto
    /// `Task` it lived in one process-global `Mutex` shared by every guest
    /// process in the carrier, so the child's `capbset_drop` below would have
    /// been observed by the parent and every sibling.
    #[test]
    fn fork_child_gets_its_own_capability_sets_and_user_namespace() {
        let (kernel, root) = bootstrap(338);
        const CAP_NET_RAW: u32 = 13;

        // The parent starts from the default container set and the initial,
        // identity-mapped user namespace.
        assert!(root.task().caps().capbset_read(CAP_NET_RAW));
        assert_eq!(
            root.task().user_ns().id,
            crate::namespace::INITIAL_USER_NS,
            "a fresh task starts in the initial user namespace"
        );

        let published = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "creds-ns child".to_owned(),
                None,
            )
            .expect("reserve fork")
            .prepare_reference(ThreadId::synthetic_for_tests(339))
            .expect("prepare fork")
            .commit()
            .expect("commit fork");
        let child = published.context().expect("child context").task();

        // Inheritance at fork is a COPY, not a share.
        assert_eq!(
            child.caps(),
            root.task().caps(),
            "fork child inherits the parent's capability sets verbatim"
        );
        assert_eq!(child.user_ns().id, root.task().user_ns().id);

        // The child drops a bounding capability.
        child.with_caps(|caps| caps.capbset_drop(CAP_NET_RAW));
        assert!(
            !child.caps().capbset_read(CAP_NET_RAW),
            "the child's own drop takes effect for the child"
        );
        assert!(
            root.task().caps().capbset_read(CAP_NET_RAW),
            "a child's PR_CAPBSET_DROP must not reach the parent"
        );

        // ...and then unshares a user namespace. Ordering matters: per
        // `user_namespaces(7)` the CREATOR of a new user namespace holds a full
        // capability set within it, so the unshare deliberately re-grants what
        // the drop above removed. Asserting the drop first keeps the two
        // effects from masking each other.
        let child_ns = child.unshare_user_ns();
        assert!(
            child.caps().capbset_read(CAP_NET_RAW),
            "creating a user namespace grants a full set within it"
        );
        assert_ne!(
            child_ns,
            root.task().user_ns().id,
            "unshare(CLONE_NEWUSER) moves only the caller"
        );
        assert_eq!(
            root.task().user_ns().id,
            crate::namespace::INITIAL_USER_NS,
            "the parent stays in the namespace it never left"
        );

        // Namespace ids are carrier-unique, so a second unsharer cannot alias
        // the first's namespace.
        assert_ne!(
            root.task().unshare_user_ns(),
            child_ns,
            "independent unshares must allocate distinct namespace ids"
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
}
