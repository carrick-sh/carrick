use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use carrick_hal::ThreadId;
use parking_lot::{Condvar, Mutex, RwLock};

use super::address::MmBackend;
use super::ids::{LinuxTid, ObjectIdError, ObjectIdRegistry, ProcessGroupId, SessionId, TaskId};
use super::objects::{
    Credentials, FileTable, FsContext, Mm, ObjectGraphError, ProcessGroup, Session, Sighand, Task,
    TaskKey, TaskRef, TaskShared, Thread, ThreadKey, ThreadRef, ThreadResources, Zombie,
};
use super::registry::{IdError, IdRegistry, TaskClaim, ThreadClaim};

/// Complete syscall identity snapshot. Each context keeps the exact shared
/// associations observed at entry, so exec/resource publication cannot tear a
/// syscall across old and new bundles.
#[derive(Debug)]
pub struct KernelContext {
    pub(super) kernel: Arc<Kernel>,
    pub(super) task: TaskRef,
    pub(super) thread: ThreadRef,
    pub(super) shared: Arc<TaskShared>,
    pub(super) resources: Arc<ThreadResources>,
    pub(super) revision: TaskRevision,
}

impl KernelContext {
    pub fn kernel(&self) -> &Arc<Kernel> {
        &self.kernel
    }

    pub fn task(&self) -> &TaskRef {
        &self.task
    }

    pub fn thread(&self) -> &ThreadRef {
        &self.thread
    }

    pub fn shared(&self) -> &Arc<TaskShared> {
        &self.shared
    }

    pub fn resources(&self) -> &Arc<ThreadResources> {
        &self.resources
    }

    pub const fn revision(&self) -> TaskRevision {
        self.revision
    }

    /// Stable task-generation handle used by runtime lanes to capture one fresh
    /// syscall context for an explicit Linux TID at every dispatch boundary.
    pub fn task_binding(&self) -> KernelTaskBinding {
        KernelTaskBinding {
            kernel: Arc::clone(&self.kernel),
            task: self.task.key(),
        }
    }

    fn capture(
        kernel: Arc<Kernel>,
        task: TaskRef,
        thread: ThreadRef,
        revision: TaskRevision,
    ) -> Self {
        let shared = task.shared();
        let resources = thread.resources();
        Self::from_parts(kernel, task, thread, shared, resources, revision)
    }

    pub(super) fn from_parts(
        kernel: Arc<Kernel>,
        task: TaskRef,
        thread: ThreadRef,
        shared: Arc<TaskShared>,
        resources: Arc<ThreadResources>,
        revision: TaskRevision,
    ) -> Self {
        Self {
            kernel,
            task,
            thread,
            shared,
            resources,
            revision,
        }
    }
}

/// Generation-safe binding from one runtime lane to one Linux task.
///
/// The binding deliberately stores a `TaskKey`, not only its reusable numeric
/// TGID. Capturing also requires an explicit `LinuxTid`; callers must never
/// reinterpret the backend-local `carrick_hal::ThreadId` as Linux identity.
#[derive(Clone, Debug)]
pub struct KernelTaskBinding {
    kernel: Arc<Kernel>,
    task: TaskKey,
}

impl KernelTaskBinding {
    pub const fn task_id(&self) -> TaskId {
        self.task.id
    }

    pub fn kernel(&self) -> &Arc<Kernel> {
        &self.kernel
    }

    pub fn capture(&self, tid: LinuxTid) -> Result<KernelContext, KernelError> {
        let context = self.kernel.context(self.task.id, tid)?;
        if context.task.key() != self.task {
            return Err(KernelError::StaleTaskBinding(self.task.id));
        }
        Ok(context)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TaskRevision(u64);

impl TaskRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }

    pub const fn raw(self) -> u64 {
        self.0
    }
}

pub struct RootBootstrap {
    task_id: TaskId,
    registry_id: ThreadId,
    mm_backend: Option<Arc<dyn MmBackend>>,
    diagnostic_name: String,
}

impl RootBootstrap {
    /// Build an identity-only root for the in-crate reference model.
    pub fn for_reference_model(
        observed_pid: i32,
        registry_id: ThreadId,
        diagnostic_name: String,
    ) -> Result<Self, KernelError> {
        Self::new(observed_pid, registry_id, None, diagnostic_name)
    }

    /// Build a production root whose mm is backed by the execution adapter.
    pub fn with_mm_backend(
        observed_pid: i32,
        registry_id: ThreadId,
        mm_backend: Arc<dyn MmBackend>,
        diagnostic_name: String,
    ) -> Result<Self, KernelError> {
        Self::new(observed_pid, registry_id, Some(mm_backend), diagnostic_name)
    }

    fn new(
        observed_pid: i32,
        registry_id: ThreadId,
        mm_backend: Option<Arc<dyn MmBackend>>,
        diagnostic_name: String,
    ) -> Result<Self, KernelError> {
        Ok(Self {
            task_id: TaskId::for_root_bootstrap(observed_pid)?,
            registry_id,
            mm_backend,
            diagnostic_name,
        })
    }
}

/// One backend-neutral Linux kernel instance.
#[derive(Debug)]
pub struct Kernel {
    domain: Arc<KernelDomain>,
    registry: Registry,
    ids: IdRegistry,
    object_ids: ObjectIdRegistry,
    pub(super) exit_subscribers: TaskExitSubscribers,
}

#[derive(Debug)]
pub(super) struct KernelDomain;

pub trait TaskExitSubscriber: Send + Sync {
    fn publish_exit(&self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VforkReleaseReason {
    Exec,
    Exit,
}

#[derive(Debug)]
struct VforkGateState {
    release: Mutex<Option<VforkReleaseReason>>,
    changed: Condvar,
}

#[derive(Clone, Debug)]
pub struct VforkParentWait {
    state: Arc<VforkGateState>,
}

impl VforkParentWait {
    pub fn released_reason(&self) -> Option<VforkReleaseReason> {
        *self.state.release.lock()
    }

    pub fn wait(&self) -> VforkReleaseReason {
        let mut release = self.state.release.lock();
        loop {
            if let Some(reason) = *release {
                return reason;
            }
            self.state.changed.wait(&mut release);
        }
    }
}

#[derive(Debug)]
pub(super) struct VforkChildRelease {
    state: Arc<VforkGateState>,
}

impl VforkChildRelease {
    pub(super) fn pair() -> (VforkParentWait, Self) {
        let state = Arc::new(VforkGateState {
            release: Mutex::new(None),
            changed: Condvar::new(),
        });
        (
            VforkParentWait {
                state: Arc::clone(&state),
            },
            Self { state },
        )
    }

    pub(super) fn release(self, reason: VforkReleaseReason) {
        *self.state.release.lock() = Some(reason);
        self.state.changed.notify_all();
    }
}

#[derive(Default)]
pub(super) struct TaskExitSubscribers {
    watchers: Mutex<BTreeMap<TaskId, Vec<Weak<dyn TaskExitSubscriber>>>>,
}

impl TaskExitSubscribers {
    pub(super) fn register<T>(&self, task_id: TaskId, subscriber: &Arc<T>)
    where
        T: TaskExitSubscriber + 'static,
    {
        let subscriber: Arc<dyn TaskExitSubscriber> = subscriber.clone();
        self.register_erased(task_id, &subscriber);
    }

    pub(super) fn register_erased(
        &self,
        task_id: TaskId,
        subscriber: &Arc<dyn TaskExitSubscriber>,
    ) {
        self.watchers
            .lock()
            .entry(task_id)
            .or_default()
            .push(Arc::downgrade(subscriber));
    }

    pub(super) fn take(&self, task_id: TaskId) -> Vec<Weak<dyn TaskExitSubscriber>> {
        self.watchers.lock().remove(&task_id).unwrap_or_default()
    }
}

impl std::fmt::Debug for TaskExitSubscribers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskExitSubscribers")
            .field("task_count", &self.watchers.lock().len())
            .finish()
    }
}

impl Kernel {
    pub fn bootstrap_root(
        bootstrap: RootBootstrap,
    ) -> Result<(Arc<Self>, KernelContext), KernelError> {
        let (ids, task_claim) = IdRegistry::with_root(bootstrap.task_id)?;
        let leader_claim = ids.claim_task_leader_thread(bootstrap.task_id)?;
        let process_group_id = ProcessGroupId::from_leader(bootstrap.task_id);
        let session_id = SessionId::from_leader(bootstrap.task_id);
        let process_group_claim = ids.claim_process_group(process_group_id)?;
        let session_claim = ids.claim_session(session_id)?;
        let object_ids = ObjectIdRegistry::new();
        let mm_id = object_ids.mm_id()?;
        let mm = match bootstrap.mm_backend {
            Some(backend) => Arc::new(Mm::with_backend(mm_id, backend)),
            None => Arc::new(Mm::new_reference(mm_id)),
        };
        let shared = Arc::new(TaskShared::new(
            mm,
            Arc::new(Sighand::new(object_ids.sighand_id()?)),
        ));
        let resources = Arc::new(ThreadResources::new(
            Arc::new(FileTable::new(object_ids.file_table_id()?)),
            Arc::new(FsContext::new(object_ids.fs_context_id()?)),
            Arc::new(Credentials::new()),
        ));
        let task_key = TaskKey {
            id: bootstrap.task_id,
            serial: object_ids.task_serial()?,
        };
        let task = Arc::new(Task::new(
            task_key,
            None,
            process_group_id,
            session_id,
            Arc::clone(&shared),
        ));
        let leader_tid = LinuxTid::for_task_leader(bootstrap.task_id);
        let leader_key = ThreadKey {
            tid: leader_tid,
            serial: object_ids.thread_serial()?,
        };
        let leader = task.attach_thread(leader_key, bootstrap.registry_id, resources)?;
        let process_group = Arc::new(ProcessGroup::new(
            process_group_id,
            session_id,
            &ids,
            process_group_claim,
        )?);
        let session = Arc::new(Session::new(session_id, &ids, session_claim)?);

        let task_record = TaskRecord {
            task: Arc::clone(&task),
            revision: TaskRevision::INITIAL,
            task_claim,
            thread_claims: BTreeMap::from([(leader_tid, leader_claim)]),
            dead_leader: None,
            vfork_release: None,
            has_execed: false,
            diagnostic_name: bootstrap.diagnostic_name,
        };
        let registry = Registry {
            state: RwLock::new(RegistryState {
                root: task_key,
                tasks: BTreeMap::from([(bootstrap.task_id, task_record)]),
                zombies: BTreeMap::new(),
                process_groups: BTreeMap::from([(
                    process_group_id,
                    ProcessGroupRecord {
                        object: process_group,
                        members: BTreeSet::from([task_key]),
                    },
                )]),
                reservations: BTreeMap::new(),
                retired_threads: Vec::new(),
                sessions: BTreeMap::from([(
                    session_id,
                    SessionRecord {
                        object: session,
                        process_groups: BTreeSet::from([process_group_id]),
                    },
                )]),
            }),
        };
        let kernel = Arc::new(Self {
            domain: Arc::new(KernelDomain),
            registry,
            ids,
            object_ids,
            exit_subscribers: TaskExitSubscribers::default(),
        });
        let context = KernelContext::capture(kernel.clone(), task, leader, TaskRevision::INITIAL);
        Ok((kernel, context))
    }

    pub(super) fn domain(&self) -> &Arc<KernelDomain> {
        &self.domain
    }

    pub const fn registry(&self) -> &Registry {
        &self.registry
    }

    pub const fn ids(&self) -> &IdRegistry {
        &self.ids
    }

    pub const fn object_ids(&self) -> &ObjectIdRegistry {
        &self.object_ids
    }

    pub fn context(
        self: &Arc<Self>,
        task_id: TaskId,
        tid: LinuxTid,
    ) -> Result<KernelContext, KernelError> {
        let state = self.registry.state.read();
        let record = state
            .tasks
            .get(&task_id)
            .ok_or(KernelError::UnknownTask(task_id))?;
        let task = Arc::clone(&record.task);
        let thread = task.thread(tid).ok_or(KernelError::UnknownThread(tid))?;
        Ok(KernelContext::capture(
            self.clone(),
            task,
            thread,
            record.revision,
        ))
    }

    pub fn validate_invariants(&self) -> Result<(), RegistryInvariantError> {
        let state = self.registry.state.read();
        if !state.tasks.contains_key(&state.root.id) {
            return Err(RegistryInvariantError::RootNotLive);
        }
        if state.reservations.keys().any(|task_id| {
            !state.tasks.contains_key(task_id) && !state.zombies.contains_key(task_id)
        }) {
            return Err(RegistryInvariantError::OrphanReservation);
        }
        for (task_id, record) in &state.tasks {
            let key = record.task.key();
            if key.id != *task_id || !self.ids.is_reserved_number(task_id.raw()) {
                return Err(RegistryInvariantError::TaskIdentity);
            }
            let group_id = record.task.process_group();
            let session_id = record.task.session();
            let Some(group) = state.process_groups.get(&group_id) else {
                return Err(RegistryInvariantError::MissingProcessGroup);
            };
            if group.object.session() != session_id || !group.members.contains(&key) {
                return Err(RegistryInvariantError::ProcessGroupBacklink);
            }
            let Some(session) = state.sessions.get(&session_id) else {
                return Err(RegistryInvariantError::MissingSession);
            };
            if !session.process_groups.contains(&group_id) {
                return Err(RegistryInvariantError::SessionBacklink);
            }
            let thread_keys = record.task.thread_keys();
            if thread_keys.len() != record.thread_claims.len()
                || thread_keys
                    .iter()
                    .any(|thread| !record.thread_claims.contains_key(&thread.tid))
            {
                return Err(RegistryInvariantError::ThreadClaims);
            }
            let leader_tid = LinuxTid::for_task_leader(*task_id);
            if record.dead_leader.as_ref().is_some_and(|retired| {
                retired._claim.raw() != leader_tid.raw()
                    || record.thread_claims.contains_key(&leader_tid)
                    || thread_keys.iter().any(|thread| thread.tid == leader_tid)
            }) {
                return Err(RegistryInvariantError::ThreadClaims);
            }
            if let Some(parent) = record.task.parent() {
                let Some(parent_record) = state.tasks.get(&parent.id) else {
                    return Err(RegistryInvariantError::MissingParent);
                };
                if !parent_record.task.children().contains(&key) {
                    return Err(RegistryInvariantError::ParentBacklink);
                }
            }
        }
        for (group_id, group) in &state.process_groups {
            if !self.ids.is_reserved_number(group_id.raw()) {
                return Err(RegistryInvariantError::ProcessGroupClaim);
            }
            for member in &group.members {
                let Some(task) = state.tasks.get(&member.id) else {
                    return Err(RegistryInvariantError::MissingGroupMember);
                };
                if task.task.key() != *member || task.task.process_group() != *group_id {
                    return Err(RegistryInvariantError::ProcessGroupBacklink);
                }
            }
        }
        for (session_id, session) in &state.sessions {
            if !self.ids.is_reserved_number(session_id.raw()) {
                return Err(RegistryInvariantError::SessionClaim);
            }
            for group_id in &session.process_groups {
                let Some(group) = state.process_groups.get(group_id) else {
                    return Err(RegistryInvariantError::MissingProcessGroup);
                };
                if group.object.session() != *session_id {
                    return Err(RegistryInvariantError::SessionBacklink);
                }
            }
        }
        for retired in &state.retired_threads {
            if !self.ids.is_reserved_number(retired._claim.raw()) {
                return Err(RegistryInvariantError::ThreadClaims);
            }
        }
        for zombie in state.zombies.values() {
            if !self.ids.is_reserved_number(zombie.zombie.key.id.raw()) {
                return Err(RegistryInvariantError::ZombieClaim);
            }
            if let Some(parent) = zombie.zombie.parent {
                let Some(parent_record) = state.tasks.get(&parent.id) else {
                    return Err(RegistryInvariantError::MissingParent);
                };
                if !parent_record.task.children().contains(&zombie.zombie.key) {
                    return Err(RegistryInvariantError::ParentBacklink);
                }
            }
        }
        for parent in state.tasks.values() {
            for child in parent.task.children() {
                let live_matches = state
                    .tasks
                    .get(&child.id)
                    .is_some_and(|record| record.task.parent() == Some(parent.task.key()));
                let zombie_matches = state
                    .zombies
                    .get(&child.id)
                    .is_some_and(|record| record.zombie.parent == Some(parent.task.key()));
                if !live_matches && !zombie_matches {
                    return Err(RegistryInvariantError::ChildBacklink);
                }
            }
        }
        Ok(())
    }
}

/// Authoritative object index. Multi-object mutations take this lock first and
/// may then take at most one Task or subsystem leaf lock.
#[derive(Debug)]
pub struct Registry {
    pub(super) state: RwLock<RegistryState>,
}

impl Registry {
    pub fn task(&self, id: TaskId) -> Option<TaskRef> {
        self.state
            .read()
            .tasks
            .get(&id)
            .map(|record| Arc::clone(&record.task))
    }

    pub fn zombie(&self, id: TaskId) -> Option<Zombie> {
        self.state
            .read()
            .zombies
            .get(&id)
            .map(|record| record.zombie.clone())
    }

    pub fn process_group(&self, id: ProcessGroupId) -> Option<Arc<ProcessGroup>> {
        self.state
            .read()
            .process_groups
            .get(&id)
            .map(|record| Arc::clone(&record.object))
    }

    pub fn session(&self, id: SessionId) -> Option<Arc<Session>> {
        self.state
            .read()
            .sessions
            .get(&id)
            .map(|record| Arc::clone(&record.object))
    }

    pub fn process_group_members(&self, id: ProcessGroupId) -> Vec<TaskKey> {
        self.state
            .read()
            .process_groups
            .get(&id)
            .map(|record| record.members.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn session_process_groups(&self, id: SessionId) -> Vec<ProcessGroupId> {
        self.state
            .read()
            .sessions
            .get(&id)
            .map(|record| record.process_groups.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn task_ids(&self) -> Vec<TaskId> {
        self.state.read().tasks.keys().copied().collect()
    }

    pub fn process_group_ids(&self) -> Vec<ProcessGroupId> {
        self.state.read().process_groups.keys().copied().collect()
    }

    pub fn task_count(&self) -> usize {
        self.state.read().tasks.len()
    }

    pub fn zombie_count(&self) -> usize {
        self.state.read().zombies.len()
    }

    pub fn process_group_count(&self) -> usize {
        self.state.read().process_groups.len()
    }

    pub fn session_count(&self) -> usize {
        self.state.read().sessions.len()
    }

    pub fn retired_thread_count(&self) -> usize {
        self.state.read().retired_threads.len()
    }
}

#[derive(Debug)]
pub(super) struct RegistryState {
    pub(super) root: TaskKey,
    pub(super) tasks: BTreeMap<TaskId, TaskRecord>,
    pub(super) zombies: BTreeMap<TaskId, ZombieRecord>,
    pub(super) process_groups: BTreeMap<ProcessGroupId, ProcessGroupRecord>,
    pub(super) reservations: BTreeMap<TaskId, carrick_hal::KernelTransactionId>,
    pub(super) retired_threads: Vec<RetiredThreadRecord>,
    pub(super) sessions: BTreeMap<SessionId, SessionRecord>,
}

#[derive(Debug)]
pub(super) struct TaskRecord {
    pub(super) task: TaskRef,
    pub(super) revision: TaskRevision,
    pub(super) task_claim: TaskClaim,
    pub(super) thread_claims: BTreeMap<LinuxTid, ThreadClaim>,
    pub(super) dead_leader: Option<RetiredThreadRecord>,
    pub(super) vfork_release: Option<VforkChildRelease>,
    pub(super) has_execed: bool,
    pub(super) diagnostic_name: String,
}

#[derive(Debug)]
pub(super) struct ZombieRecord {
    pub(super) zombie: Zombie,
    pub(super) _task_claim: TaskClaim,
}

#[derive(Debug)]
pub(super) struct RetiredThreadRecord {
    pub(super) thread: Weak<Thread>,
    pub(super) _claim: ThreadClaim,
}

#[derive(Debug)]
pub(super) struct ProcessGroupRecord {
    pub(super) object: Arc<ProcessGroup>,
    pub(super) members: BTreeSet<TaskKey>,
}

#[derive(Debug)]
pub(super) struct SessionRecord {
    pub(super) object: Arc<Session>,
    pub(super) process_groups: BTreeSet<ProcessGroupId>,
}

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error(transparent)]
    InvalidLinuxId(#[from] super::ids::InvalidLinuxId),
    #[error(transparent)]
    Id(#[from] IdError),
    #[error(transparent)]
    ObjectId(#[from] ObjectIdError),
    #[error(transparent)]
    ObjectGraph(#[from] ObjectGraphError),
    #[error("kernel task {0:?} is not live")]
    UnknownTask(TaskId),
    #[error("kernel task {0:?} binding names a retired generation")]
    StaleTaskBinding(TaskId),
    #[error("kernel thread {0:?} is not live")]
    UnknownThread(LinuxTid),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistryInvariantError {
    #[error("kernel root task is not live")]
    RootNotLive,
    #[error("task map key, object key, or numeric claim disagree")]
    TaskIdentity,
    #[error("operation reservation targets a non-live task")]
    OrphanReservation,
    #[error("task has no process-group object")]
    MissingProcessGroup,
    #[error("task and process-group backlinks disagree")]
    ProcessGroupBacklink,
    #[error("task has no session object")]
    MissingSession,
    #[error("session and process-group backlinks disagree")]
    SessionBacklink,
    #[error("thread set and thread identity claims disagree")]
    ThreadClaims,
    #[error("task or zombie parent is not live")]
    MissingParent,
    #[error("parent does not contain its child backlink")]
    ParentBacklink,
    #[error("process group has no numeric claim")]
    ProcessGroupClaim,
    #[error("process-group member is not live")]
    MissingGroupMember,
    #[error("session has no numeric claim")]
    SessionClaim,
    #[error("zombie has no retained task claim")]
    ZombieClaim,
    #[error("parent child set has no matching live task or zombie")]
    ChildBacklink,
}

#[cfg(test)]
mod tests {
    use carrick_abi::LinuxCloneFlags;

    use super::*;
    use crate::kernel::{ClonePlan, Credentials, FileTable, FsContext, Mm, Sighand};

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let bootstrap = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "root".to_string(),
        )
        .expect("root bootstrap input");
        Kernel::bootstrap_root(bootstrap).expect("root kernel")
    }

    #[test]
    fn root_adapter_preserves_observed_pid_and_all_associations() {
        let (kernel, context) = bootstrap(4242);
        let task_id = TaskId::for_root_bootstrap(4242).expect("task ID");
        let leader_tid = LinuxTid::for_task_leader(task_id);

        assert_eq!(context.task.key().id, task_id);
        assert_eq!(context.thread.key().tid, leader_tid);
        assert_eq!(kernel.registry().task_count(), 1);
        assert_eq!(context.task.process_group().raw(), 4242);
        assert_eq!(context.task.session().raw(), 4242);
        assert!(
            kernel
                .registry()
                .process_group(ProcessGroupId::from_leader(task_id))
                .is_some()
        );
        assert!(
            kernel
                .registry()
                .session(SessionId::from_leader(task_id))
                .is_some()
        );
    }

    #[test]
    fn task_binding_captures_explicit_worker_identity_and_rejects_stale_generation() {
        let (kernel, leader) = bootstrap(4300);
        let worker_registry_id = ThreadId::synthetic_for_tests(99);
        let worker = kernel
            .clone_thread(
                &leader,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                worker_registry_id,
                None,
            )
            .expect("worker");
        let binding = leader.task_binding();
        let captured = binding
            .capture(worker.thread.key().tid)
            .expect("worker context");

        assert_eq!(binding.task_id(), leader.task.key().id);
        assert!(Arc::ptr_eq(binding.kernel(), &kernel));
        assert_eq!(captured.thread.registry_id(), worker_registry_id);
        assert_eq!(captured.thread.key(), worker.thread.key());
        assert!(Arc::ptr_eq(&captured.shared, &worker.shared));
        assert!(Arc::ptr_eq(&captured.resources, &worker.resources));

        let stale = KernelTaskBinding {
            kernel,
            task: TaskKey {
                id: leader.task.key().id,
                serial: binding
                    .kernel()
                    .object_ids()
                    .task_serial()
                    .expect("different task generation"),
            },
        };
        assert!(matches!(
            stale.capture(leader.thread.key().tid),
            Err(KernelError::StaleTaskBinding(id)) if id == leader.task.key().id
        ));
    }

    #[test]
    fn context_captures_one_coherent_resource_generation() {
        let (kernel, first) = bootstrap(100);
        let task_id = first.task.key().id;
        let tid = first.thread.key().tid;
        let original_shared = Arc::clone(&first.shared);
        let original_resources = Arc::clone(&first.resources);
        first.task.replace_shared(Arc::new(TaskShared::new(
            Arc::new(Mm::new_reference(
                kernel.object_ids().mm_id().expect("new mm"),
            )),
            Arc::new(Sighand::new(
                kernel.object_ids().sighand_id().expect("new sighand"),
            )),
        )));
        first
            .thread
            .replace_resources(Arc::new(ThreadResources::new(
                Arc::new(FileTable::new(
                    kernel.object_ids().file_table_id().expect("new files"),
                )),
                Arc::new(FsContext::new(
                    kernel.object_ids().fs_context_id().expect("new fs"),
                )),
                Arc::new(Credentials::new()),
            )));

        let second = kernel.context(task_id, tid).expect("fresh context");
        assert!(Arc::ptr_eq(&first.shared, &original_shared));
        assert!(Arc::ptr_eq(&first.resources, &original_resources));
        assert!(!Arc::ptr_eq(&first.shared, &second.shared));
        assert!(!Arc::ptr_eq(&first.resources, &second.resources));
    }
}
