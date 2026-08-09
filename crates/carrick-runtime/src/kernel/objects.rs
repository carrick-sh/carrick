use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use carrick_hal::ThreadId;
use parking_lot::Mutex;

use super::clone_plan::{CloneObjectMode, ClonePlan, CloneTaskMode};
use super::ids::{
    FileDescriptionId, FileTableId, FsContextId, LinuxTid, MmId, ObjectIdError, ObjectIdRegistry,
    ProcessGroupId, SessionId, SighandId, TaskId, TaskSerial, ThreadSerial,
};
use super::registry::{IdRegistry, ProcessGroupClaim, SessionClaim};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskKey {
    pub id: TaskId,
    pub serial: TaskSerial,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadKey {
    pub tid: LinuxTid,
    pub serial: ThreadSerial,
}

#[derive(Debug)]
pub struct Mm {
    id: MmId,
}

impl Mm {
    pub const fn new(id: MmId) -> Self {
        Self { id }
    }

    pub const fn id(&self) -> MmId {
        self.id
    }
}

#[derive(Debug)]
pub struct Sighand {
    id: SighandId,
}

impl Sighand {
    pub const fn new(id: SighandId) -> Self {
        Self { id }
    }

    pub const fn id(&self) -> SighandId {
        self.id
    }
}

#[derive(Debug)]
enum FileDescriptionKind {
    Regular,
    Epoll(Mutex<BTreeMap<FileDescriptionId, Weak<FileDescription>>>),
}

/// Open-file-description identity. Epoll edges are weak and stable-keyed so
/// descriptor graphs cannot create ownership cycles.
#[derive(Debug)]
pub struct FileDescription {
    id: FileDescriptionId,
    kind: FileDescriptionKind,
}

impl FileDescription {
    pub const fn regular(id: FileDescriptionId) -> Self {
        Self {
            id,
            kind: FileDescriptionKind::Regular,
        }
    }

    pub fn epoll(id: FileDescriptionId) -> Self {
        Self {
            id,
            kind: FileDescriptionKind::Epoll(Mutex::new(BTreeMap::new())),
        }
    }

    pub const fn id(&self) -> FileDescriptionId {
        self.id
    }

    pub const fn is_epoll(&self) -> bool {
        matches!(&self.kind, FileDescriptionKind::Epoll(_))
    }

    pub fn add_epoll_interest(
        self: &Arc<Self>,
        target: &Arc<Self>,
    ) -> Result<(), ObjectGraphError> {
        let FileDescriptionKind::Epoll(interests) = &self.kind else {
            return Err(ObjectGraphError::NotEpoll(self.id));
        };
        if self.id == target.id {
            return Err(ObjectGraphError::SelfEpollInterest(self.id));
        }
        if target.is_epoll() {
            return Err(ObjectGraphError::NestedEpollInterest(target.id));
        }
        interests.lock().insert(target.id, Arc::downgrade(target));
        Ok(())
    }

    pub fn live_epoll_interest_count(&self) -> Result<usize, ObjectGraphError> {
        let FileDescriptionKind::Epoll(interests) = &self.kind else {
            return Err(ObjectGraphError::NotEpoll(self.id));
        };
        let mut interests = interests.lock();
        interests.retain(|_, target| target.strong_count() != 0);
        Ok(interests.len())
    }
}

#[derive(Debug)]
pub struct FileTable {
    id: FileTableId,
}

impl FileTable {
    pub const fn new(id: FileTableId) -> Self {
        Self { id }
    }

    pub const fn id(&self) -> FileTableId {
        self.id
    }
}

#[derive(Debug)]
pub struct FsContext {
    id: FsContextId,
}

impl FsContext {
    pub const fn new(id: FsContextId) -> Self {
        Self { id }
    }

    pub const fn id(&self) -> FsContextId {
        self.id
    }
}

/// Immutable credential snapshot. The concrete dispatcher credential state is
/// attached by the one-task adapter; distinct `Arc`s preserve per-thread COW.
#[derive(Debug, Default)]
pub struct Credentials {
    _private: (),
}

impl Credentials {
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

/// Task-directed pending-signal ownership. Signal queue details remain in the
/// signal subsystem; this object supplies the required task-level lifetime.
#[derive(Debug, Default)]
pub struct TaskPendingSignals {
    pending_count: AtomicUsize,
}

impl TaskPendingSignals {
    pub const fn new() -> Self {
        Self {
            pending_count: AtomicUsize::new(0),
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct TaskShared {
    mm: Arc<Mm>,
    sighand: Arc<Sighand>,
    pending_signals: TaskPendingSignals,
}

impl TaskShared {
    pub fn new(mm: Arc<Mm>, sighand: Arc<Sighand>) -> Self {
        Self {
            mm,
            sighand,
            pending_signals: TaskPendingSignals::new(),
        }
    }

    pub fn for_new_task(
        parent: &Self,
        plan: ClonePlan,
        ids: &ObjectIdRegistry,
    ) -> Result<Self, TaskSharedCloneError> {
        if plan.task() != CloneTaskMode::NewTask {
            return Err(TaskSharedCloneError::ThreadGroupMustReuseTaskShared);
        }
        let mm = match plan.mm() {
            CloneObjectMode::Share => Arc::clone(&parent.mm),
            CloneObjectMode::Copy => Arc::new(Mm::new(ids.mm_id()?)),
        };
        let sighand = match plan.sighand() {
            CloneObjectMode::Share => Arc::clone(&parent.sighand),
            CloneObjectMode::Copy => Arc::new(Sighand::new(ids.sighand_id()?)),
        };
        Ok(Self::new(mm, sighand))
    }

    pub fn mm(&self) -> Arc<Mm> {
        Arc::clone(&self.mm)
    }

    pub fn sighand(&self) -> Arc<Sighand> {
        Arc::clone(&self.sighand)
    }

    pub const fn pending_signals(&self) -> &TaskPendingSignals {
        &self.pending_signals
    }
}

#[derive(Debug)]
pub struct ThreadResources {
    files: Arc<FileTable>,
    fs_context: Arc<FsContext>,
    credentials: Arc<Credentials>,
}

impl ThreadResources {
    pub fn new(
        files: Arc<FileTable>,
        fs_context: Arc<FsContext>,
        credentials: Arc<Credentials>,
    ) -> Self {
        Self {
            files,
            fs_context,
            credentials,
        }
    }

    pub fn for_clone(
        parent: &Self,
        plan: ClonePlan,
        ids: &ObjectIdRegistry,
    ) -> Result<Self, ObjectIdError> {
        let files = match plan.files() {
            CloneObjectMode::Share => Arc::clone(&parent.files),
            CloneObjectMode::Copy => Arc::new(FileTable::new(ids.file_table_id()?)),
        };
        let fs_context = match plan.fs_context() {
            CloneObjectMode::Share => Arc::clone(&parent.fs_context),
            CloneObjectMode::Copy => Arc::new(FsContext::new(ids.fs_context_id()?)),
        };
        Ok(Self::new(
            files,
            fs_context,
            Arc::clone(&parent.credentials),
        ))
    }

    pub fn files(&self) -> Arc<FileTable> {
        Arc::clone(&self.files)
    }

    pub fn fs_context(&self) -> Arc<FsContext> {
        Arc::clone(&self.fs_context)
    }

    pub fn credentials(&self) -> Arc<Credentials> {
        Arc::clone(&self.credentials)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskLifecycle {
    Live,
    Exiting,
}

pub type TaskRef = Arc<Task>;
pub type ThreadRef = Arc<Thread>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskIdentity {
    process_group: ProcessGroupId,
    session: SessionId,
}

#[derive(Debug)]
pub struct Task {
    key: TaskKey,
    parent: Mutex<Option<TaskKey>>,
    children: Mutex<BTreeSet<TaskKey>>,
    identity: TaskIdentity,
    lifecycle: Mutex<TaskLifecycle>,
    shared: ArcSwap<TaskShared>,
    threads: Mutex<BTreeMap<LinuxTid, (ThreadKey, ThreadRef)>>,
}

impl Task {
    pub fn new(
        key: TaskKey,
        parent: Option<TaskKey>,
        process_group: ProcessGroupId,
        session: SessionId,
        shared: Arc<TaskShared>,
    ) -> Self {
        Self {
            key,
            parent: Mutex::new(parent),
            children: Mutex::new(BTreeSet::new()),
            identity: TaskIdentity {
                process_group,
                session,
            },
            lifecycle: Mutex::new(TaskLifecycle::Live),
            shared: ArcSwap::new(shared),
            threads: Mutex::new(BTreeMap::new()),
        }
    }

    pub const fn key(&self) -> TaskKey {
        self.key
    }

    pub fn parent(&self) -> Option<TaskKey> {
        *self.parent.lock()
    }

    pub fn reparent(&self, parent: Option<TaskKey>) {
        *self.parent.lock() = parent;
    }

    pub fn add_child(&self, child: TaskKey) -> bool {
        self.children.lock().insert(child)
    }

    pub fn remove_child(&self, child: TaskKey) -> bool {
        self.children.lock().remove(&child)
    }

    pub fn children(&self) -> Vec<TaskKey> {
        self.children.lock().iter().copied().collect()
    }

    pub const fn process_group(&self) -> ProcessGroupId {
        self.identity.process_group
    }

    pub const fn session(&self) -> SessionId {
        self.identity.session
    }

    pub fn lifecycle(&self) -> TaskLifecycle {
        *self.lifecycle.lock()
    }

    pub fn begin_exit(&self) -> bool {
        let mut lifecycle = self.lifecycle.lock();
        if *lifecycle == TaskLifecycle::Exiting {
            return false;
        }
        *lifecycle = TaskLifecycle::Exiting;
        true
    }

    pub fn shared(&self) -> Arc<TaskShared> {
        self.shared.load_full()
    }

    pub fn replace_shared(&self, replacement: Arc<TaskShared>) -> Arc<TaskShared> {
        self.shared.swap(replacement)
    }

    pub fn attach_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
    ) -> Result<ThreadRef, ObjectGraphError> {
        let mut threads = self.threads.lock();
        if threads.contains_key(&key.tid) {
            return Err(ObjectGraphError::DuplicateThread(key.tid));
        }
        if threads.is_empty() && key.tid != LinuxTid::for_task_leader(self.key.id) {
            return Err(ObjectGraphError::LeaderTidMismatch {
                task: self.key.id,
                tid: key.tid,
            });
        }
        let thread = Arc::new(Thread {
            key,
            registry_id,
            task_key: self.key,
            task: Arc::downgrade(self),
            resources: ArcSwap::new(resources),
        });
        threads.insert(key.tid, (key, Arc::clone(&thread)));
        Ok(thread)
    }

    pub fn detach_thread(&self, key: ThreadKey) -> bool {
        let mut threads = self.threads.lock();
        if threads.get(&key.tid).map(|(stored, _)| *stored) != Some(key) {
            return false;
        }
        threads.remove(&key.tid);
        true
    }

    pub fn live_thread_count(&self) -> usize {
        self.threads.lock().len()
    }
}

#[derive(Debug)]
pub struct Thread {
    key: ThreadKey,
    registry_id: ThreadId,
    task_key: TaskKey,
    task: Weak<Task>,
    resources: ArcSwap<ThreadResources>,
}

impl Thread {
    pub const fn key(&self) -> ThreadKey {
        self.key
    }

    pub const fn registry_id(&self) -> ThreadId {
        self.registry_id
    }

    pub const fn task_key(&self) -> TaskKey {
        self.task_key
    }

    pub fn task(&self) -> Option<TaskRef> {
        self.task.upgrade()
    }

    pub fn resources(&self) -> Arc<ThreadResources> {
        self.resources.load_full()
    }

    pub fn replace_resources(&self, replacement: Arc<ThreadResources>) -> Arc<ThreadResources> {
        self.resources.swap(replacement)
    }
}

#[derive(Debug)]
pub struct ProcessGroup {
    id: ProcessGroupId,
    session: SessionId,
    _claim: ProcessGroupClaim,
}

impl ProcessGroup {
    pub fn new(
        id: ProcessGroupId,
        session: SessionId,
        registry: &IdRegistry,
        claim: ProcessGroupClaim,
    ) -> Result<Self, ObjectGraphError> {
        if claim.raw() != id.raw() || !claim.belongs_to(registry) {
            return Err(ObjectGraphError::ProcessGroupClaimMismatch);
        }
        Ok(Self {
            id,
            session,
            _claim: claim,
        })
    }

    pub const fn id(&self) -> ProcessGroupId {
        self.id
    }

    pub const fn session(&self) -> SessionId {
        self.session
    }
}

#[derive(Debug)]
pub struct Session {
    id: SessionId,
    _claim: SessionClaim,
}

impl Session {
    pub fn new(
        id: SessionId,
        registry: &IdRegistry,
        claim: SessionClaim,
    ) -> Result<Self, ObjectGraphError> {
        if claim.raw() != id.raw() || !claim.belongs_to(registry) {
            return Err(ObjectGraphError::SessionClaimMismatch);
        }
        Ok(Self { id, _claim: claim })
    }

    pub const fn id(&self) -> SessionId {
        self.id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct LinuxWaitStatus(i32);

impl LinuxWaitStatus {
    pub const fn from_wait_encoding(raw: i32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaskRusage {
    pub user_time: Duration,
    pub system_time: Duration,
}

/// Compact post-exit state. It contains no task-owned `Arc` and therefore
/// cannot retain mm, files, signals, or runner state after teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zombie {
    pub key: TaskKey,
    pub parent: Option<TaskKey>,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
    pub status: LinuxWaitStatus,
    pub rusage: TaskRusage,
    pub diagnostic_name: String,
}

impl Zombie {
    pub fn from_task(
        task: &Task,
        status: LinuxWaitStatus,
        rusage: TaskRusage,
        diagnostic_name: String,
    ) -> Self {
        Self {
            key: task.key(),
            parent: task.parent(),
            process_group: task.process_group(),
            session: task.session(),
            status,
            rusage,
            diagnostic_name,
        }
    }
}

/// A pidfd edge is stable-keyed and weak: it never keeps the target alive.
#[derive(Debug)]
pub struct PidfdTarget {
    key: TaskKey,
    target: Weak<Task>,
}

impl PidfdTarget {
    pub fn new(target: &TaskRef) -> Self {
        Self {
            key: target.key(),
            target: Arc::downgrade(target),
        }
    }

    pub const fn key(&self) -> TaskKey {
        self.key
    }

    pub fn target(&self) -> Option<TaskRef> {
        self.target
            .upgrade()
            .filter(|target| target.key() == self.key)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TaskSharedCloneError {
    #[error("thread-group clones must reuse the task's existing TaskShared association")]
    ThreadGroupMustReuseTaskShared,
    #[error(transparent)]
    ObjectId(#[from] ObjectIdError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObjectGraphError {
    #[error("first thread TID {tid:?} must match task leader {task:?}")]
    LeaderTidMismatch { task: TaskId, tid: LinuxTid },
    #[error("thread TID {0:?} is already attached")]
    DuplicateThread(LinuxTid),
    #[error("process-group claim does not match its typed ID")]
    ProcessGroupClaimMismatch,
    #[error("session claim does not match its typed ID")]
    SessionClaimMismatch,
    #[error("file description {0:?} is not an epoll instance")]
    NotEpoll(FileDescriptionId),
    #[error("epoll file description {0:?} cannot monitor itself")]
    SelfEpollInterest(FileDescriptionId),
    #[error("nested epoll target {0:?} is rejected by the K1 object model")]
    NestedEpollInterest(FileDescriptionId),
}

#[cfg(test)]
mod tests {
    use carrick_abi::LinuxCloneFlags;

    use super::*;
    use crate::kernel::{ClonePlan, IdRegistry};

    struct Fixture {
        ids: ObjectIdRegistry,
        task: TaskRef,
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
            let mm = Arc::new(Mm::new(ids.mm_id().expect("mm ID")));
            let sighand = Arc::new(Sighand::new(ids.sighand_id().expect("sighand ID")));
            let shared = Arc::new(TaskShared::new(mm, sighand));
            let task = Arc::new(Task::new(
                key,
                None,
                ProcessGroupId::from_leader(task_id),
                SessionId::from_leader(task_id),
                shared,
            ));
            let resources = Arc::new(ThreadResources::new(
                Arc::new(FileTable::new(ids.file_table_id().expect("files ID"))),
                Arc::new(FsContext::new(ids.fs_context_id().expect("fs ID"))),
                Arc::new(Credentials::new()),
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
            Self { ids, task, leader }
        }
    }

    #[test]
    fn legal_thread_clone_can_copy_files_and_fs_independently() {
        let fixture = Fixture::new();
        let flags = LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM;
        let plan = ClonePlan::from_flags(flags).expect("legal clone plan");
        let parent = fixture.leader.resources();
        let child = ThreadResources::for_clone(&parent, plan, &fixture.ids).expect("resources");

        assert!(!Arc::ptr_eq(&parent.files(), &child.files()));
        assert!(!Arc::ptr_eq(&parent.fs_context(), &child.fs_context()));
        assert!(Arc::ptr_eq(&parent.credentials(), &child.credentials()));
    }

    #[test]
    fn clone_flags_control_each_shared_object_independently() {
        let fixture = Fixture::new();
        let flags = LinuxCloneFlags::VM
            | LinuxCloneFlags::SIGHAND
            | LinuxCloneFlags::FILES
            | LinuxCloneFlags::FS;
        let plan = ClonePlan::from_flags(flags).expect("legal clone plan");
        let parent_shared = fixture.task.shared();
        let child_shared =
            TaskShared::for_new_task(&parent_shared, plan, &fixture.ids).expect("shared resources");
        let parent_resources = fixture.leader.resources();
        let child_resources = ThreadResources::for_clone(&parent_resources, plan, &fixture.ids)
            .expect("thread resources");

        assert!(Arc::ptr_eq(&parent_shared.mm(), &child_shared.mm()));
        assert!(Arc::ptr_eq(
            &parent_shared.sighand(),
            &child_shared.sighand()
        ));
        assert!(Arc::ptr_eq(
            &parent_resources.files(),
            &child_resources.files()
        ));
        assert!(Arc::ptr_eq(
            &parent_resources.fs_context(),
            &child_resources.fs_context()
        ));
    }

    #[test]
    fn task_owns_threads_without_a_strong_back_link_cycle() {
        let fixture = Fixture::new();
        let task = Arc::clone(&fixture.task);
        let weak_task = Arc::downgrade(&task);
        let leader = Arc::clone(&fixture.leader);
        drop(fixture);
        assert_eq!(task.live_thread_count(), 1);
        drop(task);

        assert!(weak_task.upgrade().is_none());
        assert!(leader.task().is_none());
    }

    #[test]
    fn thread_group_plan_cannot_create_a_new_task_shared_bundle() {
        let fixture = Fixture::new();
        let flags = LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM;
        let plan = ClonePlan::from_flags(flags).expect("thread plan");

        assert!(matches!(
            TaskShared::for_new_task(&fixture.task.shared(), plan, &fixture.ids),
            Err(TaskSharedCloneError::ThreadGroupMustReuseTaskShared)
        ));
    }

    #[test]
    fn epoll_rejects_self_and_nested_edges_and_uses_weak_targets() {
        let ids = ObjectIdRegistry::new();
        let epoll = Arc::new(FileDescription::epoll(
            ids.file_description_id().expect("epoll ID"),
        ));
        let nested = Arc::new(FileDescription::epoll(
            ids.file_description_id().expect("nested epoll ID"),
        ));
        let regular = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("regular ID"),
        ));

        assert_eq!(
            epoll.add_epoll_interest(&epoll),
            Err(ObjectGraphError::SelfEpollInterest(epoll.id()))
        );
        assert_eq!(
            epoll.add_epoll_interest(&nested),
            Err(ObjectGraphError::NestedEpollInterest(nested.id()))
        );
        epoll
            .add_epoll_interest(&regular)
            .expect("regular weak interest");
        assert_eq!(epoll.live_epoll_interest_count(), Ok(1));
        drop(regular);
        assert_eq!(epoll.live_epoll_interest_count(), Ok(0));
    }

    #[test]
    fn pidfd_target_does_not_keep_task_alive() {
        let fixture = Fixture::new();
        let pidfd = PidfdTarget::new(&fixture.task);
        let key = fixture.task.key();
        drop(fixture);

        assert_eq!(pidfd.key(), key);
        assert!(pidfd.target().is_none());
    }

    #[test]
    fn compact_zombie_does_not_retain_task_resources() {
        let fixture = Fixture::new();
        let mm = fixture.task.shared().mm();
        let weak_mm = Arc::downgrade(&mm);
        let zombie = Zombie::from_task(
            &fixture.task,
            LinuxWaitStatus::from_wait_encoding(0),
            TaskRusage::default(),
            "fixture".to_string(),
        );
        drop(mm);
        drop(fixture);

        assert!(weak_mm.upgrade().is_none());
        assert_eq!(zombie.key.id.raw(), 100);
    }

    #[test]
    fn group_claim_from_another_registry_is_rejected() {
        let owner = IdRegistry::new();
        let foreign = IdRegistry::new();
        let (owner_task, owner_reservation) = owner.reserve_task().expect("owner task");
        let owner_task_claim = owner_reservation.commit();
        let (foreign_task, foreign_reservation) = foreign.reserve_task().expect("foreign task");
        let foreign_task_claim = foreign_reservation.commit();
        assert_eq!(owner_task.raw(), foreign_task.raw());
        let group = ProcessGroupId::from_leader(owner_task);
        let session = SessionId::from_leader(owner_task);
        let foreign_claim = foreign
            .claim_process_group(ProcessGroupId::from_leader(foreign_task))
            .expect("foreign group claim");

        assert!(matches!(
            ProcessGroup::new(group, session, &owner, foreign_claim),
            Err(ObjectGraphError::ProcessGroupClaimMismatch)
        ));
        drop(owner_task_claim);
        drop(foreign_task_claim);
    }

    #[test]
    fn group_and_session_objects_hold_typed_namespace_claims() {
        let ids = IdRegistry::new();
        let (task_id, task_reservation) = ids.reserve_task().expect("task reservation");
        let task_claim = task_reservation.commit();
        let group_id = ProcessGroupId::from_leader(task_id);
        let session_id = SessionId::from_leader(task_id);
        let group_claim = ids.claim_process_group(group_id).expect("group claim");
        let session_claim = ids.claim_session(session_id).expect("session claim");
        let group =
            ProcessGroup::new(group_id, session_id, &ids, group_claim).expect("group object");
        let session = Session::new(session_id, &ids, session_claim).expect("session object");

        drop(task_claim);
        assert!(ids.is_reserved_number(task_id.raw()));
        drop(group);
        assert!(ids.is_reserved_number(task_id.raw()));
        drop(session);
        assert!(!ids.is_reserved_number(task_id.raw()));
    }
}
