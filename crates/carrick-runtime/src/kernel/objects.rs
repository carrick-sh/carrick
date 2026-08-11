use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use carrick_abi::SigSet;
use carrick_hal::ThreadId;
use parking_lot::{Condvar, Mutex, RwLock};

use crate::linux_abi::LINUX_DEFAULT_UMASK;

use super::address::MmBackend;
use super::clone_plan::{CloneObjectMode, ClonePlan, CloneTaskMode};
use super::ids::{
    CredentialsId, FileDescriptionId, FileSlotNumber, FileTableId, FsContextId, LinuxSignal,
    LinuxTid, MmId, ObjectIdError, ObjectIdRegistry, ProcessGroupId, SessionId, SighandId, TaskId,
    TaskSerial, ThreadSerial,
};
use super::registry::{IdRegistry, ProcessGroupClaim, SessionClaim};

#[derive(Default)]
pub(super) struct ObjectRevision(AtomicU64);

impl ObjectRevision {
    const fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    pub(super) fn load(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn publish(&self) {
        if self.0.fetch_add(1, Ordering::Release) == u64::MAX {
            std::process::abort();
        }
    }
}

impl std::fmt::Debug for ObjectRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ObjectRevision")
            .field(&self.load())
            .finish()
    }
}

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

pub struct Mm {
    id: MmId,
    backend: Option<Arc<dyn MmBackend>>,
}

impl Mm {
    /// Identity-only constructor for the in-crate K1 reference model. Runtime
    /// adapters must use `with_backend`; callers outside `kernel` cannot create
    /// an observation-less mm.
    pub(super) const fn new_reference(id: MmId) -> Self {
        Self { id, backend: None }
    }

    pub fn with_backend(id: MmId, backend: Arc<dyn MmBackend>) -> Self {
        Self {
            id,
            backend: Some(backend),
        }
    }

    pub const fn id(&self) -> MmId {
        self.id
    }

    pub fn backend(&self) -> Option<&Arc<dyn MmBackend>> {
        self.backend.as_ref()
    }
}

impl std::fmt::Debug for Mm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Mm")
            .field("id", &self.id)
            .field("has_backend", &self.backend.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalDisposition {
    Default,
    Ignore,
    Caught,
}

#[derive(Debug)]
pub struct Sighand {
    id: SighandId,
    dispositions: Mutex<BTreeMap<LinuxSignal, SignalDisposition>>,
    revision: ObjectRevision,
}

impl Sighand {
    pub fn new(id: SighandId) -> Self {
        Self {
            id,
            dispositions: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        }
    }

    fn for_fork_copy(id: SighandId, parent: &Self) -> Self {
        Self {
            id,
            dispositions: Mutex::new(parent.dispositions.lock().clone()),
            revision: ObjectRevision::new(),
        }
    }

    fn for_exec(id: SighandId, caller: &Self) -> Self {
        let dispositions = caller
            .dispositions
            .lock()
            .iter()
            .filter_map(|(signal, disposition)| {
                (*disposition == SignalDisposition::Ignore).then_some((*signal, *disposition))
            })
            .collect();
        Self {
            id,
            dispositions: Mutex::new(dispositions),
            revision: ObjectRevision::new(),
        }
    }

    pub const fn id(&self) -> SighandId {
        self.id
    }

    pub fn set_disposition(&self, signal: LinuxSignal, disposition: SignalDisposition) {
        let mut dispositions = self.dispositions.lock();
        if disposition == SignalDisposition::Default {
            dispositions.remove(&signal);
        } else {
            dispositions.insert(signal, disposition);
        }
        self.revision.publish();
    }

    pub fn disposition(&self, signal: LinuxSignal) -> SignalDisposition {
        self.dispositions
            .lock()
            .get(&signal)
            .copied()
            .unwrap_or(SignalDisposition::Default)
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, Vec<(LinuxSignal, SignalDisposition)>)> {
        let values = self.dispositions.try_lock_until(deadline)?;
        Some((
            self.revision.load(),
            values.iter().map(|(k, v)| (*k, *v)).collect(),
        ))
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
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
    revision: ObjectRevision,
}

impl FileDescription {
    pub const fn regular(id: FileDescriptionId) -> Self {
        Self {
            id,
            kind: FileDescriptionKind::Regular,
            revision: ObjectRevision::new(),
        }
    }

    pub fn epoll(id: FileDescriptionId) -> Self {
        Self {
            id,
            kind: FileDescriptionKind::Epoll(Mutex::new(BTreeMap::new())),
            revision: ObjectRevision::new(),
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
        let mut interests = interests.lock();
        interests.insert(target.id, Arc::downgrade(target));
        self.revision.publish();
        Ok(())
    }

    pub fn live_epoll_interest_count(&self) -> Result<usize, ObjectGraphError> {
        let FileDescriptionKind::Epoll(interests) = &self.kind else {
            return Err(ObjectGraphError::NotEpoll(self.id));
        };
        let mut interests = interests.lock();
        let before = interests.len();
        interests.retain(|_, target| target.strong_count() != 0);
        if interests.len() != before {
            self.revision.publish();
        }
        Ok(interests.len())
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, bool, Vec<FileDescriptionId>)> {
        match &self.kind {
            FileDescriptionKind::Regular => Some((self.revision.load(), false, Vec::new())),
            FileDescriptionKind::Epoll(interests) => {
                let interests = interests.try_lock_until(deadline)?;
                Some((
                    self.revision.load(),
                    true,
                    interests
                        .iter()
                        .filter_map(|(id, target)| (target.strong_count() != 0).then_some(*id))
                        .collect(),
                ))
            }
        }
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

#[derive(Clone, Debug)]
pub struct FileSlot {
    description: Arc<FileDescription>,
    close_on_exec: bool,
}

impl FileSlot {
    pub fn description(&self) -> Arc<FileDescription> {
        Arc::clone(&self.description)
    }

    pub const fn close_on_exec(&self) -> bool {
        self.close_on_exec
    }
}

#[derive(Debug)]
pub struct FileTable {
    id: FileTableId,
    slots: Mutex<BTreeMap<FileSlotNumber, FileSlot>>,
    revision: ObjectRevision,
}

impl FileTable {
    pub fn new(id: FileTableId) -> Self {
        Self {
            id,
            slots: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        }
    }

    fn for_fork_copy(id: FileTableId, parent: &Self) -> Self {
        Self {
            id,
            slots: Mutex::new(parent.slots.lock().clone()),
            revision: ObjectRevision::new(),
        }
    }

    fn for_exec(id: FileTableId, caller: &Self) -> Self {
        let slots = caller
            .slots
            .lock()
            .iter()
            .filter_map(|(number, slot)| (!slot.close_on_exec).then_some((*number, slot.clone())))
            .collect();
        Self {
            id,
            slots: Mutex::new(slots),
            revision: ObjectRevision::new(),
        }
    }

    pub const fn id(&self) -> FileTableId {
        self.id
    }

    pub fn install(
        &self,
        number: FileSlotNumber,
        description: Arc<FileDescription>,
        close_on_exec: bool,
    ) -> Option<FileSlot> {
        let mut slots = self.slots.lock();
        let replaced = slots.insert(
            number,
            FileSlot {
                description,
                close_on_exec,
            },
        );
        self.revision.publish();
        replaced
    }

    pub fn slot(&self, number: FileSlotNumber) -> Option<FileSlot> {
        self.slots.lock().get(&number).cloned()
    }

    pub fn slot_count(&self) -> usize {
        self.slots.lock().len()
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, Vec<(FileSlotNumber, FileSlot)>)> {
        let slots = self.slots.try_lock_until(deadline)?;
        Some((
            self.revision.load(),
            slots.iter().map(|(k, v)| (*k, v.clone())).collect(),
        ))
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FsContextState {
    cwd: String,
    chroot_root: Option<String>,
}

/// Authoritative Linux filesystem traversal context.
///
/// Mount tables and rootfs services remain runtime infrastructure. Only the
/// caller-visible `fs_struct` values live here, so `CLONE_FS` can share them
/// while fork and clones without `CLONE_FS` copy their exact values.
#[derive(Debug)]
pub struct FsContext {
    id: FsContextId,
    state: RwLock<FsContextState>,
    revision: ObjectRevision,
}

impl FsContext {
    pub fn new(id: FsContextId) -> Self {
        Self {
            id,
            state: RwLock::new(FsContextState {
                cwd: "/".to_owned(),
                chroot_root: None,
            }),
            revision: ObjectRevision::new(),
        }
    }

    fn for_fork_copy(id: FsContextId, parent: &Self) -> Self {
        Self {
            id,
            state: RwLock::new(parent.state.read().clone()),
            revision: ObjectRevision::new(),
        }
    }

    pub const fn id(&self) -> FsContextId {
        self.id
    }

    pub fn cwd(&self) -> String {
        self.state.read().cwd.clone()
    }

    pub fn chroot_root(&self) -> Option<String> {
        self.state.read().chroot_root.clone()
    }

    pub fn set_cwd(&self, cwd: String) {
        let mut state = self.state.write();
        if state.cwd != cwd {
            state.cwd = cwd;
            self.revision.publish();
        }
    }

    pub fn set_chroot_root(&self, chroot_root: Option<String>) {
        let mut state = self.state.write();
        if state.chroot_root != chroot_root {
            state.chroot_root = chroot_root;
            self.revision.publish();
        }
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, String, Option<String>)> {
        let state = self.state.try_read_until(deadline)?;
        Some((
            self.revision.load(),
            state.cwd.clone(),
            state.chroot_root.clone(),
        ))
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

/// Immutable Linux credential register file. A mutation publishes a fresh
/// object and replaces only the calling thread's `ThreadResources` association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    id: CredentialsId,
    pub(crate) ruid: u32,
    pub(crate) euid: u32,
    pub(crate) suid: u32,
    pub(crate) rgid: u32,
    pub(crate) egid: u32,
    pub(crate) sgid: u32,
    pub(crate) fsuid: u32,
    pub(crate) fsgid: u32,
    pub(crate) umask: u32,
    /// `None` preserves launch-time `/etc/group` fallback; `Some`, including an
    /// empty vector, is the complete set installed by `setgroups(2)`.
    supplementary_groups_override: Option<Vec<u32>>,
}

impl Credentials {
    pub const fn root(id: CredentialsId) -> Self {
        Self {
            id,
            ruid: 0,
            euid: 0,
            suid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            fsuid: 0,
            fsgid: 0,
            umask: LINUX_DEFAULT_UMASK,
            supplementary_groups_override: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub const fn from_values(
        id: CredentialsId,
        ruid: u32,
        euid: u32,
        suid: u32,
        rgid: u32,
        egid: u32,
        sgid: u32,
        fsuid: u32,
        fsgid: u32,
        umask: u32,
    ) -> Self {
        Self {
            id,
            ruid,
            euid,
            suid,
            rgid,
            egid,
            sgid,
            fsuid,
            fsgid,
            umask,
            supplementary_groups_override: None,
        }
    }

    pub(super) fn for_copy(id: CredentialsId, source: &Self) -> Self {
        let mut copy = source.clone();
        copy.id = id;
        copy
    }

    pub const fn id(&self) -> CredentialsId {
        self.id
    }
    pub const fn ruid(&self) -> u32 {
        self.ruid
    }
    pub const fn euid(&self) -> u32 {
        self.euid
    }
    pub const fn suid(&self) -> u32 {
        self.suid
    }
    pub const fn rgid(&self) -> u32 {
        self.rgid
    }
    pub const fn egid(&self) -> u32 {
        self.egid
    }
    pub const fn sgid(&self) -> u32 {
        self.sgid
    }
    pub const fn fsuid(&self) -> u32 {
        self.fsuid
    }
    pub const fn fsgid(&self) -> u32 {
        self.fsgid
    }
    pub const fn umask(&self) -> u32 {
        self.umask
    }
    pub fn supplementary_groups_override(&self) -> Option<&[u32]> {
        self.supplementary_groups_override.as_deref()
    }

    pub(crate) fn seed_identity(&mut self, uid: u32, gid: u32) {
        self.ruid = uid;
        self.euid = uid;
        self.suid = uid;
        self.fsuid = uid;
        self.rgid = gid;
        self.egid = gid;
        self.sgid = gid;
        self.fsgid = gid;
    }

    pub(crate) const fn is_privileged(&self) -> bool {
        self.euid == 0
    }
    pub(crate) fn set_uid_triple(&mut self, ruid: u32, euid: u32, suid: u32) {
        self.ruid = ruid;
        self.euid = euid;
        self.suid = suid;
        self.fsuid = euid;
    }
    pub(crate) fn set_gid_triple(&mut self, rgid: u32, egid: u32, sgid: u32) {
        self.rgid = rgid;
        self.egid = egid;
        self.sgid = sgid;
        self.fsgid = egid;
    }
    pub(crate) fn set_fsuid(&mut self, fsuid: u32) {
        self.fsuid = fsuid;
    }
    pub(crate) fn set_fsgid(&mut self, fsgid: u32) {
        self.fsgid = fsgid;
    }
    pub(crate) fn set_umask(&mut self, umask: u32) {
        self.umask = umask;
    }
    pub(crate) fn set_supplementary_groups(&mut self, groups: Vec<u32>) {
        self.supplementary_groups_override = Some(groups);
    }
    pub(crate) fn copy_values_from(&mut self, source: &Self) {
        self.ruid = source.ruid;
        self.euid = source.euid;
        self.suid = source.suid;
        self.rgid = source.rgid;
        self.egid = source.egid;
        self.sgid = source.sgid;
        self.fsuid = source.fsuid;
        self.fsgid = source.fsgid;
        self.umask = source.umask;
        self.supplementary_groups_override = source.supplementary_groups_override.clone();
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
    pending_signals: Arc<TaskPendingSignals>,
}

impl TaskShared {
    pub fn new(mm: Arc<Mm>, sighand: Arc<Sighand>) -> Self {
        Self {
            mm,
            sighand,
            pending_signals: Arc::new(TaskPendingSignals::new()),
        }
    }

    pub fn for_new_task_with_mm(
        parent: &Self,
        plan: ClonePlan,
        ids: &ObjectIdRegistry,
        copied_mm: Option<Arc<Mm>>,
    ) -> Result<Self, TaskSharedCloneError> {
        if plan.task() != CloneTaskMode::NewTask {
            return Err(TaskSharedCloneError::ThreadGroupMustReuseTaskShared);
        }
        let mm = match (plan.mm(), copied_mm) {
            (CloneObjectMode::Share, None) => Arc::clone(&parent.mm),
            (CloneObjectMode::Copy, Some(mm)) => mm,
            (CloneObjectMode::Copy, None) => return Err(TaskSharedCloneError::MissingCopiedMm),
            (CloneObjectMode::Share, Some(_)) => {
                return Err(TaskSharedCloneError::UnexpectedCopiedMm);
            }
        };
        let sighand = match plan.sighand() {
            CloneObjectMode::Share => Arc::clone(&parent.sighand),
            CloneObjectMode::Copy => {
                Arc::new(Sighand::for_fork_copy(ids.sighand_id()?, &parent.sighand))
            }
        };
        Ok(Self::new(mm, sighand))
    }

    #[cfg(test)]
    pub(super) fn for_new_task_reference(
        parent: &Self,
        plan: ClonePlan,
        ids: &ObjectIdRegistry,
    ) -> Result<Self, TaskSharedCloneError> {
        let copied_mm = (plan.mm() == CloneObjectMode::Copy)
            .then(|| ids.mm_id().map(Mm::new_reference).map(Arc::new))
            .transpose()?;
        Self::for_new_task_with_mm(parent, plan, ids, copied_mm)
    }

    pub(super) fn for_exec_with_mm(
        caller: &Self,
        ids: &ObjectIdRegistry,
        mm: Arc<Mm>,
    ) -> Result<Self, ObjectIdError> {
        Ok(Self {
            mm,
            // Ignored dispositions survive; caught handlers reset to default.
            // K4 binds this model to the concrete signal backend.
            sighand: Arc::new(Sighand::for_exec(ids.sighand_id()?, &caller.sighand)),
            pending_signals: Arc::clone(&caller.pending_signals),
        })
    }

    pub fn mm(&self) -> Arc<Mm> {
        Arc::clone(&self.mm)
    }

    pub fn sighand(&self) -> Arc<Sighand> {
        Arc::clone(&self.sighand)
    }

    pub fn pending_signals(&self) -> Arc<TaskPendingSignals> {
        Arc::clone(&self.pending_signals)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadSignalState {
    blocked: SigSet,
    pending: SigSet,
    altstack_enabled: bool,
    handler_frame_depth: usize,
}

impl ThreadSignalState {
    pub const fn new(
        blocked: SigSet,
        pending: SigSet,
        altstack_enabled: bool,
        handler_frame_depth: usize,
    ) -> Self {
        Self {
            blocked,
            pending,
            altstack_enabled,
            handler_frame_depth,
        }
    }

    const fn for_fork(caller: Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: SigSet::EMPTY,
            altstack_enabled: caller.altstack_enabled,
            handler_frame_depth: caller.handler_frame_depth,
        }
    }

    const fn for_clone_thread(caller: Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: SigSet::EMPTY,
            altstack_enabled: false,
            handler_frame_depth: 0,
        }
    }

    const fn for_exec(caller: Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: caller.pending,
            altstack_enabled: false,
            handler_frame_depth: 0,
        }
    }

    pub const fn blocked(self) -> SigSet {
        self.blocked
    }

    pub const fn pending(self) -> SigSet {
        self.pending
    }

    pub const fn altstack_enabled(self) -> bool {
        self.altstack_enabled
    }

    pub const fn handler_frame_depth(self) -> usize {
        self.handler_frame_depth
    }
}

impl Default for ThreadSignalState {
    fn default() -> Self {
        Self::new(SigSet::EMPTY, SigSet::EMPTY, false, 0)
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
            CloneObjectMode::Copy => Arc::new(FileTable::for_fork_copy(
                ids.file_table_id()?,
                &parent.files,
            )),
        };
        let fs_context = match plan.fs_context() {
            CloneObjectMode::Share => Arc::clone(&parent.fs_context),
            CloneObjectMode::Copy => Arc::new(FsContext::for_fork_copy(
                ids.fs_context_id()?,
                &parent.fs_context,
            )),
        };
        Ok(Self::new(
            files,
            fs_context,
            Arc::new(Credentials::for_copy(
                ids.credentials_id()?,
                &parent.credentials,
            )),
        ))
    }

    pub(super) fn for_exec(caller: &Self, ids: &ObjectIdRegistry) -> Result<Self, ObjectIdError> {
        Ok(Self::new(
            Arc::new(FileTable::for_exec(ids.file_table_id()?, &caller.files)),
            Arc::clone(&caller.fs_context),
            Arc::clone(&caller.credentials),
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

    pub(super) fn with_credentials(&self, credentials: Arc<Credentials>) -> Self {
        Self::new(
            Arc::clone(&self.files),
            Arc::clone(&self.fs_context),
            credentials,
        )
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
    identity: Mutex<TaskIdentity>,
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
            identity: Mutex::new(TaskIdentity {
                process_group,
                session,
            }),
            lifecycle: Mutex::new(TaskLifecycle::Live),
            shared: ArcSwap::new(shared),
            threads: Mutex::new(BTreeMap::new()),
        }
    }

    pub const fn key(&self) -> TaskKey {
        self.key
    }

    pub(super) fn parent(&self) -> Option<TaskKey> {
        *self.parent.lock()
    }

    pub(super) fn reparent(&self, parent: Option<TaskKey>) {
        *self.parent.lock() = parent;
    }

    pub(super) fn add_child(&self, child: TaskKey) -> bool {
        self.children.lock().insert(child)
    }

    pub(super) fn remove_child(&self, child: TaskKey) -> bool {
        self.children.lock().remove(&child)
    }

    pub(super) fn children(&self) -> Vec<TaskKey> {
        self.children.lock().iter().copied().collect()
    }

    pub(super) fn children_set(&self) -> BTreeSet<TaskKey> {
        self.children.lock().clone()
    }

    pub(super) fn publish_prepared_children(&self, children: BTreeSet<TaskKey>) {
        *self.children.lock() = children;
    }

    pub(super) fn process_group(&self) -> ProcessGroupId {
        self.identity.lock().process_group
    }

    pub(super) fn session(&self) -> SessionId {
        self.identity.lock().session
    }

    /// Registry-transaction publication point. Callers must hold the kernel
    /// registry write lock before taking this one task leaf lock.
    pub(super) fn replace_identity(&self, process_group: ProcessGroupId, session: SessionId) {
        *self.identity.lock() = TaskIdentity {
            process_group,
            session,
        };
    }

    pub(super) fn lifecycle(&self) -> TaskLifecycle {
        *self.lifecycle.lock()
    }

    pub(super) fn begin_exit(&self) -> bool {
        let mut lifecycle = self.lifecycle.lock();
        if *lifecycle == TaskLifecycle::Exiting {
            return false;
        }
        *lifecycle = TaskLifecycle::Exiting;
        true
    }

    pub(super) fn shared(&self) -> Arc<TaskShared> {
        self.shared.load_full()
    }

    pub(super) fn replace_shared(&self, replacement: Arc<TaskShared>) -> Arc<TaskShared> {
        self.shared.swap(replacement)
    }

    pub(super) fn prepare_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
    ) -> ThreadRef {
        Arc::new(Thread {
            key,
            registry_id,
            task_key: self.key,
            task: Arc::downgrade(self),
            resources: ArcSwap::new(resources),
            signal_state: Mutex::new(ThreadSignalState::default()),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
        })
    }

    pub(super) fn prepare_clone_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller_signal_state: ThreadSignalState,
    ) -> ThreadRef {
        Arc::new(Thread {
            key,
            registry_id,
            task_key: self.key,
            task: Arc::downgrade(self),
            resources: ArcSwap::new(resources),
            signal_state: Mutex::new(ThreadSignalState::for_clone_thread(caller_signal_state)),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
        })
    }

    pub(super) fn prepare_fork_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller_signal_state: ThreadSignalState,
    ) -> ThreadRef {
        Arc::new(Thread {
            key,
            registry_id,
            task_key: self.key,
            task: Arc::downgrade(self),
            resources: ArcSwap::new(resources),
            signal_state: Mutex::new(ThreadSignalState::for_fork(caller_signal_state)),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
        })
    }

    pub(super) fn prepare_exec_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller: &ThreadRef,
    ) -> ThreadRef {
        Arc::new(Thread {
            key,
            registry_id,
            task_key: self.key,
            task: Arc::downgrade(self),
            resources: ArcSwap::new(resources),
            signal_state: Mutex::new(ThreadSignalState::for_exec(caller.signal_state())),
            revision: ObjectRevision::new(),
            runner_gate: Arc::clone(&caller.runner_gate),
        })
    }

    /// Publish a prepared thread. Kernel operations call this only while the
    /// registry write lock is held, after every other fallible preparation.
    pub(super) fn publish_thread(&self, thread: ThreadRef) -> Result<(), ObjectGraphError> {
        if thread.task_key != self.key {
            return Err(ObjectGraphError::WrongThreadTask);
        }
        let key = thread.key;
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
        threads.insert(key.tid, (key, thread));
        Ok(())
    }

    pub(super) fn attach_fork_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller_signal_state: ThreadSignalState,
    ) -> Result<ThreadRef, ObjectGraphError> {
        let thread = self.prepare_fork_thread(key, registry_id, resources, caller_signal_state);
        self.publish_thread(Arc::clone(&thread))?;
        Ok(thread)
    }

    pub(super) fn attach_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
    ) -> Result<ThreadRef, ObjectGraphError> {
        let thread = self.prepare_thread(key, registry_id, resources);
        self.publish_thread(Arc::clone(&thread))?;
        Ok(thread)
    }

    pub(super) fn prepare_exec_thread_set(
        &self,
        replacement: ThreadRef,
    ) -> Result<PreparedThreadSet, ObjectGraphError> {
        if replacement.task_key != self.key {
            return Err(ObjectGraphError::WrongThreadTask);
        }
        let leader_tid = LinuxTid::for_task_leader(self.key.id);
        if replacement.key.tid != leader_tid {
            return Err(ObjectGraphError::LeaderTidMismatch {
                task: self.key.id,
                tid: replacement.key.tid,
            });
        }
        Ok(PreparedThreadSet {
            task_key: self.key,
            threads: BTreeMap::from([(leader_tid, (replacement.key, replacement))]),
        })
    }

    pub(super) fn publish_exec_thread_set(
        &self,
        prepared: PreparedThreadSet,
    ) -> BTreeMap<LinuxTid, (ThreadKey, ThreadRef)> {
        debug_assert_eq!(prepared.task_key, self.key);
        let mut threads = self.threads.lock();
        std::mem::replace(&mut *threads, prepared.threads)
    }

    pub(super) fn drain_exec_siblings(&self, caller: ThreadKey) -> ExecDrain {
        let gates = self
            .threads
            .lock()
            .values()
            .filter(|(key, _)| *key != caller)
            .map(|(_, thread)| Arc::clone(&thread.runner_gate))
            .collect();
        ExecDrain::new(gates)
    }

    pub(super) fn thread_keys(&self) -> Vec<ThreadKey> {
        self.threads.lock().values().map(|(key, _)| *key).collect()
    }

    pub(super) fn thread(&self, tid: LinuxTid) -> Option<ThreadRef> {
        self.threads
            .lock()
            .get(&tid)
            .map(|(_, thread)| Arc::clone(thread))
    }

    pub(super) fn retire_thread(&self, key: ThreadKey) -> Option<ThreadRef> {
        let mut threads = self.threads.lock();
        if threads
            .get(&key.tid)
            .is_none_or(|(published_key, _)| *published_key != key)
        {
            return None;
        }
        threads.remove(&key.tid).map(|(_, thread)| thread)
    }

    pub(super) fn live_thread_count(&self) -> usize {
        self.threads.lock().len()
    }

    pub(super) fn parent_until(&self, deadline: std::time::Instant) -> Option<Option<TaskKey>> {
        self.parent.try_lock_until(deadline).map(|parent| *parent)
    }

    pub(super) fn children_until(&self, deadline: std::time::Instant) -> Option<Vec<TaskKey>> {
        self.children
            .try_lock_until(deadline)
            .map(|children| children.iter().copied().collect())
    }

    pub(super) fn identity_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(ProcessGroupId, SessionId)> {
        self.identity
            .try_lock_until(deadline)
            .map(|identity| (identity.process_group, identity.session))
    }

    pub(super) fn lifecycle_until(&self, deadline: std::time::Instant) -> Option<TaskLifecycle> {
        self.lifecycle.try_lock_until(deadline).map(|state| *state)
    }

    pub(super) fn threads_until(&self, deadline: std::time::Instant) -> Option<Vec<ThreadRef>> {
        self.threads.try_lock_until(deadline).map(|threads| {
            threads
                .values()
                .map(|(_, thread)| Arc::clone(thread))
                .collect()
        })
    }
}

#[derive(Debug)]
pub(super) struct PreparedThreadSet {
    task_key: TaskKey,
    threads: BTreeMap<LinuxTid, (ThreadKey, ThreadRef)>,
}

impl PreparedThreadSet {
    pub(super) const fn task_key(&self) -> TaskKey {
        self.task_key
    }
}

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
struct RunnerGate {
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

pub(super) struct ExecDrain {
    gates: Vec<Arc<RunnerGate>>,
    resolved: bool,
}

impl ExecDrain {
    fn new(gates: Vec<Arc<RunnerGate>>) -> Self {
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

    pub(super) fn resume_and_wait(mut self) {
        for gate in &self.gates {
            gate.resume_and_wait();
        }
        self.resolved = true;
    }

    pub(super) fn terminate_and_wait(mut self) {
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

#[derive(Debug)]
pub struct Thread {
    key: ThreadKey,
    registry_id: ThreadId,
    task_key: TaskKey,
    task: Weak<Task>,
    resources: ArcSwap<ThreadResources>,
    signal_state: Mutex<ThreadSignalState>,
    revision: ObjectRevision,
    runner_gate: Arc<RunnerGate>,
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

    pub fn signal_state(&self) -> ThreadSignalState {
        *self.signal_state.lock()
    }

    pub fn replace_signal_state(&self, replacement: ThreadSignalState) {
        let mut state = self.signal_state.lock();
        *state = replacement;
        self.revision.publish();
    }

    pub fn bind_runner(self: &Arc<Self>) -> Result<ThreadRunner, ObjectGraphError> {
        self.runner_gate.bind(self.key, Arc::clone(self))
    }

    pub(super) fn transfer_runner_to(&self, replacement: &ThreadRef) {
        debug_assert!(Arc::ptr_eq(&self.runner_gate, &replacement.runner_gate));
        self.runner_gate.transfer_owner(self.key, replacement.key);
    }

    pub fn task(&self) -> Option<TaskRef> {
        self.task.upgrade()
    }

    pub(super) fn resources(&self) -> Arc<ThreadResources> {
        self.resources.load_full()
    }

    pub(super) fn snapshot_signal_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, ThreadSignalState)> {
        let state = self.signal_state.try_lock_until(deadline)?;
        Some((self.revision.load(), *state))
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }

    pub(super) fn replace_resources(
        &self,
        replacement: Arc<ThreadResources>,
    ) -> Arc<ThreadResources> {
        let previous = self.resources.swap(replacement);
        self.revision.publish();
        previous
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
    #[error("a copied mm must be prepared before fork publication")]
    MissingCopiedMm,
    #[error("a shared-mm clone cannot publish a replacement mm")]
    UnexpectedCopiedMm,
    #[error(transparent)]
    ObjectId(#[from] ObjectIdError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObjectGraphError {
    #[error("first thread TID {tid:?} must match task leader {task:?}")]
    LeaderTidMismatch { task: TaskId, tid: LinuxTid },
    #[error("thread TID {0:?} is already attached")]
    DuplicateThread(LinuxTid),
    #[error("prepared thread belongs to a different task")]
    WrongThreadTask,
    #[error("thread {0:?} already has a bound backend runner")]
    RunnerAlreadyBound(ThreadKey),
    #[error("thread {0:?} is draining and cannot bind a backend runner")]
    RunnerDraining(ThreadKey),
    #[error("thread {0:?} no longer owns its backend runner gate")]
    RunnerOwnershipChanged(ThreadKey),
    #[error("thread {0:?} does not share this backend runner gate")]
    RunnerGateMismatch(ThreadKey),
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
            let mm = Arc::new(Mm::new_reference(ids.mm_id().expect("mm ID")));
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
                Arc::new(Credentials::root(
                    ids.credentials_id().expect("credentials ID"),
                )),
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
        parent.fs_context().set_cwd("/parent/cwd".to_owned());
        parent
            .fs_context()
            .set_chroot_root(Some("/parent/root".to_owned()));
        let child = ThreadResources::for_clone(&parent, plan, &fixture.ids).expect("resources");

        assert!(!Arc::ptr_eq(&parent.files(), &child.files()));
        assert!(!Arc::ptr_eq(&parent.fs_context(), &child.fs_context()));
        assert_eq!(child.fs_context().cwd(), "/parent/cwd");
        assert_eq!(
            child.fs_context().chroot_root().as_deref(),
            Some("/parent/root")
        );
        child.fs_context().set_cwd("/child/cwd".to_owned());
        assert_eq!(parent.fs_context().cwd(), "/parent/cwd");
        assert!(!Arc::ptr_eq(&parent.credentials(), &child.credentials()));
        assert_eq!(parent.credentials().ruid(), child.credentials().ruid());
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
        let child_shared = TaskShared::for_new_task_reference(&parent_shared, plan, &fixture.ids)
            .expect("shared resources");
        let parent_resources = fixture.leader.resources();
        parent_resources
            .fs_context()
            .set_cwd("/shared/cwd".to_owned());
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
        child_resources
            .fs_context()
            .set_cwd("/shared/updated".to_owned());
        assert_eq!(parent_resources.fs_context().cwd(), "/shared/updated");
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
            TaskShared::for_new_task_reference(&fixture.task.shared(), plan, &fixture.ids),
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
