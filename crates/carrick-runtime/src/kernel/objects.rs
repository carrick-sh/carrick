use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use carrick_abi::keyring::{KeyRequestDefault, KeySerial};
use carrick_abi::{
    LINUX_RLIM_INFINITY, LinuxGuestAbi, LinuxResource, LinuxRlimit, LinuxSigaction,
    LinuxSigaltstack, LinuxSiginfo, NsGid, NsUid, SigSet,
};
use carrick_hal::ThreadId;
use carrick_hal::threaded::GuestCpuState;
use parking_lot::{Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::linux_abi::LINUX_DEFAULT_UMASK;
use crate::namespace::process::{CapabilitySet, ProcessCredsNs};
use crate::namespace::user::UserNs;

use super::address::MmBackend;
use super::clone_plan::{CloneObjectMode, ClonePlan, CloneTaskMode};
use super::crash_capture::{CrashCaptureGeneration, CrashRegisterVote};
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

pub(super) struct MmIoStateSnapshot {
    pub(super) revision: u64,
    pub(super) io_uring_mappings: Vec<crate::dispatch::ioring::IoUringMappingSnapshot>,
    pub(super) legacy_aio_context_count: usize,
    pub(super) next_legacy_aio_context: u64,
}

pub struct Mm {
    id: MmId,
    backend: Option<Arc<dyn MmBackend>>,
    io_uring_mappings: RwLock<Vec<crate::dispatch::ioring::IoUringMapping>>,
    legacy_aio_contexts: RwLock<BTreeSet<crate::dispatch::LegacyAioContextId>>,
    next_legacy_aio_context: AtomicU64,
    revision: ObjectRevision,
}

impl Mm {
    /// Identity-only constructor for the in-crate K1 reference model. Runtime
    /// adapters must use `with_backend`; callers outside `kernel` cannot create
    /// an observation-less mm.
    pub(super) fn new_reference(id: MmId) -> Self {
        Self {
            id,
            backend: None,
            io_uring_mappings: RwLock::new(Vec::new()),
            legacy_aio_contexts: RwLock::new(BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            revision: ObjectRevision::new(),
        }
    }

    pub fn with_backend(id: MmId, backend: Arc<dyn MmBackend>) -> Self {
        Self {
            id,
            backend: Some(backend),
            io_uring_mappings: RwLock::new(Vec::new()),
            legacy_aio_contexts: RwLock::new(BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            revision: ObjectRevision::new(),
        }
    }

    #[cfg(test)]
    pub(super) fn new_reference_for_fork(id: MmId, parent: &Self) -> Self {
        Self {
            id,
            backend: None,
            io_uring_mappings: RwLock::new(parent.io_uring_mappings.read().clone()),
            legacy_aio_contexts: RwLock::new(BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            revision: ObjectRevision::new(),
        }
    }

    pub fn with_backend_for_fork(id: MmId, backend: Arc<dyn MmBackend>, parent: &Self) -> Self {
        Self {
            id,
            backend: Some(backend),
            io_uring_mappings: RwLock::new(parent.io_uring_mappings.read().clone()),
            legacy_aio_contexts: RwLock::new(BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            revision: ObjectRevision::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn read_io_uring_mappings(
        &self,
    ) -> RwLockReadGuard<'_, Vec<crate::dispatch::ioring::IoUringMapping>> {
        self.io_uring_mappings.read()
    }

    pub(crate) fn replace_io_uring_mappings(
        &self,
        start: u64,
        len: u64,
        replacement: Option<crate::dispatch::ioring::IoUringMapping>,
    ) {
        let Some(end) = start.checked_add(len) else {
            std::process::abort();
        };
        let mut mappings = self.io_uring_mappings.write();
        let mut retained = Vec::with_capacity(mappings.len().saturating_add(2));
        for mapping in mappings.drain(..) {
            let mapping_start = mapping.start;
            let mapping_end = mapping.end;
            if mapping_start >= end || mapping_end <= start {
                retained.push(mapping);
                continue;
            }
            if mapping_start < start {
                retained.push(mapping.fragment(mapping_start, start));
            }
            if end < mapping_end {
                retained.push(mapping.fragment(end, mapping_end));
            }
        }
        if let Some(replacement) = replacement {
            retained.push(replacement);
        }
        retained.sort_unstable_by_key(|mapping| mapping.start);
        if *mappings != retained {
            *mappings = retained;
            self.revision.publish();
        }
    }

    pub(crate) fn io_uring_mapping_overlaps(&self, start: u64, len: u64) -> bool {
        let end = start.saturating_add(len);
        self.io_uring_mappings
            .read()
            .iter()
            .any(|mapping| mapping.start < end && start < mapping.end)
    }

    pub(crate) fn copy_io_uring_mappings_for_host_fork(&self, inherited: &Self) {
        let mut mappings = self.io_uring_mappings.write();
        if !mappings.is_empty() {
            tracing::error!(mm = ?self.id, "host-fork mm io state replacement was not empty");
            std::process::abort();
        }
        mappings.clone_from(&inherited.io_uring_mappings.read());
        if !mappings.is_empty() {
            self.revision.publish();
        }
    }

    pub(super) fn clear_io_uring_mappings(&self) {
        let mut mappings = self.io_uring_mappings.write();
        if !mappings.is_empty() {
            mappings.clear();
            self.revision.publish();
        }
    }

    pub(crate) fn read_legacy_aio_contexts(
        &self,
    ) -> RwLockReadGuard<'_, BTreeSet<crate::dispatch::LegacyAioContextId>> {
        self.legacy_aio_contexts.read()
    }

    pub(crate) fn write_legacy_aio_contexts(&self) -> MmLegacyAioWriteGuard<'_> {
        MmLegacyAioWriteGuard {
            guard: self.legacy_aio_contexts.write(),
            revision: &self.revision,
        }
    }

    pub(crate) fn allocate_legacy_aio_context(&self) -> u64 {
        let raw = self.next_legacy_aio_context.fetch_add(1, Ordering::Relaxed);
        self.revision.publish();
        raw
    }

    pub(super) fn io_state_snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<MmIoStateSnapshot> {
        let mappings = self.io_uring_mappings.try_read_until(deadline)?;
        let contexts = self.legacy_aio_contexts.try_read_until(deadline)?;
        let mut io_uring_mappings = mappings
            .iter()
            .map(crate::dispatch::ioring::IoUringMapping::snapshot)
            .collect::<Vec<_>>();
        io_uring_mappings.sort_unstable_by_key(|mapping| mapping.start);
        Some(MmIoStateSnapshot {
            revision: self.revision.load(),
            io_uring_mappings,
            legacy_aio_context_count: contexts.len(),
            next_legacy_aio_context: self.next_legacy_aio_context.load(Ordering::Relaxed),
        })
    }

    pub const fn id(&self) -> MmId {
        self.id
    }

    pub fn backend(&self) -> Option<&Arc<dyn MmBackend>> {
        self.backend.as_ref()
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

impl std::fmt::Debug for Mm {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Mm")
            .field("id", &self.id)
            .field("has_backend", &self.backend.is_some())
            .field(
                "legacy_aio_contexts",
                &self.legacy_aio_contexts.read().len(),
            )
            .finish()
    }
}

pub(crate) struct MmLegacyAioWriteGuard<'a> {
    guard: RwLockWriteGuard<'a, BTreeSet<crate::dispatch::LegacyAioContextId>>,
    revision: &'a ObjectRevision,
}

impl Deref for MmLegacyAioWriteGuard<'_> {
    type Target = BTreeSet<crate::dispatch::LegacyAioContextId>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for MmLegacyAioWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for MmLegacyAioWriteGuard<'_> {
    fn drop(&mut self) {
        self.revision.publish();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalDisposition {
    Default,
    Ignore,
    Caught,
}

/// Complete Linux signal-action authority shared according to
/// `CLONE_SIGHAND`. An absent entry is `SIG_DFL`; stored records retain every
/// guest-visible field needed for delivery and `rt_sigaction` round trips.
#[derive(Debug)]
pub struct Sighand {
    id: SighandId,
    actions: Mutex<BTreeMap<LinuxSignal, LinuxSigaction>>,
    revision: ObjectRevision,
}

impl Sighand {
    pub fn new(id: SighandId) -> Self {
        Self {
            id,
            actions: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        }
    }

    fn for_fork_copy(id: SighandId, parent: &Self) -> Self {
        Self {
            id,
            actions: Mutex::new(parent.actions.lock().clone()),
            revision: ObjectRevision::new(),
        }
    }

    pub(crate) fn for_exec(id: SighandId, caller: &Self) -> Self {
        let actions = caller
            .actions
            .lock()
            .iter()
            .filter_map(|(signal, action)| {
                (action.sa_handler == crate::linux_abi::LINUX_SIG_IGN).then_some((*signal, *action))
            })
            .collect();
        Self {
            id,
            actions: Mutex::new(actions),
            revision: ObjectRevision::new(),
        }
    }

    pub const fn id(&self) -> SighandId {
        self.id
    }

    /// Install one complete Linux action. Explicit `SIG_DFL` records retain
    /// their flags, mask, and restorer for exact `rt_sigaction` round trips.
    pub fn install_action(&self, signal: LinuxSignal, action: LinuxSigaction) {
        let mut actions = self.actions.lock();
        if actions.insert(signal, action) != Some(action) {
            self.revision.publish();
        }
    }

    pub fn action(&self, signal: LinuxSignal) -> LinuxSigaction {
        self.action_entry(signal)
            .unwrap_or_else(LinuxSigaction::empty)
    }

    pub fn action_entry(&self, signal: LinuxSignal) -> Option<LinuxSigaction> {
        self.actions.lock().get(&signal).copied()
    }

    pub fn actions(&self) -> Vec<(LinuxSignal, LinuxSigaction)> {
        self.actions
            .lock()
            .iter()
            .map(|(signal, action)| (*signal, *action))
            .collect()
    }

    pub fn replace_actions(&self, replacement: Vec<(LinuxSignal, LinuxSigaction)>) {
        let replacement = replacement.into_iter().collect::<BTreeMap<_, _>>();
        let mut actions = self.actions.lock();
        if *actions != replacement {
            *actions = replacement;
            self.revision.publish();
        }
    }

    pub fn disposition(&self, signal: LinuxSignal) -> SignalDisposition {
        match self.action(signal).sa_handler {
            crate::linux_abi::LINUX_SIG_DFL => SignalDisposition::Default,
            crate::linux_abi::LINUX_SIG_IGN => SignalDisposition::Ignore,
            _ => SignalDisposition::Caught,
        }
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, Vec<(LinuxSignal, LinuxSigaction)>)> {
        let actions = self.actions.try_lock_until(deadline)?;
        Some((
            self.revision.load(),
            actions
                .iter()
                .map(|(signal, action)| (*signal, *action))
                .collect(),
        ))
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDescriptionBackingKind {
    Closed,
    File,
    Directory,
    SyntheticFile,
    SyntheticDevice,
    EventFd,
    TimerFd,
    Epoll,
    Pidfd,
    PipeReader,
    PipeWriter,
    HostPipe,
    HostFile,
    HostSocket,
    Inotify,
    Fanotify,
    SignalFd,
    Netlink,
    Mqueue,
    BpfMap,
    BpfProg,
    PerfEvent,
    IoUring,
    /// A new-mount-API filesystem context (`fsopen(2)`/`fspick(2)`).
    FsContext,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenDescriptionBackingSnapshot {
    pub kind: FileDescriptionBackingKind,
    pub status_flags: Option<u64>,
    pub offset: Option<u64>,
    pub host_fd: Option<i32>,
    pub path: Option<String>,
    pub pipe_id: Option<u64>,
    pub logical_fd_refs: usize,
    pub epoll_interests: Vec<FileDescriptionId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileDescriptionBackingSnapshot {
    Open(OpenDescriptionBackingSnapshot),
    IoUring(crate::dispatch::ioring::IoUringDescriptionSnapshot),
}

impl FileDescriptionBackingSnapshot {
    pub(crate) const fn kind(&self) -> FileDescriptionBackingKind {
        match self {
            Self::Open(snapshot) => snapshot.kind,
            Self::IoUring(_) => FileDescriptionBackingKind::IoUring,
        }
    }

    pub(crate) const fn logical_fd_refs(&self) -> usize {
        match self {
            Self::Open(snapshot) => snapshot.logical_fd_refs,
            Self::IoUring(snapshot) => snapshot.logical_fd_refs,
        }
    }

    pub(crate) fn epoll_interests(&self) -> &[FileDescriptionId] {
        match self {
            Self::Open(snapshot) => &snapshot.epoll_interests,
            Self::IoUring(_) => &[],
        }
    }
}

pub(crate) trait FileDescriptionBacking: Any + Send + Sync {
    fn is_epoll(&self) -> bool;

    fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileDescriptionBackingSnapshot>;

    fn epoll_wake_fd(&self) -> Option<i32>;

    fn retain_fd_ref(&self);

    fn release_fd_ref(&self);

    fn fd_ref_count(&self) -> usize;

    fn as_any(&self) -> &dyn Any;
}

struct OpaqueFileDescriptionBacking(Arc<dyn FileDescriptionBacking>);

impl OpaqueFileDescriptionBacking {
    fn new<T>(backing: Arc<T>) -> Self
    where
        T: FileDescriptionBacking,
    {
        Self(backing)
    }

    fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: FileDescriptionBacking,
    {
        self.0.as_any().downcast_ref()
    }
}

impl std::fmt::Debug for OpaqueFileDescriptionBacking {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpaqueFileDescriptionBacking")
    }
}

#[derive(Debug)]
enum FileDescriptionKind {
    Concrete(OpaqueFileDescriptionBacking),
    Regular,
    Epoll(Mutex<BTreeMap<FileDescriptionId, Weak<FileDescription>>>),
}

/// Open-file-description identity. Epoll edges are weak and stable-keyed so
/// descriptor graphs cannot create ownership cycles.
type FileDescriptionObservation = (
    u64,
    bool,
    Vec<FileDescriptionId>,
    Option<FileDescriptionBackingSnapshot>,
    Vec<(FileDescriptionId, i32)>,
);

#[derive(Debug)]
pub struct FileDescription {
    id: FileDescriptionId,
    kind: FileDescriptionKind,
    epoll_registrations: Mutex<BTreeMap<(FileDescriptionId, i32), Weak<FileDescription>>>,
    revision: ObjectRevision,
}

impl FileDescription {
    pub(crate) fn concrete<T>(backing: Arc<T>) -> Result<Self, ObjectIdError>
    where
        T: FileDescriptionBacking,
    {
        Ok(Self {
            id: super::ids::allocate_file_description_id()?,
            kind: FileDescriptionKind::Concrete(OpaqueFileDescriptionBacking::new(backing)),
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn concrete_restored<T>(
        stable_id: u64,
        backing: Arc<T>,
    ) -> Result<Self, ObjectIdError>
    where
        T: FileDescriptionBacking,
    {
        Ok(Self {
            id: super::ids::restore_file_description_id(stable_id)?,
            kind: FileDescriptionKind::Concrete(OpaqueFileDescriptionBacking::new(backing)),
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        })
    }

    pub const fn regular(id: FileDescriptionId) -> Self {
        Self {
            id,
            kind: FileDescriptionKind::Regular,
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        }
    }

    pub fn epoll(id: FileDescriptionId) -> Self {
        Self {
            id,
            kind: FileDescriptionKind::Epoll(Mutex::new(BTreeMap::new())),
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        }
    }

    pub const fn id(&self) -> FileDescriptionId {
        self.id
    }

    pub fn is_epoll(&self) -> bool {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.is_epoll(),
            FileDescriptionKind::Regular => false,
            FileDescriptionKind::Epoll(_) => true,
        }
    }

    pub(crate) fn register_epoll_owner(self: &Arc<Self>, owner: &Arc<Self>, registration_fd: i32) {
        self.epoll_registrations
            .lock()
            .insert((owner.id(), registration_fd), Arc::downgrade(owner));
        self.revision.publish();
    }

    pub(crate) fn unregister_epoll_owner(&self, owner: &Arc<Self>, registration_fd: i32) {
        if self
            .epoll_registrations
            .lock()
            .remove(&(owner.id(), registration_fd))
            .is_some()
        {
            self.revision.publish();
        }
    }

    pub(crate) fn take_epoll_owners(&self) -> Vec<(Arc<Self>, i32)> {
        let registrations = std::mem::take(&mut *self.epoll_registrations.lock());
        if !registrations.is_empty() {
            self.revision.publish();
        }
        registrations
            .into_iter()
            .filter_map(|((_, fd), owner)| owner.upgrade().map(|owner| (owner, fd)))
            .collect()
    }

    pub(crate) fn concrete_backing<T>(&self) -> Option<&T>
    where
        T: FileDescriptionBacking,
    {
        let FileDescriptionKind::Concrete(backing) = &self.kind else {
            return None;
        };
        backing.downcast_ref()
    }

    pub(crate) fn publish_mutation(&self) {
        self.revision.publish();
    }

    pub(crate) fn epoll_wake_fd(&self) -> Option<i32> {
        let FileDescriptionKind::Concrete(backing) = &self.kind else {
            return None;
        };
        backing.0.epoll_wake_fd()
    }

    pub(crate) fn retain_fd_ref(&self) {
        let FileDescriptionKind::Concrete(backing) = &self.kind else {
            return;
        };
        backing.0.retain_fd_ref();
        self.revision.publish();
    }

    pub(crate) fn release_fd_ref(&self) {
        let FileDescriptionKind::Concrete(backing) = &self.kind else {
            return;
        };
        backing.0.release_fd_ref();
        self.revision.publish();
    }

    pub(crate) fn fd_ref_count(&self) -> usize {
        let FileDescriptionKind::Concrete(backing) = &self.kind else {
            return 0;
        };
        backing.0.fd_ref_count()
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
    ) -> Option<FileDescriptionObservation> {
        let owners = self.epoll_registrations.try_lock_until(deadline)?;
        let mut owners = owners
            .iter()
            .filter_map(|(&(owner, fd), weak)| (weak.strong_count() != 0).then_some((owner, fd)))
            .collect::<Vec<_>>();
        owners.sort_unstable();
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => {
                let state = backing.0.snapshot_until(deadline)?;
                let is_epoll = state.kind() == FileDescriptionBackingKind::Epoll;
                let interests = state.epoll_interests().to_vec();
                Some((
                    self.revision.load(),
                    is_epoll,
                    interests,
                    Some(state),
                    owners,
                ))
            }
            FileDescriptionKind::Regular => {
                Some((self.revision.load(), false, Vec::new(), None, owners))
            }
            FileDescriptionKind::Epoll(interests) => {
                let interests = interests.try_lock_until(deadline)?;
                Some((
                    self.revision.load(),
                    true,
                    interests
                        .iter()
                        .filter_map(|(id, target)| (target.strong_count() != 0).then_some(*id))
                        .collect(),
                    None,
                    owners,
                ))
            }
        }
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileDescriptionObservation> {
        self.snapshot_until(deadline)
    }
}

#[derive(Clone, Debug)]
pub struct FileSlot {
    pub(crate) description: Arc<FileDescription>,
    pub(crate) fd_flags: u64,
}

impl FileSlot {
    pub(crate) fn new(description: Arc<FileDescription>, fd_flags: u64) -> Self {
        Self {
            description,
            fd_flags,
        }
    }

    pub fn description(&self) -> Arc<FileDescription> {
        Arc::clone(&self.description)
    }

    pub fn close_on_exec(&self) -> bool {
        carrick_abi::LinuxFdFlags::from_bits_truncate(self.fd_flags)
            .contains(carrick_abi::LinuxFdFlags::CLOEXEC)
    }
}

pub(super) struct FileTableStateSnapshot {
    pub(super) revision: u64,
    pub(super) functional_refs_active: bool,
    pub(super) slots: Vec<(FileSlotNumber, FileSlot)>,
    pub(super) next_fd: i32,
    pub(super) stdio_cloexec: [bool; 3],
    pub(super) closed_stdio: [bool; 3],
    pub(super) fd_open_paths: Vec<(FileSlotNumber, String)>,
    pub(super) splice_pushback_description_ids: Vec<FileDescriptionId>,
    pub(super) epoll_fds: Vec<FileSlotNumber>,
}

#[derive(Debug, Default)]
struct FileTableFunctionalState {
    accepting: bool,
    frozen: bool,
    active_uses: usize,
    active_mutations: usize,
}

#[derive(Debug)]
struct FileTableFunctionalGate {
    state: Mutex<FileTableFunctionalState>,
    changed: Condvar,
}

impl FileTableFunctionalGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(FileTableFunctionalState {
                accepting: true,
                ..FileTableFunctionalState::default()
            }),
            changed: Condvar::new(),
        }
    }

    fn acquire_use(self: &Arc<Self>) -> Option<FileTableFunctionalLease> {
        let mut state = self.state.lock();
        while state.accepting && state.frozen {
            self.changed.wait(&mut state);
        }
        if !state.accepting {
            return None;
        }
        state.active_uses = state.active_uses.checked_add(1)?;
        Some(FileTableFunctionalLease {
            gate: Arc::clone(self),
        })
    }

    fn acquire_mutation(self: &Arc<Self>) -> Option<FileTableMutationLease> {
        let mut state = self.state.lock();
        while state.accepting && state.frozen {
            self.changed.wait(&mut state);
        }
        if !state.accepting {
            return None;
        }
        state.active_mutations = state.active_mutations.checked_add(1)?;
        Some(FileTableMutationLease {
            gate: Arc::clone(self),
        })
    }

    fn freeze(self: &Arc<Self>) -> Option<FileTableExecFreeze> {
        let mut state = self.state.lock();
        while state.accepting && state.frozen {
            self.changed.wait(&mut state);
        }
        if !state.accepting {
            return None;
        }
        state.frozen = true;
        while state.active_uses != 0 || state.active_mutations != 0 {
            self.changed.wait(&mut state);
        }
        Some(FileTableExecFreeze {
            gate: Arc::clone(self),
            active: true,
        })
    }

    #[cfg(test)]
    fn is_frozen(&self) -> bool {
        self.state.lock().frozen
    }

    fn retire(&self) -> bool {
        let mut state = self.state.lock();
        if !state.accepting {
            return false;
        }
        state.accepting = false;
        self.changed.notify_all();
        while state.active_uses != 0 || state.active_mutations != 0 {
            self.changed.wait(&mut state);
        }
        true
    }
}

pub(crate) struct FileTableFunctionalLease {
    gate: Arc<FileTableFunctionalGate>,
}

impl Drop for FileTableFunctionalLease {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        state.active_uses = state.active_uses.checked_sub(1).unwrap_or_else(|| {
            tracing::error!("FileTable functional lease underflow");
            std::process::abort();
        });
        self.gate.changed.notify_all();
    }
}

struct FileTableMutationLease {
    gate: Arc<FileTableFunctionalGate>,
}

impl Drop for FileTableMutationLease {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        state.active_mutations = state.active_mutations.checked_sub(1).unwrap_or_else(|| {
            tracing::error!("FileTable mutation lease underflow");
            std::process::abort();
        });
        self.gate.changed.notify_all();
    }
}

pub(super) struct FileTableExecFreeze {
    gate: Arc<FileTableFunctionalGate>,
    active: bool,
}

impl Drop for FileTableExecFreeze {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.gate.state.lock();
        state.frozen = false;
        self.gate.changed.notify_all();
        self.active = false;
    }
}

#[derive(Debug)]
pub struct FileTable {
    id: FileTableId,
    open_files: RwLock<HashMap<i32, FileSlot>>,
    next_fd: Mutex<i32>,
    stdio_cloexec: Mutex<[bool; 3]>,
    closed_stdio: Mutex<[bool; 3]>,
    fd_open_paths: RwLock<HashMap<i32, String>>,
    splice_pushback: Mutex<HashMap<FileDescriptionId, Arc<Mutex<crate::dispatch::SplicePushback>>>>,
    epoll_fds: RwLock<BTreeSet<i32>>,
    epoll_wake_registry: crate::dispatch::EpollWakeRegistry,
    functional_gate: Arc<FileTableFunctionalGate>,
    functional_refs_active: AtomicBool,
    revision: ObjectRevision,
}

impl FileTable {
    pub fn new(id: FileTableId) -> Self {
        Self {
            id,
            open_files: RwLock::new(HashMap::new()),
            next_fd: Mutex::new(3),
            stdio_cloexec: Mutex::new([false; 3]),
            closed_stdio: Mutex::new([false; 3]),
            fd_open_paths: RwLock::new(HashMap::new()),
            splice_pushback: Mutex::new(HashMap::new()),
            epoll_fds: RwLock::new(BTreeSet::new()),
            epoll_wake_registry: crate::dispatch::new_epoll_wake_registry(),
            functional_gate: Arc::new(FileTableFunctionalGate::new()),
            functional_refs_active: AtomicBool::new(true),
            revision: ObjectRevision::new(),
        }
    }

    pub(super) fn for_fork_copy(id: FileTableId, parent: &Self) -> Self {
        let open_files = parent.open_files.read().clone();
        for slot in open_files.values() {
            slot.description.retain_fd_ref();
        }
        let epoll_wake_registry = crate::dispatch::new_epoll_wake_registry();
        for slot in open_files.values() {
            if let Some(wake_fd) = slot.description.epoll_wake_fd() {
                crate::dispatch::register_epoll_kqueue(&epoll_wake_registry, wake_fd);
            }
        }
        Self {
            id,
            open_files: RwLock::new(open_files),
            next_fd: Mutex::new(*parent.next_fd.lock()),
            stdio_cloexec: Mutex::new(*parent.stdio_cloexec.lock()),
            closed_stdio: Mutex::new(*parent.closed_stdio.lock()),
            fd_open_paths: RwLock::new(parent.fd_open_paths.read().clone()),
            splice_pushback: Mutex::new(parent.splice_pushback.lock().clone()),
            epoll_fds: RwLock::new(parent.epoll_fds.read().clone()),
            epoll_wake_registry,
            functional_gate: Arc::new(FileTableFunctionalGate::new()),
            functional_refs_active: AtomicBool::new(true),
            revision: ObjectRevision::new(),
        }
    }

    fn for_exec(id: FileTableId, caller: &Self) -> Self {
        let open_files: HashMap<_, _> = caller
            .open_files
            .read()
            .iter()
            .filter_map(|(number, slot)| (!slot.close_on_exec()).then_some((*number, slot.clone())))
            .collect();
        for slot in open_files.values() {
            slot.description.retain_fd_ref();
        }
        let mut closed_stdio = *caller.closed_stdio.lock();
        for (closed, close_on_exec) in closed_stdio
            .iter_mut()
            .zip(caller.stdio_cloexec.lock().iter())
        {
            *closed |= *close_on_exec;
        }
        let epoll_wake_registry = crate::dispatch::new_epoll_wake_registry();
        for slot in open_files.values() {
            if let Some(wake_fd) = slot.description.epoll_wake_fd() {
                crate::dispatch::register_epoll_kqueue(&epoll_wake_registry, wake_fd);
            }
        }
        let next_fd = *caller.next_fd.lock();
        let fd_open_paths = caller
            .fd_open_paths
            .read()
            .iter()
            .filter_map(|(fd, path)| open_files.contains_key(fd).then_some((*fd, path.clone())))
            .collect();
        let surviving_descriptions = open_files
            .values()
            .map(|slot| slot.description.id())
            .collect::<BTreeSet<_>>();
        let splice_pushback = caller
            .splice_pushback
            .lock()
            .iter()
            .filter_map(|(description, pushback)| {
                surviving_descriptions
                    .contains(description)
                    .then_some((*description, Arc::clone(pushback)))
            })
            .collect();
        let epoll_fds = caller
            .epoll_fds
            .read()
            .iter()
            .filter(|fd| open_files.contains_key(fd))
            .copied()
            .collect();
        Self {
            id,
            open_files: RwLock::new(open_files),
            next_fd: Mutex::new(next_fd),
            stdio_cloexec: Mutex::new([false; 3]),
            closed_stdio: Mutex::new(closed_stdio),
            fd_open_paths: RwLock::new(fd_open_paths),
            splice_pushback: Mutex::new(splice_pushback),
            epoll_fds: RwLock::new(epoll_fds),
            epoll_wake_registry,
            functional_gate: Arc::new(FileTableFunctionalGate::new()),
            functional_refs_active: AtomicBool::new(true),
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
        let _mutation = self.mutation_lease();
        let mut open_files = self.open_files.write();
        let replaced = open_files.insert(
            number.raw(),
            FileSlot::new(
                description,
                u64::from(close_on_exec) * crate::linux_abi::LINUX_FD_CLOEXEC,
            ),
        );
        self.revision.publish();
        replaced
    }

    pub fn slot(&self, number: FileSlotNumber) -> Option<FileSlot> {
        self.open_files.read().get(&number.raw()).cloned()
    }

    pub fn slot_count(&self) -> usize {
        self.open_files.read().len()
    }

    pub(crate) fn read_open_files(&self) -> RwLockReadGuard<'_, HashMap<i32, FileSlot>> {
        self.open_files.read()
    }

    pub(crate) fn write_open_files(&self) -> FileTableWriteGuard<'_> {
        let mutation = self.mutation_lease();
        FileTableWriteGuard {
            guard: self.open_files.write(),
            _mutation: mutation,
            revision: &self.revision,
        }
    }

    pub(crate) fn lock_next_fd(&self) -> FileTableMutexGuard<'_, i32> {
        self.mutex_write(&self.next_fd)
    }

    pub(crate) fn lock_stdio_cloexec(&self) -> FileTableMutexGuard<'_, [bool; 3]> {
        self.mutex_write(&self.stdio_cloexec)
    }

    pub(crate) fn lock_closed_stdio(&self) -> FileTableMutexGuard<'_, [bool; 3]> {
        self.mutex_write(&self.closed_stdio)
    }

    pub(crate) fn read_fd_open_paths(&self) -> RwLockReadGuard<'_, HashMap<i32, String>> {
        self.fd_open_paths.read()
    }

    pub(crate) fn write_fd_open_paths(&self) -> FileTableRwWriteGuard<'_, HashMap<i32, String>> {
        self.rw_write(&self.fd_open_paths)
    }

    pub(crate) fn lock_splice_pushback(
        &self,
    ) -> FileTableMutexGuard<
        '_,
        HashMap<FileDescriptionId, Arc<Mutex<crate::dispatch::SplicePushback>>>,
    > {
        self.mutex_write(&self.splice_pushback)
    }

    pub(crate) fn has_splice_pushback(&self) -> bool {
        !self.splice_pushback.lock().is_empty()
    }

    pub(crate) fn read_epoll_fds(&self) -> RwLockReadGuard<'_, BTreeSet<i32>> {
        self.epoll_fds.read()
    }

    pub(crate) fn write_epoll_fds(&self) -> FileTableRwWriteGuard<'_, BTreeSet<i32>> {
        self.rw_write(&self.epoll_fds)
    }

    pub(crate) fn epoll_wake_registry(&self) -> &crate::dispatch::EpollWakeRegistry {
        &self.epoll_wake_registry
    }

    pub(crate) fn functional_refs_active(&self) -> bool {
        self.functional_refs_active.load(Ordering::Acquire)
    }

    pub(crate) fn acquire_functional_lease(self: &Arc<Self>) -> Option<FileTableFunctionalLease> {
        self.functional_gate.acquire_use()
    }

    pub(super) fn freeze_for_exec(self: &Arc<Self>) -> Option<FileTableExecFreeze> {
        self.functional_gate.freeze()
    }

    #[cfg(test)]
    pub(crate) fn functional_gate_is_frozen(&self) -> bool {
        self.functional_gate.is_frozen()
    }

    pub(crate) fn drain_functional_refs(&self) -> Vec<(i32, FileSlot)> {
        if !self.functional_gate.retire() {
            return Vec::new();
        }
        self.functional_refs_active.store(false, Ordering::Release);
        let slots = self
            .open_files
            .read()
            .iter()
            .map(|(fd, slot)| (*fd, slot.clone()))
            .collect();
        self.revision.publish();
        slots
    }

    fn mutation_lease(&self) -> FileTableMutationLease {
        self.functional_gate.acquire_mutation().unwrap_or_else(|| {
            tracing::error!(file_table = ?self.id, "mutation reached a draining FileTable generation");
            std::process::abort();
        })
    }

    fn mutex_write<'a, T>(&'a self, lock: &'a Mutex<T>) -> FileTableMutexGuard<'a, T> {
        let mutation = self.mutation_lease();
        FileTableMutexGuard {
            guard: lock.lock(),
            _mutation: mutation,
            revision: &self.revision,
        }
    }

    fn rw_write<'a, T>(&'a self, lock: &'a RwLock<T>) -> FileTableRwWriteGuard<'a, T> {
        let mutation = self.mutation_lease();
        FileTableRwWriteGuard {
            guard: lock.write(),
            _mutation: mutation,
            revision: &self.revision,
        }
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileTableStateSnapshot> {
        let revision = self.revision.load();
        let open_files = self.open_files.try_read_until(deadline)?;
        let next_fd = *self.next_fd.try_lock_until(deadline)?;
        let stdio_cloexec = *self.stdio_cloexec.try_lock_until(deadline)?;
        let closed_stdio = *self.closed_stdio.try_lock_until(deadline)?;
        let fd_open_paths = self.fd_open_paths.try_read_until(deadline)?;
        let splice_pushback = self.splice_pushback.try_lock_until(deadline)?;
        let epoll_fds = self.epoll_fds.try_read_until(deadline)?;

        let to_number = |fd| FileSlotNumber::for_open_fd(fd).ok();
        let mut slots = open_files
            .iter()
            .map(|(fd, slot)| Some((to_number(*fd)?, slot.clone())))
            .collect::<Option<Vec<_>>>()?;
        slots.sort_by_key(|(number, _)| *number);
        let mut paths = fd_open_paths
            .iter()
            .map(|(fd, path)| Some((to_number(*fd)?, path.clone())))
            .collect::<Option<Vec<_>>>()?;
        paths.sort_by_key(|(number, _)| *number);
        let sorted_numbers = |fds: Vec<i32>| {
            let mut numbers = fds.into_iter().map(to_number).collect::<Option<Vec<_>>>()?;
            numbers.sort_unstable();
            Some(numbers)
        };
        let mut splice_pushback_description_ids =
            splice_pushback.keys().copied().collect::<Vec<_>>();
        splice_pushback_description_ids.sort_unstable();

        Some(FileTableStateSnapshot {
            revision,
            functional_refs_active: self.functional_refs_active(),
            slots,
            next_fd,
            stdio_cloexec,
            closed_stdio,
            fd_open_paths: paths,
            splice_pushback_description_ids,
            epoll_fds: sorted_numbers(epoll_fds.iter().copied().collect())?,
        })
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

impl Drop for FileTable {
    fn drop(&mut self) {
        if !self.functional_gate.retire() {
            return;
        }
        self.functional_refs_active.store(false, Ordering::Release);
        for slot in self.open_files.get_mut().values() {
            // Model-only descriptions and tests that install observational
            // slots directly carry no functional dispatch reference.
            if slot.description.fd_ref_count() != 0 {
                slot.description.release_fd_ref();
            }
        }
    }
}

pub(crate) struct FileTableWriteGuard<'a> {
    guard: RwLockWriteGuard<'a, HashMap<i32, FileSlot>>,
    _mutation: FileTableMutationLease,
    revision: &'a ObjectRevision,
}

impl Deref for FileTableWriteGuard<'_> {
    type Target = HashMap<i32, FileSlot>;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for FileTableWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for FileTableWriteGuard<'_> {
    fn drop(&mut self) {
        self.revision.publish();
    }
}

pub(crate) struct FileTableMutexGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    _mutation: FileTableMutationLease,
    revision: &'a ObjectRevision,
}

impl<T> Deref for FileTableMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for FileTableMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for FileTableMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.revision.publish();
    }
}

pub(crate) struct FileTableRwWriteGuard<'a, T> {
    guard: RwLockWriteGuard<'a, T>,
    _mutation: FileTableMutationLease,
    revision: &'a ObjectRevision,
}

impl<T> Deref for FileTableRwWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for FileTableRwWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for FileTableRwWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.revision.publish();
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
/// Thread credentials. `clone` creates an independent copy; `set*uid`/`set*gid`
/// creates a new [`Credentials`] object and replaces only the calling thread's
/// `ThreadResources` association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    id: CredentialsId,
    pub(crate) ruid: NsUid,
    pub(crate) euid: NsUid,
    pub(crate) suid: NsUid,
    pub(crate) rgid: NsGid,
    pub(crate) egid: NsGid,
    pub(crate) sgid: NsGid,
    pub(crate) fsuid: NsUid,
    pub(crate) fsgid: NsGid,
    pub(crate) umask: u32,
    /// `None` preserves launch-time `/etc/group` fallback; `Some`, including an
    /// empty vector, is the complete set installed by `setgroups(2)`.
    supplementary_groups_override: Option<Vec<NsGid>>,
}

impl Credentials {
    pub const fn root(id: CredentialsId) -> Self {
        Self {
            id,
            ruid: NsUid::ROOT,
            euid: NsUid::ROOT,
            suid: NsUid::ROOT,
            rgid: NsGid::ROOT,
            egid: NsGid::ROOT,
            sgid: NsGid::ROOT,
            fsuid: NsUid::ROOT,
            fsgid: NsGid::ROOT,
            umask: LINUX_DEFAULT_UMASK,
            supplementary_groups_override: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub const fn from_values(
        id: CredentialsId,
        ruid: NsUid,
        euid: NsUid,
        suid: NsUid,
        rgid: NsGid,
        egid: NsGid,
        sgid: NsGid,
        fsuid: NsUid,
        fsgid: NsGid,
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
    pub const fn ruid(&self) -> NsUid {
        self.ruid
    }
    pub const fn euid(&self) -> NsUid {
        self.euid
    }
    pub const fn suid(&self) -> NsUid {
        self.suid
    }
    pub const fn rgid(&self) -> NsGid {
        self.rgid
    }
    pub const fn egid(&self) -> NsGid {
        self.egid
    }
    pub const fn sgid(&self) -> NsGid {
        self.sgid
    }
    pub const fn fsuid(&self) -> NsUid {
        self.fsuid
    }
    pub const fn fsgid(&self) -> NsGid {
        self.fsgid
    }
    pub const fn umask(&self) -> u32 {
        self.umask
    }
    pub fn supplementary_groups_override(&self) -> Option<&[NsGid]> {
        self.supplementary_groups_override.as_deref()
    }

    pub(crate) fn seed_identity(&mut self, uid: NsUid, gid: NsGid) {
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
        self.euid.is_root()
    }
    pub(crate) fn set_uid_triple(&mut self, ruid: NsUid, euid: NsUid, suid: NsUid) {
        self.ruid = ruid;
        self.euid = euid;
        self.suid = suid;
        self.fsuid = euid;
    }
    pub(crate) fn set_gid_triple(&mut self, rgid: NsGid, egid: NsGid, sgid: NsGid) {
        self.rgid = rgid;
        self.egid = egid;
        self.sgid = sgid;
        self.fsgid = egid;
    }
    pub(crate) fn set_fsuid(&mut self, fsuid: NsUid) {
        self.fsuid = fsuid;
    }
    pub(crate) fn set_fsgid(&mut self, fsgid: NsGid) {
        self.fsgid = fsgid;
    }
    pub(crate) fn set_umask(&mut self, umask: u32) {
        self.umask = umask;
    }
    pub(crate) fn set_supplementary_groups(&mut self, groups: Vec<NsGid>) {
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

/// One dequeued signal and its provenance-preserving optional payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingSignal {
    pub signal: LinuxSignal,
    pub siginfo: Option<LinuxSiginfo>,
}

/// Typed standard/real-time pending queue used by task- and thread-directed
/// owners. Standard signals coalesce to one presence bit. Real-time signals
/// retain one FIFO entry per send, including an explicit no-payload entry so a
/// later queued `siginfo` can never attach to the wrong delivery.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PendingQueue {
    present: SigSet,
    standard_siginfos: BTreeMap<LinuxSignal, LinuxSiginfo>,
    realtime: BTreeMap<LinuxSignal, VecDeque<Option<LinuxSiginfo>>>,
}

impl PendingQueue {
    pub const fn present(&self) -> SigSet {
        self.present
    }

    pub fn pending_count(&self) -> usize {
        let realtime = self.realtime.values().map(VecDeque::len).sum::<usize>();
        let realtime_signals = self.realtime.len();
        let distinct = self.present.raw().count_ones() as usize;
        distinct.saturating_sub(realtime_signals) + realtime
    }

    pub fn enqueue_standard(&mut self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        if signal.raw() >= 32 {
            tracing::error!(
                signal = signal.raw(),
                "real-time signal entered standard queue"
            );
            std::process::abort();
        }
        let already_pending = self.present.contains(signal.raw());
        self.present = self.present.with(signal.raw());
        if !already_pending && let Some(siginfo) = siginfo {
            // Standard signals coalesce into the first pending instance. Later
            // generations neither add nor replace siginfo until that instance
            // is dequeued.
            self.standard_siginfos.insert(signal, siginfo);
        }
        self.assert_invariants();
    }

    pub fn enqueue_realtime(&mut self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        if signal.raw() < 32 {
            tracing::error!(
                signal = signal.raw(),
                "standard signal entered real-time queue"
            );
            std::process::abort();
        }
        self.realtime.entry(signal).or_default().push_back(siginfo);
        self.present = self.present.with(signal.raw());
        self.assert_invariants();
    }

    /// Discard every pending instance whose signal is in `signals`.
    ///
    /// Linux job-control generation uses this for its task-wide cancellation
    /// rule: generating SIGCONT discards every pending stop signal, while
    /// generating a stop signal discards every pending SIGCONT.
    pub fn discard(&mut self, signals: SigSet) -> bool {
        let discarded = !self.present.intersect(signals).is_empty();
        if !discarded {
            return false;
        }
        self.present = self.present.difference(signals);
        self.standard_siginfos
            .retain(|signal, _| !signals.contains(signal.raw()));
        self.realtime
            .retain(|signal, _| !signals.contains(signal.raw()));
        self.assert_invariants();
        true
    }

    pub fn entries(&self) -> Vec<PendingSignal> {
        let mut entries = Vec::new();
        for raw in 1..=64 {
            if !self.present.contains(raw) {
                continue;
            }
            let Ok(signal) = LinuxSignal::for_signal_number(raw) else {
                std::process::abort();
            };
            if let Some(realtime) = self.realtime.get(&signal) {
                entries.extend(
                    realtime
                        .iter()
                        .copied()
                        .map(|siginfo| PendingSignal { signal, siginfo }),
                );
            } else {
                entries.push(PendingSignal {
                    signal,
                    siginfo: self.standard_siginfos.get(&signal).copied(),
                });
            }
        }
        entries
    }

    pub fn from_entries(entries: &[PendingSignal]) -> Self {
        let mut queue = Self::default();
        for entry in entries {
            if entry.signal.raw() >= 32 {
                queue.enqueue_realtime(entry.signal, entry.siginfo);
            } else {
                queue.enqueue_standard(entry.signal, entry.siginfo);
            }
        }
        queue
    }

    pub fn take_lowest_in(&mut self, wanted: SigSet) -> Option<PendingSignal> {
        let raw = self.present.intersect(wanted).lowest_signum()?;
        let signal = LinuxSignal::for_signal_number(raw).ok()?;
        let siginfo = if let Some(instances) = self.realtime.get_mut(&signal) {
            let siginfo = instances.pop_front().flatten();
            if instances.is_empty() {
                self.realtime.remove(&signal);
                self.present = self.present.without(raw);
            }
            siginfo
        } else {
            self.present = self.present.without(raw);
            self.standard_siginfos.remove(&signal)
        };
        self.assert_invariants();
        Some(PendingSignal { signal, siginfo })
    }

    fn assert_invariants(&self) {
        debug_assert!(self.realtime.iter().all(
            |(signal, instances)| !instances.is_empty() && self.present.contains(signal.raw())
        ));
        debug_assert!(
            self.standard_siginfos
                .keys()
                .all(|signal| self.present.contains(signal.raw()))
        );
    }
}

/// Task-directed pending-signal authority. The hint is an index published from
/// the queue while locked; `false` proves empty and `true` requires locked
/// revalidation.
#[derive(Debug, Default)]
pub struct TaskPendingSignals {
    queue: Mutex<PendingQueue>,
    pending_hint: AtomicU64,
    revision: ObjectRevision,
}

impl TaskPendingSignals {
    pub const fn new() -> Self {
        Self {
            queue: Mutex::new(PendingQueue {
                present: SigSet::EMPTY,
                standard_siginfos: BTreeMap::new(),
                realtime: BTreeMap::new(),
            }),
            pending_hint: AtomicU64::new(0),
            revision: ObjectRevision::new(),
        }
    }

    pub fn pending_count(&self) -> usize {
        self.queue.lock().pending_count()
    }

    pub fn revision(&self) -> u64 {
        self.revision.load()
    }

    pub fn may_be_nonempty(&self) -> bool {
        self.pending_hint.load(Ordering::Acquire) != 0
    }

    pub fn present(&self) -> SigSet {
        self.queue.lock().present()
    }

    pub fn enqueue_standard(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let mut queue = self.queue.lock();
        queue.enqueue_standard(signal, siginfo);
        self.publish_queue(&queue);
    }

    pub fn enqueue_realtime(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let mut queue = self.queue.lock();
        queue.enqueue_realtime(signal, siginfo);
        self.publish_queue(&queue);
    }

    pub fn take_lowest_in(&self, wanted: SigSet) -> Option<PendingSignal> {
        let mut queue = self.queue.lock();
        let pending = queue.take_lowest_in(wanted)?;
        self.publish_queue(&queue);
        Some(pending)
    }

    pub fn snapshot_entries(&self) -> Vec<PendingSignal> {
        self.queue.lock().entries()
    }

    pub fn replace_entries(&self, entries: &[PendingSignal]) {
        let replacement = PendingQueue::from_entries(entries);
        let mut queue = self.queue.lock();
        if *queue != replacement {
            *queue = replacement;
            self.publish_queue(&queue);
        }
    }

    pub(super) fn discard(&self, signals: SigSet) {
        let mut queue = self.queue.lock();
        if queue.discard(signals) {
            self.publish_queue(&queue);
        }
    }

    fn publish_queue(&self, queue: &PendingQueue) {
        self.pending_hint
            .store(queue.present().raw(), Ordering::Release);
        self.revision.publish();
        debug_assert_eq!(
            self.pending_hint.load(Ordering::Relaxed),
            queue.present().raw()
        );
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
            .then(|| {
                ids.mm_id()
                    .map(|id| Mm::new_reference_for_fork(id, &parent.mm))
                    .map(Arc::new)
            })
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
pub struct HandlerFrameState {
    pub on_altstack: bool,
    pub restore_mask: Option<SigSet>,
}

/// Complete per-thread Linux signal state. The containing Kernel `Thread`
/// serializes mutations; no field is process-global or keyed by a reusable raw
/// backend TID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadSignalState {
    blocked: SigSet,
    pending: PendingQueue,
    altstack: Option<LinuxSigaltstack>,
    handler_frames: Vec<HandlerFrameState>,
    armed_restore_mask: Option<SigSet>,
    routed_siginfos: BTreeMap<LinuxSignal, VecDeque<LinuxSiginfo>>,
    pending_actions: BTreeMap<LinuxSignal, VecDeque<LinuxSigaction>>,
}

impl ThreadSignalState {
    /// Summary-shaped constructor retained for existing Kernel model tests.
    /// Production signal publication uses the typed queue/altstack methods.
    pub fn new(
        blocked: SigSet,
        pending: SigSet,
        altstack_enabled: bool,
        handler_frame_depth: usize,
    ) -> Self {
        let mut pending_queue = PendingQueue::default();
        for raw in 1..=64 {
            if pending.contains(raw)
                && let Ok(signal) = LinuxSignal::for_signal_number(raw)
            {
                if raw >= 32 {
                    pending_queue.enqueue_realtime(signal, None);
                } else {
                    pending_queue.enqueue_standard(signal, None);
                }
            }
        }
        Self {
            blocked,
            pending: pending_queue,
            altstack: altstack_enabled.then(LinuxSigaltstack::empty),
            handler_frames: vec![
                HandlerFrameState {
                    on_altstack: false,
                    restore_mask: None,
                };
                handler_frame_depth
            ],
            armed_restore_mask: None,
            routed_siginfos: BTreeMap::new(),
            pending_actions: BTreeMap::new(),
        }
    }

    pub(crate) fn for_fork(caller: &Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: PendingQueue::default(),
            altstack: caller.altstack,
            handler_frames: caller.handler_frames.clone(),
            armed_restore_mask: caller.armed_restore_mask,
            routed_siginfos: BTreeMap::new(),
            pending_actions: BTreeMap::new(),
        }
    }

    pub(crate) fn for_clone_thread(caller: &Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: PendingQueue::default(),
            altstack: None,
            handler_frames: Vec::new(),
            armed_restore_mask: None,
            routed_siginfos: BTreeMap::new(),
            pending_actions: BTreeMap::new(),
        }
    }

    pub(crate) fn for_exec(caller: &Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: caller.pending.clone(),
            altstack: None,
            handler_frames: Vec::new(),
            armed_restore_mask: None,
            routed_siginfos: caller.routed_siginfos.clone(),
            pending_actions: BTreeMap::new(),
        }
    }

    pub const fn blocked(&self) -> SigSet {
        self.blocked
    }

    pub fn set_blocked(&mut self, blocked: SigSet) {
        self.blocked = blocked;
    }

    pub const fn pending(&self) -> SigSet {
        self.pending.present()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.pending_count()
    }

    pub fn snapshot_pending_entries(&self) -> Vec<PendingSignal> {
        self.pending.entries()
    }

    pub fn replace_pending_entries(&mut self, entries: &[PendingSignal]) {
        self.pending = PendingQueue::from_entries(entries);
    }

    pub fn enqueue_standard(&mut self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        self.pending.enqueue_standard(signal, siginfo);
    }

    pub fn enqueue_realtime(&mut self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        self.pending.enqueue_realtime(signal, siginfo);
    }

    pub fn take_lowest_in(&mut self, wanted: SigSet) -> Option<PendingSignal> {
        self.pending.take_lowest_in(wanted)
    }

    pub(super) fn discard_pending(&mut self, signals: SigSet) {
        if self.pending.discard(signals) {
            self.routed_siginfos
                .retain(|signal, _| !signals.contains(signal.raw()));
            self.pending_actions
                .retain(|signal, _| !signals.contains(signal.raw()));
        }
    }

    pub const fn altstack(&self) -> Option<LinuxSigaltstack> {
        self.altstack
    }

    pub fn set_altstack(&mut self, altstack: Option<LinuxSigaltstack>) {
        self.altstack = altstack;
    }

    pub const fn altstack_enabled(&self) -> bool {
        self.altstack.is_some()
    }

    pub fn handler_frame_depth(&self) -> usize {
        self.handler_frames.len()
    }

    pub fn handler_frames(&self) -> Vec<HandlerFrameState> {
        self.handler_frames.clone()
    }

    pub fn has_altstack_handler_frame(&self) -> bool {
        self.handler_frames.iter().any(|frame| frame.on_altstack)
    }

    pub fn clear_handler_frames(&mut self) {
        self.handler_frames.clear();
    }

    pub fn push_handler_frame(&mut self, frame: HandlerFrameState) {
        self.handler_frames.push(frame);
    }

    pub fn pop_handler_frame(&mut self) -> Option<HandlerFrameState> {
        self.handler_frames.pop()
    }

    pub const fn armed_restore_mask(&self) -> Option<SigSet> {
        self.armed_restore_mask
    }

    pub fn take_armed_restore_mask(&mut self) -> Option<SigSet> {
        self.armed_restore_mask.take()
    }

    pub fn arm_restore_mask(&mut self, restore_mask: Option<SigSet>) {
        self.armed_restore_mask = restore_mask;
    }

    pub fn record_routed_siginfo(&mut self, signal: LinuxSignal, siginfo: LinuxSiginfo) {
        let entries = self.routed_siginfos.entry(signal).or_default();
        if signal.raw() < 32 {
            entries.clear();
        }
        entries.push_back(siginfo);
    }

    pub fn take_routed_siginfo(&mut self, signal: LinuxSignal) -> Option<LinuxSiginfo> {
        let entries = self.routed_siginfos.get_mut(&signal)?;
        let siginfo = entries.pop_front();
        if entries.is_empty() {
            self.routed_siginfos.remove(&signal);
        }
        siginfo
    }

    pub fn record_pending_action(&mut self, signal: LinuxSignal, action: LinuxSigaction) {
        self.pending_actions
            .entry(signal)
            .or_default()
            .push_back(action);
    }

    pub fn take_pending_action(&mut self, signal: LinuxSignal) -> Option<LinuxSigaction> {
        let actions = self.pending_actions.get_mut(&signal)?;
        let action = actions.pop_front();
        if actions.is_empty() {
            self.pending_actions.remove(&signal);
        }
        action
    }

    pub fn routed_siginfos(&self) -> Vec<(LinuxSignal, LinuxSiginfo)> {
        self.routed_siginfos
            .iter()
            .flat_map(|(signal, entries)| entries.iter().map(|info| (*signal, *info)))
            .collect()
    }

    pub fn pending_actions(&self) -> Vec<(LinuxSignal, LinuxSigaction)> {
        self.pending_actions
            .iter()
            .flat_map(|(signal, entries)| entries.iter().map(|action| (*signal, *action)))
            .collect()
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

    pub(super) fn with_files(&self, files: Arc<FileTable>) -> Self {
        Self::new(
            files,
            Arc::clone(&self.fs_context),
            Arc::clone(&self.credentials),
        )
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JobControlStopInvalidationGeneration(u64);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DefaultStopGeneration {
    #[default]
    None,
    Pending,
    Cancelled,
}

#[derive(Debug, Default)]
struct TaskJobControl {
    stopped_by: Option<LinuxSignal>,
    pending_stop: Option<LinuxSignal>,
    pending_stop_is_ptrace: bool,
    stopped_by_ptrace: bool,
    ptrace_tracer: Option<TaskKey>,
    ptrace_resume_signal: Option<LinuxSignal>,
    pending_continue: bool,
    stop_invalidation_generation: u64,
    default_stop_generation: DefaultStopGeneration,
}

fn advance_job_control_stop_invalidation_generation(state: &mut TaskJobControl) {
    let Some(next) = state.stop_invalidation_generation.checked_add(1) else {
        tracing::error!("job-control stop invalidation generation exhausted");
        std::process::abort();
    };
    state.stop_invalidation_generation = next;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TaskJobControlEvent {
    Stopped(LinuxSignal),
    Continued,
}

/// How the kernel makes a task NOTICE something it has been handed.
///
/// Enqueuing a signal is only half of delivery. A task that reaches a syscall
/// or trap boundary polls its own pending queue and finds it; a task parked in
/// a host wait — a blocking read, a futex, `waitpid`, a kqueue — finds nothing,
/// because none of those vehicles watch the kernel's queues. Waking it is
/// unavoidably host-specific (on the kernel lane: unpark the futex table, poke
/// the wake pipes, force the vCPU out of `hv_vcpu_run`), so the kernel names
/// the CAPABILITY and each lane supplies it.
///
/// Waking is a hint, never a guarantee of consumption: the woken task re-reads
/// the authoritative queue and decides for itself. That makes a spurious wake
/// harmless and a missing implementation merely slow rather than wrong — a task
/// with no waker still notices at its next boundary.
pub trait TaskWaker: Send + Sync + std::fmt::Debug {
    /// Kick every vehicle this task may be parked on. Idempotent, and safe to
    /// call for a task that is running or already awake.
    fn wake_task(&self);
}

#[derive(Debug)]
pub struct Task {
    key: TaskKey,
    parent: Mutex<Option<TaskKey>>,
    children: Mutex<BTreeSet<TaskKey>>,
    identity: Mutex<TaskIdentity>,
    lifecycle: Mutex<TaskLifecycle>,
    /// Process-directed signal permission uses the last published thread-group
    /// leader credential generation. Keep it after a non-final leader exit; a
    /// live task must not become ESRCH merely because only siblings remain.
    process_credentials: ArcSwap<Credentials>,
    /// Guest job-control state is task scoped. HVPatch cannot lower it to host
    /// SIGSTOP/SIGCONT because all guest tasks share one Darwin process.
    signal_generation: Mutex<()>,
    job_control: Mutex<TaskJobControl>,
    job_control_changed: Condvar,
    shared: ArcSwap<TaskShared>,
    threads: Mutex<BTreeMap<LinuxTid, (ThreadKey, ThreadRef)>>,
    cpu: TaskCpu,
    /// Lane-supplied wake vehicle, absent until the runtime publishes one (and
    /// on lanes that have none). Held here rather than in a side table so it
    /// cannot outlive the task or be looked up for a retired one.
    waker: Mutex<Option<Arc<dyn TaskWaker>>>,
    /// Durable counterpart to the lane wake hint. A vCPU can be between a
    /// syscall boundary and guest re-entry when the host kick fires; retaining
    /// the generation lets that same boundary reconcile the authoritative
    /// pending state before it enters guest code.
    wake_generation: AtomicU64,
    /// Linux's per-process OOM-killer bias, `/proc/<pid>/oom_score_adj`
    /// (proc(5)): inherited at fork, independent of the parent afterwards, and
    /// shared by every thread of the process.
    ///
    /// It is task state rather than a host-process global for the same reason
    /// [`TaskCpu`] is: under HVPatch all Linux processes are threads of ONE
    /// Darwin process, so a global would publish one guest process's write to
    /// every other one. LTP's `tst_test` setup writes -1000 to *another*
    /// process's file and reads it back (`tst_memutils.c:set_oom_score_adj`),
    /// which a shared cell cannot model.
    oom_score_adj: AtomicI32,
    /// This process's nice value (`getpriority`/`setpriority`): range
    /// [-20, 19], default 0. Inherited across fork and preserved across exec.
    ///
    /// Per-TASK, not a runtime `static`: under HVPatch many logical Linux
    /// processes share one host carrier, so a global cell leaks one process's
    /// nice into every other. (Linux's own granularity is finer still — nice is
    /// really per-thread — see `nice()`.)
    nice: AtomicI32,
    /// This process's I/O priority, stored by `ioprio_set` and echoed by
    /// `ioprio_get`. Carrick has no real I/O scheduler, so this is a faithful
    /// value store, not a scheduling input. Default `IOPRIO_CLASS_BE(2)` level
    /// 4 = `(2 << 13) | 4`, what Linux reports for a process that never set one.
    ///
    /// Per-TASK for the same reason as [`Task::nice`]: it was a runtime-global
    /// `static IOPRIO_VALUE` in `dispatch/proc.rs`, which every logical Linux
    /// process in the carrier shared.
    ioprio: AtomicU32,
    /// This process's keyring pointers (`keyrings(7)`): the process keyring,
    /// the session keyring, and the `KEYCTL_SET_REQKEY_KEYRING` default.
    ///
    /// They are task state, not thread state, because Linux shares them across
    /// every thread of a process — and they are not a host-process global for
    /// the same reason [`Task::oom_score_adj`] is not: under HVPatch every
    /// Linux process is a thread of ONE Darwin process, so a global would let
    /// one guest's `KEYCTL_JOIN_SESSION_KEYRING` reassign every other guest's
    /// session keyring.
    keyrings: Mutex<ProcessKeyrings>,
    /// This process's five capability sets (`capabilities(7)`) and its
    /// user-namespace view (`user_namespaces(7)`) — the `uid_map`/`gid_map`/
    /// `setgroups` state behind `/proc/self/*`.
    ///
    /// Both are per-process attributes that a `fork` child inherits as a COPY
    /// and then owns: `PR_CAPBSET_DROP`, `capset`, `PR_CAP_AMBIENT_*` and a
    /// `uid_map` write change only the calling process. They live on the task
    /// for the same reason [`Task::oom_score_adj`] and [`Task::keyrings`] do —
    /// under HVPatch every Linux process is a thread of ONE Darwin process, so
    /// the `static` that used to hold them was a single cell shared by every
    /// guest process at once. That made one guest's capbset drop remove the
    /// capability from every other guest, irreversibly, and published one
    /// guest's `uid_map` in every other guest's `/proc/self/uid_map`.
    ///
    /// One mutex covers both because `unshare(CLONE_NEWUSER)` must replace the
    /// namespace and grant the full set as a single atomic step; splitting
    /// them would let a reader observe a fresh namespace with the old caps.
    creds_ns: Mutex<ProcessCredsNs>,
    /// This process's resource limits (`getrlimit(2)`, `prlimit(2)`).
    ///
    /// On the TASK because that is Linux's own scope — an rlimit lives in
    /// `signal_struct`, shared by every thread of a thread group — and because a
    /// peer must be able to WRITE it: `prlimit(pid, …)` sets ANOTHER process's
    /// limit. Held in the dispatcher's private `ProcState` instead, there was no
    /// path from any other task into the table at all, so `prlimit` silently
    /// wrote the CALLER's limits: the target saw nothing change and the caller's
    /// own soft NOFILE moved underneath it. Go's `TestPrlimitFileLimit` is
    /// exactly that shape.
    ///
    /// `ArcSwap` rather than a `Mutex` because the read path is hot and runs
    /// under other locks — `Nofile` is consulted inside fd allocation while the
    /// file table is held, and `Fsize` on every regular-file write — so a read
    /// must not be able to block on a writer.
    rlimits: ArcSwap<RlimitSet>,
    /// Serializes read-modify-write on [`Self::rlimits`]. `ArcSwap` gives atomic
    /// publication, not atomic update: `setrlimit` has to compare the new soft
    /// against the CURRENT hard, and two concurrent writers reading the same
    /// snapshot would each publish a set built from a stale one.
    rlimit_write: Mutex<()>,
}

/// A process's sixteen resource limits, indexed by [`LinuxResource`].
///
/// A dense array rather than a map of overrides: the previous shape stored
/// `Option<LinuxRlimit>` per slot and resolved "unset" to a default at every
/// read, which is why three different files answered "max processes" three
/// different ways. One table, one answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlimitSet {
    limits: [LinuxRlimit; LinuxResource::COUNT],
}

impl RlimitSet {
    /// The limits a guest process starts with.
    ///
    /// These are carrick's answer for a container, and they are the SINGLE
    /// source: `getrlimit`, `/proc/<pid>/limits` and every enforcement site read
    /// this table, so they cannot disagree the way the frozen `/proc` literal
    /// disagreed with `getrlimit` on four resources.
    pub const fn carrick_defaults() -> Self {
        const INF: u64 = LINUX_RLIM_INFINITY;
        let unlimited = LinuxRlimit::new(INF, INF);
        let mut limits = [unlimited; LinuxResource::COUNT];
        // Docker's default container limits, which the conformance oracle runs
        // with; anything not listed is unlimited.
        limits[LinuxResource::Nofile.index()] = LinuxRlimit::new(1_048_576, 1_048_576);
        limits[LinuxResource::Nproc.index()] = LinuxRlimit::new(8_192, 8_192);
        limits[LinuxResource::Stack.index()] = LinuxRlimit::new(8 * 1024 * 1024, INF);
        limits[LinuxResource::Sigpending.index()] = LinuxRlimit::new(63_880, 63_880);
        limits[LinuxResource::Msgqueue.index()] = LinuxRlimit::new(819_200, 819_200);
        limits[LinuxResource::Nice.index()] = LinuxRlimit::new(0, 0);
        limits[LinuxResource::Rtprio.index()] = LinuxRlimit::new(0, 0);
        Self { limits }
    }

    pub const fn get(&self, resource: LinuxResource) -> LinuxRlimit {
        self.limits[resource.index()]
    }

    /// Returns the set with `resource` replaced — `RlimitSet` is `Copy`, so a
    /// writer publishes a whole new snapshot rather than mutating one readers
    /// may be holding.
    pub const fn with(mut self, resource: LinuxResource, limit: LinuxRlimit) -> Self {
        self.limits[resource.index()] = limit;
        self
    }
}

/// A process's keyring pointers. Serials rather than object references: the
/// keys themselves live in the VM-wide [`crate::keyring::KeyringService`], and
/// naming them by serial is what lets a `fork` child share the parent's session
/// keyring by simply copying the number.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessKeyrings {
    /// `KEY_SPEC_PROCESS_KEYRING`, materialised on demand.
    pub process: Option<KeySerial>,
    /// `KEY_SPEC_SESSION_KEYRING`. `None` means this process has never joined
    /// one, so its session keyring IS its user-session keyring — Linux's
    /// default, and the reason a fresh guest can still `add_key` to
    /// `KEY_SPEC_SESSION_KEYRING`.
    pub session: Option<KeySerial>,
    /// Where `request_key(2)` links a constructed key when the caller passes
    /// destination 0.
    pub request_key_default: KeyRequestDefault,
}

/// The two CPU ledgers Linux keeps for every process, owned by the kernel
/// rather than read back out of the host.
///
/// `times(2)` reports the process's own CPU in `tms_utime`/`tms_stime` and the
/// summed CPU of its *reaped* children in `tms_cutime`/`tms_cstime`;
/// `getrusage(2)` spells the same split `RUSAGE_SELF` versus
/// `RUSAGE_CHILDREN`. Sourcing either from the host process is wrong under
/// HVPatch by construction: all Linux processes are threads of one host
/// process, so a host per-process counter is the sum over every guest at once.
#[derive(Debug, Default)]
struct TaskCpu {
    /// CPU of this task's threads that have already exited. Live threads are
    /// totalled on demand from their `guest_cpu` slots; this is the part that
    /// would otherwise be lost when a slot is released.
    exited_threads_us: AtomicU64,
    /// SYSTEM CPU of this task's exited threads, the counterpart to
    /// `exited_threads_us`. Kept separate rather than summed because Linux
    /// reports the two independently and a caller that conflates them cannot
    /// be corrected later.
    exited_threads_system_us: AtomicU64,
    /// User CPU of reaped children, including the children's own reaped
    /// children — Linux folds a reaped child's `cutime` into its parent's.
    children_user_us: AtomicU64,
    children_system_us: AtomicU64,
}

impl Task {
    pub fn new(
        key: TaskKey,
        parent: Option<TaskKey>,
        process_group: ProcessGroupId,
        session: SessionId,
        shared: Arc<TaskShared>,
        process_credentials: Arc<Credentials>,
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
            process_credentials: ArcSwap::new(process_credentials),
            signal_generation: Mutex::new(()),
            job_control: Mutex::new(TaskJobControl::default()),
            job_control_changed: Condvar::new(),
            shared: ArcSwap::new(shared),
            threads: Mutex::new(BTreeMap::new()),
            cpu: TaskCpu::default(),
            waker: Mutex::new(None),
            wake_generation: AtomicU64::new(0),
            oom_score_adj: AtomicI32::new(0),
            nice: AtomicI32::new(0),
            ioprio: AtomicU32::new(Task::DEFAULT_IOPRIO),
            keyrings: Mutex::new(ProcessKeyrings::default()),
            creds_ns: Mutex::new(ProcessCredsNs::default()),
            rlimits: ArcSwap::new(Arc::new(RlimitSet::carrick_defaults())),
            rlimit_write: Mutex::new(()),
        }
    }

    /// What Linux reports for a process that never called `ioprio_set`:
    /// `IOPRIO_CLASS_BE` (2) at level 4, packed as `(class << 13) | level`.
    pub const DEFAULT_IOPRIO: u32 = (2 << 13) | 4;

    /// This process's packed I/O priority (`ioprio_get`).
    pub fn ioprio(&self) -> u32 {
        self.ioprio.load(Ordering::SeqCst)
    }

    /// Store this process's packed I/O priority (`ioprio_set`).
    pub fn set_ioprio(&self, value: u32) {
        self.ioprio.store(value, Ordering::SeqCst);
    }

    /// This process's nice value (default 0).
    pub fn nice(&self) -> i32 {
        self.nice.load(Ordering::Relaxed)
    }

    /// Set this process's nice value.
    pub fn set_nice(&self, value: i32) {
        self.nice.store(value, Ordering::Relaxed);
    }

    /// Copy every per-process attribute Linux inherits across `fork(2)` and
    /// leaves independent thereafter, from `parent` into this fresh child task.
    ///
    /// This exists as ONE named operation because there are TWO fork paths that
    /// mint a child `Task`, and they drifted: `ForkReservation::prepare` (the
    /// in-process path HVPatch uses) carried all four, while the host-fork
    /// adapter `reset_one_task_kernel_binding_for_current_process` — taken by
    /// backends whose `supports_in_process_fork()` is false — bootstrapped a
    /// brand-new root task and carried none of them. That difference was
    /// invisible while these values lived in process-global `static`s, because
    /// `libc::fork` copied the statics for free. Moving them onto `Task` makes
    /// the omission load-bearing, so the two paths must share this one call.
    pub fn inherit_fork_attributes_from(&self, parent: &Task) {
        // oom_score_adj is inherited across fork and independent thereafter
        // (`proc(5)`).
        self.set_oom_score_adj(parent.oom_score_adj());
        // nice is inherited across fork (`fork(2)`: "the child's nice value is
        // the same as the parent's").
        self.set_nice(parent.nice());
        // I/O priority is likewise inherited across fork (`ioprio_set(2)`).
        self.set_ioprio(parent.ioprio());
        // The session and process keyrings and the `KEYCTL_SET_REQKEY_KEYRING`
        // default are inherited (`keyrings(7)`); the thread keyring is not, and
        // a fresh leader starts without one.
        self.inherit_keyrings_from(parent);
        // The five capability sets and the user-namespace view are inherited as
        // a COPY (`capabilities(7)`, `user_namespaces(7)`): the child starts
        // identical, and each side's later `PR_CAPBSET_DROP` / `capset` /
        // `uid_map` write is invisible to the other.
        self.inherit_creds_ns_from(parent);
        // Resource limits are inherited as a COPY (`fork(2)`), and each side
        // owns its own afterwards — the whole point of the defect this fixes is
        // that one process's `prlimit` must not move another's.
        self.rlimits.store(Arc::new(parent.rlimits()));
    }

    /// This process's limit for one resource.
    ///
    /// `ArcSwap::load` is a hazard-pointer guard, not an allocation, so this is
    /// safe to call on the hot paths that need it — fd allocation holds the file
    /// table while asking for `Nofile`, and every regular-file write asks for
    /// `Fsize`.
    pub fn rlimit(&self, resource: LinuxResource) -> LinuxRlimit {
        self.rlimits.load().get(resource)
    }

    /// This process's whole limit set, for `/proc/<pid>/limits`.
    pub fn rlimits(&self) -> RlimitSet {
        **self.rlimits.load()
    }

    /// Replace one resource's limit under the write lock, letting `decide` see
    /// the CURRENT value.
    ///
    /// The closure is where `setrlimit`'s rules live (a soft above the hard is
    /// EINVAL; raising the hard needs CAP_SYS_RESOURCE), and it must run against
    /// the value it will replace — which is why this is a read-modify-write
    /// under a mutex rather than a bare `ArcSwap::store`.
    pub fn replace_rlimit<E>(
        &self,
        resource: LinuxResource,
        decide: impl FnOnce(LinuxRlimit) -> Result<LinuxRlimit, E>,
    ) -> Result<LinuxRlimit, E> {
        let _write = self.rlimit_write.lock();
        let current = self.rlimits.load();
        let old = current.get(resource);
        let new = decide(old)?;
        self.rlimits.store(Arc::new(current.with(resource, new)));
        Ok(old)
    }

    /// A snapshot of this process's capability sets and user-namespace view,
    /// for the `/proc` render context.
    pub fn creds_ns(&self) -> ProcessCredsNs {
        self.creds_ns.lock().clone()
    }

    /// This process's capability sets, by value.
    pub fn caps(&self) -> CapabilitySet {
        self.creds_ns.lock().caps
    }

    /// Mutate this process's capability sets under the task lock, so a
    /// read-modify-write (`capset`, `PR_CAPBSET_DROP`, `PR_CAP_AMBIENT_RAISE`)
    /// cannot race a sibling thread of the same process. All threads of a
    /// Linux process share one set, which is why this is task state and not
    /// thread state.
    pub fn with_caps<R>(&self, f: impl FnOnce(&mut CapabilitySet) -> R) -> R {
        f(&mut self.creds_ns.lock().caps)
    }

    /// This process's user namespace, by value.
    pub fn user_ns(&self) -> UserNs {
        self.creds_ns.lock().user.clone()
    }

    /// Mutate this process's user-namespace view under the task lock — the
    /// `/proc/self/{uid_map,gid_map,setgroups}` write path.
    pub fn with_user_ns<R>(&self, f: impl FnOnce(&mut UserNs) -> R) -> R {
        f(&mut self.creds_ns.lock().user)
    }

    /// `unshare(CLONE_NEWUSER)` (and the `clone(CLONE_NEWUSER)` child path):
    /// place this process in a fresh user namespace parented at its current
    /// one, and grant it a full capability set WITHIN that namespace
    /// (`user_namespaces(7)`; design §4.1, §4.6). Returns the new id.
    ///
    /// Namespace replacement and the capability grant happen under one lock so
    /// no reader sees the new namespace with the old caps.
    pub fn unshare_user_ns(&self) -> crate::namespace::NsId {
        let id = crate::namespace::process::alloc_ns_id();
        let mut guard = self.creds_ns.lock();
        let parent = guard.user.id;
        guard.user = UserNs::fresh(id, parent);
        guard.caps = CapabilitySet::full();
        id
    }

    /// Copy the parent's capability sets and user-namespace view into a fresh
    /// `fork` child.
    ///
    /// `capabilities(7)`: `fork` preserves all five sets verbatim — the child
    /// starts identical to the parent and diverges only through its own later
    /// `capset`/`PR_CAPBSET_DROP`/`PR_CAP_AMBIENT_*`. `user_namespaces(7)`: the
    /// child is a member of the parent's user namespace, seeing the same
    /// `uid_map`/`gid_map`. Both are COPIES, so a later change on either side
    /// is invisible to the other.
    ///
    /// There is no execve counterpart: `execve` does not build a new [`Task`],
    /// and Linux preserves the bounding, inheritable and ambient sets across an
    /// exec of an ordinary (non-setuid, no-file-capability) binary — which is
    /// every exec carrick models, since it implements neither file capabilities
    /// nor the set-user-ID bit. Preserving the whole struct is therefore the
    /// correct execve behaviour and needs no code.
    pub fn inherit_creds_ns_from(&self, parent: &Task) {
        *self.creds_ns.lock() = parent.creds_ns.lock().clone();
    }

    /// This process's keyring pointers.
    pub fn keyrings(&self) -> ProcessKeyrings {
        *self.keyrings.lock()
    }

    /// Mutate this process's keyring pointers under the task lock, so a
    /// materialise-if-absent (`KEYCTL_GET_KEYRING_ID` with create) cannot race
    /// a sibling thread into two keyrings for one process.
    pub fn with_keyrings<R>(&self, f: impl FnOnce(&mut ProcessKeyrings) -> R) -> R {
        f(&mut self.keyrings.lock())
    }

    /// Copy the parent's keyring pointers into a fresh `fork` child.
    ///
    /// `keyrings(7)`: the session keyring is INHERITED — parent and child go on
    /// sharing one keyring object until one of them joins another — and so is
    /// the request-key default. The THREAD keyring is deliberately absent here:
    /// Linux does not pass it to a child, and neither does carrick (a fresh
    /// [`Thread`] starts with none).
    pub fn inherit_keyrings_from(&self, parent: &Task) {
        *self.keyrings.lock() = parent.keyrings();
    }

    /// This process's `/proc/<pid>/oom_score_adj` (default 0).
    pub fn oom_score_adj(&self) -> i32 {
        self.oom_score_adj.load(Ordering::Relaxed)
    }

    /// Set this process's `oom_score_adj`. The caller has already range-checked
    /// `value` against Linux's [-1000, 1000]; fork inheritance copies the
    /// parent's value into the child at creation.
    pub fn set_oom_score_adj(&self, value: i32) {
        self.oom_score_adj.store(value, Ordering::Relaxed);
    }

    /// Publish the lane's wake vehicle for this task, replacing any previous
    /// one. The runtime calls this once the task has a vCPU and a futex table
    /// to kick.
    pub fn set_waker(&self, waker: Arc<dyn TaskWaker>) {
        *self.waker.lock() = Some(waker);
    }

    /// Kick every vehicle this task may be parked on, so it reaches a point
    /// where it re-reads the kernel's authoritative state.
    ///
    /// THE single door for waking a task. A no-op when no waker is published —
    /// the task then notices at its next syscall or trap boundary, which is
    /// slower but not wrong. Waking is always a hint: nothing is consumed here
    /// and the woken task decides for itself what it found, so a spurious call
    /// is harmless.
    pub fn wake(&self) {
        if self
            .wake_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
                generation.checked_add(1)
            })
            .is_err()
        {
            tracing::error!(task = ?self.key, "task wake generation exhausted");
            std::process::abort();
        }
        let waker = self.waker.lock().clone();
        if let Some(waker) = waker {
            waker.wake_task();
        }
    }

    pub fn wake_generation(&self) -> u64 {
        self.wake_generation.load(Ordering::Acquire)
    }

    /// This task's own CPU (µs): its live threads plus the threads it has
    /// already retired. This is `RUSAGE_SELF` / `times`' `tms_utime`, and it
    /// deliberately does NOT consult the host process — under HVPatch that
    /// would return every guest process's CPU summed together.
    pub fn self_cpu_us(&self) -> u64 {
        let live: u64 = self
            .threads
            .lock()
            .values()
            .map(|(_, thread)| thread.cpu_us())
            .fold(0_u64, u64::saturating_add);
        live.saturating_add(self.cpu.exited_threads_us.load(Ordering::Acquire))
    }

    /// This task's own SYSTEM CPU (µs): carrick's CPU spent servicing this
    /// task's syscalls, across its live threads plus the ones that have exited.
    /// The counterpart to [`Self::self_cpu_us`], which is user time.
    pub fn self_system_cpu_us(&self) -> u64 {
        let live: u64 = self
            .threads
            .lock()
            .values()
            .map(|(_, thread)| thread.system_cpu_us())
            .fold(0_u64, u64::saturating_add);
        live.saturating_add(self.cpu.exited_threads_system_us.load(Ordering::Acquire))
    }

    /// Fold a departing thread's CPU into the task before its slot is released,
    /// so a process's own history survives its threads. BOTH ledgers — a thread
    /// that exits after servicing syscalls has system time that would otherwise
    /// vanish with it.
    pub fn retain_exited_thread_cpu(&self, thread: &Thread) {
        self.cpu
            .exited_threads_us
            .fetch_add(thread.cpu_us(), Ordering::AcqRel);
        self.cpu
            .exited_threads_system_us
            .fetch_add(thread.system_cpu_us(), Ordering::AcqRel);
    }

    /// Charge a reaped child's CPU to this task's CHILDREN ledger. Linux
    /// credits the child's own time *and* the time the child had already
    /// accumulated from its own reaped children.
    pub fn charge_reaped_child(&self, rusage: TaskRusage) {
        self.cpu.children_user_us.fetch_add(
            u64::try_from(rusage.user_time.as_micros()).unwrap_or(u64::MAX),
            Ordering::AcqRel,
        );
        self.cpu.children_system_us.fetch_add(
            u64::try_from(rusage.system_time.as_micros()).unwrap_or(u64::MAX),
            Ordering::AcqRel,
        );
    }

    /// This task's CHILDREN ledger as (user µs, system µs).
    pub fn children_cpu_us(&self) -> (u64, u64) {
        (
            self.cpu.children_user_us.load(Ordering::Acquire),
            self.cpu.children_system_us.load(Ordering::Acquire),
        )
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

    /// This task's process group — the value `getpgrp(2)` reports, and the
    /// membership key `killpg(2)` resolves against.
    pub fn process_group(&self) -> ProcessGroupId {
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

    pub(super) fn process_credentials(&self) -> Arc<Credentials> {
        self.process_credentials.load_full()
    }

    pub(super) fn replace_process_credentials(&self, credentials: Arc<Credentials>) {
        self.process_credentials.store(credentials);
    }

    pub(crate) fn is_job_control_stopped(&self) -> bool {
        self.job_control.lock().stopped_by.is_some()
    }

    pub(super) fn claim_ptrace_traceme(&self, tracer: TaskKey) -> bool {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        if state.ptrace_tracer.is_some() {
            return false;
        }
        state.ptrace_tracer = Some(tracer);
        true
    }

    pub(super) fn stop_for_ptrace(&self, signal: LinuxSignal) -> bool {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        if state.ptrace_tracer.is_none() {
            return false;
        }
        if state.stopped_by.is_some() {
            return state.stopped_by_ptrace;
        }
        state.stopped_by = Some(signal);
        state.pending_stop = Some(signal);
        state.pending_stop_is_ptrace = true;
        state.stopped_by_ptrace = true;
        true
    }

    pub(super) fn resume_from_ptrace(&self, tracer: TaskKey, signal: Option<LinuxSignal>) -> bool {
        let signal_generation = self.lock_signal_generation();
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        {
            let state = self.job_control.lock();
            if state.ptrace_tracer != Some(tracer) || !state.stopped_by_ptrace {
                return false;
            }
        }
        if let Some(signal) = signal {
            self.discard_opposing_job_control_signals(signal);
            self.record_job_control_signal_generation(signal);
            let pending = self.shared().pending_signals();
            if signal.is_realtime() {
                pending.enqueue_realtime(signal, None);
            } else {
                pending.enqueue_standard(signal, None);
            }
        }
        {
            let mut state = self.job_control.lock();
            state.ptrace_resume_signal = signal;
            state.stopped_by = None;
            state.stopped_by_ptrace = false;
        }
        drop(lifecycle);
        drop(signal_generation);
        self.job_control_changed.notify_all();
        true
    }

    pub(super) fn detach_from_ptrace(&self, tracer: TaskKey) -> bool {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        if state.ptrace_tracer != Some(tracer) {
            return false;
        }
        state.ptrace_tracer = None;
        state.ptrace_resume_signal = None;
        if state.stopped_by_ptrace {
            state.stopped_by = None;
            state.stopped_by_ptrace = false;
            self.job_control_changed.notify_all();
        }
        true
    }

    pub(super) fn consume_ptrace_resume_signal(&self, signal: LinuxSignal) -> bool {
        let mut state = self.job_control.lock();
        if state.ptrace_resume_signal == Some(signal) {
            state.ptrace_resume_signal = None;
            true
        } else {
            false
        }
    }

    /// Serialize Linux job-control generation and delivery-state transitions
    /// for this task. The guard is deliberately task-local: distinct Linux
    /// processes in HVPatch remain independent even though they share one host
    /// carrier.
    pub(super) fn lock_signal_generation(&self) -> MutexGuard<'_, ()> {
        self.signal_generation.lock()
    }

    /// Apply Linux's task-wide job-control pending-set cancellation rule while
    /// the caller holds [`Self::lock_signal_generation`]. Both the shared
    /// process queue and every live thread queue participate regardless of
    /// whether the newly generated signal itself is process- or thread-directed.
    pub(super) fn discard_opposing_job_control_signals(&self, signal: LinuxSignal) {
        let signals = if signal.raw() == carrick_abi::LINUX_SIGCONT {
            SigSet::EMPTY
                .with(carrick_abi::LINUX_SIGSTOP)
                .with(carrick_abi::LINUX_SIGTSTP)
                .with(carrick_abi::LINUX_SIGTTIN)
                .with(carrick_abi::LINUX_SIGTTOU)
        } else if matches!(
            signal.raw(),
            carrick_abi::LINUX_SIGSTOP
                | carrick_abi::LINUX_SIGTSTP
                | carrick_abi::LINUX_SIGTTIN
                | carrick_abi::LINUX_SIGTTOU
        ) {
            SigSet::EMPTY.with(carrick_abi::LINUX_SIGCONT)
        } else {
            SigSet::EMPTY
        };
        if signals.is_empty() {
            return;
        }
        self.shared().pending_signals().discard(signals);
        for thread in self.threads() {
            thread.update_signal_state(|state| state.discard_pending(signals));
        }
    }

    /// Record generation ordering for the narrow dequeue-to-default-action
    /// window. A SIGCONT can race after a vCPU removes a stop signal from its
    /// pending queue but before that vCPU applies the default stop. Remembering
    /// the cancellation lets the later action fail closed instead of re-stopping
    /// a task after the continue.
    pub(super) fn record_job_control_signal_generation(&self, signal: LinuxSignal) {
        let mut state = self.job_control.lock();
        if matches!(
            signal.raw(),
            carrick_abi::LINUX_SIGSTOP
                | carrick_abi::LINUX_SIGTSTP
                | carrick_abi::LINUX_SIGTTIN
                | carrick_abi::LINUX_SIGTTOU
        ) {
            state.default_stop_generation = DefaultStopGeneration::Pending;
        } else if matches!(
            signal.raw(),
            carrick_abi::LINUX_SIGCONT | carrick_abi::LINUX_SIGKILL
        ) {
            advance_job_control_stop_invalidation_generation(&mut state);
            state.default_stop_generation = DefaultStopGeneration::Cancelled;
        }
    }

    /// Snapshot the exact stop-invalidation epoch in which a stop left a
    /// pending queue. SIGCONT and SIGKILL both advance this epoch: neither may
    /// allow an already-dequeued stop action to park the task afterward.
    /// The caller holds [`Self::lock_signal_generation`] across dequeue and this
    /// read, so neither invalidating signal can create an ABA window.
    fn job_control_generation_for_dequeue(
        &self,
        signal: LinuxSignal,
    ) -> Option<JobControlStopInvalidationGeneration> {
        if !matches!(
            signal.raw(),
            carrick_abi::LINUX_SIGSTOP
                | carrick_abi::LINUX_SIGTSTP
                | carrick_abi::LINUX_SIGTTIN
                | carrick_abi::LINUX_SIGTTOU
        ) {
            return None;
        }
        let state = self.job_control.lock();
        match state.default_stop_generation {
            DefaultStopGeneration::Pending => Some(JobControlStopInvalidationGeneration(
                state.stop_invalidation_generation,
            )),
            DefaultStopGeneration::None | DefaultStopGeneration::Cancelled => None,
        }
    }

    /// Publish one default-stop transition and a waitable child-state event.
    /// Repeated stop signals while already stopped do not manufacture another
    /// WUNTRACED report.
    pub(super) fn stop_for_job_control(
        &self,
        signal: LinuxSignal,
        action_generation: Option<JobControlStopInvalidationGeneration>,
    ) -> bool {
        // Keep the lifecycle lock through publication. Otherwise exit could
        // clear job control between this check and the state write, leaving a
        // retired task stopped forever with nobody left to resume it.
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        match action_generation {
            Some(generation)
                if generation
                    != JobControlStopInvalidationGeneration(state.stop_invalidation_generation) =>
            {
                // Every dequeued stop action is tied to the invalidation epoch
                // in which it left pending state. A newer stop does not
                // invalidate it, but any intervening SIGCONT or SIGKILL does,
                // even if another stop has since made the aggregate state
                // Pending again.
                return true;
            }
            None if state.default_stop_generation == DefaultStopGeneration::Cancelled => {
                return true;
            }
            Some(_) | None => {}
        }
        if state.stopped_by.is_some() {
            return true;
        }
        state.stopped_by = Some(signal);
        state.pending_stop = Some(signal);
        state.pending_stop_is_ptrace = false;
        state.stopped_by_ptrace = false;
        true
    }

    fn resume_from_job_control(&self, publish_continued: bool) -> bool {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        let changed = state.stopped_by.take().is_some();
        if changed {
            state.stopped_by_ptrace = false;
            state.ptrace_resume_signal = None;
            if publish_continued {
                state.pending_continue = true;
            }
            self.job_control_changed.notify_all();
        }
        changed
    }

    /// Resume a stopped task and publish one waitable WCONTINUED transition.
    /// SIGCONT against an already-running task remains successful but creates no
    /// child-state event, matching Linux's state-change semantics.
    pub(super) fn continue_from_job_control(&self) -> bool {
        self.resume_from_job_control(true)
    }

    /// Release a stopped task so its vCPU can consume a fatal signal without
    /// manufacturing WCONTINUED. Linux reports the eventual signal death, not
    /// an intermediate continue transition caused only by SIGKILL delivery.
    pub(super) fn resume_from_job_control_for_fatal_signal(&self) -> bool {
        self.resume_from_job_control(false)
    }

    pub(crate) fn wait_until_job_control_resumed(&self) -> bool {
        let mut state = self.job_control.lock();
        let mut waited = false;
        while state.stopped_by.is_some() {
            waited = true;
            self.job_control_changed.wait(&mut state);
        }
        waited
    }

    pub(super) fn waitable_job_control_event(
        &self,
        include_stopped: bool,
        include_continued: bool,
        consume: bool,
    ) -> Option<TaskJobControlEvent> {
        let mut state = self.job_control.lock();
        if (include_stopped || state.pending_stop_is_ptrace)
            && let Some(signal) = state.pending_stop
        {
            if consume {
                state.pending_stop = None;
                state.pending_stop_is_ptrace = false;
            }
            return Some(TaskJobControlEvent::Stopped(signal));
        }
        if include_continued && state.pending_continue {
            if consume {
                state.pending_continue = false;
            }
            return Some(TaskJobControlEvent::Continued);
        }
        None
    }

    pub(super) fn begin_exit(&self) -> bool {
        let _generation = self.signal_generation.lock();
        {
            let mut lifecycle = self.lifecycle.lock();
            if *lifecycle == TaskLifecycle::Exiting {
                return false;
            }
            *lifecycle = TaskLifecycle::Exiting;
        }
        let mut job_control = self.job_control.lock();
        job_control.stopped_by = None;
        job_control.stopped_by_ptrace = false;
        job_control.ptrace_tracer = None;
        job_control.ptrace_resume_signal = None;
        self.job_control_changed.notify_all();
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
            signal_pending_hint: AtomicU64::new(0),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
            execution: Mutex::new(ThreadExecutionRecord::uninitialized()),
            cpu_accounting: Arc::new(ThreadCpuAccounting::default()),
            crash_vote: Mutex::new(None),
            crash_safe_point_participant: AtomicBool::new(false),
            thread_keyring: Mutex::new(None),
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
            signal_state: Mutex::new(ThreadSignalState::for_clone_thread(&caller_signal_state)),
            signal_pending_hint: AtomicU64::new(0),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
            execution: Mutex::new(ThreadExecutionRecord::uninitialized()),
            cpu_accounting: Arc::new(ThreadCpuAccounting::default()),
            crash_vote: Mutex::new(None),
            crash_safe_point_participant: AtomicBool::new(false),
            thread_keyring: Mutex::new(None),
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
            signal_state: Mutex::new(ThreadSignalState::for_fork(&caller_signal_state)),
            signal_pending_hint: AtomicU64::new(0),
            revision: ObjectRevision::new(),
            runner_gate: Arc::new(RunnerGate::new(key)),
            execution: Mutex::new(ThreadExecutionRecord::uninitialized()),
            cpu_accounting: Arc::new(ThreadCpuAccounting::default()),
            crash_vote: Mutex::new(None),
            crash_safe_point_participant: AtomicBool::new(false),
            thread_keyring: Mutex::new(None),
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
            signal_state: Mutex::new(ThreadSignalState::for_exec(&caller.signal_state())),
            signal_pending_hint: AtomicU64::new(caller.signal_pending_hint.load(Ordering::Acquire)),
            revision: ObjectRevision::new(),
            runner_gate: Arc::clone(&caller.runner_gate),
            execution: Mutex::new(ThreadExecutionRecord::uninitialized()),
            // The syscall service scope that committed exec still holds the
            // predecessor context until its final charge. Sharing this exact
            // logical ledger makes that post-publication interval visible to
            // the replacement without a second charge or a timing race.
            cpu_accounting: Arc::clone(&caller.cpu_accounting),
            crash_vote: Mutex::new(None),
            crash_safe_point_participant: AtomicBool::new(false),
            thread_keyring: Mutex::new(None),
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

    pub(crate) fn thread_by_registry_id(&self, registry_id: ThreadId) -> Option<ThreadRef> {
        self.threads.lock().values().find_map(|(_, thread)| {
            (thread.registry_id() == registry_id).then(|| Arc::clone(thread))
        })
    }

    pub(crate) fn threads(&self) -> Vec<ThreadRef> {
        self.threads
            .lock()
            .values()
            .map(|(_, thread)| Arc::clone(thread))
            .collect()
    }

    pub(super) fn retire_thread(&self, key: ThreadKey) -> Option<ThreadRef> {
        let mut threads = self.threads.lock();
        if threads
            .get(&key.tid)
            .is_none_or(|(published_key, _)| *published_key != key)
        {
            return None;
        }
        let retired = threads.remove(&key.tid).map(|(_, thread)| thread);
        // Retain the departing thread's CPU before it leaves the task's live
        // set: its `guest_cpu` slot is recycled by the next thread to claim
        // one, so a process that has retired threads would otherwise appear to
        // lose the CPU they burned.
        if let Some(thread) = retired.as_ref() {
            self.retain_exited_thread_cpu(thread);
            // A retired thread has left the graph and can never reach another
            // safe point. Say so at the source rather than leaving a fatal
            // sibling's quorum to infer it from a membership snapshot it took
            // before the retirement.
            thread.leave_crash_safe_point_participation();
        }
        retired
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

/// Version of one published Kernel-owned task CPU snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionGeneration(u64);

impl ExecutionGeneration {
    const INITIAL: Self = Self(1);

    fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
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
    pub(super) const fn from_scheduler(raw: u32) -> Self {
        debug_assert!(raw != 0);
        Self(raw)
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
    pub(super) fn synthetic_for_tests(raw: u32) -> Self {
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

#[derive(Debug)]
struct ThreadExecutionRecord {
    state: ThreadExecutionState,
    task_state: Option<Box<MigratableTaskState>>,
    next_executor_epoch: u64,
    exec_invalidation_pending: bool,
}

impl ThreadExecutionRecord {
    const fn uninitialized() -> Self {
        Self {
            state: ThreadExecutionState::Uninitialized,
            task_state: None,
            next_executor_epoch: 1,
            exec_invalidation_pending: false,
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
    pub const fn generation(&self) -> ExecutionGeneration {
        self.generation
    }

    pub const fn executor(&self) -> ExecutorId {
        self.executor
    }

    pub const fn executor_epoch(&self) -> u64 {
        self.executor_epoch
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
}

#[derive(Clone, Copy, Debug)]
enum ExecutionSettlement {
    Runnable,
    Blocked(BlockedReason),
    Exited,
}

impl Drop for ThreadExecutionLease {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Some(owner) = self.owner.upgrade() {
            owner.fail_unsettled_execution_lease(self);
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
    signal_pending_hint: AtomicU64,
    revision: ObjectRevision,
    runner_gate: Arc<RunnerGate>,
    execution: Mutex<ThreadExecutionRecord>,
    /// Guest USER time charged directly to this exact logical thread across
    /// every host execution interval. Executor slots are never identities.
    cpu_accounting: Arc<ThreadCpuAccounting>,
    /// Guest SYSTEM time for this thread, in nanoseconds: the CPU carrick has
    /// burned servicing THIS thread's syscalls.
    ///
    /// Service time happens on the host thread outside guest execution.
    /// Accumulated at the one
    /// dispatch boundary that reliably runs on the guest thread
    /// (`dispatch::resources::with_captured_resources`), from
    /// `CLOCK_THREAD_CPUTIME_ID` so a BLOCKED syscall — `wait4`, `epoll_wait` —
    /// contributes nothing, exactly as on Linux.
    /// This thread's answer to one task-local crash-capture generation: exact
    /// architectural state read at a safe point, or an explicit withdrawal
    /// from a park it cannot publish from. The generation prevents a delayed
    /// sibling from contaminating a later capture attempt.
    crash_vote: Mutex<Option<(CrashCaptureGeneration, CrashRegisterVote)>>,
    /// True exactly while this thread has a live vCPU loop, and therefore can
    /// still REACH a crash safe point. A thread published into the task graph
    /// whose host loop was cancelled before it started, or whose loop has
    /// already returned, is not a member of any crash quorum — waiting on one
    /// is how a fatal sibling used to burn its whole collection deadline.
    crash_safe_point_participant: AtomicBool,
    /// `KEY_SPEC_THREAD_KEYRING`, materialised on demand.
    ///
    /// Per-THREAD, keyed by this object's exact [`ThreadKey`] rather than by a
    /// host tid: under HVPatch a guest thread is a host pthread of one carrier,
    /// so a tid-keyed table would alias across guest processes and would go
    /// stale the moment a tid was reused. `keyrings(7)` makes this the one
    /// keyring a `fork` child does NOT inherit, which every constructor here
    /// gets for free by starting it at `None`.
    thread_keyring: Mutex<Option<KeySerial>>,
}

#[derive(Debug, Default)]
struct ThreadCpuAccounting {
    user_ns: AtomicU64,
    system_ns: AtomicU64,
}

impl Thread {
    pub const fn key(&self) -> ThreadKey {
        self.key
    }

    pub fn execution_state(&self) -> ThreadExecutionState {
        self.execution.lock().state
    }

    /// Hold this exact execution generation stable while a scheduler commits
    /// dependent authority. The callback may acquire run-queue state; callers
    /// must never call it from a queue-held path.
    pub(crate) fn with_execution_generation<R>(
        &self,
        generation: ExecutionGeneration,
        commit: impl FnOnce() -> R,
    ) -> Option<R> {
        let execution = self.execution.lock();
        (execution.state.generation() == Some(generation)).then(commit)
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
        let action = match execution.state {
            ThreadExecutionState::Blocked { generation, .. } => {
                let generation = generation
                    .next()
                    .ok_or(ThreadExecutionError::GenerationExhausted)?;
                execution.state = ThreadExecutionState::Runnable { generation };
                ThreadSchedulerAction::Queue {
                    key: self.key,
                    generation,
                    closing_authorized: true,
                }
            }
            ThreadExecutionState::Runnable { generation } => ThreadSchedulerAction::Queue {
                key: self.key,
                generation,
                closing_authorized: false,
            },
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
        Ok(action)
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
        execution.next_executor_epoch = next_executor_epoch;
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
        execution.exec_invalidation_pending = false;
        execution.state = ThreadExecutionState::Failed { generation, reason };
        lease.settled = true;
        drop(execution);
        self.revision.publish();
        Ok(())
    }

    /// Fail a task whose first backend snapshot could not be captured before a
    /// lease existed. No guessed or empty state is published.
    pub fn fail_uninitialized_snapshot(&self, reason: ExecutionFailure) {
        let mut execution = self.execution.lock();
        if execution.state != ThreadExecutionState::Uninitialized {
            return;
        }
        execution.task_state = None;
        execution.exec_invalidation_pending = false;
        execution.state = ThreadExecutionState::Failed {
            generation: ExecutionGeneration::INITIAL,
            reason,
        };
        drop(execution);
        self.revision.publish();
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
        if wake_pending && !scheduler_owned && !matches!(settlement, ExecutionSettlement::Exited) {
            return Err((ThreadExecutionError::SchedulerSettlementRequired, lease));
        }
        let mut action = ThreadSchedulerAction::None;
        if execution.exec_invalidation_pending {
            execution.task_state = None;
            let _ = lease.task_state.take();
            execution.state = ThreadExecutionState::Exited { generation };
            execution.exec_invalidation_pending = false;
        } else {
            match settlement {
                ExecutionSettlement::Runnable => {
                    execution.task_state = lease.task_state.take();
                    execution.state = ThreadExecutionState::Runnable { generation };
                    if scheduler_owned {
                        action = ThreadSchedulerAction::Queue {
                            key: self.key,
                            generation,
                            closing_authorized: true,
                        };
                    }
                }
                ExecutionSettlement::Blocked(reason) => {
                    execution.task_state = lease.task_state.take();
                    if wake_pending {
                        execution.state = ThreadExecutionState::Runnable { generation };
                        action = ThreadSchedulerAction::Queue {
                            key: self.key,
                            generation,
                            closing_authorized: true,
                        };
                    } else {
                        execution.state = ThreadExecutionState::Blocked { generation, reason };
                    }
                }
                ExecutionSettlement::Exited => {
                    execution.task_state = None;
                    let _ = lease.task_state.take();
                    execution.state = ThreadExecutionState::Exited { generation };
                }
            }
        }
        lease.settled = true;
        drop(execution);
        self.revision.publish();
        Ok(action)
    }

    fn validate_execution_lease_owner(
        &self,
        lease: &ThreadExecutionLease,
    ) -> Result<(), ThreadExecutionError> {
        if lease.owner_key != self.key {
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

    fn fail_unsettled_execution_lease(&self, lease: &ThreadExecutionLease) {
        let mut execution = self.execution.lock();
        if !Self::execution_state_matches_lease(execution.state, lease) {
            return;
        }
        let generation = lease
            .generation
            .next()
            .unwrap_or_else(|| std::process::abort());
        execution.task_state = None;
        execution.exec_invalidation_pending = false;
        execution.state = ThreadExecutionState::Failed {
            generation,
            reason: ExecutionFailure::UnsettledLeaseDropped {
                executor: lease.executor,
                executor_epoch: lease.executor_epoch,
            },
        };
        drop(execution);
        self.revision.publish();
    }

    /// Invalidate the old image at exec publication. The replacement starts
    /// independently at `Uninitialized` and must receive freshly materialized
    /// entry state before it can be claimed.
    pub(super) fn invalidate_execution_for_exec(&self) {
        let mut execution = self.execution.lock();
        if matches!(execution.state, ThreadExecutionState::SwitchingOut { .. }) {
            execution.exec_invalidation_pending = true;
            drop(execution);
            self.revision.publish();
            return;
        }
        let generation = execution
            .state
            .generation()
            .unwrap_or(ExecutionGeneration::INITIAL)
            .next()
            .unwrap_or_else(|| std::process::abort());
        execution.task_state = None;
        execution.exec_invalidation_pending = false;
        execution.state = ThreadExecutionState::Exited { generation };
        drop(execution);
        self.revision.publish();
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

    /// Mark that this thread's vCPU loop is live, so it can reach a crash safe
    /// point. Paired with [`Self::leave_crash_safe_point_participation`].
    pub(crate) fn enter_crash_safe_point_participation(&self) {
        self.crash_safe_point_participant
            .store(true, Ordering::Release);
    }

    /// Mark that this thread's vCPU loop has ended. It can never reach another
    /// safe point, so no crash quorum may keep expecting a vote from it. Any
    /// vote it already cast stays valid.
    pub(crate) fn leave_crash_safe_point_participation(&self) {
        self.crash_safe_point_participant
            .store(false, Ordering::Release);
    }

    /// Can this thread still reach a crash safe point?
    pub(crate) fn is_crash_safe_point_participant(&self) -> bool {
        self.crash_safe_point_participant.load(Ordering::Acquire)
    }

    /// Guest USER CPU (µs) accumulated across every execution interval.
    pub fn cpu_us(&self) -> u64 {
        self.cpu_accounting.user_ns.load(Ordering::Acquire) / 1000
    }

    /// Charge guest execution CPU directly to this logical thread. Executor
    /// slots are intentionally not accounting identities.
    pub fn charge_user_ns(&self, delta_ns: u64) {
        if delta_ns != 0 {
            self.cpu_accounting
                .user_ns
                .fetch_add(delta_ns, Ordering::AcqRel);
        }
    }

    /// Guest SYSTEM CPU (µs) this thread has accumulated — carrick's own CPU
    /// spent servicing this thread's syscalls. See [`Self::system_ns`].
    pub fn system_cpu_us(&self) -> u64 {
        self.cpu_accounting.system_ns.load(Ordering::Acquire) / 1000
    }

    /// Charge `delta_ns` of syscall-service CPU to this thread. Called once per
    /// guest syscall from the dispatch boundary, with the delta measured on the
    /// host thread's own CPU clock so blocked time is excluded.
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

    fn publish_signal_state(&self, state: &ThreadSignalState) {
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

    pub(super) fn transfer_runner_to(&self, replacement: &ThreadRef) {
        debug_assert!(Arc::ptr_eq(&self.runner_gate, &replacement.runner_gate));
        self.invalidate_execution_for_exec();
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
        Some((self.revision.load(), state.clone()))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalPendingOwner {
    Thread,
    Task,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalDequeue {
    pub owner: SignalPendingOwner,
    pub pending: PendingSignal,
    pub(crate) job_control_generation: Option<JobControlStopInvalidationGeneration>,
}

/// Exact signal leaf bundle captured from one [`super::core::KernelContext`].
/// The facade contains operations only; all state and revisions remain in the
/// referenced Kernel objects.
#[derive(Clone, Debug)]
pub struct SignalAuthority {
    sighand: Arc<Sighand>,
    task_pending: Arc<TaskPendingSignals>,
    task: TaskRef,
    thread: ThreadRef,
}

impl SignalAuthority {
    pub(crate) fn new(
        sighand: Arc<Sighand>,
        task_pending: Arc<TaskPendingSignals>,
        task: TaskRef,
        thread: ThreadRef,
    ) -> Self {
        Self {
            sighand,
            task_pending,
            task,
            thread,
        }
    }

    pub fn sighand_id(&self) -> SighandId {
        self.sighand.id()
    }

    pub fn action(&self, signal: LinuxSignal) -> LinuxSigaction {
        self.sighand.action(signal)
    }

    pub fn install_action(&self, signal: LinuxSignal, action: LinuxSigaction) {
        self.sighand.install_action(signal, action);
    }

    pub fn blocked(&self) -> SigSet {
        self.thread.signal_state.lock().blocked()
    }

    pub fn set_blocked(&self, blocked: SigSet) {
        let mut state = self.thread.signal_state.lock();
        state.set_blocked(blocked);
        self.thread.publish_signal_state(&state);
    }

    pub fn thread_pending(&self) -> SigSet {
        self.thread.signal_state.lock().pending()
    }

    pub fn task_pending(&self) -> SigSet {
        self.task_pending.present()
    }

    pub fn may_have_thread_pending(&self) -> bool {
        self.thread.may_have_pending_signals()
    }

    pub fn may_have_task_pending(&self) -> bool {
        self.task_pending.may_be_nonempty()
    }

    pub fn enqueue_thread_standard(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let mut state = self.thread.signal_state.lock();
        state.enqueue_standard(signal, siginfo);
        self.thread.publish_signal_state(&state);
    }

    pub fn enqueue_thread_realtime(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let mut state = self.thread.signal_state.lock();
        state.enqueue_realtime(signal, siginfo);
        self.thread.publish_signal_state(&state);
    }

    pub fn enqueue_task_standard(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        self.task_pending.enqueue_standard(signal, siginfo);
    }

    pub fn enqueue_task_realtime(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        self.task_pending.enqueue_realtime(signal, siginfo);
    }

    /// Choose and dequeue one candidate under the canonical thread-then-task
    /// lock order. A same-signum tie is thread-directed, preserving provenance.
    /// Job-control generation stays locked through dequeue so a later default
    /// action carries the exact stop-invalidation epoch in which it left
    /// pending state.
    pub fn take_lowest_in(&self, wanted: SigSet) -> Option<SignalDequeue> {
        let generation_guard = self.task.lock_signal_generation();
        let mut thread = self.thread.signal_state.lock();
        let mut task = self.task_pending.queue.lock();
        let thread_signal = thread.pending().intersect(wanted).lowest_signum();
        let task_signal = task.present().intersect(wanted).lowest_signum();
        let owner = match (thread_signal, task_signal) {
            (None, None) => return None,
            (Some(_), None) => SignalPendingOwner::Thread,
            (None, Some(_)) => SignalPendingOwner::Task,
            (Some(thread), Some(task)) if thread <= task => SignalPendingOwner::Thread,
            (Some(_), Some(_)) => SignalPendingOwner::Task,
        };
        let pending = match owner {
            SignalPendingOwner::Thread => {
                let mut pending = thread.take_lowest_in(wanted)?;
                if pending.siginfo.is_none() {
                    pending.siginfo = thread.take_routed_siginfo(pending.signal);
                }
                self.thread.publish_signal_state(&thread);
                pending
            }
            SignalPendingOwner::Task => {
                let pending = task.take_lowest_in(wanted)?;
                self.task_pending.publish_queue(&task);
                pending
            }
        };
        drop(thread);
        drop(task);
        let job_control_generation = self.task.job_control_generation_for_dequeue(pending.signal);
        drop(generation_guard);
        Some(SignalDequeue {
            owner,
            pending,
            job_control_generation,
        })
    }

    pub fn altstack(&self) -> Option<LinuxSigaltstack> {
        self.thread.signal_state.lock().altstack()
    }

    pub fn set_altstack(&self, altstack: Option<LinuxSigaltstack>) {
        let mut state = self.thread.signal_state.lock();
        state.set_altstack(altstack);
        self.thread.publish_signal_state(&state);
    }

    pub fn handler_frame_depth(&self) -> usize {
        self.thread.signal_state.lock().handler_frame_depth()
    }

    pub fn push_handler_frame(&self, frame: HandlerFrameState) {
        let mut state = self.thread.signal_state.lock();
        state.push_handler_frame(frame);
        self.thread.publish_signal_state(&state);
    }

    pub fn pop_handler_frame(&self) -> Option<HandlerFrameState> {
        let mut state = self.thread.signal_state.lock();
        let frame = state.pop_handler_frame();
        if frame.is_some() {
            self.thread.publish_signal_state(&state);
        }
        frame
    }

    pub fn armed_restore_mask(&self) -> Option<SigSet> {
        self.thread.signal_state.lock().armed_restore_mask()
    }

    pub fn arm_restore_mask(&self, restore_mask: Option<SigSet>) {
        let mut state = self.thread.signal_state.lock();
        state.arm_restore_mask(restore_mask);
        self.thread.publish_signal_state(&state);
    }

    pub fn record_pending_action(&self, signal: LinuxSignal, action: LinuxSigaction) {
        let mut state = self.thread.signal_state.lock();
        state.record_pending_action(signal, action);
        self.thread.publish_signal_state(&state);
    }

    pub fn take_pending_action(&self, signal: LinuxSignal) -> Option<LinuxSigaction> {
        let mut state = self.thread.signal_state.lock();
        let action = state.take_pending_action(signal);
        if action.is_some() {
            self.thread.publish_signal_state(&state);
        }
        action
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
    /// The real uid this process held when it exited. Linux `waitid(2)` reports
    /// this value in `siginfo_t.si_uid`, so it must survive task teardown.
    pub ruid: NsUid,
    /// The effective uid this process held when it exited. An unreaped process
    /// is still addressable by `sched_*`/`setpriority`/`process_vm_*`, and
    /// those calls apply the same ownership rule they apply to a live target,
    /// so the answer has to survive the task object.
    pub euid: NsUid,
    pub rusage: TaskRusage,
    /// What this task had itself accumulated from reaping its own children.
    /// Kept separate from `rusage` so `wait4` can report the child's own CPU
    /// while the reaper still charges the whole subtree to its children ledger.
    pub children_rusage: TaskRusage,
    pub diagnostic_name: String,
}

impl Zombie {
    /// Capture the exiting task's two CPU ledgers at the moment it becomes a
    /// zombie. Both are read from the kernel's own accounting: `rusage` is the
    /// child's own CPU, which `wait4` reports through its `rusage` argument,
    /// and `children_rusage` is what the child had already accumulated from
    /// reaping its own children. Linux charges a reaper BOTH, which is how
    /// `tms_cutime` totals a whole process subtree.
    pub fn from_task(task: &Task, status: LinuxWaitStatus, diagnostic_name: String) -> Self {
        let (children_user_us, children_system_us) = task.children_cpu_us();
        let credentials = task.process_credentials();
        Self {
            key: task.key(),
            parent: task.parent(),
            process_group: task.process_group(),
            session: task.session(),
            status,
            ruid: credentials.ruid(),
            euid: credentials.euid(),
            rusage: TaskRusage {
                user_time: Duration::from_micros(task.self_cpu_us()),
                system_time: Duration::from_micros(task.self_system_cpu_us()),
            },
            children_rusage: TaskRusage {
                user_time: Duration::from_micros(children_user_us),
                system_time: Duration::from_micros(children_system_us),
            },
            diagnostic_name,
        }
    }

    /// Everything a reaper must add to its own CHILDREN ledger for this child.
    pub fn total_charge_to_reaper(&self) -> TaskRusage {
        TaskRusage {
            user_time: self.rusage.user_time + self.children_rusage.user_time,
            system_time: self.rusage.system_time + self.children_rusage.system_time,
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
            let resources = Arc::new(ThreadResources::new(
                Arc::new(FileTable::new(ids.file_table_id().expect("files ID"))),
                Arc::new(FsContext::new(ids.fs_context_id().expect("fs ID"))),
                Arc::new(Credentials::root(
                    ids.credentials_id().expect("credentials ID"),
                )),
            ));
            let task = Arc::new(Task::new(
                key,
                None,
                ProcessGroupId::from_leader(task_id),
                SessionId::from_leader(task_id),
                shared,
                resources.credentials(),
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

    /// A limit belongs to ONE task, so writing another task's does not move
    /// this one's.
    ///
    /// This is the property the previous design could not have: rlimits lived in
    /// the dispatcher's private `ProcState`, reachable only by the thread running
    /// that process, so `prlimit(pid, …)` had nowhere to write except the
    /// CALLER's table. Go's `TestPrlimitFileLimit` observes both halves of that —
    /// the target unchanged AND the caller's own soft NOFILE moved underneath it.
    ///
    /// Deliberately written with TWO tasks: with one, every identity in the
    /// system coincides and the defect is invisible, which is why the four
    /// existing single-process rlimit probes all pass with the bug in place.
    #[test]
    fn an_rlimit_belongs_to_one_task_not_to_whoever_writes_it() {
        let parent = Fixture::new();
        let child = Fixture::new();

        let default_nofile = parent.task.rlimit(LinuxResource::Nofile);
        assert_eq!(child.task.rlimit(LinuxResource::Nofile), default_nofile);

        // Stand in for `prlimit(child_pid, RLIMIT_NOFILE, {42, …})`.
        let target = LinuxRlimit::new(42, default_nofile.rlim_max);
        let old = child
            .task
            .replace_rlimit(LinuxResource::Nofile, |_current| Ok::<_, ()>(target))
            .expect("replace");

        assert_eq!(
            old, default_nofile,
            "the OLD value is the target's, reported before the write"
        );
        assert_eq!(child.task.rlimit(LinuxResource::Nofile), target);
        assert_eq!(
            parent.task.rlimit(LinuxResource::Nofile),
            default_nofile,
            "writing the child's limit must not move the parent's"
        );
        // ...and only the named resource moved.
        assert_eq!(
            child.task.rlimit(LinuxResource::Fsize),
            parent.task.rlimit(LinuxResource::Fsize)
        );
    }

    /// `decide` sees the value it is replacing, which is what `setrlimit`'s
    /// rules need: a soft above the CURRENT hard is EINVAL.
    #[test]
    fn replace_rlimit_shows_the_writer_the_current_value() {
        let fixture = Fixture::new();
        let before = fixture.task.rlimit(LinuxResource::Nofile);

        let refused = fixture
            .task
            .replace_rlimit(LinuxResource::Nofile, |current| {
                assert_eq!(current, before, "the closure must see the live value");
                Err("soft above hard")
            });
        assert_eq!(refused, Err("soft above hard"));
        assert_eq!(
            fixture.task.rlimit(LinuxResource::Nofile),
            before,
            "a refused write publishes nothing"
        );
    }

    /// fork inherits limits as a COPY, and the two then diverge (`fork(2)`).
    #[test]
    fn fork_inherits_rlimits_as_a_copy() {
        let parent = Fixture::new();
        let lowered = LinuxRlimit::new(64, 4096);
        parent
            .task
            .replace_rlimit(LinuxResource::Nofile, |_| Ok::<_, ()>(lowered))
            .expect("parent lowers its own");

        let child = Fixture::new();
        child.task.inherit_fork_attributes_from(&parent.task);
        assert_eq!(
            child.task.rlimit(LinuxResource::Nofile),
            lowered,
            "inherited"
        );

        let raised = LinuxRlimit::new(128, 4096);
        child
            .task
            .replace_rlimit(LinuxResource::Nofile, |_| Ok::<_, ()>(raised))
            .expect("child changes its own");
        assert_eq!(child.task.rlimit(LinuxResource::Nofile), raised);
        assert_eq!(
            parent.task.rlimit(LinuxResource::Nofile),
            lowered,
            "the child owns its copy; the parent is untouched"
        );
    }

    /// One table answers every reader, so `getrlimit` and `/proc/<pid>/limits`
    /// cannot disagree — they disagreed on four resources when `/proc` was a
    /// frozen literal.
    #[test]
    fn the_default_set_is_the_single_source_for_every_resource() {
        let fixture = Fixture::new();
        let set = fixture.task.rlimits();
        for resource in LinuxResource::ALL {
            assert_eq!(
                set.get(resource),
                fixture.task.rlimit(resource),
                "{resource:?} must read the same through both accessors"
            );
        }
        assert_eq!(
            set.get(LinuxResource::Core),
            LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)
        );
    }

    fn siginfo(signal: LinuxSignal, payload: i32) -> LinuxSiginfo {
        let mut info: LinuxSiginfo = unsafe { std::mem::zeroed() };
        info.si_signo = signal.raw();
        info.si_code = crate::linux_abi::LINUX_SI_QUEUE;
        info._pad[..4].copy_from_slice(&payload.to_ne_bytes());
        info
    }

    #[test]
    fn task_wake_generation_is_durable_without_a_lane_waker() {
        let fixture = Fixture::new();

        assert_eq!(fixture.task.wake_generation(), 0);
        fixture.task.wake();
        assert_eq!(fixture.task.wake_generation(), 1);
        fixture.task.wake();
        assert_eq!(fixture.task.wake_generation(), 2);
    }

    #[test]
    fn sighand_retains_full_actions_and_exec_preserves_only_ignore() {
        let ids = ObjectIdRegistry::new();
        let source = Sighand::new(ids.sighand_id().expect("source sighand"));
        let ignored = LinuxSignal::for_signal_number(10).expect("ignored signal");
        let caught = LinuxSignal::for_signal_number(12).expect("caught signal");
        let mut ignored_action = LinuxSigaction::empty();
        ignored_action.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        ignored_action.sa_flags = 0x4000_0000;
        ignored_action.sa_mask = [0x55];
        let caught_action = LinuxSigaction {
            sa_handler: 0x1234_5000,
            sa_flags: 0x0800_0004,
            sa_restorer: 0x7777_0000,
            sa_mask: [0xaa],
        };
        source.install_action(ignored, ignored_action);
        source.install_action(caught, caught_action);

        let copied = Sighand::for_fork_copy(ids.sighand_id().expect("copy sighand"), &source);
        assert_eq!(copied.action(ignored), ignored_action);
        assert_eq!(copied.action(caught), caught_action);

        let exec = Sighand::for_exec(ids.sighand_id().expect("exec sighand"), &source);
        assert_eq!(exec.action(ignored), ignored_action);
        assert_eq!(exec.action(caught), LinuxSigaction::empty());
    }

    #[test]
    fn pending_queue_coalesces_standard_and_preserves_realtime_fifo_payloads() {
        let standard = LinuxSignal::for_signal_number(10).expect("standard signal");
        let realtime = LinuxSignal::for_signal_number(34).expect("realtime signal");
        let first_standard = siginfo(standard, 1);
        let coalesced_standard = siginfo(standard, 2);
        let first_rt = siginfo(realtime, 3);
        let second_rt = siginfo(realtime, 4);
        let mut queue = PendingQueue::default();

        queue.enqueue_standard(standard, Some(first_standard));
        queue.enqueue_standard(standard, Some(coalesced_standard));
        queue.enqueue_realtime(realtime, Some(first_rt));
        queue.enqueue_realtime(realtime, Some(second_rt));

        assert_eq!(queue.pending_count(), 3);
        assert_eq!(
            queue.take_lowest_in(SigSet::from_raw(u64::MAX)),
            Some(PendingSignal {
                signal: standard,
                siginfo: Some(first_standard),
            })
        );
        assert_eq!(
            queue.take_lowest_in(SigSet::from_raw(u64::MAX)),
            Some(PendingSignal {
                signal: realtime,
                siginfo: Some(first_rt),
            })
        );
        assert!(queue.present().contains(realtime.raw()));
        assert_eq!(
            queue.take_lowest_in(SigSet::from_raw(u64::MAX)),
            Some(PendingSignal {
                signal: realtime,
                siginfo: Some(second_rt),
            })
        );
        assert!(queue.present().is_empty());
    }

    #[test]
    fn task_pending_hint_never_hides_authoritative_queue_state() {
        let pending = TaskPendingSignals::new();
        let signal = LinuxSignal::for_signal_number(17).expect("signal");
        assert!(!pending.may_be_nonempty());

        pending.enqueue_standard(signal, Some(siginfo(signal, 9)));
        assert!(pending.may_be_nonempty());
        assert!(pending.present().contains(signal.raw()));

        let delivered = pending.take_lowest_in(SigSet::EMPTY.with(signal.raw()));
        assert_eq!(delivered.map(|entry| entry.signal), Some(signal));
        assert!(!pending.may_be_nonempty());
        assert!(pending.present().is_empty());
    }

    #[test]
    fn thread_signal_lifecycle_transforms_preserve_linux_owners() {
        let blocked = SigSet::EMPTY.with(10);
        let thread_pending = LinuxSignal::for_signal_number(12).expect("pending signal");
        let mut caller = ThreadSignalState::default();
        caller.set_blocked(blocked);
        caller.enqueue_standard(thread_pending, Some(siginfo(thread_pending, 7)));
        caller.set_altstack(Some(LinuxSigaltstack {
            ss_sp: 0x4000,
            ss_flags: 0,
            __pad: 0,
            ss_size: 0x2000,
        }));
        caller.push_handler_frame(HandlerFrameState {
            on_altstack: true,
            restore_mask: Some(SigSet::EMPTY.with(2)),
        });
        caller.arm_restore_mask(Some(SigSet::EMPTY.with(3)));

        let forked = ThreadSignalState::for_fork(&caller);
        assert_eq!(forked.blocked(), blocked);
        assert!(forked.pending().is_empty());
        assert!(forked.altstack_enabled());
        assert_eq!(forked.handler_frame_depth(), 1);

        let cloned = ThreadSignalState::for_clone_thread(&caller);
        assert_eq!(cloned.blocked(), blocked);
        assert!(cloned.pending().is_empty());
        assert!(!cloned.altstack_enabled());
        assert_eq!(cloned.handler_frame_depth(), 0);

        let exec = ThreadSignalState::for_exec(&caller);
        assert_eq!(exec.blocked(), blocked);
        assert!(exec.pending().contains(thread_pending.raw()));
        assert!(!exec.altstack_enabled());
        assert_eq!(exec.handler_frame_depth(), 0);
        assert_eq!(exec.armed_restore_mask(), None);
    }

    #[test]
    fn signal_authority_preserves_thread_first_same_signum_provenance() {
        let fixture = Fixture::new();
        let shared = fixture.task.shared();
        let authority = SignalAuthority::new(
            shared.sighand(),
            shared.pending_signals(),
            Arc::clone(&fixture.task),
            Arc::clone(&fixture.leader),
        );
        let signal = LinuxSignal::for_signal_number(34).expect("realtime signal");
        let thread_info = siginfo(signal, 11);
        let task_info = siginfo(signal, 22);
        authority.enqueue_task_realtime(signal, Some(task_info));
        authority.enqueue_thread_realtime(signal, Some(thread_info));

        let wanted = SigSet::EMPTY.with(signal.raw());
        assert_eq!(
            authority.take_lowest_in(wanted),
            Some(SignalDequeue {
                owner: SignalPendingOwner::Thread,
                pending: PendingSignal {
                    signal,
                    siginfo: Some(thread_info),
                },
                job_control_generation: None,
            })
        );
        assert_eq!(
            authority.take_lowest_in(wanted),
            Some(SignalDequeue {
                owner: SignalPendingOwner::Task,
                pending: PendingSignal {
                    signal,
                    siginfo: Some(task_info),
                },
                job_control_generation: None,
            })
        );
        assert!(!authority.may_have_thread_pending());
        assert!(!authority.may_have_task_pending());
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
    fn fork_copies_splice_index_while_sharing_description_pushback_cell() {
        let ids = ObjectIdRegistry::new();
        let parent = FileTable::new(ids.file_table_id().expect("parent table ID"));
        let description = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("description ID"),
        ));
        parent.install(
            FileSlotNumber::for_open_fd(3).expect("fd"),
            Arc::clone(&description),
            false,
        );
        let queue = Arc::new(Mutex::new(crate::dispatch::SplicePushback::default()));
        parent
            .splice_pushback
            .lock()
            .insert(description.id(), Arc::clone(&queue));

        let child = FileTable::for_fork_copy(ids.file_table_id().expect("child table ID"), &parent);
        let child_queue = child
            .splice_pushback
            .lock()
            .get(&description.id())
            .cloned()
            .expect("child pushback cell");
        assert!(Arc::ptr_eq(&queue, &child_queue));
    }

    #[test]
    fn file_table_retirement_waits_for_admitted_functional_use() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table ID")));
        let lease = table
            .acquire_functional_lease()
            .expect("active table lease");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let retiring = Arc::clone(&table);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("retirement started");
            let drained = retiring.drain_functional_refs();
            done_tx.send(drained).expect("retirement complete");
        });

        started_rx.recv().expect("retirement entered");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(25)).is_err(),
            "retirement completed while a functional lease was admitted"
        );
        drop(lease);
        assert!(done_rx.recv().expect("retirement released").is_empty());
        worker.join().expect("retirement worker");
        assert!(!table.functional_refs_active());
    }

    #[test]
    fn exec_freeze_blocks_table_mutation_until_publication_boundary() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table ID")));
        let freeze = table.freeze_for_exec().expect("exec freeze");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let mutating = Arc::clone(&table);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("mutation started");
            *mutating.lock_next_fd() = 4096;
            done_tx.send(()).expect("mutation complete");
        });

        started_rx.recv().expect("mutation entered");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(25)).is_err(),
            "mutation crossed the exec freeze"
        );
        drop(freeze);
        done_rx.recv().expect("mutation released");
        worker.join().expect("mutation worker");
        assert_eq!(*table.lock_next_fd(), 4096);
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
