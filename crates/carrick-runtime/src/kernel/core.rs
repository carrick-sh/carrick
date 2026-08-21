use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use carrick_hal::{FrameEventCapacity, FrameInventoryReservation, ThreadId};
use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::address::MmBackend;
use super::frame_inventory::{FrameInventoryAuthority, FrameInventoryReserveError};
use super::ids::{
    FileTableId, LinuxTid, ObjectIdError, ObjectIdRegistry, ProcessGroupId, SessionId, TaskId,
};
use super::objects::{
    Credentials, FileSlot, FileTable, FsContext, Mm, ObjectGraphError, ProcessGroup, Session,
    Sighand, Task, TaskKey, TaskLifecycle, TaskRef, TaskShared, Thread, ThreadKey, ThreadRef,
    ThreadResources, Zombie,
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
    /// Parent association observed at capture.
    ///
    /// A task's `revision` advances for any observable change, including
    /// simply gaining a child, so it cannot separate "a sibling forked"
    /// (benign for this caller) from "this task was reparented" (which must
    /// invalidate a fork, or the child attaches to the wrong parent).
    /// Recording the association itself keeps the dangerous case detectable
    /// without making the benign one fatal.
    pub(super) parent_at_capture: Option<TaskKey>,
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

    pub fn signal_authority(&self) -> super::objects::SignalAuthority {
        super::objects::SignalAuthority::new(
            self.shared.sighand(),
            self.shared.pending_signals(),
            Arc::clone(&self.task),
            Arc::clone(&self.thread),
        )
    }

    /// Retain this exact captured generation for a lifecycle handoff. This is
    /// deliberately distinct from registry capture: every Arc and revision is
    /// preserved byte-for-byte, so no newer association can be substituted.
    pub(crate) fn retain_exact(&self) -> Self {
        Self {
            kernel: Arc::clone(&self.kernel),
            task: Arc::clone(&self.task),
            thread: Arc::clone(&self.thread),
            shared: Arc::clone(&self.shared),
            resources: Arc::clone(&self.resources),
            revision: self.revision,
            parent_at_capture: self.parent_at_capture,
        }
    }

    pub fn exact_thread_is_live(&self) -> bool {
        self.task
            .thread(self.thread.key().tid)
            .is_some_and(|thread| thread.key() == self.thread.key())
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
        let parent_at_capture = task.parent();
        Self {
            kernel,
            task,
            thread,
            shared,
            resources,
            revision,
            parent_at_capture,
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

/// One coherent task-level signal observation selected under the registry read
/// lock. The context's Sighand/pending set and the live-thread roster all belong
/// to the same pre- or post-exec task revision.
pub(crate) struct KernelTaskSignalSnapshot {
    context: KernelContext,
    threads: Vec<ThreadRef>,
}

impl KernelTaskSignalSnapshot {
    pub(crate) fn context(&self) -> &KernelContext {
        &self.context
    }

    pub(crate) fn threads(&self) -> &[ThreadRef] {
        &self.threads
    }
}

impl KernelTaskBinding {
    pub const fn task_id(&self) -> TaskId {
        self.task.id
    }

    pub const fn task_key(&self) -> TaskKey {
        self.task
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

    /// Capture current signal authority for this exact task generation.
    ///
    /// The registry read lock spans task-generation validation, live-thread
    /// selection, and context capture. Exec's registry write lock therefore
    /// makes the result coherently pre- or post-exec; it can never mix the old
    /// Sighand with the replacement thread set. Selecting any live thread also
    /// handles a valid process whose original leader has retired.
    pub(crate) fn capture_signal_snapshot(&self) -> Result<KernelTaskSignalSnapshot, KernelError> {
        let state = self.kernel.registry.state.read();
        let record = state
            .tasks
            .get(&self.task.id)
            .ok_or(KernelError::UnknownTask(self.task.id))?;
        if record.task.key() != self.task {
            return Err(KernelError::StaleTaskBinding(self.task.id));
        }
        let task = Arc::clone(&record.task);
        let threads = task.threads();
        let thread = threads
            .first()
            .cloned()
            .ok_or_else(|| KernelError::UnknownThread(LinuxTid::for_task_leader(self.task.id)))?;
        Ok(KernelTaskSignalSnapshot {
            context: KernelContext::capture(
                Arc::clone(&self.kernel),
                task,
                thread,
                record.revision,
            ),
            threads,
        })
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
    frame_inventory: FrameInventoryAuthority,
    pub(super) observations: Mutex<ObservationInventory>,
    pub(super) exit_subscribers: TaskExitSubscribers,
    pub(super) pending_file_closes: Mutex<Vec<FileCloseEvent>>,
    reservation_gate: ReservationGate,
    /// The VM-wide kernel keyring store (`keyrings(7)`).
    ///
    /// It belongs to the kernel, not to a `SyscallDispatcher` or a host-process
    /// static, for the same reason the task registry does: under HVPatch every
    /// guest process is a thread of ONE carrier, so a per-dispatcher store
    /// would fragment a single Linux key namespace and a process-global one
    /// would merge every guest's keys together. Key SERIALS are only meaningful
    /// because this allocator is VM-wide.
    keyrings: crate::keyring::KeyringService,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileCloseDisposition {
    Closed,
    Transferred,
}

#[derive(Clone, Debug)]
pub(crate) struct FileCloseEvent {
    pub(crate) table: FileTableId,
    pub(crate) fd: i32,
    pub(crate) slot: FileSlot,
    pub(crate) disposition: FileCloseDisposition,
}

/// Kernel-owned, non-authoritative index of successfully published K1 object
/// generations. Every edge is weak: lifecycle and reclamation remain entirely
/// controlled by the registry/task/thread authority graph.
#[derive(Debug, Default)]
pub(super) struct ObservationInventory {
    pub(super) tasks: BTreeMap<TaskKey, Vec<Weak<Task>>>,
    pub(super) threads: BTreeMap<ThreadKey, Vec<(TaskKey, Weak<Thread>)>>,
    pub(super) mms: BTreeMap<super::ids::MmId, Vec<Weak<Mm>>>,
    pub(super) sighands: BTreeMap<super::ids::SighandId, Vec<Weak<Sighand>>>,
    pub(super) task_shared:
        BTreeMap<super::snapshot::TaskSharedObservationKey, Vec<Weak<TaskShared>>>,
    pub(super) thread_resources:
        BTreeMap<super::snapshot::ThreadResourcesObservationKey, Vec<Weak<ThreadResources>>>,
}

fn push_weak_unique<T>(objects: &mut Vec<Weak<T>>, object: &Arc<T>) {
    let weak = Arc::downgrade(object);
    if !objects.iter().any(|observed| Weak::ptr_eq(observed, &weak)) {
        objects.push(weak);
    }
}

fn retain_live_weak<T>(objects: &mut Vec<Weak<T>>) -> bool {
    objects.retain(|object| object.strong_count() != 0);
    !objects.is_empty()
}

fn observation_count(inventory: &ObservationInventory) -> usize {
    inventory.tasks.values().map(Vec::len).sum::<usize>()
        + inventory.threads.values().map(Vec::len).sum::<usize>()
        + inventory.mms.values().map(Vec::len).sum::<usize>()
        + inventory.sighands.values().map(Vec::len).sum::<usize>()
        + inventory.task_shared.values().map(Vec::len).sum::<usize>()
        + inventory
            .thread_resources
            .values()
            .map(Vec::len)
            .sum::<usize>()
}

impl ObservationInventory {
    fn register_task(
        &mut self,
        task: &TaskRef,
        thread: &ThreadRef,
        shared: &Arc<TaskShared>,
        resources: &Arc<ThreadResources>,
        publication: TaskRevision,
    ) {
        push_weak_unique(self.tasks.entry(task.key()).or_default(), task);
        self.register_task_shared(task.key(), shared, publication);
        self.register_thread(thread, resources, publication);
    }

    fn register_task_shared(
        &mut self,
        task: TaskKey,
        shared: &Arc<TaskShared>,
        publication: TaskRevision,
    ) {
        let mm = shared.mm();
        let sighand = shared.sighand();
        push_weak_unique(self.mms.entry(mm.id()).or_default(), &mm);
        push_weak_unique(self.sighands.entry(sighand.id()).or_default(), &sighand);
        push_weak_unique(
            self.task_shared
                .entry(super::snapshot::TaskSharedObservationKey {
                    task,
                    publication,
                    mm: mm.id(),
                    sighand: sighand.id(),
                })
                .or_default(),
            shared,
        );
    }

    fn register_thread(
        &mut self,
        thread: &ThreadRef,
        resources: &Arc<ThreadResources>,
        publication: TaskRevision,
    ) {
        let threads = self.threads.entry(thread.key()).or_default();
        if !threads
            .iter()
            .any(|(_, observed)| Weak::ptr_eq(observed, &Arc::downgrade(thread)))
        {
            threads.push((thread.task_key(), Arc::downgrade(thread)));
        }
        push_weak_unique(
            self.thread_resources
                .entry(super::snapshot::ThreadResourcesObservationKey {
                    thread: thread.key(),
                    publication,
                    file_table: resources.files().id(),
                    fs_context: resources.fs_context().id(),
                    credentials: resources.credentials().id(),
                })
                .or_default(),
            resources,
        );
    }

    fn sweep(&mut self) -> usize {
        let before = observation_count(self);
        self.tasks.retain(|_, objects| retain_live_weak(objects));
        self.threads.retain(|_, objects| {
            objects.retain(|(_, object)| object.strong_count() != 0);
            !objects.is_empty()
        });
        self.mms.retain(|_, objects| retain_live_weak(objects));
        self.sighands.retain(|_, objects| retain_live_weak(objects));
        self.task_shared
            .retain(|_, objects| retain_live_weak(objects));
        self.thread_resources
            .retain(|_, objects| retain_live_weak(objects));
        before - observation_count(self)
    }
}

#[derive(Debug, Default)]
struct ReservationGate {
    epoch: Mutex<u64>,
    changed: Condvar,
    #[cfg(test)]
    waiters: Mutex<usize>,
    #[cfg(test)]
    waiters_changed: Condvar,
}

impl ReservationGate {
    fn snapshot(&self) -> u64 {
        *self.epoch.lock()
    }

    fn publish_change(&self) {
        let mut epoch = self.epoch.lock();
        *epoch = epoch.wrapping_add(1);
        self.changed.notify_all();
    }

    fn wait_for_change(&self, observed: u64) {
        let mut epoch = self.epoch.lock();
        #[cfg(test)]
        {
            let mut waiters = self.waiters.lock();
            *waiters += 1;
            self.waiters_changed.notify_all();
        }
        while *epoch == observed {
            self.changed.wait(&mut epoch);
        }
        #[cfg(test)]
        {
            let mut waiters = self.waiters.lock();
            let Some(remaining) = waiters.checked_sub(1) else {
                std::process::abort();
            };
            *waiters = remaining;
            self.waiters_changed.notify_all();
        }
    }

    #[cfg(test)]
    fn wait_until_waiting(&self) {
        let mut waiters = self.waiters.lock();
        while *waiters == 0 {
            self.waiters_changed.wait(&mut waiters);
        }
    }
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

struct VforkGateState {
    publication: Mutex<VforkGatePublication>,
    changed: Condvar,
}

type VforkReleaseCallback = Arc<dyn Fn(VforkReleaseReason) + Send + Sync + 'static>;

struct VforkGatePublication {
    release: Option<VforkReleaseReason>,
    next_subscriber: u64,
    subscribers: BTreeMap<u64, VforkReleaseCallback>,
}

impl std::fmt::Debug for VforkGateState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let publication = self.publication.lock();
        formatter
            .debug_struct("VforkGateState")
            .field("release", &publication.release)
            .field("subscribers", &publication.subscribers.len())
            .finish()
    }
}

pub struct VforkReleaseSubscription {
    state: Weak<VforkGateState>,
    id: u64,
}

impl std::fmt::Debug for VforkReleaseSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VforkReleaseSubscription")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Drop for VforkReleaseSubscription {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            state.publication.lock().subscribers.remove(&self.id);
        }
    }
}

#[derive(Debug)]
pub enum VforkReleaseEnrollment {
    Ready(VforkReleaseReason),
    Subscribed(VforkReleaseSubscription),
}

#[derive(Clone, Debug)]
pub struct VforkParentWait {
    state: Arc<VforkGateState>,
}

impl VforkParentWait {
    pub fn released_reason(&self) -> Option<VforkReleaseReason> {
        self.state.publication.lock().release
    }

    pub fn subscribe_release(&self, callback: VforkReleaseCallback) -> VforkReleaseEnrollment {
        let mut publication = self.state.publication.lock();
        if let Some(reason) = publication.release {
            return VforkReleaseEnrollment::Ready(reason);
        }
        let id = publication.next_subscriber;
        publication.next_subscriber = publication
            .next_subscriber
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        publication.subscribers.insert(id, callback);
        VforkReleaseEnrollment::Subscribed(VforkReleaseSubscription {
            state: Arc::downgrade(&self.state),
            id,
        })
    }

    pub fn wait(&self) -> VforkReleaseReason {
        let mut publication = self.state.publication.lock();
        loop {
            if let Some(reason) = publication.release {
                return reason;
            }
            self.state.changed.wait(&mut publication);
        }
    }

    /// Wait for at most `timeout`, allowing an execution backend to service a
    /// concurrent quiesce request while a vfork parent remains suspended.
    pub fn wait_for_release(&self, timeout: std::time::Duration) -> Option<VforkReleaseReason> {
        let mut publication = self.state.publication.lock();
        if publication.release.is_none() {
            self.state.changed.wait_for(&mut publication, timeout);
        }
        publication.release
    }
}

#[derive(Debug)]
pub(super) struct VforkChildRelease {
    state: Arc<VforkGateState>,
}

impl VforkChildRelease {
    pub(super) fn pair() -> (VforkParentWait, Self) {
        let state = Arc::new(VforkGateState {
            publication: Mutex::new(VforkGatePublication {
                release: None,
                next_subscriber: 1,
                subscribers: BTreeMap::new(),
            }),
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
        let callbacks = {
            let mut publication = self.state.publication.lock();
            publication.release = Some(reason);
            std::mem::take(&mut publication.subscribers)
                .into_values()
                .collect::<Vec<_>>()
        };
        for callback in callbacks {
            callback(reason);
        }
        self.state.changed.notify_all();
    }
}

#[derive(Default)]
pub(super) struct TaskExitSubscribers {
    watchers: Mutex<BTreeMap<TaskKey, Vec<Weak<dyn TaskExitSubscriber>>>>,
}

impl TaskExitSubscribers {
    pub(super) fn register<T>(&self, task: TaskKey, subscriber: &Arc<T>)
    where
        T: TaskExitSubscriber + 'static,
    {
        let subscriber: Arc<dyn TaskExitSubscriber> = subscriber.clone();
        self.register_erased(task, &subscriber);
    }

    pub(super) fn register_erased(&self, task: TaskKey, subscriber: &Arc<dyn TaskExitSubscriber>) {
        self.watchers
            .lock()
            .entry(task)
            .or_default()
            .push(Arc::downgrade(subscriber));
    }

    pub(super) fn take(&self, task: TaskKey) -> Vec<Weak<dyn TaskExitSubscriber>> {
        self.watchers.lock().remove(&task).unwrap_or_default()
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
            Arc::new(Credentials::root(object_ids.credentials_id()?)),
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
            resources.credentials(),
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
            state: RegistryLock::new(RegistryState {
                epoch: 1,
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
        let mut observations = ObservationInventory::default();
        observations.register_task(
            &task,
            &leader,
            &shared,
            &leader.resources(),
            TaskRevision::INITIAL,
        );
        let kernel = Arc::new(Self {
            domain: Arc::new(KernelDomain),
            registry,
            ids,
            object_ids,
            frame_inventory: FrameInventoryAuthority::new(),
            observations: Mutex::new(observations),
            exit_subscribers: TaskExitSubscribers::default(),
            pending_file_closes: Mutex::new(Vec::new()),
            reservation_gate: ReservationGate::default(),
            keyrings: crate::keyring::KeyringService::new(),
        });
        let context = KernelContext::capture(kernel.clone(), task, leader, TaskRevision::INITIAL);
        Ok((kernel, context))
    }

    /// The VM-wide keyring store. See the field docs for why it lives here.
    pub(crate) const fn keyrings(&self) -> &crate::keyring::KeyringService {
        &self.keyrings
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

    /// Register one successfully published task generation and its initial
    /// associations. Callers hold the registry write lock first.
    pub(super) fn observe_task_publication(
        &self,
        task: &TaskRef,
        thread: &ThreadRef,
        shared: &Arc<TaskShared>,
        resources: &Arc<ThreadResources>,
        publication: TaskRevision,
    ) {
        self.observations
            .lock()
            .register_task(task, thread, shared, resources, publication);
    }

    /// Register a successfully published thread generation. Callers hold the
    /// registry write lock first.
    pub(super) fn observe_thread_publication(
        &self,
        thread: &ThreadRef,
        resources: &Arc<ThreadResources>,
        publication: TaskRevision,
    ) {
        self.observations
            .lock()
            .register_thread(thread, resources, publication);
    }

    /// Register the replacement associations made visible by exec. Callers
    /// hold the registry write lock first.
    pub(super) fn observe_exec_publication(
        &self,
        task: TaskKey,
        thread: &ThreadRef,
        shared: &Arc<TaskShared>,
        resources: &Arc<ThreadResources>,
        publication: TaskRevision,
    ) {
        let mut observations = self.observations.lock();
        observations.register_task_shared(task, shared, publication);
        observations.register_thread(thread, resources, publication);
    }

    /// Remove expired weak observations. This never changes lifecycle state or
    /// releases numeric claims. Registry-before-inventory is the fixed order,
    /// and the registry epoch makes the removal snapshot-visible.
    pub fn sweep_observations(&self) -> usize {
        let mut state = self.registry.state.write_unpublished();
        let removed = self.observations.lock().sweep();
        if removed != 0 {
            state.publish_epoch();
        }
        removed
    }

    pub(super) fn sweep_observations_until(
        &self,
        deadline: std::time::Instant,
    ) -> Result<usize, super::snapshot::KernelSnapshotError> {
        let Some(mut state) = self.registry.state.try_write_unpublished_until(deadline) else {
            return Err(if std::time::Instant::now() >= deadline {
                super::snapshot::KernelSnapshotError::TimedOut
            } else {
                super::snapshot::KernelSnapshotError::Busy
            });
        };
        let Some(mut observations) = self.observations.try_lock_until(deadline) else {
            return Err(if std::time::Instant::now() >= deadline {
                super::snapshot::KernelSnapshotError::TimedOut
            } else {
                super::snapshot::KernelSnapshotError::Busy
            });
        };
        let removed = observations.sweep();
        if removed != 0 {
            state.publish_epoch();
        }
        Ok(removed)
    }

    /// Sole runtime authority for applied frame/mapping inventory. `Stage1Mm`
    /// remains only an mm-binding seam during K1 and does not write this state.
    pub const fn frame_inventory(&self) -> &FrameInventoryAuthority {
        &self.frame_inventory
    }

    /// Allocate every candidate ID and all batch storage before entering a
    /// backend topology lock. Unclaimed candidates intentionally burn.
    pub fn reserve_frame_inventory(
        &self,
        frame_candidates: usize,
        mapping_candidates: usize,
        event_capacity: FrameEventCapacity,
    ) -> Result<FrameInventoryReservation, FrameInventoryReserveError> {
        self.frame_inventory.reserve(
            &self.object_ids,
            frame_candidates,
            mapping_candidates,
            event_capacity,
        )
    }

    pub(crate) fn reservation_epoch(&self) -> u64 {
        self.reservation_gate.snapshot()
    }

    pub(crate) fn publish_reservation_change(&self) {
        self.reservation_gate.publish_change();
    }

    pub(crate) fn wait_for_reservation_change(&self, observed: u64) {
        self.reservation_gate.wait_for_change(observed);
    }

    #[cfg(test)]
    pub(crate) fn wait_for_reservation_waiter_for_tests(&self) {
        self.reservation_gate.wait_until_waiting();
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
    pub(super) state: RegistryLock,
}

#[derive(Debug)]
pub(super) struct RegistryLock {
    inner: RwLock<RegistryState>,
}

impl RegistryLock {
    fn new(state: RegistryState) -> Self {
        Self {
            inner: RwLock::new(state),
        }
    }

    pub(super) fn read(&self) -> RwLockReadGuard<'_, RegistryState> {
        self.inner.read()
    }

    pub(super) fn try_read_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<RwLockReadGuard<'_, RegistryState>> {
        self.inner.try_read_until(deadline)
    }

    pub(super) fn write(&self) -> RwLockWriteGuard<'_, RegistryState> {
        let mut state = self.inner.write();
        state.publish_epoch();
        state
    }

    fn write_unpublished(&self) -> RwLockWriteGuard<'_, RegistryState> {
        self.inner.write()
    }

    fn try_write_unpublished_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<RwLockWriteGuard<'_, RegistryState>> {
        self.inner.try_write_until(deadline)
    }
}

/// One LIVE process's Linux identity, as [`Registry::live_processes`] reports
/// it. The field set deliberately matches the identity half of
/// [`super::snapshot::TaskSnapshotRow`] and the whole of
/// [`super::objects::Zombie`]'s identity, because the three describe the same
/// process at three points in its life and `/proc` must render them alike.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LiveProcess {
    pub key: TaskKey,
    pub parent: Option<TaskKey>,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
    pub lifecycle: TaskLifecycle,
    /// Every live thread's Linux tid, for `/proc/<pid>/task/` and — by its
    /// length — `/proc/<pid>/stat` field 20 and `status`' `Threads:`. Read from
    /// the registry's own per-task thread claims — the authority that admits
    /// and retires a thread — not from a host thread table, which under
    /// HVPatch describes the whole carrier.
    pub tids: Vec<LinuxTid>,
    pub diagnostic_name: String,
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

    pub(crate) fn zombies(&self) -> Vec<Zombie> {
        self.state
            .read()
            .zombies
            .values()
            .map(|record| record.zombie.clone())
            .collect()
    }

    /// Every LIVE process's Linux identity, for the `/proc/<pid>/{stat,status,
    /// comm,cmdline}` renderers. The sibling of [`Registry::zombies`]: that one
    /// describes the exited-but-unreaped interval, this one the interval before
    /// it, and together they are the whole set of processes a guest can name.
    ///
    /// This is a narrow read rather than a [`super::snapshot`] `TaskSnapshotRow`
    /// pass — which carries exactly these fields — because the snapshot
    /// re-derives and re-checks the entire object graph under a deadline, and
    /// the `/proc` context is rebuilt on EVERY synthetic open. The live-task
    /// count is small, so one `state` read collecting five identity fields is
    /// the whole cost.
    pub(crate) fn live_processes(&self) -> Vec<LiveProcess> {
        self.state
            .read()
            .tasks
            .values()
            .map(|record| LiveProcess {
                key: record.task.key(),
                parent: record.task.parent(),
                process_group: record.task.process_group(),
                session: record.task.session(),
                lifecycle: record.task.lifecycle(),
                tids: record.thread_claims.keys().copied().collect(),
                diagnostic_name: record.diagnostic_name.clone(),
            })
            .collect()
    }

    /// Every live process's `oom_score_adj`, keyed by its Linux pid, for the
    /// `/proc/<pid>/oom_score_adj` renderer. A snapshot rather than a per-read
    /// lookup because the synthetic-`/proc` context is assembled before the
    /// requested pid is known; the live-task count is small.
    pub(crate) fn oom_score_adj_by_pid(&self) -> BTreeMap<u32, i32> {
        // LIVE tasks only. The `/proc` renderer's contract is "a pid absent
        // from this map has no live process behind it" — that absence is what
        // makes `/proc/<dead-pid>/oom_score_adj` ENOENT. Including a lingering
        // zombie/dead record fabricated the file for a reaped pid (probe
        // `oomscoreadj`, `dead_pid_file_absent=false`).
        self.state
            .read()
            .tasks
            .iter()
            .filter(|(_, record)| record.task.lifecycle() == TaskLifecycle::Live)
            .map(|(id, record)| (id.raw() as u32, record.task.oom_score_adj()))
            .collect()
    }

    /// Apply a `/proc/<pid>/oom_score_adj` write to the live process `pid`.
    /// `false` means no such live process — the caller lowers that to ESRCH,
    /// matching a write to a pid that exited between open(2) and write(2).
    pub(crate) fn set_oom_score_adj(&self, pid: u32, value: i32) -> bool {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        let state = self.state.read();
        match state
            .tasks
            .iter()
            .find(|(id, _)| id.raw() == pid)
            .map(|(_, record)| Arc::clone(&record.task))
        {
            Some(task) => {
                task.set_oom_score_adj(value);
                true
            }
            None => false,
        }
    }

    /// The nice value of live process `pid`. `None` means no such live process,
    /// which the caller lowers to ESRCH.
    ///
    /// `getpriority(PRIO_PROCESS, peer)` needs the TARGET's value; it used to
    /// report the CALLER's, which is only right when the target IS the caller.
    pub(crate) fn task_nice(&self, pid: i32) -> Option<i32> {
        self.state
            .read()
            .tasks
            .iter()
            .find(|(id, _)| id.raw() == pid)
            .map(|(_, record)| record.task.nice())
    }

    /// Apply a nice value to live process `pid`. `false` means no such live
    /// process. Companion to [`Self::task_nice`]; nice is per-`Task`, so a
    /// cross-process `setpriority` is serviceable from the kernel graph.
    pub(crate) fn set_task_nice(&self, pid: i32, nice: i32) -> bool {
        let state = self.state.read();
        match state
            .tasks
            .iter()
            .find(|(id, _)| id.raw() == pid)
            .map(|(_, record)| Arc::clone(&record.task))
        {
            Some(task) => {
                task.set_nice(nice);
                true
            }
            None => false,
        }
    }

    /// Every LIVE task in process group `pgid`, paired with its process euid so
    /// the caller can apply setpriority(2)'s ownership rule per member. Empty
    /// means no such group (or none of its members are live) — ESRCH.
    pub(crate) fn process_group_prio_targets(
        &self,
        pgid: ProcessGroupId,
    ) -> Vec<(Arc<Task>, carrick_abi::NsUid)> {
        self.state
            .read()
            .tasks
            .values()
            .filter(|record| {
                record.task.lifecycle() == TaskLifecycle::Live
                    && record.task.process_group() == pgid
            })
            .map(|record| {
                (
                    Arc::clone(&record.task),
                    record.task.process_credentials().euid(),
                )
            })
            .collect()
    }

    /// Every LIVE task whose process euid is `uid`, for PRIO_USER. The euid in
    /// the pair is redundant (it equals `uid`) but keeps one shape with
    /// [`Self::process_group_prio_targets`] so the dispatch arm is shared.
    pub(crate) fn user_prio_targets(
        &self,
        uid: carrick_abi::NsUid,
    ) -> Vec<(Arc<Task>, carrick_abi::NsUid)> {
        self.state
            .read()
            .tasks
            .values()
            .filter(|record| {
                record.task.lifecycle() == TaskLifecycle::Live
                    && record.task.process_credentials().euid() == uid
            })
            .map(|record| {
                (
                    Arc::clone(&record.task),
                    record.task.process_credentials().euid(),
                )
            })
            .collect()
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
    pub(super) epoch: u64,
    pub(super) root: TaskKey,
    pub(super) tasks: BTreeMap<TaskId, TaskRecord>,
    pub(super) zombies: BTreeMap<TaskId, ZombieRecord>,
    pub(super) process_groups: BTreeMap<ProcessGroupId, ProcessGroupRecord>,
    pub(super) reservations: BTreeMap<TaskId, carrick_hal::KernelTransactionId>,
    pub(super) retired_threads: Vec<RetiredThreadRecord>,
    pub(super) sessions: BTreeMap<SessionId, SessionRecord>,
}

impl RegistryState {
    fn publish_epoch(&mut self) {
        let Some(next) = self.epoch.checked_add(1) else {
            std::process::abort();
        };
        self.epoch = next;
    }
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
    pub(super) _key: ThreadKey,
    pub(super) _task: TaskKey,
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
        assert!(matches!(
            stale.capture_signal_snapshot(),
            Err(KernelError::StaleTaskBinding(id)) if id == leader.task.key().id
        ));
    }

    #[test]
    fn task_binding_signal_snapshot_survives_a_retired_leader() {
        let (kernel, leader) = bootstrap(4301);
        let worker = kernel
            .clone_thread(
                &leader,
                ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::THREAD
                        | carrick_abi::LinuxCloneFlags::SIGHAND
                        | carrick_abi::LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(101),
                None,
            )
            .expect("worker");
        let binding = leader.task_binding();

        kernel.exit_thread(&leader, None).expect("retire leader");

        let captured = binding
            .capture_signal_snapshot()
            .expect("surviving worker context");
        assert_eq!(captured.context().task().key(), leader.task().key());
        assert_eq!(captured.context().thread().key(), worker.thread().key());
        assert_eq!(captured.threads().len(), 1);
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
                Arc::new(Credentials::root(
                    kernel
                        .object_ids()
                        .credentials_id()
                        .expect("new credentials"),
                )),
            )));

        let second = kernel.context(task_id, tid).expect("fresh context");
        assert!(Arc::ptr_eq(&first.shared, &original_shared));
        assert!(Arc::ptr_eq(&first.resources, &original_resources));
        assert!(!Arc::ptr_eq(&first.shared, &second.shared));
        assert!(!Arc::ptr_eq(&first.resources, &second.resources));
    }

    #[test]
    fn vfork_release_subscription_is_atomic_durable_and_exactly_once() {
        let (wait, release) = VforkChildRelease::pair();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let subscription = match wait.subscribe_release(Arc::new(move |reason| {
            assert_eq!(reason, VforkReleaseReason::Exec);
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })) {
            VforkReleaseEnrollment::Subscribed(subscription) => subscription,
            VforkReleaseEnrollment::Ready(_) => panic!("unreleased gate is not ready"),
        };
        release.release(VforkReleaseReason::Exec);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(subscription);

        assert!(matches!(
            wait.subscribe_release(Arc::new(|_| panic!("durable ready does not callback"))),
            VforkReleaseEnrollment::Ready(VforkReleaseReason::Exec)
        ));
    }

    #[test]
    fn dropped_vfork_release_subscription_is_not_called() {
        let (wait, release) = VforkChildRelease::pair();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let subscription = match wait.subscribe_release(Arc::new(move |_| {
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })) {
            VforkReleaseEnrollment::Subscribed(subscription) => subscription,
            VforkReleaseEnrollment::Ready(_) => panic!("unexpected ready"),
        };
        drop(subscription);
        release.release(VforkReleaseReason::Exit);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
