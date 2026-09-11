use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use carrick_fatal::carrick_fatal;

use carrick_hal::{FrameEventCapacity, FrameInventoryReservation, ThreadId};
use parking_lot::{Condvar, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::address::MmBackend;
use super::container::{Container, ContainerId};
use super::cpu_limit::CpuLimitWatch;
use super::frame_inventory::{FrameInventoryAuthority, FrameInventoryReserveError};
use super::ids::{
    ChildExitSignal, FileTableId, LinuxTid, ObjectIdError, ObjectIdRegistry, ProcessGroupId,
    SessionId, TaskId,
};
use super::objects::{
    Credentials, FileSlot, FileTable, FsContext, Mm, ObjectGraphError, ProcessGroup, Session,
    Sighand, Task, TaskIdentity, TaskKey, TaskLifecycle, TaskRef, TaskShared, Thread, ThreadKey,
    ThreadRef, ThreadResources, Zombie,
};
use super::operations::KernelOperationError;
use super::registry::{IdError, IdRegistry, TaskClaim, TaskReservation, ThreadClaim};

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
    /// Namespace-local identity reserved for a not-yet-published container
    /// root. This is visible only through this exact prepared context, so
    /// initialization can stamp PID 1 without publishing namespace membership
    /// ahead of the root transaction.
    provisional_namespace_pid: Option<crate::namespace::pid::PreparedNamespaceIdentityView>,
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
    pub(crate) fn issue_hvpatch_child_token(
        &self,
        cow_authority: Arc<dyn carrick_hal::FrameCowAuthority>,
        cow_identity: carrick_hal::FrameCowIdentity,
        authority_identity: std::num::NonZeroU64,
    ) -> Result<carrick_hal::HvpatchChildKernelToken, KernelError> {
        let generation = self
            .thread
            .execution_state()
            .generation()
            .ok_or(KernelError::StaleTaskBinding(self.task.key().id))?;
        if cow_identity.linux_pid != self.task.key().id.raw()
            || cow_identity.linux_tid != self.thread.key().tid.raw()
            || cow_identity.mm != self.shared.mm().id().raw()
            || cow_identity.asid == 0
        {
            return Err(KernelError::StaleTaskBinding(self.task.key().id));
        }
        Ok(self.kernel.hvpatch_child_token_issuer.issue(
            self.task.key().serial.raw(),
            self.thread.key().serial.raw(),
            generation.raw(),
            cow_identity,
            authority_identity,
            cow_authority,
        ))
    }

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

    /// The container the captured task belongs to, read through the task so
    /// the answer can never be a carrier-wide one.
    pub fn container(&self) -> Arc<Container> {
        self.task.container()
    }

    pub fn syslog(&self) -> &Arc<crate::syslog::SyslogService> {
        self.kernel.syslog()
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

    pub fn parent_at_capture(&self) -> Option<TaskKey> {
        self.parent_at_capture
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
            provisional_namespace_pid: self.provisional_namespace_pid.clone(),
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

    pub(crate) fn provisional_namespace_pid_for(&self, internal_id: u32) -> Option<u32> {
        self.provisional_namespace_pid
            .as_ref()
            .and_then(|identity| identity.visible_for(internal_id))
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
            provisional_namespace_pid: None,
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
    /// The container this kernel boots its root task into.
    container: Arc<Container>,
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
        // A reference-model kernel boots into the reference-model container.
        // Product bootstraps override this with `with_container`.
        Ok(Self {
            task_id: TaskId::for_root_bootstrap(observed_pid)?,
            registry_id,
            mm_backend,
            diagnostic_name,
            container: Arc::new(Container::for_reference_model()),
        })
    }

    /// Boot the root task inside `container` (the `Arc` `Runtime::execute`
    /// built from the CLI's `LaunchContext` and installed on the dispatcher).
    pub fn with_container(mut self, container: Arc<Container>) -> Self {
        self.container = container;
        self
    }

    pub(crate) fn into_container_root_parts(
        self,
    ) -> (ThreadId, Option<Arc<dyn MmBackend>>, String, Arc<Container>) {
        (
            self.registry_id,
            self.mm_backend,
            self.diagnostic_name,
            self.container,
        )
    }
}

/// Exact authority to unregister one auxiliary debug provider publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DebugAuxProviderRegistration {
    id: u64,
}

/// The shared carrier already has a distinct auxiliary debug provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the carrier auxiliary debug provider is already registered")]
pub struct DebugAuxProviderRegistrationError;

struct DebugAuxProviderEntry {
    id: u64,
    provider: Weak<dyn super::debug::KernelDebugAuxProvider>,
}

#[derive(Default)]
struct DebugAuxProviderRegistry {
    next_id: u64,
    carrier: Option<DebugAuxProviderEntry>,
}

impl std::fmt::Debug for DebugAuxProviderRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DebugAuxProviderRegistry")
            .field("carrier", &self.carrier.is_some())
            .finish()
    }
}

impl DebugAuxProviderRegistry {
    fn reserve_id(&mut self) -> u64 {
        self.next_id = self.next_id.checked_add(1).unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::debug_provider_identity",
                "debug provider generation exhausted u64"
            );
        });
        self.next_id
    }
}

#[cfg(test)]
#[derive(Default)]
struct ContainerRootPublicationBarriers {
    barriers: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

#[cfg(test)]
impl std::fmt::Debug for ContainerRootPublicationBarriers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContainerRootPublicationBarriers")
            .field("installed", &self.barriers.lock().is_some())
            .finish()
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
    hvpatch_child_token_issuer: Arc<carrick_hal::HvpatchChildTokenIssuer>,
    #[allow(dead_code)] // consumed by the HVPatch carrier-directory publication slice
    hvpatch_child_token_verifier: Arc<carrick_hal::HvpatchChildTokenVerifier>,
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
    /// The VM-wide kernel syslog log store (`syslog(2)` / `klogctl(3)`).
    syslog: Arc<crate::syslog::SyslogService>,
    debug_aux_providers: Mutex<DebugAuxProviderRegistry>,
    /// Controlling-terminal authority is isolated by container even though all
    /// tasks share this kernel. Each value retains the exact session/group
    /// objects, keeping their numeric claims from being reused under a relay.
    pub(super) controlling_ttys: Mutex<BTreeMap<ContainerId, ControllingTtyState>>,
    /// Every live container on this kernel, by id. The root task's container
    /// is registered by `bootstrap_root`; later ones by `create_container`.
    containers: Mutex<BTreeMap<ContainerId, Arc<Container>>>,
    pending_container_roots: Mutex<BTreeSet<ContainerId>>,
    #[cfg(test)]
    container_root_publication_barriers: ContainerRootPublicationBarriers,
    /// `RLIMIT_CPU` watchdog; see [`super::cpu_limit`].
    cpu_limit_watch: CpuLimitWatch,
    auditors: ArcSwap<crate::observe::auditor::AuditorChain>,
    abort_reason: Arc<Mutex<Option<crate::observe::auditor::AuditReason>>>,
    unpublished_jobs: AtomicUsize,
}

/// A fully constructed container-init graph that is still invisible to the
/// shared kernel. Dropping it releases every numeric/object claim; `commit`
/// is the only publication point.
#[must_use = "dropping a prepared container root rolls back every identity claim"]
pub struct PreparedContainerRoot {
    kernel: Arc<Kernel>,
    container: Arc<Container>,
    task_reservation: TaskReservation,
    leader_claim: ThreadClaim,
    task: TaskRef,
    leader: ThreadRef,
    shared: Arc<TaskShared>,
    resources: Arc<ThreadResources>,
    process_group: Arc<ProcessGroup>,
    session: Arc<Session>,
    diagnostic_name: String,
    pid_identity: Option<crate::namespace::pid::PreparedNamespaceIdentity>,
    container_reservation: ContainerRootReservation,
}

struct ContainerRootReservation {
    kernel: Weak<Kernel>,
    container: Arc<Container>,
    prepared_task: Option<TaskKey>,
    armed: bool,
}

impl ContainerRootReservation {
    fn record_prepared_task(&mut self, task: TaskKey) {
        self.prepared_task = Some(task);
    }

    fn disarm(mut self) {
        self.armed = false;
        if let Some(kernel) = self.kernel.upgrade() {
            kernel
                .pending_container_roots
                .lock()
                .remove(&self.container.id());
        }
    }
}

impl Drop for ContainerRootReservation {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(task) = self.prepared_task {
            self.container.rollback_prepared_pid_root(task);
        }
        if let Some(kernel) = self.kernel.upgrade() {
            kernel
                .pending_container_roots
                .lock()
                .remove(&self.container.id());
        }
    }
}

impl std::fmt::Debug for PreparedContainerRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedContainerRoot")
            .field("container", &self.container.id())
            .field("task", &self.task.key())
            .finish_non_exhaustive()
    }
}

impl PreparedContainerRoot {
    pub(crate) fn context(&self) -> KernelContext {
        let mut context = KernelContext::capture(
            Arc::clone(&self.kernel),
            Arc::clone(&self.task),
            Arc::clone(&self.leader),
            TaskRevision::INITIAL,
        );
        context.provisional_namespace_pid = self
            .pid_identity
            .as_ref()
            .and_then(crate::namespace::pid::PreparedNamespaceIdentity::view);
        context
    }

    /// Atomically publish every root edge after all fallible construction.
    pub fn commit(self) -> Result<KernelContext, KernelError> {
        let Self {
            kernel,
            container,
            task_reservation,
            leader_claim,
            task,
            leader,
            shared,
            resources,
            process_group,
            session,
            diagnostic_name,
            pid_identity,
            container_reservation,
        } = self;
        let task_key = task.key();
        let task_id = task_key.id;
        let leader_tid = leader.key().tid;
        let process_group_id = task.process_group();
        let session_id = task.session();
        let namespace_id = pid_identity.as_ref().map_or_else(
            || {
                u32::try_from(task_id.raw()).unwrap_or_else(|_| {
                    carrick_fatal!(
                        "kernel::container_root_publication",
                        "root without PID namespace had internal task ID outside Linux range"
                    );
                })
            },
            crate::namespace::pid::PreparedNamespaceIdentity::visible_id,
        );

        let mut state = kernel.registry.state.write_unpublished();
        let mut containers = kernel.containers.lock();
        if containers.contains_key(&container.id()) {
            return Err(KernelError::DuplicateContainer(container.id()));
        }
        if state.tasks.contains_key(&task_id) || state.container_inits.contains_key(&container.id())
        {
            return Err(KernelError::DuplicateContainer(container.id()));
        }
        let task_claim = task_reservation.commit();
        state.tasks.insert(
            task_id,
            TaskRecord {
                task: Arc::clone(&task),
                revision: TaskRevision::INITIAL,
                task_claim,
                thread_claims: BTreeMap::from([(leader_tid, leader_claim)]),
                dead_leader: None,
                vfork_release: None,
                has_execed: false,
                diagnostic_name,
            },
        );
        state.publish_process_group(
            process_group_id,
            ProcessGroupRecord {
                object: process_group,
                members: BTreeSet::from([task_key]),
                container: container.id(),
                namespace_id,
            },
        );
        state.publish_session(
            session_id,
            SessionRecord {
                object: session,
                process_groups: BTreeSet::from([process_group_id]),
                container: container.id(),
                namespace_id,
            },
        );
        state.container_inits.insert(container.id(), task_key);
        containers.insert(container.id(), Arc::clone(&container));

        // Stage every carrier-kernel edge while both graph authorities remain
        // write-locked, then publish PID membership and the container's root
        // together as the final fallible edge. A graph reader cannot return
        // the staged root until namespace identity is live, and a namespace
        // reader cannot observe membership before the complete graph exists.
        // These are commit-path locks only; steady-state PID translation and
        // graph lookup gain no additional lock or atomic operation.
        #[cfg(test)]
        kernel.pause_container_root_publication();
        if let Err(error) = container.publish_pid_root(task_key, pid_identity) {
            if containers
                .remove(&container.id())
                .is_none_or(|removed| !Arc::ptr_eq(&removed, &container))
                || state.container_inits.remove(&container.id()) != Some(task_key)
                || state.remove_session(session_id).is_none()
                || state.remove_process_group(process_group_id).is_none()
                || state.tasks.remove(&task_id).is_none()
            {
                carrick_fatal!(
                    "kernel::container_root_publication",
                    "rollback after PID-root publication failure failed to clean graph edges"
                );
            }
            return Err(error);
        }
        container.bind_kernel(&kernel);
        kernel.observe_task_publication(&task, &leader, &shared, &resources, TaskRevision::INITIAL);
        state.publish_epoch();
        drop(containers);
        drop(state);
        container_reservation.disarm();
        Ok(KernelContext::capture(
            kernel,
            task,
            leader,
            TaskRevision::INITIAL,
        ))
    }
}

#[derive(Clone, Debug)]
pub(super) struct ControllingTtyState {
    pub(super) session: Arc<Session>,
    pub(super) foreground: Arc<ProcessGroup>,
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

    /// Revoke every observation edge owned by an exact retiring task set.
    ///
    /// Weak observations normally remain useful while stale external handles
    /// drain. Container retirement is stronger: once its final topology edge
    /// disappears, no snapshot may rediscover that container through a retained
    /// `KernelContext`. Shared leaf rows are removed only when no surviving
    /// task-shared observation still names them.
    fn retire_tasks(&mut self, tasks: &BTreeSet<TaskKey>) -> usize {
        let before = observation_count(self);
        self.tasks.retain(|task, _| !tasks.contains(task));

        let mut retired_threads = BTreeSet::new();
        self.threads.retain(|thread, observations| {
            observations.retain(|(task, _)| !tasks.contains(task));
            if observations.is_empty() {
                retired_threads.insert(*thread);
                false
            } else {
                true
            }
        });
        self.thread_resources
            .retain(|key, _| !retired_threads.contains(&key.thread));

        self.task_shared.retain(|key, _| !tasks.contains(&key.task));
        let live_mms = self
            .task_shared
            .keys()
            .map(|key| key.mm)
            .collect::<BTreeSet<_>>();
        let live_sighands = self
            .task_shared
            .keys()
            .map(|key| key.sighand)
            .collect::<BTreeSet<_>>();
        self.mms.retain(|id, _| live_mms.contains(id));
        self.sighands.retain(|id, _| live_sighands.contains(id));
        self.sweep();
        before - observation_count(self)
    }

    /// Revoke every historical observation edge belonging to `container`.
    ///
    /// The live registry and zombie table are lifecycle authorities, not an
    /// observation history: a task can already have been reaped while a stale
    /// external [`KernelContext`] still keeps its weak observation upgradeable.
    /// Start from the task observations themselves so final container
    /// retirement cannot rediscover such a task through that retained handle.
    fn retire_container(&mut self, container: ContainerId) -> usize {
        let tasks = self
            .tasks
            .iter()
            .filter(|(_, observations)| {
                observations.iter().any(|task| {
                    task.upgrade()
                        .is_some_and(|task| task.container().id() == container)
                })
            })
            .map(|(task, _)| *task)
            .collect::<BTreeSet<_>>();
        self.retire_tasks(&tasks)
    }
}

type ReservationSubscriber = Arc<dyn Fn() + Send + Sync + 'static>;
type ReservationSubscribers = BTreeMap<u64, ReservationSubscriber>;

struct ReservationGate {
    epoch: Mutex<u64>,
    changed: Condvar,
    next_subscriber: AtomicU64,
    subscribers: Arc<Mutex<ReservationSubscribers>>,
    #[cfg(test)]
    waiters: Mutex<usize>,
    #[cfg(test)]
    waiters_changed: Condvar,
}

impl Default for ReservationGate {
    fn default() -> Self {
        Self {
            epoch: Mutex::new(0),
            changed: Condvar::new(),
            next_subscriber: AtomicU64::new(1),
            subscribers: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(test)]
            waiters: Mutex::new(0),
            #[cfg(test)]
            waiters_changed: Condvar::new(),
        }
    }
}

impl std::fmt::Debug for ReservationGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReservationGate")
            .field("epoch", &*self.epoch.lock())
            .field("subscribers", &self.subscribers.lock().len())
            .finish()
    }
}

pub(crate) struct ReservationChangeSubscription {
    subscribers: std::sync::Weak<Mutex<ReservationSubscribers>>,
    id: u64,
}

impl Drop for ReservationChangeSubscription {
    fn drop(&mut self) {
        if let Some(subscribers) = self.subscribers.upgrade() {
            subscribers.lock().remove(&self.id);
        }
    }
}

impl ReservationGate {
    fn snapshot(&self) -> u64 {
        *self.epoch.lock()
    }

    fn publish_change(&self) {
        let mut epoch = self.epoch.lock();
        *epoch = epoch.wrapping_add(1);
        let callbacks = std::mem::take(&mut *self.subscribers.lock());
        self.changed.notify_all();
        drop(epoch);
        for callback in callbacks.into_values() {
            callback();
        }
    }

    fn subscribe(
        &self,
        observed: u64,
        callback: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Option<ReservationChangeSubscription> {
        let epoch = self.epoch.lock();
        if *epoch != observed {
            drop(epoch);
            callback();
            return None;
        }
        let Ok(id) =
            self.next_subscriber
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                })
        else {
            drop(epoch);
            callback();
            return None;
        };
        if id == 0 {
            carrick_fatal!(
                "kernel::reservation_gate",
                "ReservationGate allocated subscriber ID 0; violates non-zero subscriber token invariant"
            );
        }
        self.subscribers.lock().insert(id, callback);
        drop(epoch);
        Some(ReservationChangeSubscription {
            subscribers: Arc::downgrade(&self.subscribers),
            id,
        })
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

    pub fn try_subscribe_release(
        &self,
        callback: VforkReleaseCallback,
    ) -> Result<VforkReleaseEnrollment, KernelOperationError> {
        let mut publication = self.state.publication.lock();
        if let Some(reason) = publication.release {
            return Ok(VforkReleaseEnrollment::Ready(reason));
        }
        let id = publication.next_subscriber;
        publication.next_subscriber = publication
            .next_subscriber
            .checked_add(1)
            .ok_or(KernelOperationError::ObjectId(ObjectIdError::Exhausted))?;
        publication.subscribers.insert(id, callback);
        Ok(VforkReleaseEnrollment::Subscribed(
            VforkReleaseSubscription {
                state: Arc::downgrade(&self.state),
                id,
            },
        ))
    }

    #[allow(clippy::expect_used)]
    pub fn subscribe_release(&self, callback: VforkReleaseCallback) -> VforkReleaseEnrollment {
        self.try_subscribe_release(callback)
            .expect("VforkParentWait subscriber ID exhaustion")
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
        let container = bootstrap.container;
        let task = Arc::new(Task::new(
            task_key,
            None,
            TaskIdentity {
                process_group: process_group_id,
                session: session_id,
            },
            Arc::clone(&shared),
            resources.credentials(),
            Arc::clone(&container),
            ChildExitSignal::SIGCHLD,
        ));
        // The container's launch-time grant is the root task's starting
        // capability set; `Task::new` seeds the grant-free Docker default
        // (`ProcessCredsNs::default()`) and forks copy whatever the parent
        // holds (`inherit_creds_ns_from`).
        let launch_caps = task.container().granted_caps();
        task.with_caps(|caps| *caps = launch_caps);
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
        let pid_identity = container.prepare_pid_root(task_key)?;
        let namespace_id = pid_identity.as_ref().map_or_else(
            || {
                u32::try_from(task_key.id.raw()).unwrap_or_else(|_| {
                    carrick_fatal!(
                        "kernel::bootstrap_identity",
                        "bootstrap root without PID namespace had internal task ID outside Linux range"
                    );
                })
            },
            crate::namespace::pid::PreparedNamespaceIdentity::visible_id,
        );
        container.publish_pid_root(task_key, pid_identity)?;

        let task_record = TaskRecord {
            task: Arc::clone(&task),
            revision: TaskRevision::INITIAL,
            task_claim,
            thread_claims: BTreeMap::from([(leader_tid, leader_claim)]),
            dead_leader: None,
            vfork_release: None,
            has_execed: false,
            diagnostic_name: bootstrap.diagnostic_name.clone(),
        };
        let registry = Registry {
            state: RegistryLock::new(RegistryState {
                epoch: 1,
                container_inits: BTreeMap::from([(container.id(), task_key)]),
                tasks: BTreeMap::from([(bootstrap.task_id, task_record)]),
                zombies: BTreeMap::new(),
                process_groups: BTreeMap::from([(
                    process_group_id,
                    ProcessGroupRecord {
                        object: process_group,
                        members: BTreeSet::from([task_key]),
                        container: container.id(),
                        namespace_id,
                    },
                )]),
                process_group_by_namespace: BTreeMap::from([(
                    (container.id(), namespace_id),
                    process_group_id,
                )]),
                reservations: BTreeMap::new(),
                retired_threads: Vec::new(),
                sessions: BTreeMap::from([(
                    session_id,
                    SessionRecord {
                        object: session,
                        process_groups: BTreeSet::from([process_group_id]),
                        container: container.id(),
                        namespace_id,
                    },
                )]),
                session_by_namespace: BTreeMap::from([(
                    (container.id(), namespace_id),
                    session_id,
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
        let (hvpatch_child_token_issuer, hvpatch_child_token_verifier) =
            carrick_hal::HvpatchChildTokenIssuer::new_pair();
        let kernel = Arc::new(Self {
            domain: Arc::new(KernelDomain),
            registry,
            ids,
            object_ids,
            frame_inventory: FrameInventoryAuthority::new(),
            hvpatch_child_token_issuer,
            hvpatch_child_token_verifier,
            observations: Mutex::new(observations),
            exit_subscribers: TaskExitSubscribers::default(),
            pending_file_closes: Mutex::new(Vec::new()),
            reservation_gate: ReservationGate::default(),
            keyrings: crate::keyring::KeyringService::new(),
            syslog: Arc::new(crate::syslog::SyslogService::new()),
            debug_aux_providers: Mutex::new(DebugAuxProviderRegistry::default()),
            controlling_ttys: Mutex::new(BTreeMap::new()),
            containers: Mutex::new(BTreeMap::from([(container.id(), Arc::clone(&container))])),
            pending_container_roots: Mutex::new(BTreeSet::new()),
            #[cfg(test)]
            container_root_publication_barriers: ContainerRootPublicationBarriers::default(),
            cpu_limit_watch: CpuLimitWatch::default(),
            auditors: {
                let auditors = crate::observe::get_container_auditors(container.id());
                ArcSwap::from(auditors)
            },
            abort_reason: Arc::new(Mutex::new(None)),
            unpublished_jobs: AtomicUsize::new(0),
        });
        container.bind_kernel(&kernel);
        let diag_name = &bootstrap.diagnostic_name;
        kernel.syslog.append(
            6,
            0,
            0,
            format!(
                "{diag_name}: process leader initialized (pid {})\n",
                bootstrap.task_id.raw()
            )
            .into_bytes(),
        );
        let context = KernelContext::capture(kernel.clone(), task, leader, TaskRevision::INITIAL);
        Ok((kernel, context))
    }

    pub fn auditors(&self) -> Arc<crate::observe::auditor::AuditorChain> {
        self.auditors.load_full()
    }

    pub fn set_auditors(&self, auditors: Arc<crate::observe::auditor::AuditorChain>) {
        self.auditors.store(auditors);
    }

    pub fn record_abort(&self, reason: crate::observe::auditor::AuditReason) {
        let mut guard = self.abort_reason.lock();
        if guard.is_none() {
            *guard = Some(reason.clone());
        }
        self.auditors.load().record_abort(reason);
    }

    pub fn abort_reason(&self) -> Option<crate::observe::auditor::AuditReason> {
        let direct = self.abort_reason.lock().clone();
        if direct.is_some() {
            return direct;
        }
        self.auditors.load().abort_reason()
    }

    pub fn unpublished_jobs(&self) -> usize {
        self.unpublished_jobs.load(Ordering::Acquire)
    }

    pub fn set_unpublished_jobs(&self, count: usize) {
        self.unpublished_jobs.store(count, Ordering::Release);
    }

    /// The kernel's `RLIMIT_CPU` watchdog.
    pub(crate) fn cpu_limit_watch(&self) -> &CpuLimitWatch {
        &self.cpu_limit_watch
    }

    pub fn container(&self, id: ContainerId) -> Option<Arc<Container>> {
        self.containers.lock().get(&id).map(Arc::clone)
    }

    pub fn container_count(&self) -> usize {
        self.containers.lock().len()
    }

    #[cfg(test)]
    pub(super) fn install_container_root_publication_barriers(
        &self,
        staged: Arc<std::sync::Barrier>,
        publish: Arc<std::sync::Barrier>,
    ) {
        let previous = self
            .container_root_publication_barriers
            .barriers
            .lock()
            .replace((staged, publish));
        assert!(previous.is_none(), "publication barriers already installed");
    }

    #[cfg(test)]
    fn pause_container_root_publication(&self) {
        let barriers = self
            .container_root_publication_barriers
            .barriers
            .lock()
            .take();
        if let Some((staged, publish)) = barriers {
            staged.wait();
            publish.wait();
        }
    }

    pub(crate) fn container_ids(&self) -> Vec<ContainerId> {
        self.containers.lock().keys().copied().collect()
    }

    /// Exact init generation for one container, never a carrier-global pid 1.
    pub fn container_init(&self, id: ContainerId) -> Option<TaskKey> {
        self.registry.state.read().container_inits.get(&id).copied()
    }

    /// Prepare a later container root without publishing any graph edge.
    pub fn prepare_container_root(
        self: &Arc<Self>,
        registry_id: ThreadId,
        mm_backend: Option<Arc<dyn MmBackend>>,
        diagnostic_name: String,
        container: Arc<Container>,
        failpoint: Option<super::operations::KernelFailpoint>,
    ) -> Result<PreparedContainerRoot, KernelError> {
        {
            let containers = self.containers.lock();
            let mut pending = self.pending_container_roots.lock();
            if containers.contains_key(&container.id())
                || pending.contains(&container.id())
                || container.pid_root().is_some()
            {
                return Err(KernelError::DuplicateContainer(container.id()));
            }
            pending.insert(container.id());
        }
        let mut container_reservation = ContainerRootReservation {
            kernel: Arc::downgrade(self),
            container: Arc::clone(&container),
            prepared_task: None,
            armed: true,
        };
        let (task_id, task_reservation) = self.ids.reserve_task()?;
        fail_container_root(failpoint, super::operations::KernelFailpoint::AfterReserve)?;
        let leader_claim = self.ids.claim_task_leader_thread(task_id)?;
        let process_group_id = ProcessGroupId::from_leader(task_id);
        let session_id = SessionId::from_leader(task_id);
        let process_group_claim = self.ids.claim_process_group(process_group_id)?;
        let session_claim = self.ids.claim_session(session_id)?;
        let mm_id = self.object_ids.mm_id()?;
        let mm = match mm_backend {
            Some(backend) => Arc::new(Mm::with_backend(mm_id, backend)),
            None => Arc::new(Mm::new_reference(mm_id)),
        };
        let shared = Arc::new(TaskShared::new(
            mm,
            Arc::new(Sighand::new(self.object_ids.sighand_id()?)),
        ));
        let resources = Arc::new(ThreadResources::new(
            Arc::new(FileTable::new(self.object_ids.file_table_id()?)),
            Arc::new(FsContext::new(self.object_ids.fs_context_id()?)),
            Arc::new(Credentials::root(self.object_ids.credentials_id()?)),
        ));
        let task_key = TaskKey {
            id: task_id,
            serial: self.object_ids.task_serial()?,
        };
        let task = Arc::new(Task::new(
            task_key,
            None,
            TaskIdentity {
                process_group: process_group_id,
                session: session_id,
            },
            Arc::clone(&shared),
            resources.credentials(),
            Arc::clone(&container),
            ChildExitSignal::SIGCHLD,
        ));
        task.with_caps(|caps| *caps = container.granted_caps());
        let leader_tid = LinuxTid::for_task_leader(task_id);
        let leader_key = ThreadKey {
            tid: leader_tid,
            serial: self.object_ids.thread_serial()?,
        };
        let leader = task.attach_thread(leader_key, registry_id, Arc::clone(&resources))?;
        let pid_identity = container.prepare_pid_root(task_key)?;
        container_reservation.record_prepared_task(task_key);
        let process_group = Arc::new(ProcessGroup::new(
            process_group_id,
            session_id,
            &self.ids,
            process_group_claim,
        )?);
        let session = Arc::new(Session::new(session_id, &self.ids, session_claim)?);
        fail_container_root(failpoint, super::operations::KernelFailpoint::AfterObjects)?;
        fail_container_root(
            failpoint,
            super::operations::KernelFailpoint::AfterBackendPrepare,
        )?;
        fail_container_root(failpoint, super::operations::KernelFailpoint::BeforePublish)?;
        Ok(PreparedContainerRoot {
            kernel: Arc::clone(self),
            container,
            task_reservation,
            leader_claim,
            task,
            leader,
            shared,
            resources,
            process_group,
            session,
            diagnostic_name,
            pid_identity,
            container_reservation,
        })
    }

    /// Settle and reap exactly one container's task tree.
    ///
    /// Validation and injected failures happen before admission closes, so a
    /// rejected retirement publishes neither topology nor an epoch. Once
    /// closed, every live task is driven through the ordinary exact exit path:
    /// thread claims, reparenting, vfork release, file-table retirement and
    /// exit subscribers therefore have the same semantics as a guest exit.
    /// The final transaction removes all exact-container zombies (including
    /// already-orphaned ones) and the container edges.
    pub fn retire_container_root(
        self: &Arc<Self>,
        container_id: ContainerId,
        failpoint: Option<super::operations::KernelFailpoint>,
    ) -> Result<crate::carrier::ContainerTeardown, KernelError> {
        fail_container_root(failpoint, super::operations::KernelFailpoint::AfterReserve)?;
        let (container, init, mut live_tasks) = {
            let state = self.registry.state.write_unpublished();
            let containers = self.containers.lock();
            let container = containers
                .get(&container_id)
                .map(Arc::clone)
                .ok_or(KernelError::UnknownContainer(container_id))?;
            let init = state
                .container_inits
                .get(&container_id)
                .copied()
                .ok_or(KernelError::UnknownContainer(container_id))?;
            let selected: BTreeSet<TaskId> = state
                .tasks
                .iter()
                .filter(|(_, record)| record.task.container().id() == container_id)
                .map(|(id, _)| *id)
                .collect();
            if (!selected.contains(&init.id)
                && state
                    .zombies
                    .get(&init.id)
                    .is_none_or(|record| record.zombie.key != init))
                || selected
                    .iter()
                    .any(|id| state.reservations.contains_key(id))
            {
                return Err(KernelError::ContainerBusy(container_id));
            }
            if selected.iter().any(|id| {
                state.tasks.get(id).is_none_or(|record| {
                    record.task.children().iter().any(|child| {
                        !selected.contains(&child.id)
                            && state
                                .zombies
                                .get(&child.id)
                                .is_none_or(|zombie| zombie.zombie.container != container_id)
                    })
                })
            }) {
                return Err(KernelError::ContainerTopology(container_id));
            }
            fail_container_root(failpoint, super::operations::KernelFailpoint::AfterObjects)?;
            fail_container_root(
                failpoint,
                super::operations::KernelFailpoint::AfterBackendPrepare,
            )?;
            fail_container_root(failpoint, super::operations::KernelFailpoint::BeforePublish)?;

            // This store occurs under the same registry write lock consulted
            // by fork/thread-clone admission, closing the validation race.
            container.begin_retirement();
            let live_tasks = selected
                .into_iter()
                .filter_map(|id| state.tasks.get(&id).map(|record| record.task.key()))
                .collect::<Vec<_>>();
            (container, init, live_tasks)
        };

        // Non-init tasks first. Their ordinary exit transaction reparents any
        // children to the still-live init; init then orphans all remaining
        // live/zombie children exactly as normal Linux task exit does.
        live_tasks.sort_by_key(|task| task.id == init.id);
        for task in live_tasks {
            self.exit_task_key_eventually(
                task,
                super::objects::LinuxWaitStatus::from_wait_encoding(0),
            )
            .map_err(|_| KernelError::ContainerTopology(container_id))?;
        }

        let retiring_tasks = {
            let state = self.registry.state.read();
            let containers = self.containers.lock();
            if containers
                .get(&container_id)
                .is_none_or(|current| !Arc::ptr_eq(current, &container))
            {
                return Err(KernelError::UnknownContainer(container_id));
            }
            if state
                .tasks
                .values()
                .any(|record| record.task.container().id() == container_id)
                || state.reservations.keys().any(|task| {
                    state
                        .tasks
                        .get(task)
                        .is_some_and(|record| record.task.container().id() == container_id)
                })
            {
                return Err(KernelError::ContainerBusy(container_id));
            }
            state
                .zombies
                .iter()
                .filter(|(_, record)| record.zombie.container == container_id)
                .map(|(_, record)| record.zombie.key)
                .collect::<BTreeSet<_>>()
        };

        // Namespace and observation authority disappear before the container's
        // final table edge. Admission is already closed and every task is a
        // zombie, so no new observation can be published for this container.
        let pid_region_released = match container.pid_region() {
            Some(region) => {
                if !region.retire() {
                    return Err(KernelError::PidNamespaceRetirement(container_id));
                }
                true
            }
            None => false,
        };
        self.observations.lock().retire_container(container_id);
        container.mark_retired();

        let tasks_reaped = {
            let mut state = self.registry.state.write_unpublished();
            let mut containers = self.containers.lock();
            if state
                .tasks
                .values()
                .any(|record| record.task.container().id() == container_id)
                || state.reservations.keys().any(|task| {
                    state
                        .tasks
                        .get(task)
                        .is_some_and(|record| record.task.container().id() == container_id)
                })
            {
                carrick_fatal!(
                    "kernel::container_retirement",
                    "live tasks or reservations reappeared after container retirement closed"
                );
            }
            let tasks_reaped = retiring_tasks
                .iter()
                .map(|key| {
                    let record = state.zombies.remove(&key.id).unwrap_or_else(|| {
                        carrick_fatal!(
                            "kernel::container_retirement",
                            "retiring task lost its zombie record"
                        );
                    });
                    if record.zombie.key != *key || record.zombie.container != container_id {
                        carrick_fatal!(
                            "kernel::container_retirement",
                            "removed zombie did not match retiring task generation and container"
                        );
                    }
                    record
                })
                .count();
            self.controlling_ttys.lock().remove(&container_id);
            if state.container_inits.remove(&container_id) != Some(init) {
                carrick_fatal!(
                    "kernel::container_retirement",
                    "container-init index did not name the root generation being retired"
                );
            }
            let removed = containers.remove(&container_id).unwrap_or_else(|| {
                carrick_fatal!(
                    "kernel::container_retirement",
                    "container registry lost the entry selected for retirement"
                );
            });
            if !Arc::ptr_eq(&removed, &container) {
                carrick_fatal!(
                    "kernel::container_retirement",
                    "removed container was not the exact object being drained"
                );
            }
            state.publish_epoch();
            tasks_reaped
        };
        Ok(crate::carrier::ContainerTeardown {
            id: container_id,
            carrier_scope_id: container.launch().carrier_scope_id.clone(),
            run_id: container.run_id().clone(),
            tasks_reaped,
            mounts_dropped: 0,
            pid_region_released,
        })
    }

    pub fn register_debug_aux_provider(
        &self,
        provider: &Arc<dyn super::debug::KernelDebugAuxProvider>,
    ) -> Result<DebugAuxProviderRegistration, DebugAuxProviderRegistrationError> {
        let mut providers = self.debug_aux_providers.lock();
        if let Some(entry) = providers.carrier.as_ref()
            && let Some(current) = entry.provider.upgrade()
        {
            return if Arc::ptr_eq(&current, provider) {
                Ok(DebugAuxProviderRegistration { id: entry.id })
            } else {
                Err(DebugAuxProviderRegistrationError)
            };
        }
        providers.carrier = None;
        let id = providers.reserve_id();
        providers.carrier = Some(DebugAuxProviderEntry {
            id,
            provider: Arc::downgrade(provider),
        });
        Ok(DebugAuxProviderRegistration { id })
    }

    pub fn unregister_debug_aux_provider(
        &self,
        registration: DebugAuxProviderRegistration,
    ) -> bool {
        let mut providers = self.debug_aux_providers.lock();
        if providers
            .carrier
            .as_ref()
            .is_none_or(|entry| entry.id != registration.id)
        {
            return false;
        }
        providers.carrier = None;
        true
    }

    /// Select the shared carrier's provider for its unscoped auxiliary tables.
    pub fn debug_aux_provider(&self) -> Option<Arc<dyn super::debug::KernelDebugAuxProvider>> {
        let mut providers = self.debug_aux_providers.lock();
        let provider = providers
            .carrier
            .as_ref()
            .and_then(|entry| entry.provider.upgrade());
        if provider.is_none() {
            providers.carrier = None;
        }
        provider
    }

    /// The VM-wide keyring store. See the field docs for why it lives here.
    pub(crate) const fn keyrings(&self) -> &crate::keyring::KeyringService {
        &self.keyrings
    }

    /// The VM-wide syslog store.
    pub(crate) fn syslog(&self) -> &Arc<crate::syslog::SyslogService> {
        &self.syslog
    }

    pub(super) fn domain(&self) -> &Arc<KernelDomain> {
        &self.domain
    }

    pub const fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn set_diagnostic_name(&self, id: TaskId, name: String) -> bool {
        self.registry.set_diagnostic_name(id, name)
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

    #[allow(dead_code)] // consumed by the HVPatch carrier-directory publication slice
    pub(crate) fn hvpatch_child_token_verifier(
        &self,
    ) -> Arc<carrick_hal::HvpatchChildTokenVerifier> {
        Arc::clone(&self.hvpatch_child_token_verifier)
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

    pub(crate) fn subscribe_reservation_change(
        &self,
        observed: u64,
        callback: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Option<ReservationChangeSubscription> {
        self.reservation_gate.subscribe(observed, callback)
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
        if state.container_inits.values().any(|root| {
            state
                .tasks
                .get(&root.id)
                .is_none_or(|record| record.task.key() != *root)
        }) {
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
            if group.object.session() != session_id
                || group.container != record.task.container().id()
                || !group.members.contains(&key)
            {
                return Err(RegistryInvariantError::ProcessGroupBacklink);
            }
            let Some(session) = state.sessions.get(&session_id) else {
                return Err(RegistryInvariantError::MissingSession);
            };
            if session.container != record.task.container().id()
                || !session.process_groups.contains(&group_id)
            {
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
        if state.process_group_by_namespace.len() != state.process_groups.len() {
            return Err(RegistryInvariantError::ProcessGroupBacklink);
        }
        let mut process_group_names = BTreeSet::new();
        for (group_id, group) in &state.process_groups {
            if !self.ids.is_reserved_number(group_id.raw()) {
                return Err(RegistryInvariantError::ProcessGroupClaim);
            }
            if !process_group_names.insert((group.container, group.namespace_id)) {
                return Err(RegistryInvariantError::ProcessGroupBacklink);
            }
            if state
                .process_group_by_namespace
                .get(&(group.container, group.namespace_id))
                != Some(group_id)
            {
                return Err(RegistryInvariantError::ProcessGroupBacklink);
            }
            for member in &group.members {
                let Some(task) = state.tasks.get(&member.id) else {
                    return Err(RegistryInvariantError::MissingGroupMember);
                };
                if task.task.key() != *member
                    || task.task.process_group() != *group_id
                    || task.task.container().id() != group.container
                {
                    return Err(RegistryInvariantError::ProcessGroupBacklink);
                }
            }
        }
        if state.session_by_namespace.len() != state.sessions.len() {
            return Err(RegistryInvariantError::SessionBacklink);
        }
        let mut session_names = BTreeSet::new();
        for (session_id, session) in &state.sessions {
            if !self.ids.is_reserved_number(session_id.raw()) {
                return Err(RegistryInvariantError::SessionClaim);
            }
            if !session_names.insert((session.container, session.namespace_id)) {
                return Err(RegistryInvariantError::SessionBacklink);
            }
            if state
                .session_by_namespace
                .get(&(session.container, session.namespace_id))
                != Some(session_id)
            {
                return Err(RegistryInvariantError::SessionBacklink);
            }
            for group_id in &session.process_groups {
                let Some(group) = state.process_groups.get(group_id) else {
                    return Err(RegistryInvariantError::MissingProcessGroup);
                };
                if group.object.session() != *session_id || group.container != session.container {
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
    pub container: ContainerId,
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

    pub(crate) fn zombies_for_container(&self, container: ContainerId) -> Vec<Zombie> {
        self.state
            .read()
            .zombies
            .values()
            .filter(|record| record.zombie.container == container)
            .map(|record| record.zombie.clone())
            .collect()
    }

    /// Every LIVE process's Linux identity, for the `/proc/<pid>/{stat,status,
    /// comm,cmdline}` renderers. The sibling of [`Registry::zombies_for_container`]: that one
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
                container: record.task.container().id(),
                parent: record.task.parent(),
                process_group: record.task.process_group(),
                session: record.task.session(),
                lifecycle: record.task.lifecycle(),
                tids: record.thread_claims.keys().copied().collect(),
                diagnostic_name: record.diagnostic_name.clone(),
            })
            .collect()
    }

    pub(crate) fn live_processes_for_container(&self, container: ContainerId) -> Vec<LiveProcess> {
        self.live_processes()
            .into_iter()
            .filter(|process| process.container == container)
            .collect()
    }

    /// Every live process's `oom_score_adj`, keyed by its Linux pid, for the
    /// `/proc/<pid>/oom_score_adj` renderer. A snapshot rather than a per-read
    /// lookup because the synthetic-`/proc` context is assembled before the
    /// requested pid is known; the live-task count is small.
    pub(crate) fn oom_score_adj_by_pid_for_container(
        &self,
        container: ContainerId,
    ) -> BTreeMap<u32, i32> {
        self.state
            .read()
            .tasks
            .iter()
            .filter(|(_, record)| {
                record.task.lifecycle() == TaskLifecycle::Live
                    && record.task.container().id() == container
            })
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
        let Ok(task_id) = TaskId::from_abi_positive(pid) else {
            return false;
        };
        let state = self.state.read();
        match state.tasks.get(&task_id) {
            Some(record) => {
                record.task.set_oom_score_adj(value);
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
        let Ok(task_id) = TaskId::from_abi_positive(pid) else {
            return None;
        };
        self.state
            .read()
            .tasks
            .get(&task_id)
            .map(|record| record.task.nice())
    }

    /// Apply a nice value to live process `pid`. `false` means no such live
    /// process. Companion to [`Self::task_nice`]; nice is per-`Task`, so a
    /// cross-process `setpriority` is serviceable from the kernel graph.
    pub(crate) fn set_task_nice(&self, pid: i32, nice: i32) -> bool {
        let Ok(task_id) = TaskId::from_abi_positive(pid) else {
            return false;
        };
        let state = self.state.read();
        match state.tasks.get(&task_id) {
            Some(record) => {
                record.task.set_nice(nice);
                true
            }
            None => false,
        }
    }

    /// Apply a diagnostic/comm name update to live process `id`. `false` means
    /// no such live process.
    pub(crate) fn set_diagnostic_name(&self, id: TaskId, name: String) -> bool {
        let mut state = self.state.write();
        match state.tasks.get_mut(&id) {
            Some(record) => {
                record.diagnostic_name = name;
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
        container: ContainerId,
        pgid: ProcessGroupId,
    ) -> Vec<(Arc<Task>, carrick_abi::NsUid)> {
        let state = self.state.read();
        let Some(group) = state.process_groups.get(&pgid) else {
            return Vec::new();
        };
        group
            .members
            .iter()
            .filter_map(|member| {
                let record = state.tasks.get(&member.id)?;
                if record.task.key() == *member
                    && record.task.container().id() == container
                    && record.task.lifecycle() == TaskLifecycle::Live
                {
                    Some((
                        Arc::clone(&record.task),
                        record.task.process_credentials().euid(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Every LIVE task whose process euid is `uid`, for PRIO_USER. The euid in
    /// the pair is redundant (it equals `uid`) but keeps one shape with
    /// [`Self::process_group_prio_targets`] so the dispatch arm is shared.
    ///
    /// Note (docs/kernel-collections-research-2026-08-23.md T2/M6): This remains
    /// a linear task scan because maintaining a reverse euid index would require
    /// joining every credential transition.
    pub(crate) fn user_prio_targets(
        &self,
        container: ContainerId,
        uid: carrick_abi::NsUid,
    ) -> Vec<(Arc<Task>, carrick_abi::NsUid)> {
        self.state
            .read()
            .tasks
            .values()
            .filter(|record| {
                record.task.lifecycle() == TaskLifecycle::Live
                    && record.task.container().id() == container
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

    /// Resolve a namespace-visible process-group id inside one container.
    ///
    /// This is deliberately backed by the process-group record rather than by
    /// the leader's task/PID entry: Linux keeps the group name live while any
    /// member remains, even after the leader has exited and been reaped.
    pub(crate) fn process_group_from_namespace(
        &self,
        container: ContainerId,
        namespace_id: u32,
    ) -> Option<ProcessGroupId> {
        let state = self.state.read();
        let id = *state
            .process_group_by_namespace
            .get(&(container, namespace_id))?;
        state.process_groups.contains_key(&id).then_some(id)
    }

    /// Render a live process-group id in exactly one container's namespace.
    pub(crate) fn process_group_to_namespace(
        &self,
        container: ContainerId,
        id: ProcessGroupId,
    ) -> Option<u32> {
        self.state
            .read()
            .process_groups
            .get(&id)
            .filter(|record| record.container == container)
            .map(|record| record.namespace_id)
    }

    pub fn session(&self, id: SessionId) -> Option<Arc<Session>> {
        self.state
            .read()
            .sessions
            .get(&id)
            .map(|record| Arc::clone(&record.object))
    }

    /// Resolve a namespace-visible session id inside one container. Session
    /// identity follows the session record, not its (possibly reaped) leader.
    pub(crate) fn session_from_namespace(
        &self,
        container: ContainerId,
        namespace_id: u32,
    ) -> Option<SessionId> {
        let state = self.state.read();
        let id = *state.session_by_namespace.get(&(container, namespace_id))?;
        state.sessions.contains_key(&id).then_some(id)
    }

    /// Render a live session id in exactly one container's namespace.
    pub(crate) fn session_to_namespace(
        &self,
        container: ContainerId,
        id: SessionId,
    ) -> Option<u32> {
        self.state
            .read()
            .sessions
            .get(&id)
            .filter(|record| record.container == container)
            .map(|record| record.namespace_id)
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
    pub(super) container_inits: BTreeMap<ContainerId, TaskKey>,
    pub(super) tasks: BTreeMap<TaskId, TaskRecord>,
    pub(super) zombies: BTreeMap<TaskId, ZombieRecord>,
    pub(super) process_groups: BTreeMap<ProcessGroupId, ProcessGroupRecord>,
    pub(super) process_group_by_namespace: BTreeMap<(ContainerId, u32), ProcessGroupId>,
    pub(super) reservations: BTreeMap<TaskId, carrick_hal::KernelTransactionId>,
    pub(super) retired_threads: Vec<RetiredThreadRecord>,
    pub(super) sessions: BTreeMap<SessionId, SessionRecord>,
    pub(super) session_by_namespace: BTreeMap<(ContainerId, u32), SessionId>,
}

fn fail_container_root(
    selected: Option<super::operations::KernelFailpoint>,
    boundary: super::operations::KernelFailpoint,
) -> Result<(), KernelError> {
    if selected == Some(boundary) {
        Err(KernelError::InjectedContainerRootFailure(boundary))
    } else {
        Ok(())
    }
}

impl RegistryState {
    fn publish_epoch(&mut self) {
        let Some(next) = self.epoch.checked_add(1) else {
            carrick_fatal!(
                "kernel::registry_epoch",
                "Kernel RegistryState epoch counter overflow"
            );
        };
        self.epoch = next;
    }

    pub(super) fn publish_process_group(&mut self, id: ProcessGroupId, record: ProcessGroupRecord) {
        let namespace_key = (record.container, record.namespace_id);
        if self.process_groups.contains_key(&id)
            || self.process_group_by_namespace.contains_key(&namespace_key)
        {
            carrick_fatal!(
                "kernel::process_group_index",
                "process-group publication collided in internal or container namespace index"
            );
        }
        self.process_group_by_namespace.insert(namespace_key, id);
        self.process_groups.insert(id, record);
    }

    pub(super) fn remove_process_group(
        &mut self,
        id: ProcessGroupId,
    ) -> Option<ProcessGroupRecord> {
        let record = self.process_groups.remove(&id)?;
        if self
            .process_group_by_namespace
            .remove(&(record.container, record.namespace_id))
            != Some(id)
        {
            carrick_fatal!(
                "kernel::process_group_index",
                "removing process-group did not remove matching container namespace index edge"
            );
        }
        Some(record)
    }

    pub(super) fn publish_session(&mut self, id: SessionId, record: SessionRecord) {
        let namespace_key = (record.container, record.namespace_id);
        if self.sessions.contains_key(&id) || self.session_by_namespace.contains_key(&namespace_key)
        {
            carrick_fatal!(
                "kernel::session_index",
                "session publication collided in internal or container namespace index"
            );
        }
        self.session_by_namespace.insert(namespace_key, id);
        self.sessions.insert(id, record);
    }

    pub(super) fn remove_session(&mut self, id: SessionId) -> Option<SessionRecord> {
        let record = self.sessions.remove(&id)?;
        if self
            .session_by_namespace
            .remove(&(record.container, record.namespace_id))
            != Some(id)
        {
            carrick_fatal!(
                "kernel::session_index",
                "removing session did not remove matching container namespace index edge"
            );
        }
        Some(record)
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
    /// Namespace that owns this group name. Internal `ProcessGroupId` remains
    /// the scheduler/kernel key; this pair is the guest-facing authority.
    pub(super) container: ContainerId,
    pub(super) namespace_id: u32,
}

#[derive(Debug)]
pub(super) struct SessionRecord {
    pub(super) object: Arc<Session>,
    pub(super) process_groups: BTreeSet<ProcessGroupId>,
    /// Namespace that owns this session name. Its lifetime is exactly this
    /// record's lifetime, independent of the leader's task slot.
    pub(super) container: ContainerId,
    pub(super) namespace_id: u32,
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
    #[error("container {0:?} is already registered on this kernel")]
    DuplicateContainer(ContainerId),
    #[error("container {0:?} already has an init task")]
    ContainerRootAlreadyPublished(ContainerId),
    #[error("container root failed at injected boundary {0:?}")]
    InjectedContainerRootFailure(super::operations::KernelFailpoint),
    #[error("container {0:?} has no live init task")]
    UnknownContainer(ContainerId),
    #[error("container {0:?} init could not join its PID namespace")]
    PidNamespaceMembership(ContainerId),
    #[error("container {0:?} PID namespace could not be retired")]
    PidNamespaceRetirement(ContainerId),
    #[error("container {0:?} still has an in-flight kernel transaction")]
    ContainerBusy(ContainerId),
    #[error("container {0:?} task tree crosses a container boundary")]
    ContainerTopology(ContainerId),
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
    use crate::kernel::container::{LaunchContext, RunId};
    use crate::kernel::{
        ClonePlan, Credentials, FileTable, FsContext, LinuxWaitStatus, Mm, Sighand,
    };

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

    #[test]
    fn vfork_parent_wait_try_subscribe_release_exhaustion() {
        let (wait, _release) = VforkChildRelease::pair();
        wait.state.publication.lock().next_subscriber = u64::MAX;
        let res = wait.try_subscribe_release(Arc::new(|_| {}));
        assert!(matches!(res, Err(KernelOperationError::ObjectId(_))));
    }

    #[test]
    fn process_attribute_lookups_by_pid_use_exact_task_id_and_reject_misses() {
        let (kernel, context) = bootstrap(4500);
        let pid = context.task.key().id.raw();

        assert_eq!(kernel.registry().task_nice(pid), Some(0));
        assert!(kernel.registry().set_task_nice(pid, 5));
        assert_eq!(kernel.registry().task_nice(pid), Some(5));

        assert!(kernel.registry().set_oom_score_adj(pid as u32, 200));
        assert_eq!(context.task.oom_score_adj(), 200);

        assert_eq!(kernel.registry().task_nice(99999), None);
        assert!(!kernel.registry().set_task_nice(99999, 10));
        assert!(!kernel.registry().set_oom_score_adj(99999, 100));

        assert_eq!(kernel.registry().task_nice(0), None);
        assert_eq!(kernel.registry().task_nice(-1), None);
        assert!(!kernel.registry().set_task_nice(0, 10));
        assert!(!kernel.registry().set_task_nice(-1, 10));
        assert!(!kernel.registry().set_oom_score_adj(0, 100));

        assert!(!kernel.registry().set_oom_score_adj(u32::MAX, 100));
    }

    #[test]
    fn process_group_prio_targets_matches_live_group_members_and_filters_dead_members() {
        let (kernel, root) = bootstrap(5000);
        let pgid_root = ProcessGroupId::from_leader(root.task.key().id);

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

        let child1 = fork(5001, "child-1");
        let child2 = fork(5002, "child-2");
        kernel
            .set_process_group(root.task.key().id, Some(child2.task.key().id), None)
            .expect("setpgid child2");
        let pgid_child2 = ProcessGroupId::from_leader(child2.task.key().id);

        let child3 = fork(5003, "child-3");
        kernel
            .exit_task(
                child3.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("child 3 exit");

        // Child 4 in root's process group, but currently Exiting (not Live)
        let child4 = fork(5004, "child-4");
        assert!(child4.task.begin_exit());

        let container = root.task.container().id();
        let root_targets = kernel
            .registry()
            .process_group_prio_targets(container, pgid_root);
        let root_target_ids: Vec<TaskId> = root_targets.iter().map(|(t, _)| t.key().id).collect();
        assert_eq!(
            root_target_ids,
            vec![root.task.key().id, child1.task.key().id]
        );

        let child2_targets = kernel
            .registry()
            .process_group_prio_targets(container, pgid_child2);
        let child2_target_ids: Vec<TaskId> =
            child2_targets.iter().map(|(t, _)| t.key().id).collect();
        assert_eq!(child2_target_ids, vec![child2.task.key().id]);

        let unknown_pgid = ProcessGroupId::from_abi_positive(99999).expect("valid pgid");
        assert!(
            kernel
                .registry()
                .process_group_prio_targets(container, unknown_pgid)
                .is_empty()
        );
    }

    /// Two containers on ONE kernel. With one container every id in the
    /// carrier coincides and aliasing is invisible; the second one is what
    /// makes `ContainerId` a real domain.
    #[test]
    fn containers_in_one_kernel_have_distinct_ids() {
        let (kernel, context) = bootstrap(4400);
        let first = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "first",
        ))));
        let second = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "second",
        ))));
        kernel
            .prepare_container_root(
                ThreadId::synthetic_for_tests(4401),
                None,
                "first-root".to_string(),
                Arc::clone(&first),
                None,
            )
            .expect("prepare first container")
            .commit()
            .expect("publish first container root");
        kernel
            .prepare_container_root(
                ThreadId::synthetic_for_tests(4402),
                None,
                "second-root".to_string(),
                Arc::clone(&second),
                None,
            )
            .expect("prepare second container")
            .commit()
            .expect("publish second container root");

        assert_ne!(first.id(), second.id());
        assert_ne!(first.id(), context.container().id());
        assert_ne!(second.id(), context.container().id());
        assert_eq!(kernel.container_count(), 3);
        assert!(Arc::ptr_eq(
            &kernel.container(first.id()).expect("registered"),
            &first
        ));
        assert!(matches!(
            kernel.prepare_container_root(
                ThreadId::synthetic_for_tests(4403),
                None,
                "duplicate-first-root".to_string(),
                Arc::clone(&first),
                None,
            ),
            Err(KernelError::DuplicateContainer(id)) if id == first.id()
        ));
    }

    /// A captured syscall context reaches its container THROUGH its task —
    /// there is no static to consult, so a second container cannot alias it.
    #[test]
    fn kernel_context_resolves_its_own_container() {
        let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "root-run",
        ))));
        let bootstrap = RootBootstrap::for_reference_model(
            4401,
            ThreadId::synthetic_for_tests(4401),
            "root".to_string(),
        )
        .expect("root bootstrap input")
        .with_container(Arc::clone(&container));
        let (kernel, context) = Kernel::bootstrap_root(bootstrap).expect("root kernel");

        let resolved = context.container();
        assert!(Arc::ptr_eq(&resolved, &container));
        assert_eq!(
            kernel.container_init(container.id()),
            Some(context.task().key())
        );
        assert_eq!(resolved.run_id().as_str(), "root-run");
        assert_eq!(resolved.pid_root(), Some(context.task().key()));
        assert_eq!(kernel.container_count(), 1);
    }
}
