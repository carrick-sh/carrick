//! Process-level resource and lifecycle boundaries in the kernel graph.
//!
//! Encapsulates address-space identity and memory translation authority ([`Mm`]),
//! shared process resource bundles ([`TaskShared`]), process termination
//! accounting ([`Zombie`], [`TaskRusage`], and [`LinuxWaitStatus`]), and weak
//! process file-descriptor edge handles ([`PidfdTarget`]).

use std::collections::BTreeSet;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use carrick_abi::NsUid;
use carrick_fatal::carrick_fatal;

use crate::kernel::address::MmBackend;
use crate::kernel::clone_plan::{CloneObjectMode, ClonePlan, CloneTaskMode};
use crate::kernel::container::ContainerId;
use crate::kernel::ids::{
    ChildExitSignal, MmId, ObjectIdError, ObjectIdRegistry, ProcessGroupId, SessionId,
};
use crate::kernel::objects::signal::{Sighand, TaskPendingSignals};
use crate::kernel::objects::{ObjectGraphError, ObjectRevision, Task, TaskKey, TaskRef};
use crate::kernel::operations::KernelOperationError;

pub(in crate::kernel) struct MmIoStateSnapshot {
    pub(in crate::kernel) revision: u64,
    pub(in crate::kernel) io_uring_mappings: Vec<crate::dispatch::ioring::IoUringMappingSnapshot>,
    pub(in crate::kernel) legacy_aio_context_count: usize,
    pub(in crate::kernel) next_legacy_aio_context: u64,
}

/// Kernel-owned Linux address-space identity.
///
/// The installed backend and foreign carrier capability are not public API:
/// callers must obtain a typed current/foreign MM authority from the kernel.
///
/// ```compile_fail
/// fn bypass(mm: &carrick_runtime::kernel::objects::Mm) {
///     let transport = mm
///         .backend()
///         .expect("raw MM backend")
///         .foreign_mm_transport()
///         .expect("raw foreign transport");
///     let _ = transport;
/// }
/// ```
pub struct Mm {
    id: MmId,
    backend: Option<Arc<dyn MmBackend>>,
    foreign_mm_endpoint: RwLock<Option<carrick_hal::ForeignMmEndpoint>>,
    foreign_mm_mutation: RwLock<Option<crate::dispatch::mm_mutation::ForeignMmMutationAuthority>>,
    io_uring_mappings: RwLock<Vec<crate::dispatch::ioring::IoUringMapping>>,
    legacy_aio_contexts: RwLock<BTreeSet<crate::dispatch::LegacyAioContextId>>,
    next_legacy_aio_context: AtomicU64,
    pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
    fork_quiesce: Arc<carrick_thread::fork_quiesce::ForkQuiesce>,
    revision: ObjectRevision,
}

impl Mm {
    /// Identity-only constructor for the in-crate K1 reference model. Runtime
    /// adapters must use `with_backend`; callers outside `kernel` cannot create
    /// an observation-less mm.
    pub(in crate::kernel) fn new_reference(id: MmId) -> Self {
        Self {
            id,
            backend: None,
            foreign_mm_endpoint: RwLock::new(None),
            foreign_mm_mutation: RwLock::new(None),
            io_uring_mappings: RwLock::new(Vec::new()),
            legacy_aio_contexts: RwLock::new(BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            fork_quiesce: Arc::new(carrick_thread::fork_quiesce::ForkQuiesce::new()),
            revision: ObjectRevision::new(),
        }
    }

    pub fn with_backend(id: MmId, backend: Arc<dyn MmBackend>) -> Self {
        Self {
            id,
            backend: Some(backend),
            foreign_mm_endpoint: RwLock::new(None),
            foreign_mm_mutation: RwLock::new(None),
            io_uring_mappings: RwLock::new(Vec::new()),
            legacy_aio_contexts: RwLock::new(BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            fork_quiesce: Arc::new(carrick_thread::fork_quiesce::ForkQuiesce::new()),
            revision: ObjectRevision::new(),
        }
    }

    #[cfg(test)]
    pub(in crate::kernel) fn new_reference_for_fork(id: MmId, parent: &Self) -> Self {
        Self {
            id,
            backend: None,
            foreign_mm_endpoint: RwLock::new(None),
            foreign_mm_mutation: RwLock::new(None),
            io_uring_mappings: RwLock::new(parent.io_uring_mappings.read().clone()),
            legacy_aio_contexts: RwLock::new(BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            fork_quiesce: Arc::new(carrick_thread::fork_quiesce::ForkQuiesce::new()),
            revision: ObjectRevision::new(),
        }
    }

    pub fn with_backend_for_fork(id: MmId, backend: Arc<dyn MmBackend>, parent: &Self) -> Self {
        Self {
            id,
            backend: Some(backend),
            foreign_mm_endpoint: RwLock::new(None),
            foreign_mm_mutation: RwLock::new(None),
            io_uring_mappings: RwLock::new(parent.io_uring_mappings.read().clone()),
            legacy_aio_contexts: RwLock::new(BTreeSet::new()),
            next_legacy_aio_context: AtomicU64::new(1),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            fork_quiesce: Arc::new(carrick_thread::fork_quiesce::ForkQuiesce::new()),
            revision: ObjectRevision::new(),
        }
    }

    pub fn pt_quiesce(&self) -> &Arc<carrick_thread::fork_quiesce::PtQuiesce> {
        &self.pt_quiesce
    }

    pub fn fork_quiesce(&self) -> &Arc<carrick_thread::fork_quiesce::ForkQuiesce> {
        &self.fork_quiesce
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
            carrick_fatal!(
                "kernel::mm_io_uring",
                "checked addition overflow in replace_io_uring_mappings"
            );
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

    pub(crate) fn copy_io_uring_mappings_for_host_fork(
        &self,
        inherited: &Self,
    ) -> Result<(), KernelOperationError> {
        let mut mappings = self.io_uring_mappings.write();
        if !mappings.is_empty() {
            tracing::error!(mm = ?self.id, "host-fork mm io state replacement was not empty");
            return Err(KernelOperationError::ObjectGraph(
                ObjectGraphError::NonEmptyForkMm,
            ));
        }
        mappings.clone_from(&inherited.io_uring_mappings.read());
        if !mappings.is_empty() {
            self.revision.publish();
        }
        Ok(())
    }

    pub(in crate::kernel) fn clear_io_uring_mappings(&self) {
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

    pub(in crate::kernel) fn io_state_snapshot_until(
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

    pub(crate) fn backend(&self) -> Option<&Arc<dyn MmBackend>> {
        self.backend.as_ref()
    }

    pub(crate) fn install_foreign_mm_endpoint(
        &self,
        endpoint: carrick_hal::ForeignMmEndpoint,
        _permit: &crate::hvpatch::ForeignMmInstallPermit,
    ) {
        *self.foreign_mm_endpoint.write() = Some(endpoint);
    }

    #[cfg(test)]
    pub(crate) fn install_foreign_mm_endpoint_for_test(
        &self,
        endpoint: carrick_hal::ForeignMmEndpoint,
    ) {
        *self.foreign_mm_endpoint.write() = Some(endpoint);
    }

    pub(in crate::kernel) fn foreign_mm_endpoint(
        &self,
        _permit: &crate::kernel::mm_access::ForeignEndpointPermit,
        deadline: std::time::Instant,
    ) -> Option<Option<carrick_hal::ForeignMmEndpoint>> {
        self.foreign_mm_endpoint
            .try_read_until(deadline)
            .map(|endpoint| endpoint.clone())
    }

    pub(crate) fn install_foreign_mm_mutation_authority(
        &self,
        authority: crate::dispatch::mm_mutation::ForeignMmMutationAuthority,
        _permit: &crate::hvpatch::ForeignMmInstallPermit,
    ) {
        *self.foreign_mm_mutation.write() = Some(authority);
    }

    #[cfg(test)]
    pub(crate) fn install_foreign_mm_mutation_authority_for_test(
        &self,
        authority: crate::dispatch::mm_mutation::ForeignMmMutationAuthority,
    ) {
        *self.foreign_mm_mutation.write() = Some(authority);
    }

    pub(in crate::kernel) fn foreign_mm_mutation_authority(
        &self,
        _permit: &crate::kernel::mm_access::ForeignEndpointPermit,
        deadline: std::time::Instant,
    ) -> Option<Option<crate::dispatch::mm_mutation::ForeignMmMutationAuthority>> {
        self.foreign_mm_mutation
            .try_read_until(deadline)
            .map(|authority| authority.clone())
    }

    pub(in crate::kernel) fn revision(&self) -> u64 {
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
                "has_foreign_mm_endpoint",
                &self.foreign_mm_endpoint.read().is_some(),
            )
            .field(
                "has_foreign_mm_mutation_authority",
                &self.foreign_mm_mutation.read().is_some(),
            )
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
    pub(in crate::kernel) fn for_new_task_reference(
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

    pub(in crate::kernel) fn for_exec_with_mm(
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
    /// PID the parent saw in its container PID namespace at exit. The live
    /// namespace membership is released by a consuming wait, so the receipt
    /// must retain this value for wait4/waitid rendering after reap.
    pub namespace_pid: u32,
    pub container: ContainerId,
    pub parent: Option<TaskKey>,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
    /// Historical process-group id in this container's PID namespace. Unlike
    /// the internal group key, this remains renderable after its leader PID
    /// mapping and the final live group record have both disappeared.
    pub namespace_process_group: u32,
    /// Historical session id in this container's PID namespace.
    pub namespace_session: u32,
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
    /// Which `wait(2)` class this zombie belongs to (`__WCLONE`/`__WALL`).
    pub exit_signal: ChildExitSignal,
    pub diagnostic_name: String,
}

impl Zombie {
    /// Capture the exiting task's two CPU ledgers at the moment it becomes a
    /// zombie. Both are read from the kernel's own accounting: `rusage` is the
    /// child's own CPU, which `wait4` reports through its `rusage` argument,
    /// and `children_rusage` is what the child had already accumulated from
    /// reaping its own children. Linux charges a reaper BOTH, which is how
    /// `tms_cutime` totals a whole process subtree.
    pub fn from_task(
        task: &Task,
        status: LinuxWaitStatus,
        diagnostic_name: String,
        namespace_process_group: u32,
        namespace_session: u32,
    ) -> Self {
        let (children_user_us, children_system_us) = task.children_cpu_us();
        let credentials = task.process_credentials();
        let internal_pid = u32::try_from(task.key().id.raw()).unwrap_or_else(|_| {
            carrick_fatal!(
                "kernel::zombie_identity",
                "exiting task internal identity outside PID namespace range"
            );
        });
        let namespace_pid = match task.pid_ns_region() {
            Some(region) => region.host_to_ns(internal_pid).unwrap_or_else(|| {
                carrick_fatal!(
                    "kernel::zombie_identity",
                    "live namespace member disappeared before zombie captured visible PID"
                );
            }),
            None => internal_pid,
        };
        Self {
            key: task.key(),
            namespace_pid,
            container: task.container().id(),
            parent: task.parent(),
            process_group: task.process_group(),
            session: task.session(),
            namespace_process_group,
            namespace_session,
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
            exit_signal: task.exit_signal(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::container::{Container, LaunchContext, RunId};
    use crate::kernel::ids::{LinuxTid, TaskId};
    use crate::kernel::objects::{
        Credentials, FileTable, FsContext, TaskIdentity, ThreadKey, ThreadResources,
    };
    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;

    struct Fixture {
        ids: ObjectIdRegistry,
        task: TaskRef,
        _leader: crate::kernel::objects::ThreadRef,
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
            let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
                "objects-fixture",
            ))));
            let task = Arc::new(Task::new(
                key,
                None,
                TaskIdentity::led_by(task_id),
                shared,
                resources.credentials(),
                container,
                ChildExitSignal::SIGCHLD,
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
            Self {
                ids,
                task,
                _leader: leader,
            }
        }
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
            u32::try_from(fixture.task.process_group().raw()).expect("positive process group"),
            u32::try_from(fixture.task.session().raw()).expect("positive session"),
        );
        drop(mm);
        drop(fixture);

        assert!(weak_mm.upgrade().is_none());
        assert_eq!(zombie.key.id.raw(), 100);
    }
}
