//! Coherent, owned K1 kernel-object snapshots.
//!
//! This module projects only the typed kernel graph. It deliberately never
//! reads dispatcher filesystem, I/O, or signal bindings as fallback state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};
use std::time::Instant;

use carrick_abi::{LinuxSigaction, LinuxSigaltstack, LinuxSiginfo, SigSet};
use carrick_hal::{FrameId, MappingId, ThreadId};

use super::address::{MmBackend, MmBinding, SnapshotError, SnapshotTable};
use super::core::{Kernel, TaskRevision};
use super::frame_inventory::{FrameRow, MappingRow};
use super::ids::{
    CredentialsId, FileDescriptionId, FileSlotNumber, FileTableId, FsContextId, LinuxSignal, MmId,
    ProcessGroupId, SessionId, SighandId,
};
use super::objects::{
    FileDescription, FileTable, FsContext, HandlerFrameState, PendingSignal, Sighand, TaskKey,
    TaskLifecycle, TaskPendingSignals, TaskRef, ThreadKey, ThreadRef, ThreadSignalState, Zombie,
};

pub const KERNEL_SNAPSHOT_V1_SCHEMA: u16 = 6;
const MAX_ATTEMPTS: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelSnapshotV1 {
    pub schema_version: u16,
    pub registry_epoch: u64,
    pub tasks: Vec<TaskSnapshotRow>,
    pub zombies: Vec<ZombieSnapshotRow>,
    pub threads: Vec<ThreadSnapshotRow>,
    pub task_shared: Vec<TaskSharedSnapshotRow>,
    pub thread_resources: Vec<ThreadResourcesSnapshotRow>,
    pub mms: Vec<MmSnapshotRow>,
    pub vmas: Vec<VmaSnapshotRow>,
    pub frames: Vec<FrameRow>,
    pub mappings: Vec<MappingRow>,
    pub file_tables: Vec<FileTableSnapshotRow>,
    pub file_slots: Vec<FileSlotSnapshotRow>,
    pub file_descriptions: Vec<FileDescriptionSnapshotRow>,
    pub fs_contexts: Vec<FsContextSnapshotRow>,
    pub credentials: Vec<CredentialsSnapshotRow>,
    pub process_groups: Vec<ProcessGroupSnapshotRow>,
    pub sessions: Vec<SessionSnapshotRow>,
    pub sighands: Vec<SighandSnapshotRow>,
    pub task_signals: Vec<TaskSignalSnapshotRow>,
    pub thread_signals: Vec<ThreadSignalSnapshotRow>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectSnapshotClass {
    Live,
    Draining,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TaskSharedObservationKey {
    pub task: TaskKey,
    pub publication: TaskRevision,
    pub mm: MmId,
    pub sighand: SighandId,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ThreadResourcesObservationKey {
    pub thread: ThreadKey,
    pub publication: TaskRevision,
    pub file_table: FileTableId,
    pub fs_context: FsContextId,
    pub credentials: CredentialsId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSnapshotRow {
    pub key: TaskKey,
    pub class: ObjectSnapshotClass,
    pub parent: Option<TaskKey>,
    pub children: Vec<TaskKey>,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
    pub lifecycle: TaskLifecycle,
    pub shared: TaskSharedObservationKey,
    pub mm: MmId,
    pub sighand: SighandId,
    pub revision: Option<TaskRevision>,
    pub diagnostic_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZombieSnapshotRow {
    pub zombie: Zombie,
}

pub type ThreadSnapshotClass = ObjectSnapshotClass;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadSnapshotRow {
    pub key: ThreadKey,
    pub task: TaskKey,
    pub registry_id: Option<ThreadId>,
    pub class: ObjectSnapshotClass,
    pub resources: ThreadResourcesObservationKey,
    pub file_table: Option<FileTableId>,
    pub fs_context: Option<FsContextId>,
    pub credentials: Option<CredentialsId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSharedSnapshotRow {
    pub key: TaskSharedObservationKey,
    pub class: ObjectSnapshotClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadResourcesSnapshotRow {
    pub key: ThreadResourcesObservationKey,
    pub class: ObjectSnapshotClass,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmSnapshotRow {
    pub id: MmId,
    pub class: ObjectSnapshotClass,
    pub revision: u64,
    pub binding: MmBinding,
    pub mapping_ids: Vec<MappingId>,
    pub io_uring_mappings: Vec<IoUringMappingSnapshotRow>,
    pub legacy_aio_context_count: usize,
    pub next_legacy_aio_context: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoUringMappingSnapshotRow {
    pub description: FileDescriptionId,
    pub region: crate::dispatch::ioring::IoUringRegion,
    pub start: u64,
    pub end: u64,
    pub backing_offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmaSnapshotRow {
    pub mm: MmId,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTableSnapshotRow {
    pub id: FileTableId,
    pub class: ObjectSnapshotClass,
    pub revision: u64,
    pub functional_refs_active: bool,
    pub next_fd: i32,
    pub stdio_cloexec: [bool; 3],
    pub closed_stdio: [bool; 3],
    pub splice_pushback_description_ids: Vec<FileDescriptionId>,
    pub epoll_index_fds: Vec<FileSlotNumber>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSlotSnapshotRow {
    pub table: FileTableId,
    pub number: FileSlotNumber,
    pub description: FileDescriptionId,
    pub close_on_exec: bool,
    pub open_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDescriptionSnapshotKind {
    Regular,
    Epoll,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDescriptionSnapshotRow {
    pub id: FileDescriptionId,
    pub class: ObjectSnapshotClass,
    pub revision: u64,
    pub kind: FileDescriptionSnapshotKind,
    pub backing: Option<super::objects::FileDescriptionBackingSnapshot>,
    pub epoll_interests: Vec<FileDescriptionId>,
    pub epoll_owners: Vec<(FileDescriptionId, i32)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsContextSnapshotRow {
    pub id: FsContextId,
    pub class: ObjectSnapshotClass,
    pub revision: u64,
    pub cwd: String,
    pub chroot_root: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialsSnapshotRow {
    pub id: CredentialsId,
    pub class: ObjectSnapshotClass,
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub umask: u32,
    /// Exact explicit `setgroups(2)` authority. `None` means the runtime will
    /// derive launch-time compatibility membership from `/etc/group`.
    pub supplementary_groups_override: Option<Vec<u32>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessGroupSnapshotRow {
    pub id: ProcessGroupId,
    pub session: SessionId,
    pub members: Vec<TaskKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionSnapshotRow {
    pub id: SessionId,
    pub process_groups: Vec<ProcessGroupId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SighandSnapshotRow {
    pub id: SighandId,
    pub class: ObjectSnapshotClass,
    pub revision: u64,
    pub actions: Vec<(LinuxSignal, LinuxSigaction)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSignalSnapshotRow {
    pub task: TaskKey,
    pub class: ObjectSnapshotClass,
    pub revision: u64,
    pub pending: Vec<PendingSignal>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadSignalSnapshotRow {
    pub thread: ThreadKey,
    pub class: ObjectSnapshotClass,
    pub revision: u64,
    pub blocked: SigSet,
    pub pending: Vec<PendingSignal>,
    pub altstack: Option<LinuxSigaltstack>,
    pub handler_frames: Vec<HandlerFrameState>,
    pub armed_restore_mask: Option<SigSet>,
    pub routed_siginfos: Vec<(LinuxSignal, LinuxSiginfo)>,
    pub pending_actions: Vec<(LinuxSignal, LinuxSigaction)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KernelSnapshotError {
    #[error("kernel snapshot authority is busy")]
    Busy,
    #[error("kernel snapshot deadline expired")]
    TimedOut,
    #[error("kernel snapshot invariant violated: {0}")]
    InvariantViolation(&'static str),
    #[error("kernel snapshot authority unavailable for {0:?}")]
    AuthorityUnavailable(SnapshotTable),
}

struct RegistryTask {
    task: TaskRef,
    revision: TaskRevision,
    diagnostic_name: String,
}

struct RegistryCopy {
    epoch: u64,
    tasks: Vec<RegistryTask>,
    zombies: Vec<Zombie>,
    groups: Vec<ProcessGroupSnapshotRow>,
    sessions: Vec<SessionSnapshotRow>,
    observed_tasks: BTreeMap<TaskKey, TaskRef>,
    observed_threads: BTreeMap<ThreadKey, (TaskKey, ThreadRef)>,
    observed_mms: BTreeMap<MmId, Arc<super::objects::Mm>>,
    observed_sighands: BTreeMap<SighandId, Arc<Sighand>>,
    observed_task_shared: BTreeMap<TaskSharedObservationKey, Arc<super::objects::TaskShared>>,
    observed_thread_resources:
        BTreeMap<ThreadResourcesObservationKey, Arc<super::objects::ThreadResources>>,
}

struct LeafChecks {
    threads: Vec<(ThreadRef, u64)>,
    sighands: Vec<(Arc<Sighand>, u64)>,
    task_pending: Vec<(Arc<TaskPendingSignals>, u64)>,
    file_tables: Vec<(Arc<FileTable>, u64)>,
    fs_contexts: Vec<(Arc<FsContext>, u64)>,
    descriptions: Vec<(Arc<FileDescription>, u64)>,
    mms: Vec<(Arc<super::objects::Mm>, u64)>,
    backends: Vec<(Arc<dyn MmBackend>, u64)>,
    vma_revisions: Vec<(Arc<dyn MmBackend>, super::VmaRevision)>,
    frame_inventory_revisions: Vec<u64>,
}

impl Kernel {
    pub fn snapshot(&self, deadline: Instant) -> Result<KernelSnapshotV1, KernelSnapshotError> {
        self.sweep_observations_until(deadline)?;
        let mut saw_race = false;
        for _ in 0..MAX_ATTEMPTS {
            if Instant::now() >= deadline {
                return Err(KernelSnapshotError::TimedOut);
            }
            match self.snapshot_once(deadline) {
                Ok(snapshot) => return Ok(snapshot),
                Err(AttemptError::Race) => saw_race = true,
                Err(AttemptError::Public(error)) => return Err(error),
            }
        }
        let _ = saw_race;
        Err(KernelSnapshotError::Busy)
    }

    fn snapshot_once(&self, deadline: Instant) -> Result<KernelSnapshotV1, AttemptError> {
        let registry = self.copy_registry(deadline)?;
        let live_task_by_key: BTreeMap<_, _> = registry
            .tasks
            .iter()
            .map(|record| (record.task.key(), record))
            .collect();
        let mut live_threads = BTreeMap::<ThreadKey, ThreadRef>::new();
        let mut live_task_shared = BTreeSet::new();
        let mut live_thread_resources = BTreeSet::new();
        let mut live_mms = BTreeMap::new();
        let mut live_sighands = BTreeMap::new();
        for record in &registry.tasks {
            if registry
                .observed_tasks
                .get(&record.task.key())
                .is_none_or(|observed| !Arc::ptr_eq(observed, &record.task))
            {
                return invariant("live registry task generation is unobserved");
            }
            let shared = record.task.shared();
            let shared_key = matching_task_shared_key(
                &registry.observed_task_shared,
                record.task.key(),
                &shared,
            )?;
            live_task_shared.insert(shared_key);
            let mm = shared.mm();
            insert_shared(
                &mut live_mms,
                mm.id(),
                mm,
                "live pointer-distinct mms share one stable identity",
            )?;
            let sighand = shared.sighand();
            insert_shared(
                &mut live_sighands,
                sighand.id(),
                sighand,
                "live pointer-distinct sighands share one stable identity",
            )?;
            for thread in lock_result(record.task.threads_until(deadline), deadline)? {
                if registry
                    .observed_threads
                    .get(&thread.key())
                    .is_none_or(|(_, observed)| !Arc::ptr_eq(observed, &thread))
                {
                    return invariant("live registry thread generation is unobserved");
                }
                let resources = thread.resources();
                let resources_key = matching_thread_resources_key(
                    &registry.observed_thread_resources,
                    thread.key(),
                    &resources,
                )?;
                live_thread_resources.insert(resources_key);
                if live_threads.insert(thread.key(), thread).is_some() {
                    return invariant("duplicate live thread identity");
                }
            }
        }

        let mut tasks = Vec::with_capacity(registry.observed_tasks.len());
        for (key, task) in &registry.observed_tasks {
            let live_record = live_task_by_key
                .get(key)
                .copied()
                .filter(|record| Arc::ptr_eq(&record.task, task));
            let shared = task.shared();
            let shared_key =
                matching_task_shared_key(&registry.observed_task_shared, *key, &shared)?;
            let (process_group, session) = lock_result(task.identity_until(deadline), deadline)?;
            tasks.push(TaskSnapshotRow {
                key: *key,
                class: if live_record.is_some() {
                    ObjectSnapshotClass::Live
                } else {
                    ObjectSnapshotClass::Draining
                },
                parent: lock_result(task.parent_until(deadline), deadline)?,
                children: lock_result(task.children_until(deadline), deadline)?,
                process_group,
                session,
                lifecycle: lock_result(task.lifecycle_until(deadline), deadline)?,
                shared: shared_key,
                mm: shared.mm().id(),
                sighand: shared.sighand().id(),
                revision: live_record.map(|record| record.revision),
                diagnostic_name: live_record.map(|record| record.diagnostic_name.clone()),
            });
        }

        let mut checks = LeafChecks {
            threads: Vec::new(),
            sighands: Vec::new(),
            task_pending: Vec::new(),
            file_tables: Vec::new(),
            fs_contexts: Vec::new(),
            descriptions: Vec::new(),
            mms: Vec::new(),
            backends: Vec::new(),
            vma_revisions: Vec::new(),
            frame_inventory_revisions: Vec::new(),
        };
        let mut thread_rows = Vec::new();
        let mut thread_signals = Vec::new();
        let mut file_table_by_id = BTreeMap::new();
        let mut fs_context_by_id = BTreeMap::<FsContextId, Arc<FsContext>>::new();
        let mut credentials_by_id = BTreeMap::new();
        let mut live_file_tables = BTreeSet::new();
        let mut live_fs_contexts = BTreeSet::new();
        let mut live_credentials = BTreeSet::new();
        for (key, resources) in &registry.observed_thread_resources {
            let files = resources.files();
            let file_table_id = files.id();
            let fs = resources.fs_context();
            let credentials = resources.credentials();
            insert_shared(
                &mut file_table_by_id,
                file_table_id,
                files,
                "duplicate file-table identity",
            )?;
            insert_shared(
                &mut fs_context_by_id,
                fs.id(),
                Arc::clone(&fs),
                "duplicate fs-context identity",
            )?;
            insert_shared(
                &mut credentials_by_id,
                credentials.id(),
                Arc::clone(&credentials),
                "duplicate credentials identity",
            )?;
            if live_thread_resources.contains(key) {
                live_file_tables.insert(file_table_id);
                live_fs_contexts.insert(fs.id());
                live_credentials.insert(credentials.id());
            }
        }
        let mut fs_contexts = Vec::with_capacity(fs_context_by_id.len());
        for fs_context in fs_context_by_id.values() {
            let (revision, cwd, chroot_root) =
                lock_result(fs_context.snapshot_until(deadline), deadline)?;
            checks.fs_contexts.push((Arc::clone(fs_context), revision));
            fs_contexts.push(FsContextSnapshotRow {
                id: fs_context.id(),
                class: if live_fs_contexts.contains(&fs_context.id()) {
                    ObjectSnapshotClass::Live
                } else {
                    ObjectSnapshotClass::Draining
                },
                revision,
                cwd,
                chroot_root,
            });
        }
        let credentials = credentials_by_id
            .values()
            .map(|credentials| CredentialsSnapshotRow {
                id: credentials.id(),
                class: if live_credentials.contains(&credentials.id()) {
                    ObjectSnapshotClass::Live
                } else {
                    ObjectSnapshotClass::Draining
                },
                ruid: credentials.ruid(),
                euid: credentials.euid(),
                suid: credentials.suid(),
                rgid: credentials.rgid(),
                egid: credentials.egid(),
                sgid: credentials.sgid(),
                fsuid: credentials.fsuid(),
                fsgid: credentials.fsgid(),
                umask: credentials.umask(),
                supplementary_groups_override: credentials
                    .supplementary_groups_override()
                    .map(<[u32]>::to_vec),
            })
            .collect();

        for (key, (task_key, thread)) in &registry.observed_threads {
            if thread.key() != *key || thread.task_key() != *task_key {
                return invariant("observed thread identity changed");
            }
            let class = if live_threads
                .get(key)
                .is_some_and(|live| Arc::ptr_eq(live, thread))
            {
                ObjectSnapshotClass::Live
            } else {
                ObjectSnapshotClass::Draining
            };
            let resources = thread.resources();
            let resources_key = matching_thread_resources_key(
                &registry.observed_thread_resources,
                *key,
                &resources,
            )?;
            let files = resources.files();
            let fs = resources.fs_context();
            let thread_credentials = resources.credentials();
            let (revision, signal) = lock_result(thread.snapshot_signal_until(deadline), deadline)?;
            checks.threads.push((Arc::clone(thread), revision));
            thread_signals.push(thread_signal_row(*key, class, revision, signal));
            thread_rows.push(ThreadSnapshotRow {
                key: *key,
                task: *task_key,
                registry_id: Some(thread.registry_id()),
                class,
                resources: resources_key,
                file_table: (class == ObjectSnapshotClass::Live).then_some(files.id()),
                fs_context: (class == ObjectSnapshotClass::Live).then_some(fs.id()),
                credentials: (class == ObjectSnapshotClass::Live)
                    .then_some(thread_credentials.id()),
            });
        }

        let mut sighands = Vec::new();
        for (id, sighand) in &registry.observed_sighands {
            let (revision, actions) = lock_result(sighand.snapshot_until(deadline), deadline)?;
            checks.sighands.push((Arc::clone(sighand), revision));
            sighands.push(SighandSnapshotRow {
                id: *id,
                class: if live_sighands
                    .get(id)
                    .is_some_and(|live| Arc::ptr_eq(live, sighand))
                {
                    ObjectSnapshotClass::Live
                } else {
                    ObjectSnapshotClass::Draining
                },
                revision,
                actions,
            });
        }

        let mut file_tables = Vec::new();
        let mut file_slots = Vec::new();
        let mut description_by_id = BTreeMap::new();
        let mut live_descriptions = BTreeSet::new();
        for (_, table) in file_table_by_id {
            let observed = lock_result(table.snapshot_until(deadline), deadline)?;
            checks
                .file_tables
                .push((Arc::clone(&table), observed.revision));
            let class = if live_file_tables.contains(&table.id()) {
                ObjectSnapshotClass::Live
            } else {
                ObjectSnapshotClass::Draining
            };
            if observed.functional_refs_active != (class == ObjectSnapshotClass::Live) {
                return invariant("file-table functional state disagrees with live classification");
            }
            let mut open_paths: BTreeMap<_, _> = observed.fd_open_paths.into_iter().collect();
            file_tables.push(FileTableSnapshotRow {
                id: table.id(),
                class,
                revision: observed.revision,
                functional_refs_active: observed.functional_refs_active,
                next_fd: observed.next_fd,
                stdio_cloexec: observed.stdio_cloexec,
                closed_stdio: observed.closed_stdio,
                splice_pushback_description_ids: observed.splice_pushback_description_ids,
                epoll_index_fds: observed.epoll_fds,
            });
            for (number, slot) in observed.slots {
                let description = slot.description();
                insert_shared(
                    &mut description_by_id,
                    description.id(),
                    Arc::clone(&description),
                    "duplicate file-description identity",
                )?;
                if class == ObjectSnapshotClass::Live {
                    live_descriptions.insert(description.id());
                }
                file_slots.push(FileSlotSnapshotRow {
                    table: table.id(),
                    number,
                    description: description.id(),
                    close_on_exec: slot.close_on_exec(),
                    open_path: open_paths.remove(&number),
                });
            }
            if !open_paths.is_empty() {
                return invariant("file-table open-path index names no live slot");
            }
        }
        let functional_tables: BTreeSet<_> = file_tables
            .iter()
            .filter_map(|table| table.functional_refs_active.then_some(table.id))
            .collect();
        let mut logical_slot_refs = BTreeMap::<FileDescriptionId, usize>::new();
        for slot in &file_slots {
            if functional_tables.contains(&slot.table) {
                *logical_slot_refs.entry(slot.description).or_default() += 1;
            }
        }

        let mut mms = Vec::new();
        let mut vmas = Vec::new();
        for (id, mm) in &registry.observed_mms {
            let backend = mm.backend().cloned().ok_or(AttemptError::Public(
                KernelSnapshotError::AuthorityUnavailable(SnapshotTable::Mms),
            ))?;
            let observed = backend.snapshot(deadline).map_err(map_backend_error)?;
            if observed.revision != backend.revision() {
                return Err(AttemptError::Race);
            }
            if let Some(revision) = observed.vma_revision {
                checks.vma_revisions.push((Arc::clone(&backend), revision));
            }
            if let Some(revision) = observed.frame_inventory_revision {
                checks.frame_inventory_revisions.push(revision);
            }
            let mut mapping_ids = observed.mapping_ids;
            mapping_ids.sort_unstable();
            if has_duplicates(&mapping_ids) {
                return invariant("backend returned duplicate mapping IDs");
            }
            for vma in observed.vmas {
                if vma.start.raw() >= vma.end.raw() {
                    return invariant("backend returned malformed VMA extent");
                }
                vmas.push(VmaSnapshotRow {
                    mm: *id,
                    start: vma.start.raw(),
                    end: vma.end.raw(),
                });
            }
            checks
                .backends
                .push((Arc::clone(&backend), observed.revision));
            let io_state = lock_result(mm.io_state_snapshot_until(deadline), deadline)?;
            let mm_class = if live_mms.get(id).is_some_and(|live| Arc::ptr_eq(live, mm)) {
                ObjectSnapshotClass::Live
            } else {
                ObjectSnapshotClass::Draining
            };
            for mapping in &io_state.io_uring_mappings {
                let description = &mapping.description;
                insert_shared(
                    &mut description_by_id,
                    description.id(),
                    Arc::clone(description),
                    "duplicate file-description identity",
                )?;
                if mm_class == ObjectSnapshotClass::Live {
                    live_descriptions.insert(description.id());
                }
            }
            let io_uring_mappings = io_state
                .io_uring_mappings
                .into_iter()
                .map(|mapping| IoUringMappingSnapshotRow {
                    description: mapping.description.id(),
                    region: mapping.region,
                    start: mapping.start,
                    end: mapping.end,
                    backing_offset: mapping.backing_offset,
                })
                .collect();
            checks.mms.push((Arc::clone(mm), io_state.revision));
            mms.push(MmSnapshotRow {
                id: *id,
                class: mm_class,
                revision: observed.revision,
                binding: observed.binding,
                mapping_ids,
                io_uring_mappings,
                legacy_aio_context_count: io_state.legacy_aio_context_count,
                next_legacy_aio_context: io_state.next_legacy_aio_context,
            });
        }

        let mut file_descriptions = Vec::new();
        for description in description_by_id.into_values() {
            let (revision, epoll, interests, backing, owners) =
                lock_result(description.snapshot_until(deadline), deadline)?;
            checks
                .descriptions
                .push((Arc::clone(&description), revision));
            file_descriptions.push(FileDescriptionSnapshotRow {
                id: description.id(),
                class: if live_descriptions.contains(&description.id()) {
                    ObjectSnapshotClass::Live
                } else {
                    ObjectSnapshotClass::Draining
                },
                revision,
                kind: if epoll {
                    FileDescriptionSnapshotKind::Epoll
                } else {
                    FileDescriptionSnapshotKind::Regular
                },
                backing,
                epoll_interests: interests,
                epoll_owners: owners,
            });
        }
        if file_descriptions.iter().any(|description| {
            description.backing.as_ref().is_some_and(|backing| {
                backing.logical_fd_refs()
                    != logical_slot_refs
                        .get(&description.id)
                        .copied()
                        .unwrap_or_default()
            })
        }) {
            return Err(AttemptError::Race);
        }

        let frame_inventory =
            lock_result(self.frame_inventory().snapshot_until(deadline), deadline)?;
        let frame_revision = frame_inventory.revision;
        if checks
            .frame_inventory_revisions
            .iter()
            .any(|revision| *revision != frame_revision)
        {
            return Err(AttemptError::Race);
        }
        self.verify_registry(&registry, deadline)?;
        let mut snapshot = KernelSnapshotV1 {
            schema_version: KERNEL_SNAPSHOT_V1_SCHEMA,
            registry_epoch: registry.epoch,
            tasks,
            zombies: registry
                .zombies
                .iter()
                .cloned()
                .map(|zombie| ZombieSnapshotRow { zombie })
                .collect(),
            threads: thread_rows,
            task_shared: registry
                .observed_task_shared
                .keys()
                .map(|key| TaskSharedSnapshotRow {
                    key: *key,
                    class: if live_task_shared.contains(key) {
                        ObjectSnapshotClass::Live
                    } else {
                        ObjectSnapshotClass::Draining
                    },
                })
                .collect(),
            thread_resources: registry
                .observed_thread_resources
                .keys()
                .map(|key| ThreadResourcesSnapshotRow {
                    key: *key,
                    class: if live_thread_resources.contains(key) {
                        ObjectSnapshotClass::Live
                    } else {
                        ObjectSnapshotClass::Draining
                    },
                })
                .collect(),
            mms,
            vmas,
            frames: frame_inventory.frames,
            mappings: frame_inventory.mappings,
            file_tables,
            file_slots,
            file_descriptions,
            fs_contexts,
            credentials,
            process_groups: registry.groups.clone(),
            sessions: registry.sessions.clone(),
            sighands,
            task_signals: registry
                .observed_tasks
                .iter()
                .map(|(key, task)| {
                    let pending = task.shared().pending_signals();
                    let revision = pending.revision();
                    let entries = pending.snapshot_entries();
                    checks.task_pending.push((Arc::clone(&pending), revision));
                    TaskSignalSnapshotRow {
                        task: *key,
                        class: if live_task_by_key
                            .get(key)
                            .is_some_and(|record| Arc::ptr_eq(&record.task, task))
                        {
                            ObjectSnapshotClass::Live
                        } else {
                            ObjectSnapshotClass::Draining
                        },
                        revision,
                        pending: entries,
                    }
                })
                .collect(),
            thread_signals,
        };
        sort_snapshot(&mut snapshot);
        validate_snapshot(&snapshot)?;

        for (thread, revision) in checks.threads {
            if thread.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (sighand, revision) in checks.sighands {
            if sighand.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (pending, revision) in checks.task_pending {
            if pending.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (table, revision) in checks.file_tables {
            if table.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (fs_context, revision) in checks.fs_contexts {
            if fs_context.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (description, revision) in checks.descriptions {
            if description.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (mm, revision) in checks.mms {
            if mm.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (backend, revision) in checks.backends {
            if backend.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (backend, revision) in checks.vma_revisions {
            if backend.vma_revision(deadline).map_err(map_backend_error)? != Some(revision) {
                return Err(AttemptError::Race);
            }
        }
        if lock_result(self.frame_inventory().revision_until(deadline), deadline)? != frame_revision
        {
            return Err(AttemptError::Race);
        }
        // Registry publication may race after the first verification while
        // leaf revisions are checked. Recheck it last so no successful
        // snapshot combines an old task association with new signal/resource
        // state.
        self.verify_registry(&registry, deadline)?;
        Ok(snapshot)
    }

    fn copy_registry(&self, deadline: Instant) -> Result<RegistryCopy, AttemptError> {
        let state = lock_result(self.registry().state.try_read_until(deadline), deadline)?;
        let tasks = state
            .tasks
            .values()
            .map(|record| RegistryTask {
                task: Arc::clone(&record.task),
                revision: record.revision,
                diagnostic_name: record.diagnostic_name.clone(),
            })
            .collect();
        let zombies = state
            .zombies
            .values()
            .map(|record| record.zombie.clone())
            .collect();
        let groups = state
            .process_groups
            .iter()
            .map(|(id, record)| ProcessGroupSnapshotRow {
                id: *id,
                session: record.object.session(),
                members: record.members.iter().copied().collect(),
            })
            .collect();
        let sessions = state
            .sessions
            .iter()
            .map(|(id, record)| SessionSnapshotRow {
                id: *id,
                process_groups: record.process_groups.iter().copied().collect(),
            })
            .collect();
        // Fixed lock order: registry -> weak observation inventory. Upgrading
        // here only pins objects for this snapshot attempt; it grants no
        // lifecycle authority and owns no claims.
        let observations = lock_result(self.observations.try_lock_until(deadline), deadline)?;
        let mut observed_tasks = BTreeMap::new();
        for (key, objects) in &observations.tasks {
            for object in objects.iter().filter_map(Weak::upgrade) {
                insert_shared(
                    &mut observed_tasks,
                    *key,
                    object,
                    "pointer-distinct tasks share one stable identity",
                )?;
            }
        }
        let mut observed_threads = BTreeMap::new();
        for (key, objects) in &observations.threads {
            for (task, weak) in objects {
                let Some(object) = weak.upgrade() else {
                    continue;
                };
                if let Some((existing_task, existing)) = observed_threads.get(key) {
                    if *existing_task != *task || !Arc::ptr_eq(existing, &object) {
                        return invariant("pointer-distinct threads share one stable identity");
                    }
                } else {
                    observed_threads.insert(*key, (*task, object));
                }
            }
        }
        let mut observed_mms = BTreeMap::new();
        for (key, objects) in &observations.mms {
            for object in objects.iter().filter_map(Weak::upgrade) {
                insert_shared(
                    &mut observed_mms,
                    *key,
                    object,
                    "pointer-distinct mms share one stable identity",
                )?;
            }
        }
        let mut observed_sighands = BTreeMap::new();
        for (key, objects) in &observations.sighands {
            for object in objects.iter().filter_map(Weak::upgrade) {
                insert_shared(
                    &mut observed_sighands,
                    *key,
                    object,
                    "pointer-distinct sighands share one stable identity",
                )?;
            }
        }
        let mut observed_task_shared = BTreeMap::new();
        for (key, objects) in &observations.task_shared {
            for object in objects.iter().filter_map(Weak::upgrade) {
                insert_shared(
                    &mut observed_task_shared,
                    *key,
                    object,
                    "pointer-distinct task-shared bundles share one observation key",
                )?;
            }
        }
        let mut observed_thread_resources = BTreeMap::new();
        for (key, objects) in &observations.thread_resources {
            for object in objects.iter().filter_map(Weak::upgrade) {
                insert_shared(
                    &mut observed_thread_resources,
                    *key,
                    object,
                    "pointer-distinct thread resources share one observation key",
                )?;
            }
        }
        Ok(RegistryCopy {
            epoch: state.epoch,
            tasks,
            zombies,
            groups,
            sessions,
            observed_tasks,
            observed_threads,
            observed_mms,
            observed_sighands,
            observed_task_shared,
            observed_thread_resources,
        })
    }

    fn verify_registry(
        &self,
        copied: &RegistryCopy,
        deadline: Instant,
    ) -> Result<(), AttemptError> {
        let state = lock_result(self.registry().state.try_read_until(deadline), deadline)?;
        if state.epoch != copied.epoch || state.tasks.len() != copied.tasks.len() {
            return Err(AttemptError::Race);
        }
        for copied_task in &copied.tasks {
            let Some(record) = state.tasks.get(&copied_task.task.key().id) else {
                return Err(AttemptError::Race);
            };
            if record.task.key() != copied_task.task.key()
                || record.revision != copied_task.revision
            {
                return Err(AttemptError::Race);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptError {
    Race,
    Public(KernelSnapshotError),
}

fn lock_result<T>(value: Option<T>, deadline: Instant) -> Result<T, AttemptError> {
    value.ok_or_else(|| {
        AttemptError::Public(if Instant::now() >= deadline {
            KernelSnapshotError::TimedOut
        } else {
            KernelSnapshotError::Busy
        })
    })
}

fn map_backend_error(error: SnapshotError) -> AttemptError {
    match error {
        SnapshotError::AuthorityUnavailable(table) => {
            AttemptError::Public(KernelSnapshotError::AuthorityUnavailable(table))
        }
        SnapshotError::ChangedDuringObservation => AttemptError::Race,
        SnapshotError::Busy => AttemptError::Public(KernelSnapshotError::Busy),
        SnapshotError::TimedOut => AttemptError::Public(KernelSnapshotError::TimedOut),
    }
}

fn invariant<T>(message: &'static str) -> Result<T, AttemptError> {
    Err(AttemptError::Public(
        KernelSnapshotError::InvariantViolation(message),
    ))
}

fn insert_shared<K: Ord, V>(
    table: &mut BTreeMap<K, Arc<V>>,
    key: K,
    value: Arc<V>,
    message: &'static str,
) -> Result<(), AttemptError> {
    if let Some(existing) = table.get(&key) {
        return if Arc::ptr_eq(existing, &value) {
            Ok(())
        } else {
            invariant(message)
        };
    }
    table.insert(key, value);
    Ok(())
}

fn matching_task_shared_key(
    observations: &BTreeMap<TaskSharedObservationKey, Arc<super::objects::TaskShared>>,
    task: TaskKey,
    shared: &Arc<super::objects::TaskShared>,
) -> Result<TaskSharedObservationKey, AttemptError> {
    let mut matches = observations.iter().filter_map(|(key, observed)| {
        (key.task == task && Arc::ptr_eq(observed, shared)).then_some(*key)
    });
    let Some(key) = matches.next() else {
        return invariant("published task-shared association is unobserved");
    };
    if matches.next().is_some() {
        return invariant("task-shared generation has duplicate observation keys");
    }
    Ok(key)
}

fn matching_thread_resources_key(
    observations: &BTreeMap<ThreadResourcesObservationKey, Arc<super::objects::ThreadResources>>,
    thread: ThreadKey,
    resources: &Arc<super::objects::ThreadResources>,
) -> Result<ThreadResourcesObservationKey, AttemptError> {
    let mut matches = observations.iter().filter_map(|(key, observed)| {
        (key.thread == thread && Arc::ptr_eq(observed, resources)).then_some(*key)
    });
    let Some(key) = matches.next() else {
        return invariant("published thread-resources association is unobserved");
    };
    if matches.next().is_some() {
        return invariant("thread-resources generation has duplicate observation keys");
    }
    Ok(key)
}

fn has_duplicates<T: Copy + Ord>(values: &[T]) -> bool {
    values.iter().copied().collect::<BTreeSet<_>>().len() != values.len()
}

fn thread_signal_row(
    thread: ThreadKey,
    class: ObjectSnapshotClass,
    revision: u64,
    state: ThreadSignalState,
) -> ThreadSignalSnapshotRow {
    ThreadSignalSnapshotRow {
        thread,
        class,
        revision,
        blocked: state.blocked(),
        pending: state.snapshot_pending_entries(),
        altstack: state.altstack(),
        handler_frames: state.handler_frames(),
        armed_restore_mask: state.armed_restore_mask(),
        routed_siginfos: state.routed_siginfos(),
        pending_actions: state.pending_actions(),
    }
}

fn sort_snapshot(snapshot: &mut KernelSnapshotV1) {
    snapshot.tasks.sort_by_key(|row| row.key);
    snapshot.zombies.sort_by_key(|row| row.zombie.key);
    snapshot.threads.sort_by_key(|row| row.key);
    snapshot.task_shared.sort_by_key(|row| row.key);
    snapshot.thread_resources.sort_by_key(|row| row.key);
    snapshot.mms.sort_by_key(|row| row.id);
    snapshot
        .vmas
        .sort_by_key(|row| (row.mm, row.start, row.end));
    snapshot.frames.sort_by_key(|row| row.frame);
    snapshot.mappings.sort_by_key(|row| row.mapping);
    snapshot.file_tables.sort_by_key(|row| row.id);
    snapshot
        .file_slots
        .sort_by_key(|row| (row.table, row.number));
    snapshot.file_descriptions.sort_by_key(|row| row.id);
    snapshot.fs_contexts.sort_by_key(|row| row.id);
    snapshot.credentials.sort_by_key(|row| row.id);
    snapshot.process_groups.sort_by_key(|row| row.id);
    snapshot.sessions.sort_by_key(|row| row.id);
    snapshot.sighands.sort_by_key(|row| row.id);
    snapshot.task_signals.sort_by_key(|row| row.task);
    snapshot.thread_signals.sort_by_key(|row| row.thread);
}

fn validate_snapshot(snapshot: &KernelSnapshotV1) -> Result<(), AttemptError> {
    let task_by_key: BTreeMap<_, _> = snapshot.tasks.iter().map(|row| (row.key, row)).collect();
    let observed_tasks: BTreeSet<_> = task_by_key.keys().copied().collect();
    let live_tasks: BTreeSet<_> = snapshot
        .tasks
        .iter()
        .filter_map(|row| (row.class == ObjectSnapshotClass::Live).then_some(row.key))
        .collect();
    let zombies: BTreeSet<_> = snapshot.zombies.iter().map(|row| row.zombie.key).collect();
    if observed_tasks.len() != snapshot.tasks.len()
        || zombies.len() != snapshot.zombies.len()
        || !live_tasks.is_disjoint(&zombies)
    {
        return invariant("duplicate or overlapping live-task/zombie key");
    }
    let mm_by_id: BTreeMap<_, _> = snapshot.mms.iter().map(|row| (row.id, row)).collect();
    let sighand_by_id: BTreeMap<_, _> = snapshot.sighands.iter().map(|row| (row.id, row)).collect();
    let mm_ids: BTreeSet<_> = mm_by_id.keys().copied().collect();
    let sighand_ids: BTreeSet<_> = sighand_by_id.keys().copied().collect();
    let shared_by_key: BTreeMap<_, _> = snapshot
        .task_shared
        .iter()
        .map(|row| (row.key, row))
        .collect();
    let resources_by_key: BTreeMap<_, _> = snapshot
        .thread_resources
        .iter()
        .map(|row| (row.key, row))
        .collect();
    let group_by_id: BTreeMap<_, _> = snapshot
        .process_groups
        .iter()
        .map(|row| (row.id, row))
        .collect();
    let session_by_id: BTreeMap<_, _> = snapshot.sessions.iter().map(|row| (row.id, row)).collect();
    let group_ids: BTreeSet<_> = group_by_id.keys().copied().collect();
    let session_ids: BTreeSet<_> = session_by_id.keys().copied().collect();
    if mm_ids.len() != snapshot.mms.len()
        || sighand_ids.len() != snapshot.sighands.len()
        || shared_by_key.len() != snapshot.task_shared.len()
        || resources_by_key.len() != snapshot.thread_resources.len()
        || group_ids.len() != snapshot.process_groups.len()
        || session_ids.len() != snapshot.sessions.len()
    {
        return invariant("duplicate mm/sighand/group/session identity");
    }
    for task in &snapshot.tasks {
        if has_duplicates(&task.children) {
            return invariant("task contains duplicate child keys");
        }
        if task.shared.task != task.key
            || task.shared.mm != task.mm
            || task.shared.sighand != task.sighand
            || !mm_ids.contains(&task.mm)
            || !sighand_ids.contains(&task.sighand)
            || !shared_by_key.contains_key(&task.shared)
        {
            return invariant("task bundle or leaf join is missing");
        }
        if task.class == ObjectSnapshotClass::Live
            && (task.revision.is_none()
                || task.diagnostic_name.is_none()
                || !group_ids.contains(&task.process_group)
                || !session_ids.contains(&task.session))
        {
            return invariant("live task registry join is missing");
        }
        if task.class == ObjectSnapshotClass::Draining
            && (task.revision.is_some() || task.diagnostic_name.is_some())
        {
            return invariant("draining task retains registry-only metadata");
        }
        if task.class == ObjectSnapshotClass::Live
            && (task.parent.is_some_and(|parent| {
                task_by_key
                    .get(&parent)
                    .is_none_or(|parent_row| !parent_row.children.contains(&task.key))
            }) || task.children.iter().any(|child| {
                task_by_key.get(child).map_or_else(
                    || {
                        snapshot
                            .zombies
                            .iter()
                            .find(|row| row.zombie.key == *child)
                            .is_none_or(|row| row.zombie.parent != Some(task.key))
                    },
                    |child_row| child_row.parent != Some(task.key),
                )
            }))
        {
            return invariant("task parent/child backlink is missing");
        }
        if task.class == ObjectSnapshotClass::Live {
            let Some(group) = group_by_id.get(&task.process_group) else {
                return invariant("task process-group join is missing");
            };
            let Some(session_row) = session_by_id.get(&task.session) else {
                return invariant("task session join is missing");
            };
            if group.session != task.session
                || !group.members.contains(&task.key)
                || !session_row.process_groups.contains(&task.process_group)
            {
                return invariant("task group/session backlink is missing");
            }
        }
    }
    for zombie in &snapshot.zombies {
        if zombie
            .zombie
            .parent
            .is_some_and(|parent| !live_tasks.contains(&parent))
        {
            return invariant("zombie parent join is missing");
        }
    }
    for group in &snapshot.process_groups {
        if has_duplicates(&group.members)
            || !session_ids.contains(&group.session)
            || group.members.iter().any(|member| {
                task_by_key.get(member).is_none_or(|task| {
                    task.class != ObjectSnapshotClass::Live
                        || task.process_group != group.id
                        || task.session != group.session
                })
            })
        {
            return invariant("process-group join is missing");
        }
        if session_by_id
            .get(&group.session)
            .is_none_or(|session| !session.process_groups.contains(&group.id))
        {
            return invariant("process-group session backlink is missing");
        }
    }
    for session in &snapshot.sessions {
        if has_duplicates(&session.process_groups)
            || session.process_groups.iter().any(|group| {
                group_by_id
                    .get(group)
                    .is_none_or(|group| group.session != session.id)
            })
        {
            return invariant("session join is missing");
        }
    }

    let live_shared: BTreeSet<_> = snapshot
        .tasks
        .iter()
        .filter_map(|row| (row.class == ObjectSnapshotClass::Live).then_some(row.shared))
        .collect();
    for shared in &snapshot.task_shared {
        if (shared.class == ObjectSnapshotClass::Live && !observed_tasks.contains(&shared.key.task))
            || !mm_ids.contains(&shared.key.mm)
            || !sighand_ids.contains(&shared.key.sighand)
            || (shared.class == ObjectSnapshotClass::Live) != live_shared.contains(&shared.key)
        {
            return invariant("task-shared class or join is inconsistent");
        }
    }
    let reachable_live_mms: BTreeSet<_> = live_shared.iter().map(|key| key.mm).collect();
    let reachable_live_sighands: BTreeSet<_> = live_shared.iter().map(|key| key.sighand).collect();
    if snapshot
        .mms
        .iter()
        .any(|row| (row.class == ObjectSnapshotClass::Live) != reachable_live_mms.contains(&row.id))
        || snapshot.sighands.iter().any(|row| {
            (row.class == ObjectSnapshotClass::Live) != reachable_live_sighands.contains(&row.id)
        })
    {
        return invariant("mm or sighand class is inconsistent with live reachability");
    }

    let thread_keys: BTreeSet<_> = snapshot.threads.iter().map(|row| row.key).collect();
    let thread_class_by_key: BTreeMap<_, _> = snapshot
        .threads
        .iter()
        .map(|row| (row.key, row.class))
        .collect();
    if thread_keys.len() != snapshot.threads.len() {
        return invariant("duplicate thread key");
    }
    let file_tables: BTreeSet<_> = snapshot.file_tables.iter().map(|row| row.id).collect();
    let fs_contexts: BTreeSet<_> = snapshot.fs_contexts.iter().map(|row| row.id).collect();
    if file_tables.len() != snapshot.file_tables.len()
        || fs_contexts.len() != snapshot.fs_contexts.len()
    {
        return invariant("duplicate file-table or fs-context identity");
    }
    let live_resources: BTreeSet<_> = snapshot
        .threads
        .iter()
        .filter_map(|row| (row.class == ObjectSnapshotClass::Live).then_some(row.resources))
        .collect();
    for resources in &snapshot.thread_resources {
        if (resources.class == ObjectSnapshotClass::Live
            && !thread_keys.contains(&resources.key.thread))
            || !file_tables.contains(&resources.key.file_table)
            || !fs_contexts.contains(&resources.key.fs_context)
            || !snapshot
                .credentials
                .iter()
                .any(|credentials| credentials.id == resources.key.credentials)
            || (resources.class == ObjectSnapshotClass::Live)
                != live_resources.contains(&resources.key)
        {
            return invariant("thread-resources class or join is inconsistent");
        }
    }
    for thread in &snapshot.threads {
        if !resources_by_key.contains_key(&thread.resources)
            || thread.resources.thread != thread.key
            || thread
                .credentials
                .is_some_and(|id| id != thread.resources.credentials)
        {
            return invariant("thread task or resources join is missing");
        }
        if thread.class == ObjectSnapshotClass::Live
            && (!observed_tasks.contains(&thread.task)
                || !live_tasks.contains(&thread.task)
                || thread.file_table.is_none()
                || thread.fs_context.is_none()
                || thread.credentials.is_none())
        {
            return invariant("live thread leaf join is missing");
        }
        if thread
            .file_table
            .is_some_and(|id| !file_tables.contains(&id))
            || thread
                .fs_context
                .is_some_and(|id| !fs_contexts.contains(&id))
        {
            return invariant("thread resource join is missing");
        }
    }
    let leaf_threads: BTreeSet<_> = snapshot
        .threads
        .iter()
        .filter_map(|row| row.registry_id.map(|_| row.key))
        .collect();
    let credential_ids: BTreeSet<_> = snapshot.credentials.iter().map(|row| row.id).collect();
    let live_credential_ids: BTreeSet<_> = snapshot
        .credentials
        .iter()
        .filter_map(|row| (row.class == ObjectSnapshotClass::Live).then_some(row.id))
        .collect();
    let thread_credential_ids: BTreeSet<_> = snapshot
        .threads
        .iter()
        .filter_map(|row| row.credentials)
        .collect();
    let signal_threads: BTreeSet<_> = snapshot
        .thread_signals
        .iter()
        .map(|row| row.thread)
        .collect();
    let task_signal_tasks: BTreeSet<_> = snapshot.task_signals.iter().map(|row| row.task).collect();
    if credential_ids.len() != snapshot.credentials.len()
        || signal_threads.len() != snapshot.thread_signals.len()
        || task_signal_tasks.len() != snapshot.task_signals.len()
        || leaf_threads != thread_keys
        || thread_credential_ids != live_credential_ids
        || signal_threads != thread_keys
        || task_signal_tasks != observed_tasks
        || snapshot
            .thread_signals
            .iter()
            .any(|row| thread_class_by_key.get(&row.thread).copied() != Some(row.class))
        || snapshot
            .task_signals
            .iter()
            .any(|row| task_by_key.get(&row.task).map(|task| task.class) != Some(row.class))
    {
        return invariant("thread credential/signal or task-signal coverage is incomplete");
    }

    let descriptions: BTreeSet<_> = snapshot
        .file_descriptions
        .iter()
        .map(|row| row.id)
        .collect();
    let slot_keys: BTreeSet<_> = snapshot
        .file_slots
        .iter()
        .map(|row| (row.table, row.number))
        .collect();
    if descriptions.len() != snapshot.file_descriptions.len()
        || slot_keys.len() != snapshot.file_slots.len()
    {
        return invariant("duplicate file-description or file-slot identity");
    }
    for slot in &snapshot.file_slots {
        if !file_tables.contains(&slot.table) || !descriptions.contains(&slot.description) {
            return invariant("file slot join is missing");
        }
    }
    let description_rows = snapshot
        .file_descriptions
        .iter()
        .map(|row| (row.id, row))
        .collect::<BTreeMap<_, _>>();
    for mm in &snapshot.mms {
        let mapping_keys = mm
            .io_uring_mappings
            .iter()
            .map(|mapping| {
                (
                    mapping.description,
                    mapping.region,
                    mapping.start,
                    mapping.end,
                    mapping.backing_offset,
                )
            })
            .collect::<Vec<_>>();
        if has_duplicates(&mapping_keys) {
            return invariant("duplicate mm io_uring mapping identity");
        }
        let mut extents = mm
            .io_uring_mappings
            .iter()
            .map(|mapping| (mapping.start, mapping.end))
            .collect::<Vec<_>>();
        extents.sort_unstable();
        if extents.windows(2).any(|window| window[0].1 > window[1].0) {
            return invariant("overlapping mm io_uring mapping extents");
        }
        for mapping in &mm.io_uring_mappings {
            let Some(description) = description_rows.get(&mapping.description) else {
                return invariant("mm io_uring description join is missing");
            };
            let Some(super::objects::FileDescriptionBackingSnapshot::IoUring(ring)) =
                description.backing.as_ref()
            else {
                return invariant("mm io_uring mapping targets a non-ring description");
            };
            let length = mapping.end.checked_sub(mapping.start);
            let region_fits = match mapping.region {
                crate::dispatch::ioring::IoUringRegion::SqCq => length.is_some_and(|length| {
                    mapping.backing_offset < ring.layout.sqes_backing_offset
                        && mapping
                            .backing_offset
                            .checked_add(length)
                            .is_some_and(|end| end <= ring.layout.sqes_backing_offset)
                }),
                crate::dispatch::ioring::IoUringRegion::Sqes => length.is_some_and(|length| {
                    mapping.backing_offset >= ring.layout.sqes_backing_offset
                        && mapping
                            .backing_offset
                            .checked_add(length)
                            .is_some_and(|end| end <= ring.layout.backing_len)
                }),
            };
            let vma_covers_mapping = snapshot
                .vmas
                .iter()
                .any(|vma| vma.mm == mm.id && vma.start <= mapping.start && mapping.end <= vma.end);
            if mapping.start >= mapping.end
                || !mapping.start.is_multiple_of(4096)
                || !mapping.end.is_multiple_of(4096)
                || !mapping.backing_offset.is_multiple_of(4096)
                || !region_fits
                || !vma_covers_mapping
            {
                return invariant("mm io_uring mapping layout or VMA join is invalid");
            }
        }
    }
    for table in &snapshot.file_tables {
        if has_duplicates(&table.splice_pushback_description_ids)
            || table
                .splice_pushback_description_ids
                .iter()
                .any(|description| !descriptions.contains(description))
        {
            return invariant("file-table subordinate description join is missing");
        }
    }
    let epoll_interests_by_description = snapshot
        .file_descriptions
        .iter()
        .map(|description| (description.id, &description.epoll_interests))
        .collect::<BTreeMap<_, _>>();
    for description in &snapshot.file_descriptions {
        if has_duplicates(&description.epoll_interests)
            || description
                .epoll_interests
                .iter()
                .any(|target| !descriptions.contains(target))
        {
            return invariant("epoll description join is missing");
        }
        if has_duplicates(&description.epoll_owners)
            || description.epoll_owners.iter().any(|(owner, _)| {
                !epoll_interests_by_description
                    .get(owner)
                    .is_some_and(|interests| interests.contains(&description.id))
            })
        {
            return invariant("reverse epoll-owner join is missing");
        }
        if let Some(backing) = &description.backing
            && backing.epoll_interests() != description.epoll_interests
        {
            return invariant("file-description backing summary is inconsistent");
        }
    }

    let vma_keys: BTreeSet<_> = snapshot
        .vmas
        .iter()
        .map(|row| (row.mm, row.start, row.end))
        .collect();
    if vma_keys.len() != snapshot.vmas.len()
        || snapshot
            .vmas
            .iter()
            .any(|row| !mm_ids.contains(&row.mm) || row.start >= row.end)
    {
        return invariant("duplicate, malformed, or unjoined VMA row");
    }

    if snapshot
        .frames
        .iter()
        .any(|row| has_duplicates(&row.mappings))
    {
        return invariant("frame contains duplicate mapping aliases");
    }
    let frame_lengths: BTreeMap<_, _> = snapshot
        .frames
        .iter()
        .map(|row| (row.frame, row.length))
        .collect();
    let frames: BTreeMap<FrameId, BTreeSet<MappingId>> = snapshot
        .frames
        .iter()
        .map(|row| (row.frame, row.mappings.iter().copied().collect()))
        .collect();
    if frames.len() != snapshot.frames.len() {
        return invariant("duplicate frame identity");
    }
    let mapping_ids: BTreeSet<_> = snapshot.mappings.iter().map(|row| row.mapping).collect();
    if mapping_ids.len() != snapshot.mappings.len() {
        return invariant("duplicate mapping identity");
    }
    for mapping in &snapshot.mappings {
        if !mm_ids.contains(&mapping.mm)
            || frames
                .get(&mapping.frame)
                .is_none_or(|aliases| !aliases.contains(&mapping.mapping))
            || frame_lengths
                .get(&mapping.frame)
                .is_none_or(|length| *length != mapping.length)
        {
            return invariant("mapping frame/mm/length join is missing");
        }
    }
    for (frame, aliases) in &frames {
        let actual: BTreeSet<_> = snapshot
            .mappings
            .iter()
            .filter_map(|mapping| (mapping.frame == *frame).then_some(mapping.mapping))
            .collect();
        if *aliases != actual {
            return invariant("frame alias list disagrees with mappings");
        }
    }
    for mm in &snapshot.mms {
        let actual: Vec<_> = snapshot
            .mappings
            .iter()
            .filter_map(|mapping| (mapping.mm == mm.id).then_some(mapping.mapping))
            .collect();
        if mm.mapping_ids != actual {
            return invariant("backend and frame inventory mappings disagree");
        }
    }
    for rows in snapshot.vmas.chunk_by(|left, right| left.mm == right.mm) {
        if rows.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return invariant("VMA rows overlap");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU16, NonZeroU64};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, Weak};
    use std::time::Duration;

    use carrick_abi::LinuxCloneFlags;
    use carrick_guest_mem::{Gpa, GuestVa};
    use carrick_hal::{MappingId, ThreadId};

    use super::*;
    use crate::kernel::{
        Asid, ClonePlan, KernelContext, LinuxWaitStatus, MmBackendSnapshot, RootBootstrap,
        SnapshotError, Stage1Root, TaskRusage, VmaSummary, WaitMode, WaitOutcome,
    };

    #[derive(Clone, Copy, Debug)]
    enum BackendMode {
        Good,
        IoUring,
        Unavailable,
        MalformedVma,
        BrokenMappingJoin,
        FrameRevisionRace,
        RevisionRace,
        VmaRevisionRace,
    }

    #[derive(Debug)]
    struct TestBackend {
        binding: MmBinding,
        revision: AtomicU64,
        vma_revision: AtomicU64,
        mode: BackendMode,
        kernel: Mutex<Option<Weak<Kernel>>>,
        bump_epoch: bool,
    }

    impl TestBackend {
        fn new(mode: BackendMode) -> Arc<Self> {
            let asid = Asid::from_registry_allocation(NonZeroU16::new(7).expect("ASID"));
            let root = Stage1Root::for_aarch64_4k(Gpa(0x8000)).expect("root");
            Arc::new(Self {
                binding: MmBinding::for_aarch64(asid, root),
                revision: AtomicU64::new(1),
                vma_revision: AtomicU64::new(1),
                mode,
                kernel: Mutex::new(None),
                bump_epoch: false,
            })
        }

        fn epoch_racer() -> Arc<Self> {
            let mut backend = Arc::try_unwrap(Self::new(BackendMode::Good)).expect("unique");
            backend.bump_epoch = true;
            Arc::new(backend)
        }
    }

    impl MmBackend for TestBackend {
        fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
            if self.bump_epoch
                && let Some(kernel) = self.kernel.lock().expect("kernel slot").as_ref()
                && let Some(kernel) = kernel.upgrade()
            {
                drop(kernel.registry().state.write());
            }
            match self.mode {
                BackendMode::Unavailable => {
                    Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas))
                }
                BackendMode::MalformedVma => Ok(MmBackendSnapshot {
                    revision: self.revision(),
                    binding: self.binding,
                    vmas: vec![VmaSummary {
                        start: GuestVa(0x2000),
                        end: GuestVa(0x1000),
                    }],
                    vma_revision: None,
                    mapping_ids: Vec::new(),
                    frame_inventory_revision: None,
                }),
                BackendMode::BrokenMappingJoin => Ok(MmBackendSnapshot {
                    revision: self.revision(),
                    binding: self.binding,
                    vmas: Vec::new(),
                    vma_revision: None,
                    mapping_ids: vec![MappingId::from_kernel_allocation(
                        NonZeroU64::new(99).expect("mapping"),
                    )],
                    frame_inventory_revision: None,
                }),
                BackendMode::FrameRevisionRace => Ok(MmBackendSnapshot {
                    revision: self.revision(),
                    binding: self.binding,
                    vmas: Vec::new(),
                    vma_revision: None,
                    mapping_ids: Vec::new(),
                    frame_inventory_revision: Some(u64::MAX),
                }),
                BackendMode::RevisionRace => {
                    let observed = self.revision.fetch_add(1, Ordering::Release);
                    Ok(MmBackendSnapshot {
                        revision: observed,
                        binding: self.binding,
                        vmas: Vec::new(),
                        vma_revision: None,
                        mapping_ids: Vec::new(),
                        frame_inventory_revision: None,
                    })
                }
                BackendMode::VmaRevisionRace => {
                    let observed = self.vma_revision.fetch_add(1, Ordering::Release);
                    Ok(MmBackendSnapshot {
                        revision: self.revision(),
                        binding: self.binding,
                        vmas: Vec::new(),
                        vma_revision: Some(crate::kernel::VmaRevision::from_authority_raw(
                            observed,
                        )),
                        mapping_ids: Vec::new(),
                        frame_inventory_revision: None,
                    })
                }
                BackendMode::Good | BackendMode::IoUring => Ok(MmBackendSnapshot {
                    revision: self.revision(),
                    binding: self.binding,
                    vmas: if matches!(self.mode, BackendMode::IoUring) {
                        vec![
                            VmaSummary {
                                start: GuestVa(0x1000),
                                end: GuestVa(0x2000),
                            },
                            VmaSummary {
                                start: GuestVa(0x3000),
                                end: GuestVa(0x4000),
                            },
                        ]
                    } else {
                        vec![VmaSummary {
                            start: GuestVa(0x1000),
                            end: GuestVa(0x2000),
                        }]
                    },
                    vma_revision: None,
                    mapping_ids: Vec::new(),
                    frame_inventory_revision: None,
                }),
            }
        }

        fn revision(&self) -> u64 {
            self.revision.load(Ordering::Acquire)
        }

        fn vma_revision(
            &self,
            _deadline: Instant,
        ) -> Result<Option<crate::kernel::VmaRevision>, SnapshotError> {
            Ok(matches!(self.mode, BackendMode::VmaRevisionRace).then(|| {
                crate::kernel::VmaRevision::from_authority_raw(
                    self.vma_revision.load(Ordering::Acquire),
                )
            }))
        }
    }

    fn bootstrap(backend: Arc<TestBackend>) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::with_mm_backend(
            7000,
            ThreadId::synthetic_for_tests(7000),
            backend.clone(),
            "root".to_string(),
        )
        .expect("bootstrap input");
        let (kernel, context) = Kernel::bootstrap_root(input).expect("bootstrap");
        *backend.kernel.lock().expect("kernel slot") = Some(Arc::downgrade(&kernel));
        (kernel, context)
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    #[test]
    fn snapshot_is_owned_sorted_and_strictly_joined() {
        let (kernel, context) = bootstrap(TestBackend::new(BackendMode::Good));
        context
            .resources()
            .fs_context()
            .set_cwd("/snapshot/cwd".to_owned());
        context
            .resources()
            .fs_context()
            .set_chroot_root(Some("/snapshot/root".to_owned()));
        let context = kernel
            .update_credentials(&context, |credentials| {
                credentials.set_supplementary_groups(vec![9, 10]);
            })
            .expect("publish credential snapshot values");
        let usr1 = LinuxSignal::for_signal_number(10).unwrap();
        let rt = LinuxSignal::for_signal_number(34).unwrap();
        let authority = context.signal_authority();
        authority.install_action(
            usr1,
            LinuxSigaction {
                sa_handler: 0x1234,
                ..LinuxSigaction::empty()
            },
        );
        authority.set_blocked(SigSet::EMPTY.with(10));
        authority.enqueue_task_standard(usr1, None);
        authority.enqueue_thread_realtime(rt, Some(LinuxSiginfo::rt_queue(34, 7, 8, 9)));
        context.thread().update_signal_state(|state| {
            state.set_altstack(Some(LinuxSigaltstack {
                ss_sp: 0x4000,
                ss_flags: 0,
                __pad: 0,
                ss_size: 0x2000,
            }));
            state.push_handler_frame(HandlerFrameState {
                on_altstack: true,
                restore_mask: Some(SigSet::EMPTY.with(12)),
            });
            state.arm_restore_mask(Some(SigSet::EMPTY.with(14)));
            state.record_routed_siginfo(usr1, LinuxSiginfo::kill(10, 0, 7, 8));
            state.record_pending_action(usr1, LinuxSigaction::empty());
        });
        let first = kernel.snapshot(deadline()).expect("snapshot");
        let second = kernel.snapshot(deadline()).expect("snapshot");
        assert_eq!(first, second);
        assert_eq!(first.schema_version, KERNEL_SNAPSHOT_V1_SCHEMA);
        assert_eq!(
            (first.tasks.len(), first.threads.len(), first.mms.len()),
            (1, 1, 1)
        );
        assert_eq!(first.vmas.len(), 1);
        let live_credentials = first
            .credentials
            .iter()
            .find(|row| row.class == ObjectSnapshotClass::Live)
            .expect("live credentials");
        assert_eq!(Some(live_credentials.id), first.threads[0].credentials);
        assert_eq!(live_credentials.umask, 0o022);
        assert_eq!(
            live_credentials.supplementary_groups_override,
            Some(vec![9, 10])
        );
        let draining_credentials = first
            .credentials
            .iter()
            .find(|row| row.class == ObjectSnapshotClass::Draining)
            .expect("captured prior credentials remain draining");
        assert_eq!(draining_credentials.supplementary_groups_override, None);
        let live_fs_context = first
            .fs_contexts
            .iter()
            .find(|row| row.class == ObjectSnapshotClass::Live)
            .expect("live filesystem context");
        assert_eq!(live_fs_context.cwd, "/snapshot/cwd");
        assert_eq!(
            live_fs_context.chroot_root.as_deref(),
            Some("/snapshot/root")
        );
        assert!(live_fs_context.revision > 1);
        assert!(first.frames.is_empty() && first.mappings.is_empty());
        assert_eq!(first.task_signals.len(), 1);
        assert_eq!(first.task_signals[0].class, ObjectSnapshotClass::Live);
        assert_eq!(first.task_signals[0].pending.len(), 1);
        assert!(first.task_signals[0].revision > 1);
        assert_eq!(first.thread_signals.len(), 1);
        let signal = &first.thread_signals[0];
        assert_eq!(signal.class, ObjectSnapshotClass::Live);
        assert_eq!(signal.blocked, SigSet::EMPTY.with(10));
        assert_eq!(signal.pending.len(), 1);
        let altstack_sp = signal.altstack.unwrap().ss_sp;
        assert_eq!(altstack_sp, 0x4000);
        assert_eq!(signal.handler_frames.len(), 1);
        assert_eq!(signal.armed_restore_mask, Some(SigSet::EMPTY.with(14)));
        assert_eq!(signal.routed_siginfos.len(), 1);
        assert_eq!(signal.pending_actions.len(), 1);
        assert_eq!(first.sighands[0].actions.len(), 1);
    }

    #[test]
    fn snapshot_joins_multiple_ring_mappings_and_mapping_owned_description() {
        let (kernel, context) = bootstrap(TestBackend::new(BackendMode::IoUring));
        let backing =
            crate::dispatch::ioring::IoUringBacking::create(8, 4096).expect("ring backing");
        let layout = backing.reexec_layout();
        let description =
            Arc::new(FileDescription::concrete(backing).expect("ring description identity"));
        let mm = context.shared().mm();
        for (start, region, backing_offset) in [
            (0x1000, crate::dispatch::ioring::IoUringRegion::SqCq, 0),
            (
                0x3000,
                crate::dispatch::ioring::IoUringRegion::Sqes,
                layout.sqes_backing_offset,
            ),
        ] {
            mm.replace_io_uring_mappings(
                start,
                0x1000,
                Some(crate::dispatch::ioring::IoUringMapping {
                    description: Arc::clone(&description),
                    region,
                    start,
                    end: start + 0x1000,
                    backing_offset,
                }),
            );
        }

        let snapshot = kernel.snapshot(deadline()).expect("ring snapshot");
        let row = snapshot
            .mms
            .iter()
            .find(|row| row.id == mm.id())
            .expect("mm row");
        assert_eq!(row.io_uring_mappings.len(), 2);
        let description_row = snapshot
            .file_descriptions
            .iter()
            .find(|row| row.id == description.id())
            .expect("mapping-owned description row");
        assert!(matches!(
            description_row.backing,
            Some(crate::kernel::objects::FileDescriptionBackingSnapshot::IoUring(_))
        ));
    }

    #[test]
    fn unavailable_authority_and_contention_fail_closed() {
        let (kernel, _) = bootstrap(TestBackend::new(BackendMode::Unavailable));
        assert_eq!(
            kernel.snapshot(deadline()),
            Err(KernelSnapshotError::AuthorityUnavailable(
                SnapshotTable::Vmas
            ))
        );
        let (kernel, _) = bootstrap(TestBackend::new(BackendMode::Good));
        let _held = kernel.registry().state.write();
        assert_eq!(
            kernel.snapshot(Instant::now() + Duration::from_millis(5)),
            Err(KernelSnapshotError::TimedOut)
        );
    }

    #[test]
    fn epoch_and_revision_races_exhaust_three_retries() {
        let (kernel, _) = bootstrap(TestBackend::epoch_racer());
        assert_eq!(kernel.snapshot(deadline()), Err(KernelSnapshotError::Busy));
        for mode in [
            BackendMode::RevisionRace,
            BackendMode::FrameRevisionRace,
            BackendMode::VmaRevisionRace,
        ] {
            let (kernel, _) = bootstrap(TestBackend::new(mode));
            assert_eq!(kernel.snapshot(deadline()), Err(KernelSnapshotError::Busy));
        }
    }

    #[test]
    fn malformed_backend_rows_and_mapping_joins_are_rejected() {
        for mode in [BackendMode::MalformedVma, BackendMode::BrokenMappingJoin] {
            let (kernel, _) = bootstrap(TestBackend::new(mode));
            assert!(matches!(
                kernel.snapshot(deadline()),
                Err(KernelSnapshotError::InvariantViolation(_))
            ));
        }
    }

    #[test]
    fn duplicate_and_broken_bidirectional_joins_fail_closed() {
        let (kernel, root) = bootstrap(TestBackend::new(BackendMode::Good));
        let _child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::VM | LinuxCloneFlags::SIGHAND)
                    .expect("shared-mm child plan"),
                ThreadId::synthetic_for_tests(7002),
                "child".to_owned(),
                None,
            )
            .expect("shared-mm child");
        let snapshot = kernel.snapshot(deadline()).expect("snapshot");
        let assert_corrupt = |snapshot: &KernelSnapshotV1| {
            assert!(matches!(
                validate_snapshot(snapshot),
                Err(AttemptError::Public(
                    KernelSnapshotError::InvariantViolation(_)
                ))
            ));
        };

        let mut duplicate_credentials = snapshot.clone();
        duplicate_credentials
            .credentials
            .push(duplicate_credentials.credentials[0].clone());
        assert_corrupt(&duplicate_credentials);

        let mut duplicate_child = snapshot.clone();
        let parent = duplicate_child
            .tasks
            .iter_mut()
            .find(|task| !task.children.is_empty())
            .expect("parent row");
        parent.children.push(parent.children[0]);
        assert_corrupt(&duplicate_child);

        let mut missing_group_backlink = snapshot.clone();
        missing_group_backlink.process_groups[0].members.clear();
        assert_corrupt(&missing_group_backlink);

        let mut unjoined_vma = snapshot.clone();
        unjoined_vma.vmas[0].mm = MmId::from_registry_allocation(
            NonZeroU64::new(u64::MAX).expect("unjoined mm identity"),
        );
        assert_corrupt(&unjoined_vma);

        let mut missing_signal = snapshot;
        missing_signal.thread_signals.clear();
        assert_corrupt(&missing_signal);
    }

    #[test]
    fn pointer_distinct_stable_identity_collision_fails_closed() {
        let (kernel, root) = bootstrap(TestBackend::new(BackendMode::Good));
        let mm_id = root.shared().mm().id();
        let backend: Arc<dyn MmBackend> = TestBackend::new(BackendMode::Good);
        let collision = Arc::new(crate::kernel::Mm::with_backend(mm_id, backend));
        kernel
            .observations
            .lock()
            .mms
            .entry(mm_id)
            .or_default()
            .push(Arc::downgrade(&collision));
        assert!(matches!(
            kernel.snapshot(deadline()),
            Err(KernelSnapshotError::InvariantViolation(
                "pointer-distinct mms share one stable identity"
            ))
        ));
    }

    #[test]
    fn pointer_distinct_bundle_key_collision_fails_closed() {
        let (kernel, root) = bootstrap(TestBackend::new(BackendMode::Good));
        let collision = Arc::new(crate::kernel::TaskShared::new(
            root.shared().mm(),
            root.shared().sighand(),
        ));
        let key = *kernel
            .observations
            .lock()
            .task_shared
            .keys()
            .next()
            .expect("root task-shared observation");
        kernel
            .observations
            .lock()
            .task_shared
            .entry(key)
            .or_default()
            .push(Arc::downgrade(&collision));
        assert!(matches!(
            kernel.snapshot(deadline()),
            Err(KernelSnapshotError::InvariantViolation(
                "pointer-distinct task-shared bundles share one observation key"
            ))
        ));
    }

    #[test]
    fn retained_exec_context_and_bundles_drain_until_their_own_last_owner() {
        let (kernel, old_context) = bootstrap(TestBackend::new(BackendMode::Good));
        let retained_shared = Arc::clone(old_context.shared());
        let retained_resources = Arc::clone(old_context.resources());
        let old_thread = old_context.thread().key();
        let old_mm = old_context.shared().mm().id();
        let old_sighand = old_context.shared().sighand().id();
        let old_file_table = old_context.resources().files();
        let old_file_table_id = old_file_table.id();
        let description = Arc::new(crate::kernel::FileDescription::regular(
            kernel.object_ids().file_description_id().unwrap(),
        ));
        let description_id = description.id();
        let slot_number = FileSlotNumber::for_open_fd(7).unwrap();
        assert!(
            old_file_table
                .install(slot_number, description, true)
                .is_none()
        );
        let prepared = kernel
            .prepare_exec_with_mm_backend(&old_context, TestBackend::new(BackendMode::Good), None)
            .expect("prepare exec");
        let new_context = kernel.commit_exec(prepared, None).expect("commit exec");

        let draining = kernel.snapshot(deadline()).expect("draining snapshot");
        assert!(
            draining
                .threads
                .iter()
                .any(|row| row.key == old_thread && row.class == ObjectSnapshotClass::Draining)
        );
        assert!(
            draining
                .mms
                .iter()
                .any(|row| row.id == old_mm && row.class == ObjectSnapshotClass::Draining)
        );
        assert!(
            draining
                .sighands
                .iter()
                .any(|row| row.id == old_sighand && row.class == ObjectSnapshotClass::Draining)
        );
        assert!(draining.file_tables.iter().any(|row| {
            row.id == old_file_table_id && row.class == ObjectSnapshotClass::Draining
        }));
        assert!(draining.file_slots.iter().any(|row| {
            row.table == old_file_table_id
                && row.number == slot_number
                && row.description == description_id
                && row.close_on_exec
        }));
        assert!(
            draining.file_descriptions.iter().any(|row| {
                row.id == description_id && row.class == ObjectSnapshotClass::Draining
            })
        );
        let old_shared = draining
            .task_shared
            .iter()
            .find(|row| row.key.mm == old_mm)
            .expect("old task-shared row")
            .key;
        let old_resources = draining
            .thread_resources
            .iter()
            .find(|row| row.key.thread == old_thread)
            .expect("old thread-resources row")
            .key;
        assert_eq!(
            draining
                .task_shared
                .iter()
                .find(|row| row.key == old_shared)
                .expect("old task-shared")
                .class,
            ObjectSnapshotClass::Draining
        );
        assert_eq!(
            draining
                .thread_resources
                .iter()
                .find(|row| row.key == old_resources)
                .expect("old thread resources")
                .class,
            ObjectSnapshotClass::Draining
        );

        drop(draining);
        drop(old_context);
        let bundles_only = kernel
            .snapshot(deadline())
            .expect("bundle-only draining snapshot");
        assert!(!bundles_only.threads.iter().any(|row| row.key == old_thread));
        assert!(
            bundles_only
                .task_shared
                .iter()
                .any(|row| { row.key == old_shared && row.class == ObjectSnapshotClass::Draining })
        );
        assert!(
            bundles_only.thread_resources.iter().any(|row| {
                row.key == old_resources && row.class == ObjectSnapshotClass::Draining
            })
        );
        assert!(bundles_only.file_tables.iter().any(|row| {
            row.id == old_resources.file_table && row.class == ObjectSnapshotClass::Draining
        }));
        assert!(bundles_only.fs_contexts.iter().any(|row| {
            row.id == old_resources.fs_context && row.class == ObjectSnapshotClass::Live
        }));
        assert!(bundles_only.mms.iter().any(|row| row.id == old_mm));
        assert!(
            bundles_only
                .sighands
                .iter()
                .any(|row| row.id == old_sighand)
        );

        drop(bundles_only);
        drop(retained_shared);
        drop(retained_resources);
        let swept = kernel
            .snapshot(deadline())
            .expect("automatic swept snapshot");
        assert!(!swept.mms.iter().any(|row| row.id == old_mm));
        assert!(!swept.sighands.iter().any(|row| row.id == old_sighand));
        assert!(!swept.task_shared.iter().any(|row| row.key == old_shared));
        assert!(
            !swept
                .thread_resources
                .iter()
                .any(|row| row.key == old_resources)
        );
        drop(new_context);
    }

    #[test]
    fn reaped_zombie_context_and_bundles_drain_independently() {
        let (kernel, root) = bootstrap(TestBackend::new(BackendMode::Good));
        let child = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "child".to_owned(),
                None,
            )
            .expect("reserve fork")
            .prepare_with_mm_backend(
                TestBackend::new(BackendMode::Good),
                ThreadId::synthetic_for_tests(7003),
            )
            .expect("prepare fork")
            .commit()
            .expect("commit fork")
            .into_parts()
            .expect("start child")
            .0;
        let retained_shared = Arc::clone(child.shared());
        let retained_resources = Arc::clone(child.resources());
        let child_key = child.task().key();
        let child_thread = child.thread().key();
        let child_mm = child.shared().mm().id();
        let child_sighand = child.shared().sighand().id();
        kernel
            .exit_task(
                child_key.id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            )
            .expect("exit child");
        assert!(matches!(
            kernel.wait_child(root.task().key().id, Some(child_key.id), WaitMode::Consume),
            Ok(WaitOutcome::Exited(_))
        ));

        let draining = kernel.snapshot(deadline()).expect("draining snapshot");
        assert!(
            !draining
                .zombies
                .iter()
                .any(|row| row.zombie.key == child_key)
        );
        assert!(
            draining
                .tasks
                .iter()
                .any(|row| { row.key == child_key && row.class == ObjectSnapshotClass::Draining })
        );
        assert!(
            draining.threads.iter().any(|row| {
                row.key == child_thread && row.class == ObjectSnapshotClass::Draining
            })
        );
        assert!(
            draining
                .mms
                .iter()
                .any(|row| { row.id == child_mm && row.class == ObjectSnapshotClass::Draining })
        );
        assert!(
            draining.sighands.iter().any(|row| {
                row.id == child_sighand && row.class == ObjectSnapshotClass::Draining
            })
        );
        assert!(draining.task_shared.iter().any(|row| {
            row.key.task == child_key && row.class == ObjectSnapshotClass::Draining
        }));
        assert!(draining.thread_resources.iter().any(|row| {
            row.key.thread == child_thread && row.class == ObjectSnapshotClass::Draining
        }));

        drop(draining);
        drop(child);
        let bundles_only = kernel.snapshot(deadline()).expect("bundle-only snapshot");
        assert!(!bundles_only.tasks.iter().any(|row| row.key == child_key));
        assert!(
            !bundles_only
                .threads
                .iter()
                .any(|row| row.key == child_thread)
        );
        assert!(bundles_only.task_shared.iter().any(|row| {
            row.key.task == child_key && row.class == ObjectSnapshotClass::Draining
        }));
        let child_resources_key = bundles_only
            .thread_resources
            .iter()
            .find(|row| row.key.thread == child_thread)
            .expect("child resources row")
            .key;
        assert_eq!(
            bundles_only
                .thread_resources
                .iter()
                .find(|row| row.key == child_resources_key)
                .expect("child resources class")
                .class,
            ObjectSnapshotClass::Draining
        );
        assert!(
            bundles_only
                .file_tables
                .iter()
                .any(|row| row.id == child_resources_key.file_table)
        );
        assert!(bundles_only.fs_contexts.iter().any(|row| {
            row.id == child_resources_key.fs_context && row.class == ObjectSnapshotClass::Draining
        }));

        drop(bundles_only);
        drop(retained_shared);
        drop(retained_resources);
        let swept = kernel
            .snapshot(deadline())
            .expect("automatic swept snapshot");
        assert!(!swept.mms.iter().any(|row| row.id == child_mm));
        assert!(!swept.sighands.iter().any(|row| row.id == child_sighand));
        assert!(
            !swept
                .task_shared
                .iter()
                .any(|row| row.key.task == child_key)
        );
        assert!(
            !swept
                .thread_resources
                .iter()
                .any(|row| row.key.thread == child_thread)
        );
    }

    #[test]
    fn retired_threads_remain_explicitly_draining() {
        let (kernel, root) = bootstrap(TestBackend::new(BackendMode::Good));
        let sibling = kernel
            .clone_thread(
                &root,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("clone plan"),
                ThreadId::synthetic_for_tests(7001),
                None,
            )
            .expect("clone thread");
        kernel.exit_thread(&sibling, None).expect("retire thread");
        let snapshot = kernel.snapshot(deadline()).expect("snapshot");
        assert!(snapshot.threads.iter().any(|thread| {
            thread.key == sibling.thread().key() && thread.class == ThreadSnapshotClass::Draining
        }));
    }
}
