//! Coherent, owned K1 kernel-object snapshots.
//!
//! This module projects only the typed kernel graph. It deliberately never
//! reads dispatcher `FsState`, `IoState`, or `SignalState` as fallback state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use carrick_abi::SigSet;
use carrick_hal::{FrameId, MappingId, ThreadId};

use super::address::{MmBackend, MmBinding, SnapshotError, SnapshotTable};
use super::core::{Kernel, TaskRevision};
use super::frame_inventory::{FrameRow, MappingRow};
use super::ids::{
    FileDescriptionId, FileSlotNumber, FileTableId, FsContextId, LinuxSignal, MmId, ProcessGroupId,
    SessionId, SighandId,
};
use super::objects::{
    FileDescription, FileTable, FsContext, Sighand, SignalDisposition, TaskKey, TaskLifecycle,
    TaskRef, ThreadKey, ThreadRef, ThreadSignalState, Zombie,
};

pub const KERNEL_SNAPSHOT_V1_SCHEMA: u16 = 1;
const MAX_ATTEMPTS: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelSnapshotV1 {
    pub schema_version: u16,
    pub registry_epoch: u64,
    pub tasks: Vec<TaskSnapshotRow>,
    pub zombies: Vec<ZombieSnapshotRow>,
    pub threads: Vec<ThreadSnapshotRow>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSnapshotRow {
    pub key: TaskKey,
    pub parent: Option<TaskKey>,
    pub children: Vec<TaskKey>,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
    pub lifecycle: TaskLifecycle,
    pub mm: MmId,
    pub sighand: SighandId,
    pub revision: TaskRevision,
    pub diagnostic_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZombieSnapshotRow {
    pub zombie: Zombie,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadSnapshotClass {
    Live,
    Draining,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadSnapshotRow {
    pub key: ThreadKey,
    pub task: TaskKey,
    pub registry_id: Option<ThreadId>,
    pub class: ThreadSnapshotClass,
    pub file_table: Option<FileTableId>,
    pub fs_context: Option<FsContextId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MmSnapshotRow {
    pub id: MmId,
    pub revision: u64,
    pub binding: MmBinding,
    pub mapping_ids: Vec<MappingId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmaSnapshotRow {
    pub mm: MmId,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileTableSnapshotRow {
    pub id: FileTableId,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSlotSnapshotRow {
    pub table: FileTableId,
    pub number: FileSlotNumber,
    pub description: FileDescriptionId,
    pub close_on_exec: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDescriptionSnapshotKind {
    Regular,
    Epoll,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDescriptionSnapshotRow {
    pub id: FileDescriptionId,
    pub revision: u64,
    pub kind: FileDescriptionSnapshotKind,
    pub epoll_interests: Vec<FileDescriptionId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FsContextSnapshotRow {
    pub id: FsContextId,
}

/// Credentials have no stable object ID in the K1 vocabulary and currently
/// contain no concrete values. The exact authoritative projection is therefore
/// one stable thread-keyed association row, not a pointer-derived identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialsSnapshotRow {
    pub thread: ThreadKey,
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
    pub revision: u64,
    pub dispositions: Vec<(LinuxSignal, SignalDisposition)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskSignalSnapshotRow {
    pub task: TaskKey,
    pub pending_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadSignalSnapshotRow {
    pub thread: ThreadKey,
    pub revision: u64,
    pub blocked: SigSet,
    pub pending: SigSet,
    pub altstack_enabled: bool,
    pub handler_frame_depth: usize,
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
    draining: Vec<(ThreadKey, TaskKey, Option<ThreadRef>)>,
}

struct LeafChecks {
    threads: Vec<(ThreadRef, u64)>,
    sighands: Vec<(Arc<Sighand>, u64)>,
    file_tables: Vec<(Arc<FileTable>, u64)>,
    descriptions: Vec<(Arc<FileDescription>, u64)>,
    backends: Vec<(Arc<dyn MmBackend>, u64)>,
    vma_revisions: Vec<(Arc<dyn MmBackend>, super::VmaRevision)>,
    frame_inventory_revisions: Vec<u64>,
}

impl Kernel {
    pub fn snapshot(&self, deadline: Instant) -> Result<KernelSnapshotV1, KernelSnapshotError> {
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
        let mut tasks = Vec::with_capacity(registry.tasks.len());
        let mut threads_by_key = BTreeMap::<ThreadKey, (ThreadRef, ThreadSnapshotClass)>::new();
        let mut mm_by_id = BTreeMap::new();
        let mut sighand_by_id = BTreeMap::new();

        for record in &registry.tasks {
            let task = &record.task;
            let parent = lock_result(task.parent_until(deadline), deadline)?;
            let children = lock_result(task.children_until(deadline), deadline)?;
            let (process_group, session) = lock_result(task.identity_until(deadline), deadline)?;
            let lifecycle = lock_result(task.lifecycle_until(deadline), deadline)?;
            let shared = task.shared();
            let mm = shared.mm();
            let sighand = shared.sighand();
            insert_shared(&mut mm_by_id, mm.id(), mm, "duplicate mm identity")?;
            insert_shared(
                &mut sighand_by_id,
                sighand.id(),
                sighand,
                "duplicate sighand identity",
            )?;
            for thread in lock_result(task.threads_until(deadline), deadline)? {
                if thread.task_key() != task.key()
                    || threads_by_key
                        .insert(thread.key(), (thread, ThreadSnapshotClass::Live))
                        .is_some()
                {
                    return invariant("duplicate or broken live thread identity");
                }
            }
            tasks.push(TaskSnapshotRow {
                key: task.key(),
                parent,
                children,
                process_group,
                session,
                lifecycle,
                mm: shared.mm().id(),
                sighand: shared.sighand().id(),
                revision: record.revision,
                diagnostic_name: record.diagnostic_name.clone(),
            });
        }

        for (key, task, thread) in &registry.draining {
            if threads_by_key.contains_key(key) {
                return invariant("thread is both live and draining");
            }
            if let Some(thread) = thread {
                if thread.key() != *key || thread.task_key() != *task {
                    return invariant("draining thread identity changed");
                }
                threads_by_key.insert(*key, (Arc::clone(thread), ThreadSnapshotClass::Draining));
            }
        }

        let mut checks = LeafChecks {
            threads: Vec::new(),
            sighands: Vec::new(),
            file_tables: Vec::new(),
            descriptions: Vec::new(),
            backends: Vec::new(),
            vma_revisions: Vec::new(),
            frame_inventory_revisions: Vec::new(),
        };
        let mut thread_rows = Vec::new();
        let mut thread_signals = Vec::new();
        let mut credentials = Vec::new();
        let mut file_table_by_id = BTreeMap::new();
        let mut fs_context_by_id = BTreeMap::<FsContextId, Arc<FsContext>>::new();

        for (key, (thread, class)) in threads_by_key {
            let resources = thread.resources();
            let files = resources.files();
            let fs = resources.fs_context();
            insert_shared(
                &mut file_table_by_id,
                files.id(),
                Arc::clone(&files),
                "duplicate file-table identity",
            )?;
            insert_shared(
                &mut fs_context_by_id,
                fs.id(),
                Arc::clone(&fs),
                "duplicate fs-context identity",
            )?;
            let (revision, signal) = lock_result(thread.snapshot_signal_until(deadline), deadline)?;
            checks.threads.push((Arc::clone(&thread), revision));
            thread_signals.push(thread_signal_row(key, revision, signal));
            credentials.push(CredentialsSnapshotRow { thread: key });
            thread_rows.push(ThreadSnapshotRow {
                key,
                task: thread.task_key(),
                registry_id: Some(thread.registry_id()),
                class,
                file_table: Some(files.id()),
                fs_context: Some(fs.id()),
            });
        }
        // A weak draining record may expire after the registry copy. Its stable
        // identity remains an explicit draining row without pretending leaf
        // state is still available.
        for (key, task, thread) in &registry.draining {
            if thread.is_none() {
                thread_rows.push(ThreadSnapshotRow {
                    key: *key,
                    task: *task,
                    registry_id: None,
                    class: ThreadSnapshotClass::Draining,
                    file_table: None,
                    fs_context: None,
                });
            }
        }

        let mut sighands = Vec::new();
        for (_, sighand) in sighand_by_id {
            let (revision, dispositions) = lock_result(sighand.snapshot_until(deadline), deadline)?;
            checks.sighands.push((Arc::clone(&sighand), revision));
            sighands.push(SighandSnapshotRow {
                id: sighand.id(),
                revision,
                dispositions,
            });
        }

        let mut file_tables = Vec::new();
        let mut file_slots = Vec::new();
        let mut description_by_id = BTreeMap::new();
        for (_, table) in file_table_by_id {
            let (revision, slots) = lock_result(table.snapshot_until(deadline), deadline)?;
            checks.file_tables.push((Arc::clone(&table), revision));
            file_tables.push(FileTableSnapshotRow {
                id: table.id(),
                revision,
            });
            for (number, slot) in slots {
                let description = slot.description();
                insert_shared(
                    &mut description_by_id,
                    description.id(),
                    Arc::clone(&description),
                    "duplicate file-description identity",
                )?;
                file_slots.push(FileSlotSnapshotRow {
                    table: table.id(),
                    number,
                    description: description.id(),
                    close_on_exec: slot.close_on_exec(),
                });
            }
        }
        let mut file_descriptions = Vec::new();
        for (_, description) in description_by_id {
            let (revision, epoll, interests) =
                lock_result(description.snapshot_until(deadline), deadline)?;
            checks
                .descriptions
                .push((Arc::clone(&description), revision));
            file_descriptions.push(FileDescriptionSnapshotRow {
                id: description.id(),
                revision,
                kind: if epoll {
                    FileDescriptionSnapshotKind::Epoll
                } else {
                    FileDescriptionSnapshotKind::Regular
                },
                epoll_interests: interests,
            });
        }

        let mut mms = Vec::new();
        let mut vmas = Vec::new();
        for (_, mm) in mm_by_id {
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
                    mm: mm.id(),
                    start: vma.start.raw(),
                    end: vma.end.raw(),
                });
            }
            checks
                .backends
                .push((Arc::clone(&backend), observed.revision));
            mms.push(MmSnapshotRow {
                id: mm.id(),
                revision: observed.revision,
                binding: observed.binding,
                mapping_ids,
            });
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
            mms,
            vmas,
            frames: frame_inventory.frames,
            mappings: frame_inventory.mappings,
            file_tables,
            file_slots,
            file_descriptions,
            fs_contexts: fs_context_by_id
                .into_keys()
                .map(|id| FsContextSnapshotRow { id })
                .collect(),
            credentials,
            process_groups: registry.groups.clone(),
            sessions: registry.sessions.clone(),
            sighands,
            task_signals: registry
                .tasks
                .iter()
                .map(|record| TaskSignalSnapshotRow {
                    task: record.task.key(),
                    pending_count: record.task.shared().pending_signals().pending_count(),
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
        for (table, revision) in checks.file_tables {
            if table.revision() != revision {
                return Err(AttemptError::Race);
            }
        }
        for (description, revision) in checks.descriptions {
            if description.revision() != revision {
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
        let mut draining: Vec<_> = state
            .retired_threads
            .iter()
            .map(|retired| (retired.key, retired.task, retired.thread.upgrade()))
            .collect();
        draining.extend(state.tasks.values().filter_map(|record| {
            record
                .dead_leader
                .as_ref()
                .map(|retired| (retired.key, retired.task, retired.thread.upgrade()))
        }));
        draining.sort_by_key(|(key, _, _)| *key);
        if draining.windows(2).any(|rows| rows[0].0 == rows[1].0) {
            return invariant("duplicate draining thread identity");
        }
        Ok(RegistryCopy {
            epoch: state.epoch,
            tasks,
            zombies,
            groups,
            sessions,
            draining,
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

fn has_duplicates<T: Copy + Ord>(values: &[T]) -> bool {
    values.iter().copied().collect::<BTreeSet<_>>().len() != values.len()
}

fn thread_signal_row(
    thread: ThreadKey,
    revision: u64,
    state: ThreadSignalState,
) -> ThreadSignalSnapshotRow {
    ThreadSignalSnapshotRow {
        thread,
        revision,
        blocked: state.blocked(),
        pending: state.pending(),
        altstack_enabled: state.altstack_enabled(),
        handler_frame_depth: state.handler_frame_depth(),
    }
}

fn sort_snapshot(snapshot: &mut KernelSnapshotV1) {
    snapshot.tasks.sort_by_key(|row| row.key);
    snapshot.zombies.sort_by_key(|row| row.zombie.key);
    snapshot.threads.sort_by_key(|row| row.key);
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
    snapshot.credentials.sort_by_key(|row| row.thread);
    snapshot.process_groups.sort_by_key(|row| row.id);
    snapshot.sessions.sort_by_key(|row| row.id);
    snapshot.sighands.sort_by_key(|row| row.id);
    snapshot.task_signals.sort_by_key(|row| row.task);
    snapshot.thread_signals.sort_by_key(|row| row.thread);
}

fn validate_snapshot(snapshot: &KernelSnapshotV1) -> Result<(), AttemptError> {
    let task_by_key: BTreeMap<_, _> = snapshot.tasks.iter().map(|row| (row.key, row)).collect();
    let live_tasks: BTreeSet<_> = task_by_key.keys().copied().collect();
    let zombies: BTreeSet<_> = snapshot.zombies.iter().map(|row| row.zombie.key).collect();
    if live_tasks.len() != snapshot.tasks.len()
        || zombies.len() != snapshot.zombies.len()
        || !live_tasks.is_disjoint(&zombies)
    {
        return invariant("duplicate or overlapping task/zombie key");
    }
    let mm_ids: BTreeSet<_> = snapshot.mms.iter().map(|row| row.id).collect();
    let sighand_ids: BTreeSet<_> = snapshot.sighands.iter().map(|row| row.id).collect();
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
        || group_ids.len() != snapshot.process_groups.len()
        || session_ids.len() != snapshot.sessions.len()
    {
        return invariant("duplicate mm/sighand/group/session identity");
    }
    for task in &snapshot.tasks {
        if has_duplicates(&task.children) {
            return invariant("task contains duplicate child keys");
        }
        if !mm_ids.contains(&task.mm)
            || !sighand_ids.contains(&task.sighand)
            || !group_ids.contains(&task.process_group)
            || !session_ids.contains(&task.session)
        {
            return invariant("task leaf or identity join is missing");
        }
        if task.parent.is_some_and(|parent| {
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
        }) {
            return invariant("task parent/child backlink is missing");
        }
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
                    task.process_group != group.id || task.session != group.session
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

    let thread_keys: BTreeSet<_> = snapshot.threads.iter().map(|row| row.key).collect();
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
    for thread in &snapshot.threads {
        if !live_tasks.contains(&thread.task) && !zombies.contains(&thread.task) {
            return invariant("thread task join is missing");
        }
        if thread.class == ThreadSnapshotClass::Live
            && (thread.file_table.is_none() || thread.fs_context.is_none())
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
    let credential_threads: BTreeSet<_> =
        snapshot.credentials.iter().map(|row| row.thread).collect();
    let signal_threads: BTreeSet<_> = snapshot
        .thread_signals
        .iter()
        .map(|row| row.thread)
        .collect();
    let task_signal_tasks: BTreeSet<_> = snapshot.task_signals.iter().map(|row| row.task).collect();
    if credential_threads.len() != snapshot.credentials.len()
        || signal_threads.len() != snapshot.thread_signals.len()
        || task_signal_tasks.len() != snapshot.task_signals.len()
        || credential_threads != leaf_threads
        || signal_threads != leaf_threads
        || task_signal_tasks != live_tasks
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
    for description in &snapshot.file_descriptions {
        if has_duplicates(&description.epoll_interests)
            || description
                .epoll_interests
                .iter()
                .any(|target| !descriptions.contains(target))
        {
            return invariant("epoll description join is missing");
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
        Asid, ClonePlan, KernelContext, MmBackendSnapshot, RootBootstrap, SnapshotError,
        Stage1Root, VmaSummary,
    };

    #[derive(Clone, Copy, Debug)]
    enum BackendMode {
        Good,
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
                BackendMode::Good => Ok(MmBackendSnapshot {
                    revision: self.revision(),
                    binding: self.binding,
                    vmas: vec![VmaSummary {
                        start: GuestVa(0x1000),
                        end: GuestVa(0x2000),
                    }],
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
        let (kernel, _) = bootstrap(TestBackend::new(BackendMode::Good));
        let first = kernel.snapshot(deadline()).expect("snapshot");
        let second = kernel.snapshot(deadline()).expect("snapshot");
        assert_eq!(first, second);
        assert_eq!(first.schema_version, KERNEL_SNAPSHOT_V1_SCHEMA);
        assert_eq!(
            (first.tasks.len(), first.threads.len(), first.mms.len()),
            (1, 1, 1)
        );
        assert_eq!(first.vmas.len(), 1);
        assert_eq!(first.credentials[0].thread, first.threads[0].key);
        assert!(first.frames.is_empty() && first.mappings.is_empty());
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
            .push(duplicate_credentials.credentials[0]);
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
