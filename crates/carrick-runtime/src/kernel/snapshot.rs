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
    FileDescription, FileTable, Sighand, SignalDisposition, TaskKey, TaskLifecycle, TaskRef,
    ThreadKey, ThreadRef, ThreadSignalState, Zombie,
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
        };
        let mut thread_rows = Vec::new();
        let mut thread_signals = Vec::new();
        let mut credentials = Vec::new();
        let mut file_table_by_id = BTreeMap::new();
        let mut fs_contexts = BTreeSet::new();

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
            fs_contexts.insert(fs.id());
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
        self.verify_registry(&registry, deadline)?;
        let mut snapshot = KernelSnapshotV1 {
            schema_version: KERNEL_SNAPSHOT_V1_SCHEMA,
            registry_epoch: registry.epoch,
            tasks,
            zombies: registry
                .zombies
                .into_iter()
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
            fs_contexts: fs_contexts
                .into_iter()
                .map(|id| FsContextSnapshotRow { id })
                .collect(),
            credentials,
            process_groups: registry.groups,
            sessions: registry.sessions,
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
        if lock_result(self.frame_inventory().revision_until(deadline), deadline)? != frame_revision
        {
            return Err(AttemptError::Race);
        }
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

fn has_duplicates<T: Eq>(values: &[T]) -> bool {
    values.windows(2).any(|window| window[0] == window[1])
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
    let live_tasks: BTreeSet<_> = snapshot.tasks.iter().map(|row| row.key).collect();
    let zombies: BTreeSet<_> = snapshot.zombies.iter().map(|row| row.zombie.key).collect();
    if live_tasks.len() != snapshot.tasks.len() || zombies.len() != snapshot.zombies.len() {
        return invariant("duplicate task or zombie key");
    }
    let mm_ids: BTreeSet<_> = snapshot.mms.iter().map(|row| row.id).collect();
    let sighand_ids: BTreeSet<_> = snapshot.sighands.iter().map(|row| row.id).collect();
    let group_ids: BTreeSet<_> = snapshot.process_groups.iter().map(|row| row.id).collect();
    let session_ids: BTreeSet<_> = snapshot.sessions.iter().map(|row| row.id).collect();
    for task in &snapshot.tasks {
        if !mm_ids.contains(&task.mm)
            || !sighand_ids.contains(&task.sighand)
            || !group_ids.contains(&task.process_group)
            || !session_ids.contains(&task.session)
        {
            return invariant("task leaf or identity join is missing");
        }
        if task
            .parent
            .is_some_and(|parent| !live_tasks.contains(&parent))
            || task
                .children
                .iter()
                .any(|child| !live_tasks.contains(child) && !zombies.contains(child))
        {
            return invariant("task parent/child join is missing");
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
        if !session_ids.contains(&group.session)
            || group
                .members
                .iter()
                .any(|member| !live_tasks.contains(member))
        {
            return invariant("process-group join is missing");
        }
    }
    for session in &snapshot.sessions {
        if session
            .process_groups
            .iter()
            .any(|group| !group_ids.contains(group))
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
    if snapshot
        .credentials
        .iter()
        .any(|row| !thread_keys.contains(&row.thread))
        || snapshot
            .thread_signals
            .iter()
            .any(|row| !thread_keys.contains(&row.thread))
    {
        return invariant("thread credential or signal join is missing");
    }

    let descriptions: BTreeSet<_> = snapshot
        .file_descriptions
        .iter()
        .map(|row| row.id)
        .collect();
    for slot in &snapshot.file_slots {
        if !file_tables.contains(&slot.table) || !descriptions.contains(&slot.description) {
            return invariant("file slot join is missing");
        }
    }
    for description in &snapshot.file_descriptions {
        if description
            .epoll_interests
            .iter()
            .any(|target| !descriptions.contains(target))
        {
            return invariant("epoll description join is missing");
        }
    }

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
        {
            return invariant("mapping frame/mm join is missing");
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
        RevisionRace,
    }

    #[derive(Debug)]
    struct TestBackend {
        binding: MmBinding,
        revision: AtomicU64,
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
                    mapping_ids: Vec::new(),
                }),
                BackendMode::BrokenMappingJoin => Ok(MmBackendSnapshot {
                    revision: self.revision(),
                    binding: self.binding,
                    vmas: Vec::new(),
                    mapping_ids: vec![MappingId::from_kernel_allocation(
                        NonZeroU64::new(99).expect("mapping"),
                    )],
                }),
                BackendMode::RevisionRace => {
                    let observed = self.revision.fetch_add(1, Ordering::Release);
                    Ok(MmBackendSnapshot {
                        revision: observed,
                        binding: self.binding,
                        vmas: Vec::new(),
                        mapping_ids: Vec::new(),
                    })
                }
                BackendMode::Good => Ok(MmBackendSnapshot {
                    revision: self.revision(),
                    binding: self.binding,
                    vmas: vec![VmaSummary {
                        start: GuestVa(0x1000),
                        end: GuestVa(0x2000),
                    }],
                    mapping_ids: Vec::new(),
                }),
            }
        }

        fn revision(&self) -> u64 {
            self.revision.load(Ordering::Acquire)
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
        let (kernel, _) = bootstrap(TestBackend::new(BackendMode::RevisionRace));
        assert_eq!(kernel.snapshot(deadline()), Err(KernelSnapshotError::Busy));
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
