//! Versioned, pointer-free wire projection of [`KernelSnapshotV1`].
//!
//! This is the shared DTO: the runtime server encodes it and the `carrick
//! debug hvpatch-kernel` client decodes it. It is deliberately a *projection*
//! and not a serde derive on the kernel objects themselves — the wire contract
//! must stay stable while the internal graph is refactored by K2..K5, and it
//! must be provably free of host pointers.
//!
//! Every table is optional so a `--table` request can ask for a subset. A
//! table the caller asked for and did not receive is a protocol error, not an
//! empty result: [`KernelDebugSnapshot::validate`] fails closed on unknown
//! schema, a missing requested table, a duplicate ID, a broken join, and a
//! partial frame. Trailing bytes are rejected one layer up, in `wire`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::super::objects::FileDescriptionBackingSnapshot;
use super::super::snapshot::{FileDescriptionSnapshotKind, KernelSnapshotV1, ObjectSnapshotClass};

/// Request schema tag. A client that sends anything else is refused.
pub const KERNEL_DEBUG_REQUEST_SCHEMA: &str = "carrick.kernel-debug-request.v1";
/// Response schema tag. A client that receives anything else fails closed.
pub const KERNEL_DEBUG_RESPONSE_SCHEMA: &str = "carrick.kernel-debug-snapshot.v1";

/// One selectable table. The names are the CLI's `--table` vocabulary and are
/// part of the wire contract; renaming one is a schema change.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KernelDebugTable {
    Task,
    Zombie,
    Thread,
    TaskShared,
    ThreadResources,
    Mm,
    Vma,
    Frame,
    Mapping,
    FileTable,
    FileSlot,
    FileDescription,
    FsContext,
    Credentials,
    ProcessGroup,
    Session,
    Sighand,
    TaskSignal,
    ThreadSignal,
}

impl KernelDebugTable {
    /// Every table, in wire order. Used for an unfiltered request and to
    /// validate that a filtered response carries exactly what was asked for.
    pub const ALL: [Self; 19] = [
        Self::Task,
        Self::Zombie,
        Self::Thread,
        Self::TaskShared,
        Self::ThreadResources,
        Self::Mm,
        Self::Vma,
        Self::Frame,
        Self::Mapping,
        Self::FileTable,
        Self::FileSlot,
        Self::FileDescription,
        Self::FsContext,
        Self::Credentials,
        Self::ProcessGroup,
        Self::Session,
        Self::Sighand,
        Self::TaskSignal,
        Self::ThreadSignal,
    ];

    /// Parse a CLI `--table` value. Unknown names are rejected by name rather
    /// than silently ignored, so a typo can never look like an empty table.
    pub fn parse(value: &str) -> Result<Self, UnknownTable> {
        Self::ALL
            .into_iter()
            .find(|table| table.wire_name() == value)
            .ok_or_else(|| UnknownTable(value.to_owned()))
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Zombie => "zombie",
            Self::Thread => "thread",
            Self::TaskShared => "task-shared",
            Self::ThreadResources => "thread-resources",
            Self::Mm => "mm",
            Self::Vma => "vma",
            Self::Frame => "frame",
            Self::Mapping => "mapping",
            Self::FileTable => "file-table",
            Self::FileSlot => "file-slot",
            Self::FileDescription => "file-description",
            Self::FsContext => "fs-context",
            Self::Credentials => "credentials",
            Self::ProcessGroup => "process-group",
            Self::Session => "session",
            Self::Sighand => "sighand",
            Self::TaskSignal => "task-signal",
            Self::ThreadSignal => "thread-signal",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unknown kernel debug table `{0}`")]
pub struct UnknownTable(pub String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelDebugRequest {
    pub schema: String,
    /// Requested tables. `None` means every table.
    pub tables: Option<Vec<KernelDebugTable>>,
}

impl KernelDebugRequest {
    pub fn for_tables(tables: Option<Vec<KernelDebugTable>>) -> Self {
        Self {
            schema: KERNEL_DEBUG_REQUEST_SCHEMA.to_owned(),
            tables,
        }
    }

    /// Exact set of tables this request selects.
    pub fn selected(&self) -> BTreeSet<KernelDebugTable> {
        match &self.tables {
            Some(tables) => tables.iter().copied().collect(),
            None => KernelDebugTable::ALL.into_iter().collect(),
        }
    }

    pub fn check_schema(&self) -> Result<(), KernelDebugDtoError> {
        if self.schema != KERNEL_DEBUG_REQUEST_SCHEMA {
            return Err(KernelDebugDtoError::UnknownSchema(self.schema.clone()));
        }
        Ok(())
    }
}

/// Object liveness class, mirrored so a reader can tell a live object from one
/// that is still draining references.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DebugClass {
    Live,
    Draining,
}

impl From<ObjectSnapshotClass> for DebugClass {
    fn from(value: ObjectSnapshotClass) -> Self {
        match value {
            ObjectSnapshotClass::Live => Self::Live,
            ObjectSnapshotClass::Draining => Self::Draining,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTaskKey {
    pub id: i32,
    pub serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugThreadKey {
    pub tid: i32,
    pub serial: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTaskRow {
    pub key: DebugTaskKey,
    pub class: DebugClass,
    pub parent: Option<DebugTaskKey>,
    pub children: Vec<DebugTaskKey>,
    pub process_group: i32,
    pub session: i32,
    pub lifecycle: String,
    pub mm: u64,
    pub sighand: u64,
    pub revision: Option<u64>,
    pub diagnostic_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugZombieRow {
    pub key: DebugTaskKey,
    pub parent: Option<DebugTaskKey>,
    pub process_group: i32,
    pub session: i32,
    pub wait_status: i32,
    pub user_time_ns: u128,
    pub system_time_ns: u128,
    pub diagnostic_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugThreadRow {
    pub key: DebugThreadKey,
    pub task: DebugTaskKey,
    pub registry_id: Option<i32>,
    pub class: DebugClass,
    pub file_table: Option<u64>,
    pub fs_context: Option<u64>,
    pub credentials: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTaskSharedRow {
    pub task: DebugTaskKey,
    pub publication: u64,
    pub mm: u64,
    pub sighand: u64,
    pub class: DebugClass,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugThreadResourcesRow {
    pub thread: DebugThreadKey,
    pub publication: u64,
    pub file_table: u64,
    pub fs_context: u64,
    pub credentials: u64,
    pub class: DebugClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugMmRow {
    pub id: u64,
    pub class: DebugClass,
    pub revision: u64,
    pub asid: u16,
    pub stage1_root_gpa: u64,
    pub ttbr0: u64,
    pub mapping_ids: Vec<u64>,
    pub legacy_aio_context_count: u64,
    pub next_legacy_aio_context: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugVmaRow {
    pub mm: u64,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugFrameRow {
    pub frame: u64,
    pub length: u64,
    pub mappings: Vec<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugMappingRow {
    pub mapping: u64,
    pub frame: u64,
    pub mm: u64,
    pub generation: u64,
    /// Guest-physical address. This is an IPA inside the Carrick-managed frame
    /// space, never a host virtual address.
    pub gpa: u64,
    pub length: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugFileTableRow {
    pub id: u64,
    pub class: DebugClass,
    pub revision: u64,
    pub functional_refs_active: bool,
    pub next_fd: i32,
    pub stdio_cloexec: [bool; 3],
    pub closed_stdio: [bool; 3],
    pub splice_pushback_description_ids: Vec<u64>,
    pub epoll_index_fds: Vec<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugFileSlotRow {
    pub table: u64,
    pub number: i32,
    pub description: u64,
    pub close_on_exec: bool,
    pub open_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugFileDescriptionRow {
    pub id: u64,
    pub class: DebugClass,
    pub revision: u64,
    /// `regular` or `epoll` — the snapshot's coarse kind.
    pub kind: String,
    /// Fine-grained backing kind when the description still has a backing.
    pub backing_kind: Option<String>,
    pub status_flags: Option<u64>,
    pub offset: Option<u64>,
    pub host_fd: Option<i32>,
    pub path: Option<String>,
    pub pipe_id: Option<u64>,
    pub logical_fd_refs: Option<u64>,
    pub epoll_interests: Vec<u64>,
    pub epoll_owners: Vec<DebugEpollOwner>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugEpollOwner {
    pub owner: u64,
    pub fd: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugFsContextRow {
    pub id: u64,
    pub class: DebugClass,
    pub revision: u64,
    pub cwd: String,
    pub chroot_root: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugCredentialsRow {
    pub id: u64,
    pub class: DebugClass,
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub umask: u32,
    pub supplementary_groups_override: Option<Vec<u32>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugProcessGroupRow {
    pub id: i32,
    pub session: i32,
    pub members: Vec<DebugTaskKey>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSessionRow {
    pub id: i32,
    pub process_groups: Vec<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSighandRow {
    pub id: u64,
    pub class: DebugClass,
    pub revision: u64,
    pub actions: Vec<DebugSigaction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSigaction {
    pub signal: i32,
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugTaskSignalRow {
    pub task: DebugTaskKey,
    pub class: DebugClass,
    pub revision: u64,
    pub pending: Vec<DebugPendingSignal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugPendingSignal {
    pub signal: i32,
    pub has_siginfo: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugThreadSignalRow {
    pub thread: DebugThreadKey,
    pub class: DebugClass,
    pub revision: u64,
    pub blocked: u64,
    pub pending: Vec<DebugPendingSignal>,
    pub altstack: Option<DebugAltstack>,
    pub handler_frame_depth: u64,
    pub armed_restore_mask: Option<u64>,
    pub routed_siginfo_signals: Vec<i32>,
    pub pending_action_signals: Vec<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugAltstack {
    pub sp: u64,
    pub flags: i32,
    pub size: u64,
}

/// The response. Every table is `Option` so a filtered request produces a
/// response whose absent tables are explicit rather than empty.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelDebugSnapshot {
    pub schema: String,
    pub snapshot_schema_version: u16,
    pub registry_epoch: u64,
    pub tasks: Option<Vec<DebugTaskRow>>,
    pub zombies: Option<Vec<DebugZombieRow>>,
    pub threads: Option<Vec<DebugThreadRow>>,
    pub task_shared: Option<Vec<DebugTaskSharedRow>>,
    pub thread_resources: Option<Vec<DebugThreadResourcesRow>>,
    pub mms: Option<Vec<DebugMmRow>>,
    pub vmas: Option<Vec<DebugVmaRow>>,
    pub frames: Option<Vec<DebugFrameRow>>,
    pub mappings: Option<Vec<DebugMappingRow>>,
    pub file_tables: Option<Vec<DebugFileTableRow>>,
    pub file_slots: Option<Vec<DebugFileSlotRow>>,
    pub file_descriptions: Option<Vec<DebugFileDescriptionRow>>,
    pub fs_contexts: Option<Vec<DebugFsContextRow>>,
    pub credentials: Option<Vec<DebugCredentialsRow>>,
    pub process_groups: Option<Vec<DebugProcessGroupRow>>,
    pub sessions: Option<Vec<DebugSessionRow>>,
    pub sighands: Option<Vec<DebugSighandRow>>,
    pub task_signals: Option<Vec<DebugTaskSignalRow>>,
    pub thread_signals: Option<Vec<DebugThreadSignalRow>>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KernelDebugDtoError {
    #[error("unknown kernel debug schema `{0}`")]
    UnknownSchema(String),
    #[error("unknown kernel snapshot schema version {0}")]
    UnknownSnapshotVersion(u16),
    #[error("response is missing requested table `{0}`")]
    MissingTable(&'static str),
    #[error("response carries table `{0}` that was not requested")]
    UnrequestedTable(&'static str),
    #[error("table `{table}` repeats id `{id}`")]
    DuplicateId { table: &'static str, id: String },
    #[error("table `{table}` is not sorted by id at `{id}`")]
    Unsorted { table: &'static str, id: String },
    #[error("`{from}` references `{to}` id `{id}` that no row defines")]
    BrokenJoin {
        from: &'static str,
        to: &'static str,
        id: String,
    },
    #[error("frame `{frame}` is partial: it lists mapping `{mapping}` that no mapping row defines")]
    PartialFrame { frame: u64, mapping: u64 },
    #[error("mapping `{mapping}` claims frame `{frame}` which does not list it back")]
    PartialFrameBackReference { mapping: u64, frame: u64 },
}

impl KernelDebugSnapshot {
    /// Project a coherent kernel snapshot onto the wire, keeping only the
    /// requested tables.
    pub fn project(snapshot: &KernelSnapshotV1, selected: &BTreeSet<KernelDebugTable>) -> Self {
        let want = |table: KernelDebugTable| selected.contains(&table);
        Self {
            schema: KERNEL_DEBUG_RESPONSE_SCHEMA.to_owned(),
            snapshot_schema_version: snapshot.schema_version,
            registry_epoch: snapshot.registry_epoch,
            tasks: want(KernelDebugTable::Task).then(|| {
                snapshot
                    .tasks
                    .iter()
                    .map(|row| DebugTaskRow {
                        key: task_key(row.key),
                        class: row.class.into(),
                        parent: row.parent.map(task_key),
                        children: row.children.iter().copied().map(task_key).collect(),
                        process_group: row.process_group.raw(),
                        session: row.session.raw(),
                        lifecycle: match row.lifecycle {
                            super::super::objects::TaskLifecycle::Live => "live".to_owned(),
                            super::super::objects::TaskLifecycle::Exiting => "exiting".to_owned(),
                        },
                        mm: row.mm.raw(),
                        sighand: row.sighand.raw(),
                        revision: row.revision.map(|revision| revision.raw()),
                        diagnostic_name: row.diagnostic_name.clone(),
                    })
                    .collect()
            }),
            zombies: want(KernelDebugTable::Zombie).then(|| {
                snapshot
                    .zombies
                    .iter()
                    .map(|row| DebugZombieRow {
                        key: task_key(row.zombie.key),
                        parent: row.zombie.parent.map(task_key),
                        process_group: row.zombie.process_group.raw(),
                        session: row.zombie.session.raw(),
                        wait_status: row.zombie.status.raw(),
                        user_time_ns: row.zombie.rusage.user_time.as_nanos(),
                        system_time_ns: row.zombie.rusage.system_time.as_nanos(),
                        diagnostic_name: row.zombie.diagnostic_name.clone(),
                    })
                    .collect()
            }),
            threads: want(KernelDebugTable::Thread).then(|| {
                snapshot
                    .threads
                    .iter()
                    .map(|row| DebugThreadRow {
                        key: thread_key(row.key),
                        task: task_key(row.task),
                        registry_id: row.registry_id.map(|id| id.raw()),
                        class: row.class.into(),
                        file_table: row.file_table.map(|id| id.raw()),
                        fs_context: row.fs_context.map(|id| id.raw()),
                        credentials: row.credentials.map(|id| id.raw()),
                    })
                    .collect()
            }),
            task_shared: want(KernelDebugTable::TaskShared).then(|| {
                snapshot
                    .task_shared
                    .iter()
                    .map(|row| DebugTaskSharedRow {
                        task: task_key(row.key.task),
                        publication: row.key.publication.raw(),
                        mm: row.key.mm.raw(),
                        sighand: row.key.sighand.raw(),
                        class: row.class.into(),
                    })
                    .collect()
            }),
            thread_resources: want(KernelDebugTable::ThreadResources).then(|| {
                snapshot
                    .thread_resources
                    .iter()
                    .map(|row| DebugThreadResourcesRow {
                        thread: thread_key(row.key.thread),
                        publication: row.key.publication.raw(),
                        file_table: row.key.file_table.raw(),
                        fs_context: row.key.fs_context.raw(),
                        credentials: row.key.credentials.raw(),
                        class: row.class.into(),
                    })
                    .collect()
            }),
            mms: want(KernelDebugTable::Mm).then(|| {
                snapshot
                    .mms
                    .iter()
                    .map(|row| DebugMmRow {
                        id: row.id.raw(),
                        class: row.class.into(),
                        revision: row.revision,
                        asid: row.binding.asid.raw(),
                        stage1_root_gpa: row.binding.stage1_root.gpa().0,
                        ttbr0: row.binding.ttbr0.raw(),
                        mapping_ids: row.mapping_ids.iter().map(|id| id.raw()).collect(),
                        legacy_aio_context_count: row.legacy_aio_context_count as u64,
                        next_legacy_aio_context: row.next_legacy_aio_context,
                    })
                    .collect()
            }),
            vmas: want(KernelDebugTable::Vma).then(|| {
                snapshot
                    .vmas
                    .iter()
                    .map(|row| DebugVmaRow {
                        mm: row.mm.raw(),
                        start: row.start,
                        end: row.end,
                    })
                    .collect()
            }),
            frames: want(KernelDebugTable::Frame).then(|| {
                snapshot
                    .frames
                    .iter()
                    .map(|row| DebugFrameRow {
                        frame: row.frame.raw(),
                        length: row.length.raw(),
                        mappings: row.mappings.iter().map(|id| id.raw()).collect(),
                    })
                    .collect()
            }),
            mappings: want(KernelDebugTable::Mapping).then(|| {
                snapshot
                    .mappings
                    .iter()
                    .map(|row| DebugMappingRow {
                        mapping: row.mapping.raw(),
                        frame: row.frame.raw(),
                        mm: row.mm.raw(),
                        generation: row.generation.raw(),
                        gpa: row.gpa.0,
                        length: row.length.raw(),
                        read: row.permissions.read,
                        write: row.permissions.write,
                        exec: row.permissions.exec,
                    })
                    .collect()
            }),
            file_tables: want(KernelDebugTable::FileTable).then(|| {
                snapshot
                    .file_tables
                    .iter()
                    .map(|row| DebugFileTableRow {
                        id: row.id.raw(),
                        class: row.class.into(),
                        revision: row.revision,
                        functional_refs_active: row.functional_refs_active,
                        next_fd: row.next_fd,
                        stdio_cloexec: row.stdio_cloexec,
                        closed_stdio: row.closed_stdio,
                        splice_pushback_description_ids: row
                            .splice_pushback_description_ids
                            .iter()
                            .map(|id| id.raw())
                            .collect(),
                        epoll_index_fds: row.epoll_index_fds.iter().map(|fd| fd.raw()).collect(),
                    })
                    .collect()
            }),
            file_slots: want(KernelDebugTable::FileSlot).then(|| {
                snapshot
                    .file_slots
                    .iter()
                    .map(|row| DebugFileSlotRow {
                        table: row.table.raw(),
                        number: row.number.raw(),
                        description: row.description.raw(),
                        close_on_exec: row.close_on_exec,
                        open_path: row.open_path.clone(),
                    })
                    .collect()
            }),
            file_descriptions: want(KernelDebugTable::FileDescription).then(|| {
                snapshot
                    .file_descriptions
                    .iter()
                    .map(|row| {
                        let open = row.backing.as_ref().and_then(|backing| match backing {
                            FileDescriptionBackingSnapshot::Open(open) => Some(open),
                            FileDescriptionBackingSnapshot::IoUring(_) => None,
                        });
                        DebugFileDescriptionRow {
                            id: row.id.raw(),
                            class: row.class.into(),
                            revision: row.revision,
                            kind: match row.kind {
                                FileDescriptionSnapshotKind::Regular => "regular".to_owned(),
                                FileDescriptionSnapshotKind::Epoll => "epoll".to_owned(),
                            },
                            backing_kind: row
                                .backing
                                .as_ref()
                                .map(|backing| backing_kind_name(backing).to_owned()),
                            status_flags: open.and_then(|open| open.status_flags),
                            offset: open.and_then(|open| open.offset),
                            host_fd: open.and_then(|open| open.host_fd),
                            path: open.and_then(|open| open.path.clone()),
                            pipe_id: open.and_then(|open| open.pipe_id),
                            logical_fd_refs: row
                                .backing
                                .as_ref()
                                .map(|backing| backing.logical_fd_refs() as u64),
                            epoll_interests: row
                                .epoll_interests
                                .iter()
                                .map(|id| id.raw())
                                .collect(),
                            epoll_owners: row
                                .epoll_owners
                                .iter()
                                .map(|(owner, fd)| DebugEpollOwner {
                                    owner: owner.raw(),
                                    fd: *fd,
                                })
                                .collect(),
                        }
                    })
                    .collect()
            }),
            fs_contexts: want(KernelDebugTable::FsContext).then(|| {
                snapshot
                    .fs_contexts
                    .iter()
                    .map(|row| DebugFsContextRow {
                        id: row.id.raw(),
                        class: row.class.into(),
                        revision: row.revision,
                        cwd: row.cwd.clone(),
                        chroot_root: row.chroot_root.clone(),
                    })
                    .collect()
            }),
            credentials: want(KernelDebugTable::Credentials).then(|| {
                snapshot
                    .credentials
                    .iter()
                    .map(|row| DebugCredentialsRow {
                        id: row.id.raw(),
                        class: row.class.into(),
                        ruid: row.ruid.raw(),
                        euid: row.euid.raw(),
                        suid: row.suid.raw(),
                        rgid: row.rgid.raw(),
                        egid: row.egid.raw(),
                        sgid: row.sgid.raw(),
                        fsuid: row.fsuid.raw(),
                        fsgid: row.fsgid.raw(),
                        umask: row.umask,
                        supplementary_groups_override: row
                            .supplementary_groups_override
                            .as_ref()
                            .map(|g| g.iter().map(|id| id.raw()).collect()),
                    })
                    .collect()
            }),
            process_groups: want(KernelDebugTable::ProcessGroup).then(|| {
                snapshot
                    .process_groups
                    .iter()
                    .map(|row| DebugProcessGroupRow {
                        id: row.id.raw(),
                        session: row.session.raw(),
                        members: row.members.iter().copied().map(task_key).collect(),
                    })
                    .collect()
            }),
            sessions: want(KernelDebugTable::Session).then(|| {
                snapshot
                    .sessions
                    .iter()
                    .map(|row| DebugSessionRow {
                        id: row.id.raw(),
                        process_groups: row.process_groups.iter().map(|id| id.raw()).collect(),
                    })
                    .collect()
            }),
            sighands: want(KernelDebugTable::Sighand).then(|| {
                snapshot
                    .sighands
                    .iter()
                    .map(|row| DebugSighandRow {
                        id: row.id.raw(),
                        class: row.class.into(),
                        revision: row.revision,
                        actions: row
                            .actions
                            .iter()
                            .map(|(signal, action)| DebugSigaction {
                                signal: signal.raw(),
                                handler: action.sa_handler,
                                flags: action.sa_flags,
                                restorer: action.sa_restorer,
                                mask: action.sa_mask[0],
                            })
                            .collect(),
                    })
                    .collect()
            }),
            task_signals: want(KernelDebugTable::TaskSignal).then(|| {
                snapshot
                    .task_signals
                    .iter()
                    .map(|row| DebugTaskSignalRow {
                        task: task_key(row.task),
                        class: row.class.into(),
                        revision: row.revision,
                        pending: row.pending.iter().map(pending_signal).collect(),
                    })
                    .collect()
            }),
            thread_signals: want(KernelDebugTable::ThreadSignal).then(|| {
                snapshot
                    .thread_signals
                    .iter()
                    .map(|row| DebugThreadSignalRow {
                        thread: thread_key(row.thread),
                        class: row.class.into(),
                        revision: row.revision,
                        blocked: row.blocked.raw(),
                        pending: row.pending.iter().map(pending_signal).collect(),
                        altstack: row.altstack.map(|altstack| DebugAltstack {
                            sp: altstack.ss_sp,
                            flags: altstack.ss_flags,
                            size: altstack.ss_size,
                        }),
                        handler_frame_depth: row.handler_frames.len() as u64,
                        armed_restore_mask: row.armed_restore_mask.map(|mask| mask.raw()),
                        routed_siginfo_signals: row
                            .routed_siginfos
                            .iter()
                            .map(|(signal, _)| signal.raw())
                            .collect(),
                        pending_action_signals: row
                            .pending_actions
                            .iter()
                            .map(|(signal, _)| signal.raw())
                            .collect(),
                    })
                    .collect()
            }),
        }
    }

    /// Which tables this response actually carries.
    pub fn present(&self) -> BTreeSet<KernelDebugTable> {
        let mut present = BTreeSet::new();
        let mut note = |table: KernelDebugTable, carried: bool| {
            if carried {
                present.insert(table);
            }
        };
        note(KernelDebugTable::Task, self.tasks.is_some());
        note(KernelDebugTable::Zombie, self.zombies.is_some());
        note(KernelDebugTable::Thread, self.threads.is_some());
        note(KernelDebugTable::TaskShared, self.task_shared.is_some());
        note(
            KernelDebugTable::ThreadResources,
            self.thread_resources.is_some(),
        );
        note(KernelDebugTable::Mm, self.mms.is_some());
        note(KernelDebugTable::Vma, self.vmas.is_some());
        note(KernelDebugTable::Frame, self.frames.is_some());
        note(KernelDebugTable::Mapping, self.mappings.is_some());
        note(KernelDebugTable::FileTable, self.file_tables.is_some());
        note(KernelDebugTable::FileSlot, self.file_slots.is_some());
        note(
            KernelDebugTable::FileDescription,
            self.file_descriptions.is_some(),
        );
        note(KernelDebugTable::FsContext, self.fs_contexts.is_some());
        note(KernelDebugTable::Credentials, self.credentials.is_some());
        note(
            KernelDebugTable::ProcessGroup,
            self.process_groups.is_some(),
        );
        note(KernelDebugTable::Session, self.sessions.is_some());
        note(KernelDebugTable::Sighand, self.sighands.is_some());
        note(KernelDebugTable::TaskSignal, self.task_signals.is_some());
        note(
            KernelDebugTable::ThreadSignal,
            self.thread_signals.is_some(),
        );
        present
    }

    /// Fail closed on unknown schema, a missing or unrequested table, a
    /// duplicate ID, unsorted rows, a broken join, or a partial frame.
    ///
    /// Joins are only enforced between two tables that are both present, so a
    /// `--table` subset never invents a failure. A table that IS present must
    /// be internally consistent regardless of the filter.
    pub fn validate(
        &self,
        requested: &BTreeSet<KernelDebugTable>,
    ) -> Result<(), KernelDebugDtoError> {
        if self.schema != KERNEL_DEBUG_RESPONSE_SCHEMA {
            return Err(KernelDebugDtoError::UnknownSchema(self.schema.clone()));
        }
        if self.snapshot_schema_version != super::super::snapshot::KERNEL_SNAPSHOT_V1_SCHEMA {
            return Err(KernelDebugDtoError::UnknownSnapshotVersion(
                self.snapshot_schema_version,
            ));
        }

        let present = self.present();
        for table in requested {
            if !present.contains(table) {
                return Err(KernelDebugDtoError::MissingTable(table.wire_name()));
            }
        }
        for table in &present {
            if !requested.contains(table) {
                return Err(KernelDebugDtoError::UnrequestedTable(table.wire_name()));
            }
        }

        let tasks = unique_sorted("task", self.tasks.as_deref(), |row| row.key)?;
        let zombies = unique_sorted("zombie", self.zombies.as_deref(), |row| row.key)?;
        let threads = unique_sorted("thread", self.threads.as_deref(), |row| row.key)?;
        let mms = unique_sorted("mm", self.mms.as_deref(), |row| row.id)?;
        let frames = unique_sorted("frame", self.frames.as_deref(), |row| row.frame)?;
        let mappings = unique_sorted("mapping", self.mappings.as_deref(), |row| row.mapping)?;
        let file_tables = unique_sorted("file-table", self.file_tables.as_deref(), |row| row.id)?;
        let file_descriptions = unique_sorted(
            "file-description",
            self.file_descriptions.as_deref(),
            |row| row.id,
        )?;
        let fs_contexts = unique_sorted("fs-context", self.fs_contexts.as_deref(), |row| row.id)?;
        let credentials = unique_sorted("credentials", self.credentials.as_deref(), |row| row.id)?;
        let process_groups =
            unique_sorted("process-group", self.process_groups.as_deref(), |row| {
                row.id
            })?;
        let sessions = unique_sorted("session", self.sessions.as_deref(), |row| row.id)?;
        let sighands = unique_sorted("sighand", self.sighands.as_deref(), |row| row.id)?;
        let _ = unique_sorted("task-signal", self.task_signals.as_deref(), |row| row.task)?;
        let _ = unique_sorted("thread-signal", self.thread_signals.as_deref(), |row| {
            row.thread
        })?;
        let _ = unique_sorted("task-shared", self.task_shared.as_deref(), |row| row.task)?;
        let _ = unique_sorted(
            "thread-resources",
            self.thread_resources.as_deref(),
            |row| row.thread,
        )?;
        let _ = unique_sorted("file-slot", self.file_slots.as_deref(), |row| {
            (row.table, row.number)
        })?;

        // A task key is defined by a live task row or by a zombie record.
        let task_universe: Option<BTreeSet<DebugTaskKey>> = match (&tasks, &zombies) {
            (Some(tasks), Some(zombies)) => Some(tasks.union(zombies).copied().collect()),
            (Some(tasks), None) => Some(tasks.clone()),
            (None, Some(_)) | (None, None) => None,
        };

        if let (Some(tasks), Some(universe)) = (&tasks, &task_universe) {
            for row in self.tasks.as_deref().unwrap_or_default() {
                if let Some(parent) = row.parent
                    && !universe.contains(&parent)
                {
                    return Err(broken_join("task.parent", "task", parent));
                }
                for child in &row.children {
                    if !universe.contains(child) {
                        return Err(broken_join("task.children", "task", *child));
                    }
                }
            }
            let _ = tasks;
        }

        if let (Some(_), Some(universe)) = (&threads, &task_universe) {
            for row in self.threads.as_deref().unwrap_or_default() {
                if !universe.contains(&row.task) {
                    return Err(broken_join("thread.task", "task", row.task));
                }
            }
        }

        join_ids("task.mm", "mm", self.tasks.as_deref(), &mms, |row| {
            Some(row.mm)
        })?;
        join_ids(
            "task.sighand",
            "sighand",
            self.tasks.as_deref(),
            &sighands,
            |row| Some(row.sighand),
        )?;
        join_ids(
            "thread.file-table",
            "file-table",
            self.threads.as_deref(),
            &file_tables,
            |row| row.file_table,
        )?;
        join_ids(
            "thread.fs-context",
            "fs-context",
            self.threads.as_deref(),
            &fs_contexts,
            |row| row.fs_context,
        )?;
        join_ids(
            "thread.credentials",
            "credentials",
            self.threads.as_deref(),
            &credentials,
            |row| row.credentials,
        )?;
        join_ids("vma.mm", "mm", self.vmas.as_deref(), &mms, |row| {
            Some(row.mm)
        })?;
        join_ids("mapping.mm", "mm", self.mappings.as_deref(), &mms, |row| {
            Some(row.mm)
        })?;
        join_ids(
            "file-slot.table",
            "file-table",
            self.file_slots.as_deref(),
            &file_tables,
            |row| Some(row.table),
        )?;
        join_ids(
            "file-slot.description",
            "file-description",
            self.file_slots.as_deref(),
            &file_descriptions,
            |row| Some(row.description),
        )?;
        join_ids(
            "process-group.session",
            "session",
            self.process_groups.as_deref(),
            &sessions,
            |row| Some(row.session),
        )?;

        if let (Some(_), Some(known)) = (&self.process_groups, &sessions) {
            let _ = known;
        }

        if let (Some(group_ids), Some(sessions)) = (&process_groups, self.sessions.as_deref()) {
            for row in sessions {
                for group in &row.process_groups {
                    if !group_ids.contains(group) {
                        return Err(KernelDebugDtoError::BrokenJoin {
                            from: "session.process-groups",
                            to: "process-group",
                            id: group.to_string(),
                        });
                    }
                }
            }
        }

        // Frame/mapping must agree in BOTH directions or the frame is partial.
        if let (Some(known_mappings), Some(frames)) = (&mappings, self.frames.as_deref()) {
            for row in frames {
                for mapping in &row.mappings {
                    if !known_mappings.contains(mapping) {
                        return Err(KernelDebugDtoError::PartialFrame {
                            frame: row.frame,
                            mapping: *mapping,
                        });
                    }
                }
            }
        }
        if let (Some(_), Some(mapping_rows)) = (&frames, self.mappings.as_deref()) {
            let frame_rows = self.frames.as_deref().unwrap_or_default();
            for row in mapping_rows {
                let Some(frame) = frame_rows.iter().find(|frame| frame.frame == row.frame) else {
                    return Err(KernelDebugDtoError::BrokenJoin {
                        from: "mapping.frame",
                        to: "frame",
                        id: row.frame.to_string(),
                    });
                };
                if !frame.mappings.contains(&row.mapping) {
                    return Err(KernelDebugDtoError::PartialFrameBackReference {
                        mapping: row.mapping,
                        frame: row.frame,
                    });
                }
            }
        }

        Ok(())
    }
}

fn backing_kind_name(backing: &FileDescriptionBackingSnapshot) -> &'static str {
    use super::super::objects::FileDescriptionBackingKind as Kind;
    match backing.kind() {
        Kind::Closed => "closed",
        Kind::File => "file",
        Kind::Directory => "directory",
        Kind::SyntheticFile => "synthetic-file",
        Kind::EventFd => "eventfd",
        Kind::TimerFd => "timerfd",
        Kind::Epoll => "epoll",
        Kind::Pidfd => "pidfd",
        Kind::PipeReader => "pipe-reader",
        Kind::PipeWriter => "pipe-writer",
        Kind::HostPipe => "host-pipe",
        Kind::HostFile => "host-file",
        Kind::HostSocket => "host-socket",
        Kind::Inotify => "inotify",
        Kind::Fanotify => "fanotify",
        Kind::SignalFd => "signalfd",
        Kind::Netlink => "netlink",
        Kind::Mqueue => "mqueue",
        Kind::BpfMap => "bpf-map",
        Kind::BpfProg => "bpf-prog",
        Kind::IoUring => "io-uring",
        Kind::FsContext => "fscontext",
    }
}

fn task_key(key: super::super::objects::TaskKey) -> DebugTaskKey {
    DebugTaskKey {
        id: key.id.raw(),
        serial: key.serial.raw(),
    }
}

fn thread_key(key: super::super::objects::ThreadKey) -> DebugThreadKey {
    DebugThreadKey {
        tid: key.tid.raw(),
        serial: key.serial.raw(),
    }
}

fn pending_signal(pending: &super::super::objects::PendingSignal) -> DebugPendingSignal {
    DebugPendingSignal {
        signal: pending.signal.raw(),
        has_siginfo: pending.siginfo.is_some(),
    }
}

fn broken_join(from: &'static str, to: &'static str, key: DebugTaskKey) -> KernelDebugDtoError {
    KernelDebugDtoError::BrokenJoin {
        from,
        to,
        id: format!("{}:{}", key.id, key.serial),
    }
}

/// Collect a table's keys, rejecting duplicates and out-of-order rows.
///
/// Sortedness is part of the debug-record invariant, and it is also what lets
/// a reader binary-search a large table without trusting the server.
fn unique_sorted<Row, Key, Extract>(
    table: &'static str,
    rows: Option<&[Row]>,
    extract: Extract,
) -> Result<Option<BTreeSet<Key>>, KernelDebugDtoError>
where
    Key: Ord + Copy + std::fmt::Debug,
    Extract: Fn(&Row) -> Key,
{
    let Some(rows) = rows else {
        return Ok(None);
    };
    let mut seen = BTreeSet::new();
    let mut previous: Option<Key> = None;
    for row in rows {
        let key = extract(row);
        if let Some(previous) = previous
            && previous > key
        {
            return Err(KernelDebugDtoError::Unsorted {
                table,
                id: format!("{key:?}"),
            });
        }
        if !seen.insert(key) {
            return Err(KernelDebugDtoError::DuplicateId {
                table,
                id: format!("{key:?}"),
            });
        }
        previous = Some(key);
    }
    Ok(Some(seen))
}

fn join_ids<Row, Key, Extract>(
    from: &'static str,
    to: &'static str,
    rows: Option<&[Row]>,
    known: &Option<BTreeSet<Key>>,
    extract: Extract,
) -> Result<(), KernelDebugDtoError>
where
    Key: Ord + std::fmt::Display,
    Extract: Fn(&Row) -> Option<Key>,
{
    let (Some(rows), Some(known)) = (rows, known.as_ref()) else {
        return Ok(());
    };
    for row in rows {
        if let Some(id) = extract(row)
            && !known.contains(&id)
        {
            return Err(KernelDebugDtoError::BrokenJoin {
                from,
                to,
                id: id.to_string(),
            });
        }
    }
    Ok(())
}
