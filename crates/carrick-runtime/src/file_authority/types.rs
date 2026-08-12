use std::num::NonZeroU64;

use carrick_kernel::domains::{HostPid, ProcessGeneration};

pub(crate) use crate::kernel::{FileDescriptionId, FileSlotNumber, FileTableId};

macro_rules! nonzero_domain {
    ($name:ident, $constructor:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub(crate) struct $name(NonZeroU64);

        impl $name {
            pub(crate) fn $constructor(raw: u64) -> Result<Self, InvalidAuthorityDomain> {
                NonZeroU64::new(raw)
                    .map(Self)
                    .ok_or(InvalidAuthorityDomain::Zero(stringify!($name)))
            }

            pub(crate) const fn raw(self) -> u64 {
                self.0.get()
            }
        }
    };
}

nonzero_domain!(AuthorityEpoch, for_run);
nonzero_domain!(ClientId, for_process_client);
nonzero_domain!(RequestId, from_client_sequence);
nonzero_domain!(VfsObjectId, from_snapshot);

impl VfsObjectId {
    pub(super) const fn from_authority_allocation(raw: NonZeroU64) -> Self {
        Self(raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ClientIdentity {
    pub(crate) id: ClientId,
    pub(crate) host_pid: HostPid,
    pub(crate) process_generation: ProcessGeneration,
}

impl ClientIdentity {
    pub(crate) fn registered(
        id: ClientId,
        host_pid: HostPid,
        process_generation: ProcessGeneration,
    ) -> Result<Self, InvalidAuthorityDomain> {
        if host_pid.raw() == 0 {
            return Err(InvalidAuthorityDomain::Zero("HostPid"));
        }
        if process_generation == ProcessGeneration::NONE {
            return Err(InvalidAuthorityDomain::Zero("ProcessGeneration"));
        }
        Ok(Self {
            id,
            host_pid,
            process_generation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct ObjectGeneration(NonZeroU64);

impl ObjectGeneration {
    pub(crate) const INITIAL: Self = Self(NonZeroU64::MIN);

    pub(crate) fn from_snapshot(raw: u64) -> Result<Self, InvalidAuthorityDomain> {
        NonZeroU64::new(raw)
            .map(Self)
            .ok_or(InvalidAuthorityDomain::Zero("ObjectGeneration"))
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct Revision(u64);

impl Revision {
    pub(crate) const ZERO: Self = Self(0);

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }

    pub(super) fn next(self) -> Result<Self, AuthorityFatal> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(AuthorityFatal::RevisionExhausted)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct NofileAllocationCeiling(u32);

impl NofileAllocationCeiling {
    pub(crate) const fn from_captured_soft_limit(raw: u32) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct DescriptorFlags(u32);

impl DescriptorFlags {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const CLOSE_ON_EXEC: Self = Self(1);

    pub(crate) fn from_linux_bits(raw: u32) -> Result<Self, AuthorityError> {
        if raw & !Self::CLOSE_ON_EXEC.0 != 0 {
            return Err(AuthorityError::InvalidDescriptorFlags);
        }
        Ok(Self(raw))
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }

    pub(crate) const fn close_on_exec(self) -> bool {
        self.0 & Self::CLOSE_ON_EXEC.0 != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessMode {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    PathOnly,
}

impl AccessMode {
    pub(crate) const fn readable(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    pub(crate) const fn writable(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }

    pub(crate) const fn seekable(self) -> bool {
        !matches!(self, Self::PathOnly)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct StatusFlags(u64);

impl StatusFlags {
    pub(crate) const fn from_linux_bits(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct FileOffset(u64);

impl FileOffset {
    pub(crate) const fn from_start(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct ByteCount(u32);

impl ByteCount {
    pub(crate) const MAX_FRAME_BYTES: u32 = 64 * 1024;

    pub(crate) fn bounded(raw: u32) -> Result<Self, AuthorityError> {
        if raw > Self::MAX_FRAME_BYTES {
            return Err(AuthorityError::PayloadTooLarge);
        }
        Ok(Self(raw))
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct CanonicalPath(String);

impl CanonicalPath {
    pub(crate) fn absolute(path: impl Into<String>) -> Result<Self, AuthorityError> {
        let path = path.into();
        if !path.starts_with('/')
            || (path.len() > 1 && path.ends_with('/'))
            || path.contains("//")
            || path
                .split('/')
                .any(|component| matches!(component, "." | ".."))
        {
            return Err(AuthorityError::InvalidCanonicalPath);
        }
        Ok(Self(path))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeekWhence {
    Start,
    Current,
    End,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Request {
    pub(crate) epoch: AuthorityEpoch,
    pub(crate) client: ClientIdentity,
    pub(crate) request_id: RequestId,
    pub(crate) expected_generation: ObjectGeneration,
    pub(crate) command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Command {
    RegisterClient,
    ExitClient,
    CreateTable,
    CreateVfsFile {
        path: CanonicalPath,
        mode: u32,
        contents: Vec<u8>,
    },
    ResolveVfs {
        path: CanonicalPath,
    },
    LinkVfs {
        object: VfsObjectId,
        path: CanonicalPath,
    },
    UnlinkVfs {
        path: CanonicalPath,
    },
    RenameVfs {
        from: CanonicalPath,
        to: CanonicalPath,
    },
    OpenVfsAndInstall {
        table: FileTableId,
        object: VfsObjectId,
        object_generation: ObjectGeneration,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        path: Option<CanonicalPath>,
    },
    CreateSyntheticAndInstall {
        table: FileTableId,
        contents: Vec<u8>,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        path: Option<CanonicalPath>,
    },
    ResolveSlot {
        table: FileTableId,
        fd: FileSlotNumber,
    },
    Read {
        table: FileTableId,
        fd: FileSlotNumber,
        maximum: ByteCount,
    },
    Write {
        table: FileTableId,
        fd: FileSlotNumber,
        bytes: Vec<u8>,
    },
    Seek {
        table: FileTableId,
        fd: FileSlotNumber,
        offset: i64,
        whence: SeekWhence,
    },
    Close {
        table: FileTableId,
        fd: FileSlotNumber,
    },
    Dup {
        table: FileTableId,
        source: FileSlotNumber,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        flags: DescriptorFlags,
    },
    ForkCopy {
        source: FileTableId,
        owner: ClientIdentity,
    },
    ShareTable {
        table: FileTableId,
        owner: ClientIdentity,
    },
    ExecSuccessor {
        source: FileTableId,
    },
    InspectDescription {
        description: FileDescriptionId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Response {
    pub(crate) request_id: RequestId,
    pub(crate) authority_revision: Revision,
    pub(crate) outcome: Outcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    ClientRegistered,
    ClientExited,
    TableCreated {
        table: FileTableId,
        generation: ObjectGeneration,
        revision: Revision,
    },
    VfsObjectCreated {
        object: VfsObjectId,
        namespace_revision: Revision,
    },
    VfsObjectResolved {
        object: VfsObjectId,
        mode: u32,
        object_revision: Revision,
        namespace_revision: Revision,
    },
    VfsNamespaceChanged {
        object: VfsObjectId,
        namespace_revision: Revision,
        object_reclaimed: bool,
    },
    Installed {
        table: FileTableId,
        fd: FileSlotNumber,
        description: FileDescriptionId,
        description_generation: ObjectGeneration,
        table_revision: Revision,
        description_revision: Revision,
    },
    Slot(SlotSnapshot),
    Bytes {
        bytes: Vec<u8>,
        offset: FileOffset,
        description_revision: Revision,
    },
    Written {
        count: ByteCount,
        offset: FileOffset,
        description_revision: Revision,
        object_revision: Option<Revision>,
    },
    Seeked {
        offset: FileOffset,
        description_revision: Revision,
    },
    Closed {
        description: FileDescriptionId,
        description_reclaimed: bool,
        object_reclaimed: bool,
        table_revision: Revision,
    },
    Duplicated {
        source: FileSlotNumber,
        fd: FileSlotNumber,
        table_revision: Revision,
    },
    ForkCopied {
        source: FileTableId,
        table: FileTableId,
        generation: ObjectGeneration,
        revision: Revision,
    },
    TableShared {
        table: FileTableId,
        revision: Revision,
    },
    ExecSucceeded {
        source: FileTableId,
        table: FileTableId,
        generation: ObjectGeneration,
        closed_on_exec: Vec<FileSlotNumber>,
        revision: Revision,
    },
    Description(DescriptionSnapshot),
    Rejected(AuthorityError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SlotSnapshot {
    pub(crate) fd: FileSlotNumber,
    pub(crate) description: FileDescriptionId,
    pub(crate) description_generation: ObjectGeneration,
    pub(crate) flags: DescriptorFlags,
    pub(crate) path: Option<CanonicalPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DescriptionSnapshot {
    pub(crate) description: FileDescriptionId,
    pub(crate) generation: ObjectGeneration,
    pub(crate) revision: Revision,
    pub(crate) offset: FileOffset,
    pub(crate) access_mode: AccessMode,
    pub(crate) status_flags: StatusFlags,
    pub(crate) logical_slot_refs: u64,
    pub(crate) backing: DescriptionBackingSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DescriptionBackingSnapshot {
    Synthetic { length: u64 },
    VfsFile { object: VfsObjectId },
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AuthorityError {
    #[error("request targets authority epoch {actual:?}, expected {expected:?}")]
    StaleEpoch {
        expected: AuthorityEpoch,
        actual: AuthorityEpoch,
    },
    #[error("client is not registered")]
    ClientNotRegistered,
    #[error("client is already registered")]
    ClientAlreadyRegistered,
    #[error("client process generation is stale")]
    StaleClientGeneration,
    #[error("object generation is stale")]
    StaleObjectGeneration,
    #[error("file table was not found")]
    TableNotFound,
    #[error("file description was not found")]
    DescriptionNotFound,
    #[error("file descriptor slot was not found")]
    SlotNotFound,
    #[error("client is not bound to the file table")]
    TableNotBound,
    #[error("file descriptor limit is exhausted")]
    NofileExceeded,
    #[error("file descriptor flags contain unknown bits")]
    InvalidDescriptorFlags,
    #[error("canonical path is invalid")]
    InvalidCanonicalPath,
    #[error("VFS path already exists")]
    VfsPathExists,
    #[error("VFS path or object does not exist")]
    VfsNotFound,
    #[error("root VFS path cannot be mutated as a file")]
    VfsRootMutation,
    #[error("request payload exceeds the bounded authority frame")]
    PayloadTooLarge,
    #[error("file offset is invalid or exhausted")]
    InvalidOffset,
    #[error("description is not readable")]
    NotReadable,
    #[error("description is not writable")]
    NotWritable,
    #[error("description is not seekable")]
    NotSeekable,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum AuthorityFatal {
    #[error("request id was reused with a different request body")]
    RequestConflict,
    #[error("request id precedes the client's last terminal request")]
    RequestOutOfOrder,
    #[error("terminal request deduplication ledger is exhausted")]
    DedupExhausted,
    #[error("file authority revision space is exhausted")]
    RevisionExhausted,
    #[error("file authority identity space is exhausted")]
    IdentityExhausted,
    #[error("file authority invariant was violated: {0}")]
    InvariantViolation(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum InvalidAuthorityDomain {
    #[error("{0} cannot be zero")]
    Zero(&'static str),
}
