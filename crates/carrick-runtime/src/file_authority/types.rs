use std::num::{NonZeroI32, NonZeroU64};
use std::os::fd::OwnedFd;

use carrick_abi::LinuxEpollEvents;
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
nonzero_domain!(CapabilityLeaseId, from_snapshot);
nonzero_domain!(PipeId, from_snapshot);

impl VfsObjectId {
    pub(super) const fn from_authority_allocation(raw: NonZeroU64) -> Self {
        Self(raw)
    }
}

impl CapabilityLeaseId {
    pub(super) const fn from_authority_allocation(raw: NonZeroU64) -> Self {
        Self(raw)
    }
}

impl PipeId {
    pub(super) const fn from_authority_allocation(raw: NonZeroU64) -> Self {
        Self(raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct InterestGeneration(std::num::NonZeroU32);

impl InterestGeneration {
    pub(super) const fn from_authority_allocation(raw: std::num::NonZeroU32) -> Self {
        Self(raw)
    }

    pub(crate) fn from_snapshot(raw: u32) -> Result<Self, InvalidAuthorityDomain> {
        std::num::NonZeroU32::new(raw)
            .map(Self)
            .ok_or(InvalidAuthorityDomain::Zero("InterestGeneration"))
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0.get()
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

    pub(super) const fn from_wire(raw: u64) -> Self {
        Self(raw)
    }

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

    pub(crate) const fn with_close_on_exec(self) -> Self {
        Self(self.0 | Self::CLOSE_ON_EXEC.0)
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

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct EpollInterestKey {
    pub(crate) registered_slot: FileSlotNumber,
    pub(crate) target_description: FileDescriptionId,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct EpollUserData(u64);

impl EpollUserData {
    pub(crate) const fn from_guest(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EpollRegistration {
    pub(crate) events: LinuxEpollEvents,
    pub(crate) data: EpollUserData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EpollReadyEvent {
    pub(crate) events: LinuxEpollEvents,
    pub(crate) data: EpollUserData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct EpollEventLimit(u16);

impl EpollEventLimit {
    pub(crate) const MAX: u16 = 256;

    pub(crate) fn bounded(raw: u16) -> Result<Self, AuthorityError> {
        if raw == 0 || raw > Self::MAX {
            return Err(AuthorityError::InvalidEpollEventLimit);
        }
        Ok(Self(raw))
    }

    pub(crate) const fn raw(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PipeEnd {
    Reader,
    Writer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct PipeCapacity(u32);

impl PipeCapacity {
    pub(crate) const MAX: u32 = 1024 * 1024;

    pub(crate) fn bounded(raw: u32) -> Result<Self, AuthorityError> {
        if raw == 0 || raw > Self::MAX {
            return Err(AuthorityError::InvalidPipeCapacity);
        }
        Ok(Self(raw))
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SameSlotBehavior {
    ReturnUnchanged,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlotRangeAction {
    Close,
    SetCloseOnExec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct SlotPageLimit(u16);

impl SlotPageLimit {
    pub(crate) const MAX: u16 = 256;

    pub(crate) fn bounded(raw: u16) -> Result<Self, AuthorityError> {
        if raw == 0 || raw > Self::MAX {
            return Err(AuthorityError::InvalidPageLimit);
        }
        Ok(Self(raw))
    }

    pub(crate) const fn raw(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityLeasePurpose {
    MappingSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EpollHostPlanAction {
    RegisterOrModify,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EpollHostPlan {
    pub(crate) epoll_description: FileDescriptionId,
    pub(crate) target_description: FileDescriptionId,
    pub(crate) registered_slot: FileSlotNumber,
    pub(crate) generation: InterestGeneration,
    pub(crate) action: EpollHostPlanAction,
    pub(crate) events: carrick_abi::LinuxEpollEvents,
    pub(crate) plan_revision: Revision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct HostErrno(NonZeroI32);

impl HostErrno {
    pub(super) fn last() -> Self {
        let raw = std::io::Error::last_os_error()
            .raw_os_error()
            .filter(|raw| *raw > 0)
            .and_then(NonZeroI32::new)
            .unwrap_or_else(|| NonZeroI32::new(libc::EIO).unwrap_or(NonZeroI32::MIN));
        Self(raw)
    }

    pub(crate) const fn from_host(raw: NonZeroI32) -> Self {
        Self(raw)
    }

    pub(crate) const fn raw(self) -> i32 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityLeaseDisposition {
    Commit,
    Abort,
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
    CreatePipeAndInstall {
        table: FileTableId,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        status_flags: StatusFlags,
        capacity: PipeCapacity,
    },
    SetPipeCapacity {
        table: FileTableId,
        fd: FileSlotNumber,
        capacity: PipeCapacity,
    },
    CreateEpollAndInstall {
        table: FileTableId,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
    },
    CreateEventCounterAndInstall {
        table: FileTableId,
        initial: u64,
        semaphore: bool,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        status_flags: StatusFlags,
    },
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
    AdoptHostFileAndInstall {
        table: FileTableId,
        minimum: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        descriptor_flags: DescriptorFlags,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        writable: bool,
        path: Option<CanonicalPath>,
    },
    AcquireCapabilityLease {
        table: FileTableId,
        fd: FileSlotNumber,
        purpose: CapabilityLeasePurpose,
    },
    ReleaseCapabilityLease {
        lease: CapabilityLeaseId,
        disposition: CapabilityLeaseDisposition,
    },
    ResolveSlot {
        table: FileTableId,
        fd: FileSlotNumber,
    },
    ListSlots {
        table: FileTableId,
        after: Option<FileSlotNumber>,
        maximum: SlotPageLimit,
    },
    SetDescriptorFlags {
        table: FileTableId,
        fd: FileSlotNumber,
        flags: DescriptorFlags,
    },
    ReplaceSlot {
        table: FileTableId,
        source: FileSlotNumber,
        target: FileSlotNumber,
        ceiling: NofileAllocationCeiling,
        flags: DescriptorFlags,
        same_slot: SameSlotBehavior,
    },
    MutateSlotRange {
        table: FileTableId,
        first: FileSlotNumber,
        last: FileSlotNumber,
        action: SlotRangeAction,
    },
    EpollCtlAdd {
        table: FileTableId,
        epoll_fd: FileSlotNumber,
        target_fd: FileSlotNumber,
        registration: EpollRegistration,
    },
    EpollCtlModify {
        table: FileTableId,
        epoll_fd: FileSlotNumber,
        target_fd: FileSlotNumber,
        registration: EpollRegistration,
    },
    EpollCtlDelete {
        table: FileTableId,
        epoll_fd: FileSlotNumber,
        target_fd: FileSlotNumber,
    },
    EpollRevalidateHostPlan {
        plan: EpollHostPlan,
    },
    ObserveReadiness {
        table: FileTableId,
        fd: FileSlotNumber,
        ready: LinuxEpollEvents,
        read_available: u64,
    },
    EpollCollect {
        table: FileTableId,
        epoll_fd: FileSlotNumber,
        maximum: EpollEventLimit,
    },
    EpollAcknowledgeIo {
        table: FileTableId,
        fd: FileSlotNumber,
        consumed: LinuxEpollEvents,
        read_available: u64,
        write_backpressured: bool,
    },
    EventCounterRead {
        table: FileTableId,
        fd: FileSlotNumber,
    },
    EventCounterWrite {
        table: FileTableId,
        fd: FileSlotNumber,
        value: u64,
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

#[derive(Debug)]
pub(crate) struct AuthorityCall {
    pub(crate) request: Request,
    pub(crate) capabilities: Vec<OwnedFd>,
}

impl AuthorityCall {
    pub(crate) fn without_capabilities(request: Request) -> Self {
        Self {
            request,
            capabilities: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuthorityReply {
    pub(crate) response: Response,
    pub(crate) capabilities: Vec<OwnedFd>,
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
    PipeCreated {
        table: FileTableId,
        pipe: PipeId,
        read_fd: FileSlotNumber,
        write_fd: FileSlotNumber,
        read_description: FileDescriptionId,
        write_description: FileDescriptionId,
        generation: ObjectGeneration,
        table_revision: Revision,
        stream_revision: Revision,
    },
    PipeCapacitySet {
        pipe: PipeId,
        capacity: PipeCapacity,
        stream_revision: Revision,
    },
    EpollCreated {
        table: FileTableId,
        fd: FileSlotNumber,
        description: FileDescriptionId,
        generation: ObjectGeneration,
        table_revision: Revision,
        description_revision: Revision,
    },
    EventCounterCreated {
        table: FileTableId,
        fd: FileSlotNumber,
        description: FileDescriptionId,
        generation: ObjectGeneration,
        table_revision: Revision,
        description_revision: Revision,
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
    SlotPage {
        table: FileTableId,
        slots: Vec<SlotSnapshot>,
        next_after: Option<FileSlotNumber>,
        table_revision: Revision,
    },
    DescriptorFlagsSet {
        table: FileTableId,
        fd: FileSlotNumber,
        flags: DescriptorFlags,
        table_revision: Revision,
    },
    SlotReplaced {
        table: FileTableId,
        source: FileSlotNumber,
        target: FileSlotNumber,
        replaced_description: Option<FileDescriptionId>,
        description_reclaimed: bool,
        object_reclaimed: bool,
        table_revision: Revision,
    },
    SlotRangeMutated {
        table: FileTableId,
        action: SlotRangeAction,
        affected: u32,
        table_revision: Revision,
    },
    EpollInterestAdded {
        key: EpollInterestKey,
        generation: InterestGeneration,
        description_revision: Revision,
        host_plan: EpollHostPlan,
    },
    EpollInterestModified {
        key: EpollInterestKey,
        generation: InterestGeneration,
        description_revision: Revision,
        host_plan: EpollHostPlan,
    },
    EpollInterestDeleted {
        key: EpollInterestKey,
        description_revision: Revision,
        host_plan: EpollHostPlan,
    },
    EpollHostPlanValidated {
        valid: bool,
        current_revision: Revision,
    },
    ReadinessObserved {
        description: FileDescriptionId,
        description_revision: Revision,
    },
    EpollEvents {
        events: Vec<EpollReadyEvent>,
        description_revision: Revision,
    },
    EpollIoAcknowledged {
        description: FileDescriptionId,
        description_revision: Revision,
    },
    EventCounterRead {
        value: u64,
        description_revision: Revision,
    },
    EventCounterWritten {
        value: u64,
        counter: u64,
        description_revision: Revision,
    },
    StreamBytes {
        pipe: PipeId,
        bytes: Vec<u8>,
        description_revision: Revision,
        stream_revision: Revision,
    },
    StreamWritten {
        pipe: PipeId,
        count: ByteCount,
        description_revision: Revision,
        stream_revision: Revision,
    },
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
    CapabilityLeaseGranted {
        lease: CapabilityLeaseId,
        description: FileDescriptionId,
        description_generation: ObjectGeneration,
        purpose: CapabilityLeasePurpose,
        revision: Revision,
    },
    CapabilityLeaseReleased {
        lease: CapabilityLeaseId,
        disposition: CapabilityLeaseDisposition,
        description_reclaimed: bool,
        object_reclaimed: bool,
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
    HostFile { writable: bool },
    Epoll { interests: u32 },
    EventCounter { counter: u64, semaphore: bool },
    PipeEnd { pipe: PipeId, end: PipeEnd },
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
    #[error("description does not have a host descriptor backing")]
    NotHostBacked,
    #[error("capability lease was not found")]
    CapabilityLeaseNotFound,
    #[error("host operation failed with errno {0:?}")]
    HostIo(HostErrno),
    #[error("host descriptor is not a regular-file backing")]
    HostBackingTypeMismatch,
    #[error("declared access mode does not match the host descriptor")]
    HostAccessMismatch,
    #[error("host file backing is read-only")]
    BackingReadOnly,
    #[error("slot page limit is zero or exceeds its protocol bound")]
    InvalidPageLimit,
    #[error("operation rejects identical source and target slots")]
    SameSlotRejected,
    #[error("file descriptor slot range is inverted")]
    InvalidSlotRange,
    #[error("description is not an epoll instance")]
    NotEpoll,
    #[error("target description does not support readiness")]
    NotEpollable,
    #[error("epoll interest already exists")]
    EpollInterestExists,
    #[error("epoll interest was not found")]
    EpollInterestNotFound,
    #[error("epoll interest would create a cycle or exceed nesting depth")]
    EpollLoop,
    #[error("epoll event limit is zero or exceeds its protocol bound")]
    InvalidEpollEventLimit,
    #[error("description is not an event counter")]
    NotEventCounter,
    #[error("event-counter operation would block")]
    WouldBlock,
    #[error("event-counter write value is invalid or would overflow")]
    InvalidEventCounterValue,
    #[error("description requires a different typed operation family")]
    WrongOperationFamily,
    #[error("description is not a pipe end")]
    NotPipe,
    #[error("pipe capacity is zero or exceeds its protocol bound")]
    InvalidPipeCapacity,
    #[error("pipe has no readers")]
    BrokenPipe,
    #[error("file descriptor table has no room for an atomic pair")]
    PairAllocationFailed,
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
    #[error("file authority could not encode a protocol frame: {0}")]
    EncodingFailure(&'static str),
    #[error("file authority protocol frame is malformed: {0}")]
    MalformedFrame(&'static str),
    #[error("file authority transport is unavailable")]
    TransportUnavailable,
    #[error("file authority response does not match its request")]
    ResponseMismatch,
    #[error("file authority capability count does not match the operation")]
    CapabilityMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum InvalidAuthorityDomain {
    #[error("{0} cannot be zero")]
    Zero(&'static str),
}
