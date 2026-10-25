//! Exact native service operations. The ring retains semantic custody until
//! an exact completion or cancellation acknowledgment is consumed.
use crate::{El1MmHandle, EntryThreadGeneration, ReservationMm, SnapshotGeneration};
use carrick_guest_arch::{Access, FaultInfo, GuestLen, GuestVa, NativeOrdinal};
use carrick_sched_core::{RecordRef, object_wait::OwnerEntry, process::TaskKey};
use core::num::{NonZeroU32, NonZeroU64};
use core::ops::Deref;
use core::sync::atomic::{AtomicU64, Ordering};

/// Opaque retained host file/loader capability. The ring may inherit this
/// value, but only the carrier that minted it can resolve the capability.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ExecCapabilityId(NonZeroU64);
impl ExecCapabilityId {
    pub const fn new(raw: NonZeroU64) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}

/// Opaque, carrier-minted authority to consume one prepared exec image.
/// The carrier separately binds it to the complete [`ServiceIdentity`]; the
/// numeric value is selection only and can never authorize adoption alone.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ExecAdoptionReceipt(NonZeroU64);
impl ExecAdoptionReceipt {
    pub const fn checked(raw: NonZeroU64) -> Option<Self> {
        if raw.get() & !EXEC_PREPARED_VALUE_MASK == 0 {
            Some(Self(raw))
        } else {
            None
        }
    }
    pub const fn raw(self) -> NonZeroU64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceBirth {
    pub process: TaskKey,
    pub thread: EntryThreadGeneration,
    pub record: RecordRef,
    pub mm: El1MmHandle,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceIdentity {
    pub birth: ServiceBirth,
    pub execution: SnapshotGeneration,
    pub sequence: NonZeroU64,
}
/// Physical demand selected by the ring; mapping policy stays with the owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceFaultSupply {
    Cow(crate::PortalGrantWindow),
    Backing(crate::PortalGrantWindow),
}

/// EL0 synchronous exception selected by the ISA boundary. The Linux
/// personality owns the signal policy; the host transport only refuses the
/// physical service request back to that owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeExceptionKind {
    Breakpoint,
    SingleStep,
    HardwareBreakpoint,
    UndefinedInstruction,
    Alignment,
    FloatingPoint,
}
impl NativeExceptionKind {
    const fn encode(self) -> u64 {
        match self {
            Self::Breakpoint => 1,
            Self::SingleStep => 2,
            Self::HardwareBreakpoint => 3,
            Self::UndefinedInstruction => 4,
            Self::Alignment => 5,
            Self::FloatingPoint => 6,
        }
    }
    const fn decode(raw: u64) -> Option<Self> {
        Some(match raw {
            1 => Self::Breakpoint,
            2 => Self::SingleStep,
            3 => Self::HardwareBreakpoint,
            4 => Self::UndefinedInstruction,
            5 => Self::Alignment,
            6 => Self::FloatingPoint,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeException {
    pub kind: NativeExceptionKind,
    pub address: carrick_guest_arch::UserVa,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceOperation {
    Fault(FaultInfo),
    Exception(NativeException),
    Crossing {
        ordinal: NativeOrdinal,
    },
    /// Deliver carrier work before resuming the exact saved instruction context.
    CarrierWork {
        entry: OwnerEntry,
    },
    /// Prepare one executable image from a bounded payload in guest memory.
    /// The exact service birth/MM authenticates the stage-1 translation; this
    /// descriptor is never a host pointer.
    Exec {
        capability: ExecCapabilityId,
        payload: ExecPayloadDescriptor,
    },
}

/// A bounded variable-length input owned by the requesting guest continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecPayloadDescriptor {
    address: GuestVa,
    length: GuestLen,
}
/// Linux's aggregate argv/envp accounting ceiling. String bytes include their
/// terminating NUL and each vector entry consumes one 64-bit pointer slot.
pub const EXEC_ARGUMENT_BYTES_MAX: usize = 2 * 1024 * 1024;
/// Linux `MAX_ARG_STRLEN` for Carrick's 4 KiB guest page ABI, including NUL.
pub const MAX_ARG_STRLEN: usize = 32 * 4096;
pub const MAX_EXEC_PATH_BYTES: usize = 4096;
pub const EXEC_PAYLOAD_HEADER_BYTES: usize = 32;
/// The wire record includes the path and a small header in addition to bytes
/// charged to Linux argv/envp accounting.
pub const MAX_EXEC_PAYLOAD_BYTES: u64 =
    (EXEC_ARGUMENT_BYTES_MAX + MAX_EXEC_PATH_BYTES + EXEC_PAYLOAD_HEADER_BYTES) as u64;

const EXEC_PAYLOAD_MAGIC: u32 = u32::from_le_bytes(*b"CEXE");
const EXEC_PAYLOAD_VERSION: u16 = 1;

/// Which Linux exec entry produced the staged request. All raw user pointers
/// have already been consumed by the ring before this value crosses the ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecCall {
    Execve,
    Execveat { dirfd: i32, flags: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecPayloadError {
    Invalid,
    TooLarge,
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Encode the fixed prefix after the ring has finished staging all strings.
pub fn encode_exec_payload_header(
    bytes: &mut [u8],
    call: ExecCall,
    path_len: usize,
    argc: usize,
    envc: usize,
) -> Result<(), ExecPayloadError> {
    if bytes.len() > MAX_EXEC_PAYLOAD_BYTES as usize
        || path_len == 0
        || path_len > MAX_EXEC_PATH_BYTES
    {
        return Err(ExecPayloadError::TooLarge);
    }
    let (kind, dirfd, flags) = match call {
        ExecCall::Execve => (1u16, 0i32, 0u32),
        ExecCall::Execveat { dirfd, flags } => (2, dirfd, flags),
    };
    let encoded_len = bytes.len();
    let header = bytes
        .get_mut(..EXEC_PAYLOAD_HEADER_BYTES)
        .ok_or(ExecPayloadError::Invalid)?;
    header.fill(0);
    header[0..4].copy_from_slice(&EXEC_PAYLOAD_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&EXEC_PAYLOAD_VERSION.to_le_bytes());
    header[6..8].copy_from_slice(&kind.to_le_bytes());
    header[8..12].copy_from_slice(&dirfd.to_le_bytes());
    header[12..16].copy_from_slice(&flags.to_le_bytes());
    for (offset, value) in [(16, path_len), (20, argc), (24, envc), (28, encoded_len)] {
        header[offset..offset + 4].copy_from_slice(
            &u32::try_from(value)
                .map_err(|_| ExecPayloadError::TooLarge)?
                .to_le_bytes(),
        );
    }
    Ok(())
}

/// Authenticated view of one complete contiguous ring-owned exec record.
#[derive(Clone, Copy, Debug)]
pub struct ExecPayloadView<'a> {
    bytes: &'a [u8],
    call: ExecCall,
    path_len: usize,
    argc: usize,
    envc: usize,
}

impl<'a> ExecPayloadView<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ExecPayloadError> {
        if bytes.len() > MAX_EXEC_PAYLOAD_BYTES as usize
            || read_u32(bytes, 0) != Some(EXEC_PAYLOAD_MAGIC)
            || read_u16(bytes, 4) != Some(EXEC_PAYLOAD_VERSION)
            || read_u32(bytes, 28).and_then(|len| usize::try_from(len).ok()) != Some(bytes.len())
        {
            return Err(ExecPayloadError::Invalid);
        }
        let dirfd = read_u32(bytes, 8)
            .map(|raw| i32::from_le_bytes(raw.to_le_bytes()))
            .ok_or(ExecPayloadError::Invalid)?;
        let flags = read_u32(bytes, 12).ok_or(ExecPayloadError::Invalid)?;
        let call = match read_u16(bytes, 6) {
            Some(1) if dirfd == 0 && flags == 0 => ExecCall::Execve,
            Some(2) => ExecCall::Execveat { dirfd, flags },
            _ => return Err(ExecPayloadError::Invalid),
        };
        let path_len = read_u32(bytes, 16)
            .and_then(|raw| usize::try_from(raw).ok())
            .ok_or(ExecPayloadError::Invalid)?;
        let argc = read_u32(bytes, 20)
            .and_then(|raw| usize::try_from(raw).ok())
            .ok_or(ExecPayloadError::Invalid)?;
        let envc = read_u32(bytes, 24)
            .and_then(|raw| usize::try_from(raw).ok())
            .ok_or(ExecPayloadError::Invalid)?;
        let path_end = EXEC_PAYLOAD_HEADER_BYTES
            .checked_add(path_len)
            .ok_or(ExecPayloadError::Invalid)?;
        let path = bytes
            .get(EXEC_PAYLOAD_HEADER_BYTES..path_end)
            .ok_or(ExecPayloadError::Invalid)?;
        if path.is_empty() || path.last() != Some(&0) || path[..path.len() - 1].contains(&0) {
            return Err(ExecPayloadError::Invalid);
        }
        let mut cursor = path_end;
        let mut accounting = (argc + envc)
            .checked_add(2)
            .and_then(|entries| entries.checked_mul(8))
            .ok_or(ExecPayloadError::TooLarge)?;
        for _ in 0..argc.checked_add(envc).ok_or(ExecPayloadError::TooLarge)? {
            let len = read_u32(bytes, cursor)
                .and_then(|raw| usize::try_from(raw).ok())
                .ok_or(ExecPayloadError::Invalid)?;
            if len == 0 || len > MAX_ARG_STRLEN {
                return Err(ExecPayloadError::TooLarge);
            }
            cursor = cursor.checked_add(4).ok_or(ExecPayloadError::Invalid)?;
            let string = bytes
                .get(cursor..cursor.checked_add(len).ok_or(ExecPayloadError::Invalid)?)
                .ok_or(ExecPayloadError::Invalid)?;
            if string.last() != Some(&0) || string[..string.len() - 1].contains(&0) {
                return Err(ExecPayloadError::Invalid);
            }
            cursor += len;
            accounting = accounting
                .checked_add(len)
                .ok_or(ExecPayloadError::TooLarge)?;
            if accounting > EXEC_ARGUMENT_BYTES_MAX {
                return Err(ExecPayloadError::TooLarge);
            }
        }
        if cursor != bytes.len() {
            return Err(ExecPayloadError::Invalid);
        }
        Ok(Self {
            bytes,
            call,
            path_len,
            argc,
            envc,
        })
    }

    pub const fn call(self) -> ExecCall {
        self.call
    }

    pub fn path(self) -> &'a [u8] {
        &self.bytes[EXEC_PAYLOAD_HEADER_BYTES..EXEC_PAYLOAD_HEADER_BYTES + self.path_len - 1]
    }

    pub fn argv(self) -> ExecPayloadStrings<'a> {
        ExecPayloadStrings {
            bytes: self.bytes,
            cursor: EXEC_PAYLOAD_HEADER_BYTES + self.path_len,
            remaining: self.argc,
        }
    }

    pub fn envp(self) -> ExecPayloadStrings<'a> {
        let mut argv = self.argv();
        while argv.next().is_some() {}
        ExecPayloadStrings {
            bytes: self.bytes,
            cursor: argv.cursor,
            remaining: self.envc,
        }
    }

    pub fn encoded_len(self) -> usize {
        self.bytes.len()
    }
}

pub struct ExecPayloadStrings<'a> {
    bytes: &'a [u8],
    cursor: usize,
    remaining: usize,
}

impl<'a> Iterator for ExecPayloadStrings<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let len = read_u32(self.bytes, self.cursor)? as usize;
        self.cursor += 4;
        let string = self.bytes.get(self.cursor..self.cursor + len)?;
        self.cursor += len;
        self.remaining -= 1;
        Some(&string[..string.len() - 1])
    }
}
impl ExecPayloadDescriptor {
    pub const fn checked(address: GuestVa, length: GuestLen) -> Option<Self> {
        if length.raw() == 0
            || length.raw() > MAX_EXEC_PAYLOAD_BYTES
            || address.raw().checked_add(length.raw()).is_none()
        {
            return None;
        }
        Some(Self { address, length })
    }
    pub const fn address(self) -> GuestVa {
        self.address
    }
    pub const fn length(self) -> GuestLen {
        self.length
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceRequest {
    pub identity: ServiceIdentity,
    pub operation: ServiceOperation,
    /// Exact ring-selected portal operation, captured before releasing the lane.
    pub fault_sequence: Option<NonZeroU64>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceResult {
    BackingFault,
    Supplied,
    ExecPrepared(ExecAdoptionReceipt),
    Refused,
    Cancelled,
    Wait(crate::PortalOwnerWait),
    Failed(ServiceFailureCode),
}

/// Personality-interpreted failure number returned by a typed service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct ServiceFailureCode(NonZeroU32);
impl ServiceFailureCode {
    /// Smallest representable personality failure. This is a fail-closed
    /// fallback for a violated producer-side positive-number invariant.
    pub const MINIMUM: Self = Self(NonZeroU32::MIN);
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }
    pub const fn raw(self) -> u32 {
        self.0.get()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    Busy,
    Stale,
    Exhausted,
}

/// Refusal to transfer a prepared result. Both the ticket and the resource
/// remain owned by the caller, including while cancellation cleanup is pending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedDeliveryError {
    Cancelled,
    Service(ServiceError),
}

pub const NATIVE_SERVICE_PROTOCOL: u64 = 6;

/// Transport selector only: authority remains in the member's retained cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceSelector {
    pub record: RecordRef,
    pub execution: SnapshotGeneration,
    pub sequence: NonZeroU64,
}
impl From<ServiceIdentity> for ServiceSelector {
    fn from(identity: ServiceIdentity) -> Self {
        Self {
            record: identity.birth.record,
            execution: identity.execution,
            sequence: identity.sequence,
        }
    }
}

/// One producer per execution lane. Publication is followed by an owned park
/// and exit; the host consumes the notice before admitting that lane again.
/// A notice is not a second task owner and contains no dereferenceable pointer.
#[repr(C)]
#[derive(Debug)]
pub struct ServiceNotice {
    record: AtomicU64,
    incarnation: AtomicU64,
    execution: AtomicU64,
    sequence: AtomicU64,
}
impl ServiceNotice {
    pub const fn new() -> Self {
        Self {
            record: AtomicU64::new(0),
            incarnation: AtomicU64::new(0),
            execution: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
        }
    }
    pub fn publish(&self, selector: ServiceSelector) -> Result<(), ServiceError> {
        self.record
            .compare_exchange(0, u64::MAX, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        self.incarnation
            .store(selector.record.incarnation, Ordering::Relaxed);
        self.execution
            .store(selector.execution.raw(), Ordering::Relaxed);
        self.sequence
            .store(selector.sequence.get(), Ordering::Relaxed);
        self.record
            .store(u64::from(selector.record.id.raw()) + 1, Ordering::Release);
        Ok(())
    }
    pub fn take(&self) -> Result<Option<ServiceSelector>, ServiceError> {
        let record = self.record.load(Ordering::Acquire);
        if record == 0 {
            return Ok(None);
        }
        if record == u64::MAX {
            return Err(ServiceError::Busy);
        }
        self.record
            .compare_exchange(record, u64::MAX, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        let selector = (|| {
            Some(ServiceSelector {
                record: RecordRef {
                    id: carrick_sched_core::RecordId::from_raw(u32::try_from(record - 1).ok()?)?,
                    incarnation: self.incarnation.load(Ordering::Relaxed),
                },
                execution: SnapshotGeneration::from_raw(self.execution.load(Ordering::Relaxed)),
                sequence: NonZeroU64::new(self.sequence.load(Ordering::Relaxed))?,
            })
        })();
        self.record.store(0, Ordering::Release);
        selector.map(Some).ok_or(ServiceError::Stale)
    }
}
impl Default for ServiceNotice {
    fn default() -> Self {
        Self::new()
    }
}

const UNBOUND: u64 = 0;
const IDLE: u64 = 1;
const WRITING: u64 = 2;
const REQUESTED: u64 = 3;
const SERVICING: u64 = 4;
const CANCEL_REQUESTED: u64 = 5;
const COMPLETED: u64 = 6;
const CANCELLED: u64 = 7;
const CANCEL_QUEUED: u64 = 8;
const OWNED_WAIT: u64 = 9;
const WAIT_CANCELLED: u64 = 10;

/// A member owns this cell, not the execution slot. Its enclosing allocation
/// and semantic MM claim must remain retained through acknowledgment. All
/// fields are atomic because rejected readers may overlap a later publication.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct ServiceCell {
    state: AtomicU64,
    sequence: AtomicU64,
    words: [AtomicU64; 12],
    result: AtomicU64,
    wait_revision: AtomicU64,
}
impl ServiceCell {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(UNBOUND),
            sequence: AtomicU64::new(0),
            words: [const { AtomicU64::new(0) }; 12],
            result: AtomicU64::new(0),
            wait_revision: AtomicU64::new(0),
        }
    }
    // Binding/publication must use authenticated lifecycle and admitted-MM
    // owners. Identity decoding grants no authority by itself.
}
impl Default for ServiceCell {
    fn default() -> Self {
        Self::new()
    }
}
impl ServiceBirth {
    fn words(self) -> [u64; 8] {
        [
            self.mm.carrier().get(),
            self.process.id.raw() as u64,
            self.process.serial.raw(),
            self.thread.raw(),
            u64::from(self.record.id.raw()),
            self.record.incarnation,
            self.mm.mm().raw(),
            self.mm.incarnation().get(),
        ]
    }
}

const EXEC_SUCCESSOR_MANIFEST_REVISION: u64 = 1;
const EXEC_SUCCESSOR_PROPOSED: u64 = 1;
const EXEC_SUCCESSOR_SEALED: u64 = 2;

/// Ring-owned reply record for one prepared exec successor. The proposal is
/// written before request publication; the exact service ticket may seal it
/// once. Completion publication is the release/acquire edge protecting these
/// plain words. The digest detects tearing, while exact retained service and
/// receipt identity provide authority.
#[repr(C, align(64))]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
    zerocopy::FromZeros,
)]
pub struct ExecSuccessorManifest {
    revision: u64,
    phase: u64,
    identity: [u64; 10],
    successor_mm: u64,
    root: u64,
    root_generation: u64,
    asid: u64,
    asid_generation: u64,
    entry: u64,
    stack_pointer: u64,
    receipt: u64,
    digest: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecSuccessorManifestView {
    pub successor_mm: ReservationMm,
    pub root: carrick_guest_arch::RootGpa,
    pub root_generation: NonZeroU64,
    pub asid: carrick_guest_arch::Asid,
    pub asid_generation: NonZeroU64,
    pub entry: carrick_guest_arch::UserVa,
    pub stack_pointer: carrick_guest_arch::UserVa,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecSuccessorEntry {
    pub entry: carrick_guest_arch::UserVa,
    pub stack_pointer: carrick_guest_arch::UserVa,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecSuccessorBacking {
    pub root: carrick_guest_arch::RootGpa,
    pub root_generation: NonZeroU64,
    pub asid: carrick_guest_arch::Asid,
    pub asid_generation: NonZeroU64,
}

impl ServiceIdentity {
    fn manifest_words(self) -> [u64; 10] {
        let birth = self.birth.words();
        [
            birth[0],
            birth[1],
            birth[2],
            birth[3],
            birth[4],
            birth[5],
            birth[6],
            birth[7],
            self.execution.raw(),
            self.sequence.get(),
        ]
    }
}

impl ExecSuccessorManifest {
    fn words(&self) -> [u64; 21] {
        [
            self.revision,
            self.phase,
            self.identity[0],
            self.identity[1],
            self.identity[2],
            self.identity[3],
            self.identity[4],
            self.identity[5],
            self.identity[6],
            self.identity[7],
            self.identity[8],
            self.identity[9],
            self.successor_mm,
            self.root,
            self.root_generation,
            self.asid,
            self.asid_generation,
            self.entry,
            self.stack_pointer,
            self.receipt,
            0,
        ]
    }

    fn has_valid_digest(&self) -> bool {
        self.digest == crate::integrity_digest(&self.words())
    }

    pub fn propose(identity: ServiceIdentity, successor_mm: ReservationMm) -> Self {
        let mut manifest = Self {
            revision: EXEC_SUCCESSOR_MANIFEST_REVISION,
            phase: EXEC_SUCCESSOR_PROPOSED,
            identity: identity.manifest_words(),
            successor_mm: successor_mm.raw(),
            root: 0,
            root_generation: 0,
            asid: 0,
            asid_generation: 0,
            entry: 0,
            stack_pointer: 0,
            receipt: 0,
            digest: 0,
        };
        manifest.digest = crate::integrity_digest(&manifest.words());
        manifest
    }

    pub fn proposal(&self, identity: ServiceIdentity) -> Option<ReservationMm> {
        (self.revision == EXEC_SUCCESSOR_MANIFEST_REVISION
            && self.phase == EXEC_SUCCESSOR_PROPOSED
            && self.identity == identity.manifest_words()
            && self.root == 0
            && self.root_generation == 0
            && self.asid == 0
            && self.asid_generation == 0
            && self.entry == 0
            && self.stack_pointer == 0
            && self.receipt == 0
            && self.has_valid_digest())
        .then(|| ReservationMm::new(self.successor_mm))?
    }

    pub fn seal(
        mut self,
        identity: ServiceIdentity,
        receipt: ExecAdoptionReceipt,
        backing: ExecSuccessorBacking,
        image: ExecSuccessorEntry,
    ) -> Option<Self> {
        self.proposal(identity)?;
        self.phase = EXEC_SUCCESSOR_SEALED;
        self.root = backing.root.address().raw();
        self.root_generation = backing.root_generation.get();
        self.asid = u64::from(backing.asid.raw());
        self.asid_generation = backing.asid_generation.get();
        self.entry = image.entry.raw();
        self.stack_pointer = image.stack_pointer.raw();
        self.receipt = receipt.raw().get();
        self.digest = crate::integrity_digest(&self.words());
        Some(self)
    }

    pub fn open(
        &self,
        identity: ServiceIdentity,
        receipt: ExecAdoptionReceipt,
    ) -> Option<ExecSuccessorManifestView> {
        if self.revision != EXEC_SUCCESSOR_MANIFEST_REVISION
            || self.phase != EXEC_SUCCESSOR_SEALED
            || self.identity != identity.manifest_words()
            || self.receipt != receipt.raw().get()
            || !self.has_valid_digest()
        {
            return None;
        }
        Some(ExecSuccessorManifestView {
            successor_mm: ReservationMm::new(self.successor_mm)?,
            root: carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(
                self.root,
            ))?,
            root_generation: NonZeroU64::new(self.root_generation)?,
            asid: carrick_guest_arch::Asid::from_registry_allocation(core::num::NonZeroU16::new(
                u16::try_from(self.asid).ok()?,
            )?),
            asid_generation: NonZeroU64::new(self.asid_generation)?,
            entry: carrick_guest_arch::UserVa::new(self.entry),
            stack_pointer: carrick_guest_arch::UserVa::new(self.stack_pointer),
        })
    }
}
impl ServiceCell {
    /// Publish only after the native owner has authenticated the complete
    /// lifecycle birth and admitted MM. No execution slot is part of custody.
    pub fn bind(&self, birth: ServiceBirth) -> Result<(), ServiceError> {
        if birth.thread.raw() == 0 || birth.record.incarnation == 0 {
            return Err(ServiceError::Stale);
        }
        self.state
            .compare_exchange(UNBOUND, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        for (word, value) in self.words.iter().zip(birth.words()) {
            word.store(value, Ordering::Relaxed);
        }
        self.state.store(IDLE, Ordering::Release);
        Ok(())
    }
    /// Recover the immutable admitted-MM identity from this member's birth.
    /// The native entry has already authenticated its task/thread/record;
    /// recovering this retained handle never acquires a reservation root.
    pub fn bound_birth(
        &self,
        process: TaskKey,
        thread: EntryThreadGeneration,
        record: RecordRef,
    ) -> Result<ServiceBirth, ServiceError> {
        self.state
            .compare_exchange(IDLE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        let birth = (|| {
            let carrier = NonZeroU64::new(self.words[0].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            let mm = crate::ReservationMm::new(self.words[6].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            let incarnation = NonZeroU64::new(self.words[7].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            // SAFETY: bind stored this admitted handle; IDLE excludes an
            // outstanding request and the WRITING reservation excludes reset.
            let mm = unsafe { El1MmHandle::from_admitted_owner(carrier, mm, incarnation) };
            let birth = ServiceBirth {
                process,
                thread,
                record,
                mm,
            };
            self.same_birth(birth)
                .then_some(birth)
                .ok_or(ServiceError::Stale)
        })();
        self.state.store(IDLE, Ordering::Release);
        birth
    }

    /// Recover the birth MM for a currently executing, exact member. This
    /// does not probe the reservation root whose contention is being handled.
    pub fn bound_mm(
        &self,
        record: RecordRef,
        thread: EntryThreadGeneration,
    ) -> Result<El1MmHandle, ServiceError> {
        let id = i32::try_from(self.words[1].load(Ordering::Acquire))
            .ok()
            .and_then(core::num::NonZeroI32::new)
            .ok_or(ServiceError::Stale)?;
        let serial =
            NonZeroU64::new(self.words[2].load(Ordering::Acquire)).ok_or(ServiceError::Stale)?;
        let process = TaskKey {
            id: carrick_sched_core::process::TaskId::from_registry_allocation(id),
            serial: carrick_sched_core::process::TaskSerial::from_registry_allocation(serial),
        };
        self.bound_birth(process, thread, record)
            .map(|birth| birth.mm)
    }

    /// Caller holds the member reset reservation. An outstanding request
    /// refuses reset even if a physical metadata pin keeps its bytes mapped.
    pub fn reset_unpublished(&self) -> Result<(), ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, UNBOUND | IDLE) {
            return Err(ServiceError::Busy);
        }
        self.state
            .compare_exchange(state, UNBOUND, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ServiceError::Busy)?;
        Ok(())
    }
    pub fn publish(
        &self,
        birth: ServiceBirth,
        execution: SnapshotGeneration,
        operation: ServiceOperation,
        fault_sequence: Option<NonZeroU64>,
    ) -> Result<ServiceRequest, ServiceError> {
        self.publish_with_reply(birth, execution, operation, fault_sequence, None)
    }
    /// Reply storage belongs to the ring continuation through service ACK.
    /// The transport authenticates its retained allocation before accessing it.
    pub fn publish_with_reply(
        &self,
        birth: ServiceBirth,
        execution: SnapshotGeneration,
        operation: ServiceOperation,
        fault_sequence: Option<NonZeroU64>,
        reply: Option<carrick_guest_arch::KernelVa>,
    ) -> Result<ServiceRequest, ServiceError> {
        self.state
            .compare_exchange(IDLE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        if !execution.issued()
            || !self.same_birth(birth)
            || (fault_sequence.is_some() && !matches!(operation, ServiceOperation::Fault(_)))
            || (reply.is_some()
                && !matches!(
                    operation,
                    ServiceOperation::Fault(fault) if !fault.present && fault_sequence.is_some()
                )
                && !matches!(operation, ServiceOperation::Exec { .. }))
            || reply.is_some_and(|address| address.raw() == 0)
        {
            self.state.store(IDLE, Ordering::Release);
            return Err(ServiceError::Stale);
        }
        let Some(next) = self
            .sequence
            .load(Ordering::Relaxed)
            .checked_add(1)
            .and_then(NonZeroU64::new)
        else {
            self.state.store(IDLE, Ordering::Release);
            return Err(ServiceError::Exhausted);
        };
        let (kind, first, second) = match operation {
            ServiceOperation::Fault(fault) => (1, fault_bits(fault), fault.address.raw()),
            ServiceOperation::Crossing { ordinal } => (2, ordinal.raw(), 0),
            ServiceOperation::CarrierWork { entry } => {
                (3, u64::from(entry == OwnerEntry::Syscall), 0)
            }
            ServiceOperation::Exception(exception) => {
                (4, exception.kind.encode(), exception.address.raw())
            }
            ServiceOperation::Exec {
                capability: _,
                payload,
            } => (5, payload.address().raw(), payload.length().raw()),
        };
        for (index, value) in [(8, execution.raw()), (9, kind), (10, first), (11, second)] {
            self.words[index].store(value, Ordering::Relaxed);
        }
        // The request stamp and completion result occupy disjoint protocol
        // phases. Claim copies the stamp before acknowledgment writes a result.
        self.result.store(
            match operation {
                ServiceOperation::Exec { capability, .. } => capability.raw().get(),
                _ => fault_sequence.map_or(0, NonZeroU64::get),
            },
            Ordering::Relaxed,
        );
        self.wait_revision
            .store(reply.map_or(0, |address| address.raw()), Ordering::Relaxed);
        self.sequence.store(next.get(), Ordering::Relaxed);
        self.state.store(REQUESTED, Ordering::Release);
        Ok(ServiceRequest {
            identity: ServiceIdentity {
                birth,
                execution,
                sequence: next,
            },
            operation,
            fault_sequence,
        })
    }
    #[inline(never)]
    fn same_birth(&self, birth: ServiceBirth) -> bool {
        self.words
            .iter()
            .zip(birth.words())
            .all(|(word, value)| word.load(Ordering::Relaxed) == value)
    }
    #[inline(never)]
    fn same(&self, identity: ServiceIdentity) -> bool {
        self.same_birth(identity.birth)
            && self.words[8].load(Ordering::Relaxed) == identity.execution.raw()
            && self.sequence.load(Ordering::Relaxed) == identity.sequence.get()
    }
    #[inline(never)]
    fn lock_exact(&self, expected: u64, identity: ServiceIdentity) -> Result<(), ServiceError> {
        self.state
            .compare_exchange(expected, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Busy)?;
        if self.same(identity) {
            return Ok(());
        }
        self.state.store(expected, Ordering::Release);
        Err(ServiceError::Stale)
    }
    /// Claim a notice against its independently retained native member.
    ///
    /// # Safety
    /// `pin` must retain the exact control allocation of `member.record` in
    /// `carrier`. The caller holds that record's native-service queue lock.
    /// The native owner published the cell under its outstanding MM/lifecycle
    /// claim; cancellation cannot release that claim during this transition.
    pub unsafe fn claim_notice<P: Deref<Target = Self>>(
        pin: P,
        selector: ServiceSelector,
        carrier: NonZeroU64,
        member: carrick_sched_core::ThreadIdentity,
    ) -> Result<ServiceTicket<P>, ServiceError> {
        let cell = &*pin;
        let state = cell.state.load(Ordering::Acquire);
        if !matches!(state, REQUESTED | CANCEL_QUEUED) {
            return Err(ServiceError::Stale);
        }
        cell.state
            .compare_exchange(state, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ServiceError::Stale)?;
        let decoded = (|| {
            let incarnation = NonZeroU64::new(cell.words[7].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            let mm = crate::ReservationMm::new(member.mm).ok_or(ServiceError::Stale)?;
            // SAFETY: this is a copy of the admitted handle retained by the
            // ring's outstanding claim, not admission from a raw host request.
            let mm = unsafe { El1MmHandle::from_admitted_owner(carrier, mm, incarnation) };
            let process_id = i32::try_from(cell.words[1].load(Ordering::Relaxed))
                .ok()
                .and_then(core::num::NonZeroI32::new)
                .ok_or(ServiceError::Stale)?;
            let birth = NonZeroU64::new(cell.words[2].load(Ordering::Relaxed))
                .ok_or(ServiceError::Stale)?;
            let process = TaskKey {
                id: carrick_sched_core::process::TaskId::from_registry_allocation(process_id),
                serial: carrick_sched_core::process::TaskSerial::from_registry_allocation(birth),
            };
            let identity = ServiceIdentity {
                birth: ServiceBirth {
                    process,
                    thread: EntryThreadGeneration::from_raw(member.serial),
                    record: selector.record,
                    mm,
                },
                execution: selector.execution,
                sequence: selector.sequence,
            };
            if member.generation != selector.execution.raw() || !cell.same(identity) {
                return Err(ServiceError::Stale);
            }
            let first = cell.words[10].load(Ordering::Relaxed);
            let operation = match cell.words[9].load(Ordering::Relaxed) {
                1 if first <= 6 && first & 3 != 3 => ServiceOperation::Fault(FaultInfo {
                    address: carrick_guest_arch::UserVa::new(
                        cell.words[11].load(Ordering::Relaxed),
                    ),
                    access: match first & 3 {
                        0 => Access::Read,
                        1 => Access::Write,
                        _ => Access::Execute,
                    },
                    present: first & 4 != 0,
                }),
                2 => ServiceOperation::Crossing {
                    ordinal: NativeOrdinal::new(first),
                },
                3 if first <= 1 && cell.words[11].load(Ordering::Relaxed) == 0 => {
                    ServiceOperation::CarrierWork {
                        entry: if first == 1 {
                            OwnerEntry::Syscall
                        } else {
                            OwnerEntry::Exception
                        },
                    }
                }
                4 => ServiceOperation::Exception(NativeException {
                    kind: NativeExceptionKind::decode(first).ok_or(ServiceError::Stale)?,
                    address: carrick_guest_arch::UserVa::new(
                        cell.words[11].load(Ordering::Relaxed),
                    ),
                }),
                5 => ServiceOperation::Exec {
                    capability: ExecCapabilityId::new(
                        NonZeroU64::new(cell.result.load(Ordering::Relaxed))
                            .ok_or(ServiceError::Stale)?,
                    ),
                    payload: ExecPayloadDescriptor::checked(
                        GuestVa::new(first),
                        GuestLen::new(cell.words[11].load(Ordering::Relaxed)),
                    )
                    .ok_or(ServiceError::Stale)?,
                },
                _ => return Err(ServiceError::Stale),
            };
            let fault_sequence = if matches!(operation, ServiceOperation::Fault(_)) {
                NonZeroU64::new(cell.result.load(Ordering::Relaxed))
            } else {
                None
            };
            if fault_sequence.is_some() && !matches!(operation, ServiceOperation::Fault(_)) {
                return Err(ServiceError::Stale);
            }
            Ok(ServiceRequest {
                identity,
                operation,
                fault_sequence,
            })
        })();
        match decoded {
            Ok(request) => {
                cell.state.store(
                    if state == CANCEL_QUEUED {
                        CANCEL_REQUESTED
                    } else {
                        SERVICING
                    },
                    Ordering::Release,
                );
                Ok(ServiceTicket {
                    reply: NonZeroU64::new(cell.wait_revision.load(Ordering::Relaxed)),
                    cell: core::mem::ManuallyDrop::new(pin),
                    request,
                    selection_taken: false,
                })
            }
            Err(error) => {
                cell.state.store(state, Ordering::Release);
                Err(error)
            }
        }
    }

    /// The transport supplies the immutable copied request; claiming validates
    /// it under the cell transition before giving out one non-cloneable ticket.
    pub fn claim(&self, request: ServiceRequest) -> Result<ServiceTicket<&Self>, ServiceError> {
        Self::claim_owned(self, request)
    }

    /// Transfer an authenticated mapping pin into the unique operation ticket.
    /// The pin, unlike the executor's slot, lives through acknowledgment.
    pub fn claim_owned<P: Deref<Target = Self>>(
        pin: P,
        request: ServiceRequest,
    ) -> Result<ServiceTicket<P>, ServiceError> {
        let cell = &*pin;
        let state = cell.state.load(Ordering::Acquire);
        if !matches!(state, REQUESTED | CANCEL_QUEUED) {
            return Err(ServiceError::Busy);
        }
        cell.lock_exact(state, request.identity)?;
        let operation_matches = match request.operation {
            ServiceOperation::Fault(fault) => {
                cell.words[9].load(Ordering::Relaxed) == 1
                    && cell.words[10].load(Ordering::Relaxed) == fault_bits(fault)
                    && cell.words[11].load(Ordering::Relaxed) == fault.address.raw()
            }
            ServiceOperation::Crossing { ordinal } => {
                cell.words[9].load(Ordering::Relaxed) == 2
                    && cell.words[10].load(Ordering::Relaxed) == ordinal.raw()
            }
            ServiceOperation::CarrierWork { entry } => {
                cell.words[9].load(Ordering::Relaxed) == 3
                    && cell.words[10].load(Ordering::Relaxed)
                        == u64::from(entry == OwnerEntry::Syscall)
                    && cell.words[11].load(Ordering::Relaxed) == 0
            }
            ServiceOperation::Exception(exception) => {
                cell.words[9].load(Ordering::Relaxed) == 4
                    && cell.words[10].load(Ordering::Relaxed) == exception.kind.encode()
                    && cell.words[11].load(Ordering::Relaxed) == exception.address.raw()
            }
            ServiceOperation::Exec {
                capability,
                payload,
            } => {
                cell.words[9].load(Ordering::Relaxed) == 5
                    && cell.words[10].load(Ordering::Relaxed) == payload.address().raw()
                    && cell.words[11].load(Ordering::Relaxed) == payload.length().raw()
                    && cell.result.load(Ordering::Relaxed) == capability.raw().get()
            }
        };
        if !operation_matches
            || (!matches!(request.operation, ServiceOperation::Exec { .. })
                && cell.result.load(Ordering::Relaxed)
                    != request.fault_sequence.map_or(0, NonZeroU64::get))
        {
            cell.state.store(state, Ordering::Release);
            return Err(ServiceError::Stale);
        }
        cell.state.store(
            if state == CANCEL_QUEUED {
                CANCEL_REQUESTED
            } else {
                SERVICING
            },
            Ordering::Release,
        );
        Ok(ServiceTicket {
            reply: NonZeroU64::new(cell.wait_revision.load(Ordering::Relaxed)),
            cell: core::mem::ManuallyDrop::new(pin),
            request,
            selection_taken: false,
        })
    }
    /// Return true only when no host operation remains. Cancellation of an
    /// active ticket needs the ticket's acknowledgment, retaining all custody.
    pub fn cancel(&self, identity: ServiceIdentity) -> Result<bool, ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        match state {
            IDLE => {
                // Consumption and graph removal are separate owner steps.
                // Under the operation queue lock, cancellation may observe
                // that acknowledged sequence between those steps.
                self.lock_exact(IDLE, identity)?;
                self.state.store(IDLE, Ordering::Release);
                Ok(true)
            }
            OWNED_WAIT | WAIT_CANCELLED => {
                self.lock_exact(state, identity)?;
                self.state.store(WAIT_CANCELLED, Ordering::Release);
                Ok(true)
            }
            REQUESTED | CANCEL_QUEUED | SERVICING | CANCEL_REQUESTED | COMPLETED | CANCELLED => {
                self.lock_exact(state, identity)?;
                let acknowledged = matches!(state, COMPLETED | CANCELLED);
                self.state.store(
                    if acknowledged {
                        CANCELLED
                    } else if matches!(state, REQUESTED | CANCEL_QUEUED) {
                        CANCEL_QUEUED
                    } else {
                        CANCEL_REQUESTED
                    },
                    Ordering::Release,
                );
                Ok(acknowledged)
            }
            _ => Err(ServiceError::Busy),
        }
    }
    /// Roll back a request whose transport publication failed.
    ///
    /// # Safety
    /// No notice or ticket for this identity may have been delivered. Once a
    /// notice is published, even cancellation must wait for physical intake.
    pub unsafe fn abort_unpublished(&self, identity: ServiceIdentity) -> Result<(), ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, REQUESTED | CANCEL_QUEUED) {
            return Err(ServiceError::Busy);
        }
        self.lock_exact(state, identity)?;
        self.state.store(CANCELLED, Ordering::Release);
        Ok(())
    }

    /// The ring consumes exactly one acknowledged operation before releasing
    /// its retained MM/member capabilities or deciding a guest-visible result.
    pub fn consume(&self, identity: ServiceIdentity) -> Result<ServiceResult, ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, COMPLETED | CANCELLED) {
            return Err(ServiceError::Busy);
        }
        self.lock_exact(state, identity)?;
        let result = if state == CANCELLED {
            ServiceResult::Cancelled
        } else if self.result.load(Ordering::Relaxed) == 16 {
            ServiceResult::BackingFault
        } else if self.result.load(Ordering::Relaxed) == 1 {
            ServiceResult::Supplied
        } else if let Some(receipt) = decode_exec_prepared(self.result.load(Ordering::Relaxed)) {
            ServiceResult::ExecPrepared(receipt)
        } else if let Some(failure) = decode_failure(self.result.load(Ordering::Relaxed)) {
            ServiceResult::Failed(failure)
        } else if let Some(cause) =
            crate::PortalWaitCause::decode(self.result.load(Ordering::Relaxed).saturating_sub(2))
        {
            // SAFETY: complete_wait checked the retained exact MM identity;
            // the service ticket supplies its pre-probe resource revision.
            ServiceResult::Wait(unsafe {
                crate::PortalOwnerWait::from_owner(
                    identity.birth.mm,
                    cause,
                    self.wait_revision.load(Ordering::Relaxed),
                )
            })
        } else {
            ServiceResult::Refused
        };
        self.state.store(
            if matches!(result, ServiceResult::Wait(_)) {
                OWNED_WAIT
            } else {
                IDLE
            },
            Ordering::Release,
        );
        Ok(result)
    }
    /// Reserve a ring-owned resource wait without publishing external work.
    /// Caller holds the member service queue across request/phase publication.
    pub fn begin_owner_wait(
        &self,
        birth: ServiceBirth,
        execution: SnapshotGeneration,
        operation: ServiceOperation,
        wait: crate::PortalOwnerWait,
    ) -> Result<ServiceRequest, ServiceError> {
        if wait.handle() != birth.mm {
            return Err(ServiceError::Stale);
        }
        let request = self.publish(birth, execution, operation, None)?;
        self.lock_exact(REQUESTED, request.identity)?;
        self.result
            .store(2 + wait.cause().encode(), Ordering::Relaxed);
        self.wait_revision.store(wait.revision(), Ordering::Relaxed);
        self.state.store(OWNED_WAIT, Ordering::Release);
        Ok(request)
    }
    /// Inspect sticky cancellation under the stable member service queue.
    pub fn owner_wait_cancelled(&self, identity: ServiceIdentity) -> Result<bool, ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, OWNED_WAIT | WAIT_CANCELLED) {
            return Err(ServiceError::Busy);
        }
        self.lock_exact(state, identity)?;
        self.state.store(state, Ordering::Release);
        Ok(state == WAIT_CANCELLED)
    }
    /// Consume the one owner wait after its producer edge or cancellation.
    /// No external ticket or second acknowledgment exists for this phase.
    pub fn finish_owner_wait(
        &self,
        identity: ServiceIdentity,
    ) -> Result<ServiceResult, ServiceError> {
        let state = self.state.load(Ordering::Acquire);
        if !matches!(state, OWNED_WAIT | WAIT_CANCELLED) {
            return Err(ServiceError::Busy);
        }
        self.lock_exact(state, identity)?;
        self.state.store(IDLE, Ordering::Release);
        Ok(if state == WAIT_CANCELLED {
            ServiceResult::Cancelled
        } else {
            ServiceResult::Supplied
        })
    }
}
/// Dropping a transport handle is not completion: it leaves the operation and
/// its retained resources outstanding. Only explicit acknowledgment releases it.
#[must_use]
pub struct ServiceTicket<P: Deref<Target = ServiceCell>> {
    cell: core::mem::ManuallyDrop<P>,
    request: ServiceRequest,
    selection_taken: bool,
    // Preserve NonZeroU64's niche instead of expanding an optional domain
    // wrapper inside every retained service ticket.
    reply: Option<NonZeroU64>,
}
#[allow(
    clippy::result_large_err,
    reason = "the linear ticket must be returned on refusal so exact service custody is never lost"
)]
impl<P: Deref<Target = ServiceCell>> ServiceTicket<P> {
    pub fn reply_address(&self) -> Option<carrick_guest_arch::KernelVa> {
        self.reply
            .map(|address| carrick_guest_arch::KernelVa::new(address.get()))
    }

    pub fn request(&self) -> ServiceRequest {
        self.request
    }
    /// Claim at most one lane selection before the transport releases that
    /// execution lane. The ticket cannot later consume a successor's window.
    pub fn take_fault_selection(
        &mut self,
        slot: &crate::PortalGrantSlot,
    ) -> Result<Option<ServiceFaultSupply>, ServiceError> {
        if self.selection_taken {
            return Err(ServiceError::Stale);
        }
        self.selection_taken = true;
        slot.take_native_fault_selection(self)
    }
    pub fn complete_backing_fault(self) -> Result<(), (ServiceError, Self)> {
        if !matches!(self.request().operation, ServiceOperation::Fault(fault) if !fault.present) {
            return Err((ServiceError::Stale, self));
        }
        self.acknowledge(16, 0)
    }
    pub fn complete(self, supplied: bool) -> Result<(), (ServiceError, Self)> {
        self.acknowledge(u64::from(supplied), 0)
    }
    pub fn complete_failure(self, failure: ServiceFailureCode) -> Result<(), (ServiceError, Self)> {
        self.acknowledge(FAILURE_TAG | u64::from(failure.raw()), 0)
    }
    /// Acknowledge physical service and transfer the same continuation to an
    /// exact-MM producer. No physical resource guard survives this call.
    pub fn complete_wait(self, wait: crate::PortalOwnerWait) -> Result<(), (ServiceError, Self)> {
        if wait.handle() != self.request.identity.birth.mm {
            return Err((ServiceError::Stale, self));
        }
        self.acknowledge(2 + wait.cause().encode(), wait.revision())
    }
    /// Transfer a prepared result to its established owner before publishing
    /// the exact completion. The transfer must be a bounded, infallible custody
    /// handoff; all I/O, allocation and fallible preparation precede this call.
    ///
    /// This is delivery, not process/MM adoption. The receiving owner retains
    /// the result even if the ring cancels after delivery. On cancellation
    /// before delivery no callback runs and no acknowledgment is published:
    /// the returned ticket must survive rollback (including cleanup refusal).
    pub fn publish_prepared<T>(
        mut self,
        prepared: T,
        transfer: impl FnOnce(T),
    ) -> Result<(), (PreparedDeliveryError, Self, T)> {
        let cancelled = match self.reserve_acknowledgment() {
            Ok(cancelled) => cancelled,
            Err(error) => return Err((PreparedDeliveryError::Service(error), self, prepared)),
        };
        if cancelled {
            self.cell.state.store(CANCEL_REQUESTED, Ordering::Release);
            return Err((PreparedDeliveryError::Cancelled, self, prepared));
        }
        transfer(prepared);
        self.finish_acknowledgment(1, 0, false);
        Ok(())
    }

    /// Transfer one prepared exec image and publish the carrier-minted,
    /// single-consumption receipt that selects it. The transfer callback must
    /// bind the receipt to this ticket's exact identity before it returns.
    pub fn publish_exec_prepared<T>(
        mut self,
        receipt: ExecAdoptionReceipt,
        prepared: T,
        transfer: impl FnOnce(ExecAdoptionReceipt, T),
    ) -> Result<(), (PreparedDeliveryError, Self, T)> {
        if !matches!(self.request.operation, ServiceOperation::Exec { .. }) {
            return Err((
                PreparedDeliveryError::Service(ServiceError::Stale),
                self,
                prepared,
            ));
        }
        let cancelled = match self.reserve_acknowledgment() {
            Ok(cancelled) => cancelled,
            Err(error) => return Err((PreparedDeliveryError::Service(error), self, prepared)),
        };
        if cancelled {
            self.cell.state.store(CANCEL_REQUESTED, Ordering::Release);
            return Err((PreparedDeliveryError::Cancelled, self, prepared));
        }
        transfer(receipt, prepared);
        self.finish_acknowledgment(EXEC_PREPARED_TAG | receipt.raw().get(), 0, false);
        Ok(())
    }

    fn reserve_acknowledgment(&self) -> Result<bool, ServiceError> {
        let cell = &**self.cell;
        let state = cell.state.load(Ordering::Acquire);
        if !matches!(state, SERVICING | CANCEL_REQUESTED) {
            return Err(if state == WRITING {
                ServiceError::Busy
            } else {
                ServiceError::Stale
            });
        }
        cell.lock_exact(state, self.request.identity)?;
        Ok(state == CANCEL_REQUESTED)
    }

    fn acknowledge(mut self, result: u64, revision: u64) -> Result<(), (ServiceError, Self)> {
        let cancelled = match self.reserve_acknowledgment() {
            Ok(cancelled) => cancelled,
            Err(error) => return Err((error, self)),
        };
        self.finish_acknowledgment(result, revision, cancelled);
        Ok(())
    }

    fn finish_acknowledgment(&mut self, result: u64, revision: u64, cancelled: bool) {
        let cell = &**self.cell;
        cell.result.store(result, Ordering::Relaxed);
        cell.wait_revision.store(revision, Ordering::Relaxed);
        cell.state.store(
            if cancelled { CANCELLED } else { COMPLETED },
            Ordering::Release,
        );
        // Only acknowledgment releases the physical mapping pin. Every caller
        // first reserves the exact request and consumes this ticket on success.
        // SAFETY: ManuallyDrop has no drop glue, and a successful acknowledgment
        // is the terminal operation on this ticket.
        unsafe { core::mem::ManuallyDrop::drop(&mut self.cell) };
    }
}

fn fault_bits(fault: FaultInfo) -> u64 {
    let access = match fault.access {
        Access::Read => 0,
        Access::Write => 1,
        Access::Execute => 2,
    };
    access | (u64::from(fault.present) << 2)
}

const FAILURE_TAG: u64 = 1 << 63;
const EXEC_PREPARED_TAG: u64 = 1 << 62;
const EXEC_PREPARED_VALUE_MASK: u64 = EXEC_PREPARED_TAG - 1;
fn decode_exec_prepared(raw: u64) -> Option<ExecAdoptionReceipt> {
    (raw & (FAILURE_TAG | EXEC_PREPARED_TAG) == EXEC_PREPARED_TAG)
        .then(|| NonZeroU64::new(raw & EXEC_PREPARED_VALUE_MASK))
        .flatten()
        .and_then(ExecAdoptionReceipt::checked)
}
fn decode_failure(raw: u64) -> Option<ServiceFailureCode> {
    (raw & FAILURE_TAG != 0)
        .then(|| u32::try_from(raw & !FAILURE_TAG).ok())
        .flatten()
        .and_then(ServiceFailureCode::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_arch::UserVa;
    use carrick_sched_core::{
        RecordId,
        process::{TaskId, TaskSerial},
    };
    use core::num::NonZeroI32;

    fn birth(id: u32, generation: u64) -> ServiceBirth {
        let generation = NonZeroU64::new(generation).unwrap();
        ServiceBirth {
            process: TaskKey {
                id: TaskId::from_registry_allocation(NonZeroI32::new(id as i32).unwrap()),
                serial: TaskSerial::from_registry_allocation(generation),
            },
            thread: EntryThreadGeneration::from_raw(generation.get()),
            record: RecordRef {
                id: RecordId::from_raw(id).unwrap(),
                incarnation: generation.get(),
            },
            // SAFETY: this wire-protocol fixture owns an immutable, never-reused
            // synthetic MM identity. It does not authorize a memory operation.
            mm: unsafe {
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::MIN,
                    crate::ReservationMm::new(u64::from(id)).unwrap(),
                    generation,
                )
            },
        }
    }
    fn fault() -> ServiceOperation {
        ServiceOperation::Fault(FaultInfo {
            address: UserVa::new(0x6000000fd8),
            access: Access::Write,
            present: true,
        })
    }

    fn exec_payload(address: u64, bytes: u64) -> ExecPayloadDescriptor {
        ExecPayloadDescriptor::checked(
            carrick_guest_arch::GuestVa::new(address),
            carrick_guest_arch::GuestLen::new(bytes),
        )
        .unwrap()
    }
    fn exec_capability() -> ExecCapabilityId {
        ExecCapabilityId::new(NonZeroU64::new(17).unwrap())
    }

    #[test]
    fn exec_payload_round_trips_without_fixed_word_truncation() {
        let cell = ServiceCell::new();
        let owner = birth(1, 7);
        cell.bind(owner).unwrap();
        let payload = exec_payload(0x4000_0000, 2 * 1024 * 1024);
        let request = cell
            .publish(
                owner,
                SnapshotGeneration::INITIAL,
                ServiceOperation::Exec {
                    capability: exec_capability(),
                    payload,
                },
                None,
            )
            .unwrap();
        let ticket = cell.claim(request).unwrap();
        assert_eq!(
            ticket.request().operation,
            ServiceOperation::Exec {
                capability: exec_capability(),
                payload,
            }
        );
        assert!(ticket.complete(true).is_ok());
        assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Supplied));
    }

    #[test]
    fn exec_preparation_returns_one_typed_adoption_receipt() {
        let cell = ServiceCell::new();
        let owner = birth(1, 7);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(
                owner,
                SnapshotGeneration::INITIAL,
                ServiceOperation::Exec {
                    capability: exec_capability(),
                    payload: exec_payload(0x4000_0000, 4096),
                },
                None,
            )
            .unwrap();
        let receipt = ExecAdoptionReceipt::checked(NonZeroU64::new(41).unwrap()).unwrap();
        let mut delivered = None;
        assert!(
            cell.claim(request)
                .unwrap()
                .publish_exec_prepared(receipt, 17u8, |receipt, resource| {
                    delivered = Some((receipt, resource));
                })
                .is_ok()
        );
        assert_eq!(delivered, Some((receipt, 17)));
        assert_eq!(
            cell.consume(request.identity),
            Ok(ServiceResult::ExecPrepared(receipt))
        );
        assert_eq!(cell.consume(request.identity), Err(ServiceError::Busy));
    }

    #[test]
    fn exec_successor_manifest_is_exactly_bound_and_torn_records_refuse() {
        let identity = ServiceIdentity {
            birth: birth(17, 23),
            execution: SnapshotGeneration::from_raw(29),
            sequence: NonZeroU64::new(31).unwrap(),
        };
        let successor = ReservationMm::new(37).unwrap();
        let proposal = ExecSuccessorManifest::propose(identity, successor);
        assert_eq!(proposal.proposal(identity), Some(successor));

        let receipt = ExecAdoptionReceipt::checked(NonZeroU64::new(41).unwrap()).unwrap();
        let root =
            carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x90_0000))
                .unwrap();
        let root_generation = NonZeroU64::new(43).unwrap();
        let asid = carrick_guest_arch::Asid::from_registry_allocation(
            core::num::NonZeroU16::new(47).unwrap(),
        );
        let asid_generation = NonZeroU64::new(53).unwrap();
        let entry = carrick_guest_arch::UserVa::new(0x40_0000);
        let stack_pointer = carrick_guest_arch::UserVa::new(0x7fff_f000);
        let sealed = proposal
            .seal(
                identity,
                receipt,
                ExecSuccessorBacking {
                    root,
                    root_generation,
                    asid,
                    asid_generation,
                },
                ExecSuccessorEntry {
                    entry,
                    stack_pointer,
                },
            )
            .unwrap();
        assert_eq!(
            sealed.open(identity, receipt),
            Some(ExecSuccessorManifestView {
                successor_mm: successor,
                root,
                root_generation,
                asid,
                asid_generation,
                entry,
                stack_pointer,
            })
        );
        let mut stale = identity;
        stale.sequence = NonZeroU64::new(59).unwrap();
        assert_eq!(sealed.open(stale, receipt), None);
        let other = ExecAdoptionReceipt::checked(NonZeroU64::new(61).unwrap()).unwrap();
        assert_eq!(sealed.open(identity, other), None);

        let mut torn = sealed;
        torn.root_generation = 67;
        assert_eq!(torn.open(identity, receipt), None);
    }

    #[test]
    fn exec_payload_rejects_zero_overflow_and_arg_max_excess() {
        use carrick_guest_arch::{GuestLen, GuestVa};
        let max = GuestLen::new(MAX_EXEC_PAYLOAD_BYTES);
        assert!(ExecPayloadDescriptor::checked(GuestVa::new(0x1000), GuestLen::new(0)).is_none());
        assert!(ExecPayloadDescriptor::checked(GuestVa::new(u64::MAX), GuestLen::new(2)).is_none());
        assert!(
            ExecPayloadDescriptor::checked(GuestVa::new(0x1000), GuestLen::new(max.raw() + 1),)
                .is_none()
        );
    }

    #[test]
    fn exec_failure_preserves_the_exact_errno_number() {
        let cell = ServiceCell::new();
        let owner = birth(1, 9);
        cell.bind(owner).unwrap();
        for errno in [2, 13, 8] {
            let request = cell
                .publish(
                    owner,
                    SnapshotGeneration::INITIAL,
                    ServiceOperation::Exec {
                        capability: exec_capability(),
                        payload: exec_payload(0x5000_0000, 64),
                    },
                    None,
                )
                .unwrap();
            let failure = ServiceFailureCode::new(errno).unwrap();
            assert!(
                cell.claim(request)
                    .unwrap()
                    .complete_failure(failure)
                    .is_ok()
            );
            assert_eq!(
                cell.consume(request.identity),
                Ok(ServiceResult::Failed(failure))
            );
        }
    }

    #[test]
    fn exec_claim_rejects_old_mm_and_sequence() {
        let cell = ServiceCell::new();
        let owner = birth(1, 11);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(
                owner,
                SnapshotGeneration::INITIAL,
                ServiceOperation::Exec {
                    capability: exec_capability(),
                    payload: exec_payload(0x6000_0000, 256),
                },
                None,
            )
            .unwrap();
        let mut stale = request;
        stale.identity.birth.mm = birth(1, 10).mm;
        assert!(matches!(cell.claim(stale), Err(ServiceError::Stale)));
        stale = request;
        stale.identity.sequence = NonZeroU64::new(request.identity.sequence.get() + 1).unwrap();
        assert!(matches!(cell.claim(stale), Err(ServiceError::Stale)));
        stale = request;
        let ServiceOperation::Exec { payload, .. } = stale.operation else {
            unreachable!();
        };
        stale.operation = ServiceOperation::Exec {
            capability: ExecCapabilityId::new(NonZeroU64::new(18).unwrap()),
            payload,
        };
        assert!(matches!(cell.claim(stale), Err(ServiceError::Stale)));
        assert!(cell.claim(request).unwrap().complete(true).is_ok());
    }

    #[test]
    fn prepared_delivery_retains_cancelled_resources_until_cleanup_ack() {
        use alloc::sync::Arc;
        use core::sync::atomic::AtomicUsize;
        struct Prepared(Arc<AtomicUsize>);
        impl Drop for Prepared {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let first = Arc::new(ServiceCell::new());
        let second = Arc::new(ServiceCell::new());
        let a = birth(1, 1);
        let b = birth(2, 1);
        first.bind(a).unwrap();
        second.bind(b).unwrap();
        let a_request = first
            .publish(a, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let b_request = second
            .publish(b, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let a_ticket = ServiceCell::claim_owned(first.clone(), a_request).unwrap();
        let b_ticket = ServiceCell::claim_owned(second.clone(), b_request).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        assert!(!first.cancel(a_request.identity).unwrap());
        let failed = a_ticket.publish_prepared(Prepared(drops.clone()), |_| {
            panic!("cancelled result must never publish");
        });
        let Err((PreparedDeliveryError::Cancelled, ticket, prepared)) = failed else {
            panic!("cancelled delivery must return its complete custody");
        };
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(Arc::strong_count(&first), 2);
        assert_eq!(first.consume(a_request.identity), Err(ServiceError::Busy));
        // Another operation can transfer custody while cleanup remains pending.
        let mut published = None;
        assert!(
            b_ticket
                .publish_prepared(Prepared(drops.clone()), |resource| {
                    published = Some(resource);
                })
                .is_ok()
        );
        assert_eq!(
            second.consume(b_request.identity),
            Ok(ServiceResult::Supplied)
        );
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        // Cleanup refusal simply keeps these owners: there is no premature ACK.
        assert_eq!(first.reset_unpublished(), Err(ServiceError::Busy));
        drop(prepared);
        assert!(ticket.complete(false).is_ok());
        assert_eq!(
            first.consume(a_request.identity),
            Ok(ServiceResult::Cancelled)
        );
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        drop(published);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn prepared_delivery_rejects_old_mm_and_sequence_without_losing_custody() {
        let cell = ServiceCell::new();
        let owner = birth(1, 2);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let mut ticket = cell.claim(request).unwrap();
        for stale_mm in [true, false] {
            if stale_mm {
                ticket.request.identity.birth.mm = birth(1, 1).mm;
            } else {
                ticket.request.identity.sequence = NonZeroU64::new(2).unwrap();
            }
            let Err((PreparedDeliveryError::Service(ServiceError::Stale), returned, resource)) =
                ticket.publish_prepared(42, |_| panic!("stale result published"))
            else {
                panic!("stale delivery lost its owners")
            };
            assert_eq!(resource, 42);
            assert_eq!(cell.consume(request.identity), Err(ServiceError::Busy));
            ticket = returned;
            ticket.request = request;
        }
        let mut retained = None;
        assert!(
            ticket
                .publish_prepared(42, |resource| {
                    // No cancellation/consumption can cut between custody transfer and ACK.
                    assert_eq!(cell.cancel(request.identity), Err(ServiceError::Busy));
                    assert_eq!(cell.consume(request.identity), Err(ServiceError::Busy));
                    retained = Some(resource);
                })
                .is_ok()
        );
        // A later cancellation belongs to the recipient, which still owns the result.
        assert!(cell.cancel(request.identity).unwrap());
        assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Cancelled));
        assert_eq!(retained.take(), Some(42));
    }

    #[test]
    fn two_service_cells_cancel_one_without_consuming_the_other() {
        let first = ServiceCell::new();
        let second = ServiceCell::new();
        let first_birth = birth(1, 1);
        let second_birth = birth(2, 1);
        first.bind(first_birth).unwrap();
        second.bind(second_birth).unwrap();
        let a = first
            .publish(first_birth, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let b = second
            .publish(second_birth, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let a_ticket = first.claim(a).unwrap();
        let b_ticket = second.claim(b).unwrap();
        assert!(!first.cancel(a.identity).unwrap());
        assert_eq!(first.consume(a.identity), Err(ServiceError::Busy));
        assert_eq!(first.reset_unpublished(), Err(ServiceError::Busy));
        assert!(b_ticket.complete(true).is_ok());
        assert_eq!(second.consume(b.identity), Ok(ServiceResult::Supplied));
        assert_eq!(first.consume(a.identity), Err(ServiceError::Busy));
        assert!(a_ticket.complete(true).is_ok());
        assert_eq!(first.consume(a.identity), Ok(ServiceResult::Cancelled));
        assert_eq!(first.consume(a.identity), Err(ServiceError::Busy));
        assert_eq!(second.consume(b.identity), Err(ServiceError::Busy));
    }

    #[test]
    fn consumed_request_cancellation_does_not_cancel_its_successor() {
        let cell = ServiceCell::new();
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        let first = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        assert!(cell.claim(first).unwrap().complete(true).is_ok());
        assert_eq!(cell.consume(first.identity), Ok(ServiceResult::Supplied));
        assert_eq!(cell.cancel(first.identity), Ok(true));
        let next = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        assert_eq!(cell.cancel(first.identity), Err(ServiceError::Stale));
        assert!(cell.claim(next).unwrap().complete(true).is_ok());
        assert_eq!(cell.consume(next.identity), Ok(ServiceResult::Supplied));
    }

    #[test]
    fn owned_ticket_keeps_backing_until_acknowledgment() {
        use alloc::sync::Arc;
        let cell = Arc::new(ServiceCell::new());
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        let ticket = ServiceCell::claim_owned(cell.clone(), request).unwrap();
        assert_eq!(Arc::strong_count(&cell), 2);
        assert!(!cell.cancel(request.identity).unwrap());
        assert_eq!(Arc::strong_count(&cell), 2);
        assert!(ticket.complete(true).is_ok());
        assert_eq!(Arc::strong_count(&cell), 1);
        assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Cancelled));
    }

    #[test]
    fn recycled_birth_rejects_old_request_and_keeps_monotone_sequence() {
        let cell = ServiceCell::new();
        let old_birth = birth(1, 1);
        cell.bind(old_birth).unwrap();
        let old = cell
            .publish(old_birth, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        assert!(!cell.cancel(old.identity).unwrap());
        assert_eq!(cell.consume(old.identity), Err(ServiceError::Busy));
        assert!(cell.claim(old).unwrap().complete(false).is_ok());
        assert_eq!(cell.consume(old.identity), Ok(ServiceResult::Cancelled));
        cell.reset_unpublished().unwrap();
        let new_birth = birth(1, 2);
        cell.bind(new_birth).unwrap();
        assert_eq!(
            cell.bound_birth(old_birth.process, old_birth.thread, old_birth.record),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            cell.bound_birth(new_birth.process, old_birth.thread, new_birth.record),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            cell.bound_birth(new_birth.process, new_birth.thread, old_birth.record),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            cell.bound_birth(new_birth.process, new_birth.thread, new_birth.record),
            Ok(new_birth)
        );
        let new = cell
            .publish(new_birth, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        assert!(new.identity.sequence > old.identity.sequence);
        assert!(matches!(cell.claim(old), Err(ServiceError::Stale)));
        let mut wrong = new;
        wrong.identity.execution = SnapshotGeneration::from_raw(2);
        assert!(matches!(cell.claim(wrong), Err(ServiceError::Stale)));
        wrong = new;
        wrong.operation = ServiceOperation::Crossing {
            ordinal: NativeOrdinal::new(57),
        };
        assert!(matches!(cell.claim(wrong), Err(ServiceError::Stale)));
        let ticket = cell.claim(new).unwrap();
        assert!(ticket.complete(false).is_ok());
        assert_eq!(cell.consume(old.identity), Err(ServiceError::Stale));
        assert_eq!(cell.consume(new.identity), Ok(ServiceResult::Refused));
    }
    #[test]
    fn backing_reply_is_bound_to_the_claimed_request_phase() {
        let cell = ServiceCell::new();
        let birth = birth(1, 1);
        cell.bind(birth).unwrap();
        let operation = ServiceOperation::Fault(FaultInfo {
            address: UserVa::new(0x4000),
            access: Access::Read,
            present: false,
        });
        let address = carrick_guest_arch::KernelVa::new(0x10000);
        let request = cell
            .publish_with_reply(
                birth,
                SnapshotGeneration::INITIAL,
                operation,
                Some(NonZeroU64::MIN),
                Some(address),
            )
            .unwrap();
        let ticket = cell.claim(request).unwrap();
        assert_eq!(ticket.reply_address(), Some(address));
        assert!(ticket.complete_backing_fault().is_ok());
        assert_eq!(
            cell.consume(request.identity),
            Ok(ServiceResult::BackingFault)
        );
        let request = cell
            .publish(birth, SnapshotGeneration::INITIAL, operation, None)
            .unwrap();
        let ticket = cell.claim(request).unwrap();
        assert_eq!(
            ticket.reply_address(),
            None,
            "successor cannot inherit the previous buffer"
        );
        assert!(ticket.complete(false).is_ok());
        assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Refused));
    }

    #[test]
    fn native_exception_kinds_round_trip_through_notice_claim() {
        let cell = ServiceCell::new();
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        for (index, kind) in [
            NativeExceptionKind::Breakpoint,
            NativeExceptionKind::SingleStep,
            NativeExceptionKind::HardwareBreakpoint,
            NativeExceptionKind::UndefinedInstruction,
            NativeExceptionKind::Alignment,
            NativeExceptionKind::FloatingPoint,
        ]
        .into_iter()
        .enumerate()
        {
            let operation = ServiceOperation::Exception(NativeException {
                kind,
                address: UserVa::new(0x4000 + index as u64 * 4),
            });
            let request = cell
                .publish(owner, SnapshotGeneration::INITIAL, operation, None)
                .unwrap();
            let member = carrick_sched_core::ThreadIdentity {
                tid: 1,
                serial: owner.thread.raw(),
                mm: owner.mm.mm().raw(),
                generation: SnapshotGeneration::INITIAL.raw(),
                ..Default::default()
            };
            // SAFETY: the local cell and synthetic exact member remain alive
            // for the claim and use the same immutable birth identity.
            let ticket = unsafe {
                ServiceCell::claim_notice(
                    &cell,
                    request.identity.into(),
                    owner.mm.carrier(),
                    member,
                )
            }
            .unwrap();
            assert_eq!(ticket.request().operation, operation);
            assert!(ticket.complete(false).is_ok());
            assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Refused));
        }
    }

    fn supply_window(owner: ServiceBirth) -> crate::PortalGrantWindow {
        let page = match fault() {
            ServiceOperation::Fault(fault) => fault.address.raw() & !4095,
            _ => unreachable!(),
        };
        crate::PortalGrantWindow {
            operation: crate::PortalOperation {
                carrier: owner.mm.carrier(),
                mm: owner.mm.mm(),
                incarnation: owner.mm.incarnation(),
                sequence: NonZeroU64::MIN,
            },
            mapping_incarnation: crate::ReservationIncarnation::new(1).unwrap(),
            range: crate::ReservationRange::new(page, page + 4096).unwrap(),
            protection: crate::ReservationProtection::from_bits(3).unwrap(),
            fault_page: page,
            host_backing: None,
            fork_sequence: None,
        }
    }

    #[test]
    fn fault_supply_transfer_survives_lane_reuse_and_cancellation() {
        let slot = crate::PortalGrantSlot::new();
        let first = ServiceCell::new();
        let second = ServiceCell::new();
        let a = birth(1, 1);
        let b = birth(2, 1);
        first.bind(a).unwrap();
        second.bind(b).unwrap();
        let a_request = first
            .publish(
                a,
                SnapshotGeneration::INITIAL,
                fault(),
                Some(NonZeroU64::MIN),
            )
            .unwrap();
        let b_request = second
            .publish(b, SnapshotGeneration::INITIAL, fault(), NonZeroU64::new(2))
            .unwrap();
        let mut a_ticket = first.claim(a_request).unwrap();
        let mut b_ticket = second.claim(b_request).unwrap();
        let a_window = supply_window(a);
        let mut b_window = supply_window(b);
        b_window.operation.sequence = NonZeroU64::new(2).unwrap();
        assert!(slot.publish_cow_fault_selection(1, a_window));
        assert_eq!(
            a_ticket.take_fault_selection(&slot),
            Ok(Some(ServiceFaultSupply::Cow(a_window)))
        );
        assert!(!slot.has_outstanding_for(a.mm.mm().raw()));
        assert!(!first.cancel(a_request.identity).unwrap());
        assert_eq!(first.consume(a_request.identity), Err(ServiceError::Busy));
        assert!(slot.publish_fault_selection(2, b_window));
        assert_eq!(
            a_ticket.take_fault_selection(&slot),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            slot.pending_fault_selection(b.mm.mm().raw(), b_window.fault_page),
            Some((2, b_window))
        );
        assert_eq!(
            b_ticket.take_fault_selection(&slot),
            Ok(Some(ServiceFaultSupply::Backing(b_window)))
        );
        assert!(b_ticket.complete(false).is_ok());
        assert_eq!(
            second.consume(b_request.identity),
            Ok(ServiceResult::Refused)
        );
        assert!(a_ticket.complete(true).is_ok());
        assert_eq!(
            first.consume(a_request.identity),
            Ok(ServiceResult::Cancelled)
        );
    }

    #[test]
    fn fault_supply_transfer_rejects_recycled_mm_incarnation() {
        let slot = crate::PortalGrantSlot::new();
        let cell = ServiceCell::new();
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(
                owner,
                SnapshotGeneration::INITIAL,
                fault(),
                Some(NonZeroU64::MIN),
            )
            .unwrap();
        let mut ticket = cell.claim(request).unwrap();
        let window = supply_window(birth(1, 2));
        assert!(slot.publish_cow_fault_selection(1, window));
        assert_eq!(ticket.take_fault_selection(&slot), Err(ServiceError::Stale));
        assert_eq!(
            slot.pending_cow_fault_selection(owner.mm.mm().raw(), window.fault_page),
            Some((1, window))
        );
        assert!(ticket.complete(false).is_ok());
        assert_eq!(cell.consume(request.identity), Ok(ServiceResult::Refused));
    }

    #[test]
    fn delayed_first_fault_take_cannot_steal_same_mm_page_successor() {
        let slot = crate::PortalGrantSlot::new();
        let first = ServiceCell::new();
        let second = ServiceCell::new();
        let a = birth(1, 1);
        let mut b = birth(2, 1);
        b.mm = a.mm;
        first.bind(a).unwrap();
        second.bind(b).unwrap();
        let a_request = first
            .publish(
                a,
                SnapshotGeneration::INITIAL,
                fault(),
                Some(NonZeroU64::MIN),
            )
            .unwrap();
        let b_request = second
            .publish(b, SnapshotGeneration::INITIAL, fault(), NonZeroU64::new(2))
            .unwrap();
        let mut old_ticket = first.claim(a_request).unwrap();
        let mut next_ticket = second.claim(b_request).unwrap();
        let mut successor = supply_window(b);
        successor.operation.sequence = NonZeroU64::new(2).unwrap();
        assert!(slot.publish_cow_fault_selection(2, successor));
        assert_eq!(
            old_ticket.take_fault_selection(&slot),
            Err(ServiceError::Stale)
        );
        assert_eq!(
            slot.pending_cow_fault_selection(a.mm.mm().raw(), successor.fault_page),
            Some((2, successor))
        );
        assert_eq!(
            next_ticket.take_fault_selection(&slot),
            Ok(Some(ServiceFaultSupply::Cow(successor)))
        );
        assert!(next_ticket.complete(false).is_ok());
        assert!(old_ticket.complete(false).is_ok());
        assert_eq!(
            first.consume(a_request.identity),
            Ok(ServiceResult::Refused)
        );
        assert_eq!(
            second.consume(b_request.identity),
            Ok(ServiceResult::Refused)
        );
    }
    #[test]
    fn mm_busy_ack_preserves_the_native_claim_until_its_owner_wakes() {
        let cell = ServiceCell::new();
        let owner = birth(1, 1);
        cell.bind(owner).unwrap();
        let request = cell
            .publish(owner, SnapshotGeneration::INITIAL, fault(), None)
            .unwrap();
        // SAFETY: fixture names its exact admitted source before the busy probe.
        let wait = unsafe {
            crate::PortalOwnerWait::from_owner(owner.mm, crate::PortalWaitCause::Editor, 7)
        };
        assert!(cell.claim(request).unwrap().complete_wait(wait).is_ok());
        assert_eq!(
            cell.consume(request.identity),
            Ok(ServiceResult::Wait(wait))
        );
        assert_eq!(cell.reset_unpublished(), Err(ServiceError::Busy));
    }
}
