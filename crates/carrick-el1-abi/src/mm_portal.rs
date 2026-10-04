//! Bounded host-to-owner UserTransfer records in the existing EL1 service ABI.
//! Physical storage custody outlives the request until exact completion has
//! settled. A dropped ticket never frees a slot or revokes its storage pin.
use crate::ReservationMm;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

// SELECT success carries the pre-selection Reservations observation in x16/x17.
pub const MM_PORTAL_PROTOCOL: u64 = 5;
pub const MM_PORTAL_MAX_BYTES: u64 = 4096;
pub const MM_PORTAL_BIND_ESR: u64 = 0x4352_4d4d_4249_0004;
/// A closed initial root's one-publication identity, minted only by the
/// holder of its unpublished address-space publication. It authorizes the
/// BIND service to authenticate a root before its installation gate opens;
/// the service rechecks that it is still never-opened and exact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortalClosedRootBind {
    carrier: NonZeroU64,
    mm: ReservationMm,
    ttbr0: u64,
}
impl PortalClosedRootBind {
    /// # Safety
    /// Only the exact unpublished initial address-space owner may mint this,
    /// after checking the still-closed slot and its MM/root identity.
    pub unsafe fn from_unpublished_owner(
        carrier: NonZeroU64,
        mm: ReservationMm,
        ttbr0: u64,
    ) -> Self {
        Self { carrier, mm, ttbr0 }
    }
    pub const fn carrier(self) -> NonZeroU64 {
        self.carrier
    }
    pub const fn mm(self) -> ReservationMm {
        self.mm
    }
    pub const fn ttbr0(self) -> u64 {
        self.ttbr0
    }
}
/// Identity of an admitted owner. It contains no editor, table, or host pointer.
///
/// Safe callers cannot manufacture admitted ownership.
/// ```compile_fail
/// use carrick_el1_abi::{El1MmHandle, ReservationMm};
/// let one = core::num::NonZeroU64::new(1).unwrap();
/// let handle = El1MmHandle { carrier: one, mm: ReservationMm::new(1).unwrap(), incarnation: one };
/// ```
/// An admitted handle also cannot expose a host editor.
/// ```compile_fail
/// fn edit(handle: carrick_el1_abi::El1MmHandle) { handle.editor(); }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct El1MmHandle {
    carrier: NonZeroU64,
    mm: ReservationMm,
    incarnation: NonZeroU64,
}
impl El1MmHandle {
    /// # Safety
    /// Mint only while borrowing the production owner's admitted root, or from
    /// the exact completed EL1 bind service under its borrowed TTBR0 admission.
    pub unsafe fn from_admitted_owner(
        carrier: NonZeroU64,
        mm: ReservationMm,
        incarnation: NonZeroU64,
    ) -> Self {
        Self {
            carrier,
            mm,
            incarnation,
        }
    }
    pub const fn carrier(self) -> NonZeroU64 {
        self.carrier
    }
    pub const fn mm(self) -> ReservationMm {
        self.mm
    }
    pub const fn incarnation(self) -> NonZeroU64 {
        self.incarnation
    }
}

pub const MM_PORTAL_SELECT_ESR: u64 = 0x4352_4d4d_5345_0004;
pub const MM_PORTAL_SERVICE_ESR: u64 = 0x4352_4d4d_5452_0004;
pub const EL1_MM_PORTAL_OFFSET: u64 = 0x1C_0000;
pub const EL1_MM_PORTAL_BASE: u64 = crate::EL1_REGION_BASE + EL1_MM_PORTAL_OFFSET;
const IDLE: u64 = 0;
const WRITING: u64 = 1;
const REQUESTED: u64 = 2;
const SERVICING: u64 = 3;
const COMPLETED: u64 = 4;
const READING: u64 = 5;
const COPY_REQUESTED: u64 = 6;
const COPY_DONE: u64 = 7;
const PREPARED: u64 = 8;
const SUSPENDED: u64 = 9;

/// The resource whose real release completes an owner PREPARE wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum PortalWaitCause {
    Editor = 1,
    Reservations = 2,
    PendingEdit = 3,
    Gate = 4,
    Metadata = 5,
    ReservationPool = 6,
}
impl PortalWaitCause {
    pub const fn encode(self) -> u64 {
        self as u64
    }
    pub const fn decode(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::Editor),
            2 => Some(Self::Reservations),
            3 => Some(Self::PendingEdit),
            4 => Some(Self::Gate),
            5 => Some(Self::Metadata),
            6 => Some(Self::ReservationPool),
            _ => None,
        }
    }
}
/// Exact admitted owner and producer revision sampled before a failed probe.
/// Contains no resource guard or prepared semantic permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortalOwnerWait {
    handle: El1MmHandle,
    cause: PortalWaitCause,
    revision: u64,
}
impl PortalOwnerWait {
    /// # Safety
    /// `revision` must come from this admitted owner's exact cause source,
    /// sampled before checking the resource predicate. Wire decoders must
    /// authenticate the completed service against this same owner handle.
    pub const unsafe fn from_owner(
        handle: El1MmHandle,
        cause: PortalWaitCause,
        revision: u64,
    ) -> Self {
        Self {
            handle,
            cause,
            revision,
        }
    }
    pub const fn handle(self) -> El1MmHandle {
        self.handle
    }
    pub const fn cause(self) -> PortalWaitCause {
        self.cause
    }
    pub const fn revision(self) -> u64 {
        self.revision
    }
}

/// PREPARE refused before any consuming effect. Aggregate callers cancel all
/// earlier page permits before requesting metadata capacity or reselecting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortalPrepareSuspension {
    SelectionChanged,
    ReservationMetadata,
    Owner(PortalOwnerWait),
}

/// Owner-issued semantic admission. The operation generation and slot
/// incarnation authenticate settlement independently of MM policy edits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalPreparedPermit {
    pub index: u32,
    pub generation: NonZeroU64,
    pub operation: PortalOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortalTransferPhase {
    Transfer,
    Prepare,
    Commit,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortalTransferIntent {
    UserRead,
    UserWrite,
    ReadInstruction,
    CarrickInternalRead,
}
impl PortalTransferIntent {
    pub const fn encode(self) -> u64 {
        match self {
            Self::UserRead => 1,
            Self::UserWrite => 2,
            Self::ReadInstruction => 3,
            Self::CarrickInternalRead => 4,
        }
    }
    pub const fn decode(raw: u64) -> Option<Self> {
        match raw {
            1 => Some(Self::UserRead),
            2 => Some(Self::UserWrite),
            3 => Some(Self::ReadInstruction),
            4 => Some(Self::CarrickInternalRead),
            _ => None,
        }
    }
}

/// Exact owner and operation identities; neither root addresses nor host
/// pointers grant authority on this wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalOperation {
    pub carrier: NonZeroU64,
    pub mm: ReservationMm,
    pub incarnation: NonZeroU64,
    pub sequence: NonZeroU64,
}

/// Unaligned guest byte range, distinct from physical transfer storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalByteRange {
    address: u64,
    len: u64,
}
impl PortalByteRange {
    pub fn new(address: u64, len: u64) -> Option<Self> {
        (len <= MM_PORTAL_MAX_BYTES && address.checked_add(len).is_some())
            .then_some(Self { address, len })
    }
    pub const fn address(self) -> u64 {
        self.address
    }
    pub const fn len(self) -> u64 {
        self.len
    }
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

/// Physical identity issued only by the host carrier's existing stage-2
/// custodian. Zero owner words together name a record with no logical owner;
/// a root generation never substitutes for either physical generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalRetainedData {
    pub record: NonZeroU64,
    pub vm_generation: NonZeroU64,
    pub owner: Option<(NonZeroU64, NonZeroU64)>,
}

/// EL1 selection is a receipt, not physical custody. The host must pin its
/// exact record before submitting the revalidation/copy request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalSelectedData {
    pub ipa: u64,
    pub executable: bool,
    pub root_generation: NonZeroU64,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalTransferRequest {
    pub operation: PortalOperation,
    pub range: PortalByteRange,
    pub intent: PortalTransferIntent,
    pub selected: PortalSelectedData,
    pub retained: PortalRetainedData,
    pub fork_sequence: Option<NonZeroU64>,
}
impl PortalTransferRequest {
    pub fn new(
        operation: PortalOperation,
        range: PortalByteRange,
        intent: PortalTransferIntent,
        selected: PortalSelectedData,
        retained: PortalRetainedData,
    ) -> Option<Self> {
        if range.address().checked_sub(selected.offset).is_none()
            || range.is_empty()
            || range.len() > 4096 - (range.address() & 4095)
            || (selected.ipa & 4095) != (range.address() & 4095)
            || selected.ipa.checked_add(range.len()).is_none()
            || selected.offset.checked_add(range.len()).is_none()
        {
            return None;
        }
        Some(Self {
            operation,
            range,
            intent,
            selected,
            retained,
            fork_sequence: None,
        })
    }
    #[doc(hidden)]
    pub fn words(self) -> [u64; 17] {
        [
            MM_PORTAL_PROTOCOL,
            self.operation.carrier.get(),
            self.operation.mm.raw(),
            self.operation.incarnation.get(),
            self.operation.sequence.get(),
            self.range.address(),
            self.range.len(),
            self.intent.encode(),
            self.selected.ipa,
            self.selected.root_generation.get(),
            self.selected.offset,
            self.retained.record.get(),
            self.retained.vm_generation.get(),
            self.retained.owner.map_or(0, |owner| owner.0.get()),
            self.retained.owner.map_or(0, |owner| owner.1.get()),
            u64::from(self.selected.executable),
            self.fork_sequence.map_or(0, NonZeroU64::get),
        ]
    }
    #[doc(hidden)]
    pub fn decode(w: [u64; 17]) -> Option<Self> {
        if w[0] != MM_PORTAL_PROTOCOL || w[15] > 1 {
            return None;
        }
        let owner = match (w[13], w[14]) {
            (0, 0) => None,
            (id, generation) => Some((NonZeroU64::new(id)?, NonZeroU64::new(generation)?)),
        };
        Self::new(
            PortalOperation {
                carrier: NonZeroU64::new(w[1])?,
                mm: ReservationMm::new(w[2])?,
                incarnation: NonZeroU64::new(w[3])?,
                sequence: NonZeroU64::new(w[4])?,
            },
            PortalByteRange::new(w[5], w[6])?,
            PortalTransferIntent::decode(w[7])?,
            PortalSelectedData {
                ipa: w[8],
                executable: w[15] == 1,
                root_generation: NonZeroU64::new(w[9])?,
                offset: w[10],
            },
            PortalRetainedData {
                record: NonZeroU64::new(w[11])?,
                vm_generation: NonZeroU64::new(w[12])?,
                owner,
            },
        )
        .map(|mut request| {
            request.fork_sequence = NonZeroU64::new(w[16]);
            request
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalTransferCompletion {
    pub operation: PortalOperation,
    pub completed: u64,
    pub retained: PortalRetainedData,
    /// Linux errno number, zero only for a complete successful transfer.
    pub errno: u32,
}

#[repr(C, align(64))]
pub struct PortalTransferSlot {
    state: AtomicU64,
    request: [AtomicU64; 17],
    completed: AtomicU64,
    errno: AtomicU64,
    phase: AtomicU64,
    permit: [AtomicU64; 2],
    copy_len: AtomicU64,
}
/// Appended prepared-transfer vocabulary and field offsets participate even
/// when new words fit in the previous cache-line padding.
pub const MM_TRANSFER_LAYOUT_HASH: u64 = {
    let words = [
        3u64,
        MM_PORTAL_PROTOCOL,
        PortalWaitCause::ReservationPool as u64,
        PREPARED,
        SUSPENDED,
        core::mem::size_of::<PortalTransferSlot>() as u64,
        core::mem::offset_of!(PortalTransferSlot, phase) as u64,
        core::mem::offset_of!(PortalTransferSlot, permit) as u64,
        core::mem::offset_of!(PortalTransferSlot, copy_len) as u64,
    ];
    let mut hash = 0xcbf29ce484222325u64;
    let mut i = 0;
    while i < words.len() {
        hash = (hash ^ words[i]).wrapping_mul(0x100000001b3);
        i += 1;
    }
    hash
};

impl Default for PortalTransferSlot {
    fn default() -> Self {
        Self::new()
    }
}
impl PortalTransferSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(IDLE),
            request: [const { AtomicU64::new(0) }; 17],
            completed: AtomicU64::new(0),
            errno: AtomicU64::new(0),
            phase: AtomicU64::new(0),
            permit: [const { AtomicU64::new(0) }; 2],
            copy_len: AtomicU64::new(0),
        }
    }
    /// The producer must retain the exact physical storage pin independently
    /// until take_completion settles. Busy slots never demote to host access.
    pub fn submit(&self, request: PortalTransferRequest) -> Option<PortalTransferTicket<'_>> {
        self.submit_phase(
            request,
            PortalTransferPhase::Transfer,
            None,
            request.range.len(),
        )
    }
    pub fn submit_prepare(
        &self,
        request: PortalTransferRequest,
    ) -> Option<PortalTransferTicket<'_>> {
        self.submit_phase(request, PortalTransferPhase::Prepare, None, 0)
    }
    pub fn submit_commit(
        &self,
        request: PortalTransferRequest,
        permit: PortalPreparedPermit,
        copy_len: u64,
    ) -> Option<PortalTransferTicket<'_>> {
        if permit.operation != request.operation || copy_len > request.range.len() {
            return None;
        }
        self.submit_phase(request, PortalTransferPhase::Commit, Some(permit), copy_len)
    }
    pub fn submit_cancel(
        &self,
        request: PortalTransferRequest,
        permit: PortalPreparedPermit,
    ) -> Option<PortalTransferTicket<'_>> {
        if permit.operation != request.operation {
            return None;
        }
        self.submit_phase(request, PortalTransferPhase::Cancel, Some(permit), 0)
    }
    fn submit_phase(
        &self,
        request: PortalTransferRequest,
        phase: PortalTransferPhase,
        permit: Option<PortalPreparedPermit>,
        copy_len: u64,
    ) -> Option<PortalTransferTicket<'_>> {
        self.state
            .compare_exchange(IDLE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        for (target, value) in self.request.iter().zip(request.words()) {
            target.store(value, Ordering::Relaxed);
        }
        self.completed.store(0, Ordering::Relaxed);
        self.errno.store(0, Ordering::Relaxed);
        self.phase.store(
            match phase {
                PortalTransferPhase::Transfer => 0,
                PortalTransferPhase::Prepare => 1,
                PortalTransferPhase::Commit => 2,
                PortalTransferPhase::Cancel => 3,
            },
            Ordering::Relaxed,
        );
        self.permit[0].store(permit.map_or(0, |p| u64::from(p.index)), Ordering::Relaxed);
        self.permit[1].store(permit.map_or(0, |p| p.generation.get()), Ordering::Relaxed);
        self.copy_len.store(copy_len, Ordering::Relaxed);
        self.state.store(REQUESTED, Ordering::Release);
        Some(PortalTransferTicket {
            slot: self,
            request,
            settled: false,
        })
    }
    pub fn copy_pending(&self) -> bool {
        self.state.load(Ordering::Acquire) == COPY_REQUESTED
    }
    fn load_request(&self) -> Option<PortalTransferRequest> {
        PortalTransferRequest::decode(core::array::from_fn(|i| {
            self.request[i].load(Ordering::Relaxed)
        }))
    }
    /// EL1 acquires immutable request storage. Invalid wire data stays closed;
    /// no Rust enum or pointer is read from an unvalidated discriminant.
    pub fn claim(&self) -> Option<PortalTransferService<'_>> {
        self.state
            .compare_exchange(REQUESTED, SERVICING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let request = self.load_request()?;
        let phase = match self.phase.load(Ordering::Relaxed) {
            0 => PortalTransferPhase::Transfer,
            1 => PortalTransferPhase::Prepare,
            2 => PortalTransferPhase::Commit,
            3 => PortalTransferPhase::Cancel,
            _ => return None,
        };
        let permit = match phase {
            PortalTransferPhase::Commit | PortalTransferPhase::Cancel => {
                Some(PortalPreparedPermit {
                    index: u32::try_from(self.permit[0].load(Ordering::Relaxed)).ok()?,
                    generation: NonZeroU64::new(self.permit[1].load(Ordering::Relaxed))?,
                    operation: request.operation,
                })
            }
            _ => None,
        };
        Some(PortalTransferService {
            slot: self,
            request,
            phase,
            permit,
        })
    }
}

/// Non-escapable authorization issued only for the guest's revalidated copy
/// phase. The host physical pin cannot copy using a plain wire request.
pub struct PortalCopyRequest<'a> {
    request: PortalTransferRequest,
    _scope: core::marker::PhantomData<&'a mut ()>,
}
impl PortalCopyRequest<'_> {
    pub fn request(&self) -> PortalTransferRequest {
        self.request
    }
}

/// Non-Copy producer capability. Drop intentionally leaves in-flight storage
/// and the slot owned; cancellation must settle through the same custodian.
pub struct PortalTransferTicket<'a> {
    slot: &'a PortalTransferSlot,
    request: PortalTransferRequest,
    settled: bool,
}
impl PortalTransferTicket<'_> {
    /// Detach the owner permit, freeing only wire storage. Physical custody
    /// must remain live until a later exact COMMIT or CANCEL settles it.
    pub fn take_prepared(&mut self) -> Option<PortalPreparedPermit> {
        if self.settled
            || self.slot.state.load(Ordering::Acquire) != PREPARED
            || self.slot.load_request()? != self.request
        {
            return None;
        }
        let permit = PortalPreparedPermit {
            index: u32::try_from(self.slot.permit[0].load(Ordering::Relaxed)).ok()?,
            generation: NonZeroU64::new(self.slot.permit[1].load(Ordering::Relaxed))?,
            operation: self.request.operation,
        };
        self.slot
            .state
            .compare_exchange(PREPARED, READING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        self.settled = true;
        self.slot.state.store(IDLE, Ordering::Release);
        Some(permit)
    }
    /// Service one bounded physical copy while EL1 retains its semantic permit
    /// on the suspended stack. The callback must neither block nor re-enter
    /// EL1. A refusal resumes the exact service for permit settlement.
    pub fn copy_requested(
        &mut self,
        copy: impl for<'copy> FnOnce(PortalCopyRequest<'copy>) -> bool,
    ) -> bool {
        if self.settled
            || self.slot.state.load(Ordering::Acquire) != COPY_REQUESTED
            || self.slot.load_request() != Some(self.request)
        {
            return false;
        }
        let mut request = self.request;
        let Some(range) = PortalByteRange::new(
            request.range.address(),
            self.slot.copy_len.load(Ordering::Relaxed),
        ) else {
            return false;
        };
        request.range = range;
        let success = copy(PortalCopyRequest {
            request,
            _scope: core::marker::PhantomData,
        });
        self.slot
            .errno
            .store(if success { 0 } else { 125 }, Ordering::Relaxed);
        self.slot.state.store(COPY_DONE, Ordering::Release);
        true
    }

    /// Cancel only before EL1 acquired the slot. Once servicing has started,
    /// cancellation must resume EL1's exact stack through the copy response.
    pub fn cancel_unclaimed(&mut self) -> bool {
        if self.settled || self.slot.load_request() != Some(self.request) {
            return false;
        }
        if self
            .slot
            .state
            .compare_exchange(REQUESTED, READING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.settled = true;
        self.slot.state.store(IDLE, Ordering::Release);
        true
    }
    /// Consume a pre-effect refusal and release this wire slot. Detached
    /// permits prepared on earlier pages remain the caller's responsibility.
    pub fn take_prepare_suspension(&mut self) -> Option<PortalPrepareSuspension> {
        if self.settled
            || self.slot.state.load(Ordering::Acquire) != SUSPENDED
            || self.slot.load_request()? != self.request
        {
            return None;
        }
        let reason = match self.slot.errno.load(Ordering::Relaxed) {
            1 => PortalPrepareSuspension::SelectionChanged,
            2 => PortalPrepareSuspension::ReservationMetadata,
            tag => {
                let cause = PortalWaitCause::decode(tag.checked_sub(2)?)?;
                let operation = self.request.operation;
                // SAFETY: exact request equality above authenticates the completed service.
                let handle = unsafe {
                    El1MmHandle::from_admitted_owner(
                        operation.carrier,
                        operation.mm,
                        operation.incarnation,
                    )
                };
                PortalPrepareSuspension::Owner(unsafe {
                    PortalOwnerWait::from_owner(
                        handle,
                        cause,
                        self.slot.completed.load(Ordering::Relaxed),
                    )
                })
            }
        };
        self.slot
            .state
            .compare_exchange(SUSPENDED, READING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        self.settled = true;
        self.slot.state.store(IDLE, Ordering::Release);
        Some(reason)
    }
    pub fn take_completion(&mut self) -> Option<PortalTransferCompletion> {
        if self.settled
            || self.slot.state.load(Ordering::Acquire) != COMPLETED
            || self.slot.load_request()? != self.request
        {
            return None;
        }
        let completed = self.slot.completed.load(Ordering::Relaxed);
        let errno = self.slot.errno.load(Ordering::Relaxed);
        if completed > self.request.range.len()
            || errno > 4095
            || (errno == 0 && completed != self.slot.copy_len.load(Ordering::Relaxed))
        {
            return None;
        }
        self.slot
            .state
            .compare_exchange(COMPLETED, READING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let receipt = PortalTransferCompletion {
            operation: self.request.operation,
            retained: self.request.retained,
            completed,
            errno: errno as u32,
        };
        self.settled = true;
        self.slot.state.store(IDLE, Ordering::Release);
        Some(receipt)
    }
}

pub struct PortalTransferService<'a> {
    slot: &'a PortalTransferSlot,
    request: PortalTransferRequest,
    phase: PortalTransferPhase,
    permit: Option<PortalPreparedPermit>,
}
impl PortalTransferService<'_> {
    pub const fn phase(&self) -> PortalTransferPhase {
        self.phase
    }
    pub const fn permit(&self) -> Option<PortalPreparedPermit> {
        self.permit
    }
    pub fn copy_len(&self) -> u64 {
        self.slot.copy_len.load(Ordering::Relaxed)
    }
    pub fn suspend_prepare(self, reason: PortalPrepareSuspension) -> bool {
        if !matches!(
            self.phase,
            PortalTransferPhase::Prepare | PortalTransferPhase::Transfer
        ) {
            return false;
        }
        self.slot.errno.store(
            match reason {
                PortalPrepareSuspension::SelectionChanged => 1,
                PortalPrepareSuspension::ReservationMetadata => 2,
                PortalPrepareSuspension::Owner(wait) => {
                    if wait.handle.carrier() != self.request.operation.carrier
                        || wait.handle.mm() != self.request.operation.mm
                        || wait.handle.incarnation() != self.request.operation.incarnation
                    {
                        return false;
                    }
                    self.slot.completed.store(wait.revision, Ordering::Relaxed);
                    wait.cause.encode() + 2
                }
            },
            Ordering::Relaxed,
        );
        self.slot.state.store(SUSPENDED, Ordering::Release);
        true
    }
    pub fn complete_prepared(self, permit: PortalPreparedPermit) -> bool {
        if self.phase != PortalTransferPhase::Prepare || permit.operation != self.request.operation
        {
            return false;
        }
        self.slot.permit[0].store(u64::from(permit.index), Ordering::Relaxed);
        self.slot.permit[1].store(permit.generation.get(), Ordering::Relaxed);
        self.slot.state.store(PREPARED, Ordering::Release);
        true
    }
    pub const fn request(&self) -> PortalTransferRequest {
        self.request
    }
    /// Publish the copy effect and suspend on the same EL1 stack. `cross`
    /// returns only after the host has acknowledged copy or cancellation.
    pub fn copy_with(&self, cross: impl FnOnce()) -> bool {
        if self.slot.state.load(Ordering::Acquire) != SERVICING {
            return false;
        }
        self.slot.state.store(COPY_REQUESTED, Ordering::Release);
        cross();
        self.slot.state.load(Ordering::Acquire) == COPY_DONE
            && self.slot.errno.load(Ordering::Relaxed) == 0
    }
    pub fn complete(self, completed: u64, errno: u32) -> bool {
        if completed > self.request.range.len()
            || errno > 4095
            || (errno == 0 && completed != self.copy_len())
        {
            return false;
        }
        self.slot.completed.store(completed, Ordering::Relaxed);
        self.slot.errno.store(u64::from(errno), Ordering::Relaxed);
        self.slot.state.store(COMPLETED, Ordering::Release);
        true
    }
}

/// Enrollment authority joined from one retained carrier region and its exact
/// live MM source. It cannot be paired with another zone or recycled MM.
pub struct PortalWaitEnrollment<'a> {
    source: carrick_sched_core::spaces::notification::SpaceNotificationLease<'a>,
    cause: carrick_sched_core::spaces::notification::SpaceWaitCause,
    revision: u64,
}
impl PortalWaitEnrollment<'_> {
    pub fn park_host(
        self,
        record: carrick_sched_core::RecordId,
        operation: carrick_sched_core::object_wait::OperationToken,
        completion: &dyn Fn(carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>),
    ) -> Result<
        (),
        (
            carrick_sched_core::object_wait::ObjectWaitError,
            carrick_sched_core::object_wait::OperationToken,
        ),
    > {
        self.source.reserve(self.cause).park_host_rechecked(
            self.source.observed_revision(self.cause, self.revision),
            record,
            operation,
            completion,
            || self.source.is_live(),
        )
    }
}

#[repr(C, align(64))]
pub struct MmPortalSlots {
    carrier: AtomicU64,
    executable: [crate::PortalExecutableSlot; crate::EL1_STACK_SLOTS as usize],
    forks: [crate::PortalForkSlot; crate::EL1_STACK_SLOTS as usize],
    grants: [crate::PortalGrantSlot; crate::EL1_STACK_SLOTS as usize],
    slots: [PortalTransferSlot; crate::EL1_STACK_SLOTS as usize],
}
impl Default for MmPortalSlots {
    fn default() -> Self {
        Self::new()
    }
}
impl MmPortalSlots {
    pub const fn new() -> Self {
        Self {
            carrier: AtomicU64::new(0),
            executable: [const { crate::PortalExecutableSlot::new() };
                crate::EL1_STACK_SLOTS as usize],
            forks: [const { crate::PortalForkSlot::new() }; crate::EL1_STACK_SLOTS as usize],
            grants: [const { crate::PortalGrantSlot::new() }; crate::EL1_STACK_SLOTS as usize],
            slots: [const { PortalTransferSlot::new() }; crate::EL1_STACK_SLOTS as usize],
        }
    }
    /// Authenticate the service receipt using the bound carrier and both
    /// actual retained-region views; no container dereference or global lookup.
    pub fn authenticate_wait<'a>(
        &'a self,
        zone: &'a carrick_sched_core::ZoneTables,
        receipt: PortalOwnerWait,
    ) -> Result<PortalWaitEnrollment<'a>, carrick_sched_core::object_wait::ObjectWaitError> {
        use carrick_sched_core::object_wait::ObjectWaitError;
        use carrick_sched_core::spaces::notification::SpaceWaitCause;
        let portal_region =
            (self as *const Self as usize).checked_sub(EL1_MM_PORTAL_OFFSET as usize);
        let zone_region = (zone as *const _ as usize).checked_sub(crate::EL1_ZONE_OFFSET as usize);
        if portal_region.is_none()
            || portal_region != zone_region
            || self.carrier() != Some(receipt.handle.carrier())
        {
            return Err(ObjectWaitError::Stale);
        }
        let cause = match receipt.cause {
            PortalWaitCause::Editor => SpaceWaitCause::Editor,
            PortalWaitCause::Reservations => SpaceWaitCause::Reservations,
            PortalWaitCause::PendingEdit => SpaceWaitCause::PendingEdit,
            PortalWaitCause::Gate => SpaceWaitCause::Gate,
            PortalWaitCause::Metadata => SpaceWaitCause::Metadata,
            PortalWaitCause::ReservationPool => return Err(ObjectWaitError::Stale),
        };
        let entry = zone
            .space_entry(NonZeroU64::new(receipt.handle.mm().raw()).ok_or(ObjectWaitError::Stale)?)
            .ok_or(ObjectWaitError::Stale)?;
        let source = entry.notifications(receipt.handle.incarnation())?;
        Ok(PortalWaitEnrollment {
            source,
            cause,
            revision: receipt.revision,
        })
    }
    pub fn fork(&self, slot: usize) -> Option<&crate::PortalForkSlot> {
        self.forks.get(slot)
    }
    pub fn has_outstanding_transfer(&self, mm: ReservationMm) -> bool {
        self.slots.iter().any(|slot| {
            let state = slot.state.load(Ordering::Acquire);
            state != IDLE
                && (state == WRITING
                    || slot
                        .load_request()
                        .is_none_or(|request| request.operation.mm == mm))
        }) || self
            .grants
            .iter()
            .any(|slot| slot.has_outstanding_for(mm.raw()))
    }
    /// Bind this retained carrier region once. Independent custody objects
    /// must use distinct IDs even when their VM generations both start at one.
    pub fn bind_carrier(&self, carrier: NonZeroU64) -> bool {
        self.carrier
            .compare_exchange(0, carrier.get(), Ordering::AcqRel, Ordering::Acquire)
            .map_or_else(|current| current == carrier.get(), |_| true)
    }
    pub fn carrier(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.carrier.load(Ordering::Acquire))
    }
    pub fn executable(&self, slot: usize) -> Option<&crate::PortalExecutableSlot> {
        self.executable.get(slot)
    }
    pub fn grant(&self, slot: usize) -> Option<&crate::PortalGrantSlot> {
        self.grants.get(slot)
    }
    pub fn slot(&self, slot: usize) -> Option<&PortalTransferSlot> {
        self.slots.get(slot)
    }
}
const _: () =
    assert!(EL1_MM_PORTAL_OFFSET >= crate::EL1_COW_COPY_OFFSET + crate::EL1_COW_COPY_SIZE);
const _: () = assert!(
    EL1_MM_PORTAL_OFFSET + core::mem::size_of::<MmPortalSlots>() as u64 <= crate::EL1_STACKS_OFFSET
);

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn request(sequence: u64) -> PortalTransferRequest {
        PortalTransferRequest::new(
            PortalOperation {
                carrier: NonZeroU64::new(1).unwrap(),
                mm: ReservationMm::new(2).unwrap(),
                incarnation: NonZeroU64::new(3).unwrap(),
                sequence: NonZeroU64::new(sequence).unwrap(),
            },
            PortalByteRange::new(0x1234, 4).unwrap(),
            PortalTransferIntent::UserRead,
            PortalSelectedData {
                ipa: 0x102234,
                executable: false,
                root_generation: NonZeroU64::new(7).unwrap(),
                offset: 0,
            },
            PortalRetainedData {
                record: NonZeroU64::new(8).unwrap(),
                vm_generation: NonZeroU64::new(9).unwrap(),
                owner: None,
            },
        )
        .unwrap()
    }
    #[test]
    fn portal_wire_bounds_and_discriminants_fail_closed() {
        assert!(PortalByteRange::new(u64::MAX, 1).is_none());
        assert!(PortalByteRange::new(0, MM_PORTAL_MAX_BYTES + 1).is_none());
        let mut w = request(1).words();
        for (index, invalid) in [
            (0, MM_PORTAL_PROTOCOL + 1),
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 0),
            (7, 99),
            (9, 0),
            (11, 0),
            (12, 0),
            (13, 1),
            (15, 2),
        ] {
            let saved = w[index];
            w[index] = invalid;
            assert!(PortalTransferRequest::decode(w).is_none());
            w[index] = saved;
        }
    }
    #[test]
    fn portal_slot_is_single_flight_and_completion_is_exact_once() {
        let slot = PortalTransferSlot::new();
        let mut ticket = slot.submit(request(1)).unwrap();
        assert!(slot.submit(request(2)).is_none());
        assert!(ticket.take_completion().is_none());
        let service = slot.claim().unwrap();
        assert!(slot.claim().is_none());
        assert!(service.complete(2, 14));
        let receipt = ticket.take_completion().unwrap();
        assert_eq!(receipt.completed, 2);
        assert_eq!(receipt.errno, 14);
        let mut next = slot.submit(request(2)).unwrap();
        assert!(slot.claim().unwrap().complete(4, 0));
        assert!(ticket.take_completion().is_none());
        assert_eq!(next.take_completion().unwrap().operation.sequence.get(), 2);
        assert!(next.take_completion().is_none());
    }
    #[test]
    fn portal_drop_does_not_reuse_unsettled_storage() {
        let slot = PortalTransferSlot::new();
        {
            let _ticket = slot.submit(request(1)).unwrap();
        }
        assert!(slot.submit(request(2)).is_none());
        assert!(slot.claim().unwrap().complete(4, 0));
        assert!(slot.submit(request(2)).is_none());
    }
}

#[cfg(test)]
mod prepared_tests {
    use super::*;
    #[test]
    fn owner_wait_wire_preserves_exact_identity_revision_and_slot_geometry() {
        assert_eq!(core::mem::size_of::<PortalTransferSlot>(), 192);
        for cause in [
            PortalWaitCause::Editor,
            PortalWaitCause::Reservations,
            PortalWaitCause::PendingEdit,
            PortalWaitCause::Gate,
            PortalWaitCause::Metadata,
            PortalWaitCause::ReservationPool,
        ] {
            let slot = PortalTransferSlot::new();
            let request = super::tests::request(1);
            let mut ticket = slot.submit_prepare(request).unwrap();
            let handle = unsafe {
                El1MmHandle::from_admitted_owner(
                    request.operation.carrier,
                    request.operation.mm,
                    request.operation.incarnation,
                )
            };
            let reason = PortalPrepareSuspension::Owner(unsafe {
                PortalOwnerWait::from_owner(handle, cause, u64::MAX - 3)
            });
            assert!(slot.claim().unwrap().suspend_prepare(reason));
            assert!(ticket.take_completion().is_none());
            assert_eq!(ticket.take_prepare_suspension(), Some(reason));
            assert!(ticket.take_prepare_suspension().is_none());
            assert!(slot.submit_prepare(request).is_some());
        }
    }

    #[test]
    fn detached_page_receipts_reuse_wire_slot_and_preserve_exact_settlement() {
        let slot = PortalTransferSlot::new();
        let request = super::tests::request(1);
        let first = PortalPreparedPermit {
            index: 11,
            generation: NonZeroU64::new(21).unwrap(),
            operation: request.operation,
        };
        let second = PortalPreparedPermit {
            index: 12,
            generation: NonZeroU64::new(22).unwrap(),
            operation: request.operation,
        };
        for permit in [first, second] {
            let mut ticket = slot.submit_prepare(request).unwrap();
            let service = slot.claim().unwrap();
            assert_eq!(service.phase(), PortalTransferPhase::Prepare);
            assert!(service.complete_prepared(permit));
            assert_eq!(ticket.take_prepared(), Some(permit));
        }
        let mut cancel = slot.submit_cancel(request, second).unwrap();
        let service = slot.claim().unwrap();
        assert_eq!(service.permit(), Some(second));
        assert!(service.complete(0, 0));
        assert_eq!(cancel.take_completion().unwrap().completed, 0);
        let mut commit = slot.submit_commit(request, first, 2).unwrap();
        let service = slot.claim().unwrap();
        assert!(
            service.copy_with(|| assert!(
                commit.copy_requested(|copy| copy.request().range.len() == 2)
            ))
        );
        assert!(service.complete(2, 0));
        assert_eq!(commit.take_completion().unwrap().completed, 2);
    }
}
