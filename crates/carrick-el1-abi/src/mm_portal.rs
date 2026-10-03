//! Bounded host-to-owner UserTransfer records in the existing EL1 service ABI.
//! Physical storage custody outlives the request until exact completion has
//! settled. A dropped ticket never frees a slot or revokes its storage pin.
use crate::ReservationMm;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MM_PORTAL_PROTOCOL: u64 = 2;
pub const MM_PORTAL_MAX_BYTES: u64 = 4096;
pub const MM_PORTAL_BIND_ESR: u64 = 0x4352_4d4d_4249_0002;
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

pub const MM_PORTAL_SELECT_ESR: u64 = 0x4352_4d4d_5345_0002;
pub const MM_PORTAL_SERVICE_ESR: u64 = 0x4352_4d4d_5452_0002;
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
        })
    }
    fn words(self) -> [u64; 16] {
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
        ]
    }
    fn decode(w: [u64; 16]) -> Option<Self> {
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
    request: [AtomicU64; 16],
    completed: AtomicU64,
    errno: AtomicU64,
}
impl Default for PortalTransferSlot {
    fn default() -> Self {
        Self::new()
    }
}
impl PortalTransferSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(IDLE),
            request: [const { AtomicU64::new(0) }; 16],
            completed: AtomicU64::new(0),
            errno: AtomicU64::new(0),
        }
    }
    /// The producer must retain the exact physical storage pin independently
    /// until take_completion settles. Busy slots never demote to host access.
    pub fn submit(&self, request: PortalTransferRequest) -> Option<PortalTransferTicket<'_>> {
        self.state
            .compare_exchange(IDLE, WRITING, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        for (target, value) in self.request.iter().zip(request.words()) {
            target.store(value, Ordering::Relaxed);
        }
        self.completed.store(0, Ordering::Relaxed);
        self.errno.store(0, Ordering::Relaxed);
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
        Some(PortalTransferService {
            slot: self,
            request,
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
    /// Service one bounded physical copy while EL1 retains its real editor
    /// on the suspended stack. The callback must neither block nor re-enter
    /// EL1. A refusal is resumed to release that exact guard before settlement.
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
        let success = copy(PortalCopyRequest {
            request: self.request,
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
            || (errno == 0 && completed != self.request.range.len())
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
}
impl PortalTransferService<'_> {
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
            || (errno == 0 && completed != self.request.range.len())
        {
            return false;
        }
        self.slot.completed.store(completed, Ordering::Relaxed);
        self.slot.errno.store(u64::from(errno), Ordering::Relaxed);
        self.slot.state.store(COMPLETED, Ordering::Release);
        true
    }
}

#[repr(C, align(64))]
pub struct MmPortalSlots {
    carrier: AtomicU64,
    executable: [crate::PortalExecutableSlot; crate::EL1_STACK_SLOTS as usize],
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
            grants: [const { crate::PortalGrantSlot::new() }; crate::EL1_STACK_SLOTS as usize],
            slots: [const { PortalTransferSlot::new() }; crate::EL1_STACK_SLOTS as usize],
        }
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
    fn request(sequence: u64) -> PortalTransferRequest {
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
