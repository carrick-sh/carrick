//! Bounded host-to-owner UserTransfer records in the existing EL1 service ABI.
//! Physical storage custody outlives the request until exact completion has
//! settled. A dropped ticket never frees a slot or revokes its storage pin.
use crate::{MetadataExtent, ReservationMm};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MM_PORTAL_PROTOCOL: u64 = 1;
pub const MM_PORTAL_MAX_BYTES: u64 = 65536;
pub const EL1_MM_PORTAL_OFFSET: u64 = 0x1C_0000;
pub const EL1_MM_PORTAL_BASE: u64 = crate::EL1_REGION_BASE + EL1_MM_PORTAL_OFFSET;
const IDLE: u64 = 0;
const WRITING: u64 = 1;
const REQUESTED: u64 = 2;
const SERVICING: u64 = 3;
const COMPLETED: u64 = 4;
const READING: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortalTransferIntent {
    UserRead,
    UserWrite,
    ReadInstruction,
    CarrickInternalRead,
}
impl PortalTransferIntent {
    const fn encode(self) -> u64 {
        match self {
            Self::UserRead => 1,
            Self::UserWrite => 2,
            Self::ReadInstruction => 3,
            Self::CarrickInternalRead => 4,
        }
    }
    const fn decode(raw: u64) -> Option<Self> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalTransferRequest {
    pub operation: PortalOperation,
    pub range: PortalByteRange,
    pub intent: PortalTransferIntent,
    storage: MetadataExtent,
    storage_offset: u64,
}
impl PortalTransferRequest {
    pub fn new(
        operation: PortalOperation,
        range: PortalByteRange,
        intent: PortalTransferIntent,
        storage: MetadataExtent,
        storage_offset: u64,
    ) -> Option<Self> {
        storage
            .base()
            .checked_add(storage_offset)
            .filter(|start| storage.contains(*start, range.len()))?;
        Some(Self {
            operation,
            range,
            intent,
            storage,
            storage_offset,
        })
    }
    pub const fn storage(self) -> MetadataExtent {
        self.storage
    }
    pub const fn storage_offset(self) -> u64 {
        self.storage_offset
    }
    fn words(self) -> [u64; 12] {
        [
            MM_PORTAL_PROTOCOL,
            self.operation.carrier.get(),
            self.operation.mm.raw(),
            self.operation.incarnation.get(),
            self.operation.sequence.get(),
            self.range.address(),
            self.range.len(),
            self.intent.encode(),
            self.storage.base(),
            self.storage.len(),
            self.storage.token(),
            self.storage_offset,
        ]
    }
    fn decode(w: [u64; 12]) -> Option<Self> {
        if w[0] != MM_PORTAL_PROTOCOL {
            return None;
        }
        Self::new(
            PortalOperation {
                carrier: NonZeroU64::new(w[1])?,
                mm: ReservationMm::new(w[2])?,
                incarnation: NonZeroU64::new(w[3])?,
                sequence: NonZeroU64::new(w[4])?,
            },
            PortalByteRange::new(w[5], w[6])?,
            PortalTransferIntent::decode(w[7])?,
            MetadataExtent::new(w[8], w[9], w[10])?,
            w[11],
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalTransferCompletion {
    pub operation: PortalOperation,
    pub completed: u64,
    /// Linux errno number, zero only for a complete successful transfer.
    pub errno: u32,
}

#[repr(C, align(64))]
pub struct PortalTransferSlot {
    state: AtomicU64,
    request: [AtomicU64; 12],
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
            request: [const { AtomicU64::new(0) }; 12],
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

/// Non-Copy producer capability. Drop intentionally leaves in-flight storage
/// and the slot owned; cancellation must settle through the same custodian.
pub struct PortalTransferTicket<'a> {
    slot: &'a PortalTransferSlot,
    request: PortalTransferRequest,
    settled: bool,
}
impl PortalTransferTicket<'_> {
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
            slots: [const { PortalTransferSlot::new() }; crate::EL1_STACK_SLOTS as usize],
        }
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
            MetadataExtent::new(0x100000, 4096, 7).unwrap(),
            16,
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
            (10, 0),
            (11, 4096),
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
