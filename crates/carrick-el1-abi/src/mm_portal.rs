//! Bounded host-to-owner UserTransfer records in the existing EL1 service ABI.
//! Physical storage custody outlives the request until exact completion has
//! settled. A dropped ticket never frees a slot or revokes its storage pin.
use crate::ReservationMm;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

// SELECT success carries the pre-selection Reservations observation in x16/x17.
use carrick_core_abi::*;
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
/// A proposal for one page of pending heap retirement, never user-copy authority.
/// The owner must authenticate the complete request and admitted incarnation
/// again before selecting any physical backing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalBackingMaintenance {
    handle: El1MmHandle,
    pending: crate::ReservationRequest,
    page: u64,
}
impl PortalBackingMaintenance {
    pub fn new(handle: El1MmHandle, pending: crate::ReservationRequest, page: u64) -> Option<Self> {
        (handle.mm() == pending.mm
            && pending.operation == crate::ReservationOperation::Retire
            && pending.protection == crate::ReservationProtection::NONE
            && pending.source.is_none()
            && page.is_multiple_of(4096)
            && pending.range.contains(page))
        .then_some(Self {
            handle,
            pending,
            page,
        })
    }
    pub const fn handle(self) -> El1MmHandle {
        self.handle
    }
    pub const fn pending(self) -> crate::ReservationRequest {
        self.pending
    }
    pub const fn page(self) -> u64 {
        self.page
    }
    pub fn words(self) -> [u64; 8] {
        [
            self.handle.carrier().get(),
            self.pending.mm.raw(),
            self.handle.incarnation().get(),
            self.pending.generation.raw(),
            self.pending.sequence.raw(),
            self.pending.range.start(),
            self.pending.range.end(),
            self.page,
        ]
    }
    pub fn decode(w: [u64; 8]) -> Option<Self> {
        let mm = crate::ReservationMm::new(w[1])?;
        // SAFETY: candidate only; the maintenance service authenticates it.
        let handle = unsafe {
            El1MmHandle::from_admitted_owner(NonZeroU64::new(w[0])?, mm, NonZeroU64::new(w[2])?)
        };
        Self::new(
            handle,
            crate::ReservationRequest {
                mm,
                generation: crate::ReservationGeneration::new(w[3])?,
                sequence: crate::ReservationSequence::new(w[4])?,
                range: crate::ReservationRange::new(w[5], w[6])?,
                protection: crate::ReservationProtection::NONE,
                operation: crate::ReservationOperation::Retire,
                source: None,
            },
            w[7],
        )
    }
}
pub const MM_PORTAL_MAINTENANCE_ESR: u64 = 0x4352_4d4d_424d_0001;

pub const MM_PORTAL_SELECT_ESR: u64 = 0x4352_4d4d_5345_0004;
pub const MM_PORTAL_SERVICE_ESR: u64 = 0x4352_4d4d_5452_0004;
pub const EL1_MM_PORTAL_OFFSET: u64 = 0x1C_0000;
pub const EL1_MM_PORTAL_BASE: u64 = crate::EL1_REGION_BASE + EL1_MM_PORTAL_OFFSET;
pub use carrick_core_abi::PortalWaitEnrollment;

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
            || self.carrier() != Some(receipt.handle().carrier())
        {
            return Err(ObjectWaitError::Stale);
        }
        let cause = match receipt.cause() {
            PortalWaitCause::Editor => SpaceWaitCause::Editor,
            PortalWaitCause::Reservations => SpaceWaitCause::Reservations,
            PortalWaitCause::PendingEdit => SpaceWaitCause::PendingEdit,
            PortalWaitCause::Gate => SpaceWaitCause::Gate,
            PortalWaitCause::Metadata => SpaceWaitCause::Metadata,
            PortalWaitCause::ReservationPool => return Err(ObjectWaitError::Stale),
        };
        let entry = zone
            .space_entry(
                NonZeroU64::new(receipt.handle().mm().raw()).ok_or(ObjectWaitError::Stale)?,
            )
            .ok_or(ObjectWaitError::Stale)?;
        let source = entry.notifications(receipt.handle().incarnation())?;
        Ok(PortalWaitEnrollment::new(source, cause, receipt.revision()))
    }
    pub fn fork(&self, slot: usize) -> Option<&crate::PortalForkSlot> {
        self.forks.get(slot)
    }
    pub fn has_outstanding_transfer(&self, mm: ReservationMm) -> bool {
        self.slots.iter().any(|slot| slot.has_outstanding_for(mm))
            || self
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
impl carrick_core_abi::GrantSlotVenue for MmPortalSlots {
    fn carrier(&self) -> Option<core::num::NonZeroU64> {
        MmPortalSlots::carrier(self)
    }
    fn grant(&self, slot: usize) -> Option<&carrick_core_abi::PortalGrantSlot> {
        MmPortalSlots::grant(self, slot)
    }
}
