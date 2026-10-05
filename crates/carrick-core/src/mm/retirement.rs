//! Load admission, drain and invalidation custody shared by both ISAs.
//! Synchronization and architectural invalidation stay with the execution venue.

use core::fmt;
use core::ops::DerefMut;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidencyError {
    Retiring,
    AlreadyRetiring,
    ExecutorStillLoading,
    HardwareAlreadyDirty,
    UnexpectedLoad,
    StaleGeneration,
}
impl fmt::Display for ResidencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Retiring => "address generation is closed to new executor loads",
            Self::AlreadyRetiring => "address generation retirement already began",
            Self::ExecutorStillLoading => "an executor load is still in flight",
            Self::HardwareAlreadyDirty => "load hardware-dirty boundary was already armed",
            Self::UnexpectedLoad => "load already completed",
            Self::StaleGeneration => "stale address generation invalidation",
        })
    }
}
impl core::error::Error for ResidencyError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ResidencyLifecycle {
    #[default]
    Live,
    RetirementPrepared,
    Retired,
}

/// The sole logical residency state. Its fields cannot be mutated by adapters.
#[derive(Debug, Default)]
pub struct ResidencyState {
    lifecycle: ResidencyLifecycle,
    loading: usize,
    hardware_dirty: bool,
    installed: bool,
    invalidated: bool,
}

/// Exclusive access and notification for one residency owner.
///
/// # Safety
/// Clones must access the same state. Guards must exclude all other accesses.
/// Waiting must atomically release and reacquire that guard, and notifications
/// must wake a waiter after an admitted load settles.
pub unsafe trait ResidencyVenue: Clone + fmt::Debug + Default {
    type Guard<'a>: DerefMut<Target = ResidencyState>
    where
        Self: 'a;
    fn lock(&self) -> Self::Guard<'_>;
    fn wait(&self, guard: &mut Self::Guard<'_>);
    fn notify_all(&self);
}

/// Architectural completion, minted after invalidating this exact generation.
///
/// # Safety
/// The reported generation must identify a completed invalidation covering
/// every execution venue which could cache its translations.
pub unsafe trait InvalidationProof<G> {
    fn generation(&self) -> G;
}

#[derive(Clone, Debug)]
pub struct AddressResidency<V: ResidencyVenue, G: Copy + Eq> {
    generation: G,
    venue: V,
}
impl<V: ResidencyVenue, G: Copy + Eq> AddressResidency<V, G> {
    pub fn new(generation: G) -> Self {
        Self {
            generation,
            venue: V::default(),
        }
    }
    pub fn begin_load(&self) -> Result<ResidencyLoad<V>, ResidencyError> {
        let mut state = self.venue.lock();
        if state.lifecycle != ResidencyLifecycle::Live {
            return Err(ResidencyError::Retiring);
        }
        state.loading += 1;
        Ok(ResidencyLoad {
            venue: self.venue.clone(),
            active: true,
            hardware_dirty: false,
        })
    }
    pub fn is_retiring(&self) -> bool {
        self.venue.lock().lifecycle != ResidencyLifecycle::Live
    }
    pub fn was_installed(&self) -> bool {
        let state = self.venue.lock();
        state.installed || state.hardware_dirty
    }
    pub fn prepare_retirement(&self) -> Result<PreparedResidencyRetirement<V, G>, ResidencyError> {
        let mut state = self.venue.lock();
        if state.lifecycle != ResidencyLifecycle::Live {
            return Err(ResidencyError::AlreadyRetiring);
        }
        state.lifecycle = ResidencyLifecycle::RetirementPrepared;
        Ok(PreparedResidencyRetirement {
            residency: self.clone(),
            active: true,
        })
    }
    pub fn begin_retirement(&self) -> Result<ResidencyRetirement<V, G>, ResidencyError> {
        Ok(self.prepare_retirement()?.commit())
    }
}

#[derive(Debug)]
pub struct ResidencyLoad<V: ResidencyVenue> {
    venue: V,
    active: bool,
    hardware_dirty: bool,
}
impl<V: ResidencyVenue> ResidencyLoad<V> {
    pub fn arm_hardware_dirty(&mut self) -> Result<(), ResidencyError> {
        if self.hardware_dirty {
            return Err(ResidencyError::HardwareAlreadyDirty);
        }
        if !self.active {
            return Err(ResidencyError::UnexpectedLoad);
        }
        self.venue.lock().hardware_dirty = true;
        self.hardware_dirty = true;
        Ok(())
    }
    pub fn mark_resident(mut self) -> Result<(), ResidencyError> {
        let mut state = self.venue.lock();
        state.loading = state
            .loading
            .checked_sub(1)
            .ok_or(ResidencyError::UnexpectedLoad)?;
        state.installed = true;
        self.active = false;
        self.venue.notify_all();
        Ok(())
    }
}
impl<V: ResidencyVenue> Drop for ResidencyLoad<V> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // Cancellation after the hardware boundary cannot erase exposure.
        let mut state = self.venue.lock();
        state.loading = state.loading.saturating_sub(1);
        self.venue.notify_all();
    }
}

#[derive(Debug)]
pub struct PreparedResidencyRetirement<V: ResidencyVenue, G: Copy + Eq> {
    residency: AddressResidency<V, G>,
    active: bool,
}
impl<V: ResidencyVenue, G: Copy + Eq> PreparedResidencyRetirement<V, G> {
    pub fn needs_invalidation(&self) -> bool {
        let state = self.residency.venue.lock();
        state.installed || state.hardware_dirty || state.loading != 0
    }
    pub fn requires_quarantine(&self) -> bool {
        let state = self.residency.venue.lock();
        state.hardware_dirty || state.loading != 0
    }
    pub fn commit(mut self) -> ResidencyRetirement<V, G> {
        // Only this non-cloneable token can leave RetirementPrepared.
        self.residency.venue.lock().lifecycle = ResidencyLifecycle::Retired;
        self.active = false;
        ResidencyRetirement {
            generation: self.residency.generation,
            venue: self.residency.venue.clone(),
        }
    }
}
impl<V: ResidencyVenue, G: Copy + Eq> Drop for PreparedResidencyRetirement<V, G> {
    fn drop(&mut self) {
        if self.active {
            self.residency.venue.lock().lifecycle = ResidencyLifecycle::Live;
        }
    }
}

#[derive(Debug)]
pub struct ResidencyRetirement<V: ResidencyVenue, G: Copy + Eq> {
    generation: G,
    venue: V,
}
impl<V: ResidencyVenue, G: Copy + Eq> ResidencyRetirement<V, G> {
    pub const fn generation(&self) -> G {
        self.generation
    }
    pub fn wait_for_admitted_loads(&self) {
        let mut state = self.venue.lock();
        while state.loading != 0 {
            self.venue.wait(&mut state);
        }
    }
    pub fn needs_invalidation(&self) -> bool {
        let state = self.venue.lock();
        (state.installed || state.hardware_dirty || state.loading != 0) && !state.invalidated
    }
    pub fn acknowledge(
        &self,
        invalidation: impl InvalidationProof<G>,
    ) -> Result<(), ResidencyError> {
        if invalidation.generation() != self.generation {
            return Err(ResidencyError::StaleGeneration);
        }
        let mut state = self.venue.lock();
        if state.loading != 0 {
            return Err(ResidencyError::ExecutorStillLoading);
        }
        state.invalidated = true;
        Ok(())
    }
    pub fn is_complete(&self) -> bool {
        let state = self.venue.lock();
        state.invalidated || (!state.installed && !state.hardware_dirty && state.loading == 0)
    }
}

use core::sync::atomic::{AtomicU64, Ordering};
static NEXT_ROOT_RETIREMENT_NONCE: AtomicU64 = AtomicU64::new(1);

/// Native geometry of one structural root extent; no ownership is conferred.
pub trait RootSlot: Copy + Eq + fmt::Debug {
    fn base(self) -> u64;
    fn size(self) -> u64;
}

/// Backend proof that structural backing is terminal, including every pin.
///
/// # Safety
/// Coordinates must name the exact terminal physical custody record. Removing
/// a memslot or reloading one CPU's root is insufficient to mint this proof.
pub unsafe trait TerminalRootProof {
    fn base(&self) -> u64;
    fn size(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootRetirementError {
    Incomplete,
    TicketAlreadyIssued,
    TicketUnavailable,
    ReceiptMissing,
    UnexpectedReceipt,
    Mismatch {
        expected_base: u64,
        expected_size: u64,
        actual_base: u64,
        actual_size: u64,
    },
}
impl fmt::Display for RootRetirementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "root retirement: {self:?}")
    }
}
impl core::error::Error for RootRetirementError {}

/// One-shot ticket; it carries the nonce through terminal backend custody.
#[derive(Debug)]
pub struct RootRetirementTicket<S: RootSlot> {
    slot: S,
    nonce: u64,
}
impl<S: RootSlot> RootRetirementTicket<S> {
    pub fn base(&self) -> u64 {
        self.slot.base()
    }
    pub fn size(&self) -> u64 {
        self.slot.size()
    }
    pub fn redeem(
        self,
        proof: impl TerminalRootProof,
    ) -> Result<RootRetirementReceipt<S>, RootRetirementError> {
        if (proof.base(), proof.size()) != (self.slot.base(), self.slot.size()) {
            return Err(RootRetirementError::Mismatch {
                expected_base: self.slot.base(),
                expected_size: self.slot.size(),
                actual_base: proof.base(),
                actual_size: proof.size(),
            });
        }
        Ok(RootRetirementReceipt {
            slot: self.slot,
            nonce: self.nonce,
        })
    }
}
#[derive(Debug)]
pub struct RootRetirementReceipt<S: RootSlot> {
    slot: S,
    nonce: u64,
}

/// The sole root-reuse gate for one retirement. Neither cloneable nor mintable
/// from a receipt; aborted admission burns a nonce without authorizing reuse.
#[derive(Debug)]
pub struct RootQuarantine<S: RootSlot> {
    slot: Option<S>,
    nonce: Option<u64>,
    ticket_issued: bool,
}
impl<S: RootSlot> RootQuarantine<S> {
    pub const fn rootless() -> Self {
        Self {
            slot: None,
            nonce: None,
            ticket_issued: false,
        }
    }
    pub fn reserve(slot: Option<S>) -> Result<Self, RootRetirementError> {
        let Some(slot) = slot else {
            return Ok(Self::rootless());
        };
        let nonce = NEXT_ROOT_RETIREMENT_NONCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| RootRetirementError::TicketUnavailable)?;
        Ok(Self {
            slot: Some(slot),
            nonce: Some(nonce),
            ticket_issued: false,
        })
    }
    pub fn take_ticket(&mut self) -> Result<Option<RootRetirementTicket<S>>, RootRetirementError> {
        let Some(slot) = self.slot else {
            return Ok(None);
        };
        if self.ticket_issued {
            return Err(RootRetirementError::TicketAlreadyIssued);
        }
        let nonce = self.nonce.ok_or(RootRetirementError::TicketUnavailable)?;
        self.ticket_issued = true;
        Ok(Some(RootRetirementTicket { slot, nonce }))
    }
    fn settle(
        self,
        receipt: Option<RootRetirementReceipt<S>>,
    ) -> Result<Option<S>, RootRetirementError> {
        match (self.slot, self.nonce, receipt) {
            (None, None, None) => Ok(None),
            (Some(slot), Some(nonce), Some(receipt))
                if receipt.slot == slot && receipt.nonce == nonce =>
            {
                Ok(Some(slot))
            }
            (Some(slot), _, Some(receipt)) => Err(RootRetirementError::Mismatch {
                expected_base: slot.base(),
                expected_size: slot.size(),
                actual_base: receipt.slot.base(),
                actual_size: receipt.slot.size(),
            }),
            (Some(_), _, None) => Err(RootRetirementError::ReceiptMissing),
            (None, _, Some(_)) | (None, Some(_), None) => {
                Err(RootRetirementError::UnexpectedReceipt)
            }
        }
    }
}
impl<V: ResidencyVenue, G: Copy + Eq> ResidencyRetirement<V, G> {
    /// Reuse follows settled loads, required invalidation, and exact terminal
    /// structural custody. No caller-supplied completion boolean is accepted.
    pub fn complete_root<S: RootSlot>(
        &self,
        root: RootQuarantine<S>,
        receipt: Option<RootRetirementReceipt<S>>,
    ) -> Result<Option<S>, RootRetirementError> {
        if !self.is_complete() {
            return Err(RootRetirementError::Incomplete);
        }
        root.settle(receipt)
    }
}

pub use carrick_core_abi::mm::custody::*;

pub fn record_identity_mismatch(
    record: &CarrierStage2Record,
    identity: CarrierStage2RecordIdentity,
) -> Option<CarrierStage2RetireOutcome> {
    if record.snapshot.record_id != identity.record_id {
        return Some(CarrierStage2RetireOutcome::NotFound);
    }
    if record.snapshot.vm_generation != identity.vm_generation {
        return Some(CarrierStage2RetireOutcome::VmGenerationMismatch);
    }
    match (record.snapshot.logical_owner, identity.logical_owner) {
        (Some(expected), Some(actual)) if expected.id != actual.id => {
            Some(CarrierStage2RetireOutcome::OwnerIdentityMismatch)
        }
        (Some(expected), Some(actual)) if expected.generation != actual.generation => {
            Some(CarrierStage2RetireOutcome::OwnerGenerationMismatch)
        }
        (None, None) | (Some(_), Some(_)) => None,
        (None, Some(_)) | (Some(_), None) => {
            Some(CarrierStage2RetireOutcome::OwnerIdentityMismatch)
        }
    }
}

/// Supplies lookup/exclusion over the backend's one physical custody ledger.
pub trait RecordPinVenue: fmt::Debug {
    fn release_pin(&self, identity: CarrierStage2RecordIdentity);
}
#[derive(Debug)]
pub struct RecordPin<V: RecordPinVenue> {
    venue: V,
    identity: CarrierStage2RecordIdentity,
    active: bool,
}
impl<V: RecordPinVenue> RecordPin<V> {
    pub fn into_transferred_identity(mut self) -> CarrierStage2RecordIdentity {
        self.active = false;
        self.identity
    }
}
impl<V: RecordPinVenue> Drop for RecordPin<V> {
    fn drop(&mut self) {
        if self.active {
            self.venue.release_pin(self.identity);
        }
    }
}

pub fn pin_record<V: RecordPinVenue>(
    record: &mut CarrierStage2Record,
    identity: CarrierStage2RecordIdentity,
    venue: V,
) -> Result<RecordPin<V>, CarrierStage2PinError> {
    if let Some(mismatch) = record_identity_mismatch(record, identity) {
        return Err(match mismatch {
            CarrierStage2RetireOutcome::VmGenerationMismatch => {
                CarrierStage2PinError::VmGenerationMismatch
            }
            CarrierStage2RetireOutcome::OwnerIdentityMismatch => {
                CarrierStage2PinError::OwnerIdentityMismatch
            }
            CarrierStage2RetireOutcome::OwnerGenerationMismatch => {
                CarrierStage2PinError::OwnerGenerationMismatch
            }
            _ => CarrierStage2PinError::NotFound,
        });
    }
    if record.snapshot.terminalized_by_vm_destroy {
        return Err(CarrierStage2PinError::TerminalizedByVmDestroy);
    }
    if record.snapshot.retirement_requested || record.unmap_in_flight {
        return Err(CarrierStage2PinError::RetirementRequested);
    }
    if !record.snapshot.mapped {
        return Err(CarrierStage2PinError::NotMapped);
    }
    record.snapshot.pin_count = record
        .snapshot
        .pin_count
        .checked_add(1)
        .ok_or(CarrierStage2PinError::PinCountExhausted)?;
    Ok(RecordPin {
        venue,
        identity,
        active: true,
    })
}

pub fn request_record_retirement(
    record: &mut CarrierStage2Record,
    identity: CarrierStage2RecordIdentity,
) -> CarrierStage2RetireOutcome {
    if let Some(mismatch) = record_identity_mismatch(record, identity) {
        return mismatch;
    }
    if record.snapshot.terminalized_by_vm_destroy {
        return CarrierStage2RetireOutcome::TerminalizedByVmDestroy;
    }
    record.snapshot.retirement_requested = true;
    record.snapshot.retry_eligible = record.snapshot.pin_count == 0;
    CarrierStage2RetireOutcome::DeferredActivePins
}
#[derive(Debug, Eq, PartialEq)]
pub enum RecordRetirement {
    Complete(CarrierStage2RetireOutcome),
    Unmap { ipa: u64, len: usize },
}
pub fn prepare_record_retirement(
    record: &mut CarrierStage2Record,
    identity: CarrierStage2RecordIdentity,
) -> RecordRetirement {
    if let Some(mismatch) = record_identity_mismatch(record, identity) {
        return RecordRetirement::Complete(mismatch);
    }
    if record.snapshot.terminalized_by_vm_destroy {
        return RecordRetirement::Complete(CarrierStage2RetireOutcome::TerminalizedByVmDestroy);
    }
    record.snapshot.retirement_requested = true;
    if record.snapshot.pin_count != 0 {
        record.snapshot.retry_eligible = false;
        return RecordRetirement::Complete(CarrierStage2RetireOutcome::DeferredActivePins);
    }
    if !record.snapshot.mapped {
        record.snapshot.retry_eligible = false;
        record.snapshot.retry_pending = None;
        return RecordRetirement::Complete(CarrierStage2RetireOutcome::RetiredUnmapped);
    }
    if record.unmap_in_flight {
        return RecordRetirement::Complete(CarrierStage2RetireOutcome::RetryPending(
            CarrierStage2BackendError::ConcurrentRetirement,
        ));
    }
    if !record.snapshot.backend_map_installed {
        record.snapshot.mapped = false;
        record.snapshot.retry_eligible = false;
        record.snapshot.retry_pending = None;
        return RecordRetirement::Complete(CarrierStage2RetireOutcome::RetiredUnmapped);
    }
    record.unmap_in_flight = true;
    record.snapshot.retry_eligible = false;
    RecordRetirement::Unmap {
        ipa: record.snapshot.ipa,
        len: record.snapshot.len,
    }
}
pub fn settle_record_retirement(
    record: &mut CarrierStage2Record,
    identity: CarrierStage2RecordIdentity,
    backend_result: Result<(), CarrierStage2BackendError>,
) -> CarrierStage2RetireOutcome {
    if let Some(mismatch) = record_identity_mismatch(record, identity) {
        return mismatch;
    }
    record.unmap_in_flight = false;
    if record.snapshot.terminalized_by_vm_destroy {
        return CarrierStage2RetireOutcome::TerminalizedByVmDestroy;
    }
    match backend_result {
        Ok(()) => {
            record.snapshot.mapped = false;
            record.snapshot.backend_map_installed = false;
            record.snapshot.retry_eligible = false;
            record.snapshot.retry_pending = None;
            CarrierStage2RetireOutcome::RetiredUnmapped
        }
        Err(error) => {
            record.snapshot.retry_eligible = true;
            record.snapshot.retry_pending = Some(error);
            CarrierStage2RetireOutcome::RetryPending(error)
        }
    }
}
/// Whether the physical ledger can discard a terminal superseded predecessor.
pub fn release_record_pin(
    record: &mut CarrierStage2Record,
    identity: CarrierStage2RecordIdentity,
) -> bool {
    if record_identity_mismatch(record, identity).is_some() {
        return false;
    }
    record.snapshot.pin_count = record.snapshot.pin_count.saturating_sub(1);
    if record.snapshot.pin_count == 0
        && record.snapshot.retirement_requested
        && record.snapshot.mapped
        && !record.snapshot.terminalized_by_vm_destroy
    {
        record.snapshot.retry_eligible = true;
    }
    record.snapshot.pin_count == 0
        && record.snapshot.terminalized_by_vm_destroy
        && record.snapshot.superseded_by_rebind
}
pub fn terminalize_record(record: &mut CarrierStage2Record) {
    record.snapshot.mapped = false;
    record.snapshot.backend_map_installed = false;
    record.snapshot.retirement_requested = true;
    record.snapshot.retry_eligible = false;
    record.snapshot.retry_pending = None;
    record.snapshot.terminalized_by_vm_destroy = true;
    record.unmap_in_flight = false;
}

/// Retire the owner's published extensions before removing them from its one
/// capacity list. A refused physical unmap leaves remaining capacity charged.
pub fn retire_table_arenas<E>(
    published: &mut alloc::vec::Vec<u64>,
    root: Option<u64>,
    mut retire: impl FnMut(u64) -> Result<(), E>,
) -> Result<(), E> {
    let mut index = 0;
    while index < published.len() {
        let base = published[index];
        if Some(base) == root {
            index += 1;
            continue;
        }
        retire(base)?;
        published.swap_remove(index);
    }
    Ok(())
}

/// Borrowed outstanding inheritance, with physical/probe fields left native.
pub trait PendingRetirementReference {
    fn child_mapping(&self) -> carrick_core_abi::MappingId;
    fn frame(&self) -> carrick_core_abi::FrameId;
}
/// Why a retirement receipt did or did not authenticate, clause by clause.
///
/// The abort this feeds is unrecoverable, so it must name the failing clause: a
/// receipt that leaves the mm non-empty, one that covers a different number of
/// mappings, and one that omits a pending fork frame call for entirely different
/// fixes, and a bare "malformed" verdict cannot tell them apart.
#[derive(Clone, Copy, Debug)]
pub struct PendingRetirementAudit {
    mm_empty_at_revision: bool,
    expected_non_empty: bool,
    cardinality_matches: bool,
    expected_authorized: bool,
    pending_authorized: bool,
}

impl PendingRetirementAudit {
    pub const fn ok(self) -> bool {
        self.mm_empty_at_revision
            && self.expected_non_empty
            && self.cardinality_matches
            && self.expected_authorized
            && self.pending_authorized
    }
}

pub fn authenticate_pending_retirement<P: PendingRetirementReference>(
    expected: &[(carrick_core_abi::MappingId, carrick_core_abi::FrameId)],
    pending: &[P],
    receipt: &carrick_core_abi::FrameInventoryRetirementReceipt,
) -> PendingRetirementAudit {
    // O((n + p) log n): `authorizes` is a binary search over the receipt's
    // sorted set, and pending receipts are matched against sorted expected
    // mapping ids. Both were linear scans per element (O(n^2) and O(p*n)).
    let mut expected_mappings: alloc::vec::Vec<carrick_core_abi::MappingId> =
        expected.iter().map(|&(mapping, _)| mapping).collect();
    expected_mappings.sort_unstable();
    PendingRetirementAudit {
        mm_empty_at_revision: receipt.mm_empty_at_revision(),
        expected_non_empty: !expected.is_empty(),
        cardinality_matches: expected.len() == receipt.mapping_set().len(),
        expected_authorized: expected
            .iter()
            .all(|&(mapping, frame)| receipt.authorizes(mapping, frame)),
        // Only OUTSTANDING inheritances. A pending receipt records an
        // obligation created at fork publication: "this child mapping holds a
        // frame inherited from the parent". It is discharged either here, by the
        // retirement unmapping that mapping with that frame, or EARLIER, when
        // the mapping was superseded — `stage_cow_inventory_split` pushes its
        // own `UnmapMapping` and `RetireFrame` for the old mapping and
        // `commit_cow_inventory_split` drops the extent, all inside that
        // transaction. Demanding that retirement account for an already-settled
        // obligation is a category error, and it failed every forked child that
        // wrote to an inherited page: the superseded mapping id is simply absent
        // from the retirement's set. A mapping still live in `expected` must
        // still retire under the frame it inherited.
        pending_authorized: pending
            .iter()
            .filter(|pending| {
                expected_mappings
                    .binary_search(&pending.child_mapping())
                    .is_ok()
            })
            .all(|pending| receipt.authorizes(pending.child_mapping(), pending.frame())),
    }
}

/// The existing lease publication gate, now neutral. It is separate from
/// hardware residency: an uninstalled root still must close publication.
#[derive(Debug, Default)]
pub struct LeaseGate {
    lifecycle: ResidencyLifecycle,
}
impl LeaseGate {
    pub fn is_live(&self) -> bool {
        self.lifecycle == ResidencyLifecycle::Live
    }
    pub fn prepare(&mut self) -> bool {
        if !self.is_live() {
            return false;
        }
        self.lifecycle = ResidencyLifecycle::RetirementPrepared;
        true
    }
    /// Called by the existing non-cloneable prepared retirement's commit.
    pub fn commit(&mut self) {
        self.lifecycle = ResidencyLifecycle::Retired;
    }
    /// Reopen only after physical allocation and residency rollback settle.
    pub fn rollback(&mut self) {
        if self.lifecycle == ResidencyLifecycle::RetirementPrepared {
            self.lifecycle = ResidencyLifecycle::Live;
        }
    }
}
/// Existing sched-core publication, owned by the kernel's placement adapter.
pub trait AddressPublication {
    fn retire_reservations(&self);
}
/// Drop the closed publication (draining sched-core occupants) before waiting
/// for admitted host loads and deciding which hardware invalidation is owed.
pub fn drain_publication<V: ResidencyVenue, G: Copy + Eq, P: AddressPublication>(
    publication: Option<P>,
    residency: &ResidencyRetirement<V, G>,
) {
    if let Some(publication) = publication.as_ref() {
        publication.retire_reservations();
    }
    drop(publication);
    residency.wait_for_admitted_loads();
}
