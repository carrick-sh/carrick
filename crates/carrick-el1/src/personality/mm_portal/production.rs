//! Transfers borrow the admitted production owner. No table or frame ledger
//! is constructed here. Physical pinning happens after selection, on host.
use super::{El1MmHandle, GuestVa, MmError, TransferIntent};
use crate::fault::{CowResolver, PreparedPageResolver, request_lazy_frames};
use crate::memory::reservations::{Reservations, ResolvedReservationNodes, SharedReservations};
use carrick_el1_abi::{
    FrameGrantMailbox, FrameGrantResidencyTable, PinnedMetadataExtent, ReservationMm,
    ReservationProtection,
};
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_mmu_core::aarch64::{GuestPreparedCommit, LeafAccess, terminal_descriptor_permits_el0};
use carrick_sched_core::{AddressSpaces, SpaceEditor};
use core::num::NonZeroU64;

/// At most one Linux page is fenced through a host memcpy. Bigger transfers
/// retain their byte offset and select/revalidate each next page separately.
pub const TRANSFER_CHUNK_BYTES: u64 = 4096;
const PA: u64 = 0x0000_ffff_ffff_f000;

pub struct MmPortal<'a, P: PinnedMetadataExtent> {
    pub(super) carrier: NonZeroU64,
    pub(super) roots: &'a SharedReservations,
    pub(super) spaces: &'a AddressSpaces,
    pub(super) nodes: Option<&'a ResolvedReservationNodes<P>>,
    pub(super) zone: Option<&'a carrick_sched_core::ZoneTables>,
    #[cfg(any(test, feature = "host-test"))]
    pub(super) vma_visits: core::sync::atomic::AtomicUsize,
}

/// Authenticated before effects, while dropping the claim can restore LIVE.
/// Publication cannot reject a prepared settlement afterward.
enum PreparedDelivery<'a> {
    Standalone,
    Scheduler {
        zone: &'a carrick_sched_core::ZoneTables,
        key: carrick_sched_core::object_wait::ObjectWaitKey,
        waker: carrick_sched_core::SlotId,
    },
}
impl PreparedDelivery<'_> {
    fn publish(self) {
        if let Self::Scheduler { zone, key, waker } = self {
            let completion =
                |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>| {
                    crate::substrate::sched::object_wait::deliver_completion(zone, waker, effects)
                };
            // SAFETY: this capability came from the exact claimed node's
            // retained PREPARE admission, before that claim was released.
            unsafe { zone.retained_object_notification(key) }
                .publish(carrick_sched_core::Waker::El1 { slot: waker }, &completion);
        }
    }
}

/// Owned request position. Suspension never discards already copied bytes.
pub struct TransferContinuation {
    pub handle: El1MmHandle,
    pub intent: TransferIntent,
    address: GuestVa,
    len: u64,
    offset: u64,
    sequence: NonZeroU64,
    fork_sequence: Option<NonZeroU64>,
}

impl TransferContinuation {
    fn new(
        handle: El1MmHandle,
        address: GuestVa,
        len: u64,
        intent: TransferIntent,
        sequence: NonZeroU64,
    ) -> Result<Self, MmError> {
        address.raw().checked_add(len).ok_or(MmError::Invalid)?;
        Ok(Self {
            handle,
            intent,
            address,
            len,
            offset: 0,
            sequence,
            fork_sequence: None,
        })
    }
    pub fn settle(
        &mut self,
        request: carrick_el1_abi::PortalTransferRequest,
        receipt: carrick_el1_abi::PortalTransferCompletion,
    ) -> Result<(), MmError> {
        if receipt.operation != request.operation
            || receipt.retained != request.retained
            || request.operation.carrier != self.handle.carrier()
            || request.operation.mm != self.handle.mm()
            || request.operation.incarnation != self.handle.incarnation()
            || request.operation.sequence != self.sequence
            || request.selected.offset != self.offset
            || request.range.address() != self.address.raw() + self.offset
            || receipt.completed > request.range.len()
            || receipt.completed > self.len - self.offset
        {
            return Err(MmError::Stale);
        }
        self.offset += receipt.completed;
        Ok(())
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn is_complete(&self) -> bool {
        self.offset == self.len
    }
}

/// EL1-selected data, not metadata storage. Host enriches this with its exact
/// physical record identity and retains the matching stage-2 pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedChunk {
    fork_sequence: Option<NonZeroU64>,
    handle: El1MmHandle,
    sequence: NonZeroU64,
    pub(super) generation: u64,
    offset: u64,
    pub va: GuestVa,
    pub ipa: u64,
    pub executable: bool,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferStep {
    Selected(SelectedChunk),
    Supply(carrick_el1_abi::PortalGrantWindow),
    CowSupply(carrick_el1_abi::PortalGrantWindow),
    /// A gate/editor wait or the existing lazy FrameGrantRequest path. No
    /// root lock, editor, or physical pin survives this return.
    Suspended,
    Complete,
}

/// Exact-MM authorization for one bounded copy. A host custodian must retain
/// the selected physical identities before obtaining this fence. Drop before
/// any host I/O, lazy supply, suspension, or selection of the next chunk.
pub struct ValidatedChunk<'a> {
    selected: SelectedChunk,
    _editor: SpaceEditor<'a>,
}
impl ValidatedChunk<'_> {
    pub fn selected(&self) -> SelectedChunk {
        self.selected
    }
    pub fn complete(self, continuation: &mut TransferContinuation) -> Result<(), MmError> {
        if continuation.handle != self.selected.handle
            || continuation.sequence != self.selected.sequence
            || continuation.offset != self.selected.offset
        {
            return Err(MmError::Stale);
        }
        continuation.offset += self.selected.len;
        Ok(())
    }
}

impl<'a, P: PinnedMetadataExtent> MmPortal<'a, P> {
    pub fn new(
        carrier: NonZeroU64,
        roots: &'a SharedReservations,
        spaces: &'a AddressSpaces,
        nodes: &'a ResolvedReservationNodes<P>,
    ) -> Self {
        Self {
            carrier,
            roots,
            spaces,
            nodes: Some(nodes),
            zone: None,
            #[cfg(any(test, feature = "host-test"))]
            vma_visits: core::sync::atomic::AtomicUsize::new(0),
        }
    }
    /// Add the production scheduler, using the same address-space authority.
    pub fn with_zone(mut self, zone: &'a carrick_sched_core::ZoneTables) -> Result<Self, MmError> {
        if !core::ptr::eq(self.spaces, &zone.spaces) {
            return Err(MmError::Stale);
        }
        self.zone = Some(zone);
        Ok(self)
    }
    pub fn prepared_wait_key(
        &self,
        handle: El1MmHandle,
    ) -> Result<carrick_sched_core::object_wait::ObjectWaitKey, MmError> {
        if handle.carrier() != self.carrier {
            return Err(MmError::Stale);
        }
        let index = self
            .spaces
            .find(handle.mm().raw())
            .ok_or(MmError::Stale)?
            .index();
        carrick_sched_core::object_wait::ObjectWaitKey::address_space(
            index,
            handle.incarnation().get(),
        )
        .ok_or(MmError::Stale)
    }
    fn prepared_delivery(
        &self,
        claim: &crate::memory::reservations::ClaimedPreparedCopy<'_>,
        slot: u32,
    ) -> Result<PreparedDelivery<'_>, MmError> {
        let Some(key) = claim.notification() else {
            return Ok(PreparedDelivery::Standalone);
        };
        let zone = self.zone.ok_or(MmError::Core)?;
        let waker =
            carrick_sched_core::SlotId::from_index(slot as usize).ok_or(MmError::Invalid)?;
        Ok(PreparedDelivery::Scheduler { zone, key, waker })
    }
    /// Release semantic custody by exact atomic identity. This does not
    /// acquire the root or descriptor editor, even while either is held.
    pub fn cancel_prepared(
        &self,
        permit: carrick_el1_abi::PortalPreparedPermit,
        request: carrick_el1_abi::PortalTransferRequest,
        slot: u32,
    ) -> Result<(), MmError> {
        if request.operation.carrier != self.carrier
            || carrick_sched_core::SlotId::from_index(slot as usize).is_none()
        {
            return Err(MmError::Stale);
        }
        let claim = self.roots.claim_prepared(self.nodes, permit, request)?;
        let delivery = self.prepared_delivery(&claim, slot)?;
        if !claim.release() {
            return Err(MmError::Stale);
        }
        delivery.publish();
        Ok(())
    }
    pub(super) fn space_access(
        &self,
        slot: u32,
    ) -> Result<carrick_sched_core::spaces::notification::SpaceAccess<'_>, MmError> {
        if let Some(zone) = self.zone {
            let slot =
                carrick_sched_core::SlotId::from_index(slot as usize).ok_or(MmError::Invalid)?;
            return Ok(crate::substrate::sched::object_wait::space_access(
                zone, slot,
            ));
        }
        #[cfg(any(test, feature = "host-test"))]
        {
            return Ok(
                carrick_sched_core::spaces::notification::SpaceAccess::source_free(self.spaces),
            );
        }
        #[cfg(not(any(test, feature = "host-test")))]
        Err(MmError::Stale)
    }
    pub(super) fn root_any(
        &self,
        mm: ReservationMm,
        slot: u32,
    ) -> Result<Reservations<'_>, MmError> {
        let index = self.spaces.find(mm.raw()).ok_or(MmError::Stale)?.index();
        if let Some(venue) = self.space_access(slot)?.venue() {
            let roots = crate::memory::reservations::RootReleaseVenue::new(self.roots, venue)?;
            return match self.nodes {
                Some(nodes) => Ok(roots.lock_el1_resolved(index, mm, nodes, slot)?),
                None => Ok(roots.lock_el1(index, mm, slot)?),
            };
        }
        #[cfg(any(test, feature = "host-test"))]
        {
            return match self.nodes {
                Some(nodes) => Ok(self.roots.lock_el1_resolved(index, mm, nodes, slot)?),
                None => Ok(self.roots.lock_el1(index, mm, slot)?),
            };
        }
        #[cfg(not(any(test, feature = "host-test")))]
        Err(MmError::Stale)
    }
    pub(super) fn root(&self, mm: ReservationMm, slot: u32) -> Result<Reservations<'_>, MmError> {
        let index = self.spaces.find(mm.raw()).ok_or(MmError::Stale)?.index();
        if !self.roots.admitted(index, mm) {
            return Err(MmError::Stale);
        }
        self.root_any(mm, slot)
    }

    pub fn admitted_handle(&self, mm: ReservationMm, slot: u32) -> Result<El1MmHandle, MmError> {
        let root = self.root(mm, slot)?;
        // SAFETY: this exact root is production-admitted and retained above.
        Ok(unsafe {
            El1MmHandle::from_admitted_owner(
                self.carrier,
                mm,
                NonZeroU64::new(root.incarnation().raw()).ok_or(MmError::Stale)?,
            )
        })
    }
    pub fn begin(
        &self,
        handle: El1MmHandle,
        address: GuestVa,
        len: u64,
        intent: TransferIntent,
        slot: u32,
    ) -> Result<TransferContinuation, MmError> {
        if handle.carrier() != self.carrier {
            return Err(MmError::Stale);
        }
        let mut root = self.root_for(handle, slot)?;
        if root.incarnation().raw() != handle.incarnation().get() {
            return Err(MmError::Stale);
        }
        let sequence = root.next_transfer_sequence()?;
        TransferContinuation::new(handle, address, len, intent, sequence)
    }
    pub fn begin_fork_parent_write(
        &self,
        handle: El1MmHandle,
        address: GuestVa,
        len: u64,
        intent: TransferIntent,
        fork_sequence: NonZeroU64,
        slot: u32,
    ) -> Result<TransferContinuation, MmError> {
        if handle.carrier() != self.carrier
            || !matches!(intent, TransferIntent::UserRead | TransferIntent::UserWrite)
        {
            return Err(MmError::Stale);
        }
        let mut root = self.root_for(handle, slot)?;
        if root.incarnation().raw() != handle.incarnation().get() {
            return Err(MmError::Stale);
        }
        let sequence = root.next_fork_write_sequence(fork_sequence)?;
        let mut continuation = TransferContinuation::new(handle, address, len, intent, sequence)?;
        continuation.fork_sequence = Some(fork_sequence);
        Ok(continuation)
    }
    fn observe_wait(
        &self,
        handle: El1MmHandle,
        cause: carrick_el1_abi::PortalWaitCause,
    ) -> Result<Option<carrick_el1_abi::PortalOwnerWait>, MmError> {
        use carrick_el1_abi::PortalWaitCause as Wire;
        use carrick_sched_core::spaces::notification::SpaceWaitCause as Cause;
        if handle.carrier() != self.carrier {
            return Err(MmError::Stale);
        }
        let Some(zone) = self.zone else {
            #[cfg(any(test, feature = "host-test"))]
            return Ok(None);
            #[cfg(not(any(test, feature = "host-test")))]
            return Err(MmError::Stale);
        };
        let entry = zone
            .space_entry(NonZeroU64::new(handle.mm().raw()).ok_or(MmError::Stale)?)
            .ok_or(MmError::Stale)?;
        let source = entry
            .notifications(handle.incarnation())
            .map_err(|_| MmError::Stale)?;
        let source_cause = match cause {
            Wire::Editor => Cause::Editor,
            Wire::Reservations => Cause::Reservations,
            Wire::PendingEdit => Cause::PendingEdit,
            Wire::Gate => Cause::Gate,
            Wire::Metadata => Cause::Metadata,
            Wire::ReservationPool => return Err(MmError::Invalid),
        };
        // SAFETY: exact live source authenticated above; caller probes afterward.
        Ok(Some(unsafe {
            carrick_el1_abi::PortalOwnerWait::from_owner(
                handle,
                cause,
                source.observe(source_cause).revision(),
            )
        }))
    }
    fn editor_for(&self, handle: El1MmHandle, slot: u32) -> Result<SpaceEditor<'_>, MmError> {
        use carrick_el1_abi::PortalWaitCause;
        use carrick_sched_core::spaces::EditAdmissionRefusal;
        let editor = self.observe_wait(handle, PortalWaitCause::Editor)?;
        let gate = self.observe_wait(handle, PortalWaitCause::Gate)?;
        let index = self.spaces.find(handle.mm().raw()).ok_or(MmError::Stale)?;
        let access = self.space_access(slot)?;
        self.spaces
            .try_begin_edit_cause(
                index,
                handle.mm().raw(),
                NonZeroU64::new(u64::from(slot) + 1).ok_or(MmError::Invalid)?,
                access.venue(),
            )
            .map_err(|cause| match cause {
                EditAdmissionRefusal::Editor => editor.map_or(MmError::Busy, MmError::Wait),
                EditAdmissionRefusal::Gate => gate.map_or(MmError::Busy, MmError::Wait),
                EditAdmissionRefusal::Stale => MmError::Stale,
            })
    }
    fn root_for(&self, handle: El1MmHandle, slot: u32) -> Result<Reservations<'_>, MmError> {
        let observed = self.observe_wait(handle, carrick_el1_abi::PortalWaitCause::Reservations)?;
        let root = self.root(handle.mm(), slot).map_err(|error| match error {
            MmError::Busy => observed.map_or(MmError::Busy, MmError::Wait),
            other => other,
        })?;
        if root.incarnation().raw() != handle.incarnation().get() {
            return Err(MmError::Stale);
        }
        Ok(root)
    }
    fn authorize(
        &self,
        continuation: &TransferContinuation,
        va: u64,
        len: u64,
        slot: u32,
    ) -> Result<u64, MmError> {
        if continuation.handle.carrier() != self.carrier {
            return Err(MmError::Stale);
        }
        let pending = self.observe_wait(
            continuation.handle,
            carrick_el1_abi::PortalWaitCause::PendingEdit,
        )?;
        let mut root = self.root_for(continuation.handle, slot)?;
        if root.fork_pending() && !root.fork_write_authorized(continuation.fork_sequence) {
            return Err(pending.map_or(MmError::Busy, MmError::Wait));
        }
        if root.incarnation().raw() != continuation.handle.incarnation().get() {
            return Err(MmError::Stale);
        }
        if root.pending().is_some() {
            return Err(pending.map_or(MmError::Busy, MmError::Wait));
        }
        if continuation.intent == TransferIntent::CarrickInternalRead {
            // Production image header page: immutable after image admission,
            // kernel-only and never a generic privileged user-copy bypass.
            let base = carrick_el1_abi::EL1_REGION_BASE + carrick_el1_abi::EL1_IMAGE_OFFSET;
            if va < base || va.checked_add(len).is_none_or(|end| end > base + 4096) {
                return Err(MmError::Fault);
            }
        } else {
            let mapping = root.mapping(va).ok_or(MmError::Fault)?;
            let access = match continuation.intent {
                TransferIntent::UserWrite => ReservationProtection::from_bits(2).unwrap(),
                TransferIntent::ReadInstruction => ReservationProtection::from_bits(4).unwrap(),
                _ => ReservationProtection::from_bits(1).unwrap(),
            };
            if !mapping.protection.permits(access) || va + len > mapping.range.end() {
                return Err(MmError::Fault);
            }
        }
        #[cfg(any(test, feature = "host-test"))]
        self.vma_visits
            .fetch_add(root.work, core::sync::atomic::Ordering::Relaxed);
        Ok(root.generation().raw())
    }

    // These are independently borrowed production owner venues, not portal state.
    #[allow(clippy::too_many_arguments)]
    pub fn select<W: LiveDescriptorWords + ?Sized, R: PreparedPageResolver, C: CowResolver>(
        &self,
        continuation: &TransferContinuation,
        words: &W,
        prepared: &mut R,
        cow: &mut C,
        residency: &FrameGrantResidencyTable,
        mailbox: &FrameGrantMailbox,
        slot: u32,
    ) -> Result<TransferStep, MmError> {
        if continuation.is_complete() {
            return Ok(TransferStep::Complete);
        }
        let mm = continuation.handle.mm().raw();
        let index = self.spaces.find(mm).ok_or(MmError::Stale)?;
        let _editor = match self.editor_for(continuation.handle, slot) {
            Err(MmError::Busy) => return Ok(TransferStep::Suspended),
            result => result?,
        };
        let gate =
            self.observe_wait(continuation.handle, carrick_el1_abi::PortalWaitCause::Gate)?;
        let Some(grant) = self.spaces.grant(index, mm) else {
            return match gate {
                Some(wait) => Err(MmError::Wait(wait)),
                None => Ok(TransferStep::Suspended),
            };
        };
        let va = continuation.address.raw() + continuation.offset;
        let len = (continuation.len - continuation.offset).min(4096 - (va & 4095));
        let generation = match self.authorize(continuation, va, len, slot) {
            Err(MmError::Busy) => return Ok(TransferStep::Suspended),
            result => result?,
        };
        let access = match continuation.intent {
            TransferIntent::UserWrite => LeafAccess::Write,
            TransferIntent::ReadInstruction => LeafAccess::Execute,
            _ => LeafAccess::Read,
        };
        let root = grant.ttbr0 & PA;
        let mut leaf = match translated(words, root, va, access, continuation.intent) {
            Err(MmError::Fault) if access == LeafAccess::Write => {
                use carrick_mmu_core::aarch64::descriptor_txn::guest_cow::{
                    GuestCowClass, GuestCowNotArmed, classify_guest_cow_write,
                };
                match classify_guest_cow_write(
                    words,
                    carrick_mmu_core::aarch64::SubstrateGpa(root),
                    va,
                    cow.executable_publication(),
                ) {
                    Ok(_) | Err(GuestCowClass::AlreadyWritable) => {}
                    Err(GuestCowClass::NotArmed(GuestCowNotArmed::Executable)) => {
                        return Err(MmError::UnsupportedExecutableCow);
                    }
                    Err(GuestCowClass::NotArmed(_)) => return Err(MmError::Fault),
                    Err(GuestCowClass::Unreachable(_)) => return Err(MmError::Core),
                }
                match cow.resolve_cow_outcome(grant.ttbr0, mm, va) {
                    crate::fault::CowResolution::Resolved => {
                        #[cfg(target_os = "none")]
                        if let (Some(sequence), Some(completion)) =
                            (continuation.fork_sequence, cow.take_cow_completion())
                        {
                            super::fork::reconcile_pending_parent_write(
                                slot as usize,
                                continuation.handle,
                                sequence,
                                completion,
                                words,
                            )?;
                        }
                    }
                    crate::fault::CowResolution::Refused => return Err(MmError::Core),
                    crate::fault::CowResolution::NeedsSupply => {
                        let mut root = self.root(continuation.handle.mm(), slot)?;
                        if root.fork_pending()
                            && !root.fork_write_authorized(continuation.fork_sequence)
                        {
                            return Err(MmError::Busy);
                        }
                        // The live classifier already proved private COW.
                        // Imported file nodes participate here even though
                        // anonymous zero-fill fault_plan must reject them.
                        let mapping = root.mapping(va).ok_or(MmError::Fault)?;
                        if !mapping
                            .protection
                            .permits(ReservationProtection::READ_WRITE)
                        {
                            return Err(MmError::Fault);
                        }
                        let page = va & !4095;
                        let plan = crate::memory::reservations::ReservationFaultPlan {
                            mm: continuation.handle.mm(),
                            generation: mapping.generation,
                            range: carrick_el1_abi::ReservationRange::new(page, page + 4096)
                                .ok_or(MmError::Invalid)?,
                            protection: mapping.protection,
                            fault_page: page,
                        };
                        return Ok(TransferStep::CowSupply(
                            carrick_el1_abi::PortalGrantWindow {
                                operation: carrick_el1_abi::PortalOperation {
                                    carrier: continuation.handle.carrier(),
                                    mm: continuation.handle.mm(),
                                    incarnation: continuation.handle.incarnation(),
                                    sequence: continuation.sequence,
                                },
                                generation: plan.generation,
                                range: plan.range,
                                protection: plan.protection,
                                fault_page: plan.fault_page,
                                host_backing: None,
                                fork_sequence: continuation.fork_sequence,
                            },
                        ));
                    }
                }
                translated(words, root, va, access, continuation.intent)?
            }
            result => result?,
        };
        if leaf.is_none() {
            if let Some(page) = residency.lookup(mm, va)
                && matches!(
                    prepared.commit_prepared(grant.ttbr0, va, page.expected_ipa, access),
                    Ok(GuestPreparedCommit::Committed | GuestPreparedCommit::AlreadyResident)
                )
            {
                residency.record_commit(page);
            }
            leaf = translated(words, root, va, access, continuation.intent)?;
        }
        let Some((ipa, executable)) = leaf else {
            // Permission policy was already checked. Reuse the one lazy supply
            // mailbox; failed admission keeps the same continuation position.
            let bits = match access {
                LeafAccess::Read => 1,
                LeafAccess::Write => 2,
                LeafAccess::Execute => 4,
            };
            let mut root = self.root(continuation.handle.mm(), slot)?;
            if root.fork_pending() && !root.fork_write_authorized(continuation.fork_sequence) {
                return Err(MmError::Busy);
            }
            let target = if root
                .mapping(va)
                .is_some_and(|mapping| mapping.host_backing.is_some())
            {
                4096
            } else {
                carrick_el1_abi::EL1_FRAME_GRANT_TARGET_SIZE
            };
            let plan = root.fork_transfer_fault_plan(
                va,
                target,
                ReservationProtection::from_bits(bits).ok_or(MmError::Invalid)?,
                continuation.fork_sequence,
            )?;
            let host_backing = root.mapping(plan.range.start()).and_then(|mapping| {
                mapping
                    .host_backing
                    .and_then(|source| source.advance(plan.range.start() - mapping.range.start()))
            });
            drop(root);
            if !request_lazy_frames(mailbox, mm, va, bits) {
                return Ok(TransferStep::Suspended);
            }
            return Ok(TransferStep::Supply(carrick_el1_abi::PortalGrantWindow {
                operation: carrick_el1_abi::PortalOperation {
                    carrier: continuation.handle.carrier(),
                    mm: continuation.handle.mm(),
                    incarnation: continuation.handle.incarnation(),
                    sequence: continuation.sequence,
                },
                generation: plan.generation,
                range: plan.range,
                protection: plan.protection,
                fault_page: plan.fault_page,
                host_backing,
                fork_sequence: continuation.fork_sequence,
            }));
        };
        Ok(TransferStep::Selected(SelectedChunk {
            fork_sequence: continuation.fork_sequence,
            handle: continuation.handle,
            sequence: continuation.sequence,
            generation,
            offset: continuation.offset,
            va: GuestVa::new(va),
            ipa,
            executable: continuation.intent == TransferIntent::UserWrite && executable,
            len,
        }))
    }

    /// Physical pins have been acquired, with no MM/root lock held. A stale
    /// selection returns Suspended so the caller releases pins and resumes
    /// selection at the current byte offset instead of restarting at zero.
    pub fn revalidate<W: LiveDescriptorWords + ?Sized>(
        &self,
        continuation: &TransferContinuation,
        selected: SelectedChunk,
        words: &W,
        slot: u32,
    ) -> Result<Option<ValidatedChunk<'_>>, MmError> {
        if selected.fork_sequence != continuation.fork_sequence
            || selected.handle != continuation.handle
            || selected.sequence != continuation.sequence
            || selected.offset != continuation.offset
        {
            return Err(MmError::Stale);
        }
        let mm = selected.handle.mm().raw();
        let index = self.spaces.find(mm).ok_or(MmError::Stale)?;
        let editor = match self.editor_for(selected.handle, slot) {
            Err(MmError::Busy) => return Ok(None),
            result => result?,
        };
        let gate = self.observe_wait(selected.handle, carrick_el1_abi::PortalWaitCause::Gate)?;
        let Some(grant) = self.spaces.grant(index, mm) else {
            return match gate {
                Some(wait) => Err(MmError::Wait(wait)),
                None => Ok(None),
            };
        };
        let generation = match self.authorize(continuation, selected.va.raw(), selected.len, slot) {
            Err(MmError::Fault | MmError::Busy) => return Ok(None),
            result => result?,
        };
        let access = match continuation.intent {
            TransferIntent::UserWrite => LeafAccess::Write,
            TransferIntent::ReadInstruction => LeafAccess::Execute,
            _ => LeafAccess::Read,
        };
        let current = match translated(
            words,
            grant.ttbr0 & PA,
            selected.va.raw(),
            access,
            continuation.intent,
        ) {
            Err(MmError::Fault) => return Ok(None),
            result => result?,
        };
        let expected = (selected.ipa, selected.executable);
        let current = current.map(|(ipa, executable)| {
            (
                ipa,
                continuation.intent == TransferIntent::UserWrite && executable,
            )
        });
        if generation != selected.generation || current != Some(expected) {
            return Ok(None);
        }
        Ok(Some(ValidatedChunk {
            selected,
            _editor: editor,
        }))
    }
}

fn translated<W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: u64,
    va: u64,
    access: LeafAccess,
    intent: TransferIntent,
) -> Result<Option<(u64, bool)>, MmError> {
    let mut table = root;
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let descriptor = words
            .load(table + ((va >> shift) & 511) * 8)
            .map_err(|_| MmError::Core)?;
        if descriptor & 1 == 0 {
            return Ok(None);
        }
        if level == 3 || descriptor & 3 == 1 {
            if level == 0 {
                return Err(MmError::Core);
            }
            if intent != TransferIntent::CarrickInternalRead
                && !terminal_descriptor_permits_el0(descriptor, access)
            {
                return Err(MmError::Fault);
            }
            let mask = (1u64 << shift) - 1;
            return Ok(Some((
                (descriptor & PA & !mask) + (va & mask),
                terminal_descriptor_permits_el0(descriptor, LeafAccess::Execute),
            )));
        }
        table = descriptor & PA;
    }
    Err(MmError::Core)
}

impl SelectedChunk {
    pub fn request(
        self,
        intent: TransferIntent,
        retained: carrick_el1_abi::PortalRetainedData,
    ) -> Result<carrick_el1_abi::PortalTransferRequest, MmError> {
        use carrick_el1_abi::{
            PortalByteRange, PortalOperation, PortalSelectedData, PortalTransferRequest,
        };
        PortalTransferRequest::new(
            PortalOperation {
                carrier: self.handle.carrier(),
                mm: self.handle.mm(),
                incarnation: self.handle.incarnation(),
                sequence: self.sequence,
            },
            PortalByteRange::new(self.va.raw(), self.len).ok_or(MmError::Invalid)?,
            intent,
            PortalSelectedData {
                ipa: self.ipa,
                executable: self.executable,
                root_generation: NonZeroU64::new(self.generation).ok_or(MmError::Stale)?,
                offset: self.offset,
            },
            retained,
        )
        .map(|mut request| {
            request.fork_sequence = self.fork_sequence;
            request
        })
        .ok_or(MmError::Invalid)
    }
}

/// PREPARE finishes all fault/supply work and authenticates physical custody
/// before publishing semantic admission. A refusal occurs before consumption.
pub fn prepare_transfer<P: PinnedMetadataExtent, W: LiveDescriptorWords + ?Sized>(
    portal: &MmPortal<'_, P>,
    request: carrick_el1_abi::PortalTransferRequest,
    words: &W,
    slot: u32,
) -> Result<Option<carrick_el1_abi::PortalPreparedPermit>, MmError> {
    // SAFETY: revalidate below authenticates every field before any effect.
    let handle = unsafe {
        El1MmHandle::from_admitted_owner(
            request.operation.carrier,
            request.operation.mm,
            request.operation.incarnation,
        )
    };
    let address = request
        .range
        .address()
        .checked_sub(request.selected.offset)
        .ok_or(MmError::Invalid)?;
    let continuation = TransferContinuation {
        handle,
        intent: request.intent,
        address: GuestVa::new(address),
        len: request.selected.offset + request.range.len(),
        offset: request.selected.offset,
        sequence: request.operation.sequence,
        fork_sequence: request.fork_sequence,
    };
    let selected = SelectedChunk {
        fork_sequence: request.fork_sequence,
        handle,
        sequence: request.operation.sequence,
        generation: request.selected.root_generation.get(),
        offset: request.selected.offset,
        va: GuestVa::new(request.range.address()),
        ipa: request.selected.ipa,
        executable: request.selected.executable,
        len: request.range.len(),
    };
    let Some(fence) = portal.revalidate(&continuation, selected, words, slot)? else {
        return Ok(None);
    };
    let mut root = portal.root_for(handle, slot)?;
    let notification = root.notification_ticket(
        carrick_sched_core::spaces::notification::SpaceWaitCause::PreparedOverlap,
    );
    // On allocation refusal the ticket cancels its admission before returning.
    let key = notification.as_ref().map(|ticket| ticket.key());
    let permit = root.prepare_copy(request, key)?;
    if let Some(ticket) = notification {
        let _ = ticket.detach();
    }
    drop(root);
    drop(fence);
    Ok(Some(permit))
}

/// One-shot transfers and two-phase ready-source copies share the same owner
/// permit. COMMIT never revalidates or reacquires a root/editor after consuming.
pub fn serve_transfer<P: PinnedMetadataExtent, W: LiveDescriptorWords + ?Sized>(
    portal: &MmPortal<'_, P>,
    service: carrick_el1_abi::PortalTransferService<'_>,
    words: &W,
    slot: u32,
    host_copy: impl FnOnce(),
) -> Result<(), MmError> {
    use carrick_el1_abi::PortalTransferPhase;
    let request = service.request();
    let permit = match service.phase() {
        PortalTransferPhase::Transfer | PortalTransferPhase::Prepare => {
            match prepare_transfer(portal, request, words, slot) {
                Ok(Some(permit)) => permit,
                Ok(None) => {
                    service.suspend_prepare(
                        carrick_el1_abi::PortalPrepareSuspension::SelectionChanged,
                    );
                    return Ok(());
                }
                Err(MmError::Wait(wait)) => {
                    if !service
                        .suspend_prepare(carrick_el1_abi::PortalPrepareSuspension::Owner(wait))
                    {
                        return Err(MmError::Stale);
                    }
                    return Ok(());
                }
                Err(MmError::MetadataRequired) => {
                    service.suspend_prepare(
                        carrick_el1_abi::PortalPrepareSuspension::ReservationMetadata,
                    );
                    return Ok(());
                }
                Err(error) => {
                    service.complete(0, error.errno());
                    return Err(error);
                }
            }
        }
        PortalTransferPhase::Commit | PortalTransferPhase::Cancel => {
            service.permit().ok_or(MmError::Stale)?
        }
    };
    if service.phase() == PortalTransferPhase::Prepare {
        if !service.complete_prepared(permit) {
            portal.cancel_prepared(permit, request, slot)?;
            return Err(MmError::Stale);
        }
        return Ok(());
    }
    settle_prepared_service(portal, service, permit, slot, host_copy)
}

/// Exact prepared settlement has no descriptor-table or live-MM gate input.
pub(super) fn settle_prepared_service<P: PinnedMetadataExtent>(
    portal: &MmPortal<'_, P>,
    service: carrick_el1_abi::PortalTransferService<'_>,
    permit: carrick_el1_abi::PortalPreparedPermit,
    slot: u32,
    host_copy: impl FnOnce(),
) -> Result<(), MmError> {
    let request = service.request();
    if request.operation.carrier != portal.carrier
        || carrick_sched_core::SlotId::from_index(slot as usize).is_none()
    {
        service.complete(0, MmError::Stale.errno());
        return Err(MmError::Stale);
    }
    let claim = match portal.roots.claim_prepared(portal.nodes, permit, request) {
        Ok(claim) => claim,
        Err(error) => {
            service.complete(0, MmError::from(error).errno());
            return Err(error.into());
        }
    };
    let delivery = match portal.prepared_delivery(&claim, slot) {
        Ok(delivery) => delivery,
        Err(error) => {
            // Claim Drop restores exact LIVE custody. Refusal completes the
            // wire request without copying or releasing the retained permit.
            drop(claim);
            service.complete(0, error.errno());
            return Err(error);
        }
    };
    let cancel = service.phase() == carrick_el1_abi::PortalTransferPhase::Cancel;
    let copied = !cancel && (service.copy_len() == 0 || service.copy_with(host_copy));
    let completed = if copied { service.copy_len() } else { 0 };
    let errno = if copied || cancel { 0 } else { 125 };
    if !claim.release() {
        return Err(MmError::Stale);
    }
    delivery.publish();
    if !service.complete(completed, errno) {
        return Err(MmError::Stale);
    }
    Ok(())
}

#[cfg(target_os = "none")]
pub enum GuestMetadataPin {}
#[cfg(target_os = "none")]
// SAFETY: uninhabited; guest identity banks never construct a host pin.
unsafe impl PinnedMetadataExtent for GuestMetadataPin {
    fn extent(&self) -> carrick_el1_abi::MetadataExtent {
        match *self {}
    }
    fn host_base(&self) -> core::ptr::NonNull<u8> {
        match *self {}
    }
}

#[cfg(target_os = "none")]
pub fn serve_transfer_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    let Some(executor_slot) = carrick_el1_abi::service_slot_from_stack(
        crate::substrate::sched::hw::read_current_sp(),
        frame.slot,
    ) else {
        frame.x[0] = 3;
        return;
    };
    let _ = executor_slot;
    use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
    let slots =
        unsafe { &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots) };
    let Some(service) = slots
        .slot(frame.slot as usize)
        .and_then(|slot| slot.claim())
    else {
        return;
    };
    let request = service.request();
    if slots.carrier() != Some(request.operation.carrier) {
        service.complete(0, 3);
        return;
    }
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    let portal = MmPortal::<GuestMetadataPin> {
        carrier: request.operation.carrier,
        roots: crate::memory::reservations::shared_guest(),
        spaces: &zone.spaces,
        nodes: None,
        zone: Some(zone),
    };
    if matches!(
        service.phase(),
        carrick_el1_abi::PortalTransferPhase::Commit | carrick_el1_abi::PortalTransferPhase::Cancel
    ) {
        let Some(permit) = service.permit() else {
            service.complete(0, 3);
            return;
        };
        let _ = settle_prepared_service(
            &portal,
            service,
            permit,
            frame.slot as u32,
            yield_host_effect,
        );
        return;
    }
    let Some(grant) = zone
        .spaces
        .find(request.operation.mm.raw())
        .and_then(|index| zone.spaces.grant(index, request.operation.mm.raw()))
    else {
        service.complete(0, 11);
        return;
    };
    let live_ttbr: u64;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) live_ttbr, options(nomem, nostack));
    }
    let Some(table) = carrick_el1_abi::service_target_table_window(live_ttbr, grant.ttbr0) else {
        service.complete(0, 3);
        return;
    };
    let maintenance = CallerInvalidatesAsid;
    let words = unsafe {
        PrimaryTableWords::new(
            table.words,
            table.physical_base,
            carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
            &maintenance,
        )
        .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
    };
    let Ok(words) = words else {
        service.complete(0, 5);
        return;
    };
    let _ = serve_transfer(&portal, service, &words, frame.slot as u32, || {
        // The host resumes this exact stack after copy OR cancellation. The
        // permit cannot be abandoned by resetting service-call registers.
        yield_host_effect();
    });
}

/// Suspend the current portal service stack for an authenticated host effect.
/// The host must resume this exact stack after servicing or cancelling the
/// effect; the portal keeps its operation and semantic permit across the yield.
#[cfg(target_os = "none")]
pub(super) fn yield_host_effect() {
    unsafe {
        core::arch::asm!("hvc #1", clobber_abi("C"));
    }
}

/// Selection entry for a borrowed target root. Input x1..x7 is carrier, MM,
/// admitted incarnation, VA, chunk length, intent, and completed host prefix.
/// Output x0 is errno; x8..x10 is sequence, policy generation, selected IPA.
#[cfg(target_os = "none")]
pub fn select_transfer_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    let Some(executor_slot) = carrick_el1_abi::service_slot_from_stack(
        crate::substrate::sched::hw::read_current_sp(),
        frame.slot,
    ) else {
        frame.x[0] = 3;
        return;
    };
    let _ = executor_slot;
    use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
    let run = |frame: &mut carrick_el1_abi::TrapFrame| -> Result<(), MmError> {
        let slots = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        let carrier = slots.carrier().ok_or(MmError::Stale)?;
        if frame.x[1] != carrier.get() {
            return Err(MmError::Stale);
        }
        let mm = ReservationMm::new(frame.x[2]).ok_or(MmError::Stale)?;
        let intent = TransferIntent::decode(frame.x[6]).ok_or(MmError::Invalid)?;
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let portal = MmPortal::<GuestMetadataPin> {
            carrier,
            roots: crate::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        // SAFETY: source and root authentication below validate this exact request.
        let handle = unsafe {
            El1MmHandle::from_admitted_owner(
                carrier,
                mm,
                NonZeroU64::new(frame.x[3]).ok_or(MmError::Stale)?,
            )
        };
        let gate = portal.observe_wait(handle, carrick_el1_abi::PortalWaitCause::Gate)?;
        let index = zone.spaces.find(mm.raw()).ok_or(MmError::Stale)?;
        let grant = zone
            .spaces
            .grant(index, mm.raw())
            .ok_or_else(|| gate.map_or(MmError::Busy, MmError::Wait))?;
        let live_ttbr: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1", out(reg) live_ttbr, options(nomem, nostack));
        }
        let table = carrick_el1_abi::service_target_table_window(live_ttbr, grant.ttbr0)
            .ok_or(MmError::Stale)?;
        let range = carrick_el1_abi::PortalByteRange::new(frame.x[4], frame.x[5])
            .ok_or(MmError::Invalid)?;
        if range.is_empty() || range.len() > 4096 - (range.address() & 4095) {
            return Err(MmError::Invalid);
        }
        let continuation = if let Some(sequence) = NonZeroU64::new(frame.x[19]) {
            super::fork::authenticate_pending_parent_write(frame.slot as usize, handle, sequence)?;
            portal.begin_fork_parent_write(
                handle,
                GuestVa::new(range.address()),
                range.len(),
                intent,
                sequence,
                frame.slot as u32,
            )?
        } else {
            portal.begin(
                handle,
                GuestVa::new(range.address()),
                range.len(),
                intent,
                frame.slot as u32,
            )?
        };
        let maintenance = CallerInvalidatesAsid;
        let words = unsafe {
            PrimaryTableWords::new(
                table.words,
                table.physical_base,
                carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
                &maintenance,
            )
            .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
        }
        .map_err(|_| MmError::Core)?;
        let mailbox = carrick_el1_abi::frame_grant_mailbox_guest_for_slot(frame.slot as usize)
            .ok_or(MmError::Invalid)?;
        match portal.select(
            &continuation,
            &words,
            &mut crate::fault::HardwarePreparedResolver,
            &mut crate::fault::HardwareCowResolver {
                publication: slots.executable(frame.slot as usize),
                completion: None,
                service_slot: Some(executor_slot),
            },
            carrick_el1_abi::frame_grant_residency_guest(),
            mailbox,
            frame.slot as u32,
        )? {
            TransferStep::Selected(selected) => {
                frame.x[8] = selected.sequence.get();
                frame.x[9] = selected.generation;
                frame.x[10] = selected.ipa;
                frame.x[15] = u64::from(selected.executable);
                Ok(())
            }
            step @ (TransferStep::Supply(_) | TransferStep::CowSupply(_)) => {
                let cow = matches!(step, TransferStep::CowSupply(_));
                let (TransferStep::Supply(window) | TransferStep::CowSupply(window)) = step else {
                    unreachable!()
                };
                frame.x[8] = window.operation.sequence.get();
                frame.x[9] = window.generation.raw();
                frame.x[10] = window.range.start();
                frame.x[11] = window.range.end();
                frame.x[12] = window.protection.bits();
                frame.x[13] = window.fault_page;
                frame.x[14] = if cow { 2 } else { 1 };
                frame.x[16] = window
                    .host_backing
                    .map_or(0, |source| source.handle().get());
                frame.x[17] = window
                    .host_backing
                    .map_or(0, |source| source.generation().get());
                frame.x[18] = window.host_backing.map_or(0, |source| source.offset());
                Err(MmError::Busy)
            }
            TransferStep::Suspended => Err(MmError::Busy),
            TransferStep::Complete => Err(MmError::Invalid),
        }
    };
    frame.x[0] = match run(frame) {
        Ok(()) => 0,
        Err(MmError::Busy) => 11,
        Err(MmError::Wait(wait)) => {
            frame.x[14] = 3;
            frame.x[16] = wait.cause().encode();
            frame.x[17] = wait.revision();
            11
        }
        Err(error) => u64::from(error.errno()),
    };
}

/// Revalidate an owner-selected lazy window and apply its isolated submission
/// through the existing descriptor executor. Normal descriptor drains cannot
/// see the submission before this exact-generation check.
pub fn serve_grant<P: PinnedMetadataExtent, W: LiveDescriptorWords + ?Sized>(
    portal: &MmPortal<'_, P>,
    slot: &carrick_el1_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable,
    worker: u32,
    invalidate: impl FnOnce(),
) -> Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt> {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorOutcome, DescriptorRefusal, InlineJournal, execute_descriptor_txn,
    };
    let window = slot.window()?;
    let mm = window.operation.mm;
    let claimed = slot.descriptor().claim_for_mm(mm.raw())?;
    let editor = portal.spaces.find(mm.raw()).and_then(|index| {
        portal.space_access(worker).ok()?.try_begin_edit(
            index,
            mm.raw(),
            NonZeroU64::new(u64::from(worker) + 1)?,
        )
    });
    let outcome = (|| {
        if editor.is_none() {
            return DescriptorOutcome::Refused(DescriptorRefusal::Contended);
        }
        let Ok(txn) = claimed.txn() else {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
        };
        let authenticated = (|| -> Result<(), MmError> {
            if window.operation.carrier != portal.carrier {
                return Err(MmError::Stale);
            }
            let mut root = portal.root(mm, worker)?;
            let plan = crate::memory::reservations::ReservationFaultPlan {
                mm,
                generation: window.generation,
                range: window.range,
                protection: window.protection,
                fault_page: window.fault_page,
            };
            if root.incarnation().raw() != window.operation.incarnation.get()
                || !root.authenticate_fork_transfer_fault(
                    plan,
                    window.host_backing,
                    window.fork_sequence,
                )
            {
                return Err(MmError::Stale);
            }
            Ok(())
        })();
        if authenticated.is_err() {
            return DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot);
        }
        let Some(grant) = portal
            .spaces
            .find(mm.raw())
            .and_then(|index| portal.spaces.grant(index, mm.raw()))
        else {
            return DescriptorOutcome::Refused(DescriptorRefusal::Contended);
        };
        let DescriptorOp::Prepare {
            publication,
            resident,
            backing,
        } = txn.op
        else {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
        };
        if publication.va != window.range.start()
            || publication.len != window.range.len()
            || publication.writable != (window.protection.bits() & 2 != 0)
            || publication.executable != (window.protection.bits() & 4 != 0)
            || resident.va != window.fault_page
            || resident.len != 4096
        {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
        }
        // The authenticated remapped root may replace a core-typed retired
        // terminal with fresh backing. Never revive its output, or replace a
        // prepared/live predecessor. The window is at most 512 pages.
        for va in (publication.va..publication.va + publication.len).step_by(4096) {
            let mut table = grant.ttbr0 & PA;
            for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
                let Ok(word) = words.load(table + ((va >> shift) & 511) * 8) else {
                    return DescriptorOutcome::Refused(DescriptorRefusal::TableOutsidePrimary);
                };
                if word == 0 {
                    break;
                }
                if word & 3 != 3 || level == 3 {
                    if level != 0
                        && carrick_mmu_core::aarch64::el1_private_leaf_state(word)
                            == carrick_mmu_core::aarch64::El1PrivateLeafState::Retired
                    {
                        break;
                    }
                    return DescriptorOutcome::Refused(DescriptorRefusal::Occupied);
                }
                table = word & PA;
            }
        }
        let identity = carrick_el1_abi::FrameGrantResidencyIdentity {
            mm_key: mm.raw(),
            semantic_base: publication.va,
            physical_ipa: publication.ipa,
            len: publication.len,
            mapping_id: backing.mapping_id.get(),
            frame_id: backing.frame_id.get(),
            owner_generation: backing.owner_generation.get(),
            inventory_revision: backing.inventory_revision.get(),
        };
        let Some(residency_slot) = residency.publish(identity) else {
            return DescriptorOutcome::Refused(DescriptorRefusal::JournalCapacity);
        };
        let outcome = execute_descriptor_txn(
            words,
            carrick_mmu_core::aarch64::SubstrateGpa(grant.ttbr0 & PA),
            txn,
            &mut InlineJournal::new(),
        )
        .outcome;
        if let DescriptorOutcome::Applied(_) = outcome {
            if let Some(page) = residency.lookup(mm.raw(), window.fault_page) {
                residency.record_commit(page);
            }
        } else {
            residency.retire(residency_slot, identity);
        }
        outcome
    })();
    let receipt = claimed.complete(outcome, invalidate);
    drop(editor);
    Some(receipt)
}

#[cfg(target_os = "none")]
pub fn serve_grant_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    let Some(executor_slot) = carrick_el1_abi::service_slot_from_stack(
        crate::substrate::sched::hw::read_current_sp(),
        frame.slot,
    ) else {
        frame.x[0] = 3;
        return;
    };
    let _ = executor_slot;
    use carrick_mmu_core::aarch64::descriptor_txn::PrimaryTableWords;
    let slots =
        unsafe { &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots) };
    let Some(slot) = slots.grant(frame.slot as usize) else {
        return;
    };
    let Some(window) = slot.window() else {
        return;
    };
    let zone = unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
    let ttbr: u64;
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1",out(reg)ttbr,options(nomem,nostack));
    }
    let Some(grant) = zone
        .spaces
        .find(window.operation.mm.raw())
        .and_then(|index| zone.spaces.grant(index, window.operation.mm.raw()))
    else {
        return;
    };
    let Some(table) = carrick_el1_abi::service_target_table_window(ttbr, grant.ttbr0) else {
        return;
    };
    let maintenance = crate::fault::El1TableMaintenance { ttbr0: grant.ttbr0 };
    let Ok(words) = (unsafe {
        PrimaryTableWords::new(
            table.words,
            table.physical_base,
            carrick_el1_abi::AARCH64_STAGE1_TABLES_PRIMARY_SIZE as usize,
            &maintenance,
        )
        .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
    }) else {
        return;
    };
    let Some(carrier) = slots.carrier() else {
        return;
    };
    let portal = MmPortal::<GuestMetadataPin> {
        carrier,
        roots: crate::memory::reservations::shared_guest(),
        spaces: &zone.spaces,
        nodes: None,
        zone: Some(zone),
    };
    if zone
        .spaces
        .find(window.operation.mm.raw())
        .and_then(|index| zone.spaces.grant(index, window.operation.mm.raw()))
        .is_none_or(|current| current.ttbr0 != grant.ttbr0)
    {
        return;
    }
    serve_grant(
        &portal,
        slot,
        &words,
        carrick_el1_abi::frame_grant_residency_guest(),
        frame.slot as u32,
        || {
            crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, grant.ttbr0);
        },
    );
}

#[cfg(target_os = "none")]
pub fn bind_transfer_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    let Some(executor_slot) = carrick_el1_abi::service_slot_from_stack(
        crate::substrate::sched::hw::read_current_sp(),
        frame.slot,
    ) else {
        frame.x[0] = 3;
        return;
    };
    let _ = executor_slot;
    let result = (|| -> Result<(), MmError> {
        let slots = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        let carrier = slots.carrier().ok_or(MmError::Stale)?;
        if frame.x[1] != carrier.get() {
            return Err(MmError::Stale);
        }
        let mm = ReservationMm::new(frame.x[2]).ok_or(MmError::Stale)?;
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let index = zone.spaces.find(mm.raw()).ok_or(MmError::Stale)?;
        let grant = zone.spaces.grant(index, mm.raw()).ok_or(MmError::Busy)?;
        let live: u64;
        unsafe {
            core::arch::asm!("mrs {}, ttbr0_el1",out(reg)live,options(nomem,nostack));
        }
        if carrick_el1_abi::service_target_table_window(live, grant.ttbr0).is_none() {
            return Err(MmError::Stale);
        }
        let portal = MmPortal::<GuestMetadataPin> {
            carrier,
            roots: crate::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        frame.x[3] = portal
            .admitted_handle(mm, frame.slot as u32)?
            .incarnation()
            .get();
        frame.x[4] = portal.root(mm, frame.slot as u32)?.generation().raw();
        frame.x[5] = portal
            .root(mm, frame.slot as u32)?
            .next_transfer_sequence()?
            .get();
        Ok(())
    })();
    frame.x[0] = result.err().map_or(0, |error| u64::from(error.errno()));
}
