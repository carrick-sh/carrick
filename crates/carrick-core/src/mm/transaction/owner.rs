//! One MM admission, selection and prepared service transaction for both ISAs.
use super::MmError;
use crate::mm::reservation::{
    ClaimedPreparedCopy, ReservationGeometry, ReservationPolicy, Reservations,
    ResolvedReservationNodes, RootReleaseVenue, SharedReservations,
};
use crate::mm::transfer::resolver::{CowResolution, CowResolver, PreparedPageResolver};
use crate::mm::transfer::{GuestVa, SelectedChunk, TransferContinuation, ValidatedChunk};
use carrick_core_abi::PortalTransferIntent as TransferIntent;
use carrick_core_abi::*;
use carrick_guest_arch::UserVa;
use carrick_mmu_core::aarch64::descriptor_txn::{LiveDescriptorWords, PageSpan};
use carrick_mmu_core::aarch64::{GuestPreparedCommit, LeafAccess};
use carrick_mmu_core::owner_mmu::{Aarch64Mmu, OwnerMmu, OwnerMmuRefusal};
use carrick_sched_core::{AddressSpaces, SpaceEditor};
use core::num::NonZeroU64;

/// Native wake delivery and Linux wire encoding, with no MM owner state.
pub trait OwnerVenue<
    Context: Copy + Send + Sync + zerocopy::FromZeros = carrick_sched_core::ThreadCtx,
>
{
    fn space_access(
        zone: &carrick_sched_core::ZoneTables<Context>,
        slot: carrick_sched_core::SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_, Context>;
    fn deliver_completion(
        zone: &carrick_sched_core::ZoneTables<Context>,
        slot: carrick_sched_core::SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, Context>,
    );
    fn encode_error(error: MmError) -> u32;
    fn cancelled_copy_code() -> u32;
}

/// Independently borrowed venues; no owner state or permit is created here.
pub struct SelectionVenues<'a, R, C> {
    pub prepared: &'a mut R,
    pub cow: &'a mut C,
    pub residency: &'a FrameGrantResidencyTable,
    pub slot: u32,
}

/// At most one Linux page is fenced through a host memcpy. Bigger transfers
/// retain their byte offset and select/revalidate each next page separately.
pub const TRANSFER_CHUNK_BYTES: u64 = 4096;

pub struct MmPortal<
    'a,
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu = Aarch64Mmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros = carrick_sched_core::ThreadCtx,
> {
    pub backend: core::marker::PhantomData<(B, Venue)>,
    pub carrier: NonZeroU64,
    pub roots: &'a SharedReservations<Policy, Geometry>,
    pub spaces: &'a AddressSpaces,
    pub nodes: Option<&'a ResolvedReservationNodes<P, Policy, Geometry>>,
    pub zone: Option<&'a carrick_sched_core::ZoneTables<Context>>,
    #[cfg(any(test, feature = "host-test"))]
    pub vma_visits: core::sync::atomic::AtomicUsize,
}

/// Authenticated before effects, while dropping the claim can restore LIVE.
/// Publication cannot reject a prepared settlement afterward.
enum PreparedDelivery<
    'a,
    Venue: OwnerVenue<Context>,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
> {
    Standalone,
    Scheduler {
        venue: core::marker::PhantomData<Venue>,
        zone: &'a carrick_sched_core::ZoneTables<Context>,
        key: carrick_sched_core::object_wait::ObjectWaitKey,
        waker: carrick_sched_core::SlotId,
    },
}
impl<Venue: OwnerVenue<Context>, Context: Copy + Send + Sync + zerocopy::FromZeros>
    PreparedDelivery<'_, Venue, Context>
{
    fn publish(self) {
        if let Self::Scheduler {
            zone, key, waker, ..
        } = self
        {
            let completion = |effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                '_,
                Context,
            >| { Venue::deliver_completion(zone, waker, effects) };
            // SAFETY: this capability came from the exact claimed node's
            // retained PREPARE admission, before that claim was released.
            unsafe { zone.retained_object_notification(key) }
                .publish(carrick_sched_core::Waker::El1 { slot: waker }, &completion);
        }
    }
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum TransferStep {
    Selected(SelectedChunk),
    Supply(carrick_core_abi::PortalGrantWindow),
    CowSupply(carrick_core_abi::PortalGrantWindow),
    /// A gate/editor wait or the existing lazy FrameGrantRequest path. No
    /// root lock, editor, or physical pin survives this return.
    Suspended,
    Complete,
}

impl<
    'a,
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
> MmPortal<'a, P, Policy, Geometry, Venue, Aarch64Mmu, Context>
{
    pub fn new(
        carrier: NonZeroU64,
        roots: &'a SharedReservations<Policy, Geometry>,
        spaces: &'a AddressSpaces,
        nodes: &'a ResolvedReservationNodes<P, Policy, Geometry>,
    ) -> Self {
        Self {
            backend: core::marker::PhantomData,
            carrier,
            roots,
            spaces,
            nodes: Some(nodes),
            zone: None,
            #[cfg(any(test, feature = "host-test"))]
            vma_visits: core::sync::atomic::AtomicUsize::new(0),
        }
    }
    /// Select descriptor geometry without reconstructing owner state.
    pub fn with_mmu<B: OwnerMmu>(
        self,
        _: B,
    ) -> MmPortal<'a, P, Policy, Geometry, Venue, B, Context> {
        MmPortal {
            backend: core::marker::PhantomData,
            carrier: self.carrier,
            roots: self.roots,
            spaces: self.spaces,
            nodes: self.nodes,
            zone: self.zone,
            #[cfg(any(test, feature = "host-test"))]
            vma_visits: self.vma_visits,
        }
    }
}
impl<
    'a,
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
> MmPortal<'a, P, Policy, Geometry, Venue, B, Context>
{
    pub fn fork_mapping_count(
        &self,
        mm: carrick_core_abi::ReservationMm,
        worker: u32,
    ) -> Result<usize, MmError> {
        let mut root = self.root(mm, worker)?;
        let mut count = 0usize;
        root.observe_mappings(&mut |_| count += 1)?;
        Ok(count)
    }
    pub fn child_root(
        &self,
        mm: carrick_core_abi::ReservationMm,
        worker: u32,
    ) -> Result<Reservations<'_, Policy, Geometry, Context>, MmError> {
        self.root_any(mm, worker)
    }

    /// Add the production scheduler, using the same address-space authority.
    pub fn with_zone(
        mut self,
        zone: &'a carrick_sched_core::ZoneTables<Context>,
    ) -> Result<Self, MmError> {
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
        claim: &ClaimedPreparedCopy<'_, Policy, Geometry>,
        slot: u32,
    ) -> Result<PreparedDelivery<'_, Venue, Context>, MmError> {
        let Some(key) = claim.notification() else {
            return Ok(PreparedDelivery::Standalone);
        };
        let zone = self.zone.ok_or(MmError::Core)?;
        let waker =
            carrick_sched_core::SlotId::from_index(slot as usize).ok_or(MmError::Invalid)?;
        Ok(PreparedDelivery::Scheduler {
            venue: core::marker::PhantomData,
            zone,
            key,
            waker,
        })
    }
    /// Release semantic custody by exact atomic identity. This does not
    /// acquire the root or descriptor editor, even while either is held.
    pub fn cancel_prepared(
        &self,
        permit: carrick_core_abi::PortalPreparedPermit,
        request: carrick_core_abi::PortalTransferRequest,
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
    pub fn space_access(
        &self,
        slot: u32,
    ) -> Result<carrick_sched_core::spaces::notification::SpaceAccess<'_, Context>, MmError> {
        if let Some(zone) = self.zone {
            let slot =
                carrick_sched_core::SlotId::from_index(slot as usize).ok_or(MmError::Invalid)?;
            return Ok(Venue::space_access(zone, slot));
        }
        #[cfg(any(test, feature = "host-test"))]
        {
            Ok(
                carrick_sched_core::spaces::notification::SpaceAccess::source_free_with_context(
                    self.spaces,
                ),
            )
        }
        #[cfg(not(any(test, feature = "host-test")))]
        Err(MmError::Stale)
    }
    pub fn root_any(
        &self,
        mm: ReservationMm,
        slot: u32,
    ) -> Result<Reservations<'_, Policy, Geometry, Context>, MmError> {
        let index = self.spaces.find(mm.raw()).ok_or(MmError::Stale)?.index();
        if let Some(venue) = self.space_access(slot)?.venue() {
            let roots = RootReleaseVenue::new(self.roots, venue)?;
            return match self.nodes {
                Some(nodes) => Ok(roots.lock_el1_resolved(index, mm, nodes, slot)?),
                None => Ok(roots.lock_el1(index, mm, slot)?),
            };
        }
        #[cfg(any(test, feature = "host-test"))]
        {
            match self.nodes {
                Some(nodes) => Ok(self
                    .roots
                    .lock_el1_resolved_with_context(index, mm, nodes, slot)?),
                None => Ok(self.roots.lock_el1_with_context(index, mm, slot)?),
            }
        }
        #[cfg(not(any(test, feature = "host-test")))]
        Err(MmError::Stale)
    }
    pub fn root(
        &self,
        mm: ReservationMm,
        slot: u32,
    ) -> Result<Reservations<'_, Policy, Geometry, Context>, MmError> {
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
        unsafe { TransferContinuation::from_owner_sequence(handle, address, len, intent, sequence) }
            .map_err(MmError::from)
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
        let continuation = unsafe {
            TransferContinuation::from_owner_sequence(handle, address, len, intent, sequence)
        }
        .map_err(MmError::from)?;
        Ok(unsafe { continuation.with_fork_sequence(fork_sequence) })
    }
    pub fn observe_wait(
        &self,
        handle: El1MmHandle,
        cause: carrick_core_abi::PortalWaitCause,
    ) -> Result<Option<carrick_core_abi::PortalOwnerWait>, MmError> {
        use carrick_core_abi::PortalWaitCause as Wire;
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
            carrick_core_abi::PortalOwnerWait::from_owner(
                handle,
                cause,
                source.observe(source_cause).revision(),
            )
        }))
    }
    pub(crate) fn editor_for(
        &self,
        handle: El1MmHandle,
        slot: u32,
    ) -> Result<SpaceEditor<'_, Context>, MmError> {
        use carrick_core_abi::PortalWaitCause;
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
    pub(crate) fn root_for(
        &self,
        handle: El1MmHandle,
        slot: u32,
    ) -> Result<Reservations<'_, Policy, Geometry, Context>, MmError> {
        let observed =
            self.observe_wait(handle, carrick_core_abi::PortalWaitCause::Reservations)?;
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
            carrick_core_abi::PortalWaitCause::PendingEdit,
        )?;
        let mut root = self.root_for(continuation.handle, slot)?;
        if root.fork_pending() && !root.fork_write_authorized(continuation.fork_sequence()) {
            return Err(pending.map_or(MmError::Busy, MmError::Wait));
        }
        if root.incarnation().raw() != continuation.handle.incarnation().get() {
            return Err(MmError::Stale);
        }
        if root.pending().is_some() {
            return Err(pending.map_or(MmError::Busy, MmError::Wait));
        }
        if continuation.intent == TransferIntent::CarrickInternalRead {
            // Only named Carrick control windows bypass user-VMA permission
            // selection. Live translation and exact owner validation still apply.
            if !Geometry::authorizes_internal_read(continuation.address().raw(), continuation.len())
            {
                return Err(MmError::Fault);
            }
        } else {
            let mapping = root.mapping(va).ok_or(MmError::Fault)?;
            let access = match continuation.intent {
                TransferIntent::UserWrite => ReservationProtection::WRITE,
                TransferIntent::ReadInstruction => ReservationProtection::EXECUTE,
                _ => ReservationProtection::READ,
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
    pub fn select<W: LiveDescriptorWords + ?Sized, R: PreparedPageResolver, C: CowResolver>(
        &self,
        continuation: &TransferContinuation,
        words: &W,
        venues: SelectionVenues<'_, R, C>,
    ) -> Result<TransferStep, MmError> {
        let SelectionVenues {
            prepared,
            cow,
            residency,
            slot,
        } = venues;
        if continuation.is_complete() {
            return Ok(TransferStep::Complete);
        }
        let retry = self.observe_wait(
            continuation.handle,
            carrick_core_abi::PortalWaitCause::Reservations,
        )?;
        let mm = continuation.handle.mm().raw();
        let index = self.spaces.find(mm).ok_or(MmError::Stale)?;
        let _editor = match self.editor_for(continuation.handle, slot) {
            Err(MmError::Busy) => return Ok(TransferStep::Suspended),
            result => result?,
        };
        let gate =
            self.observe_wait(continuation.handle, carrick_core_abi::PortalWaitCause::Gate)?;
        let Some(grant) = self.spaces.grant(index, mm) else {
            return match gate {
                Some(wait) => Err(MmError::Wait(wait)),
                None => Ok(TransferStep::Suspended),
            };
        };
        let va = continuation.address().raw() + continuation.offset();
        let len = (continuation.len() - continuation.offset()).min(4096 - (va & 4095));
        let generation = match self.authorize(continuation, va, len, slot) {
            Err(MmError::Busy) => return Ok(TransferStep::Suspended),
            result => result?,
        };
        let access = match continuation.intent {
            TransferIntent::UserWrite => LeafAccess::Write,
            TransferIntent::ReadInstruction => LeafAccess::Execute,
            _ => LeafAccess::Read,
        };
        let root = B::root(grant.ttbr0).map_err(mmu_error)?;
        let mut leaf = match translated::<B, W>(words, root, va, access, continuation.intent) {
            Err(MmError::Fault) if access == LeafAccess::Write => {
                B::classify_cow(words, root, UserVa::new(va), cow.executable_publication())
                    .map_err(mmu_error)?;
                match cow.resolve_cow_outcome(grant.ttbr0, mm, va) {
                    CowResolution::Resolved => {
                        #[cfg(target_os = "none")]
                        cow.finish_resolution(
                            slot,
                            continuation.handle,
                            continuation.fork_sequence(),
                            words,
                        )?;
                    }
                    CowResolution::Refused => return Err(MmError::Core),
                    CowResolution::NeedsSupply => {
                        let mut root = self.root(continuation.handle.mm(), slot)?;
                        return Ok(TransferStep::CowSupply(
                            crate::mm::fault::select_cow_supply_window(
                                &mut root,
                                carrick_core_abi::PortalOperation {
                                    carrier: continuation.handle.carrier(),
                                    mm: continuation.handle.mm(),
                                    incarnation: continuation.handle.incarnation(),
                                    sequence: continuation.sequence(),
                                },
                                UserVa::new(va),
                                continuation.fork_sequence(),
                            )?,
                        ));
                    }
                }
                translated::<B, W>(words, root, va, access, continuation.intent)?
            }
            result => result?,
        };
        if leaf.is_none() {
            if let Some(page) = residency.lookup(mm, va)
                && matches!(
                    prepared.commit_prepared(
                        grant.ttbr0,
                        PageSpan::containing(va).va,
                        page.expected_ipa,
                        access,
                    ),
                    Ok(GuestPreparedCommit::Committed | GuestPreparedCommit::AlreadyResident)
                )
            {
                residency.record_commit(page);
            }
            leaf = translated::<B, W>(words, root, va, access, continuation.intent)?;
        }
        let Some((ipa, executable)) = leaf else {
            // Permission policy was already checked. Reuse the one lazy supply
            // owner receipt; no fault-mailbox transport is consumed by selection.
            let bits = match access {
                LeafAccess::Read => 1,
                LeafAccess::Write => 2,
                LeafAccess::Execute => 4,
            };
            let mut root = self.root(continuation.handle.mm(), slot)?;
            if root.fork_pending() && !root.fork_write_authorized(continuation.fork_sequence()) {
                return Err(MmError::Busy);
            }
            let target = if root
                .mapping(va)
                .is_some_and(|mapping| mapping.host_backing.is_some())
            {
                4096
            } else {
                carrick_core_abi::EL1_FRAME_GRANT_TARGET_SIZE
            };
            let plan = root.fork_transfer_fault_plan(
                va,
                target,
                ReservationProtection::from_bits(bits).ok_or(MmError::Invalid)?,
                continuation.fork_sequence(),
            )?;
            let host_backing = root.mapping(plan.range.start()).and_then(|mapping| {
                mapping
                    .host_backing
                    .and_then(|source| source.advance(plan.range.start() - mapping.range.start()))
            });
            drop(root);
            return Ok(TransferStep::Supply(carrick_core_abi::PortalGrantWindow {
                operation: carrick_core_abi::PortalOperation {
                    carrier: continuation.handle.carrier(),
                    mm: continuation.handle.mm(),
                    incarnation: continuation.handle.incarnation(),
                    sequence: continuation.sequence(),
                },
                generation: plan.generation,
                range: plan.range,
                protection: plan.protection,
                fault_page: plan.fault_page,
                host_backing,
                fork_sequence: continuation.fork_sequence(),
            }));
        };
        // SAFETY: the exact editor, admitted MM, reservation and translation
        // license this selection. Copy still requires physical custody and revalidation.
        Ok(TransferStep::Selected(unsafe {
            SelectedChunk::from_owner_selection(
                continuation.handle,
                continuation.sequence(),
                PortalSelectedData {
                    root_generation: NonZeroU64::new(generation).ok_or(MmError::Stale)?,
                    offset: continuation.offset(),
                    ipa,
                    executable: continuation.intent == TransferIntent::UserWrite && executable,
                },
                PortalByteRange::new(va, len).ok_or(MmError::Invalid)?,
                continuation.fork_sequence(),
                retry,
            )
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
    ) -> Result<Option<ValidatedChunk<'_, Context>>, MmError> {
        if !selected.matches(continuation) {
            return Err(MmError::Stale);
        }
        let mm = selected.handle().mm().raw();
        let index = self.spaces.find(mm).ok_or(MmError::Stale)?;
        let editor = match self.editor_for(selected.handle(), slot) {
            Err(MmError::Busy) => return Ok(None),
            result => result?,
        };
        let gate = self.observe_wait(selected.handle(), carrick_core_abi::PortalWaitCause::Gate)?;
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
        let current = match translated::<B, W>(
            words,
            B::root(grant.ttbr0).map_err(mmu_error)?,
            selected.va.raw(),
            access,
            continuation.intent,
        ) {
            Err(MmError::Fault) => return Ok(None),
            result => result?,
        };
        // SAFETY: exact-MM editor, reservation generation and live output
        // were authenticated above; core publishes the sole bounded fence.
        unsafe {
            crate::mm::transaction::validate_selection(
                continuation,
                selected,
                editor,
                generation,
                current,
            )
        }
        .map_err(MmError::from)
    }
}

fn mmu_error(error: OwnerMmuRefusal) -> MmError {
    match error {
        OwnerMmuRefusal::Protection => MmError::Fault,
        OwnerMmuRefusal::Unreachable => MmError::Core,
        OwnerMmuRefusal::ExecutableCow => MmError::UnsupportedExecutableCow,
    }
}
fn translated<B: OwnerMmu, W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: carrick_guest_arch::RootGpa,
    va: u64,
    access: LeafAccess,
    intent: TransferIntent,
) -> Result<Option<(u64, bool)>, MmError> {
    B::translate(
        words,
        root,
        UserVa::new(va),
        access,
        intent != TransferIntent::CarrickInternalRead,
    )
    .map(|leaf| leaf.map(|leaf| (leaf.output.raw(), leaf.executable)))
    .map_err(mmu_error)
}

/// PREPARE finishes all fault/supply work and authenticates physical custody
/// before publishing semantic admission. A refusal occurs before consumption.
pub fn prepare_transfer<
    P: PinnedMetadataExtent,
    W: LiveDescriptorWords + ?Sized,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    portal: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    request: carrick_core_abi::PortalTransferRequest,
    words: &W,
    slot: u32,
) -> Result<Option<carrick_core_abi::PortalPreparedPermit>, MmError> {
    // SAFETY: revalidate below authenticates every field before any effect.
    let handle = unsafe {
        El1MmHandle::from_admitted_owner(
            request.operation.carrier,
            request.operation.mm,
            request.operation.incarnation,
        )
    };
    // SAFETY: candidate only; live owner revalidation below precedes effects.
    let continuation = unsafe { TransferContinuation::from_request(request) }?;
    let selected = unsafe { SelectedChunk::from_request(request) };
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
pub fn serve_transfer<
    P: PinnedMetadataExtent,
    W: LiveDescriptorWords + ?Sized,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    portal: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    service: carrick_core_abi::PortalTransferService<'_>,
    words: &W,
    slot: u32,
    host_copy: impl FnOnce(),
) -> Result<(), MmError> {
    use carrick_core_abi::PortalTransferPhase;
    let request = service.request();
    let permit = match service.phase() {
        PortalTransferPhase::Transfer | PortalTransferPhase::Prepare => {
            // Sample before probing. A rejected selection names completed
            // owner mutation; metadata supply names its distinct producer.
            // COMMIT/CANCEL deliberately never revisit these admissions.
            let handle = unsafe {
                El1MmHandle::from_admitted_owner(
                    request.operation.carrier,
                    request.operation.mm,
                    request.operation.incarnation,
                )
            };
            let observations = (|| {
                Ok::<_, MmError>((
                    portal.observe_wait(handle, carrick_core_abi::PortalWaitCause::Reservations)?,
                    portal.observe_wait(handle, carrick_core_abi::PortalWaitCause::Metadata)?,
                ))
            })();
            let (changed, metadata) = match observations {
                Ok(observations) => observations,
                Err(error) => {
                    service.complete(0, Venue::encode_error(error));
                    return Err(error);
                }
            };
            match prepare_transfer(portal, request, words, slot) {
                Ok(Some(permit)) => permit,
                Ok(None) => {
                    service.suspend_prepare(changed.map_or(
                        carrick_core_abi::PortalPrepareSuspension::SelectionChanged,
                        carrick_core_abi::PortalPrepareSuspension::Owner,
                    ));
                    return Ok(());
                }
                Err(MmError::Wait(wait)) => {
                    if !service
                        .suspend_prepare(carrick_core_abi::PortalPrepareSuspension::Owner(wait))
                    {
                        return Err(MmError::Stale);
                    }
                    return Ok(());
                }
                Err(MmError::MetadataRequired) => {
                    service.suspend_prepare(metadata.map_or(
                        carrick_core_abi::PortalPrepareSuspension::ReservationMetadata,
                        carrick_core_abi::PortalPrepareSuspension::Owner,
                    ));
                    return Ok(());
                }
                Err(error) => {
                    service.complete(0, Venue::encode_error(error));
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
pub fn settle_prepared_service<
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    portal: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    service: carrick_core_abi::PortalTransferService<'_>,
    permit: carrick_core_abi::PortalPreparedPermit,
    slot: u32,
    host_copy: impl FnOnce(),
) -> Result<(), MmError> {
    let request = service.request();
    if request.operation.carrier != portal.carrier
        || carrick_sched_core::SlotId::from_index(slot as usize).is_none()
    {
        service.complete(0, Venue::encode_error(MmError::Stale));
        return Err(MmError::Stale);
    }
    let claim = match portal.roots.claim_prepared(portal.nodes, permit, request) {
        Ok(claim) => claim,
        Err(error) => {
            service.complete(0, Venue::encode_error(MmError::from(error)));
            return Err(error.into());
        }
    };
    let delivery = match portal.prepared_delivery(&claim, slot) {
        Ok(delivery) => delivery,
        Err(error) => {
            // Claim Drop restores exact LIVE custody. Refusal completes the
            // wire request without copying or releasing the retained permit.
            drop(claim);
            service.complete(0, Venue::encode_error(error));
            return Err(error);
        }
    };
    let cancel = service.phase() == carrick_core_abi::PortalTransferPhase::Cancel;
    let copied = !cancel && (service.copy_len() == 0 || service.copy_with(host_copy));
    let completed = if copied { service.copy_len() } else { 0 };
    let errno = if copied || cancel {
        0
    } else {
        Venue::cancelled_copy_code()
    };
    if !claim.release() {
        return Err(MmError::Stale);
    }
    delivery.publish();
    if !service.complete(completed, errno) {
        return Err(MmError::Stale);
    }
    Ok(())
}

/// Resolve the pre-service root before a hardware table window can be built.
/// Kept in the VM-free owner layer so the hardware preamble's refusal uses
/// the same exact operation and release producer as the transfer body.
pub fn admit_service_root<
    's,
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    portal: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    service: carrick_core_abi::PortalTransferService<'s>,
) -> Option<(
    carrick_core_abi::PortalTransferService<'s>,
    carrick_sched_core::spaces::SpaceGrant,
)> {
    let request = service.request();
    // SAFETY: candidate identity only; observe_wait authenticates the exact
    // current incarnation and carrier before returning a release receipt.
    let handle = unsafe {
        El1MmHandle::from_admitted_owner(
            request.operation.carrier,
            request.operation.mm,
            request.operation.incarnation,
        )
    };
    // Observe BEFORE checking the gate. Release before enrollment then
    // reports Changed; release after enrollment delivers this owned wait.
    let gate = match portal.observe_wait(handle, carrick_core_abi::PortalWaitCause::Gate) {
        Ok(gate) => gate,
        Err(error) => {
            service.complete(0, Venue::encode_error(error));
            return None;
        }
    };
    let Some(index) = portal.spaces.find(request.operation.mm.raw()) else {
        service.complete(0, Venue::encode_error(MmError::Stale));
        return None;
    };
    let Some(grant) = portal.spaces.grant(index, request.operation.mm.raw()) else {
        if let Some(wait) = gate {
            service.suspend_prepare(carrick_core_abi::PortalPrepareSuspension::Owner(wait));
        } else {
            // VM-free portals without a zone have no producer to enroll on.
            // Production always authenticates a zone notification above.
            service.complete(0, Venue::encode_error(MmError::Busy));
        }
        return None;
    };
    Some((service, grant))
}

pub fn bind_service_root(
    spaces: &carrick_sched_core::AddressSpaces,
    mm: ReservationMm,
    closed: bool,
    expected_root: u64,
) -> Result<u64, MmError> {
    let index = spaces.find(mm.raw()).ok_or(MmError::Stale)?;
    if closed {
        let root = spaces
            .closed_root_identity(index, mm.raw())
            .ok_or(MmError::Stale)?;
        if root != expected_root {
            return Err(MmError::Stale);
        }
        Ok(root)
    } else {
        Ok(spaces.grant(index, mm.raw()).ok_or(MmError::Busy)?.ttbr0)
    }
}
