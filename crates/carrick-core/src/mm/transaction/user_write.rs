//! The native user-write protocol, moved from the x86 process adapter.
//! Selection, physical supply and completion retain the same MM continuation.
use super::{MmError, MmPortal, OwnerVenue, SelectionVenues, TransferStep};
use crate::mm::reservation::{ReservationGeometry, ReservationPolicy};
use crate::mm::transfer::resolver::{CowResolver, PreparedPageResolver};
use crate::mm::transfer::{GuestVa, ValidatedChunk};
use carrick_core_abi::{
    El1MmHandle, PinnedMetadataExtent, PortalGrantWindow, PortalTransferIntent,
};
use carrick_guest_arch::{SlotId, UserVa};
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_mmu_core::owner_mmu::OwnerMmu;

/// One exact-owner write; the existing transfer owns its byte position.
pub struct UserWriteRequest<'a> {
    pub handle: El1MmHandle,
    pub address: UserVa,
    pub bytes: &'a [u8],
    pub slot: SlotId,
}

/// Mapping preparation never writes guest bytes or consumes an I/O source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyoutRequest {
    pub address: UserVa,
    pub len: carrick_guest_arch::GuestLen,
}

/// One endpoint/cursor token changes wait source, never completion owner.
#[derive(Debug)]
pub enum CopyoutPreparation {
    Ready(carrick_sched_core::object_wait::OperationToken),
    /// Transient admission contention without an enrollable owner dependency.
    Busy(carrick_sched_core::object_wait::OperationToken),
    Wait {
        operation: carrick_sched_core::object_wait::OperationToken,
        wait: carrick_core_abi::PortalOwnerWait,
    },
    Fault(carrick_sched_core::object_wait::OperationToken),
    Unrouted(carrick_sched_core::object_wait::OperationToken),
    Complete(i64),
    Suspended,
}

/// An owned execution yield cannot request another memory preparation.
/// Keeping this reply distinct prevents Busy from becoming a retry loop in
/// the yield venue itself; a native owner suspends through CarrierWork.
#[derive(Debug)]
pub enum OwnedOperationYield {
    Ready(carrick_sched_core::object_wait::OperationToken),
    Unrouted(carrick_sched_core::object_wait::OperationToken),
    Complete(i64),
    Suspended,
}

#[derive(Clone, Copy, Debug)]
pub struct UserWriteTarget {
    pub handle: El1MmHandle,
    pub address: UserVa,
    pub len: carrick_guest_arch::GuestLen,
    pub slot: SlotId,
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum UserWriteError<E> {
    Owner(MmError),
    Mechanics(E),
    Busy,
    InvalidSource,
    Fault,
    UnsupportedSupply,
}
impl<E> From<MmError> for UserWriteError<E> {
    fn from(error: MmError) -> Self {
        Self::Owner(error)
    }
}
impl<E> From<crate::mm::transfer::TransferError> for UserWriteError<E> {
    fn from(error: crate::mm::transfer::TransferError) -> Self {
        Self::Owner(error.into())
    }
}

/// Why a venue's copy-on-write crossing (a supply or a settlement) did not
/// finish. The carrier met the MM's editor held on another CPU: that is "not
/// now", and the protocol answers it with the editor-release wait it sampled
/// before the crossing (#3061), the same wait an EL0 copy-on-write fault
/// parks on. Only a refusal of the crossing itself is the venue's error.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum CowCrossing<E> {
    /// The MM's editor was held: nothing was supplied or settled.
    EditorHeld,
    Failed(E),
}
impl<E> From<E> for CowCrossing<E> {
    fn from(error: E) -> Self {
        Self::Failed(error)
    }
}

/// ISA copy mechanics and the existing physical supply crossing. This owns
/// neither grants nor a pool. Supply must publish or return a refusal; it
/// cannot report progress merely because the producer was notified.
pub trait UserWriteVenue<Context: Copy + Send + Sync + zerocopy::FromZeros> {
    type Prepared: PreparedPageResolver;
    type Cow: CowResolver;
    type Error;

    fn selection_venues(&mut self) -> SelectionVenues<'_, Self::Prepared, Self::Cow>;
    fn settle_completions(
        &mut self,
        request: &UserWriteRequest<'_>,
    ) -> Result<(), CowCrossing<Self::Error>>;
    fn supply_cow(&mut self, window: PortalGrantWindow) -> Result<(), CowCrossing<Self::Error>>;
    fn supply_backing(&mut self, _window: PortalGrantWindow) -> Option<Result<(), Self::Error>> {
        None
    }
    fn settle_preparation(
        &mut self,
        _target: &UserWriteTarget,
    ) -> Result<(), CowCrossing<Self::Error>> {
        Ok(())
    }

    /// Copy only while the exact owner fence is live; the bytes are the
    /// selected slice of the original kernel source, never a replayed prefix.
    fn copy(&mut self, fence: &ValidatedChunk<'_, Context>, bytes: &[u8]) -> bool;
}

/// A copy-on-write crossing's refusal, as the protocol's answer: a held
/// editor is the editor-release wait enrolled before the last probe.
fn cow_crossing_refusal<E>(
    crossing: CowCrossing<E>,
    editor: Option<carrick_core_abi::PortalOwnerWait>,
) -> UserWriteError<E> {
    match crossing {
        CowCrossing::EditorHeld => editor.map_or(UserWriteError::Busy, |wait| {
            UserWriteError::Owner(MmError::Wait(wait))
        }),
        CowCrossing::Failed(error) => UserWriteError::Mechanics(error),
    }
}

/// The settlement crossing a write or a preparation rings (#2716).
fn settle<Context: Copy + Send + Sync + zerocopy::FromZeros, V: UserWriteVenue<Context>>(
    venue: &mut V,
    request: Option<&UserWriteRequest<'_>>,
    target: &UserWriteTarget,
) -> Result<(), CowCrossing<V::Error>> {
    match request {
        Some(request) => venue.settle_completions(request),
        None => venue.settle_preparation(target),
    }
}

impl<
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
> MmPortal<'_, P, Policy, Geometry, Venue, B, Context>
{
    /// Run the existing native-copy protocol. Every CowSupply releases the
    /// MM editor before crossing and then reselects the same continuation.
    /// A suspended owner returns Busy; this path never polls a gate/editor.
    pub fn write_user_bytes<W: LiveDescriptorWords + ?Sized, V: UserWriteVenue<Context>>(
        &self,
        request: UserWriteRequest<'_>,
        words: &W,
        venue: &mut V,
    ) -> Result<(), UserWriteError<V::Error>> {
        let target = UserWriteTarget {
            handle: request.handle,
            address: request.address,
            len: carrick_guest_arch::GuestLen::new(request.bytes.len() as u64),
            slot: request.slot,
        };
        self.write_user_target(
            target,
            Some(request),
            PortalTransferIntent::UserWrite,
            words,
            venue,
        )
    }

    pub fn prepare_user_write<W: LiveDescriptorWords + ?Sized, V: UserWriteVenue<Context>>(
        &self,
        target: UserWriteTarget,
        words: &W,
        venue: &mut V,
    ) -> Result<(), UserWriteError<V::Error>> {
        self.write_user_target(target, None, PortalTransferIntent::UserWrite, words, venue)
    }

    /// Materialize readable memory using the same exact-owner transfer and
    /// physical supply protocol as output preparation. Read-only mappings
    /// remain read-only and never enter COW write preparation.
    pub fn prepare_user_read<W: LiveDescriptorWords + ?Sized, V: UserWriteVenue<Context>>(
        &self,
        target: UserWriteTarget,
        words: &W,
        venue: &mut V,
    ) -> Result<(), UserWriteError<V::Error>> {
        self.write_user_target(target, None, PortalTransferIntent::UserRead, words, venue)
    }

    /// One copy-on-write crossing, with "not now" as the editor's release
    /// (#3061): an uncontended crossing costs nothing beyond itself. One
    /// that meets the MM's editor held enrols on the editor's release (it
    /// samples the release source after that refusal, so any later release
    /// completes the wait) and probes once more. A second refusal parks the
    /// copy on that wait; it never re-rings while the editor stays held.
    fn cross_cow<E>(
        &self,
        handle: El1MmHandle,
        mut crossing: impl FnMut() -> Result<(), CowCrossing<E>>,
    ) -> Result<(), UserWriteError<E>> {
        match crossing() {
            Err(CowCrossing::EditorHeld) => {}
            other => return other.map_err(|refusal| cow_crossing_refusal(refusal, None)),
        }
        let editor = self.observe_wait(handle, carrick_core_abi::PortalWaitCause::Editor)?;
        crossing().map_err(|refusal| cow_crossing_refusal(refusal, editor))
    }

    fn write_user_target<W: LiveDescriptorWords + ?Sized, V: UserWriteVenue<Context>>(
        &self,
        target: UserWriteTarget,
        request: Option<UserWriteRequest<'_>>,
        intent: PortalTransferIntent,
        words: &W,
        venue: &mut V,
    ) -> Result<(), UserWriteError<V::Error>> {
        let slot = u32::from(target.slot.raw());
        let mut continuation = self.begin(
            target.handle,
            GuestVa::new(target.address.raw()),
            target.len.raw(),
            intent,
            slot,
        )?;
        // One successful supply must make the next selection advance this
        // continuation. A venue that merely acknowledges the crossing may
        // not keep an EL1 worker inside an unbounded selection loop.
        let mut awaiting_supply_progress = false;
        while !continuation.is_complete() {
            let venues = venue.selection_venues();
            if venues.slot != slot {
                return Err(MmError::Stale.into());
            }
            let step = self.select(&continuation, words, venues);
            // The settlement follows every selection, a failed one included:
            // an earlier supply of this call may still be owed to the venue
            // (#2716). The selection's own error is the one reported, and a
            // failed selection's settlement is probed once, never re-probed:
            // the selection's wait already parks this copy.
            let step = match step {
                Ok(step) => step,
                Err(error) => {
                    let _ = settle(venue, request.as_ref(), &target);
                    return Err(error.into());
                }
            };
            self.cross_cow(target.handle, || settle(venue, request.as_ref(), &target))?;
            match step {
                TransferStep::CowSupply(window) => {
                    if awaiting_supply_progress {
                        return Err(UserWriteError::Busy);
                    }
                    self.cross_cow(target.handle, || venue.supply_cow(window))?;
                    awaiting_supply_progress = true;
                }
                TransferStep::Selected(selected) => {
                    let fence = self
                        .revalidate(&continuation, selected, words, slot)?
                        .ok_or_else(|| {
                            selected.retry().map_or(UserWriteError::Busy, |wait| {
                                UserWriteError::Owner(MmError::Wait(wait))
                            })
                        })?;
                    if let Some(request) = request.as_ref() {
                        let offset = usize::try_from(continuation.offset())
                            .map_err(|_| UserWriteError::InvalidSource)?;
                        let count = usize::try_from(selected.len)
                            .map_err(|_| UserWriteError::InvalidSource)?;
                        let end = offset
                            .checked_add(count)
                            .ok_or(UserWriteError::InvalidSource)?;
                        let bytes = request
                            .bytes
                            .get(offset..end)
                            .ok_or(UserWriteError::InvalidSource)?;
                        if !venue.copy(&fence, bytes) {
                            return Err(UserWriteError::Fault);
                        }
                    }
                    fence.complete(&mut continuation)?;
                    awaiting_supply_progress = false;
                }
                TransferStep::Supply(window) => {
                    if awaiting_supply_progress {
                        return Err(UserWriteError::Busy);
                    }
                    match venue.supply_backing(window) {
                        Some(result) => result.map_err(UserWriteError::Mechanics)?,
                        None => return Err(UserWriteError::UnsupportedSupply),
                    }
                    awaiting_supply_progress = true;
                }
                TransferStep::GrowResidency => {
                    if !venue.selection_venues().cow.grow_residency() {
                        return Err(UserWriteError::Owner(MmError::NoMemory));
                    }
                }
                TransferStep::Suspended => return Err(UserWriteError::Busy),
                TransferStep::Complete => break,
            }
        }
        Ok(())
    }
}
