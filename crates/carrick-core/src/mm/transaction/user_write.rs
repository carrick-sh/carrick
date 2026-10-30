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

/// ISA copy mechanics and the existing physical supply crossing. This owns
/// neither grants nor a pool. Supply must publish or return a refusal; it
/// cannot report progress merely because the producer was notified.
pub trait UserWriteVenue<Context: Copy + Send + Sync + zerocopy::FromZeros> {
    type Prepared: PreparedPageResolver;
    type Cow: CowResolver;
    type Error;

    fn selection_venues(&mut self) -> SelectionVenues<'_, Self::Prepared, Self::Cow>;
    fn settle_completions(&mut self, request: &UserWriteRequest<'_>) -> Result<(), Self::Error>;
    fn supply_cow(&mut self, window: PortalGrantWindow) -> Result<(), Self::Error>;
    fn supply_backing(&mut self, _window: PortalGrantWindow) -> Option<Result<(), Self::Error>> {
        None
    }
    fn settle_preparation(&mut self, _target: &UserWriteTarget) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Copy only while the exact owner fence is live; the bytes are the
    /// selected slice of the original kernel source, never a replayed prefix.
    fn copy(&mut self, fence: &ValidatedChunk<'_, Context>, bytes: &[u8]) -> bool;
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
        self.write_user_target(target, Some(request), words, venue)
    }

    pub fn prepare_user_write<W: LiveDescriptorWords + ?Sized, V: UserWriteVenue<Context>>(
        &self,
        target: UserWriteTarget,
        words: &W,
        venue: &mut V,
    ) -> Result<(), UserWriteError<V::Error>> {
        self.write_user_target(target, None, words, venue)
    }

    fn write_user_target<W: LiveDescriptorWords + ?Sized, V: UserWriteVenue<Context>>(
        &self,
        target: UserWriteTarget,
        request: Option<UserWriteRequest<'_>>,
        words: &W,
        venue: &mut V,
    ) -> Result<(), UserWriteError<V::Error>> {
        let slot = u32::from(target.slot.raw());
        let mut continuation = self.begin(
            target.handle,
            GuestVa::new(target.address.raw()),
            target.len.raw(),
            PortalTransferIntent::UserWrite,
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
            let step = self.select(&continuation, words, venues)?;
            match request.as_ref() {
                Some(request) => venue.settle_completions(request),
                None => venue.settle_preparation(&target),
            }
            .map_err(UserWriteError::Mechanics)?;
            match step {
                TransferStep::CowSupply(window) => {
                    if awaiting_supply_progress {
                        return Err(UserWriteError::Busy);
                    }
                    venue
                        .supply_cow(window)
                        .map_err(UserWriteError::Mechanics)?;
                    awaiting_supply_progress = true;
                }
                TransferStep::Selected(selected) => {
                    let fence = self
                        .revalidate(&continuation, selected, words, slot)?
                        .ok_or(UserWriteError::Busy)?;
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
                TransferStep::Suspended => return Err(UserWriteError::Busy),
                TransferStep::Complete => break,
            }
        }
        Ok(())
    }
}
