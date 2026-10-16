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
        let slot = u32::from(request.slot.raw());
        let mut continuation = self.begin(
            request.handle,
            GuestVa::new(request.address.raw()),
            u64::try_from(request.bytes.len()).map_err(|_| MmError::Invalid)?,
            PortalTransferIntent::UserWrite,
            slot,
        )?;
        while !continuation.is_complete() {
            let venues = venue.selection_venues();
            if venues.slot != slot {
                return Err(MmError::Stale.into());
            }
            let step = self.select(&continuation, words, venues)?;
            venue
                .settle_completions(&request)
                .map_err(UserWriteError::Mechanics)?;
            match step {
                TransferStep::CowSupply(window) => venue
                    .supply_cow(window)
                    .map_err(UserWriteError::Mechanics)?,
                TransferStep::Selected(selected) => {
                    let fence = self
                        .revalidate(&continuation, selected, words, slot)?
                        .ok_or(UserWriteError::Busy)?;
                    let offset = usize::try_from(continuation.offset())
                        .map_err(|_| UserWriteError::InvalidSource)?;
                    let count =
                        usize::try_from(selected.len).map_err(|_| UserWriteError::InvalidSource)?;
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
                    fence.complete(&mut continuation)?;
                }
                TransferStep::Supply(_) => return Err(UserWriteError::UnsupportedSupply),
                TransferStep::Suspended => return Err(UserWriteError::Busy),
                TransferStep::Complete => break,
            }
        }
        Ok(())
    }
}
