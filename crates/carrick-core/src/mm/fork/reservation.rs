//! Fork operations bind the same shared reservation authority.
use super::{ForkChildRoot, ForkError, ForkOwnerRefusal, ForkParentRoot};
use crate::mm::reservation::{ReservationGeometry, ReservationPolicy, Reservations};
use carrick_core_abi::PortalForkRequest;
use carrick_core_abi::Refusal;

pub fn refusal_to_fork_error(e: Refusal) -> ForkError {
    match e {
        Refusal::Stale => ForkError::Stale,
        Refusal::Busy | Refusal::PreparedConflict => ForkError::Busy,
        Refusal::MetadataRequired => ForkError::MetadataRequired,
        Refusal::Invalid => ForkError::OwnerRefusal(ForkOwnerRefusal::Invalid),
        Refusal::Collision => ForkError::OwnerRefusal(ForkOwnerRefusal::Collision),
        Refusal::Hole => ForkError::OwnerRefusal(ForkOwnerRefusal::Hole),
        Refusal::ForeignMapping => ForkError::OwnerRefusal(ForkOwnerRefusal::ForeignMapping),
        Refusal::Limit => ForkError::OwnerRefusal(ForkOwnerRefusal::Limit),
    }
}

impl<P: ReservationPolicy, G: ReservationGeometry> ForkChildRoot for Reservations<'_, P, G> {
    fn incarnation(&self) -> u64 {
        self.incarnation().raw()
    }

    fn is_admitted(&self) -> bool {
        self.is_admitted()
    }

    fn fork_write_authorized(&mut self, sequence: Option<core::num::NonZeroU64>) -> bool {
        self.fork_write_authorized(sequence)
    }

    fn authenticate_fork_origin(&mut self, request: PortalForkRequest) -> bool {
        self.authenticate_fork_origin(request)
    }

    fn set_fork_origin(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        self.set_fork_origin(request).map_err(refusal_to_fork_error)
    }

    fn clear_fork_origin(&mut self) {
        self.clear_fork_origin();
    }

    fn publish_fork_child(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        self.publish_fork_child(request)
            .map_err(refusal_to_fork_error)
    }

    fn finish_fork_publication(
        &mut self,
        operation: carrick_core_abi::PortalOperation,
    ) -> Result<(), ForkError> {
        self.finish_fork_publication(operation)
            .map_err(refusal_to_fork_error)
    }

    fn retire(self) -> Result<(), ForkError> {
        self.retire().map_err(refusal_to_fork_error)
    }
}

impl<'b, P: ReservationPolicy, G: ReservationGeometry> ForkParentRoot<Reservations<'b, P, G>>
    for Reservations<'_, P, G>
{
    fn incarnation(&self) -> u64 {
        self.incarnation().raw()
    }

    fn generation(&self) -> carrick_core_abi::ReservationGeneration {
        self.generation()
    }

    fn operation_sequence(&self) -> u64 {
        self.operation_sequence()
    }

    fn fork_ready(&mut self) -> bool {
        self.fork_ready()
    }

    fn fork_write_authorized(&mut self, sequence: Option<core::num::NonZeroU64>) -> bool {
        self.fork_write_authorized(sequence)
    }

    fn reserve_fork_certificate(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        self.reserve_fork_certificate(request)
            .map_err(refusal_to_fork_error)
    }

    fn clone_into(&mut self, child: &mut Reservations<'b, P, G>) -> Result<(), ForkError> {
        self.clone_into(child).map_err(refusal_to_fork_error)
    }

    fn publish_fork_parent(
        &mut self,
        request: PortalForkRequest,
    ) -> Result<carrick_core_abi::ReservationGeneration, ForkError> {
        self.publish_fork_parent(request)
            .map_err(refusal_to_fork_error)
    }

    fn finish_fork_publication(
        &mut self,
        operation: carrick_core_abi::PortalOperation,
    ) -> Result<(), ForkError> {
        self.finish_fork_publication(operation)
            .map_err(refusal_to_fork_error)
    }

    fn commit_fork_generation(
        &mut self,
    ) -> Result<carrick_core_abi::ReservationGeneration, ForkError> {
        self.commit_fork_generation().map_err(refusal_to_fork_error)
    }
}
