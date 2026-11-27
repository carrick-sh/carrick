//! HVF's carrier metadata access for the shared carrier lifecycle publisher
//! ([`carrick_kernel::dispatch::carrier_lifecycle`]) and the shared
//! reservation provider ([`CarrierReservations`]).

use std::sync::Arc;

use carrick_el1_abi::{MetadataExtent, MetadataExtentResolver, MetadataResolutionError};
use carrick_hal::retained_metadata::{
    RetainedMetadataBacking, RetainedMetadataExtent, RetainedMetadataMapper,
};
use carrick_kernel::dispatch::mem::el1_reservations::{
    CarrierReservationAccess, CarrierReservations,
};
use carrick_vmm_hvf::metadata_grant::{
    CarrierMetadataAccess, HostMetadataExtentPin, RetainedMetadataMapping,
};

/// The exact carrier generation's metadata aperture.
pub(super) struct HvfRetainedMetadata(CarrierMetadataAccess);

/// One stage-2 mapping retained in that carrier's custody.
pub(super) struct HvfRetainedExtent(RetainedMetadataMapping);

impl RetainedMetadataMapper for HvfRetainedMetadata {
    type Extent = HvfRetainedExtent;

    fn region(&self) -> Result<core::ptr::NonNull<u8>, MetadataResolutionError> {
        self.0.region()
    }

    fn map_retained(
        &self,
        backing: Arc<dyn RetainedMetadataBacking>,
    ) -> Result<HvfRetainedExtent, MetadataResolutionError> {
        self.0.map_retained(backing).map(HvfRetainedExtent)
    }
}

impl MetadataExtentResolver for HvfRetainedMetadata {
    type Pin = HostMetadataExtentPin;

    fn pin(
        &self,
        extent: MetadataExtent,
    ) -> Result<HostMetadataExtentPin, MetadataResolutionError> {
        self.0.pin(extent)
    }
}

impl CarrierReservationAccess for HvfRetainedMetadata {
    fn carrier_identity(&self) -> core::num::NonZeroU64 {
        self.0.carrier_identity()
    }

    fn guest_cow_settlement(&self) -> Option<Arc<dyn carrick_el1_abi::CowGrantSettlement>> {
        Some(self.0.guest_cow_settlement())
    }
}

impl RetainedMetadataExtent for HvfRetainedExtent {
    type Pin = HostMetadataExtentPin;

    fn pin(&self) -> Result<HostMetadataExtentPin, MetadataResolutionError> {
        self.0.pin()
    }

    fn try_retire(self) -> Result<(), Self> {
        self.0.try_retire().map_err(Self)
    }
}

pub(super) type CarrierLifecycleMappings =
    carrick_kernel::dispatch::carrier_lifecycle::CarrierLifecycleMappings<HvfRetainedMetadata>;

pub(super) fn carrier_lifecycle_mappings(
    access: CarrierMetadataAccess,
) -> CarrierLifecycleMappings {
    CarrierLifecycleMappings::new(HvfRetainedMetadata(access))
}

/// The shared reservation provider over this carrier generation's metadata
/// access.
pub(super) fn carrier_reservations(
    access: CarrierMetadataAccess,
) -> CarrierReservations<HvfRetainedMetadata> {
    CarrierReservations::new(HvfRetainedMetadata(access))
}
