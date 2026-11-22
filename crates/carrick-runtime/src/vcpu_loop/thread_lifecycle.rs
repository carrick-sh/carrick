//! HVF's retained-metadata mapper for the shared carrier lifecycle
//! publisher ([`carrick_kernel::dispatch::carrier_lifecycle`]).

use std::sync::Arc;

use carrick_el1_abi::{MetadataResolutionError, PinnedMetadataExtent};
use carrick_guest_mem::GuestVa;
use carrick_hal::retained_metadata::{
    RetainedMetadataBacking, RetainedMetadataExtent, RetainedMetadataMapper,
};
use carrick_vmm_hvf::metadata_grant::{CarrierMetadataAccess, RetainedMetadataMapping};

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

impl RetainedMetadataExtent for HvfRetainedExtent {
    fn guest_base(&self) -> Result<GuestVa, MetadataResolutionError> {
        let pin = self.0.pin()?;
        Ok(GuestVa::new(pin.extent().base()))
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
