//! A carrier's capability to publish retained ABI storage into its EL1-only
//! dynamic metadata aperture without copying it.
//!
//! The backend owns the stage-2 mapping, its inventory and its generation;
//! shared host code owns what is mapped, when, and in which order it retires.

use std::sync::Arc;

use carrick_el1_abi::MetadataResolutionError;
use carrick_guest_mem::{GuestVa, HostVa};

/// Storage published read/write to EL1 without copying it.
///
/// # Safety
/// The range must remain allocated and at a stable address until this owner
/// drops. It must contain only shared ABI data, permit concurrent atomic
/// access, and be aligned and sized to the host's 16 KiB mapping granule.
/// The host VM object must also remain stable while published (for example,
/// MAP_SHARED backing); host COW must not replace the object mapped by HVF.
pub unsafe trait RetainedMetadataBacking: std::fmt::Debug + Send + Sync {
    fn host_base(&self) -> HostVa;
    fn mapped_len(&self) -> usize;
}

/// One carrier generation's authority to map retained backings into its EL1
/// metadata aperture. Every call fails `StaleOwner` once that generation is
/// no longer live.
pub trait RetainedMetadataMapper: Send + Sync {
    type Extent: RetainedMetadataExtent;

    /// The carrier's EL1 region. The address is borrowed from this mapper's
    /// retained carrier mapping.
    fn region(&self) -> Result<core::ptr::NonNull<u8>, MetadataResolutionError>;

    /// Map `backing` into the aperture. Stage-2 publication and its inventory
    /// entry commit together before the extent is returned.
    fn map_retained(
        &self,
        backing: Arc<dyn RetainedMetadataBacking>,
    ) -> Result<Self::Extent, MetadataResolutionError>;
}

/// The owned authority to one retained mapping in its exact carrier.
/// Dropping it releases only the authority, never live backing: carrier
/// custody keeps the backing through VM destruction.
pub trait RetainedMetadataExtent: Send + Sized {
    /// The EL1 address of the mapped backing's first byte.
    fn guest_base(&self) -> Result<GuestVa, MetadataResolutionError>;

    /// Retire the mapping. A refused retirement returns the extent, which
    /// keeps the mapping and its backing for another attempt.
    fn try_retire(self) -> Result<(), Self>;
}
