//! The stage-1 mm projection a kernel-level mm mutation consumes. Implemented
//! by the carrier's `Stage1MmLease` (HVPatch on HVF today; any execution
//! backend tomorrow). The kernel never names the implementation.
//!
//! # What crosses this seam
//!
//! Dispatch builds one `ForeignMmMutationAuthority` per Linux process at
//! dispatcher bind time and hands it the process's projection. The authority
//! itself never inspects the projection: it carries it to the carrier's
//! exact-MM quiesce, which is where the three operations below are consumed
//! when a foreign-COW write invalidates the target's exact ASID:
//!
//! - [`Stage1MmProjection::foreign_mm_binding`] authenticates the caller's
//!   expected `(ASID, stage-1 root)` against what the mm publishes now, so a
//!   recycled numeric ASID cannot acknowledge work for an older root;
//! - [`Stage1MmProjection::foreign_stage1_identity`] addresses the
//!   invalidation to the exact `(mm, binding, ASID generation)`;
//! - [`Stage1MmProjection::publish_foreign_cow_invalidation`] mints the
//!   generation every executor resident on the mm must observe before it
//!   re-enters the guest.
//!
//! All three are expressed in the foreign-mm domain types of this crate; a
//! backend-private handle (a page-table manager, a hypervisor VM) never
//! appears in a signature, which is what lets the kernel hold the projection
//! type-erased.

use std::fmt::Debug;

use crate::foreign_mm::{
    ForeignCowInvalidationGeneration, ForeignMmBinding, ForeignMmId, ForeignStage1Identity,
};

/// The kernel's view of one Linux process's stage-1 address space.
///
/// Object-safe: dispatch and the kernel graph hold `Arc<dyn
/// Stage1MmProjection>` and never learn the backend's concrete lease type.
pub trait Stage1MmProjection: Debug + Send + Sync {
    /// The exact ASID and stage-1 root this mm publishes right now.
    fn foreign_mm_binding(&self) -> ForeignMmBinding;

    /// The exact stage-1 identity a foreign-COW invalidation of `mm` is
    /// addressed to: the current binding plus the lifetime of its ASID.
    fn foreign_stage1_identity(&self, mm: ForeignMmId) -> ForeignStage1Identity;

    /// Publish one more COW invalidation generation to every executor
    /// resident on this mm and return it; the invalidation is acknowledged
    /// against exactly that generation.
    fn publish_foreign_cow_invalidation(&self) -> ForeignCowInvalidationGeneration;
}

/// The backend that may install foreign-mm state on a kernel mm, and the
/// capability its lifecycle code mints to do so.
///
/// The kernel's `Mm::install_foreign_mm_*` operations are generic over an
/// installer and take `&I::InstallPermit`, so the kernel never names the
/// permit type. A backend keeps its permit's constructor private to its
/// bootstrap/lifecycle module: a syscall handler, which only ever holds a
/// type-erased [`Stage1MmProjection`], cannot mint one and so cannot replace
/// the carrier endpoint on an mm.
///
/// This is a companion of [`Stage1MmProjection`] rather than an associated
/// type on it because a trait object must name every associated type of its
/// trait; `dyn Stage1MmProjection` would otherwise have to spell out the
/// backend's permit, which is exactly what the seam hides.
pub trait ForeignMmInstaller: Stage1MmProjection {
    /// The backend-minted install capability.
    type InstallPermit;
}
