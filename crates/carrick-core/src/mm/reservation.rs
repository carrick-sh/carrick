//! Neutral reservation storage records and prepared-copy custody.
//!
//! Raw selections cannot mint copy permits outside the revalidating owner.
//! Even a request naming the right MM and VA cannot authorize a peer IPA:
//! ```compile_fail
//! use carrick_core::mm::reservation::Reservations;
//! use carrick_core_abi::{ReservationGeometry, ReservationPolicy, PortalTransferRequest};
//! fn forge<P: ReservationPolicy, G: ReservationGeometry>(
//!     root: &mut Reservations<'_, P, G>, mut request: PortalTransferRequest,
//! ) {
//!     request.selected.ipa += 0x10000; // same-VA peer's output
//!     let _ = root.prepare_copy(request, None);
//! }
//! ```
use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU64;

#[repr(C)]
pub struct ReservationNode {
    // The original AtomicU32 had four bytes of alignment padding here.
    // AtomicU64 preserves the stride and carries exact generation+phase CAS.
    pub next_free: AtomicU64,
    pub data: UnsafeCell<ReservationNodePayload>,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PreparedNodeHeader {
    pub next: u32,
    pub tail: u32,
    pub words: [u64; 13],
}
#[derive(Clone, Copy)]
pub union ReservationNodePayload {
    pub mapping: ReservationNodeData,
    pub prepared: PreparedNodeHeader,
    pub words: [u64; 14],
}
const _: () = assert!(
    core::mem::size_of::<ReservationNodePayload>() == core::mem::size_of::<ReservationNodeData>()
);
// A live node belongs to exactly one locked root. Free nodes are handed over
// using the generation-qualified free list's release/acquire operations.
unsafe impl Sync for ReservationNode {}

pub mod prepared;

pub use carrick_core_abi::{
    Charges, Mapping, ReservationGeometry, ReservationMetadataAllocator, ReservationNodeData,
    ReservationPolicy,
};

pub mod root;
pub use root::*;
