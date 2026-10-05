//! Neutral reservation storage records and prepared-copy custody.
use carrick_core_abi::*;
use core::cell::UnsafeCell;
use core::sync::atomic::AtomicU64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    /// Non-anonymous mappings participate in placement but cannot be edited.
    pub anonymous: bool,
    /// Insertion-time attributes; anything but plain private anonymous is
    /// host-owned and every EL1 edit touching it forwards.
    pub flags: ReservationNodeFlags,
    pub generation: ReservationGeneration,
    pub host_backing: Option<carrick_core_abi::HostBackingIdentity>,
}

/// Byte charges of committed nodes, whole-root or within one range: every
/// node (`RLIMIT_AS`), `RLIMIT_DATA` nodes, and `LOCKED` anonymous nodes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Charges {
    pub bytes: u64,
    pub data: u64,
    pub locked: u64,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct ReservationNodeData {
    pub start: u64,
    pub end: u64,
    pub first: u64,
    pub last: u64,
    pub gap: u64,
    pub bytes: u64,
    pub data: u64,
    /// Subtree bytes of `LOCKED` anonymous nodes.
    pub locked: u64,
    /// This node's [`ReservationIncarnation`]; zero never names one.
    pub incarnation: u64,
    pub left: u32,
    pub right: u32,
    pub height: u32,
    /// [`ReservationProtection`] bits (three) and [`ReservationNodeFlags`]
    /// bits (seven), packed so the bootstrap table fits its region.
    pub prot: u16,
    pub flags: u16,
    pub host_backing: Option<carrick_core_abi::HostBackingIdentity>,
}
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
