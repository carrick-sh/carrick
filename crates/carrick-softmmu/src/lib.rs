//! Platform-neutral linear guest-physical placement, software TLB, and stage-1 walker binding
//! for Carrick's software vCPU (`carrick-softmmu`).
//!
//! # Architecture (`carrick-sh/carrick#578`, slice 1a `#580`)
//!
//! - [`LinearPlacement`]: places guest-physical extents at `host = gpa + K` inside one reserved
//!   host virtual span and provides [`LinearPlacement::host`], the **only** conversion from an
//!   authenticated guest-physical address ([`FrameGpa`] or [`RootGpa`]) to [`HostVa`].
//! - [`MmioHoles`]: excludes guest-physical MMIO regions (such as the xAPIC page at
//!   [`LAPIC_MMIO_BASE_GPA`] = `0xfee0_0000`) from placement and [`SoftTlb`] fills so accesses
//!   always trap into device models.
//! - [`SoftTlb`]: per-CPU direct-mapped 1024-entry L1 software TLB per access plane (`read`,
//!   `write`, `exec`) with 16-byte [`SoftTlbEntry`] records tagged by `va_page | cpl_bit | ac_bit`
//!   and `addend = host_page - va_page`. Flushed on `mov cr3` ([`SoftTlb::flush_all`]) and evicted
//!   on `invlpg` ([`SoftTlb::evict_va`]) or code-page translation registration
//!   ([`SoftTlb::evict_write_va`]).
//! - [`SoftWalker`]: binds [`carrick_mmu_core::x86::descriptor_txn::translate_leaf`] over
//!   [`carrick_mmu_core::live_descriptor_words::LiveDescriptorWords`] with hardware x86-64
//!   permission semantics (`PRESENT`, `USER` vs CPL, `WRITE` across ancestors and leaf, `NX`,
//!   SMAP via `RFLAGS.AC` in `CPL0`, SMEP for `CPL0` instruction fetch on user pages, reserved
//!   bits, `COW` write classification, extent authentication `(Stage1Gpa, OwnerGeneration) ->
//!   FrameGpa`, and code-page generation bumping).
//! - [`VecGuestMemory`]: VM-free `Vec<AtomicU64>`-backed [`SoftMmuMemory`] implementation for
//!   deterministic unit and property tests in `carrick-softmmu` and `carrick-softcpu-x86`.

#![no_std]
extern crate alloc;

pub mod domains;
pub mod placement;
pub mod tlb;
pub mod walker;

pub use domains::{
    Access, Cpl, CpuAccessMode, FaultClass, FrameGpa, GuestVa, OwnerGeneration, PAGE_BASE_MASK_4K,
    PAGE_OFFSET_MASK_4K, PAGE_SHIFT_4K, PAGE_SIZE_4K, PageFaultErrorCode, PageFaultInfo, RootGpa,
    SoftFaultClass, Stage1Gpa, TranslatedLeaf, UserVa,
};
pub use placement::{
    HostVa, LAPIC_MMIO_BASE_GPA, LAPIC_MMIO_SIZE_BYTES, LinearPlacement, MAX_MMIO_HOLES, MmioHole,
    MmioHoles, PlacementError, PlacementGpa,
};
pub use tlb::{
    SOFT_TLB_BITS, SOFT_TLB_ENTRIES, SOFT_TLB_INDEX_MASK, SoftTlb, SoftTlbEntry, SoftTlbPlane,
    SoftTlbStats, TLB_TAG_AC_BIT, TLB_TAG_CPL3_BIT, TLB_TAG_INVALID, TLB_TAG_MODE_MASK,
};
pub use walker::{
    DEFAULT_MAX_PHY_ADDR, ExtentRecord, ExtentTable, MAX_MAX_PHY_ADDR, MIN_MAX_PHY_ADDR,
    ResolvedAccess, ResolvedSpan, SoftMmuMemory, SoftWalker, SoftWalkerStats, VecGuestMemory,
    WalkOutcome, has_reserved_bits_when_present, reserved_phyaddr_mask,
};
