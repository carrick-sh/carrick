//! Platform-neutral linear guest-physical placement, software TLB, and stage-1 walker binding
//! for Carrick's software vCPU (`carrick-softmmu`).
//!
//! # Architecture (`carrick-sh/carrick#578`, slice 1a `#580`)
//!
//! - [`LinearPlacement`]: places guest-physical extents at `host = gpa + K` inside one reserved
//!   host virtual span and provides [`LinearPlacement::host`], the **only** conversion from an
//!   extent-authenticated guest-physical address ([`AuthenticatedGpa`]) to [`HostVa`].
//! - [`MmioHoles`]: excludes guest-physical MMIO regions (such as the xAPIC page at
//!   [`LAPIC_MMIO_BASE_GPA`] = `0xfee0_0000`) from placement and [`SoftTlb`] fills so accesses
//!   return [`WalkOutcome::Mmio`] / [`AccessOutcome::Mmio`] / [`ResolvedSpan::Mmio`] and never
//!   inject a `#PF`.
//! - [`SoftTlb`]: per-CPU direct-mapped 1024-entry L1 software TLB per access plane (`read`,
//!   `write`, `exec`) with 16-byte [`SoftTlbEntry`] records tagged by `va_page | mode_bits` and
//!   `addend = host_page - va_page`. Flushed on `mov cr3` ([`SoftTlb::flush_all`]), evicted across
//!   4 KiB or 2 MiB / 1 GiB sibling slots on `invlpg` ([`SoftTlb::evict_va`]), and write-plane
//!   flushed across CPUs when an authenticated frame becomes a code page
//!   ([`ExtentTable::mark_code_page`]).
//! - [`SoftWalker`]: binds [`carrick_mmu_core::x86::descriptor_txn::translate_leaf_hardware`] over
//!   [`carrick_mmu_core::live_descriptor_words::LiveDescriptorWords`] in a single 4-level walk with
//!   hardware x86-64 permission semantics (`PRESENT`, `USER` vs CPL, `WRITE` with `CR0.WP`, `NX`
//!   with `EFER.NXE`, `CR4.SMAP` via `RFLAGS.AC` in `CPL0`, `CR4.SMEP` for `CPL0` instruction fetch
//!   on user pages, reserved bits vs `MAXPHYADDR`, non-leaf/leaf ignored software bits, atomic CAS
//!   `ACCESSED`/`DIRTY` updates, `COW` write classification, extent authentication
//!   `(Stage1Gpa, leaf.size, OwnerGeneration) -> AuthenticatedGpa`, and frame-keyed code-page
//!   generation bumping).

#![no_std]
extern crate alloc;
extern crate std;

pub mod domains;
pub mod placement;
pub mod shootdown;
pub mod tlb;
pub mod walker;

pub use domains::{
    ACCESSED, ADDRESS, Access, AuthenticatedGpa, COW, Cpl, CpuAccessMode, DEFAULT_MAX_PHY_ADDR,
    DIRTY, DescriptorRefusal, FaultClass, FrameGpa, GuestVa, HUGE, HardwareFaultClass,
    HardwareWalkConfig, LeafSize, LiveDescriptorWords, MAX_AD_CAS_RETRIES, MAX_MAX_PHY_ADDR,
    MAY_EXEC, MAY_WRITE, MIN_MAX_PHY_ADDR, NX, OwnerGeneration, PAGE, PAGE_BASE_MASK_4K,
    PAGE_OFFSET_MASK_4K, PAGE_SHIFT_4K, PAGE_SIZE_4K, PAT_LARGE, PREPARED, PRESENT, PRIVATE,
    PageFaultClass, PageFaultErrorCode, PageFaultInfo, RETIRED, RootGpa, SoftCpuException,
    SoftFaultClass, SoftTranslationError, Stage1Gpa, TranslatedLeaf, USER, UserVa, WRITE,
    has_hardware_reserved_bits_when_present, reserved_phyaddr_mask, translate_leaf_hardware,
};
pub use placement::{
    HostVa, LAPIC_MMIO_BASE_GPA, LAPIC_MMIO_SIZE_BYTES, LinearPlacement, MAX_MMIO_HOLES, MmioHole,
    MmioHoles, PlacementError, PlacementGpa,
};
pub use shootdown::{
    PendingShootdown, ShootdownAuthority, ShootdownEpoch, ShootdownKick, ShootdownStamp,
    ShootdownStats, VcpuShootdown, VcpuShootdownState,
};
pub use tlb::{
    SOFT_TLB_BITS, SOFT_TLB_ENTRIES, SOFT_TLB_INDEX_MASK, SoftTlb, SoftTlbEntry, SoftTlbPlane,
    SoftTlbStats, TLB_TAG_AC_BIT, TLB_TAG_CPL3_BIT, TLB_TAG_INVALID, TLB_TAG_MODE_MASK,
    TLB_TAG_NXE_OFF_BIT, TLB_TAG_SMAP_OFF_BIT, TLB_TAG_SMEP_OFF_BIT, TLB_TAG_WP_OFF_BIT,
};
pub use walker::{
    AccessOutcome, AuthenticatedDescriptorWords, ExtentRecord, ExtentTable, ResolvedAccess,
    ResolvedSpan, SoftMmuMemory, SoftWalker, SoftWalkerStats, WalkOutcome,
};
