//! Stage-1 page-table walker binding over [`translate_leaf`], [`LiveDescriptorWords`],
//! [`LinearPlacement`], and [`SoftTlb`].
//!
//! Enforces hardware x86-64 4-level paging semantics (Intel SDM Vol. 3A §4.5 and §4.7) across all
//! 4 levels (`PML4`, `PDPT`, `PD`, `PT`):
//! - `PRESENT` at every level (`FaultClass::NotPresent`; when `P == 0`, bits `63:1` are ignored
//!   by hardware and never raise `RSVD`),
//! - `USER` at every level vs `CPL` (`FaultClass::Protection`),
//! - `WRITE` at every level and `COW` on leaf (`FaultClass::Protection` / `FaultClass::CowWrite`),
//! - `NX` (`XD`, bit 63) at every level on `Access::Execute` (`FaultClass::Nx` -> `#PF` with
//!   `P | I/D` when `EFER.NXE == 1`, or `FaultClass::Reserved` when `EFER.NXE == 0`),
//! - Supervisor Mode Access Prevention (SMAP): `CPL0` data read/write to an effective-`USER` page
//!   when `RFLAGS.AC == 0` faults with [`SoftFaultClass::SmapProtection`],
//! - Supervisor Mode Execution Prevention (SMEP): `CPL0` instruction fetch from an effective-`USER`
//!   page always faults with [`SoftFaultClass::SmepProtection`] regardless of `RFLAGS.AC`,
//! - Reserved-bit checking on every present entry parameterized by `MAXPHYADDR` (Intel SDM Vol. 3A
//!   §4.5: bits `[51:MAXPHYADDR]` are reserved and raise `#PF(RSVD=1)`; bits `52..=58` are
//!   ignored/available to software; bits `59..=62` are ignored when PKE is off; `PML4E.PS` bit 7
//!   and unaligned large-page address bits on 1 GiB `PDPTE` / 2 MiB `PDE` are reserved),
//! - Extent authentication (`(Stage1Gpa, len, OwnerGeneration) -> FrameGpa`) before calling
//!   [`LinearPlacement::host`],
//! - MMIO hole exclusion (e.g. xAPIC at `0xfee0_0000` is never filled into [`SoftTlb`]),
//! - Code-page write trapping (`write` TLB entries remain invalid for pages holding cached
//!   translations, and writes bump the page's code generation).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering, fence};

use carrick_mmu_core::x86::descriptor_txn::{
    ADDRESS, COW, DescriptorRefusal, HUGE, LiveDescriptorWords, MAY_EXEC, MAY_WRITE, NX, PAGE,
    PREPARED, PRESENT, RETIRED, USER, WRITE, translate_leaf,
};

use crate::domains::{
    Access, Cpl, CpuAccessMode, FaultClass, FrameGpa, GuestVa, OwnerGeneration, PAGE_BASE_MASK_4K,
    PAGE_OFFSET_MASK_4K, PAGE_SIZE_4K, PageFaultInfo, RootGpa, SoftFaultClass, Stage1Gpa,
    TranslatedLeaf,
};
use crate::placement::{HostVa, LinearPlacement, PlacementError};
use crate::tlb::SoftTlb;

const DESCRIPTORS_PER_TABLE: usize = 512;

/// Default `MAXPHYADDR` for the pinned x86-64-v3 guest CPUID view (`48` physical address bits).
pub const DEFAULT_MAX_PHY_ADDR: u8 = 48;

/// Minimum architectural `MAXPHYADDR` in 64-bit paging (`32`).
pub const MIN_MAX_PHY_ADDR: u8 = 32;

/// Maximum architectural `MAXPHYADDR` in 64-bit 4-level paging (`52`).
pub const MAX_MAX_PHY_ADDR: u8 = 52;

/// Hardware-ignored software/PKE bits (`52..=62`) on present paging-structure entries
/// (Intel SDM Vol. 3A §4.5: bits `52..=58` are ignored; bits `59..=62` are ignored when PKE=0).
const IGNORED_HIGH_BITS_52_TO_62: u64 = 0x7ff0_0000_0000_0000;

/// Hardware-ignored software bits (`8..=11`) on non-leaf table descriptors (`PML4E`, non-huge
/// `PDPTE`/`PDE`).
const IGNORED_NONLEAF_LOW_SW_BITS: u64 = RETIRED | PREPARED | COW | MAY_WRITE;

const fn level_bytes(level: usize) -> u64 {
    1u64 << (39 - level * 9)
}

/// Compute the mask of reserved physical-address bits `[51 : max_phy_addr]` for a given
/// `max_phy_addr` (`32..=52`), per Intel SDM Vol. 3A §4.5.
#[inline]
pub const fn reserved_phyaddr_mask(max_phy_addr: u8) -> u64 {
    let clamped = if max_phy_addr < MIN_MAX_PHY_ADDR {
        MIN_MAX_PHY_ADDR
    } else if max_phy_addr > MAX_MAX_PHY_ADDR {
        MAX_MAX_PHY_ADDR
    } else {
        max_phy_addr
    };
    if clamped >= MAX_MAX_PHY_ADDR {
        0
    } else {
        let width = (MAX_MAX_PHY_ADDR - clamped) as u32;
        ((1u64 << width) - 1) << (clamped as u32)
    }
}

/// Return `true` if a **present** (`P == 1`) paging-structure entry at `level` (`0 = PML4 .. 3 = PT`)
/// has any hardware-reserved bit set under `(max_phy_addr, nxe)` per Intel SDM Vol. 3A §4.5.
#[inline]
pub const fn has_reserved_bits_when_present(
    entry: u64,
    level: usize,
    max_phy_addr: u8,
    nxe: bool,
) -> bool {
    // 1. Bits [51 : MAXPHYADDR] are reserved at every paging level.
    if (entry & reserved_phyaddr_mask(max_phy_addr)) != 0 {
        return true;
    }
    // 2. Bit 63 (XD / NX) is reserved when EFER.NXE == 0.
    if !nxe && (entry & NX) != 0 {
        return true;
    }
    // 3. PML4E (level 0): bit 7 (PS / HUGE) must be 0.
    if level == 0 && (entry & HUGE) != 0 {
        return true;
    }
    // 4. Large-page PDPTE (1 GiB, level 1) or PDE (2 MiB, level 2): bits [29:13] or [20:13] must be 0.
    if (level == 1 || level == 2) && (entry & HUGE) != 0 {
        let unaligned_mask = (level_bytes(level) - 1) & ADDRESS & !(1u64 << 12);
        if (entry & unaligned_mask) != 0 {
            return true;
        }
    }
    // Bits 52..=58 (ignored) and 59..=62 (protection keys when PKE=1, ignored otherwise) are
    // never reserved bits on x86-64.
    false
}

/// Adapter over [`LiveDescriptorWords`] that strips hardware-ignored software bits (`52..=62`,
/// plus non-leaf software bits `8..=11`) after [`SoftWalker`] has already validated hardware
/// reserved bits, so [`translate_leaf`]'s internal software-planner bitmask check does not
/// falsely reject hardware-ignored bits such as bit 55.
struct HardwareDescriptorView<'a, M: ?Sized> {
    inner: &'a M,
}

impl<'a, M: LiveDescriptorWords + ?Sized> LiveDescriptorWords for HardwareDescriptorView<'a, M> {
    #[inline]
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        let raw = self.inner.load(pa)?;
        // Preserve COW (bit 10) on 4 KiB PTEs and huge leaves; strip hardware-ignored high bits
        // 52..=62 so `translate_leaf` evaluates pure hardware permissions + COW.
        Ok(raw & !IGNORED_HIGH_BITS_52_TO_62)
    }

    #[inline]
    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        self.inner.compare_exchange(pa, current, new)
    }

    #[inline]
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.inner.store_unlinked(pa, value)
    }

    #[inline]
    fn publish_barrier(&self) {
        self.inner.publish_barrier();
    }

    #[inline]
    fn invalidate_range(&self, va: u64, len: u64) {
        self.inner.invalidate_range(va, len);
    }
}

/// Committed physical extent record used to authenticate `(Stage1Gpa, len, OwnerGeneration) -> FrameGpa`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentRecord {
    /// Starting 4 KiB-aligned frame GPA of the extent.
    pub base: FrameGpa,
    /// Byte length of the extent (multiple of 4 KiB).
    pub len_bytes: u64,
    /// Active owner generation for this extent.
    pub generation: OwnerGeneration,
}

impl ExtentRecord {
    /// Construct a new 4 KiB-aligned extent record.
    #[inline]
    pub const fn new(base: FrameGpa, len_bytes: u64, generation: OwnerGeneration) -> Self {
        Self {
            base,
            len_bytes,
            generation,
        }
    }

    /// Exclusive end GPA of the extent.
    #[inline]
    pub const fn end_gpa(self) -> u64 {
        self.base.raw().saturating_add(self.len_bytes)
    }

    /// Return `true` if `[gpa, gpa + len_bytes)` lies wholly inside this extent.
    #[inline]
    pub const fn contains_span(self, gpa: u64, len_bytes: u64) -> bool {
        let span_end = match gpa.checked_add(len_bytes) {
            Some(end) => end,
            None => return false,
        };
        gpa >= self.base.raw() && span_end <= self.end_gpa()
    }
}

/// Physical extent inventory authenticating `(Stage1Gpa, len, OwnerGeneration) -> FrameGpa`.
#[derive(Clone, Debug, Default)]
pub struct ExtentTable {
    /// Map from `base.raw()` to [`ExtentRecord`].
    by_base: BTreeMap<u64, ExtentRecord>,
}

impl ExtentTable {
    /// Create an empty extent table.
    #[inline]
    pub const fn new() -> Self {
        Self {
            by_base: BTreeMap::new(),
        }
    }

    /// Install or replace an extent at `record.base`.
    ///
    /// Returns `false` if the extent is zero-sized, not 4 KiB-aligned, or overlaps an existing
    /// extent at a different base.
    pub fn install(&mut self, record: ExtentRecord) -> bool {
        let base = record.base.raw();
        if record.len_bytes == 0
            || (base & PAGE_OFFSET_MASK_4K) != 0
            || (record.len_bytes & PAGE_OFFSET_MASK_4K) != 0
        {
            return false;
        }
        let end = match base.checked_add(record.len_bytes) {
            Some(end) => end,
            None => return false,
        };
        if let Some((_, prev)) = self.by_base.range(..=base).next_back()
            && prev.base.raw() != base
            && prev.end_gpa() > base
        {
            return false;
        }
        if let Some((&next_base, _)) = self.by_base.range(base..).find(|&(&k, _)| k != base)
            && next_base < end
        {
            return false;
        }
        self.by_base.insert(base, record);
        true
    }

    /// Remove the extent starting at `base`.
    pub fn remove(&mut self, base: FrameGpa) -> Option<ExtentRecord> {
        self.by_base.remove(&base.raw())
    }

    /// Look up the extent covering `[gpa, gpa + len_bytes)`.
    #[inline]
    pub fn lookup_span(&self, gpa: u64, len_bytes: u64) -> Option<ExtentRecord> {
        let (_, record) = self.by_base.range(..=gpa).next_back()?;
        if record.contains_span(gpa, len_bytes) {
            Some(*record)
        } else {
            None
        }
    }

    /// Authenticate a stage-1 output page `(stage1_gpa, len_bytes)` against `expected_generation`,
    /// returning the corresponding [`FrameGpa`] only when both the extent span and
    /// [`OwnerGeneration`] match.
    #[inline]
    pub fn authenticate(
        &self,
        stage1_gpa: Stage1Gpa,
        len_bytes: u64,
        expected_generation: OwnerGeneration,
    ) -> Option<FrameGpa> {
        let page_gpa = stage1_gpa.raw() & PAGE_BASE_MASK_4K;
        let record = self.lookup_span(page_gpa, len_bytes)?;
        if record.generation == expected_generation {
            Some(FrameGpa::new(page_gpa))
        } else {
            None
        }
    }

    /// Authenticate a page-table frame GPA during a stage-1 descriptor walk.
    #[inline]
    pub fn authenticate_table_frame(&self, table: Stage1Gpa) -> Option<FrameGpa> {
        let page_gpa = table.raw() & PAGE_BASE_MASK_4K;
        let _record = self.lookup_span(page_gpa, PAGE_SIZE_4K)?;
        Some(FrameGpa::new(page_gpa))
    }
}

/// Trait representing the guest-physical memory and metadata view seen by [`SoftWalker`].
///
/// Implementing this over a `Vec<AtomicU64>` ([`VecGuestMemory`]) allows all `carrick-softmmu`
/// and `carrick-softcpu-x86` tests to run VM-free without `mmap` or `/dev/kvm`.
pub trait SoftMmuMemory: LiveDescriptorWords {
    /// Return the active [`LinearPlacement`] (`host = gpa + K`).
    fn placement(&self) -> &LinearPlacement;

    /// Authenticate a stage-1 [`TranslatedLeaf`] under `root` into a [`FrameGpa`] accepted by
    /// [`LinearPlacement::host`], returning `Err(expected_generation)` when the extent is missing
    /// or its [`OwnerGeneration`] does not match.
    fn authenticate_leaf(
        &self,
        root: RootGpa,
        stage1_gpa: Stage1Gpa,
        leaf: &TranslatedLeaf,
    ) -> Result<FrameGpa, OwnerGeneration>;

    /// Return `true` if `frame_gpa` currently holds cached translated blocks (so its `write` TLB
    /// entry must stay invalid).
    fn is_code_page(&self, frame_gpa: FrameGpa) -> bool;

    /// Return the current code generation for `frame_gpa` (`0` if never translated).
    fn code_generation(&self, frame_gpa: FrameGpa) -> u64;

    /// Notify the memory space that a guest write is about to modify a page holding cached
    /// translations, bumping its code generation and returning the new generation.
    fn on_code_page_write(&mut self, frame_gpa: FrameGpa) -> u64;
}

/// Successful single-page translation returned by [`SoftWalker`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedAccess {
    /// Exact host virtual address for `va` (`host_page + va.page_offset()`).
    pub host_addr: usize,
    /// Host base address of the containing 4 KiB page.
    pub host_page: HostVa,
    /// Authenticated physical frame GPA (`va` page base).
    pub frame_gpa: FrameGpa,
    /// Live stage-1 leaf descriptor.
    pub leaf: TranslatedLeaf,
    /// Whether the page is user-accessible (`USER` set at all paging levels).
    pub is_user_page: bool,
    /// Code generation of `frame_gpa` after any write-triggered bump.
    pub code_generation: u64,
    /// `true` if this write hit a page with cached translations and bumped its code generation.
    pub invalidated_code_page: bool,
}

/// Outcome of resolving a single-page guest memory access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkOutcome {
    /// Normal RAM page resolved to a [`HostVa`].
    Ram(ResolvedAccess),
    /// Stage-1 leaf mapped an unplaced MMIO hole (e.g. xAPIC at `0xfee0_0000`); never filled into
    /// [`SoftTlb`].
    Mmio {
        /// Byte-granular guest physical address (`leaf.output + va.page_offset()`).
        gpa: u64,
        /// Underlying stage-1 leaf descriptor.
        leaf: TranslatedLeaf,
    },
}

/// Resolved host address(es) for a potentially page-crossing operand of length `1..=4096`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedSpan {
    /// Entire operand lies within one 4 KiB page.
    SinglePage {
        /// Host start address of the operand.
        host_addr: usize,
        /// Byte length of the operand.
        len: usize,
    },
    /// Operand straddles the boundary between `va`'s page and the next 4 KiB page.
    Straddling {
        /// Host address of the prefix bytes in the first page.
        first_host_addr: usize,
        /// Number of bytes in the first page (`1..len`).
        first_len: usize,
        /// Host address of the suffix bytes at the start of the second page.
        second_host_addr: usize,
        /// Number of bytes in the second page (`len - first_len`).
        second_len: usize,
    },
}

/// Deterministic structural counters for [`SoftWalker`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SoftWalkerStats {
    /// Stage-1 page-table walks performed on TLB misses.
    pub walks: u64,
    /// TLB entries filled across `read`, `write`, and `exec`.
    pub tlb_fills: u64,
    /// Architectural page faults (`#PF`) raised.
    pub page_faults: u64,
    /// Accesses routed to an MMIO hole (e.g. xAPIC).
    pub mmio_exits: u64,
    /// Writes that bumped a translated code page's generation.
    pub code_page_invalidations: u64,
    /// Multi-byte accesses that straddled a 4 KiB page boundary.
    pub page_crossing_accesses: u64,
}

/// Stage-1 page-table walker binding that enforces x86 hardware permission rules and populates
/// [`SoftTlb`].
///
/// Parameterized by the guest CPU's `MAXPHYADDR` (`32..=52`, defaulting to
/// [`DEFAULT_MAX_PHY_ADDR`] = `48` for the pinned x86-64-v3 CPUID view) and `EFER.NXE` (`true` by
/// default).
#[derive(Clone, Copy, Debug)]
pub struct SoftWalker {
    max_phy_addr: u8,
    nxe: bool,
    stats: SoftWalkerStats,
}

impl Default for SoftWalker {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl SoftWalker {
    /// Create a new [`SoftWalker`] with [`DEFAULT_MAX_PHY_ADDR`] (`48`) and `EFER.NXE == true`.
    #[inline]
    pub const fn new() -> Self {
        Self::with_paging_config(DEFAULT_MAX_PHY_ADDR, true)
    }

    /// Create a [`SoftWalker`] parameterized by the guest CPUID's `MAXPHYADDR` (`32..=52`) with
    /// `EFER.NXE == true`.
    #[inline]
    pub const fn with_max_phy_addr(max_phy_addr: u8) -> Self {
        Self::with_paging_config(max_phy_addr, true)
    }

    /// Create a [`SoftWalker`] parameterized by `MAXPHYADDR` (`32..=52`) and `EFER.NXE`.
    #[inline]
    pub const fn with_paging_config(max_phy_addr: u8, nxe: bool) -> Self {
        let clamped = if max_phy_addr < MIN_MAX_PHY_ADDR {
            MIN_MAX_PHY_ADDR
        } else if max_phy_addr > MAX_MAX_PHY_ADDR {
            MAX_MAX_PHY_ADDR
        } else {
            max_phy_addr
        };
        Self {
            max_phy_addr: clamped,
            nxe,
            stats: SoftWalkerStats {
                walks: 0,
                tlb_fills: 0,
                page_faults: 0,
                mmio_exits: 0,
                code_page_invalidations: 0,
                page_crossing_accesses: 0,
            },
        }
    }

    /// Configured physical-address width (`MAXPHYADDR`, `32..=52`).
    #[inline]
    pub const fn max_phy_addr(&self) -> u8 {
        self.max_phy_addr
    }

    /// Update `MAXPHYADDR` (`32..=52`).
    #[inline]
    pub fn set_max_phy_addr(&mut self, max_phy_addr: u8) {
        self.max_phy_addr = max_phy_addr.clamp(MIN_MAX_PHY_ADDR, MAX_MAX_PHY_ADDR);
    }

    /// Configured `EFER.NXE` state.
    #[inline]
    pub const fn nxe(&self) -> bool {
        self.nxe
    }

    /// Update `EFER.NXE`.
    #[inline]
    pub fn set_nxe(&mut self, nxe: bool) {
        self.nxe = nxe;
    }

    /// Snapshot deterministic structural counters.
    #[inline]
    pub const fn stats(&self) -> SoftWalkerStats {
        self.stats
    }

    /// Reset structural counters to zero.
    #[inline]
    pub fn reset_stats(&mut self) {
        self.stats = SoftWalkerStats::default();
    }

    /// Inspect the paging hierarchy per Intel SDM Vol. 3A §4.5:
    /// - `P == 0` stops the walk with [`FaultClass::NotPresent`] before any reserved-bit check
    ///   (bits `63:1` of non-present entries are ignored by hardware).
    /// - Present entries (`P == 1`) are checked for reserved bits in `[51 : MAXPHYADDR]`, `XD`
    ///   when `EFER.NXE == 0`, `PML4E.PS == 1`, and unaligned large-page bits on 1 GiB / 2 MiB
    ///   leaves. Bits `52..=58` (and `59..=62` when PKE is off) are ignored and never fault.
    /// - Computes whether `USER` (`U/S`, bit 2) is set at every level of the walk.
    fn inspect_hierarchy_and_effective_user<M: LiveDescriptorWords>(
        &self,
        words: &M,
        root: RootGpa,
        va: GuestVa,
    ) -> Result<(bool, u64), FaultClass> {
        if !va.is_canonical_48bit() {
            return Err(FaultClass::Reserved);
        }
        let mut table = root.address().raw();
        if (table & reserved_phyaddr_mask(self.max_phy_addr)) != 0 {
            return Err(FaultClass::Reserved);
        }
        let mut all_user = true;

        for level in 0..4 {
            let index = (va.raw() >> (39 - level * 9)) & 511;
            let entry = words
                .load(table + index * 8)
                .map_err(|_| FaultClass::NotPresent)?;
            if entry & PRESENT == 0 {
                return Err(FaultClass::NotPresent);
            }
            if has_reserved_bits_when_present(entry, level, self.max_phy_addr, self.nxe) {
                return Err(FaultClass::Reserved);
            }
            if entry & USER == 0 {
                all_user = false;
            }
            if level == 3 || entry & HUGE != 0 {
                return Ok((all_user, entry));
            }
            if (entry & IGNORED_NONLEAF_LOW_SW_BITS) != 0 {
                // Hardware ignores bits 8..=11 on non-leaf entries, but `translate_leaf` rejects
                // them; only leaf entries carry Carrick COW/PREPARED flags.
            }
            table = entry & ADDRESS;
        }
        Err(FaultClass::Reserved)
    }

    /// Perform a full slow-path stage-1 walk for `(root, va, access, mode)` and populate
    /// `tlb` when the target is a valid RAM page.
    pub fn walk_and_fill<M: SoftMmuMemory>(
        &mut self,
        memory: &mut M,
        tlb: &mut SoftTlb,
        root: RootGpa,
        va: GuestVa,
        access: Access,
        mode: CpuAccessMode,
    ) -> Result<WalkOutcome, PageFaultInfo> {
        self.stats.walks = self.stats.walks.saturating_add(1);

        // 1. Hardware precedence check per Intel SDM Vol. 3A §4.5 and §4.7:
        //    - `P == 0` -> `NotPresent` (bits 63:1 ignored),
        //    - `P == 1` with any bit in `[51:MAXPHYADDR]` (or `NX` when `!nxe`, or `PML4E.PS`) -> `ReservedBit`,
        //    - bits `52..=62` are ignored by hardware.
        let (is_user_page, raw_terminal_descriptor) =
            match self.inspect_hierarchy_and_effective_user(memory, root, va) {
                Ok(pair) => pair,
                Err(arch_class) => {
                    self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                    let soft_class = match arch_class {
                        FaultClass::NotPresent => SoftFaultClass::NotPresent,
                        FaultClass::Reserved => SoftFaultClass::ReservedBit,
                        FaultClass::Protection | FaultClass::Nx => SoftFaultClass::Protection,
                        FaultClass::CowWrite => SoftFaultClass::CowWrite,
                    };
                    return Err(PageFaultInfo::new(va, access, mode, soft_class, None));
                }
            };

        // 2. Bind to `carrick_mmu_core::x86::descriptor_txn::translate_leaf` through
        //    `HardwareDescriptorView` (which strips hardware-ignored bits 52..=62 after step 1's
        //    exact hardware reserved-bit check) for canonical stage-1 leaf extraction, USER (when
        //    CPL3), NX (when Execute), WRITE across ancestors/leaf, and COW.
        let hw_view = HardwareDescriptorView { inner: memory };
        let mut leaf = match translate_leaf(
            &hw_view,
            root,
            va.to_descriptor_va(),
            access,
            mode.cpl.is_user(),
        ) {
            Ok(leaf) => leaf,
            Err(arch_class) => {
                self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                let soft_class = match arch_class {
                    FaultClass::NotPresent => SoftFaultClass::NotPresent,
                    FaultClass::Protection | FaultClass::Nx => SoftFaultClass::Protection,
                    FaultClass::Reserved => SoftFaultClass::ReservedBit,
                    FaultClass::CowWrite => SoftFaultClass::CowWrite,
                };
                return Err(PageFaultInfo::new(va, access, mode, soft_class, None));
            }
        };
        // Preserve the unmodified raw descriptor word (including software-available bits 52..=58)
        // in the returned `TranslatedLeaf`.
        leaf.descriptor = raw_terminal_descriptor;

        // 3. Enforce CPL0 SMEP and SMAP on effective-USER pages.
        if matches!(mode.cpl, Cpl::Ring0) && is_user_page {
            if matches!(access, Access::Execute) {
                self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                return Err(PageFaultInfo::new(
                    va,
                    access,
                    mode,
                    SoftFaultClass::SmepProtection,
                    Some(leaf),
                ));
            }
            if !mode.ac {
                self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                return Err(PageFaultInfo::new(
                    va,
                    access,
                    mode,
                    SoftFaultClass::SmapProtection,
                    Some(leaf),
                ));
            }
        }

        // 4. MMIO holes (e.g. xAPIC page at 0xfee0_0000) are never placed and never filled into SoftTlb.
        let stage1_gpa = Stage1Gpa::from_leaf_page(&leaf);
        let byte_gpa = stage1_gpa.raw() | (va.page_offset() as u64);
        if memory.placement().is_mmio_hole(stage1_gpa.raw())
            || memory.placement().is_mmio_hole(byte_gpa)
        {
            self.stats.mmio_exits = self.stats.mmio_exits.saturating_add(1);
            return Ok(WalkOutcome::Mmio {
                gpa: byte_gpa,
                leaf,
            });
        }

        // 5. Authenticate `(Stage1Gpa, len, OwnerGeneration)` through the extent table into a `FrameGpa`.
        let frame_gpa = match memory.authenticate_leaf(root, stage1_gpa, &leaf) {
            Ok(frame) => frame,
            Err(expected_generation) => {
                self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                return Err(PageFaultInfo::new(
                    va,
                    access,
                    mode,
                    SoftFaultClass::UnauthenticatedExtent {
                        stage1_gpa,
                        expected_generation,
                    },
                    Some(leaf),
                ));
            }
        };

        // 6. Convert authenticated `FrameGpa -> HostVa` through the sole `LinearPlacement::host` seam.
        let host_page = match memory.placement().host(frame_gpa) {
            Ok(host_va) => host_va,
            Err(PlacementError::MmioHole { gpa }) => {
                self.stats.mmio_exits = self.stats.mmio_exits.saturating_add(1);
                return Ok(WalkOutcome::Mmio {
                    gpa: gpa | (va.page_offset() as u64),
                    leaf,
                });
            }
            Err(_) => {
                self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                return Err(PageFaultInfo::new(
                    va,
                    access,
                    mode,
                    SoftFaultClass::PlacementOutOfBounds { frame_gpa },
                    Some(leaf),
                ));
            }
        };

        // 7. Code-page write protection and SoftTlb plane population.
        let was_code_page = memory.is_code_page(frame_gpa);
        let mut invalidated_code_page = false;

        match access {
            Access::Read => {
                tlb.fill_plane(Access::Read, va, mode, host_page);
                self.stats.tlb_fills = self.stats.tlb_fills.saturating_add(1);
            }
            Access::Write => {
                tlb.fill_plane(Access::Read, va, mode, host_page);
                self.stats.tlb_fills = self.stats.tlb_fills.saturating_add(1);
                if was_code_page {
                    // Pages holding cached translations keep their `write` TLB entry invalid;
                    // the write takes the slow path and bumps the page's code generation.
                    let _ = tlb.evict_write_va(va);
                    let _ = memory.on_code_page_write(frame_gpa);
                    invalidated_code_page = true;
                    self.stats.code_page_invalidations =
                        self.stats.code_page_invalidations.saturating_add(1);
                } else {
                    tlb.fill_plane(Access::Write, va, mode, host_page);
                    self.stats.tlb_fills = self.stats.tlb_fills.saturating_add(1);
                }
            }
            Access::Execute => {
                if was_code_page {
                    let _ = tlb.evict_write_va(va);
                }
                tlb.fill_plane(Access::Read, va, mode, host_page);
                tlb.fill_plane(Access::Execute, va, mode, host_page);
                self.stats.tlb_fills = self.stats.tlb_fills.saturating_add(2);
            }
        }

        let code_generation = memory.code_generation(frame_gpa);
        let host_addr = host_page.page_base() + va.page_offset();

        Ok(WalkOutcome::Ram(ResolvedAccess {
            host_addr,
            host_page,
            frame_gpa,
            leaf,
            is_user_page,
            code_generation,
            invalidated_code_page,
        }))
    }

    /// Fast-path probe followed by slow-path [`Self::walk_and_fill`] for a non-page-crossing access.
    #[allow(clippy::too_many_arguments)]
    pub fn probe_or_walk<M: SoftMmuMemory>(
        &mut self,
        memory: &mut M,
        tlb: &mut SoftTlb,
        root: RootGpa,
        va: GuestVa,
        len: usize,
        access: Access,
        mode: CpuAccessMode,
    ) -> Result<usize, PageFaultInfo> {
        if let Some(host_addr) = tlb.probe(va, len, access, mode) {
            return Ok(host_addr);
        }
        match self.walk_and_fill(memory, tlb, root, va, access, mode)? {
            WalkOutcome::Ram(resolved) => Ok(resolved.host_addr),
            WalkOutcome::Mmio { gpa, leaf } => {
                self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                Err(PageFaultInfo::new(
                    va,
                    access,
                    mode,
                    SoftFaultClass::MmioHole { gpa },
                    Some(leaf),
                ))
            }
        }
    }

    /// Resolve a potentially page-crossing RAM operand of length `1..=4096` bytes.
    ///
    /// - Single-page operands probe [`SoftTlb`] first and walk on miss.
    /// - Page-straddling operands never hit [`SoftTlb`] directly: both pages are translated and
    ///   permission-checked before returning [`ResolvedSpan::Straddling`] so the caller's bounce
    ///   buffer sees atomic two-page validation (if the second page faults, no write to the first
    ///   page has occurred yet).
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_span<M: SoftMmuMemory>(
        &mut self,
        memory: &mut M,
        tlb: &mut SoftTlb,
        root: RootGpa,
        va: GuestVa,
        len: usize,
        access: Access,
        mode: CpuAccessMode,
    ) -> Result<ResolvedSpan, PageFaultInfo> {
        if !va.crosses_page(len) {
            let host_addr = self.probe_or_walk(memory, tlb, root, va, len, access, mode)?;
            return Ok(ResolvedSpan::SinglePage { host_addr, len });
        }

        // Record the page-crossing miss on the TLB and in walker stats.
        let _ = tlb.probe(va, len, access, mode);
        self.stats.page_crossing_accesses = self.stats.page_crossing_accesses.saturating_add(1);

        let first_len = (PAGE_SIZE_4K as usize) - va.page_offset();
        let second_len = len.saturating_sub(first_len);
        let second_va = match va.checked_add(first_len as u64) {
            Some(next) => next,
            None => {
                self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                return Err(PageFaultInfo::new(
                    va,
                    access,
                    mode,
                    SoftFaultClass::NotPresent,
                    None,
                ));
            }
        };

        let first_host_addr = match self.walk_and_fill(memory, tlb, root, va, access, mode)? {
            WalkOutcome::Ram(resolved) => resolved.host_addr,
            WalkOutcome::Mmio { gpa, leaf } => {
                self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                return Err(PageFaultInfo::new(
                    va,
                    access,
                    mode,
                    SoftFaultClass::MmioHole { gpa },
                    Some(leaf),
                ));
            }
        };

        let second_host_addr =
            match self.walk_and_fill(memory, tlb, root, second_va, access, mode)? {
                WalkOutcome::Ram(resolved) => resolved.host_addr,
                WalkOutcome::Mmio { gpa, leaf } => {
                    self.stats.page_faults = self.stats.page_faults.saturating_add(1);
                    return Err(PageFaultInfo::new(
                        second_va,
                        access,
                        mode,
                        SoftFaultClass::MmioHole { gpa },
                        Some(leaf),
                    ));
                }
            };

        Ok(ResolvedSpan::Straddling {
            first_host_addr,
            first_len,
            second_host_addr,
            second_len,
        })
    }
}

/// VM-free guest physical memory backed by a 4 KiB-aligned slice inside a `Vec<AtomicU64>`.
///
/// Designed for unit tests in `carrick-softmmu` and `carrick-softcpu-x86`: uses no `mmap`,
/// no hypervisor, and enforces the exact [`LinearPlacement`] and [`ExtentTable`] invariants.
#[derive(Debug)]
pub struct VecGuestMemory {
    backing: Vec<AtomicU64>,
    aligned_word_offset: usize,
    word_len: usize,
    placement: LinearPlacement,
    extents: ExtentTable,
    default_generation: OwnerGeneration,
    root_generations: BTreeMap<u64, OwnerGeneration>,
    code_pages: BTreeMap<u64, (bool, u64)>,
}

impl VecGuestMemory {
    /// Allocate a zero-initialized guest-physical memory space of `span_bytes` (must be a non-zero
    /// multiple of 4 KiB) with [`crate::placement::MmioHoles::x86_default`].
    pub fn new(span_bytes: u64) -> Result<Self, PlacementError> {
        Self::with_holes(span_bytes, crate::placement::MmioHoles::x86_default())
    }

    /// Allocate a zero-initialized guest-physical memory space of `span_bytes` with explicit
    /// [`crate::placement::MmioHoles`].
    pub fn with_holes(
        span_bytes: u64,
        holes: crate::placement::MmioHoles,
    ) -> Result<Self, PlacementError> {
        if span_bytes == 0 || (span_bytes & PAGE_OFFSET_MASK_4K) != 0 {
            return Err(PlacementError::UnalignedPlacement {
                base_host_addr: 0,
                span_bytes,
            });
        }
        let span_usize = usize::try_from(span_bytes)
            .map_err(|_| PlacementError::AddressOverflow { gpa: span_bytes })?;
        let word_len = span_usize / core::mem::size_of::<AtomicU64>();
        let extra_words = (PAGE_SIZE_4K as usize) / core::mem::size_of::<AtomicU64>();
        let total_words = word_len
            .checked_add(extra_words)
            .ok_or(PlacementError::AddressOverflow { gpa: span_bytes })?;

        let mut backing = Vec::with_capacity(total_words);
        backing.resize_with(total_words, || AtomicU64::new(0));

        let raw_base = backing.as_ptr() as usize;
        let aligned_base =
            (raw_base + (PAGE_OFFSET_MASK_4K as usize)) & !(PAGE_OFFSET_MASK_4K as usize);
        let aligned_word_offset = (aligned_base - raw_base) / core::mem::size_of::<AtomicU64>();

        let placement = LinearPlacement::new(aligned_base, span_bytes, holes)?;
        Ok(Self {
            backing,
            aligned_word_offset,
            word_len,
            placement,
            extents: ExtentTable::new(),
            default_generation: OwnerGeneration::new(1),
            root_generations: BTreeMap::new(),
            code_pages: BTreeMap::new(),
        })
    }

    /// Immutable access to the extent inventory.
    #[inline]
    pub const fn extents(&self) -> &ExtentTable {
        &self.extents
    }

    /// Mutable access to the extent inventory.
    #[inline]
    pub fn extents_mut(&mut self) -> &mut ExtentTable {
        &mut self.extents
    }

    /// Set the expected [`OwnerGeneration`] for walks under `root`.
    pub fn set_root_generation(&mut self, root: RootGpa, generation: OwnerGeneration) {
        self.root_generations
            .insert(root.address().raw(), generation);
    }

    /// Expected [`OwnerGeneration`] for `root` (defaults to `OwnerGeneration::new(1)`).
    #[inline]
    pub fn expected_generation(&self, root: RootGpa) -> OwnerGeneration {
        self.root_generations
            .get(&root.address().raw())
            .copied()
            .unwrap_or(self.default_generation)
    }

    /// Install an extent `[base, base + len_bytes)` with `generation` into the extent inventory.
    #[inline]
    pub fn install_extent(
        &mut self,
        base: FrameGpa,
        len_bytes: u64,
        generation: OwnerGeneration,
    ) -> bool {
        if self.placement.holes().overlaps_range(base.raw(), len_bytes) {
            return false;
        }
        let end = match base.raw().checked_add(len_bytes) {
            Some(end) => end,
            None => return false,
        };
        if end > self.placement.span_bytes() {
            return false;
        }
        self.extents
            .install(ExtentRecord::new(base, len_bytes, generation))
    }

    /// Mark `frame_gpa` as holding cached translated blocks (initializes code generation to at
    /// least `1`).
    ///
    /// Also returns the resulting code generation.
    pub fn mark_code_page(&mut self, frame_gpa: FrameGpa) -> u64 {
        let key = frame_gpa.raw() & PAGE_BASE_MASK_4K;
        let entry = self.code_pages.entry(key).or_insert((false, 0));
        entry.0 = true;
        if entry.1 == 0 {
            entry.1 = 1;
        }
        entry.1
    }

    /// Clear the cached-translation mark on `frame_gpa` while preserving its monotonic generation.
    pub fn clear_code_page(&mut self, frame_gpa: FrameGpa) {
        let key = frame_gpa.raw() & PAGE_BASE_MASK_4K;
        if let Some(entry) = self.code_pages.get_mut(&key) {
            entry.0 = false;
        }
    }

    /// Compute the 9-bit page-table index `(0..512)` for `va` at `level` (`0 = PML4 .. 3 = PT`).
    #[inline]
    pub const fn descriptor_index(va: GuestVa, level: usize) -> usize {
        ((va.raw() >> (39 - level * 9)) & 511) as usize
    }

    /// Store a 64-bit page-table descriptor word at `(table, index)` (`index < 512`).
    pub fn store_descriptor_word(
        &self,
        table: FrameGpa,
        index: usize,
        value: u64,
    ) -> Result<(), PlacementError> {
        if index >= DESCRIPTORS_PER_TABLE {
            return Err(PlacementError::OutOfBounds {
                gpa: table.raw(),
                span_bytes: self.placement.span_bytes(),
            });
        }
        let _host_va = self.placement.host(table)?;
        let table_word_base = (table.raw() as usize) / core::mem::size_of::<AtomicU64>();
        let word_idx = table_word_base + index;
        if word_idx >= self.word_len {
            return Err(PlacementError::OutOfBounds {
                gpa: table.raw(),
                span_bytes: self.placement.span_bytes(),
            });
        }
        self.backing[self.aligned_word_offset + word_idx].store(value, Ordering::Release);
        Ok(())
    }

    /// Write raw bytes at an authenticated `frame_gpa + offset` inside the backing buffer.
    pub fn write_frame_bytes(
        &self,
        frame_gpa: FrameGpa,
        offset_in_frame: usize,
        data: &[u8],
    ) -> Result<(), PlacementError> {
        let total_len =
            offset_in_frame
                .checked_add(data.len())
                .ok_or(PlacementError::AddressOverflow {
                    gpa: frame_gpa.raw(),
                })?;
        let host_base = self.placement.host_range(frame_gpa, total_len)?;
        let dst = (host_base.raw() + offset_in_frame) as *mut u8;
        // SAFETY: `host_range` verified that `[frame_gpa, frame_gpa + total_len)` lies inside our
        // live `backing` allocation and outside any MMIO hole.
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
        Ok(())
    }

    /// Read raw bytes from an authenticated `frame_gpa + offset` inside the backing buffer.
    pub fn read_frame_bytes(
        &self,
        frame_gpa: FrameGpa,
        offset_in_frame: usize,
        out: &mut [u8],
    ) -> Result<(), PlacementError> {
        let total_len =
            offset_in_frame
                .checked_add(out.len())
                .ok_or(PlacementError::AddressOverflow {
                    gpa: frame_gpa.raw(),
                })?;
        let host_base = self.placement.host_range(frame_gpa, total_len)?;
        let src = (host_base.raw() + offset_in_frame) as *const u8;
        // SAFETY: `host_range` verified that `[frame_gpa, frame_gpa + total_len)` lies inside our
        // live `backing` allocation and outside any MMIO hole.
        unsafe {
            core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), out.len());
        }
        Ok(())
    }

    /// Helper to install a standard 4-level page-table mapping (`PML4 -> PDPT -> PD -> PT -> leaf`)
    /// in tests.
    pub fn map_4k_chain(
        &self,
        root: RootGpa,
        va: GuestVa,
        pdpt_frame: FrameGpa,
        pd_frame: FrameGpa,
        pt_frame: FrameGpa,
        leaf_entry: u64,
    ) -> Result<(), PlacementError> {
        self.map_4k_chain_with_intermediate_flags(
            root,
            va,
            pdpt_frame,
            pd_frame,
            pt_frame,
            PRESENT | WRITE | USER,
            PRESENT | WRITE | USER,
            PRESENT | WRITE | USER,
            leaf_entry,
        )
    }

    /// Helper to install a 4-level page-table mapping with explicit flags on `PML4E`, `PDPTE`,
    /// `PDE`, and `PTE`.
    #[allow(clippy::too_many_arguments)]
    pub fn map_4k_chain_with_intermediate_flags(
        &self,
        root: RootGpa,
        va: GuestVa,
        pdpt_frame: FrameGpa,
        pd_frame: FrameGpa,
        pt_frame: FrameGpa,
        pml4_flags: u64,
        pdpt_flags: u64,
        pd_flags: u64,
        leaf_entry: u64,
    ) -> Result<(), PlacementError> {
        let pml4_frame = root.address();
        let pml4_idx = Self::descriptor_index(va, 0);
        let pdpt_idx = Self::descriptor_index(va, 1);
        let pd_idx = Self::descriptor_index(va, 2);
        let pt_idx = Self::descriptor_index(va, 3);

        self.store_descriptor_word(
            pml4_frame,
            pml4_idx,
            (pdpt_frame.raw() & ADDRESS) | pml4_flags,
        )?;
        self.store_descriptor_word(
            pdpt_frame,
            pdpt_idx,
            (pd_frame.raw() & ADDRESS) | pdpt_flags,
        )?;
        self.store_descriptor_word(pd_frame, pd_idx, (pt_frame.raw() & ADDRESS) | pd_flags)?;
        self.store_descriptor_word(pt_frame, pt_idx, leaf_entry)?;
        Ok(())
    }

    /// Build a raw x86-64 4 KiB leaf PTE from a target GPA and hardware/COW permission flags.
    #[inline]
    pub const fn encode_leaf_pte(
        target_gpa: u64,
        writable: bool,
        user: bool,
        executable: bool,
        cow: bool,
    ) -> u64 {
        let mut entry = (target_gpa & ADDRESS) | PRESENT;
        if writable {
            entry |= WRITE | MAY_WRITE;
        }
        if user {
            entry |= USER;
        }
        if executable {
            entry |= MAY_EXEC;
        } else {
            entry |= NX;
        }
        if cow {
            entry |= COW | MAY_WRITE;
        }
        entry
    }

    fn word_index_for_pa(&self, pa: u64) -> Result<usize, DescriptorRefusal> {
        if (pa & 0b111) != 0 {
            return Err(DescriptorRefusal::BadRange);
        }
        let table = Stage1Gpa::new(pa & PAGE_BASE_MASK_4K);
        let table_frame = self
            .extents
            .authenticate_table_frame(table)
            .ok_or(DescriptorRefusal::MissingTable)?;
        let _host_va = self
            .placement
            .host(table_frame)
            .map_err(|_| DescriptorRefusal::BadRange)?;
        let word_idx = usize::try_from(pa / (core::mem::size_of::<AtomicU64>() as u64))
            .map_err(|_| DescriptorRefusal::BadRange)?;
        if word_idx >= self.word_len {
            return Err(DescriptorRefusal::BadRange);
        }
        Ok(self.aligned_word_offset + word_idx)
    }
}

impl LiveDescriptorWords for VecGuestMemory {
    #[inline]
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        let idx = self.word_index_for_pa(pa)?;
        Ok(self.backing[idx].load(Ordering::Acquire))
    }

    #[inline]
    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        let idx = self.word_index_for_pa(pa)?;
        Ok(self.backing[idx]
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }

    #[inline]
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        let idx = self.word_index_for_pa(pa)?;
        self.backing[idx].store(value, Ordering::Release);
        Ok(())
    }

    #[inline]
    fn publish_barrier(&self) {
        fence(Ordering::SeqCst);
    }

    #[inline]
    fn invalidate_range(&self, _va: u64, _len: u64) {}
}

impl SoftMmuMemory for VecGuestMemory {
    #[inline]
    fn placement(&self) -> &LinearPlacement {
        &self.placement
    }

    #[inline]
    fn authenticate_leaf(
        &self,
        root: RootGpa,
        stage1_gpa: Stage1Gpa,
        leaf: &TranslatedLeaf,
    ) -> Result<FrameGpa, OwnerGeneration> {
        let expected = self.expected_generation(root);
        let check_len = leaf.size.max(PAGE);
        self.extents
            .authenticate(stage1_gpa, check_len, expected)
            .ok_or(expected)
    }

    #[inline]
    fn is_code_page(&self, frame_gpa: FrameGpa) -> bool {
        let key = frame_gpa.raw() & PAGE_BASE_MASK_4K;
        self.code_pages
            .get(&key)
            .map(|&(active, _)| active)
            .unwrap_or(false)
    }

    #[inline]
    fn code_generation(&self, frame_gpa: FrameGpa) -> u64 {
        let key = frame_gpa.raw() & PAGE_BASE_MASK_4K;
        self.code_pages
            .get(&key)
            .map(|&(_, generation)| generation)
            .unwrap_or(0)
    }

    #[inline]
    fn on_code_page_write(&mut self, frame_gpa: FrameGpa) -> u64 {
        let key = frame_gpa.raw() & PAGE_BASE_MASK_4K;
        let entry = self.code_pages.entry(key).or_insert((true, 0));
        entry.0 = true;
        entry.1 = entry.1.saturating_add(1);
        entry.1
    }
}
