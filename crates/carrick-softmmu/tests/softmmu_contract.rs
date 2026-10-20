//! VM-free contract tests for `carrick-softmmu` (`softmmu.x86.tlb-walker`, #580).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
    SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
};
use carrick_mmu_core::x86::descriptor_txn::{
    ACCESSED, Access, COW, DIRTY, DescriptorRefusal, FaultClass, HUGE, LiveDescriptorWords,
    MAX_AD_CAS_RETRIES, NX, PRESENT, USER, WRITE, translate_leaf,
};
use carrick_softmmu::{
    AccessOutcome, AuthenticatedDescriptorWords, Cpl, CpuAccessMode, ExtentEditError, ExtentRecord,
    ExtentTable, FrameGpa, GuestVa, LAPIC_MMIO_BASE_GPA, LAPIC_MMIO_SIZE_BYTES, LinearPlacement,
    MmioHole, MmioHoles, OwnerGeneration, PAGE_OFFSET_MASK_4K, PAGE_SIZE_4K, PageFaultClass,
    PageFaultErrorCode, PageFaultInfo, PlacementError, ResolvedAccess, ResolvedSpan, Retirement,
    RootGpa, SOFT_TLB_ENTRIES, SoftCpuException, SoftMmuMemory, SoftTlb, SoftTlbEntry,
    SoftTlbPlane, SoftTranslationError, SoftWalker, TLB_TAG_AC_BIT, TLB_TAG_CPL3_BIT,
    TLB_TAG_NXE_OFF_BIT, TLB_TAG_SMAP_OFF_BIT, TLB_TAG_SMEP_OFF_BIT, TLB_TAG_WP_OFF_BIT,
    WalkOutcome, X86HostPage4K,
};

const TEST_SPAN_BYTES: u64 = 0x0100_0000;
const PML4_A_GPA: u64 = 0x0000_1000;
const PDPT_A_GPA: u64 = 0x0000_2000;
const PD_A_GPA: u64 = 0x0000_3000;
const PT_A_GPA: u64 = 0x0000_4000;
const PML4_B_GPA: u64 = 0x0000_5000;
const PDPT_B_GPA: u64 = 0x0000_6000;
const PD_B_GPA: u64 = 0x0000_7000;
const PT_B_GPA: u64 = 0x0000_8000;
const F1_GPA: u64 = 0x0001_0000;
const F2_GPA: u64 = 0x0001_1000;
const F3_GPA: u64 = 0x0001_2000;
const F4_GPA: u64 = 0x0001_3000;
const CUSTOM_MMIO_GPA: u64 = 0x0020_0000;
const HUGE_2M_BASE_GPA: u64 = 0x0040_0000;
const HUGE_2M_SIZE: u64 = 1 << 21;

const fn idx(va: GuestVa, level: usize) -> usize {
    let shift = [39, 30, 21, 12][level];
    ((va.raw() >> shift) & 0x1ff) as usize
}

const fn pte(gpa: u64, w: bool, u: bool, x: bool, cow: bool) -> u64 {
    let mut desc = (gpa & 0x000f_ffff_ffff_f000) | PRESENT;
    if w {
        desc |= WRITE;
    }
    if u {
        desc |= USER;
    }
    if !x {
        desc |= NX;
    }
    if cow {
        desc |= COW;
    }
    desc
}

fn generation(raw: u64) -> OwnerGeneration {
    OwnerGeneration::from_raw(raw).expect("nonzero owner generation")
}

/// Complete a retirement no running CPU owes and release its identities.
fn retire_now<T>(
    mem: &mut VecGuestMemory,
    edit: Result<Option<Retirement<T>>, ExtentEditError>,
) -> Option<T> {
    let Retirement { retired, pending } = edit.expect("retirement published")?;
    let completion = pending.try_complete().expect("every counted CPU is parked");
    mem.extents_mut().reclaim(&completion);
    Some(retired)
}

fn root_gpa(raw: u64) -> RootGpa {
    RootGpa::page_aligned(FrameGpa::new(raw)).expect("4 KiB-aligned root GPA")
}

struct VecGuestMemory {
    backing: Arc<Vec<AtomicU64>>,
    aligned_word_offset: usize,
    placement: LinearPlacement,
    extents: ExtentTable,
    descriptor_loads: Arc<AtomicU64>,
}

/// Copies share the backing; each gets an independent record copy in its
/// own invalidation domain (`ExtentTable` has no `Clone`).
impl Clone for VecGuestMemory {
    fn clone(&self) -> Self {
        Self {
            backing: Arc::clone(&self.backing),
            aligned_word_offset: self.aligned_word_offset,
            placement: self.placement,
            extents: self.extents.try_clone().expect("no retirement pending"),
            descriptor_loads: Arc::clone(&self.descriptor_loads),
        }
    }
}

impl VecGuestMemory {
    fn with_holes(span_bytes: u64, holes: MmioHoles) -> Result<Self, PlacementError> {
        Self::with_placement_span(span_bytes, span_bytes, holes)
    }

    fn with_placement_span(
        backing_bytes: u64,
        placement_span_bytes: u64,
        holes: MmioHoles,
    ) -> Result<Self, PlacementError> {
        let word_len = usize::try_from(backing_bytes.max(placement_span_bytes)).unwrap() / 8;
        let total_words = word_len + (PAGE_SIZE_4K as usize) / 8;
        let mut backing = Vec::with_capacity(total_words);
        backing.resize_with(total_words, || AtomicU64::new(0));
        let raw_base = backing.as_ptr() as usize;
        let mask = PAGE_OFFSET_MASK_4K as usize;
        let aligned_base = (raw_base + mask) & !mask;
        let aligned_word_offset = (aligned_base - raw_base) / 8;
        // SAFETY: the initialized AtomicU64 allocation covers the entire placement
        // plus alignment padding. Its Arc keeps the stable allocation alive across
        // clones and all walker/TLB uses; shared descriptor accesses are atomic.
        let placement = unsafe { LinearPlacement::new(aligned_base, placement_span_bytes, holes)? };
        Ok(Self {
            backing: Arc::new(backing),
            aligned_word_offset,
            placement,
            extents: ExtentTable::new().expect("fresh invalidation domain"),
            descriptor_loads: Arc::new(AtomicU64::new(0)),
        })
    }

    fn install_extent(&mut self, base: FrameGpa, len_bytes: u64, gen_id: OwnerGeneration) -> bool {
        if self.placement.holes().overlaps_range(base.raw(), len_bytes) {
            return false;
        }
        let Some(end) = base.raw().checked_add(len_bytes) else {
            return false;
        };
        if end > self.placement.span_bytes() {
            return false;
        }
        self.extents
            .install(ExtentRecord::new(base, len_bytes, gen_id))
    }

    fn host_of(&self, raw_gpa: u64) -> usize {
        self.placement.base_host_addr() + usize::try_from(raw_gpa).unwrap()
    }
    fn loads(&self) -> u64 {
        self.descriptor_loads.load(Ordering::Relaxed)
    }
    fn reset_loads(&self) {
        self.descriptor_loads.store(0, Ordering::Relaxed);
    }
    fn set(&self, table_gpa: u64, i: usize, word: u64) {
        let word_idx = usize::try_from(table_gpa / 8).unwrap() + i;
        self.backing[self.aligned_word_offset + word_idx].store(word, Ordering::Release);
    }
    fn get(&self, table_gpa: u64, i: usize) -> u64 {
        let word_idx = usize::try_from(table_gpa / 8).unwrap() + i;
        self.backing[self.aligned_word_offset + word_idx].load(Ordering::Acquire)
    }
    fn map_4k_a(&self, root: RootGpa, va: GuestVa, leaf: u64) {
        let f = PRESENT | WRITE | USER;
        self.map_4k_flags_a(root, va, f, f, f, leaf);
    }
    fn map_4k_flags_a(&self, root: RootGpa, va: GuestVa, f0: u64, f1: u64, f2: u64, leaf: u64) {
        self.map_4k_chain(root, va, PDPT_A_GPA, PD_A_GPA, PT_A_GPA, f0, f1, f2, leaf);
    }
    #[allow(clippy::too_many_arguments)]
    fn map_4k_chain(
        &self,
        root: RootGpa,
        va: GuestVa,
        pdpt: u64,
        pd: u64,
        pt: u64,
        f0: u64,
        f1: u64,
        f2: u64,
        leaf: u64,
    ) {
        let m = 0x000f_ffff_ffff_f000u64;
        self.set(root.address().raw(), idx(va, 0), (pdpt & m) | (f0 & !m));
        self.set(pdpt, idx(va, 1), (pd & m) | (f1 & !m));
        self.set(pd, idx(va, 2), (pt & m) | (f2 & !m));
        self.set(pt, idx(va, 3), leaf);
    }
}

// SAFETY: Owns the full aligned, initialized backing via Arc; it never resizes
// or relocates, and clones share only AtomicU64 descriptor accesses.
unsafe impl SoftMmuMemory for VecGuestMemory {
    fn placement(&self) -> &LinearPlacement {
        &self.placement
    }
    fn extents(&self) -> &ExtentTable {
        &self.extents
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        &mut self.extents
    }
    fn on_descriptor_load(&self) {
        self.descriptor_loads.fetch_add(1, Ordering::Relaxed);
    }
}

struct Rig {
    mem: VecGuestMemory,
    tlb: SoftTlb,
    walker: SoftWalker,
    root: RootGpa,
}

impl Rig {
    fn new() -> Result<Self, PlacementError> {
        Ok(Self::from_mem(setup_memory()?, root_gpa(PML4_A_GPA)))
    }
    fn from_mem(mem: VecGuestMemory, root: RootGpa) -> Self {
        Self {
            mem,
            tlb: SoftTlb::new(),
            walker: SoftWalker::new(),
            root,
        }
    }
    fn map_a(&self, va: GuestVa, leaf: u64) {
        self.mem.map_4k_a(self.root, va, leaf);
    }
    fn map_flags(&self, va: GuestVa, f0: u64, f1: u64, f2: u64, leaf: u64) {
        self.mem.map_4k_flags_a(self.root, va, f0, f1, f2, leaf);
    }
    fn walk(
        &mut self,
        va: GuestVa,
        acc: Access,
        mode: CpuAccessMode,
    ) -> Result<WalkOutcome, SoftTranslationError> {
        self.walker
            .walk_and_fill(&mut self.mem, &mut self.tlb, self.root, va, acc, mode)
    }
    fn walk_mem<M: SoftMmuMemory>(
        &mut self,
        mem: &mut M,
        va: GuestVa,
        acc: Access,
        mode: CpuAccessMode,
    ) -> Result<WalkOutcome, SoftTranslationError> {
        self.walker
            .walk_and_fill(mem, &mut self.tlb, self.root, va, acc, mode)
    }
    fn probe_tlb(&mut self, tlb: &mut SoftTlb, va: GuestVa, acc: Access, mode: CpuAccessMode) {
        let _ = self
            .walker
            .probe_or_walk_outcome(&mut self.mem, tlb, self.root, va, 8, acc, mode)
            .unwrap();
    }
    fn walk_ram(&mut self, va: GuestVa, acc: Access, mode: CpuAccessMode) -> ResolvedAccess {
        match self.walk(va, acc, mode).unwrap() {
            WalkOutcome::Ram(r) => r,
            WalkOutcome::Mmio { gpa, .. } => panic!("unexpected Mmio at {gpa:#x}"),
        }
    }
    fn walk_pf(&mut self, va: GuestVa, acc: Access, mode: CpuAccessMode) -> PageFaultInfo {
        *self
            .walk(va, acc, mode)
            .unwrap_err()
            .as_page_fault()
            .unwrap()
    }
    fn probe(
        &mut self,
        va: GuestVa,
        acc: Access,
        mode: CpuAccessMode,
    ) -> Result<AccessOutcome, SoftTranslationError> {
        self.walker
            .probe_or_walk_outcome(&mut self.mem, &mut self.tlb, self.root, va, 8, acc, mode)
    }
    fn probe_ram(&mut self, va: GuestVa, acc: Access, mode: CpuAccessMode) -> usize {
        match self.probe(va, acc, mode).unwrap() {
            AccessOutcome::Ram(addr) => addr,
            AccessOutcome::Mmio { gpa, .. } => panic!("unexpected Mmio at {gpa:#x}"),
        }
    }
    fn probe_pf(&mut self, va: GuestVa, acc: Access, mode: CpuAccessMode) -> PageFaultInfo {
        *self
            .probe(va, acc, mode)
            .unwrap_err()
            .as_page_fault()
            .unwrap()
    }
    fn span(
        &mut self,
        va: GuestVa,
        len: usize,
        acc: Access,
        mode: CpuAccessMode,
    ) -> Result<ResolvedSpan, SoftTranslationError> {
        self.walker
            .resolve_span(&mut self.mem, &mut self.tlb, self.root, va, len, acc, mode)
    }
}

fn setup_memory() -> Result<VecGuestMemory, PlacementError> {
    let holes = MmioHoles::x86_default().with_hole(CUSTOM_MMIO_GPA, PAGE_SIZE_4K)?;
    let mut mem = VecGuestMemory::with_holes(TEST_SPAN_BYTES, holes)?;
    let gen1 = generation(1);
    for gpa in [
        PML4_A_GPA, PDPT_A_GPA, PD_A_GPA, PT_A_GPA, PML4_B_GPA, PDPT_B_GPA, PD_B_GPA, PT_B_GPA,
        F1_GPA, F2_GPA, F3_GPA, F4_GPA,
    ] {
        assert!(mem.install_extent(FrameGpa::new(gpa), PAGE_SIZE_4K, gen1));
    }
    assert!(mem.install_extent(FrameGpa::new(HUGE_2M_BASE_GPA), HUGE_2M_SIZE, gen1));
    mem.extents_mut()
        .set_root_generation(root_gpa(PML4_A_GPA), gen1);
    mem.extents_mut()
        .set_root_generation(root_gpa(PML4_B_GPA), gen1);
    Ok(mem)
}

#[test]
fn linear_placement_enforces_alignment_bounds_and_mmio_holes() -> Result<(), PlacementError> {
    assert_eq!(SoftTlbEntry::SIZE, 16);
    assert_eq!(
        (SoftTlbEntry::TAG_OFFSET, SoftTlbEntry::ADDEND_OFFSET),
        (0, 8)
    );
    assert_eq!(
        (SoftTlbPlane::BYTE_SIZE, SOFT_TLB_ENTRIES),
        (16 * 1024, 1024)
    );
    assert_eq!(
        (
            SoftTlb::READ_PLANE_OFFSET,
            SoftTlb::WRITE_PLANE_OFFSET,
            SoftTlb::EXEC_PLANE_OFFSET
        ),
        (0, 16 * 1024, 32 * 1024)
    );
    assert_eq!(
        (Cpl::from_cs_selector(0x08), Cpl::from_cs_selector(0x2b)),
        (Ok(Cpl::Ring0), Ok(Cpl::Ring3))
    );
    assert_eq!(
        (Cpl::from_cs_selector(0x01), Cpl::from_cs_selector(0x02)),
        (Err(1), Err(2))
    );

    let backing = VecGuestMemory::with_holes(TEST_SPAN_BYTES, MmioHoles::empty())?;
    let base_k = backing.placement().base_host_addr();
    let span = TEST_SPAN_BYTES;
    let err_unaligned = PlacementError::UnalignedPlacement {
        base_host_addr: base_k + 1,
        span_bytes: span,
    };
    assert_eq!(
        // SAFETY: unaligned input is rejected before a placement is constructed.
        unsafe { LinearPlacement::with_x86_defaults(base_k + 1, span) },
        Err(err_unaligned)
    );
    let err_zero = PlacementError::UnalignedPlacement {
        base_host_addr: base_k,
        span_bytes: 0,
    };
    // SAFETY: a zero span is rejected before a placement is constructed.
    assert_eq!(
        unsafe { LinearPlacement::with_x86_defaults(base_k, 0) },
        Err(err_zero)
    );
    let err_hole = PlacementError::UnalignedHole {
        base_gpa: 0x1001,
        size_bytes: PAGE_SIZE_4K,
    };
    assert_eq!(MmioHole::new(0x1001, PAGE_SIZE_4K), Err(err_hole));

    // SAFETY: backing owns this aligned, initialized full span for all uses of
    // placement below; these checks only calculate addresses and do not write.
    let placement = unsafe { LinearPlacement::with_x86_defaults(base_k, span)? };
    assert_eq!(
        (placement.base_host_addr(), placement.span_bytes()),
        (base_k, span)
    );
    assert!(placement.is_mmio_hole(LAPIC_MMIO_BASE_GPA + 0x3f0));
    assert!(!placement.is_mmio_hole(LAPIC_MMIO_BASE_GPA + LAPIC_MMIO_SIZE_BYTES));

    let mut rig = Rig::new()?;
    let gen1 = generation(1);
    let mode = CpuAccessMode::ring3();
    let before_mmio = CUSTOM_MMIO_GPA - PAGE_SIZE_4K;
    assert!(
        rig.mem
            .install_extent(FrameGpa::new(before_mmio), PAGE_SIZE_4K, gen1)
    );
    let oob_rec = ExtentRecord::new(FrameGpa::new(TEST_SPAN_BYTES), PAGE_SIZE_4K, gen1);
    assert!(rig.mem.extents_mut().install(oob_rec));

    let va_f1 = GuestVa::new(0x0000_0010_0000);
    let va_before = GuestVa::new(0x0000_0010_1000);
    let va_oob = GuestVa::new(0x0000_0010_2000);
    rig.map_a(va_f1, pte(F1_GPA, true, true, true, false));
    let p_before = pte(before_mmio, true, true, true, false);
    let p_oob = pte(TEST_SPAN_BYTES, true, true, true, false);
    rig.mem.set(PT_A_GPA, idx(va_before, 3), p_before);
    rig.mem.set(PT_A_GPA, idx(va_oob, 3), p_oob);

    let auth_f1 = rig.walk_ram(va_f1, Access::Read, mode).frame_gpa;
    let host_va = placement.host(auth_f1)?;
    assert_eq!(
        (host_va.raw(), host_va.page_base()),
        (base_k + (F1_GPA as usize), base_k + (F1_GPA as usize))
    );

    let auth_before = rig.walk_ram(va_before, Access::Read, mode).frame_gpa;
    let two_pages = 2 * (PAGE_SIZE_4K as usize);
    assert_eq!(
        rig.mem.placement().host_range(auth_before, two_pages),
        Err(PlacementError::MmioHole { gpa: before_mmio })
    );
    let one_page = PAGE_SIZE_4K as usize;
    assert_eq!(
        rig.mem.placement().host_range(auth_before, one_page)?.raw(),
        rig.mem.host_of(before_mmio)
    );

    let oob_err = PlacementError::OutOfBounds {
        gpa: TEST_SPAN_BYTES,
        span_bytes: TEST_SPAN_BYTES,
    };
    let SoftTranslationError::Placement {
        va,
        frame_gpa: auth_oob,
        error,
    } = rig.walk(va_oob, Access::Read, mode).unwrap_err()
    else {
        panic!("expected Placement(OutOfBounds)");
    };
    assert_eq!((va, error), (va_oob, oob_err));
    assert_eq!(rig.mem.placement().host(auth_oob), Err(oob_err));
    Ok(())
}

/// Review item 1: Huge-page (`2 MiB` and `1 GiB`) authentication at offsets `0`, `0x1000`, and `size - 8`.
#[test]
fn huge_page_authentication_2m_and_1g_at_zero_page_and_tail_offsets() -> Result<(), PlacementError>
{
    let mut rig = Rig::new()?;
    let gen1 = generation(1);
    let mode = CpuAccessMode::ring3();
    let f = PRESENT | WRITE | USER;

    let va_2m = GuestVa::new(0x0000_0020_0000);
    rig.mem.set(PML4_A_GPA, idx(va_2m, 0), PDPT_A_GPA | f);
    rig.mem.set(PDPT_A_GPA, idx(va_2m, 1), PD_A_GPA | f);
    rig.mem
        .set(PD_A_GPA, idx(va_2m, 2), HUGE_2M_BASE_GPA | f | HUGE);

    let host_2m_base = rig.mem.host_of(HUGE_2M_BASE_GPA);
    for offset in [0u64, 0x1000, HUGE_2M_SIZE - 8] {
        let r = rig.walk_ram(GuestVa::new(va_2m.raw() + offset), Access::Read, mode);
        assert_eq!(r.leaf.size, HUGE_2M_SIZE);
        assert_eq!(r.frame_gpa.raw(), (HUGE_2M_BASE_GPA + offset) & !0xfff);
        assert_eq!(r.host_addr, host_2m_base + (offset as usize));
    }

    let removed = rig
        .mem
        .extents_mut()
        .remove(FrameGpa::new(HUGE_2M_BASE_GPA), None);
    assert!(retire_now(&mut rig.mem, removed).is_some());
    let short_2m = HUGE_2M_SIZE - PAGE_SIZE_4K;
    assert!(
        rig.mem
            .install_extent(FrameGpa::new(HUGE_2M_BASE_GPA), short_2m, gen1)
    );
    assert!(matches!(
        rig.walk(va_2m, Access::Read, mode),
        Err(SoftTranslationError::UnauthenticatedExtent { stage1_gpa, .. }) if stage1_gpa.raw() == HUGE_2M_BASE_GPA
    ));

    let leaf_1g_size = 1u64 << 30;
    let leaf_1g_gpa = 0x4000_0000u64;
    let va_1g = GuestVa::new(0x0000_4000_0000);
    let mut mem_1g = VecGuestMemory::with_placement_span(
        256 * PAGE_SIZE_4K,
        2 * leaf_1g_size,
        MmioHoles::x86_default(),
    )?;
    assert!(mem_1g.install_extent(FrameGpa::new(PML4_A_GPA), 4 * PAGE_SIZE_4K, gen1));
    assert!(mem_1g.install_extent(FrameGpa::new(leaf_1g_gpa), leaf_1g_size, gen1));
    mem_1g.extents_mut().set_root_generation(rig.root, gen1);
    mem_1g.set(PML4_A_GPA, idx(va_1g, 0), PDPT_A_GPA | f);
    mem_1g.set(PDPT_A_GPA, idx(va_1g, 1), leaf_1g_gpa | f | HUGE);

    let host_1g_base = mem_1g.placement().base_host_addr() + (leaf_1g_gpa as usize);
    let mut rig_1g = Rig::from_mem(mem_1g, rig.root);
    for offset in [0u64, 0x1000, leaf_1g_size - 8] {
        let r = rig_1g.walk_ram(GuestVa::new(va_1g.raw() + offset), Access::Read, mode);
        assert_eq!(r.leaf.size, leaf_1g_size);
        assert_eq!(r.frame_gpa.raw(), (leaf_1g_gpa + offset) & !0xfff);
        assert_eq!(r.host_addr, host_1g_base + (offset as usize));
    }
    Ok(())
}

/// Review item 2: `invlpg` (`evict_va`) on a large page evicts all sibling slots filled from that leaf.
#[test]
fn invlpg_on_large_page_evicts_all_sibling_slots() -> Result<(), PlacementError> {
    let mut rig = Rig::new()?;
    let mode = CpuAccessMode::ring3();

    let va_base = GuestVa::new(0x0000_0020_0000);
    let va_sib1 = GuestVa::new(0x0000_0020_5008);
    let va_sib2 = GuestVa::new(0x0000_003f_fff8);
    let va_4k = GuestVa::new(0x0000_0040_2000);

    rig.map_a(va_4k, pte(F1_GPA, true, true, true, false));
    let pd_idx_2m = idx(va_base, 2);
    let pde_2m = HUGE_2M_BASE_GPA | PRESENT | WRITE | USER | HUGE;
    rig.mem.set(PD_A_GPA, pd_idx_2m, pde_2m);

    for va in [va_base, va_sib1, va_sib2, va_4k] {
        let _ = rig.probe_ram(va, Access::Write, mode);
        assert!(rig.tlb.probe_readonly(va, 8, Access::Read, mode).is_some());
        assert!(rig.tlb.probe_readonly(va, 8, Access::Write, mode).is_some());
    }

    rig.mem.set(PD_A_GPA, pd_idx_2m, 0);
    rig.tlb.evict_va(va_base);

    assert_eq!(rig.tlb.probe(va_sib1, 8, Access::Read, mode), None);
    assert_eq!(rig.tlb.probe(va_sib1, 8, Access::Write, mode), None);
    assert_eq!(rig.tlb.probe(va_sib2, 8, Access::Read, mode), None);
    assert!(
        rig.tlb
            .probe_readonly(va_4k, 8, Access::Read, mode)
            .is_some()
    );
    assert_eq!(
        rig.probe_pf(va_sib1, Access::Read, mode).class,
        PageFaultClass::NotPresent
    );
    Ok(())
}

/// Review items 3 & 4: Single-walk hardware mode in `carrick-mmu-core` and ignored non-leaf bits `8..=11`.
#[test]
fn red_first_non_present_precedence_ignored_nonleaf_bits_and_reserved_bits()
-> Result<(), PlacementError> {
    let mut rig = Rig::new()?;
    rig.walker.set_max_phy_addr(36);
    let va = GuestVa::new(0x0000_0040_0000);
    let mode = CpuAccessMode::ring3();
    let d_va = va.to_descriptor_va();

    rig.map_a(va, (1u64 << 55) | (1u64 << 45) | WRITE | USER);
    let words = AuthenticatedDescriptorWords::new(&rig.mem, rig.root);
    assert_eq!(
        translate_leaf(&words, rig.root, d_va, Access::Read, true),
        Err(FaultClass::Reserved)
    );
    let pf = rig.walk_pf(va, Access::Read, mode);
    assert_eq!(
        (pf.class, pf.error_code.bits()),
        (PageFaultClass::NotPresent, PageFaultErrorCode::USER)
    );

    let f = PRESENT | WRITE | USER;
    let valid_leaf = pte(F1_GPA, true, true, true, false) | (1u64 << 55);
    rig.map_flags(va, f | (1 << 9), f | (1 << 10), f | (1 << 11), valid_leaf);
    let words = AuthenticatedDescriptorWords::new(&rig.mem, rig.root);
    assert_eq!(
        translate_leaf(&words, rig.root, d_va, Access::Read, true),
        Err(FaultClass::Reserved)
    );
    assert_eq!(rig.walk_ram(va, Access::Read, mode).frame_gpa.raw(), F1_GPA);

    rig.tlb.flush_all();
    rig.map_a(va, pte(F1_GPA, true, true, true, false) | (1u64 << 36));
    let rsvd_pf = rig.walk_pf(va, Access::Read, mode);
    assert_eq!(rsvd_pf.class, PageFaultClass::ReservedBit);
    let rsvd_bits =
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::RESERVED_WRITE | PageFaultErrorCode::USER;
    assert_eq!(rsvd_pf.error_code.bits(), rsvd_bits);
    rig.walker.set_max_phy_addr(48);
    assert!(matches!(
        rig.walk(va, Access::Read, mode),
        Err(SoftTranslationError::UnauthenticatedExtent { .. })
    ));

    rig.tlb.flush_all();
    rig.map_flags(va, f | HUGE, f, f, pte(F1_GPA, true, true, true, false));
    assert_eq!(
        rig.walk_pf(va, Access::Read, mode).class,
        PageFaultClass::ReservedBit
    );
    Ok(())
}

/// Review item 5 & Round 3 item 1: Control-register gating (`CR4.SMEP`, `CR4.SMAP`, `CR0.WP`, `EFER.NXE`), `I/D` bit, and SMAP TLB isolation across `Execute` vs `Read`.
#[test]
fn cr_gating_smep_smap_wp_and_id_error_code_bit() -> Result<(), PlacementError> {
    let mut rig = Rig::new()?;
    let va_ro = GuestVa::new(0x0000_0050_0000);
    rig.map_a(va_ro, pte(F1_GPA, false, true, true, false));
    let host_f1 = rig.mem.host_of(F1_GPA);

    let r0 = CpuAccessMode::ring0(false);
    let r0_ac = CpuAccessMode::ring0(true);
    let r3 = CpuAccessMode::ring3();
    for (m, expected) in [
        (r3, TLB_TAG_CPL3_BIT),
        (r0, 0),
        (r0_ac, TLB_TAG_AC_BIT),
        (r0.with_cr0_wp(false), TLB_TAG_WP_OFF_BIT),
        (r0.with_cr4_smep(false), TLB_TAG_SMEP_OFF_BIT),
        (r0.with_cr4_smap(false), TLB_TAG_SMAP_OFF_BIT),
        (
            r3.with_efer_nxe(false),
            TLB_TAG_CPL3_BIT | TLB_TAG_NXE_OFF_BIT,
        ),
    ] {
        assert_eq!(SoftTlb::mode_tag_bits(m), expected);
    }

    assert_eq!(
        rig.probe_pf(va_ro, Access::Read, r0).class,
        PageFaultClass::SmapProtection
    );
    assert_eq!(
        rig.probe_ram(va_ro, Access::Read, r0.with_cr4_smap(false)),
        host_f1
    );
    assert_eq!(rig.tlb.probe(va_ro, 4, Access::Read, r0), None);
    assert_eq!(rig.probe_ram(va_ro, Access::Read, r0_ac), host_f1);

    let smep_pf = rig.probe_pf(va_ro, Access::Execute, r0_ac);
    assert_eq!(smep_pf.class, PageFaultClass::SmepProtection);
    assert_eq!(
        smep_pf.error_code.bits(),
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::INSTRUCTION_FETCH
    );
    let r0_smep0 = r0.with_cr4_smep(false);
    assert_eq!(rig.probe_ram(va_ro, Access::Execute, r0_smep0), host_f1);
    assert_eq!(rig.tlb.probe(va_ro, 4, Access::Read, r0_smep0), None);
    assert_eq!(
        rig.probe_pf(va_ro, Access::Read, r0_smep0).class,
        PageFaultClass::SmapProtection
    );
    assert_eq!(rig.tlb.probe(va_ro, 4, Access::Execute, r0_ac), None);

    assert_eq!(
        rig.probe_pf(va_ro, Access::Write, r0_ac).class,
        PageFaultClass::Protection
    );
    assert_eq!(
        rig.probe_ram(va_ro, Access::Write, r0_ac.with_cr0_wp(false)),
        host_f1
    );
    assert_eq!(rig.tlb.probe(va_ro, 4, Access::Write, r0_ac), None);

    let va_np = GuestVa::new(0x0000_0055_0000);
    let r3_no_nx_smep = r3.with_efer_nxe(false).with_cr4_smep(false);
    let pf_off = rig.walk_pf(va_np, Access::Execute, r3_no_nx_smep);
    assert!(!pf_off.error_code.instruction_fetch());
    assert_eq!(pf_off.error_code.bits(), PageFaultErrorCode::USER);
    assert!(
        rig.walk_pf(va_np, Access::Execute, r3.with_cr4_smep(false))
            .error_code
            .instruction_fetch()
    );
    assert!(
        rig.walk_pf(va_np, Access::Execute, r3.with_efer_nxe(false))
            .error_code
            .instruction_fetch()
    );
    Ok(())
}

/// Review item 6: Non-canonical `#GP(0)` / `#SS(0)`, MMIO non-fault outcome, and consistent `DescriptorLoad`.
#[test]
fn fault_classes_non_canonical_gp_ss_mmio_non_fault_and_descriptor_load()
-> Result<(), PlacementError> {
    let mut rig = Rig::new()?;
    let mode = CpuAccessMode::ring3();

    let non_canon = GuestVa::new(0x0001_0000_0000_0000);
    let gp_res = rig.walk(non_canon, Access::Read, mode);
    let gp_exc = SoftCpuException::GeneralProtection0 {
        va: non_canon,
        access: Access::Read,
    };
    assert_eq!(gp_res, Err(SoftTranslationError::CpuException(gp_exc)));
    assert!(gp_res.as_ref().unwrap_err().as_page_fault().is_none());
    let ss_exc = SoftCpuException::StackSegment0 {
        va: non_canon,
        access: Access::Write,
    };
    assert_eq!(
        rig.walk(non_canon, Access::Write, mode.with_stack_access(true)),
        Err(SoftTranslationError::CpuException(ss_exc))
    );

    let mmio_va = GuestVa::new(0xffff_ffff_fee0_0020);
    let sup = PRESENT | WRITE;
    rig.map_flags(
        mmio_va,
        sup,
        sup,
        sup,
        pte(CUSTOM_MMIO_GPA, true, false, false, false),
    );
    let r0 = CpuAccessMode::ring0(false);
    assert!(matches!(
        rig.walk(mmio_va, Access::Read, r0),
        Ok(WalkOutcome::Mmio {
            gpa: 0x0020_0020,
            ..
        })
    ));
    assert!(matches!(
        rig.probe(mmio_va, Access::Read, r0),
        Ok(AccessOutcome::Mmio {
            gpa: 0x0020_0020,
            ..
        })
    ));
    assert!(matches!(
        rig.span(mmio_va, 4, Access::Read, r0),
        Ok(ResolvedSpan::Mmio { va, gpa: 0x0020_0020, len: 4, .. }) if va == mmio_va
    ));
    assert_eq!(
        rig.tlb.read().entry(SoftTlb::index_for(mmio_va)),
        SoftTlbEntry::INVALID
    );

    let bad_va = GuestVa::new(0x0000_00c0_0000);
    rig.map_a(bad_va, 0);
    rig.mem.set(
        PD_A_GPA,
        idx(bad_va, 2),
        0x0030_0000 | PRESENT | WRITE | USER,
    );
    let expected = Err(SoftTranslationError::DescriptorLoad {
        va: bad_va,
        refusal: DescriptorRefusal::MissingTable,
    });
    assert_eq!(rig.walk(bad_va, Access::Read, mode).map(|_| ()), expected);
    assert_eq!(rig.probe(bad_va, Access::Read, mode).map(|_| ()), expected);
    assert_eq!(
        rig.span(bad_va, 4, Access::Read, mode).map(|_| ()),
        expected
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum CasFaultKind {
    ClearPresentOnce,
    ToggleIgnoredBit { max_toggles: u64 },
    FlipOutputAddressAlways,
}

struct CasFaultMemory {
    inner: VecGuestMemory,
    target_pa: u64,
    kind: CasFaultKind,
    cas_attempts: AtomicU64,
}

// SAFETY: Delegates placement and extents to the owned VecGuestMemory; the
// fault hook modifies live descriptor words only through AtomicU64.
unsafe impl SoftMmuMemory for CasFaultMemory {
    fn placement(&self) -> &LinearPlacement {
        self.inner.placement()
    }
    fn extents(&self) -> &ExtentTable {
        self.inner.extents()
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        self.inner.extents_mut()
    }
    fn on_descriptor_load(&self) {
        self.inner.on_descriptor_load();
    }
    fn before_descriptor_cas(&self, pa: u64, slot: &AtomicU64, current: u64, _new: u64) {
        if pa != self.target_pa {
            return;
        }
        let attempt = self.cas_attempts.fetch_add(1, Ordering::Relaxed);
        match self.kind {
            CasFaultKind::ClearPresentOnce if attempt == 0 => {
                slot.store(0, Ordering::Release);
            }
            CasFaultKind::ToggleIgnoredBit { max_toggles } if attempt < max_toggles => {
                slot.store(current ^ (1u64 << 52), Ordering::Release);
            }
            CasFaultKind::FlipOutputAddressAlways => {
                slot.store(current ^ PAGE_SIZE_4K, Ordering::Release);
            }
            _ => {}
        }
    }
}

#[derive(Clone)]
struct ConcurrentImmaterialWriterMemory {
    inner: VecGuestMemory,
    target_pa: u64,
    cas_attempts: Arc<AtomicU64>,
    step_req: Arc<AtomicU64>,
    step_ack: Arc<AtomicU64>,
    lockstep_limit: u64,
}

// SAFETY: Retains the inner Arc-backed placement and extents; the peer writer
// uses AtomicU64 operations on the same live descriptor backing.
unsafe impl SoftMmuMemory for ConcurrentImmaterialWriterMemory {
    fn placement(&self) -> &LinearPlacement {
        self.inner.placement()
    }
    fn extents(&self) -> &ExtentTable {
        self.inner.extents()
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        self.inner.extents_mut()
    }
    fn before_descriptor_cas(&self, pa: u64, _slot: &AtomicU64, _current: u64, _new: u64) {
        if pa != self.target_pa {
            return;
        }
        let n = self.cas_attempts.fetch_add(1, Ordering::AcqRel) + 1;
        if n <= self.lockstep_limit {
            self.step_req.store(n, Ordering::Release);
            while self.step_ack.load(Ordering::Acquire) < n {
                std::hint::spin_loop();
            }
        }
    }
}

/// Review item 7, Round 3 item 3, Round 4 F4 & Round 5: Hardware `A`/`D` updates via CAS, same-word retry
/// under benign contention, walk restart on `P`-clear, and bounded termination under an adversarial
/// concurrent writer flipping only software-available bits `9..=11`.
#[test]
fn hardware_accessed_and_dirty_bits_updated_via_cas() -> Result<(), PlacementError> {
    let mut rig = Rig::new()?;
    let va = GuestVa::new(0x0000_0065_0000);
    let mode = CpuAccessMode::ring3();

    let fresh_leaf = pte(F1_GPA, true, true, true, false);
    assert_eq!(fresh_leaf & (ACCESSED | DIRTY), 0);
    rig.map_a(va, fresh_leaf);

    let read_res = rig.walk_ram(va, Access::Read, mode);
    assert_ne!(rig.mem.get(PML4_A_GPA, idx(va, 0)) & ACCESSED, 0);
    assert_ne!(rig.mem.get(PDPT_A_GPA, idx(va, 1)) & ACCESSED, 0);
    assert_ne!(rig.mem.get(PD_A_GPA, idx(va, 2)) & ACCESSED, 0);
    let pte_r = rig.mem.get(PT_A_GPA, idx(va, 3));
    assert_eq!(pte_r & (ACCESSED | DIRTY), ACCESSED);
    assert_eq!(read_res.leaf.descriptor & (ACCESSED | DIRTY), ACCESSED);
    assert_eq!(
        rig.tlb.write().entry(SoftTlb::index_for(va)),
        SoftTlbEntry::INVALID
    );

    let write_res = rig.walk_ram(va, Access::Write, mode);
    let pte_w = rig.mem.get(PT_A_GPA, idx(va, 3));
    assert_eq!(pte_w & (ACCESSED | DIRTY), ACCESSED | DIRTY);
    assert_eq!(
        write_res.leaf.descriptor & (ACCESSED | DIRTY),
        ACCESSED | DIRTY
    );
    assert!(rig.tlb.write().entry(SoftTlb::index_for(va)).is_valid());

    let va_race = GuestVa::new(0x0000_0065_1000);
    let pt_idx = idx(va_race, 3);
    let race_pte_pa = PT_A_GPA + (pt_idx as u64) * 8;
    rig.mem.set(PT_A_GPA, pt_idx, fresh_leaf);
    let toggles = 5u64;
    let mut peer_mem = CasFaultMemory {
        inner: rig.mem.clone(),
        target_pa: race_pte_pa,
        kind: CasFaultKind::ToggleIgnoredBit {
            max_toggles: toggles,
        },
        cas_attempts: AtomicU64::new(0),
    };
    peer_mem.inner.reset_loads();
    let WalkOutcome::Ram(peer_ram) = rig
        .walk_mem(&mut peer_mem, va_race, Access::Read, mode)
        .unwrap()
    else {
        panic!("expected Ram");
    };
    assert_eq!(peer_mem.cas_attempts.load(Ordering::Relaxed), toggles + 1);
    assert_eq!(peer_mem.inner.loads(), 4 + toggles);
    assert_eq!(rig.walker.stats().ad_cas_retries_exhausted, 0);
    assert_eq!(
        peer_ram.leaf.descriptor & (ACCESSED | (1u64 << 52)),
        ACCESSED | (1u64 << 52)
    );

    rig.mem.set(PT_A_GPA, pt_idx, fresh_leaf);
    let mut p_clear_mem = CasFaultMemory {
        inner: rig.mem.clone(),
        target_pa: race_pte_pa,
        kind: CasFaultKind::ClearPresentOnce,
        cas_attempts: AtomicU64::new(0),
    };
    let p_err = rig
        .walk_mem(&mut p_clear_mem, va_race, Access::Read, mode)
        .unwrap_err();
    assert_eq!(p_clear_mem.cas_attempts.load(Ordering::Relaxed), 1);
    assert_eq!(
        p_err.as_page_fault().unwrap().class,
        PageFaultClass::NotPresent
    );

    rig.mem.set(PT_A_GPA, pt_idx, fresh_leaf);
    let mut cap_mem = CasFaultMemory {
        inner: rig.mem.clone(),
        target_pa: race_pte_pa,
        kind: CasFaultKind::FlipOutputAddressAlways,
        cas_attempts: AtomicU64::new(0),
    };
    let cap_err = rig
        .walk_mem(&mut cap_mem, va_race, Access::Read, mode)
        .unwrap_err();
    let expected_cap = SoftTranslationError::AdCasRetryExhausted {
        va: va_race,
        retries: MAX_AD_CAS_RETRIES,
    };
    assert_eq!(cap_err, expected_cap);
    assert_eq!(rig.walker.stats().ad_cas_retries_exhausted, 1);
    assert_eq!(
        cap_mem.cas_attempts.load(Ordering::Relaxed),
        (MAX_AD_CAS_RETRIES as u64) + 1
    );

    rig.mem.set(PT_A_GPA, pt_idx, fresh_leaf);
    let lockstep_limit = (MAX_AD_CAS_RETRIES as u64) * 4;
    let mut writer_mem = ConcurrentImmaterialWriterMemory {
        inner: rig.mem.clone(),
        target_pa: race_pte_pa,
        cas_attempts: Arc::new(AtomicU64::new(0)),
        step_req: Arc::new(AtomicU64::new(0)),
        step_ack: Arc::new(AtomicU64::new(0)),
        lockstep_limit,
    };
    let stop_writer = AtomicBool::new(false);
    std::thread::scope(|s| {
        let w_mem = writer_mem.inner.clone();
        let req = Arc::clone(&writer_mem.step_req);
        let ack = Arc::clone(&writer_mem.step_ack);
        let stop = &stop_writer;
        let writer = s.spawn(move || {
            let mut handled = 0u64;
            while !stop.load(Ordering::Acquire) {
                let target = req.load(Ordering::Acquire);
                if target > handled {
                    let cur = w_mem.get(PT_A_GPA, pt_idx);
                    w_mem.set(PT_A_GPA, pt_idx, cur ^ (0b111u64 << 9));
                    handled = target;
                    ack.store(handled, Ordering::Release);
                } else {
                    std::hint::spin_loop();
                }
            }
        });
        let adv_res = rig.walk_mem(&mut writer_mem, va_race, Access::Read, mode);
        assert_eq!(adv_res, Err(expected_cap));
        assert_eq!(
            writer_mem.cas_attempts.load(Ordering::Acquire),
            (MAX_AD_CAS_RETRIES as u64) + 1
        );
        assert_eq!(rig.walker.stats().ad_cas_retries_exhausted, 2);

        writer_mem.lockstep_limit = 0;
        let free_mem = writer_mem.inner.clone();
        let free_stop = &stop_writer;
        let free_writer = s.spawn(move || {
            let mut mask = 1u64 << 9;
            while !free_stop.load(Ordering::Acquire) {
                let cur = free_mem.get(PT_A_GPA, pt_idx);
                free_mem.set(PT_A_GPA, pt_idx, (cur & !(0b111u64 << 9)) | mask);
                mask = if mask == (0b111u64 << 9) {
                    1u64 << 9
                } else {
                    mask + (1u64 << 9)
                };
            }
        });
        for _ in 0..16 {
            writer_mem.inner.set(PT_A_GPA, pt_idx, fresh_leaf);
            writer_mem.cas_attempts.store(0, Ordering::Release);
            let res = rig.walk_mem(&mut writer_mem, va_race, Access::Read, mode);
            assert!(matches!(res, Ok(WalkOutcome::Ram(_))) || res == Err(expected_cap));
            assert!(
                writer_mem.cas_attempts.load(Ordering::Acquire) <= (MAX_AD_CAS_RETRIES as u64) + 1
            );
        }
        stop_writer.store(true, Ordering::Release);
        assert!(writer.join().is_ok());
        assert!(free_writer.join().is_ok());
    });
    Ok(())
}

struct DisagreeingRawPaMemory {
    inner: VecGuestMemory,
    override_pa: u64,
    override_word: AtomicU64,
}

impl LiveDescriptorWords for DisagreeingRawPaMemory {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        if pa == self.override_pa {
            return Ok(self.override_word.load(Ordering::Acquire));
        }
        Ok(self.inner.get(pa & !0xfff, ((pa & 0xfff) / 8) as usize))
    }
    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        if pa == self.override_pa {
            return Ok(self
                .override_word
                .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok());
        }
        Ok(true)
    }
    fn store_unlinked(&self, _pa: u64, _value: u64) -> Result<(), DescriptorRefusal> {
        Ok(())
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _va: u64, _len: u64) {}
}

// SAFETY: Delegates placement and extents to the owned VecGuestMemory. The
// separate raw-PA adapter never changes the backing used by SoftMmuMemory.
unsafe impl SoftMmuMemory for DisagreeingRawPaMemory {
    fn placement(&self) -> &LinearPlacement {
        self.inner.placement()
    }
    fn extents(&self) -> &ExtentTable {
        self.inner.extents()
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        self.inner.extents_mut()
    }
}

/// Review items 8 & 9 + Round 3 items 2 & 4 + Round 4 F2/F3: Frame-keyed `mark_code_page`, unregistered-root refusal,
/// `LinearPlacement`-backed descriptor access vs raw-PA disagreement, and `remove` / `remove_root_generation` TLB shootdowns.
#[test]
fn frame_keyed_code_page_alias_invalidation_and_retired_table_frame_refusal()
-> Result<(), PlacementError> {
    let mut rig = Rig::new()?;
    let mut tlb_cpu1 = SoftTlb::new();
    let mode = CpuAccessMode::ring3();

    let va_rw = GuestVa::new(0x0000_0080_0000);
    let va_rx = GuestVa::new(0x0000_0080_5000);
    rig.map_a(va_rw, pte(F2_GPA, true, true, false, false));
    rig.mem.set(
        PT_A_GPA,
        idx(va_rx, 3),
        pte(F2_GPA, false, true, true, false),
    );

    assert!(
        !rig.mem
            .extents_mut()
            .set_root_generation(rig.root, generation(9))
    );
    let unreg_root = root_gpa(0x0000_9000);
    assert_eq!(rig.mem.extents().expected_generation(unreg_root), None);
    let missing_tbl = SoftTranslationError::DescriptorLoad {
        va: va_rw,
        refusal: DescriptorRefusal::MissingTable,
    };
    assert_eq!(
        rig.walker.walk_and_fill(
            &mut rig.mem,
            &mut rig.tlb,
            unreg_root,
            va_rw,
            Access::Read,
            mode
        ),
        Err(missing_tbl)
    );

    let rw_pte_pa = PT_A_GPA + (idx(va_rw, 3) as u64) * 8;
    let mut disagree = DisagreeingRawPaMemory {
        inner: rig.mem.clone(),
        override_pa: rw_pte_pa,
        override_word: AtomicU64::new(pte(F3_GPA, true, true, false, false)),
    };
    let d_va = va_rw.to_descriptor_va();
    assert_eq!(
        translate_leaf(&disagree, rig.root, d_va, Access::Read, true)
            .unwrap()
            .output
            .raw(),
        F3_GPA
    );
    let WalkOutcome::Ram(placed_walk) = rig
        .walk_mem(&mut disagree, va_rw, Access::Read, mode)
        .unwrap()
    else {
        panic!("expected Ram");
    };
    assert_eq!(placed_walk.frame_gpa.raw(), F2_GPA);
    assert_eq!(disagree.override_word.load(Ordering::Acquire) & ACCESSED, 0);

    let _ = rig.probe_ram(va_rw, Access::Write, mode);
    rig.probe_tlb(&mut tlb_cpu1, va_rw, Access::Write, mode);
    assert!(
        rig.tlb
            .probe_readonly(va_rw, 8, Access::Write, mode)
            .is_some()
    );
    assert!(
        tlb_cpu1
            .probe_readonly(va_rw, 8, Access::Write, mode)
            .is_some()
    );

    let rx_walk = rig.walk_ram(va_rx, Access::Execute, mode);
    assert_eq!(rx_walk.frame_gpa.raw(), F2_GPA);

    let gen1 = rig
        .mem
        .mark_code_page(rx_walk.frame_gpa, &mut [&mut rig.tlb, &mut tlb_cpu1]);
    assert_eq!(gen1, 1);
    assert_eq!(rig.tlb.probe(va_rw, 8, Access::Write, mode), None);
    assert_eq!(tlb_cpu1.probe(va_rw, 8, Access::Write, mode), None);

    let alias_w = rig.walk_ram(va_rw, Access::Write, mode);
    assert!(alias_w.invalidated_code_page);
    assert_eq!(
        (
            alias_w.code_generation,
            rig.mem.code_generation(rx_walk.frame_gpa)
        ),
        (2, 2)
    );
    assert_eq!(rig.tlb.probe(va_rw, 8, Access::Write, mode), None);
    assert!(
        rig.tlb
            .probe_readonly(va_rw, 8, Access::Read, mode)
            .is_some()
    );

    // Seat both TLBs as members of the inventory's domain, parked between steps.
    let mut vcpu0 = rig
        .mem
        .extents()
        .register_vcpu(std::mem::replace(&mut rig.tlb, SoftTlb::new()))
        .unwrap();
    let mut vcpu1 = rig.mem.extents().register_vcpu(tlb_cpu1).unwrap();
    for vcpu in [&mut vcpu0, &mut vcpu1] {
        vcpu.probe_or_walk_outcome(
            &mut rig.walker,
            &mut rig.mem,
            rig.root,
            va_rw,
            8,
            Access::Read,
            mode,
        )
        .unwrap();
    }
    let removed = rig.mem.extents_mut().remove(FrameGpa::new(F4_GPA), None);
    assert!(retire_now(&mut rig.mem, removed).is_some());
    // Each CPU serves the retirement at its next block entry.
    for vcpu in [&mut vcpu0, &mut vcpu1] {
        // One block: the run guard parks the CPU again when it drops.
        assert!(vcpu.run().block_entry().unwrap());
    }
    assert_eq!(vcpu0.probe(va_rw, 8, Access::Read, mode), None);
    assert_eq!(vcpu1.probe(va_rw, 8, Access::Read, mode), None);

    for vcpu in [&mut vcpu0, &mut vcpu1] {
        vcpu.probe_or_walk_outcome(
            &mut rig.walker,
            &mut rig.mem,
            rig.root,
            va_rw,
            8,
            Access::Read,
            mode,
        )
        .unwrap();
    }
    let retired_pt = ExtentRecord::new(FrameGpa::new(PT_A_GPA), PAGE_SIZE_4K, generation(2));
    assert!(!rig.mem.extents_mut().install(retired_pt));
    let replaced = rig.mem.extents_mut().replace(retired_pt, None);
    assert!(retire_now(&mut rig.mem, replaced).is_some());
    for vcpu in [&mut vcpu0, &mut vcpu1] {
        // One block: the run guard parks the CPU again when it drops.
        assert!(vcpu.run().block_entry().unwrap());
    }
    assert_eq!(vcpu0.probe(va_rw, 8, Access::Read, mode), None);
    assert_eq!(vcpu1.probe(va_rw, 8, Access::Read, mode), None);
    assert_ne!(rig.mem.get(PT_A_GPA, idx(va_rw, 3)), 0);
    assert_eq!(
        vcpu0.probe_or_walk_outcome(
            &mut rig.walker,
            &mut rig.mem,
            rig.root,
            va_rw,
            8,
            Access::Read,
            mode
        ),
        Err(missing_tbl)
    );

    let restored_pt = ExtentRecord::new(FrameGpa::new(PT_A_GPA), PAGE_SIZE_4K, generation(1));
    let restored = rig.mem.extents_mut().replace(restored_pt, None);
    assert!(retire_now(&mut rig.mem, restored).is_some());
    for vcpu in [&mut vcpu0, &mut vcpu1] {
        // One block: the run guard parks the CPU again when it drops.
        assert!(vcpu.run().block_entry().unwrap());
    }
    for vcpu in [&mut vcpu0, &mut vcpu1] {
        vcpu.probe_or_walk_outcome(
            &mut rig.walker,
            &mut rig.mem,
            rig.root,
            va_rw,
            8,
            Access::Read,
            mode,
        )
        .unwrap();
    }
    let root = rig.root;
    let removed_root = rig.mem.extents_mut().remove_root_generation(root, None);
    assert_eq!(retire_now(&mut rig.mem, removed_root), Some(generation(1)));
    for vcpu in [&mut vcpu0, &mut vcpu1] {
        // One block: the run guard parks the CPU again when it drops.
        assert!(vcpu.run().block_entry().unwrap());
    }
    assert_eq!(vcpu0.probe(va_rw, 8, Access::Read, mode), None);
    assert_eq!(vcpu1.probe(va_rw, 8, Access::Read, mode), None);
    assert_eq!(
        vcpu0.probe_or_walk_outcome(
            &mut rig.walker,
            &mut rig.mem,
            rig.root,
            va_rw,
            8,
            Access::Read,
            mode
        ),
        Err(missing_tbl)
    );
    Ok(())
}

#[test]
fn permission_classes_not_present_write_cow_nx_and_upper_half_va() -> Result<(), PlacementError> {
    let mut rig = Rig::new()?;
    let mode = CpuAccessMode::ring3();

    let va_rw = GuestVa::new(0x0000_0060_0000);
    rig.map_a(va_rw, pte(F1_GPA, true, true, false, false));
    let host_f1 = rig.mem.host_of(F1_GPA);
    assert_eq!(rig.probe_ram(va_rw, Access::Read, mode), host_f1);
    assert_eq!(
        rig.probe_ram(GuestVa::new(va_rw.raw() + 0x128), Access::Read, mode),
        host_f1 + 0x128
    );

    let nx_pf = rig.probe_pf(va_rw, Access::Execute, mode);
    assert_eq!(nx_pf.class, PageFaultClass::NxProtection);
    let nx_bits = PageFaultErrorCode::PRESENT
        | PageFaultErrorCode::USER
        | PageFaultErrorCode::INSTRUCTION_FETCH;
    assert_eq!(nx_pf.error_code.bits(), nx_bits);

    let va_cow = GuestVa::new(0x0000_0060_1000);
    rig.mem.set(
        PT_A_GPA,
        idx(va_cow, 3),
        pte(F2_GPA, false, true, false, true),
    );
    let cow_pf = rig.probe_pf(va_cow, Access::Write, mode);
    assert_eq!(cow_pf.class, PageFaultClass::CowWrite);
    let cow_bits =
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::WRITE | PageFaultErrorCode::USER;
    assert_eq!(cow_pf.error_code.bits(), cow_bits);

    let va_ro = GuestVa::new(0x0000_0060_2000);
    rig.mem.set(
        PT_A_GPA,
        idx(va_ro, 3),
        pte(F3_GPA, false, true, false, false),
    );
    assert_eq!(
        rig.probe_pf(va_ro, Access::Write, mode).class,
        PageFaultClass::Protection
    );

    let va_r0 = GuestVa::new(0xffff_ffff_8000_0000);
    let sup = PRESENT | WRITE;
    let r0_leaf = pte(F4_GPA, true, false, true, false);
    rig.mem.map_4k_chain(
        rig.root, va_r0, PDPT_B_GPA, PD_B_GPA, PT_B_GPA, sup, sup, sup, r0_leaf,
    );
    let host_f4 = rig.mem.host_of(F4_GPA);
    assert_eq!(
        rig.probe_ram(va_r0, Access::Execute, CpuAccessMode::ring0(false)),
        host_f4
    );
    let user_pf = rig.probe_pf(va_r0, Access::Read, mode);
    assert_eq!(user_pf.class, PageFaultClass::Protection);
    assert_eq!(
        user_pf.error_code.bits(),
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::USER
    );
    Ok(())
}

#[test]
fn page_crossing_access_misses_tlb_and_validates_both_pages() -> Result<(), PlacementError> {
    let mut rig = Rig::new()?;
    let mode = CpuAccessMode::ring3();

    let page0_va = GuestVa::new(0x0000_0070_0000);
    let page1_va = GuestVa::new(0x0000_0070_1000);
    let straddle_va = GuestVa::new(0x0000_0070_0ffc);
    rig.map_a(page0_va, pte(F1_GPA, true, true, false, false));
    rig.mem.set(
        PT_A_GPA,
        idx(page1_va, 3),
        pte(F2_GPA, false, true, false, false),
    );

    let host_f1 = rig.mem.host_of(F1_GPA);
    let host_f2 = rig.mem.host_of(F2_GPA);
    let _ = rig.probe_ram(page0_va, Access::Write, mode);
    let _ = rig.probe_ram(page1_va, Access::Read, mode);
    assert_eq!(
        rig.tlb.probe_readonly(straddle_va, 8, Access::Read, mode),
        None
    );

    assert_eq!(
        rig.span(straddle_va, 8, Access::Read, mode).unwrap(),
        ResolvedSpan::Straddling {
            first_host_addr: host_f1 + 0xffc,
            first_len: 4,
            second_host_addr: host_f2,
            second_len: 4,
        }
    );

    let err = *rig
        .span(straddle_va, 8, Access::Write, mode)
        .unwrap_err()
        .as_page_fault()
        .unwrap();
    assert_eq!((err.va, err.class), (page1_va, PageFaultClass::Protection));
    Ok(())
}

/// Review item 10: Concurrent PTE writer vs walker snapshot consistency and structural budget evaluation.
#[test]
fn concurrent_pte_writer_snapshot_consistency_and_structural_budgets() -> Result<(), PlacementError>
{
    let mem = setup_memory()?;
    let root = root_gpa(PML4_A_GPA);
    let race_va = GuestVa::new(0x0000_00d0_0000);

    let pte_a = pte(F1_GPA, true, false, true, false) | ACCESSED | DIRTY;
    let pte_b = pte(F2_GPA, true, true, true, false) | ACCESSED | DIRTY;
    mem.map_4k_a(root, race_va, pte_a);

    let host_f1 = mem.host_of(F1_GPA);
    let pt_idx = idx(race_va, 3);
    let mem_ref = &mem;
    let stop = AtomicBool::new(false);
    let barrier = Barrier::new(2);

    std::thread::scope(|s| {
        let stop_w = &stop;
        let b_w = &barrier;
        let writer = s.spawn(move || {
            b_w.wait();
            let mut i = 0u64;
            while !stop_w.load(Ordering::Relaxed) {
                mem_ref.set(PT_A_GPA, pt_idx, if (i & 1) == 0 { pte_b } else { pte_a });
                i += 1;
            }
        });

        let stop_r = &stop;
        let b_r = &barrier;
        let reader = s.spawn(move || {
            let mut rig = Rig::from_mem(mem_ref.clone(), root);
            let mode = CpuAccessMode::ring0(false);
            b_r.wait();

            for iter in 0..2000u64 {
                rig.tlb.flush_all();
                let access = if (iter & 1) == 0 {
                    Access::Execute
                } else {
                    Access::Read
                };
                match rig.walk(race_va, access, mode) {
                    Ok(WalkOutcome::Ram(r)) => {
                        assert_eq!(
                            (r.frame_gpa.raw(), r.host_addr, r.is_user_page),
                            (F1_GPA, host_f1, false)
                        );
                    }
                    Ok(WalkOutcome::Mmio { .. }) => panic!("unexpected MMIO"),
                    Err(err) => {
                        let pf = err.as_page_fault().unwrap();
                        let expected = if matches!(access, Access::Execute) {
                            PageFaultClass::SmepProtection
                        } else {
                            PageFaultClass::SmapProtection
                        };
                        assert_eq!(pf.class, expected);
                    }
                }
            }
            stop_r.store(true, Ordering::Release);
        });

        assert!(reader.join().is_ok());
        assert!(writer.join().is_ok());
    });

    let mut observations = Vec::new();
    let span_1g = 2 * (1u64 << 30);
    for extent_count in [1u64, 16, 256] {
        let mut b_mem =
            VecGuestMemory::with_placement_span(0x0200_0000, span_1g, MmioHoles::x86_default())?;
        let gen1 = generation(1);
        assert!(b_mem.install_extent(FrameGpa::new(PML4_A_GPA), 4 * PAGE_SIZE_4K, gen1));
        for i in 0..extent_count {
            let gpa = 0x0100_0000 + i * 2 * PAGE_SIZE_4K;
            assert!(b_mem.install_extent(FrameGpa::new(gpa), PAGE_SIZE_4K, gen1));
        }
        assert!(b_mem.install_extent(FrameGpa::new(0x0040_0000), 1 << 21, gen1));
        assert!(b_mem.install_extent(FrameGpa::new(1u64 << 30), 1 << 30, gen1));
        b_mem.extents_mut().set_root_generation(root, gen1);

        let target_4k = 0x0100_0000 + (extent_count - 1) * 2 * PAGE_SIZE_4K;
        let va_4k = GuestVa::new(0x0000_0090_0000);
        b_mem.map_4k_a(
            root,
            va_4k,
            pte(target_4k, true, true, true, false) | ACCESSED | DIRTY,
        );
        let va_2m = GuestVa::new(0x0000_0020_0000);
        let f_huge = PRESENT | WRITE | USER | HUGE | ACCESSED | DIRTY;
        b_mem.set(PD_A_GPA, idx(va_2m, 2), 0x0040_0000 | f_huge);
        let va_1g = GuestVa::new(0x0000_4000_0000);
        b_mem.set(PDPT_A_GPA, idx(va_1g, 1), (1u64 << 30) | f_huge);

        let mut rig = Rig::from_mem(b_mem, root);
        let mode = CpuAccessMode::ring3();

        rig.mem.reset_loads();
        rig.mem.extents().reset_extents_visited();
        let _ = rig.probe_ram(va_4k, Access::Read, mode);
        let loads_4k = rig.mem.loads();
        assert_eq!(loads_4k, 4);

        rig.mem.reset_loads();
        rig.mem.extents().reset_extents_visited();
        let _ = rig.probe_ram(va_4k, Access::Read, mode);
        assert_eq!(
            (rig.mem.loads(), rig.mem.extents().extents_visited()),
            (0, 0)
        );

        rig.mem.reset_loads();
        let _ = rig.probe_ram(va_2m, Access::Read, mode);
        assert_eq!(rig.mem.loads(), 3);

        rig.mem.reset_loads();
        let _ = rig.probe_ram(va_1g, Access::Read, mode);
        assert_eq!(rig.mem.loads(), 2);

        let mut work = WorkSnapshot::new();
        work.insert(WorkMetric::DescriptorLoadsPerMiss, loads_4k)
            .unwrap();
        observations.push(ContractObservation {
            contract_id: ContractId::new("softmmu.x86.tlb-walker").unwrap(),
            layer: ExecutionLayer::VmFree,
            implementation_revision: "softmmu-contract-v1".into(),
            fixture_identity: "carrick-softmmu::tests::softmmu_contract".into(),
            scale: extent_count,
            semantic_assertions: vec![SemanticAssertion::pass(
                "single_walk_descriptor_loads_equal_levels_walked_and_snapshot_is_consistent",
            )],
            work: Some(work),
            timing: None,
            completeness: Completeness::Complete,
        });
    }

    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = ContractRegistry::load(repo_root).unwrap();
    evaluate(
        registry.require("softmmu.x86.tlb-walker").unwrap(),
        &observations,
    )
    .unwrap();
    Ok(())
}

#[test]
fn two_thread_invlpg_eviction_and_cr3_root_switch_flush_match_hardware()
-> Result<(), PlacementError> {
    let mem = setup_memory()?;
    let root_a = root_gpa(PML4_A_GPA);
    let root_b = root_gpa(PML4_B_GPA);
    let va_evict = GuestVa::new(0x0000_00b0_0000);
    let va_keep = GuestVa::new(0x0000_00b0_1000);

    let leaf_f1 = pte(F1_GPA, true, true, true, false) | ACCESSED;
    let leaf_f2 = pte(F2_GPA, true, true, true, false) | ACCESSED;
    let leaf_f3 = pte(F3_GPA, true, true, true, false) | ACCESSED;

    let f = PRESENT | WRITE | USER;
    mem.map_4k_a(root_a, va_evict, leaf_f1);
    let pt_keep_idx = idx(va_keep, 3);
    mem.set(PT_A_GPA, pt_keep_idx, leaf_f2);
    mem.map_4k_chain(
        root_b, va_evict, PDPT_B_GPA, PD_B_GPA, PT_B_GPA, f, f, f, leaf_f3,
    );
    mem.set(PT_B_GPA, pt_keep_idx, leaf_f3);

    let host_f1 = mem.host_of(F1_GPA);
    let host_f2 = mem.host_of(F2_GPA);
    let host_f3 = mem.host_of(F3_GPA);

    let mem_ref = &mem;
    let barrier = Barrier::new(2);
    let shootdown_va = AtomicU64::new(0);
    let shootdown_pending = AtomicBool::new(false);

    std::thread::scope(|s| {
        let b0 = &barrier;
        let sd_va0 = &shootdown_va;
        let sd_pending0 = &shootdown_pending;
        let cpu0 = s.spawn(move || {
            let mut rig = Rig::from_mem(mem_ref.clone(), root_a);
            let mode = CpuAccessMode::ring3();

            assert_eq!(rig.probe_ram(va_evict, Access::Read, mode), host_f1);
            assert_eq!(rig.probe_ram(va_keep, Access::Read, mode), host_f2);
            b0.wait();

            mem_ref.set(PT_A_GPA, idx(va_evict, 3), leaf_f2);
            rig.tlb.evict_va(va_evict);
            sd_va0.store(va_evict.raw(), Ordering::Release);
            sd_pending0.store(true, Ordering::Release);
            b0.wait();

            assert_eq!(rig.probe_ram(va_evict, Access::Read, mode), host_f2);
            assert_eq!(rig.probe_ram(va_keep, Access::Read, mode), host_f2);
        });

        let b1 = &barrier;
        let sd_va1 = &shootdown_va;
        let sd_pending1 = &shootdown_pending;
        let cpu1 = s.spawn(move || {
            let mut rig = Rig::from_mem(mem_ref.clone(), root_a);
            let mode = CpuAccessMode::ring3();

            assert_eq!(rig.probe_ram(va_evict, Access::Read, mode), host_f1);
            assert_eq!(rig.probe_ram(va_keep, Access::Read, mode), host_f2);
            b1.wait();
            b1.wait();

            assert!(sd_pending1.load(Ordering::Acquire));
            let target = GuestVa::new(sd_va1.load(Ordering::Acquire));
            rig.tlb.evict_va(target);
            assert_eq!(rig.tlb.probe(target, 8, Access::Read, mode), None);
            assert_eq!(rig.tlb.probe(va_keep, 8, Access::Read, mode), Some(host_f2));
            assert_eq!(rig.probe_ram(target, Access::Read, mode), host_f2);

            rig.tlb.flush_all();
            rig.root = root_b;
            assert_eq!(rig.tlb.probe(target, 8, Access::Read, mode), None);
            assert_eq!(rig.tlb.probe(va_keep, 8, Access::Read, mode), None);
            assert_eq!(rig.probe_ram(target, Access::Read, mode), host_f3);
            assert_eq!(rig.probe_ram(va_keep, Access::Read, mode), host_f3);
        });

        assert!(cpu0.join().is_ok());
        assert!(cpu1.join().is_ok());
    });
    Ok(())
}
