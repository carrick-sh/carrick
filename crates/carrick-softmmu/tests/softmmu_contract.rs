//! VM-free contract and permission witnesses for `carrick-softmmu` (`carrick-sh/carrick#580`).

use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use carrick_mmu_core::x86::descriptor_txn::{
    DescriptorRefusal, HUGE, LiveDescriptorWords, NX, PRESENT, USER, WRITE, translate_leaf,
};
use carrick_softmmu::{
    Access, Cpl, CpuAccessMode, FaultClass, FrameGpa, GuestVa, LAPIC_MMIO_BASE_GPA,
    LAPIC_MMIO_SIZE_BYTES, LinearPlacement, MmioHoles, OwnerGeneration, PAGE_SIZE_4K,
    PageFaultErrorCode, PlacementError, ResolvedSpan, RootGpa, SOFT_TLB_ENTRIES, SoftFaultClass,
    SoftMmuMemory, SoftTlb, SoftTlbEntry, SoftWalker, Stage1Gpa, TLB_TAG_AC_BIT, TLB_TAG_CPL3_BIT,
    TLB_TAG_INVALID, TranslatedLeaf, VecGuestMemory, WalkOutcome,
};

const TEST_SPAN_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

const PML4_A_GPA: u64 = 0x0001_0000;
const PDPT_A_GPA: u64 = 0x0001_1000;
const PD_A_GPA: u64 = 0x0001_2000;
const PT_A_GPA: u64 = 0x0001_3000;

const PML4_B_GPA: u64 = 0x0002_0000;
const PDPT_B_GPA: u64 = 0x0002_1000;
const PD_B_GPA: u64 = 0x0002_2000;
const PT_B_GPA: u64 = 0x0002_3000;

const DATA_FRAME_1_GPA: u64 = 0x0010_0000;
const DATA_FRAME_2_GPA: u64 = 0x0010_1000;
const DATA_FRAME_3_GPA: u64 = 0x0010_2000;

fn root_gpa(raw: u64) -> RootGpa {
    match RootGpa::page_aligned(FrameGpa::new(raw)) {
        Some(r) => r,
        None => unreachable!(),
    }
}

fn setup_memory() -> Result<VecGuestMemory, PlacementError> {
    let mut mem = VecGuestMemory::new(TEST_SPAN_BYTES)?;
    let gen1 = OwnerGeneration::new(1);
    assert!(mem.install_extent(FrameGpa::new(PML4_A_GPA), 4 * PAGE_SIZE_4K, gen1));
    assert!(mem.install_extent(FrameGpa::new(PML4_B_GPA), 4 * PAGE_SIZE_4K, gen1));
    assert!(mem.install_extent(FrameGpa::new(DATA_FRAME_1_GPA), 8 * PAGE_SIZE_4K, gen1));
    Ok(mem)
}

#[test]
fn linear_placement_enforces_alignment_bounds_and_mmio_holes() -> Result<(), PlacementError> {
    let base_k = 0x7000_0000_0000usize;
    let span = 0x1_0000_0000u64; // 4 GiB

    assert_eq!(
        LinearPlacement::with_x86_defaults(base_k + 1, span),
        Err(PlacementError::UnalignedPlacement {
            base_host_addr: base_k + 1,
            span_bytes: span,
        })
    );
    assert_eq!(
        LinearPlacement::with_x86_defaults(base_k, 0),
        Err(PlacementError::UnalignedPlacement {
            base_host_addr: base_k,
            span_bytes: 0,
        })
    );

    let placement = LinearPlacement::with_x86_defaults(base_k, span)?;
    let frame = FrameGpa::new(0x0040_0000);
    let root = root_gpa(0x0001_0000);

    let host_frame = placement.host(frame)?;
    assert_eq!(host_frame.raw(), base_k + 0x0040_0000);
    assert_eq!(placement.host(root)?.raw(), base_k + 0x0001_0000);

    // Default xAPIC MMIO hole at 0xfee0_0000..0xfee0_1000 is rejected.
    assert_eq!(
        placement.host(FrameGpa::new(LAPIC_MMIO_BASE_GPA)),
        Err(PlacementError::MmioHole {
            gpa: LAPIC_MMIO_BASE_GPA
        })
    );
    assert_eq!(
        placement.host_range(
            FrameGpa::new(LAPIC_MMIO_BASE_GPA - PAGE_SIZE_4K),
            (2 * PAGE_SIZE_4K) as usize
        ),
        Err(PlacementError::MmioHole {
            gpa: LAPIC_MMIO_BASE_GPA - PAGE_SIZE_4K
        })
    );

    // Pages immediately before and after the xAPIC hole succeed.
    assert!(
        placement
            .host(FrameGpa::new(LAPIC_MMIO_BASE_GPA - PAGE_SIZE_4K))
            .is_ok()
    );
    assert!(
        placement
            .host(FrameGpa::new(LAPIC_MMIO_BASE_GPA + LAPIC_MMIO_SIZE_BYTES))
            .is_ok()
    );

    // Out-of-bounds GPAs are rejected.
    assert_eq!(
        placement.host(FrameGpa::new(span)),
        Err(PlacementError::OutOfBounds {
            gpa: span,
            span_bytes: span,
        })
    );
    Ok(())
}

/// Architectural authority: Intel SDM Vol. 3 §4.5 (4-Level Paging):
/// - When `P == 0`, bits `63:1` are ignored by hardware and never produce `RSVD = 1`.
/// - When `P == 1`:
///   - Bits `[51 : MAXPHYADDR]` are reserved (`#PF` with `RSVD = 1`).
///   - Bits `58:52` are ignored by hardware (available to software; e.g. bit 55 set must NOT fault).
///   - Bits `62:59` are protection-key bits when `CR4.PKE == 1` and ignored otherwise.
///   - Bit `63` (`XD` / `NX`) is reserved only when `IA32_EFER.NXE == 0`.
#[test]
fn red_first_non_present_precedence_and_reserved_bits_on_present_entries()
-> Result<(), PlacementError> {
    let mut mem = setup_memory()?;
    let mut tlb = SoftTlb::new();
    let mut walker = SoftWalker::with_max_phy_addr(48);
    let root = root_gpa(PML4_A_GPA);

    // 1. Red witness: a non-present PTE (`PRESENT == 0`) with bit 55 or bit 51 set (e.g. OS swap
    // metadata) is rejected as `FaultClass::Reserved` by bare `translate_leaf` because
    // `validate_entry` runs before `entry & PRESENT == 0`. On x86-64 hardware (Intel SDM Vol. 3
    // §4.5), `P == 0` ignores bits 63:1 and always produces a non-present #PF (`P = 0, RSVD = 0`).
    let swap_va = GuestVa::new(0x0000_0040_0000);
    let non_present_with_upper_bits = (1u64 << 55) | (1u64 << 51);
    mem.map_4k_chain(
        root,
        swap_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        non_present_with_upper_bits,
    )?;

    assert_eq!(
        translate_leaf(&mem, root, swap_va.to_descriptor_va(), Access::Read, true),
        Err(FaultClass::Reserved)
    );

    let swap_err = match walker.walk_and_fill(
        &mut mem,
        &mut tlb,
        root,
        swap_va,
        Access::Read,
        CpuAccessMode::ring3(),
    ) {
        Ok(outcome) => {
            return Err(PlacementError::AddressOverflow {
                gpa: outcome_gpa(outcome),
            });
        }
        Err(fault) => fault,
    };
    assert_eq!(swap_err.class, SoftFaultClass::NotPresent);
    assert!(!swap_err.error_code.present());
    assert!(!swap_err.error_code.reserved_bit());
    assert_eq!(swap_err.error_code.bits(), PageFaultErrorCode::USER);

    // 2. Red witness on hardware-ignored bit 55 (`58:52`, Intel SDM Vol. 3 §4.5):
    // Bare `translate_leaf` rejects bit 55 on a present PTE as `FaultClass::Reserved`, whereas
    // x86-64 hardware ignores bits `58:52` (and `62:59` when PKE=0). `SoftWalker` must NOT fault
    // when bit 55 is set on a present PTE.
    let bit55_va = GuestVa::new(0x0000_0040_2000);
    let bit55_leaf =
        VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, true, false) | (1u64 << 55);
    let pt_idx_55 = VecGuestMemory::descriptor_index(bit55_va, 3);
    mem.store_descriptor_word(FrameGpa::new(PT_A_GPA), pt_idx_55, bit55_leaf)?;

    assert_eq!(
        translate_leaf(&mem, root, bit55_va.to_descriptor_va(), Access::Read, true),
        Err(FaultClass::Reserved)
    );
    let bit55_host = walker
        .probe_or_walk(
            &mut mem,
            &mut tlb,
            root,
            bit55_va,
            8,
            Access::Read,
            CpuAccessMode::ring3(),
        )
        .map_err(|_| PlacementError::TooManyHoles)?;
    assert_eq!(
        bit55_host,
        mem.placement().host(FrameGpa::new(DATA_FRAME_1_GPA))?.raw()
    );

    // 3. Parameterised `MAXPHYADDR` boundary check (Intel SDM Vol. 3 §4.5):
    // Bits `[51 : MAXPHYADDR]` are reserved (`#PF` with `RSVD = 1`), while physical address bits
    // `< MAXPHYADDR` are not reserved.
    // Under `MAXPHYADDR = 48`:
    //   - bit 48 and bit 51 are in `[51:48]` -> MUST fault with `SoftFaultClass::ReservedBit`.
    //   - under `MAXPHYADDR = 52`, bit 48 and bit 51 are valid physical address bits (so they do
    //     not fault with `ReservedBit`, instead reaching extent lookup for the high GPA).
    for &rsvd_bit in &[48u32, 51u32] {
        let rsvd_va = GuestVa::new(0x0000_0040_1000);
        let bad_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, true, false)
            | (1u64 << rsvd_bit);
        let pt_idx = VecGuestMemory::descriptor_index(rsvd_va, 3);
        mem.store_descriptor_word(FrameGpa::new(PT_A_GPA), pt_idx, bad_leaf)?;

        let err_48 = match walker.walk_and_fill(
            &mut mem,
            &mut tlb,
            root,
            rsvd_va,
            Access::Execute,
            CpuAccessMode::ring3(),
        ) {
            Ok(outcome) => {
                return Err(PlacementError::AddressOverflow {
                    gpa: outcome_gpa(outcome),
                });
            }
            Err(fault) => fault,
        };
        assert_eq!(err_48.class, SoftFaultClass::ReservedBit);
        assert_eq!(
            err_48.error_code.bits(),
            PageFaultErrorCode::PRESENT
                | PageFaultErrorCode::USER
                | PageFaultErrorCode::RESERVED_WRITE
                | PageFaultErrorCode::INSTRUCTION_FETCH
        );

        // On a walker with MAXPHYADDR = 52, bit `rsvd_bit` (48 or 51) is NOT a reserved bit:
        // it passes reserved-bit validation and reaches extent authentication for that 52-bit GPA.
        let mut walker_52 = SoftWalker::with_max_phy_addr(52);
        let err_52 = match walker_52.walk_and_fill(
            &mut mem,
            &mut tlb,
            root,
            rsvd_va,
            Access::Execute,
            CpuAccessMode::ring3(),
        ) {
            Ok(outcome) => {
                return Err(PlacementError::AddressOverflow {
                    gpa: outcome_gpa(outcome),
                });
            }
            Err(fault) => fault,
        };
        assert_eq!(
            err_52.class,
            SoftFaultClass::UnauthenticatedExtent {
                stage1_gpa: Stage1Gpa::new(DATA_FRAME_1_GPA | (1u64 << rsvd_bit)),
                expected_generation: OwnerGeneration::new(1),
            }
        );
        assert!(!err_52.error_code.reserved_bit());
    }

    // Also test a narrower `MAXPHYADDR = 36` boundary on both sides:
    // bit 35 (`< MAXPHYADDR`) is not reserved, while bit 36 (`== MAXPHYADDR`) faults with RSVD=1.
    let mut walker_36 = SoftWalker::with_max_phy_addr(36);
    let boundary_va = GuestVa::new(0x0000_0040_3000);
    let pt_idx_b = VecGuestMemory::descriptor_index(boundary_va, 3);

    let leaf_bit35 =
        VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, true, false) | (1u64 << 35);
    mem.store_descriptor_word(FrameGpa::new(PT_A_GPA), pt_idx_b, leaf_bit35)?;
    let err_bit35 = match walker_36.walk_and_fill(
        &mut mem,
        &mut tlb,
        root,
        boundary_va,
        Access::Read,
        CpuAccessMode::ring3(),
    ) {
        Ok(outcome) => {
            return Err(PlacementError::AddressOverflow {
                gpa: outcome_gpa(outcome),
            });
        }
        Err(fault) => fault,
    };
    assert_eq!(
        err_bit35.class,
        SoftFaultClass::UnauthenticatedExtent {
            stage1_gpa: Stage1Gpa::new(DATA_FRAME_1_GPA | (1u64 << 35)),
            expected_generation: OwnerGeneration::new(1),
        }
    );
    assert!(!err_bit35.error_code.reserved_bit());

    let leaf_bit36 =
        VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, true, false) | (1u64 << 36);
    mem.store_descriptor_word(FrameGpa::new(PT_A_GPA), pt_idx_b, leaf_bit36)?;
    let err_bit36 = match walker_36.walk_and_fill(
        &mut mem,
        &mut tlb,
        root,
        boundary_va,
        Access::Read,
        CpuAccessMode::ring3(),
    ) {
        Ok(outcome) => {
            return Err(PlacementError::AddressOverflow {
                gpa: outcome_gpa(outcome),
            });
        }
        Err(fault) => fault,
    };
    assert_eq!(err_bit36.class, SoftFaultClass::ReservedBit);
    assert!(err_bit36.error_code.reserved_bit());

    // 4. Bit 63 (`XD`/`NX`) is reserved only when `EFER.NXE == 0` (Intel SDM Vol. 3 §4.5).
    let mut walker_no_nxe = SoftWalker::with_paging_config(48, false);
    let nx_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, false, false); // NX = 1
    mem.store_descriptor_word(FrameGpa::new(PT_A_GPA), pt_idx_b, nx_leaf)?;
    let err_no_nxe = match walker_no_nxe.walk_and_fill(
        &mut mem,
        &mut tlb,
        root,
        boundary_va,
        Access::Read,
        CpuAccessMode::ring3(),
    ) {
        Ok(outcome) => {
            return Err(PlacementError::AddressOverflow {
                gpa: outcome_gpa(outcome),
            });
        }
        Err(fault) => fault,
    };
    assert_eq!(err_no_nxe.class, SoftFaultClass::ReservedBit);
    assert!(err_no_nxe.error_code.reserved_bit());

    // 5. PS=1 (`HUGE`) on PML4E is caught as ReservedBit.
    let va2 = GuestVa::new(0x0000_0080_0000);
    let good_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, true, false);
    mem.map_4k_chain_with_intermediate_flags(
        root,
        va2,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        PRESENT | WRITE | USER | HUGE,
        PRESENT | WRITE | USER,
        PRESENT | WRITE | USER,
        good_leaf,
    )?;
    let err_pml4 = match walker.walk_and_fill(
        &mut mem,
        &mut tlb,
        root,
        va2,
        Access::Read,
        CpuAccessMode::ring3(),
    ) {
        Ok(outcome) => {
            return Err(PlacementError::AddressOverflow {
                gpa: outcome_gpa(outcome),
            });
        }
        Err(fault) => fault,
    };
    assert_eq!(err_pml4.class, SoftFaultClass::ReservedBit);
    assert!(err_pml4.error_code.reserved_bit());
    Ok(())
}

#[test]
fn red_first_smap_and_smep_enforced_across_tlb_and_walker() -> Result<(), PlacementError> {
    let mut mem = setup_memory()?;
    let mut tlb = SoftTlb::new();
    let mut walker = SoftWalker::new();
    let root = root_gpa(PML4_A_GPA);
    let user_va = GuestVa::new(0x0000_0050_0120);

    let user_exec_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, true, false);
    mem.map_4k_chain(
        root,
        user_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        user_exec_leaf,
    )?;

    // Red witness: bare `translate_leaf` with `user = false` (CPL0) has no SMAP or SMEP concept
    // and allows both CPL0 read with AC=0 and CPL0 execute on a user page.
    assert!(translate_leaf(&mem, root, user_va.to_descriptor_va(), Access::Read, false).is_ok());
    assert!(
        translate_leaf(
            &mem,
            root,
            user_va.to_descriptor_va(),
            Access::Execute,
            false
        )
        .is_ok()
    );

    // 1. CPL0 data read with AC=0 must fault with SmapProtection (error code: P=1, W/R=0, U/S=0).
    let smap_read_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        user_va,
        8,
        Access::Read,
        CpuAccessMode::ring0(false),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(smap_read_err.class, SoftFaultClass::SmapProtection);
    assert_eq!(smap_read_err.error_code.bits(), PageFaultErrorCode::PRESENT);

    // 2. CPL0 data write with AC=1 (`stac`) succeeds and caches an entry tagged with TLB_TAG_AC_BIT.
    let host_addr = walker
        .probe_or_walk(
            &mut mem,
            &mut tlb,
            root,
            user_va,
            8,
            Access::Write,
            CpuAccessMode::ring0(true),
        )
        .map_err(|_| PlacementError::TooManyHoles)?;
    assert_eq!(
        host_addr,
        mem.placement().host(FrameGpa::new(DATA_FRAME_1_GPA))?.raw() + user_va.page_offset()
    );
    let idx = SoftTlb::index_for(user_va);
    assert_eq!(
        tlb.write.entries[idx].tag,
        user_va.page_base() | TLB_TAG_AC_BIT
    );

    // 3. After `clac` (AC=0), WITHOUT flushing SoftTlb, a CPL0 write must miss the AC=1 TLB entry
    // and fault with SmapProtection (error code: P=1, W/R=1, U/S=0).
    assert_eq!(
        tlb.probe_readonly(user_va, 8, Access::Write, CpuAccessMode::ring0(false)),
        None
    );
    let smap_write_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        user_va,
        8,
        Access::Write,
        CpuAccessMode::ring0(false),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(smap_write_err.class, SoftFaultClass::SmapProtection);
    assert_eq!(
        smap_write_err.error_code.bits(),
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::WRITE
    );

    // 4. CPL0 instruction fetch on a user page faults with SmepProtection even when AC=1!
    let smep_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        user_va,
        1,
        Access::Execute,
        CpuAccessMode::ring0(true),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(smep_err.class, SoftFaultClass::SmepProtection);
    assert_eq!(
        smep_err.error_code.bits(),
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::INSTRUCTION_FETCH
    );

    // 5. Multi-level USER check: if PDE has USER=0 and leaf PTE has USER=1, the page is
    // effectively supervisor-only (`is_user_page == false`), so CPL0 with AC=0 can read/execute it
    // while CPL3 faults with Protection.
    let mixed_va = GuestVa::new(0x0000_0050_1000);
    mem.map_4k_chain_with_intermediate_flags(
        root,
        mixed_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        PRESENT | WRITE | USER,
        PRESENT | WRITE | USER,
        PRESENT | WRITE, // USER clear on PDE!
        user_exec_leaf,
    )?;
    assert!(
        walker
            .probe_or_walk(
                &mut mem,
                &mut tlb,
                root,
                mixed_va,
                8,
                Access::Read,
                CpuAccessMode::ring0(false)
            )
            .is_ok()
    );
    let cpl3_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        mixed_va,
        8,
        Access::Read,
        CpuAccessMode::ring3(),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(cpl3_err.class, SoftFaultClass::Protection);
    assert_eq!(
        cpl3_err.error_code.bits(),
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::USER
    );
    Ok(())
}

#[test]
fn permission_classes_not_present_write_cow_nx_and_upper_half_va() -> Result<(), PlacementError> {
    let mut mem = setup_memory()?;
    let mut tlb = SoftTlb::new();
    let mut walker = SoftWalker::new();
    let root = root_gpa(PML4_A_GPA);

    // 1. Unmapped VA -> NotPresent (P=0, U/S=1).
    let unmapped_va = GuestVa::new(0x0000_0090_0000);
    let np_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        unmapped_va,
        4,
        Access::Read,
        CpuAccessMode::ring3(),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(np_err.class, SoftFaultClass::NotPresent);
    assert_eq!(np_err.error_code.bits(), PageFaultErrorCode::USER);

    // 2. Read-only leaf -> Read succeeds (and does NOT fill write TLB); Write faults with Protection.
    let ro_va = GuestVa::new(0x0000_0060_0000);
    let ro_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, false, true, false, false);
    mem.map_4k_chain(
        root,
        ro_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        ro_leaf,
    )?;
    assert!(
        walker
            .probe_or_walk(
                &mut mem,
                &mut tlb,
                root,
                ro_va,
                4,
                Access::Read,
                CpuAccessMode::ring3()
            )
            .is_ok()
    );
    assert_eq!(
        tlb.write.entries[SoftTlb::index_for(ro_va)],
        SoftTlbEntry::INVALID
    );
    let ro_write_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        ro_va,
        4,
        Access::Write,
        CpuAccessMode::ring3(),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(ro_write_err.class, SoftFaultClass::Protection);
    assert_eq!(
        ro_write_err.error_code.bits(),
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::WRITE | PageFaultErrorCode::USER
    );

    // 3. NX on leaf -> Execute faults with Protection (P | U/S | I/D) and leaves exec TLB invalid.
    let nx_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        ro_va,
        1,
        Access::Execute,
        CpuAccessMode::ring3(),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(nx_err.class, SoftFaultClass::Protection);
    assert_eq!(
        nx_err.error_code.bits(),
        PageFaultErrorCode::PRESENT
            | PageFaultErrorCode::USER
            | PageFaultErrorCode::INSTRUCTION_FETCH
    );
    assert_eq!(
        tlb.exec.entries[SoftTlb::index_for(ro_va)],
        SoftTlbEntry::INVALID
    );

    // 4. Ancestor NX (`NX` on PDE, executable leaf) -> Execute faults with Protection.
    let anc_nx_va = GuestVa::new(0x0000_0060_1000);
    let exec_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, true, false);
    mem.map_4k_chain_with_intermediate_flags(
        root,
        anc_nx_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        PRESENT | WRITE | USER,
        PRESENT | WRITE | USER,
        PRESENT | WRITE | USER | NX,
        exec_leaf,
    )?;
    let anc_nx_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        anc_nx_va,
        1,
        Access::Execute,
        CpuAccessMode::ring3(),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(anc_nx_err.class, SoftFaultClass::Protection);

    // 5. COW-armed leaf (`COW = 1, WRITE = 0`): Read hits, Write faults with `SoftFaultClass::CowWrite`.
    let cow_va = GuestVa::new(0x0000_0060_2000);
    let cow_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_2_GPA, false, true, false, true);
    mem.map_4k_chain(
        root,
        cow_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        cow_leaf,
    )?;
    assert!(
        walker
            .probe_or_walk(
                &mut mem,
                &mut tlb,
                root,
                cow_va,
                8,
                Access::Read,
                CpuAccessMode::ring3()
            )
            .is_ok()
    );
    let cow_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        cow_va,
        8,
        Access::Write,
        CpuAccessMode::ring3(),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(cow_err.class, SoftFaultClass::CowWrite);
    assert_eq!(
        cow_err.error_code.bits(),
        PageFaultErrorCode::PRESENT | PageFaultErrorCode::WRITE | PageFaultErrorCode::USER
    );

    // 6. Upper-half canonical supervisor VA (`0xffff_ffff_c000_0340`, CPL0 ring region):
    // verifies modular 64-bit `va.wrapping_add(addend)` arithmetic in `SoftTlbEntry::translate`.
    let sup_va = GuestVa::new(0xffff_ffff_c000_0340);
    assert!(sup_va.is_canonical_48bit());
    let sup_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_3_GPA, true, false, true, false);
    mem.map_4k_chain_with_intermediate_flags(
        root,
        sup_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        PRESENT | WRITE,
        PRESENT | WRITE,
        PRESENT | WRITE,
        sup_leaf,
    )?;
    let resolved_sup = walker
        .probe_or_walk(
            &mut mem,
            &mut tlb,
            root,
            sup_va,
            8,
            Access::Write,
            CpuAccessMode::ring0(false),
        )
        .map_err(|_| PlacementError::TooManyHoles)?;
    let expected_sup = mem.placement().host(FrameGpa::new(DATA_FRAME_3_GPA))?.raw() + 0x340;
    assert_eq!(resolved_sup, expected_sup);

    // Subsequent fast-path probe hits without walking.
    let walks_before = walker.stats().walks;
    let cached_sup = walker
        .probe_or_walk(
            &mut mem,
            &mut tlb,
            root,
            sup_va,
            8,
            Access::Write,
            CpuAccessMode::ring0(false),
        )
        .map_err(|_| PlacementError::TooManyHoles)?;
    assert_eq!(cached_sup, expected_sup);
    assert_eq!(walker.stats().walks, walks_before);
    Ok(())
}

#[test]
fn mmio_hole_and_extent_generation_authentication_and_code_page_tracking()
-> Result<(), PlacementError> {
    // Allocate a small memory space with a custom MMIO hole at `0x0020_0000..0x0020_1000`.
    const CUSTOM_MMIO_GPA: u64 = 0x0020_0000;
    let holes = MmioHoles::x86_default().with_hole(CUSTOM_MMIO_GPA, PAGE_SIZE_4K)?;
    let mut mem = VecGuestMemory::with_holes(TEST_SPAN_BYTES, holes)?;
    let gen1 = OwnerGeneration::new(1);
    assert!(mem.install_extent(FrameGpa::new(PML4_A_GPA), 4 * PAGE_SIZE_4K, gen1));
    assert!(mem.install_extent(FrameGpa::new(DATA_FRAME_1_GPA), 8 * PAGE_SIZE_4K, gen1));

    let mut tlb = SoftTlb::new();
    let mut walker = SoftWalker::new();
    let root = root_gpa(PML4_A_GPA);

    // 1. Stage-1 leaf mapped to the MMIO hole (`0x0020_0000`) is never cached in SoftTlb.
    let mmio_va = GuestVa::new(0xffff_ffff_fee0_0020);
    let mmio_leaf = VecGuestMemory::encode_leaf_pte(CUSTOM_MMIO_GPA, true, false, false, false);
    mem.map_4k_chain_with_intermediate_flags(
        root,
        mmio_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        PRESENT | WRITE,
        PRESENT | WRITE,
        PRESENT | WRITE,
        mmio_leaf,
    )?;
    let outcome = walker
        .walk_and_fill(
            &mut mem,
            &mut tlb,
            root,
            mmio_va,
            Access::Read,
            CpuAccessMode::ring0(false),
        )
        .map_err(|_| PlacementError::TooManyHoles)?;
    assert!(matches!(
        outcome,
        WalkOutcome::Mmio {
            gpa: 0x0020_0020,
            ..
        }
    ));
    assert_eq!(
        tlb.read.entries[SoftTlb::index_for(mmio_va)],
        SoftTlbEntry::INVALID
    );
    assert_eq!(walker.stats().mmio_exits, 1);

    // 2. Stale OwnerGeneration for the root/extent is rejected by ExtentTable authentication.
    let stale_va = GuestVa::new(0x0000_0070_0000);
    let stale_leaf = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, false, false);
    mem.map_4k_chain(
        root,
        stale_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        stale_leaf,
    )?;
    mem.set_root_generation(root, OwnerGeneration::new(2)); // extent was registered with generation 1
    let stale_err = match walker.probe_or_walk(
        &mut mem,
        &mut tlb,
        root,
        stale_va,
        8,
        Access::Read,
        CpuAccessMode::ring3(),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(
        stale_err.class,
        SoftFaultClass::UnauthenticatedExtent {
            stage1_gpa: Stage1Gpa::new(DATA_FRAME_1_GPA),
            expected_generation: OwnerGeneration::new(2),
        }
    );
    mem.set_root_generation(root, gen1);

    // 3. Code-page write tracking: marking a frame as holding translated code keeps `tlb.write`
    // invalid and bumps `code_generation` on every write.
    let code_va = GuestVa::new(0x0000_0070_1000);
    let code_frame = FrameGpa::new(DATA_FRAME_2_GPA);
    let code_leaf = VecGuestMemory::encode_leaf_pte(code_frame.raw(), true, true, true, false);
    mem.map_4k_chain(
        root,
        code_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        code_leaf,
    )?;

    // First write before code translation fills `tlb.write`.
    let _ = walker
        .probe_or_walk(
            &mut mem,
            &mut tlb,
            root,
            code_va,
            4,
            Access::Write,
            CpuAccessMode::ring3(),
        )
        .map_err(|_| PlacementError::TooManyHoles)?;
    assert!(tlb.write.entries[SoftTlb::index_for(code_va)].is_valid());

    // Translator caches a block on `code_frame` and evicts `code_va` from `tlb.write`.
    let gen_initial = mem.mark_code_page(code_frame);
    assert_eq!(gen_initial, 1);
    assert!(tlb.evict_write_va(code_va));
    assert!(!tlb.write.entries[SoftTlb::index_for(code_va)].is_valid());

    // Subsequent guest write misses `tlb.write`, takes the slow path, bumps code generation to 2,
    // and keeps `tlb.write` invalid so further self-modifying writes also trap.
    let write_outcome = walker
        .walk_and_fill(
            &mut mem,
            &mut tlb,
            root,
            code_va,
            Access::Write,
            CpuAccessMode::ring3(),
        )
        .map_err(|_| PlacementError::TooManyHoles)?;
    match write_outcome {
        WalkOutcome::Ram(resolved) => {
            assert!(resolved.invalidated_code_page);
            assert_eq!(resolved.code_generation, 2);
        }
        WalkOutcome::Mmio { .. } => return Err(PlacementError::TooManyHoles),
    }
    assert!(!tlb.write.entries[SoftTlb::index_for(code_va)].is_valid());
    assert_eq!(walker.stats().code_page_invalidations, 1);
    Ok(())
}

#[test]
fn page_crossing_access_misses_tlb_and_validates_both_pages() -> Result<(), PlacementError> {
    let mut mem = setup_memory()?;
    let mut tlb = SoftTlb::new();
    let mut walker = SoftWalker::new();
    let root = root_gpa(PML4_A_GPA);

    let page0_va = GuestVa::new(0x0000_00a0_0000);
    let page1_va = GuestVa::new(0x0000_00a0_1000);
    let straddle_va = GuestVa::new(0x0000_00a0_0ffc); // 4 bytes in page 0, 4 bytes in page 1

    let leaf0 = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, false, false);
    mem.map_4k_chain(
        root,
        page0_va,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        leaf0,
    )?;

    // Warm page 0 in SoftTlb.
    assert!(
        walker
            .probe_or_walk(
                &mut mem,
                &mut tlb,
                root,
                page0_va,
                8,
                Access::Write,
                CpuAccessMode::ring3()
            )
            .is_ok()
    );

    // Page-crossing probe on `straddle_va` (len = 8) MUST miss SoftTlb even though page 0 is warm,
    // and `resolve_span` must fault on unmapped `page1_va` with `fault.va == page1_va`.
    assert_eq!(
        tlb.probe(straddle_va, 8, Access::Write, CpuAccessMode::ring3()),
        None
    );
    let cross_err = match walker.resolve_span(
        &mut mem,
        &mut tlb,
        root,
        straddle_va,
        8,
        Access::Write,
        CpuAccessMode::ring3(),
    ) {
        Ok(_) => return Err(PlacementError::TooManyHoles),
        Err(fault) => fault,
    };
    assert_eq!(cross_err.va, page1_va);
    assert_eq!(cross_err.class, SoftFaultClass::NotPresent);

    // Map page 1 to DATA_FRAME_3_GPA (non-contiguous physical frame!) and resolve the straddling span.
    let leaf1 = VecGuestMemory::encode_leaf_pte(DATA_FRAME_3_GPA, true, true, false, false);
    let pt_idx1 = VecGuestMemory::descriptor_index(page1_va, 3);
    mem.store_descriptor_word(FrameGpa::new(PT_A_GPA), pt_idx1, leaf1)?;

    let span = walker
        .resolve_span(
            &mut mem,
            &mut tlb,
            root,
            straddle_va,
            8,
            Access::Write,
            CpuAccessMode::ring3(),
        )
        .map_err(|_| PlacementError::TooManyHoles)?;
    let expected_first = mem.placement().host(FrameGpa::new(DATA_FRAME_1_GPA))?.raw() + 0xffc;
    let expected_second = mem.placement().host(FrameGpa::new(DATA_FRAME_3_GPA))?.raw();
    assert_eq!(
        span,
        ResolvedSpan::Straddling {
            first_host_addr: expected_first,
            first_len: 4,
            second_host_addr: expected_second,
            second_len: 4,
        }
    );
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

    // Root A initially maps va_evict -> DATA_FRAME_1_GPA and va_keep -> DATA_FRAME_2_GPA.
    let leaf_f1 = VecGuestMemory::encode_leaf_pte(DATA_FRAME_1_GPA, true, true, true, false);
    let leaf_f2 = VecGuestMemory::encode_leaf_pte(DATA_FRAME_2_GPA, true, true, true, false);
    let leaf_f3 = VecGuestMemory::encode_leaf_pte(DATA_FRAME_3_GPA, true, true, true, false);

    mem.map_4k_chain(
        root_a,
        va_evict,
        FrameGpa::new(PDPT_A_GPA),
        FrameGpa::new(PD_A_GPA),
        FrameGpa::new(PT_A_GPA),
        leaf_f1,
    )?;
    let pt_keep_idx = VecGuestMemory::descriptor_index(va_keep, 3);
    mem.store_descriptor_word(FrameGpa::new(PT_A_GPA), pt_keep_idx, leaf_f2)?;

    // Root B maps both va_evict and va_keep -> DATA_FRAME_3_GPA.
    mem.map_4k_chain(
        root_b,
        va_evict,
        FrameGpa::new(PDPT_B_GPA),
        FrameGpa::new(PD_B_GPA),
        FrameGpa::new(PT_B_GPA),
        leaf_f3,
    )?;
    mem.store_descriptor_word(FrameGpa::new(PT_B_GPA), pt_keep_idx, leaf_f3)?;

    let host_f1 = mem.placement().host(FrameGpa::new(DATA_FRAME_1_GPA))?.raw();
    let host_f2 = mem.placement().host(FrameGpa::new(DATA_FRAME_2_GPA))?.raw();
    let host_f3 = mem.placement().host(FrameGpa::new(DATA_FRAME_3_GPA))?.raw();

    // Shared Read-Only view of page tables (descriptor words are AtomicU64) + shootdown mailbox.
    let mem_ref = &mem;
    let barrier = Barrier::new(2);
    let shootdown_va = AtomicU64::new(0);
    let shootdown_pending = AtomicBool::new(false);

    std::thread::scope(|s| {
        // CPU 0: mutates PTE for `va_evict` in Root A (`DATA_FRAME_1 -> DATA_FRAME_3`), issues
        // local `invlpg` + cross-CPU shootdown to CPU 1.
        let b0 = &barrier;
        let sd_va0 = &shootdown_va;
        let sd_pending0 = &shootdown_pending;
        let cpu0 = s.spawn(move || {
            let mut view = SharedReadOnlyMemory(mem_ref);
            let mut tlb = SoftTlb::new();
            let mut walker = SoftWalker::new();
            let mode = CpuAccessMode::ring3();

            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_a, va_evict, 8, Access::Read, mode),
                Ok(host_f1)
            );
            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_a, va_keep, 8, Access::Read, mode),
                Ok(host_f2)
            );

            // Wait until both CPUs have warmed their SoftTlb on Root A.
            b0.wait();

            // Rewrite PTE for `va_evict` in Root A to point to `DATA_FRAME_3_GPA`.
            let pt_evict_idx = VecGuestMemory::descriptor_index(va_evict, 3);
            assert!(
                mem_ref
                    .store_descriptor_word(FrameGpa::new(PT_A_GPA), pt_evict_idx, leaf_f3)
                    .is_ok()
            );

            // Local `invlpg` on CPU 0 and shootdown publication to CPU 1.
            tlb.evict_va(va_evict);
            sd_va0.store(va_evict.raw(), Ordering::Release);
            sd_pending0.store(true, Ordering::Release);
            b0.wait();

            // CPU 0 sees the new frame for `va_evict` (1 new walk) while `va_keep` hits SoftTlb (0 walks).
            let walks_before = walker.stats().walks;
            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_a, va_keep, 8, Access::Read, mode),
                Ok(host_f2)
            );
            assert_eq!(walker.stats().walks, walks_before);
            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_a, va_evict, 8, Access::Read, mode),
                Ok(host_f3)
            );
            assert_eq!(walker.stats().walks, walks_before + 1);

            b0.wait();
        });

        // CPU 1: warms SoftTlb on Root A, processes `invlpg` shootdown for `va_evict`, then
        // switches CR3 to Root B (`flush_all`).
        let b1 = &barrier;
        let sd_va1 = &shootdown_va;
        let sd_pending1 = &shootdown_pending;
        let cpu1 = s.spawn(move || {
            let mut view = SharedReadOnlyMemory(mem_ref);
            let mut tlb = SoftTlb::new();
            let mut walker = SoftWalker::new();
            let mode = CpuAccessMode::ring3();

            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_a, va_evict, 8, Access::Read, mode),
                Ok(host_f1)
            );
            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_a, va_keep, 8, Access::Read, mode),
                Ok(host_f2)
            );
            assert_eq!(
                walker.probe_or_walk(
                    &mut view,
                    &mut tlb,
                    root_a,
                    va_evict,
                    1,
                    Access::Execute,
                    mode
                ),
                Ok(host_f1)
            );

            b1.wait();
            b1.wait();

            // Before acknowledging shootdown, CPU 1's stale TLB entry still maps `va_evict` to `host_f1`.
            assert_eq!(
                tlb.probe_readonly(va_evict, 8, Access::Read, mode),
                Some(host_f1)
            );

            // Acknowledge IPI shootdown and execute `invlpg` for the requested VA.
            assert!(sd_pending1.load(Ordering::Acquire));
            let target_va = GuestVa::new(sd_va1.load(Ordering::Acquire));
            tlb.evict_va(target_va);

            // Both `read` and `exec` planes for `va_evict` are now invalid, while `va_keep` stays valid!
            assert_eq!(tlb.probe_readonly(va_evict, 8, Access::Read, mode), None);
            assert_eq!(tlb.probe_readonly(va_evict, 1, Access::Execute, mode), None);
            assert_eq!(
                tlb.probe_readonly(va_keep, 8, Access::Read, mode),
                Some(host_f2)
            );

            let walks_before = walker.stats().walks;
            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_a, va_keep, 8, Access::Read, mode),
                Ok(host_f2)
            );
            assert_eq!(walker.stats().walks, walks_before);
            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_a, va_evict, 8, Access::Read, mode),
                Ok(host_f3)
            );
            assert_eq!(walker.stats().walks, walks_before + 1);

            // Now simulate `mov cr3, root_b`: flush all entries and verify `va_keep` resolves to Root B's frame (`host_f3`).
            tlb.flush_all();
            assert_eq!(tlb.stats().full_flushes, 1);
            assert_eq!(tlb.probe_readonly(va_keep, 8, Access::Read, mode), None);
            assert_eq!(
                walker.probe_or_walk(&mut view, &mut tlb, root_b, va_keep, 8, Access::Read, mode),
                Ok(host_f3)
            );

            b1.wait();
        });

        assert!(cpu0.join().is_ok());
        assert!(cpu1.join().is_ok());
    });

    // Verify constants exported for 1b JIT emitter.
    assert_eq!(SOFT_TLB_ENTRIES, 1024);
    assert_eq!(TLB_TAG_INVALID, u64::MAX);
    assert_eq!(TLB_TAG_CPL3_BIT, 1);
    assert_eq!(TLB_TAG_AC_BIT, 2);
    assert_eq!(Cpl::from_cs_selector(0x33), Ok(Cpl::Ring3));
    assert_eq!(Cpl::from_cs_selector(0x08), Ok(Cpl::Ring0));
    assert_eq!(Cpl::from_cs_selector(0x11), Err(1));
    Ok(())
}

struct SharedReadOnlyMemory<'a>(&'a VecGuestMemory);

impl LiveDescriptorWords for SharedReadOnlyMemory<'_> {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        self.0.load(pa)
    }

    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        self.0.compare_exchange(pa, current, new)
    }

    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.0.store_unlinked(pa, value)
    }

    fn publish_barrier(&self) {
        self.0.publish_barrier();
    }

    fn invalidate_range(&self, va: u64, len: u64) {
        self.0.invalidate_range(va, len);
    }
}

impl carrick_softmmu::SoftMmuMemory for SharedReadOnlyMemory<'_> {
    fn placement(&self) -> &LinearPlacement {
        self.0.placement()
    }

    fn authenticate_leaf(
        &self,
        root: RootGpa,
        stage1_gpa: Stage1Gpa,
        leaf: &TranslatedLeaf,
    ) -> Result<FrameGpa, OwnerGeneration> {
        self.0.authenticate_leaf(root, stage1_gpa, leaf)
    }

    fn is_code_page(&self, frame_gpa: FrameGpa) -> bool {
        self.0.is_code_page(frame_gpa)
    }

    fn code_generation(&self, frame_gpa: FrameGpa) -> u64 {
        self.0.code_generation(frame_gpa)
    }

    fn on_code_page_write(&mut self, frame_gpa: FrameGpa) -> u64 {
        self.0.code_generation(frame_gpa).saturating_add(1)
    }
}

const fn outcome_gpa(outcome: WalkOutcome) -> u64 {
    match outcome {
        WalkOutcome::Ram(resolved) => resolved.frame_gpa.raw(),
        WalkOutcome::Mmio { gpa, .. } => gpa,
    }
}
