//! KVM bindings: stage1-publication, address-space-occupancy and exact context
//! drain. Intel SDM page-fault P/W/U/I bits plus Linux mmap/mprotect/fork
//! semantics. These are hardware fixtures, not N1 or OCI acceptance.
//! No Docker, absent-KVM skips, retries, or timing claims.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::panic)]
use carrick_mmu_core::x86::descriptor_txn::{DescriptorOp, PAGE, PageSpan, Permissions};
use carrick_vmm_kvm::carrier_memory::fixture::{DATA_VA, MemoryWitness, Observation};
fn code(ops: &[(u64, Option<u8>)]) -> Vec<u8> {
    let mut code = Vec::new();
    for &(va, write) in ops {
        code.extend_from_slice(&[0x48, 0xbb]);
        code.extend_from_slice(&va.to_le_bytes());
        if let Some(value) = write {
            code.extend_from_slice(&[0xc6, 0x03, value]);
        }
        code.extend_from_slice(&[0x0f, 0xb6, 0x03, 0x0f, 0x05]); // movzx eax,[rbx]; syscall observation
    }
    code.extend_from_slice(&[0x0f, 0x0b]);
    code
}
fn byte(w: &mut MemoryWitness, mm: usize, value: u8) {
    assert!(matches!(w.observe(mm).unwrap(),Observation::Byte(actual) if actual==value));
}
fn fault(w: &mut MemoryWitness, mm: usize, error: u64) {
    match w.observe(mm).unwrap() {
        Observation::Fault(record) => {
            assert_eq!(record.vector, 14);
            assert_eq!(record.error_code, error);
            assert_eq!(record.cr2, DATA_VA);
            assert_eq!(record.cs & 3, 3);
        }
        other => panic!("expected page fault, got {other:?}"),
    }
}
#[test]
fn two_live_mms_map_identical_vas_to_private_bytes_and_share_only_explicit_edges() {
    let shared_va = DATA_VA + PAGE;
    let a = code(&[(DATA_VA, None), (shared_va, Some(0x77)), (shared_va, None)]);
    let b = code(&[(DATA_VA, None), (shared_va, None), (DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&a, &b]).unwrap();
    let private_a = w.private_extent(0x41).unwrap();
    let private_b = w.private_extent(0x42).unwrap();
    let shared = w.private_extent(0x66).unwrap();
    w.map(0, DATA_VA, private_a, true).unwrap();
    w.map(1, DATA_VA, private_b, true).unwrap();
    w.map(0, shared_va, shared, true).unwrap();
    assert!(
        w.map(1, shared_va, shared, true).is_err(),
        "sharing requires the issued frame edge"
    );
    w.share_with(1, shared).unwrap();
    w.map(1, shared_va, shared, true).unwrap();
    byte(&mut w, 0, 0x41);
    byte(&mut w, 1, 0x42);
    byte(&mut w, 0, 0x77);
    byte(&mut w, 1, 0x77);
    byte(&mut w, 0, 0x77);
    byte(&mut w, 1, 0x42);
    assert_eq!(w.backing_byte(private_a).unwrap(), 0x41);
    assert_eq!(w.backing_byte(private_b).unwrap(), 0x42);
    assert_eq!(w.backing_byte(shared).unwrap(), 0x77);
    assert_eq!(
        w.slot_count(),
        4,
        "one system plus three extents, independent of MM aliases"
    );
}
#[test]
fn first_touch_faults_then_retries_on_private_backing() {
    let program = code(&[(DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&program, &program]).unwrap();
    let a = w.private_extent(0).unwrap();
    let b = w.private_extent(0x42).unwrap();
    w.map(0, DATA_VA, a, false).unwrap();
    w.map(1, DATA_VA, b, false).unwrap();
    fault(&mut w, 0, 4);
    fault(&mut w, 1, 4);
    w.first_touch(0, a).unwrap();
    w.first_touch(1, b).unwrap();
    byte(&mut w, 0, 0);
    byte(&mut w, 1, 0x42);
}
#[test]
fn cow_write_fault_breaks_to_private_bytes_without_changing_the_sibling() {
    let writer = code(&[(DATA_VA, Some(0x99))]);
    let reader = code(&[(DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&writer, &reader]).unwrap();
    let shared = w.private_extent(0x41).unwrap();
    let private = w.private_extent(0).unwrap();
    w.map(0, DATA_VA, shared, true).unwrap();
    w.share_with(1, shared).unwrap();
    w.map(1, DATA_VA, shared, true).unwrap();
    for mm in 0..2 {
        w.edit(mm, DescriptorOp::ArmCow(PageSpan::new(DATA_VA, PAGE)))
            .unwrap();
    }
    fault(&mut w, 0, 7);
    w.cow_break(0, shared, private).unwrap();
    byte(&mut w, 0, 0x99);
    byte(&mut w, 1, 0x41);
    assert_eq!(w.backing_byte(private).unwrap(), 0x99);
    assert_eq!(w.backing_byte(shared).unwrap(), 0x41);
}
#[test]
fn nx_and_readonly_violations_report_user_instruction_and_write_faults() {
    let mut jump = vec![0x48, 0xbb];
    jump.extend_from_slice(&DATA_VA.to_le_bytes());
    jump.extend_from_slice(&[0xff, 0xe3]);
    let writer = code(&[(DATA_VA, Some(0x99))]);
    let mut w = MemoryWitness::boot([&jump, &writer]).unwrap();
    let a = w.private_extent(0x41).unwrap();
    let b = w.private_extent(0x42).unwrap();
    w.map(0, DATA_VA, a, true).unwrap();
    w.map(1, DATA_VA, b, true).unwrap();
    w.edit(
        1,
        DescriptorOp::Protect {
            span: PageSpan::new(DATA_VA, PAGE),
            permissions: Permissions {
                writable: false,
                executable: false,
                user: true,
            },
        },
    )
    .unwrap();
    fault(&mut w, 0, 21);
    fault(&mut w, 1, 7);
    assert_eq!(w.backing_byte(b).unwrap(), 0x42);
}
#[test]
fn revoke_drains_loaded_translation_and_rejects_recycled_slot_edges() {
    let program = code(&[(DATA_VA, None), (DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&program, &program]).unwrap();
    let a = w.private_extent(0x41).unwrap();
    let b = w.private_extent(0x42).unwrap();
    w.map(0, DATA_VA, a, true).unwrap();
    w.map(1, DATA_VA, b, true).unwrap();
    byte(&mut w, 0, 0x41);
    byte(&mut w, 1, 0x42);
    assert!(
        w.revoke(a).is_err(),
        "a live stage-1 alias prevents physical revoke"
    );
    w.edit(0, DescriptorOp::Unmap(PageSpan::new(DATA_VA, PAGE)))
        .unwrap();
    let drains = w.drain_count;
    w.revoke(a).unwrap();
    assert_eq!(w.drain_count, drains + 1);
    fault(&mut w, 0, 4);
    byte(&mut w, 1, 0x42);
    let replacement = w.private_extent(0x99).unwrap();
    assert_eq!(replacement.slot_index(), a.slot_index());
    assert_ne!(replacement.generation(), a.generation());
    assert!(w.share_with(1, a).is_err());
    w.map(0, DATA_VA, replacement, true).unwrap();
    byte(&mut w, 0, 0x99);
}
#[test]
fn shared_revoke_requires_both_alias_unlinks_and_both_exact_context_drains() {
    let program = code(&[(DATA_VA, None), (DATA_VA, None)]);
    let mut w = MemoryWitness::boot([&program, &program]).unwrap();
    let shared = w.private_extent(0x55).unwrap();
    w.map(0, DATA_VA, shared, true).unwrap();
    w.share_with(1, shared).unwrap();
    w.map(1, DATA_VA, shared, true).unwrap();
    byte(&mut w, 0, 0x55);
    byte(&mut w, 1, 0x55);
    w.edit(0, DescriptorOp::Unmap(PageSpan::new(DATA_VA, PAGE)))
        .unwrap();
    assert!(w.revoke(shared).is_err());
    byte(&mut w, 1, 0x55);
    w.edit(1, DescriptorOp::Unmap(PageSpan::new(DATA_VA, PAGE)))
        .unwrap();
    let drains = w.drain_count;
    w.revoke(shared).unwrap();
    assert_eq!(w.drain_count, drains + 2);
    fault(&mut w, 0, 4);
}

fn cpl0_image() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-none/release/carrick-x86-cpl0")
}

fn cpl3_grant_program(data_va: u64) -> Vec<u8> {
    let mut code = Vec::new();
    // One unbound refusal followed by the 16/64/256-page owner grants. Each
    // control boundary lets the host publish only the next authenticated slot.
    for _ in 0..4 {
        code.extend_from_slice(&[0x48, 0x31, 0xff]);
        code.extend_from_slice(&[0x48, 0xb8]);
        code.extend_from_slice(&carrick_el1_abi::MM_PORTAL_GRANT_ESR.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05]);
        code.extend_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0xb8]);
        code.extend_from_slice(&carrick_x86::cpl0_entry::OBSERVE_NATIVE.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05]);
    }

    // 3. Read byte at data_va
    code.extend_from_slice(&[0x48, 0xbb]); // mov rbx, data_va
    code.extend_from_slice(&data_va.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0xb6, 0x03]); // movzx eax, byte ptr [rbx]
    code.extend_from_slice(&[0x48, 0x89, 0xc7, 0x48, 0xb8]); // mov rdi, rax; mov rax, OBSERVE_NATIVE
    code.extend_from_slice(&carrick_x86::cpl0_entry::OBSERVE_NATIVE.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]); // syscall

    code.extend_from_slice(&[0x0f, 0x0b]); // ud2
    code
}

#[test]
fn x1_shared_mm_owner() {
    use carrick_core_abi::{
        PortalGrantWindow, PortalOperation, ReservationGeneration, ReservationMm,
        ReservationProtection, ReservationRange,
    };
    use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, TableGrants,
    };
    use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
    use carrick_personality_linux::mm::LinuxReservationLayout;
    use carrick_sched_core::{SlotId, ThreadIdentity};
    use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
    use carrick_x86::cpl0_scheduler::{ContextBinding, InterruptFrame, NativeContext, XsaveArea};
    use std::num::NonZeroU64;

    let slot = SlotId::new(0);
    let mm11 = 11u64;
    let mm12 = 12u64;
    let root1 = RootGpa::page_aligned(FrameGpa::new(0x60_0000)).unwrap();
    let root2 = RootGpa::page_aligned(FrameGpa::new(0x68_0000)).unwrap();

    let p = cpl3_grant_program(DATA_VA);
    let mut carrier = Cpl0Carrier::boot_shared(&cpl0_image(), &p, slot, |zone, binding| {
        zone.drive(slot, 1);
        zone.publish_slot(slot, 11, Some(0), 0);
        zone.enter_guest(slot);

        let s1 = zone
            .spaces
            .publish_closed(mm11, root1.address().raw(), 0)
            .unwrap();
        zone.spaces.open(s1);
        let s2 = zone
            .spaces
            .publish_closed(mm12, root2.address().raw(), 0)
            .unwrap();
        zone.spaces.open(s2);

        let record = zone
            .alloc_record(ThreadIdentity {
                mm: mm11,
                tid: 41,
                serial: 101,
                generation: 5,
                ..Default::default()
            })
            .unwrap();
        zone.requeue_preempted(slot, record);
        let on_cpu = zone.switch_in(slot).unwrap();
        assert_eq!(on_cpu, record);

        let mut xsave = XsaveArea::ZERO;
        xsave.0[0..2].copy_from_slice(&0x37fu16.to_le_bytes());
        xsave.0[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        xsave.0[512..520].copy_from_slice(&3u64.to_le_bytes());

        *binding = ContextBinding {
            record: zone.record_ref(record),
            context: NativeContext {
                frame: InterruptFrame {
                    gpr: [0; 15],
                    rip: carrick_vmm_kvm::cpl0_boot::USER_CODE,
                    cs: 0x23,
                    flags: 0x202,
                    rsp: 0x3_1ff0,
                    ss: 0x1b,
                },
                address: AddressContext {
                    root: root1,
                    mm: MmGeneration::new(NonZeroU64::new(mm11).unwrap()),
                    generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
                },
                fs_base: 0x1000,
                gs_base: 0x2000,
                xsave,
            },
        };
    })
    .expect("boot shared carrier on KVM");

    // 1. Setup intermediate page tables for root1 (0x60_0000) and root2 (0x68_0000)
    // MM11: PD at 0x70_0000, PT at 0x70_1000.
    // DATA_VA = 0x4000_0000 has PDPT index 1, PD index 0, PT index 0.
    carrier
        .write_guest_bytes(0x60_1000 + 8, &(0x70_0000u64 | 7).to_le_bytes())
        .unwrap();
    carrier
        .write_guest_bytes(0x70_0000, &(0x70_1000u64 | 7).to_le_bytes())
        .unwrap();
    carrier
        .write_guest_bytes(0x70_1000, &0u64.to_le_bytes())
        .unwrap();

    // MM12: PD at 0x71_0000, PT at 0x71_1000.
    carrier
        .write_guest_bytes(0x68_1000 + 8, &(0x71_0000u64 | 7).to_le_bytes())
        .unwrap();
    carrier
        .write_guest_bytes(0x71_0000, &(0x71_1000u64 | 7).to_le_bytes())
        .unwrap();
    carrier
        .write_guest_bytes(0x71_1000, &0u64.to_le_bytes())
        .unwrap();

    // 2. Put physical backing page at GPA 0x80_0000 with byte 0x5a
    carrier
        .write_guest_bytes(0x80_0000, &[0x5a; 336 * 4096])
        .unwrap();

    // 3. Publish and admit anonymous memory for MM11 and MM12 at DATA_VA
    let table = unsafe {
        &*carrier
            .guest_ptr::<carrick_x86::cpl0_mmu::SharedReservations>(
                carrick_x86::cpl0_mmu::PROGRESS_RESERVATIONS,
            )
            .unwrap()
    };
    let r_mm11 = ReservationMm::new(mm11).unwrap();
    let r_mm12 = ReservationMm::new(mm12).unwrap();
    let layout = LinuxReservationLayout {
        heap: ReservationRange::new(4096, DATA_VA).unwrap(),
        arena: ReservationRange::new(DATA_VA, DATA_VA + 0x1000_0000).unwrap(),
        brk: 4096,
        address_limit: u64::MAX,
        data_limit: u64::MAX,
        external_address_bytes: 0,
        external_data_bytes: 0,
    };
    let zone = unsafe {
        &*carrier
            .guest_ptr::<carrick_sched_core::ZoneTables>(carrick_x86::cpl0_scheduler::PROGRESS_ZONE)
            .unwrap()
    };
    let idx1 = zone.spaces.find(mm11).unwrap().index();
    let idx2 = zone.spaces.find(mm12).unwrap().index();

    use carrick_core::mm::transaction::OwnerVenue;
    table.publish(idx1, r_mm11, layout).unwrap();
    let access1 = carrick_x86::cpl0_mmu::X86OwnerVenue::space_access(zone, SlotId::new(0));
    let mut g1 = table.lock_in(access1, idx1, r_mm11, 0).unwrap();
    g1.import(
        ReservationRange::new(DATA_VA, DATA_VA + 336 * 4096).unwrap(),
        ReservationProtection::READ_WRITE,
        true,
    )
    .unwrap();
    g1.finish_import().unwrap();
    drop(g1);

    table.publish(idx2, r_mm12, layout).unwrap();
    let access2 = carrick_x86::cpl0_mmu::X86OwnerVenue::space_access(zone, SlotId::new(0));
    let mut g2 = table.lock_in(access2, idx2, r_mm12, 0).unwrap();
    g2.import(
        ReservationRange::new(DATA_VA, DATA_VA + 4096).unwrap(),
        ReservationProtection::READ_WRITE,
        true,
    )
    .unwrap();
    g2.finish_import().unwrap();
    drop(g2);

    assert!(table.admitted(idx1, r_mm11));
    assert!(table.admitted(idx2, r_mm12));

    // 4. Bind portal slots carrier
    let portal_slots = unsafe {
        &*carrier
            .guest_ptr::<carrick_el1_abi::MmPortalSlots>(carrick_x86::cpl0_mmu::PROGRESS_PORTAL)
            .unwrap()
    };
    let grant_slot = portal_slots.grant(0).unwrap();

    let nz = |n| NonZeroU64::new(n).unwrap();
    let make_grant = |first_page: u64, pages: u64, sequence: u64| {
        let va = DATA_VA + first_page * 4096;
        let len = pages * 4096;
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: nz(mm11),
                generation: nz(sequence),
            },
            root: SubstrateGpa(0x60_0000),
            op: DescriptorOp::Prepare {
                publication: GuestLeafPublication {
                    va,
                    ipa: 0x80_0000 + first_page * 4096,
                    len,
                    writable: true,
                    executable: false,
                },
                resident: PageSpan::new(va, 4096),
                backing: BackingIdentity {
                    frame_id: nz(sequence),
                    mapping_id: nz(2),
                    owner_generation: nz(3),
                    inventory_revision: nz(4),
                },
            },
            tables: TableGrants::new(&[]).unwrap(),
        };
        let window = PortalGrantWindow {
            operation: PortalOperation {
                carrier: nz(1),
                mm: r_mm11,
                incarnation: nz(1),
                sequence: nz(sequence),
            },
            generation: ReservationGeneration::new(1).unwrap(),
            range: ReservationRange::new(va, va + len).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            fault_page: va,
            host_backing: None,
            fork_sequence: None,
        };
        (txn, window)
    };
    let [(txn, window), (txn64, window64), (txn256, window256)] = [
        make_grant(0, 16, 1),
        make_grant(16, 64, 2),
        make_grant(80, 256, 3),
    ];

    // Case 1: missing carrier authority refuses without consuming the grant.
    assert!(grant_slot.submit(window, &txn));

    let obs1 = carrier.observe(0).expect("observe 1");
    assert_eq!(
        obs1.result, 22,
        "an unbound carrier must refuse with EINVAL (22)"
    );
    let residency = unsafe {
        &*carrier
            .guest_ptr::<carrick_core_abi::FrameGrantResidencyTable>(
                carrick_x86::cpl0_mmu::PROGRESS_RESIDENCY,
            )
            .unwrap()
    };
    assert!(
        residency.lookup(mm11, DATA_VA).is_none(),
        "refused grant must not commit residency"
    );
    assert!(
        residency.lookup(mm12, DATA_VA).is_none(),
        "MM12 must not commit residency"
    );
    assert_eq!(obs1.forwarded, 0, "refusal must not generate host forwards");
    assert_eq!(
        obs1.semantic_host_exits, 0,
        "refusal must not cross the semantic host-forward boundary"
    );
    assert!(
        grant_slot.take_receipt(window, &txn).is_none(),
        "missing authority must not manufacture an owner receipt"
    );

    // Case 2: bind authority and serve the still-pending valid grant on MM11.
    portal_slots.bind_carrier(NonZeroU64::new(1).unwrap());

    let obs2 = carrier.observe(0).expect("observe 2");
    assert_eq!(obs2.result, 0, "valid grant must return 0");
    let receipt2 = grant_slot.take_receipt(window, &txn);
    assert!(
        matches!(receipt2, Some(r) if matches!(r.outcome, carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(_))),
        "valid grant must produce Applied receipt, got: {receipt2:?}"
    );
    assert!(
        residency.is_guest_committed(mm11, DATA_VA),
        "residency must be committed for MM11"
    );
    assert!(
        residency.lookup(mm12, DATA_VA).is_none(),
        "MM12 must remain uncommitted (isolation)"
    );
    assert_eq!(
        obs2.forwarded, 0,
        "served grant must have zero host forwards"
    );
    assert_eq!(
        obs2.semantic_host_exits, 0,
        "served grant must have zero semantic host forwards"
    );

    for (pages, next_window, next_txn) in [(64, window64, txn64), (256, window256, txn256)] {
        assert!(grant_slot.submit(next_window, &next_txn));
        let observation = carrier.observe(0).expect("observe scaled grant");
        assert_eq!(observation.result, 0, "{pages}-page CPL0 grant failed");
        assert_eq!(observation.semantic_host_exits, 0);
        let receipt = grant_slot.take_receipt(next_window, &next_txn);
        assert!(
            matches!(receipt, Some(r) if matches!(r.outcome, carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(_))),
            "{pages}-page grant did not complete: {receipt:?}"
        );
    }

    // Case 3: Read hardware bytes at DATA_VA after all three grant scales.
    let obs3 = carrier.observe(0).expect("observe hardware read");
    assert_eq!(
        obs3.result, 0x5a,
        "CPL3 must read the physically backed byte from CPL0 mapping"
    );
    assert!(obs3.entries[0] > 0, "nonzero owner entries required");
    assert!(
        obs3.completions[0] > 0,
        "nonzero owner completions required"
    );
    assert!(
        obs3.publications[0] > 0,
        "nonzero owner publications required"
    );
    assert_eq!(obs3.forwarded, 0, "zero semantic host forwards required");
    assert_eq!(
        obs3.semantic_host_exits, 0,
        "hardware read must have zero semantic host forwards"
    );
}
