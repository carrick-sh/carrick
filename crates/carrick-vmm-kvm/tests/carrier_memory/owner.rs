//! Linked CPL0 anonymous owner witnesses. Host code prepares retained hardware
//! and authentic physical grants; it never decides or applies an MM edit.
use super::cpl0_image;
use carrick_core_abi::*;
use carrick_guest_arch::*;
use carrick_mmu_core::aarch64::descriptor_txn::*;
use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
use carrick_personality_linux::mm::LinuxReservationLayout;
use carrick_sched_core::{SlotId, ThreadIdentity};
use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
use carrick_x86::cpl0_scheduler::{ContextBinding, InterruptFrame, NativeContext, XsaveArea};
use std::num::NonZeroU64;
const VA: u64 = super::DATA_VA;
const TARGET: u64 = VA + 0x20_0000;
const ROOT: u64 = 0x60_0000;
// Keep physical bytes outside bootstrap tables, IDT/stubs, stacks and metadata.
const IPA: u64 = 0x1c0_0000;
fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}

fn context(
    zone: &carrick_sched_core::ZoneTables,
    slot: SlotId,
    mm: u64,
    root: u64,
) -> ContextBinding {
    zone.drive(slot, 1);
    zone.publish_slot(slot, mm, Some(slot.raw() as u32), 0);
    zone.enter_guest(slot);
    let record = zone
        .alloc_record(ThreadIdentity {
            mm,
            tid: 41 + slot.raw() as u64,
            serial: 101 + slot.raw() as u64,
            generation: 5,
            affinity: 1 << slot.raw(),
            ..Default::default()
        })
        .unwrap();
    zone.requeue_preempted(slot, record);
    assert_eq!(zone.switch_in(slot), Some(record));
    let mut xsave = XsaveArea::ZERO;
    xsave.0[0..2].copy_from_slice(&0x37fu16.to_le_bytes());
    xsave.0[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    xsave.0[512..520].copy_from_slice(&3u64.to_le_bytes());
    ContextBinding {
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
                root: RootGpa::page_aligned(FrameGpa::new(root)).unwrap(),
                mm: MmGeneration::new(nz(mm)),
                generation: ContextGeneration::new(nz(1)),
            },
            fs_base: 0x1000,
            gs_base: 0x2000,
            xsave,
        },
    }
}

fn fixture(program: &[u8], pages: u64) -> Cpl0Carrier {
    fixture_fault_page(program, pages, VA)
}
fn fixture_fault_page(program: &[u8], pages: u64, fault_page: u64) -> Cpl0Carrier {
    let mut carrier = Cpl0Carrier::boot_shared(&cpl0_image(), program, SlotId::new(0), |zone| {
        let index = zone.spaces.publish_closed(11, ROOT, 0).unwrap();
        zone.spaces.open(index);
        context(zone, SlotId::new(0), 11, ROOT)
    })
    .unwrap();
    // DATA and destination are empty leaves in retained hardware tables.
    for (at, word) in [
        (ROOT + 4096 + 8, 0x70_0000u64 | 7),
        (0x70_0000, 0x70_1000u64 | 7),
        (0x70_0000 + 8, 0x70_2000u64 | 7),
    ] {
        carrier.write_guest_bytes(at, &word.to_le_bytes()).unwrap();
    }
    carrier
        .write_guest_bytes(IPA, &vec![0x5a; pages as usize * 4096])
        .unwrap();
    // SAFETY: fixture owns stopped, aligned carrier metadata for its whole run.
    let table = unsafe {
        &*carrier
            .guest_ptr::<carrick_x86::cpl0_mmu::SharedReservations>(
                carrick_x86::cpl0_mmu::PROGRESS_RESERVATIONS,
            )
            .unwrap()
    };
    let mm = ReservationMm::new(11).unwrap();
    let index = carrier.zone().unwrap().spaces.find(11).unwrap().index();
    table
        .publish(
            index,
            mm,
            LinuxReservationLayout {
                heap: ReservationRange::new(4096, VA).unwrap(),
                arena: ReservationRange::new(VA, VA + 0x1000_0000).unwrap(),
                brk: 4096,
                address_limit: u64::MAX,
                data_limit: u64::MAX,
                external_address_bytes: 0,
                external_data_bytes: 0,
            },
        )
        .unwrap();
    carrier.owner_bindings().unwrap().with_space_access(
        SlotId::new(0),
        &carrier.owner_transport(),
        |access| {
            let mut root = table.lock_in(access, index, mm, 0).unwrap();
            root.import(
                ReservationRange::new(VA, VA + pages * 4096).unwrap(),
                ReservationProtection::READ_WRITE,
                true,
            )
            .unwrap();
            root.finish_import().unwrap();
        },
    );
    // SAFETY: retained stopped carrier's initialized slots.
    let slots = unsafe {
        &*carrier
            .guest_ptr::<carrick_el1_abi::MmPortalSlots>(carrick_x86::cpl0_mmu::PROGRESS_PORTAL)
            .unwrap()
    };
    slots.bind_carrier(nz(1));
    let window = PortalGrantWindow {
        operation: PortalOperation {
            carrier: nz(1),
            mm,
            incarnation: nz(1),
            sequence: nz(1),
        },
        generation: ReservationGeneration::new(1).unwrap(),
        range: ReservationRange::new(VA, VA + pages * 4096).unwrap(),
        protection: ReservationProtection::READ_WRITE,
        fault_page,
        host_backing: None,
        fork_sequence: None,
    };
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: nz(11),
            generation: nz(1),
        },
        root: SubstrateGpa(ROOT),
        op: DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va: VA,
                ipa: IPA,
                len: pages * 4096,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(fault_page, 4096),
            backing: BackingIdentity {
                frame_id: nz(1),
                mapping_id: nz(2),
                owner_generation: nz(3),
                inventory_revision: nz(4),
            },
        },
        tables: TableGrants::new(&[]).unwrap(),
    };
    assert!(slots.grant(0).unwrap().submit(window, &txn));
    carrier
}

fn mov(code: &mut Vec<u8>, register: u8, value: u64) {
    code.extend_from_slice(&[0x48, register]);
    code.extend_from_slice(&value.to_le_bytes());
}
fn syscall(code: &mut Vec<u8>, nr: u64, args: &[u64]) {
    for (&reg, &value) in [0xbf, 0xbe, 0xba].iter().zip(args) {
        mov(code, reg, value);
    }
    if let Some(&value) = args.get(3) {
        code.extend_from_slice(&[0x49, 0xba]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    if let Some(&value) = args.get(4) {
        code.extend_from_slice(&[0x49, 0xb8]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    if let Some(&value) = args.get(5) {
        code.extend_from_slice(&[0x49, 0xb9]);
        code.extend_from_slice(&value.to_le_bytes());
    }
    mov(code, 0xb8, nr);
    code.extend_from_slice(&[0x0f, 0x05]);
}
fn observe_result(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x48, 0x89, 0xc7]);
    syscall(code, carrick_x86::cpl0_entry::OBSERVE_NATIVE, &[]);
}
fn read(code: &mut Vec<u8>, va: u64) {
    mov(code, 0xbb, va);
    code.extend_from_slice(&[0x0f, 0xb6, 0x03]);
}

#[test]
fn x1_shared_anonymous_edits() {
    for pages in [16, 64, 256, 512] {
        for nr in [10, 11, 25] {
            let mut program = Vec::new();
            syscall(&mut program, carrick_el1_abi::MM_PORTAL_GRANT_ESR, &[0]);
            observe_result(&mut program);
            read(&mut program, VA);
            observe_result(&mut program); // Warm the actual user TLB.
            let args = if nr == 25 {
                vec![VA, pages * 4096, pages * 4096, 3, TARGET]
            } else {
                vec![VA, pages * 4096, 1]
            };
            syscall(&mut program, nr, &args);
            observe_result(&mut program);
            if nr == 25 {
                read(&mut program, TARGET);
                observe_result(&mut program);
            }
            mov(&mut program, 0xbb, VA);
            if nr == 10 {
                program.extend_from_slice(&[0xc6, 0x03, 0x77]);
            } else {
                program.extend_from_slice(&[0x0f, 0xb6, 0x03]);
            }
            observe_result(&mut program); // Reached only when the stale mapping survives.
            let mut carrier = fixture(&program, pages);
            assert_eq!(carrier.observe(0).unwrap().result, 0);
            assert_eq!(carrier.observe(0).unwrap().result, 0x5a);
            let edit = carrier
                .observe(0)
                .expect("native Linux MM call must execute the linked owner");
            assert_eq!(edit.result, if nr == 25 { TARGET as i64 } else { 0 });
            assert_eq!(edit.entries[0], 2);
            assert_eq!(edit.completions[0], 2);
            assert_eq!(edit.semantic_host_exits, 0);
            assert!(edit.admissions[0] > 0);
            if nr == 25 {
                assert_eq!(carrier.observe(0).unwrap().result, 0x5a);
            }
            let error = carrier.observe(0).unwrap_err();
            assert!(
                error.to_string().contains("CPL0 hardware fault"),
                "actual user fault: {error}"
            );
            let record = carrier
                .take_fault(0)
                .unwrap()
                .expect("complete native hardware record");
            assert_eq!(record.vector, 14);
            assert_eq!(record.error_code, if nr == 10 { 7 } else { 4 });
            assert_eq!(record.cr2, VA);
            assert_eq!(record.cs & 3, 3);
        }
    }
}

fn invalidation(nr: u64) {
    let mut program = Vec::new();
    syscall(&mut program, carrick_el1_abi::MM_PORTAL_GRANT_ESR, &[0]);
    observe_result(&mut program);
    // No observation/host exit occurs from entry through publication. The
    // explicit native-boundary interposition primes before the source CAS and
    // checks access immediately after its real invalidation.
    let fault_page = VA + 15 * 4096;
    read(&mut program, fault_page);
    if nr == 10 {
        // Set the hardware dirty bit before owner planning: otherwise a first
        // cached write may re-walk the changed PTE merely to set D, masking a
        // missing invalidation even though read access was cached.
        program.extend_from_slice(&[0xc6, 0x03, 0x5a]);
    }
    let args = if nr == 25 {
        vec![VA, 16 * 4096, 16 * 4096, 3, TARGET]
    } else {
        vec![VA, 16 * 4096, 1]
    };
    let mut command = vec![nr];
    command.extend_from_slice(&args);
    syscall(
        &mut program,
        carrick_x86::cpl0_entry::PRIME_ANONYMOUS_NATIVE,
        &command,
    );
    if nr == 25 {
        read(&mut program, TARGET + 15 * 4096);
    }
    mov(&mut program, 0xbb, fault_page);
    if nr == 10 {
        program.extend_from_slice(&[0xc6, 0x03, 0x77]);
    } else {
        program.extend_from_slice(&[0x0f, 0xb6, 0x03]);
    }
    observe_result(&mut program);
    let mut carrier = fixture_fault_page(&program, 16, fault_page);
    assert_eq!(carrier.observe(0).unwrap().result, 0);
    let error = carrier.observe(0).unwrap_err();
    assert!(error.to_string().contains("CPL0 hardware fault"), "{error}");
    let fault = carrier.take_fault(0).unwrap().unwrap();
    assert_eq!(fault.vector, 14);
    assert_eq!(fault.cr2, fault_page);
    assert_eq!(fault.error_code, if nr == 10 { 3 } else { 0 });
    // The bounded interposition checks the native invalidation boundary before
    // later metadata work can incidentally evict the stale entry.
    assert_eq!(fault.cs & 3, 0);
}

#[test]
fn x1_shared_protect_without_host_boundary() {
    invalidation(10);
}
#[test]
fn x1_shared_unmap_without_host_boundary() {
    invalidation(11);
}
#[test]
fn x1_shared_remap_invalidation() {
    invalidation(25);
}

#[test]
fn x1_partial_grant_retirement_preserves_live_neighbor() {
    let mut program = Vec::new();
    syscall(&mut program, carrick_el1_abi::MM_PORTAL_GRANT_ESR, &[0]);
    observe_result(&mut program);
    read(&mut program, VA);
    observe_result(&mut program);
    syscall(&mut program, 11, &[VA + 4096, 4096]);
    observe_result(&mut program);
    read(&mut program, VA);
    observe_result(&mut program);
    // The resident neighbor of a partially retired 16 KiB compound retains
    // both real bytes and exact grant custody for a subsequent owner edit.
    syscall(&mut program, 10, &[VA, 4096, 1]);
    observe_result(&mut program);
    read(&mut program, VA);
    observe_result(&mut program);
    read(&mut program, VA + 4096);
    observe_result(&mut program);
    let mut carrier = fixture(&program, 4);
    assert_eq!(carrier.observe(0).unwrap().result, 0);
    assert_eq!(carrier.observe(0).unwrap().result, 0x5a);
    assert_eq!(carrier.observe(0).unwrap().result, 0);
    assert_eq!(carrier.observe(0).unwrap().result, 0x5a);
    let edit = carrier.observe(0).unwrap();
    assert_eq!(edit.result, 0);
    assert_eq!(edit.entries[0], 3);
    assert_eq!(edit.completions[0], 3);
    assert_eq!(edit.semantic_host_exits, 0);
    assert_eq!(carrier.observe(0).unwrap().result, 0x5a);
    assert!(
        carrier
            .observe(0)
            .unwrap_err()
            .to_string()
            .contains("CPL0 hardware fault")
    );
    let fault = carrier.take_fault(0).unwrap().unwrap();
    assert_eq!(fault.vector, 14);
    assert_eq!(fault.error_code, 4);
    assert_eq!(fault.cr2, VA + 4096);
}
