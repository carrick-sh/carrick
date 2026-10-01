//! Hardware binding for kernel.el1.stage1-publication. Run via just test-hvf.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_aarch64::descriptor_drain::{EngineDrainVenue, apply_guest_descriptor_txns_now};
use carrick_guest_mem::GuestMemory;
use carrick_hal::{GuestVmBackend, SyscallTrap, ThreadedEngine};
use carrick_mem::{elf::SegmentPerms, memory::AddressSpace};
use carrick_mmu_core::aarch64::LiveDescriptorOwner;
use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorOp, PageSpan, TerminalEdit};
use carrick_vmm_hvf::trap::new_hvf_trap_engine;
use std::num::NonZeroU64;

struct RootBacking {
    ipa: u64,
    host: usize,
    len: usize,
}
// SAFETY: the isolated test retains the VM and its fixed root mapping for every
// access; no root retirement or concurrent host mutation is possible.
unsafe impl carrick_mmu_core::aarch64::HostArenaResolver for RootBacking {
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        (base == self.ipa && len <= self.len).then_some(self.host as *mut u8)
    }
}

#[test]
#[ignore = "requires signed HVF execution through just test-hvf"]
fn serial_host_el1_descriptor_service_executes_and_settles() {
    const ENTRY: u64 = 0x20_0000;
    const DATA: u64 = 0x40_0000;
    let code: Vec<u8> = [0xd2800ba8_u32, 0xd4000001, 0x14000000]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let image = AddressSpace::from_segments(
        ENTRY,
        [
            (
                ENTRY,
                SegmentPerms {
                    read: true,
                    write: false,
                    execute: true,
                },
                code,
                4096,
            ),
            (
                DATA,
                SegmentPerms {
                    read: true,
                    write: true,
                    execute: false,
                },
                vec![0x5a; 4096],
                4096,
            ),
        ],
    )
    .unwrap()
    .with_el0_trampoline()
    .unwrap()
    .with_el1_vectors_mailbox(false)
    .unwrap()
    .with_syscall_mailbox_arena()
    .unwrap()
    .with_carrier_maintenance_root()
    .unwrap()
    .with_fd_ceiling_control()
    .unwrap()
    .with_stage1_page_tables()
    .unwrap()
    .with_linux_initial_stack(["descriptor-service"], std::iter::empty::<&str>())
    .unwrap();
    // Entitlement denial is a failure, never a skip.
    let mut staged = new_hvf_trap_engine(&image).expect("signed HVF VM");
    let cpu = staged.snapshot_guest_state_for_publication().unwrap();
    let factory =
        carrick_vmm_hvf::hvf_aarch64_engine::persistent_executor_factory_authority(&mut staged)
            .unwrap();
    let (task, staged_cpu) = carrick_vmm_hvf::hvf_aarch64_engine::split_initial_task_engine(staged);
    drop(staged_cpu);
    let (mut lifecycle, vcpu) = factory.create_executor_parts().unwrap();
    let mut engine =
        carrick_vmm_hvf::hvf_aarch64_engine::attach_task_engine(task, &mut lifecycle, vcpu);
    engine.overlay_task_state_on_live_executor(&cpu).unwrap();
    assert_eq!(engine.next_syscall().unwrap().unwrap().number.raw(), 93);
    // Adopt the actual boot tables before transferring this isolated root.
    engine.protect_range(DATA, 4096, 3).unwrap();
    let ttbr0 = engine.live_ttbr0().unwrap();
    let root = ttbr0 & 0x0000_ffff_ffff_f000;
    let root_len = carrick_mem::memory::LINUX_PAGE_TABLES_SIZE as usize;
    let root_host = engine.vm().host_ptr(root, root_len).unwrap() as usize;
    // SAFETY: fixed root backing is retained by engine for this test's lifetime.
    unsafe {
        engine
            .page_tables()
            .bind_live_backing(std::sync::Arc::new(RootBacking {
                ipa: root,
                host: root_host,
                len: root_len,
            }));
    }
    let live_leaf = |engine: &carrick_vmm_hvf::trap::HvfTrapEngine| {
        let mut table = ttbr0 & 0x0000_ffff_ffff_f000;
        for shift in [39, 30, 21, 12] {
            let ipa = table + ((DATA >> shift) & 511) * 8;
            let ptr = engine.vm().host_ptr(ipa, 8).expect("live table backing");
            // SAFETY: mapped table word in the stopped, exclusively owned VM.
            let word = unsafe { (ptr as *const u64).read_volatile() };
            if shift == 12 || word & 3 != 3 {
                return word;
            }
            table = word & 0x0000_ffff_ffff_f000;
        }
        unreachable!()
    };
    assert_eq!(live_leaf(&engine) & (3 << 6), 1 << 6, "initial user RW");
    let region = carrick_el1_abi::get_el1_region_host_ptr();
    assert_ne!(region, 0);
    // SAFETY: this test owns the only VM; its mapped EL1 region outlives zone.
    let zone = unsafe {
        &*((region + carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            as *const carrick_el1_abi::ZoneTables)
    };
    let mm = NonZeroU64::new(77).unwrap();
    assert!(engine.select_live_descriptor_owner(LiveDescriptorOwner::Guest));
    let txn = engine
        .page_tables()
        .prepare_guest_descriptor_txn(
            mm,
            DescriptorOp::Terminal {
                span: PageSpan::new(DATA, 4096),
                edit: TerminalEdit::fork_arm(false, false, false, false, 0, 0),
            },
        )
        .unwrap();
    let slots = carrick_el1_abi::descriptor_txn_slots_host().unwrap();
    let before = live_leaf(&engine);
    let refused =
        apply_guest_descriptor_txns_now(&mut EngineDrainVenue(&mut engine), slots, &[txn]);
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("could not claim the MM")
    );
    assert_eq!(live_leaf(&engine), before, "unpublished MM cannot edit");
    assert_eq!(
        slots.submitted_for(mm.get()).count(),
        0,
        "refused submission withdrawn"
    );
    engine.abandon_el1_descriptor_txn(&txn).unwrap();
    zone.spaces.publish_closed(mm.get(), ttbr0, ttbr0).unwrap();
    let txn = engine
        .page_tables()
        .prepare_guest_descriptor_txn(mm, txn.op)
        .unwrap();
    let receipts =
        apply_guest_descriptor_txns_now(&mut EngineDrainVenue(&mut engine), slots, &[txn])
            .expect("hardware descriptor execution and exact settlement");
    assert_eq!(receipts.len(), 1);
    assert_eq!(*receipts[0].txn(), txn);
    assert_eq!(slots.submitted_for(mm.get()).count(), 0);
    assert_eq!(
        live_leaf(&engine) & (3 << 6),
        3 << 6,
        "EL1 published user RO"
    );
    // Host mutation remains fenced after successful hardware settlement.
    assert!(engine.protect_range(DATA, 4096, 3).is_err());
}
