//! The production reservation/permit owner, exercised over x86 descriptors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "x86_acceleration/mm_owner.rs"]
mod mm_owner;
use carrick_core::mm::transaction::{admit_service_root, serve_transfer};
use carrick_core::mm::transfer::resolver::{NoopCowResolver, NoopPreparedResolver};
use carrick_core_abi::{PortalRetainedData, PortalTransferSlot};
use carrick_el1::personality::mm_portal::test_support::*;
use carrick_el1::personality::mm_portal::*;
use carrick_mmu_core::aarch64::descriptor_txn::CallerInvalidatesAsid;
use carrick_mmu_core::x86::descriptor_txn::{NX, PRESENT, USER, WRITE};
use carrick_sched_core::AddressSpaces;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;

fn transfer_fixture(pages: usize, unrelated: usize) {
    let mut region = Region::new();
    region.add_bank();
    let spaces = AddressSpaces::new();
    let mms = [
        admit(&region, &spaces, 1, ROOT, pages, unrelated),
        admit(&region, &spaces, 2, ROOT + 0x10000, pages, 512),
    ];
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view)
        .with_mmu(carrick_mmu_core::x86::owner_mmu::X86Mmu);
    // Stable, separately owned byte buffers stand in for physical custody in
    // this VM-free test. Hardware pin/retirement acceptance is a separate gate.
    let mut backing = [vec![0u8; pages * 4096], vec![0u8; pages * 4096]];
    for (index, mm) in mms.into_iter().enumerate() {
        let tables = Tables::new(
            ROOT + index as u64 * 0x10000,
            IPA + index as u64 * 0x1000000,
            pages,
        );
        for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
            tables.words[entry].store(
                (tables.base + offset) | PRESENT | WRITE | USER,
                Ordering::Relaxed,
            );
        }
        for page in 0..pages {
            tables.words[1536 + page].store(
                (IPA + index as u64 * 0x1000000 + page as u64 * 4096) | PRESENT | WRITE | USER | NX,
                Ordering::Relaxed,
            );
        }
        let maintenance = CallerInvalidatesAsid;
        let live = tables.live(&maintenance);
        let words = CountWords {
            words: &live,
            loads: core::cell::Cell::new(0),
        };
        let mut transfer = portal
            .begin(
                portal.admitted_handle(mm, 0).unwrap(),
                GuestVa::new(VA),
                pages as u64 * 4096,
                TransferIntent::UserWrite,
                0,
            )
            .unwrap();
        for page in 0..pages {
            let step = portal
                .select(
                    &transfer,
                    &words,
                    carrick_core::mm::transaction::SelectionVenues {
                        prepared: &mut NoopPreparedResolver,
                        cow: &mut NoopCowResolver,
                        residency: &residency(),
                        slot: 0,
                    },
                )
                .unwrap();
            let TransferStep::Selected(selected) = step else {
                panic!("resident x86 owner page must be selected: {step:?}")
            };
            assert_eq!(
                selected.ipa,
                IPA + index as u64 * 0x1000000 + page as u64 * 4096
            );
            assert!(!selected.executable);
            let identity = PortalRetainedData {
                record: NonZeroU64::new((page + 1) as u64).unwrap(),
                vm_generation: NonZeroU64::new(1).unwrap(),
                owner: Some((
                    NonZeroU64::new(mm.raw()).unwrap(),
                    NonZeroU64::new(1).unwrap(),
                )),
            };
            let request = selected
                .request(TransferIntent::UserWrite, identity)
                .unwrap();
            let slot = PortalTransferSlot::new();
            let mut ticket = slot.submit(request).unwrap();
            let (service, grant) = admit_service_root(&portal, slot.claim().unwrap()).unwrap();
            assert_eq!(grant.ttbr0, tables.base);
            serve_transfer(&portal, service, &words, 0, || {
                // PREPARE has released both MM locks before host bytes move.
                assert!(region.table().el1_slot_holding(0).is_none());
                let other_editor = spaces
                    .try_begin_edit(
                        spaces.find(mm.raw()).unwrap(),
                        mm.raw(),
                        NonZeroU64::new(2).unwrap(),
                    )
                    .unwrap();
                let root = portal.root(mm, 1).unwrap();
                assert!(root.has_prepared_copy());
                drop(root);
                drop(other_editor);
                assert!(ticket.copy_requested(|copy| {
                    let authorized = copy.request();
                    assert_eq!(authorized.retained, identity);
                    assert_eq!(authorized.selected.ipa, selected.ipa);
                    let start =
                        (authorized.selected.ipa - (IPA + index as u64 * 0x1000000)) as usize;
                    let end = start + authorized.range.len() as usize;
                    backing[index][start..end].fill(0x31 + index as u8);
                    true
                }));
            })
            .unwrap();
            transfer
                .settle(request, ticket.take_completion().unwrap())
                .unwrap();
            let mut root = portal.root(mm, 0).unwrap();
            root.reap_prepared();
            assert!(!root.has_prepared_copy());
        }
        assert!(transfer.is_complete());
        assert_eq!(
            words.loads.get(),
            8 * pages,
            "two four-level walks per touched page; unrelated reservations add no descriptor work"
        );
    }
    assert!(backing[0].iter().all(|byte| *byte == 0x31));
    assert!(backing[1].iter().all(|byte| *byte == 0x32));
}

#[test]
fn x86_transfer_16_pages() {
    transfer_fixture(16, 16);
}
#[test]
fn x86_transfer_64_pages() {
    transfer_fixture(64, 16);
}
#[test]
fn x86_transfer_256_pages() {
    transfer_fixture(256, 16);
}

#[test]
fn x86_wrong_output_pin_refuses_before_preparing_copy() {
    let region = Region::new();
    let spaces = AddressSpaces::new();
    let mms = [
        admit(&region, &spaces, 1, ROOT, 1, 16),
        admit(&region, &spaces, 2, ROOT + 0x10000, 1, 16),
    ];
    let view = nodes(&region);
    let portal = MmPortal::new(NonZeroU64::new(1).unwrap(), region.table(), &spaces, &view)
        .with_mmu(carrick_mmu_core::x86::owner_mmu::X86Mmu);
    let tables = Tables::new(ROOT, IPA, 1);
    for (entry, offset) in [(0, 4096), (513, 8192), (1024, 12288)] {
        tables.words[entry].store((ROOT + offset) | PRESENT | WRITE | USER, Ordering::Relaxed);
    }
    tables.words[1536].store(IPA | PRESENT | WRITE | USER | NX, Ordering::Relaxed);
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let transfer = portal
        .begin(
            portal.admitted_handle(mms[0], 0).unwrap(),
            GuestVa::new(VA),
            4096,
            TransferIntent::UserWrite,
            0,
        )
        .unwrap();
    let TransferStep::Selected(selected) = portal
        .select(
            &transfer,
            &words,
            carrick_core::mm::transaction::SelectionVenues {
                prepared: &mut NoopPreparedResolver,
                cow: &mut NoopCowResolver,
                residency: &residency(),
                slot: 0,
            },
        )
        .unwrap()
    else {
        panic!("resident page must select")
    };
    let mut request = selected
        .request(
            TransferIntent::UserWrite,
            carrick_core_abi::PortalRetainedData {
                record: NonZeroU64::new(7).unwrap(),
                vm_generation: NonZeroU64::new(1).unwrap(),
                owner: Some((NonZeroU64::new(3).unwrap(), NonZeroU64::new(1).unwrap())),
            },
        )
        .unwrap();
    request.selected.ipa += 0x1000000; // same VA, peer physical output
    assert!(
        prepare_transfer(&portal, request, &words, 0)
            .unwrap()
            .is_none()
    );
    assert!(
        !region
            .table()
            .lock(spaces.find(mms[0].raw()).unwrap().index(), mms[0])
            .unwrap()
            .has_prepared_copy()
    );
}

/// VM-free order-1 witness. CPL0 execution remains a separate integration gate.
#[test]
fn x1_shared_mm_owner() {
    mm_owner::transfer_revalidates_exact_mm_before_copy();
    mm_owner::prepared_copy_commit_and_cancel_never_acquire_held_root_or_editor();
    transfer_fixture(16, 16);
    transfer_fixture(64, 16);
    transfer_fixture(256, 16);
    x86_wrong_output_pin_refuses_before_preparing_copy();
}

mod fork_cow {
    use carrick_core::mm::fork::{
        ForkReceiptError, ForkScratch, Mapping, copy_table, rollback, validate_fork_completion,
    };
    use carrick_el1_abi::{
        El1MmHandle, PortalForkCompletion, PortalForkRequest, PortalForkTableArena,
        PortalOperation, ReservationGeneration, ReservationMm, ReservationNodeFlags,
        ReservationProtection, ReservationRange,
    };
    use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorRefusal, LiveDescriptorWords};
    use carrick_mmu_core::owner_mmu::Aarch64Mmu;
    use carrick_mmu_core::x86::descriptor_txn::{COW, MAY_WRITE, NX, PRESENT, USER, WRITE};
    use carrick_mmu_core::x86::owner_mmu::X86Mmu;
    use core::num::NonZeroU64;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct TestMemory {
        words: Mutex<BTreeMap<u64, u64>>,
    }

    impl TestMemory {
        fn new() -> Self {
            Self {
                words: Mutex::new(BTreeMap::new()),
            }
        }

        fn store(&self, addr: u64, val: u64) {
            self.words.lock().unwrap().insert(addr, val);
        }
    }

    impl LiveDescriptorWords for TestMemory {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            Ok(*self.words.lock().unwrap().get(&pa).unwrap_or(&0))
        }

        fn compare_exchange(
            &self,
            pa: u64,
            before: u64,
            after: u64,
        ) -> Result<bool, DescriptorRefusal> {
            let mut map = self.words.lock().unwrap();
            let val = map.entry(pa).or_insert(0);
            if *val == before {
                *val = after;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
            self.store(pa, value);
            Ok(())
        }

        fn publish_barrier(&self) {}
        fn invalidate_range(&self, _va: u64, _len: u64) {}
    }

    fn sample_request(parent_gen: u64) -> PortalForkRequest {
        PortalForkRequest {
            operation: PortalOperation {
                carrier: NonZeroU64::new(1).unwrap(),
                mm: ReservationMm::new(10).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            parent_generation: ReservationGeneration::new(parent_gen).unwrap(),
            child_mm: ReservationMm::new(20).unwrap(),
            child_tables: PortalForkTableArena::new(0x20_0000, 0x1_0000).unwrap(),
            parent_tables: PortalForkTableArena::new(0x30_0000, 0x1_0000).unwrap(),
            kernel_control_ipa: 0x40_0000,
        }
    }

    fn sample_child_handle(mm: u64) -> El1MmHandle {
        unsafe {
            El1MmHandle::from_admitted_owner(
                NonZeroU64::new(1).unwrap(),
                ReservationMm::new(mm).unwrap(),
                NonZeroU64::new(1).unwrap(),
            )
        }
    }

    #[test]
    fn x2_shared_fork_cow() {
        let req = sample_request(5);
        let child_handle = sample_child_handle(20);
        let initial_completion = PortalForkCompletion {
            request: req,
            child: child_handle,
            parent_generation: ReservationGeneration::new(5).unwrap(),
            child_tables_used: 4096,
            parent_tables_used: 0,
        };

        // 1. Receipt validation defect witnesses
        // Injected defect: Stale child
        let stale_child_completion = PortalForkCompletion {
            child: sample_child_handle(99),
            ..initial_completion
        };
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(stale_child_completion),
                true,
            ),
            Err(ForkReceiptError::StaleChild),
            "validate_fork_completion must reject stale or mismatched child handle"
        );

        // Injected defect: Abort without incrementing parent generation
        let unincremented_abort_completion = PortalForkCompletion {
            parent_generation: ReservationGeneration::new(5).unwrap(),
            child_tables_used: 0,
            ..initial_completion
        };
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(unincremented_abort_completion),
                false,
            ),
            Err(ForkReceiptError::InvalidAbortParentGeneration),
            "validate_fork_completion must reject abort without parent generation increment"
        );

        // Injected defect: Abort with nonzero child tables used
        let nonzero_child_abort_completion = PortalForkCompletion {
            parent_generation: ReservationGeneration::new(6).unwrap(),
            child_tables_used: 4096,
            ..initial_completion
        };
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(nonzero_child_abort_completion),
                false,
            ),
            Err(ForkReceiptError::InvalidAbortChildTables),
            "validate_fork_completion must reject abort with nonzero child tables retained"
        );

        // Valid commit validation
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(initial_completion),
                true,
            ),
            Ok(initial_completion),
            "valid commit receipt must pass"
        );

        // Valid abort validation
        let valid_abort_completion = PortalForkCompletion {
            parent_generation: ReservationGeneration::new(6).unwrap(),
            child_tables_used: 0,
            ..initial_completion
        };
        assert_eq!(
            validate_fork_completion(
                req,
                child_handle,
                initial_completion,
                Ok(valid_abort_completion),
                false,
            ),
            Ok(valid_abort_completion),
            "valid abort receipt must pass"
        );

        // 2. Fork and COW execution with X86Mmu
        let mem = TestMemory::new();
        let root_pa = 0x10_0000;
        let l3_pa = 0x10_1000;
        let l2_pa = 0x10_2000;
        let l1_pa = 0x10_3000;
        let leaf_pa = 0x10_4000;

        // Build 4-level page table for VA 0x0000_0000_0000_0000
        // PML4 -> PDPT -> PD -> PT -> 4KiB page (writable, user, present)
        mem.store(root_pa, l3_pa | PRESENT | WRITE | USER);
        mem.store(l3_pa, l2_pa | PRESENT | WRITE | USER);
        mem.store(l2_pa, l1_pa | PRESENT | WRITE | USER);
        let original_leaf = leaf_pa | PRESENT | WRITE | USER;
        mem.store(l1_pa, original_leaf);

        let mappings = vec![Mapping {
            range: ReservationRange::new(0, 0x0000_8000_0000_0000).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: true,
            flags: ReservationNodeFlags::PRIVATE,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        }];

        let mut scratch = ForkScratch::bounded(req, 1, 512 * 4, 512 * 4, 512 * 4, 512).unwrap();
        scratch.mappings = mappings;

        // Run copy_table with X86Mmu
        copy_table::<X86Mmu, _>(&mem, req, &mut scratch, root_pa, 0, 0, 0).unwrap();

        // Check that parent leaf was armed for COW: WRITE removed, COW | MAY_WRITE added
        let parent_edit = scratch.edits.iter().find(|e| e.pa == l1_pa).unwrap();
        assert_eq!(parent_edit.before, original_leaf);
        assert_eq!(parent_edit.after & WRITE, 0, "parent write bit cleared");
        assert_eq!(
            parent_edit.after & (COW | MAY_WRITE),
            COW | MAY_WRITE,
            "parent armed with COW | MAY_WRITE"
        );

        // Apply edits
        for edit in &scratch.edits {
            assert!(
                mem.compare_exchange(edit.pa, edit.before, edit.after)
                    .unwrap()
            );
        }
        assert_eq!(mem.load(l1_pa).unwrap(), parent_edit.after);

        // Injected defect: Parent write during pending fork without reconciliation
        // Rollback before reconciliation: if mem was modified by un-reconciled write
        let unreconciled_leaf = 0x50_0000 | PRESENT | WRITE | USER;
        mem.store(l1_pa, unreconciled_leaf);
        assert!(
            rollback(&mem, &scratch.edits).is_err(),
            "rollback must fail when unreconciled parent write occurs"
        );

        // Restore to edited state and verify clean rollback
        mem.store(l1_pa, parent_edit.after);
        rollback(&mem, &scratch.edits).unwrap();
        assert_eq!(
            mem.load(l1_pa).unwrap(),
            original_leaf,
            "rollback restores exact original descriptor"
        );

        // 3. Verify the same copy_table runs against Aarch64Mmu
        let arm_mem = TestMemory::new();
        let arm_root = 0x80_0000;
        let arm_l3 = 0x80_1000;
        let arm_l2 = 0x80_2000;
        let arm_l1 = 0x80_3000;
        let arm_leaf = 0x80_4000 | 3 | (1 << 6); // table descriptor / user leaf
        arm_mem.store(arm_root, arm_l3 | 3);
        arm_mem.store(arm_l3, arm_l2 | 3);
        arm_mem.store(arm_l2, arm_l1 | 3);
        arm_mem.store(arm_l1, arm_leaf);

        let mut arm_scratch = ForkScratch::bounded(req, 1, 512 * 4, 512 * 4, 512 * 4, 512).unwrap();
        arm_scratch.mappings = vec![Mapping {
            range: ReservationRange::new(0, 0x0000_8000_0000_0000).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: true,
            flags: ReservationNodeFlags::PRIVATE,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        }];

        copy_table::<Aarch64Mmu, _>(&arm_mem, req, &mut arm_scratch, arm_root, 0, 0, 0).unwrap();
        assert!(
            !arm_scratch.edits.is_empty(),
            "AArch64 copy_table runs using the exact same generic capsule"
        );

        // 4. Red-first witness: x86 table-descriptor cloning must preserve ancestor
        // permissions (NX, read-only, supervisor), never synthesize PRESENT|WRITE|USER.
        let perms_mem = TestMemory::new();
        let root_pa = 0x10_0000;
        let l3_pa = 0x10_1000;
        let l2_pa = 0x10_2000;
        let l1_pa = 0x10_3000;
        let leaf_pa = 0x10_4000;

        // L4 entry: points to L3 with NX set
        perms_mem.store(root_pa, l3_pa | PRESENT | WRITE | USER | NX);
        // L3 entry: points to L2 with read-only (WRITE cleared)
        perms_mem.store(l3_pa, l2_pa | PRESENT | USER);
        // L2 entry: points to L1 with supervisor (USER cleared)
        perms_mem.store(l2_pa, l1_pa | PRESENT | WRITE);
        // L1 entry: points to leaf
        perms_mem.store(l1_pa, leaf_pa | PRESENT | WRITE | USER);

        let mut perms_scratch = ForkScratch::bounded(req, 1, 512 * 8, 512 * 8, 512 * 8, 512).unwrap();
        perms_scratch.mappings = vec![Mapping {
            range: ReservationRange::new(0, 0x0000_8000_0000_0000).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: true,
            flags: ReservationNodeFlags::PRIVATE,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        }];

        copy_table::<X86Mmu, _>(&perms_mem, req, &mut perms_scratch, root_pa, 0, 0, 0).unwrap();

        // Check the child table descriptors created in perms_scratch.child
        // Index 0 in child root table (offset 0) points to child L3 table.
        let child_l3_desc = perms_scratch.child[0];
        assert_ne!(
            child_l3_desc & NX,
            0,
            "child table descriptor must preserve NX from parent ancestor"
        );

        // Child L3 table (offset 512) index 0 points to child L2 table.
        let child_l2_desc = perms_scratch.child[512];
        assert_eq!(
            child_l2_desc & WRITE,
            0,
            "child table descriptor must preserve read-only (no WRITE) from parent ancestor"
        );

        // Child L2 table (offset 1024) index 0 points to child L1 table.
        let child_l1_desc = perms_scratch.child[1024];
        assert_eq!(
            child_l1_desc & USER,
            0,
            "child table descriptor must preserve supervisor (no USER) from parent ancestor"
        );
    }
}
