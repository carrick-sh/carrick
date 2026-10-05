//! Conformance and defect witnesses for the neutral MM / fork / COW substrate.

use carrick_core::mm::fork::{
    ForkReceiptError, ForkScratch, Mapping, copy_table, rollback, validate_fork_completion,
};
use carrick_el1_abi::{
    El1MmHandle, PortalForkCompletion, PortalForkRequest, PortalForkTableArena, PortalOperation,
    ReservationGeneration, ReservationMm, ReservationNodeFlags, ReservationProtection,
    ReservationRange,
};
use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorRefusal, LiveDescriptorWords};
use carrick_mmu_core::owner_mmu::Aarch64Mmu;
use carrick_mmu_core::x86::descriptor_txn::{COW, MAY_WRITE, PRESENT, USER, WRITE};
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
        Ok(self.words.lock().unwrap().get(&pa).copied().unwrap_or(0))
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
}
