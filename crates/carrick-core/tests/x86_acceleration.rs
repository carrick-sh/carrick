//! Conformance and defect witnesses for the neutral MM / fork / COW substrate.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_core::mm::fork::{
    ForkChildRoot, ForkError, ForkParentRoot, ForkReceiptError, ForkScratch, ForkTableCursor,
    Mapping, PreparedOwnerFork, copy_table, validate_fork_completion,
};
use carrick_el1_abi::{
    CowGrant, CowGrantCompletion, CowGrantPurpose, El1MmHandle, PortalForkCompletion,
    PortalForkCustody, PortalForkRequest, PortalForkTableArena, PortalOperation,
    ReservationGeneration, ReservationMm, ReservationNodeFlags, ReservationProtection,
    ReservationRange,
};
use carrick_mmu_core::aarch64::descriptor_txn::{
    BackingIdentity, DescriptorRefusal, LiveDescriptorWords,
};
use carrick_mmu_core::owner_mmu::Aarch64Mmu;
use carrick_mmu_core::x86::descriptor_txn::{COW, MAY_WRITE, NX, PRESENT, USER, WRITE};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use core::num::NonZeroU64;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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

#[derive(Clone)]
struct TestChildRoot {
    incarnation: u64,
    admitted: bool,
    authorized: bool,
    origin: Option<PortalForkRequest>,
    finished: bool,
    retired: Arc<AtomicBool>,
}

impl ForkChildRoot for TestChildRoot {
    fn incarnation(&self) -> u64 {
        self.incarnation
    }
    fn is_admitted(&self) -> bool {
        self.admitted
    }
    fn fork_write_authorized(&mut self, _sequence: Option<NonZeroU64>) -> bool {
        self.authorized
    }
    fn authenticate_fork_origin(&mut self, request: PortalForkRequest) -> bool {
        self.origin.is_some_and(|o| o == request)
    }
    fn set_fork_origin(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        self.origin = Some(request);
        Ok(())
    }
    fn clear_fork_origin(&mut self) {
        self.origin = None;
    }
    fn publish_fork_child(&mut self, _request: PortalForkRequest) {}
    fn finish_fork_publication(&mut self, _operation: PortalOperation) -> Result<(), ForkError> {
        self.finished = true;
        Ok(())
    }
    fn retire(self) -> Result<(), ForkError> {
        self.retired.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone)]
struct TestParentRoot {
    incarnation: u64,
    generation: ReservationGeneration,
    sequence: u64,
    ready: bool,
    authorized: bool,
    finished: bool,
}

impl ForkParentRoot<TestChildRoot> for TestParentRoot {
    fn incarnation(&self) -> u64 {
        self.incarnation
    }
    fn generation(&self) -> ReservationGeneration {
        self.generation
    }
    fn operation_sequence(&self) -> u64 {
        self.sequence
    }
    fn fork_ready(&mut self) -> bool {
        self.ready
    }
    fn fork_write_authorized(&mut self, _sequence: Option<NonZeroU64>) -> bool {
        self.authorized
    }
    fn reserve_fork_certificate(&mut self, _request: PortalForkRequest) -> Result<(), ForkError> {
        Ok(())
    }
    fn clone_into(&mut self, _child: &mut TestChildRoot) -> Result<(), ForkError> {
        Ok(())
    }
    fn publish_fork_parent(&mut self, _request: PortalForkRequest) -> ReservationGeneration {
        self.generation
    }
    fn finish_fork_publication(&mut self, _operation: PortalOperation) -> Result<(), ForkError> {
        self.finished = true;
        Ok(())
    }
    fn commit_fork_generation(&mut self) -> Result<ReservationGeneration, ForkError> {
        let next = ReservationGeneration::new(self.generation.raw() + 1).unwrap();
        self.generation = next;
        Ok(next)
    }
}

struct LinuxForkPolicy;

impl carrick_core::mm::fork::MappingInheritancePolicy for LinuxForkPolicy {
    fn inheritance_policy(&self, mapping: &Mapping) -> carrick_core::mm::fork::Policy {
        if mapping.flags.contains(ReservationNodeFlags::DONTFORK) {
            carrick_core::mm::fork::Policy::Omit
        } else if mapping.flags.contains(ReservationNodeFlags::WIPEONFORK) {
            carrick_core::mm::fork::Policy::Wipe
        } else if mapping.flags.contains(ReservationNodeFlags::PRIVATE) {
            carrick_core::mm::fork::Policy::Private
        } else {
            carrick_core::mm::fork::Policy::Keep
        }
    }

    fn is_shared(&self, mapping: &Mapping) -> bool {
        !mapping.flags.contains(ReservationNodeFlags::PRIVATE)
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
    copy_table::<X86Mmu, _, _>(
        &LinuxForkPolicy,
        &mem,
        req,
        &mut scratch,
        ForkTableCursor {
            table: root_pa,
            level: 0,
            base: 0,
            child_offset: 0,
        },
    )
    .unwrap();

    // Check that parent leaf was armed for COW: WRITE removed, COW | MAY_WRITE added
    let (parent_edit_before, parent_edit_after) = {
        let parent_edit = scratch.edits.iter().find(|e| e.pa == l1_pa).unwrap();
        (parent_edit.before, parent_edit.after)
    };
    assert_eq!(parent_edit_before, original_leaf);
    assert_eq!(parent_edit_after & WRITE, 0, "parent write bit cleared");
    assert_eq!(
        parent_edit_after & (COW | MAY_WRITE),
        COW | MAY_WRITE,
        "parent armed with COW | MAY_WRITE"
    );

    // Retained custody check
    let prepared = PreparedOwnerFork::<X86Mmu>::new(req, root_pa, scratch);
    assert_eq!(prepared.custody().len(), 1);
    assert!(
        matches!(prepared.custody()[0], PortalForkCustody::Frame { ipa, .. } if ipa == leaf_pa),
        "prepared fork must retain custody of private frame"
    );

    // Publish fork child transaction
    let child_retired = Arc::new(AtomicBool::new(false));
    let child_root = TestChildRoot {
        incarnation: 1,
        admitted: false,
        authorized: true,
        origin: None,
        finished: false,
        retired: child_retired.clone(),
    };
    let parent_root = TestParentRoot {
        incarnation: 1,
        generation: ReservationGeneration::new(5).unwrap(),
        sequence: 1,
        ready: true,
        authorized: true,
        finished: false,
    };
    let mut unpublished = prepared
        .publish(&mem, parent_root.clone(), child_root.clone(), child_handle)
        .unwrap();

    // Verify publish applied the COW edits to live memory
    assert_eq!(
        mem.load(l1_pa).unwrap(),
        parent_edit_after,
        "publish applied descriptor edits to live table"
    );

    // Stale-child control defect witness: abort and commit must reject an unauthenticated child
    let unauthenticated_child = TestChildRoot {
        origin: None,
        ..child_root.clone()
    };
    let mut stale_attempt = unpublished.clone();
    assert_eq!(
        stale_attempt.abort(&mem, parent_root.clone(), unauthenticated_child.clone()),
        Err(ForkError::Stale),
        "abort must fail with Stale when child does not authenticate origin"
    );
    assert_eq!(
        stale_attempt.commit(parent_root.clone(), unauthenticated_child),
        Err(ForkError::Stale),
        "commit must fail with Stale when child does not authenticate origin"
    );

    // Simulate parent write fault: parent resolves COW write to new page (0x50_0000)
    let new_ipa = 0x50_0000;
    let new_leaf = new_ipa | PRESENT | WRITE | USER | MAY_WRITE;
    mem.store(l1_pa, new_leaf);

    // Injected defect: Calling abort before reconciliation must fail
    // Rollback will detect live memory modified by un-reconciled write
    let mut unreconciled_child = unpublished.clone();
    let unrec_child_root = TestChildRoot {
        origin: Some(req),
        ..child_root.clone()
    };
    assert_eq!(
        unreconciled_child.abort(&mem, parent_root.clone(), unrec_child_root),
        Err(ForkError::Core),
        "abort before parent write reconciliation must fail with ForkError::Core due to rollback failure"
    );

    // Reconcile parent write with COW grant completion
    let cow_completion = CowGrantCompletion {
        purpose: CowGrantPurpose::UserWrite,
        grant: CowGrant {
            slot: 0,
            epoch: 8,
            mm_key: req.operation.mm.raw(),
            physical_ipa: new_ipa,
            backing: BackingIdentity {
                frame_id: NonZeroU64::new(1).unwrap(),
                mapping_id: NonZeroU64::new(1).unwrap(),
                owner_generation: NonZeroU64::new(1).unwrap(),
                inventory_revision: NonZeroU64::new(1).unwrap(),
            },
        },
        span_va: 0,
        span_len: 4096,
        old_ipa: leaf_pa,
        new_ipa,
    };
    assert!(cow_completion.is_well_formed());
    unpublished
        .reconcile_parent_write(&mem, cow_completion)
        .unwrap();

    // Abort after reconciliation: must succeed, retain the parent write, and retire the child
    let valid_abort_child = TestChildRoot {
        origin: Some(req),
        retired: child_retired.clone(),
        ..child_root
    };
    unpublished
        .abort(&mem, parent_root, valid_abort_child)
        .unwrap();

    // Verify parent's write was preserved in live memory
    assert_eq!(
        mem.load(l1_pa).unwrap(),
        new_leaf,
        "reconciled parent write must be preserved on abort"
    );
    // Verify child retirement
    assert!(
        child_retired.load(Ordering::SeqCst),
        "abort must retire child root"
    );
    // Verify completion status
    assert_eq!(
        unpublished.completion().child_tables_used,
        0,
        "abort clears child_tables_used"
    );
    assert_eq!(
        unpublished.completion().parent_generation,
        ReservationGeneration::new(6).unwrap(),
        "abort commits next parent generation"
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

    copy_table::<Aarch64Mmu, _, _>(
        &LinuxForkPolicy,
        &arm_mem,
        req,
        &mut arm_scratch,
        ForkTableCursor {
            table: arm_root,
            level: 0,
            base: 0,
            child_offset: 0,
        },
    )
    .unwrap();
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

    copy_table::<X86Mmu, _, _>(
        &LinuxForkPolicy,
        &perms_mem,
        req,
        &mut perms_scratch,
        ForkTableCursor {
            table: root_pa,
            level: 0,
            base: 0,
            child_offset: 0,
        },
    )
    .unwrap();

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

    // 5. Witness: uncovered x86 descriptors must use B::is_user, not ARM bit 6.
    let clean_user = 0x1000 | PRESENT | WRITE | USER;
    let pol_user =
        carrick_core::mm::fork::policy::<X86Mmu, _>(&LinuxForkPolicy, &[], 0, 4096, clean_user)
            .unwrap();
    assert_eq!(
        pol_user,
        carrick_core::mm::fork::Policy::Omit,
        "uncovered clean x86 user leaf must be omitted"
    );

    let dirty_supervisor = 0x2000 | PRESENT | WRITE | (1 << 6);
    let pol_sup = carrick_core::mm::fork::policy::<X86Mmu, _>(
        &LinuxForkPolicy,
        &[],
        0,
        4096,
        dirty_supervisor,
    )
    .unwrap();
    assert_eq!(
        pol_sup,
        carrick_core::mm::fork::Policy::Keep,
        "uncovered dirty x86 supervisor leaf must be kept"
    );
}
