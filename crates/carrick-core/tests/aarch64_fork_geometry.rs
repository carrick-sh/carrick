//! AArch64 translation geometry, fork census, copy, and rollback tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_core::mm::fork::{
    ForkCapacityFailure, ForkCensus, ForkChildRoot, ForkError, ForkParentRoot, ForkScratch,
    ForkTableCursor, Mapping, MappingInheritancePolicy, Policy, PreparedOwnerFork, census_table,
    copy_table, rollback,
};
use carrick_core_abi::{
    El1MmHandle, PortalForkCustody, PortalForkRequest, PortalForkTableArena, PortalOperation,
    ReservationGeneration, ReservationMm, ReservationNodeFlags, ReservationProtection,
    ReservationRange,
};
use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorRefusal, LiveDescriptorWords};
use carrick_mmu_core::aarch64::owner_fork::{
    GRANULE_SIZE, IDENTITY_PAGE_BASE, IDENTITY_PAGE_OFFSET, IDENTITY_PAGE_SIZE,
    KERNEL_CONTROL_BASE, KERNEL_CONTROL_SPAN, LEVELS, SHIFTS, STAGE1_TABLES_ALIAS_BASE,
    STAGE1_TABLES_ALIAS_OFFSET, STAGE1_TABLES_PRIMARY_SIZE, VA_BITS,
};
use carrick_mmu_core::owner_mmu::{Aarch64Mmu, OwnerForkMmu};
use core::num::NonZeroU64;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// AArch64 descriptor bits
// Hardware bits (matching memory.rs / aarch64.rs)
const TYPE_TABLE_OR_PAGE: u64 = 0b11;
const TYPE_BLOCK: u64 = 0b01;
const AP_RW: u64 = 0b01 << 6;
const AP_RO: u64 = 0b11 << 6;
const SH_IS: u64 = 0b11 << 8;
const AF: u64 = 1 << 10;
const NON_GLOBAL: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

// Software bits (matching aarch64.rs)
const SW_EL1_COW: u64 = 1 << 55;
const SW_EL1_PRIVATE: u64 = 1 << 56;
const SW_EL1_MAY_WRITE: u64 = 1 << 57;

const USER_BLOCK_FLAGS: u64 = PXN | AF | SH_IS | AP_RW | TYPE_BLOCK;
const USER_PAGE_FLAGS: u64 = PXN | AF | SH_IS | AP_RW | TYPE_TABLE_OR_PAGE;
const KERNEL_PAGE_FLAGS: u64 = UXN | AF | SH_IS | TYPE_TABLE_OR_PAGE;

struct TestMemory {
    words: Mutex<BTreeMap<u64, u64>>,
}

#[test]
fn arm_fork_copy_reports_the_exact_exhausted_table_bound() {
    let request = sample_arm_request(1);
    let words = TestMemory::new();
    let parent_root = 0x10_0000;
    words.store(parent_root, 0x10_1000 | TYPE_TABLE_OR_PAGE);
    let mut scratch = ForkScratch::bounded(request, 0, 512, 0, 1024, 0).unwrap();
    let error = copy_table::<Aarch64Mmu, _, _>(
        &LinuxForkPolicy,
        &words,
        request,
        &mut scratch,
        ForkTableCursor {
            table: parent_root,
            level: 0,
            base: 0,
            child_offset: 0,
        },
    )
    .unwrap_err();
    assert_eq!(error, ForkError::NoMemory);
    assert_eq!(
        scratch.capacity_failure,
        Some(ForkCapacityFailure::ChildTables)
    );
}

#[test]
fn arm_fork_control_alias_maps_only_loaned_child_table_pages() {
    let mut request = sample_arm_request(1);
    let words = TestMemory::new();
    let root = 0x10_0000;
    let l1 = 0x10_1000;
    let l2 = 0x10_2000;
    words.store(root, l1 | TYPE_TABLE_OR_PAGE);
    words.store(l1 + 180 * 8, l2 | TYPE_TABLE_OR_PAGE);
    words.store(l2, KERNEL_CONTROL_BASE | AF | SH_IS | TYPE_BLOCK);

    let mut count = ForkCensus {
        child: 0,
        parent: 0,
        live: 0,
        custody: 0,
    };
    census_table::<Aarch64Mmu, _, _>(&LinuxForkPolicy, &words, &[], root, 0, 0, &mut count)
        .unwrap();
    assert_eq!(count.child, 4 * 512);
    request.child_tables = PortalForkTableArena::new(0x40_0000, (count.child * 8) as u64).unwrap();
    let mut scratch = ForkScratch::bounded(
        request,
        0,
        count.child,
        count.parent,
        count.live,
        count.custody,
    )
    .unwrap();
    copy_table::<Aarch64Mmu, _, _>(
        &LinuxForkPolicy,
        &words,
        request,
        &mut scratch,
        ForkTableCursor {
            table: root,
            level: 0,
            base: 0,
            child_offset: 0,
        },
    )
    .unwrap();
    let alias_entry = 3 * 512 + (STAGE1_TABLES_ALIAS_OFFSET >> SHIFTS[3]) as usize;
    assert_eq!(
        scratch.child[alias_entry] & Aarch64Mmu::ADDRESS_MASK,
        0x40_0000
    );
    assert_eq!(scratch.child[alias_entry + 4], 0);
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

    fn snapshot(&self) -> BTreeMap<u64, u64> {
        self.words.lock().unwrap().clone()
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

#[derive(Clone)]
struct TestChildRoot {
    incarnation: u64,
    admitted: bool,
    authorized: bool,
    origin: Arc<Mutex<Option<PortalForkRequest>>>,
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
        self.origin.lock().unwrap().is_some_and(|o| o == request)
    }
    fn set_fork_origin(&mut self, request: PortalForkRequest) -> Result<(), ForkError> {
        *self.origin.lock().unwrap() = Some(request);
        Ok(())
    }
    fn clear_fork_origin(&mut self) {
        *self.origin.lock().unwrap() = None;
    }
    fn publish_fork_child(&mut self, _request: PortalForkRequest) -> Result<(), ForkError> {
        Ok(())
    }
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
    generation: Arc<Mutex<ReservationGeneration>>,
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
        *self.generation.lock().unwrap()
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
    fn publish_fork_parent(
        &mut self,
        _request: PortalForkRequest,
    ) -> Result<ReservationGeneration, ForkError> {
        let mut current_gen = self.generation.lock().unwrap();
        let next = ReservationGeneration::new(current_gen.raw() + 1).unwrap();
        *current_gen = next;
        Ok(next)
    }
    fn finish_fork_publication(&mut self, _operation: PortalOperation) -> Result<(), ForkError> {
        self.finished = true;
        Ok(())
    }
    fn commit_fork_generation(&mut self) -> Result<ReservationGeneration, ForkError> {
        let mut current_gen = self.generation.lock().unwrap();
        let next = ReservationGeneration::new(current_gen.raw() + 1).unwrap();
        *current_gen = next;
        Ok(next)
    }
}

struct LinuxForkPolicy;

impl MappingInheritancePolicy for LinuxForkPolicy {
    fn inheritance_policy(&self, mapping: &Mapping) -> Policy {
        if mapping.flags.contains(ReservationNodeFlags::DONTFORK) {
            Policy::Omit
        } else if mapping.flags.contains(ReservationNodeFlags::WIPEONFORK) {
            Policy::Wipe
        } else if mapping.flags.contains(ReservationNodeFlags::PRIVATE) {
            Policy::Private
        } else {
            Policy::Keep
        }
    }

    fn is_shared(&self, mapping: &Mapping) -> bool {
        !mapping.flags.contains(ReservationNodeFlags::PRIVATE)
    }
}

fn sample_arm_request(parent_gen: u64) -> PortalForkRequest {
    PortalForkRequest {
        operation: PortalOperation {
            carrier: NonZeroU64::new(1).unwrap(),
            mm: ReservationMm::new(10).unwrap(),
            incarnation: NonZeroU64::new(1).unwrap(),
            sequence: NonZeroU64::new(1).unwrap(),
        },
        parent_generation: ReservationGeneration::new(parent_gen).unwrap(),
        child_mm: ReservationMm::new(20).unwrap(),
        child_tables: PortalForkTableArena::new(0x40_0000, 0x4_0000).unwrap(),
        parent_tables: PortalForkTableArena::new(0x50_0000, 0x4_0000).unwrap(),
        kernel_control_ipa: 0x60_0000,
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
fn test_arm_translation_regime_facts() {
    // Citations for authoritative ARM translation geometry:
    // TCR_EL1: crates/carrick-mem/src/arch_sysregs.rs:43-58
    // Kernel region: crates/carrick-mem/src/memory.rs:220-222
    // Memory layout: crates/carrick-mem/src/memory.rs:3369-3540
    assert_eq!(VA_BITS, 48);
    assert_eq!(GRANULE_SIZE, 4096);
    assert_eq!(LEVELS, 4);
    assert_eq!(SHIFTS, [39, 30, 21, 12]);
    assert_eq!(KERNEL_CONTROL_BASE, 180 << 30);
    assert_eq!(KERNEL_CONTROL_SPAN, 1 << 21);
    assert_eq!(STAGE1_TABLES_ALIAS_BASE, KERNEL_CONTROL_BASE + 0x2_0000);
    assert_eq!(STAGE1_TABLES_PRIMARY_SIZE, 0x1C_0000);
    assert_eq!(IDENTITY_PAGE_BASE, KERNEL_CONTROL_BASE + 0x1E_4000);
    assert_eq!(IDENTITY_PAGE_SIZE, 0x4000);
    assert_eq!(Aarch64Mmu::ADDRESS_MASK, 0x0000_ffff_ffff_f000);
    assert!(!Aarch64Mmu::is_shared_root_entry(0));
    assert!(!Aarch64Mmu::is_shared_root_entry(511));
}

#[test]
fn test_arm_fork_geometry_and_cow_lifecycle() {
    let req = sample_arm_request(1);
    let mem = TestMemory::new();

    // Four-level table hierarchy using authoritative geometry:
    // L0: 512 GiB / entry (shift 39)
    // L1: 1 GiB / entry (shift 30)
    // L2: 2 MiB / entry (shift 21)
    // L3: 4 KiB / entry (shift 12)
    let root_pa = 0x10_0000;
    let l1_pa = 0x10_1000;
    let l2_user_pa = 0x10_2000;
    let l2_kernel_pa = 0x10_3000;
    let l3_user_pa = 0x10_4000;
    let l3_kernel_pa = 0x10_5000;

    // L0[0] -> L1
    mem.store(root_pa, l1_pa | TYPE_TABLE_OR_PAGE);

    // L1[0] -> L2 user table (covers 0..1 GiB)
    mem.store(l1_pa, l2_user_pa | TYPE_TABLE_OR_PAGE);

    // L1[180] -> L2 kernel table (covers 180 GiB = KERNEL_CONTROL_BASE)
    let kernel_l1_idx = (KERNEL_CONTROL_BASE >> SHIFTS[1]) as usize;
    assert_eq!(kernel_l1_idx, 180);
    mem.store(
        l1_pa + kernel_l1_idx as u64 * 8,
        l2_kernel_pa | TYPE_TABLE_OR_PAGE,
    );

    // L2 user table:
    // Entry 0 (VA 0..2 MiB) -> L3 user table
    mem.store(l2_user_pa, l3_user_pa | TYPE_TABLE_OR_PAGE);
    // Entry 1 (VA 2 MiB..4 MiB) -> A VALID BLOCK DESCRIPTOR!
    let block_va = 1u64 << SHIFTS[2]; // 0x20_0000 (2 MiB)
    let block_output = 0x70_0000;
    let original_block = block_output | USER_BLOCK_FLAGS | SW_EL1_PRIVATE | SW_EL1_MAY_WRITE;
    mem.store(l2_user_pa + 8, original_block);

    // L3 user table:
    // Entry 16 (VA 0x1_0000, 64 KiB) -> A PRIVATE ANONYMOUS LEAF
    let priv_va = 0x1_0000u64;
    let priv_output = 0x80_0000;
    let original_priv_leaf = priv_output | USER_PAGE_FLAGS | SW_EL1_PRIVATE | SW_EL1_MAY_WRITE;
    mem.store(l3_user_pa + 16 * 8, original_priv_leaf);

    // Entry 17 (VA 0x1_1000, 68 KiB) -> A SHARED/GLOBAL MAPPING
    let shared_va = 0x1_1000u64;
    let shared_output = 0x80_1000;
    let original_shared_leaf = shared_output | USER_PAGE_FLAGS;
    mem.store(l3_user_pa + 17 * 8, original_shared_leaf);

    // L2 kernel table:
    // Entry 0 covers KERNEL_CONTROL_BASE (0x2D_0000_0000..0x2D_0020_0000) -> L3 kernel table
    mem.store(l2_kernel_pa, l3_kernel_pa | TYPE_TABLE_OR_PAGE);

    // L3 kernel table:
    // Stage-1 tables alias entry
    let alias_idx = (STAGE1_TABLES_ALIAS_OFFSET >> SHIFTS[3]) as usize; // 32
    let alias_output = 0x90_0000;
    mem.store(
        l3_kernel_pa + alias_idx as u64 * 8,
        alias_output | KERNEL_PAGE_FLAGS,
    );

    // Identity page entry
    let identity_idx = (IDENTITY_PAGE_OFFSET >> SHIFTS[3]) as usize; // 484
    let identity_output = 0x95_0000;
    mem.store(
        l3_kernel_pa + identity_idx as u64 * 8,
        identity_output | KERNEL_PAGE_FLAGS,
    );

    // Mappings setup
    let mappings = vec![
        Mapping {
            range: ReservationRange::new(priv_va, priv_va + 4096).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: true,
            flags: ReservationNodeFlags::PRIVATE,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        },
        Mapping {
            range: ReservationRange::new(shared_va, shared_va + 4096).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: false,
            flags: ReservationNodeFlags::EMPTY,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        },
        Mapping {
            range: ReservationRange::new(block_va, block_va + (1 << SHIFTS[2])).unwrap(),
            protection: ReservationProtection::READ_WRITE,
            anonymous: true,
            flags: ReservationNodeFlags::PRIVATE,
            generation: ReservationGeneration::new(1).unwrap(),
            host_backing: None,
        },
    ];

    // 1. Run census
    let mut census = ForkCensus {
        child: 0,
        parent: 0,
        live: 0,
        custody: 0,
    };
    census_table::<Aarch64Mmu, _, _>(
        &LinuxForkPolicy,
        &mem,
        &mappings,
        root_pa,
        0,
        0,
        &mut census,
    )
    .unwrap();

    // 2. Run copy
    let mut scratch = ForkScratch::bounded(
        req,
        mappings.len(),
        census.child,
        census.parent,
        census.live,
        census.custody,
    )
    .unwrap();
    scratch.mappings = mappings;

    let pre_fork_memory = mem.snapshot();

    copy_table::<Aarch64Mmu, _, _>(
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

    // Assert exact census counts
    assert_eq!(scratch.child_used, census.child, "child table budget exact");
    assert_eq!(
        scratch.parent_used, census.parent,
        "parent table budget exact"
    );
    assert_eq!(scratch.reads.len(), census.live, "live reads budget exact");
    assert_eq!(scratch.custody.len(), census.custody, "custody count exact");

    // Assert child tables are distinct from parent tables
    let child_arena_start = req.child_tables.base;
    let child_arena_end = child_arena_start + req.child_tables.len;
    fn check_child_table(
        table_offset: usize,
        level: usize,
        scratch: &ForkScratch,
        child_arena_start: u64,
        child_arena_end: u64,
    ) {
        for i in 0..512 {
            let word = scratch.child[table_offset + i];
            if level < 3 && Aarch64Mmu::is_table(word, level) {
                let next_table = word & Aarch64Mmu::ADDRESS_MASK;
                assert!(
                    next_table >= child_arena_start && next_table < child_arena_end,
                    "child table word at index {} must point to child arena: {:#x}",
                    table_offset + i,
                    next_table
                );
                assert!(
                    !(0x10_0000..=0x10_6000).contains(&next_table),
                    "child table pointer must be distinct from parent table addresses"
                );
                let next_offset = ((next_table - child_arena_start) / 8) as usize;
                check_child_table(
                    next_offset,
                    level + 1,
                    scratch,
                    child_arena_start,
                    child_arena_end,
                );
            }
        }
    }
    check_child_table(0, 0, &scratch, child_arena_start, child_arena_end);

    // Assert private leaves are COW-armed in parent edits and child table:
    // L3 private page:
    let priv_edit = scratch
        .edits
        .iter()
        .find(|e| e.pa == l3_user_pa + 16 * 8)
        .expect("private leaf edit recorded");
    assert_eq!(priv_edit.before, original_priv_leaf);
    assert_eq!(
        priv_edit.after & AP_RO,
        AP_RO,
        "parent private leaf armed read-only"
    );
    assert_ne!(
        priv_edit.after & SW_EL1_COW,
        0,
        "parent private leaf has SW_EL1_COW"
    );
    assert_ne!(
        priv_edit.after & NON_GLOBAL,
        0,
        "parent private leaf has NON_GLOBAL"
    );

    // L2 private block:
    let block_edit = scratch
        .edits
        .iter()
        .find(|e| e.pa == l2_user_pa + 8)
        .expect("private block edit recorded");
    assert_eq!(block_edit.before, original_block);
    assert_eq!(
        block_edit.after & AP_RO,
        AP_RO,
        "parent private block armed read-only"
    );
    assert_ne!(
        block_edit.after & SW_EL1_COW,
        0,
        "parent private block has SW_EL1_COW"
    );
    assert_ne!(
        block_edit.after & NON_GLOBAL,
        0,
        "parent private block has NON_GLOBAL"
    );

    // Assert shared leaf is NOT edited in parent
    assert!(
        !scratch.edits.iter().any(|e| e.pa == l3_user_pa + 17 * 8),
        "shared leaf must not have parent edits"
    );

    // Assert custody records
    assert!(
        scratch.custody.iter().any(|c| matches!(c, PortalForkCustody::Frame { ipa, shared: false, .. } if *ipa == priv_output)),
        "private page frame custody retained"
    );
    assert!(
        scratch.custody.iter().any(|c| matches!(c, PortalForkCustody::Frame { ipa, shared: true, .. } if *ipa == shared_output)),
        "shared page frame custody retained"
    );
    assert!(
        scratch.custody.iter().any(|c| matches!(c, PortalForkCustody::StructuralCopy { source_ipa, destination_ipa, len, .. }
            if *source_ipa == identity_output
                && *destination_ipa == req.kernel_control_ipa + IDENTITY_PAGE_OFFSET
                && *len == 4096)),
        "identity page structural copy custody retained"
    );

    // Publish fork
    let child_retired = Arc::new(AtomicBool::new(false));
    let child_root = TestChildRoot {
        incarnation: 1,
        admitted: false,
        authorized: true,
        origin: Arc::new(Mutex::new(None)),
        finished: false,
        retired: child_retired.clone(),
    };
    let parent_root = TestParentRoot {
        incarnation: 1,
        generation: Arc::new(Mutex::new(ReservationGeneration::new(1).unwrap())),
        sequence: 1,
        ready: true,
        authorized: true,
        finished: false,
    };
    let prepared = PreparedOwnerFork::<Aarch64Mmu>::new(req, root_pa, scratch.clone());
    let unpublished = prepared
        .publish(
            &mem,
            parent_root.clone(),
            child_root.clone(),
            sample_child_handle(20),
        )
        .unwrap();

    // Verify parent edits are live
    assert_eq!(mem.load(l3_user_pa + 16 * 8).unwrap(), priv_edit.after);
    assert_eq!(mem.load(l2_user_pa + 8).unwrap(), block_edit.after);

    // Abort and test rollback
    let mut abort_child = unpublished;
    abort_child.abort(&mem, parent_root, child_root).unwrap();

    // Bit-for-bit restoration check
    let post_rollback_memory = mem.snapshot();
    for (addr, original_word) in &pre_fork_memory {
        let current_word = post_rollback_memory.get(addr).copied().unwrap_or(0);
        assert_eq!(
            current_word, *original_word,
            "rollback must restore parent memory bit-for-bit at {addr:#x}: expected {original_word:#x}, found {current_word:#x}"
        );
    }
}

#[test]
fn test_arm_fork_break_before_make_on_block_split() {
    let req = sample_arm_request(1);
    let mem = TestMemory::new();

    let root_pa = 0x10_0000;
    let l1_pa = 0x10_1000;
    let l2_pa = 0x10_2000;

    mem.store(root_pa, l1_pa | TYPE_TABLE_OR_PAGE);
    mem.store(l1_pa, l2_pa | TYPE_TABLE_OR_PAGE);

    // Block descriptor at L2 covering 0..2 MiB
    let block_desc = 0x70_0000 | USER_BLOCK_FLAGS;
    mem.store(l2_pa, block_desc);

    // Partial private mapping covering only 0x1_0000..0x2_0000 (forces Policy::Mixed on the 2 MiB block)
    let mappings = vec![Mapping {
        range: ReservationRange::new(0x1_0000, 0x1_0000 + 4096).unwrap(),
        protection: ReservationProtection::READ_WRITE,
        anonymous: true,
        flags: ReservationNodeFlags::PRIVATE,
        generation: ReservationGeneration::new(1).unwrap(),
        host_backing: None,
    }];

    let mut census = ForkCensus {
        child: 0,
        parent: 0,
        live: 0,
        custody: 0,
    };
    census_table::<Aarch64Mmu, _, _>(
        &LinuxForkPolicy,
        &mem,
        &mappings,
        root_pa,
        0,
        0,
        &mut census,
    )
    .unwrap();

    let mut scratch = ForkScratch::bounded(
        req,
        mappings.len(),
        census.child,
        census.parent,
        census.live,
        census.custody,
    )
    .unwrap();
    scratch.mappings = mappings;

    let pre_fork_memory = mem.snapshot();

    copy_table::<Aarch64Mmu, _, _>(
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

    // Verify BBM entry was generated for the block-to-table transition in parent
    let bbm_edit = scratch
        .edits
        .iter()
        .find(|e| e.pa == l2_pa)
        .expect("parent edit for split block");
    assert_eq!(bbm_edit.before, block_desc);
    assert!(
        Aarch64Mmu::is_table(bbm_edit.after, 2),
        "after must be table descriptor"
    );
    assert_eq!(
        bbm_edit.bbm_len,
        1 << SHIFTS[2],
        "BBM length must equal block span (2 MiB)"
    );
    assert_eq!(bbm_edit.bbm_va, 0);

    // Apply edits to parent memory so rollback can roll them back
    for edit in &scratch.edits {
        mem.store(edit.pa, edit.after);
    }

    // Rollback test
    rollback(&mem, &scratch.edits).unwrap();
    let post_rollback_memory = mem.snapshot();
    for (addr, original_word) in &pre_fork_memory {
        let current_word = post_rollback_memory.get(addr).copied().unwrap_or(0);
        assert_eq!(
            current_word, *original_word,
            "BBM rollback must restore parent memory bit-for-bit at {addr:#x}"
        );
    }
}
