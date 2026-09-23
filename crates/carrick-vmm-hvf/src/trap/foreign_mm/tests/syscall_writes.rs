use super::*;
use crate::trap::host_writes::HostWrites;
use carrick_guest_mem::{GuestMemory, HostVa, HostWriteGuard, HostWriteRange, MemoryError};

struct WriteFixture {
    task: HvfTaskState,
    writes: HostWrites,
    installed: InstalledMm,
}

impl WriteFixture {
    fn new() -> Self {
        let transport = CarrierForeignMmTransport::new();
        let installed = install_mm(
            &transport,
            201,
            0x9a00_6700_0000,
            0x9b00_6700_0000,
            *b"old!",
        );
        let owner = global_frame_host_owners().lock()[&installed.owners.0[1]]
            .owner()
            .clone();
        let mut task = hvpatch_neutral_task_state_for_test();
        task.mm_access = Arc::clone(&installed.state);
        task.persistent_vm_lifecycle = true;
        task.mm_root_slot = Some(installed.owners.0[0]);
        let mut row = crate::trap::thread_sibling_tests::mapped_region(
            TEST_VA,
            TEST_VA + OWNER_LEN as u64,
            installed.owners.0[1].0,
        );
        row.host_addr = owner.ptr();
        row.owner_generation = owner.generation();
        task.mappings = TaskMappingIndex::from_region(row);
        Self {
            task,
            writes: HostWrites::default(),
            installed,
        }
    }

    fn owner(&self) -> Arc<GlobalFrameHostOwner> {
        global_frame_host_owners().lock()[&self.installed.owners.0[1]]
            .owner()
            .clone()
    }

    fn range(&self, offset: usize, len: usize) -> HostWriteRange {
        HostWriteRange {
            guest: GuestVa(TEST_VA + offset as u64),
            len,
            host: HostVa(self.owner().ptr() as usize + offset),
        }
    }
}

// The production HostWrites is VM-free; this adapter supplies only the
// GuestMemory callback wiring so the public guard's failure/unwind lifecycle
// can be exercised with real carrier owners, translations and dependencies.
impl GuestMemory for WriteFixture {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        Err(MemoryError::OutOfBounds { address, length })
    }
    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.task
            .copy_guest_mapping_in(legacy_test_carrier_vm_custody(), address, address, bytes)
            .map(|_| ())
    }
    fn begin_host_write(&mut self, ranges: &[HostWriteRange]) -> Result<(), MemoryError> {
        self.writes
            .begin(&self.task, legacy_test_carrier_vm_custody(), ranges)
    }
    fn finish_host_write(&mut self, _: &[HostWriteRange]) {
        self.writes.finish();
    }
}

#[test]
fn native_code_content_host_write_guard_retains_and_revokes_all_fragments() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let mut fixture = WriteFixture::new();
    let owner = fixture.owner();
    let content = &owner.mapping.code_content;
    let a = content.observe(0, 4).unwrap();
    let b = content.observe(4096, 4).unwrap();
    let untouched = content.observe(8192, 4).unwrap();
    let ranges = [fixture.range(4095, 2)];
    let original_pins = owner.mapping.pin_count();
    let guard = HostWriteGuard::new(&mut fixture, &ranges).unwrap();
    assert!(
        !a.is_current(),
        "zero-copy admission did not revoke first page"
    );
    assert!(
        !b.is_current(),
        "zero-copy admission did not revoke second page"
    );
    assert!(untouched.is_current());
    assert_eq!(owner.mapping.pin_count(), original_pins + 1);
    assert!(matches!(
        content.observe(0, 4),
        Err(crate::trap::code_content::ContentError::WriteInProgress)
    ));
    // SAFETY: exact two-byte destination, both physical fragments retained by guard.
    unsafe {
        std::ptr::copy_nonoverlapping(b"AB".as_ptr(), ranges[0].host.raw() as *mut u8, 2);
    }
    drop(guard);
    assert_eq!(owner.mapping.pin_count(), original_pins);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(ranges[0].host.raw() as *const u8, 2) },
        b"AB"
    );
    let fresh = content.observe(0, 4).unwrap();
    let guard = HostWriteGuard::new(&mut fixture, &ranges).unwrap();
    assert!(
        !fresh.is_current(),
        "reused scratch skipped new write admission"
    );
    drop(guard);
    assert!(content.observe(0, 4).unwrap().is_current());
}

#[test]
fn native_code_content_partial_host_write_admission_rolls_back_on_error_and_unwind() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let mut fixture = WriteFixture::new();
    let owner = fixture.owner();
    let before = owner.mapping.pin_count();
    let first = fixture.range(0, 4);
    let mut stale = fixture.range(4096, 4);
    stale.host = HostVa(stale.host.raw() + 1);
    assert!(HostWriteGuard::new(&mut fixture, &[first, stale]).is_err());
    assert_eq!(
        owner.mapping.pin_count(),
        before,
        "partially admitted owner leaked"
    );
    let fresh = owner.mapping.code_content.observe(0, 4).unwrap();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owner.ptr(), 4) },
        b"old!"
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let ranges = [first];
        let _guard = HostWriteGuard::new(&mut fixture, &ranges).unwrap();
        panic!("exercise host-call unwind cleanup");
    }));
    assert!(result.is_err());
    assert!(!fresh.is_current());
    assert_eq!(owner.mapping.pin_count(), before);
    assert!(
        owner
            .mapping
            .code_content
            .observe(0, 4)
            .unwrap()
            .is_current()
    );
}

#[test]
fn native_code_content_host_write_rejects_stale_owner_permissions_and_bounds() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let mut fixture = WriteFixture::new();
    let owner = fixture.owner();
    let observed = owner.mapping.code_content.observe(0, 4).unwrap();
    let valid = fixture.range(0, 4);
    fixture.task.protections.set_no_write(TEST_VA, 4096, true);
    assert!(HostWriteGuard::new(&mut fixture, &[valid]).is_err());
    fixture.task.protections.set_no_write(TEST_VA, 4096, false);
    fixture.task.protections.set_no_access(TEST_VA, 4096, true);
    assert!(HostWriteGuard::new(&mut fixture, &[valid]).is_err());
    fixture.task.protections.set_no_access(TEST_VA, 4096, false);
    let overflow = HostWriteRange {
        guest: GuestVa(u64::MAX),
        len: 2,
        host: valid.host,
    };
    assert!(HostWriteGuard::new(&mut fixture, &[overflow]).is_err());
    let past_end = fixture.range(OWNER_LEN - 1, 2);
    assert!(HostWriteGuard::new(&mut fixture, &[past_end]).is_err());
    for generation in [owner.generation() + 1, 0] {
        let mut row = crate::trap::thread_sibling_tests::mapped_region(
            TEST_VA,
            TEST_VA + OWNER_LEN as u64,
            fixture.installed.owners.0[1].0,
        );
        row.host_addr = owner.ptr();
        row.owner_generation = generation;
        fixture.task.mappings = TaskMappingIndex::from_region(row);
        assert!(HostWriteGuard::new(&mut fixture, &[valid]).is_err());
        assert!(fixture.write_bytes_raw(TEST_VA, b"bad!").is_err());
    }
    assert!(observed.is_current());
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owner.ptr(), 4) },
        b"old!"
    );
}

#[test]
fn native_code_content_host_write_rejects_changed_second_leaf_and_releases_pin() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let mut fixture = WriteFixture::new();
    let owner = fixture.owner();
    let pins = owner.mapping.pin_count();
    let range = fixture.range(4095, 2);
    let authority = fixture.task.page_tables_authority();
    let mut tables = authority.snapshot_image().unwrap();
    // The original task row and selected host pointer remain contiguous, but
    // the live second leaf now aliases the first physical page.
    tables
        .map_aliased(
            TEST_VA + 4096,
            fixture.installed.owners.0[1].0,
            4096,
            true,
            None,
        )
        .unwrap();
    authority.set_manager(tables);
    assert!(HostWriteGuard::new(&mut fixture, &[range]).is_err());
    assert_eq!(owner.mapping.pin_count(), pins);
    assert!(
        owner
            .mapping
            .code_content
            .observe(0, 4)
            .unwrap()
            .is_current()
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owner.ptr(), 4) },
        b"old!"
    );
}

#[test]
fn native_code_content_syscall_alias_fallback_revokes_original_instruction_read() {
    use carrick_hal::foreign_mm::ForeignInstructionContentStatus;
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let _aliases = ExternalAliasStateRestore::capture();
    let mut fixture = WriteFixture::new();
    let owner = fixture.owner();
    let transport = CarrierForeignMmTransport::new();
    transport.register(&fixture.installed.snapshot, &fixture.installed.state);
    let mut bytes = [0; 4];
    let receipt = read_instructions_installed(&transport, &fixture.installed, &mut bytes).unwrap();
    assert_eq!(
        receipt.instruction_content_status(),
        ForeignInstructionContentStatus::UnchangedTrackedWrites
    );
    let alias_va = TEST_VA + 0x40000;
    let key = fixture.installed.owners.0[1];
    let authority = fixture.task.page_tables_authority();
    let mut tables = authority.snapshot_image().unwrap();
    tables
        .map_aliased(alias_va, key.0, OWNER_LEN as u64, false, None)
        .unwrap();
    authority.set_manager(tables);
    register_shared_alias(AliasBacking {
        start: alias_va,
        ipa: key.0,
        host_addr: owner.ptr() as usize,
        size: OWNER_LEN,
        physical_ipa: key.0,
        physical_host_addr: owner.ptr() as usize,
        physical_size: OWNER_LEN,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: alias_ownership_scope(
            GuestMappingSharing::Private,
            fixture.task.mm_root_slot,
            fixture.task.container_root,
        ),
        inventory_backing: InventoryBackingIdentity::Private(2010),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: owner.generation(),
    });
    // No task row for the writable alias: production lookup must use the
    // process-scoped registry and still invalidate the original physical page.
    fixture.write_bytes_raw(alias_va, b"new!").unwrap();
    assert_eq!(
        receipt.instruction_content_status(),
        ForeignInstructionContentStatus::Changed
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owner.ptr(), 4) },
        b"new!"
    );
}

#[test]
fn native_code_content_structural_syscall_write_uses_owner_offset_and_pin() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let size = 0x4000;
    let ipa = 0x8800_7100_0000;
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .unwrap();
    let epoch = next_structural_epoch().unwrap();
    let owner = StructuralBackingOwner::new(
        mapping,
        GlobalFrameStage2Lease::fixed(ipa, size as u64),
        epoch,
        ipa,
        size,
    )
    .unwrap();
    let identity = owner.record_identity();
    let custody = legacy_test_carrier_vm_custody();
    let mut task = hvpatch_neutral_task_state_for_test();
    let mut row = crate::trap::thread_sibling_tests::mapped_region(0x400000, 0x401000, ipa + 4096);
    row.physical_ipa = ipa;
    row.physical_size = size;
    row.host_addr = unsafe { owner.ptr().add(4096) };
    row.structural_owner = Some(Arc::clone(&owner));
    row.owner_generation = epoch.raw();
    task.mappings = TaskMappingIndex::from_region(row);
    let outside = owner.retained.mapping.code_content.observe(0, 4).unwrap();
    let dependent = owner
        .retained
        .mapping
        .code_content
        .observe(4096, 4)
        .unwrap();
    task.copy_guest_mapping_in(custody, 0x400000, 0x400000, b"new!")
        .unwrap();
    assert!(!dependent.is_current());
    assert!(outside.is_current());
    let mut writes = HostWrites::default();
    let range = HostWriteRange {
        guest: GuestVa(0x400000),
        len: 4,
        host: HostVa(owner.ptr() as usize + 4096),
    };
    writes.begin(&task, custody, &[range]).unwrap();
    assert_eq!(
        custody
            .stage2_record_snapshot(identity.record_id)
            .unwrap()
            .pin_count,
        1
    );
    writes.finish();
    assert_eq!(
        custody
            .stage2_record_snapshot(identity.record_id)
            .unwrap()
            .pin_count,
        0
    );
    drop(task);
    drop(owner);
    retry_structural_backing_identities_in_using(
        custody,
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .unwrap();
}

mod allocations {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };
    thread_local! { pub(super) static COUNT: Cell<Option<u64>> = const { Cell::new(None) }; }
    struct Allocator;
    #[global_allocator]
    static ALLOCATOR: Allocator = Allocator;
    fn count() {
        let _ = COUNT.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
    }
    // SAFETY: all allocation arguments pass unchanged to System. TLS records
    // only the measured thread and does not allocate.
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            count();
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            count();
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            count();
            unsafe { System.realloc(ptr, layout, size) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }
}

#[test]
fn syscall_code_write_cost_contract() {
    use carrick_conformance_contract::{
        Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
        SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
    };
    use sha2::{Digest, Sha256};
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let mut fixture = WriteFixture::new();
    let owner = fixture.owner();
    let range = fixture.range(0, 4);
    // Warm the reusable vector once; captures are translation setup, excluded
    // from the per-syscall writer measurement.
    fixture.begin_host_write(&[range]).unwrap();
    fixture.finish_host_write(&[range]);
    allocations::COUNT.set(Some(0));
    let control = std::hint::black_box(vec![std::hint::black_box(42u8); 64]);
    assert!(allocations::COUNT.replace(None).unwrap() > 0);
    drop(control);
    let unrelated = owner.mapping.code_content.observe(4096, 4).unwrap();
    let mut observations = Vec::new();
    for scale in [1, 8, 32, 128] {
        let mut visits = 0;
        let mut allocations = 0;
        for _ in 0..scale {
            let dependency = owner.mapping.code_content.observe(0, 4).unwrap();
            allocations::COUNT.set(Some(0));
            fixture.begin_host_write(&[range]).unwrap();
            visits += fixture.writes.visited_pages() as u64;
            unsafe {
                std::ptr::write_volatile(range.host.raw() as *mut u8, b'!');
            }
            fixture.finish_host_write(&[range]);
            allocations += allocations::COUNT.replace(None).unwrap();
            assert!(!dependency.is_current());
            assert!(unrelated.is_current());
        }
        assert_eq!(visits, scale);
        assert_eq!(allocations, 0);
        let mut work = WorkSnapshot::new();
        work.insert(WorkMetric::NativeCodeInvalidationPages, visits)
            .unwrap();
        work.insert(WorkMetric::HostHeapAllocations, allocations)
            .unwrap();
        observations.push(ContractObservation {
            contract_id: ContractId::new("kernel.mm.syscall-code-write").unwrap(),
            layer: ExecutionLayer::VmFree,
            implementation_revision: format!(
                "sha256:{:x}",
                Sha256::digest(include_bytes!("../../host_writes.rs"))
            ),
            fixture_identity: "unit:syscall-code-write".into(),
            scale,
            semantic_assertions: vec![SemanticAssertion::pass(
                "host_write_revokes_exact_backing_and_releases_every_admission",
            )],
            work: Some(work),
            timing: None,
            completeness: Completeness::Complete,
        });
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = ContractRegistry::load(root).unwrap();
    println!(
        "syscall_code_write_observations {}",
        serde_json::to_string(&observations).unwrap()
    );
    evaluate(
        registry.require("kernel.mm.syscall-code-write").unwrap(),
        &observations,
    )
    .unwrap();
}

#[test]
fn native_code_content_syscall_copy_after_cow_preserves_source_dependency() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let _aliases = ExternalAliasStateRestore::capture();
    let mut fixture = WriteFixture::new();
    let old_owner = fixture.owner();
    let unchanged = old_owner.mapping.code_content.observe(0, 4).unwrap();
    let (_authority, lease, mut invalidator) = prepare_foreign_cow(&fixture.installed);
    let cow = lease
        .break_cow(
            &mut invalidator,
            &fixture.installed.snapshot,
            GuestVa(TEST_VA),
            4,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    let key = (cow.physical_base().raw(), cow.physical_len());
    fixture.installed.owners.0.push(key);
    let owner = global_frame_host_owners().lock()[&key].owner().clone();
    let changed = owner.mapping.code_content.observe(0, 4).unwrap();
    fixture.write_bytes_raw(TEST_VA, b"new!").unwrap();
    assert!(!changed.is_current());
    assert!(unchanged.is_current());
    assert_eq!(
        unsafe { std::slice::from_raw_parts(old_owner.ptr(), 4) },
        b"old!"
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(owner.ptr(), 4) },
        b"new!"
    );
}
