use super::*;
use crate::frame_pool::PreMappedFramePool;

const READ_VA: u64 = 0x6000_3000_0000;

/// One mm whose only row names a pooled global frame, the way an HVPatch
/// anonymous page does after first touch.
struct PooledReadFixture {
    custody: Arc<CarrierVmCustody>,
    pool: Arc<PreMappedFramePool>,
    key: (u64, u64),
    generation: u64,
    task: HvfTaskState,
}

impl PooledReadFixture {
    fn new(fill: u8) -> Self {
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        // One compound: whatever mm allocates next receives exactly this frame.
        let pool = Arc::new(PreMappedFramePool::new_test_fixture(1));
        let handle = pool.allocate_compound().unwrap();
        let key = (handle.ipa(), handle.len() as u64);
        let generation = register_pooled_global_frame_host_owner_in(
            &custody,
            handle,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
        .unwrap();
        let owner = Arc::clone(custody.global_frame_host_owners.lock()[&key].owner());
        // SAFETY: the freshly registered owner exclusively covers `key.1` bytes.
        unsafe { std::ptr::write_bytes(owner.ptr(), fill, key.1 as usize) };
        let mut task = hvpatch_neutral_task_state_for_test();
        task.persistent_vm_lifecycle = true;
        let mut row =
            crate::trap::thread_sibling_tests::mapped_region(READ_VA, READ_VA + key.1, key.0);
        row.host_addr = owner.ptr();
        row.owner_generation = generation;
        task.mappings = TaskMappingIndex::from_region(row);
        Self {
            custody,
            pool,
            key,
            generation,
            task,
        }
    }

    /// munmap's frame release for this mm's only reference.
    fn retire(&self) -> GlobalFrameRetirementOutcome {
        retire_global_frame_host_owner_if_generation_in_using(
            &self.custody,
            self.key.0,
            self.key.1,
            self.generation,
            &mut |_, _| panic!("the pool retains its stage-2 map"),
        )
    }
}

/// A zero-copy host read (write/send/pwritev source) obtained by mm A must
/// keep A's exact frame owned until the host call ends. Retiring it under the
/// live read handed the pooled compound to mm B, and the stale pointer then
/// disclosed B's bytes to A's host call.
#[test]
fn host_read_retains_pooled_frame_across_concurrent_munmap() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let fixture = PooledReadFixture::new(b'A');
    let len = fixture.key.1 as usize;
    let read = fixture
        .task
        .admit_host_read(&fixture.custody, READ_VA, len)
        .expect("contiguous pooled row admits a zero-copy read");
    assert_eq!(read.len(), len);

    let outcome = fixture.retire();
    assert!(
        matches!(
            outcome,
            GlobalFrameRetirementOutcome::DeferredActivePins { .. }
        ),
        "frame retired under a live host read: {outcome:?}"
    );
    let reissued = fixture.pool.allocate_compound();
    if let Some(frame) = &reissued {
        // mm B's first touch of the recycled compound.
        // SAFETY: the handle exclusively owns its compound.
        unsafe { std::ptr::write_bytes(frame.as_mut_ptr(), b'B', frame.len()) };
    }
    let mut seen = vec![0_u8; len];
    assert_eq!(read.copy_into(&mut seen), len);
    let foreign = seen.iter().filter(|byte| **byte == b'B').count();
    assert!(
        reissued.is_none(),
        "pool reissued a compound still read by a host call"
    );
    assert_eq!(foreign, 0, "host read disclosed another mm's bytes");
    assert!(seen.iter().all(|byte| *byte == b'A'));

    drop(read);
    let outcome = fixture.retire();
    assert!(
        outcome.is_retired(),
        "release of the last read pin did not let retirement finish: {outcome:?}"
    );
    assert_eq!(fixture.pool.allocated_count(), 0);
    let recycled = fixture.pool.allocate_compound().expect("recycled compound");
    // SAFETY: the handle exclusively owns its compound.
    let zeroed = unsafe { std::slice::from_raw_parts(recycled.as_ptr(), recycled.len()) }
        .iter()
        .all(|byte| *byte == 0);
    assert!(zeroed, "recycled compound kept mm A's bytes");
}

/// The per-page copy path (`read_guest_bytes_into` → `copy_guest_mapping_out`)
/// admits the same exact owner: a retired incarnation is refused rather than
/// read, and a live one is pinned only for the copy.
#[test]
fn guest_copy_out_pins_only_the_exact_live_owner() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let fixture = PooledReadFixture::new(b'A');
    let owner = Arc::clone(fixture.custody.global_frame_host_owners.lock()[&fixture.key].owner());
    let pins = owner.mapping.pin_count();
    let mut dst = [0_u8; 64];
    let view = fixture
        .task
        .copy_guest_mapping_out(&fixture.custody, READ_VA + 128, READ_VA + 128, &mut dst)
        .expect("live row selected")
        .expect("exact owner admitted");
    assert_eq!(view.start, READ_VA);
    assert!(dst.iter().all(|byte| *byte == b'A'));
    assert_eq!(owner.mapping.pin_count(), pins, "copy leaked its owner pin");

    // A row stamped with a stale generation names a previous incarnation.
    let mut task = hvpatch_neutral_task_state_for_test();
    task.persistent_vm_lifecycle = true;
    let mut row = crate::trap::thread_sibling_tests::mapped_region(
        READ_VA,
        READ_VA + fixture.key.1,
        fixture.key.0,
    );
    row.host_addr = owner.ptr();
    row.owner_generation = fixture.generation + 1;
    task.mappings = TaskMappingIndex::from_region(row);
    let mut stale = [0_u8; 64];
    assert!(
        !matches!(
            task.copy_guest_mapping_out(&fixture.custody, READ_VA, READ_VA, &mut stale),
            Some(Ok(_))
        ),
        "stale incarnation read"
    );
    assert!(
        task.admit_host_read(&fixture.custody, READ_VA, 64)
            .is_none()
    );
    assert_eq!(stale, [0_u8; 64]);
    assert_eq!(owner.mapping.pin_count(), pins);
}

/// The unpinned (untracked) branch is a checked invariant in the persistent
/// carrier: only the fixed carrier control mappings, which outlive the VM's
/// every access, may be accessed without an owner pin. Any other unstamped
/// row could be torn down by a sibling's unmap and is refused.
#[test]
fn untracked_rows_are_admitted_only_for_carrier_control_mappings() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let custody = Arc::new(CarrierVmCustody::new_live_fixture());
    let backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .unwrap();
    let row_at = |start: u64| {
        let mut row =
            crate::trap::thread_sibling_tests::mapped_region(start, start + 0x4000, start);
        row.host_addr = backing.as_ptr();
        row.owner_generation = 0;
        row
    };
    for persistent in [true, false] {
        let mut task = hvpatch_neutral_task_state_for_test();
        task.persistent_vm_lifecycle = persistent;
        let carrier = carrick_mem::memory::LINUX_EL1_MAINT_BASE;
        task.mappings = TaskMappingIndex::from_region(row_at(carrier));
        let read = task
            .admit_host_read(&custody, carrier, 16)
            .expect("carrier control mapping admits an untracked read");
        assert_eq!(read.as_ptr(), backing.as_ptr() as *const u8);
        let access = task
            .with_mapping_for_range_in(&custody, carrier, 16, |source| {
                source.begin_access(
                    crate::trap::host_writes::HostAccess::Read,
                    &task,
                    &custody,
                    carrier,
                    16,
                    None,
                )
            })
            .unwrap()
            .unwrap();
        assert!(!access.retains_owner());

        let guest = carrick_mem::memory::LINUX_ROSETTA_IPA_BASE;
        task.mappings = TaskMappingIndex::from_region(row_at(guest));
        assert_eq!(
            task.admit_host_read(&custody, guest, 16).is_some(),
            !persistent,
            "persistent={persistent}: unstamped guest row admitted without an owner pin"
        );
    }
}

/// Per-access cost of the read pin, printed for review (timing is never
/// asserted: the host is shared). Compares the pre-pin scalar selection with
/// the pinned per-page copy and the zero-copy admission, all on one 4 KiB
/// fragment of a live pooled row.
#[test]
fn read_pin_cost_microbenchmark() {
    let _lock = FOREIGN_MM_TEST_LOCK.lock();
    let fixture = PooledReadFixture::new(b'A');
    let owner = Arc::clone(fixture.custody.global_frame_host_owners.lock()[&fixture.key].owner());
    const ITERATIONS: u32 = 20_000;
    let mut dst = [0_u8; 4096];
    let time = |label: &str, op: &mut dyn FnMut()| {
        for _ in 0..1_000 {
            op();
        }
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            op();
        }
        let per = start.elapsed().as_nanos() / u128::from(ITERATIONS);
        println!("read_pin_cost {label} ns_per_op={per}");
    };
    time("unpinned_select_and_copy_4k", &mut || {
        let view = fixture
            .task
            .mapping_for_range_in(&fixture.custody, READ_VA, dst.len())
            .unwrap();
        // SAFETY: benchmark of the pre-fix shape on a fixture-owned frame.
        unsafe {
            volatile_copy_from_guest(view.host_addr, dst.as_mut_ptr(), dst.len());
        }
    });
    time("pinned_copy_out_4k", &mut || {
        fixture
            .task
            .copy_guest_mapping_out(&fixture.custody, READ_VA, READ_VA, &mut dst)
            .unwrap()
            .unwrap();
    });
    time("admit_host_read_16k_and_release", &mut || {
        let read = fixture
            .task
            .admit_host_read(&fixture.custody, READ_VA, fixture.key.1 as usize)
            .unwrap();
        std::hint::black_box(read.as_ptr());
    });
    assert!(dst.iter().all(|byte| *byte == b'A'));
    assert_eq!(owner.mapping.pin_count(), 0);
}
