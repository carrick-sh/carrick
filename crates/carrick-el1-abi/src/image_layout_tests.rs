//! Loaded-image capacity and shared ARM/CPL0 aperture non-overlap contract.
use super::*;

#[test]
fn enlarged_image_and_shared_arm_x86_regions_do_not_overlap() {
    // Exercise the full authorized image capacity, not today's ELF length.
    let required_image_bytes = EL1_IMAGE_SIZE.raw();
    assert_eq!(required_image_bytes, 1536 * 1024);
    assert!(EL1_IMAGE_OFFSET + required_image_bytes <= EL1_COUNTERS_OFFSET);
    let regions = [
        (EL1_IMAGE_OFFSET, required_image_bytes),
        (EL1_COUNTERS_OFFSET, EL1_COUNTERS_SIZE),
        (EL1_STACKS_OFFSET, EL1_STACKS_SIZE),
        (EL1_CURRENT_TASKS_OFFSET, EL1_CURRENT_TASKS_SIZE),
        (EL1_BOOTSTRAP_METADATA_OFFSET, EL1_BOOTSTRAP_METADATA_SIZE),
        (EL1_HEAP_OFFSET, EL1_HEAP_SIZE),
    ];
    for base in [EL1_REGION_BASE, X86_CPL0_REGION_BASE] {
        for (i, &(offset, size)) in regions.iter().enumerate() {
            assert!(offset + size <= EL1_REGION_SIZE);
            assert!((base + offset).is_multiple_of(4096));
            for &(other, other_size) in &regions[i + 1..] {
                assert!(disjoint(base + offset, size, base + other, other_size));
            }
        }
    }
    let control = [
        (EL1_COUNTERS_OFFSET, core::mem::size_of::<Counters>() as u64),
        (
            EL1_RESERVATIONS_OFFSET,
            EL1_RESERVATIONS_END - EL1_RESERVATIONS_OFFSET,
        ),
        (
            EL1_DESCRIPTOR_TXN_OFFSET,
            core::mem::size_of::<DescriptorTxnSlots>() as u64,
        ),
        (EL1_COW_COPY_OFFSET, EL1_COW_COPY_SIZE),
        (
            EL1_SERVICE_COPY_TABLE_OFFSET,
            core::mem::size_of::<ServiceCopyTable>() as u64,
        ),
        (
            EL1_APERTURE_CONTROL_OFFSET,
            core::mem::size_of::<ApertureControl>() as u64,
        ),
        (
            EL1_MM_PORTAL_OFFSET,
            core::mem::size_of::<MmPortalSlots>() as u64,
        ),
    ];
    for (i, &(offset, size)) in control.iter().enumerate() {
        assert!(offset >= EL1_COUNTERS_OFFSET);
        assert!(offset + size <= EL1_STACKS_OFFSET);
        for &(other, other_size) in &control[i + 1..] {
            assert!(disjoint(offset, size, other, other_size));
        }
    }
    assert_eq!(EL1_COW_COPY_BASE, EL1_REGION_BASE + EL1_COW_COPY_OFFSET);
    const {
        // The shared heap holds fixed tables, not a second overlapping allocator.
        assert!(EL1_CACHE_OFFSET + EL1_CACHE_SIZE <= EL1_INOTIFY_TABLE_OFFSET);
        assert!(EL1_INOTIFY_TABLE_OFFSET + EL1_INOTIFY_TABLE_SIZE <= EL1_NAME_CACHE_OFFSET);
        assert!(EL1_NAME_CACHE_OFFSET + EL1_NAME_CACHE_SIZE <= EL1_ZONE_OFFSET);
        assert!(EL1_ZONE_OFFSET + EL1_ZONE_SIZE <= EL1_REGION_SIZE);
        assert!(EL1_STACK_STRIDE * EL1_STACK_SLOTS == EL1_STACKS_SIZE);
        assert!(EL1_REGION_BASE + EL1_REGION_SIZE <= EL1_DYNAMIC_METADATA_BASE);
        assert!(EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE <= EL1_IPC_BASE);
        assert!(disjoint(
            X86_CPL0_SUPERVISOR_IMAGE_BASE,
            X86_CPL0_SUPERVISOR_IMAGE_SIZE,
            X86_CPL0_REGION_BASE,
            EL1_REGION_SIZE
        ));
        assert!(disjoint(
            X86_CPL0_BOOTSTRAP_METADATA_BASE,
            EL1_BOOTSTRAP_METADATA_SIZE,
            X86_CPL0_REGION_BASE,
            EL1_REGION_SIZE
        ));
    }
}

#[test]
fn counters_area_occupants_include_guard_tables_and_detect_overlap() {
    let end = EL1_COUNTERS_OFFSET + EL1_COUNTERS_SIZE;
    assert_eq!(
        first_region_overlap(&EL1_COUNTERS_AREA_OCCUPANTS, EL1_COUNTERS_OFFSET, end),
        None
    );
    // The static guard tables are enumerated at their documented place:
    // from counters+0xA_4000, one page per level-3 table, within the
    // counters+0xA_4000..0xA_A000 gap the layout reserves for them.
    let guard = EL1_COUNTERS_AREA_OCCUPANTS
        .iter()
        .find(|(name, ..)| *name == "stack-guard level-3 tables")
        .expect("guard tables are declared");
    assert_eq!(guard.1, EL1_COUNTERS_OFFSET + 0xA_4000);
    assert_eq!(guard.2, EL1_STACK_TABLE_PAGES as u64 * 4096);
    assert!(guard.1 + guard.2 <= EL1_COUNTERS_OFFSET + 0xA_A000);

    // A new field squatting on any byte of the guard tables is refused, as
    // is an empty or out-of-area entry.
    let mut occupants = [("new field", 0, 0x100); 9];
    occupants[..8].copy_from_slice(&EL1_COUNTERS_AREA_OCCUPANTS);
    for squat in [guard.1, guard.1 + 0x1000, guard.1 + guard.2 - 1] {
        occupants[8] = ("new field", squat, 1);
        assert!(first_region_overlap(&occupants, EL1_COUNTERS_OFFSET, end).is_some());
    }
    occupants[8] = ("new field", guard.1 - 0x100, 0x200);
    assert!(first_region_overlap(&occupants, EL1_COUNTERS_OFFSET, end).is_some());
    occupants[8] = ("empty", end - 0x10, 0);
    assert!(first_region_overlap(&occupants, EL1_COUNTERS_OFFSET, end).is_some());
    occupants[8] = ("escapes", end - 0x10, 0x20);
    assert!(first_region_overlap(&occupants, EL1_COUNTERS_OFFSET, end).is_some());
    // A neighbour exactly adjacent to the guard tables is fine.
    occupants[8] = ("adjacent", guard.1 + guard.2, 0x10);
    assert_eq!(
        first_region_overlap(&occupants, EL1_COUNTERS_OFFSET, end),
        None
    );
}
