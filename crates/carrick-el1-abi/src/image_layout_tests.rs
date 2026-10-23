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
        assert!(EL1_STACK_SIZE * EL1_STACK_SLOTS == EL1_STACKS_SIZE);
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
