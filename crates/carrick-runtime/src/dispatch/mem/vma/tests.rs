use super::super::*;
use super::*;
use crate::memory::LINUX_HEAP_BASE;

#[test]
fn boot_vma_preserves_file_subranges_and_anonymous_bss() {
    let regions = vec![ProcMapsEntry {
        start: 0x1000,
        end: 0x5000,
        read: true,
        write: true,
        execute: true,
        sharing: ProcMapSharing::Private,
        path: String::new(),
    }];
    let files = vec![
        crate::core_dump::FileMapping {
            start: 0x1000,
            end: 0x2000,
            file_page_offset: 0,
            path: "/fixture".to_owned(),
        },
        crate::core_dump::FileMapping {
            start: 0x3000,
            end: 0x4000,
            file_page_offset: 2,
            path: "/fixture".to_owned(),
        },
    ];
    let vmas = semantic_vmas_from_boot_regions(
        &regions,
        &files,
        MemoryLayout::hvf_default(),
        LINUX_HEAP_BASE,
    )
    .into_vec();
    let actual: Vec<_> = vmas
        .iter()
        .map(|vma| (vma.start, vma.end, vma.provenance, vma.file_page_offset))
        .collect();
    assert_eq!(
        actual,
        vec![
            (0x1000, 0x2000, VmaBackingProvenance::PrivateFile, Some(0)),
            (0x2000, 0x3000, VmaBackingProvenance::PrivateAnonymous, None),
            (0x3000, 0x4000, VmaBackingProvenance::PrivateFile, Some(2)),
            (0x4000, 0x5000, VmaBackingProvenance::PrivateAnonymous, None),
        ]
    );
}

#[test]
fn vma_snapshot_projects_permissions_and_splits_kernel_hidden_coverage() {
    let mut mem = MemState::new_with_layout(MemoryLayout::hvf_default());
    mem.address_space_regions = Some(vec![ProcMapsEntry {
        start: 0x1000,
        end: 0x5000,
        read: true,
        write: false,
        execute: true,
        sharing: ProcMapSharing::Private,
        path: "/fixture".to_owned(),
    }]);
    locked_ranges_insert(
        &mut mem.secretmem_maps,
        crate::vfs::GuestMemoryRange::new(GuestVa(0x2000), GuestVa(0x3000)).expect("secret range"),
    );

    assert_eq!(
        project_vma_summaries(&mem),
        vec![
            crate::kernel::VmaSummary {
                start: GuestVa(0x1000),
                end: GuestVa(0x2000),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: false,
                    executable: true,
                    kernel_visible: true,
                },
            },
            crate::kernel::VmaSummary {
                start: GuestVa(0x2000),
                end: GuestVa(0x3000),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: false,
                    executable: true,
                    kernel_visible: false,
                },
            },
            crate::kernel::VmaSummary {
                start: GuestVa(0x3000),
                end: GuestVa(0x5000),
                access: crate::kernel::VmaAccess {
                    readable: true,
                    writable: false,
                    executable: true,
                    kernel_visible: true,
                },
            },
        ]
    );
}

#[test]
fn vma_projection_preserves_adjacency_and_removes_unmapped_boot_ranges() {
    let dispatcher = SyscallDispatcher::new();
    dispatcher.set_address_space_regions(vec![
        ProcMapsEntry {
            start: 0x1000,
            end: 0x2000,
            read: true,
            write: false,
            execute: true,
            sharing: ProcMapSharing::Private,
            path: "text".to_owned(),
        },
        ProcMapsEntry {
            start: 0x2000,
            end: 0x3000,
            read: true,
            write: false,
            execute: false,
            sharing: ProcMapSharing::Private,
            path: "rodata".to_owned(),
        },
    ]);
    let before = dispatcher
        .mem()
        .snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("adjacent VMA snapshot");
    assert_eq!(before.vmas.len(), 2);

    dispatcher.with_vma_dispatch_for_test(|_vma_dispatch| {
        dispatcher.remove_mapping_metadata(0x1000, 0x1000);
    });
    let after = dispatcher
        .mem()
        .snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
        .expect("trimmed VMA snapshot");
    assert_eq!(
        after.vmas,
        vec![crate::kernel::VmaSummary {
            start: GuestVa(0x2000),
            end: GuestVa(0x3000),
            access: crate::kernel::VmaAccess {
                readable: true,
                writable: false,
                executable: false,
                kernel_visible: true,
            },
        }]
    );
}

#[test]
fn coalesce_preserves_dontdump_policy_on_subrange() {
    let mut vmas = vec![
        SemanticVma {
            start: 0x1000,
            end: 0x2000,
            read: true,
            write: true,
            execute: false,
            provenance: VmaBackingProvenance::PrivateAnonymous,
            fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
            dump_policy: carrick_abi::VmaDumpPolicy::Include,
            droppable: false,
            path: "[anon]".to_string(),
            file_page_offset: None,
        },
        SemanticVma {
            start: 0x2000,
            end: 0x4000,
            read: true,
            write: true,
            execute: false,
            provenance: VmaBackingProvenance::PrivateAnonymous,
            fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
            dump_policy: carrick_abi::VmaDumpPolicy::Include,
            droppable: false,
            path: "[anon]".to_string(),
            file_page_offset: None,
        },
    ];

    // Apply DONTDUMP to sub-range [0x2000, 0x3000) of B
    update_semantic_vma_policy(
        &mut vmas,
        0x2000,
        0x1000,
        None,
        None,
        Some(carrick_abi::VmaDumpPolicy::Omit),
    );

    // Coalesce explicitly
    coalesce_semantic_vmas(&mut vmas);

    assert_eq!(vmas.len(), 3);
    assert_eq!(vmas[0].start, 0x1000);
    assert_eq!(vmas[0].end, 0x2000);
    assert_eq!(vmas[0].dump_policy, carrick_abi::VmaDumpPolicy::Include);

    assert_eq!(vmas[1].start, 0x2000);
    assert_eq!(vmas[1].end, 0x3000);
    assert_eq!(vmas[1].dump_policy, carrick_abi::VmaDumpPolicy::Omit);

    assert_eq!(vmas[2].start, 0x3000);
    assert_eq!(vmas[2].end, 0x4000);
    assert_eq!(vmas[2].dump_policy, carrick_abi::VmaDumpPolicy::Include);
}

#[test]
fn vma_map_lifecycle_sequence() {
    let mut map = VmaMap::new();

    // 1. Initial [0x10000, 0x16000), 24 KiB (6 pages) file-backed entry
    let vma = SemanticVma {
        start: 0x10000,
        end: 0x16000,
        read: true,
        write: false,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable: false,
        path: "/bin/app".to_string(),
        file_page_offset: Some(0),
    };
    map.insert(vma)
        .expect("initial non-overlapping insert succeeds");
    assert_eq!(map.len(), 1);
    assert_eq!(map[0].start, 0x10000);
    assert_eq!(map[0].end, 0x16000);
    assert_eq!(map[0].file_page_offset, Some(0));
    assert!(map[0].read);
    assert!(!map[0].write);
    assert!(!map[0].execute);

    // 2. mprotect sub-range [0x12000, 0x15000) to RX
    map.update_prot(0x12000, 0x15000, true, false, true);
    assert_eq!(map.len(), 3);
    assert_eq!(map[0].start, 0x10000);
    assert_eq!(map[0].end, 0x12000);
    assert_eq!(map[0].file_page_offset, Some(0));
    assert!(map[0].read);
    assert!(!map[0].execute);

    assert_eq!(map[1].start, 0x12000);
    assert_eq!(map[1].end, 0x15000);
    assert_eq!(map[1].file_page_offset, Some(2));
    assert!(map[1].read);
    assert!(map[1].execute);

    assert_eq!(map[2].start, 0x15000);
    assert_eq!(map[2].end, 0x16000);
    assert_eq!(map[2].file_page_offset, Some(5));
    assert!(map[2].read);
    assert!(!map[2].execute);

    // 3. madvise sub-range [0x11000, 0x13000) with DONTFORK and DONTDUMP (straddling boundary at 0x12000)
    map.update_policy(
        0x11000,
        0x13000,
        Some(carrick_abi::VmaForkCopyPolicy::Omit),
        None,
        Some(carrick_abi::VmaDumpPolicy::Omit),
    );
    assert_eq!(map.len(), 5);
    // [0x10000, 0x11000): R, Default fork, Include dump, offset 0
    assert_eq!(map[0].start, 0x10000);
    assert_eq!(map[0].end, 0x11000);
    assert_eq!(map[0].file_page_offset, Some(0));
    assert_eq!(
        map[0].fork_policy.copy,
        carrick_abi::VmaForkCopyPolicy::Inherit
    );
    assert_eq!(map[0].dump_policy, carrick_abi::VmaDumpPolicy::Include);
    assert!(!map[0].execute);

    // [0x11000, 0x12000): R, Omit fork, Omit dump, offset 1
    assert_eq!(map[1].start, 0x11000);
    assert_eq!(map[1].end, 0x12000);
    assert_eq!(map[1].file_page_offset, Some(1));
    assert_eq!(
        map[1].fork_policy.copy,
        carrick_abi::VmaForkCopyPolicy::Omit
    );
    assert_eq!(map[1].dump_policy, carrick_abi::VmaDumpPolicy::Omit);
    assert!(!map[1].execute);

    // [0x12000, 0x13000): RX, Omit fork, Omit dump, offset 2
    assert_eq!(map[2].start, 0x12000);
    assert_eq!(map[2].end, 0x13000);
    assert_eq!(map[2].file_page_offset, Some(2));
    assert_eq!(
        map[2].fork_policy.copy,
        carrick_abi::VmaForkCopyPolicy::Omit
    );
    assert_eq!(map[2].dump_policy, carrick_abi::VmaDumpPolicy::Omit);
    assert!(map[2].execute);

    // [0x13000, 0x15000): RX, Default fork, Include dump, offset 3
    assert_eq!(map[3].start, 0x13000);
    assert_eq!(map[3].end, 0x15000);
    assert_eq!(map[3].file_page_offset, Some(3));
    assert_eq!(
        map[3].fork_policy.copy,
        carrick_abi::VmaForkCopyPolicy::Inherit
    );
    assert_eq!(map[3].dump_policy, carrick_abi::VmaDumpPolicy::Include);
    assert!(map[3].execute);

    // [0x15000, 0x16000): R, Default fork, Include dump, offset 5
    assert_eq!(map[4].start, 0x15000);
    assert_eq!(map[4].end, 0x16000);
    assert_eq!(map[4].file_page_offset, Some(5));
    assert_eq!(
        map[4].fork_policy.copy,
        carrick_abi::VmaForkCopyPolicy::Inherit
    );
    assert_eq!(map[4].dump_policy, carrick_abi::VmaDumpPolicy::Include);
    assert!(!map[4].execute);

    // 4. munmap middle [0x12000, 0x14000)
    map.remove_range(0x12000, 0x14000);
    assert_eq!(map.len(), 4);
    assert_eq!(map[0].start, 0x10000);
    assert_eq!(map[0].end, 0x11000);
    assert_eq!(map[0].file_page_offset, Some(0));

    assert_eq!(map[1].start, 0x11000);
    assert_eq!(map[1].end, 0x12000);
    assert_eq!(map[1].file_page_offset, Some(1));

    // Right fragment of [0x13000, 0x15000) shifted by unmapped 0x12000..0x14000:
    // Surviving range is [0x14000, 0x15000) with file_page_offset = 3 + (0x1000 >> 12) = 4
    assert_eq!(map[2].start, 0x14000);
    assert_eq!(map[2].end, 0x15000);
    assert_eq!(map[2].file_page_offset, Some(4));
    assert!(map[2].execute);

    assert_eq!(map[3].start, 0x15000);
    assert_eq!(map[3].end, 0x16000);
    assert_eq!(map[3].file_page_offset, Some(5));
    assert!(!map[3].execute);

    // 5. mremap [0x14000, 0x16000) to [0x20000, 0x22000)
    let captured = MremapForkSemantics::capture(&map, 0x14000, 0x2000).expect("capture succeeds");
    map.remove_range(0x14000, 0x16000);
    let remapped = captured.project(0x20000, 0x2000).expect("project succeeds");
    map.insert_many_replacing(remapped);

    assert_eq!(map.len(), 4);
    assert_eq!(map[0].start, 0x10000);
    assert_eq!(map[0].end, 0x11000);
    assert_eq!(map[1].start, 0x11000);
    assert_eq!(map[1].end, 0x12000);

    assert_eq!(map[2].start, 0x20000);
    assert_eq!(map[2].end, 0x21000);
    assert_eq!(map[2].file_page_offset, Some(4));
    assert!(map[2].execute);

    assert_eq!(map[3].start, 0x21000);
    assert_eq!(map[3].end, 0x22000);
    assert_eq!(map[3].file_page_offset, Some(5));
    assert!(!map[3].execute);

    // 6. brk grow [0x30000, 0x33000), further grow to 0x34000 (assert coalesce), then trim to 0x31000
    map.update_heap_pages(0x30000, 0x33000);
    assert_eq!(map.len(), 5);
    assert_eq!(map[4].start, 0x30000);
    assert_eq!(map[4].end, 0x33000);
    assert_eq!(map[4].path, "[heap]");
    assert_eq!(map[4].file_page_offset, None);

    // Growing heap coalesces with existing heap entry
    map.update_heap_pages(0x33000, 0x34000);
    assert_eq!(map.len(), 5);
    assert_eq!(map[4].start, 0x30000);
    assert_eq!(map[4].end, 0x34000);

    // Trimming heap shrinks range
    map.update_heap_pages(0x34000, 0x31000);
    assert_eq!(map.len(), 5);
    assert_eq!(map[4].start, 0x30000);
    assert_eq!(map[4].end, 0x31000);

    // 7. fork wipe: child drops DONTFORK VMA [0x11000, 0x12000), parent retains it
    let child = map.fork_wipe();
    // Parent still has all 5 VMAs
    assert_eq!(map.len(), 5);
    assert_eq!(map[1].start, 0x11000);
    assert_eq!(map[1].end, 0x12000);
    assert_eq!(
        map[1].fork_policy.copy,
        carrick_abi::VmaForkCopyPolicy::Omit
    );

    // Child has 4 VMAs with [0x11000, 0x12000) omitted
    assert_eq!(child.len(), 4);
    assert_eq!(child[0].start, 0x10000);
    assert_eq!(child[0].end, 0x11000);
    assert_eq!(child[1].start, 0x20000);
    assert_eq!(child[1].end, 0x21000);
    assert_eq!(child[2].start, 0x21000);
    assert_eq!(child[2].end, 0x22000);
    assert_eq!(child[3].start, 0x30000);
    assert_eq!(child[3].end, 0x31000);
}

#[test]
fn vma_map_offset_math_and_coalesce() {
    // Contiguous file_page_offset merge check:
    // VMA 1: [0x1000, 0x2000), 1 page (4096 B), offset 10
    // VMA 2: [0x2000, 0x3000), 1 page (4096 B), offset 11
    let mut map = VmaMap::new();
    let v1 = SemanticVma {
        start: 0x1000,
        end: 0x2000,
        read: true,
        write: false,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable: false,
        path: "/lib/libc.so".to_string(),
        file_page_offset: Some(10),
    };
    let v2 = SemanticVma {
        start: 0x2000,
        end: 0x3000,
        read: true,
        write: false,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable: false,
        path: "/lib/libc.so".to_string(),
        file_page_offset: Some(11),
    };
    assert!(v1.attributes().can_merge_with(&v2.attributes(), 0x1000));
    map.insert(v1).unwrap();
    map.insert(v2).unwrap();
    assert_eq!(map.len(), 1, "contiguous offsets must coalesce");
    assert_eq!(map[0].start, 0x1000);
    assert_eq!(map[0].end, 0x3000);
    assert_eq!(map[0].file_page_offset, Some(10));

    // Non-contiguous file_page_offset reject:
    // VMA 3: [0x3000, 0x4000), offset 13 (expected 12)
    let v3 = SemanticVma {
        start: 0x3000,
        end: 0x4000,
        read: true,
        write: false,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable: false,
        path: "/lib/libc.so".to_string(),
        file_page_offset: Some(13),
    };
    assert!(!map[0].attributes().can_merge_with(&v3.attributes(), 0x2000));
    map.insert(v3).unwrap();
    assert_eq!(map.len(), 2, "non-contiguous offset must reject merge");
    assert_eq!(map[0].end, 0x3000);
    assert_eq!(map[1].start, 0x3000);
    assert_eq!(map[1].file_page_offset, Some(13));

    // Mixed offset (Some vs None) reject:
    let v_anon = SemanticVma {
        start: 0x4000,
        end: 0x5000,
        read: true,
        write: false,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable: false,
        path: "/lib/libc.so".to_string(),
        file_page_offset: None,
    };
    assert!(
        !map[1]
            .attributes()
            .can_merge_with(&v_anon.attributes(), 0x1000)
    );
    map.insert(v_anon).unwrap();
    assert_eq!(map.len(), 3, "Some vs None offset must reject merge");
}

#[test]
fn vma_map_out_of_order_and_overlapping_insert() {
    let mut map = VmaMap::new();

    let make_vma = |start, end| SemanticVma {
        start,
        end,
        read: true,
        write: false,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable: false,
        path: format!("[vma-0x{start:x}]"),
        file_page_offset: None,
    };

    // Out of order inserts normalize to ascending order:
    map.insert(make_vma(0x5000, 0x6000)).unwrap();
    map.insert(make_vma(0x1000, 0x2000)).unwrap();
    map.insert(make_vma(0x3000, 0x4000)).unwrap();

    assert_eq!(map.len(), 3);
    assert_eq!(map[0].start, 0x1000);
    assert_eq!(map[1].start, 0x3000);
    assert_eq!(map[2].start, 0x5000);

    // Overlapping insert returns error and preserves state:
    let overlap_res = map.insert(make_vma(0x2800, 0x3800));
    assert_eq!(
        overlap_res,
        Err(VmaOverlapError {
            start: 0x2800,
            end: 0x3800,
        })
    );
    assert_eq!(map.len(), 3, "map must not be modified on overlap error");
    assert_eq!(map[0].start, 0x1000);
    assert_eq!(map[1].start, 0x3000);
    assert_eq!(map[2].start, 0x5000);

    // insert_replacing unmaps the overlapping portion and succeeds:
    map.insert_replacing(make_vma(0x2800, 0x3800));
    // The previous [0x3000, 0x4000) had [0x3000, 0x3800) overwritten,
    // leaving [0x3800, 0x4000) as remainder
    assert_eq!(map.len(), 4);
    assert_eq!(map[0].start, 0x1000);
    assert_eq!(map[0].end, 0x2000);
    assert_eq!(map[1].start, 0x2800);
    assert_eq!(map[1].end, 0x3800);
    assert_eq!(map[2].start, 0x3800);
    assert_eq!(map[2].end, 0x4000);
    assert_eq!(map[3].start, 0x5000);
    assert_eq!(map[3].end, 0x6000);
}

#[test]
fn vma_map_empty_and_subrange_nonexistent_operations() {
    let mut empty = VmaMap::new();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert!(empty.find(0x1000).is_none());
    assert_eq!(empty.overlapping(0x1000, 0x2000).count(), 0);

    // Empty map operations do not panic
    empty.remove_range(0x1000, 0x2000);
    empty.modify_range(0x1000, 0x2000, |_| panic!("should not be called"));
    empty.update_prot(0x1000, 0x2000, true, true, false);
    empty.update_policy(0x1000, 0x2000, None, None, None);
    empty.coalesce();
    let child = empty.fork_wipe();
    assert!(child.is_empty());
    empty.update_heap_pages(0x1000, 0x1000);
    assert!(empty.is_empty());

    // Populate one VMA
    let mut map = VmaMap::new();
    let original = SemanticVma {
        start: 0x10000,
        end: 0x12000,
        read: true,
        write: true,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable: false,
        path: "[anon]".to_string(),
        file_page_offset: None,
    };
    map.insert(original.clone()).unwrap();

    // Operations on non-existent sub-ranges are safe no-ops
    map.remove_range(0x20000, 0x22000);
    map.update_prot(0x20000, 0x22000, true, false, true);
    map.update_policy(
        0x20000,
        0x22000,
        Some(carrick_abi::VmaForkCopyPolicy::Omit),
        None,
        Some(carrick_abi::VmaDumpPolicy::Omit),
    );
    assert_eq!(map.len(), 1);
    assert_eq!(map[0], original);

    // Inverted ranges (start >= end) are safe no-ops
    map.remove_range(0x12000, 0x10000);
    map.remove_range(0x10000, 0x10000);
    map.update_prot(0x12000, 0x10000, false, false, false);
    assert_eq!(map.len(), 1);
    assert_eq!(map[0], original);
}

#[test]
fn vma_map_mutation_complexity_is_logarithmic_plus_affected() {
    let mut map = VmaMap::new();
    const COUNT: u64 = 20_000;
    const STRIDE: u64 = 0x2000; // 8 KiB stride: 4 KiB VMA + 4 KiB gap
    // Insert 20,000 disjoint VMAs: [0, 0x1000), [0x2000, 0x3000), ...
    for i in 0..COUNT {
        let start = i * STRIDE;
        let end = start + 0x1000;
        map.push(SemanticVma {
            start,
            end,
            read: true,
            write: true,
            execute: false,
            provenance: VmaBackingProvenance::PrivateAnonymous,
            fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
            dump_policy: carrick_abi::VmaDumpPolicy::Include,
            droppable: false,
            path: "[anon]".to_string(),
            file_page_offset: None,
        });
    }
    assert_eq!(map.len(), COUNT as usize);

    // Bound: for N = 20,000, log2(N) ≈ 14.3.
    // An O(log N + affected) operation with affected <= 2 should examine
    // at most 2 * ceil(log2(N)) + affected + neighbor_checks <= 2 * 15 + 2 + 2 = 34 entries.
    // We set a conservative upper bound of 100 visits.
    // The previous O(N) implementation visits all 20,000+ entries.
    const MAX_VISITS_BOUND: usize = 100;

    // 1. Insert into a gap in the middle
    let mid_start = (COUNT / 2) * STRIDE + 0x1000;
    let mid_end = mid_start + 0x800;
    VmaMap::reset_visit_count();
    map.insert(SemanticVma {
        start: mid_start,
        end: mid_end,
        read: true,
        write: true,
        execute: false,
        provenance: VmaBackingProvenance::PrivateAnonymous,
        fork_policy: carrick_abi::VmaForkPolicy::DEFAULT,
        dump_policy: carrick_abi::VmaDumpPolicy::Include,
        droppable: false,
        path: "[anon]".to_string(),
        file_page_offset: None,
    })
    .unwrap();
    let insert_visits = VmaMap::visit_count();
    assert!(
        insert_visits <= MAX_VISITS_BOUND,
        "insert visited {insert_visits} entries; expected <= {MAX_VISITS_BOUND} (O(log N))"
    );

    // 2. Modify one VMA in the middle
    let target_start = (COUNT / 2) * STRIDE;
    let target_end = target_start + 0x1000;
    VmaMap::reset_visit_count();
    map.update_prot(target_start, target_end, true, false, false);
    let modify_visits = VmaMap::visit_count();
    assert!(
        modify_visits <= MAX_VISITS_BOUND,
        "modify visited {modify_visits} entries; expected <= {MAX_VISITS_BOUND} (O(log N + affected))"
    );

    // 3. Remove that one VMA
    VmaMap::reset_visit_count();
    map.remove_range(target_start, target_end);
    let remove_visits = VmaMap::visit_count();
    assert!(
        remove_visits <= MAX_VISITS_BOUND,
        "remove visited {remove_visits} entries; expected <= {MAX_VISITS_BOUND} (O(log N + affected))"
    );
}
