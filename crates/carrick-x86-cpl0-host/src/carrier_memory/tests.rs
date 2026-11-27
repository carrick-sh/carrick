use super::test_support::TestMemoryIo;
use super::*;
#[test]
fn retained_backings_follow_committed_slot_installs() {
    let mut memory =
        CarrierMemory::new(test_support::MemoryTestIo::new(TestMemoryIo::default())).unwrap();
    let mut ram = GuestRam::new();
    ram.add_window(0x1000, PAGE as usize, crate::guest_ram::WindowKind::Private)
        .unwrap();
    memory.install_bootstrap(Arc::new(ram)).unwrap();
    let tag = NonZeroU64::new(2).unwrap();
    let backing = |gpa| PreparedBacking {
        extent: Arc::new(BackingExtent::private(FrameGpa::new(gpa), PAGE as usize).unwrap()),
        identity: BackingIdentity {
            frame_id: tag,
            mapping_id: tag,
            owner_generation: tag,
            inventory_revision: tag,
        },
    };
    let installed = backing(0x2000);
    let redundant = backing(0x1000);
    assert!(memory.install(&[installed.clone(), redundant]).is_err());
    assert_eq!(memory.retained_backings().count(), 1);
    assert_eq!(
        memory.retained_backings().next().unwrap().base.raw(),
        0x1000
    );

    memory.install(std::slice::from_ref(&installed)).unwrap();
    assert_eq!(memory.retained_backings().count(), 2);
    assert!(
        memory
            .retained_backings()
            .any(|extent| Arc::ptr_eq(extent, &installed.extent))
    );
}

#[test]
fn one_memslot_authenticates_each_inventoried_frame_independently() {
    test_support::one_memslot_authenticates_each_inventoried_frame_independently(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn carrier_publication_requires_an_already_applied_guest_edit() {
    test_support::carrier_publication_requires_an_already_applied_guest_edit(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn failed_second_memslot_install_restores_custody_and_reuses_slot_zero() {
    test_support::failed_second_memslot_install_restores_custody_and_reuses_slot_zero(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn inventory_failure_before_guest_edit_rolls_back_and_after_edit_quarantines() {
    test_support::inventory_failure_before_guest_edit_rolls_back_and_after_edit_quarantines(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn inventory_rollback_failure_quarantines_and_retains_registered_bytes() {
    test_support::inventory_rollback_failure_quarantines_and_retains_registered_bytes(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn extent_custody_scales_in_bytes_not_page_slots() {
    test_support::extent_custody_scales_in_bytes_not_page_slots(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn physical_alias_unlink_visits_only_touched_edges_at_three_populations() {
    test_support::physical_alias_unlink_visits_only_touched_edges_at_three_populations(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn drain_failure_retains_slot_and_retirement_failure_reinstalls_same_generation() {
    test_support::drain_failure_retains_slot_and_retirement_failure_reinstalls_same_generation(
        || test_support::MemoryTestIo::new(TestMemoryIo::default()),
    );
}
#[test]
fn two_live_vms_reject_each_others_local_mm_backing_capabilities() {
    test_support::two_live_vms_reject_each_others_local_mm_backing_capabilities(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn inherited_inventory_edges_authorize_only_selected_child_pages() {
    test_support::inherited_inventory_edges_authorize_only_selected_child_pages(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn inherited_prepared_leaf_retains_exact_storage_without_committing_it() {
    test_support::inherited_prepared_leaf_retains_exact_storage_without_committing_it(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn inherited_compound_inventory_authenticates_only_exact_live_owner_pages() {
    test_support::inherited_compound_inventory_authenticates_only_exact_live_owner_pages(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn retire_child_revokes_private_slots_and_keeps_slots_a_live_parent_shares() {
    test_support::retire_child_revokes_private_slots_and_keeps_slots_a_live_parent_shares(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn grandchild_inherits_a_slot_after_its_parent_retired() {
    test_support::grandchild_inherits_a_slot_after_its_parent_retired(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn an_owner_retired_slot_goes_with_the_retirement_that_drops_its_last_hold() {
    test_support::an_owner_retired_slot_goes_with_the_retirement_that_drops_its_last_hold(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn a_released_slot_whose_frame_another_mm_maps_quarantines_the_carrier() {
    test_support::a_released_slot_whose_frame_another_mm_maps_quarantines_the_carrier(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn a_retirement_without_a_carrier_root_quarantines_the_carrier() {
    test_support::a_retirement_without_a_carrier_root_quarantines_the_carrier(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn a_released_slot_its_retiring_mm_still_maps_quarantines_the_carrier() {
    test_support::a_released_slot_its_retiring_mm_still_maps_quarantines_the_carrier(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn inherited_inventory_edge_survives_protect_advancing_mapping_generation() {
    test_support::inherited_inventory_edge_survives_protect_advancing_mapping_generation(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    })
    .unwrap();
}

#[test]
fn ipc_memslots_retain_original_authority_without_copying() {
    use carrick_el1_abi::IpcWindowBacking;
    use carrick_kernel::el1_ipc::HostIpc;
    let owner = Arc::new(HostIpc::new(HostIpc::DEFAULT_POOL_BYTES).unwrap());
    let weak = Arc::downgrade(&owner);
    let directory = IpcWindowBacking::directory_ptr(&*owner) as u64;
    let pool = IpcWindowBacking::pool_ptr(&*owner) as u64;
    let mut memory = CarrierMemory::new(TestMemoryIo::default()).unwrap();
    let backings: Vec<_> = [
        (IpcWindowPart::Directory, 0x2_0000_0000),
        (IpcWindowPart::Pool, 0x2_0800_0000),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (part, base))| {
        let serial = NonZeroU64::new(index as u64 + 1).unwrap();
        PreparedBacking {
            extent: Arc::new(
                BackingExtent::ipc_window(FrameGpa::new(base), owner.clone(), part).unwrap(),
            ),
            identity: BackingIdentity {
                frame_id: serial,
                mapping_id: serial,
                owner_generation: serial,
                inventory_revision: serial,
            },
        }
    })
    .collect();
    memory.install(&backings).unwrap();
    let regions = memory.vm.regions.lock().unwrap();
    assert_eq!(regions[&0].userspace_addr, directory);
    assert_eq!(regions[&1].userspace_addr, pool);
    drop(regions);
    drop(backings);
    drop(owner);
    assert!(
        weak.upgrade().is_some(),
        "registered bytes retain their authority"
    );
    drop(memory);
    assert!(
        weak.upgrade().is_none(),
        "VM destruction releases authority"
    );
}

/// #1338 step 2: a host-file window extent is the file's page cache, not a
/// copy. A store through the carrier's view is the file's byte at once (no
/// write-back), a host write is visible through the view, the memslot
/// projects the mapping itself, and the extent refuses private
/// initialization.
#[test]
fn host_file_window_extent_shares_the_file_page_cache() {
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileExt;
    let path = std::env::temp_dir().join(format!(
        "carrick-host-file-window-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    file.set_len(2 * PAGE).unwrap();
    file.write_all_at(b"from-the-host", PAGE).unwrap();

    let base = FrameGpa::new(0x3_0000_0000);
    let mut extent =
        BackingExtent::host_file_window(base, file.as_fd(), PAGE, PAGE as usize).unwrap();
    assert_eq!(
        extent.read_unpublished(base.raw(), 13).unwrap(),
        b"from-the-host",
        "the window starts at its file offset"
    );
    let view = extent.ptr(base.raw() + 64, 5).unwrap();
    // SAFETY: the extent owns this live shared mapping of 5 bytes at +64.
    unsafe { core::ptr::copy_nonoverlapping(b"guest".as_ptr(), view, 5) };
    let mut stored = [0; 5];
    file.read_exact_at(&mut stored, PAGE + 64).unwrap();
    assert_eq!(
        &stored, b"guest",
        "a store is the file's byte, with no write-back"
    );
    file.write_all_at(b"again", PAGE + 128).unwrap();
    assert_eq!(
        extent.read_unpublished(base.raw() + 128, 5).unwrap(),
        b"again"
    );
    assert!(
        extent.initialize(0, b"x").is_err(),
        "a host-file window is never private RAM"
    );
    assert!(BackingExtent::host_file_window(base, file.as_fd(), 1, PAGE as usize).is_err());

    let host = extent.host_base().unwrap();
    let serial = NonZeroU64::new(7).unwrap();
    let backing = PreparedBacking {
        extent: Arc::new(extent),
        identity: BackingIdentity {
            frame_id: serial,
            mapping_id: serial,
            owner_generation: serial,
            inventory_revision: serial,
        },
    };
    let mut memory = CarrierMemory::new(TestMemoryIo::default()).unwrap();
    let handle = memory.install(std::slice::from_ref(&backing)).unwrap()[0];
    let region = memory.vm.regions.lock().unwrap()[&handle.slot_index()];
    assert_eq!(region.guest_phys_addr, base.raw());
    assert_eq!(region.memory_size, PAGE);
    assert_eq!(
        region.userspace_addr,
        host.raw() as u64,
        "the slot is the mapping"
    );
    assert!(
        memory.share(handle).is_ok(),
        "a window is shareable guest data"
    );
}
#[test]
fn retire_child_keeps_a_shared_file_window_slot_for_the_run() {
    test_support::retire_child_keeps_a_shared_file_window_slot_for_the_run(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}
#[test]
fn forked_shared_file_window_leaf_is_never_an_inventoried_frame() {
    test_support::forked_shared_file_window_leaf_is_never_an_inventoried_frame(|| {
        test_support::MemoryTestIo::new(TestMemoryIo::default())
    });
}

#[test]
fn window_slot_budget_bounds_windows_preserves_headroom_and_rolls_back() {
    use carrick_core::mm::window::WINDOW_CHUNK_BYTES;
    use std::io::Write;
    use std::os::fd::AsFd;

    let path = std::env::temp_dir().join(format!(
        "carrick-window-budget-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    file.set_len(PAGE).unwrap();
    file.write_all(b"budget").unwrap();

    let mut memory =
        CarrierMemory::new(test_support::MemoryTestIo::new(TestMemoryIo::default())).unwrap();
    let mut ram = GuestRam::new();
    ram.add_window(0x1000, PAGE as usize, crate::guest_ram::WindowKind::Private)
        .unwrap();
    memory.install_bootstrap(Arc::new(ram)).unwrap();

    // TestMemoryIo has limit 512 -> headroom 128 -> 383 available after 1 bootstrap slot.
    assert_eq!(memory.available_window_slots(), 383);
    assert!(memory.admit_window_slots(384).is_none());

    let serial = NonZeroU64::new(9).unwrap();
    let id = BackingIdentity {
        frame_id: serial,
        mapping_id: serial,
        owner_generation: serial,
        inventory_revision: serial,
    };
    let window_backing = |gpa| PreparedBacking {
        extent: Arc::new(
            BackingExtent::host_file_window(
                FrameGpa::new(gpa),
                file.as_fd(),
                0,
                WINDOW_CHUNK_BYTES as usize,
            )
            .unwrap(),
        ),
        identity: id,
    };
    let private_backing = |gpa| PreparedBacking {
        extent: Arc::new(BackingExtent::private(FrameGpa::new(gpa), PAGE as usize).unwrap()),
        identity: id,
    };

    // Stale budget across a private install is refused.
    let stale_budget = memory.admit_window_slots(1).unwrap();
    memory.install(&[private_backing(0x2000)]).unwrap();
    assert_eq!(memory.available_window_slots(), 382);
    assert!(
        memory
            .install_window_slots(stale_budget, &[window_backing(0x1000_0000)])
            .is_err()
    );

    // Mismatched count and non-window extent are refused without consuming slots.
    let bad_len = memory.admit_window_slots(1).unwrap();
    assert!(memory.install_window_slots(bad_len, &[]).is_err());
    let non_window = memory.admit_window_slots(1).unwrap();
    assert!(
        memory
            .install_window_slots(non_window, &[private_backing(0x3000)])
            .is_err()
    );
    assert_eq!(memory.window_slots(), 0);

    // Mid-batch set_region failure rolls back window_slots cleanly.
    let fail_budget = memory.admit_window_slots(2).unwrap();
    memory.vm().fail_region_call(1);
    assert!(
        memory
            .install_window_slots(
                fail_budget,
                &[window_backing(0x1000_0000), window_backing(0x1020_0000)],
            )
            .is_err()
    );
    memory.vm().clear_region_failure();
    assert_eq!(memory.window_slots(), 0);
    assert_eq!(memory.available_window_slots(), 382);

    // Filling the remaining window budget leaves the 128-slot non-window headroom intact.
    let mut backings = Vec::with_capacity(382);
    for idx in 0..382u64 {
        backings.push(window_backing(0x2000_0000 + idx * WINDOW_CHUNK_BYTES));
    }
    let full_budget = memory.admit_window_slots(382).unwrap();
    memory.install_window_slots(full_budget, &backings).unwrap();
    assert_eq!(memory.window_slots(), 382);
    assert_eq!(memory.available_window_slots(), 0);
    assert!(memory.admit_window_slots(1).is_none());
    memory.install(&[private_backing(0x4000)]).unwrap();

    // Large KVM-like slot limits stay bounded by MAX_WINDOW_SLOTS.
    struct LargeSlotIo;
    impl CarrierMemoryIo for LargeSlotIo {
        fn carrier_slot_limit(&self) -> Result<u32, carrick_hal::OsError> {
            Ok(32764)
        }
        unsafe fn set_user_memory_region(
            &self,
            _: CarrierMemoryRegion,
        ) -> Result<(), carrick_hal::OsError> {
            Ok(())
        }
        fn signal_msi(&self, _: u32, _: u32) -> Result<(), carrick_hal::OsError> {
            Ok(())
        }
    }
    let large = CarrierMemory::new(LargeSlotIo).unwrap();
    assert_eq!(large.available_window_slots(), MAX_WINDOW_SLOTS);
}
