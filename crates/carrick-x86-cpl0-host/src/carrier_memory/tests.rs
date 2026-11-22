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
fn refused_retire_child_mutates_nothing_and_its_retry_completes() {
    test_support::refused_retire_child_mutates_nothing_and_its_retry_completes(|| {
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

#[test]
fn prepare_settlement_accepts_a_sibling_protect_of_its_window() {
    test_support::prepare_settlement_accepts_a_sibling_edit_of_its_window(
        || test_support::MemoryTestIo::new(TestMemoryIo::default()),
        false,
    )
    .unwrap();
}
#[test]
fn prepare_settlement_accepts_a_sibling_retire_of_its_window() {
    test_support::prepare_settlement_accepts_a_sibling_edit_of_its_window(
        || test_support::MemoryTestIo::new(TestMemoryIo::default()),
        true,
    )
    .unwrap();
}
