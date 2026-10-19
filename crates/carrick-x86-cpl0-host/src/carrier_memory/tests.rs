use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
#[derive(Default)]
struct TestMemoryIo {
    regions: Mutex<HashMap<u32, CarrierMemoryRegion>>,
}
impl CarrierMemoryIo for TestMemoryIo {
    fn carrier_slot_limit(&self) -> Result<u32, carrick_hal::OsError> {
        Ok(512)
    }
    unsafe fn set_user_memory_region(
        &self,
        region: CarrierMemoryRegion,
    ) -> Result<(), carrick_hal::OsError> {
        let mut regions = self.regions.lock().unwrap();
        if region.memory_size == 0 {
            regions.remove(&region.slot);
        } else {
            regions.insert(region.slot, region);
        }
        Ok(())
    }
    fn signal_msi(&self, _: u32, _: u32) -> Result<(), carrick_hal::OsError> {
        Err(carrick_hal::OsError::new("unused test MSI"))
    }
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
