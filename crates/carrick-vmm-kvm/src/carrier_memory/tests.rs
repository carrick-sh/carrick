use carrick_x86_cpl0_host::carrier_memory::test_support;
fn real_memory_io() -> test_support::MemoryTestIo {
    test_support::MemoryTestIo::new(crate::KvmVm::create_empty().unwrap())
}
#[test]
fn one_memslot_authenticates_each_inventoried_frame_independently() {
    carrick_test_support::require_kvm!();
    test_support::one_memslot_authenticates_each_inventoried_frame_independently(real_memory_io);
}
#[test]
fn carrier_publication_requires_an_already_applied_guest_edit() {
    carrick_test_support::require_kvm!();
    test_support::carrier_publication_requires_an_already_applied_guest_edit(real_memory_io);
}
#[test]
fn failed_second_memslot_install_restores_custody_and_reuses_slot_zero() {
    carrick_test_support::require_kvm!();
    test_support::failed_second_memslot_install_restores_custody_and_reuses_slot_zero(
        real_memory_io,
    );
}
#[test]
fn inventory_failure_before_guest_edit_rolls_back_and_after_edit_quarantines() {
    carrick_test_support::require_kvm!();
    test_support::inventory_failure_before_guest_edit_rolls_back_and_after_edit_quarantines(
        real_memory_io,
    );
}
#[test]
fn inventory_rollback_failure_quarantines_and_retains_registered_bytes() {
    carrick_test_support::require_kvm!();
    test_support::inventory_rollback_failure_quarantines_and_retains_registered_bytes(
        real_memory_io,
    );
}
#[test]
fn extent_custody_scales_in_bytes_not_page_slots() {
    carrick_test_support::require_kvm!();
    test_support::extent_custody_scales_in_bytes_not_page_slots(real_memory_io);
}
#[test]
fn physical_alias_unlink_visits_only_touched_edges_at_three_populations() {
    carrick_test_support::require_kvm!();
    test_support::physical_alias_unlink_visits_only_touched_edges_at_three_populations(
        real_memory_io,
    );
}
#[test]
fn drain_failure_retains_slot_and_retirement_failure_reinstalls_same_generation() {
    carrick_test_support::require_kvm!();
    test_support::drain_failure_retains_slot_and_retirement_failure_reinstalls_same_generation(
        real_memory_io,
    );
}
#[test]
fn two_live_vms_reject_each_others_local_mm_backing_capabilities() {
    carrick_test_support::require_kvm!();
    test_support::two_live_vms_reject_each_others_local_mm_backing_capabilities(real_memory_io);
}
#[test]
fn inherited_inventory_edges_authorize_only_selected_child_pages() {
    carrick_test_support::require_kvm!();
    test_support::inherited_inventory_edges_authorize_only_selected_child_pages(real_memory_io);
}
#[test]
fn inherited_prepared_leaf_retains_exact_storage_without_committing_it() {
    test_support::inherited_prepared_leaf_retains_exact_storage_without_committing_it(
        real_memory_io,
    );
}
#[test]
fn inherited_compound_inventory_authenticates_only_exact_live_owner_pages() {
    test_support::inherited_compound_inventory_authenticates_only_exact_live_owner_pages(
        real_memory_io,
    );
}
#[test]
fn retire_child_revokes_private_slots_and_keeps_slots_a_live_parent_shares() {
    carrick_test_support::require_kvm!();
    test_support::retire_child_revokes_private_slots_and_keeps_slots_a_live_parent_shares(
        real_memory_io,
    );
}
#[test]
fn grandchild_inherits_a_slot_after_its_parent_retired() {
    carrick_test_support::require_kvm!();
    test_support::grandchild_inherits_a_slot_after_its_parent_retired(real_memory_io);
}
#[test]
fn a_released_slot_whose_frame_another_mm_maps_quarantines_the_carrier() {
    carrick_test_support::require_kvm!();
    test_support::a_released_slot_whose_frame_another_mm_maps_quarantines_the_carrier(
        real_memory_io,
    );
}
#[test]
fn a_released_slot_its_retiring_mm_still_maps_quarantines_the_carrier() {
    carrick_test_support::require_kvm!();
    test_support::a_released_slot_its_retiring_mm_still_maps_quarantines_the_carrier(
        real_memory_io,
    );
}
#[test]
fn prepare_settlement_accepts_a_sibling_protect_applied_before_it() {
    carrick_test_support::require_kvm!();
    test_support::prepare_settlement_accepts_a_sibling_protect_applied_before_it(real_memory_io);
}
#[test]
fn prepare_settlement_with_its_editor_held_refuses_changed_permissions() {
    carrick_test_support::require_kvm!();
    test_support::prepare_settlement_with_its_editor_held_refuses_changed_permissions(
        real_memory_io,
    );
}
#[test]
fn prepare_settlement_refuses_a_leaf_outside_its_ceiling() {
    carrick_test_support::require_kvm!();
    test_support::prepare_settlement_refuses_a_leaf_outside_its_ceiling(real_memory_io);
}
#[test]
fn inherited_inventory_edge_survives_protect_advancing_mapping_generation() {
    carrick_test_support::require_kvm!();
    test_support::inherited_inventory_edge_survives_protect_advancing_mapping_generation(
        real_memory_io,
    )
    .unwrap();
}
#[test]
fn retire_child_keeps_a_shared_file_window_slot_for_the_run() {
    carrick_test_support::require_kvm!();
    test_support::retire_child_keeps_a_shared_file_window_slot_for_the_run(real_memory_io);
}
#[test]
fn forked_shared_file_window_leaf_is_never_an_inventoried_frame() {
    carrick_test_support::require_kvm!();
    test_support::forked_shared_file_window_leaf_is_never_an_inventoried_frame(real_memory_io);
}
