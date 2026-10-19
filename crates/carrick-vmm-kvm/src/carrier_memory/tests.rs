use carrick_x86_cpl0_host::carrier_memory::test_support;
fn real_memory_io() -> test_support::MemoryTestIo {
    test_support::MemoryTestIo::new(crate::KvmVm::create_empty().unwrap())
}
#[test]
fn one_memslot_authenticates_each_inventoried_frame_independently() {
    test_support::one_memslot_authenticates_each_inventoried_frame_independently(real_memory_io);
}
#[test]
fn carrier_publication_requires_an_already_applied_guest_edit() {
    test_support::carrier_publication_requires_an_already_applied_guest_edit(real_memory_io);
}
#[test]
fn failed_second_memslot_install_restores_custody_and_reuses_slot_zero() {
    test_support::failed_second_memslot_install_restores_custody_and_reuses_slot_zero(
        real_memory_io,
    );
}
#[test]
fn inventory_failure_before_guest_edit_rolls_back_and_after_edit_quarantines() {
    test_support::inventory_failure_before_guest_edit_rolls_back_and_after_edit_quarantines(
        real_memory_io,
    );
}
#[test]
fn inventory_rollback_failure_quarantines_and_retains_registered_bytes() {
    test_support::inventory_rollback_failure_quarantines_and_retains_registered_bytes(
        real_memory_io,
    );
}
#[test]
fn extent_custody_scales_in_bytes_not_page_slots() {
    test_support::extent_custody_scales_in_bytes_not_page_slots(real_memory_io);
}
#[test]
fn physical_alias_unlink_visits_only_touched_edges_at_three_populations() {
    test_support::physical_alias_unlink_visits_only_touched_edges_at_three_populations(
        real_memory_io,
    );
}
#[test]
fn drain_failure_retains_slot_and_retirement_failure_reinstalls_same_generation() {
    test_support::drain_failure_retains_slot_and_retirement_failure_reinstalls_same_generation(
        real_memory_io,
    );
}
#[test]
fn two_live_vms_reject_each_others_local_mm_backing_capabilities() {
    test_support::two_live_vms_reject_each_others_local_mm_backing_capabilities(real_memory_io);
}
#[test]
fn inherited_inventory_edges_authorize_only_selected_child_pages() {
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
    test_support::retire_child_revokes_private_slots_and_keeps_slots_a_live_parent_shares(
        real_memory_io,
    );
}
#[test]
fn grandchild_inherits_a_slot_after_its_parent_retired() {
    test_support::grandchild_inherits_a_slot_after_its_parent_retired(real_memory_io);
}
#[test]
fn refused_retire_child_mutates_nothing_and_its_retry_completes() {
    test_support::refused_retire_child_mutates_nothing_and_its_retry_completes(real_memory_io);
}
#[test]
fn inherited_inventory_edge_survives_protect_advancing_mapping_generation() {
    test_support::inherited_inventory_edge_survives_protect_advancing_mapping_generation(
        real_memory_io,
    );
}
