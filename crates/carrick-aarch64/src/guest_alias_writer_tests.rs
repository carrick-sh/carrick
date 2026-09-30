//! The engine's two remaining alias writers on the guest-owned lane.
//!
//! `restore_shared_identity` and `map_host_alias` used the host-only
//! `map_aliased` funnel, which refuses on a guest-owned MM. They must hand
//! the lane to the backend's EL1 publication (with the driving-vCPU
//! service) BEFORE the host funnel, and a refused host alias must be undone
//! in the host lane's end state without the refusing funnel.

fn production() -> &'static str {
    include_str!("engine.rs")
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .expect("production AArch64 engine source")
}

fn body<'a>(source: &'a str, signature: &str) -> &'a str {
    source
        .split(signature)
        .nth(1)
        .and_then(|tail| tail.split("\n    fn ").next())
        .unwrap_or_else(|| panic!("production path {signature}"))
}

#[test]
fn guest_lane_alias_writers_publish_through_el1_before_the_host_funnel() {
    let source = production();
    let restore = body(source, "fn restore_shared_identity(");
    let guest = restore
        .find("LiveDescriptorOwner::Guest")
        .expect("identity restore branches on the guest-owned lane");
    let publish = restore
        .find("restore_guest_shared_identity(")
        .expect("guest identity restore is published by the backend");
    let host = restore
        .find("pt_edit_and_flush_after_adopting")
        .expect("host lane keeps the host editor");
    assert!(guest < publish && publish < host);
    assert!(restore.contains("EngineStage1Services::<V>"));

    let alias = body(source, "fn map_host_alias(");
    let staged = alias.find(".add_alias(").expect("alias backing is staged");
    let branch = alias
        .find("map_host_alias_on_guest_lane(")
        .expect("guest lane hands off after staging");
    let host = alias.find("pt_edit_and_flush(").expect("host lane edit");
    assert!(staged < branch && branch < host);

    let guest = body(source, "fn map_host_alias_on_guest_lane(");
    assert!(guest.contains("EngineStage1Services::<V>") && guest.contains("slot"));
    assert!(guest.contains("publish_guest_host_alias("));
    for forbidden in ["pt_edit", "unmap_alias_range", "map_aliased("] {
        assert!(
            !guest.contains(forbidden),
            "the guest lane must not reach the refusing host funnel via {forbidden}"
        );
    }
    // Before the authority saw the mapping: discard staging, then retire
    // the span through EL1; then (both arms) unregister and mark unmapped,
    // as the host lane's `unmap_alias_range` does.
    let abandon = guest
        .find("abandon_alias_inventory()")
        .expect("unapplied staging is discarded");
    let retire = guest
        .find("self.apply_stage1_rules(")
        .expect("span is retired through the lane-agnostic applier");
    let unregister = guest
        .find("self.vm.on_unmap(")
        .expect("alias is unregistered");
    let unmapped = guest
        .find("self.set_unmapped(")
        .expect("range is marked unmapped");
    assert!(abandon < retire && retire < unregister && unregister < unmapped);
}
