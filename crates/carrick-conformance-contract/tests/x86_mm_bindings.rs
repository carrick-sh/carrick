use carrick_conformance_contract::ContractRegistry;

#[test]
fn x1_owner_witness_is_bound_without_promoting_hardware_acceptance() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let registry = ContractRegistry::load(root).unwrap();
    for id in [
        "kernel.el1.mm-exclusive-owner",
        "kernel.el1.stage1-publication",
        "kernel.mm.address-space-occupancy",
    ] {
        let contract = registry.require(id).unwrap();
        assert!(
            contract
                .bindings
                .vm_free
                .as_deref()
                .unwrap()
                .contains("carrick-core::x86_acceleration::x1_shared_mm_owner"),
            "the shared order-1 witness must be registered for {id}"
        );
        assert!(contract.bindings.unresolved["x86_cpl0"].contains("orders 3a/3b"));
    }
}
