use carrick_conformance_contract::ContractRegistry;

#[test]
fn write_seek_has_real_signed_and_docker_bindings() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let registry = ContractRegistry::load(root).unwrap();
    let contract = registry.require("kernel.fs.write-seek").unwrap();
    assert_eq!(
        contract.bindings.embed.as_deref(),
        Some("carrick-embed::contracts::write_seek_structural_contract")
    );
    assert_eq!(contract.bindings.docker.as_deref(), Some("probe:writeseek"));
}
