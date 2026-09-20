use carrick_abi::syscall::SupportLevel;
use carrick_conformance_contract::{ContractRegistry, SyscallInventory};
use std::path::Path;

#[test]
fn inventory_covers_entire_aarch64_table() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = ContractRegistry::load(repo_root).expect("failed to load contract registry");
    let inventory = SyscallInventory::generate(&registry);

    let table = carrick_abi::syscall::aarch64_table();
    assert_eq!(inventory.entries.len(), table.len());
    assert_eq!(inventory.summary.total_entries, table.len());

    let expected_bring_up = table
        .iter()
        .filter(|s| s.support == SupportLevel::BringUp)
        .count();
    let expected_deferred = table
        .iter()
        .filter(|s| s.support == SupportLevel::Deferred)
        .count();
    let expected_planned = table
        .iter()
        .filter(|s| s.support == SupportLevel::Planned)
        .count();

    assert_eq!(inventory.summary.bring_up, expected_bring_up);
    assert_eq!(inventory.summary.deferred, expected_deferred);
    assert_eq!(inventory.summary.planned, expected_planned);

    // Sum of categorized entries must equal total entries
    assert_eq!(
        inventory.summary.bring_up + inventory.summary.deferred + inventory.summary.planned,
        inventory.summary.total_entries
    );
    assert_eq!(
        inventory.summary.with_claims + inventory.summary.without_claims,
        inventory.summary.total_entries
    );
}

#[test]
fn inventory_serializes_to_valid_json() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = ContractRegistry::load(repo_root).expect("failed to load contract registry");
    let inventory = SyscallInventory::generate(&registry);

    let json = serde_json::to_string_pretty(&inventory).expect("serialization failed");
    let deserialized: SyscallInventory =
        serde_json::from_str(&json).expect("deserialization failed");
    assert_eq!(inventory.summary, deserialized.summary);
    assert_eq!(inventory.entries.len(), deserialized.entries.len());
}
