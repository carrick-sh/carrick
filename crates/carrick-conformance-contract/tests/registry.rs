#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use carrick_conformance_contract::{ContractId, ContractRegistry, RegistryError};
use tempfile::TempDir;

const COMPLETE_CONTRACT: &str = r#"
schema_version = 1
id = "kernel.futex.contention"
title = "Futex contention"
guest_surfaces = ["syscall:futex", "scheduler:continuation"]
semantic_authority = ["man 2 futex", "oracle:futexpingpong", "oracle:futexwakeexact"]
fixture = "probe:futexpingpong"
scale_points = [1, 8, 32, 128]
rationale = "Futex blocking must park once and wake in work proportional to affected waiters."

[bindings]
vm_free = "carrick-kernel-example::futex_contention_contract"
embed = "carrick-embed::futex_contention_contract"
docker = "probe:futexpingpong"
ecosystem = ["go:sync", "cpython:concurrent_futures"]

[[structural_budgets]]
kind = "affine"
metric = "continuation_enrollments"
base = 0
per_unit = 1
rationale = "Each blocking waiter enrolls exactly once before parking."

[[structural_budgets]]
kind = "affine"
metric = "futex_queue_visits"
base = 1
per_unit = 1
rationale = "Wake visits only the queue head and the affected waiter set."

[runtime_ratio]
maximum = 2.0
statistic = "p50"
minimum_samples = 20
"#;

const EMPTY_SURFACES: &str = "schema_version = 1\nsurfaces = []\n";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is nested under the repository root")
        .to_path_buf()
}

fn fixture_root(contract: &str, surfaces: &str) -> TempDir {
    let root = TempDir::new().expect("temporary registry root");
    let contracts = root.path().join("conformance-contracts/contracts");
    fs::create_dir_all(&contracts).expect("contracts directory");
    fs::write(contracts.join("contract.toml"), contract).expect("contract fixture");
    fs::write(
        root.path().join("conformance-contracts/surfaces.toml"),
        surfaces,
    )
    .expect("surface fixture");
    root
}

#[test]
fn futex_contract_has_structural_and_runtime_authority() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .get(&ContractId::new("kernel.futex.contention").expect("id"))
        .expect("futex contract");
    assert_eq!(contract.scale_points, vec![1, 8, 32, 128]);
    assert!(contract.bindings.vm_free.is_some());
    assert!(contract.bindings.embed.is_some());
    assert!(contract.bindings.docker.is_some());
    assert!(contract.runtime_ratio.is_some());
}

#[test]
fn duplicate_contract_ids_are_rejected() {
    let root = fixture_root(COMPLETE_CONTRACT, EMPTY_SURFACES);
    fs::write(
        root.path()
            .join("conformance-contracts/contracts/duplicate.toml"),
        COMPLETE_CONTRACT,
    )
    .expect("duplicate fixture");

    assert!(matches!(
        ContractRegistry::load(root.path()),
        Err(RegistryError::Duplicate(id)) if id.as_str() == "kernel.futex.contention"
    ));
}

#[test]
fn unknown_binding_layers_are_rejected_as_toml() {
    let contract = COMPLETE_CONTRACT.replace(
        "docker = \"probe:futexpingpong\"",
        "docker = \"probe:futexpingpong\"\nmystery = \"not-a-layer\"",
    );
    let root = fixture_root(&contract, EMPTY_SURFACES);

    assert!(matches!(
        ContractRegistry::load(root.path()),
        Err(RegistryError::Toml { .. })
    ));
}

#[test]
fn unknown_work_metrics_are_rejected_as_toml() {
    let contract = COMPLETE_CONTRACT.replacen(
        "metric = \"continuation_enrollments\"",
        "metric = \"made_up_work\"",
        1,
    );
    let root = fixture_root(&contract, EMPTY_SURFACES);

    assert!(matches!(
        ContractRegistry::load(root.path()),
        Err(RegistryError::Toml { .. })
    ));
}

#[test]
fn fields_from_another_budget_kind_are_rejected_as_toml() {
    let contract = COMPLETE_CONTRACT.replacen(
        "kind = \"affine\"\nmetric = \"continuation_enrollments\"\nbase = 0\nper_unit = 1",
        "kind = \"exact\"\nmetric = \"continuation_enrollments\"\nvalue = 1\nbase = 0\nper_unit = 1",
        1,
    );
    let root = fixture_root(&contract, EMPTY_SURFACES);

    assert!(matches!(
        ContractRegistry::load(root.path()),
        Err(RegistryError::Toml { .. })
    ));
}

#[test]
fn non_toml_contract_entries_are_rejected() {
    let root = fixture_root(COMPLETE_CONTRACT, EMPTY_SURFACES);
    let path = root
        .path()
        .join("conformance-contracts/contracts/README.md");
    fs::write(&path, "not a contract").expect("non-TOML fixture");

    assert!(matches!(
        ContractRegistry::load(root.path()),
        Err(RegistryError::UnexpectedContractFile(actual)) if actual == path
    ));
}

#[test]
fn missing_budget_rationale_is_rejected() {
    let contract = COMPLETE_CONTRACT.replacen(
        "rationale = \"Each blocking waiter enrolls exactly once before parking.\"",
        "",
        1,
    );
    let root = fixture_root(&contract, EMPTY_SURFACES);

    assert!(matches!(
        ContractRegistry::load(root.path()),
        Err(RegistryError::MissingBudgetRationale { id, index: 0 })
            if id.as_str() == "kernel.futex.contention"
    ));
}

#[test]
fn affine_budgets_require_three_scale_points() {
    let contract =
        COMPLETE_CONTRACT.replace("scale_points = [1, 8, 32, 128]", "scale_points = [1, 8]");
    let root = fixture_root(&contract, EMPTY_SURFACES);

    assert!(matches!(
        ContractRegistry::load(root.path()),
        Err(RegistryError::InsufficientScalePoints { id })
            if id.as_str() == "kernel.futex.contention"
    ));
}

#[test]
fn surfaces_must_reference_registered_contracts() {
    let surfaces = r#"
schema_version = 1

[[surfaces]]
path = "crates/carrick-kernel/src/dispatch/futex.rs"
contracts = ["kernel.futex.missing"]
"#;
    let root = fixture_root(COMPLETE_CONTRACT, surfaces);

    assert!(matches!(
        ContractRegistry::load(root.path()),
        Err(RegistryError::UnknownSurfaceContract { surface, contract })
            if surface == "crates/carrick-kernel/src/dispatch/futex.rs"
                && contract.as_str() == "kernel.futex.missing"
    ));
}

#[test]
fn contract_ids_reject_empty_or_non_lowercase_segments() {
    for invalid in [
        "",
        ".kernel",
        "kernel.",
        "kernel..futex",
        "Kernel.futex",
        "kernel_futex",
    ] {
        assert!(ContractId::new(invalid).is_err(), "accepted {invalid:?}");
    }
    assert_eq!(
        ContractId::new("kernel.futex-wake")
            .expect("valid id")
            .as_str(),
        "kernel.futex-wake"
    );
}
