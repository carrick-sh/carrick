//! Conformance contract tests for futex contention in carrick-embed.
//!
//! Run ONLY through `scripts/test-signed.sh`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_conformance_contract::{ContractRegistry, ExecutionLayer, evaluate};
use carrick_embed::{
    run_futex_requeue_structural_contract, run_futex_requeue_timing_contract,
    run_futex_structural_contract, run_futex_timing_contract,
};

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("manifest dir has repo root")
        .to_path_buf()
}

#[test]
fn futex_structural_and_timing_receipts_are_distinct() {
    let structural = run_futex_structural_contract();
    let timing = run_futex_timing_contract();
    assert_eq!(structural.layer, ExecutionLayer::EmbedStructural);
    assert!(structural.work.is_some());
    assert!(structural.timing.is_none());
    assert_eq!(timing.layer, ExecutionLayer::EmbedTiming);
    assert!(timing.work.is_none());
    assert!(timing.timing.is_some());
    assert_ne!(structural.implementation_revision, "");
    assert_eq!(structural.fixture_identity, timing.fixture_identity);
}

#[test]
fn futex_structural_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.futex.contention")
        .expect("contract");
    let obs = run_futex_structural_contract();
    evaluate(contract, &[obs]).expect("futex structural contract evaluation");
}

#[test]
fn futex_timing_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.futex.contention")
        .expect("contract");
    let obs = run_futex_timing_contract();
    evaluate(contract, &[obs]).expect("futex timing contract evaluation");
}

#[test]
fn futex_requeue_structural_and_timing_receipts_are_distinct() {
    let structural = run_futex_requeue_structural_contract();
    let timing = run_futex_requeue_timing_contract();
    assert_eq!(structural.layer, ExecutionLayer::EmbedStructural);
    assert!(structural.work.is_some());
    assert!(structural.timing.is_none());
    assert_eq!(timing.layer, ExecutionLayer::EmbedTiming);
    assert!(timing.work.is_none());
    assert!(timing.timing.is_some());
    assert_ne!(structural.implementation_revision, "");
    assert_eq!(structural.fixture_identity, timing.fixture_identity);
}

#[test]
fn futex_requeue_structural_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.futex.requeue").expect("contract");
    let obs = run_futex_requeue_structural_contract();
    evaluate(contract, &[obs]).expect("futex requeue structural contract evaluation");
}

#[test]
fn futex_requeue_timing_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.futex.requeue").expect("contract");
    let obs = run_futex_requeue_timing_contract();
    evaluate(contract, &[obs]).expect("futex requeue timing contract evaluation");
}
