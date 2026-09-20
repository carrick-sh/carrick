//! Conformance contract tests for futex contention in carrick-embed.
//!
//! Run ONLY through `scripts/test-signed.sh`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_conformance_contract::{ContractRegistry, ExecutionLayer, evaluate};
use carrick_embed::{
    run_fork_stage1_image_structural_contract, run_fork_stage1_image_structural_contract_with,
    run_fork_stage1_image_timing_contract, run_futex_requeue_structural_contract,
    run_futex_requeue_timing_contract, run_futex_structural_contract, run_futex_timing_contract,
};
use carrick_observability::work_meter::WorkMetric;

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

/// `kernel.fork.stage1-image`: fresh stage-1 image allocations must stay
/// constant while the serial fork count grows. Runs every contract scale
/// point on the real runtime work scope (no defaults filled in).
#[test]
fn fork_stage1_image_structural_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.fork.stage1-image")
        .expect("contract");
    let observations = [1u64, 8, 32, 128]
        .into_iter()
        .map(run_fork_stage1_image_structural_contract)
        .collect::<Vec<_>>();
    for obs in &observations {
        eprintln!(
            "fork.stage1-image scale={} task_admissions={:?} page_table_image_allocations={:?} host_mapping_allocations={:?} fork_projection_rows_visited={:?} completeness={:?}",
            obs.scale,
            obs.work_value(WorkMetric::TaskAdmissions),
            obs.work_value(WorkMetric::PageTableImageAllocations),
            obs.work_value(WorkMetric::HostMappingAllocations),
            obs.work_value(WorkMetric::ForkProjectionRowsVisited),
            obs.completeness
        );
        assert_eq!(
            obs.work_value(WorkMetric::TaskAdmissions),
            Some(obs.scale),
            "one task admission per serial fork at scale {}",
            obs.scale
        );
    }
    evaluate(contract, &observations).expect("fork stage-1 image structural contract evaluation");
}

#[test]
fn fork_stage1_image_timing_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.fork.stage1-image")
        .expect("contract");
    let obs = run_fork_stage1_image_timing_contract();
    eprintln!("fork.stage1-image timing={:?}", obs.timing);
    evaluate(contract, &[obs]).expect("fork stage-1 image timing contract evaluation");
}

/// Same contract with the parent dirtying a private page between forks
/// (`ltp-fork14`'s shape): each iteration legitimately splits one COW frame,
/// so the projection may revisit rows proportional to that change only.
#[test]
fn fork_stage1_image_structural_contract_dirty_parent() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.fork.stage1-image")
        .expect("contract");
    let observations = [1u64, 8, 32, 128]
        .into_iter()
        .map(|scale| run_fork_stage1_image_structural_contract_with(scale, true))
        .collect::<Vec<_>>();
    for obs in &observations {
        eprintln!(
            "fork.stage1-image(dirty) scale={} task_admissions={:?} page_table_image_allocations={:?} host_mapping_allocations={:?} fork_projection_rows_visited={:?} completeness={:?}",
            obs.scale,
            obs.work_value(WorkMetric::TaskAdmissions),
            obs.work_value(WorkMetric::PageTableImageAllocations),
            obs.work_value(WorkMetric::HostMappingAllocations),
            obs.work_value(WorkMetric::ForkProjectionRowsVisited),
            obs.completeness
        );
    }
    evaluate(contract, &observations)
        .expect("fork stage-1 image structural contract evaluation (dirty parent)");
}
