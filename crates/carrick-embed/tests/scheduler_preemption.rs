//! Conformance contract and guest preemption tests for carrick-embed.
//!
//! Run ONLY through `scripts/test-signed.sh` (`just test-embed scheduler_preemption`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use carrick_conformance_contract::{ContractRegistry, ExecutionLayer, evaluate};
use carrick_embed::{
    Carrier, EmbedError, PullPolicy, run_scheduler_cost_structural_contract,
    run_scheduler_cost_timing_contract, run_scheduler_lifecycle_structural_contract,
    run_scheduler_lifecycle_timing_contract, run_scheduler_progress_structural_contract,
    run_scheduler_progress_timing_contract,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("manifest dir has repo root")
        .to_path_buf()
}

#[test]
fn scheduler_progress_structural_and_timing_receipts_are_distinct() {
    let structural = run_scheduler_progress_structural_contract();
    let timing = run_scheduler_progress_timing_contract();
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
fn scheduler_progress_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.scheduler.runnable-progress")
        .expect("contract");
    let obs = run_scheduler_progress_structural_contract();
    evaluate(contract, &[obs]).expect("scheduler progress structural contract evaluation");
    let timing_obs = run_scheduler_progress_timing_contract();
    evaluate(contract, &[timing_obs]).expect("scheduler progress timing contract evaluation");
}

#[test]
fn scheduler_lifecycle_structural_and_timing_receipts_are_distinct() {
    let structural = run_scheduler_lifecycle_structural_contract();
    let timing = run_scheduler_lifecycle_timing_contract();
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
fn scheduler_lifecycle_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.scheduler.preemption-lifecycle")
        .expect("contract");
    let obs = run_scheduler_lifecycle_structural_contract();
    evaluate(contract, &[obs]).expect("scheduler lifecycle structural contract evaluation");
    let timing_obs = run_scheduler_lifecycle_timing_contract();
    evaluate(contract, &[timing_obs]).expect("scheduler lifecycle timing contract evaluation");
}

#[test]
fn scheduler_cost_structural_and_timing_receipts_are_distinct() {
    let structural = run_scheduler_cost_structural_contract();
    let timing = run_scheduler_cost_timing_contract();
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
fn scheduler_cost_contract() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.scheduler.preemption-cost")
        .expect("contract");
    let obs = run_scheduler_cost_structural_contract();
    evaluate(contract, &[obs]).expect("scheduler cost structural contract evaluation");
    let timing_obs = run_scheduler_cost_timing_contract();
    evaluate(contract, &[timing_obs]).expect("scheduler cost timing contract evaluation");
}

#[test]
fn scheduler_preemption_guest_compute_progress() {
    let _guest = common::guest_lock();
    let fixture_path = repo_root().join(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-scheduler-preemption",
    );
    assert!(
        fixture_path.is_file(),
        "fixture binary missing at {}; run scripts/build-linux-fixtures.sh",
        fixture_path.display()
    );

    let p_dir = fixture_path.parent().expect("fixture parent dir");
    let bin_name = fixture_path
        .file_name()
        .and_then(|n| n.to_str())
        .expect("bin name");

    let carrier = match Carrier::new() {
        Ok(c) => c,
        Err(EmbedError::Entitlement) => panic!(
            "HV_DENIED (0xfae94007): test executable lacks hypervisor entitlement. Run via `just test-embed`."
        ),
        Err(e) => panic!("carrier initialization failed: {e}"),
    };

    let builder = carrier
        .container(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .command([format!("/p/{bin_name}")])
        .mount_readonly(p_dir.to_string_lossy(), "/p");

    let result = common::run_or_fail(builder.run_blocking());
    assert_eq!(
        result.exit_code, 0,
        "guest preemption fixture failed with exit code: {}",
        result.exit_code
    );
    let stdout = result.stdout_utf8();
    assert!(
        stdout.contains("preemption ok"),
        "guest output missing 'preemption ok': {stdout}"
    );
}
