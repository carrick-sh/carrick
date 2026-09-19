#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use carrick_conformance_contract::{ContractRegistry, evaluate};
use carrick_kernel_example::contracts::{
    fork_filetable_contract, futex_contention_contract, futex_requeue_contract,
    futex_requeue_scenario, inotify_watch_contract,
};
use carrick_observability::work_meter::WorkMetric;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn futex_contention_contract_is_semantically_exact_and_linear() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.futex.contention")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| futex_contention_contract(scale, 0).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("semantic and structural conformance");
}

#[test]
fn unrelated_futex_population_does_not_increase_target_queue_visits() {
    let isolated = futex_contention_contract(8, 0).expect("isolated");
    let populated = futex_contention_contract(8, 128).expect("populated");
    assert_eq!(
        isolated.work_value(WorkMetric::FutexQueueVisits),
        populated.work_value(WorkMetric::FutexQueueVisits),
    );
}

#[test]
fn futex_zero_wake_visits_queue_head_without_waiter_inspections() {
    let obs = futex_contention_contract(0, 0).expect("zero wake observation");
    assert_eq!(obs.work_value(WorkMetric::FutexQueueVisits), Some(1));
    assert_eq!(obs.work_value(WorkMetric::FutexWaitersWoken), Some(0));
    assert_eq!(obs.work_value(WorkMetric::ContinuationEnrollments), Some(0));
}

#[test]
fn futex_partial_wake_scales_with_target_wake_count() {
    let obs = carrick_kernel_example::contracts::futex_contention_scenario(8, 4, 0)
        .expect("partial wake observation");
    assert_eq!(obs.work_value(WorkMetric::FutexWaitersWoken), Some(4));
    assert_eq!(obs.work_value(WorkMetric::FutexQueueVisits), Some(5));
    assert_eq!(obs.work_value(WorkMetric::ContinuationEnrollments), Some(8));
}

#[test]
fn futex_structural_red_control() {
    let fault = std::env::var("CARRICK_CONTRACT_FAULT").unwrap_or_default();
    if fault != "extra-futex-visit" {
        return;
    }
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.futex.contention")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| futex_contention_contract(scale, 0).expect("observation"))
        .collect::<Vec<_>>();
    let err =
        evaluate(contract, &observations).expect_err("should violate scaling with injected fault");
    match err {
        carrick_conformance_contract::EvaluationError::ScalingViolation {
            scale, metric, ..
        } => {
            assert_eq!(scale, 1, "smallest affected scale must be 1");
            assert_eq!(metric, WorkMetric::FutexQueueVisits);
        }
        other => panic!("expected ScalingViolation, got: {other:?}"),
    }
}

#[test]
fn futex_requeue_contract_is_semantically_exact_and_linear() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.futex.requeue").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| futex_requeue_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("requeue semantic and structural conformance");
}

#[test]
fn futex_requeue_partial_and_full() {
    let obs = futex_requeue_scenario(8, 2, 3).expect("partial requeue observation");
    assert_eq!(obs.work_value(WorkMetric::FutexWaitersWoken), Some(5)); // 2 woken by requeue + 3 woken by dest_wake
    assert_eq!(obs.work_value(WorkMetric::FutexQueueVisits), Some(10)); // (1 + 2 + 3) + (1 + 3) = 10
    assert_eq!(obs.work_value(WorkMetric::ContinuationEnrollments), Some(8));
}

#[test]
fn futex_requeue_structural_red_control() {
    let fault = std::env::var("CARRICK_CONTRACT_FAULT").unwrap_or_default();
    if fault != "extra-futex-requeue-visit" {
        return;
    }
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.futex.requeue").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| futex_requeue_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    let err =
        evaluate(contract, &observations).expect_err("should violate scaling with injected fault");
    match err {
        carrick_conformance_contract::EvaluationError::ScalingViolation {
            scale, metric, ..
        } => {
            assert_eq!(scale, 1, "smallest affected scale must be 1");
            assert_eq!(metric, WorkMetric::FutexQueueVisits);
        }
        other => panic!("expected ScalingViolation, got: {other:?}"),
    }
}

#[test]
fn fork_filetable_contract_is_semantically_exact_and_affine() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.fork.filetable").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| fork_filetable_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("semantic and structural conformance");
}

#[test]
fn fork_filetable_structural_red_control() {
    let fault = std::env::var("CARRICK_CONTRACT_FAULT").unwrap_or_default();
    if fault != "extra-fork-copy" {
        return;
    }
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.fork.filetable").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| fork_filetable_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    let err =
        evaluate(contract, &observations).expect_err("should violate scaling with injected fault");
    match err {
        carrick_conformance_contract::EvaluationError::ScalingViolation {
            scale, metric, ..
        } => {
            assert_eq!(scale, 1, "smallest affected scale must be 1");
            assert_eq!(metric, WorkMetric::GuestMemoryCopyBytes);
        }
        other => panic!("expected ScalingViolation, got: {other:?}"),
    }
}

#[test]
fn inotify_watch_contract_is_semantically_exact() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.inotify.watch").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| inotify_watch_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("semantic and structural conformance");
}

#[test]
fn inotify_watch_structural_red_control() {
    let fault = std::env::var("CARRICK_CONTRACT_FAULT").unwrap_or_default();
    if fault != "unbatched-inotify" {
        return;
    }
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.inotify.watch").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| inotify_watch_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    let err =
        evaluate(contract, &observations).expect_err("should violate budget with injected fault");
    match err {
        carrick_conformance_contract::EvaluationError::WorkBudgetExceeded { metric, .. } => {
            assert_eq!(metric, WorkMetric::HostBackendCalls);
        }
        other => panic!("expected WorkBudgetExceeded, got: {other:?}"),
    }
}
