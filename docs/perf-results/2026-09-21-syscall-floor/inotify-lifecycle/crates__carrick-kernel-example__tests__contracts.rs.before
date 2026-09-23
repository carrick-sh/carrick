#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use carrick_conformance_contract::{ContractRegistry, evaluate};
use carrick_kernel_example::contracts::{
    fork_filetable_contract, fork_mappings_contract, fork_stage1_image_contract,
    futex_contention_contract, futex_requeue_contract, futex_requeue_scenario,
    inotify_hotpath_contract, inotify_readiness_contract, inotify_watch_contract,
    scheduler_cost_contract, scheduler_lifecycle_contract, scheduler_progress_contract,
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

#[test]
fn inotify_readiness_contract_does_not_scan_the_queue() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.inotify.readiness")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| inotify_readiness_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("semantic and structural conformance");
}

/// Readiness is a non-emptiness question, so a deeper queue must not make it
/// more expensive. This is the shape LTP's `inotify09` sustains for millions of
/// iterations, where an O(depth) readiness answer becomes O(depth^2) overall.
#[test]
fn inotify_readiness_cost_does_not_grow_with_queue_depth() {
    let visits = |observation: &carrick_conformance_contract::ContractObservation| {
        observation
            .work
            .as_ref()
            .and_then(|work| work.get(WorkMetric::InotifyQueueVisits))
            .expect("inotify queue visits must be measured")
    };
    let shallow = inotify_readiness_contract(8).expect("shallow queue");
    let deep = inotify_readiness_contract(128).expect("deep queue");
    assert_eq!(
        visits(&shallow),
        visits(&deep),
        "readiness inspected {} records at depth 8 and {} at depth 128",
        visits(&shallow),
        visits(&deep),
    );
}

#[test]
fn inotify_readiness_structural_red_control() {
    let fault = std::env::var("CARRICK_CONTRACT_FAULT").unwrap_or_default();
    if fault != "scanning-inotify-readiness" {
        return;
    }
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.inotify.readiness")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| inotify_readiness_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    let err =
        evaluate(contract, &observations).expect_err("should violate budget with injected fault");
    match err {
        carrick_conformance_contract::EvaluationError::ScalingViolation {
            scale, metric, ..
        } => {
            assert_eq!(scale, 1, "smallest affected scale must be 1");
            assert_eq!(metric, WorkMetric::InotifyQueueVisits);
        }
        other => panic!("expected ScalingViolation, got: {other:?}"),
    }
}

#[test]
fn inotify09_hotpath_is_semantically_exact_and_linear() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.inotify.mark-race-hotpath")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| inotify_hotpath_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("semantic and structural conformance");
}

#[test]
fn inotify09_hotpath_structural_red_control() {
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() != Ok("amplified-inotify09-hotpath") {
        return;
    }
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.inotify.mark-race-hotpath")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| inotify_hotpath_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    let err = evaluate(contract, &observations).expect_err("fault must violate work slope");
    match err {
        carrick_conformance_contract::EvaluationError::ScalingViolation { metric, .. } => {
            assert_eq!(metric, WorkMetric::HostBackendCalls);
        }
        other => panic!("expected ScalingViolation, got: {other:?}"),
    }
}

#[test]
fn fork_mappings_contract_is_semantically_exact_and_constant() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.fork.mappings").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| fork_mappings_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("semantic and structural conformance");
}

#[test]
fn fork_mappings_structural_red_control() {
    let fault = std::env::var("CARRICK_CONTRACT_FAULT").unwrap_or_default();
    if fault != "extra-backing-alloc" {
        return;
    }
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry.require("kernel.fork.mappings").expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| fork_mappings_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    let err =
        evaluate(contract, &observations).expect_err("should violate budget with injected fault");
    match err {
        carrick_conformance_contract::EvaluationError::WorkBudgetExceeded { metric, .. } => {
            assert_eq!(metric, WorkMetric::BackingAllocations);
        }
        other => panic!("expected WorkBudgetExceeded, got: {other:?}"),
    }
}

#[test]
fn scheduler_progress_contract_is_semantically_exact_and_linear() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.scheduler.runnable-progress")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| scheduler_progress_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("scheduler progress conformance");
}

#[test]
fn scheduler_lifecycle_contract_is_semantically_exact_and_constant() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.scheduler.preemption-lifecycle")
        .expect("contract");
    let observations = [1, 2, 4, 8]
        .into_iter()
        .map(|scale| scheduler_lifecycle_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("scheduler lifecycle conformance");
}

#[test]
fn scheduler_cost_contract_is_semantically_exact_and_constant() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.scheduler.preemption-cost")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| scheduler_cost_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    evaluate(contract, &observations).expect("scheduler cost conformance");
}

#[test]
fn fork_stage1_image_contract_admits_one_task_per_serial_fork() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.fork.stage1-image")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| fork_stage1_image_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    for (scale, obs) in [1u64, 8, 32, 128].into_iter().zip(&observations) {
        assert_eq!(obs.work_value(WorkMetric::TaskAdmissions), Some(scale));
        // The scripted dispatcher has no stage-1 image; the budget is proven
        // under signed execution and must read as zero, never as unknown, here.
        assert_eq!(
            obs.work_value(WorkMetric::PageTableImageAllocations),
            Some(0)
        );
    }
    evaluate(contract, &observations).expect("serial fork semantic and admission conformance");
}

#[test]
fn fork_stage1_image_structural_red_control() {
    let fault = std::env::var("CARRICK_CONTRACT_FAULT").unwrap_or_default();
    if fault != "extra-task-admission" {
        return;
    }
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let contract = registry
        .require("kernel.fork.stage1-image")
        .expect("contract");
    let observations = [1, 8, 32, 128]
        .into_iter()
        .map(|scale| fork_stage1_image_contract(scale).expect("observation"))
        .collect::<Vec<_>>();
    let err = evaluate(contract, &observations).expect_err("injected admissions must violate");
    match err {
        carrick_conformance_contract::EvaluationError::ScalingViolation { metric, .. } => {
            assert_eq!(metric, WorkMetric::TaskAdmissions);
        }
        other => panic!("expected ScalingViolation, got: {other:?}"),
    }
}
