#![allow(clippy::expect_used, clippy::unwrap_used)]

use carrick_conformance_contract::{
    Budget, Completeness, ConformanceContract, ContractFailure, ContractId, ContractObservation,
    ContractRegistry, ExecutionLayer, RuntimeRatioPolicy, SemanticAssertion, StructuralBudget,
    TimingDistribution, TimingStatistic, WorkMetric, WorkSnapshot, evaluate,
};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn futex_contract() -> ConformanceContract {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    registry
        .get(&ContractId::new("kernel.futex.contention").expect("id"))
        .expect("futex contract")
        .clone()
}

fn observation(layer: ExecutionLayer, scale: u64) -> ContractObservation {
    let mut work = WorkSnapshot::new();
    work.insert(WorkMetric::ContinuationEnrollments, scale)
        .unwrap();
    work.insert(WorkMetric::FutexQueueVisits, scale + 1)
        .unwrap();

    ContractObservation {
        contract_id: ContractId::new("kernel.futex.contention").unwrap(),
        layer,
        implementation_revision: "head123".into(),
        fixture_identity: "probe:futexpingpong".into(),
        scale,
        semantic_assertions: vec![SemanticAssertion::pass("wake_cardinality")],
        work: Some(work),
        timing: None,
        completeness: Completeness::Complete,
    }
}

fn observation_with_visits(scale: u64, visits: u64) -> ContractObservation {
    let mut obs = observation(ExecutionLayer::VmFree, scale);
    let mut work = WorkSnapshot::new();
    work.insert(WorkMetric::ContinuationEnrollments, scale)
        .unwrap();
    work.insert(WorkMetric::FutexQueueVisits, visits).unwrap();
    obs.work = Some(work);
    obs
}

#[test]
fn instrumented_observation_cannot_supply_timing_evidence() {
    let mut obs = observation(ExecutionLayer::EmbedStructural, 8);
    obs.timing = Some(TimingDistribution::new(vec![3.0; 20]).expect("timing"));
    assert!(matches!(
        obs.validate(),
        Err(ContractFailure::IncompleteMeasurement { reason, .. })
            if reason.contains("instrumented layer cannot supply timing")
    ));
}

#[test]
fn uninstrumented_timing_observation_cannot_claim_structural_completeness() {
    let mut obs = observation(ExecutionLayer::EmbedTiming, 8);
    obs.timing = Some(TimingDistribution::new(vec![1.5; 20]).expect("timing"));
    // work is Some(WorkSnapshot)
    assert!(matches!(
        obs.validate(),
        Err(ContractFailure::IncompleteMeasurement { reason, .. })
            if reason.contains("uninstrumented") || reason.contains("structural completeness")
    ));
}

#[test]
fn affine_failure_reports_smallest_scale_point() {
    let contract = futex_contract();
    let observations = [
        observation_with_visits(1, 2),
        observation_with_visits(8, 12),
    ];
    assert!(matches!(
        evaluate(&contract, &observations),
        Err(ContractFailure::ScalingViolation {
            scale: 8,
            actual: 12,
            maximum: 9,
            ..
        })
    ));
}

#[test]
fn exact_budget_success_and_failure() {
    let mut contract = futex_contract();
    contract.structural_budgets = vec![StructuralBudget {
        budget: Budget::Exact {
            metric: WorkMetric::ContinuationEnrollments,
            value: 1,
        },
        layers: vec![ExecutionLayer::VmFree, ExecutionLayer::EmbedStructural],
        rationale: Some("exact test".into()),
    }];

    let pass_obs = [observation(ExecutionLayer::VmFree, 1)];
    assert!(evaluate(&contract, &pass_obs).is_ok());

    let fail_obs = [observation(ExecutionLayer::VmFree, 8)];
    assert!(matches!(
        evaluate(&contract, &fail_obs),
        Err(ContractFailure::WorkBudgetExceeded {
            metric: WorkMetric::ContinuationEnrollments,
            actual: 8,
            maximum: 1,
            ..
        })
    ));
}

#[test]
fn upper_bound_budget_failure() {
    let mut contract = futex_contract();
    contract.structural_budgets = vec![StructuralBudget {
        budget: Budget::UpperBound {
            metric: WorkMetric::FutexQueueVisits,
            maximum: 5,
        },
        layers: vec![ExecutionLayer::VmFree, ExecutionLayer::EmbedStructural],
        rationale: Some("upper bound test".into()),
    }];

    let fail_obs = [observation_with_visits(8, 6)];
    assert!(matches!(
        evaluate(&contract, &fail_obs),
        Err(ContractFailure::WorkBudgetExceeded {
            metric: WorkMetric::FutexQueueVisits,
            actual: 6,
            maximum: 5,
            ..
        })
    ));
}

#[test]
fn structural_budget_applies_only_to_named_layer() {
    let mut contract = futex_contract();
    contract.structural_budgets = vec![StructuralBudget {
        budget: Budget::Exact {
            metric: WorkMetric::ContinuationEnrollments,
            value: 1,
        },
        layers: vec![ExecutionLayer::VmFree],
        rationale: Some("VM-free fixture body only".into()),
    }];

    assert!(
        evaluate(
            &contract,
            &[observation(ExecutionLayer::EmbedStructural, 8)]
        )
        .is_ok()
    );
    assert!(matches!(
        evaluate(&contract, &[observation(ExecutionLayer::VmFree, 8)]),
        Err(ContractFailure::WorkBudgetExceeded {
            actual: 8,
            maximum: 1,
            ..
        })
    ));
}

#[test]
fn missing_metric_fails_closed() {
    let contract = futex_contract();
    let mut obs = observation(ExecutionLayer::VmFree, 1);
    let mut work = WorkSnapshot::new();
    // Only insert ContinuationEnrollments, omitting FutexQueueVisits
    work.insert(WorkMetric::ContinuationEnrollments, 1).unwrap();
    obs.work = Some(work);

    assert!(matches!(
        evaluate(&contract, &[obs]),
        Err(ContractFailure::IncompleteMeasurement { reason, .. })
            if reason.contains("missing work metric")
    ));
}

#[test]
fn dropped_events_fail_closed() {
    let contract = futex_contract();
    let mut obs = observation(ExecutionLayer::VmFree, 1);
    obs.work = Some(WorkSnapshot::new().with_dropped_events(5));

    assert!(matches!(
        evaluate(&contract, &[obs]),
        Err(ContractFailure::IncompleteMeasurement { reason, .. })
            if reason.contains("dropped events")
    ));
}

#[test]
fn fixture_mismatch_fails_closed() {
    let contract = futex_contract();
    let mut obs = observation(ExecutionLayer::VmFree, 1);
    obs.fixture_identity = "wrong_fixture".into();

    assert!(matches!(
        evaluate(&contract, &[obs]),
        Err(ContractFailure::FixtureMismatch { ref expected, ref actual, .. })
            if expected == "probe:futexpingpong" && actual == "wrong_fixture"
    ));
}

#[test]
fn semantic_mismatch_fails_closed() {
    let contract = futex_contract();
    let mut obs = observation(ExecutionLayer::VmFree, 1);
    obs.semantic_assertions = vec![SemanticAssertion::fail(
        "wake_cardinality",
        "woke 0, expected 1",
    )];

    assert!(matches!(
        evaluate(&contract, &[obs]),
        Err(ContractFailure::SemanticMismatch { ref assertion, .. })
            if assertion.contains("woke 0")
    ));
}

#[test]
fn timing_ratio_failure_fails_closed() {
    let mut contract = futex_contract();
    contract.runtime_ratio = Some(RuntimeRatioPolicy {
        maximum: 2.0,
        statistic: TimingStatistic::P50,
        minimum_samples: 20,
    });

    let mut obs = observation(ExecutionLayer::EmbedTiming, 1);
    obs.work = None;
    obs.timing = Some(TimingDistribution::new(vec![2.5; 20]).expect("timing"));

    assert!(matches!(
        evaluate(&contract, &[obs]),
        Err(ContractFailure::RuntimeRatioExceeded { actual, maximum, .. })
            if (actual - 2.5).abs() < f64::EPSILON && (maximum - 2.0).abs() < f64::EPSILON
    ));
}

#[test]
fn unresolved_signed_binding_is_not_execution_coverage() {
    let registry = ContractRegistry::load(&repo_root()).unwrap();
    let mut contract = registry.require("kernel.fs.write-seek").unwrap().clone();
    contract.bindings.embed = None;
    contract.bindings.unresolved.insert(
        "embed_structural".into(),
        "test: binding not implemented".into(),
    );
    let mut obs = observation(ExecutionLayer::EmbedStructural, 1);
    obs.contract_id = contract.id.clone();
    obs.fixture_identity = contract.fixture.clone();
    assert!(matches!(
        evaluate(&contract, &[obs]),
        Err(ContractFailure::UnsupportedLayer { .. })
    ));
}

// These are verifier negative controls, not native execution observations.
// A copied HVF errno transcript or an empty counter snapshot must not qualify
// an execution adapter whose real bindings have not been implemented.
#[test]
fn native_syscall_contract_rejects_unbound_execution_evidence() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let id = ContractId::new("kernel.execution.native-synchronous-syscall").unwrap();
    let contract = registry.get(&id).expect("native syscall contract");
    for layer in [
        ExecutionLayer::VmFree,
        ExecutionLayer::EmbedStructural,
        ExecutionLayer::Docker,
    ] {
        let mut obs = observation(layer, 1);
        obs.contract_id = id.clone();
        obs.fixture_identity = contract.fixture.clone();
        obs.semantic_assertions = vec![SemanticAssertion::pass("negative-control-errno-only")];
        obs.work = None;
        assert!(matches!(
            evaluate(contract, &[obs]),
            Err(ContractFailure::UnsupportedLayer { layer: actual, .. }) if actual == layer
        ));
    }
    assert!(matches!(
        evaluate(contract, &[]),
        Err(ContractFailure::IncompleteMeasurement { .. })
    ));
}

#[test]
fn native_syscall_contract_requires_measured_zero_counters() {
    let registry = ContractRegistry::load(&repo_root()).expect("registry");
    let id = ContractId::new("kernel.execution.native-synchronous-syscall").unwrap();
    let mut contract = registry.get(&id).expect("native syscall contract").clone();
    // Enable only a local synthetic binding to exercise the budget checker.
    // This never registers a production binding or claims guest execution.
    contract.bindings.embed = Some("verifier-negative-control".into());
    let mut obs = observation(ExecutionLayer::EmbedStructural, 1);
    obs.contract_id = id;
    obs.fixture_identity = contract.fixture.clone();
    obs.work = Some(WorkSnapshot::new());
    assert!(matches!(evaluate(&contract, &[obs.clone()]),
        Err(ContractFailure::IncompleteMeasurement { reason, .. })
            if reason.contains("missing work metric")));
    for metric in [WorkMetric::HvfSyscallExits, WorkMetric::HostHeapAllocations] {
        let mut work = WorkSnapshot::new();
        work.insert(WorkMetric::HvfSyscallExits, 0).unwrap();
        work.insert(WorkMetric::HostHeapAllocations, 0).unwrap();
        work.insert(WorkMetric::KernelDispatches, 2).unwrap();
        // Build a fresh census with exactly one forbidden unit of work.
        let mut violation = WorkSnapshot::new();
        for item in [
            WorkMetric::HvfSyscallExits,
            WorkMetric::HostHeapAllocations,
            WorkMetric::KernelDispatches,
        ] {
            violation
                .insert(
                    item,
                    if item == metric {
                        1
                    } else {
                        work.get(item).unwrap()
                    },
                )
                .unwrap();
        }
        obs.work = Some(violation);
        assert!(matches!(evaluate(&contract, &[obs.clone()]),
            Err(ContractFailure::WorkBudgetExceeded { metric: actual, maximum: 0, .. })
                if actual == metric));
    }
}
