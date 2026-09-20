use carrick_conformance_contract::{CapabilityClass, ContractId, ExecutionLayer};
use carrick_investigation::{
    Investigation, InvestigationError, InvestigationId, SelectedFailure, Stage,
};

fn sample_failure() -> SelectedFailure {
    SelectedFailure {
        suite: "ltp-futex01".to_string(),
        test_id: "futex_wake_01".to_string(),
        run_id: "conf-12345-c01".to_string(),
        binary_sha256: "abc123sha".to_string(),
        details: "EAGAIN != 0".to_string(),
    }
}

#[test]
fn cannot_skip_classified_stage() {
    let mut inv = Investigation::new(
        InvestigationId::new("inv-test-01").unwrap(),
        sample_failure(),
    );
    assert_eq!(inv.stage, Stage::Queued);

    // Attempting to jump directly to Reducing must fail
    let res = inv.transition(Stage::Reducing {
        layer: ExecutionLayer::VmFree,
        preserved_mechanisms: vec!["waiters".to_string()],
    });

    assert!(matches!(
        res,
        Err(InvestigationError::InvalidTransition { .. })
    ));
}

#[test]
fn diagnosing_requires_red_evidence() {
    let mut inv = Investigation::new(
        InvestigationId::new("inv-test-02").unwrap(),
        sample_failure(),
    );

    inv.transition(Stage::Classified {
        contract: ContractId::new("kernel.futex.contention").unwrap(),
        capability: CapabilityClass::VmFreeExisting {
            capability: "futex_wake".to_string(),
        },
    })
    .unwrap();

    inv.transition(Stage::Reducing {
        layer: ExecutionLayer::VmFree,
        preserved_mechanisms: vec!["wake_cardinality".to_string()],
    })
    .unwrap();

    // Transition to Diagnosing with empty red evidence must fail
    let res = inv.transition(Stage::Diagnosing {
        red_evidence: vec![],
        fixture_active: true,
    });
    assert!(matches!(res, Err(InvestigationError::MissingRedEvidence)));
}

#[test]
fn parking_and_resumption_restores_prior_stage() {
    let mut inv = Investigation::new(
        InvestigationId::new("inv-test-03").unwrap(),
        sample_failure(),
    );

    inv.transition(Stage::Classified {
        contract: ContractId::new("kernel.futex.contention").unwrap(),
        capability: CapabilityClass::VmFreeExisting {
            capability: "futex_wake".to_string(),
        },
    })
    .unwrap();

    let before_park = inv.stage.clone();

    inv.park(
        "Experiment budget limit reached".to_string(),
        "Budget refreshed by operator".to_string(),
    )
    .unwrap();

    assert!(matches!(inv.stage, Stage::Parked { .. }));

    inv.resume().unwrap();
    assert_eq!(inv.stage, before_park);
}
