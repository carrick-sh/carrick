use carrick_conformance_contract::{CapabilityClass, ContractId, ExecutionLayer};
use carrick_investigation::{Investigation, InvestigationId, SelectedFailure, Stage};
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn investigation_full_lifecycle_and_jsonl_persistence() {
    let temp = tempdir().unwrap();
    let file_path = temp.path().join("inv-full-01.jsonl");

    let failure = SelectedFailure {
        suite: "ltp-futex01".to_string(),
        test_id: "futex_wake_01".to_string(),
        run_id: "conf-12345-c01".to_string(),
        binary_sha256: "abc123sha".to_string(),
        details: "EAGAIN != 0".to_string(),
    };

    let mut inv = Investigation::new(InvestigationId::new("inv-full-01").unwrap(), failure);

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

    inv.transition(Stage::Diagnosing {
        red_evidence: vec!["rev_bad_123: SemanticMismatch".to_string()],
        fixture_active: true,
    })
    .unwrap();

    let review_pkg = PathBuf::from("target/reviews/inv-full-01.md");
    inv.transition(Stage::ReviewReady {
        review_package_path: review_pkg.clone(),
    })
    .unwrap();

    // Persist to JSONL
    inv.save_to_file(&file_path).unwrap();
    assert!(file_path.exists());

    // Load from JSONL and verify round trip
    let loaded = Investigation::load_from_file(&file_path).unwrap();
    assert_eq!(inv.id, loaded.id);
    assert_eq!(inv.stage, loaded.stage);
    assert_eq!(inv.selected_failure, loaded.selected_failure);
    assert_eq!(inv.history.len(), loaded.history.len());
}
