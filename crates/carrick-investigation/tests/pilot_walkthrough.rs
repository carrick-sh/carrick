//! A scripted narrative is not a real pilot, even if it starts with an LTP row.
use carrick_conformance_contract::ExecutionLayer;
use carrick_investigation::Stage;

#[test]
fn synthetic_pilot_narrative_cannot_reach_diagnosis() {
    assert!(
        Stage::validate_transition(
            &Stage::Reducing {
                layer: ExecutionLayer::VmFree,
                preserved_mechanisms: vec!["connect".into()]
            },
            &Stage::Diagnosing {
                red_evidence: vec!["rev-21816: SemanticMismatch".into()],
                fixture_active: true
            }
        )
        .is_err()
    );
}
