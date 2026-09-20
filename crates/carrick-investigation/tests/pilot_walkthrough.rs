use std::path::Path;

use carrick_conformance_contract::{CapabilityClass, ClaimId, ContractId, ExecutionLayer};
use carrick_investigation::{
    Diagnosis, ExperimentPlan, ExperimentResult, Hypothesis, Investigation, InvestigationId,
    ProposedCorrection, ReviewPackage, Stage, scan_results,
};
use tempfile::tempdir;

#[test]
fn pilot_walkthrough_connect01_reaches_review_ready() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let baseline_path = repo_root.join("scripts/conformance/baseline.jsonl");
    assert!(baseline_path.exists(), "baseline.jsonl must exist");

    // 1. Intake: scan baseline results for candidates
    let candidates = scan_results(&baseline_path).expect("intake scanning must succeed");
    assert!(!candidates.is_empty(), "must find candidates in baseline");

    let connect_candidate = candidates
        .iter()
        .find(|c| c.failure.suite == "ltp-connect01")
        .expect("ltp-connect01 must be among candidates");

    // Initialize investigation in Queued stage
    let inv_id = InvestigationId::new("inv-pilot-connect01").unwrap();
    let mut inv = Investigation::new(inv_id.clone(), connect_candidate.failure.clone());
    assert_eq!(inv.stage, Stage::Queued);

    // 2. Classify: non-VMM decision. AF_UNIX / loopback socket connect error semantics
    // can be verified in carrick-kernel-example without a VMM.
    let contract_id = ContractId::new("kernel.net.connect-semantics").unwrap();
    let capability = CapabilityClass::VmFreeExisting {
        capability: "carrick-kernel-example::socket_connect".to_string(),
    };

    inv.transition(Stage::Classified {
        contract: contract_id.clone(),
        capability: capability.clone(),
    })
    .expect("transition to Classified must succeed");

    // 3. Reducing: choose cheapest capable layer (VmFree) and preserve socket error invariants
    inv.transition(Stage::Reducing {
        layer: ExecutionLayer::VmFree,
        preserved_mechanisms: vec![
            "socket_connect_immediate_refusal".to_string(),
            "unconnected_state_settlement".to_string(),
        ],
    })
    .expect("transition to Reducing must succeed");

    // Plan and record diagnostic experiments
    let mut exp1 = ExperimentResult::new(
        ExperimentPlan {
            question:
                "Does non-blocking connect to closed port return ECONNREFUSED or EINPROGRESS?"
                    .to_string(),
            discriminating_outcomes: vec![
                "ECONNREFUSED -> conformant Linux semantics".to_string(),
                "EINPROGRESS -> asynchronous state leak".to_string(),
            ],
            required_layer: ExecutionLayer::VmFree,
            estimated_duration_seconds: 5,
        },
        1,
    );
    exp1.record_observation("carrick returned EINPROGRESS where Linux returns ECONNREFUSED");
    exp1.record_inference(
        "connection state machine entered connecting state before checking peer listener",
    );
    exp1.success = true;

    inv.hypotheses.push(Hypothesis {
        id: "H1".to_string(),
        statement: "Socket state machine transitions to Connecting before admission validation"
            .to_string(),
        tested: true,
        outcome: Some("Confirmed by experiment 1".to_string()),
    });

    // 4. Diagnosing: attach red evidence from known-bad revision
    inv.transition(Stage::Diagnosing {
        red_evidence: vec![
            "rev-21816: SemanticMismatch: connect01 test 7 failed: expected ECONNREFUSED (111), got EINPROGRESS (115)".to_string(),
        ],
        fixture_active: true,
    })
    .expect("transition to Diagnosing must succeed");

    // 5. ReviewReady: build review package and finalize
    let temp = tempdir().unwrap();
    let review_pkg_path = temp.path().join("inv-pilot-connect01-review.md");

    let review_package = ReviewPackage {
        failing_contract: contract_id,
        failing_claim: ClaimId::new("kernel.net.connect-semantics.immediate-refusal").unwrap(),
        linux_authority: vec![
            "man 2 connect: ECONNREFUSED No-one listening on the remote address".to_string(),
            "ltp/testcases/kernel/syscalls/connect/connect01.c".to_string(),
        ],
        diagnosis: Diagnosis {
            root_cause: "Connect operation enrolls in asynchronous wait before checking local endpoint listener presence"
                .to_string(),
            causal_evidence: vec![
                "connect01 line 84: connect() returned EINPROGRESS instead of ECONNREFUSED".to_string(),
                "Scripted kernel trace shows connection continuation enrolled unconditionally".to_string(),
            ],
        },
        proposed_correction: ProposedCorrection {
            summary: "Check local peer socket backlog readiness before deferring connect to asynchronous continuation"
                .to_string(),
            target_components: vec![
                "crates/carrick-kernel/src/dispatch/net.rs".to_string(),
            ],
            semantic_neutrality_assessment: "Preserves POSIX nonblocking semantics; affects only immediate refusal path on unlistened ports"
                .to_string(),
        },
        affected_invariants: vec![
            "AF_UNIX stream socket connect must fail immediately with ECONNREFUSED when listener backlog is closed"
                .to_string(),
        ],
        validation_plan: vec![
            "Run VM-free connect contract: cargo test -p carrick-kernel-example --test socket_connect".to_string(),
            "Run signed embed probe: just test-embed connect".to_string(),
            "Run LTP differential: just conformance --suite ltp-connect01".to_string(),
        ],
        open_higher_layer_gates: vec![
            ExecutionLayer::EmbedStructural,
            ExecutionLayer::Docker,
        ],
        hypotheses_considered: inv.hypotheses.clone(),
    };

    let md = review_package.render_markdown();
    std::fs::write(&review_pkg_path, md).unwrap();

    inv.transition(Stage::ReviewReady {
        review_package_path: review_pkg_path.clone(),
    })
    .expect("transition to ReviewReady must succeed");

    // Save durable investigation record
    let inv_log_path = temp.path().join("inv-pilot-connect01.jsonl");
    inv.save_to_file(&inv_log_path)
        .expect("saving investigation must succeed");

    // Verify durable record reloads accurately
    let reloaded = Investigation::load_from_file(&inv_log_path).expect("loading must succeed");
    assert_eq!(reloaded.id, inv.id);
    assert_eq!(reloaded.stage, inv.stage);
    assert_eq!(reloaded.history.len(), 5); // Queued -> Classified -> Reducing -> Diagnosing -> ReviewReady
}
