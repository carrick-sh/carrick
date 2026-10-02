#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_xtask::probe_coverage::{
    CoverageError, ProbeIdentity, ReviewedRetirementRecord, load_coverage_base, validate_coverage,
};
use carrick_xtask::probe_inventory::{
    ProbeInventoryRow, derive_partition, load_inventory_from_str, validate_source_membership,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn sample_row(class: &str, runner: &str, excluded: bool) -> ProbeInventoryRow {
    ProbeInventoryRow {
        class: class.to_string(),
        runner: runner.to_string(),
        excluded,
        contract_ids: None,
    }
}

fn sample_identity(class: &str, runner: &str, excluded: bool) -> ProbeIdentity {
    ProbeIdentity {
        class: class.to_string(),
        runner: runner.to_string(),
        excluded,
    }
}

#[test]
fn duplicate_inventory_key_fails() {
    let raw = r#"{
        "probe_a": {
            "class": "conformance",
            "runner": "generic",
            "excluded": false
        },
        "probe_a": {
            "class": "conformance",
            "runner": "generic",
            "excluded": false
        }
    }"#;
    let res = load_inventory_from_str(raw);
    assert!(res.is_err(), "duplicate inventory keys must be rejected");
}

#[test]
fn source_inventory_drift_fails() {
    let inv_names = BTreeSet::from(["probe_a".to_string(), "probe_b".to_string()]);
    let src_names = BTreeSet::from(["probe_a".to_string(), "probe_c".to_string()]);
    let res = validate_source_membership(&inv_names, &src_names);
    assert!(
        res.is_err(),
        "inventory and source mismatch must be rejected"
    );
}

#[test]
fn free_addition_passes() {
    let base_head = "commit_1";
    let base_probes = BTreeMap::from([(
        "probe_a".to_string(),
        sample_identity("conformance", "generic", false),
    )]);
    let current_inventory = BTreeMap::from([
        (
            "probe_a".to_string(),
            sample_row("conformance", "generic", false),
        ),
        (
            "probe_new".to_string(),
            sample_row("conformance", "generic", false),
        ),
    ]);
    let sources = BTreeSet::from(["probe_a".to_string(), "probe_new".to_string()]);
    let retirements = Vec::new();

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(
        res.is_ok(),
        "free addition with valid generic runner must pass without retirement record: {res:?}"
    );
}

#[test]
fn coordinated_source_and_inventory_deletion_fails() {
    let base_head = "commit_1";
    let base_probes = BTreeMap::from([
        (
            "probe_a".to_string(),
            sample_identity("conformance", "generic", false),
        ),
        (
            "probe_b".to_string(),
            sample_identity("conformance", "generic", false),
        ),
    ]);
    // probe_b is deleted from BOTH inventory and sources
    let current_inventory = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    let sources = BTreeSet::from(["probe_a".to_string()]);
    let retirements = Vec::new();

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(
        res.is_err(),
        "coordinated deletion of probe_b must fail coverage ratchet without review"
    );
}

#[test]
fn exclusion_requires_review() {
    let base_head = "commit_1";
    let base_probes = BTreeMap::from([(
        "probe_a".to_string(),
        sample_identity("conformance", "generic", false),
    )]);
    let current_inventory = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", true),
    )]);
    let sources = BTreeSet::from(["probe_a".to_string()]);
    let retirements = Vec::new();

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(
        res.is_err(),
        "setting excluded: true must require a retirement review record"
    );
}

#[test]
fn reclassification_requires_review() {
    let base_head = "commit_1";
    let base_probes = BTreeMap::from([(
        "probe_a".to_string(),
        sample_identity("conformance", "generic", false),
    )]);
    let current_inventory = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("performance", "generic", false),
    )]);
    let sources = BTreeSet::from(["probe_a".to_string()]);
    let retirements = Vec::new();

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(res.is_err(), "reclassifying probe_a must require review");
}

#[test]
fn runner_change_requires_review() {
    let base_head = "commit_1";
    let base_probes = BTreeMap::from([(
        "probe_a".to_string(),
        sample_identity("conformance", "generic", false),
    )]);
    let current_inventory = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "bridge_tcp_peer", false),
    )]);
    let sources = BTreeSet::from(["probe_a".to_string()]);
    let retirements = Vec::new();

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(res.is_err(), "runner change must require review");
}

#[test]
fn exact_reviewed_retirement_passes_ratchet() {
    let base_head = "commit_1";
    let before = sample_identity("conformance", "generic", false);
    let base_probes = BTreeMap::from([("probe_a".to_string(), before.clone())]);
    let current_inventory = BTreeMap::new();
    let sources = BTreeSet::new();
    let retirements = vec![ReviewedRetirementRecord {
        base_head: base_head.to_string(),
        probe: "probe_a".to_string(),
        before,
        after: None,
        rationale: "retired as obsolete".to_string(),
        work_item: "B2".to_string(),
        director_review: "ref-review-123".to_string(),
    }];

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(res.is_ok(), "exact reviewed retirement must pass: {res:?}");
}

#[test]
fn wrong_base_review_fails() {
    let base_head = "commit_1";
    let before = sample_identity("conformance", "generic", false);
    let base_probes = BTreeMap::from([("probe_a".to_string(), before.clone())]);
    let current_inventory = BTreeMap::new();
    let sources = BTreeSet::new();
    let retirements = vec![ReviewedRetirementRecord {
        base_head: "wrong_commit_2".to_string(),
        probe: "probe_a".to_string(),
        before,
        after: None,
        rationale: "retired as obsolete".to_string(),
        work_item: "B2".to_string(),
        director_review: "ref-review-123".to_string(),
    }];

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    match res {
        Err(CoverageError::WrongBase { .. }) | Err(CoverageError::UnreviewedRemoval { .. }) => {}
        other => panic!("expected WrongBase or UnreviewedRemoval error, got: {other:?}"),
    }
}

#[test]
fn incomplete_review_fails() {
    let base_head = "commit_1";
    let before = sample_identity("conformance", "generic", false);
    let base_probes = BTreeMap::from([("probe_a".to_string(), before.clone())]);
    let current_inventory = BTreeMap::new();
    let sources = BTreeSet::new();
    let retirements = vec![ReviewedRetirementRecord {
        base_head: base_head.to_string(),
        probe: "probe_a".to_string(),
        before,
        after: None,
        rationale: "".to_string(), // Empty rationale!
        work_item: "B2".to_string(),
        director_review: "ref-review-123".to_string(),
    }];

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(
        res.is_err(),
        "incomplete review record with empty rationale must fail"
    );
}

#[test]
fn partition_is_sorted_disjoint_and_complete() {
    let mut inventory = BTreeMap::new();
    let probe_names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta"];
    for name in probe_names {
        inventory.insert(
            name.to_string(),
            sample_row("conformance", "generic", false),
        );
    }
    // Add non-generic or excluded or non-conformance rows to test filtering
    inventory.insert(
        "perf_1".to_string(),
        sample_row("performance", "generic", false),
    );
    inventory.insert(
        "excl_1".to_string(),
        sample_row("conformance", "generic", true),
    );
    inventory.insert(
        "ded_1".to_string(),
        sample_row("conformance", "bridge_tcp_peer", false),
    );

    let partition = derive_partition(&inventory);
    assert_eq!(
        partition.generic_names,
        vec!["alpha", "beta", "delta", "epsilon", "eta", "gamma", "zeta"]
    );

    // Shards must be disjoint and form complete union
    let mut union = BTreeSet::new();
    for (idx, shard) in partition.shards.iter().enumerate() {
        let mut sorted = shard.clone();
        sorted.sort();
        assert_eq!(shard, &sorted, "shard {idx} must be sorted");
        for item in shard {
            assert!(
                union.insert(item.clone()),
                "shard {idx} has duplicate item: {item}"
            );
        }
    }
    assert_eq!(
        union,
        partition.generic_names.into_iter().collect::<BTreeSet<_>>()
    );
}

#[test]
fn landing_base_protects_later_additions() {
    // landing_base contains a probe added after initial bootstrap
    let landing_base_head = "commit_landing";
    let base_probes = BTreeMap::from([
        (
            "bootstrap_probe".to_string(),
            sample_identity("conformance", "generic", false),
        ),
        (
            "post_bootstrap_probe".to_string(),
            sample_identity("conformance", "generic", false),
        ),
    ]);
    // Current inventory attempts to delete the newly added probe without review
    let current_inventory = BTreeMap::from([(
        "bootstrap_probe".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    let sources = BTreeSet::from(["bootstrap_probe".to_string()]);
    let retirements = Vec::new();

    let res = validate_coverage(
        landing_base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(
        res.is_err(),
        "landing base must protect later additions from unreviewed removal"
    );
}

#[test]
fn fixture_coverage_base_loads_correctly() {
    let fixture_path = Path::new("tests/fixtures/probe_coverage.json");
    let base = load_coverage_base(fixture_path).expect("load fixture base");
    assert_eq!(base.schema, "carrick-probe-coverage-base-v1");
    assert_eq!(base.probes.len(), 3);
}

#[test]
fn refresh_base_refuses_to_drop_unreviewed_row() {
    let base_head = "commit_1";
    let base_probes = BTreeMap::from([
        (
            "probe_a".to_string(),
            sample_identity("conformance", "generic", false),
        ),
        (
            "probe_b".to_string(),
            sample_identity("conformance", "generic", false),
        ),
    ]);
    let current_inventory = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    let sources = BTreeSet::from(["probe_a".to_string()]);
    let retirements = Vec::new();

    let res = validate_coverage(
        base_head,
        &base_probes,
        &current_inventory,
        &sources,
        &retirements,
    );
    assert!(
        res.is_err(),
        "refreshing base must refuse to drop an unreviewed row"
    );
}

