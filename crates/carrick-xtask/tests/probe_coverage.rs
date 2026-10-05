#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_xtask::probe_coverage::{
    CoverageError, ProbeIdentity, ReviewedRetirementRecord, run_probe_coverage,
    run_probe_coverage_with_env, validate_coverage,
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

fn init_git_repo() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let repo_path = dir.path().to_path_buf();

    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(&repo_path)
            .output()
            .expect("git execution");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    git(&["init", "-b", "main"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "Test User"]);
    git(&["config", "commit.gpgsign", "false"]);

    std::fs::create_dir_all(repo_path.join("conformance-probes/src/bin")).expect("mkdir src/bin");
    std::fs::write(
        repo_path.join("conformance-probes/reviewed-retirements.json"),
        "[]\n",
    )
    .expect("write retirements");

    (dir, repo_path)
}

fn write_probe_source(repo_path: &Path, name: &str) {
    let p = repo_path
        .join("conformance-probes/src/bin")
        .join(format!("{name}.rs"));
    std::fs::write(&p, "// probe source\nfn main() {}\n").expect("write probe source");
}

fn remove_probe_source(repo_path: &Path, name: &str) {
    let p = repo_path
        .join("conformance-probes/src/bin")
        .join(format!("{name}.rs"));
    let _ = std::fs::remove_file(&p);
}

fn write_inventory(repo_path: &Path, rows: &BTreeMap<String, ProbeInventoryRow>) {
    let p = repo_path.join("conformance-probes/probe-inventory.json");
    let json = serde_json::to_string_pretty(rows).expect("serialize inventory");
    std::fs::write(&p, format!("{json}\n")).expect("write inventory");
}

fn write_retirements(repo_path: &Path, records: &[ReviewedRetirementRecord]) {
    let p = repo_path.join("conformance-probes/reviewed-retirements.json");
    let json = serde_json::to_string_pretty(records).expect("serialize retirements");
    std::fs::write(&p, format!("{json}\n")).expect("write retirements");
}

fn git_commit_all(repo_path: &Path, msg: &str) {
    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(repo_path)
            .output()
            .expect("git execution");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    };

    git(&["add", "."]);
    git(&["commit", "-m", msg]);
}

fn git_checkout_new_branch(repo_path: &Path, branch: &str) {
    let output = std::process::Command::new("git")
        .args(["checkout", "-b", branch])
        .current_dir(repo_path)
        .output()
        .expect("git checkout");
    assert!(output.status.success());
}

fn git_checkout_branch(repo_path: &Path, branch: &str) {
    let output = std::process::Command::new("git")
        .args(["checkout", branch])
        .current_dir(repo_path)
        .output()
        .expect("git checkout");
    assert!(output.status.success());
}

#[test]
fn self_comparison_fails_clearly() {
    let (_dir, repo_path) = init_git_repo();
    write_probe_source(&repo_path, "probe_a");
    let inv = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "commit 1");

    // Explicitly passing HEAD
    let res = run_probe_coverage(Some(&repo_path), Some("HEAD"));
    match res {
        Err(CoverageError::CannotCompareHeadToItself { .. }) => {}
        other => panic!("expected CannotCompareHeadToItself, got: {other:?}"),
    }

    // Local resolution on main (where merge-base with main is HEAD)
    // Run with explicit env_base=None so it does not inherit CARRICK_PROBE_COVERAGE_BASE from CI
    let res_none = run_probe_coverage_with_env(Some(&repo_path), None, None);
    match res_none {
        Err(CoverageError::CannotCompareHeadToItself { .. }) => {}
        other => panic!("expected CannotCompareHeadToItself on local resolution, got: {other:?}"),
    }

    // Also verify via child process with CARRICK_PROBE_COVERAGE_BASE removed from environment
    let bin = env!("CARGO_BIN_EXE_carrick-xtask");
    let output = std::process::Command::new(bin)
        .arg("--root")
        .arg(&repo_path)
        .arg("probe-coverage")
        .env_remove("CARRICK_PROBE_COVERAGE_BASE")
        .output()
        .expect("execute carrick-xtask child process");
    assert!(
        !output.status.success(),
        "child process must fail on self-comparison"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot compare HEAD to itself")
            || stderr.contains("CannotCompareHeadToItself"),
        "unexpected stderr from child process: {stderr}"
    );
}

#[test]
fn diverged_branch_history_uses_merge_base() {
    let (_dir, repo_path) = init_git_repo();

    // M1: base commit with probe_base
    write_probe_source(&repo_path, "probe_base");
    let mut inv = BTreeMap::from([(
        "probe_base".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "M1: base commit");

    // Create feature branch
    git_checkout_new_branch(&repo_path, "feature");
    // F1: add probe_feat
    write_probe_source(&repo_path, "probe_feat");
    inv.insert(
        "probe_feat".to_string(),
        sample_row("conformance", "generic", false),
    );
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "F1: feature commit");

    // Checkout main, create M2 (diverging)
    git_checkout_branch(&repo_path, "main");
    // M2: add probe_main (not present on feature branch)
    write_probe_source(&repo_path, "probe_main");
    let main_inv = BTreeMap::from([
        (
            "probe_base".to_string(),
            sample_row("conformance", "generic", false),
        ),
        (
            "probe_main".to_string(),
            sample_row("conformance", "generic", false),
        ),
    ]);
    write_inventory(&repo_path, &main_inv);
    git_commit_all(&repo_path, "M2: main branch advances");

    // Switch back to feature branch
    git_checkout_branch(&repo_path, "feature");

    // Probe coverage against "main" must compute merge-base (M1) and pass
    let res = run_probe_coverage(Some(&repo_path), Some("main"));
    assert!(
        res.is_ok(),
        "diverged history must use merge-base and pass: {res:?}"
    );
}

#[test]
fn git_probe_removal_fails() {
    let (_dir, repo_path) = init_git_repo();
    write_probe_source(&repo_path, "probe_a");
    write_probe_source(&repo_path, "probe_b");
    let inv = BTreeMap::from([
        (
            "probe_a".to_string(),
            sample_row("conformance", "generic", false),
        ),
        (
            "probe_b".to_string(),
            sample_row("conformance", "generic", false),
        ),
    ]);
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "M1: two probes");

    git_checkout_new_branch(&repo_path, "feature");
    remove_probe_source(&repo_path, "probe_b");
    let shrunken_inv = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    write_inventory(&repo_path, &shrunken_inv);
    git_commit_all(&repo_path, "F1: remove probe_b without review");

    let res = run_probe_coverage(Some(&repo_path), Some("main"));
    match res {
        Err(CoverageError::UnreviewedRemoval { probe, .. }) => {
            assert_eq!(probe, "probe_b");
        }
        other => panic!("expected UnreviewedRemoval for probe_b, got: {other:?}"),
    }
}

#[test]
fn git_probe_identity_change_fails() {
    let (_dir, repo_path) = init_git_repo();
    write_probe_source(&repo_path, "probe_a");
    let inv = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "M1: probe_a");

    git_checkout_new_branch(&repo_path, "feature");
    let weakened_inv = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", true),
    )]);
    write_inventory(&repo_path, &weakened_inv);
    git_commit_all(&repo_path, "F1: exclude probe_a");

    let res = run_probe_coverage(Some(&repo_path), Some("main"));
    match res {
        Err(CoverageError::UnreviewedChange { probe, .. }) => {
            assert_eq!(probe, "probe_a");
        }
        other => panic!("expected UnreviewedChange for probe_a, got: {other:?}"),
    }
}

#[test]
fn git_wrong_base_review_fails() {
    let (_dir, repo_path) = init_git_repo();
    write_probe_source(&repo_path, "probe_a");
    let inv = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "M1: probe_a");

    git_checkout_new_branch(&repo_path, "feature");
    remove_probe_source(&repo_path, "probe_a");
    let empty_inv = BTreeMap::new();
    write_inventory(&repo_path, &empty_inv);

    let retirement = ReviewedRetirementRecord {
        base_head: "0123456789abcdef0123456789abcdef01234567".to_string(),
        probe: "probe_a".to_string(),
        before: sample_identity("conformance", "generic", false),
        after: None,
        rationale: "retired for testing".to_string(),
        work_item: "PR-5".to_string(),
        director_review: "ref-1".to_string(),
    };
    write_retirements(&repo_path, &[retirement]);
    git_commit_all(&repo_path, "F1: retirement with wrong base");

    let res = run_probe_coverage(Some(&repo_path), Some("main"));
    match res {
        Err(CoverageError::WrongBase { probe, .. }) => {
            assert_eq!(probe, "probe_a");
        }
        other => panic!("expected WrongBase for probe_a, got: {other:?}"),
    }
}

#[test]
fn git_probe_addition_passes_without_baseline_file() {
    let (_dir, repo_path) = init_git_repo();
    write_probe_source(&repo_path, "probe_a");
    let mut inv = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "M1: probe_a");

    git_checkout_new_branch(&repo_path, "feature");
    write_probe_source(&repo_path, "probe_new");
    inv.insert(
        "probe_new".to_string(),
        sample_row("conformance", "generic", false),
    );
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "F1: add probe_new");

    // Confirm coverage-base.json does not exist
    assert!(
        !repo_path
            .join("conformance-probes/coverage-base.json")
            .exists()
    );

    let res = run_probe_coverage(Some(&repo_path), Some("main"));
    assert!(
        res.is_ok(),
        "adding probe without coverage-base.json must succeed: {res:?}"
    );

    // Confirm coverage-base.json was not created
    assert!(
        !repo_path
            .join("conformance-probes/coverage-base.json")
            .exists()
    );
}

#[test]
fn multi_commit_push_removal_detected_by_push_base() {
    let (_dir, repo_path) = init_git_repo();
    write_probe_source(&repo_path, "probe_a");
    write_probe_source(&repo_path, "probe_b");
    let inv = BTreeMap::from([
        (
            "probe_a".to_string(),
            sample_row("conformance", "generic", false),
        ),
        (
            "probe_b".to_string(),
            sample_row("conformance", "generic", false),
        ),
    ]);
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "Commit A: base with probe_a and probe_b");
    let head_a =
        carrick_xtask::command::run_checked("git", ["rev-parse", "HEAD"], Some(&repo_path))
            .expect("rev-parse A")
            .stdout
            .trim()
            .to_string();

    // Commit B: unreviewed removal of probe_b
    remove_probe_source(&repo_path, "probe_b");
    let shrunken_inv = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    write_inventory(&repo_path, &shrunken_inv);
    git_commit_all(&repo_path, "Commit B: remove probe_b without review");

    // Commit C: unrelated documentation change
    let doc_path = repo_path.join("README.md");
    std::fs::write(&doc_path, "unrelated documentation update\n").expect("write doc");
    git_commit_all(&repo_path, "Commit C: update docs");

    // Flawed HEAD~1 comparison (as previously in CI): compares C to B, escapes detection!
    let head1_res = run_probe_coverage(Some(&repo_path), Some("HEAD~1"));
    assert!(
        head1_res.is_ok(),
        "comparing against HEAD~1 blindly passes despite probe_b removal in B: {head1_res:?}"
    );

    // Correct push base comparison (github.event.before, which is commit A):
    // compares C to A, catches unreviewed probe removal in B!
    let push_res = run_probe_coverage(Some(&repo_path), Some(&head_a));
    match push_res {
        Err(CoverageError::UnreviewedRemoval { probe, .. }) => {
            assert_eq!(probe, "probe_b");
        }
        other => panic!(
            "expected UnreviewedRemoval when comparing against push base commit A, got: {other:?}"
        ),
    }
}

#[test]
fn all_zero_push_base_fails_clearly() {
    let (_dir, repo_path) = init_git_repo();
    write_probe_source(&repo_path, "probe_a");
    let inv = BTreeMap::from([(
        "probe_a".to_string(),
        sample_row("conformance", "generic", false),
    )]);
    write_inventory(&repo_path, &inv);
    git_commit_all(&repo_path, "commit 1");

    let zero_base = "0000000000000000000000000000000000000000";
    let res = run_probe_coverage_with_env(Some(&repo_path), None, Some(zero_base));
    match res {
        Err(CoverageError::BaseResolution(msg)) => {
            assert!(
                msg.contains("all-zero"),
                "expected all-zero error, got: {msg}"
            );
        }
        other => panic!("expected BaseResolution error for all-zero push base, got: {other:?}"),
    }
}
