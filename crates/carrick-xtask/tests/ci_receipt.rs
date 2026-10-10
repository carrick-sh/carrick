#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::accept::{
    AcceptReceipt, CleanupCount, ProbeDiff, StepResult, parse_failed_tests,
};
use carrick_xtask::ci_receipt::{Lane, artifact_name, diff, failure_keys, trusted_baseline_run};
use std::path::PathBuf;

fn step(name: &str, passed: bool, failed: &[&str]) -> StepResult {
    StepResult {
        name: name.into(),
        command: format!("just {name}"),
        exit_code: Some(if passed { 0 } else { 101 }),
        log_path: PathBuf::from(format!("target/el1-gate/x/{name}.log")),
        duration_s: 1.0,
        passed,
        error: None,
        failed_tests: failed.iter().map(|t| (*t).to_owned()).collect(),
    }
}

fn receipt(steps: Vec<StepResult>) -> AcceptReceipt {
    AcceptReceipt {
        schema_version: 1,
        timestamp: "20261010-000000".into(),
        head: "a".repeat(40),
        clean_tree: true,
        phase: "signed".into(),
        profile: "no-docker".into(),
        overall: "FAIL".into(),
        steps,
        skipped_steps: vec![],
        artifact: None,
        fixture_validation: None,
        el1: None,
        probe_diffs: vec![],
        cleanup_counts: vec![],
        fixture_bundle: None,
        host_load: Default::default(),
        failures: vec![],
    }
}

#[test]
fn cargo_failures_are_qualified_by_their_test_binary() {
    let log = "\
     Running unittests src/lib.rs (target/debug/deps/carrick_vmm_kvm-0123abcd4567ef89)
test vcpu::boots ... ok
test vcpu::traps ... FAILED
     Running tests/live_vcpu_x86.rs (target/debug/deps/live_vcpu_x86-89abcdef01234567)
test traps ... FAILED
test traps ... FAILED

failures:
    vcpu::traps
";
    assert_eq!(
        parse_failed_tests(log),
        vec!["carrick_vmm_kvm::vcpu::traps", "live_vcpu_x86::traps"]
    );
}

#[test]
fn diff_reports_new_and_fixed_failures_by_identity() {
    let base = receipt(vec![
        step("el1-embed", true, &["embed::el1_a", "embed::el1_b"]),
        step("fresh-executable-page", true, &[]),
    ]);
    let next = receipt(vec![
        step("el1-embed", false, &["embed::el1_b", "embed::el1_c"]),
        step("fresh-executable-page", true, &[]),
    ]);
    let result = diff(&base, &next).unwrap();
    assert_eq!(result.new, vec!["test:el1-embed:embed::el1_c"]);
    assert_eq!(result.fixed, vec!["test:el1-embed:embed::el1_a"]);
    assert!(diff(&base, &base).unwrap().new.is_empty());
}

#[test]
fn a_crashed_step_probe_diff_leak_or_dirty_tree_is_a_failure_identity() {
    let mut next = receipt(vec![
        step("build", false, &[]),
        step("probe-cases", false, &[]),
    ]);
    next.probe_diffs.push(ProbeDiff {
        step: "probe-cases".into(),
        probe: "case_pipe".into(),
        line: "DIFF case_pipe".into(),
    });
    next.cleanup_counts.push(CleanupCount {
        step: "build".into(),
        run_id: "r".into(),
        remaining_count: 2,
    });
    next.clean_tree = false;
    let keys: Vec<_> = failure_keys(&next).into_iter().collect();
    assert_eq!(
        keys,
        vec![
            "dirty-checkout",
            "leak:build",
            "probe:probe-cases:case_pipe",
            "step:build"
        ]
    );
    let result = diff(&receipt(vec![]), &next).unwrap();
    assert_eq!(result.new.len(), 4);
}

#[test]
fn receipts_of_different_gates_are_not_comparable() {
    let base = receipt(vec![]);
    let mut kvm = receipt(vec![]);
    kvm.phase = "host".into();
    kvm.profile = "kvm".into();
    assert!(diff(&base, &kvm).is_err());
}

#[test]
fn receipt_json_round_trips_failed_tests_and_tolerates_older_receipts() {
    let original = receipt(vec![step("kvm-tests", false, &["live_vcpu_x86::traps"])]);
    let restored: AcceptReceipt =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(restored.steps[0].failed_tests, ["live_vcpu_x86::traps"]);
    let mut value = serde_json::to_value(&original).unwrap();
    value["steps"][0]
        .as_object_mut()
        .unwrap()
        .remove("failed_tests");
    let older: AcceptReceipt = serde_json::from_value(value).unwrap();
    assert!(older.steps[0].failed_tests.is_empty());
}

fn run(event: &str, branch: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "event": event,
        "head_branch": branch,
        "head_sha": "b".repeat(40),
        "path": path,
        "repository": {"full_name": "carrick-sh/carrick"},
        "head_repository": {"full_name": "carrick-sh/carrick"},
    })
}

#[test]
fn only_push_to_main_and_merge_queue_runs_publish_baselines() {
    let sha = "b".repeat(40);
    let kernel = ".github/workflows/kernel-runtime.yml";
    assert!(trusted_baseline_run(&run("push", "main", kernel), &sha));
    assert!(trusted_baseline_run(
        &run("merge_group", "gh-readonly-queue/main/pr-1-abc", kernel),
        &sha
    ));
    for rejected in [
        run("workflow_dispatch", "main", kernel),
        run("pull_request", "main", kernel),
        run("push", "work/x", kernel),
        run("push", "main", ".github/workflows/ci.yml"),
    ] {
        assert!(!trusted_baseline_run(&rejected, &sha));
    }
    let mut fork = run("push", "main", kernel);
    fork["head_repository"]["full_name"] = "fork/carrick".into();
    assert!(!trusted_baseline_run(&fork, &sha));
    assert!(!trusted_baseline_run(
        &run("push", "main", kernel),
        &"c".repeat(40)
    ));
    assert_eq!(artifact_name(Lane::Hvf, &sha), format!("receipt-hvf-{sha}"));
}
