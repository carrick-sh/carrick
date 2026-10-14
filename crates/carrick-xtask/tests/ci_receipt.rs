#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::accept::{
    AcceptReceipt, CLEANUP_UNKNOWN, CleanupCount, ProbeDiff, StepResult, evaluate_el1_step,
    parse_failed_tests, parse_test_log, parse_unitemized_failures, populate_step_from_log,
};
use carrick_xtask::ci_receipt::{
    Baseline, Lane, artifact_name, baseline_decision, diff, failure_keys, newest_receipt,
    pick_candidate, trusted_baseline_run,
};
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
        unitemized_failures: vec![],
        started_tests: vec![],
        finished_binaries: vec![],
        unfinished_binaries: vec![],
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
fn successful_python_banner_is_not_an_unfinished_cargo_binary() {
    let log = "Ran 4 tests in 2.487s\n\nOK\nRunning check-dispatch-lock-authority self-tests...\n";
    let mut policy = step("lint-domains-source", true, &[]);
    let mut failures = Vec::new();
    populate_step_from_log(&mut policy, log, &mut failures);
    assert!(policy.passed, "{failures:?}");
    assert!(policy.unfinished_binaries.is_empty());
    let crashed = parse_test_log(
        "Running tests/policy.rs (target/debug/deps/policy-0123abcd4567ef89)\nrunning 1 test\n",
    );
    assert_eq!(crashed.unfinished_binaries, vec!["policy"]);
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
fn push_dispatch_on_main_and_merge_queue_runs_publish_baselines() {
    let sha = "b".repeat(40);
    let kernel = ".github/workflows/kernel-runtime.yml";
    assert!(trusted_baseline_run(&run("push", "main", kernel), &sha));
    // The owner's reseed path.
    assert!(trusted_baseline_run(
        &run("workflow_dispatch", "main", kernel),
        &sha
    ));
    assert!(trusted_baseline_run(
        &run("merge_group", "gh-readonly-queue/main/pr-1-abc", kernel),
        &sha
    ));
    for rejected in [
        run("workflow_dispatch", "work/x", kernel),
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
    assert_eq!(
        artifact_name(Lane::Hvf, &sha, 2),
        format!("receipt-hvf-{sha}-2")
    );
}

fn listed(id: u64, status: &str, event: &str, branch: &str) -> serde_json::Value {
    let mut value = run(event, branch, ".github/workflows/kernel-runtime.yml");
    value["id"] = id.into();
    value["status"] = status.into();
    value
}
fn artifacts(names: &[&str]) -> serde_json::Value {
    serde_json::json!({"artifacts": names.iter().map(|n| serde_json::json!({"name": n, "expired": false})).collect::<Vec<_>>()})
}

#[test]
fn baseline_waits_for_an_in_progress_base_run_and_fails_closed_when_finished() {
    let sha = "b".repeat(40);
    let one = format!("receipt-hvf-{sha}-1");
    let two = format!("receipt-hvf-{sha}-2");
    let queue = "gh-readonly-queue/main/pr-1-abc";
    // The newest attempt of the newest trusted run wins.
    let found = baseline_decision(
        &[
            (listed(5, "completed", "push", "main"), artifacts(&[&one])),
            (
                listed(9, "completed", "merge_group", queue),
                artifacts(&[&one, &two, &format!("receipt-kvm-{sha}-3")]),
            ),
        ],
        Lane::Hvf,
        &sha,
    );
    assert_eq!(found, Baseline::Found(9, two.clone()));
    assert_eq!(
        newest_receipt(&artifacts(&[&one, &two]), Lane::Hvf, &sha),
        Some((2, two))
    );
    // Queue depth above one: the base entry's run has not uploaded yet.
    let pending = baseline_decision(
        &[(
            listed(9, "in_progress", "merge_group", queue),
            artifacts(&[]),
        )],
        Lane::Hvf,
        &sha,
    );
    assert_eq!(pending, Baseline::Pending);
    // Finished without a receipt: fail closed, never wait.
    let missing = baseline_decision(
        &[(listed(9, "completed", "merge_group", queue), artifacts(&[]))],
        Lane::Hvf,
        &sha,
    );
    assert_eq!(missing, Baseline::Missing);
    assert_eq!(baseline_decision(&[], Lane::Hvf, &sha), Baseline::Missing);
    // An untrusted run never stands in, even with a matching artifact.
    let untrusted = baseline_decision(
        &[(
            listed(3, "completed", "pull_request", "main"),
            artifacts(&[&one]),
        )],
        Lane::Hvf,
        &sha,
    );
    assert_eq!(untrusted, Baseline::Missing);
}

#[test]
fn crashes_and_unknown_cleanup_are_failure_identities_beside_itemized_tests() {
    let log = "\
test a::b ... FAILED
error: test failed, to rerun pass `-p x --test t`
Caused by:
  process didn't exit successfully: `/w/target/debug/deps/t-0123abcd --nocapture` (signal: 11, SIGSEGV: invalid memory reference)
  process didn't exit successfully: `/w/target/debug/deps/u-0123abcd` (exit status: 101)
error: could not compile `carrick-embed` (test \"x\") due to 1 previous error
";
    assert_eq!(
        parse_unitemized_failures(log),
        vec!["compile:carrick-embed", "crash:t"]
    );
    let base = receipt(vec![step("el1-embed", false, &["embed::a"])]);
    let mut next = receipt(vec![step("el1-embed", false, &["embed::a"])]);
    next.steps[0].unitemized_failures = vec!["crash:embed".into()];
    next.failures
        .push(format!("step 'probe-cases' {CLEANUP_UNKNOWN}"));
    let result = diff(&base, &next).unwrap();
    assert_eq!(
        result.new,
        vec![
            "cleanup-unknown:probe-cases",
            "step:el1-embed",
            "unitemized:el1-embed:crash:embed"
        ]
    );
}

#[test]
fn a_gate_only_rerun_uses_the_newest_receipt_attempt_not_after_it() {
    let sha = "b".repeat(40);
    let names: Vec<String> = [1, 2, 4]
        .iter()
        .map(|n| artifact_name(Lane::Kvm, &sha, *n))
        .chain([format!("receipt-hvf-{sha}-3"), "unrelated".into()])
        .collect();
    // Attempt 3 re-ran only the gate: attempt 2's receipt is the candidate.
    assert_eq!(
        pick_candidate(&names, Lane::Kvm, &sha, 3),
        Some(artifact_name(Lane::Kvm, &sha, 2))
    );
    assert_eq!(
        pick_candidate(&names, Lane::Kvm, &sha, 4),
        Some(artifact_name(Lane::Kvm, &sha, 4))
    );
    // Never a later attempt's receipt, never another lane's.
    assert_eq!(pick_candidate(&names, Lane::Kvm, &sha, 0), None);
    assert_eq!(pick_candidate(&names, Lane::Hvf, &sha, 2), None);
}

const MAIN_EL1_EXCERPT: &str = include_str!("fixtures/el1-embed-main-3eda28c32-excerpt.log");
const PR338_EL1_EXCERPT: &str = include_str!("fixtures/el1-embed-pr338-6d4e2f25e-excerpt.log");

fn legacy_single_line_failed_tests(log: &str) -> Vec<String> {
    log.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("test ")?
                .strip_suffix(" ... FAILED")
                .map(str::to_owned)
        })
        .collect()
}

#[test]
fn nocapture_signed_logs_itemize_failures_and_crashes_from_real_excerpts() {
    // Under --nocapture, single-line `test X ... FAILED` never appears in either real excerpt.
    assert!(legacy_single_line_failed_tests(MAIN_EL1_EXCERPT).is_empty());
    assert!(legacy_single_line_failed_tests(PR338_EL1_EXCERPT).is_empty());

    let main_parsed = parse_test_log(MAIN_EL1_EXCERPT);
    assert_eq!(
        main_parsed.failed_tests,
        vec![
            "el1_gic::el1_gic_vtimer_reaches_el1_without_host_exits",
            "el1_host_copyout::el1_file_mmap_replaces_a_live_anonymous_grant",
            "el1_host_copyout::el1_host_buffers_follow_reused_mapping_in_two_live_processes",
            "el1_host_copyout::el1_host_copyout_into_and_out_of_untouched_reserved_memory",
            "el1_inotify::el1_inotify09_contract",
            "el1_kick_served_loop::el1_served_burst_surfaces_kicks_under_oversubscription",
        ]
    );
    assert!(main_parsed.unitemized_failures.is_empty());
    assert!(main_parsed.unfinished_binaries.is_empty());
    assert_eq!(
        main_parsed.finished_binaries,
        vec![
            "el1_gic",
            "el1_host_copyout",
            "el1_inotify",
            "el1_kick_served_loop",
            "entitlement_negative",
        ]
    );

    let pr338_parsed = parse_test_log(PR338_EL1_EXCERPT);
    assert_eq!(
        pr338_parsed.failed_tests,
        vec![
            "el1_host_copyout::el1_file_mmap_replaces_a_live_anonymous_grant",
            "el1_host_copyout::el1_host_buffers_follow_reused_mapping_in_two_live_processes",
            "el1_host_copyout::el1_host_copyout_into_and_out_of_untouched_reserved_memory",
            "el1_inotify::el1_inotify09_contract",
            "el1_inotify::el1_inotify_recall_on_dir_watch",
        ]
    );
    assert_eq!(
        pr338_parsed.unitemized_failures,
        vec!["crash:el1_kick_served_loop"]
    );
    assert_eq!(
        pr338_parsed.unfinished_binaries,
        vec!["el1_kick_served_loop"]
    );
    assert_eq!(
        pr338_parsed.finished_binaries,
        vec![
            "el1_gic",
            "el1_host_copyout",
            "el1_inotify",
            "entitlement_negative",
        ]
    );
    // Even when `test el1_gic_vtimer_reaches_el1_without_host_exits ...` was glued
    // after `mailbox=`, it is still recorded in `started_tests`.
    assert!(
        pr338_parsed
            .started_tests
            .contains(&"el1_gic::el1_gic_vtimer_reaches_el1_without_host_exits".to_string())
    );
}

#[test]
fn replay_pr338_excerpt_against_main_excerpt_yields_new_keys_for_failures_missing_and_abort() {
    let allowlist = vec![
        "el1_file_mmap_replaces_a_live_anonymous_grant".to_string(),
        "el1_gic_vtimer_reaches_el1_without_host_exits".to_string(),
        "el1_host_buffers_follow_reused_mapping_in_two_live_processes".to_string(),
        "el1_host_copyout_into_and_out_of_untouched_reserved_memory".to_string(),
        "el1_inotify09_contract".to_string(),
        "el1_served_burst_surfaces_kicks_under_oversubscription".to_string(),
    ];

    let (_, main_passed, main_err) = evaluate_el1_step(Some(1), MAIN_EL1_EXCERPT, &allowlist);
    assert!(
        main_passed,
        "main with all failures allowlisted and finished binaries should pass: {main_err:?}"
    );
    let mut main_step = step("el1-embed", main_passed, &[]);
    let mut main_failures = Vec::new();
    populate_step_from_log(&mut main_step, MAIN_EL1_EXCERPT, &mut main_failures);
    assert!(main_failures.is_empty());
    let base_receipt = receipt(vec![main_step]);

    let (_, pr338_passed, pr338_err) = evaluate_el1_step(Some(1), PR338_EL1_EXCERPT, &allowlist);
    assert!(
        !pr338_passed,
        "pr338 must fail on unexpected failure + crashed/unfinished binary"
    );
    assert!(pr338_err.is_some());
    let mut pr338_step = step("el1-embed", pr338_passed, &[]);
    let mut pr338_failures = Vec::new();
    populate_step_from_log(&mut pr338_step, PR338_EL1_EXCERPT, &mut pr338_failures);
    let cand_receipt = receipt(vec![pr338_step]);

    let result = diff(&base_receipt, &cand_receipt).unwrap();
    assert_eq!(
        result.new,
        vec![
            "missing:el1_kick_served_loop::el1_served_loop_surfaces_kicks",
            "step:el1-embed",
            "test:el1-embed:el1_inotify::el1_inotify_recall_on_dir_watch",
            "unfinished:el1_kick_served_loop",
            "unitemized:el1-embed:crash:el1_kick_served_loop",
        ]
    );
    assert_eq!(
        result.fixed,
        vec![
            "test:el1-embed:el1_gic::el1_gic_vtimer_reaches_el1_without_host_exits",
            "test:el1-embed:el1_kick_served_loop::el1_served_burst_surfaces_kicks_under_oversubscription",
        ]
    );
}

#[test]
fn el1_step_fails_closed_when_binary_aborts_after_an_allowlisted_failure() {
    let log = "\
test-signed: running /w/target/release/deps/el1_a-1111111111111111 el1_ --nocapture
running 1 test
test el1_known_red ...
FAILED

failures:

failures:
    el1_known_red

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s

test-signed: FAIL /w/target/release/deps/el1_a-1111111111111111
test-signed: running /w/target/release/deps/el1_b-2222222222222222 el1_ --nocapture
running 1 test
test el1_aborts_mid_run ...
scripts/lib/test-signed-body.sh: line 431: 999 Abort trap: 6
test-signed: FAIL /w/target/release/deps/el1_b-2222222222222222
";
    let allowlist = vec!["el1_known_red".to_string()];
    let (cmp, passed, error) = evaluate_el1_step(Some(1), log, &allowlist);
    assert!(cmp.unexpected_failures.is_empty());
    assert!(
        !passed,
        "aborted binary must not pass behind an allowlisted failure"
    );
    let err = error.unwrap();
    assert!(err.contains("crash:el1_b"));
    assert!(err.contains("el1_b"));
}

#[test]
fn empty_itemization_with_test_result_failed_is_a_parse_error_that_fails_the_gate() {
    let log = "\
test-signed: running /w/target/release/deps/el1_broken-abcdef0123456789 el1_ --nocapture
running 1 test
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test-signed: FAIL /w/target/release/deps/el1_broken-abcdef0123456789
";
    let parsed = parse_test_log(log);
    assert!(parsed.failed_tests.is_empty());
    assert!(
        parsed
            .unitemized_failures
            .contains(&"parse-error:el1_broken".to_string())
    );

    let (_, el1_passed, el1_err) = evaluate_el1_step(Some(1), log, &[]);
    assert!(!el1_passed);
    assert!(el1_err.unwrap().contains("empty itemization"));

    let mut s = step("el1-embed", true, &[]);
    let mut failures = Vec::new();
    populate_step_from_log(&mut s, log, &mut failures);
    assert!(!s.passed);
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("empty itemization"));

    let keys = failure_keys(&receipt(vec![s]));
    assert!(keys.contains("unitemized:el1-embed:parse-error:el1_broken"));
    assert!(keys.contains("step:el1-embed"));
}
