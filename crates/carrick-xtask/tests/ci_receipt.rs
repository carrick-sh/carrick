#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::accept::{
    AcceptReceipt, CLEANUP_UNKNOWN, CleanupCount, ProbeDiff, StepResult, evaluate_el1_step,
    parse_failed_tests, parse_test_log, parse_unitemized_failures, populate_step_from_log,
};
use carrick_xtask::ci_receipt::{
    Baseline, Lane, RETIRED_TESTS_PATH, artifact_name, baseline_decision, diff, diff_trees,
    diff_with_retired, failure_keys, load_retired_tests, newest_receipt, parse_retired_tests,
    pick_candidate, tree_has_test, trusted_baseline_run,
};
use std::path::{Path, PathBuf};
use std::process::Command;

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
fn only_push_and_owner_dispatch_on_main_publish_baselines() {
    let sha = "b".repeat(40);
    let kernel = ".github/workflows/kernel-runtime.yml";
    assert!(trusted_baseline_run(&run("push", "main", kernel), &sha));
    // The owner's reseed path.
    assert!(trusted_baseline_run(
        &run("workflow_dispatch", "main", kernel),
        &sha
    ));
    for rejected in [
        run("merge_group", "gh-readonly-queue/main/pr-1-abc", kernel),
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
    // The newest attempt of the newest trusted run wins.
    let found = baseline_decision(
        &[
            (listed(5, "completed", "push", "main"), artifacts(&[&one])),
            (
                listed(9, "completed", "workflow_dispatch", "main"),
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
    // The parent main push has not uploaded yet.
    let pending = baseline_decision(
        &[(listed(9, "in_progress", "push", "main"), artifacts(&[]))],
        Lane::Hvf,
        &sha,
    );
    assert_eq!(pending, Baseline::Pending);
    // Finished without a receipt: fail closed, never wait.
    let missing = baseline_decision(
        &[(
            listed(9, "completed", "workflow_dispatch", "main"),
            artifacts(&[]),
        )],
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

#[cfg(unix)]
mod serial_host {
    use super::*;

    #[test]
    fn parent_receipt_is_used_and_missing_parent_is_visible_without_ancestor_fallback() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let fake_gh = bin.join("gh");
        std::fs::write(
        &fake_gh,
        r#"#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
main, head, middle = (os.environ[k] for k in ('CHAIN_MAIN', 'CHAIN_HEAD', 'CHAIN_MIDDLE'))
args = sys.argv[1:]
if args[0] == 'api' and '/runs?head_sha=' in args[-1]:
    sha = args[-1].split('head_sha=')[1].split('&')[0]
    event, branch = 'push', 'main'
    if os.environ.get('PARENT_MISSING') == 'cancelled':
        status = 'completed'
    elif os.environ.get('PARENT_MISSING') == 'pending':
        status = 'in_progress'
    else:
        status = 'completed'
    run = {'id': {main: 1, head: 2, middle: 3}[sha], 'status': status,
           'event': event, 'head_branch': branch, 'head_sha': sha,
           'conclusion': 'cancelled' if os.environ.get('PARENT_MISSING') == 'cancelled' else None,
           'path': '.github/workflows/kernel-runtime.yml',
           'repository': {'full_name': 'carrick-sh/carrick'},
           'head_repository': {'full_name': 'carrick-sh/carrick'}}
    print(json.dumps({'workflow_runs': [] if os.environ.get('PARENT_MISSING') == 'absent' else [run]}))
elif args[0] == 'api' and '/artifacts?' in args[-1]:
    names = [f'receipt-hvf-{main}-1'] if '/runs/1/' in args[-1] and not os.environ.get('PARENT_MISSING') else []
    print(json.dumps({'artifacts': [{'name': name, 'expired': False} for name in names]}))
elif args[:2] == ['run', 'download']:
    dest = pathlib.Path(args[args.index('--dir') + 1])
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(os.environ['CHAIN_BASE_RECEIPT'], dest / 'receipt.json')
else:
    raise SystemExit(f'unexpected gh invocation: {args}')
"#,
    )
    .unwrap();
        let mut permissions = std::fs::metadata(&fake_gh).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake_gh, permissions).unwrap();

        let main = "a".repeat(40);
        let head = "b".repeat(40);
        let middle = "c".repeat(40);
        let deep = "d".repeat(40);
        let mut baseline = receipt(vec![]);
        baseline.head = main.clone();
        let baseline_file = dir.path().join("base.json");
        std::fs::write(&baseline_file, serde_json::to_vec(&baseline).unwrap()).unwrap();
        let mut candidate = baseline;
        candidate.head = deep.clone();
        let candidate_dir = dir.path().join("candidate");
        let candidate_artifact = candidate_dir.join(artifact_name(Lane::Hvf, &deep, 1));
        std::fs::create_dir_all(&candidate_artifact).unwrap();
        std::fs::write(
            candidate_artifact.join("receipt.json"),
            serde_json::to_vec(&candidate).unwrap(),
        )
        .unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["ci-receipt", "gate", "--lane", "hvf", "--base-sha", &main])
            .arg("--candidate-dir")
            .arg(&candidate_dir)
            .args(["--candidate-sha", &deep, "--run-attempt", "1"])
            .arg("--download-dir")
            .arg(dir.path().join("download"))
            .arg("--base-tree")
            .arg(dir.path())
            .arg("--candidate-tree")
            .arg(dir.path())
            .args(["--wait-minutes", "0"])
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("CHAIN_MAIN", &main)
            .env("CHAIN_HEAD", &head)
            .env("CHAIN_MIDDLE", &middle)
            .env("CHAIN_DEEP", &deep)
            .env("CHAIN_BASE_RECEIPT", &baseline_file)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("receipt diff against {main}: 0 NEW"))
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("selected baseline ancestor {main} (overall FAIL")),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );

        // A missing parent never falls back to an older receipt or GraphQL.
        // Both lanes report a distinct non-success outcome, including summary.
        for lane in ["hvf", "kvm"] {
            let lane_value = if lane == "hvf" { Lane::Hvf } else { Lane::Kvm };
            let artifact = candidate_dir.join(artifact_name(lane_value, &deep, 1));
            std::fs::create_dir_all(&artifact).unwrap();
            std::fs::write(
                artifact.join("receipt.json"),
                serde_json::to_vec(&candidate).unwrap(),
            )
            .unwrap();
            for missing in ["absent", "cancelled", "pending"] {
                let summary = dir.path().join(format!("summary-{lane}-{missing}.md"));
                let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
                    .args(["ci-receipt", "gate", "--lane", lane, "--base-sha", &main])
                    .arg("--candidate-dir")
                    .arg(&candidate_dir)
                    .args(["--candidate-sha", &deep, "--run-attempt", "1"])
                    .arg("--download-dir")
                    .arg(dir.path().join("missing-download"))
                    .args(["--wait-minutes", "0"])
                    .env(
                        "PATH",
                        format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
                    )
                    .env("CHAIN_MAIN", &main)
                    .env("CHAIN_HEAD", &head)
                    .env("CHAIN_MIDDLE", &middle)
                    .env("CHAIN_DEEP", &deep)
                    .env("PARENT_MISSING", missing)
                    .env("GITHUB_STEP_SUMMARY", &summary)
                    .output()
                    .unwrap();
                assert!(!output.status.success(), "{lane} {missing}");
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stdout.contains(&format!(
                        "::error title={} receipt gate: No baseline::",
                        lane.to_uppercase()
                    )),
                    "{stdout}"
                );
                assert!(
                    stderr.contains("no baseline: parent main commit"),
                    "{stderr}"
                );
                assert!(
                    !stdout.contains(" NEW"),
                    "missing baseline is not a regression: {stdout}"
                );
                let summary = std::fs::read_to_string(summary).unwrap();
                assert!(summary.contains("No baseline"), "{summary}");
                assert!(summary.contains(&main), "{summary}");
                assert!(
                    summary.contains("No regression comparison was made"),
                    "{summary}"
                );
                assert!(
                    summary.contains("gh workflow run kernel-runtime.yml"),
                    "{summary}"
                );
            }
        }

        // Verify `ci-receipt gate` fetches `candidate_sha` from `origin` and reads
        // `.github/retired-tests.toml` from the candidate commit when checked out at `base_sha`.
        let origin = dir.path().join("origin.git");
        let work = dir.path().join("work");
        std::fs::create_dir_all(&work).unwrap();
        let git = |cwd: &Path, args: &[&str]| -> String {
            let out = Command::new("git")
                .current_dir(cwd)
                .args(args)
                .env("GIT_AUTHOR_NAME", "T")
                .env("GIT_AUTHOR_EMAIL", "t@e")
                .env("GIT_COMMITTER_NAME", "T")
                .env("GIT_COMMITTER_EMAIL", "t@e")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        git(dir.path(), &["init", "--bare", origin.to_str().unwrap()]);
        git(&work, &["init"]);
        git(
            &work,
            &["remote", "add", "origin", origin.to_str().unwrap()],
        );
        write_test_tree(
            &work,
            "#[test]\nfn wait4_rejects_unwritable_rusage_without_writing_status() {}\n",
            None,
        );
        git(&work, &["add", "."]);
        git(&work, &["commit", "-m", "base"]);
        let base_sha = git(&work, &["rev-parse", "HEAD"]);
        git(&work, &["push", "origin", "HEAD:refs/heads/main"]);
        write_test_tree(
            &work,
            "#[test]\nfn wait4_writes_status_before_unwritable_rusage_efault() {}\n",
            Some(PR583_RETIRED_TOML),
        );
        git(&work, &["add", "."]);
        git(&work, &["commit", "-m", "cand"]);
        let cand_sha = git(&work, &["rev-parse", "HEAD"]);
        git(&work, &["push", "origin", "HEAD:refs/heads/candidate"]);
        let checkout = dir.path().join("gate-checkout");
        git(
            dir.path(),
            &[
                "clone",
                "--no-tags",
                "--branch",
                "main",
                "--single-branch",
                origin.to_str().unwrap(),
                checkout.to_str().unwrap(),
            ],
        );
        assert!(!checkout.join(RETIRED_TESTS_PATH).exists());

        let mut git_base = cpl0_receipt(&[OLD_WAIT4], &[]);
        git_base.head = base_sha.clone();
        std::fs::write(&baseline_file, serde_json::to_vec(&git_base).unwrap()).unwrap();
        let mut git_cand = cpl0_receipt(&[NEW_WAIT4], &[]);
        git_cand.head = cand_sha.clone();
        let cand_art = candidate_dir.join(artifact_name(Lane::Hvf, &cand_sha, 1));
        std::fs::create_dir_all(&cand_art).unwrap();
        std::fs::write(
            cand_art.join("receipt.json"),
            serde_json::to_vec(&git_cand).unwrap(),
        )
        .unwrap();

        let fetched = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .current_dir(&checkout)
            .args([
                "ci-receipt",
                "gate",
                "--lane",
                "hvf",
                "--base-sha",
                &base_sha,
            ])
            .arg("--candidate-dir")
            .arg(&candidate_dir)
            .args(["--candidate-sha", &cand_sha, "--run-attempt", "1"])
            .arg("--download-dir")
            .arg(dir.path().join("git-download"))
            .args(["--wait-minutes", "0"])
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("CHAIN_MAIN", &base_sha)
            .env("CHAIN_HEAD", &head)
            .env("CHAIN_MIDDLE", &middle)
            .env("CHAIN_DEEP", &cand_sha)
            .env("CHAIN_BASE_RECEIPT", &baseline_file)
            .output()
            .unwrap();
        assert!(
            fetched.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&fetched.stderr)
        );
        assert!(
            String::from_utf8_lossy(&fetched.stdout)
                .contains(&format!("receipt diff against {base_sha}: 0 NEW"))
        );
    }
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

#[test]
fn per_binary_deadline_expiry_is_recorded_as_unfinished_and_fails_gate() {
    let log = "\
test-signed: running /w/target/release/deps/el1_wedged-1111111111111111 el1_ --nocapture
running 1 test
test el1_forgot_watchdog ...
test-signed: capturing deadline diagnostics for /w/target/release/deps/el1_wedged-1111111111111111 (pid=4242, CARRICK_RUN_ID=embed-signed-99-b1)
test-signed: deadline host backtrace (pid=4242):
thread #1: tid = 0x01, el1_forgot_watchdog
test-signed: DEADLINE /w/target/release/deps/el1_wedged-1111111111111111 (600s, CARRICK_RUN_ID=embed-signed-99-b1)
test-signed: FAIL /w/target/release/deps/el1_wedged-1111111111111111
test-signed: running /w/target/release/deps/el1_after-2222222222222222 el1_ --nocapture
running 1 test
test el1_after_ok ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
";
    let parsed = parse_test_log(log);
    assert_eq!(parsed.unfinished_binaries, vec!["el1_wedged"]);
    assert_eq!(parsed.finished_binaries, vec!["el1_after"]);
    assert_eq!(parsed.unitemized_failures, vec!["crash:el1_wedged"]);
    assert_eq!(
        parsed.started_tests,
        vec!["el1_after::el1_after_ok", "el1_wedged::el1_forgot_watchdog",]
    );

    let (_, el1_passed, el1_err) = evaluate_el1_step(Some(1), log, &[]);
    assert!(!el1_passed, "deadline-killed binary must fail the el1 step");
    let err = el1_err.unwrap();
    assert!(err.contains("el1_wedged"), "error={err}");

    let mut s = step("el1-embed", false, &[]);
    let mut failures = Vec::new();
    populate_step_from_log(&mut s, log, &mut failures);
    assert_eq!(s.unfinished_binaries, vec!["el1_wedged"]);
    let keys = failure_keys(&receipt(vec![s]));
    assert!(keys.contains("unfinished:el1_wedged"));
    assert!(keys.contains("unitemized:el1-embed:crash:el1_wedged"));
    assert!(keys.contains("step:el1-embed"));
}

fn receipt_from_el1_log(passed: bool, log: &str) -> AcceptReceipt {
    let mut s = step("el1-embed", passed, &[]);
    let mut failures = Vec::new();
    populate_step_from_log(&mut s, log, &mut failures);
    receipt(vec![s])
}

#[test]
fn replay_pr389_all_failed_base_binary_crashing_in_candidate_yields_no_new_failures() {
    let base_log = "\
test-signed: running /w/target/release/deps/el1_host_copyout-983cd9ce6da5d7a1 el1_ --nocapture

running 3 tests
test el1_file_mmap_replaces_a_live_anonymous_grant ...
FAILED
test el1_host_buffers_follow_reused_mapping_in_two_live_processes ...
FAILED
test el1_host_copyout_into_and_out_of_untouched_reserved_memory ...
FAILED

failures:

failures:
    el1_file_mmap_replaces_a_live_anonymous_grant
    el1_host_buffers_follow_reused_mapping_in_two_live_processes
    el1_host_copyout_into_and_out_of_untouched_reserved_memory

test result: FAILED. 0 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.32s

test-signed: FAIL /w/target/release/deps/el1_host_copyout-983cd9ce6da5d7a1
";
    let cand_log = "\
test-signed: running /w/target/release/deps/el1_host_copyout-9e4a145bcc081d87 el1_ --nocapture

running 3 tests
test el1_file_mmap_replaces_a_live_anonymous_grant ...
scripts/lib/test-signed-body.sh: line 431: 35031 Abort trap: 6           env RUST_TEST_THREADS=1 \"$exe\" \"$@\"
test-signed: FAIL /w/target/release/deps/el1_host_copyout-9e4a145bcc081d87
";
    let base = receipt_from_el1_log(true, base_log);
    let cand = receipt_from_el1_log(false, cand_log);
    assert_eq!(cand.steps[0].started_tests.len(), 1);
    assert_eq!(cand.steps[0].unfinished_binaries, ["el1_host_copyout"]);
    assert_eq!(
        cand.steps[0].unitemized_failures,
        ["crash:el1_host_copyout"]
    );

    let result = diff(&base, &cand).unwrap();
    assert!(
        result.new.is_empty(),
        "a crash in a binary whose base tests all failed must not report NEW failures, got: {:?}",
        result.new
    );
    assert_eq!(
        result.fixed,
        vec![
            "test:el1-embed:el1_host_copyout::el1_file_mmap_replaces_a_live_anonymous_grant",
            "test:el1-embed:el1_host_copyout::el1_host_buffers_follow_reused_mapping_in_two_live_processes",
            "test:el1-embed:el1_host_copyout::el1_host_copyout_into_and_out_of_untouched_reserved_memory",
        ]
    );
}

#[test]
fn replay_base_passing_binary_with_candidate_missing_tests_yields_new_failures() {
    let base_log = "\
test-signed: running /w/target/release/deps/el1_gic-ee0e960234e427a0 el1_ --nocapture

running 2 tests
test el1_gic_el0_id_view_hides_the_gic ... ok
test el1_gic_vtimer_reaches_el1_without_host_exits ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s
";
    let cand_log = "\
test-signed: running /w/target/release/deps/el1_gic-ee0e960234e427a0 el1_ --nocapture

running 1 test
test el1_gic_el0_id_view_hides_the_gic ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
";
    let base = receipt_from_el1_log(true, base_log);
    let cand = receipt_from_el1_log(true, cand_log);
    let result = diff(&base, &cand).unwrap();
    assert_eq!(
        result.new,
        vec!["missing:el1_gic::el1_gic_vtimer_reaches_el1_without_host_exits"]
    );
}

#[test]
fn replay_partially_passing_base_binary_crashing_before_passing_test_yields_new_failures() {
    let base_log = "\
test-signed: running /w/target/release/deps/el1_kick_served_loop-a52172b471abd796 el1_ --nocapture

running 3 tests
test el1_served_burst_surfaces_kicks_under_oversubscription ...
FAILED
test el1_served_second_known_red ...
FAILED
test el1_served_loop_surfaces_kicks ...
ok

failures:

failures:
    el1_served_burst_surfaces_kicks_under_oversubscription
    el1_served_second_known_red

test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.35s

test-signed: FAIL /w/target/release/deps/el1_kick_served_loop-a52172b471abd796
";
    let cand_log = "\
test-signed: running /w/target/release/deps/el1_kick_served_loop-4bc14b20aecdb3a9 el1_ --nocapture

running 3 tests
test el1_served_burst_surfaces_kicks_under_oversubscription ...
scripts/lib/test-signed-body.sh: line 431: 34920 Abort trap: 6           env RUST_TEST_THREADS=1 \"$exe\" \"$@\"
test-signed: FAIL /w/target/release/deps/el1_kick_served_loop-4bc14b20aecdb3a9
";
    let base = receipt_from_el1_log(true, base_log);
    let cand = receipt_from_el1_log(false, cand_log);
    let result = diff(&base, &cand).unwrap();
    assert_eq!(
        result.new,
        vec![
            "missing:el1_kick_served_loop::el1_served_loop_surfaces_kicks",
            "step:el1-embed",
            "unfinished:el1_kick_served_loop",
            "unitemized:el1-embed:crash:el1_kick_served_loop",
        ]
    );
}

fn write_test_tree(root: &Path, cpl0_source: &str, retired_toml: Option<&str>) {
    let test_file = root.join("crates/carrick-vmm-kvm/tests/cpl0_fork_e2e.rs");
    std::fs::create_dir_all(test_file.parent().unwrap()).unwrap();
    std::fs::write(&test_file, cpl0_source).unwrap();
    if let Some(toml_body) = retired_toml {
        let toml_path = root.join(RETIRED_TESTS_PATH);
        std::fs::create_dir_all(toml_path.parent().unwrap()).unwrap();
        std::fs::write(&toml_path, toml_body).unwrap();
    }
}

fn cpl0_receipt(started: &[&str], failed: &[&str]) -> AcceptReceipt {
    let mut s = step("kvm-tests", failed.is_empty(), failed);
    s.started_tests = started.iter().map(|t| (*t).to_owned()).collect();
    s.finished_binaries = vec!["cpl0_fork_e2e".into()];
    receipt(vec![s])
}

const OLD_WAIT4: &str = "cpl0_fork_e2e::wait4_rejects_unwritable_rusage_without_writing_status";
const NEW_WAIT4: &str = "cpl0_fork_e2e::wait4_writes_status_before_unwritable_rusage_efault";
const PR583_RETIRED_TOML: &str = r#"[[retired]]
test = "cpl0_fork_e2e::wait4_rejects_unwritable_rusage_without_writing_status"
replaced_by = "cpl0_fork_e2e::wait4_writes_status_before_unwritable_rusage_efault"
reason = "Linux reaps and writes status before -EFAULT on an unwritable rusage"
pr = 583
"#;

#[test]
fn declared_rename_passes_and_undeclared_disappearance_stays_new() {
    let dir = tempfile::tempdir().unwrap();
    let (base_tree, cand_tree) = (dir.path().join("base"), dir.path().join("cand"));
    write_test_tree(
        &base_tree,
        "#[test]\nfn wait4_rejects_unwritable_rusage_without_writing_status() {}\n#[test]\nfn undeclared_disappearance() {}\n",
        None,
    );
    write_test_tree(
        &cand_tree,
        "// Renamed from wait4_rejects_unwritable_rusage_without_writing_status\n#[test]\nfn wait4_writes_status_before_unwritable_rusage_efault() {}\n",
        Some(PR583_RETIRED_TOML),
    );
    assert!(
        tree_has_test(
            &base_tree,
            "cpl0_fork_e2e",
            "wait4_rejects_unwritable_rusage_without_writing_status"
        )
        .unwrap()
    );
    assert!(
        !tree_has_test(
            &cand_tree,
            "cpl0_fork_e2e",
            "wait4_rejects_unwritable_rusage_without_writing_status"
        )
        .unwrap()
    );

    let base_receipt = cpl0_receipt(&[OLD_WAIT4, "cpl0_fork_e2e::keep_passing"], &[]);
    let cand_receipt = cpl0_receipt(&[NEW_WAIT4, "cpl0_fork_e2e::keep_passing"], &[]);

    assert_eq!(
        diff(&base_receipt, &cand_receipt).unwrap().new,
        vec![format!("missing:{OLD_WAIT4}")]
    );
    let declared = diff_trees(&base_receipt, &cand_receipt, &base_tree, &cand_tree).unwrap();
    assert!(declared.new.is_empty(), "got: {:?}", declared.new);

    let base_with_extra = cpl0_receipt(
        &[
            OLD_WAIT4,
            "cpl0_fork_e2e::keep_passing",
            "cpl0_fork_e2e::undeclared_disappearance",
        ],
        &[],
    );
    let partial = diff_trees(&base_with_extra, &cand_receipt, &base_tree, &cand_tree).unwrap();
    assert_eq!(
        partial.new,
        vec!["missing:cpl0_fork_e2e::undeclared_disappearance"]
    );
}

#[test]
fn declared_retired_test_still_in_source_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (base_tree, cand_tree) = (dir.path().join("base"), dir.path().join("cand"));
    let both_fns = "#[test]\nfn wait4_rejects_unwritable_rusage_without_writing_status() {}\n#[test]\nfn wait4_writes_status_before_unwritable_rusage_efault() {}\n";
    write_test_tree(&base_tree, both_fns, None);
    write_test_tree(&cand_tree, both_fns, Some(PR583_RETIRED_TOML));

    let err = diff_trees(
        &cpl0_receipt(&[OLD_WAIT4], &[]),
        &cpl0_receipt(&[NEW_WAIT4], &[]),
        &base_tree,
        &cand_tree,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("still exists in candidate source"),
        "{err}"
    );
}

#[test]
fn replaced_by_that_never_started_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (base_tree, cand_tree) = (dir.path().join("base"), dir.path().join("cand"));
    write_test_tree(
        &base_tree,
        "#[test]\nfn wait4_rejects_unwritable_rusage_without_writing_status() {}\n",
        None,
    );
    write_test_tree(
        &cand_tree,
        "#[test]\nfn wait4_writes_status_before_unwritable_rusage_efault() {}\n",
        Some(PR583_RETIRED_TOML),
    );

    let err = diff_trees(
        &cpl0_receipt(&[OLD_WAIT4], &[]),
        &cpl0_receipt(&["cpl0_fork_e2e::unrelated_test"], &[]),
        &base_tree,
        &cand_tree,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("did not start in candidate receipt"),
        "{err}"
    );
}

#[test]
fn failing_test_cannot_be_retired() {
    let dir = tempfile::tempdir().unwrap();
    let (base_tree, cand_tree) = (dir.path().join("base"), dir.path().join("cand"));
    write_test_tree(
        &base_tree,
        "#[test]\nfn wait4_rejects_unwritable_rusage_without_writing_status() {}\n",
        None,
    );
    write_test_tree(
        &cand_tree,
        "#[test]\nfn wait4_writes_status_before_unwritable_rusage_efault() {}\n",
        Some(PR583_RETIRED_TOML),
    );

    for (base_r, cand_r) in [
        (
            cpl0_receipt(&[OLD_WAIT4], &[OLD_WAIT4]),
            cpl0_receipt(&[NEW_WAIT4], &[]),
        ),
        (
            cpl0_receipt(&[OLD_WAIT4], &[]),
            cpl0_receipt(&[OLD_WAIT4, NEW_WAIT4], &[OLD_WAIT4]),
        ),
    ] {
        let err = diff_trees(&base_r, &cand_r, &base_tree, &cand_tree).unwrap_err();
        assert!(err.to_string().contains("cannot be retired"), "{err}");
    }
}

#[test]
fn stale_declaration_is_inert_after_the_retirement_lands() {
    let dir = tempfile::tempdir().unwrap();
    let (base_tree, cand_tree) = (dir.path().join("base"), dir.path().join("cand"));
    write_test_tree(
        &base_tree,
        "#[test]\nfn wait4_writes_status_before_unwritable_rusage_efault() {}\n",
        None,
    );
    write_test_tree(
        &cand_tree,
        "#[test]\nfn wait4_writes_status_before_unwritable_rusage_efault() {}\n",
        Some(PR583_RETIRED_TOML),
    );

    let r = cpl0_receipt(&[NEW_WAIT4], &[]);
    let result = diff_trees(&r, &r, &base_tree, &cand_tree).unwrap();
    assert!(result.new.is_empty(), "{result:?}");

    let baseline_file = dir.path().join("baseline.json");
    let candidate_file = dir.path().join("candidate.json");
    std::fs::write(&baseline_file, serde_json::to_vec(&r).unwrap()).unwrap();
    std::fs::write(&candidate_file, serde_json::to_vec(&r).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["ci-receipt", "diff", "--baseline"])
        .arg(&baseline_file)
        .arg("--candidate")
        .arg(&candidate_file)
        .arg("--base-tree")
        .arg(&base_tree)
        .arg("--candidate-tree")
        .arg(&cand_tree)
        .arg("--fail-on-new")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let summary = String::from_utf8_lossy(&output.stdout);
    assert!(
        summary.contains("WARNING") && summary.contains(OLD_WAIT4),
        "{summary}"
    );
    let empty_err =
        parse_retired_tests("retired = []\n", Path::new(RETIRED_TESTS_PATH)).unwrap_err();
    assert!(
        empty_err.to_string().contains("delete the file when empty"),
        "{empty_err}"
    );
    assert!(load_retired_tests(&base_tree).unwrap().is_empty());
    assert!(
        diff_with_retired(&r, &r, &[], &base_tree, &cand_tree)
            .unwrap()
            .new
            .is_empty()
    );
}

fn retirement(test: &str, replacement: Option<&str>) -> carrick_xtask::ci_receipt::RetiredTest {
    carrick_xtask::ci_receipt::RetiredTest {
        test: test.into(),
        reason: "review regression fixture".into(),
        pr: 613,
        replaced_by: replacement.map(str::to_owned),
    }
}

fn write_source(root: &Path, path: &str, source: &str) {
    let file = root.join(path);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, source).unwrap();
}

#[test]
fn retirement_cannot_excuse_another_binary_with_a_matching_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base");
    let cand = dir.path().join("cand");
    write_source(
        &base,
        "crates/example/tests/foo.rs",
        "mod bar { #[test] fn baz() {} }",
    );
    let result = diff_with_retired(
        &cpl0_receipt(&["foo::bar::baz", "bar::baz"], &[]),
        &cpl0_receipt(&[], &[]),
        &[retirement("foo::bar::baz", None)],
        &base,
        &cand,
    )
    .unwrap();
    assert_eq!(result.new, ["missing:bar::baz"]);
}

#[test]
fn replacement_must_start_in_its_declared_binary() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base");
    let cand = dir.path().join("cand");
    write_test_tree(
        &base,
        "#[test] fn wait4_rejects_unwritable_rusage_without_writing_status() {}",
        None,
    );
    let result = diff_with_retired(
        &cpl0_receipt(&[OLD_WAIT4], &[]),
        &cpl0_receipt(&["bar::baz"], &[]),
        &[retirement(OLD_WAIT4, Some("foo::bar::baz"))],
        &base,
        &cand,
    );
    assert!(
        result.is_err(),
        "wrong binary satisfied replacement: {result:?}"
    );
}

#[test]
fn failures_in_another_binary_do_not_poison_a_retirement_or_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base");
    let cand = dir.path().join("cand");
    write_source(
        &base,
        "crates/example/tests/foo.rs",
        "mod bar { #[test] fn baz() {} }",
    );
    for entry in [
        retirement("foo::bar::baz", None),
        retirement("foo::bar::baz", Some("foo::bar::qux")),
    ] {
        let result = diff_with_retired(
            &cpl0_receipt(&["foo::bar::baz"], &["bar::baz"]),
            &cpl0_receipt(&["foo::bar::qux"], &["bar::baz", "bar::qux"]),
            &[entry],
            &base,
            &cand,
        );
        assert!(
            result.is_ok(),
            "wrong binary poisoned declaration: {result:?}"
        );
    }
}

#[test]
fn retirement_identities_require_rust_identifier_segments() {
    for invalid in [
        "..::gone",
        ".::gone",
        "9bin::gone",
        "bin::mod::::gone",
        "bin::mod::9gone",
        "bin::mod::..",
        "bin::bad-name",
        "bin::white space",
        "bin::é",
    ] {
        for entry in [
            retirement(invalid, None),
            retirement("bin::gone", Some(invalid)),
        ] {
            let result = parse_retired_tests(
                &format!(
                    "[[retired]]\ntest = {:?}\nreason = {:?}\npr = 613\n{}",
                    entry.test,
                    entry.reason,
                    entry
                        .replaced_by
                        .map(|r| format!("replaced_by = {r:?}\n"))
                        .unwrap_or_default()
                ),
                Path::new(RETIRED_TESTS_PATH),
            );
            assert!(
                result.is_err(),
                "accepted invalid identity {invalid}: {result:?}"
            );
        }
    }
}

#[test]
fn stale_declaration_neither_validates_candidate_nor_excuses_missing_tests() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base");
    let cand = dir.path().join("cand");
    write_test_tree(&base, "", None);
    write_test_tree(
        &cand,
        "#[test] fn wait4_rejects_unwritable_rusage_without_writing_status() {}",
        Some(PR583_RETIRED_TOML),
    );
    let result = diff_trees(
        &cpl0_receipt(&[OLD_WAIT4], &[]),
        &cpl0_receipt(&[], &[OLD_WAIT4]),
        &base,
        &cand,
    )
    .unwrap();
    assert!(
        result.new.contains(&format!("missing:{OLD_WAIT4}")),
        "{result:?}"
    );
    assert!(
        result.new.contains(&format!("test:kvm-tests:{OLD_WAIT4}")),
        "{result:?}"
    );
}

fn assert_candidate_scan_refuses(extra_path: &str, extra_source: &str, manifest: Option<&str>) {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base");
    let cand = dir.path().join("cand");
    write_source(&base, "crates/example/tests/foo.rs", "#[test] fn gone() {}");
    write_source(&cand, "crates/example/tests/foo.rs", "");
    write_source(
        &cand,
        "crates/example/kept.rs",
        "#[test] #[ignore] fn gone() {}",
    );
    write_source(&cand, extra_path, extra_source);
    if let Some(manifest) = manifest {
        write_source(&cand, "crates/example/Cargo.toml", manifest);
    }
    let result = diff_with_retired(
        &cpl0_receipt(&["foo::gone"], &[]),
        &cpl0_receipt(&[], &[]),
        &[retirement("foo::gone", None)],
        &base,
        &cand,
    );
    let error = result
        .expect_err("unresolved source excused missing:foo::gone")
        .to_string();
    assert!(
        error.contains("cannot resolve") || error.contains("cannot parse"),
        "{error}"
    );
}

#[test]
fn retirement_refuses_macro_generated_tests_anywhere_in_candidate_crate() {
    assert_candidate_scan_refuses(
        "crates/example/src/lib.rs",
        "macro_rules! binding { ($name:ident) => { #[test] #[ignore] fn $name() {} }; } binding!(gone);",
        None,
    );
}

#[test]
fn retirement_refuses_path_modules_anywhere_in_candidate_crate() {
    assert_candidate_scan_refuses(
        "crates/example/src/lib.rs",
        "#[path = \"../kept.rs\"] mod kept;",
        None,
    );
}

#[test]
fn retirement_refuses_include_anywhere_in_candidate_crate() {
    assert_candidate_scan_refuses(
        "crates/example/src/lib.rs",
        "include!(\"../kept.rs\");",
        None,
    );
}

#[test]
fn retirement_refuses_unparseable_files_anywhere_in_candidate_crate() {
    // Balanced tokens parse as a TokenStream but not as a Rust file.
    assert_candidate_scan_refuses("crates/example/src/unrelated.rs", "fn broken(,) {}", None);
}

#[test]
fn retirement_refuses_explicit_test_paths_outside_tests() {
    for path in ["kept.rs", "tests/../kept.rs", "../elsewhere.rs"] {
        assert_candidate_scan_refuses(
            "crates/example/kept.rs",
            "#[test] #[ignore] fn gone() {}",
            Some(&format!(
                "[package]\nname = 'example'\n[[test]]\nname = 'foo'\npath = '{path}'\n"
            )),
        );
    }
}

#[test]
fn ordinary_functions_cannot_establish_base_test_presence() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base");
    let cand = dir.path().join("cand");
    write_source(&base, "crates/example/tests/foo.rs", "fn gone() {}");
    let result = diff_with_retired(
        &cpl0_receipt(&["foo::gone"], &[]),
        &cpl0_receipt(&[], &[]),
        &[retirement("foo::gone", None)],
        &base,
        &cand,
    )
    .unwrap();
    assert_eq!(result.new, ["missing:foo::gone"]);
}

#[test]
fn retirement_scans_auto_and_explicit_binary_test_sources() {
    for (path, manifest, bin) in [
        ("src/bin/tool.rs", "[package]\nname = 'example'\n", "tool"),
        (
            "src/bin/tool/main.rs",
            "[package]\nname = 'example'\n",
            "tool",
        ),
        (
            "src/main.rs",
            "[package]\nname = 'carrick-cli'\n[[bin]]\nname = 'carrick'\npath = 'src/main.rs'\n",
            "carrick",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        let cand = dir.path().join("cand");
        for root in [&base, &cand] {
            write_source(root, "crates/example/Cargo.toml", manifest);
            write_source(
                root,
                &format!("crates/example/{path}"),
                "#[tokio::test] #[ignore] async fn gone() {}",
            );
        }
        let qualified = format!("{bin}::gone");
        let result = diff_with_retired(
            &cpl0_receipt(&[&qualified], &[]),
            &cpl0_receipt(&[], &[]),
            &[retirement(&qualified, None)],
            &base,
            &cand,
        );
        let error = result
            .expect_err("retained binary test was retired")
            .to_string();
        assert!(
            error.contains("still exists in candidate source"),
            "{bin}: {error}"
        );
    }
}

#[test]
fn replacement_in_another_lane_does_not_need_to_start() {
    for lane_metadata in [
        "",
        "[package.metadata.carrick.test-lanes]\nfoo = { lane = 'manual', reason = 'hardware' }\n",
        "[package.metadata.carrick.test-lanes]\n'*' = { lane = 'kvm' }\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        let cand = dir.path().join("cand");
        write_source(&base, "crates/example/tests/foo.rs", "#[test] fn gone() {}");
        write_source(
            &cand,
            "crates/example/tests/foo.rs",
            "#[test] fn replacement() {}",
        );
        write_source(
            &cand,
            "crates/example/Cargo.toml",
            &format!("[package]\nname = 'example'\n{lane_metadata}"),
        );
        let result = diff_with_retired(
            &cpl0_receipt(&[], &[]),
            &cpl0_receipt(&[], &[]),
            &[retirement("foo::gone", Some("foo::replacement"))],
            &base,
            &cand,
        );
        assert!(
            result.is_ok(),
            "off-lane replacement was required: {lane_metadata}: {result:?}"
        );
    }
}

#[test]
fn failures_from_another_lane_do_not_refuse_retirement() {
    for lane_metadata in [
        "",
        "[package.metadata.carrick.test-lanes]\nfoo = { lane = 'manual', reason = 'hardware' }\n",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base");
        let cand = dir.path().join("cand");
        write_source(&base, "crates/example/tests/foo.rs", "#[test] fn gone() {}");
        write_source(
            &base,
            "crates/example/Cargo.toml",
            &format!("[package]\nname = 'example'\n{lane_metadata}"),
        );
        let result = diff_with_retired(
            &cpl0_receipt(&[], &["foo::gone"]),
            &cpl0_receipt(&[], &[]),
            &[retirement("foo::gone", None)],
            &base,
            &cand,
        );
        assert!(
            result.is_ok(),
            "off-lane failure refused retirement: {result:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn source_scan_skips_symlink_files_and_directories() {
    use std::os::unix::fs::symlink;
    for link_dir in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("tree");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        write_source(&outside, "foo.rs", "#[test] fn gone() {}");
        let tests = root.join("crates/example/tests");
        std::fs::create_dir_all(&tests).unwrap();
        if link_dir {
            symlink(&outside, tests.join("foo")).unwrap();
        } else {
            symlink(outside.join("foo.rs"), tests.join("foo.rs")).unwrap();
        }
        assert!(
            !tree_has_test(&root, "foo", "gone").unwrap(),
            "followed symlink (directory={link_dir})"
        );
    }
}

#[test]
fn retirement_refuses_opaque_item_macros_and_unscanned_target_paths() {
    for source in [
        "use generators::binding; binding!(gone);",
        "#[cfg_attr(test, path = \"../kept.rs\")] mod kept;",
    ] {
        assert_candidate_scan_refuses("crates/example/src/lib.rs", source, None);
    }
    for (section, path) in [
        ("test", "tests/kept"),
        ("bin", "../kept.rs"),
        ("lib", "../kept.rs"),
    ] {
        let header = if section == "lib" {
            "[lib]"
        } else if section == "bin" {
            "[[bin]]"
        } else {
            "[[test]]"
        };
        assert_candidate_scan_refuses(
            "crates/example/kept.rs",
            "#[test] #[ignore] fn gone() {}",
            Some(&format!(
                "[package]\nname = 'example'\n{header}\nname = 'foo'\npath = '{path}'\n"
            )),
        );
    }
}
