#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::accept::{AcceptReceipt, ProbeDiff};
use carrick_xtask::signed_gate::{
    allowed, label_authorized, validate_queue_entries, validate_receipt,
};
use carrick_xtask::signed_receipt::compare;
use serde_json::json;
use std::process::Command;

fn base() -> AcceptReceipt {
    serde_json::from_str(include_str!("fixtures/signed-base.json")).unwrap()
}

#[test]
fn killed_binary_cannot_fix_even_an_entirely_failed_base_binary() {
    let mut base = base();
    base.steps[0].failed_tests = base.steps[0].started_tests.clone();
    let candidate = serde_json::from_str(include_str!("fixtures/signed-killed.json")).unwrap();
    // Both comparisons reject missing execution even when all baseline
    // tests failed; a killed binary cannot be grandfathered.
    assert!(
        carrick_xtask::ci_receipt::diff(&base, &candidate)
            .unwrap()
            .new
            .iter()
            .any(|key| key.starts_with("not-run:el1-embed:"))
    );
    let diff = compare(&base, &candidate).unwrap();
    assert!(!diff.passed);
    assert_eq!(diff.steps[0].failed_tests.fixed.len(), 3);
    assert!(diff.new.contains("unfinished:el1-embed:embed"));
    assert!(diff.new.contains("population:el1-embed:started:1<3"));
    assert!(diff.new.contains("population:el1-embed:finished:0<1"));
    assert!(diff.new.contains("unitemized:el1-embed:crash:embed"));
}

#[test]
fn population_drop_fails_without_any_new_failure_name() {
    let candidate =
        serde_json::from_str(include_str!("fixtures/signed-population-drop.json")).unwrap();
    let diff = compare(&base(), &candidate).unwrap();
    assert!(!diff.passed);
    assert!(diff.steps[0].failed_tests.new.is_empty());
    assert_eq!(
        diff.new.iter().collect::<Vec<_>>(),
        [&"population:el1-embed:started:2<3"]
    );
}

#[test]
fn itemized_failures_el1_sets_and_human_strings_are_independent() {
    let base = base();
    let mut next = base.clone();
    next.failures = vec!["completely different human text".into()];
    assert!(compare(&base, &next).unwrap().passed);
    next.steps[0].failed_tests = vec!["embed::red_b".into(), "embed::new".into()];
    next.el1.as_mut().unwrap().unexpected_failures = vec!["new_unexpected".into()];
    let diff = compare(&base, &next).unwrap();
    assert!(!diff.passed);
    assert!(diff.new.contains("test:el1-embed:embed::new"));
    assert!(diff.fixed.contains("test:el1-embed:embed::red_a"));
    assert!(diff.new.contains("el1-unexpected:new_unexpected"));
    assert!(diff.fixed.contains("el1-unexpected:red_a"));
    assert!(diff.markdown().contains("Started base → candidate"));
}

#[test]
fn baseline_unfinished_binary_does_not_allow_another_unfinished_binary() {
    let mut base = base();
    base.steps[0].unfinished_binaries = vec!["old".into()];
    let mut next = base.clone();
    next.steps[0].unfinished_binaries = vec!["new".into()];
    assert!(
        compare(&base, &next)
            .unwrap()
            .new
            .contains("unfinished:el1-embed:new")
    );
    assert!(!compare(&base, &base).unwrap().passed);
}

#[test]
fn missing_steps_duplicate_steps_and_wrong_gates_fail_closed() {
    let base = base();
    let mut next = base.clone();
    next.steps[0].name = "replacement".into();
    assert!(
        compare(&base, &next)
            .unwrap()
            .new
            .contains("missing-step:el1-embed")
    );
    next.steps = vec![base.steps[0].clone(); 2];
    assert!(compare(&base, &next).is_err());
    next = base.clone();
    next.phase = "host".into();
    assert!(compare(&base, &next).is_err());
    next = base.clone();
    next.steps.clear();
    assert!(compare(&base, &next).is_err());
}

#[test]
fn shrinking_finished_population_or_replacing_a_binary_is_a_regression() {
    let base = base();
    let mut next = base.clone();
    next.steps[0].finished_binaries = vec!["replacement".into()];
    assert!(
        compare(&base, &next)
            .unwrap()
            .new
            .contains("missing-finished:el1-embed:embed")
    );
}

#[test]
fn cli_prints_and_persists_diff_before_returning_failure() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args([
            "ci-receipt",
            "signed-diff",
            "--base",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/signed-base.json"
            ),
            "--candidate",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/signed-killed.json"
            ),
            "--json",
        ])
        .arg(dir.path().join("diff.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Signed gate: **FAIL**"));
    let diff: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("diff.json")).unwrap()).unwrap();
    assert_eq!(diff["passed"], false);
}

/// #2038: advisory-only NEW entries print "PASS (advisory NEW only)" and must
/// exit 0, matching the Markdown; a blocking pair still exits non-zero.
#[test]
fn cli_advisory_only_new_entries_exit_zero() {
    let fixture =
        |name: &str| concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/").to_owned() + name;
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args([
            "ci-receipt",
            "signed-diff",
            "--base",
            &fixture("signed-base.json"),
            "--candidate",
            &fixture("signed-population-drop.json"),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Signed gate: **PASS (advisory NEW only)**"),
        "{stdout}"
    );
    assert!(output.status.success(), "{stdout}");
}

#[test]
fn owner_only_and_latest_label_transition_is_authority() {
    assert!(allowed("tjfontaine"));
    // The workers App is agent-held; it must never request a gate (#654).
    assert!(!allowed("carrick-workers[bot]"));
    assert!(!allowed("carrick-workers"));
    assert!(!allowed("someone-else"));
    let owner = json!({"id":1,"event":"labeled","label":{"name":"gate:signed"},"actor":{"login":"tjfontaine"}});
    assert!(label_authorized(std::slice::from_ref(&owner), "tjfontaine"));
    let unauthorized = json!({"id":2,"event":"labeled","label":{"name":"gate:signed"},"actor":{"login":"someone-else"}});
    assert!(!label_authorized(
        &[owner.clone(), unauthorized],
        "tjfontaine"
    ));
    let bot = json!({"id":4,"event":"labeled","label":{"name":"gate:signed"},"actor":{"login":"carrick-workers[bot]"}});
    assert!(!label_authorized(
        std::slice::from_ref(&bot),
        "carrick-workers[bot]"
    ));
    let removed = json!({"id":3,"event":"unlabeled","label":{"name":"gate:signed"},"actor":{"login":"tjfontaine"}});
    assert!(!label_authorized(&[owner, removed], "tjfontaine"));
}

#[test]
fn receipt_admission_fails_closed() {
    assert!(validate_receipt(&base(), &"a".repeat(40)).is_err());
}

/// Write the evidence the gate job leaves for its paired base run (#1884).
fn write_paired_base(results: &std::path::Path, base: &AcceptReceipt) -> std::path::PathBuf {
    let paired = results.join("base");
    std::fs::create_dir_all(&paired).unwrap();
    std::fs::write(paired.join("base.json"), serde_json::to_vec(base).unwrap()).unwrap();
    std::fs::write(
        paired.join("identity.json"),
        serde_json::to_vec(&base.artifact).unwrap(),
    )
    .unwrap();
    std::fs::write(
        paired.join("cleanup.json"),
        serde_json::to_vec(&base.cleanup_counts).unwrap(),
    )
    .unwrap();
    // Completed itemized failures: acceptance exits nonzero (#1889 review).
    std::fs::write(paired.join("accept-exit.json"), r#"{"success":false}"#).unwrap();
    seal_paired_base(results, &base.head);
    paired
}

/// Write the sealed record `execute` leaves after the candidate run.
fn seal_paired_base(results: &std::path::Path, base: &str) {
    std::fs::write(
        results.join("base-seal.json"),
        json!({"base": base, "files": inventory(&results.join("base"))}).to_string(),
    )
    .unwrap();
}

fn admitted(head: &str) -> AcceptReceipt {
    let mut value = serde_json::to_value(base()).unwrap();
    value["head"] = json!(head);
    // Match accept --profile no-docker --phase signed, independently of
    // the production declaration so this witnesses the real receipt shape.
    value["skipped_steps"] = json!([
        "conformance-probes-retained",
        "ltp",
        "inotify09-el1",
        "inotify09-el0"
    ]);
    value["artifact"] = json!({"path":"target/release/carrick","sha256":"1".repeat(64),"cdhash":"2".repeat(40),"lc_uuid":"some-uuid","hypervisor_entitlement":true,"dof_present":true});
    value["fixture_validation"] = json!({"validation_method":"input_identity","elf_hash_verification":"recomputed","checkout_head":head,"checkout_tree":"3".repeat(40),"bundle_source_head":"a".repeat(40),"checkout_dirty":false,"manifest_sha256":"4".repeat(64),"content_sha256":"6".repeat(64),"inputs_sha256":"5".repeat(64)});
    let names = [
        "fixtures",
        "build",
        "el1-embed",
        "fresh-executable-page",
        "generic-probe-shards",
        "probe-cases",
    ];
    let template = value["steps"][0].clone();
    value["steps"] = json!(
        names
            .iter()
            .map(|name| {
                let mut step = template.clone();
                step["name"] = json!(name);
                if *name == "fixtures" || *name == "build" {
                    step["passed"] = json!(true);
                }
                step
            })
            .collect::<Vec<_>>()
    );
    value["cleanup_counts"] = json!(
        names
            .iter()
            .skip(1)
            .map(|name| json!({"step":name,"run_id":format!("fixture-{name}"),"remaining_count":0}))
            .collect::<Vec<_>>()
    );
    serde_json::from_value(value).unwrap()
}

#[test]
fn no_docker_receipt_admits_exactly_the_declared_skips() {
    let sha = "a".repeat(40);
    let valid = admitted(&sha);
    validate_receipt(&valid, &sha).unwrap();
    // Skips describe a set; serialization order carries no authority.
    let mut reordered = valid.clone();
    reordered.skipped_steps.reverse();
    validate_receipt(&reordered, &sha).unwrap();
}

#[test]
fn no_docker_receipt_rejects_extra_missing_and_duplicate_skips() {
    let sha = "a".repeat(40);
    let valid = admitted(&sha);
    let mut extra = valid.clone();
    extra.skipped_steps.push("probe-cases".into());
    let mut missing = valid.clone();
    missing.skipped_steps.pop();
    let mut duplicate = valid.clone();
    duplicate.skipped_steps.push("ltp".into());
    let mut empty = valid;
    empty.skipped_steps.clear();
    for receipt in [extra, missing, duplicate, empty] {
        let error = validate_receipt(&receipt, &sha).unwrap_err().to_string();
        assert!(error.contains("receipt skipped_steps mismatch"), "{error}");
    }
}

#[test]
fn no_docker_receipt_names_each_mismatched_admission_field() {
    let sha = "a".repeat(40);
    let valid = admitted(&sha);
    for (field, replacement) in [
        ("head", json!("b".repeat(40))),
        ("clean_tree", json!(false)),
        ("phase", json!("host")),
        ("profile", json!("linux-portable")),
    ] {
        let mut value = serde_json::to_value(&valid).unwrap();
        value[field] = replacement;
        let receipt = serde_json::from_value(value).unwrap();
        let error = validate_receipt(&receipt, &sha).unwrap_err().to_string();
        assert!(
            error.contains(&format!("receipt {field} mismatch")),
            "{field}: {error}"
        );
    }
    for step in &valid.steps {
        let mut missing = valid.clone();
        missing.steps.retain(|s| s.name != step.name);
        let error = validate_receipt(&missing, &sha).unwrap_err().to_string();
        assert!(
            error.contains("step") && error.contains(&step.name),
            "{error}"
        );
    }
}

#[test]
fn baseline_admission_requires_every_population_identity_and_scoped_cleanup() {
    let sha = "a".repeat(40);
    let valid = admitted(&sha);
    validate_receipt(&valid, &sha).unwrap();
    let mut truncated = valid.clone();
    truncated.steps.pop();
    assert!(validate_receipt(&truncated, &sha).is_err());
    let mut killed = valid.clone();
    killed.steps[2].unfinished_binaries.push("embed".into());
    // A recorded main crash may be compared, but a newly unfinished binary fails.
    validate_receipt(&killed, &sha).unwrap();
    let mut no_cleanup = valid.clone();
    no_cleanup.cleanup_counts.clear();
    assert!(validate_receipt(&no_cleanup, &sha).is_err());
    let mut no_entitlement = valid.clone();
    no_entitlement
        .artifact
        .as_mut()
        .unwrap()
        .hypervisor_entitlement = false;
    assert!(validate_receipt(&no_entitlement, &sha).is_err());
    let mut no_population = valid;
    no_population.steps[2].started_tests.clear();
    assert!(validate_receipt(&no_population, &sha).is_err());
}

#[cfg(unix)]
#[test]
fn actions_prepare_and_publish_use_the_paired_base_and_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // Local immutable graph replays the queue topology without network access.
    let repo = dir.path().join("graph");
    std::fs::create_dir(&repo).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "-b", "main"]);
    git(&["config", "user.name", "Replay"]);
    git(&["config", "user.email", "replay@example.invalid"]);
    git(&["config", "uploadpack.allowAnySHA1InWant", "true"]);
    let commit = |message: &str| {
        git(&["commit", "--allow-empty", "-m", message]);
        git(&["rev-parse", "HEAD"])
    };
    let a = commit("main");
    let d = commit("first queued PR");
    let b = commit("second queued PR");
    let c = commit("next group");
    let tree = git(&["rev-parse", "HEAD^{tree}"]);
    let x = git(&["commit-tree", &tree, "-p", &c, "-m", "unqueued descendant"]);
    git(&[
        "update-ref",
        "refs/heads/gh-readonly-queue/main/pr-123-a",
        &d,
    ]);
    git(&[
        "update-ref",
        "refs/heads/gh-readonly-queue/main/pr-124-d",
        &b,
    ]);
    git(&[
        "update-ref",
        "refs/heads/gh-readonly-queue/main/pr-125-b",
        &c,
    ]);
    git(&["checkout", "-B", "main", &a]);
    let tree = git(&["rev-parse", "HEAD^{tree}"]);
    let unrelated = git(&["commit-tree", &tree, "-m", "unrelated root"]);
    let git_shim = bin.join("git");
    let real_git = Command::new("which").arg("git").output().unwrap();
    let real_git = String::from_utf8(real_git.stdout)
        .unwrap()
        .trim()
        .to_owned();
    carrick_test_support::executable::write_executable(
        &git_shim,
        format!(
            r#"#!/usr/bin/env python3
import os, sys
args = [os.environ['TEST_GRAPH'] if a == 'https://github.com/carrick-sh/carrick.git' else a for a in sys.argv[1:]]
if args[:2] == ['ls-remote', '--refs'] and os.environ.get('TEST_HIDE_QUEUE_REFS'):
    raise SystemExit(0)
os.execv({real_git:?}, ['git'] + args)
"#
        ),
    );
    let gh = bin.join("gh");
    carrick_test_support::executable::write_executable(
        &gh,
        r#"#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
base, head = os.environ['TEST_BASE_SHA'], os.environ['TEST_HEAD_SHA']
# The paired gate executes its own base; stored receipts are never fetched.
if args[:2] in (['run', 'watch'], ['run', 'download']):
    raise SystemExit('stored signed baseline access is retired: '+repr(args))
elif '--method' in args and args[args.index('--method')+1] == 'POST':
    endpoint = args[args.index('POST')+1]
    with open(os.environ['TEST_POSTS'], 'a') as out:
        out.write(json.dumps({'endpoint':endpoint,'body':json.load(sys.stdin)})+'\n')
elif args[:2] == ['api', 'graphql']:
    nodes = json.loads(os.environ.get('TEST_QUEUE_ENTRIES', '[]'))
    entries = {'pageInfo': {'hasNextPage': os.environ.get('TEST_QUEUE_HAS_NEXT') == '1'}}
    if os.environ.get('TEST_QUEUE_OMIT_NODES') != '1':
        entries['nodes'] = nodes
    print(json.dumps({'data':{'repository':{'mergeQueue':{'entries':entries}}}}))
elif args[0] == 'api':
    endpoint = args[-1]
    if '/pulls/' in endpoint:
        print(json.dumps({'state':'open','head':{'sha':head},'base':{'ref':'main'}}))
    elif '/compare/' in endpoint:
        print(json.dumps({'merge_base_commit':{'sha':base}}))
    elif '/commits/' in endpoint and '/pulls?' in endpoint:
        print(json.dumps([json.loads(os.environ.get('TEST_REST_PULLS', '[]'))]))
    elif '/events?' in endpoint:
        print(json.dumps([[{'id':1,'event':'labeled','label':{'name':'gate:signed'},'actor':{'login':os.environ.get('TEST_LABEL_ACTOR','tjfontaine')}}]]))
    else:
        raise SystemExit('unexpected API endpoint: '+endpoint)
else:
    raise SystemExit('unexpected gh invocation: '+repr(args))
"#,
    );
    let base = admitted(&a);
    let event = dir.path().join("event.json");
    std::fs::write(&event, json!({"repository":{"full_name":"carrick-sh/carrick"},"inputs":{"pr":"123","sha":b.clone()}}).to_string()).unwrap();
    let posts = dir.path().join("posts.jsonl");
    let child = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
        cmd.env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("GITHUB_ACTOR", "tjfontaine")
        .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
        .env("GITHUB_EVENT_NAME", "workflow_dispatch")
        .env("GITHUB_REF", "refs/heads/main")
        .env("TEST_BASE_SHA", &a)
        .env("TEST_HEAD_SHA", &b)
        .env("TEST_GRAPH", &repo)
        .env("TEST_PREVIOUS_SHA", &d)
        .env("TEST_POSTS", &posts)
        .env_remove("GITHUB_OUTPUT");
        cmd
    };
    let request_dir = dir.path().join("request");
    let prepared = child()
        .args(["signed-gate", "prepare", "--event"])
        .arg(&event)
        .arg("--output")
        .arg(&request_dir)
        .output()
        .unwrap();
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    // Authorization names the pair only; no stored base receipt is fetched.
    let names: Vec<_> = std::fs::read_dir(&request_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["request.json"]);
    let denied = child()
        .env("GITHUB_TRIGGERING_ACTOR", "someone-else")
        .args(["signed-gate", "prepare", "--event"])
        .arg(&event)
        .arg("--output")
        .arg(dir.path().join("denied"))
        .output()
        .unwrap();
    assert!(!denied.status.success());
    assert!(!dir.path().join("denied").exists());

    let label_event = dir.path().join("label.json");
    std::fs::write(&label_event, json!({"repository":{"full_name":"carrick-sh/carrick"},"action":"labeled","label":{"name":"gate:signed"},"sender":{"login":"tjfontaine"},"number":123,"pull_request":{"head":{"sha":b.clone()}}}).to_string()).unwrap();
    let label = |actor: &str| {
        child()
            .env("GITHUB_EVENT_NAME", "pull_request_target")
            .env("TEST_LABEL_ACTOR", actor)
            .args(["signed-gate", "prepare", "--event"])
            .arg(&label_event)
            .arg("--output")
            .arg(dir.path().join(format!("label-{actor}")))
            .output()
            .unwrap()
    };
    assert!(label("tjfontaine").status.success());
    assert!(!label("someone-else").status.success());

    let queue_ref = "refs/heads/gh-readonly-queue/main/pr-124-test";
    let queue_event = dir.path().join("queue.json");
    let queue_payload = json!({"repository":{"full_name":"carrick-sh/carrick"},"action":"checks_requested","merge_group":{"base_ref":"refs/heads/main","head_ref":queue_ref,"head_sha":b.clone(),"base_sha":a.clone()}});
    std::fs::write(&queue_event, queue_payload.to_string()).unwrap();
    let queue_dir = dir.path().join("queue-request");
    let queue_with_config = |payload: &serde_json::Value,
                             entries: &str,
                             has_next: &str,
                             omit_nodes: &str,
                             rest_pulls: &str| {
        std::fs::write(&queue_event, payload.to_string()).unwrap();
        child()
            .env("GITHUB_EVENT_NAME", "merge_group")
            .env("GITHUB_ACTOR", "github-merge-queue[bot]")
            .env("GITHUB_TRIGGERING_ACTOR", "github-merge-queue[bot]")
            .env(
                "GITHUB_REF",
                payload["merge_group"]["head_ref"]
                    .as_str()
                    .unwrap_or(queue_ref),
            )
            .env(
                "GITHUB_SHA",
                payload["merge_group"]["head_sha"].as_str().unwrap_or(&b),
            )
            .env("TEST_QUEUE_ENTRIES", entries)
            .env("TEST_QUEUE_HAS_NEXT", has_next)
            .env("TEST_QUEUE_OMIT_NODES", omit_nodes)
            .env("TEST_HIDE_QUEUE_REFS", "1")
            .env("TEST_REST_PULLS", rest_pulls)
            .args(["signed-gate", "prepare", "--event"])
            .arg(&queue_event)
            .arg("--output")
            .arg(&queue_dir)
            .output()
            .unwrap()
    };
    let queue_with_entries = |payload: &serde_json::Value, entries: &str| {
        let rest_pulls = if payload["merge_group"]["head_ref"]
            == "refs/heads/gh-readonly-queue/main/forged"
        {
            r#"[{"number":777,"merged_at":"2026-01-01T00:00:00Z","base":{"ref":"main","repo":{"full_name":"carrick-sh/carrick"}}}]"#
        } else {
            "[]"
        };
        queue_with_config(payload, entries, "0", "0", rest_pulls)
    };
    let live_predecessor = serde_json::json!([
        {"baseCommit":{"oid":a},"headCommit":{"oid":d},"pullRequest":{"number":123,"baseRefName":"main","baseRepository":{"nameWithOwner":"carrick-sh/carrick"}}},
        {"baseCommit":{"oid":d},"headCommit":{"oid":b},"pullRequest":{"number":124,"baseRefName":"main","baseRepository":{"nameWithOwner":"carrick-sh/carrick"}}},
        {"baseCommit":{"oid":b},"headCommit":{"oid":c},"pullRequest":{"number":125,"baseRefName":"main","baseRepository":{"nameWithOwner":"carrick-sh/carrick"}}}
    ])
    .to_string();
    let queue = |payload: &serde_json::Value| queue_with_entries(payload, &live_predecessor);
    let queued = queue(&queue_payload);
    assert!(
        queued.status.success(),
        "{}",
        String::from_utf8_lossy(&queued.stderr)
    );
    let queue_request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(queue_dir.join("request.json")).unwrap()).unwrap();
    assert_eq!(queue_request["kind"], "MergeGroup");
    assert_eq!(queue_request["base"], a.clone());
    assert_eq!(queue_request["sha"], b.clone());
    assert_eq!(queue_request["prs"], json!([123, 124]));
    // Replay a second-in-line group: D is still queued on A, and B
    // contains both groups. The receipt must compare the whole group to A.
    let mut second = queue_payload.clone();
    second["merge_group"]["base_sha"] = json!(d.clone());
    let replay = queue(&second);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let second_request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(queue_dir.join("request.json")).unwrap()).unwrap();
    assert_eq!(second_request["base"], a.clone());
    assert_eq!(second_request["prs"], json!([123, 124]));
    let mut third = queue_payload.clone();
    third["merge_group"]["head_ref"] = json!("refs/heads/gh-readonly-queue/main/pr-125-test");
    third["merge_group"]["head_sha"] = json!(c.clone());
    third["merge_group"]["base_sha"] = json!(b.clone());
    let third = queue(&third);
    assert!(
        third.status.success(),
        "{}",
        String::from_utf8_lossy(&third.stderr)
    );
    let third_request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(queue_dir.join("request.json")).unwrap()).unwrap();
    assert_eq!(third_request["prs"], json!([123, 124, 125]));

    let truncated_queue = queue_with_config(&queue_payload, &live_predecessor, "1", "0", "[]");
    let missing_queue_nodes = queue_with_config(&queue_payload, "[]", "0", "1", "[]");
    assert!(
        !truncated_queue.status.success() && !missing_queue_nodes.status.success(),
        "partial or structurally incomplete queue data was accepted"
    );

    // If a predecessor leaves the queue between event creation and lookup,
    // its merged PR association must survive into the receipt. An empty or
    // unmerged REST association cannot silently drop it.
    let current_only = serde_json::json!([{
        "baseCommit":{"oid":d},"headCommit":{"oid":b},
        "pullRequest":{"number":124,"baseRefName":"main","baseRepository":{"nameWithOwner":"carrick-sh/carrick"}}
    }]).to_string();
    let merged_predecessor = r#"[{"number":123,"merged_at":"2026-01-01T00:00:00Z","base":{"ref":"main","repo":{"full_name":"carrick-sh/carrick"}}}]"#;
    let race_resolved = queue_with_config(&second, &current_only, "0", "0", merged_predecessor);
    assert!(
        race_resolved.status.success(),
        "{}",
        String::from_utf8_lossy(&race_resolved.stderr)
    );
    let race_request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(queue_dir.join("request.json")).unwrap()).unwrap();
    assert_eq!(race_request["prs"], json!([123, 124]));
    let race_unresolved = queue_with_config(&second, &current_only, "0", "0", "[]");
    let race_unmerged = queue_with_config(
        &second,
        &current_only,
        "0",
        "0",
        r#"[{"number":123,"merged_at":null,"base":{"ref":"main","repo":{"full_name":"carrick-sh/carrick"}}}]"#,
    );
    assert!(
        !race_unresolved.status.success() && !race_unmerged.status.success(),
        "unresolved or unmerged predecessor association was accepted"
    );
    // An unqueued descendant cannot borrow the current live PR's number.
    let mut forged_descendant = second.clone();
    forged_descendant["merge_group"]["head_sha"] = json!(x.clone());
    let forged_descendant = queue_with_entries(&forged_descendant, &live_predecessor);
    let unqueued_descendant_refused = !forged_descendant.status.success();
    // A malformed queue ref cannot fall back to REST commit associations.
    let mut malformed_queue_ref = queue_payload.clone();
    malformed_queue_ref["merge_group"]["head_ref"] =
        json!("refs/heads/gh-readonly-queue/main/forged");
    let malformed_ref = queue_with_entries(&malformed_queue_ref, "[]");
    assert!(
        unqueued_descendant_refused && !malformed_ref.status.success(),
        "unqueued descendant refused={unqueued_descendant_refused}; malformed ref refused={}",
        !malformed_ref.status.success()
    );
    // A first-parent ancestor is not enough: second-in-line authorization
    // requires the predecessor to still be a live entry in main's queue.
    let stale_base = queue_with_entries(&second, "[]");
    let stale_was_refused = !stale_base.status.success();
    let dequeued_entry = serde_json::json!([{
        "baseCommit": {"oid": a},
        "headCommit": {"oid": d},
        "pullRequest": {
            "number": 123,
            "baseRefName": "main",
            "baseRepository": {"nameWithOwner": "carrick-sh/carrick"}
        }
    }])
    .to_string();
    let dequeued_base = queue_with_entries(&second, &dequeued_entry);
    let dequeued_was_refused = !dequeued_base.status.success();
    let foreign_branch_entry = serde_json::json!([{
        "baseCommit": {"oid": d},
        "headCommit": {"oid": d},
        "pullRequest": {
            "number": 123,
            "baseRefName": "release",
            "baseRepository": {"nameWithOwner": "carrick-sh/carrick"}
        }
    }])
    .to_string();
    let foreign_branch = queue_with_entries(&second, &foreign_branch_entry);
    let foreign_branch_was_refused = !foreign_branch.status.success();
    let mut forged_ref = second.clone();
    forged_ref["merge_group"]["head_ref"] =
        json!("refs/heads/gh-readonly-queue/main/pr-999-forged");
    let forged = queue(&forged_ref);
    let forged_was_refused = !forged.status.success();
    assert!(
        stale_was_refused
            && dequeued_was_refused
            && foreign_branch_was_refused
            && forged_was_refused,
        "refusal witnesses: stale={stale_was_refused}, dequeued={dequeued_was_refused}, foreign_branch={foreign_branch_was_refused}, forged={forged_was_refused}"
    );
    for (field, bad) in [
        ("base_ref", "refs/heads/other"),
        ("head_ref", "refs/heads/feature"),
        ("head_sha", "c"),
        ("base_sha", "invalid"),
    ] {
        let mut wrong = queue_payload.clone();
        wrong["merge_group"][field] = json!(bad);
        assert!(!queue(&wrong).status.success(), "accepted {field}");
    }
    let mut unrelated_base = queue_payload.clone();
    unrelated_base["merge_group"]["base_sha"] = json!(unrelated);
    let refused = queue(&unrelated_base);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("not a live entry"));
    let mut wrong = queue_payload.clone();
    wrong["action"] = json!("destroyed");
    assert!(!queue(&wrong).status.success());
    wrong = queue_payload.clone();
    wrong["merge_group"]["head_sha"] = json!(c.clone());
    assert!(!queue(&wrong).status.success());
    wrong = queue_payload.clone();
    wrong["merge_group"]["base_sha"] = json!(c.clone());
    assert!(!queue(&wrong).status.success());
    let mut wrong = queue_payload.clone();
    wrong["repository"]["full_name"] = json!("someone/fork");
    assert!(!queue(&wrong).status.success());

    let results = dir.path().join("results");
    std::fs::create_dir(&results).unwrap();
    // The gate job executed base A on the same Mac with the same bundle.
    let paired = write_paired_base(&results, &base);
    let paired_path = paired.join("base.json");
    let candidate = admitted(&b);
    let candidate_path = results.join("candidate.json");
    std::fs::write(&candidate_path, serde_json::to_vec(&candidate).unwrap()).unwrap();
    std::fs::write(
        results.join("identity.json"),
        serde_json::to_vec(&candidate.artifact).unwrap(),
    )
    .unwrap();
    std::fs::write(
        results.join("cleanup.json"),
        serde_json::to_vec(&candidate.cleanup_counts).unwrap(),
    )
    .unwrap();
    let publish = |execution: &str| {
        child()
            .args(["signed-gate", "publish", "--request"])
            .arg(request_dir.join("request.json"))
            .arg("--results")
            .arg(&results)
            .args([
                "--run-url",
                "https://github.com/carrick-sh/carrick/actions/runs/200",
                "--execution-result",
                execution,
            ])
            .output()
            .unwrap()
    };
    let passed = publish("success");
    assert!(
        passed.status.success(),
        "{}",
        String::from_utf8_lossy(&passed.stderr)
    );
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&posts)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows[0]["body"]["state"], "success");
    assert_eq!(rows[0]["body"]["context"], "signed-gate");
    assert!(
        rows[1]["body"]["body"]
            .as_str()
            .unwrap()
            .contains("Started base → candidate")
    );

    let publish_queue = || {
        child()
            .args(["signed-gate", "publish", "--request"])
            .arg(queue_dir.join("request.json"))
            .arg("--results")
            .arg(&results)
            .args([
                "--run-url",
                "https://github.com/carrick-sh/carrick/actions/runs/202",
                "--execution-result",
                "success",
            ])
            .output()
            .unwrap()
    };
    assert!(publish_queue().status.success());
    assert!(
        std::fs::read_to_string(results.join("comment.md"))
            .unwrap()
            .contains("Pull requests: #123, #124")
    );
    let mut regression = candidate.clone();
    regression.steps[2]
        .failed_tests
        .push("new_queue_failure".into());
    std::fs::write(&candidate_path, serde_json::to_vec(&regression).unwrap()).unwrap();
    assert!(!publish_queue().status.success());
    let queue_posts: Vec<serde_json::Value> = std::fs::read_to_string(&posts)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let last = &queue_posts[queue_posts.len() - 3..];
    assert_eq!(last[0]["body"]["state"], "failure");
    assert!(
        last[1]["endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/123/comments")
    );
    assert!(
        last[2]["endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/124/comments")
    );
    for item in &last[1..] {
        let body = item["body"]["body"].as_str().unwrap();
        assert!(body.contains("Pull requests: #123, #124"), "{body}");
        assert!(body.contains("new_queue_failure"), "{body}");
    }
    std::fs::write(&candidate_path, serde_json::to_vec(&candidate).unwrap()).unwrap();

    let mut foreign = candidate.clone();
    foreign.host_identity.as_mut().unwrap().runner_name = "foreign-mac".into();
    foreign.steps[2]
        .failed_tests
        .push("host_dependent_failure".into());
    std::fs::write(&candidate_path, serde_json::to_vec(&foreign).unwrap()).unwrap();
    let refused = publish("success");
    assert!(!refused.status.success());
    let body = std::fs::read_to_string(results.join("comment.md")).unwrap();
    assert!(body.contains("INCOMPARABLE BASE — BLOCKED"), "{body}");
    assert!(!body.contains("NEW="), "{body}");
    assert!(
        !results.join("diff.json").exists(),
        "refusal retained a stale comparison"
    );
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&posts)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows[rows.len() - 2]["body"]["state"], "failure");
    assert!(
        rows[rows.len() - 2]["body"]["description"]
            .as_str()
            .unwrap()
            .contains("Incomparable base")
    );
    std::fs::write(&candidate_path, serde_json::to_vec(&candidate).unwrap()).unwrap();

    // Without its paired base, or with unadmitted base evidence, a request
    // cannot pass; publication never falls back to a stored receipt.
    std::fs::write(paired.join("cleanup.json"), "[]").unwrap();
    seal_paired_base(&results, &a);
    assert!(!publish("success").status.success());
    let body = std::fs::read_to_string(results.join("comment.md")).unwrap();
    assert!(body.contains("Base evidence admission failed"), "{body}");
    write_paired_base(&results, &base);
    std::fs::rename(&paired_path, paired.join("moved.json")).unwrap();
    assert!(!publish("success").status.success());
    let body = std::fs::read_to_string(results.join("comment.md")).unwrap();
    assert!(body.contains("No valid comparison"), "{body}");
    std::fs::rename(paired.join("moved.json"), &paired_path).unwrap();
    assert!(publish("success").status.success());

    // A valid receipt cannot hide a failed execution job, nor can an unrelated
    // identity file stand in for independently inspected artifact identity.
    assert!(!publish("failure").status.success());
    std::fs::write(results.join("identity.json"), "{}").unwrap();
    assert!(!publish("success").status.success());
    std::fs::remove_file(&candidate_path).unwrap();
    assert!(!publish("failure").status.success());
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&posts)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows[rows.len() - 2]["body"]["state"], "failure");
    assert!(
        rows.last().unwrap()["body"]["body"]
            .as_str()
            .unwrap()
            .contains("No valid comparison")
    );
    // A failed (not cancelled) job with no candidate is still a FAIL.
    let body = std::fs::read_to_string(results.join("comment.md")).unwrap();
    assert!(body.starts_with("Signed gate: **FAIL**"), "{body}");

    // A cancelled run that never produced a candidate has no verdict to
    // report, but still must not pass the required check.
    let cancelled = publish("cancelled");
    assert!(!cancelled.status.success());
    let body = std::fs::read_to_string(results.join("comment.md")).unwrap();
    assert!(
        body.starts_with("Signed gate: **CANCELLED — no verdict**"),
        "{body}"
    );
    assert!(!body.contains("**FAIL**"), "{body}");
    assert!(!body.contains("No valid comparison"), "{body}");
    assert!(body.contains("actions/runs/200"), "{body}");
    assert!(body.contains(&format!("`{b}`")), "{body}");
    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&posts)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows[rows.len() - 2]["body"]["state"], "failure");

    // Cancelled but with a candidate: the normal path, never "no verdict".
    std::fs::write(&candidate_path, serde_json::to_vec(&candidate).unwrap()).unwrap();
    assert!(!publish("cancelled").status.success());
    let body = std::fs::read_to_string(results.join("comment.md")).unwrap();
    assert!(!body.contains("no verdict"), "{body}");
    assert!(body.contains("Execution job: `cancelled`"), "{body}");
    std::fs::remove_file(&candidate_path).unwrap();

    // The main reseed path uses the same gate, without needing a previous base.
    std::fs::write(&event, json!({"repository":{"full_name":"carrick-sh/carrick"},"ref":"refs/heads/main","deleted":false,"after":a.clone()}).to_string()).unwrap();
    let main_dir = dir.path().join("main-request");
    let main = child()
        .env("GITHUB_EVENT_NAME", "push")
        .env("GITHUB_SHA", a.clone())
        .env("GITHUB_ACTOR", "merge-bot")
        .env("GITHUB_TRIGGERING_ACTOR", "merge-bot")
        .args(["signed-gate", "prepare", "--event"])
        .arg(&event)
        .arg("--output")
        .arg(&main_dir)
        .output()
        .unwrap();
    assert!(
        main.status.success(),
        "{}",
        String::from_utf8_lossy(&main.stderr)
    );
    assert!(!main_dir.join("base.json").exists());
    std::fs::write(
        results.join("candidate.json"),
        serde_json::to_vec(&base).unwrap(),
    )
    .unwrap();
    std::fs::write(
        results.join("identity.json"),
        serde_json::to_vec(&base.artifact).unwrap(),
    )
    .unwrap();
    let main = child()
        .args(["signed-gate", "publish", "--request"])
        .arg(main_dir.join("request.json"))
        .arg("--results")
        .arg(&results)
        .args([
            "--run-url",
            "https://github.com/carrick-sh/carrick/actions/runs/201",
            "--execution-result",
            "success",
        ])
        .output()
        .unwrap();
    assert!(
        main.status.success(),
        "{}",
        String::from_utf8_lossy(&main.stderr)
    );
    // Next landing: main B seeds its own baseline automatically, and group C
    // uses B rather than A or a PR merge base, without manual dispatch.
    git(&["checkout", "-B", "main", &b]);
    let next_main = json!({"repository":{"full_name":"carrick-sh/carrick"},"ref":"refs/heads/main","deleted":false,"after":b.clone()});
    std::fs::write(&event, next_main.to_string()).unwrap();
    let next_child = || {
        let mut cmd = child();
        cmd.env("TEST_BASE_SHA", &b).env("TEST_HEAD_SHA", &c);
        cmd
    };
    let main = next_child()
        .env("GITHUB_EVENT_NAME", "push")
        .env("GITHUB_SHA", b.clone())
        .env("GITHUB_ACTOR", "merge-bot")
        .env("GITHUB_TRIGGERING_ACTOR", "merge-bot")
        .args(["signed-gate", "prepare", "--event"])
        .arg(&event)
        .arg("--output")
        .arg(&main_dir)
        .output()
        .unwrap();
    assert!(
        main.status.success(),
        "{}",
        String::from_utf8_lossy(&main.stderr)
    );
    let mut next_queue = queue_payload;
    next_queue["merge_group"]["head_ref"] = json!("refs/heads/gh-readonly-queue/main/pr-123-next");
    next_queue["merge_group"]["head_sha"] = json!(c.clone());
    next_queue["merge_group"]["base_sha"] = json!(b.clone());
    std::fs::write(&queue_event, next_queue.to_string()).unwrap();
    let queued = next_child()
        .env("GITHUB_EVENT_NAME", "merge_group")
        .env(
            "GITHUB_REF",
            "refs/heads/gh-readonly-queue/main/pr-123-next",
        )
        .env("GITHUB_SHA", c.clone())
        .env(
            "TEST_QUEUE_ENTRIES",
            serde_json::json!([{
                "baseCommit": {"oid": b},
                "headCommit": {"oid": c},
                "pullRequest": {
                    "number": 123,
                    "baseRefName": "main",
                    "baseRepository": {"nameWithOwner": "carrick-sh/carrick"}
                }
            }])
            .to_string(),
        )
        .env("GITHUB_ACTOR", "merge-bot")
        .env("GITHUB_TRIGGERING_ACTOR", "merge-bot")
        .args(["signed-gate", "prepare", "--event"])
        .arg(&queue_event)
        .arg("--output")
        .arg(&queue_dir)
        .output()
        .unwrap();
    assert!(
        queued.status.success(),
        "{}",
        String::from_utf8_lossy(&queued.stderr)
    );
    let next: serde_json::Value =
        serde_json::from_slice(&std::fs::read(queue_dir.join("request.json")).unwrap()).unwrap();
    assert_eq!(next["base"], b.clone());
    assert_eq!(next["sha"], c.clone());
}

#[test]
fn panic_headers_differing_only_in_numeric_thread_id_produce_no_new_or_fixed() {
    let mut base = base();
    let mut candidate = base.clone();
    base.probe_diffs = vec![ProbeDiff {
        step: "probe-cases".into(),
        probe: "case_04_id_root_credentials".into(),
        line: "thread 'case_04_id_root_credentials' (26967979) panicked at crates/carrick-embed/src/testing.rs:466:9:".into(),
    }];
    candidate.probe_diffs = vec![ProbeDiff {
        step: "probe-cases".into(),
        probe: "case_04_id_root_credentials".into(),
        line: "thread 'case_04_id_root_credentials' (31288555) panicked at crates/carrick-embed/src/testing.rs:466:9:".into(),
    }];
    let diff = compare(&base, &candidate).unwrap();
    assert!(diff.passed, "expected diff to pass but got: {:?}", diff.new);
    assert!(
        diff.new.is_empty(),
        "expected 0 NEW but got: {:?}",
        diff.new
    );
    assert!(
        diff.fixed.is_empty(),
        "expected 0 FIXED but got: {:?}",
        diff.fixed
    );
}

#[test]
fn embedded_multiline_panic_headers_differing_only_in_thread_id_produce_no_new_or_fixed() {
    let mut base = base();
    let mut candidate = base.clone();
    base.probe_diffs = vec![ProbeDiff {
        step: "probe-cases".into(),
        probe: "case_04_id_root_credentials".into(),
        line: "stack backtrace:\nthread 'case_04_id_root_credentials' (26967979) panicked at crates/carrick-embed/src/testing.rs:466:9:\nsome backtrace line".into(),
    }];
    candidate.probe_diffs = vec![ProbeDiff {
        step: "probe-cases".into(),
        probe: "case_04_id_root_credentials".into(),
        line: "stack backtrace:\nthread 'case_04_id_root_credentials' (31288555) panicked at crates/carrick-embed/src/testing.rs:466:9:\nsome backtrace line".into(),
    }];
    let diff = compare(&base, &candidate).unwrap();
    assert!(
        diff.passed,
        "expected multiline to pass but got: {:?}",
        diff.new
    );
    assert!(diff.new.is_empty());
    assert!(diff.fixed.is_empty());
}

#[test]
fn negative_controls_changed_errno_location_diagnostic_test_or_malformed_header_produce_new() {
    let base_receipt = base();

    // 1. Changed errno/value elsewhere in line produces NEW
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (12345) panicked at src/lib.rs:10:5: Os { code: 2, kind: NotFound }".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (67890) panicked at src/lib.rs:10:5: Os { code: 22, kind: InvalidInput }".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 2. Changed diagnostic suffix/message produces NEW
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (12345) panicked at src/lib.rs:10:5: assertion `left == right` failed".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (67890) panicked at src/lib.rs:10:5: assertion `left != right` failed".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 3. Changed test identity produces NEW
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (12345) panicked at src/lib.rs:10:5:".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_05' (67890) panicked at src/lib.rs:10:5:".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 4. Changed source location (line / column / file) produces NEW
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (12345) panicked at src/lib.rs:10:5:".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (67890) panicked at src/lib.rs:20:5:".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 5. Malformed header (non-numeric thread ID) stays exact and produces NEW
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (not_a_number) panicked at src/lib.rs:10:5:".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'case_04' (other_token) panicked at src/lib.rs:10:5:".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 6. Malformed header (missing quotes) stays exact and produces NEW
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread case_04 (12345) panicked at src/lib.rs:10:5:".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread case_04 (67890) panicked at src/lib.rs:10:5:".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 7. DIFF payload containing panic-like phrase stays exact
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "DIFF encoded=thread 'worker' (14) panicked at src/lib.rs:10:5:".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "DIFF encoded=thread 'worker' (22) panicked at src/lib.rs:10:5:".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 8. Unqualified source location stays exact
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'worker' (14) panicked at not_a_source_location".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'worker' (22) panicked at not_a_source_location".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 9. Quoted/escaped panic phrase in diagnostic message stays exact
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "\"thread 'worker' (14) panicked at src/lib.rs:10:5:\"".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "\"thread 'worker' (22) panicked at src/lib.rs:10:5:\"".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 10. Ambiguous multiple panic-header delimiters in thread name stay exact
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "thread-name-control".into(),
            line: "thread 'worker' (14) panicked at src/lib.rs:10:5: name' (999) panicked at src/main.rs:20:3:".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "thread-name-control".into(),
            line: "thread 'worker' (22) panicked at src/lib.rs:10:5: name' (999) panicked at src/main.rs:20:3:".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }

    // 11. Ambiguous panic-header delimiter in diagnostic suffix stays exact
    {
        let mut b = base_receipt.clone();
        let mut c = base_receipt.clone();
        b.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'worker' (999) panicked at src/main.rs:20:3: nested ' (14) panicked at src/lib.rs:10:5:".into(),
        }];
        c.probe_diffs = vec![ProbeDiff {
            step: "probe-cases".into(),
            probe: "probe".into(),
            line: "thread 'worker' (999) panicked at src/main.rs:20:3: nested ' (22) panicked at src/lib.rs:10:5:".into(),
        }];
        let diff = compare(&b, &c).unwrap();
        assert!(!diff.passed);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 1);
    }
}

#[test]
fn historical_fixture_evidence_does_not_invent_hash_work_status() {
    let mut value = serde_json::to_value(admitted(&"b".repeat(40))).unwrap();
    value["fixture_validation"]
        .as_object_mut()
        .unwrap()
        .remove("elf_hash_verification");
    let receipt: AcceptReceipt = serde_json::from_value(value).unwrap();
    assert_eq!(
        serde_json::to_value(receipt).unwrap()["fixture_validation"]["elf_hash_verification"],
        "not_recorded"
    );
}

#[cfg(unix)]
#[test]
fn merge_group_rejects_bases_without_first_parent_main_ancestry() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let repo = dir.path().join("graph");
    std::fs::create_dir(&repo).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "-b", "main"]);
    git(&["config", "user.name", "Replay"]);
    git(&["config", "user.email", "replay@example.invalid"]);
    git(&["config", "uploadpack.allowAnySHA1InWant", "true"]);
    git(&["commit", "--allow-empty", "-m", "main root"]);
    let m0 = git(&["rev-parse", "HEAD"]);
    let tree = git(&["rev-parse", "HEAD^{tree}"]);

    // Side history merged into main ONLY as a second parent of m1.
    let side_root = git(&["commit-tree", &tree, "-m", "side root"]);
    let side_a = git(&["commit-tree", &tree, "-p", &side_root, "-m", "side a"]);
    let side_b = git(&["commit-tree", &tree, "-p", &side_a, "-m", "side b"]);
    let side_c = git(&["commit-tree", &tree, "-p", &side_b, "-m", "side c"]);
    let m1 = git(&[
        "commit-tree",
        &tree,
        "-p",
        &m0,
        "-p",
        &side_a,
        "-m",
        "main merge side_a as second parent",
    ]);
    git(&["update-ref", "refs/heads/main", &m1]);

    // Unrelated root history, and a candidate that merges main only as a second parent.
    let orphan_base = git(&["commit-tree", &tree, "-m", "orphan base"]);
    let orphan_head = git(&[
        "commit-tree",
        &tree,
        "-p",
        &orphan_base,
        "-m",
        "orphan head",
    ]);
    let trick_merge = git(&[
        "commit-tree",
        &tree,
        "-p",
        &orphan_base,
        "-p",
        &m1,
        "-m",
        "orphan first parent with main second parent",
    ]);
    let trick_head = git(&["commit-tree", &tree, "-p", &trick_merge, "-m", "trick head"]);

    // Positive controls descending along first-parent from m1 on main.
    let valid_g1 = git(&["commit-tree", &tree, "-p", &m1, "-m", "valid group 1"]);
    let valid_g2 = git(&["commit-tree", &tree, "-p", &valid_g1, "-m", "valid group 2"]);
    git(&[
        "update-ref",
        "refs/heads/gh-readonly-queue/main/pr-901-m1",
        &valid_g1,
    ]);
    git(&[
        "update-ref",
        "refs/heads/gh-readonly-queue/main/pr-902-g1",
        &valid_g2,
    ]);

    let real_git = String::from_utf8(Command::new("which").arg("git").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let git_shim = bin.join("git");
    carrick_test_support::executable::write_executable(
        &git_shim,
        format!(
            "#!/usr/bin/env python3\nimport os, sys\nargs = [os.environ['TEST_GRAPH'] if a == 'https://github.com/carrick-sh/carrick.git' else a for a in sys.argv[1:]]\nos.execv({real_git:?}, ['git'] + args)\n"
        ),
    );

    let baselines = dir.path().join("baselines");
    std::fs::create_dir(&baselines).unwrap();
    for sha in [&m0, &m1, &side_a] {
        std::fs::write(
            baselines.join(format!("{sha}.json")),
            serde_json::to_vec(&admitted(sha)).unwrap(),
        )
        .unwrap();
    }

    let gh = bin.join("gh");
    carrick_test_support::executable::write_executable(
        &gh,
        format!(
            r#"#!/usr/bin/env python3
import json, os, pathlib, shutil, subprocess, sys
args = sys.argv[1:]
graph = os.environ['TEST_GRAPH']
baselines = pathlib.Path(os.environ['TEST_BASELINES'])
git_bin = {real_git:?}
if args[:2] == ['run', 'download']:
    name = args[args.index('--name') + 1]
    sha = name.removeprefix('signed-baseline-').rsplit('-', 1)[0]
    shutil.copyfile(baselines / (sha + '.json'), pathlib.Path(args[args.index('--dir') + 1]) / 'candidate.json')
elif args[:2] == ['api', 'graphql']:
    nodes = json.loads(os.environ['TEST_QUEUE_ENTRIES'])
    print(json.dumps({{'data': {{'repository': {{'mergeQueue': {{'entries': {{'nodes': nodes, 'pageInfo': {{'hasNextPage': False}}}}}}}}}}}}))
elif args[0] == 'api':
    endpoint = args[-1]
    if '/compare/' in endpoint and '?per_page=' not in endpoint:
        spec = endpoint.split('/compare/')[1]
        left, right = spec.split('...', 1)
        left_ref = 'refs/heads/main' if left == 'main' else left
        proc = subprocess.run([git_bin, '-C', graph, 'merge-base', left_ref, right], text=True, capture_output=True)
        if proc.returncode != 0:
            sys.stderr.write('gh: No common ancestor\n')
            raise SystemExit(1)
        print(json.dumps({{'merge_base_commit': {{'sha': proc.stdout.strip()}}}}))
    elif '/compare/' in endpoint and '?per_page=' in endpoint:
        spec = endpoint.split('/compare/')[1].split('?', 1)[0]
        left, right = spec.split('...', 1)
        proc = subprocess.run([git_bin, '-C', graph, 'rev-list', '--reverse', f'{{left}}..{{right}}'], text=True, capture_output=True, check=True)
        commits = [{{'sha': line}} for line in proc.stdout.splitlines() if line]
        print(json.dumps([{{'commits': commits}}]))
    elif '/commits/' in endpoint and '/pulls?' in endpoint:
        print(json.dumps([[{{'number': 901, 'merged_at': '2026-01-01T00:00:00Z', 'base': {{'ref': 'main', 'repo': {{'full_name': 'carrick-sh/carrick'}}}}}}]]))
    elif '/workflows/signed-gate.yml/runs' in endpoint:
        run = {{'id': 100, 'path': '.github/workflows/signed-gate.yml', 'head_branch': 'main', 'event': 'workflow_dispatch', 'status': 'completed', 'repository': {{'full_name': 'carrick-sh/carrick'}}, 'head_repository': {{'full_name': 'carrick-sh/carrick'}}, 'actor': {{'login': 'tjfontaine'}}, 'triggering_actor': {{'login': 'tjfontaine'}}}}
        print(json.dumps([{{'workflow_runs': [run]}}]))
    elif '/artifacts?' in endpoint:
        rows = [{{'name': f'signed-baseline-{{p.stem}}-1', 'expired': False}} for p in baselines.glob('*.json')]
        print(json.dumps([{{'artifacts': rows}}]))
    else:
        raise SystemExit('unexpected API endpoint: ' + endpoint)
else:
    raise SystemExit('unexpected gh invocation: ' + repr(args))
"#
        ),
    );

    let run_prepare = |label: &str, base_sha: &str, head_sha: &str, pr_num: u64| {
        let head_ref = format!("refs/heads/gh-readonly-queue/main/pr-{pr_num}-{label}");
        let event_path = dir.path().join(format!("event-{label}.json"));
        let out_dir = dir.path().join(format!("out-{label}"));
        std::fs::write(
            &event_path,
            json!({
                "repository": { "full_name": "carrick-sh/carrick" },
                "action": "checks_requested",
                "merge_group": {
                    "base_ref": "refs/heads/main",
                    "head_ref": head_ref,
                    "head_sha": head_sha,
                    "base_sha": base_sha,
                }
            })
            .to_string(),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("GITHUB_ACTOR", "github-merge-queue[bot]")
            .env("GITHUB_TRIGGERING_ACTOR", "github-merge-queue[bot]")
            .env("GITHUB_EVENT_NAME", "merge_group")
            .env("GITHUB_REF", &head_ref)
            .env("GITHUB_SHA", head_sha)
            .env("TEST_GRAPH", &repo)
            .env("TEST_BASELINES", &baselines)
            .env(
                "TEST_QUEUE_ENTRIES",
                serde_json::json!([
                    {
                        "baseCommit": {"oid": m1},
                        "headCommit": {"oid": valid_g1},
                        "pullRequest": {"number": 901, "baseRefName": "main", "baseRepository": {"nameWithOwner": "carrick-sh/carrick"}}
                    },
                    {
                        "baseCommit": {"oid": valid_g1},
                        "headCommit": {"oid": valid_g2},
                        "pullRequest": {"number": 902, "baseRefName": "main", "baseRepository": {"nameWithOwner": "carrick-sh/carrick"}}
                    }
                ])
                .to_string(),
            )
            .env_remove("GITHUB_OUTPUT")
            .args(["signed-gate", "prepare", "--event"])
            .arg(&event_path)
            .arg("--output")
            .arg(&out_dir)
            .output()
            .unwrap();
        (output, out_dir)
    };

    // Positive controls: first-in-line and second-in-line on m1 both resolve to m1.
    let (ok1, out1) = run_prepare("valid-1", &m1, &valid_g1, 901);
    assert!(
        ok1.status.success(),
        "{}",
        String::from_utf8_lossy(&ok1.stderr)
    );
    let req1: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out1.join("request.json")).unwrap()).unwrap();
    assert_eq!(req1["base"], m1);

    let (ok2, out2) = run_prepare("valid-2", &valid_g1, &valid_g2, 902);
    assert!(
        ok2.status.success(),
        "{}",
        String::from_utf8_lossy(&ok2.stderr)
    );
    let req2: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out2.join("request.json")).unwrap()).unwrap();
    assert_eq!(req2["base"], m1);

    // Negative controls: none of these bases is on main's first-parent chain or
    // between the candidate's first-parent main ancestor and the candidate.
    for (label, bad_base, bad_head) in [
        ("orphan", orphan_base.as_str(), orphan_head.as_str()),
        ("second-parent-direct", side_a.as_str(), side_b.as_str()),
        ("second-parent-queued", side_b.as_str(), side_c.as_str()),
        (
            "candidate-second-parent-main",
            trick_merge.as_str(),
            trick_head.as_str(),
        ),
        ("stale-main-behind-ancestor", m0.as_str(), valid_g2.as_str()),
        ("self-base", valid_g2.as_str(), valid_g2.as_str()),
    ] {
        let (refused, _) = run_prepare(label, bad_base, bad_head, 999);
        assert!(
            !refused.status.success(),
            "accepted non-first-parent or invalid base case '{label}'"
        );
    }
}

#[cfg(unix)]
#[test]
fn queued_merge_group_resolves_rebased_prs_and_names_them_in_published_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let repo = dir.path().join("graph");
    std::fs::create_dir(&repo).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .current_dir(&repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "-b", "main"]);
    git(&["config", "user.name", "Replay"]);
    git(&["config", "user.email", "replay@example.invalid"]);
    git(&["config", "uploadpack.allowAnySHA1InWant", "true"]);
    git(&["commit", "--allow-empty", "-m", "main baseline A"]);
    let a = git(&["rev-parse", "HEAD"]);
    let tree = git(&["rev-parse", "HEAD^{tree}"]);

    // Rebased queue commits: GitHub's /commits/{sha}/pulls returns [] for all of
    // these while queued because the rebase queue rewrites every PR commit SHA.
    let d_mid = git(&["commit-tree", &tree, "-p", &a, "-m", "pr 1762 part 1"]);
    let d = git(&["commit-tree", &tree, "-p", &d_mid, "-m", "pr 1762 part 2"]);
    let b = git(&["commit-tree", &tree, "-p", &d, "-m", "pr 1788"]);
    let c = git(&["commit-tree", &tree, "-p", &b, "-m", "pr 1799 later group"]);
    let stale = git(&["commit-tree", &tree, "-p", &a, "-m", "pr 1700 evicted"]);
    let batched_mid = git(&["commit-tree", &tree, "-p", &a, "-m", "pr 1801 batched"]);
    let batched = git(&[
        "commit-tree",
        &tree,
        "-p",
        &batched_mid,
        "-m",
        "pr 1802 batched",
    ]);

    let ref_1762 = format!("refs/heads/gh-readonly-queue/main/pr-1762-{a}");
    let ref_1788 = format!("refs/heads/gh-readonly-queue/main/pr-1788-{d}");
    let ref_1799 = format!("refs/heads/gh-readonly-queue/main/pr-1799-{b}");
    let ref_gap_head = format!("refs/heads/gh-readonly-queue/main/pr-125-{c}");
    let ref_1700 = format!("refs/heads/gh-readonly-queue/main/pr-1700-{a}");
    let ref_1801 = format!("refs/heads/gh-readonly-queue/main/pr-1801-{a}");
    let ref_1802 = format!("refs/heads/gh-readonly-queue/main/pr-1802-{a}");
    git(&["update-ref", &ref_1762, &d]);
    git(&["update-ref", &ref_1788, &b]);
    git(&["update-ref", &ref_1799, &c]);
    git(&["update-ref", &ref_1700, &stale]);
    git(&["update-ref", &ref_1801, &batched]);
    git(&["update-ref", &ref_1802, &batched]);

    let real_git = String::from_utf8(Command::new("which").arg("git").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let git_shim = bin.join("git");
    carrick_test_support::executable::write_executable(
        &git_shim,
        format!(
            "#!/usr/bin/env python3\nimport os, sys\nargs = [os.environ['TEST_GRAPH'] if a == 'https://github.com/carrick-sh/carrick.git' else a for a in sys.argv[1:]]\nif args[:2] == ['ls-remote', '--refs'] and os.environ.get('TEST_HIDE_QUEUE_REFS') == '1': raise SystemExit(0)\nos.execv({real_git:?}, ['git'] + args)\n"
        ),
    );

    let base_receipt = admitted(&a);
    let baseline_path = dir.path().join("base-a.json");
    std::fs::write(&baseline_path, serde_json::to_vec(&base_receipt).unwrap()).unwrap();
    let entries_path = dir.path().join("merge-queue-entries.json");
    let merged_pulls_path = dir.path().join("merged-commit-pulls.json");
    let posts_path = dir.path().join("posts.jsonl");
    std::fs::write(&merged_pulls_path, "{}").unwrap();
    std::fs::write(
        &entries_path,
        json!([
            {
                "baseCommit": { "oid": a },
                "headCommit": { "oid": d },
                "pullRequest": {
                    "number": 1762,
                    "baseRefName": "main",
                    "baseRepository": { "nameWithOwner": "carrick-sh/carrick" }
                }
            },
            {
                "baseCommit": { "oid": d },
                "headCommit": { "oid": b },
                "pullRequest": {
                    "number": 1788,
                    "baseRefName": "main",
                    "baseRepository": { "nameWithOwner": "carrick-sh/carrick" }
                }
            },
            {
                "baseCommit": { "oid": b },
                "headCommit": { "oid": c },
                "pullRequest": {
                    "number": 1799,
                    "baseRefName": "main",
                    "baseRepository": { "nameWithOwner": "carrick-sh/carrick" }
                }
            },
            {
                "baseCommit": { "oid": a },
                "headCommit": { "oid": batched_mid },
                "pullRequest": {
                    "number": 1801,
                    "baseRefName": "main",
                    "baseRepository": { "nameWithOwner": "carrick-sh/carrick" }
                }
            },
            {
                "baseCommit": { "oid": batched_mid },
                "headCommit": { "oid": batched },
                "pullRequest": {
                    "number": 1802,
                    "baseRefName": "main",
                    "baseRepository": { "nameWithOwner": "carrick-sh/carrick" }
                }
            },
            {
                "baseCommit": { "oid": batched_mid },
                "headCommit": { "oid": batched },
                "pullRequest": {
                    "number": 9999,
                    "baseRefName": "release",
                    "baseRepository": { "nameWithOwner": "carrick-sh/carrick" }
                }
            }
        ])
        .to_string(),
    )
    .unwrap();

    let gh = bin.join("gh");
    carrick_test_support::executable::write_executable(
        &gh,
        r#"#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
if args[:2] == ['run', 'download']:
    shutil.copyfile(os.environ['TEST_BASE'], pathlib.Path(args[args.index('--dir') + 1]) / 'candidate.json')
elif '--method' in args and args[args.index('--method') + 1] == 'POST':
    endpoint = args[args.index('POST') + 1]
    with open(os.environ['TEST_POSTS'], 'a') as out:
        out.write(json.dumps({'endpoint': endpoint, 'body': json.load(sys.stdin)}) + '\n')
elif args[:2] == ['api', 'graphql']:
    nodes = json.loads(pathlib.Path(os.environ['TEST_ENTRIES']).read_text())
    print(json.dumps({'data': {'repository': {'mergeQueue': {'entries': {'nodes': nodes, 'pageInfo': {'hasNextPage': False}}}}}}))
elif args[0] == 'api':
    endpoint = args[-1]
    if '/commits/' in endpoint and '/pulls?' in endpoint:
        sha = endpoint.split('/commits/')[1].split('/pulls', 1)[0]
        merged = json.loads(pathlib.Path(os.environ['TEST_MERGED_PULLS']).read_text())
        rows = [
            {'number': n, 'merged_at': '2026-01-01T00:00:00Z', 'base': {'ref': 'main', 'repo': {'full_name': 'carrick-sh/carrick'}}}
            for n in merged.get(sha, [])
        ]
        print(json.dumps([rows]))
    elif '/workflows/signed-gate.yml/runs' in endpoint:
        run = {'id': 100, 'path': '.github/workflows/signed-gate.yml', 'head_branch': 'main', 'event': 'workflow_dispatch', 'status': 'completed', 'repository': {'full_name': 'carrick-sh/carrick'}, 'head_repository': {'full_name': 'carrick-sh/carrick'}, 'actor': {'login': 'tjfontaine'}, 'triggering_actor': {'login': 'tjfontaine'}}
        print(json.dumps([{'workflow_runs': [run]}]))
    elif '/artifacts?' in endpoint:
        base_sha = os.environ['TEST_BASE_SHA']
        print(json.dumps([{'artifacts': [{'name': f'signed-baseline-{base_sha}-1', 'expired': False}]}]))
    else:
        raise SystemExit('unexpected API endpoint: ' + endpoint)
else:
    raise SystemExit('unexpected gh invocation: ' + repr(args))
"#,
    );

    let run_prepare_output = |label: &str, head_ref: &str, base_sha: &str, head_sha: &str| {
        let event_path = dir.path().join(format!("event-{label}.json"));
        let out_dir = dir.path().join(format!("out-{label}"));
        std::fs::write(
            &event_path,
            json!({
                "repository": { "full_name": "carrick-sh/carrick" },
                "action": "checks_requested",
                "merge_group": {
                    "base_ref": "refs/heads/main",
                    "head_ref": head_ref,
                    "head_sha": head_sha,
                    "base_sha": base_sha,
                }
            })
            .to_string(),
        )
        .unwrap();
        Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("GITHUB_ACTOR", "github-merge-queue[bot]")
            .env("GITHUB_TRIGGERING_ACTOR", "github-merge-queue[bot]")
            .env("GITHUB_EVENT_NAME", "merge_group")
            .env("GITHUB_REF", head_ref)
            .env("GITHUB_SHA", head_sha)
            .env("TEST_GRAPH", &repo)
            .env("TEST_BASE", &baseline_path)
            .env("TEST_BASE_SHA", &a)
            .env("TEST_ENTRIES", &entries_path)
            .env("TEST_MERGED_PULLS", &merged_pulls_path)
            .env("TEST_POSTS", &posts_path)
            .env(
                "TEST_HIDE_QUEUE_REFS",
                if label.starts_with("gap-") || label == "null-node" {
                    "1"
                } else {
                    "0"
                },
            )
            .env_remove("GITHUB_OUTPUT")
            .args(["signed-gate", "prepare", "--event"])
            .arg(&event_path)
            .arg("--output")
            .arg(&out_dir)
            .output()
            .unwrap()
    };
    let run_prepare = |label: &str, head_ref: &str, base_sha: &str, head_sha: &str| {
        let output = run_prepare_output(label, head_ref, base_sha, head_sha);
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let out_dir = dir.path().join(format!("out-{label}"));
        let req: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out_dir.join("request.json")).unwrap()).unwrap();
        (req, out_dir)
    };

    // (1) First-in-line group resolves its rebased PR against main A.
    let (first_req, _) = run_prepare("first", &ref_1762, &a, &d);
    assert_eq!(first_req["base"], a);
    assert_eq!(first_req["prs"], json!([1762]));

    // (2) Second-in-line group resolves main A and BOTH queued PRs (#1762, #1788),
    // excluding later (#1799) and evicted (#1700) queue refs.
    let (second_req, second_dir) = run_prepare("second", &ref_1788, &d, &b);
    assert_eq!(second_req["base"], a);
    assert_eq!(second_req["prs"], json!([1762, 1788]));

    // (3) Batched multi-PR group resolves every queued entry in the range.
    let (batched_req, _) = run_prepare("batched", &ref_1802, &a, &batched);
    assert_eq!(batched_req["base"], a);
    assert_eq!(batched_req["prs"], json!([1801, 1802]));

    // A missing live queue entry in the middle of the candidate range must be
    // attributed to a merged main PR, just like a missing prefix entry.
    let gap_entries = json!([
        {"baseCommit":{"oid":a},"headCommit":{"oid":d},"pullRequest":{"number":123,"baseRefName":"main","baseRepository":{"nameWithOwner":"carrick-sh/carrick"}}},
        {"baseCommit":{"oid":b},"headCommit":{"oid":c},"pullRequest":{"number":125,"baseRefName":"main","baseRepository":{"nameWithOwner":"carrick-sh/carrick"}}}
    ]);
    std::fs::write(&entries_path, gap_entries.to_string()).unwrap();
    let gap_unresolved = run_prepare_output("gap-unresolved", &ref_gap_head, &a, &c);
    let gap_refused_with_commit = !gap_unresolved.status.success()
        && String::from_utf8_lossy(&gap_unresolved.stderr).contains(&b);
    std::fs::write(&merged_pulls_path, json!({b.clone():[124]}).to_string()).unwrap();
    let gap_resolved = run_prepare_output("gap-resolved", &ref_gap_head, &a, &c);
    let gap_receipt_names_all_prs = gap_resolved.status.success()
        && serde_json::from_slice::<serde_json::Value>(
            &std::fs::read(dir.path().join("out-gap-resolved/request.json")).unwrap(),
        )
        .is_ok_and(|request| request["prs"] == json!([123, 124, 125]));
    std::fs::write(&merged_pulls_path, "{}").unwrap();
    std::fs::write(&entries_path, json!([
        {"baseCommit":{"oid":a},"headCommit":{"oid":d},"pullRequest":{"number":123,"baseRefName":"main","baseRepository":{"nameWithOwner":"carrick-sh/carrick"}}},
        null,
        {"baseCommit":{"oid":b},"headCommit":{"oid":c},"pullRequest":{"number":125,"baseRefName":"main","baseRepository":{"nameWithOwner":"carrick-sh/carrick"}}}
    ]).to_string()).unwrap();
    let null_node = run_prepare_output("null-node", &ref_gap_head, &a, &c);
    let null_node_refused = !null_node.status.success();
    assert!(
        gap_refused_with_commit && gap_receipt_names_all_prs && null_node_refused,
        "unattributed_gap_refused_with_commit={gap_refused_with_commit}; resolved_gap_names_all_prs={gap_receipt_names_all_prs}; null_node_refused={null_node_refused}; unresolved stderr={}; resolved stderr={}; null stderr={}",
        String::from_utf8_lossy(&gap_unresolved.stderr),
        String::from_utf8_lossy(&gap_resolved.stderr),
        String::from_utf8_lossy(&null_node.stderr),
    );

    // (4) Publish names both PRs in comment.md, GITHUB_STEP_SUMMARY, and PR comments
    // on both PASS and FAIL paths.
    let results = dir.path().join("results");
    std::fs::create_dir(&results).unwrap();
    write_paired_base(&results, &base_receipt);
    let cand = admitted(&b);
    std::fs::write(
        results.join("candidate.json"),
        serde_json::to_vec(&cand).unwrap(),
    )
    .unwrap();
    std::fs::write(
        results.join("identity.json"),
        serde_json::to_vec(&cand.artifact).unwrap(),
    )
    .unwrap();
    std::fs::write(
        results.join("cleanup.json"),
        serde_json::to_vec(&cand.cleanup_counts).unwrap(),
    )
    .unwrap();
    let summary_path = dir.path().join("step-summary.md");
    let run_publish = |exec_result: &str| {
        let _ = std::fs::remove_file(&summary_path);
        Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("GITHUB_STEP_SUMMARY", &summary_path)
            .env("TEST_POSTS", &posts_path)
            .args(["signed-gate", "publish", "--request"])
            .arg(second_dir.join("request.json"))
            .arg("--results")
            .arg(&results)
            .args([
                "--run-url",
                "https://github.com/carrick-sh/carrick/actions/runs/300",
                "--execution-result",
                exec_result,
            ])
            .output()
            .unwrap()
    };
    let pub_ok = run_publish("success");
    assert!(
        pub_ok.status.success(),
        "{}",
        String::from_utf8_lossy(&pub_ok.stderr)
    );
    let comment_md = std::fs::read_to_string(results.join("comment.md")).unwrap();
    let summary_md = std::fs::read_to_string(&summary_path).unwrap();
    assert!(
        comment_md.contains("Pull requests: #1762, #1788"),
        "{comment_md}"
    );
    assert!(
        summary_md.contains("Pull requests: #1762, #1788"),
        "{summary_md}"
    );

    std::fs::remove_file(results.join("candidate.json")).unwrap();
    let pub_err = run_publish("failure");
    assert!(!pub_err.status.success());
    let fail_comment_md = std::fs::read_to_string(results.join("comment.md")).unwrap();
    assert!(
        fail_comment_md.contains("Pull requests: #1762, #1788"),
        "{fail_comment_md}"
    );
    let post_rows: Vec<serde_json::Value> = std::fs::read_to_string(&posts_path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(post_rows.len(), 6);
    for idx in [1, 2, 4, 5] {
        assert!(
            post_rows[idx]["body"]["body"]
                .as_str()
                .unwrap()
                .contains("Pull requests: #1762, #1788")
        );
    }
}

#[test]
fn different_hosts_refuse_false_new_at_production_comparison() {
    let mut a = serde_json::to_value(base()).unwrap();
    a["host_identity"] =
        json!({"runner_name":"host-a","hardware_model":"Mac14,2","product_build":"25A1"});
    let mut b = a.clone();
    b["host_identity"]["runner_name"] = json!("host-b");
    b["steps"][0]["failed_tests"] = json!(["el1_sched::el1_tlb_first_missed_ack_is_terminal"]);
    let result = compare(
        &serde_json::from_value(a).unwrap(),
        &serde_json::from_value(b).unwrap(),
    );
    assert!(
        result.is_err(),
        "different hosts must not produce NEW: {result:?}"
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("incomparable base")
    );
}

#[test]
fn legacy_or_incomplete_identity_and_different_bundles_are_incomparable() {
    use carrick_xtask::ci_receipt::ReceiptError;
    let candidate = base();
    let mut legacy = serde_json::to_value(&candidate).unwrap();
    legacy.as_object_mut().unwrap().remove("host_identity");
    let legacy = serde_json::from_value(legacy).unwrap();
    let err = compare(&legacy, &candidate).unwrap_err();
    assert!(matches!(err, ReceiptError::IncomparableBase(_)));
    assert!(
        err.to_string()
            .contains("base receipt missing complete host identity")
    );
    for field in ["runner_name", "hardware_model", "product_build"] {
        let mut old = serde_json::to_value(&candidate).unwrap();
        old["host_identity"][field] = json!("different");
        assert!(matches!(
            compare(&serde_json::from_value(old).unwrap(), &candidate),
            Err(ReceiptError::IncomparableBase(_))
        ));
    }
    let mut old = candidate.clone();
    old.host_identity.as_mut().unwrap().runner_name.clear();
    assert!(
        compare(&old, &candidate)
            .unwrap_err()
            .to_string()
            .contains("missing complete host identity")
    );
    old = candidate.clone();
    old.fixture_validation = None;
    assert!(
        compare(&old, &candidate)
            .unwrap_err()
            .to_string()
            .contains("missing fixture bundle identity")
    );
    let mut old = serde_json::to_value(&candidate).unwrap();
    old["fixture_validation"]["content_sha256"] = json!("9".repeat(64));
    assert!(
        compare(&serde_json::from_value(old).unwrap(), &candidate)
            .unwrap_err()
            .to_string()
            .contains("fixture bundle identity differs")
    );
}

#[test]
fn identical_fixture_content_from_different_commits_is_comparable() {
    use carrick_xtask::fixtures::{BuildPolicy, Manifest};
    use sha2::{Digest, Sha256};
    let manifest = Manifest {
        schema: "test".into(),
        source_head: "a".repeat(40).try_into().unwrap(),
        compiler_inputs: vec!["fixture.rs".into()],
        sources: [("fixture.rs".into(), "1".repeat(64).try_into().unwrap())].into(),
        build_policy: BuildPolicy::default(),
        toolchain: carrick_xtask::fixtures::Toolchain {
            rustc: "rustc pinned".into(),
            cargo: "cargo pinned".into(),
            gnu_linker: "ld pinned".into(),
        },
        executables: vec![carrick_xtask::fixtures::Executable {
            path: "fixture".into(),
            target: carrick_xtask::fixtures::GuestTarget::Musl,
            sha256: "2".repeat(64).try_into().unwrap(),
        }],
    };
    let receipt = |manifest: &Manifest| {
        let mut receipt = base();
        let validation = receipt.fixture_validation.as_mut().unwrap();
        validation.bundle_source_head = manifest.source_head.clone();
        validation.inputs_sha256 = manifest.input_identity().unwrap();
        validation.content_sha256 = Some(manifest.content_identity().unwrap());
        validation.manifest_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(manifest).unwrap())
        )
        .try_into()
        .unwrap();
        receipt
    };
    let old = receipt(&manifest);
    let mut republished = manifest.clone();
    republished.source_head = "b".repeat(40).try_into().unwrap();
    assert_eq!(
        manifest.input_identity().unwrap(),
        republished.input_identity().unwrap()
    );
    assert!(compare(&old, &receipt(&republished)).unwrap().passed);
    for field in ["executable", "input", "toolchain"] {
        let mut changed = republished.clone();
        match field {
            "executable" => changed.executables[0].sha256 = "9".repeat(64).try_into().unwrap(),
            "input" => {
                changed
                    .sources
                    .insert("fixture.rs".into(), "9".repeat(64).try_into().unwrap());
            }
            _ => changed.toolchain.rustc = "other compiler".into(),
        }
        assert!(matches!(
            compare(&old, &receipt(&changed)),
            Err(carrick_xtask::ci_receipt::ReceiptError::IncomparableBase(_))
        ));
    }
    let mut legacy = old.clone();
    legacy.fixture_validation.as_mut().unwrap().content_sha256 = None;
    assert!(compare(&legacy, &legacy).is_err());
    assert!(compare(&legacy, &old).is_err());
    assert!(compare(&old, &legacy).is_err());
}

#[test]
fn cli_refusal_removes_previous_passing_json() {
    let dir = tempfile::tempdir().unwrap();
    let base_path = dir.path().join("base.json");
    let candidate_path = dir.path().join("candidate.json");
    let diff_path = dir.path().join("diff.json");
    let receipt = base();
    std::fs::write(&base_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    std::fs::write(&candidate_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["ci-receipt", "signed-diff", "--base"])
            .arg(&base_path)
            .arg("--candidate")
            .arg(&candidate_path)
            .arg("--json")
            .arg(&diff_path)
            .output()
            .unwrap()
    };
    assert!(run().status.success());
    let passed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&diff_path).unwrap()).unwrap();
    assert_eq!(passed["passed"], true);
    let mut refused = receipt;
    refused.host_identity.as_mut().unwrap().runner_name = "different-runner".into();
    std::fs::write(&candidate_path, serde_json::to_vec(&refused).unwrap()).unwrap();
    assert!(!run().status.success());
    assert!(!diff_path.exists(), "refusal left stale passing diff.json");
}

/// A paired PR request and its gate evidence, published through the real
/// `signed-gate publish` command with a `gh` stub that records POSTs.
#[cfg(unix)]
struct PublishBench {
    dir: tempfile::TempDir,
    base: String,
    head: String,
}

#[cfg(unix)]
impl PublishBench {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        carrick_test_support::executable::write_executable(
            bin.join("gh"),
            r#"#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if '--method' in args and args[args.index('--method')+1] == 'POST':
    with open(os.environ['TEST_POSTS'], 'a') as out:
        out.write(json.dumps({'endpoint': args[args.index('POST')+1], 'body': json.load(sys.stdin)})+'\n')
else:
    raise SystemExit('unexpected gh invocation: '+repr(args))
"#,
        );
        let bench = Self {
            dir,
            base: "a".repeat(40),
            head: "b".repeat(40),
        };
        std::fs::create_dir(bench.results()).unwrap();
        std::fs::write(
            bench.dir.path().join("request.json"),
            json!({"kind":"PullRequest","prs":[123],"sha":bench.head,"base":bench.base})
                .to_string(),
        )
        .unwrap();
        bench
    }

    fn results(&self) -> std::path::PathBuf {
        self.dir.path().join("results")
    }

    /// Evidence `execute` leaves for one side: receipt, identity, cleanup and
    /// the recorded acceptance exit status.
    fn write_side(&self, dir: &std::path::Path, name: &str, receipt: &AcceptReceipt, ok: bool) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), serde_json::to_vec(receipt).unwrap()).unwrap();
        std::fs::write(
            dir.join("identity.json"),
            serde_json::to_vec(&receipt.artifact).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("cleanup.json"),
            serde_json::to_vec(&receipt.cleanup_counts).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("accept-exit.json"),
            json!({ "success": ok }).to_string(),
        )
        .unwrap();
    }

    /// Base evidence plus the executor's seal over it.
    fn write_base(&self, receipt: &AcceptReceipt, accepted: bool) {
        self.write_base_unsealed(receipt, accepted);
        seal_paired_base(&self.results(), &self.base);
    }

    /// Rewrite base evidence after the seal, as candidate code could.
    fn write_base_unsealed(&self, receipt: &AcceptReceipt, accepted: bool) {
        self.write_side(&self.results().join("base"), "base.json", receipt, accepted);
    }

    fn write_candidate(&self, receipt: &AcceptReceipt, accepted: bool) {
        self.write_side(&self.results(), "candidate.json", receipt, accepted);
    }

    /// Description of the last `signed-gate` status the stub recorded.
    fn status_description(&self) -> String {
        let posts = std::fs::read_to_string(self.dir.path().join("posts.jsonl")).unwrap();
        let last = posts
            .lines()
            .rev()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .find(|post| post["endpoint"].as_str().unwrap().contains("/statuses/"))
            .unwrap();
        last["body"]["description"].as_str().unwrap().to_string()
    }

    fn publish(&self) -> (bool, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.dir.path().join("bin").display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .env("TEST_POSTS", self.dir.path().join("posts.jsonl"))
            .env_remove("GITHUB_STEP_SUMMARY")
            .args(["signed-gate", "publish", "--request"])
            .arg(self.dir.path().join("request.json"))
            .arg("--results")
            .arg(self.results())
            .args([
                "--run-url",
                "https://github.com/carrick-sh/carrick/actions/runs/300",
                "--execution-result",
                "success",
            ])
            .output()
            .unwrap();
        let body = std::fs::read_to_string(self.results().join("comment.md")).unwrap_or_default();
        (output.status.success(), body)
    }
}

/// #2045: an incomplete paired base is advisory when the candidate completed
/// (owner, 2026-11-10, #231). Completed known failures stay comparable.
#[cfg(unix)]
#[test]
fn incomplete_paired_base_is_advisory_but_known_failures_compare() {
    let bench = PublishBench::new();
    let candidate = admitted(&bench.head);
    bench.write_candidate(&candidate, false);

    // (d) Completed base with the same itemized failures: differential PASS.
    let complete = admitted(&bench.base);
    bench.write_base(&complete, false);
    let (passed, body) = bench.publish();
    assert!(
        passed,
        "completed known failures must stay comparable: {body}"
    );
    assert!(!body.contains("paired base is incomplete"), "{body}");
    assert!(
        bench
            .status_description()
            .starts_with("No introduced failures"),
        "{}",
        bench.status_description()
    );

    // An unfinished base binary, complete candidate: PASS with a warning.
    let mut unfinished = complete.clone();
    unfinished.steps[2].unfinished_binaries.push("embed".into());
    bench.write_base(&unfinished, false);
    let (passed, body) = bench.publish();
    assert!(passed, "unfinished base binary blocked: {body}");
    assert!(body.contains("paired base is incomplete"), "{body}");
    assert!(body.contains("step el1-embed did not run"), "{body}");

    // A base that never reported a step (NotRun).
    let mut not_run = complete.clone();
    not_run.steps[3].passed = false;
    not_run.steps[3].exit_code = None;
    not_run.steps[3].failed_tests.clear();
    bench.write_base(&not_run, false);
    let (passed, body) = bench.publish();
    assert!(passed, "NotRun base step blocked: {body}");
    assert!(body.contains("paired base is incomplete"), "{body}");

    // A failing acceptance exit with nothing completed to explain it.
    let mut clean = complete.clone();
    for step in &mut clean.steps {
        step.passed = true;
        step.exit_code = Some(0);
        step.failed_tests.clear();
    }
    clean.el1.as_mut().unwrap().failed_tests.clear();
    clean.el1.as_mut().unwrap().unexpected_failures.clear();
    bench.write_base(&clean, false);
    let (passed, body) = bench.publish();
    assert!(
        passed,
        "unexplained base acceptance failure blocked: {body}"
    );
    assert!(body.contains("infrastructure failure"), "{body}");

    // Missing exit evidence is not success: still a refusal.
    std::fs::remove_file(bench.results().join("base/accept-exit.json")).unwrap();
    let (passed, body) = bench.publish();
    assert!(!passed, "missing base exit status published PASS: {body}");
}

/// (a) A base interrupted mid-EL1 with a clean candidate passes, and both the
/// comment and the status description name the gap.
#[cfg(unix)]
#[test]
fn base_interrupted_mid_el1_is_advisory_with_a_named_gap() {
    let bench = PublishBench::new();
    bench.write_candidate(&admitted(&bench.head), false);
    let mut base = admitted(&bench.base);
    base.steps[2].not_run_tests = (0..7).map(|i| format!("el1::unrun_{i}")).collect();
    bench.write_base(&base, false);
    let (passed, body) = bench.publish();
    assert!(passed, "{body}");
    assert!(
        body.contains("step el1-embed interrupted before 7 test(s) ran"),
        "{body}"
    );
    let description = bench.status_description();
    assert!(description.len() <= 140, "{description}");
    assert!(
        description.contains("step el1-embed interrupted before 7 test(s) ran"),
        "{description}"
    );
}

/// #2049: the base-gap advisory may claim candidate completion only when the
/// candidate has no gap of its own. A mixed case names both and still blocks.
#[cfg(unix)]
#[test]
fn base_gap_with_candidate_gap_does_not_claim_candidate_completed() {
    let bench = PublishBench::new();
    let mut candidate = admitted(&bench.head);
    candidate.steps[2].not_run_tests = vec!["el1::cut_short".into()];
    bench.write_candidate(&candidate, false);
    let mut base = admitted(&bench.base);
    base.steps[2].not_run_tests = (0..7).map(|i| format!("el1::unrun_{i}")).collect();
    bench.write_base(&base, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "{body}");
    assert!(
        body.contains("Advisory: the paired base is incomplete"),
        "{body}"
    );
    assert!(!body.contains("the candidate completed"), "{body}");
    assert!(body.contains("Candidate is incomplete — BLOCKED"), "{body}");
}

/// #2049: a base gap with a complete candidate keeps the completed wording.
#[cfg(unix)]
#[test]
fn base_gap_alone_still_says_the_candidate_completed() {
    let bench = PublishBench::new();
    bench.write_candidate(&admitted(&bench.head), false);
    let mut base = admitted(&bench.base);
    base.steps[2].not_run_tests = (0..7).map(|i| format!("el1::unrun_{i}")).collect();
    bench.write_base(&base, false);
    let (passed, body) = bench.publish();
    assert!(passed, "{body}");
    assert!(body.contains("the candidate completed"), "{body}");
    assert!(!body.contains("Candidate is incomplete"), "{body}");
}

/// (b) The same base gap plus a failure the candidate introduced still blocks.
#[cfg(unix)]
#[test]
fn base_gap_does_not_excuse_an_introduced_candidate_failure() {
    let bench = PublishBench::new();
    let mut candidate = admitted(&bench.head);
    candidate.steps[2]
        .failed_tests
        .push("introduced_regression".into());
    bench.write_candidate(&candidate, false);
    let mut base = admitted(&bench.base);
    base.steps[2].not_run_tests = (0..7).map(|i| format!("el1::unrun_{i}")).collect();
    bench.write_base(&base, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "{body}");
    assert!(body.contains("introduced_regression"), "{body}");
}

/// (c) A candidate interrupted mid-EL1 blocks even though the base is
/// incomplete too, and even when the base is complete.
#[cfg(unix)]
#[test]
fn candidate_interrupted_mid_el1_blocks_when_the_base_has_a_gap() {
    let bench = PublishBench::new();
    let mut candidate = admitted(&bench.head);
    candidate.steps[2].not_run_tests = vec!["el1::cut_short".into()];
    bench.write_candidate(&candidate, false);
    let mut base = admitted(&bench.base);
    base.steps[2].not_run_tests = (0..7).map(|i| format!("el1::unrun_{i}")).collect();
    bench.write_base(&base, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "candidate interruption passed: {body}");
    assert!(body.contains("Candidate is incomplete"), "{body}");
    assert!(
        bench.status_description().contains("Candidate incomplete"),
        "{}",
        bench.status_description()
    );
}

/// Base step killed before it reported any population (the #1974 shape).
fn base_killed_before_reporting(commit: &str) -> AcceptReceipt {
    let mut base = admitted(commit);
    let step = &mut base.steps[2];
    step.started_tests.clear();
    step.finished_binaries.clear();
    step.failed_tests.clear();
    step.passed = false;
    step.exit_code = None;
    step.not_run_tests = (0..7).map(|i| format!("el1::unrun_{i}")).collect();
    base
}

/// Review P0 on #2047: a COMPLETE base must not hide a candidate interruption.
#[cfg(unix)]
#[test]
fn complete_base_does_not_hide_candidate_interruption() {
    let bench = PublishBench::new();
    let mut candidate = admitted(&bench.head);
    candidate.steps[2].not_run_tests = vec!["el1::cut_short".into()];
    bench.write_candidate(&candidate, false);
    bench.write_base(&admitted(&bench.base), false);
    let (passed, body) = bench.publish();
    assert!(!passed, "candidate interruption passed: {body}");
    assert!(body.contains("Candidate is incomplete"), "{body}");
    assert!(body.contains("step el1-embed interrupted"), "{body}");
}

/// Review P0 on #2047: empty base populations are advisory through `publish`.
#[cfg(unix)]
#[test]
fn review_base_missing_population_clean_candidate_must_pass() {
    let bench = PublishBench::new();
    let mut candidate = admitted(&bench.head);
    candidate.steps[2].failed_tests.clear();
    candidate.steps[2].passed = true;
    candidate.steps[2].exit_code = Some(0);
    bench.write_candidate(&candidate, false);
    bench.write_base(&base_killed_before_reporting(&bench.base), false);
    let (passed, body) = bench.publish();
    assert!(passed, "{body}");
    assert!(body.contains("paired base is incomplete"), "{body}");
    assert!(body.contains("step el1-embed"), "{body}");
    let description = bench.status_description();
    assert!(description.len() <= 140, "{description}");
    assert!(description.contains("step el1-embed"), "{description}");
}

/// Candidate failures in tests the base never started count as introduced.
#[cfg(unix)]
#[test]
fn missing_base_population_does_not_excuse_introduced_failure_or_empty_candidate() {
    let bench = PublishBench::new();
    bench.write_base(&base_killed_before_reporting(&bench.base), false);

    let mut introduced = admitted(&bench.head);
    introduced.steps[2].failed_tests = vec!["introduced_regression".into()];
    introduced.steps[2]
        .failed_tests
        .push("introduced_regression".into());
    bench.write_candidate(&introduced, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "{body}");
    assert!(body.contains("introduced_regression"), "{body}");

    let mut empty = admitted(&bench.head);
    empty.steps[2].started_tests.clear();
    empty.steps[2].finished_binaries.clear();
    bench.write_candidate(&empty, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "empty candidate population passed: {body}");
}

/// The production admission `execute_one` ends with, driven through
/// `execute_pair`: a base killed before reporting populations must not stop
/// the candidate, while the same shape on the candidate side is refused.
#[test]
fn execute_pair_admits_a_base_without_populations_and_still_runs_the_candidate() {
    use carrick_xtask::signed_gate::{Request, RequestKind, execute_pair, validate_side_receipt};
    let request = Request {
        kind: RequestKind::PullRequest,
        prs: vec![123],
        sha: "b".repeat(40),
        base: "a".repeat(40),
    };
    let dir = tempfile::tempdir().unwrap();
    let mut ran = Vec::new();
    execute_pair(&request, dir.path(), None, |run| {
        ran.push(run.receipt_name);
        let receipt = if run.receipt_name == "base.json" {
            base_killed_before_reporting(&run.commit)
        } else {
            admitted(&run.commit)
        };
        write_run_evidence(&run.output, run.receipt_name, &receipt);
        validate_side_receipt(run.side, &receipt, &run.commit)
    })
    .unwrap();
    assert_eq!(ran, ["base.json", "candidate.json"]);

    let dir = tempfile::tempdir().unwrap();
    let result = execute_pair(&request, dir.path(), None, |run| {
        let receipt = base_killed_before_reporting(&run.commit);
        write_run_evidence(&run.output, run.receipt_name, &receipt);
        validate_side_receipt(run.side, &receipt, &run.commit)
    });
    assert!(result.is_err(), "candidate without populations admitted");
}

/// An incomplete base no longer stops the pairing before the candidate runs.
#[test]
fn execute_pair_still_runs_the_candidate_when_the_base_is_incomplete() {
    use carrick_xtask::signed_gate::{Request, RequestKind, execute_pair};
    let request = Request {
        kind: RequestKind::PullRequest,
        prs: vec![123],
        sha: "b".repeat(40),
        base: "a".repeat(40),
    };
    let dir = tempfile::tempdir().unwrap();
    let mut ran = Vec::new();
    execute_pair(&request, dir.path(), None, |run| {
        ran.push(run.receipt_name);
        let mut receipt = admitted(&run.commit);
        if run.receipt_name == "base.json" {
            receipt.steps[2].not_run_tests.push("el1::unrun".into());
        }
        write_run_evidence(&run.output, run.receipt_name, &receipt);
        Ok(())
    })
    .unwrap();
    assert_eq!(ran, ["base.json", "candidate.json"]);
    assert!(dir.path().join("base-seal.json").exists());
}

/// Digest inventory of every file under `dir`, computed independently of the
/// executor: relative `/`-separated path to lowercase SHA-256.
fn inventory(dir: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    fn walk(
        root: &std::path::Path,
        dir: &std::path::Path,
        out: &mut std::collections::BTreeMap<String, String>,
    ) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let relative = path.strip_prefix(root).unwrap();
                let key = relative
                    .components()
                    .map(|c| c.as_os_str().to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(
                    key,
                    format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap())),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

/// Evidence one runner side leaves, as `execute_one` would.
fn write_run_evidence(dir: &std::path::Path, name: &str, receipt: &AcceptReceipt) {
    std::fs::create_dir_all(dir.join("steps")).unwrap();
    std::fs::write(dir.join(name), serde_json::to_vec(receipt).unwrap()).unwrap();
    std::fs::write(
        dir.join("identity.json"),
        serde_json::to_vec(&receipt.artifact).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("cleanup.json"),
        serde_json::to_vec(&receipt.cleanup_counts).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("accept-exit.json"), r#"{"success":false}"#).unwrap();
    std::fs::write(dir.join("steps/el1-embed.log"), "log").unwrap();
}

/// Review P1 on #1889: candidate code runs after the base on the same Mac
/// and could rewrite the base's evidence. The pairing seals a digest
/// inventory of the base directory in executor memory immediately after the
/// base run, re-verifies it after the candidate run and its cleanup, and only
/// then writes the sealed record. Any changed, missing or added file fails.
#[test]
fn candidate_phase_mutation_of_paired_base_evidence_is_refused() {
    use carrick_xtask::signed_gate::{Request, RequestKind, execute_pair};
    let request = Request {
        kind: RequestKind::PullRequest,
        prs: vec![123],
        sha: "b".repeat(40),
        base: "a".repeat(40),
    };
    type Tamper = fn(&std::path::Path);
    let tampers: [(&str, Tamper); 4] = [
        ("changed receipt", |base| {
            let path = base.join("base.json");
            let mut receipt: AcceptReceipt =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            receipt.steps[2]
                .failed_tests
                .push("candidate_regression".into());
            std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        }),
        ("missing file", |base| {
            std::fs::remove_file(base.join("steps/el1-embed.log")).unwrap()
        }),
        ("added file", |base| {
            std::fs::write(base.join("extra.json"), "{}").unwrap()
        }),
        ("replaced seal", |base| {
            // A candidate cannot pre-plant the sealed record either.
            std::fs::write(base.parent().unwrap().join("base-seal.json"), "{}").unwrap()
        }),
    ];
    for (label, tamper) in tampers {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path();
        let result = execute_pair(&request, output, None, |run| {
            if run.receipt_name == "base.json" {
                write_run_evidence(&run.output, run.receipt_name, &admitted(&request.base));
            } else {
                write_run_evidence(&run.output, run.receipt_name, &admitted(&request.sha));
                tamper(&output.join("base"));
            }
            Ok(())
        });
        if label == "replaced seal" {
            // The executor overwrites the planted record with its own seal.
            result.unwrap();
            let seal: serde_json::Value =
                serde_json::from_slice(&std::fs::read(output.join("base-seal.json")).unwrap())
                    .unwrap();
            assert_eq!(seal["base"], request.base);
            assert_eq!(
                serde_json::to_value(inventory(&output.join("base"))).unwrap(),
                seal["files"]
            );
            continue;
        }
        let error = result.expect_err(label).to_string();
        assert!(error.contains("base evidence seal"), "{label}: {error}");
        assert!(
            !output.join("base-seal.json").exists(),
            "{label}: sealed a tampered base"
        );
        let diagnostic = std::fs::read_to_string(output.join("execution-error.txt")).unwrap();
        assert!(diagnostic.contains("base evidence seal"), "{label}");
    }
}

/// Publication checks the sealed record against the base evidence it loads:
/// a rewritten base receipt cannot hide a candidate regression.
#[cfg(unix)]
#[test]
fn publish_refuses_base_evidence_that_differs_from_its_seal() {
    let bench = PublishBench::new();
    let base = admitted(&bench.base);
    bench.write_base(&base, false);
    let mut candidate = admitted(&bench.head);
    candidate.steps[2]
        .failed_tests
        .push("candidate_regression".into());
    bench.write_candidate(&candidate, false);
    let seal = |files: std::collections::BTreeMap<String, String>| {
        std::fs::write(
            bench.results().join("base-seal.json"),
            json!({"base": bench.base, "files": files}).to_string(),
        )
        .unwrap();
    };
    seal(inventory(&bench.results().join("base")));
    let (passed, body) = bench.publish();
    assert!(!passed, "regression passed: {body}");
    assert!(body.contains("candidate_regression"), "{body}");

    // Rewrite the base so the regression looks pre-existing.
    let mut forged = base.clone();
    forged.steps[2]
        .failed_tests
        .push("candidate_regression".into());
    bench.write_base_unsealed(&forged, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "forged base passed: {body}");
    assert!(body.contains("base evidence seal"), "{body}");

    // A missing record, or one naming another base, is no seal.
    bench.write_base(&base, false);
    std::fs::write(
        bench.results().join("base-seal.json"),
        json!({"base": "c".repeat(40), "files": inventory(&bench.results().join("base"))})
            .to_string(),
    )
    .unwrap();
    let (passed, body) = bench.publish();
    assert!(!passed && body.contains("base evidence seal"), "{body}");
    std::fs::remove_file(bench.results().join("base-seal.json")).unwrap();
    let (passed, body) = bench.publish();
    assert!(!passed && body.contains("base evidence seal"), "{body}");
}

/// Review P1 on #1889: the candidate must not supply the base's fixture
/// authority. Both sides restore the bundle a trusted main push published
/// for the merge base; the candidate is admitted against it by equal inputs.
#[test]
fn both_paired_runs_restore_the_trusted_base_fixture_bundle() {
    use carrick_xtask::signed_gate::{Request, RequestKind, execute_pair};
    for kind in [RequestKind::PullRequest, RequestKind::MergeGroup] {
        let request = Request {
            kind,
            prs: vec![123],
            sha: "b".repeat(40),
            base: "a".repeat(40),
        };
        let dir = tempfile::tempdir().unwrap();
        let mut seen = Vec::new();
        execute_pair(&request, dir.path(), None, |run| {
            seen.push((run.commit.clone(), run.fixture_publisher.clone()));
            let head = run.commit.clone();
            write_run_evidence(&run.output, run.receipt_name, &admitted(&head));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                (request.base.clone(), request.base.clone()),
                (request.sha.clone(), request.base.clone()),
            ],
            "{kind:?}: the candidate's bundle served as fixture authority"
        );
    }
}

/// `signed-gate base-fixtures` fetches the merge base's bundle only from an
/// authenticated main-push run of the trusted fixture publisher, keyed by
/// `request.base`, and blocks when none is available.
#[cfg(unix)]
#[test]
fn base_fixtures_come_only_from_an_authenticated_main_run_of_the_base() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    carrick_test_support::executable::write_executable(
        bin.join("gh"),
        r#"#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
base = os.environ['TEST_BASE_SHA']
name = 'signed-fixtures-' + base
trusted = {'id': 500, 'path': '.github/workflows/kernel-runtime.yml', 'head_branch': 'main', 'head_sha': base, 'event': 'push', 'status': 'completed', 'repository': {'full_name': 'carrick-sh/carrick'}, 'head_repository': {'full_name': 'carrick-sh/carrick'}, 'actor': {'login': 'github-merge-queue[bot]'}, 'triggering_actor': {'login': 'github-merge-queue[bot]'}}
def variant(run_id, **changes):
    run = json.loads(json.dumps(trusted))
    run['id'] = run_id
    for key, value in changes.items():
        if key in ('repository', 'head_repository'):
            run[key] = {'full_name': value}
        elif key in ('actor', 'triggering_actor'):
            run[key] = {'login': value}
        else:
            run[key] = value
    return run
# Newer untrusted runs, each carrying a planted bundle, must never be used.
untrusted = [
    variant(601, path='.github/workflows/signed-gate.yml'),
    variant(602, head_branch='feature'),
    variant(603, event='pull_request'),
    variant(604, repository='someone/fork'),
    variant(605, head_repository='someone/fork'),
    variant(606, head_sha='c' * 40),
    variant(607, event='workflow_dispatch', actor='carrick-workers[bot]', triggering_actor='carrick-workers[bot]'),
]
mode = os.environ.get('TEST_MODE', 'trusted')
if args[:2] == ['run', 'download']:
    run_id = args[2]
    assert args[args.index('--repo')+1] == 'carrick-sh/carrick', args
    assert args[args.index('--name')+1] == name, args
    out = pathlib.Path(args[args.index('--dir')+1])
    out.mkdir(parents=True, exist_ok=True)
    (out / ('bundle-from-run-' + run_id + '.tar.gz')).write_text(run_id)
elif args[0] == 'api':
    endpoint = args[-1]
    if '/actions/workflows/kernel-runtime.yml/runs?' in endpoint:
        assert 'branch=main' in endpoint and 'head_sha=' + base in endpoint, endpoint
        runs = untrusted + ([] if mode == 'none' else [trusted])
        print(json.dumps([{'workflow_runs': runs}]))
    elif endpoint.endswith('/artifacts?per_page=100'):
        run_id = int(endpoint.split('/runs/')[1].split('/')[0])
        rows = [{'name': name, 'expired': False}]
        if run_id == 500 and mode == 'missing':
            rows = [{'name': 'signed-fixtures-' + 'c' * 40, 'expired': False}]
        if run_id == 500 and mode == 'expired':
            rows = [{'name': name, 'expired': True}]
        print(json.dumps([{'artifacts': rows}]))
    else:
        raise SystemExit('unexpected API endpoint: ' + endpoint)
else:
    raise SystemExit('unexpected gh invocation: ' + repr(args))
"#,
    );
    let base = "a".repeat(40);
    let request = dir.path().join("request.json");
    std::fs::write(
        &request,
        json!({"kind":"MergeGroup","prs":[123],"sha":"b".repeat(40),"base":base}).to_string(),
    )
    .unwrap();
    let fetch = |mode: &str| {
        let output = dir.path().join(format!("fixtures-{mode}"));
        let result = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("TEST_BASE_SHA", &base)
            .env("TEST_MODE", mode)
            .args(["signed-gate", "base-fixtures", "--request"])
            .arg(&request)
            .arg("--output")
            .arg(&output)
            .args(["--wait-minutes", "0"])
            .output()
            .unwrap();
        (result, output)
    };
    let (fetched, output) = fetch("trusted");
    assert!(
        fetched.status.success(),
        "{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
    let bundles: Vec<_> = std::fs::read_dir(&output)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".tar.gz"))
        .collect();
    assert_eq!(bundles, ["bundle-from-run-500.tar.gz"]);
    let provenance: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("provenance.json")).unwrap()).unwrap();
    assert_eq!(provenance["run_id"], 500);
    assert_eq!(provenance["head_sha"], base);
    assert_eq!(
        provenance["workflow"],
        ".github/workflows/kernel-runtime.yml"
    );
    assert_eq!(provenance["artifact"], format!("signed-fixtures-{base}"));
    for mode in ["none", "missing", "expired"] {
        let (refused, output) = fetch(mode);
        assert!(
            !refused.status.success(),
            "{mode}: untrusted bundle admitted"
        );
        let stderr = String::from_utf8_lossy(&refused.stderr);
        assert!(stderr.contains("trusted base fixture"), "{mode}: {stderr}");
        let planted = std::fs::read_dir(&output).map_or(0, |entries| {
            entries
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tar.gz")
                })
                .count()
        });
        assert_eq!(planted, 0, "{mode}: downloaded an untrusted bundle");
    }
}

fn queue_entry(head: &str, number: u64) -> serde_json::Value {
    json!({
        "baseCommit": {"oid": "b".repeat(40)},
        "headCommit": {"oid": head},
        "pullRequest": {
            "number": number,
            "baseRefName": "main",
            "baseRepository": {"nameWithOwner": "carrick-sh/carrick"}
        }
    })
}

fn unmergeable_entry() -> serde_json::Value {
    json!({
        "baseCommit": null,
        "headCommit": null,
        "pullRequest": {"number": 1902, "baseRefName": null, "baseRepository": null}
    })
}

#[test]
fn queue_ignores_unmergeable_sibling() {
    let head = "a".repeat(40);
    for sibling in [unmergeable_entry(), serde_json::Value::Null] {
        let entries = [queue_entry(&head, 1950), sibling];
        validate_queue_entries(&entries, &head, 1950).unwrap();
    }
}

#[test]
fn queue_refuses_incomplete_own_entry() {
    let head = "a".repeat(40);
    let mut no_base = queue_entry(&head, 1950);
    no_base["baseCommit"] = serde_json::Value::Null;
    let mut no_number = queue_entry(&head, 1950);
    no_number["pullRequest"]["number"] = serde_json::Value::Null;
    for own in [no_base, no_number] {
        let err = validate_queue_entries(&[own], &head, 1950).unwrap_err();
        assert!(err.to_string().contains("null or incomplete"), "{err}");
    }
}

#[test]
fn queue_refuses_missing_own_entry() {
    let head = "a".repeat(40);
    let entries = [queue_entry(&"c".repeat(40), 1951), unmergeable_entry()];
    let err = validate_queue_entries(&entries, &head, 1950).unwrap_err();
    assert!(err.to_string().contains("not the live entry"), "{err}");
}

impl PublishBench {
    /// The `signed-gate` commit status last posted by `publish`.
    fn last_status(&self) -> (String, String) {
        let posts = std::fs::read_to_string(self.dir.path().join("posts.jsonl")).unwrap();
        let post: serde_json::Value = posts
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .rfind(|post| post["endpoint"].as_str().unwrap().contains("/statuses/"))
            .unwrap();
        (
            post["body"]["state"].as_str().unwrap().to_owned(),
            post["body"]["description"].as_str().unwrap().to_owned(),
        )
    }

    /// Publish a candidate whose `el1-embed` step differs from the base's
    /// (started red_a, red_b, green; failed red_a, red_b).
    fn publish_with(
        &self,
        edit: impl FnOnce(&mut carrick_xtask::accept::StepResult),
    ) -> (bool, String, (String, String)) {
        self.write_base(&admitted(&self.base), false);
        let mut candidate = admitted(&self.head);
        edit(&mut candidate.steps[2]);
        self.write_candidate(&candidate, false);
        let (passed, body) = self.publish();
        (passed, body, self.last_status())
    }
}

/// #2035 (a): a failing test the group's own PRs add is not in the base's
/// started tests, so it blocks and is named in the status and the comment.
#[cfg(unix)]
#[test]
fn introduced_failing_test_blocks_and_is_named() {
    let bench = PublishBench::new();
    let (passed, body, (state, description)) = bench.publish_with(|step| {
        step.failed_tests.push("embed::brand_new".into());
        step.started_tests.push("embed::brand_new".into());
    });
    assert!(!passed, "{body}");
    assert_eq!(state, "failure");
    assert!(description.contains("embed::brand_new"), "{description}");
    assert!(description.len() <= 140, "{description}");
    assert!(body.starts_with("Signed gate: **FAIL**"), "{body}");
    assert!(
        body.contains("BLOCKING={\"test:el1-embed:embed::brand_new\"}"),
        "{body}"
    );
    assert!(body.contains("introduced by its own PRs"), "{body}");
}

/// #2035 (b): a test the base already started that fails only in the
/// candidate is a pre-existing flake: advisory, listed, never blocking.
#[cfg(unix)]
#[test]
fn preexisting_flake_alone_is_advisory() {
    let bench = PublishBench::new();
    let (passed, body, (state, description)) = bench.publish_with(|step| {
        step.failed_tests.push("embed::green".into());
    });
    assert!(passed, "{body}");
    assert_eq!(state, "success");
    assert!(
        body.starts_with("Signed gate: **PASS (advisory NEW only)**"),
        "{body}"
    );
    assert!(body.contains("NEW entries are advisory"), "{body}");
    assert!(
        body.contains("ADVISORY={\"test:el1-embed:embed::green\"}"),
        "{body}"
    );
    assert!(body.contains("BLOCKING={}"), "{body}");
    assert_eq!(
        description, "advisory NEW entries present; see comment",
        "advisory-only pass must not claim preservation"
    );
}

/// #2038: a clean pass (no NEW entry at all) keeps the preservation wording.
#[cfg(unix)]
#[test]
fn clean_pass_keeps_the_preservation_wording() {
    let bench = PublishBench::new();
    let (passed, body, (state, description)) = bench.publish_with(|_| {});
    assert!(passed, "{body}");
    assert_eq!(state, "success");
    assert_eq!(
        description,
        "No introduced failures; populations and completion preserved"
    );
}

/// #2035 (c): a mix blocks and names only the introduced test as blocking.
#[cfg(unix)]
#[test]
fn mixed_flake_and_introduced_test_blocks_naming_only_the_introduced() {
    let bench = PublishBench::new();
    let (passed, body, (state, description)) = bench.publish_with(|step| {
        step.failed_tests.push("embed::green".into());
        step.failed_tests.push("embed::brand_new".into());
        step.started_tests.push("embed::brand_new".into());
    });
    assert!(!passed, "{body}");
    assert_eq!(state, "failure");
    assert!(description.contains("embed::brand_new"), "{description}");
    assert!(!description.contains("embed::green"), "{description}");
    assert!(
        body.contains("BLOCKING={\"test:el1-embed:embed::brand_new\"}"),
        "{body}"
    );
    assert!(
        body.contains("ADVISORY={\"test:el1-embed:embed::green\"}"),
        "{body}"
    );
}

/// #2035 (d): a binary absent from the base that never finishes is introduced.
/// A base-finished binary that stops finishing is a pre-existing one.
#[test]
fn new_unfinished_binary_is_introduced_and_blocks() {
    let base = base();
    let mut next = base.clone();
    next.steps[0].unfinished_binaries = vec!["newbin".into(), "embed".into()];
    let diff = compare(&base, &next).unwrap();
    assert!(diff.blocks());
    assert!(diff.blocking.contains("unfinished:el1-embed:newbin"));
    assert!(!diff.blocking.contains("unfinished:el1-embed:embed"));
    assert!(diff.advisory.contains("unfinished:el1-embed:embed"));
    assert!(
        diff.steps[0]
            .introduced_unfinished_binaries
            .contains("newbin")
    );
}

/// A deadline kill of a test the base started is the same flake, not new.
#[test]
fn deadline_failure_of_a_base_started_test_is_not_introduced() {
    let base = base();
    let mut next = base.clone();
    next.steps[0].failed_tests = vec!["deadline:embed::green".into(), "embed::red_a".into()];
    let diff = compare(&base, &next).unwrap();
    assert!(!diff.blocks(), "{:?}", diff.blocking);
    assert!(
        diff.advisory
            .contains("test:el1-embed:deadline:embed::green")
    );
}

/// Incomplete evidence keeps blocking: a missing step is not an advisory.
#[test]
fn incomplete_evidence_still_blocks() {
    let base = base();
    let mut next = base.clone();
    next.steps[0].name = "replacement".into();
    let diff = compare(&base, &next).unwrap();
    assert!(diff.blocking.contains("missing-step:el1-embed"));
}

#[cfg(unix)]
mod base_reuse_witnesses {
    use super::*;
    use carrick_xtask::accept::SignedHostIdentity;
    use carrick_xtask::fixtures::{
        BuildPolicy, Executable, GuestTarget, Manifest, Toolchain, archive,
    };
    use carrick_xtask::signed_gate::{
        PairSide, Request, RequestKind, ReuseExecutionContext, ReuseMissReason,
        compute_base_reuse_key, execute_pair, trusted_reuse_run,
    };
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn arm64_musl_elf(tag: &[u8]) -> Vec<u8> {
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize = 64
        elf.extend_from_slice(tag);
        elf
    }

    fn git_cmd(cwd: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(cwd)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    struct PackedBundle {
        archive: PathBuf,
        manifest_sha256: String,
        inputs_sha256: String,
        content_sha256: String,
    }

    fn pack_test_bundle(
        work: &Path,
        source_head: &str,
        tag: &[u8],
        input_seed: &str,
    ) -> PackedBundle {
        let elf = arm64_musl_elf(tag);
        let elf_sha = format!("{:x}", Sha256::digest(&elf));
        let src_sha = format!("{:x}", Sha256::digest(input_seed.as_bytes()));
        let manifest = Manifest {
            schema: "carrick.fixtures.v3".into(),
            source_head: source_head.to_string().try_into().unwrap(),
            compiler_inputs: vec!["probe.rs".into()],
            sources: [("probe.rs".into(), src_sha.try_into().unwrap())].into(),
            build_policy: BuildPolicy::default(),
            toolchain: Toolchain {
                rustc: "rustc 1.96.0".into(),
                cargo: "cargo 1.96.0".into(),
                gnu_linker: "aarch64-linux-gnu-gcc".into(),
            },
            executables: vec![Executable {
                path: "conformance-probes/target/aarch64-unknown-linux-musl/release/probe".into(),
                target: GuestTarget::Musl,
                sha256: elf_sha.clone().try_into().unwrap(),
            }],
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let manifest_sha256 = format!("{:x}", Sha256::digest(&manifest_bytes));
        let bundle_dir = work.join("bundle-src").join(&manifest_sha256);
        std::fs::create_dir_all(bundle_dir.join("objects")).unwrap();
        let manifest_path = bundle_dir.join("manifest.json");
        std::fs::write(&manifest_path, &manifest_bytes).unwrap();
        let obj_path = bundle_dir.join("objects").join(&elf_sha);
        std::fs::write(&obj_path, &elf).unwrap();
        std::fs::set_permissions(&obj_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let archive = archive::pack(&manifest_path, &work.join("packed")).unwrap();
        PackedBundle {
            archive,
            manifest_sha256,
            inputs_sha256: String::from(manifest.input_identity().unwrap()),
            content_sha256: String::from(manifest.content_identity().unwrap()),
        }
    }

    struct ReuseBench {
        dir: tempfile::TempDir,
        repo: PathBuf,
        bin: PathBuf,
        artifacts_root: PathBuf,
        base: String,
        head: String,
        host: SignedHostIdentity,
        bundle: PackedBundle,
    }

    impl ReuseBench {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let repo = dir.path().join("repo");
            std::fs::create_dir_all(repo.join("scripts")).unwrap();
            git_cmd(&repo, &["init", "-q", "-b", "main"]);
            git_cmd(&repo, &["config", "user.name", "Reuse Test"]);
            git_cmd(&repo, &["config", "user.email", "reuse@example.test"]);
            std::fs::write(
                repo.join("rust-toolchain.toml"),
                b"[toolchain]\nchannel = \"1.96.0\"\n",
            )
            .unwrap();
            std::fs::write(
                repo.join("scripts/entitlements.plist"),
                b"<plist><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>\n",
            )
            .unwrap();
            git_cmd(
                &repo,
                &["add", "rust-toolchain.toml", "scripts/entitlements.plist"],
            );
            git_cmd(&repo, &["commit", "-q", "-m", "base"]);
            let base = git_cmd(&repo, &["rev-parse", "HEAD"]);

            std::fs::write(repo.join("README.md"), b"candidate change\n").unwrap();
            git_cmd(&repo, &["add", "README.md"]);
            git_cmd(&repo, &["commit", "-q", "-m", "candidate"]);
            let head = git_cmd(&repo, &["rev-parse", "HEAD"]);

            let host = SignedHostIdentity {
                runner_name: "carrick-gate-mac-1".into(),
                hardware_model: "Mac15,12".into(),
                product_build: "24D70".into(),
            };
            let bundle = pack_test_bundle(&dir.path().join("b1"), &base, b"v1", "seed-1");

            let bin = dir.path().join("bin");
            let artifacts_root = dir.path().join("gh-artifacts");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::create_dir_all(&artifacts_root).unwrap();

            // Shims for SignedHostIdentity::capture() and GitHub API/artifact transport.
            std::fs::write(
                bin.join("sysctl"),
                r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "-n" ] && [ "${2:-}" = "hw.model" ]; then
  printf '%s\n' "${TEST_HW_MODEL:-Mac15,12}"
  exit 0
fi
exit 1
"#,
            )
            .unwrap();
            std::fs::set_permissions(bin.join("sysctl"), std::fs::Permissions::from_mode(0o755))
                .unwrap();

            std::fs::write(
                bin.join("sw_vers"),
                r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "-buildVersion" ]; then
  printf '%s\n' "${TEST_PRODUCT_BUILD:-24D70}"
  exit 0
fi
exit 1
"#,
            )
            .unwrap();
            std::fs::set_permissions(bin.join("sw_vers"), std::fs::Permissions::from_mode(0o755))
                .unwrap();

            std::fs::write(
                bin.join("gh"),
                r#"#!/usr/bin/env python3
import json, os, pathlib, shutil, sys, urllib.parse
args = sys.argv[1:]
if '--method' in args and args[args.index('--method') + 1] == 'POST':
    with open(os.environ['TEST_POSTS'], 'a') as out:
        out.write(json.dumps({'endpoint': args[args.index('POST') + 1], 'body': json.load(sys.stdin)}) + '\n')
    sys.exit(0)

state = json.loads(pathlib.Path(os.environ['TEST_GH_STATE']).read_text())

if args[:2] == ['run', 'download']:
    run_id = int(args[2])
    assert args[args.index('--repo') + 1] == 'carrick-sh/carrick', args
    name = args[args.index('--name') + 1]
    dest = pathlib.Path(args[args.index('--dir') + 1])
    for art in state['artifacts']:
        if art['workflow_run']['id'] == run_id and (art['name'] == name or art.get('serve_for_any_name', False)) and not art.get('expired', False):
            src = pathlib.Path(art['dir'])
            dest.mkdir(parents=True, exist_ok=True)
            for item in src.iterdir():
                target = dest / item.name
                if item.is_symlink():
                    os.symlink(os.readlink(item), target)
                elif item.is_dir():
                    shutil.copytree(item, target, symlinks=True)
                else:
                    shutil.copy2(item, target)
            sys.exit(0)
    raise SystemExit(f'no downloadable artifact for run {run_id} name {name}')

if args[0] == 'api':
    endpoint = args[-1]
    if '/actions/artifacts?' in endpoint:
        query = urllib.parse.parse_qs(endpoint.split('?', 1)[1])
        wanted = query.get('name', [''])[0]
        rows = [
            {
                'id': art['id'],
                'name': art['name'],
                'expired': art.get('expired', False),
                'workflow_run': art['workflow_run'],
            }
            for art in state['artifacts']
            if art['name'] == wanted or art.get('serve_for_any_name', False)
        ]
        print(json.dumps([{'artifacts': rows}]))
        sys.exit(0)
    if '/actions/runs/' in endpoint:
        run_id = int(endpoint.split('/actions/runs/')[1].split('/')[0])
        for run in state['runs']:
            if run['id'] == run_id:
                print(json.dumps(run))
                sys.exit(0)
        raise SystemExit(f'unknown run {run_id}')

raise SystemExit('unexpected gh invocation: ' + repr(args))
"#,
            )
            .unwrap();
            std::fs::set_permissions(bin.join("gh"), std::fs::Permissions::from_mode(0o755))
                .unwrap();

            Self {
                dir,
                repo,
                bin,
                artifacts_root,
                base,
                head,
                host,
                bundle,
            }
        }

        fn path_env(&self) -> String {
            format!(
                "{}:{}",
                self.bin.display(),
                std::env::var("PATH").unwrap_or_default()
            )
        }

        fn receipt_for(&self, commit: &str) -> AcceptReceipt {
            let mut r = admitted(commit);
            r.host_identity = Some(self.host.clone());
            let fv = r.fixture_validation.as_mut().unwrap();
            fv.checkout_head = commit.to_string().try_into().unwrap();
            fv.bundle_source_head = self.base.clone().try_into().unwrap();
            fv.manifest_sha256 = self.bundle.manifest_sha256.clone().try_into().unwrap();
            fv.inputs_sha256 = self.bundle.inputs_sha256.clone().try_into().unwrap();
            fv.content_sha256 = Some(self.bundle.content_sha256.clone().try_into().unwrap());
            r
        }

        fn write_gh_state(&self, runs: Vec<serde_json::Value>, artifacts: Vec<serde_json::Value>) {
            std::fs::write(
                self.dir.path().join("gh-state.json"),
                serde_json::to_vec_pretty(&json!({
                    "runs": runs,
                    "artifacts": artifacts,
                }))
                .unwrap(),
            )
            .unwrap();
        }

        fn trusted_main_run(&self, run_id: u64) -> serde_json::Value {
            json!({
                "id": run_id,
                "path": ".github/workflows/signed-gate.yml",
                "head_branch": "main",
                "head_sha": self.base,
                "event": "push",
                "status": "completed",
                "repository": { "full_name": "carrick-sh/carrick" },
                "head_repository": { "full_name": "carrick-sh/carrick" },
                "actor": { "login": "github-merge-queue[bot]" },
                "triggering_actor": { "login": "github-merge-queue[bot]" }
            })
        }

        fn publish_main_reusable_artifact(
            &self,
            run_id: u64,
            receipt: &AcceptReceipt,
        ) -> (String, PathBuf) {
            let main_dir = self.dir.path().join(format!("main-run-{run_id}"));
            let results = main_dir.join("results");
            std::fs::create_dir_all(&results).unwrap();
            write_run_evidence(&results, "candidate.json", receipt);
            let req_path = main_dir.join("request.json");
            std::fs::write(
                &req_path,
                serde_json::to_vec(&Request {
                    kind: RequestKind::Main,
                    prs: vec![],
                    sha: self.base.clone(),
                    base: self.base.clone(),
                })
                .unwrap(),
            )
            .unwrap();

            let posts = main_dir.join("posts.jsonl");
            let pub_out = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
                .env("PATH", self.path_env())
                .env("TEST_POSTS", &posts)
                .env_remove("GITHUB_STEP_SUMMARY")
                .args(["--root", &self.repo.to_string_lossy()])
                .args(["signed-gate", "publish", "--request"])
                .arg(&req_path)
                .args(["--results"])
                .arg(&results)
                .args([
                    "--run-url",
                    "https://github.com/carrick-sh/carrick/actions/runs/500",
                    "--execution-result",
                    "success",
                ])
                .output()
                .unwrap();
            assert!(
                pub_out.status.success(),
                "main publish failed: stdout={} stderr={}",
                String::from_utf8_lossy(&pub_out.stdout),
                String::from_utf8_lossy(&pub_out.stderr)
            );

            let gh_output = main_dir.join("github-output.txt");
            let artifact_dir = self.artifacts_root.join(format!("artifact-{run_id}"));
            let prep = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
                .env("GITHUB_OUTPUT", &gh_output)
                .args(["--root", &self.repo.to_string_lossy()])
                .args(["signed-gate", "prepare-reuse-upload", "--request"])
                .arg(&req_path)
                .arg("--results")
                .arg(&results)
                .arg("--fixture-bundle")
                .arg(&self.bundle.archive)
                .args(["--run-id", &run_id.to_string(), "--output"])
                .arg(&artifact_dir)
                .output()
                .unwrap();
            assert!(
                prep.status.success(),
                "prepare-reuse-upload failed: stdout={} stderr={}",
                String::from_utf8_lossy(&prep.stdout),
                String::from_utf8_lossy(&prep.stderr)
            );
            let out_text = std::fs::read_to_string(&gh_output).unwrap();
            let artifact_name = out_text
                .lines()
                .find_map(|l| l.strip_prefix("artifact_name="))
                .expect("prepare-reuse-upload must write artifact_name to GITHUB_OUTPUT")
                .to_string();
            (artifact_name, artifact_dir)
        }

        fn run_lookup(
            &self,
            request: &Request,
            bundle: &Path,
            host: &SignedHostIdentity,
            out_dir: &Path,
        ) -> std::process::Output {
            let req_path = self.dir.path().join("lookup-request.json");
            std::fs::write(&req_path, serde_json::to_vec(request).unwrap()).unwrap();
            Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
                .env("PATH", self.path_env())
                .env("TEST_GH_STATE", self.dir.path().join("gh-state.json"))
                .env("RUNNER_NAME", &host.runner_name)
                .env("TEST_HW_MODEL", &host.hardware_model)
                .env("TEST_PRODUCT_BUILD", &host.product_build)
                .args(["--root", &self.repo.to_string_lossy()])
                .args(["signed-gate", "reuse-lookup", "--request"])
                .arg(&req_path)
                .arg("--fixture-bundle")
                .arg(bundle)
                .arg("--output")
                .arg(out_dir)
                .output()
                .unwrap()
        }

        fn publish_group(
            &self,
            request: &Request,
            results: &Path,
        ) -> (bool, String, serde_json::Value, String) {
            let req_path = results.join("publish-request.json");
            std::fs::write(&req_path, serde_json::to_vec(request).unwrap()).unwrap();
            let posts = results.join("posts.jsonl");
            let _ = std::fs::remove_file(&posts);
            let out = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
                .env("PATH", self.path_env())
                .env("TEST_POSTS", &posts)
                .env_remove("GITHUB_STEP_SUMMARY")
                .args(["--root", &self.repo.to_string_lossy()])
                .args(["signed-gate", "publish", "--request"])
                .arg(&req_path)
                .arg("--results")
                .arg(results)
                .args([
                    "--run-url",
                    "https://github.com/carrick-sh/carrick/actions/runs/777",
                    "--execution-result",
                    "success",
                ])
                .output()
                .unwrap();
            let comment = std::fs::read_to_string(results.join("comment.md")).unwrap_or_default();
            let diff = std::fs::read(results.join("diff.json"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(serde_json::Value::Null);
            let status_desc = std::fs::read_to_string(&posts)
                .unwrap_or_default()
                .lines()
                .rev()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .find(|p| {
                    p["endpoint"]
                        .as_str()
                        .unwrap_or_default()
                        .contains("/statuses/")
                })
                .and_then(|p| p["body"]["description"].as_str().map(str::to_owned))
                .unwrap_or_default();
            (out.status.success(), comment, diff, status_desc)
        }
    }

    /// Round-trip witness (#1918): a `Main` push run publishes under the exact
    /// key `reuse-lookup` computes, untrusted/expired runs are ignored,
    /// `execute_pair` skips `PairSide::Base` (runner count == candidate only),
    /// and `publish` reports the reused artifact and run ID instead of claiming
    /// the base ran in this job.
    #[test]
    fn reuse_round_trip_from_main_skips_base_execution_and_records_provenance() {
        let bench = ReuseBench::new();
        let base_receipt = bench.receipt_for(&bench.base);
        let (artifact_name, artifact_dir) =
            bench.publish_main_reusable_artifact(500, &base_receipt);

        let expected_key = compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &bench.bundle.archive,
        )
        .expect("compute_base_reuse_key");
        assert_eq!(expected_key.artifact_name().unwrap(), artifact_name);

        // Verify `trusted_reuse_run` admits push to main and owner dispatch, and rejects untrusted runs.
        let trusted_push = bench.trusted_main_run(500);
        assert!(trusted_reuse_run(&trusted_push, &bench.base));
        let mut owner_dispatch = trusted_push.clone();
        owner_dispatch["event"] = json!("workflow_dispatch");
        owner_dispatch["head_sha"] = json!("f".repeat(40));
        owner_dispatch["actor"] = json!({ "login": "tjfontaine" });
        owner_dispatch["triggering_actor"] = json!({ "login": "tjfontaine" });
        assert!(trusted_reuse_run(&owner_dispatch, &bench.base));

        let mut untrusted_runs = Vec::new();
        let mut untrusted_artifacts = Vec::new();
        for (idx, (label, tweak)) in [
            (
                "wrong_workflow",
                json!({"path": ".github/workflows/ci.yml"}),
            ),
            ("wrong_branch", json!({"head_branch": "feat/untrusted"})),
            ("wrong_event", json!({"event": "pull_request_target"})),
            (
                "wrong_repo",
                json!({"repository": {"full_name": "attacker/carrick"}}),
            ),
            (
                "wrong_head_repo",
                json!({"head_repository": {"full_name": "attacker/carrick"}}),
            ),
            ("wrong_push_sha", json!({"head_sha": "c".repeat(40)})),
            (
                "bot_dispatch",
                json!({
                    "event": "workflow_dispatch",
                    "actor": {"login": "carrick-workers[bot]"},
                    "triggering_actor": {"login": "carrick-workers[bot]"}
                }),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let run_id = 600 + idx as u64;
            let mut run = trusted_push.clone();
            run["id"] = json!(run_id);
            for (k, v) in tweak.as_object().unwrap() {
                run[k] = v.clone();
            }
            assert!(
                !trusted_reuse_run(&run, &bench.base),
                "{label}: untrusted run admitted"
            );
            let planted = bench.dir.path().join(format!("planted-{idx}"));
            std::fs::create_dir_all(&planted).unwrap();
            std::fs::write(planted.join("base-seal.json"), b"poisoned").unwrap();
            untrusted_runs.push(run);
            untrusted_artifacts.push(json!({
                "id": 9500 + idx as u64,
                "name": artifact_name,
                "expired": false,
                "workflow_run": { "id": run_id },
                "dir": planted,
            }));
        }
        // Also plant a newer expired artifact on the trusted run.
        untrusted_artifacts.push(json!({
            "id": 9999,
            "name": artifact_name,
            "expired": true,
            "workflow_run": { "id": 500 },
            "dir": bench.dir.path().join("missing-expired"),
        }));

        let mut runs = untrusted_runs;
        runs.push(trusted_push);
        let mut artifacts = untrusted_artifacts;
        artifacts.push(json!({
            "id": 9001,
            "name": artifact_name,
            "expired": false,
            "workflow_run": { "id": 500 },
            "dir": artifact_dir,
        }));
        bench.write_gh_state(runs, artifacts);

        let group_request = Request {
            kind: RequestKind::MergeGroup,
            prs: vec![42],
            sha: bench.head.clone(),
            base: bench.base.clone(),
        };
        let reuse_dir = bench.dir.path().join("reused-base");
        let lookup = bench.run_lookup(
            &group_request,
            &bench.bundle.archive,
            &bench.host,
            &reuse_dir,
        );
        assert!(
            lookup.status.success(),
            "reuse-lookup exited nonzero: {}",
            String::from_utf8_lossy(&lookup.stderr)
        );
        assert!(
            reuse_dir.join("base-seal.json").exists(),
            "reuse-lookup did not write verified base-seal.json; stderr={}",
            String::from_utf8_lossy(&lookup.stderr)
        );

        let results = bench.dir.path().join("group-results");
        std::fs::create_dir_all(&results).unwrap();
        let ctx = ReuseExecutionContext {
            root: &bench.repo,
            bundle: &bench.bundle.archive,
            host_identity: Some(bench.host.clone()),
            reuse_dir: &reuse_dir,
        };
        let mut executed_sides = Vec::new();
        execute_pair(&group_request, &results, Some(&ctx), |run| {
            executed_sides.push(run.side);
            write_run_evidence(
                &run.output,
                run.receipt_name,
                &bench.receipt_for(&run.commit),
            );
            Ok(())
        })
        .unwrap();
        assert_eq!(
            executed_sides,
            [PairSide::Candidate],
            "PairSide::Base must NOT run when a matching sealed receipt is reused"
        );

        let (passed, comment, _diff, _desc) = bench.publish_group(&group_request, &results);
        assert!(passed, "published group failed: {comment}");
        assert!(
            comment.contains("reused base receipt 9001 from run 500"),
            "missing reuse provenance in comment: {comment}"
        );
        assert!(
            !comment.contains("ran on the same host in this job."),
            "reused base must not falsely claim in-job base execution: {comment}"
        );
    }

    /// Key-field mismatch witness (#1918): mismatching ANY key field (base SHA,
    /// runner_name, hardware_model, product_build, fixture archive/inputs/content,
    /// rust-toolchain.toml hash, entitlements.plist hash, hypervisor_entitlement,
    /// dof_present, profile, phase) is a logged miss that runs `PairSide::Base`.
    #[test]
    fn reuse_misses_and_runs_base_on_every_key_field_mismatch() {
        let bench = ReuseBench::new();
        let base_receipt = bench.receipt_for(&bench.base);
        let (artifact_name, artifact_dir) =
            bench.publish_main_reusable_artifact(500, &base_receipt);

        // Prepare a valid downloaded reuse_dir first so we can also test
        // spoofing/collision and direct execute_pair key verification per field.
        bench.write_gh_state(
            vec![bench.trusted_main_run(500)],
            vec![json!({
                "id": 9001,
                "name": artifact_name,
                "expired": false,
                "workflow_run": { "id": 500 },
                "dir": artifact_dir,
            })],
        );
        let base_request = Request {
            kind: RequestKind::MergeGroup,
            prs: vec![42],
            sha: bench.head.clone(),
            base: bench.base.clone(),
        };
        let valid_reuse = bench.dir.path().join("valid-reuse");
        let ok = bench.run_lookup(
            &base_request,
            &bench.bundle.archive,
            &bench.host,
            &valid_reuse,
        );
        assert!(ok.status.success());
        assert!(
            valid_reuse.join("base-seal.json").exists(),
            "baseline lookup must succeed before field-mismatch mutations"
        );

        // Alternate git commits for base_sha, toolchain, and entitlements changes.
        git_cmd(
            &bench.repo,
            &["checkout", "-q", "-b", "alt-toolchain", &bench.base],
        );
        std::fs::write(
            bench.repo.join("rust-toolchain.toml"),
            b"[toolchain]\nchannel = \"1.97.0\"\n",
        )
        .unwrap();
        git_cmd(&bench.repo, &["add", "rust-toolchain.toml"]);
        git_cmd(&bench.repo, &["commit", "-q", "-m", "alt toolchain"]);
        let toolchain_sha = git_cmd(&bench.repo, &["rev-parse", "HEAD"]);

        git_cmd(
            &bench.repo,
            &["checkout", "-q", "-b", "alt-entitlements", &bench.base],
        );
        std::fs::write(
            bench.repo.join("scripts/entitlements.plist"),
            b"<plist><dict><key>com.apple.security.hypervisor</key><true/><key>extra</key><true/></dict></plist>\n",
        )
        .unwrap();
        git_cmd(&bench.repo, &["add", "scripts/entitlements.plist"]);
        git_cmd(&bench.repo, &["commit", "-q", "-m", "alt entitlements"]);
        let entitlements_sha = git_cmd(&bench.repo, &["rev-parse", "HEAD"]);
        git_cmd(&bench.repo, &["checkout", "-q", "main"]);

        let alt_archive_bundle = pack_test_bundle(
            &bench.dir.path().join("b-alt-elf"),
            &bench.base,
            b"v2",
            "seed-1",
        );
        let alt_inputs_bundle = pack_test_bundle(
            &bench.dir.path().join("b-alt-in"),
            &bench.base,
            b"v1",
            "seed-2",
        );
        let toolchain_bundle = pack_test_bundle(
            &bench.dir.path().join("b-tc"),
            &toolchain_sha,
            b"v1",
            "seed-1",
        );
        let entitlements_bundle = pack_test_bundle(
            &bench.dir.path().join("b-ent"),
            &entitlements_sha,
            b"v1",
            "seed-1",
        );

        // Serve the original artifact even if a different name is requested,
        // proving field-by-field comparison refuses name collisions too.
        bench.write_gh_state(
            vec![
                bench.trusted_main_run(500),
                {
                    let mut r = bench.trusted_main_run(501);
                    r["head_sha"] = json!(toolchain_sha);
                    r
                },
                {
                    let mut r = bench.trusted_main_run(502);
                    r["head_sha"] = json!(entitlements_sha);
                    r
                },
            ],
            vec![json!({
                "id": 9001,
                "name": artifact_name,
                "expired": false,
                "serve_for_any_name": true,
                "workflow_run": { "id": 500 },
                "dir": artifact_dir,
            })],
        );

        let copy_dir = |src: &Path, dst: &Path| {
            let status = Command::new("cp")
                .args(["-R", &src.to_string_lossy(), &dst.to_string_lossy()])
                .status()
                .unwrap();
            assert!(status.success());
        };

        // 1. Live environment/input mismatches against the valid seal.
        let env_cases: Vec<(&str, String, PathBuf, SignedHostIdentity)> = vec![
            (
                "base_sha",
                toolchain_sha.clone(),
                toolchain_bundle.archive.clone(),
                bench.host.clone(),
            ),
            (
                "host_identity.runner_name",
                bench.base.clone(),
                bench.bundle.archive.clone(),
                SignedHostIdentity {
                    runner_name: "carrick-gate-mac-2".into(),
                    ..bench.host.clone()
                },
            ),
            (
                "host_identity.hardware_model",
                bench.base.clone(),
                bench.bundle.archive.clone(),
                SignedHostIdentity {
                    hardware_model: "Mac14,9".into(),
                    ..bench.host.clone()
                },
            ),
            (
                "host_identity.product_build",
                bench.base.clone(),
                bench.bundle.archive.clone(),
                SignedHostIdentity {
                    product_build: "24E999".into(),
                    ..bench.host.clone()
                },
            ),
            (
                "fixture_archive_sha256",
                bench.base.clone(),
                alt_archive_bundle.archive.clone(),
                bench.host.clone(),
            ),
            (
                "fixture_inputs_sha256",
                bench.base.clone(),
                alt_inputs_bundle.archive.clone(),
                bench.host.clone(),
            ),
        ];

        for (field, req_base, bundle_path, host) in env_cases {
            let req = Request {
                kind: RequestKind::MergeGroup,
                prs: vec![42],
                sha: bench.head.clone(),
                base: req_base.clone(),
            };
            let out_lookup = bench.dir.path().join(format!("miss-lookup-{field}"));
            let lookup = bench.run_lookup(&req, &bundle_path, &host, &out_lookup);
            assert!(lookup.status.success(), "{field}: reuse-lookup must exit 0");
            assert!(
                !out_lookup.join("base-seal.json").exists(),
                "{field}: reuse-lookup must not write base-seal.json on mismatch"
            );
            let stderr = String::from_utf8_lossy(&lookup.stderr);
            assert!(
                stderr.contains("base reuse miss"),
                "{field}: expected logged miss reason, got stderr={stderr}"
            );

            let out_exec = bench.dir.path().join(format!("miss-exec-{field}"));
            std::fs::create_dir_all(&out_exec).unwrap();
            let ctx = ReuseExecutionContext {
                root: &bench.repo,
                bundle: &bundle_path,
                host_identity: Some(host.clone()),
                reuse_dir: &valid_reuse,
            };
            let mut sides = Vec::new();
            execute_pair(&req, &out_exec, Some(&ctx), |run| {
                sides.push(run.side);
                write_run_evidence(
                    &run.output,
                    run.receipt_name,
                    &bench.receipt_for(&run.commit),
                );
                Ok(())
            })
            .unwrap();
            assert_eq!(
                sides,
                [PairSide::Base, PairSide::Candidate],
                "{field}: mismatch must fall back to executing PairSide::Base"
            );
        }

        // 2. Sealed-key field mutations (toolchain, entitlements, hypervisor, dof, profile, phase).
        for (field, mutate_key) in [
            (
                "rust_toolchain_sha256",
                (|k: &mut serde_json::Value| k["rust_toolchain_sha256"] = json!("9".repeat(64)))
                    as fn(&mut serde_json::Value),
            ),
            ("entitlements_sha256", |k| {
                k["entitlements_sha256"] = json!("8".repeat(64));
            }),
            ("hypervisor_entitlement", |k| {
                k["hypervisor_entitlement"] = json!(false);
            }),
            ("dof_present", |k| {
                k["dof_present"] = json!(false);
            }),
            ("profile", |k| {
                k["profile"] = json!("linux-portable");
            }),
            ("phase", |k| {
                k["phase"] = json!("host");
            }),
        ] {
            let mutated_dir = bench.dir.path().join(format!("mutated-key-{field}"));
            copy_dir(&valid_reuse, &mutated_dir);
            let seal_path = mutated_dir.join("base-seal.json");
            let mut seal: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&seal_path).unwrap()).unwrap();
            mutate_key(&mut seal["reuse"]["key"]);
            let canonical = serde_json::to_string(&seal["reuse"]["key"]).unwrap();
            seal["reuse"]["key_sha256"] =
                json!(format!("{:x}", Sha256::digest(canonical.as_bytes())));
            std::fs::write(&seal_path, serde_json::to_vec_pretty(&seal).unwrap()).unwrap();

            // Serve this mutated seal via fake gh and check reuse-lookup names the field.
            bench.write_gh_state(
                vec![bench.trusted_main_run(500)],
                vec![json!({
                    "id": 9010,
                    "name": artifact_name,
                    "expired": false,
                    "workflow_run": { "id": 500 },
                    "dir": mutated_dir,
                })],
            );
            let lookup_out = bench.dir.path().join(format!("lookup-keymut-{field}"));
            let lookup = bench.run_lookup(
                &base_request,
                &bench.bundle.archive,
                &bench.host,
                &lookup_out,
            );
            assert!(lookup.status.success());
            assert!(!lookup_out.join("base-seal.json").exists(), "{field}");
            let stderr = String::from_utf8_lossy(&lookup.stderr);
            assert!(
                stderr.contains("KeyFieldMismatch") && stderr.contains(field),
                "{field}: expected KeyFieldMismatch naming {field}, got: {stderr}"
            );

            let out_exec = bench.dir.path().join(format!("exec-keymut-{field}"));
            std::fs::create_dir_all(&out_exec).unwrap();
            let ctx = ReuseExecutionContext {
                root: &bench.repo,
                bundle: &bench.bundle.archive,
                host_identity: Some(bench.host.clone()),
                reuse_dir: &mutated_dir,
            };
            let mut sides = Vec::new();
            execute_pair(&base_request, &out_exec, Some(&ctx), |run| {
                sides.push(run.side);
                write_run_evidence(
                    &run.output,
                    run.receipt_name,
                    &bench.receipt_for(&run.commit),
                );
                Ok(())
            })
            .unwrap();
            assert_eq!(
                sides,
                [PairSide::Base, PairSide::Candidate],
                "{field}: mutated key must fall back to running PairSide::Base"
            );
        }

        // Verify toolchain_sha & entitlements_sha actually produce distinct keys via compute_base_reuse_key!
        let k_base = compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &bench.bundle.archive,
        )
        .unwrap();
        let k_tc = compute_base_reuse_key(
            &bench.repo,
            &toolchain_sha,
            bench.host.clone(),
            &toolchain_bundle.archive,
        )
        .unwrap();
        let k_ent = compute_base_reuse_key(
            &bench.repo,
            &entitlements_sha,
            bench.host.clone(),
            &entitlements_bundle.archive,
        )
        .unwrap();
        assert_ne!(k_base.rust_toolchain_sha256, k_tc.rust_toolchain_sha256);
        assert_ne!(k_base.entitlements_sha256, k_ent.entitlements_sha256);
    }

    /// Tampered and stale seal witness (#1918): changed file, added file,
    /// removed file, symlink, wrong base in record, or stale seal for another
    /// key are refused as misses on lookup/execute (running `PairSide::Base`),
    /// candidate mutation after reuse installation fails `execute_pair`, and a
    /// tampered/stale reuse seal in `signed-result` fails `publish` closed.
    #[test]
    fn reuse_refuses_tampered_or_stale_seals_on_lookup_execute_and_publish() {
        let bench = ReuseBench::new();
        let base_receipt = bench.receipt_for(&bench.base);
        let (artifact_name, artifact_dir) =
            bench.publish_main_reusable_artifact(500, &base_receipt);
        bench.write_gh_state(
            vec![bench.trusted_main_run(500)],
            vec![json!({
                "id": 9001,
                "name": artifact_name,
                "expired": false,
                "workflow_run": { "id": 500 },
                "dir": artifact_dir,
            })],
        );
        let request = Request {
            kind: RequestKind::MergeGroup,
            prs: vec![42],
            sha: bench.head.clone(),
            base: bench.base.clone(),
        };
        let valid_reuse = bench.dir.path().join("valid-reuse");
        bench.run_lookup(&request, &bench.bundle.archive, &bench.host, &valid_reuse);
        assert!(valid_reuse.join("base-seal.json").exists());

        let copy_dir = |src: &Path, dst: &Path| {
            let status = Command::new("cp")
                .args(["-R", &src.to_string_lossy(), &dst.to_string_lossy()])
                .status()
                .unwrap();
            assert!(status.success());
        };

        type SealTamper = fn(&Path);
        let tampers: [(&str, &str, SealTamper); 6] = [
            ("changed_file", "InventoryTampered", |dir| {
                std::fs::write(dir.join("base/steps/el1-embed.log"), b"forged log").unwrap();
            }),
            ("added_file", "InventoryTampered", |dir| {
                std::fs::write(dir.join("base/planted.txt"), b"extra").unwrap();
            }),
            ("removed_file", "InventoryTampered", |dir| {
                std::fs::remove_file(dir.join("base/steps/el1-embed.log")).unwrap();
            }),
            ("symlink_in_base", "InventoryTampered", |dir| {
                std::os::unix::fs::symlink("/etc/hosts", dir.join("base/link")).unwrap();
            }),
            ("wrong_base_in_record", "SealBaseMismatch", |dir| {
                let p = dir.join("base-seal.json");
                let mut v: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
                v["base"] = json!("d".repeat(40));
                std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
            }),
            ("stale_seal_for_other_key", "KeyFieldMismatch", |dir| {
                let p = dir.join("base-seal.json");
                let mut v: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
                v["reuse"]["key_sha256"] = json!("e".repeat(64));
                std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
            }),
        ];

        for (label, expected_variant, tamper) in tampers {
            let tampered = bench.dir.path().join(format!("tamper-{label}"));
            copy_dir(&valid_reuse, &tampered);
            tamper(&tampered);

            bench.write_gh_state(
                vec![bench.trusted_main_run(500)],
                vec![json!({
                    "id": 9100,
                    "name": artifact_name,
                    "expired": false,
                    "workflow_run": { "id": 500 },
                    "dir": tampered,
                })],
            );
            let out_lookup = bench.dir.path().join(format!("lookup-{label}"));
            let lookup =
                bench.run_lookup(&request, &bench.bundle.archive, &bench.host, &out_lookup);
            assert!(lookup.status.success(), "{label}");
            assert!(!out_lookup.join("base-seal.json").exists(), "{label}");
            let stderr = String::from_utf8_lossy(&lookup.stderr);
            assert!(
                stderr.contains(expected_variant),
                "{label}: expected {expected_variant} in {stderr}"
            );

            let out_exec = bench.dir.path().join(format!("exec-{label}"));
            std::fs::create_dir_all(&out_exec).unwrap();
            let ctx = ReuseExecutionContext {
                root: &bench.repo,
                bundle: &bench.bundle.archive,
                host_identity: Some(bench.host.clone()),
                reuse_dir: &tampered,
            };
            let mut sides = Vec::new();
            execute_pair(&request, &out_exec, Some(&ctx), |run| {
                sides.push(run.side);
                write_run_evidence(
                    &run.output,
                    run.receipt_name,
                    &bench.receipt_for(&run.commit),
                );
                Ok(())
            })
            .unwrap();
            assert_eq!(
                sides,
                [PairSide::Base, PairSide::Candidate],
                "{label}: tampered seal must miss and run PairSide::Base"
            );
        }

        // Candidate-phase mutation of installed reused base evidence must fail hard.
        let out_cand_tamper = bench.dir.path().join("cand-tamper");
        std::fs::create_dir_all(&out_cand_tamper).unwrap();
        let ctx = ReuseExecutionContext {
            root: &bench.repo,
            bundle: &bench.bundle.archive,
            host_identity: Some(bench.host.clone()),
            reuse_dir: &valid_reuse,
        };
        let err = execute_pair(&request, &out_cand_tamper, Some(&ctx), |run| {
            write_run_evidence(
                &run.output,
                run.receipt_name,
                &bench.receipt_for(&run.commit),
            );
            std::fs::write(out_cand_tamper.join("base/injected.txt"), b"bad").unwrap();
            Ok(())
        });
        assert!(
            err.is_err(),
            "candidate mutation of reused base must fail execute_pair"
        );

        // Hosted `publish` re-verifies the reuse seal and fails closed on stale/tampered reuse metadata.
        let clean_results = bench.dir.path().join("publish-tamper-base");
        std::fs::create_dir_all(&clean_results).unwrap();
        execute_pair(&request, &clean_results, Some(&ctx), |run| {
            write_run_evidence(
                &run.output,
                run.receipt_name,
                &bench.receipt_for(&run.commit),
            );
            Ok(())
        })
        .unwrap();

        for (label, mutate_seal) in [
            (
                "wrong_key_sha256",
                (|v: &mut serde_json::Value| v["reuse"]["key_sha256"] = json!("f".repeat(64)))
                    as fn(&mut serde_json::Value),
            ),
            ("missing_artifact_id", |v| {
                v["reuse"].as_object_mut().unwrap().remove("artifact_id");
            }),
            ("stale_host_in_key", |v| {
                v["reuse"]["key"]["host_identity"]["runner_name"] = json!("other-mac");
                let c = serde_json::to_string(&v["reuse"]["key"]).unwrap();
                v["reuse"]["key_sha256"] = json!(format!("{:x}", Sha256::digest(c.as_bytes())));
            }),
        ] {
            let case_results = bench.dir.path().join(format!("pub-tamper-{label}"));
            copy_dir(&clean_results, &case_results);
            let p = case_results.join("base-seal.json");
            let mut v: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
            mutate_seal(&mut v);
            std::fs::write(&p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
            let (passed, comment, _, _) = bench.publish_group(&request, &case_results);
            assert!(
                !passed,
                "{label}: publish must fail closed on tampered reuse seal, got PASS: {comment}"
            );
        }
    }

    /// Verdict-equivalence witness (#1918 + #2045): publishing with a reused
    /// base receipt produces identical `diff.json` and pass/fail as a freshly
    /// computed paired base across passing, blocking-regression, and
    /// incomplete/advisory-base (#2045) scenarios.
    #[test]
    fn reused_receipt_verdict_equals_fresh_paired_base_verdict() {
        let bench = ReuseBench::new();
        let request = Request {
            kind: RequestKind::MergeGroup,
            prs: vec![77],
            sha: bench.head.clone(),
            base: bench.base.clone(),
        };

        let complete_base = bench.receipt_for(&bench.base);
        let (art_name, art_dir) = bench.publish_main_reusable_artifact(500, &complete_base);
        bench.write_gh_state(
            vec![bench.trusted_main_run(500)],
            vec![json!({
                "id": 9001,
                "name": art_name,
                "expired": false,
                "workflow_run": { "id": 500 },
                "dir": art_dir,
            })],
        );
        let complete_reuse = bench.dir.path().join("complete-reuse");
        bench.run_lookup(
            &request,
            &bench.bundle.archive,
            &bench.host,
            &complete_reuse,
        );
        assert!(complete_reuse.join("base-seal.json").exists());

        // Also build a sealed reuse directory whose base receipt is incomplete (#2045)
        // to prove `paired_base_gaps` is derived afresh and never cached.
        let mut advisory_base = bench.receipt_for(&bench.base);
        advisory_base.steps[2].not_run_tests = vec!["el1::unrun_a".into(), "el1::unrun_b".into()];
        let advisory_reuse = bench.dir.path().join("advisory-reuse");
        std::fs::create_dir_all(advisory_reuse.join("base")).unwrap();
        write_run_evidence(&advisory_reuse.join("base"), "base.json", &advisory_base);
        let key = compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &bench.bundle.archive,
        )
        .unwrap();
        let files = inventory(&advisory_reuse.join("base"));
        std::fs::write(
            advisory_reuse.join("base-seal.json"),
            serde_json::to_vec_pretty(&json!({
                "base": bench.base,
                "files": files,
                "reuse": {
                    "key": key,
                    "key_sha256": key.key_sha256().unwrap(),
                    "source_run_id": 501u64,
                    "artifact_id": 9002u64,
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let clean_candidate = bench.receipt_for(&bench.head);
        let mut regressing_candidate = bench.receipt_for(&bench.head);
        regressing_candidate.steps[2]
            .failed_tests
            .push("embed::introduced_regression".into());

        for (label, base_r, cand_r, reuse_dir, expect_pass) in [
            (
                "clean_pass",
                &complete_base,
                &clean_candidate,
                &complete_reuse,
                true,
            ),
            (
                "introduced_regression",
                &complete_base,
                &regressing_candidate,
                &complete_reuse,
                false,
            ),
            (
                "advisory_incomplete_base_passes",
                &advisory_base,
                &clean_candidate,
                &advisory_reuse,
                true,
            ),
            (
                "advisory_incomplete_base_with_regression_blocks",
                &advisory_base,
                &regressing_candidate,
                &advisory_reuse,
                false,
            ),
        ] {
            let fresh_out = bench.dir.path().join(format!("fresh-{label}"));
            std::fs::create_dir_all(&fresh_out).unwrap();
            execute_pair(&request, &fresh_out, None, |run| {
                let r = if run.side == PairSide::Base {
                    base_r
                } else {
                    cand_r
                };
                write_run_evidence(&run.output, run.receipt_name, r);
                Ok(())
            })
            .unwrap();

            let reused_out = bench.dir.path().join(format!("reused-{label}"));
            std::fs::create_dir_all(&reused_out).unwrap();
            let ctx = ReuseExecutionContext {
                root: &bench.repo,
                bundle: &bench.bundle.archive,
                host_identity: Some(bench.host.clone()),
                reuse_dir,
            };
            let mut reused_sides = Vec::new();
            execute_pair(&request, &reused_out, Some(&ctx), |run| {
                reused_sides.push(run.side);
                write_run_evidence(&run.output, run.receipt_name, cand_r);
                Ok(())
            })
            .unwrap();
            assert_eq!(reused_sides, [PairSide::Candidate], "{label}");

            let (fresh_pass, fresh_comment, fresh_diff, fresh_desc) =
                bench.publish_group(&request, &fresh_out);
            let (reused_pass, reused_comment, reused_diff, reused_desc) =
                bench.publish_group(&request, &reused_out);

            assert_eq!(fresh_pass, expect_pass, "{label} fresh: {fresh_comment}");
            assert_eq!(
                reused_pass, fresh_pass,
                "{label} pass mismatch:\nreused={reused_comment}\nfresh={fresh_comment}"
            );
            assert_eq!(reused_diff, fresh_diff, "{label} diff.json mismatch");
            assert_eq!(
                reused_desc, fresh_desc,
                "{label} status description mismatch"
            );
            assert!(fresh_comment.contains("ran on the same host in this job."));
            assert!(!reused_comment.contains("ran on the same host in this job."));
            assert!(reused_comment.contains("reused base receipt "));
            if label.starts_with("advisory_incomplete_base") {
                assert!(reused_comment.contains("Advisory: the paired base is incomplete"));
            }
        }
    }

    fn recompress_bundle_archive(src: &Path, dst: &Path) {
        use flate2::{Compression, read::MultiGzDecoder, write::GzEncoder};
        use std::io::{Read, Write};

        let mut tar_bytes = Vec::new();
        MultiGzDecoder::new(std::fs::File::open(src).unwrap())
            .read_to_end(&mut tar_bytes)
            .unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
        encoder.write_all(&tar_bytes).unwrap();
        let gz_bytes = encoder.finish().unwrap();
        std::fs::write(dst, gz_bytes).unwrap();
    }

    /// The reuse key admits a base bundle only after the publisher's own
    /// object-integrity check: an archive whose object bytes no longer match
    /// the manifest's hash is refused, not keyed.
    #[test]
    fn reuse_key_refuses_a_bundle_whose_objects_are_corrupt() {
        use flate2::{Compression, read::MultiGzDecoder, write::GzEncoder};
        use std::io::Read;

        let bench = ReuseBench::new();
        let corrupt = bench.dir.path().join("corrupt.tar.gz");
        let mut source = tar::Archive::new(MultiGzDecoder::new(
            std::fs::File::open(&bench.bundle.archive).unwrap(),
        ));
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for entry in source.entries().unwrap() {
            let mut entry = entry.unwrap();
            let mut header = entry.header().clone();
            let path = entry.path().unwrap().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            if path.components().any(|c| c.as_os_str() == "objects")
                && header.entry_type().is_file()
            {
                let last = bytes.len() - 1;
                bytes[last] ^= 0xff;
            }
            builder
                .append_data(&mut header, &path, bytes.as_slice())
                .unwrap();
        }
        std::fs::write(&corrupt, builder.into_inner().unwrap().finish().unwrap()).unwrap();

        let refused =
            compute_base_reuse_key(&bench.repo, &bench.base, bench.host.clone(), &corrupt)
                .expect_err("corrupt bundle objects must be refused");
        assert!(
            matches!(refused, ReuseMissReason::FixtureBundleInvalid(_)),
            "{refused:?}"
        );
        compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &bench.bundle.archive,
        )
        .expect("intact bundle is accepted");
    }

    /// Witness A (#1918 review M1): holding every other key input constant and
    /// varying one `SignedHostIdentity` component at a time (`runner_name`,
    /// `hardware_model`, `product_build`) must change both the canonical digest
    /// (`BaseReuseKey::key_sha256`) and the artifact name
    /// (`signed-base-reuse-<base>-<key_sha256>`), and the three variants must
    /// be pairwise distinct across `compute_base_reuse_key`,
    /// `prepare-reuse-upload`, and `reuse-lookup`.
    #[test]
    fn host_identity_components_each_change_canonical_reuse_key_and_artifact_name() {
        let bench = ReuseBench::new();
        let base_key = compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &bench.bundle.archive,
        )
        .unwrap();
        let base_digest = base_key.key_sha256().unwrap();
        let base_artifact = base_key.artifact_name().unwrap();
        assert_eq!(
            base_artifact,
            format!("signed-base-reuse-{}-{base_digest}", bench.base)
        );

        let base_receipt = bench.receipt_for(&bench.base);
        let (published_base_name, base_art_dir) =
            bench.publish_main_reusable_artifact(500, &base_receipt);
        assert_eq!(published_base_name, base_artifact);

        bench.write_gh_state(
            vec![bench.trusted_main_run(500)],
            vec![json!({
                "id": 9001,
                "name": published_base_name,
                "expired": false,
                "workflow_run": { "id": 500 },
                "dir": base_art_dir,
            })],
        );
        let group_request = Request {
            kind: RequestKind::MergeGroup,
            prs: vec![42],
            sha: bench.head.clone(),
            base: bench.base.clone(),
        };

        let host_variants = [
            (
                "runner_name",
                SignedHostIdentity {
                    runner_name: "carrick-gate-mac-2".into(),
                    ..bench.host.clone()
                },
            ),
            (
                "hardware_model",
                SignedHostIdentity {
                    hardware_model: "Mac14,9".into(),
                    ..bench.host.clone()
                },
            ),
            (
                "product_build",
                SignedHostIdentity {
                    product_build: "24E999".into(),
                    ..bench.host.clone()
                },
            ),
        ];

        let mut observed = Vec::new();
        for (idx, (component, alt_host)) in host_variants.into_iter().enumerate() {
            let alt_key = compute_base_reuse_key(
                &bench.repo,
                &bench.base,
                alt_host.clone(),
                &bench.bundle.archive,
            )
            .unwrap();
            let mut expected_other_fields = base_key.clone();
            expected_other_fields.host_identity = alt_host.clone();
            assert_eq!(
                alt_key, expected_other_fields,
                "{component}: non-host key input unexpectedly changed"
            );

            let alt_digest = alt_key.key_sha256().unwrap();
            let alt_artifact = alt_key.artifact_name().unwrap();
            assert_eq!(
                alt_artifact,
                format!("signed-base-reuse-{}-{alt_digest}", bench.base),
                "{component}: artifact_name must follow signed-base-reuse-<base>-<key_sha256>"
            );
            assert_ne!(
                alt_digest, base_digest,
                "{component}: varying host_identity.{component} must change key_sha256"
            );
            assert_ne!(
                alt_artifact, base_artifact,
                "{component}: varying host_identity.{component} must change artifact_name"
            );

            let mut alt_receipt = bench.receipt_for(&bench.base);
            alt_receipt.host_identity = Some(alt_host.clone());
            let (published_alt_name, _) =
                bench.publish_main_reusable_artifact(510 + idx as u64, &alt_receipt);
            assert_eq!(published_alt_name, alt_artifact, "{component}");
            assert_ne!(
                published_alt_name, published_base_name,
                "{component}: prepare-reuse-upload emitted unchanged artifact_name"
            );

            let lookup_dir = bench.dir.path().join(format!("host-name-miss-{component}"));
            let lookup = bench.run_lookup(
                &group_request,
                &bench.bundle.archive,
                &alt_host,
                &lookup_dir,
            );
            assert!(lookup.status.success(), "{component}");
            assert!(
                !lookup_dir.join("base-seal.json").exists(),
                "{component}: reuse-lookup must miss when host_identity.{component} differs"
            );
            let stderr = String::from_utf8_lossy(&lookup.stderr);
            assert!(
                stderr.contains("NoMatchingArtifact") && stderr.contains(&alt_artifact),
                "{component}: expected NoMatchingArtifact for {alt_artifact}, got: {stderr}"
            );

            observed.push((component, alt_digest, alt_artifact));
        }

        assert_eq!(observed.len(), 3);
        for i in 0..observed.len() {
            for j in (i + 1)..observed.len() {
                assert_ne!(
                    observed[i].1, observed[j].1,
                    "key_sha256 collision between {} and {}",
                    observed[i].0, observed[j].0
                );
                assert_ne!(
                    observed[i].2, observed[j].2,
                    "artifact_name collision between {} and {}",
                    observed[i].0, observed[j].0
                );
            }
        }
    }

    /// Witness B1 (#1918 review M3, `compare_reuse_keys` half): an archive-only
    /// mismatch (recompressed `.tar.gz` of the identical tar stream: every
    /// other `BaseReuseKey` field is equal, only `fixture_archive_sha256`
    /// differs) misses at `reuse-lookup` and `execute_pair` (`PairSide::Base`
    /// runs), naming `fixture_archive_sha256`.
    #[test]
    fn archive_only_key_mismatch_misses_and_names_fixture_archive_sha256() {
        let bench = ReuseBench::new();
        let recompressed_archive = bench.dir.path().join("recompressed-bundle.tar.gz");
        recompress_bundle_archive(&bench.bundle.archive, &recompressed_archive);

        let live_key = compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &bench.bundle.archive,
        )
        .unwrap();
        let alt_archive_key = compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &recompressed_archive,
        )
        .unwrap();
        assert_ne!(
            alt_archive_key.fixture_archive_sha256,
            live_key.fixture_archive_sha256
        );
        let mut expected_equal = live_key.clone();
        expected_equal.fixture_archive_sha256 = alt_archive_key.fixture_archive_sha256.clone();
        assert_eq!(
            alt_archive_key, expected_equal,
            "recompressed archive must leave manifest, inputs, content, and all other key fields equal"
        );
        assert_ne!(
            alt_archive_key.key_sha256().unwrap(),
            live_key.key_sha256().unwrap()
        );
        assert_ne!(
            alt_archive_key.artifact_name().unwrap(),
            live_key.artifact_name().unwrap()
        );

        let base_receipt = bench.receipt_for(&bench.base);
        let cand_receipt = bench.receipt_for(&bench.head);
        let (control_art_name, control_art_dir) =
            bench.publish_main_reusable_artifact(500, &base_receipt);

        let group_request = Request {
            kind: RequestKind::MergeGroup,
            prs: vec![42],
            sha: bench.head.clone(),
            base: bench.base.clone(),
        };

        bench.write_gh_state(
            vec![bench.trusted_main_run(500)],
            vec![json!({
                "id": 9001,
                "name": control_art_name,
                "expired": false,
                "workflow_run": { "id": 500 },
                "dir": control_art_dir,
            })],
        );
        let control_reuse = bench.dir.path().join("control-archive-reuse");
        let control_lookup = bench.run_lookup(
            &group_request,
            &bench.bundle.archive,
            &bench.host,
            &control_reuse,
        );
        assert!(control_lookup.status.success());
        assert!(control_reuse.join("base-seal.json").exists());

        // Pre-download lookup name miss when serving exact artifact names.
        let archive_name_miss_dir = bench.dir.path().join("archive-only-name-miss");
        let archive_name_miss = bench.run_lookup(
            &group_request,
            &recompressed_archive,
            &bench.host,
            &archive_name_miss_dir,
        );
        assert!(archive_name_miss.status.success());
        assert!(!archive_name_miss_dir.join("base-seal.json").exists());
        let name_miss_stderr = String::from_utf8_lossy(&archive_name_miss.stderr);
        assert!(
            name_miss_stderr.contains("NoMatchingArtifact")
                && name_miss_stderr.contains(&alt_archive_key.artifact_name().unwrap()),
            "expected NoMatchingArtifact for recompressed archive key, got: {name_miss_stderr}"
        );

        // Post-download lookup key check (serving control_art_dir across names)
        // must specifically name `fixture_archive_sha256` when every other field matches.
        bench.write_gh_state(
            vec![bench.trusted_main_run(500)],
            vec![json!({
                "id": 9001,
                "name": control_art_name,
                "expired": false,
                "serve_for_any_name": true,
                "workflow_run": { "id": 500 },
                "dir": control_art_dir,
            })],
        );
        let archive_key_miss_dir = bench.dir.path().join("archive-only-key-miss");
        let archive_key_miss = bench.run_lookup(
            &group_request,
            &recompressed_archive,
            &bench.host,
            &archive_key_miss_dir,
        );
        assert!(archive_key_miss.status.success());
        assert!(!archive_key_miss_dir.join("base-seal.json").exists());
        let key_miss_stderr = String::from_utf8_lossy(&archive_key_miss.stderr);
        assert!(
            key_miss_stderr.contains("KeyFieldMismatch")
                && key_miss_stderr.contains("fixture_archive_sha256"),
            "archive-only mismatch must report KeyFieldMismatch on fixture_archive_sha256, got: {key_miss_stderr}"
        );

        // Execution (`execute_pair` / `--reuse-base` install path) misses and runs PairSide::Base.
        let archive_exec_out = bench.dir.path().join("archive-only-exec");
        std::fs::create_dir_all(&archive_exec_out).unwrap();
        let archive_exec_ctx = ReuseExecutionContext {
            root: &bench.repo,
            bundle: &recompressed_archive,
            host_identity: Some(bench.host.clone()),
            reuse_dir: &control_reuse,
        };
        let mut archive_exec_sides = Vec::new();
        execute_pair(
            &group_request,
            &archive_exec_out,
            Some(&archive_exec_ctx),
            |run| {
                archive_exec_sides.push(run.side);
                let r = if run.side == PairSide::Base {
                    &base_receipt
                } else {
                    &cand_receipt
                };
                write_run_evidence(&run.output, run.receipt_name, r);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            archive_exec_sides,
            [PairSide::Base, PairSide::Candidate],
            "archive-only mismatch must miss and run PairSide::Base"
        );
        let archive_exec_seal: serde_json::Value = serde_json::from_slice(
            &std::fs::read(archive_exec_out.join("base-seal.json")).unwrap(),
        )
        .unwrap();
        assert!(
            archive_exec_seal["reuse"].is_null(),
            "archive-only miss must seal fresh in-job base without reuse metadata"
        );
    }

    /// Witness B2 (#1918 review M3, `verify_receipt_matches_key` half): a
    /// coherent sealed receipt with a populated `fixture_bundle` whose
    /// `archive_sha256` alone disagrees with the live bundle/key is refused at
    /// `prepare-reuse-upload`, misses at `reuse-lookup` and `execute_pair`
    /// (`PairSide::Base` runs), and fails closed at `publish`, each naming
    /// `fixture_bundle.archive_sha256`, while a matching coherent
    /// `fixture_bundle` receipt is accepted across all four boundaries
    /// (control).
    #[test]
    fn receipt_fixture_bundle_archive_disagreement_refuses_upload_lookup_execute_and_publish() {
        let bench = ReuseBench::new();
        let recompressed_archive = bench.dir.path().join("recompressed-bundle.tar.gz");
        recompress_bundle_archive(&bench.bundle.archive, &recompressed_archive);

        let live_key = compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &bench.bundle.archive,
        )
        .unwrap();
        let alt_archive_key = compute_base_reuse_key(
            &bench.repo,
            &bench.base,
            bench.host.clone(),
            &recompressed_archive,
        )
        .unwrap();
        assert_ne!(
            alt_archive_key.fixture_archive_sha256,
            live_key.fixture_archive_sha256
        );

        let make_bundle_receipt = |archive_path: &Path, archive_sha256: &str| {
            carrick_xtask::accept::FixtureBundleReceipt {
                source: "local".into(),
                path: archive_path.to_string_lossy().into_owned(),
                captured_path: archive_path.to_string_lossy().into_owned(),
                identity: bench.bundle.manifest_sha256.clone(),
                archive_sha256: archive_sha256.to_owned(),
            }
        };

        // Control: coherent receipt with populated `fixture_bundle` matching live bundle/key.
        let mut matching_base_receipt = bench.receipt_for(&bench.base);
        matching_base_receipt.fixture_bundle = Some(make_bundle_receipt(
            &bench.bundle.archive,
            &live_key.fixture_archive_sha256,
        ));
        let mut matching_cand_receipt = bench.receipt_for(&bench.head);
        matching_cand_receipt.fixture_bundle = Some(make_bundle_receipt(
            &bench.bundle.archive,
            &live_key.fixture_archive_sha256,
        ));

        let (control_art_name, control_art_dir) =
            bench.publish_main_reusable_artifact(500, &matching_base_receipt);
        assert_eq!(control_art_name, live_key.artifact_name().unwrap());

        let group_request = Request {
            kind: RequestKind::MergeGroup,
            prs: vec![42],
            sha: bench.head.clone(),
            base: bench.base.clone(),
        };

        bench.write_gh_state(
            vec![bench.trusted_main_run(500)],
            vec![json!({
                "id": 9001,
                "name": control_art_name,
                "expired": false,
                "workflow_run": { "id": 500 },
                "dir": control_art_dir,
            })],
        );
        let control_reuse = bench.dir.path().join("control-fb-reuse");
        let control_lookup = bench.run_lookup(
            &group_request,
            &bench.bundle.archive,
            &bench.host,
            &control_reuse,
        );
        assert!(
            control_lookup.status.success(),
            "control lookup failed: {}",
            String::from_utf8_lossy(&control_lookup.stderr)
        );
        assert!(
            control_reuse.join("base-seal.json").exists(),
            "control lookup must accept matching populated fixture_bundle: {}",
            String::from_utf8_lossy(&control_lookup.stderr)
        );

        let control_results = bench.dir.path().join("control-fb-results");
        std::fs::create_dir_all(&control_results).unwrap();
        let control_ctx = ReuseExecutionContext {
            root: &bench.repo,
            bundle: &bench.bundle.archive,
            host_identity: Some(bench.host.clone()),
            reuse_dir: &control_reuse,
        };
        let mut control_sides = Vec::new();
        execute_pair(
            &group_request,
            &control_results,
            Some(&control_ctx),
            |run| {
                control_sides.push(run.side);
                write_run_evidence(&run.output, run.receipt_name, &matching_cand_receipt);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            control_sides,
            [PairSide::Candidate],
            "matching populated fixture_bundle must reuse base without running PairSide::Base"
        );
        let (control_passed, control_comment, _, _) =
            bench.publish_group(&group_request, &control_results);
        assert!(
            control_passed,
            "control publish must pass: {control_comment}"
        );
        assert!(
            control_comment.contains("reused base receipt 9001 from run 500"),
            "control comment missing reuse provenance: {control_comment}"
        );

        // Disagreeing receipt: populated `fixture_bundle` whose `archive_sha256`
        // alone disagrees with the live bundle/key.
        let mut disagreeing_base_receipt = matching_base_receipt.clone();
        disagreeing_base_receipt
            .fixture_bundle
            .as_mut()
            .unwrap()
            .archive_sha256 = alt_archive_key.fixture_archive_sha256.clone();

        // (a) `prepare-reuse-upload` refuses to stage a receipt whose `fixture_bundle.archive_sha256`
        // disagrees with `--fixture-bundle`.
        let bad_main_dir = bench.dir.path().join("bad-fb-main");
        let bad_main_results = bad_main_dir.join("results");
        std::fs::create_dir_all(&bad_main_results).unwrap();
        write_run_evidence(
            &bad_main_results,
            "candidate.json",
            &disagreeing_base_receipt,
        );
        let bad_main_req = bad_main_dir.join("request.json");
        std::fs::write(
            &bad_main_req,
            serde_json::to_vec(&Request {
                kind: RequestKind::Main,
                prs: vec![],
                sha: bench.base.clone(),
                base: bench.base.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        let bad_prep_out = bad_main_dir.join("staged");
        let bad_prep = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["--root", &bench.repo.to_string_lossy()])
            .args(["signed-gate", "prepare-reuse-upload", "--request"])
            .arg(&bad_main_req)
            .arg("--results")
            .arg(&bad_main_results)
            .arg("--fixture-bundle")
            .arg(&bench.bundle.archive)
            .args(["--run-id", "555", "--output"])
            .arg(&bad_prep_out)
            .output()
            .unwrap();
        assert!(
            !bad_prep.status.success(),
            "prepare-reuse-upload must refuse disagreeing fixture_bundle.archive_sha256"
        );
        let bad_prep_stderr = String::from_utf8_lossy(&bad_prep.stderr);
        assert!(
            bad_prep_stderr.contains("ReceiptKeyInconsistent")
                && bad_prep_stderr.contains("fixture_bundle.archive_sha256"),
            "prepare-reuse-upload must name fixture_bundle.archive_sha256, got: {bad_prep_stderr}"
        );

        // Build a coherent sealed reuse directory (`files` inventory matches `base/base.json`,
        // `reuse.key` and `reuse.key_sha256` match `live_key`) where ONLY
        // `base.json`'s `fixture_bundle.archive_sha256` disagrees.
        let copy_dir = |src: &Path, dst: &Path| {
            let status = Command::new("cp")
                .args(["-R", &src.to_string_lossy(), &dst.to_string_lossy()])
                .status()
                .unwrap();
            assert!(status.success());
        };
        let coherent_bad_fb_reuse = bench.dir.path().join("coherent-bad-fb-reuse");
        copy_dir(&control_reuse, &coherent_bad_fb_reuse);
        std::fs::write(
            coherent_bad_fb_reuse.join("base/base.json"),
            serde_json::to_vec_pretty(&disagreeing_base_receipt).unwrap(),
        )
        .unwrap();
        let bad_fb_seal_path = coherent_bad_fb_reuse.join("base-seal.json");
        let mut bad_fb_seal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bad_fb_seal_path).unwrap()).unwrap();
        bad_fb_seal["files"] = json!(inventory(&coherent_bad_fb_reuse.join("base")));
        std::fs::write(
            &bad_fb_seal_path,
            serde_json::to_vec_pretty(&bad_fb_seal).unwrap(),
        )
        .unwrap();

        // (b) `reuse-lookup` rejects the coherent package on `fixture_bundle.archive_sha256`.
        bench.write_gh_state(
            vec![bench.trusted_main_run(500)],
            vec![json!({
                "id": 9001,
                "name": control_art_name,
                "expired": false,
                "workflow_run": { "id": 500 },
                "dir": coherent_bad_fb_reuse,
            })],
        );
        let bad_fb_lookup_dir = bench.dir.path().join("bad-fb-lookup-out");
        let bad_fb_lookup = bench.run_lookup(
            &group_request,
            &bench.bundle.archive,
            &bench.host,
            &bad_fb_lookup_dir,
        );
        assert!(bad_fb_lookup.status.success());
        assert!(
            !bad_fb_lookup_dir.join("base-seal.json").exists(),
            "reuse-lookup must reject disagreeing fixture_bundle.archive_sha256"
        );
        let bad_fb_lookup_stderr = String::from_utf8_lossy(&bad_fb_lookup.stderr);
        assert!(
            bad_fb_lookup_stderr.contains("ReceiptKeyInconsistent")
                && bad_fb_lookup_stderr.contains("fixture_bundle.archive_sha256"),
            "reuse-lookup must name fixture_bundle.archive_sha256, got: {bad_fb_lookup_stderr}"
        );

        // (c) `execute_pair` (`--reuse-base` install path) rejects the coherent package
        // and runs `PairSide::Base` in-job.
        let bad_fb_exec_out = bench.dir.path().join("bad-fb-exec-out");
        std::fs::create_dir_all(&bad_fb_exec_out).unwrap();
        let bad_fb_exec_ctx = ReuseExecutionContext {
            root: &bench.repo,
            bundle: &bench.bundle.archive,
            host_identity: Some(bench.host.clone()),
            reuse_dir: &coherent_bad_fb_reuse,
        };
        let mut bad_fb_exec_sides = Vec::new();
        execute_pair(
            &group_request,
            &bad_fb_exec_out,
            Some(&bad_fb_exec_ctx),
            |run| {
                bad_fb_exec_sides.push(run.side);
                let r = if run.side == PairSide::Base {
                    &matching_base_receipt
                } else {
                    &matching_cand_receipt
                };
                write_run_evidence(&run.output, run.receipt_name, r);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            bad_fb_exec_sides,
            [PairSide::Base, PairSide::Candidate],
            "disagreeing fixture_bundle.archive_sha256 must miss and run PairSide::Base"
        );
        let bad_fb_exec_seal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bad_fb_exec_out.join("base-seal.json")).unwrap())
                .unwrap();
        assert!(bad_fb_exec_seal["reuse"].is_null());

        // (d) `publish` refuses a coherent reuse seal whose base receipt's
        // `fixture_bundle.archive_sha256` disagrees with `reuse.key.fixture_archive_sha256`.
        let bad_fb_publish_results = bench.dir.path().join("bad-fb-publish-results");
        copy_dir(&control_results, &bad_fb_publish_results);
        std::fs::write(
            bad_fb_publish_results.join("base/base.json"),
            serde_json::to_vec_pretty(&disagreeing_base_receipt).unwrap(),
        )
        .unwrap();
        let pub_seal_path = bad_fb_publish_results.join("base-seal.json");
        let mut pub_seal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&pub_seal_path).unwrap()).unwrap();
        pub_seal["files"] = json!(inventory(&bad_fb_publish_results.join("base")));
        std::fs::write(
            &pub_seal_path,
            serde_json::to_vec_pretty(&pub_seal).unwrap(),
        )
        .unwrap();

        let (bad_pub_passed, bad_pub_comment, _, _) =
            bench.publish_group(&group_request, &bad_fb_publish_results);
        assert!(
            !bad_pub_passed,
            "publish must fail closed on disagreeing fixture_bundle.archive_sha256: {bad_pub_comment}"
        );
        assert!(
            bad_pub_comment.contains("ReceiptKeyInconsistent")
                && bad_pub_comment.contains("fixture_bundle.archive_sha256"),
            "publish comment must name fixture_bundle.archive_sha256, got: {bad_pub_comment}"
        );
    }
}
