#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::accept::{AcceptReceipt, ProbeDiff};
use carrick_xtask::signed_gate::{allowed, label_authorized, validate_receipt};
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
    use std::os::unix::fs::PermissionsExt;
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
    std::fs::write(&git_shim, format!(r#"#!/usr/bin/env python3
import os, sys
args = [os.environ['TEST_GRAPH'] if a == 'https://github.com/carrick-sh/carrick.git' else a for a in sys.argv[1:]]
if args[:2] == ['ls-remote', '--refs'] and os.environ.get('TEST_HIDE_QUEUE_REFS'):
    raise SystemExit(0)
os.execv({real_git:?}, ['git'] + args)
"#)).unwrap();
    std::fs::set_permissions(&git_shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let gh = bin.join("gh");
    std::fs::write(&gh, r#"#!/usr/bin/env python3
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
"#).unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
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
    std::fs::remove_file(candidate_path).unwrap();
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
    use std::os::unix::fs::PermissionsExt;
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
    std::fs::write(
        &git_shim,
        format!(
            "#!/usr/bin/env python3\nimport os, sys\nargs = [os.environ['TEST_GRAPH'] if a == 'https://github.com/carrick-sh/carrick.git' else a for a in sys.argv[1:]]\nos.execv({real_git:?}, ['git'] + args)\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&git_shim, std::fs::Permissions::from_mode(0o755)).unwrap();

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
    std::fs::write(
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
    )
    .unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();

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
    use std::os::unix::fs::PermissionsExt;
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
    std::fs::write(
        &git_shim,
        format!(
            "#!/usr/bin/env python3\nimport os, sys\nargs = [os.environ['TEST_GRAPH'] if a == 'https://github.com/carrick-sh/carrick.git' else a for a in sys.argv[1:]]\nif args[:2] == ['ls-remote', '--refs'] and os.environ.get('TEST_HIDE_QUEUE_REFS') == '1': raise SystemExit(0)\nos.execv({real_git:?}, ['git'] + args)\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&git_shim, std::fs::Permissions::from_mode(0o755)).unwrap();

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
    std::fs::write(
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
    )
    .unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();

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
fn base_selection_prefers_matching_host_and_bundle_over_newest() {
    use carrick_xtask::signed_receipt::select_base;
    let candidate = base();
    let mut other = candidate.clone();
    other.host_identity.as_mut().unwrap().runner_name = "other-mac".into();
    let bases = [other, candidate.clone()];
    assert!(std::ptr::eq(
        select_base(&bases, &candidate).unwrap(),
        &bases[1]
    ));
    assert!(
        select_base(&bases[..1], &candidate)
            .unwrap_err()
            .to_string()
            .contains("incomparable base")
    );
    assert!(select_base(&[], &candidate).is_err());
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
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::write(
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
        )
        .unwrap();
        std::fs::set_permissions(bin.join("gh"), std::fs::Permissions::from_mode(0o755)).unwrap();
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

/// Review P1 on #1889: an interrupted paired base must block before any
/// comparison. Its killed binary would otherwise read as FIXED and let a
/// complete candidate PASS. Completed known failures stay comparable.
#[cfg(unix)]
#[test]
fn incomplete_paired_base_blocks_publication_but_known_failures_compare() {
    let bench = PublishBench::new();
    let candidate = admitted(&bench.head);
    bench.write_candidate(&candidate, false);

    // Completed base with the same itemized failures: differential PASS.
    let complete = admitted(&bench.base);
    bench.write_base(&complete, false);
    let (passed, body) = bench.publish();
    assert!(
        passed,
        "completed known failures must stay comparable: {body}"
    );

    // The reviewer's case: an unfinished base binary, complete candidate.
    let mut unfinished = complete.clone();
    unfinished.steps[2].unfinished_binaries.push("embed".into());
    bench.write_base(&unfinished, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "unfinished base binary published PASS: {body}");
    assert!(body.contains("paired base incomplete"), "{body}");

    // A base that never reported a step (NotRun) cannot be admitted either.
    let mut not_run = complete.clone();
    not_run.steps[3].passed = false;
    not_run.steps[3].exit_code = None;
    not_run.steps[3].failed_tests.clear();
    bench.write_base(&not_run, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "NotRun base step published PASS: {body}");
    assert!(body.contains("paired base incomplete"), "{body}");

    // Tests skipped after the binary budget expired are an interrupted run.
    let mut interrupted = complete.clone();
    interrupted.steps[4]
        .not_run_tests
        .push("probe::after_budget".into());
    bench.write_base(&interrupted, false);
    let (passed, body) = bench.publish();
    assert!(!passed, "interrupted base published PASS: {body}");
    assert!(body.contains("paired base incomplete"), "{body}");

    // A failing acceptance exit with nothing completed to explain it is an
    // infrastructure failure, even when every recorded step passed.
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
        !passed,
        "unexplained base acceptance failure published PASS: {body}"
    );
    assert!(body.contains("paired base incomplete"), "{body}");
    // Missing exit evidence is not success.
    std::fs::remove_file(bench.results().join("base/accept-exit.json")).unwrap();
    let (passed, body) = bench.publish();
    assert!(!passed, "missing base exit status published PASS: {body}");
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
        let result = execute_pair(&request, output, |run| {
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
