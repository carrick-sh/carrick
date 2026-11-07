#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::accept::{AcceptReceipt, ProbeDiff};
use carrick_xtask::signed_gate::{allowed, label_authorized, trusted_run, validate_receipt};
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
fn baseline_workflow_provenance_and_receipt_admission_fail_closed() {
    let run = json!({"path":".github/workflows/signed-gate.yml","head_branch":"main","event":"workflow_dispatch","status":"completed","repository":{"full_name":"carrick-sh/carrick"},"head_repository":{"full_name":"carrick-sh/carrick"},"actor":{"login":"tjfontaine"},"triggering_actor":{"login":"tjfontaine"}});
    assert!(trusted_run(&run));
    let mut pushed = run.clone();
    pushed["event"] = json!("push");
    pushed["actor"]["login"] = json!("github-merge-queue[bot]");
    pushed["triggering_actor"]["login"] = json!("github-merge-queue[bot]");
    assert!(trusted_run(&pushed));
    pushed["head_repository"]["full_name"] = json!("someone/fork");
    assert!(!trusted_run(&pushed));
    let mut bot = run.clone();
    bot["triggering_actor"]["login"] = json!("carrick-workers[bot]");
    assert!(!trusted_run(&bot));
    let mut wrong = run.clone();
    wrong["head_branch"] = json!("feature");
    assert!(!trusted_run(&wrong));
    wrong = run;
    wrong["triggering_actor"]["login"] = json!("someone-else");
    assert!(!trusted_run(&wrong));
    assert!(validate_receipt(&base(), &"a".repeat(40)).is_err());
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
    value["fixture_validation"] = json!({"validation_method":"input_identity","elf_hash_verification":"recomputed","checkout_head":head,"checkout_tree":"3".repeat(40),"bundle_source_head":"a".repeat(40),"checkout_dirty":false,"manifest_sha256":"4".repeat(64),"inputs_sha256":"5".repeat(64)});
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
fn actions_prepare_download_and_publish_use_exact_baseline_and_fail_closed() {
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
os.execv({real_git:?}, ['git'] + args)
"#)).unwrap();
    std::fs::set_permissions(&git_shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    let gh = bin.join("gh");
    std::fs::write(&gh, r#"#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
base, head = os.environ['TEST_BASE_SHA'], os.environ['TEST_HEAD_SHA']
if args[:2] == ['run', 'watch']:
    assert args[2] == '100'
    pathlib.Path(os.environ['TEST_POSTS']+'.waited').touch()
elif args[:2] == ['run', 'download']:
    assert args[2] == '100' and args[args.index('--name')+1] == 'signed-baseline-'+base+'-2'
    shutil.copyfile(os.environ['TEST_BASE'], pathlib.Path(args[args.index('--dir')+1])/'candidate.json')
elif '--method' in args and args[args.index('--method')+1] == 'POST':
    endpoint = args[args.index('POST')+1]
    with open(os.environ['TEST_POSTS'], 'a') as out:
        out.write(json.dumps({'endpoint':endpoint,'body':json.load(sys.stdin)})+'\n')
elif args[:2] == ['api', 'graphql']:
    nodes = json.loads(os.environ.get('TEST_QUEUE_ENTRIES', '[]'))
    print(json.dumps({'data':{'repository':{'mergeQueue':{'entries':{'nodes':nodes}}}}}))
elif args[0] == 'api':
    endpoint = args[-1]
    if '/pulls/' in endpoint:
        print(json.dumps({'state':'open','head':{'sha':head},'base':{'ref':'main'}}))
    elif '/compare/' in endpoint:
        print(json.dumps({'merge_base_commit':{'sha':base}}))
    elif '/commits/' in endpoint and '/pulls?' in endpoint:
        print(json.dumps([[]]))
    elif '/actions/runs/100' == endpoint[-17:]:
        print(json.dumps({'id':100,'path':'.github/workflows/signed-gate.yml','head_branch':'main','event':'push','head_sha':base,'status':'completed','repository':{'full_name':'carrick-sh/carrick'},'head_repository':{'full_name':'carrick-sh/carrick'}}))
    elif '/workflows/signed-gate.yml/runs' in endpoint:
        run = {'id':100,'path':'.github/workflows/signed-gate.yml','head_branch':'main','event':'workflow_dispatch','status':'completed','repository':{'full_name':'carrick-sh/carrick'},'head_repository':{'full_name':'carrick-sh/carrick'},'actor':{'login':'tjfontaine'},'triggering_actor':{'login':'tjfontaine'}}
        if os.environ.get('TEST_AUTOMATIC_BASE'):
            run.update(event='push', head_sha=base)
        if os.environ.get('TEST_PENDING_BASE'):
            run.update(event='push', head_sha=base, status='in_progress')
        discovery = pathlib.Path(os.environ['TEST_POSTS']+'.discovered')
        if os.environ.get('TEST_PENDING_BASE') and not discovery.exists():
            discovery.touch()
            print(json.dumps([{'workflow_runs':[]}]))
        else:
            print(json.dumps([{'workflow_runs':[run]}]))
    elif '/events?' in endpoint:
        print(json.dumps([[{'id':1,'event':'labeled','label':{'name':'gate:signed'},'actor':{'login':os.environ.get('TEST_LABEL_ACTOR','tjfontaine')}}]]))
    elif '/artifacts?' in endpoint:
        rows = [] if os.environ.get('TEST_NO_BASE') else [{'name':'signed-baseline-'+base+'-4','expired':True},{'name':'signed-baseline-'+base+'-1','expired':False},{'name':'signed-baseline-'+base+'-2','expired':False}]
        print(json.dumps([{'artifacts':rows}]))
    else:
        raise SystemExit('unexpected API endpoint: '+endpoint)
else:
    raise SystemExit('unexpected gh invocation: '+repr(args))
"#).unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let base = admitted(&a);
    let baseline_path = dir.path().join("source-base.json");
    std::fs::write(&baseline_path, serde_json::to_vec(&base).unwrap()).unwrap();
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
        .env("TEST_BASE", &baseline_path)
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
    assert_eq!(
        std::fs::read(request_dir.join("base.json")).unwrap(),
        std::fs::read(&baseline_path).unwrap()
    );
    let missing = child()
        .env("TEST_NO_BASE", "1")
        .args(["signed-gate", "prepare", "--event"])
        .arg(&event)
        .arg("--output")
        .arg(dir.path().join("no-baseline"))
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("pr=main"));
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

    let queue_ref = "refs/heads/gh-readonly-queue/main/pr-123-test";
    let queue_event = dir.path().join("queue.json");
    let queue_payload = json!({"repository":{"full_name":"carrick-sh/carrick"},"action":"checks_requested","merge_group":{"base_ref":"refs/heads/main","head_ref":queue_ref,"head_sha":b.clone(),"base_sha":a.clone()}});
    std::fs::write(&queue_event, queue_payload.to_string()).unwrap();
    let queue_dir = dir.path().join("queue-request");
    let queue_with_entries = |payload: &serde_json::Value, entries: &str| {
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
            .env("GITHUB_SHA", b.clone())
            .env("TEST_PENDING_BASE", "1")
            .env("TEST_QUEUE_ENTRIES", entries)
            .args(["signed-gate", "prepare", "--event"])
            .arg(&queue_event)
            .arg("--output")
            .arg(&queue_dir)
            .output()
            .unwrap()
    };
    let live_predecessor = serde_json::json!([{
        "baseCommit": {"oid": d},
        "headCommit": {"oid": d},
        "pullRequest": {
            "number": 123,
            "baseRefName": "main",
            "baseRepository": {"nameWithOwner": "carrick-sh/carrick"}
        }
    }])
    .to_string();
    let queue = |payload: &serde_json::Value| queue_with_entries(payload, &live_predecessor);
    let queued = queue(&queue_payload);
    assert!(
        queued.status.success(),
        "{}",
        String::from_utf8_lossy(&queued.stderr)
    );
    assert!(posts.with_extension("jsonl.waited").exists());
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
        .env("TEST_NO_BASE", "1")
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
        cmd.env("TEST_BASE_SHA", &b)
            .env("TEST_HEAD_SHA", &c)
            .env("TEST_AUTOMATIC_BASE", "1");
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
    std::fs::write(&baseline_path, serde_json::to_vec(&admitted(&b)).unwrap()).unwrap();
    let mut next_queue = queue_payload;
    next_queue["merge_group"]["head_sha"] = json!(c.clone());
    next_queue["merge_group"]["base_sha"] = json!(b.clone());
    std::fs::write(&queue_event, next_queue.to_string()).unwrap();
    let queued = next_child()
        .env("GITHUB_EVENT_NAME", "merge_group")
        .env("GITHUB_REF", queue_ref)
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
    print(json.dumps({{'data': {{'repository': {{'mergeQueue': {{'entries': {{'nodes': nodes}}}}}}}}}}))
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
        print(json.dumps([[{{'number': 901, 'base': {{'ref': 'main', 'repo': {{'full_name': 'carrick-sh/carrick'}}}}}}]]))
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
    let ref_1700 = format!("refs/heads/gh-readonly-queue/main/pr-1700-{a}");
    let ref_1801 = format!("refs/heads/gh-readonly-queue/main/pr-1801-{a}");
    git(&["update-ref", &ref_1762, &d]);
    git(&["update-ref", &ref_1788, &b]);
    git(&["update-ref", &ref_1799, &c]);
    git(&["update-ref", &ref_1700, &stale]);
    git(&["update-ref", &ref_1801, &batched]);

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
                "baseCommit": { "oid": c },
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
    print(json.dumps({'data': {'repository': {'mergeQueue': {'entries': {'nodes': nodes}}}}}))
elif args[0] == 'api':
    endpoint = args[-1]
    if '/commits/' in endpoint and '/pulls?' in endpoint:
        sha = endpoint.split('/commits/')[1].split('/pulls', 1)[0]
        merged = json.loads(pathlib.Path(os.environ['TEST_MERGED_PULLS']).read_text())
        rows = [
            {'number': n, 'base': {'ref': 'main', 'repo': {'full_name': 'carrick-sh/carrick'}}}
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

    let run_prepare = |label: &str, head_ref: &str, base_sha: &str, head_sha: &str| {
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
            .env("GITHUB_REF", head_ref)
            .env("GITHUB_SHA", head_sha)
            .env("TEST_GRAPH", &repo)
            .env("TEST_BASE", &baseline_path)
            .env("TEST_BASE_SHA", &a)
            .env("TEST_ENTRIES", &entries_path)
            .env("TEST_MERGED_PULLS", &merged_pulls_path)
            .env("TEST_POSTS", &posts_path)
            .env_remove("GITHUB_OUTPUT")
            .args(["signed-gate", "prepare", "--event"])
            .arg(&event_path)
            .arg("--output")
            .arg(&out_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
    let (batched_req, _) = run_prepare("batched", &ref_1801, &a, &batched);
    assert_eq!(batched_req["base"], a);
    assert_eq!(batched_req["prs"], json!([1801, 1802]));

    // (4) Publish names both PRs in comment.md, GITHUB_STEP_SUMMARY, and PR comments
    // on both PASS and FAIL paths.
    let results = dir.path().join("results");
    std::fs::create_dir(&results).unwrap();
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
