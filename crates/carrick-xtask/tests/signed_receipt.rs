#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::accept::AcceptReceipt;
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
    // The previous comparator explicitly permits this all-failed binary's
    // crash, producing a false green. The strict gate must reject it.
    assert!(
        carrick_xtask::ci_receipt::diff(&base, &candidate)
            .unwrap()
            .new
            .is_empty()
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
    assert!(compare(&base, &base).unwrap().passed);
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
fn owner_and_exact_app_login_only_and_latest_label_transition_is_authority() {
    assert!(allowed("tjfontaine"));
    assert!(allowed("carrick-workers[bot]"));
    assert!(!allowed("carrick-workers"));
    assert!(!allowed("someone-else"));
    let owner = json!({"id":1,"event":"labeled","label":{"name":"gate:signed"},"actor":{"login":"tjfontaine"}});
    assert!(label_authorized(std::slice::from_ref(&owner), "tjfontaine"));
    let unauthorized = json!({"id":2,"event":"labeled","label":{"name":"gate:signed"},"actor":{"login":"someone-else"}});
    assert!(!label_authorized(
        &[owner.clone(), unauthorized],
        "tjfontaine"
    ));
    let removed = json!({"id":3,"event":"unlabeled","label":{"name":"gate:signed"},"actor":{"login":"tjfontaine"}});
    assert!(!label_authorized(&[owner, removed], "tjfontaine"));
}

#[test]
fn baseline_workflow_provenance_and_receipt_admission_fail_closed() {
    let run = json!({"path":".github/workflows/signed-gate.yml","head_branch":"main","event":"workflow_dispatch","status":"completed","repository":{"full_name":"carrick-sh/carrick"},"head_repository":{"full_name":"carrick-sh/carrick"},"actor":{"login":"tjfontaine"},"triggering_actor":{"login":"carrick-workers[bot]"}});
    assert!(trusted_run(&run));
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
    value["artifact"] = json!({"path":"target/release/carrick","sha256":"1".repeat(64),"cdhash":"2".repeat(40),"lc_uuid":"some-uuid","hypervisor_entitlement":true,"dof_present":true});
    value["fixture_validation"] = json!({"validation_method":"input_identity","checkout_head":head,"checkout_tree":"3".repeat(40),"bundle_source_head":"a".repeat(40),"checkout_dirty":false,"manifest_sha256":"4".repeat(64),"inputs_sha256":"5".repeat(64)});
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
    let gh = bin.join("gh");
    std::fs::write(&gh, r#"#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
base, head = 'a'*40, 'b'*40
if args[:2] == ['run', 'download']:
    assert args[2] == '100' and args[args.index('--name')+1] == 'signed-baseline-'+base+'-2'
    shutil.copyfile(os.environ['TEST_BASE'], pathlib.Path(args[args.index('--dir')+1])/'candidate.json')
elif '--method' in args and args[args.index('--method')+1] == 'POST':
    endpoint = args[args.index('POST')+1]
    with open(os.environ['TEST_POSTS'], 'a') as out:
        out.write(json.dumps({'endpoint':endpoint,'body':json.load(sys.stdin)})+'\n')
elif args[0] == 'api':
    endpoint = args[-1]
    if '/pulls/' in endpoint:
        print(json.dumps({'state':'open','head':{'sha':head},'base':{'ref':'main'}}))
    elif '/compare/' in endpoint:
        print(json.dumps({'merge_base_commit':{'sha':base}}))
    elif '/workflows/signed-gate.yml/runs' in endpoint:
        run = {'id':100,'path':'.github/workflows/signed-gate.yml','head_branch':'main','event':'workflow_dispatch','status':'completed','repository':{'full_name':'carrick-sh/carrick'},'head_repository':{'full_name':'carrick-sh/carrick'},'actor':{'login':'tjfontaine'},'triggering_actor':{'login':'tjfontaine'}}
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
    let base = admitted(&"a".repeat(40));
    let baseline_path = dir.path().join("source-base.json");
    std::fs::write(&baseline_path, serde_json::to_vec(&base).unwrap()).unwrap();
    let event = dir.path().join("event.json");
    std::fs::write(&event, json!({"repository":{"full_name":"carrick-sh/carrick"},"inputs":{"pr":"123","sha":"b".repeat(40)}}).to_string()).unwrap();
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
    std::fs::write(&label_event, json!({"repository":{"full_name":"carrick-sh/carrick"},"action":"labeled","label":{"name":"gate:signed"},"sender":{"login":"tjfontaine"},"number":123,"pull_request":{"head":{"sha":"b".repeat(40)}}}).to_string()).unwrap();
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

    let results = dir.path().join("results");
    std::fs::create_dir(&results).unwrap();
    let candidate = admitted(&"b".repeat(40));
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
    std::fs::write(&event, json!({"repository":{"full_name":"carrick-sh/carrick"},"inputs":{"pr":"main","sha":"a".repeat(40)}}).to_string()).unwrap();
    let main_dir = dir.path().join("main-request");
    let main = child()
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
}
