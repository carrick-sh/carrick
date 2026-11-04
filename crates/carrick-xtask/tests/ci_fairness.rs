#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_xtask::ci_fairness::{Defect, classify, closed_candidate};
use serde_json::json;

fn issues() -> Vec<Defect> {
    serde_json::from_value(json!([
        {"number": 1619, "state":"open", "labels":[{"name":"main-defect"}], "body":"Failing test: `kernel::wake`\nFailing test: other"},
        {"number": 2, "state":"closed", "labels":[{"name":"main-defect"}], "body":"Failing test: kernel::wake"},
        {"number": 3, "state":"open", "labels":[], "body":"Failing test: kernel::wake"},
        {"number": 4, "state":"open", "labels":[{"name":"main-defect"}], "body": null}
    ])).unwrap()
}

#[test]
fn exact_failures_only() {
    let found = classify(
        &issues(),
        "2026-11-04T10:00:00.000Z test kernel::wake ... \x1b[31mFAILED\x1b[0m\ntest kernel::wake ... FAILED",
    );
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].issue, 1619);
    assert_eq!(found[0].test, "kernel::wake");
    for log in [
        "test kernel::wake ... ok",
        "test kernel::wake_more ... FAILED",
        "Failing test: kernel::wake",
        "error: kernel::wake",
        "test other ... ignored",
    ] {
        assert!(classify(&issues(), log).is_empty(), "{log}");
    }
}

#[test]
fn closure_never_cancels_other_workflows_events_prs_or_completed_runs() {
    let run = json!({"event":"pull_request", "path":".github/workflows/ci.yml", "status":"queued", "pull_requests":[{"number":42}]});
    assert!(closed_candidate(&run, 42));
    let mut qualified = run.clone();
    qualified["path"] = json!(".github/workflows/ci.yml@refs/pull/42/merge");
    assert!(closed_candidate(&qualified, 42));
    assert!(!closed_candidate(&run, 43));
    for (field, value) in [
        ("event", json!("merge_group")),
        ("path", json!(".github/workflows/kernel-runtime.yml")),
        ("status", json!("completed")),
        ("pull_requests", json!([])),
    ] {
        let mut other = run.clone();
        other[field] = value;
        assert!(!closed_candidate(&other, 42));
    }
}

#[test]
fn classifier_cli_witness() {
    let dir = tempfile::tempdir().unwrap();
    let issue_file = dir.path().join("issues.json");
    let log_file = dir.path().join("log");
    std::fs::write(&issue_file, r#"[{"number":1619,"state":"open","labels":[{"name":"main-defect"}],"body":"Failing test: kernel::wake"}]"#).unwrap();
    std::fs::write(&log_file, "test kernel::wake ... FAILED\n").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .arg("ci-fairness")
        .arg("classify")
        .arg(issue_file)
        .arg(log_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        json!([{"issue":1619,"test":"kernel::wake"}])
    );
}

// The fake is test-only; the production entry point still invokes gh and parses
// its real JSON/log wire formats. PATH is scoped to each child, never mutated.
#[cfg(unix)]
fn observer_fixture(command: &str, responses: serde_json::Value) -> (String, String) {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let calls = dir.path().join("calls");
    let gh = dir.path().join("gh");
    let quote = |text: &str| format!("'{}'", text.replace('\'', "'\"'\"'"));
    let mut script =
        String::from("#!/bin/sh\nprintf '%s %s\\n' \"$3\" \"$4\" >> \"$CALLS\"\ncase \"$4\" in\n");
    for (endpoint, value) in responses.as_object().unwrap() {
        let response = value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string());
        script.push_str(&format!(
            "{}) printf '%s\\n' {} ;;\n",
            quote(endpoint),
            quote(&response)
        ));
    }
    script.push_str("*) printf 'unexpected API call: %s\\n' \"$4\" >&2; exit 1 ;;\nesac\n");
    std::fs::write(&gh, script).unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["ci-fairness", command, "owner/repo", "42"])
        .env("PATH", dir.path())
        .env("CALLS", &calls)
        .env_remove("GITHUB_STEP_SUMMARY")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        String::from_utf8(output.stdout).unwrap(),
        std::fs::read_to_string(calls).unwrap(),
    )
}

#[test]
#[cfg(unix)]
fn closed_cli_cancels_only_associated_active_hosted_ci_runs() {
    let run = json!({"id":7,"event":"pull_request","path":".github/workflows/ci.yml","status":"queued","pull_requests":[{"number":42}]});
    let mut unrelated = run.clone();
    unrelated["id"] = json!(8);
    unrelated["pull_requests"] = json!([{"number":43}]);
    let mut responses = json!({"repos/owner/repo/pulls/42":{"state":"closed"},"repos/owner/repo/actions/runs/7/cancel":""});
    for status in ["queued", "in_progress", "waiting", "pending", "requested"] {
        responses[format!(
            "repos/owner/repo/actions/workflows/ci.yml/runs?event=pull_request&status={status}&per_page=100&page=1"
        )] = json!({"workflow_runs": if status == "queued" { vec![run.clone(), unrelated.clone()] } else {vec![]} });
    }
    let (_, calls) = observer_fixture("closed", responses);
    assert_eq!(
        calls
            .lines()
            .filter(|l| l.starts_with("POST"))
            .collect::<Vec<_>>(),
        vec!["POST repos/owner/repo/actions/runs/7/cancel"]
    );
    let (_, calls) = observer_fixture(
        "closed",
        json!({"repos/owner/repo/pulls/42":{"state":"open"}}),
    );
    assert!(!calls.contains("POST"));
}

#[test]
#[cfg(unix)]
fn watcher_cli_cancels_exact_defect_with_remaining_mac_job() {
    let (out, calls) = observer_fixture(
        "watch",
        json!({
            "repos/owner/repo/actions/runs/42":{"id":42,"event":"pull_request","path":".github/workflows/ci.yml","status":"in_progress","run_attempt":2,"pull_requests":[{"number":1}]},
            "repos/owner/repo/pulls/1":{"state":"open"},
            "repos/owner/repo/actions/runs/42/attempts/2/jobs?per_page=100&page=1":{"jobs":[
                {"id":3,"name":"lint-gates","status":"completed","conclusion":"failure"},
                {"id":4,"name":"macos-unit-a","status":"queued","labels":["self-hosted","carrick-macos-ci"]}
            ]},
            "repos/owner/repo/issues?state=open&labels=main-defect&per_page=100&page=1":[{"number":1619,"state":"open","labels":[{"name":"main-defect"}],"body":"Failing test: kernel::wake"}],
            "repos/owner/repo/actions/jobs/3/logs":"2026-11-04T10:00:00Z test kernel::wake ... FAILED\n",
            "repos/owner/repo/actions/runs/42/cancel":""
        }),
    );
    assert!(out.contains("https://github.com/owner/repo/issues/1619"));
    assert!(calls.contains("POST repos/owner/repo/actions/runs/42/cancel"));
}

#[test]
#[cfg(unix)]
fn watcher_cli_closes_census_race_but_never_cancels_merge_group() {
    let (_, calls) = observer_fixture(
        "watch",
        json!({
            "repos/owner/repo/actions/runs/42":{"event":"pull_request","path":".github/workflows/ci.yml","status":"in_progress","pull_requests":[{"number":1}]},
            "repos/owner/repo/pulls/1":{"state":"closed"},
            "repos/owner/repo/actions/runs/42/cancel":""
        }),
    );
    assert!(calls.contains("POST"));
    let (_, calls) = observer_fixture(
        "watch",
        json!({
            "repos/owner/repo/actions/runs/42":{"event":"merge_group","path":".github/workflows/ci.yml","status":"in_progress"}
        }),
    );
    assert!(!calls.contains("POST"));
}
