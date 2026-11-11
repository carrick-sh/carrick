#![allow(clippy::unwrap_used)]
use std::{fs, path::Path};

/// The Signed gate restores fixtures only from a trusted producer keyed by
/// the merge base: main's own published `signed-fixtures-<base>` artifact,
/// fetched by trusted main code that authenticates its producing run. No
/// job publishes a bundle from candidate code (#1889 review P1); trusted main
/// code builds only added probes beside it (#1980).
#[test]
fn signed_gate_restores_the_trusted_base_fixture_artifact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(root.join(".github/workflows/signed-gate.yml")).unwrap();
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let jobs = &docs[0]["jobs"];
    assert!(
        jobs["signed-fixtures"].is_badvalue(),
        "a candidate fixture publisher must not supply fixture authority"
    );
    assert!(!text.contains("fixtures-publish"));
    let fetcher = &jobs["base-fixtures"];
    assert_eq!(fetcher["needs"].as_str(), Some("authorize"));
    let steps = fetcher["steps"].as_vec().unwrap();
    assert_eq!(steps[0]["with"]["ref"].as_str(), Some("main"));
    assert_eq!(
        fetcher["permissions"]["actions"].as_str(),
        Some("read"),
        "the fetcher reads the producing run through the API"
    );
    let fetch = steps
        .iter()
        .find(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.contains("signed-gate base-fixtures"))
        })
        .unwrap();
    assert!(fetch["run"].as_str().unwrap().contains("request.json"));
    let upload = steps
        .iter()
        .find(|s| s["uses"].as_str() == Some("actions/upload-artifact@v4"))
        .unwrap();
    let name = upload["with"]["name"].as_str().unwrap();
    assert!(name.contains("github.run_attempt"), "{name}");
    let gate = &jobs["gate"];
    assert!(
        gate["needs"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("base-fixtures"))
    );
    let download = gate["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|s| s["with"]["name"].as_str() == Some(name))
        .unwrap();
    assert_eq!(
        download["uses"].as_str(),
        Some("actions/download-artifact@v4")
    );
    // Owner decision #1980: one job builds added probes from candidate code.
    // It runs main's code on the publisher's runner class, needs the trusted
    // base bundle, and hands the gate a per-attempt artifact.
    let probes = &jobs["candidate-probes"];
    assert_eq!(probes["runs-on"].as_str(), Some("ubuntu-24.04-arm"));
    let needs: Vec<_> = probes["needs"]
        .as_vec()
        .unwrap()
        .iter()
        .filter_map(|s| s.as_str())
        .collect();
    assert_eq!(needs, ["authorize", "base-fixtures"]);
    let steps = probes["steps"].as_vec().unwrap();
    assert_eq!(steps[0]["with"]["ref"].as_str(), Some("main"));
    assert_eq!(
        steps[0]["with"]["persist-credentials"].as_bool(),
        Some(false)
    );
    assert!(steps.iter().any(|s| {
        s["run"]
            .as_str()
            .is_some_and(|r| r.contains("signed-gate candidate-probes"))
    }));
    assert!(
        probes["permissions"]["contents"].as_str() == Some("read")
            && probes["permissions"].as_hash().unwrap().len() == 2,
        "the candidate probe builder holds no write permission"
    );
    let upload = steps
        .iter()
        .find(|s| s["uses"].as_str() == Some("actions/upload-artifact@v4"))
        .unwrap();
    let set = upload["with"]["name"].as_str().unwrap();
    assert!(set.contains("github.run_attempt"), "{set}");
    assert!(
        gate["needs"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("candidate-probes"))
    );
    assert!(
        gate["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s["with"]["name"].as_str() == Some(set))
    );
    // Candidate code is checked out only by trusted xtask code, never by a job.
    for (job, body) in jobs.as_hash().unwrap() {
        for step in body["steps"].as_vec().into_iter().flatten() {
            assert_ne!(
                step["with"]["ref"].as_str(),
                Some("${{ needs.authorize.outputs.sha }}"),
                "{job:?} checks out the candidate"
            );
        }
    }
    assert!(!text.contains("vars.CARRICK_SIGNED_FIXTURE_BUNDLE"));
    // The trusted producer is main's own fixture publisher.
    let kernel = fs::read_to_string(root.join(".github/workflows/kernel-runtime.yml")).unwrap();
    let kernel = yaml_rust2::YamlLoader::load_from_str(&kernel).unwrap();
    let published = kernel[0]["jobs"]["signed-fixtures"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .filter_map(|s| s["with"]["name"].as_str())
        .collect::<Vec<_>>();
    assert!(published.contains(&"signed-fixtures-${{ github.sha }}"));
}

/// The required check must fail on any skipped or failed dependency, while
/// PRs receive a cheap placeholder rather than an automatic signed run.
#[test]
fn signed_queue_workflow_requires_published_group_pass_and_seeds_main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(root.join(".github/workflows/signed-gate.yml")).unwrap();
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let workflow = &docs[0];
    assert_eq!(
        workflow["on"]["merge_group"]["types"][0].as_str(),
        Some("checks_requested")
    );
    assert_eq!(workflow["on"]["push"]["branches"][0].as_str(), Some("main"));
    // Every main push must retain its admitted receipt, including when another
    // push arrives. Coalescing these runs would strand a queue's exact base.
    assert!(workflow["concurrency"].is_badvalue());
    let jobs = &workflow["jobs"];
    let baseline = jobs["publish"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|step| step["name"].as_str() == Some("Publish admitted main baseline"))
        .unwrap();
    assert_eq!(
        baseline["if"].as_str(),
        Some("needs.authorize.outputs.main == 'true' && steps.verdict.outcome == 'success'")
    );
    assert_eq!(
        baseline["with"]["name"].as_str(),
        Some("signed-baseline-${{ needs.authorize.outputs.sha }}-${{ github.run_attempt }}")
    );
    assert_eq!(
        baseline["with"]["path"].as_str(),
        Some("${{ runner.temp }}/signed-result/candidate.json")
    );
    let check = &jobs["signed-queue-gate"];
    assert_eq!(check["name"].as_str(), Some("Signed queue gate"));
    assert_eq!(
        check["if"].as_str(),
        Some("always() && github.event_name == 'merge_group'")
    );
    let required = check["needs"].as_vec().unwrap();
    for job in [
        "authorize",
        "base-fixtures",
        "candidate-probes",
        "gate",
        "publish",
    ] {
        assert!(required.iter().any(|j| j.as_str() == Some(job)));
    }
    let command = check["steps"][0]["run"].as_str().unwrap();
    // Execute the committed command only after checking that Actions supplies
    // each dependency's actual result (a constant success would fail open).
    for (variable, job) in [
        ("AUTHORIZE", "authorize"),
        ("FIXTURES", "base-fixtures"),
        ("PROBES", "candidate-probes"),
        ("GATE", "gate"),
        ("PUBLISH", "publish"),
    ] {
        assert_eq!(
            check["steps"][0]["env"][variable].as_str().unwrap(),
            format!("${{{{ needs.{job}.result }}}}")
        );
    }
    for dependency in ["AUTHORIZE", "FIXTURES", "PROBES", "GATE", "PUBLISH"] {
        assert!(command.contains(&format!("test \"${dependency}\" = success")));
    }
    // Run the workflow's actual shell with GitHub's fail-fast behavior.
    // A failure in any dependency must not be hidden by a later success.
    let dependencies = ["AUTHORIZE", "FIXTURES", "PROBES", "GATE", "PUBLISH"];
    let run_check = |refused: Option<(&str, &str)>| {
        let mut shell = std::process::Command::new("bash");
        shell.args(["-e", "-c", command]);
        for name in dependencies {
            shell.env(name, "success");
        }
        if let Some((name, result)) = refused {
            shell.env(name, result);
        }
        shell.output().unwrap().status.success()
    };
    assert!(run_check(None));
    for name in dependencies {
        for result in ["failure", "cancelled", "skipped"] {
            assert!(!run_check(Some((name, result))), "accepted {name}={result}");
        }
    }
    let placeholder =
        fs::read_to_string(root.join(".github/workflows/trusted-hardware-pr.yml")).unwrap();
    let placeholder = yaml_rust2::YamlLoader::load_from_str(&placeholder).unwrap();
    assert!(placeholder[0]["on"]["merge_group"].is_badvalue());
    assert_eq!(
        placeholder[0]["jobs"]["signed-queue-gate"]["name"].as_str(),
        Some("Signed queue gate")
    );
    assert!(workflow["on"]["pull_request"].is_badvalue());
    assert_eq!(
        workflow["on"]["pull_request_target"]["types"][0].as_str(),
        Some("labeled")
    );
}

/// Only automatic events bypass the early owner check. Rust then verifies
/// their repository, queue ref, action and exact commit identity.
#[test]
fn signed_workflow_keeps_manual_requests_owner_only() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(root.join(".github/workflows/signed-gate.yml")).unwrap();
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let authorize = &docs[0]["jobs"]["authorize"];
    for (name, expression) in [
        ("EVENT_NAME", "${{ github.event_name }}"),
        ("ACTOR", "${{ github.actor }}"),
        ("TRIGGERING_ACTOR", "${{ github.triggering_actor }}"),
    ] {
        assert_eq!(
            authorize["steps"][0]["env"][name].as_str(),
            Some(expression)
        );
    }
    let guard = authorize["steps"][0]["run"].as_str().unwrap();
    let run_guard = |event: &str, actor: &str, triggering: &str| {
        std::process::Command::new("bash")
            .args(["-e", "-c", guard])
            .env("EVENT_NAME", event)
            .env("ACTOR", actor)
            .env("TRIGGERING_ACTOR", triggering)
            .output()
            .unwrap()
            .status
            .success()
    };
    for event in ["merge_group", "push"] {
        assert!(run_guard(event, "carrick-workers[bot]", "contributor"));
    }
    for event in ["workflow_dispatch", "pull_request_target"] {
        assert!(run_guard(event, "tjfontaine", "tjfontaine"));
        assert!(!run_guard(event, "contributor", "tjfontaine"));
        assert!(!run_guard(event, "tjfontaine", "contributor"));
    }
    let condition = authorize["if"].as_str().unwrap();
    assert!(condition.contains("github.repository == 'carrick-sh/carrick'"));
    assert!(condition.contains("github.event.label.name == 'gate:signed'"));
}
