#![allow(clippy::unwrap_used)]
use std::{fs, path::Path};

/// The Signed gate builds its fixtures for the exact authorized SHA in the
/// same run and hands that archive to the Mac gate (#1581). The workflow half
/// landed as #1602; this checks the live workflow.
#[test]
fn signed_gate_wires_same_run_authorized_fixture_artifact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let text = fs::read_to_string(root.join(".github/workflows/signed-gate.yml")).unwrap();
    let docs = yaml_rust2::YamlLoader::load_from_str(&text).unwrap();
    let jobs = &docs[0]["jobs"];
    let publisher = &jobs["signed-fixtures"];
    assert_eq!(publisher["needs"].as_str(), Some("authorize"));
    assert_eq!(publisher["runs-on"].as_str(), Some("ubuntu-24.04-arm"));
    let steps = publisher["steps"].as_vec().unwrap();
    assert_eq!(
        steps[0]["with"]["ref"].as_str(),
        Some("${{ needs.authorize.outputs.sha }}")
    );
    let upload = steps
        .iter()
        .find(|s| s["uses"].as_str() == Some("actions/upload-artifact@v4"))
        .unwrap();
    assert!(
        upload["with"]["path"]
            .as_str()
            .unwrap()
            .contains("needs.authorize.outputs.sha")
    );
    assert!(
        upload["with"]["name"]
            .as_str()
            .unwrap()
            .contains("github.run_attempt")
    );
    let gate = &jobs["gate"];
    assert!(
        gate["needs"]
            .as_vec()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("signed-fixtures"))
    );
    let download = gate["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|s| s["with"]["name"] == upload["with"]["name"])
        .unwrap();
    assert_eq!(
        download["uses"].as_str(),
        Some("actions/download-artifact@v4")
    );
    assert!(!text.contains("vars.CARRICK_SIGNED_FIXTURE_BUNDLE"));
    // The publisher runs the same commands as main's own fixture publisher,
    // for the authorized SHA instead of the pushed one.
    let kernel = fs::read_to_string(root.join(".github/workflows/kernel-runtime.yml")).unwrap();
    let kernel = yaml_rust2::YamlLoader::load_from_str(&kernel).unwrap();
    for step in steps.iter().filter(|s| !s["run"].is_badvalue()) {
        let name = step["name"].as_str().unwrap();
        let original = kernel[0]["jobs"]["signed-fixtures"]["steps"]
            .as_vec()
            .unwrap()
            .iter()
            .find(|s| s["name"].as_str() == Some(name))
            .unwrap();
        assert_eq!(
            step["run"].as_str().unwrap(),
            original["run"]
                .as_str()
                .unwrap()
                .replace("$GITHUB_SHA", "$FIXTURE_SHA")
        );
    }
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
    for job in ["authorize", "signed-fixtures", "gate", "publish"] {
        assert!(required.iter().any(|j| j.as_str() == Some(job)));
    }
    let command = check["steps"][0]["run"].as_str().unwrap();
    // Execute the committed command only after checking that Actions supplies
    // each dependency's actual result (a constant success would fail open).
    for (variable, job) in [
        ("AUTHORIZE", "authorize"),
        ("FIXTURES", "signed-fixtures"),
        ("GATE", "gate"),
        ("PUBLISH", "publish"),
    ] {
        assert_eq!(
            check["steps"][0]["env"][variable].as_str().unwrap(),
            format!("${{{{ needs.{job}.result }}}}")
        );
    }
    for dependency in ["AUTHORIZE", "FIXTURES", "GATE", "PUBLISH"] {
        assert!(command.contains(&format!("test \"${dependency}\" = success")));
    }
    // Run the workflow's actual shell with GitHub's fail-fast behavior.
    // A failure in any dependency must not be hidden by a later success.
    let dependencies = ["AUTHORIZE", "FIXTURES", "GATE", "PUBLISH"];
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
