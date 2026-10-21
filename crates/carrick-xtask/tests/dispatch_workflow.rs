//! Shape B's workflow contract; H1's executable witnesses stay in-file.
use yaml_rust2::YamlLoader;

#[test]
fn disposable_worker_has_no_publisher_or_artifact_transfer() {
    let text = include_str!("../../../.github/workflows/dispatch-worker.yml");
    let docs = YamlLoader::load_from_str(text).unwrap();
    let workflow = &docs[0];
    assert!(workflow["jobs"]["publish"].is_badvalue());
    for removed in [
        "download-artifact",
        "artifact-ids:",
        "artifact_id:",
        "AGENT_WORKER_TOKEN",
        "agent-execution",
        "agent-dispatch",
    ] {
        assert!(!text.contains(removed), "retained {removed}");
    }
    let worker = &workflow["jobs"]["worker"];
    assert_eq!(worker["timeout-minutes"].as_i64(), Some(40));
    assert_eq!(worker["runs-on"][0].as_str(), Some("carrick-agent"));
    let permissions = worker["permissions"].as_hash().unwrap();
    assert_eq!(permissions.len(), 4);
    for name in ["contents", "pull-requests", "issues", "checks"] {
        assert_eq!(worker["permissions"][name].as_str(), Some("write"));
    }
    assert_eq!(
        workflow["on"]["issues"]["types"][0].as_str(),
        Some("labeled")
    );
    let steps = worker["steps"].as_vec().unwrap();
    let bootstrap = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("bootstrap"))
        .unwrap();
    let agent = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("worker"))
        .unwrap();
    let complete = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("complete"))
        .unwrap();
    let upload = steps
        .iter()
        .position(|s| s["uses"].as_str().unwrap_or("").contains("upload-artifact"))
        .unwrap();
    assert!(bootstrap < agent && agent < complete && complete < upload);
    assert_eq!(
        steps[bootstrap]["env"]["GH_TOKEN"].as_str(),
        Some("${{ secrets.AGENT_DIRECTOR_TOKEN }}")
    );
    assert_eq!(
        steps[complete]["env"]["GH_TOKEN"].as_str(),
        Some("${{ github.token }}")
    );
    assert!(
        steps[complete]["run"]
            .as_str()
            .unwrap()
            .contains("dispatch-worker complete")
    );
    assert!(
        steps[upload]["if"]
            .as_str()
            .unwrap()
            .contains("steps.complete.outcome == 'success'")
    );
    for (index, step) in steps.iter().enumerate() {
        if index != bootstrap {
            assert!(
                !step["env"]["GH_TOKEN"]
                    .as_str()
                    .unwrap_or("")
                    .contains("AGENT_DIRECTOR_TOKEN")
            );
        }
    }
}

#[test]
fn foreground_agent_has_no_tokens_and_only_workflow_completion_reports() {
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("checkout");
    let state = temp.path().join("carrick-agent-42-1");
    let bin = temp.path().join("driver-bin");
    let cargo = temp.path().join("cargo");
    let rustup = temp.path().join("rustup");
    for path in [
        &root,
        &bin,
        &cargo,
        &rustup,
        &state.join("home"),
        &state.join("bin"),
        &state.join("director/agy-director/scripts"),
    ] {
        std::fs::create_dir_all(path).unwrap();
    }
    let git = |args: &[&str]| {
        let output = Command::new("/usr/bin/git")
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@localhost",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    git(&["init", "-b", "main"]);
    std::fs::write(root.join("base"), "base").unwrap();
    git(&["add", "base"]);
    git(&["commit", "-m", "fixture"]);
    let base = git(&["rev-parse", "HEAD"]);
    let event = temp.path().join("event.json");
    std::fs::write(&event, serde_json::to_vec(&json!({
        "repository":{"full_name":"carrick-sh/carrick"}, "action":"labeled",
        "sender":{"login":"tjfontaine","type":"User"}, "label":{"name":"dispatch:sol-high"},
        "issue":{"number":733,"title":"Fixture","user":{"login":"tjfontaine"},"body":"## Brief\nImplement the fixture"}
    })).unwrap()).unwrap();
    // A fixture launcher stands in for the pinned private script. The real
    // driver constructs and executes its full command, including private homes.
    std::fs::write(state.join("director/agy-director/scripts/agy_worker.py"), r#"
import json, os, pathlib, subprocess, sys
for key in ['GH_TOKEN', 'GITHUB_TOKEN', 'AGENT_DIRECTOR_TOKEN', 'GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY']:
    assert key not in os.environ, key
assert os.environ['RUSTC_WRAPPER'] == ''
assert os.environ['RUSTC_WORKSPACE_WRAPPER'] == ''
assert os.environ['CARRICK_SCCACHE'] == '0'
pathlib.Path('payload').write_text('candidate\n')
subprocess.run(['git', 'add', 'payload'], check=True)
subprocess.run(['git', 'commit', '-m', 'test(ci): fixture work'], check=True)
result = sys.argv[sys.argv.index('--result-file') + 1]
pathlib.Path(result).write_text(json.dumps({'structured_output': {
    'status':'done', 'summary':'fixture-job-token implemented', 'tests':['fixture'], 'risks':[]}}))
print('stdout transcript fixture-job-token')
print('stderr transcript', file=sys.stderr)
print('x' * 70000)
"#).unwrap();
    for (name, script) in [
        (
            "git",
            "#!/bin/sh\nfor arg do\n if [ \"$arg\" = push ]; then\n  printf '%s\\n' \"$@\" > \"$RUNNER_TEMP/push.args\"\n  exit 0\n fi\ndone\nexec /usr/bin/git \"$@\"\n",
        ),
        (
            "gh",
            "#!/bin/sh\nprevious=\"\"\nfor arg do\n if [ \"$previous\" = --body-file ] && [ \"$(wc -c < \"$arg\")\" -gt 60000 ]; then exit 90; fi\n previous=\"$arg\"\ndone\nprintf '%s\\n' \"$@\" >> \"$RUNNER_TEMP/gh.args\"\nif [ \"$1\" = api ]; then echo '[]'; else echo 'https://github.com/carrick-sh/carrick/pull/1'; fi\n",
        ),
    ] {
        let path = bin.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let summary = temp.path().join("summary.md");
    let outputs = temp.path().join("outputs");
    std::fs::write(&summary, "").unwrap();
    std::fs::write(&outputs, "").unwrap();
    let invoke = |action| {
        let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(["dispatch-worker", action, "--event"])
            .arg(&event)
            .current_dir(&root)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/local/bin:/usr/bin:/bin", bin.display()),
            )
            .env("HOME", temp.path())
            .env("CARGO_HOME", &cargo)
            .env("RUSTUP_HOME", &rustup)
            .env("RUNNER_TEMP", temp.path())
            .env("GITHUB_RUN_ID", "42")
            .env("GITHUB_RUN_ATTEMPT", "1")
            .env("GITHUB_SHA", &base)
            .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
            .env("GH_TOKEN", "fixture-job-token")
            .env("GITHUB_TOKEN", "fixture-job-token")
            .env("AGENT_DIRECTOR_TOKEN", "fixture-bootstrap-read-token")
            .env("GITHUB_STEP_SUMMARY", &summary)
            .env("GITHUB_OUTPUT", &outputs)
            .output()
            .unwrap();
        assert!(output.status.success(), "{action}: {output:?}");
    };
    invoke("run");
    assert!(!temp.path().join("push.args").exists());
    assert!(!temp.path().join("gh.args").exists());
    assert!(std::fs::read_to_string(&summary).unwrap().is_empty());
    invoke("complete");
    let push = std::fs::read_to_string(temp.path().join("push.args")).unwrap();
    assert_eq!(
        push.lines().last(),
        Some("HEAD:refs/heads/work/dispatch-733-42")
    );
    let gh = std::fs::read_to_string(temp.path().join("gh.args")).unwrap();
    assert!(gh.contains("create\n") && gh.contains("--draft\n"));
    assert!(gh.contains("issue\ncomment\n733\n"));
    let body = std::fs::read_to_string(state.join("pr-body.md")).unwrap();
    assert!(body.contains("Closes #733"));
    assert!(body.contains("Dispatch run: https://github.com/carrick-sh/carrick/actions/runs/42"));
    let artifacts = temp.path().join("dispatch-output");
    for name in ["raw.log", "transcript.md", "contract.json", "diffstat.txt"] {
        let text = std::fs::read_to_string(artifacts.join(name)).unwrap();
        assert!(!text.contains("fixture-job-token"), "{name}");
    }
    let transcript = std::fs::read_to_string(artifacts.join("transcript.md")).unwrap();
    assert!(transcript.contains("stderr transcript"));
    assert!(!std::fs::read_to_string(summary).unwrap().is_empty());
    assert!(std::fs::read_to_string(outputs).unwrap().is_empty());
}
