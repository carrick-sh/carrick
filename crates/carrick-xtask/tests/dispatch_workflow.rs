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
    assert_eq!(worker["timeout-minutes"].as_i64(), Some(60));
    assert_eq!(worker["runs-on"][0].as_str(), Some("carrick-agent"));
    let permissions = worker["permissions"].as_hash().unwrap();
    assert_eq!(permissions.len(), 4);
    assert_eq!(worker["permissions"]["actions"].as_str(), Some("read"));
    for name in ["contents", "pull-requests", "issues"] {
        assert_eq!(worker["permissions"][name].as_str(), Some("write"));
    }
    assert!(
        !text.contains("dispatch-toolchain-"),
        "restore-only cache remains"
    );
    assert_eq!(
        workflow["on"]["issues"]["types"][0].as_str(),
        Some("labeled")
    );
    let steps = worker["steps"].as_vec().unwrap();
    let bootstrap = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("bootstrap"))
        .unwrap();
    let position = |id| {
        steps
            .iter()
            .position(|s| s["id"].as_str() == Some(id))
            .unwrap()
    };
    let agent = position("loop");
    let retire = position("retire");
    let upload = position("upload");
    assert!(
        bootstrap < position("admission")
            && position("admission") < agent
            && agent < retire
            && retire < upload
    );
    assert!(!format!("{:?}", steps[retire]).contains("github.token"));
    assert_eq!(
        steps[bootstrap]["env"]["GH_TOKEN"].as_str(),
        Some("${{ secrets.AGENT_DIRECTOR_TOKEN }}")
    );
    assert_eq!(
        steps[agent]["env"]["GH_TOKEN"].as_str(),
        Some("${{ github.token }}")
    );
    assert!(!steps[agent]["if"].as_str().unwrap().contains("event_name"));
    assert!(
        steps[upload]["if"]
            .as_str()
            .unwrap()
            .contains("steps.loop.outcome == 'success'")
    );
    assert!(
        steps[upload]["if"]
            .as_str()
            .unwrap()
            .contains("steps.loop.outcome == 'failure'"),
        "failed runs must preserve their handoff"
    );
    assert!(
        steps[upload]["if"]
            .as_str()
            .unwrap()
            .contains("steps.loop.outputs.artifacts_ready == 'true'"),
        "unscanned artifacts must never upload"
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
fn provider_workflow_provisions_every_available_worker_credential() {
    let docs = YamlLoader::load_from_str(include_str!(
        "../../../.github/workflows/dispatch-worker.yml"
    ))
    .unwrap();
    let auth = docs[0]["jobs"]["worker"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|s| s["id"].as_str() == Some("auth"))
        .unwrap();
    assert_eq!(
        auth["env"]["CODEX_AUTH_JSON"].as_str(),
        Some("${{ secrets.CODEX_AUTH_JSON }}")
    );
    assert_eq!(
        auth["env"]["AGY_OAUTH_TOKEN"].as_str(),
        Some("${{ secrets.AGY_OAUTH_TOKEN }}")
    );
    assert!(!include_str!("../../../.github/dispatch-tiers.toml").contains("[tiers."));
}

#[test]
fn only_dispatch_workflow_references_dispatch_secrets() {
    let workflows =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let secrets = ["AGENT_DIRECTOR_TOKEN", "CODEX_AUTH_JSON", "AGY_OAUTH_TOKEN"];
    let mut saw_dispatch = false;
    let mut other_workflows = 0;
    for entry in std::fs::read_dir(workflows).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        if path.file_name().and_then(|n| n.to_str()) == Some("dispatch-worker.yml") {
            saw_dispatch = true;
            for secret in secrets {
                assert!(
                    text.contains(secret),
                    "dispatch-worker.yml missing {secret}"
                );
            }
        } else {
            other_workflows += 1;
            for secret in secrets {
                assert!(
                    !text.contains(secret),
                    "{} references dispatch secret {secret}",
                    path.display()
                );
            }
        }
    }
    assert!(saw_dispatch, "missing dispatch-worker.yml");
    assert!(other_workflows > 0, "no other workflows checked");
}

#[test]
fn git_configuration_comment_is_honest() {
    let source = include_str!("../src/dispatch_worker.rs");
    assert!(source.contains("Worktree .gitattributes is honored"));
    assert!(
        !source.contains("All repositories used by the driver have freshly created configuration.")
    );
}

#[test]
fn residual_documentation_is_honest() {
    let docs = include_str!("../../../docs/ci/dispatch-worker.md");
    assert!(docs.contains("25522481 was deleted"));
    assert!(docs.contains("25523683 is active"));
    assert!(docs.contains("fixed refspec"));
    for residual in [
        "dedicated",
        "refresh token",
        "25522481",
        "25523683",
        "40 minutes",
        "other runs",
        "pinned launcher",
    ] {
        assert!(docs.contains(residual), "missing residual: {residual}");
    }
}

#[test]
fn dispatch_requires_precreated_account_and_agent_only_sudo() {
    let source = include_str!("../src/dispatch_worker.rs");
    assert!(
        !source.contains("/usr/sbin/useradd"),
        "runtime account creation needs root"
    );
    assert!(
        !source.contains("/usr/sbin/userdel"),
        "runtime account deletion needs root"
    );
    let helper = source
        .split("fn sudo(args:")
        .nth(1)
        .unwrap()
        .split("fn hand_over")
        .next()
        .unwrap();
    assert!(helper.contains("AGENT_USER"), "sudo helper can run as root");
    assert!(
        !source.contains("let _ = sudo(&[\"/bin/kill\""),
        "retirement discards signaling errors"
    );
    assert!(
        !source.contains("File::create(state.join(\"agent.out\"))"),
        "runner-owned output handed to agent metadata repair"
    );
}

#[test]
fn review_workflow_pins_main_and_orders_the_loop() {
    let docs = YamlLoader::load_from_str(include_str!(
        "../../../.github/workflows/dispatch-worker.yml"
    ))
    .unwrap();
    let w = &docs[0];
    assert_eq!(
        w["on"]["pull_request_review"]["types"][0].as_str(),
        Some("submitted")
    );
    assert_eq!(w["jobs"]["worker"]["timeout-minutes"].as_i64(), Some(60));
    assert_eq!(
        w["jobs"]["guard"]["outputs"]["base"].as_str(),
        Some("${{ steps.validate.outputs.base }}")
    );
    for job in ["guard", "worker"] {
        let steps = w["jobs"][job]["steps"].as_vec().unwrap();
        let checkout = steps
            .iter()
            .find(|s| s["uses"].as_str() == Some("actions/checkout@v4"))
            .unwrap();
        let reference = if job == "guard" {
            "${{ steps.base.outputs.base }}"
        } else {
            "${{ needs.guard.outputs.base }}"
        };
        assert_eq!(checkout["with"]["ref"].as_str(), Some(reference));
    }
    let steps = w["jobs"]["worker"]["steps"].as_vec().unwrap();
    let position = |id| {
        steps
            .iter()
            .position(|s| s["id"].as_str() == Some(id))
            .unwrap()
    };
    assert!(position("admission") < position("loop") && position("loop") < position("retire"));
    for s in steps {
        if !s["env"]["GH_TOKEN"].is_badvalue() {
            assert!(
                ["bootstrap", "admission", "loop"].contains(&s["id"].as_str().unwrap_or(""))
                    || s["name"].as_str() == Some("Mask the job token before agent execution")
            );
        }
    }
}

#[test]
fn review_base_scripts_resolve_main_and_refuse_bad_checkouts_before_build() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let docs = YamlLoader::load_from_str(include_str!(
        "../../../.github/workflows/dispatch-worker.yml"
    ))
    .unwrap();
    let guard = docs[0]["jobs"]["guard"]["steps"].as_vec().unwrap();
    let resolved = guard
        .iter()
        .position(|s| s["id"].as_str() == Some("base"))
        .unwrap();
    let guard_checkout = guard
        .iter()
        .position(|s| s["uses"].as_str() == Some("actions/checkout@v4"))
        .unwrap();
    let validate = guard
        .iter()
        .position(|s| s["id"].as_str() == Some("validate"))
        .unwrap();
    assert!(resolved < guard_checkout && guard_checkout < validate);
    let resolve = guard[resolved]["run"].as_str().unwrap();
    let steps = docs[0]["jobs"]["worker"]["steps"].as_vec().unwrap();
    let verify = steps
        .iter()
        .position(|s| {
            s["name"].as_str()
                == Some("Verify admitted base against freshly fetched main before building")
        })
        .unwrap();
    let build = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("driver"))
        .unwrap();
    let checkout = steps
        .iter()
        .position(|s| s["uses"].as_str() == Some("actions/checkout@v4"))
        .unwrap();
    assert!(checkout < verify && verify < build);
    let temp = tempfile::tempdir().unwrap();
    let git = temp.path().join("git");
    std::fs::write(&git, r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FIXTURE_CALLS"
case "$1" in
ls-remote) test "$2 $3" = 'https://github.com/carrick-sh/carrick refs/heads/main'; printf '%s\trefs/heads/main\n' "$FIXTURE_MAIN" ;;
fetch) test "$2 $3 $4" = '--no-tags https://github.com/carrick-sh/carrick refs/heads/main' ;;
rev-parse) test "$2" = HEAD; printf '%s\n' "$FIXTURE_CHECKOUT" ;;
merge-base) test "$2 $3 $4" = "--is-ancestor $FIXTURE_MAIN FETCH_HEAD"; exit "$FIXTURE_ANCESTOR" ;;
*) exit 91 ;;
esac
"#).unwrap();
    std::fs::set_permissions(git, std::fs::Permissions::from_mode(0o700)).unwrap();
    let main = "a".repeat(40);
    let merge = "b".repeat(40);
    let output = temp.path().join("output");
    let calls = temp.path().join("calls");
    let command = |script: &str| {
        let mut command = Command::new("/bin/bash");
        command
            .args(["-eu", "-c", script])
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", temp.path().display()))
            .env("FIXTURE_MAIN", &main)
            .env("FIXTURE_CALLS", &calls)
            .env("EVENT_SHA", &merge)
            .env("GITHUB_OUTPUT", &output)
            .env("CARRICK_DISPATCH_BASE", &main);
        command
    };
    for (event, expected) in [
        ("pull_request_review", &main),
        ("issue_comment", &main),
        ("issues", &merge),
    ] {
        std::fs::write(&output, "").unwrap();
        assert!(
            command(resolve)
                .env("EVENT_NAME", event)
                .output()
                .unwrap()
                .status
                .success()
        );
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            format!("base={expected}\n")
        );
    }
    let verify = steps[verify]["run"].as_str().unwrap();
    for (checkout, ancestor, allowed) in [
        (&main, "0", true),
        (&merge, "0", false),
        (&main, "1", false),
    ] {
        std::fs::write(&calls, "").unwrap();
        let result = command(verify)
            .env("FIXTURE_CHECKOUT", checkout)
            .env("FIXTURE_ANCESTOR", ancestor)
            .output()
            .unwrap();
        assert_eq!(result.status.success(), allowed, "{result:?}");
        assert!(std::fs::read_to_string(&calls).unwrap().starts_with(
            "fetch --no-tags https://github.com/carrick-sh/carrick refs/heads/main\n"
        ));
    }
}

#[test]
#[cfg(target_os = "linux")]
fn loop_client_alias_sends_one_strict_json_request() {
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixListener;
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("tools.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let alias = temp.path().join("dispatch-worker");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_carrick-xtask"), &alias).unwrap();
    // #814: deterministically retain the write description a concurrent fork
    // can inherit during copy. Links to the original inode need no writer.
    use std::os::unix::fs::MetadataExt;
    let source = std::fs::metadata(env!("CARGO_BIN_EXE_carrick-xtask")).unwrap();
    let target = std::fs::metadata(&alias).unwrap();
    let _inherited_writer =
        ((source.dev(), source.ino()) != (target.dev(), target.ino())).then(|| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&alias)
                .unwrap()
        });
    let mut child = Command::new(&alias)
        .args(["tool", "read_state"])
        .current_dir(temp.path())
        .env_clear()
        .env("CARRICK_DISPATCH_SOCKET", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{}").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("client did not connect: {e}");
            }
        }
    };
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let mut request = String::new();
    std::io::BufReader::new(&stream)
        .read_line(&mut request)
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&request).unwrap(),
        serde_json::json!({"tool":"read_state","arguments":{}})
    );
    writeln!(stream, "{{\"ok\":true}}").unwrap();
    drop(stream);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "{\"ok\":true}"
    );
}

#[test]
fn review_setup_failure_posts_fallback_only_on_the_admitted_pr() {
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let base = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(base.status.success());
    let base = String::from_utf8(base.stdout).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    let state = temp.path().join("carrick-agent-999-1");
    std::fs::create_dir(&bin).unwrap();
    std::fs::create_dir(&state).unwrap();
    let pr = json!({"number":800,"user":{"login":"github-actions[bot]","type":"Bot"},
        "head":{"sha":"a".repeat(40),"ref":"work/dispatch-799-42","repo":{"full_name":"carrick-sh/carrick"}},
        "base":{"ref":"main"},"draft":true,"body":"Closes #799\nDispatch run: https://github.com/carrick-sh/carrick/actions/runs/42"});
    let issue = json!({"number":799,"title":"Fixture","state":"open","user":{"login":"tjfontaine","type":"User"},"body":"## Brief\nFixture", "labels":[{"name":"dispatch:sol-high"}]});
    let run = json!({"id":42,"path":".github/workflows/dispatch-worker.yml","event":"issues","head_branch":"main","repository":{"full_name":"carrick-sh/carrick"},"actor":{"login":"tjfontaine","type":"User"},"triggering_actor":{"login":"tjfontaine","type":"User"},"head_repository":{"full_name":"carrick-sh/carrick"},"head_sha":"a".repeat(40)});
    for (name, value) in [
        ("pr.json", json!([pr.clone()])),
        ("pr-object.json", pr.clone()),
        ("issue.json", issue),
        ("run.json", run),
    ] {
        std::fs::write(temp.path().join(name), value.to_string()).unwrap();
    }
    let event = temp.path().join("event.json");
    std::fs::write(&event, json!({"repository":{"full_name":"carrick-sh/carrick"},"action":"submitted", "sender":{"login":"tjfontaine","type":"User"}, "pull_request":pr, "review":{"id":77,"state":"changes_requested","user":{"login":"tjfontaine","type":"User"},"body":"Fix it"}}).to_string()).unwrap();
    let gh = bin.join("gh");
    std::fs::write(
        &gh,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$@" >> "$RUNNER_TEMP/gh.args"
if [ "$1" = api ]; then
  case "$2" in
    */actions/runs/42) cat "$RUNNER_TEMP/run.json" ;;
    */pulls/800) cat "$RUNNER_TEMP/pr-object.json" ;;
    */issues/799) cat "$RUNNER_TEMP/issue.json" ;;
    *'/pulls?'*) cat "$RUNNER_TEMP/pr.json" ;;
    *) exit 91 ;;
  esac
else
  test "$1 $2 $3" = 'issue comment 800'
  previous=''
  for arg do
    if [ "$previous" = --body-file ]; then cp "$arg" "$RUNNER_TEMP/posted.md"; fi
    previous="$arg"
  done
fi
"#,
    )
    .unwrap();
    std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (name, script) in [
        (
            "git",
            "#!/bin/sh\nfor arg do [ \"$arg\" != fetch ] || exit 0; done\nexec /usr/bin/git \"$@\"\n",
        ),
        (
            "curl",
            "#!/bin/sh\necho curl >> \"$RUNNER_TEMP/gh.args\"\nexit 91\n",
        ),
    ] {
        let path = bin.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let invoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
            .args(args)
            .arg(&event)
            .current_dir(&root)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("RUNNER_TEMP", temp.path())
            .env("GITHUB_RUN_ID", "999")
            .env("GITHUB_RUN_ATTEMPT", "1")
            .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
            .env("CARRICK_DISPATCH_BASE", base.trim())
            .env("GITHUB_SHA", "b".repeat(40))
            .env("GH_TOKEN", "fixture-job-token")
            .output()
            .unwrap()
    };
    let admission = invoke(&["dispatch-worker", "guard", "--admit", "--event"]);
    assert!(admission.status.success(), "{admission:?}");
    // A remote relabel after admission must not reselect credentials or tier.
    let mut relabeled: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(temp.path().join("issue.json")).unwrap())
            .unwrap();
    relabeled["labels"] = json!([{"name":"dispatch:opus"}]);
    std::fs::write(temp.path().join("issue.json"), relabeled.to_string()).unwrap();
    let output = invoke(&[
        "dispatch-worker",
        "loop",
        "--setup-status",
        "failure/skipped",
        "--event",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fallback outcome posted"),
        "{output:?}"
    );
    let report = std::fs::read_to_string(temp.path().join("posted.md")).unwrap();
    assert!(report.contains("Dispatch outcome: Failed"));
    assert!(report.contains("Worker was not invoked"));
    assert!(report.contains("\"calls\":0"));
    assert!(
        report.contains("Dispatch run: https://github.com/carrick-sh/carrick/actions/runs/999")
    );
    assert!(!report.contains("fixture-job-token"));
    let calls = std::fs::read_to_string(temp.path().join("gh.args")).unwrap();
    assert!(calls.contains("issue\ncomment\n800\n"));
    assert!(!calls.contains("issue\ncomment\n799"));
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.ends_with("/issues/799"))
            .count(),
        1,
        "loop re-queried issue labels after admission"
    );
    std::fs::create_dir(state.join("home")).unwrap();
    let auth = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["agent-runner", "auth", "--event"])
        .arg(&event)
        .current_dir(&root)
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("RUNNER_TEMP", temp.path())
        .env("GITHUB_RUN_ID", "999")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
        .env("CODEX_AUTH_JSON", "{\"token\":\"worker-codex-secret\"}")
        .env("AGY_OAUTH_TOKEN", "loop-agy-secret")
        .output()
        .unwrap();
    assert!(auth.status.success(), "{auth:?}");
    assert_eq!(
        std::fs::read_to_string(temp.path().join("gh.args")).unwrap(),
        calls,
        "auth called the API after admission"
    );
    assert!(state.join("home/.codex/auth.json").is_file());
    assert!(state.join("home/.gemini").exists());
    assert!(!state.join("loop-home/.codex").exists());
    let credential = state.join("loop-home/.gemini/antigravity-cli/antigravity-oauth-token");
    assert_eq!(
        std::fs::read_to_string(&credential).unwrap(),
        "loop-agy-secret"
    );
    assert_eq!(
        std::fs::metadata(credential).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn guard_skips_reviews_outside_dispatch_changes_requests() {
    let docs = YamlLoader::load_from_str(include_str!(
        "../../../.github/workflows/dispatch-worker.yml"
    ))
    .unwrap();
    let condition = docs[0]["jobs"]["guard"]["if"].as_str().unwrap();
    assert!(condition.contains("github.actor == 'tjfontaine'"));
    for trigger in [
        "github.event_name == 'issues'",
        "github.event_name == 'issue_comment'",
        "github.event.review.state == 'changes_requested'",
    ] {
        assert!(condition.contains(trigger));
    }
}

#[test]
fn dispatch_review_stale_head_fails_before_checkout_or_build() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let docs = YamlLoader::load_from_str(include_str!(
        "../../../.github/workflows/dispatch-worker.yml"
    ))
    .unwrap();
    let steps = docs[0]["jobs"]["guard"]["steps"].as_vec().unwrap();
    let check = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("review-head"))
        .expect("hosted stale head check missing");
    let checkout = steps
        .iter()
        .position(|s| s["uses"].as_str() == Some("actions/checkout@v4"))
        .unwrap();
    assert!(check < checkout);
    let step = &steps[check];
    assert_eq!(
        step["if"].as_str(),
        Some("github.event_name == 'pull_request_review'")
    );
    assert_eq!(
        step["env"]["REVIEW_HEAD"].as_str(),
        Some("${{ github.event.pull_request.head.sha }}")
    );
    let temp = tempfile::tempdir().unwrap();
    let curl = temp.path().join("curl");
    std::fs::write(&curl, "#!/bin/sh\nfor arg do url=$arg; done\ntest \"$url\" = https://api.github.com/repos/carrick-sh/carrick/pulls/800 || exit 91\nprintf '{\"head\":{\"sha\":\"%s\"}}' \"$LIVE_HEAD\"\n").unwrap();
    std::fs::set_permissions(curl, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (live, allowed) in [("a", true), ("b", false)] {
        let output = Command::new("/bin/bash")
            .args(["-c", step["run"].as_str().unwrap()])
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", temp.path().display()))
            .env("REVIEW_PR", "800")
            .env("GH_TOKEN", "job-token")
            .env("REVIEW_HEAD", "a".repeat(40))
            .env("LIVE_HEAD", live.repeat(40))
            .output()
            .unwrap();
        assert_eq!(output.status.success(), allowed, "{output:?}");
        if !allowed {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("Stale owner review"),
                "{output:?}"
            );
        }
    }
}

#[test]
fn all_dispatch_triggers_use_one_loop() {
    let text = include_str!("../../../.github/workflows/dispatch-worker.yml");
    assert!(
        !text.contains("dispatch-worker run --event"),
        "fixed run path retained"
    );
    assert!(
        !text.contains("dispatch-worker complete --event"),
        "fixed completion retained"
    );
    let docs = YamlLoader::load_from_str(text).unwrap();
    assert_eq!(
        docs[0]["on"]["issue_comment"]["types"][0].as_str(),
        Some("created")
    );
}

#[test]
fn issue_triggers_default_to_run_branch_without_parsing_body_directives() {
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    for trigger in ["label", "comment"] {
        for owned in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let bin = temp.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            let branch = "work/dispatch-587-42";
            let pr = json!({"state":"open","number":801,"user":{"login":"github-actions[bot]","type":"Bot"},"head":{"ref":branch,"repo":{"full_name":"carrick-sh/carrick"}},"base":{"ref":"main"},"draft":true,"body":"Closes #587\nDispatch run: https://github.com/carrick-sh/carrick/actions/runs/42"});
            let run = json!({"id":42,"repository":{"full_name":"carrick-sh/carrick"},"head_repository":{"full_name":"carrick-sh/carrick"},"path":".github/workflows/dispatch-worker.yml","event":"issues","head_branch":"main","head_sha":"a".repeat(40),"actor":{"login":"tjfontaine","type":"User"},"triggering_actor":{"login":"tjfontaine","type":"User"}});
            let comment = json!({"id":123,"user":{"login":"tjfontaine","type":"User"},"body":"/agent do the acceptance criterion","created_at":"2026-10-24T00:00:00Z","updated_at":"2026-10-24T00:00:00Z"});
            let mut event = json!({"repository":{"full_name":"carrick-sh/carrick"},"action":"labeled","sender":{"login":"tjfontaine","type":"User"},"label":{"name":"dispatch:free text context"},"issue":{"number":587,"title":"Fixture","body":"Free-form body\nBranch: work/foreign\nThis is model context only.","user":{"login":"tjfontaine","type":"User"}}});
            event["issue"]["state"] = "open".into();
            if trigger == "comment" {
                event["action"] = "created".into();
                event["comment"] = comment.clone();
            }
            let event_path = temp.path().join("event.json");
            for (path, value) in [
                ("event.json", event),
                ("prs.json", if owned { json!([pr]) } else { json!([]) }),
                ("run.json", run),
                ("comment.json", comment),
            ] {
                std::fs::write(temp.path().join(path), value.to_string()).unwrap();
            }
            let gh = bin.join("gh");
            std::fs::write(
                &gh,
                r#"#!/bin/sh
case "$2" in
 *'/pulls?'*) cat "$RUNNER_TEMP/prs.json" ;;
 */actions/runs/42) cat "$RUNNER_TEMP/run.json" ;;
 */issues/comments/123) cat "$RUNNER_TEMP/comment.json" ;;
 *) exit 91 ;;
esac
"#,
            )
            .unwrap();
            std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o700)).unwrap();
            let result = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
                .args(["dispatch-worker", "guard", "--admit", "--event"])
                .arg(&event_path)
                .env_clear()
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .env("RUNNER_TEMP", temp.path())
                .env("GITHUB_RUN_ID", "999")
                .env("GITHUB_RUN_ATTEMPT", "1")
                .env("GITHUB_SHA", "b".repeat(40))
                .env("CARRICK_DISPATCH_BASE", "a".repeat(40))
                .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
                .env("GH_TOKEN", "fixture-token")
                .output()
                .unwrap();
            assert!(result.status.success(), "{trigger}/{owned}: {result:?}");
            let snapshot: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(temp.path().join("carrick-agent-999-1/admission.json"))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                snapshot["dispatch"]["base"],
                if trigger == "comment" {
                    "a".repeat(40)
                } else {
                    "b".repeat(40)
                }
            );
            assert_eq!(snapshot["dispatch"]["resume"], false);
            assert_eq!(snapshot["dispatch"]["branch"], "work/dispatch-587-999");
            assert!(
                snapshot["dispatch"]["body"]
                    .as_str()
                    .unwrap()
                    .contains("Branch: work/foreign")
            );
        }
    }
}
