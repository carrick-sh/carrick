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
    assert_eq!(permissions.len(), 3);
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
    let agent = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("worker"))
        .unwrap();
    assert!(
        steps[agent]["env"]["GH_TOKEN"].is_badvalue(),
        "agent step retains job token"
    );
    assert!(
        steps
            .iter()
            .any(|step| step["id"].as_str() == Some("admission"))
    );
    let complete = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("complete"))
        .unwrap();
    let upload = steps
        .iter()
        .position(|s| s["uses"].as_str().unwrap_or("").contains("upload-artifact"))
        .unwrap();
    let retire = steps
        .iter()
        .position(|s| s["id"].as_str() == Some("retire"))
        .expect("missing token-free retirement step");
    assert!(agent < retire && retire < complete);
    assert!(!format!("{:?}", steps[retire]).contains("github.token"));
    assert!(
        steps[complete]["if"]
            .as_str()
            .unwrap()
            .contains("steps.retire.outcome == 'success'")
    );
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
fn provider_workflow_selects_only_the_admitted_backend() {
    let text = include_str!("../../../.github/workflows/dispatch-worker.yml");
    assert!(
        text.contains("needs.guard.outputs.backend == 'codex' && secrets.CODEX_AUTH_JSON || ''")
    );
    assert!(text.contains("(needs.guard.outputs.backend == 'agy' || github.event_name == 'pull_request_review') && secrets.AGY_OAUTH_TOKEN || ''"));
    assert!(text.contains("backend: ${{ steps.tier.outputs.backend }}"));
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
#[cfg(target_os = "linux")]
#[ignore = "runner-only OS account witness; run with --include-ignored"]
fn serial_host_agent_uid_boundary() {
    foreground("boundary");
}
#[test]
#[cfg(target_os = "linux")]
#[ignore = "runner-only OS account witness; run with --include-ignored"]
fn serial_host_agent_secret_custody() {
    foreground("secrets");
}
#[test]
#[cfg(target_os = "linux")]
#[ignore = "runner-only OS account witness; run with --include-ignored"]
fn serial_host_detached_agent_is_retired() {
    foreground("retirement");
}
#[test]
#[cfg(target_os = "linux")]
#[ignore = "runner-only OS account witness; run with --include-ignored"]
fn serial_host_successful_push_rerun_reports_existing_pr() {
    foreground("rerun");
}
#[test]
#[cfg(target_os = "linux")]
#[ignore = "runner-only OS account witness; run with --include-ignored"]
fn serial_host_workflow_edits_are_reported_without_push() {
    foreground("workflow");
}

#[cfg(target_os = "linux")]
#[allow(clippy::unwrap_used)] // Shared integration fixture, not a product entry point.
fn foreground(case: &str) {
    static ACCOUNT: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _account = ACCOUNT.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: this serial fixture adopts only its own command descendants.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);

    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    if !matches!(case, "oversize" | "checkout") {
        let account = Command::new("/usr/bin/id")
            .args(["-u", "carrick-dispatch-agent"])
            .output()
            .unwrap();
        if account.status.code() == Some(1) {
            eprintln!("UNRUN: pre-created carrick-dispatch-agent account absent");
            return;
        }
        assert!(account.status.success());
        assert!(
            !Command::new("/usr/bin/sudo")
                .args(["-n", "-u", "root", "--", "/usr/bin/true"])
                .status()
                .unwrap()
                .success(),
            "runner can become root"
        );
    }
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
    std::os::unix::fs::symlink("base", root.join("base-link")).unwrap();
    git(&["add", "base", "base-link"]);
    git(&["commit", "-m", "fixture"]);
    let base = git(&["rev-parse", "HEAD"]);
    let event = temp.path().join("event.json");
    std::fs::write(&event, serde_json::to_vec(&json!({
        "repository":{"full_name":"carrick-sh/carrick"}, "action":"labeled",
        "sender":{"login":"tjfontaine","type":"User"}, "label":{"name":"dispatch:sol-high"},
        "issue":{"number":733,"title":"Fixture","user":{"login":"tjfontaine"},"body":"## Brief\nImplement the fixture"}
    })).unwrap()).unwrap();
    struct Runner(std::process::Child);
    impl Drop for Runner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let runner = Runner(
        Command::new("/bin/sleep")
            .arg("120")
            .env("ACTIONS_RUNTIME_TOKEN", "fixture-runtime-token")
            .spawn()
            .unwrap(),
    );
    let driver = temp.path().join("runner-driver");
    std::fs::write(&driver, "runner executable").unwrap();
    std::fs::set_permissions(&driver, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir_all(state.join("home/.codex")).unwrap();
    std::fs::write(
        state.join("home/.codex/auth.json"),
        "selected-provider-refresh",
    )
    .unwrap();
    std::fs::write(
        state.join("redaction-secrets.json"),
        "[\"runner-only-secret\"]",
    )
    .unwrap();
    let resources = json!([
        runner.0.id(),
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        driver,
        temp.path().join("dispatch-output/tamper"),
        state.join("redaction-secrets.json"),
        case
    ]);
    // A fixture launcher stands in for the pinned private script. The real
    // driver constructs and executes its full command, including private homes.
    std::fs::write(state.join("director/agy-director/scripts/agy_worker.py"), r#"
import json, os, pathlib, subprocess, sys, pwd, time
pid, runner_uid, runner_gid, driver, artifacts, secret, fixture_case = FIXTURE_RESOURCES

def denied_read(path):
    try: pathlib.Path(path).read_bytes(); return False
    except PermissionError: return True

def denied_write(path):
    try:
        with open(path, 'a') as stream: stream.write('actor write')
        if path == artifacts: pathlib.Path(path).unlink()
        return False
    except PermissionError: return True

facts = dict(uid=os.getuid() != runner_uid, user=pwd.getpwuid(os.getuid()).pw_name == 'carrick-dispatch-agent',
    runner_env=denied_read(f'/proc/{pid}/environ'), driver=denied_write(driver),
    artifacts=denied_write(artifacts), secrets=denied_read(secret),
    auth=(pathlib.Path(os.environ['HOME']) / '.codex/auth.json').read_text() == 'selected-provider-refresh',
    shell=pwd.getpwuid(os.getuid()).pw_shell == '/usr/sbin/nologin',
    groups=runner_gid != os.getgid() and runner_gid not in os.getgroups(),
    sudo=subprocess.run(['/usr/bin/sudo', '-n', '-l', '-U', 'carrick-dispatch-agent'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0)
print('BOUNDARY ' + json.dumps(facts), flush=True)
if fixture_case == 'retirement':
    child = subprocess.Popen(['/usr/bin/setsid', '/bin/sleep', '120'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(500):
        if os.getsid(child.pid) == child.pid: break
        time.sleep(.01)
    else:
        child.kill()
        raise AssertionError('detached child did not establish its session')
    print(f'DETACHED {child.pid}', flush=True)
if fixture_case == 'workflow':
    path = pathlib.Path('.github/workflows/actor.yml')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('name: actor\n')
for key in ['GH_TOKEN', 'GITHUB_TOKEN', 'AGENT_DIRECTOR_TOKEN', 'GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY']:
    assert key not in os.environ, key
assert os.environ['RUSTC_WRAPPER'] == ''
assert os.environ['RUSTC_WORKSPACE_WRAPPER'] == ''
assert os.environ['CARRICK_SCCACHE'] == '0'
pathlib.Path('payload').write_text('candidate\n')
subprocess.run(['git', 'add', 'payload'], check=True)
subprocess.run(['git', 'commit', '-m', 'test(ci): fixture work'], check=True)
if fixture_case == 'boundary':
    pathlib.Path('.gitattributes').write_text('payload filter=runner\n')
    subprocess.run(['git', 'config', 'filter.runner.clean', 'echo privileged-filter >> ' + driver + '; cat'], check=True)
    pathlib.Path('payload').write_text('unfinished candidate\n')
result = sys.argv[sys.argv.index('--result-file') + 1]
pathlib.Path(result).write_text(json.dumps({'structured_output': {
    'status':'done', 'summary':'fixture-job-token implemented', 'tests':['fixture'], 'risks':[]}}))
print('stdout transcript fixture-job-token')
print('stderr transcript', file=sys.stderr)
print('x' * 70000)
"#.replace("FIXTURE_RESOURCES", &resources.to_string())).unwrap();
    for (name, script) in [
        (
            "git",
            r#"#!/bin/sh
for arg do
 case "$arg" in
 ls-remote) if test -f "$RUNNER_TEMP/push.tip"; then printf '%s\trefs/heads/work/dispatch-733-42\n' "$(cat "$RUNNER_TEMP/push.tip")"; fi; exit 0 ;;
 push) test ! -f "$RUNNER_TEMP/push.tip" || exit 93; /usr/bin/git rev-parse HEAD > "$RUNNER_TEMP/push.tip"; printf '%s\n' "$@" > "$RUNNER_TEMP/push.args"; exit 0 ;;
 esac
done
exec /usr/bin/git "$@"
"#,
        ),
        (
            "gh",
            r#"#!/bin/sh
previous=""
for arg do
 if [ "$previous" = --body-file ] && [ "$(wc -c < "$arg")" -gt 60000 ]; then exit 90; fi
 previous="$arg"
done
printf '%s\n' "$@" >> "$RUNNER_TEMP/gh.args"
if [ "$1" = api ]; then
 case "$2" in
 *'/pulls?'*) if test -f "$RUNNER_TEMP/pr.created"; then cat "$RUNNER_TEMP/pr.json"; else echo '[]'; fi ;;
 *'/actions/runs/42') cat "$RUNNER_TEMP/run.json" ;;
 *) echo '[]' ;;
 esac
else
 if [ "$1 $2" = 'pr create' ]; then test ! -f "$RUNNER_TEMP/pr.created" || exit 94; touch "$RUNNER_TEMP/pr.created"; fi
 echo 'https://github.com/carrick-sh/carrick/pull/1'
fi
"#,
        ),
    ] {
        let path = bin.join(name);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(temp.path().join("pr.json"), json!([{"number":1,"user":{"login":"github-actions[bot]","type":"Bot"},"head":{"repo":{"full_name":"carrick-sh/carrick"},"ref":"work/dispatch-733-42"},"base":{"ref":"main"},"draft":true,"body":"Closes #733\nDispatch run: https://github.com/carrick-sh/carrick/actions/runs/42"}]).to_string()).unwrap();
    std::fs::write(temp.path().join("run.json"), json!({"id":42,"path":".github/workflows/dispatch-worker.yml","event":"issues","head_branch":"main","repository":{"full_name":"carrick-sh/carrick"},"actor":{"login":"tjfontaine"}}).to_string()).unwrap();
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
            .envs((action != "run").then_some(("GH_TOKEN", "fixture-job-token")))
            .env("GITHUB_STEP_SUMMARY", &summary)
            .env("GITHUB_OUTPUT", &outputs)
            .output()
            .unwrap();
        assert!(output.status.success(), "{action}: {output:?}");
    };
    if matches!(case, "oversize" | "checkout") {
        let package = temp.path().join("dispatch-output");
        std::fs::create_dir(&package).unwrap();
        std::fs::File::create(package.join("raw.log"))
            .unwrap()
            .set_len(21 * 1024 * 1024)
            .unwrap();
        if case == "checkout" {
            std::fs::write(root.join(".git/HEAD"), "broken\n").unwrap();
        }
        invoke("complete");
        assert!(
            std::fs::read_to_string(temp.path().join("gh.args"))
                .unwrap()
                .contains("issue\ncomment\n733\n")
        );
        assert!(
            std::fs::read_to_string(&outputs)
                .unwrap()
                .contains("worker_failed=true")
        );
        assert!(!temp.path().join("push.args").exists());
        for entry in std::fs::read_dir(package).unwrap() {
            let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            assert!(!text.contains("fixture-job-token"));
        }
        return;
    }
    invoke("run");
    let raw = std::fs::read_to_string(temp.path().join("dispatch-output/raw.log")).unwrap();
    if case == "retirement" {
        let pid: i32 = raw
            .lines()
            .find_map(|l| l.strip_prefix("DETACHED "))
            .unwrap()
            .parse()
            .unwrap();
        println!("retirement witness detached pid={pid}");
        let alive = std::path::Path::new(&format!("/proc/{pid}"))
            .try_exists()
            .unwrap();
        if alive {
            assert!(
                Command::new("/usr/bin/sudo")
                    .args([
                        "-n",
                        "-u",
                        "carrick-dispatch-agent",
                        "--",
                        "/bin/kill",
                        "-KILL",
                        &pid.to_string()
                    ])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        if alive {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::path::Path::new(&format!("/proc/{pid}"))
                .try_exists()
                .unwrap()
                && std::time::Instant::now() < deadline
            {
                // SAFETY: reap only the fixture's known adopted detached PID.
                unsafe {
                    libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        assert!(
            !alive,
            "detached setsid child survived production process-group cleanup"
        );
    }
    if case == "boundary" || case == "secrets" {
        let facts: serde_json::Value = serde_json::from_str(
            raw.lines()
                .find_map(|l| l.strip_prefix("BOUNDARY "))
                .unwrap(),
        )
        .unwrap();
        let keys: &[&str] = if case == "secrets" {
            &["secrets", "auth"]
        } else {
            &[
                "uid",
                "user",
                "runner_env",
                "driver",
                "artifacts",
                "shell",
                "sudo",
                "groups",
            ]
        };
        for key in keys {
            assert_eq!(facts[*key], true, "agent boundary {key}: {facts}");
        }
    }
    assert!(!temp.path().join("push.args").exists());
    assert!(!temp.path().join("gh.args").exists());
    assert!(std::fs::read_to_string(&summary).unwrap().is_empty());
    invoke("complete");
    if case == "workflow" {
        assert!(
            !temp.path().join("push.args").exists(),
            "workflow modification was pushed"
        );
        assert!(!temp.path().join("pr.created").exists());
        assert!(
            std::fs::read_to_string(&summary)
                .unwrap()
                .contains("workflow")
        );
        assert!(
            std::fs::read_to_string(&outputs)
                .unwrap()
                .contains("worker_failed=true")
        );
        return;
    }
    if case == "rerun" {
        let retry = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(state.join("work"))
            .args([
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@localhost",
                "commit",
                "--allow-empty",
                "-m",
                "fixture rerun candidate",
            ])
            .output()
            .unwrap();
        assert!(retry.status.success(), "{retry:?}");
        invoke("complete");
        assert!(
            std::fs::read_to_string(&summary)
                .unwrap()
                .contains("Existing dispatch branch")
        );
    }
    if case == "boundary" {
        assert_eq!(
            std::fs::read_to_string(&driver).unwrap(),
            "runner executable",
            "agent git filter executed with runner authority"
        );
    }

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
    let outcome = std::fs::read_to_string(outputs).unwrap();
    assert_eq!(outcome.contains("worker_failed=true"), case == "boundary");
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
fn agent_phase_rejects_a_job_token_in_its_own_environment() {
    use std::process::Command;
    let mut command = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"));
    command.args(["dispatch-worker", "run", "--event", "/missing-event"]);
    let output = command.env("GH_TOKEN", "fixture-token").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("agent phase received a job token"));
    let output = command
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("agent phase received a job token"));
}

#[test]
#[cfg(target_os = "linux")]
fn oversized_partial_produce_still_reports() {
    foreground("oversize");
}

#[test]
fn agent_step_has_no_job_token() {
    let docs = YamlLoader::load_from_str(include_str!(
        "../../../.github/workflows/dispatch-worker.yml"
    ))
    .unwrap();
    let worker = docs[0]["jobs"]["worker"]["steps"]
        .as_vec()
        .unwrap()
        .iter()
        .find(|s| s["id"].as_str() == Some("worker"))
        .unwrap();
    assert!(worker["env"]["GH_TOKEN"].is_badvalue());
    assert!(!format!("{worker:?}").contains("github.token"));
}

#[test]
#[cfg(target_os = "linux")]
fn failed_checkout_still_reports() {
    foreground("checkout");
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
        Some("${{ steps.tier.outputs.base }}")
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
                ["bootstrap", "admission", "complete", "loop"]
                    .contains(&s["id"].as_str().unwrap_or(""))
                    || s["name"].as_str() == Some("Mask the job token before agent execution")
            );
        }
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
    std::fs::copy(env!("CARGO_BIN_EXE_carrick-xtask"), &alias).unwrap();
    let mut child = Command::new(&alias)
        .args(["tool", "read_state"])
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
        "head":{"ref":"work/dispatch-799-42","repo":{"full_name":"carrick-sh/carrick"}},
        "base":{"ref":"main"},"draft":true,"body":"Closes #799\nDispatch run: https://github.com/carrick-sh/carrick/actions/runs/42"});
    let issue = json!({"number":799,"title":"Fixture","state":"open","user":{"login":"tjfontaine","type":"User"},"body":"## Brief\nFixture", "labels":[{"name":"dispatch:sol-high"}]});
    let run = json!({"id":42,"path":".github/workflows/dispatch-worker.yml","event":"issues","head_branch":"main","repository":{"full_name":"carrick-sh/carrick"},"actor":{"login":"tjfontaine"}});
    for (name, value) in [
        ("pr.json", json!([pr.clone()])),
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
    */issues/799) cat "$RUNNER_TEMP/issue.json" ;;
    *'/pulls?'*) cat "$RUNNER_TEMP/pr.json" ;;
    *) exit 91 ;;
  esac
else
  test "$1 $2 $3" = 'pr comment 800'
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
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args([
            "dispatch-worker",
            "loop",
            "--setup-status",
            "failure/skipped",
            "--event",
        ])
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
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fallback outcome posted"),
        "{output:?}"
    );
    let report = std::fs::read_to_string(temp.path().join("posted.md")).unwrap();
    assert!(report.contains("Review continuation: Failed"));
    assert!(report.contains("Worker was not invoked"));
    assert!(report.contains("\"calls\":0"));
    assert!(
        report.contains("Dispatch run: https://github.com/carrick-sh/carrick/actions/runs/999")
    );
    assert!(!report.contains("fixture-job-token"));
    let calls = std::fs::read_to_string(temp.path().join("gh.args")).unwrap();
    assert!(calls.contains("pr\ncomment\n800\n"));
    assert!(!calls.contains("issue\ncomment"));
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
        .env("GH_TOKEN", "fixture-job-token")
        .env("CODEX_AUTH_JSON", "{\"token\":\"worker-codex-secret\"}")
        .env("AGY_OAUTH_TOKEN", "loop-agy-secret")
        .output()
        .unwrap();
    assert!(auth.status.success(), "{auth:?}");
    assert!(state.join("home/.codex/auth.json").is_file());
    assert!(!state.join("home/.gemini").exists());
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
