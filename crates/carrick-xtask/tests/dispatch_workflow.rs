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
    assert_eq!(permissions.len(), 3);
    for name in ["contents", "pull-requests", "issues"] {
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
fn provider_workflow_selects_only_the_admitted_backend() {
    let text = include_str!("../../../.github/workflows/dispatch-worker.yml");
    for (backend, secret) in [("codex", "CODEX_AUTH_JSON"), ("agy", "AGY_OAUTH_TOKEN")] {
        assert!(
            text.contains(&format!(
                "needs.guard.outputs.backend == '{backend}' && secrets.{secret} || ''"
            )),
            "unconditional provider secret: {secret}"
        );
    }
    assert!(text.contains("backend: ${{ steps.tier.outputs.backend }}"));
}

#[test]
fn git_configuration_comment_is_honest() {
    let source = include_str!("../src/dispatch_worker.rs");
    assert!(
        !source.contains("All repositories used by the driver have freshly created configuration.")
    );
}

#[test]
fn residual_documentation_is_honest() {
    let docs = include_str!("../../../docs/ci/dispatch-worker.md");
    for residual in [
        "dedicated",
        "refresh token",
        "25522481",
        "25523683",
        "40 minutes",
        "other runs",
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
fn foreground(case: &str) {
    static ACCOUNT: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _account = ACCOUNT.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: this serial fixture adopts only its own command descendants.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);

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
    sudo=subprocess.run(['/usr/bin/sudo', '-n', '/usr/bin/true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0)
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
                    .args(["-n", "/bin/kill", "-KILL", &pid.to_string()])
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
