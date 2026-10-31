#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use serde::Deserialize;
use std::collections::BTreeMap;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct Fixture {
    jobs: BTreeMap<String, Job>,
}
#[derive(Deserialize)]
struct Job {
    steps: Vec<Step>,
}
#[derive(Deserialize)]
struct Step {
    #[serde(rename = "if")]
    condition: String,
    run: String,
}

struct OwnedRunnerGroup {
    child: Child,
    status: Option<ExitStatus>,
}
impl OwnedRunnerGroup {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.status = Some(status);
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "runner fixture exceeded five seconds"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedRunnerGroup {
    fn drop(&mut self) {
        if self.status.is_none() {
            // Child is still owned and unreaped: this fresh group cannot be
            // confused with another invocation, including another test lane.
            let group = i32::try_from(self.child.id()).unwrap();
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
    }
}

fn fixture_run(hook: &str) -> (tempfile::TempDir, ExitStatus) {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/ci-scaler/rejected-job.yml")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hook.sh"), hook).unwrap();
    // A failed hook is a failed step, not a terminal job. This local worker
    // implements just the two fixture predicates, with controls proving both
    // execute after an ordinary hook failure. Terminal proof is OS process
    // death, independent of how a workflow scheduler evaluates these predicates.
    let mut worker = "failed=0\n/bin/sh hook.sh || failed=1\n".to_owned();
    for step in &fixture.jobs["rejected"].steps {
        match step.condition.as_str() {
            "always()" => worker.push_str(&format!("{}\n", step.run)),
            "failure()" => {
                worker.push_str(&format!("if [ \"$failed\" = 1 ]; then {}; fi\n", step.run))
            }
            _ => panic!("unsupported fixture predicate"),
        }
    }
    std::fs::write(dir.path().join("worker.sh"), worker).unwrap();
    // Listener -> worker -> actual hook, all in the dedicated group used by
    // the production setsid launch. No process in the test harness joins it.
    let child = Command::new("/bin/sh")
        .args([
            "-c",
            "/bin/sh worker.sh & wait; printf 'listener survived\\n' > listener-survived",
        ])
        .current_dir(dir.path())
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = OwnedRunnerGroup {
        child,
        status: None,
    }
    .wait();
    (dir, status)
}

#[test]
fn serial_host_rejected_hook_kills_worker_before_always_and_failure_steps() {
    let (control, status) = fixture_run("exit 1\n");
    assert!(status.success());
    assert!(control.path().join("always-ran").exists());
    assert!(control.path().join("failure-ran").exists());
    let source = include_str!("../../../scripts/ci/admit-job.sh");
    // Substitute only the policy decision: Admission::authorize has its own tests.
    // The complete production rejection wrapper executes unchanged.
    let hook = source.replace(
        "/usr/local/bin/carrick-xtask ci-scaler admit-job",
        "/usr/bin/false",
    );
    let (rejected, status) = fixture_run(&hook);
    assert!(
        !rejected.path().join("always-ran").exists()
            && !rejected.path().join("failure-ran").exists(),
        "rejected workflow executed always={} failure={}",
        rejected.path().join("always-ran").exists(),
        rejected.path().join("failure-ran").exists()
    );
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(!rejected.path().join("always-ran").exists());
    assert!(!rejected.path().join("failure-ran").exists());
    assert!(!rejected.path().join("listener-survived").exists());
    let hook = source.replace(
        "/usr/local/bin/carrick-xtask ci-scaler admit-job",
        "/usr/bin/true",
    );
    let (admitted, status) = fixture_run(&hook);
    assert!(status.success());
    assert!(admitted.path().join("always-ran").exists());
    assert!(!admitted.path().join("failure-ran").exists());
}

#[test]
fn launch_isolates_the_runner_group_before_it_can_receive_a_job() {
    let source = include_str!("../../../scripts/ci/runner-once.sh");
    assert!(
        source.contains("ACTIONS_RUNNER_INPUT_JITCONFIG=\"$jit\" /usr/bin/setsid --wait ./run.sh")
    );
    assert!(!source.contains("--jitconfig \"$jit\""));
}

#[test]
fn serial_host_cloudmac_hook_is_the_same_terminal_wrapper() {
    let state = tempfile::tempdir().unwrap();
    // The cloudmac hook is the shared script with only its xtask/policy/state
    // paths substituted; the decision itself is substituted here as above.
    let rejected = carrick_xtask::ci_scaler::mac_hook_script(
        std::path::Path::new("/usr/bin/false"),
        state.path(),
    )
    .unwrap();
    assert!(rejected.contains("--state-dir"));
    let (dir, status) = fixture_run(&rejected);
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(!dir.path().join("always-ran").exists());
    assert!(!dir.path().join("failure-ran").exists());
    assert!(!dir.path().join("listener-survived").exists());
    let admitted = carrick_xtask::ci_scaler::mac_hook_script(
        std::path::Path::new("/usr/bin/true"),
        state.path(),
    )
    .unwrap();
    let (dir, status) = fixture_run(&admitted);
    assert!(status.success());
    assert!(dir.path().join("always-ran").exists());
}

#[test]
fn serial_host_standing_hook_admits_a_re_vetted_assignment_and_kills_a_refused_one() {
    // Issue #333: GitHub assigned the clone minted for run A a job from run B.
    // Only the controller's re-vet may admit B, or the reserved run A.
    let hook = carrick_xtask::ci_scaler::standing_hook_script().unwrap();
    let bound = "/usr/local/bin/carrick-xtask ci-scaler admit-job";
    let revet = format!("{bound} --controller");
    assert!(
        hook.contains(&revet),
        "standing hook never asks for a re-vet"
    );
    // Both reserved and reassigned jobs require the controller's approval.
    let (dir, status) = fixture_run(&hook.replace(&revet, "/usr/bin/true"));
    assert!(status.success(), "re-vetted assignment was refused");
    assert!(dir.path().join("always-ran").exists());
    // Withheld approval kills the whole session before any workflow step.
    let (dir, status) = fixture_run(&hook.replace(&revet, "/usr/bin/false"));
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(!dir.path().join("always-ran").exists());
    assert!(!dir.path().join("failure-ran").exists());
    assert!(!dir.path().join("listener-survived").exists());
}

#[test]
fn cloudmac_launch_isolates_the_runner_session_before_it_can_receive_a_job() {
    let source = include_str!("../src/ci_scaler/mac.rs");
    assert!(source.contains("libc::setsid()"));
    assert!(source.contains("ACTIONS_RUNNER_HOOK_JOB_STARTED"));
    assert!(source.contains(".env(\"ACTIONS_RUNNER_INPUT_JITCONFIG\", &jit)"));
    assert!(!source.contains(".arg(\"--jitconfig\")"));
    assert!(source.contains("libc::setuid(uid)"));
}

#[test]
fn serial_host_reserved_standing_job_cannot_bypass_controller_rendezvous() {
    let bin = tempfile::tempdir().unwrap();
    let fake = bin.path().join("admit");
    std::fs::write(&fake,"#!/bin/sh\ncase \" $* \" in\n  *' --controller '*) touch rendezvous-requested; exit 1 ;;\n  *) touch reserved-bypass; exit 0 ;;\nesac\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let hook = carrick_xtask::ci_scaler::standing_hook_script()
        .unwrap()
        .replace(
            "/usr/local/bin/carrick-xtask ci-scaler admit-job",
            fake.to_str().unwrap(),
        );
    let (dir, status) = fixture_run(&hook);
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "a reserved job with no controller approval must fail at the hook"
    );
    assert!(dir.path().join("rendezvous-requested").exists());
    assert!(!dir.path().join("reserved-bypass").exists());
}

#[test]
fn agent_auth_provisions_all_worker_credentials_and_only_agy_for_loop() {
    use std::os::unix::fs::PermissionsExt;
    let xtask = env!("CARGO_BIN_EXE_carrick-xtask");
    for backend in ["codex", "agy"] {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("carrick-agent-42-1");
        let home = state.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let event = temp.path().join("event.json");
        let label = if backend == "codex" {
            "dispatch:sol-high"
        } else {
            "dispatch:opus"
        };
        std::fs::write(&event, serde_json::json!({"repository":{"full_name":"carrick-sh/carrick"},
            "action":"labeled","sender":{"login":"tjfontaine","type":"User"},
            "label":{"name":label},"issue":{"number":634,"user":{"login":"tjfontaine"},"title":"Fixture","body":"## Brief\nImplement fixture"}}).to_string()).unwrap();
        // The guard checks the trigger's collaborator permission and reads
        // the issue brief live (#1214). A fake `gh` answers both, so the test
        // never reaches GitHub through a developer's logged-in `gh`.
        let fake_bin = temp.path().join("bin");
        std::fs::create_dir_all(&fake_bin).unwrap();
        let fake_gh = fake_bin.join("gh");
        std::fs::write(
            &fake_gh,
            r###"#!/bin/sh
case " $* " in
  *collaborators/tjfontaine/permission*) echo '{"permission":"admin"}' ;;
  *graphql*) printf '%s\n' '{"data":{"repository":{"issue":{"number":634,"author":{"login":"tjfontaine"},"title":"Fixture","lastEditedAt":null,"editor":null,"body":"## Brief\nImplement fixture","renames":{"pageInfo":{"hasPreviousPage":false},"nodes":[]}}}}}' ;;
  *) echo "fake gh: unexpected call: $*" >&2; exit 1 ;;
esac
"###,
        )
        .unwrap();
        std::fs::set_permissions(&fake_gh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let invoke = |args: &[&str]| {
            Command::new(xtask)
                .args(args)
                .env("PATH", &path)
                .env_remove("GH_TOKEN")
                .env_remove("GITHUB_TOKEN")
                .env("GITHUB_SHA", "a".repeat(40))
                .env("RUNNER_TEMP", temp.path())
                .env("GITHUB_RUN_ID", "42")
                .env("GITHUB_RUN_ATTEMPT", "1")
                .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
                .env("CODEX_AUTH_JSON", r#"{"access_token":"codex-only-secret"}"#)
                .env("AGY_OAUTH_TOKEN", "agy-only-secret\nraw")
                .output()
                .unwrap()
        };
        let admitted = invoke(&[
            "dispatch-worker",
            "guard",
            "--admit",
            "--event",
            event.to_str().unwrap(),
        ]);
        assert!(admitted.status.success(), "{admitted:?}");
        let output = invoke(&["agent-runner", "auth", "--event", event.to_str().unwrap()]);
        assert!(output.status.success(), "{output:?}");
        for secret in ["codex-only-secret", "agy-only-secret"] {
            assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
            assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
        }
        let auth = if backend == "codex" {
            home.join(".codex/auth.json")
        } else {
            home.join(".gemini/antigravity-cli/antigravity-oauth-token")
        };
        assert_eq!(auth.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        if backend == "agy" {
            assert_eq!(std::fs::read(&auth).unwrap(), b"agy-only-secret\nraw");
            assert_eq!(
                std::fs::read_dir(auth.parent().unwrap()).unwrap().count(),
                1
            );
        }
        let remembered = std::fs::read_to_string(state.join("redaction-secrets.json")).unwrap();
        let unselected = if backend == "codex" {
            "agy-only-secret"
        } else {
            "codex-only-secret"
        };
        assert!(remembered.contains(unselected));
        assert!(home.join(".codex").exists());
        assert!(home.join(".gemini").exists());
        assert!(!state.join("loop-home/.codex").exists());
        assert!(state.join("loop-home/.gemini").exists());
        assert!(
            !invoke(&["agent-runner", "auth", "--event", event.to_str().unwrap()])
                .status
                .success()
        );
        assert!(invoke(&["agent-runner", "cleanup"]).status.success());
        assert!(!state.exists());
        assert!(invoke(&["agent-runner", "cleanup"]).status.success());
    }
}

#[test]
fn bootstrap_without_a_controller_token_stops_before_downloads() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    // An inherited GH_TOKEN would satisfy these stubs; bootstrap must not
    // fall back to it when the controller mints nothing (#1034).
    for (name, source) in [
        (
            "gh",
            "#!/bin/sh\ntouch \"$RUNNER_TEMP/inherited-token-used\"\nexit 0\n",
        ),
        (
            "git",
            "#!/bin/sh\ntouch \"$RUNNER_TEMP/inherited-token-used\"\nexit 0\n",
        ),
        (
            "curl",
            "#!/bin/sh\ntouch \"$RUNNER_TEMP/download-started\"\nexit 91\n",
        ),
    ] {
        let path = bin.join(name);
        std::fs::write(&path, source).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_carrick-xtask"))
        .args(["agent-runner", "bootstrap"])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("GH_TOKEN", "fixture-only-secret")
        .env("RUNNER_TEMP", temp.path())
        .env("GITHUB_RUN_ID", "42")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("host/infra"), "{stderr}");
    assert!(
        stderr.contains("no controller-minted bootstrap token"),
        "{stderr}"
    );
    assert!(stderr.contains("uses no other token"), "{stderr}");
    assert!(!stderr.contains("fixture-only-secret"));
    assert!(!temp.path().join("inherited-token-used").exists());
    assert!(!temp.path().join("download-started").exists());
    assert!(!temp.path().join("carrick-agent-42-1").exists());
}

fn hvf_hook_script_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/ci")
        .join(name)
}

fn hvf_auth_env(
    xtask: &std::path::Path,
    policy: &std::path::Path,
    workspace: &std::path::Path,
    runner_temp: &std::path::Path,
    github_env: &std::path::Path,
) -> Vec<(String, String)> {
    vec![
        (
            "PATH".into(),
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        ),
        ("CARRICK_XTASK".into(), xtask.display().to_string()),
        (
            "CARRICK_CI_POLICY_FILE".into(),
            policy.display().to_string(),
        ),
        ("CARRICK_HVF_MIN_FREE_GIB".into(), "1".into()),
        ("GITHUB_WORKSPACE".into(), workspace.display().to_string()),
        ("RUNNER_TEMP".into(), runner_temp.display().to_string()),
        ("GITHUB_ENV".into(), github_env.display().to_string()),
        ("GITHUB_REPOSITORY".into(), "carrick-sh/carrick".into()),
        ("GITHUB_EVENT_NAME".into(), "push".into()),
        ("GITHUB_ACTOR".into(), "tjfontaine".into()),
        ("GITHUB_TRIGGERING_ACTOR".into(), "tjfontaine".into()),
        (
            "GITHUB_WORKFLOW_REF".into(),
            "carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main".into(),
        ),
        ("GITHUB_REF".into(), "refs/heads/main".into()),
        ("GITHUB_SHA".into(), "a".repeat(40)),
        ("GITHUB_RUN_ID".into(), "4242".into()),
        ("GITHUB_RUN_ATTEMPT".into(), "1".into()),
    ]
}

fn run_isolated_hook_session(
    script: &std::path::Path,
    envs: &[(String, String)],
) -> (tempfile::TempDir, ExitStatus) {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/ci-scaler/rejected-job.yml")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut worker = format!("failed=0\n/bin/sh '{}' || failed=1\n", script.display());
    for step in &fixture.jobs["rejected"].steps {
        match step.condition.as_str() {
            "always()" => worker.push_str(&format!("{}\n", step.run)),
            "failure()" => {
                worker.push_str(&format!("if [ \"$failed\" = 1 ]; then {}; fi\n", step.run))
            }
            _ => panic!("unsupported fixture predicate"),
        }
    }
    std::fs::write(dir.path().join("worker.sh"), worker).unwrap();
    let mut cmd = Command::new("/bin/sh");
    cmd.args([
        "-c",
        "/bin/sh worker.sh & wait; printf 'listener survived\\n' > listener-survived",
    ])
    .current_dir(dir.path())
    .env_clear()
    .process_group(0)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let child = cmd.spawn().unwrap();
    let status = OwnedRunnerGroup {
        child,
        status: None,
    }
    .wait();
    (dir, status)
}

#[test]
fn serial_host_hvf_job_started_kills_session_on_policy_rejection_or_empty_auth_vars() {
    use std::os::unix::fs::PermissionsExt;
    let script = hvf_hook_script_path("hvf-job-started.sh");
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    let etc = temp.path().join("etc");
    let workspace = temp.path().join("workspace");
    let runner_temp = temp.path().join("runner-temp");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::create_dir_all(workspace.join("target")).unwrap();
    std::fs::write(workspace.join("target/untouched-before-auth"), "keep").unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();
    let github_env = runner_temp.join("github.env");

    let policy = etc.join("policy");
    std::fs::write(&policy, "standing\n").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();

    // Real xtask binary rejects a non-root policy file when unprivileged, and
    // the hook terminates the session before conditional steps or target pruning.
    if unsafe { libc::geteuid() } != 0 {
        let real_xtask = std::path::Path::new(env!("CARGO_BIN_EXE_carrick-xtask"));
        let envs = hvf_auth_env(real_xtask, &policy, &workspace, &runner_temp, &github_env);
        let (session, status) = run_isolated_hook_session(&script, &envs);
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(!session.path().join("always-ran").exists());
        assert!(!session.path().join("failure-ran").exists());
        assert!(!session.path().join("listener-survived").exists());
        assert!(workspace.join("target/untouched-before-auth").exists());
    }

    let marker = temp.path().join("xtask-invoked");
    let fake_xtask = bin.join("fake-xtask");
    std::fs::write(
        &fake_xtask,
        format!(
            "#!/bin/sh\ntouch '{}'\n[ \"$1\" = \"ci-scaler\" ] && [ \"$2\" = \"admit-job\" ] && [ \"$3\" = \"--policy-file\" ] && [ \"$4\" = '{}' ] && [ \"${{ADMIT_DECISION:-0}}\" = \"0\" ]\n",
            marker.display(),
            policy.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_xtask, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Policy rejection from admit-job kills the whole runner process group.
    let mut rejected_env =
        hvf_auth_env(&fake_xtask, &policy, &workspace, &runner_temp, &github_env);
    rejected_env.push(("ADMIT_DECISION".into(), "1".into()));
    let (session, status) = run_isolated_hook_session(&script, &rejected_env);
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(marker.exists());
    assert!(!session.path().join("always-ran").exists());
    assert!(!session.path().join("failure-ran").exists());
    assert!(!session.path().join("listener-survived").exists());

    // Every required authorization variable must reject unset, empty, and whitespace-only values
    // before invoking xtask, and must terminate the session group.
    for required in [
        "GITHUB_REPOSITORY",
        "GITHUB_EVENT_NAME",
        "GITHUB_ACTOR",
        "GITHUB_TRIGGERING_ACTOR",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ] {
        for bad_val in [None, Some(""), Some("   "), Some("bad\nline")] {
            let _ = std::fs::remove_file(&marker);
            let mut envs =
                hvf_auth_env(&fake_xtask, &policy, &workspace, &runner_temp, &github_env);
            envs.retain(|(k, _)| k != required);
            if let Some(val) = bad_val {
                envs.push((required.into(), val.into()));
            }
            let (session, status) = run_isolated_hook_session(&script, &envs);
            assert_eq!(
                status.signal(),
                Some(libc::SIGKILL),
                "{required}={bad_val:?} did not kill session"
            );
            assert!(
                !marker.exists(),
                "xtask should not run when {required}={bad_val:?}"
            );
            assert!(!session.path().join("always-ran").exists());
            assert!(!session.path().join("failure-ran").exists());
        }
    }

    // Empty or non-canonical CARRICK_XTASK / CARRICK_CI_POLICY_FILE overrides also kill the session.
    for (key, bad) in [
        ("CARRICK_XTASK", ""),
        ("CARRICK_XTASK", "   "),
        ("CARRICK_XTASK", "relative/xtask"),
        ("CARRICK_XTASK", "/tmp/../bin/xtask"),
        ("CARRICK_CI_POLICY_FILE", ""),
        ("CARRICK_CI_POLICY_FILE", "   "),
        ("CARRICK_CI_POLICY_FILE", "relative/policy"),
        ("CARRICK_CI_POLICY_FILE", "/tmp/../etc/policy"),
    ] {
        let _ = std::fs::remove_file(&marker);
        let mut envs = hvf_auth_env(&fake_xtask, &policy, &workspace, &runner_temp, &github_env);
        envs.retain(|(k, _)| k != key);
        envs.push((key.into(), bad.into()));
        let (session, status) = run_isolated_hook_session(&script, &envs);
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{key}={bad:?}");
        assert!(!marker.exists(), "{key}={bad:?}");
        assert!(!session.path().join("always-ran").exists());
    }
}

#[test]
fn serial_host_hvf_job_started_enforces_workspace_guards_reclaims_target_and_checks_disk() {
    use std::os::unix::fs::PermissionsExt;
    let script = hvf_hook_script_path("hvf-job-started.sh");
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    let etc = temp.path().join("etc");
    let workspace = temp.path().join("workspace");
    let runner_temp = temp.path().join("runner-temp");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();
    let github_env = temp.path().join("github.env");

    let policy = etc.join("policy");
    std::fs::write(&policy, "standing\n").unwrap();
    let fake_xtask = bin.join("fake-xtask");
    std::fs::write(&fake_xtask, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&fake_xtask, std::fs::Permissions::from_mode(0o755)).unwrap();

    let run_hook = |overrides: &[(&str, Option<&str>)]| {
        let mut envs = hvf_auth_env(&fake_xtask, &policy, &workspace, &runner_temp, &github_env);
        for (k, v) in overrides {
            envs.retain(|(ek, _)| ek != k);
            if let Some(val) = v {
                envs.push(((*k).into(), (*val).into()));
            }
        }
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(&script).current_dir(&workspace).env_clear();
        for (k, v) in &envs {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };

    // Strict empty-variable and canonical-directory guards on workspace, temp, env, and disk floor.
    let link_ws = temp.path().join("workspace-link");
    std::os::unix::fs::symlink(&workspace, &link_ws).unwrap();
    let link_tmp = temp.path().join("temp-link");
    std::os::unix::fs::symlink(&runner_temp, &link_tmp).unwrap();
    let link_env = temp.path().join("env-link");
    std::os::unix::fs::symlink(&github_env, &link_env).unwrap();

    let ws_slash = format!("{}/", workspace.display());
    let ws_double = format!("{}//sub", temp.path().display());
    let ws_dotdot = format!("{}/../workspace", workspace.display());
    let nested_tmp = workspace.join("nested-temp");
    std::fs::create_dir_all(&nested_tmp).unwrap();

    for (label, overrides) in [
        ("unset GITHUB_WORKSPACE", vec![("GITHUB_WORKSPACE", None)]),
        (
            "empty GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(""))],
        ),
        (
            "whitespace GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("   "))],
        ),
        (
            "relative GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("relative/path"))],
        ),
        (
            "root GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("/"))],
        ),
        (
            "top-level GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("/tmp"))],
        ),
        (
            "trailing-slash GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(ws_slash.as_str()))],
        ),
        (
            "double-slash GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(ws_double.as_str()))],
        ),
        (
            "dotdot GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(ws_dotdot.as_str()))],
        ),
        (
            "symlink GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(link_ws.to_str().unwrap()))],
        ),
        ("unset RUNNER_TEMP", vec![("RUNNER_TEMP", None)]),
        ("empty RUNNER_TEMP", vec![("RUNNER_TEMP", Some(""))]),
        (
            "symlink RUNNER_TEMP",
            vec![("RUNNER_TEMP", Some(link_tmp.to_str().unwrap()))],
        ),
        (
            "same GITHUB_WORKSPACE and RUNNER_TEMP",
            vec![("RUNNER_TEMP", Some(workspace.to_str().unwrap()))],
        ),
        (
            "RUNNER_TEMP inside GITHUB_WORKSPACE",
            vec![("RUNNER_TEMP", Some(nested_tmp.to_str().unwrap()))],
        ),
        ("empty GITHUB_ENV", vec![("GITHUB_ENV", Some(""))]),
        (
            "relative GITHUB_ENV",
            vec![("GITHUB_ENV", Some("relative.env"))],
        ),
        (
            "symlink GITHUB_ENV",
            vec![("GITHUB_ENV", Some(link_env.to_str().unwrap()))],
        ),
        (
            "empty SCCACHE_SERVER_UDS",
            vec![("SCCACHE_SERVER_UDS", Some(""))],
        ),
        (
            "relative SCCACHE_SERVER_UDS",
            vec![("SCCACHE_SERVER_UDS", Some("sccache.sock"))],
        ),
        (
            "empty CARRICK_HVF_MIN_FREE_GIB",
            vec![("CARRICK_HVF_MIN_FREE_GIB", Some(""))],
        ),
        (
            "zero CARRICK_HVF_MIN_FREE_GIB",
            vec![("CARRICK_HVF_MIN_FREE_GIB", Some("0"))],
        ),
        (
            "non-numeric CARRICK_HVF_MIN_FREE_GIB",
            vec![("CARRICK_HVF_MIN_FREE_GIB", Some("40G"))],
        ),
    ] {
        let out = run_hook(&overrides);
        assert!(
            !out.status.success(),
            "{label} unexpectedly succeeded: {out:?}"
        );
    }
    std::fs::remove_dir_all(&nested_tmp).unwrap();

    // Symlinked $GITHUB_WORKSPACE/target is refused without touching the target directory.
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep.txt"), "precious").unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("target")).unwrap();
    let out = run_hook(&[]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("symlinked target path"),
        "{out:?}"
    );
    assert!(outside.join("keep.txt").exists());
    std::fs::remove_file(workspace.join("target")).unwrap();

    // Simulated cloudmac 34 GiB free condition fails up front against default 40 GiB floor.
    let fake_df = bin.join("df");
    std::fs::write(
        &fake_df,
        format!(
            "#!/bin/sh\nif [ -e '{}/target' ]; then\n  avail=$((34 * 1048576))\nelse\n  avail=\"${{FAKE_DF_AVAIL_KIB:-$((34 * 1048576))}}\"\nfi\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/disk3s1 244000000 100000000 %s 42%% /Volumes/carrick-hvf\\n' \"$avail\"\n",
            workspace.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_df, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path_with_fake_df = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
    );

    let low_disk = run_hook(&[
        ("PATH", Some(&path_with_fake_df)),
        ("CARRICK_HVF_MIN_FREE_GIB", None),
    ]);
    assert!(!low_disk.status.success(), "{low_disk:?}");
    let stdout = String::from_utf8_lossy(&low_disk.stdout);
    let stderr = String::from_utf8_lossy(&low_disk.stderr);
    assert!(
        stdout.contains("::error title=HVF disk admission failed::")
            && stdout.contains("34 GiB")
            && stdout.contains("40 GiB"),
        "stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(stderr.contains("below the 40 GiB minimum"), "{stderr}");

    // Leftover read-only target/ from an interrupted run is reclaimed BEFORE df is sampled,
    // allowing admission to succeed when reclaiming target/ restores free space >= 40 GiB.
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/lib.rs"), "pub fn keep() {}\n").unwrap();
    let ro_dir = workspace.join("target/readonly");
    std::fs::create_dir_all(&ro_dir).unwrap();
    std::fs::write(ro_dir.join("stale.o"), "stale").unwrap();
    std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o500)).unwrap();

    let reclaimed = run_hook(&[
        ("PATH", Some(&path_with_fake_df)),
        ("CARRICK_HVF_MIN_FREE_GIB", None),
        ("FAKE_DF_AVAIL_KIB", Some("125829120")), // 120 GiB once target/ is removed
    ]);
    assert!(reclaimed.status.success(), "{reclaimed:?}");
    assert!(!workspace.join("target").exists());
    assert!(workspace.join("src/lib.rs").exists());
    let env_contents = std::fs::read_to_string(&github_env).unwrap();
    assert_eq!(
        env_contents,
        format!(
            "SCCACHE_SERVER_UDS={}/sccache.sock\n",
            runner_temp.display()
        )
    );

    // Real OS df -Pk also fails closed when threshold exceeds actual disk space.
    let impossible_floor = run_hook(&[("CARRICK_HVF_MIN_FREE_GIB", Some("999999"))]);
    assert!(!impossible_floor.status.success());
}

#[test]
fn serial_host_hvf_job_completed_enforces_strict_guards_and_prunes_target_safely() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    let script = hvf_hook_script_path("hvf-job-completed.sh");
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    let workspace = temp.path().join("workspace");
    let runner_temp = temp.path().join("runner-temp");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();

    let run_completed = |overrides: &[(&str, Option<&str>)]| {
        let mut envs: Vec<(String, String)> = vec![
            (
                "PATH".into(),
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into())
                ),
            ),
            ("GITHUB_WORKSPACE".into(), workspace.display().to_string()),
            ("RUNNER_TEMP".into(), runner_temp.display().to_string()),
            ("GITHUB_RUN_ID".into(), "4242".into()),
            ("GITHUB_RUN_ATTEMPT".into(), "1".into()),
        ];
        for (k, v) in overrides {
            envs.retain(|(ek, _)| ek != k);
            if let Some(val) = v {
                envs.push(((*k).into(), (*val).into()));
            }
        }
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(&script).current_dir(&workspace).env_clear();
        for (k, v) in &envs {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };

    let link_ws = temp.path().join("ws-link");
    std::os::unix::fs::symlink(&workspace, &link_ws).unwrap();
    let link_tmp = temp.path().join("tmp-link");
    std::os::unix::fs::symlink(&runner_temp, &link_tmp).unwrap();
    let ws_slash = format!("{}/", workspace.display());
    let ws_dotdot = format!("{}/../workspace", workspace.display());
    let ws_evil_bin = workspace.join("evil-sccache");
    std::fs::write(&ws_evil_bin, "#!/bin/sh\ntouch evil-ran\n").unwrap();
    std::fs::set_permissions(&ws_evil_bin, std::fs::Permissions::from_mode(0o755)).unwrap();

    for (label, overrides) in [
        ("unset GITHUB_WORKSPACE", vec![("GITHUB_WORKSPACE", None)]),
        (
            "empty GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(""))],
        ),
        (
            "whitespace GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("   "))],
        ),
        (
            "relative GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("relative/work"))],
        ),
        (
            "root GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("/"))],
        ),
        (
            "top-level GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("/tmp"))],
        ),
        (
            "trailing-slash GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(ws_slash.as_str()))],
        ),
        (
            "dotdot GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(ws_dotdot.as_str()))],
        ),
        (
            "symlink GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some(link_ws.to_str().unwrap()))],
        ),
        ("unset RUNNER_TEMP", vec![("RUNNER_TEMP", None)]),
        ("empty RUNNER_TEMP", vec![("RUNNER_TEMP", Some(""))]),
        (
            "symlink RUNNER_TEMP",
            vec![("RUNNER_TEMP", Some(link_tmp.to_str().unwrap()))],
        ),
        (
            "overlapping dirs",
            vec![("RUNNER_TEMP", Some(workspace.to_str().unwrap()))],
        ),
        ("empty GITHUB_RUN_ID", vec![("GITHUB_RUN_ID", Some(""))]),
        ("zero GITHUB_RUN_ID", vec![("GITHUB_RUN_ID", Some("0"))]),
        ("bad GITHUB_RUN_ID", vec![("GITHUB_RUN_ID", Some("run-1"))]),
        (
            "empty GITHUB_RUN_ATTEMPT",
            vec![("GITHUB_RUN_ATTEMPT", Some(""))],
        ),
        (
            "zero GITHUB_RUN_ATTEMPT",
            vec![("GITHUB_RUN_ATTEMPT", Some("0"))],
        ),
        (
            "empty SCCACHE_SERVER_UDS",
            vec![("SCCACHE_SERVER_UDS", Some(""))],
        ),
        (
            "relative SCCACHE_SERVER_UDS",
            vec![("SCCACHE_SERVER_UDS", Some("rel.sock"))],
        ),
        (
            "empty CARRICK_SCCACHE_BIN",
            vec![("CARRICK_SCCACHE_BIN", Some(""))],
        ),
        (
            "relative CARRICK_SCCACHE_BIN",
            vec![("CARRICK_SCCACHE_BIN", Some("./evil-sccache"))],
        ),
        (
            "workspace CARRICK_SCCACHE_BIN",
            vec![("CARRICK_SCCACHE_BIN", Some(ws_evil_bin.to_str().unwrap()))],
        ),
    ] {
        let out = run_completed(&overrides);
        assert!(
            !out.status.success(),
            "{label} unexpectedly succeeded: {out:?}"
        );
        assert!(!workspace.join("evil-ran").exists());
    }
    std::fs::remove_file(&ws_evil_bin).unwrap();

    // Symlinked $GITHUB_WORKSPACE/target is refused without touching the target directory.
    let outside_ro = temp.path().join("outside-readonly");
    std::fs::create_dir_all(&outside_ro).unwrap();
    std::fs::write(outside_ro.join("precious"), "keep").unwrap();
    std::fs::set_permissions(&outside_ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::os::unix::fs::symlink(&outside_ro, workspace.join("target")).unwrap();
    let refused = run_completed(&[]);
    assert!(!refused.status.success());
    assert!(outside_ro.join("precious").exists());
    std::fs::remove_file(workspace.join("target")).unwrap();

    // Real target/ with read-only subdirs AND a symlink to outside_ro is pruned cleanly
    // without following the symlink or altering outside_ro's permissions, while stopping
    // the per-job sccache socket.
    let sccache_stopped = temp.path().join("sccache-stopped");
    let fake_sccache = bin.join("sccache");
    std::fs::write(
        &fake_sccache,
        format!(
            "#!/bin/sh\nif [ \"$1\" = \"--stop-server\" ]; then printf '%s\\n' \"$SCCACHE_SERVER_UDS\" >> '{}'; fi\n",
            sccache_stopped.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake_sccache, std::fs::Permissions::from_mode(0o755)).unwrap();
    let sock_path = runner_temp.join("sccache.sock");
    let _listener = UnixListener::bind(&sock_path).unwrap();

    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/main.rs"), "fn main() {}\n").unwrap();
    let ro_sub = workspace.join("target/release/ro-bundle");
    std::fs::create_dir_all(&ro_sub).unwrap();
    std::fs::write(ro_sub.join("blob"), "artifact").unwrap();
    std::fs::set_permissions(&ro_sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::os::unix::fs::symlink(&outside_ro, workspace.join("target/escaped-link")).unwrap();

    let ok = run_completed(&[]);
    assert!(ok.status.success(), "{ok:?}");
    assert!(!workspace.join("target").exists());
    assert!(workspace.join("src/main.rs").exists());
    assert!(outside_ro.join("precious").exists());
    assert_eq!(
        std::fs::metadata(&outside_ro).unwrap().permissions().mode() & 0o777,
        0o500
    );
    assert_eq!(
        std::fs::read_to_string(&sccache_stopped).unwrap(),
        format!("{}\n", sock_path.display())
    );

    // Restore write permission on outside_ro so TempDir drop cleans up cleanly,
    // and verify idempotency when target/ is already absent.
    std::fs::set_permissions(&outside_ro, std::fs::Permissions::from_mode(0o700)).unwrap();
    let second = run_completed(&[]);
    assert!(second.status.success(), "{second:?}");
}
