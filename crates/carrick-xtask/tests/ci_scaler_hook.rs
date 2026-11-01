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
    write_executable(
        &fake,
        "#!/bin/sh\ncase \" $* \" in\n  *' --controller '*) touch rendezvous-requested; exit 1 ;;\n  *) touch reserved-bypass; exit 0 ;;\nesac\n",
        0o755,
    );
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
        write_executable(
            &fake_gh,
            r###"#!/bin/sh
case " $* " in
  *collaborators/tjfontaine/permission*) echo '{"permission":"admin"}' ;;
  *graphql*) printf '%s\n' '{"data":{"repository":{"issue":{"number":634,"author":{"login":"tjfontaine"},"title":"Fixture","lastEditedAt":null,"editor":null,"body":"## Brief\nImplement fixture","renames":{"pageInfo":{"hasPreviousPage":false},"nodes":[]}}}}}' ;;
  *) echo "fake gh: unexpected call: $*" >&2; exit 1 ;;
esac
"###,
            0o755,
        );
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
        write_executable(&path, source, 0o700);
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

fn shell_quote_arg(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn copy_owner_only_xtask(dest_dir: &std::path::Path) -> std::path::PathBuf {
    let bin = dest_dir.join("carrick-xtask");
    copy_executable(
        std::path::Path::new(env!("CARGO_BIN_EXE_carrick-xtask")),
        &bin,
        0o755,
    );
    bin
}

/// Write an executable the test will exec, from a child shell. Sibling
/// tests in this binary run on parallel threads and fork; a fork that
/// inherits this process's writable descriptor for a fresh executable
/// makes the next exec of it fail with `ETXTBSY` (#1294's lint-gates). A
/// child's descriptor table is its own, so no sibling can inherit it.
fn write_executable(path: &std::path::Path, contents: &str, mode: u32) {
    use std::io::Write as _;
    let mut child = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod \"$2\" \"$1\"", "sh"])
        .arg(path)
        .arg(format!("{mode:o}"))
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "{}", path.display());
}

/// [`write_executable`] for a copy of an existing file.
fn copy_executable(source: &std::path::Path, dest: &std::path::Path, mode: u32) {
    let status = Command::new("/bin/sh")
        .args(["-c", "cp -- \"$1\" \"$2\" && chmod \"$3\" \"$2\"", "sh"])
        .arg(source)
        .arg(dest)
        .arg(format!("{mode:o}"))
        .status()
        .unwrap();
    assert!(status.success(), "{}", dest.display());
}

fn hvf_auth_env(
    workspace: &std::path::Path,
    runner_temp: &std::path::Path,
) -> Vec<(String, String)> {
    vec![
        (
            "PATH".into(),
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
        ),
        ("GITHUB_WORKSPACE".into(), workspace.display().to_string()),
        ("RUNNER_TEMP".into(), runner_temp.display().to_string()),
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

fn apply_env_overrides(
    base: &[(String, String)],
    overrides: &[(&str, Option<&str>)],
) -> Vec<(String, String)> {
    let mut envs = base.to_vec();
    for (k, v) in overrides {
        envs.retain(|(ek, _)| ek != k);
        if let Some(val) = v {
            envs.push(((*k).into(), (*val).into()));
        }
    }
    envs
}

fn run_isolated_hook_session(
    script: &std::path::Path,
    script_args: &[&str],
    envs: &[(String, String)],
) -> (tempfile::TempDir, ExitStatus) {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/ci-scaler/rejected-job.yml")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut invoke = format!("/bin/sh {}", shell_quote_arg(&script.display().to_string()));
    for arg in script_args {
        invoke.push(' ');
        invoke.push_str(&shell_quote_arg(arg));
    }
    let mut worker = format!("failed=0\n{invoke} || failed=1\n");
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
fn serial_host_hvf_job_started_refuses_env_overrides_and_writable_or_non_root_xtask_or_policy_before_execution()
 {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

    let uid = unsafe { libc::geteuid() };
    let uid_str = uid.to_string();
    let wrong_uid_str = uid.wrapping_add(1).to_string();

    let marker = temp.path().join("spy-xtask-executed");
    let spy_xtask = bin.join("spy-xtask");
    write_executable(
        &spy_xtask,
        &format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
        0o755,
    );

    let policy = etc.join("policy");
    std::fs::write(&policy, "standing\n").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();

    let base_env = hvf_auth_env(&workspace, &runner_temp);

    // 1. Environment overrides (`CARRICK_XTASK`, `CARRICK_CI_POLICY_FILE`) from `.env`
    //    must NEVER replace the hardcoded `/usr/local/bin/carrick-xtask` and `/etc/carrick-ci/policy`.
    let poisoned_env = apply_env_overrides(
        &base_env,
        &[
            ("CARRICK_XTASK", Some(spy_xtask.to_str().unwrap())),
            ("CARRICK_CI_POLICY_FILE", Some(policy.to_str().unwrap())),
        ],
    );
    let (session, status) = run_isolated_hook_session(&script, &[], &poisoned_env);
    assert!(
        !marker.exists(),
        "CARRICK_XTASK environment override executed spy binary"
    );
    if !std::path::Path::new("/usr/local/bin/carrick-xtask").exists()
        || !std::path::Path::new("/etc/carrick-ci/policy").exists()
    {
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(!session.path().join("always-ran").exists());
        assert!(!session.path().join("failure-ran").exists());
        assert!(!session.path().join("listener-survived").exists());
    }

    // 2. Non-root xtask is refused BEFORE execution.
    if uid != 0 {
        let (session, status) = run_isolated_hook_session(
            &script,
            &[
                "--test-xtask",
                spy_xtask.to_str().unwrap(),
                "--test-policy-file",
                policy.to_str().unwrap(),
            ],
            &base_env,
        );
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(
            !marker.exists(),
            "non-root xtask must be refused before execution"
        );
        assert!(!session.path().join("always-ran").exists());
        assert!(!session.path().join("failure-ran").exists());
        assert!(!session.path().join("listener-survived").exists());
    }
    let (session, status) = run_isolated_hook_session(
        &script,
        &[
            "--test-xtask",
            spy_xtask.to_str().unwrap(),
            "--test-policy-file",
            policy.to_str().unwrap(),
            "--test-owner-uid",
            &wrong_uid_str,
        ],
        &base_env,
    );
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(!marker.exists());
    assert!(!session.path().join("always-ran").exists());

    // 3. Group-writable, other-writable, non-executable, symlinked, or workspace-resident
    //    xtask is refused BEFORE execution.
    for bad_mode in [0o775, 0o757, 0o777, 0o644] {
        std::fs::set_permissions(&spy_xtask, std::fs::Permissions::from_mode(bad_mode)).unwrap();
        let (session, status) = run_isolated_hook_session(
            &script,
            &[
                "--test-xtask",
                spy_xtask.to_str().unwrap(),
                "--test-policy-file",
                policy.to_str().unwrap(),
                "--test-owner-uid",
                &uid_str,
            ],
            &base_env,
        );
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "xtask mode {bad_mode:o}"
        );
        assert!(
            !marker.exists(),
            "xtask with mode {bad_mode:o} executed instead of failing closed beforehand"
        );
        assert!(!session.path().join("always-ran").exists());
    }
    std::fs::set_permissions(&spy_xtask, std::fs::Permissions::from_mode(0o755)).unwrap();

    let xtask_link = bin.join("xtask-link");
    std::os::unix::fs::symlink(&spy_xtask, &xtask_link).unwrap();
    let (_, status) = run_isolated_hook_session(
        &script,
        &[
            "--test-xtask",
            xtask_link.to_str().unwrap(),
            "--test-policy-file",
            policy.to_str().unwrap(),
            "--test-owner-uid",
            &uid_str,
        ],
        &base_env,
    );
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(!marker.exists(), "symlinked xtask executed");

    let ws_xtask = workspace.join("ws-xtask");
    copy_executable(&spy_xtask, &ws_xtask, 0o755);
    let (_, status) = run_isolated_hook_session(
        &script,
        &[
            "--test-xtask",
            ws_xtask.to_str().unwrap(),
            "--test-policy-file",
            policy.to_str().unwrap(),
            "--test-owner-uid",
            &uid_str,
        ],
        &base_env,
    );
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(!marker.exists(), "workspace-resident xtask executed");
    std::fs::remove_file(&ws_xtask).unwrap();

    // 4. Non-root, group-writable, other-writable, symlinked, or workspace-resident
    //    policy file is refused BEFORE xtask executes.
    if uid != 0
        && let Some(root_true) = ["/usr/bin/true", "/bin/true"]
            .into_iter()
            .find(|candidate| {
                std::fs::symlink_metadata(candidate).is_ok_and(|meta| {
                    meta.is_file() && meta.uid() == 0 && meta.permissions().mode() & 0o022 == 0
                })
            })
    {
        // `root_true` satisfies root-owned executable checks and would exit 0 if invoked;
        // non-root `policy` must still cause pre-execution SIGKILL.
        let (session, status) = run_isolated_hook_session(
            &script,
            &[
                "--test-xtask",
                root_true,
                "--test-policy-file",
                policy.to_str().unwrap(),
            ],
            &base_env,
        );
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(!session.path().join("always-ran").exists());
        assert!(!session.path().join("failure-ran").exists());
    }

    for bad_mode in [0o664, 0o646, 0o666] {
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(bad_mode)).unwrap();
        let (session, status) = run_isolated_hook_session(
            &script,
            &[
                "--test-xtask",
                spy_xtask.to_str().unwrap(),
                "--test-policy-file",
                policy.to_str().unwrap(),
                "--test-owner-uid",
                &uid_str,
            ],
            &base_env,
        );
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "policy mode {bad_mode:o}"
        );
        assert!(
            !marker.exists(),
            "xtask executed despite writable policy mode {bad_mode:o}"
        );
        assert!(!session.path().join("always-ran").exists());
    }
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();

    let policy_link = etc.join("policy-link");
    std::os::unix::fs::symlink(&policy, &policy_link).unwrap();
    let (_, status) = run_isolated_hook_session(
        &script,
        &[
            "--test-xtask",
            spy_xtask.to_str().unwrap(),
            "--test-policy-file",
            policy_link.to_str().unwrap(),
            "--test-owner-uid",
            &uid_str,
        ],
        &base_env,
    );
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(!marker.exists(), "xtask executed despite symlinked policy");

    let tmp_policy = runner_temp.join("temp-policy");
    std::fs::write(&tmp_policy, "standing\n").unwrap();
    std::fs::set_permissions(&tmp_policy, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (_, status) = run_isolated_hook_session(
        &script,
        &[
            "--test-xtask",
            spy_xtask.to_str().unwrap(),
            "--test-policy-file",
            tmp_policy.to_str().unwrap(),
            "--test-owner-uid",
            &uid_str,
        ],
        &base_env,
    );
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert!(
        !marker.exists(),
        "xtask executed despite RUNNER_TEMP policy"
    );
    std::fs::remove_file(&tmp_policy).unwrap();

    // 5. Malformed CLI arguments fail closed before xtask execution.
    for bad_args in [
        vec!["--unknown-flag"],
        vec!["--test-xtask"],
        vec![
            "--test-xtask",
            "relative/xtask",
            "--test-policy-file",
            policy.to_str().unwrap(),
            "--test-owner-uid",
            &uid_str,
        ],
        vec![
            "--test-xtask",
            spy_xtask.to_str().unwrap(),
            "--test-policy-file",
            "/tmp/../policy",
            "--test-owner-uid",
            &uid_str,
        ],
        vec![
            "--test-xtask",
            spy_xtask.to_str().unwrap(),
            "--test-policy-file",
            policy.to_str().unwrap(),
            "--test-owner-uid",
            "root",
        ],
    ] {
        let (_, status) = run_isolated_hook_session(&script, &bad_args, &base_env);
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{bad_args:?}");
        assert!(!marker.exists(), "{bad_args:?}");
    }

    // 6. Positive control: valid owner-only xtask and policy succeed.
    let (session, status) = run_isolated_hook_session(
        &script,
        &[
            "--test-xtask",
            spy_xtask.to_str().unwrap(),
            "--test-policy-file",
            policy.to_str().unwrap(),
            "--test-owner-uid",
            &uid_str,
        ],
        &base_env,
    );
    assert!(status.success(), "{status:?}");
    assert!(marker.exists());
    assert!(session.path().join("always-ran").exists());
    assert!(!session.path().join("failure-ran").exists());
}

#[test]
fn serial_host_admit_job_binary_and_shell_hooks_enforce_standing_policy_end_to_end() {
    use std::os::unix::fs::PermissionsExt;
    let hvf_script = hvf_hook_script_path("hvf-job-started.sh");
    let shared_admit_source = include_str!("../../../scripts/ci/admit-job.sh");
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    let etc = temp.path().join("etc");
    let workspace = temp.path().join("workspace");
    let runner_temp = temp.path().join("runner-temp");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::create_dir_all(workspace.join("target")).unwrap();
    std::fs::write(workspace.join("target/untouched-on-reject"), "keep").unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();

    let xtask = copy_owner_only_xtask(&bin);
    let policy = etc.join("policy");
    std::fs::write(&policy, "standing\n").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();

    let uid = unsafe { libc::geteuid() };
    let uid_str = uid.to_string();
    let base_env = hvf_auth_env(&workspace, &runner_temp);

    // Without `--test-policy-owner-uid`, `admit-job` defaults to root (uid 0) and rejects
    // a non-root policy file when unprivileged.
    if uid != 0 {
        let mut cmd = Command::new(&xtask);
        cmd.args(["ci-scaler", "admit-job", "--policy-file"])
            .arg(&policy)
            .env_clear();
        for (k, v) in &base_env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        assert!(!out.status.success(), "{out:?}");
    }

    let run_admit_binary = |envs: &[(String, String)]| {
        let mut cmd = Command::new(&xtask);
        cmd.args([
            "ci-scaler",
            "admit-job",
            "--policy-file",
            policy.to_str().unwrap(),
            "--test-policy-owner-uid",
            &uid_str,
        ])
        .env_clear();
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };

    let shared_admit_script = temp.path().join("admit-job-real.sh");
    std::fs::write(
        &shared_admit_script,
        shared_admit_source.replace(
            "/usr/local/bin/carrick-xtask ci-scaler admit-job",
            &format!(
                "{} ci-scaler admit-job --policy-file {} --test-policy-owner-uid {}",
                shell_quote_arg(xtask.to_str().unwrap()),
                shell_quote_arg(policy.to_str().unwrap()),
                shell_quote_arg(&uid_str),
            ),
        ),
    )
    .unwrap();

    let hvf_args = [
        "--test-xtask",
        xtask.to_str().unwrap(),
        "--test-policy-file",
        policy.to_str().unwrap(),
        "--test-owner-uid",
        &uid_str,
    ];

    // Admitted positive controls: push to main (any actor) and owner workflow_dispatch on main.
    for (label, overrides) in [
        (
            "push on main",
            vec![
                ("GITHUB_EVENT_NAME", Some("push")),
                ("GITHUB_ACTOR", Some("contributor")),
                ("GITHUB_TRIGGERING_ACTOR", Some("contributor")),
            ],
        ),
        (
            "owner workflow_dispatch on main",
            vec![
                ("GITHUB_EVENT_NAME", Some("workflow_dispatch")),
                ("GITHUB_ACTOR", Some("tjfontaine")),
                ("GITHUB_TRIGGERING_ACTOR", Some("tjfontaine")),
            ],
        ),
    ] {
        let envs = apply_env_overrides(&base_env, &overrides);
        let bin_out = run_admit_binary(&envs);
        assert!(bin_out.status.success(), "{label}: {bin_out:?}");
        assert!(
            String::from_utf8_lossy(&bin_out.stdout).contains("admitted workflow, event and ref"),
            "{label}: {bin_out:?}"
        );

        let (hvf_session, hvf_status) = run_isolated_hook_session(&hvf_script, &hvf_args, &envs);
        assert!(hvf_status.success(), "{label} (hvf hook): {hvf_status:?}");
        assert!(hvf_session.path().join("always-ran").exists());
        assert!(!hvf_session.path().join("failure-ran").exists());

        let (shared_session, shared_status) =
            run_isolated_hook_session(&shared_admit_script, &[], &envs);
        assert!(
            shared_status.success(),
            "{label} (admit-job.sh): {shared_status:?}"
        );
        assert!(shared_session.path().join("always-ran").exists());
        assert!(!shared_session.path().join("failure-ran").exists());
    }

    // Re-seed target marker to verify rejected runs die before target/ reclamation too.
    std::fs::create_dir_all(workspace.join("target")).unwrap();
    std::fs::write(workspace.join("target/untouched-on-reject"), "keep").unwrap();

    // End-to-end adversarial rejections across `admit-job`, `hvf-job-started.sh`, and `admit-job.sh`:
    // - `workflow_run`
    // - `pull_request_target`
    // - `workflow_dispatch` on a non-main ref (plus non-owner dispatch on main)
    // - `GITHUB_REF` containing `@`
    // - fork-PR `GITHUB_WORKFLOW_REF`
    for (label, overrides) in [
        (
            "workflow_run on main",
            vec![("GITHUB_EVENT_NAME", Some("workflow_run"))],
        ),
        (
            "pull_request_target on main",
            vec![("GITHUB_EVENT_NAME", Some("pull_request_target"))],
        ),
        (
            "workflow_dispatch on non-main ref with matching workflow_ref",
            vec![
                ("GITHUB_EVENT_NAME", Some("workflow_dispatch")),
                ("GITHUB_REF", Some("refs/heads/work/feature")),
                (
                    "GITHUB_WORKFLOW_REF",
                    Some(
                        "carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/work/feature",
                    ),
                ),
            ],
        ),
        (
            "workflow_dispatch on non-main ref with main workflow_ref",
            vec![
                ("GITHUB_EVENT_NAME", Some("workflow_dispatch")),
                ("GITHUB_REF", Some("refs/heads/work/feature")),
            ],
        ),
        (
            "non-owner workflow_dispatch triggering_actor on main",
            vec![
                ("GITHUB_EVENT_NAME", Some("workflow_dispatch")),
                ("GITHUB_TRIGGERING_ACTOR", Some("contributor")),
            ],
        ),
        (
            "non-owner workflow_dispatch actor on main",
            vec![
                ("GITHUB_EVENT_NAME", Some("workflow_dispatch")),
                ("GITHUB_ACTOR", Some("contributor")),
            ],
        ),
        (
            "GITHUB_REF containing @ on main prefix",
            vec![
                ("GITHUB_REF", Some("refs/heads/main@evil")),
                (
                    "GITHUB_WORKFLOW_REF",
                    Some(
                        "carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main@evil",
                    ),
                ),
            ],
        ),
        (
            "GITHUB_REF containing @ spoofing refs/heads/main suffix",
            vec![
                ("GITHUB_REF", Some("refs/heads/feature@refs/heads/main")),
                (
                    "GITHUB_WORKFLOW_REF",
                    Some(
                        "carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/feature@refs/heads/main",
                    ),
                ),
            ],
        ),
        (
            "fork-PR workflow_ref on pull_request event",
            vec![
                ("GITHUB_EVENT_NAME", Some("pull_request")),
                ("GITHUB_REF", Some("refs/pull/42/merge")),
                (
                    "GITHUB_WORKFLOW_REF",
                    Some(
                        "attacker-fork/carrick/.github/workflows/kernel-runtime.yml@refs/pull/42/merge",
                    ),
                ),
            ],
        ),
        (
            "fork workflow_ref even when event and ref claim push on main",
            vec![(
                "GITHUB_WORKFLOW_REF",
                Some("attacker-fork/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main"),
            )],
        ),
        (
            "same-repo PR workflow_ref",
            vec![
                ("GITHUB_EVENT_NAME", Some("pull_request")),
                ("GITHUB_REF", Some("refs/pull/42/merge")),
                (
                    "GITHUB_WORKFLOW_REF",
                    Some(
                        "carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/pull/42/merge",
                    ),
                ),
            ],
        ),
        (
            "foreign workflow file on main",
            vec![(
                "GITHUB_WORKFLOW_REF",
                Some("carrick-sh/carrick/.github/workflows/ci.yml@refs/heads/main"),
            )],
        ),
        ("zero GITHUB_RUN_ID", vec![("GITHUB_RUN_ID", Some("0"))]),
        (
            "zero GITHUB_RUN_ATTEMPT",
            vec![("GITHUB_RUN_ATTEMPT", Some("0"))],
        ),
        (
            "u32-overflow GITHUB_RUN_ATTEMPT",
            vec![("GITHUB_RUN_ATTEMPT", Some("4294967296"))],
        ),
        ("short GITHUB_SHA", vec![("GITHUB_SHA", Some("deadbeef"))]),
        (
            "pull_request_review without GITHUB_EVENT_PATH",
            vec![("GITHUB_EVENT_NAME", Some("pull_request_review"))],
        ),
    ] {
        let envs = apply_env_overrides(&base_env, &overrides);

        let bin_out = run_admit_binary(&envs);
        assert!(
            !bin_out.status.success(),
            "{label} unexpectedly passed admit-job binary: {bin_out:?}"
        );

        let (hvf_session, hvf_status) = run_isolated_hook_session(&hvf_script, &hvf_args, &envs);
        assert_eq!(
            hvf_status.signal(),
            Some(libc::SIGKILL),
            "{label} did not kill hvf-job-started session"
        );
        assert!(!hvf_session.path().join("always-ran").exists(), "{label}");
        assert!(!hvf_session.path().join("failure-ran").exists(), "{label}");
        assert!(
            !hvf_session.path().join("listener-survived").exists(),
            "{label}"
        );
        assert!(
            workspace.join("target/untouched-on-reject").exists(),
            "{label} touched workspace before authorization"
        );

        let (shared_session, shared_status) =
            run_isolated_hook_session(&shared_admit_script, &[], &envs);
        assert_eq!(
            shared_status.signal(),
            Some(libc::SIGKILL),
            "{label} did not kill admit-job.sh session"
        );
        assert!(
            !shared_session.path().join("always-ran").exists(),
            "{label}"
        );
        assert!(
            !shared_session.path().join("failure-ran").exists(),
            "{label}"
        );
    }

    // Missing, empty, whitespace-only, or newline-bearing required authorization variables
    // fail closed in both the `admit-job` binary and `hvf-job-started.sh`.
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
            let envs = apply_env_overrides(&base_env, &[(required, bad_val)]);
            let bin_out = run_admit_binary(&envs);
            assert!(
                !bin_out.status.success(),
                "{required}={bad_val:?} unexpectedly passed admit-job binary"
            );

            let (session, status) = run_isolated_hook_session(&hvf_script, &hvf_args, &envs);
            assert_eq!(
                status.signal(),
                Some(libc::SIGKILL),
                "{required}={bad_val:?} did not kill session"
            );
            assert!(!session.path().join("always-ran").exists());
            assert!(!session.path().join("failure-ran").exists());
        }
    }
}

#[test]
fn serial_host_hvf_job_started_enforces_workspace_guards_and_reclaims_stale_target() {
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

    let xtask = copy_owner_only_xtask(&bin);
    let policy = etc.join("policy");
    std::fs::write(&policy, "standing\n").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();

    let uid_str = unsafe { libc::geteuid() }.to_string();
    let base_env = hvf_auth_env(&workspace, &runner_temp);

    let run_hook = |overrides: &[(&str, Option<&str>)]| {
        let envs = apply_env_overrides(&base_env, overrides);
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(&script)
            .args([
                "--test-xtask",
                xtask.to_str().unwrap(),
                "--test-policy-file",
                policy.to_str().unwrap(),
                "--test-owner-uid",
                &uid_str,
            ])
            .current_dir(&workspace)
            .env_clear()
            .process_group(0);
        for (k, v) in &envs {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };

    let link_ws = temp.path().join("workspace-link");
    std::os::unix::fs::symlink(&workspace, &link_ws).unwrap();
    let link_tmp = temp.path().join("temp-link");
    std::os::unix::fs::symlink(&runner_temp, &link_tmp).unwrap();

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
            "top-level /tmp GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("/tmp"))],
        ),
        (
            "top-level /var GITHUB_WORKSPACE",
            vec![("GITHUB_WORKSPACE", Some("/var"))],
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

    // Leftover read-only target/ from an interrupted run is reclaimed while
    // workspace sources and runner-prepared `_github_workflow/event.json` in
    // RUNNER_TEMP survive job-start admission.
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/lib.rs"), "pub fn keep() {}\n").unwrap();
    let ro_dir = workspace.join("target/readonly");
    std::fs::create_dir_all(&ro_dir).unwrap();
    std::fs::write(ro_dir.join("stale.o"), "stale").unwrap();
    std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::create_dir_all(runner_temp.join("_github_workflow")).unwrap();
    std::fs::write(runner_temp.join("_github_workflow/event.json"), "{}").unwrap();

    let reclaimed = run_hook(&[]);
    assert!(reclaimed.status.success(), "{reclaimed:?}");
    assert!(!workspace.join("target").exists());
    assert!(workspace.join("src/lib.rs").exists());
    assert!(runner_temp.join("_github_workflow/event.json").exists());
}

#[test]
fn serial_host_hvf_job_completed_enforces_strict_guards_and_prunes_target_and_runner_temp_safely() {
    use std::os::unix::fs::PermissionsExt;
    let script = hvf_hook_script_path("hvf-job-completed.sh");
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("workspace");
    let runner_temp = temp.path().join("runner-temp");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();

    let run_completed = |extra_args: &[&str], overrides: &[(&str, Option<&str>)]| {
        let base: Vec<(String, String)> = vec![
            (
                "PATH".into(),
                std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()),
            ),
            ("GITHUB_WORKSPACE".into(), workspace.display().to_string()),
            ("RUNNER_TEMP".into(), runner_temp.display().to_string()),
            ("GITHUB_RUN_ID".into(), "4242".into()),
            ("GITHUB_RUN_ATTEMPT".into(), "1".into()),
        ];
        let envs = apply_env_overrides(&base, overrides);
        let mut cmd = Command::new("/bin/sh");
        cmd.arg(&script)
            .args(extra_args)
            .current_dir(&workspace)
            .env_clear();
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

    assert!(!run_completed(&["--unexpected"], &[]).status.success());

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
    ] {
        let out = run_completed(&[], &overrides);
        assert!(
            !out.status.success(),
            "{label} unexpectedly succeeded: {out:?}"
        );
    }

    // Symlinked $GITHUB_WORKSPACE/target is refused without touching the target directory.
    let outside_ro = temp.path().join("outside-readonly");
    std::fs::create_dir_all(&outside_ro).unwrap();
    std::fs::write(outside_ro.join("precious"), "keep").unwrap();
    std::fs::set_permissions(&outside_ro, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::os::unix::fs::symlink(&outside_ro, workspace.join("target")).unwrap();
    let refused = run_completed(&[], &[]);
    assert!(!refused.status.success());
    assert!(outside_ro.join("precious").exists());
    std::fs::remove_file(workspace.join("target")).unwrap();

    // Real target/ AND RUNNER_TEMP contents (regular files, dotfiles, read-only subdirs,
    // and symlinks to outside_ro) are pruned cleanly without following symlinks or altering
    // outside_ro's permissions, while preserving RUNNER_TEMP itself.
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(workspace.join("src/main.rs"), "fn main() {}\n").unwrap();
    let ro_sub = workspace.join("target/release/ro-bundle");
    std::fs::create_dir_all(&ro_sub).unwrap();
    std::fs::write(ro_sub.join("blob"), "artifact").unwrap();
    std::fs::set_permissions(&ro_sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::os::unix::fs::symlink(&outside_ro, workspace.join("target/escaped-link")).unwrap();

    std::fs::write(runner_temp.join("scratch.tar.gz"), "bundle").unwrap();
    std::fs::write(runner_temp.join(".hidden-temp"), "dotfile").unwrap();
    std::fs::write(runner_temp.join("..double-dot-temp"), "dotdotfile").unwrap();
    let ro_tmp_sub = runner_temp.join("ro-temp-dir");
    std::fs::create_dir_all(&ro_tmp_sub).unwrap();
    std::fs::write(ro_tmp_sub.join("item"), "temp").unwrap();
    std::fs::set_permissions(&ro_tmp_sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::os::unix::fs::symlink(&outside_ro, runner_temp.join("escaped-temp-link")).unwrap();

    let ok = run_completed(&[], &[]);
    assert!(ok.status.success(), "{ok:?}");
    assert!(!workspace.join("target").exists());
    assert!(workspace.join("src/main.rs").exists());
    assert!(runner_temp.is_dir());
    assert_eq!(std::fs::read_dir(&runner_temp).unwrap().count(), 0);
    assert!(outside_ro.join("precious").exists());
    assert_eq!(
        std::fs::metadata(&outside_ro).unwrap().permissions().mode() & 0o777,
        0o500
    );

    // Restore write permission on outside_ro so TempDir drop cleans up cleanly,
    // and verify idempotency when target/ is absent and RUNNER_TEMP is already empty.
    std::fs::set_permissions(&outside_ro, std::fs::Permissions::from_mode(0o700)).unwrap();
    let second = run_completed(&[], &[]);
    assert!(second.status.success(), "{second:?}");
    assert!(runner_temp.is_dir());
    assert_eq!(std::fs::read_dir(&runner_temp).unwrap().count(), 0);
}
