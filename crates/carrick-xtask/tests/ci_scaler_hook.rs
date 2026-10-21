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
fn agent_auth_is_job_scoped_private_and_always_cleanable() {
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
        let invoke = |args: &[&str]| {
            Command::new(xtask)
                .args(args)
                .env("RUNNER_TEMP", temp.path())
                .env("GITHUB_RUN_ID", "42")
                .env("GITHUB_RUN_ATTEMPT", "1")
                .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
                .env("CODEX_AUTH_JSON", r#"{"access_token":"codex-only-secret"}"#)
                .env("AGY_OAUTH_TOKEN", "agy-only-secret\nraw")
                .output()
                .unwrap()
        };
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
        assert!(
            !remembered.contains(unselected),
            "captured unselected provider {unselected}"
        );
        assert_eq!(home.join(".codex").exists(), backend == "codex");
        assert_eq!(home.join(".gemini").exists(), backend == "agy");
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
fn rejected_director_token_stops_bootstrap_before_downloads() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    for (name, source) in [
        (
            "gh",
            "#!/bin/sh\ntest \"$1 $2\" = 'api repos/carrick-sh/agy-director' || exit 91\necho 'HTTP 401: expired fixture-only-secret' >&2\nexit 1\n",
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
    assert!(stderr.contains("AGENT_DIRECTOR_TOKEN"), "{stderr}");
    assert!(!stderr.contains("fixture-only-secret"));
    assert!(!temp.path().join("download-started").exists());
    assert!(!temp.path().join("carrick-agent-42-1").exists());
}
