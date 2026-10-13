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
    // The bound policy refuses B; only the controller's re-vet may admit it.
    let hook = carrick_xtask::ci_scaler::standing_hook_script().unwrap();
    let bound = "/usr/local/bin/carrick-xtask ci-scaler admit-job";
    let revet = format!("{bound} --controller");
    assert!(
        hook.contains(&revet),
        "standing hook never asks for a re-vet"
    );
    let decide = |bound_ok: bool, revet_ok: bool| {
        let truth = |ok| {
            if ok {
                "/usr/bin/true"
            } else {
                "/usr/bin/false"
            }
        };
        hook.replace(&revet, truth(revet_ok))
            .replace(bound, truth(bound_ok))
    };
    // Reserved run A: the bound policy admits it, as before.
    let (dir, status) = fixture_run(&decide(true, false));
    assert!(status.success());
    assert!(dir.path().join("always-ran").exists());
    // Admissible run B: bound refuses, the controller approves B's own policy.
    let (dir, status) = fixture_run(&decide(false, true));
    assert!(status.success(), "re-vetted assignment B was refused");
    assert!(dir.path().join("always-ran").exists());
    // Inadmissible run B: both refuse, the whole session dies before any step.
    let (dir, status) = fixture_run(&decide(false, false));
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
