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
    // Substitute only the policy decision: authorize_job has its own tests.
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
    assert!(source.contains("setsid --wait ./run.sh --jitconfig"));
}
