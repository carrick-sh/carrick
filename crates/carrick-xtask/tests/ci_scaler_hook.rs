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

/// The full dispatch driver runs against a real local git remote and the real
/// lease broker over stdio. Only the agent/GitHub service and deadline duration
/// are substituted. No credentials, network or Proxmox mutations are involved.
#[cfg(target_os = "linux")]
#[test]
fn dispatch_foreground_publishes_success_failure_and_timeout() {
    foreground_cases(&[
        "done",
        "failed",
        "timeout",
        "update",
        "agy",
        "collision",
        "push-failure",
        "setup-failed",
        "aged-job",
        "token-rejected",
        "token-expired-on-push",
    ]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_refuses_credentials_in_a_committed_file() {
    foreground_cases(&["leak-file"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_refuses_credentials_in_contract_summary() {
    foreground_cases(&["leak-summary"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_refuses_json_escaped_credentials_before_pushing() {
    foreground_cases(&["leak-escaped-summary"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_push_does_not_follow_credential_bearing_tags() {
    foreground_cases(&["follow-tags"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_refuses_a_bundle_from_another_branch() {
    foreground_cases(&["leak-bundle-ref"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_refuses_credentials_before_wip_staging() {
    foreground_cases(&["leak-checkpoint"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_refuses_credentials_in_result_artifacts() {
    foreground_cases(&["leak-artifact"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_refuses_oversized_files() {
    foreground_cases(&["leak-oversize"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_refuses_a_branch_linked_to_another_issue() {
    foreground_cases(&["foreign-branch"]);
}
#[cfg(target_os = "linux")]
#[test]
fn dispatch_preserves_existing_pr_body_and_ready_state() {
    foreground_cases(&["update"]);
}

#[cfg(target_os = "linux")]
fn foreground_cases(cases: &[&str]) {
    use std::os::unix::fs::PermissionsExt;
    let xtask = env!("CARGO_BIN_EXE_carrick-xtask");
    for &case in cases {
        let branch = if case == "foreign-branch" {
            "work/foreign-799"
        } else if case == "update" {
            "work/related-634"
        } else {
            "work/dispatch-634-fixture"
        };
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let checkout = root.join("checkout");
        let bin = root.join("bin");
        std::fs::create_dir(&checkout).unwrap();
        std::fs::create_dir(&bin).unwrap();
        std::fs::create_dir(root.join("cargo")).unwrap();
        std::fs::create_dir(root.join("rustup")).unwrap();
        let run_git = |cwd: &std::path::Path, args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .env("GIT_AUTHOR_NAME", "Fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@localhost")
                .env("GIT_COMMITTER_NAME", "Fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@localhost")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(output.status.success(), "git {args:?}: {output:?}");
            String::from_utf8(output.stdout).unwrap()
        };
        run_git(&checkout, &["init", "-b", "main"]);
        run_git(&checkout, &["config", "core.hooksPath", "/dev/null"]);
        std::fs::write(checkout.join("README"), "fixture base").unwrap();
        run_git(&checkout, &["add", "README"]);
        run_git(&checkout, &["commit", "-m", "fixture base"]);
        let remote = root.join("origin.git");
        run_git(root, &["init", "--bare", remote.to_str().unwrap()]);
        run_git(&checkout, &["push", remote.to_str().unwrap(), "main"]);
        if matches!(case, "update" | "collision" | "foreign-branch") {
            run_git(&checkout, &["checkout", "-b", "seed"]);
            std::fs::write(checkout.join("previous"), "earlier worker change").unwrap();
            run_git(&checkout, &["add", "previous"]);
            run_git(&checkout, &["commit", "-m", "previous worker"]);
            run_git(
                &checkout,
                &[
                    "push",
                    remote.to_str().unwrap(),
                    &format!("HEAD:refs/heads/{branch}"),
                ],
            );
            run_git(&checkout, &["checkout", "main"]);
        }
        run_git(
            &checkout,
            &[
                "fetch",
                remote.to_str().unwrap(),
                "+refs/heads/*:refs/remotes/origin/*",
            ],
        );
        let scripts = [
            ("git", r#"#!/bin/sh
if [ "$1" = push ]; then
  if [ "$TEST_CASE" = push-failure ]; then exit 77; fi
  if [ "$TEST_CASE" = token-expired-on-push ]; then touch "$TEST_ROOT/token-expired"; exit 77; fi
fi
exec /usr/bin/git "$@"
"#.to_owned()),
            ("gh", r#"#!/bin/sh
case "$1 $2" in
  'api repos/carrick-sh/carrick')
    if [ "$TEST_CASE" = token-rejected ] || [ -e "$TEST_ROOT/token-expired" ]; then
      echo 'HTTP 401: Bad credentials fixture-only-secret' >&2; exit 1
    fi
    echo '{"full_name":"carrick-sh/carrick"}' ;;
  'auth setup-git') exit 0 ;;
  'pr list')
    if [ "$TEST_CASE" = update ] || [ "$TEST_CASE" = foreign-branch ]; then
      if [ "$TEST_CASE" = update ]; then body='References #634'; else body='Closes #799'; fi
      printf '[{"number":999,"url":"https://github.com/carrick-sh/carrick/pull/999","body":"%s","isDraft":false,"author":{"login":"someone-else"},"headRepositoryOwner":{"login":"carrick-sh"},"headRepository":{"name":"carrick"}}]\n' "$body"
    else echo '[]'; fi ;;
  'pr ready') printf 'draft\n' > "$TEST_ROOT/draft" ;;
  'pr edit')
    touch "$TEST_ROOT/edited"
    for arg in "$@"; do last=$arg; done
    cp "$last" "$TEST_ROOT/pr-body.md" ;;
  'pr comment')
    for arg in "$@"; do last=$arg; done
    cp "$last" "$TEST_ROOT/pr-body.md" ;;
  'pr create')
    for arg in "$@"; do last=$arg; done
    cp "$last" "$TEST_ROOT/pr-body.md"
    echo 'https://github.com/carrick-sh/carrick/pull/999' ;;
  'issue comment')
    if [ "$TEST_CASE" = token-rejected ] || [ -e "$TEST_ROOT/token-expired" ]; then exit 1; fi
    for arg in "$@"; do last=$arg; done
    cp "$last" "$TEST_ROOT/comment.md" ;;
  *) exit 91 ;;
esac
"#.to_owned()),
            ("python3", r#"#!/bin/sh
test -z "${GITHUB_OUTPUT:-}${GITHUB_ENV:-}${GITHUB_PATH:-}${GITHUB_STEP_SUMMARY:-}" || exit 98
if [ "$TEST_CASE" = agy ]; then
  test "$AGY_BIN" = "$TEST_ROOT/carrick-agent-42-1/bin/agy" || exit 96
fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = --timeout ]; then shift; printf '%s' "$1" > "$TEST_ROOT/turn-timeout"; fi
  if [ "$1" = --result-file ]; then shift; result=$1; fi
  shift
done
printf 'worker change\n' > payload
if [ "$TEST_CASE" = leak-file ]; then cat "$HOME/.codex/auth.json" > payload; fi
if [ "$TEST_CASE" = leak-checkpoint ]; then cat "$HOME/.codex/auth.json" > payload; exit 7; fi
if [ "$TEST_CASE" = leak-artifact ]; then cat "$HOME/.codex/auth.json" > "$TEST_ROOT/checkout/dispatch-result/evil.txt"; fi
if [ "$TEST_CASE" = leak-oversize ]; then head -c 1048577 /dev/zero > payload; fi
mkdir -p conformance-probes
ln -s /tmp conformance-probes/target
case "$TEST_CASE" in
  timeout) exit 124 ;;
  failed) exit 7 ;;
esac
git add -- payload
git commit -m 'feat(ci): fixture worker change' -m 'Why: test foreground dispatch.

What: preserve worker changes.

Verified: local fixture.

Co-Authored-By: GPT-6.1 Sol <noreply@openai.com>' || exit $?
if [ "$TEST_CASE" = follow-tags ]; then
  git config push.followTags true
  git tag -a secret-tag -m "$GH_TOKEN" HEAD || exit $?
fi
if [ "$TEST_CASE" = leak-bundle-ref ]; then
  git branch clean-output HEAD || exit $?
  cat "$HOME/.codex/auth.json" > payload
  git add -- payload
  git commit -m 'fixture hidden credentials' || exit $?
  git checkout clean-output || exit $?
fi
if [ "$TEST_CASE" = agy ]; then
  git commit --amend -m 'feat(ci): fixture agy worker change' -m 'Why: test dispatch.

What: preserve worker changes.

Verified: fixture.

Co-Authored-By: Gemini 4 Argon <noreply@google.com>' || exit $?
fi
printf '%s\n' '{"status":"SUCCESS","transport":{"exit_code":0,"timed_out":false},"structured_output":{"status":"done","summary":"fixture complete","tests":["fixture"],"risks":[]}}' > "$result"
if [ "$TEST_CASE" = leak-summary ]; then
  printf '%s\n' '{"structured_output":{"status":"done","summary":"codex-fake-access-634","tests":[],"risks":[]}}' > "$result"
fi
if [ "$TEST_CASE" = leak-escaped-summary ]; then
  printf '%s\n' '{"structured_output":{"status":"done","summary":"opaque-A\"B\nC","tests":[],"risks":[]}}' > "$result"
fi
"#.to_owned()),
            ("ssh", format!("#!/bin/sh\nexec '{}' host-lease broker --lock-path \"$TEST_ROOT/host.lock\"\n", xtask)),
        ];
        for (name, script) in scripts {
            let path = bin.join(name);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::File::create(root.join("host.lock")).unwrap();
        std::fs::write(root.join("site.toml"), "broker = 'fixture@localhost'\nidentity_file = '/unused/key'\nknown_hosts_file = '/unused/known_hosts'\n").unwrap();
        let brief = if matches!(case, "update" | "foreign-branch") {
            format!("## Brief\nBranch: {branch}\nContinue fixture.")
        } else {
            "## Brief\nImplement fixture.".to_owned()
        };
        let label = if case == "agy" {
            "dispatch:argon-high"
        } else {
            "dispatch:sol-high"
        };
        let event = serde_json::json!({"repository":{"full_name":"carrick-sh/carrick"},"action":"labeled",
            "sender":{"login":"tjfontaine","type":"User"},"label":{"name":label},
            "issue":{"number":634,"user":{"login":"tjfontaine"},"title":"Fixture","body":brief}});
        std::fs::write(root.join("event.json"), event.to_string()).unwrap();
        for name in ["step-outputs", "step-env", "step-path", "step-summary"] {
            std::fs::write(root.join(name), "").unwrap();
        }
        let state = root.join("carrick-agent-42-1");
        std::fs::create_dir_all(state.join("home")).unwrap();
        std::fs::create_dir(state.join("home/.codex")).unwrap();
        std::fs::write(state.join("home/.codex/auth.json"), r#"{"tokens":{"access_token":"codex-fake-access-634","refresh_token":"codex-fake-refresh-634"}}"#).unwrap();
        if case == "leak-escaped-summary" {
            std::fs::write(
                state.join("home/.codex/auth.json"),
                r#"{"tokens":{"access_token":"opaque-A\"B\nC"}}"#,
            )
            .unwrap();
        }
        let output = Command::new("/usr/bin/timeout")
            .args(["30", xtask, "dispatch-worker", "run", "--event"])
            .arg(root.join("event.json"))
            .arg("--setup-status")
            .arg(if case == "setup-failed" {
                "failure/skipped"
            } else {
                "success/success"
            })
            .current_dir(&checkout)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HOME", root)
            .env("CARGO_HOME", root.join("cargo"))
            .env("RUSTUP_HOME", root.join("rustup"))
            .env("GH_TOKEN", "fixture-only")
            .env("GITHUB_TRIGGERING_ACTOR", "tjfontaine")
            .env("GITHUB_OUTPUT", root.join("step-outputs"))
            .env("GITHUB_ENV", root.join("step-env"))
            .env("GITHUB_PATH", root.join("step-path"))
            .env("GITHUB_STEP_SUMMARY", root.join("step-summary"))
            .env(
                "CARRICK_AGENT_JOB_STARTED_AT",
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    - if case == "aged-job" { 1200 } else { 0 })
                .to_string(),
            )
            .env("GITHUB_RUN_ID", "42")
            .env("GITHUB_RUN_ATTEMPT", "1")
            .env("RUNNER_TEMP", root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_CONFIG_COUNT", "1")
            .env(
                "GIT_CONFIG_KEY_0",
                format!("url.{}.insteadOf", remote.display()),
            )
            .env(
                "GIT_CONFIG_VALUE_0",
                "https://github.com/carrick-sh/carrick",
            )
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@localhost")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@localhost")
            .env("TEST_ROOT", root)
            .env("TEST_CASE", case)
            .env_remove("CARRICK_HOST_LEASE_SOCKET")
            .env_remove("CARRICK_HOST_LEASE_SCOPE_FD")
            .env_remove("CARRICK_HOST_LEASE_FD")
            .env_remove("CARRICK_HOST_LEASE_MODE")
            .env_remove("CARRICK_HOST_LEASE_PATH")
            .env("CARRICK_HOST_LEASE_CONFIG", root.join("site.toml"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            matches!(case, "done" | "update" | "agy" | "aged-job" | "follow-tags"),
            "{case}: {output:?}"
        );
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(checkout.join("dispatch-result/result.json")).unwrap(),
        )
        .unwrap();
        let output_spec = std::fs::read_to_string(root.join("step-outputs")).unwrap();
        let sealed =
            std::path::PathBuf::from(output_spec.trim().strip_prefix("artifact_path=").unwrap());
        assert_ne!(sealed, checkout.join("dispatch-result"));
        assert!(
            sealed
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("dispatch-validated-")
        );
        for entry in std::fs::read_dir(&sealed).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("codex-fake-"));
        }
        if case == "foreign-branch" {
            assert!(receipt["pr"].is_null());
            assert!(
                !root.join("turn-timeout").exists(),
                "agent ran on a foreign branch"
            );
            continue;
        }
        if case.starts_with("leak-") {
            assert!(
                run_git(
                    &remote,
                    &[
                        "for-each-ref",
                        &format!("refs/heads/{branch}"),
                        "--format=%(refname)"
                    ]
                )
                .is_empty(),
                "published before validating all outputs"
            );
            if case == "leak-checkpoint" {
                assert!(
                    run_git(&checkout, &["diff", "--cached", "--name-only"]).is_empty(),
                    "staged credentials before validation"
                );
            }
            assert_eq!(receipt["success"], false);
            assert!(receipt["pr"].is_null());
            assert_eq!(receipt["contract"]["status"], "failed");
            assert!(receipt.to_string().contains("redaction gate"));
            assert!(!root.join("pr-body.md").exists());
            for entry in std::fs::read_dir(checkout.join("dispatch-result")).unwrap() {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                let contents = String::from_utf8_lossy(&bytes);
                assert!(
                    !contents.contains("codex-fake-"),
                    "leaked through {}",
                    path.display()
                );
                assert!(!contents.contains("opaque-A"), "leaked escaped credential");
                assert!(
                    !contents.contains("refresh_token"),
                    "leaked credential JSON"
                );
            }
            assert!(!checkout.join("dispatch-result/work.bundle").exists());
            assert!(!checkout.join("dispatch-result/wip.patch").exists());
            continue;
        }
        assert_eq!(
            receipt["success"],
            matches!(case, "done" | "update" | "agy" | "aged-job" | "follow-tags"),
            "{case}: {receipt}"
        );
        if case == "follow-tags" {
            assert!(
                run_git(
                    &remote,
                    &["for-each-ref", "refs/tags", "--format=%(refname)"]
                )
                .is_empty(),
                "pushed an unscanned annotated tag"
            );
        }
        if matches!(case, "token-rejected" | "token-expired-on-push") {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("host/infra"), "{stderr}");
            assert!(stderr.contains("AGENT_WORKER_TOKEN"), "{stderr}");
            assert!(!stderr.contains("fixture-only-secret"));
            assert!(receipt["pr"].is_null());
            if case == "token-rejected" {
                assert!(receipt["sha"].is_null());
            } else {
                assert!(checkout.join("dispatch-result/work.bundle").is_file());
            }
            continue;
        }
        if case == "aged-job" {
            let timeout = std::fs::read_to_string(root.join("turn-timeout")).unwrap();
            assert!(
                timeout.ends_with('s'),
                "setup time was not deducted: {timeout}"
            );
            assert!(timeout.trim_end_matches('s').parse::<u64>().unwrap() <= 600);
        }
        if case == "setup-failed" {
            assert!(receipt["pr"].is_null());
            assert!(
                std::fs::read_to_string(root.join("comment.md"))
                    .unwrap()
                    .contains("no agent was started")
            );
            continue;
        }
        if case == "push-failure" {
            assert!(receipt["pr"].is_null());
            let bundle = checkout.join("dispatch-result/work.bundle");
            assert!(bundle.is_file());
            run_git(
                &remote,
                &[
                    "fetch",
                    bundle.to_str().unwrap(),
                    "HEAD:refs/heads/recovered",
                ],
            );
            assert_eq!(
                run_git(&remote, &["rev-parse", "recovered"]).trim(),
                receipt["sha"].as_str().unwrap()
            );
            assert!(run_git(&remote, &["ls-tree", "--name-only", "recovered"]).contains("payload"));
            assert!(
                std::fs::read_to_string(root.join("comment.md"))
                    .unwrap()
                    .contains("PR publication")
            );
            continue;
        }
        if case == "collision" {
            assert!(receipt["pr"].is_null());
            assert!(
                std::fs::read_to_string(root.join("comment.md"))
                    .unwrap()
                    .contains("branch already exists")
            );
            let files = run_git(&remote, &["ls-tree", "--name-only", branch]);
            assert!(files.contains("previous"));
            assert!(!files.contains("payload"));
            continue;
        }
        assert_eq!(receipt["timeout"], case == "timeout");
        assert_eq!(
            receipt["pr"],
            "https://github.com/carrick-sh/carrick/pull/999"
        );
        assert!(
            std::fs::read_to_string(root.join("comment.md"))
                .unwrap()
                .contains(receipt["sha"].as_str().unwrap())
        );
        let message = run_git(&remote, &["log", "-1", "--format=%B", branch]);
        let trailer = if case == "agy" {
            "Co-Authored-By: Gemini 4 Argon <noreply@google.com>"
        } else {
            "Co-Authored-By: GPT-6.1 Sol <noreply@openai.com>"
        };
        assert!(message.contains(trailer));
        assert!(
            std::fs::read_to_string(root.join("pr-body.md"))
                .unwrap()
                .contains("Closes #634")
        );
        let body = std::fs::read_to_string(root.join("pr-body.md")).unwrap();
        assert!(!body.contains("NEW: none"));
        assert!(body.contains("Not compared"));
        if case == "update" {
            assert!(!root.join("draft").exists(), "changed PR ready state");
            assert!(!root.join("edited").exists(), "overwrote a foreign PR body");
        }
        if matches!(case, "failed" | "timeout") {
            assert!(message.contains("checkpoint issue 634"));
        }
        let files = run_git(&remote, &["ls-tree", "--name-only", branch]);
        assert!(files.contains("payload"));
        assert!(!files.contains("conformance-probes"));
    }
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
                .env("CODEX_AUTH_JSON", r#"{"access_token":"fixture-secret"}"#)
                .env("AGY_OAUTH_TOKEN", "fixture-secret\nraw")
                .output()
                .unwrap()
        };
        let output = invoke(&["agent-runner", "auth", "--event", event.to_str().unwrap()]);
        assert!(output.status.success(), "{output:?}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-secret"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-secret"));
        let auth = if backend == "codex" {
            home.join(".codex/auth.json")
        } else {
            home.join(".gemini/antigravity-cli/antigravity-oauth-token")
        };
        assert_eq!(auth.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        if backend == "agy" {
            assert_eq!(std::fs::read(&auth).unwrap(), b"fixture-secret\nraw");
            assert_eq!(
                std::fs::read_dir(auth.parent().unwrap()).unwrap().count(),
                1
            );
        }
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
