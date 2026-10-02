//! Shared, exact suite launch envelopes for conformance and impact.
use crate::manifest::{EnvKv, Suite};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DockerPlatform {
    LinuxArm64,
    LinuxAmd64,
}

impl DockerPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            DockerPlatform::LinuxArm64 => "linux/arm64",
            DockerPlatform::LinuxAmd64 => "linux/amd64",
        }
    }
}

fn env_args(envs: &[&[EnvKv]]) -> Vec<String> {
    let mut v = Vec::new();
    for set in envs {
        for kv in *set {
            v.push("-e".to_string());
            v.push(format!("{}={}", kv.key, kv.val));
        }
    }
    v
}

/// The command to actually launch for a suite.
///
/// LTP's `tst_test` framework forks the test body into a child and the main
/// process reaps it. When the test binary is PID 1 the kernel drops un-handled
/// signals to it, so the framework's reap/watchdog path breaks and EVERY test
/// TBROKs with "Main test process might have exit!" / "Test killed! (timeout?)".
/// This bites BOTH sides on current LTP (20260529 tightened the monitor):
/// carrick runs the binary as guest PID 1 over its host-process fork model, and
/// docker runs it as container PID 1. carrick is being *faithful* to Linux PID-1
/// semantics here — real Docker added `--init` for exactly this class of app.
///
/// Run the LTP test under `/bin/sh -c` instead, so the shell is PID 1 (a proper
/// reaper) and the test is its child — the same way `scripts/ltp-baseline.py`
/// and LTP's own runners invoke it. Applied identically to carrick AND docker so
/// the differential stays symmetric (both: sh=PID1 -> test=child). Scoped to
/// LTP; cpython/go/node keep their bare cmd.
fn effective_cmd(suite: &Suite) -> Vec<String> {
    if matches!(suite.ecosystem, crate::manifest::Ecosystem::Ltp) {
        vec!["/bin/sh".to_string(), "-c".to_string(), suite.cmd.join(" ")]
    } else {
        suite.cmd.clone()
    }
}

/// Build the carrick argv: `run --name <run-id> <envelope flags> <image> <cmd...>`.
/// `--name` gives carrick the SAME single handle docker gets — carrick derives
/// the proctitle / scoped-kill id from it (precedence: CARRICK_RUN_ID -> --name
/// -> auto), so the run-id, the container name, and the kill scope are one thing.
pub fn carrick_argv(suite: &Suite, carrick_bin: &str, run_id: &str) -> Vec<String> {
    let mut a = vec![carrick_bin.to_string(), "run".to_string()];
    a.push("--name".to_string());
    a.push(run_id.to_string());
    // Disable carrick's trap watchdog for conformance. It counts SYSCALL traps
    // as a proxy for "stuck", but that proxy is wrong: a legitimate fork- or
    // file-heavy test (fork_procs; getcwd04 creating/renaming thousands of
    // files) exceeds the 1M-trap default and is wrongly recorded CRASH before
    // it ever reaches its real verdict — verified: fork_procs PASSES with a
    // raised budget. The authoritative "stuck" guards in the gate are the
    // per-suite TIMEOUT (mac-side kill / guest-side `timeout`) and each LTP
    // test's own 30s SIGALRM watchdog, so the trap counter is pure downside.
    // A suite may still override this via its own carrick_flags (added below).
    a.push("--max-traps".to_string());
    a.push(usize::MAX.to_string());
    // NO per-run `--pull`: it defaults to `missing` (pull each image at most
    // once). Version skew (a rebuilt+repushed image — same tag, new digest) is
    // handled ONCE by the harness image-guard, which re-pulls moved images
    // before phase 1. A per-run `--pull always` re-fetches the registry manifest
    // for every one of the ~2000 suites — that pins `com.docker.backend` and the
    // Docker VM at hundreds of % CPU, the exact carrick‖docker contention the
    // two-phase gate exists to avoid, and it corrupts the timing-sensitive
    // fuzzy-sync verdicts. The one-shot image-guard gives the same skew safety
    // for free.
    a.extend(suite.carrick_flags.iter().cloned());
    // Oracle-fidelity symmetry for the launch-time syscall policy: `carrick run`
    // models Docker's default seccomp profile BY DEFAULT (matching a bare
    // `docker run` oracle), so a suite whose docker oracle is deliberately
    // UNCONFINED (`--security-opt seccomp=unconfined` in docker_flags — the
    // keyring/pidfd_getfd/fanotify/clone3 families compare real-syscall
    // capability, not container policy) must run the carrick side unconfined
    // too. Match both docker spellings (two-token `--security-opt X` and
    // one-token `--security-opt=X`) so a manifest reformat can't silently drop
    // the symmetry.
    let docker_unconfined = suite
        .docker_flags
        .iter()
        .any(|f| f == "seccomp=unconfined" || f == "--security-opt=seccomp=unconfined");
    if docker_unconfined {
        a.push("--security-opt".to_string());
        a.push("seccomp=unconfined".to_string());
    }
    if let Some(ep) = suite.entrypoint.as_ref().and_then(|e| e.for_carrick()) {
        a.push("--entrypoint".to_string());
        a.push(ep);
    }
    for m in &suite.bind_mounts {
        a.push("-v".to_string());
        a.push(m.clone());
    }
    if let Some(w) = &suite.workdir {
        a.push("-w".to_string());
        a.push(w.clone());
    }
    a.extend(env_args(&[&suite.env, &suite.env_carrick]));
    a.push(suite.image.clone());
    a.extend(effective_cmd(suite));
    a
}

/// Build the docker argv: `run --name conf-<id> --platform <platform> <flags> <image> <cmd...>`.
pub fn docker_argv(suite: &Suite, run_id: &str, platform: DockerPlatform) -> Vec<String> {
    let mut a = vec![
        "docker".to_string(),
        "run".to_string(),
        "--name".to_string(),
        run_id.to_string(), // already `conf-<pid>-<seq>` from the orchestrator
        "--platform".to_string(),
        platform.as_str().to_string(),
    ];
    a.extend(suite.docker_flags.iter().cloned());
    if let Some(ep) = suite.entrypoint.as_ref().and_then(|e| e.for_docker()) {
        a.push("--entrypoint".to_string());
        a.push(ep);
    }
    for m in &suite.bind_mounts {
        a.push("-v".to_string());
        a.push(m.clone());
    }
    if let Some(w) = &suite.workdir {
        a.push("-w".to_string());
        a.push(w.clone());
    }
    a.extend(env_args(&[&suite.env, &suite.env_docker]));
    a.push(suite.image.clone());
    a.extend(effective_cmd(suite));
    a
}
