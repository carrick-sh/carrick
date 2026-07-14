//! Symmetric subprocess execution: run one suite on one engine, capture to
//! files (never pipes — a wedged guest holding a pipe survives the parent's
//! timeout), enforce a per-run timeout, and clean up SCOPED to this run's id.
//!
//! Both engines are `std::process::Command` subprocesses launched with identical
//! trailing argv (`<image> <cmd...>`); the engines differ only in the envelope.
//!
//! Flag ordering: carrick's `run` declares `command` as `trailing_var_arg`, so
//! the FIRST positional (the image) terminates option parsing and everything
//! after it is handed to the guest. Therefore ALL envelope flags (`--raw`,
//! `--fs`, `-v`, `-w`, `-e`, `--entrypoint`) go BEFORE the image, and only `cmd`
//! follows it — identical to `docker run [opts] <image> <cmd>` (and to
//! `scripts/go-conformance-image.sh`).

use crate::manifest::{EnvKv, Suite};
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct RunOutput {
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub exit_code: i32,
    pub timed_out: bool,
    pub elapsed_ms: u64,
    pub run_id: String,
    pub argv: Vec<String>,
}

impl RunOutput {
    /// Load the captured output into a parser-ready [`crate::parsers::Raw`]
    /// (lossy UTF-8 — guest output may contain non-UTF-8 bytes).
    pub fn raw(&self) -> crate::parsers::Raw {
        let read = |p: &Path| {
            std::fs::read(p)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default()
        };
        crate::parsers::Raw {
            stdout: read(&self.stdout_path),
            stderr: read(&self.stderr_path),
            exit_code: self.exit_code,
            timed_out: self.timed_out,
        }
    }
}

pub(crate) fn raw_dir() -> PathBuf {
    PathBuf::from("target/conformance/raw")
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
pub(crate) fn carrick_argv(suite: &Suite, carrick_bin: &str, run_id: &str) -> Vec<String> {
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
fn docker_argv(suite: &Suite, run_id: &str, platform: crate::lane::DockerPlatform) -> Vec<String> {
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

pub fn carrick_dry_run(
    suite: &Suite,
    carrick_bin: &str,
    run_id: &str,
    lane: &crate::lane::Lane,
) -> Vec<String> {
    crate::lane::carrick_invocation_argv(suite, carrick_bin, run_id, lane)
}
pub fn docker_dry_run(
    suite: &Suite,
    run_id: &str,
    platform: crate::lane::DockerPlatform,
) -> Vec<String> {
    docker_argv(suite, run_id, platform)
}

pub fn run_carrick(
    suite: &Suite,
    carrick_bin: &str,
    run_id: &str,
    lane: &crate::lane::Lane,
) -> anyhow::Result<RunOutput> {
    let argv = crate::lane::carrick_invocation_argv(suite, carrick_bin, run_id, lane);
    // SAFE: argv comes from the version-controlled manifest (suites.toml), not external
    // input; `Command::args` passes each token literally (no shell), so there is no
    // metacharacter interpolation / injection surface.
    let mut cmd = Command::new(&argv[0]); // nosemgrep
    cmd.args(&argv[1..]);
    // Scope comes from `--name <run_id>` in the argv now (carrick derives the
    // proctitle/kill id from it). Remove an operator's inherited outer scope:
    // CARRICK_RUN_ID deliberately has precedence over --name, which otherwise
    // makes every concurrent case share one cleanup identity.
    clear_inherited_carrick_run_id(&mut cmd);
    // Hvf still sets the insecure-registry env on the LOCAL process; Kvm already
    // carried it INTO the guest argv (`env …`), so only set it for Hvf.
    if lane.needs_local_registry_env()
        && let Some(host) = suite.registry_host()
    {
        cmd.env("CARRICK_INSECURE_REGISTRIES", host);
    }
    let cleanup = CarrickCleanup::from_lane(lane);
    // Lane-scaled deadline: nested-KVM runs get a stretched budget (the gate
    // asserts correctness parity with docker, not speed parity); docker
    // oracles below keep the unscaled suite budget.
    run_one(
        cmd,
        argv,
        lane.scaled_timeout(suite.timeout_s),
        run_id,
        Engine::Carrick,
        Some(cleanup),
    )
}

fn clear_inherited_carrick_run_id(cmd: &mut Command) {
    cmd.env_remove("CARRICK_RUN_ID");
}

pub fn run_docker(
    suite: &Suite,
    run_id: &str,
    platform: crate::lane::DockerPlatform,
) -> anyhow::Result<RunOutput> {
    // Idempotent pre-clean: a prior crashed run with the same deterministic id
    // may have left the container around; free the name before `docker run --name`.
    let container = run_id.to_string();
    let _ = Command::new("docker")
        .args(["rm", "-f", &container])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let argv = docker_argv(suite, run_id, platform);
    // SAFE: see run_carrick — argv is from the trusted manifest; `Command::args` is shell-free.
    let mut cmd = Command::new(&argv[0]); // nosemgrep
    cmd.args(&argv[1..]);
    let out = run_one(cmd, argv, suite.timeout_s, run_id, Engine::Docker, None);
    // Always remove the container we named (no `--rm`, so the exit code came
    // straight from the `docker run` process).
    let _ = Command::new("docker")
        .args(["rm", "-f", &container])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    out
}

#[derive(Clone, Copy)]
enum Engine {
    Carrick,
    Docker,
}

#[derive(Clone)]
enum CarrickCleanup {
    Hvf,
    KvmLima(crate::lane::LimaConfig),
    KvmLocal,
    BhyveLocal,
    NvmmLocal,
}

impl CarrickCleanup {
    fn from_lane(lane: &crate::lane::Lane) -> Self {
        match lane {
            crate::lane::Lane::Hvf | crate::lane::Lane::MacosNativeDsr(_) => CarrickCleanup::Hvf,
            crate::lane::Lane::Kvm(cfg) => CarrickCleanup::KvmLima(cfg.clone()),
            crate::lane::Lane::KvmLocal(_) => CarrickCleanup::KvmLocal,
            crate::lane::Lane::BhyveLocal(_) => CarrickCleanup::BhyveLocal,
            crate::lane::Lane::NvmmLocal(_) => CarrickCleanup::NvmmLocal,
        }
    }
}

fn run_one(
    mut cmd: Command,
    argv: Vec<String>,
    timeout_s: u64,
    run_id: &str,
    engine: Engine,
    cleanup: Option<CarrickCleanup>,
) -> anyhow::Result<RunOutput> {
    std::fs::create_dir_all(raw_dir())?;
    let stdout_path = raw_dir().join(format!("{run_id}.out"));
    let stderr_path = raw_dir().join(format!("{run_id}.err"));
    let out_file = File::create(&stdout_path)?;
    let err_file = File::create(&stderr_path)?;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file))
        .process_group(0); // own group, so we can kill the whole guest tree

    let start = Instant::now();
    let deadline = Duration::from_secs(timeout_s);
    let mut child = cmd.spawn()?;
    let pid = child.id() as i32;

    let mut timed_out = false;
    let exit_code = loop {
        match child.try_wait()? {
            Some(status) => break status.code().unwrap_or(-1),
            None => {
                if start.elapsed() >= deadline {
                    timed_out = true;
                    kill_scoped(pid, run_id, engine, cleanup.as_ref());
                    // Reap whatever is left.
                    let _ = child.wait();
                    break -1;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    };

    // Reap any guest processes that escaped this run's process group — a guest
    // that did setsid/setpgid (LTP process-group tests), or a forked child that
    // re-parented to init when the carrick parent exited. The in-loop
    // kill_scoped only fires on TIMEOUT, so a normally-completing test that
    // leaked a re-parented child would leave it lingering; across a 1429-suite
    // run these accumulate and drive box load up, which spuriously TIMEOUTs
    // *other* concurrent suites (turning a clean ~33 CRASH_TIMEOUT baseline into
    // 160+). The pkill is scoped to this run's unique `--name` and is a no-op
    // when nothing escaped, so always running it after the wait is safe.
    if matches!(engine, Engine::Carrick) {
        kill_scoped(pid, run_id, engine, cleanup.as_ref());
    }

    Ok(RunOutput {
        stdout_path,
        stderr_path,
        exit_code,
        timed_out,
        elapsed_ms: elapsed_ms(start.elapsed()),
        run_id: run_id.to_string(),
        argv,
    })
}

fn elapsed_ms(duration: Duration) -> u64 {
    let ms = duration.as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

/// Kill exactly this run — never an unscoped reap.
fn kill_scoped(pid: i32, run_id: &str, engine: Engine, cleanup: Option<&CarrickCleanup>) {
    // Group kill of the direct child tree (cheap, scoped to our spawned pid).
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    match (engine, cleanup) {
        (Engine::Carrick, Some(CarrickCleanup::KvmLima(cfg))) => {
            // KVM lane: the group kill above only reached the MAC side (limactl/
            // ssh); the carrick tree lives in the GUEST and carrick escapes its
            // process group there (it manages guest pgids), so reap it with a
            // SCOPED in-guest pkill. On Linux carrick never rewrites argv
            // (proctitle.rs is macOS-only) and fork children / in-place execve
            // keep the spawn argv, so `run --name <run-id> ` (trailing space:
            // run-id prefix safety) matches exactly this run's host processes.
            // Killing the run's leftover wrapper sh/sg as well is fine — the
            // whole run is being torn down. Best-effort: the in-band guest-side
            // `timeout`+pkill (lane.rs) is the backstop if this cannot connect.
            let _ = Command::new("limactl")
                .args([
                    "shell",
                    &cfg.vm,
                    "--",
                    "pkill",
                    "-9",
                    "-f",
                    &format!("run --name {run_id} "),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        (
            Engine::Carrick,
            Some(CarrickCleanup::KvmLocal | CarrickCleanup::BhyveLocal | CarrickCleanup::NvmmLocal),
        ) => {
            // Local Linux/KVM, FreeBSD/bhyve, NetBSD/NVMM: a guest may have
            // escaped its process group (setsid/setpgid), so kill by name, not
            // by tree. TWO patterns, both scoped to this run's unique id:
            //   - the top-level carrick parent keeps its argv `run --name <id>`
            //   - the guest CHILDREN rewrite their argv/comm to
            //     `carrick:<id>: <test>` (the proctitle IS rewritten on Linux —
            //     a prior comment claiming otherwise was wrong), so the first
            //     pattern misses them and they leak (re-parented to init). Over
            //     a full suite the leaked guests accumulate and drive box load
            //     up, spuriously TIMEOUTing other concurrent suites.
            for pat in [format!("run --name {run_id} "), format!("carrick:{run_id}")] {
                let _ = Command::new("pkill")
                    .args(["-9", "-f", &pat])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
        (Engine::Carrick, Some(CarrickCleanup::Hvf) | None) => {
            // Belt for a guest that escaped its group (setpgid/setsid): the
            // SCOPED kill.sh, which matches only `carrick:<run-id>` and refuses
            // a global reap. Best-effort (needs the sudoers entry).
            let cleanup = Command::new("sudo")
                .args(["-n", "scripts/sudo/kill.sh", run_id])
                .output();
            if let Ok(output) = cleanup
                && !output.status.success()
            {
                eprintln!(
                    "warning: scoped carrick cleanup failed for {run_id}: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        (Engine::Docker, _) => {
            let container = run_id.to_string();
            let _ = Command::new("docker")
                .args(["kill", &container])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrick_command_removes_inherited_outer_run_id() {
        let mut command = Command::new("carrick");
        command.env("CARRICK_RUN_ID", "outer-scope");
        clear_inherited_carrick_run_id(&mut command);

        assert!(command.get_envs().any(|(key, value)| {
            key == std::ffi::OsStr::new("CARRICK_RUN_ID") && value.is_none()
        }));
    }
    use crate::lane::DockerPlatform;

    #[test]
    fn carrick_argv_has_no_per_run_pull() {
        let suite = Suite::for_test("localhost:5050/ltp:arm64", &["true"]);

        let argv = carrick_argv(&suite, "target/release/carrick", "conf-1");

        // No per-run `--pull`: `--pull always` re-fetches the registry manifest
        // for every suite, pinning the Docker backend/VM at hundreds of % CPU in
        // contention with carrick's HVF (and corrupting timing-sensitive fuzzy-
        // sync verdicts). Version skew is handled ONCE by the harness image-guard;
        // `--pull` defaults to `missing` (pull each image at most once).
        assert!(
            !argv.windows(2).any(|w| w[0] == "--pull"),
            "carrick_argv must not add a per-run --pull; got {argv:?}"
        );
    }

    #[test]
    fn docker_argv_uses_requested_platform() {
        let suite = Suite::for_test("localhost:5050/ltp:amd64", &["true"]);

        let argv = docker_dry_run(&suite, "conf-1", DockerPlatform::LinuxAmd64);

        let platform = argv
            .windows(2)
            .find(|w| w[0] == "--platform")
            .map(|w| w[1].as_str());
        assert_eq!(platform, Some("linux/amd64"));
    }

    fn has_unconfined(argv: &[String]) -> bool {
        argv.windows(2)
            .any(|w| w[0] == "--security-opt" && w[1] == "seccomp=unconfined")
    }

    #[test]
    fn carrick_argv_mirrors_docker_seccomp_unconfined() {
        // A suite whose docker oracle is deliberately unconfined (keyring/
        // pidfd_getfd/fanotify/clone3 families compare real-syscall capability)
        // must run the carrick side unconfined too — otherwise carrick's
        // default container policy (the Docker default-seccomp model) would be
        // compared against an unconfined oracle.
        let mut suite = Suite::for_test("localhost:5050/ltp:arm64", &["add_key01"]);
        suite.docker_flags = vec![
            "--security-opt".to_string(),
            "seccomp=unconfined".to_string(),
        ];
        let argv = carrick_argv(&suite, "target/release/carrick", "conf-1");
        assert!(
            has_unconfined(&argv),
            "carrick side must mirror the oracle's seccomp=unconfined: {argv:?}"
        );

        // The one-token docker spelling must be recognized too — a manifest
        // reformat to `--security-opt=seccomp=unconfined` must not silently
        // drop the symmetry.
        let mut suite = Suite::for_test("localhost:5050/ltp:arm64", &["add_key01"]);
        suite.docker_flags = vec!["--security-opt=seccomp=unconfined".to_string()];
        let argv = carrick_argv(&suite, "target/release/carrick", "conf-1");
        assert!(
            has_unconfined(&argv),
            "one-token --security-opt= spelling must forward too: {argv:?}"
        );
    }

    #[test]
    fn carrick_argv_stays_default_confined_without_docker_unconfined() {
        // Default suites (no docker unconfined flag) run BOTH engines under the
        // default container policy: no --security-opt is injected.
        let suite = Suite::for_test("localhost:5050/ltp:arm64", &["true"]);
        let argv = carrick_argv(&suite, "target/release/carrick", "conf-1");
        assert!(
            !argv.iter().any(|t| t == "--security-opt"),
            "no security-opt for a default-confined suite: {argv:?}"
        );
    }
}
