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

fn raw_dir() -> PathBuf {
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

/// Build the carrick argv: `run <envelope flags> <image> <cmd...>`.
fn carrick_argv(suite: &Suite, carrick_bin: &str) -> Vec<String> {
    let mut a = vec![carrick_bin.to_string(), "run".to_string()];
    a.extend(suite.carrick_flags.iter().cloned());
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
    a.extend(suite.cmd.iter().cloned());
    a
}

/// Build the docker argv: `run --name conf-<id> --platform linux/arm64 <flags> <image> <cmd...>`.
fn docker_argv(suite: &Suite, run_id: &str) -> Vec<String> {
    let mut a = vec![
        "docker".to_string(),
        "run".to_string(),
        "--name".to_string(),
        run_id.to_string(), // already `conf-<pid>-<seq>` from the orchestrator
        "--platform".to_string(),
        "linux/arm64".to_string(),
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
    a.extend(suite.cmd.iter().cloned());
    a
}

pub fn carrick_dry_run(suite: &Suite, carrick_bin: &str) -> Vec<String> {
    carrick_argv(suite, carrick_bin)
}
pub fn docker_dry_run(suite: &Suite, run_id: &str) -> Vec<String> {
    docker_argv(suite, run_id)
}

pub fn run_carrick(suite: &Suite, carrick_bin: &str, run_id: &str) -> anyhow::Result<RunOutput> {
    let argv = carrick_argv(suite, carrick_bin);
    // SAFE: argv comes from the version-controlled manifest (suites.toml), not external
    // input; `Command::args` passes each token literally (no shell), so there is no
    // metacharacter interpolation / injection surface.
    let mut cmd = Command::new(&argv[0]); // nosemgrep
    cmd.args(&argv[1..]);
    cmd.env("CARRICK_RUN_ID", run_id);
    if let Some(host) = suite.registry_host() {
        cmd.env("CARRICK_INSECURE_REGISTRIES", host);
    }
    run_one(cmd, argv, suite.timeout_s, run_id, Engine::Carrick)
}

pub fn run_docker(suite: &Suite, run_id: &str) -> anyhow::Result<RunOutput> {
    // Idempotent pre-clean: a prior crashed run with the same deterministic id
    // may have left the container around; free the name before `docker run --name`.
    let container = run_id.to_string();
    let _ = Command::new("docker")
        .args(["rm", "-f", &container])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let argv = docker_argv(suite, run_id);
    // SAFE: see run_carrick — argv is from the trusted manifest; `Command::args` is shell-free.
    let mut cmd = Command::new(&argv[0]); // nosemgrep
    cmd.args(&argv[1..]);
    let out = run_one(cmd, argv, suite.timeout_s, run_id, Engine::Docker);
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

fn run_one(
    mut cmd: Command,
    argv: Vec<String>,
    timeout_s: u64,
    run_id: &str,
    engine: Engine,
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
                    kill_scoped(pid, run_id, engine);
                    // Reap whatever is left.
                    let _ = child.wait();
                    break -1;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    };

    Ok(RunOutput {
        stdout_path,
        stderr_path,
        exit_code,
        timed_out,
        run_id: run_id.to_string(),
        argv,
    })
}

/// Kill exactly this run — never an unscoped reap.
fn kill_scoped(pid: i32, run_id: &str, engine: Engine) {
    // Group kill of the direct child tree (cheap, scoped to our spawned pid).
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    match engine {
        Engine::Carrick => {
            // Belt for a guest that escaped its group (setpgid/setsid): the
            // SCOPED kill.sh, which matches only `carrick:<run-id>` and refuses
            // a global reap. Best-effort (needs the sudoers entry).
            let _ = Command::new("sudo")
                .args(["-n", "scripts/sudo/kill.sh", run_id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        Engine::Docker => {
            let container = run_id.to_string();
            let _ = Command::new("docker")
                .args(["kill", &container])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
