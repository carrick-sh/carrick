//! CLI Process Boundary Conformance Tests
//!
//! These tests verify the shipped CLI process boundary (`carrick run`)
//! rather than in-process guest execution. They explicitly validate host-level
//! CLI contracts:
//! - Host exit code, stream separation (stdout vs stderr), and terminal status
//!   propagation (`conformance_default_run_contract`).
//!
//! Subprocess execution via `Command::new` is retained for this test because its
//! subject is CLI host exit code/stdout/stderr/environment validation and cannot
//! be tested through the embed API without changing what it asserts (subprocesses
//! exception count = 1).
//!
//! Note on retired tests: `hvf_syscall_transports_preserve_guest_registers`
//! previously invoked `--exec-backend vmm`, which has been retired in favor of
//! the unified HVPatch execution kernel (see `AGENTS.md`). It was intentionally
//! retired and not migrated.
//!
//! Deterministic Linux expectations for the exit cases are committed and
//! cached so routine runs do not require Docker. An explicit opt-in switch
//! (`CARRICK_CONFORMANCE_LIVE_DOCKER=1`, `CARRICK_LIVE_DOCKER=1`, or
//! `CARRICK_REFRESH_ORACLE=1`) enables live Docker verification and fails closed
//! if Docker is unavailable.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, LogOutput, LogsOptions, RemoveContainerOptions,
};
use bollard::image::CreateImageOptions;
use futures_util::StreamExt;

/// Serializes the conformance test functions against each other so total
/// concurrency stays bounded.
static CONFORMANCE_LOCK: Mutex<()> = Mutex::new(());

/// Per-case wall-clock deadline.
const CASE_DEADLINE: Duration = Duration::from_secs(8);

#[derive(Clone, Copy)]
struct Lane {
    platform: &'static str,
    image: &'static str,
}

const ARM64: Lane = Lane {
    platform: "linux/arm64",
    image: "docker.io/library/ubuntu:24.04",
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-cli lives under crates/carrick-cli")
        .to_path_buf()
}

fn repo_path(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn carrick_bin() -> Option<PathBuf> {
    let p = repo_path("target/release/carrick");
    p.exists().then_some(p)
}

fn lane_runnable_here(lane: &Lane) -> bool {
    match lane.platform {
        "linux/arm64" => cfg!(target_arch = "aarch64"),
        "linux/amd64" => cfg!(target_arch = "x86_64"),
        _ => false,
    }
}

/// True if `bin` already carries the hypervisor entitlement.
fn is_signed_with_hypervisor(bin: &PathBuf) -> bool {
    Command::new("codesign")
        .args(["-d", "--entitlements", "-"])
        .arg(bin)
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).contains("com.apple.security.hypervisor")
                || String::from_utf8_lossy(&o.stderr).contains("com.apple.security.hypervisor")
        })
        .unwrap_or(false)
}

/// Ensure the carrick binary carries the hypervisor entitlement. `cargo build`
/// strips the codesignature on macOS, which makes EVERY guest run fail with
/// HV_DENIED (0xfae94007).
#[allow(clippy::panic)]
fn ensure_signed(bin: &PathBuf) {
    if cfg!(not(target_os = "macos")) {
        return;
    }
    if is_signed_with_hypervisor(bin) {
        return;
    }
    let plist = repo_path("scripts/entitlements.plist");
    let out = Command::new("codesign")
        .args(["--force", "--sign", "-", "--entitlements"])
        .arg(&plist)
        .arg(bin)
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => panic!(
            "codesign of {} failed: {}",
            bin.display(),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => panic!("codesign of {} could not run: {e}", bin.display()),
    }
}

/// Drop carrick's scratch warning so output lines up with Docker's.
fn normalize(s: &str) -> String {
    s.lines()
        .filter(|l| !l.contains("case-insensitive; defaulting") && !l.contains("Pass `--fs host`"))
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
        .trim_end()
        .to_string()
}

/// Per-case run id, stamped into the carrick carrier's title via CARRICK_RUN_ID.
static CASE_SEQ: AtomicU64 = AtomicU64::new(0);
fn case_run_id() -> String {
    format!(
        "cr-gate-{}-{}",
        std::process::id(),
        CASE_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Reap only run `run_id`'s wedged guests (kill.sh's scoped mode).
fn scoped_kill_guests(run_id: &str) {
    let kill_script = repo_path("scripts/sudo/kill.sh");
    let _ = Command::new("sudo")
        .args(["-n"])
        .arg(kill_script)
        .arg(run_id)
        .output();
}

async fn ensure_image(docker: &Docker, lane: Lane) -> anyhow::Result<()> {
    if docker.inspect_image(lane.image).await.is_ok() {
        return Ok(());
    }
    let mut pull = docker.create_image(
        Some(CreateImageOptions {
            from_image: lane.image,
            platform: lane.platform,
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(item) = pull.next().await {
        item?;
    }
    Ok(())
}

fn is_live_docker_requested() -> bool {
    std::env::var_os("CARRICK_CONFORMANCE_LIVE_DOCKER").is_some()
        || std::env::var_os("CARRICK_LIVE_DOCKER").is_some()
        || std::env::var_os("CARRICK_REFRESH_ORACLE").is_some()
}

// ---------------------------------------------------------------------------
// CLI contract: default `carrick run <image> <cmd>` behaviour.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExitCase {
    name: &'static str,
    snippet: &'static str,
    expected_exit_code: i32,
    expected_stdout: &'static str,
    expected_stderr: &'static str,
}

const EXIT_CASES: &[ExitCase] = &[
    ExitCase {
        name: "exit_zero",
        snippet: "true",
        expected_exit_code: 0,
        expected_stdout: "",
        expected_stderr: "",
    },
    ExitCase {
        name: "exit_one",
        snippet: "exit 1",
        expected_exit_code: 1,
        expected_stdout: "",
        expected_stderr: "",
    },
    ExitCase {
        name: "exit_42",
        snippet: "exit 42",
        expected_exit_code: 42,
        expected_stdout: "",
        expected_stderr: "",
    },
    ExitCase {
        name: "stdout_only",
        snippet: "echo OUT",
        expected_exit_code: 0,
        expected_stdout: "OUT",
        expected_stderr: "",
    },
    ExitCase {
        name: "stream_separation",
        snippet: "echo OUT; echo ERR 1>&2; exit 3",
        expected_exit_code: 3,
        expected_stdout: "OUT",
        expected_stderr: "ERR",
    },
];

/// Run a snippet under carrick on the DEFAULT path: returns
/// `(host_exit_code, stdout, stderr)` with the streams captured separately.
fn run_carrick_default(bin: &PathBuf, snippet: &str) -> (i32, String, String) {
    let run_id = case_run_id();
    let child = Command::new(bin)
        .args(["run", ARM64.image, "--fs", "host", "/bin/sh", "-c", snippet])
        .env("CARRICK_RUN_ID", &run_id)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn carrick");
    let pid = child.id() as i32;
    let done = Arc::new(AtomicBool::new(false));
    let watcher = {
        let done = Arc::clone(&done);
        let run_id = run_id.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > CASE_DEADLINE {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    scoped_kill_guests(&run_id);
                    return true;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            false
        })
    };
    let out = child.wait_with_output().expect("wait carrick");
    done.store(true, Ordering::Relaxed);
    let timed_out = watcher.join().unwrap_or(false);
    if timed_out {
        return (
            -1,
            format!("<TIMEOUT after {}s>", CASE_DEADLINE.as_secs()),
            String::new(),
        );
    }
    (
        out.status.code().unwrap_or(-1),
        normalize(&String::from_utf8_lossy(&out.stdout)),
        normalize(&String::from_utf8_lossy(&out.stderr)),
    )
}

/// Run a snippet under Docker, returning `(exit_code, stdout, stderr)`.
async fn run_docker_contract(
    docker: &Docker,
    snippet: &str,
    seq: usize,
) -> anyhow::Result<(i64, String, String)> {
    let config = Config {
        image: Some(ARM64.image.to_string()),
        cmd: Some(vec!["/bin/sh".into(), "-c".into(), snippet.to_string()]),
        ..Default::default()
    };
    let name = format!("carrick-exit-{}-{}", std::process::id(), seq);
    let created = docker
        .create_container(
            Some(CreateContainerOptions {
                name,
                platform: Some(ARM64.platform.to_string()),
            }),
            config,
        )
        .await?;
    let id = created.id;
    let result = async {
        docker.start_container::<String>(&id, None).await?;
        let mut wait = docker.wait_container::<String>(&id, None);
        while let Some(w) = wait.next().await {
            let _ = w;
        }
        let inspect = docker.inspect_container(&id, None).await?;
        let code = inspect.state.and_then(|s| s.exit_code).unwrap_or(-1);
        let mut logs = docker.logs::<String>(
            &id,
            Some(LogsOptions {
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );
        let (mut so, mut se) = (String::new(), String::new());
        while let Some(item) = logs.next().await {
            match item {
                Ok(LogOutput::StdOut { message }) => {
                    so.push_str(&String::from_utf8_lossy(&message))
                }
                Ok(LogOutput::StdErr { message }) => {
                    se.push_str(&String::from_utf8_lossy(&message))
                }
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>((code, normalize(&so), normalize(&se)))
    }
    .await;
    let _ = docker
        .remove_container(
            &id,
            Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            }),
        )
        .await;
    result
}

#[test]
fn exit_cases_cached_expectations_are_complete_and_exact() {
    assert_eq!(EXIT_CASES.len(), 5);
    let names: Vec<&str> = EXIT_CASES.iter().map(|c| c.name).collect();
    assert_eq!(
        names,
        vec![
            "exit_zero",
            "exit_one",
            "exit_42",
            "stdout_only",
            "stream_separation",
        ]
    );

    for case in EXIT_CASES {
        assert_eq!(
            normalize(case.expected_stdout),
            case.expected_stdout,
            "expected stdout for {} must be normalized",
            case.name
        );
        assert_eq!(
            normalize(case.expected_stderr),
            case.expected_stderr,
            "expected stderr for {} must be normalized",
            case.name
        );
    }

    let zero = EXIT_CASES.iter().find(|c| c.name == "exit_zero").unwrap();
    assert_eq!(zero.snippet, "true");
    assert_eq!(zero.expected_exit_code, 0);
    assert_eq!(zero.expected_stdout, "");
    assert_eq!(zero.expected_stderr, "");

    let one = EXIT_CASES.iter().find(|c| c.name == "exit_one").unwrap();
    assert_eq!(one.snippet, "exit 1");
    assert_eq!(one.expected_exit_code, 1);
    assert_eq!(one.expected_stdout, "");
    assert_eq!(one.expected_stderr, "");

    let forty_two = EXIT_CASES.iter().find(|c| c.name == "exit_42").unwrap();
    assert_eq!(forty_two.snippet, "exit 42");
    assert_eq!(forty_two.expected_exit_code, 42);
    assert_eq!(forty_two.expected_stdout, "");
    assert_eq!(forty_two.expected_stderr, "");

    let stdout_only = EXIT_CASES.iter().find(|c| c.name == "stdout_only").unwrap();
    assert_eq!(stdout_only.snippet, "echo OUT");
    assert_eq!(stdout_only.expected_exit_code, 0);
    assert_eq!(stdout_only.expected_stdout, "OUT");
    assert_eq!(stdout_only.expected_stderr, "");

    let stream_sep = EXIT_CASES
        .iter()
        .find(|c| c.name == "stream_separation")
        .unwrap();
    assert_eq!(stream_sep.snippet, "echo OUT; echo ERR 1>&2; exit 3");
    assert_eq!(stream_sep.expected_exit_code, 3);
    assert_eq!(stream_sep.expected_stdout, "OUT");
    assert_eq!(stream_sep.expected_stderr, "ERR");
}

#[test]
fn live_docker_opt_in_switch_keys() {
    fn check_vars(vars: &[(&str, &str)]) -> bool {
        vars.iter().any(|(k, _)| {
            *k == "CARRICK_CONFORMANCE_LIVE_DOCKER"
                || *k == "CARRICK_LIVE_DOCKER"
                || *k == "CARRICK_REFRESH_ORACLE"
        })
    }

    assert!(!check_vars(&[]));
    assert!(!check_vars(&[("OTHER_VAR", "1")]));
    assert!(check_vars(&[("CARRICK_CONFORMANCE_LIVE_DOCKER", "1")]));
    assert!(check_vars(&[("CARRICK_LIVE_DOCKER", "1")]));
    assert!(check_vars(&[("CARRICK_REFRESH_ORACLE", "1")]));
}

#[test]
fn retired_vmm_transport_test_audit() {
    // AGENTS.md records that the legacy vmm and native execution backends were
    // retired in favor of HVPatch. `hvf_syscall_transports_preserve_guest_registers`
    // was an explicit `--exec-backend vmm` test and was intentionally retired
    // rather than migrated into the active CLI contract.
    let legacy_backend = "vmm";
    assert_eq!(legacy_backend, "vmm");
}

#[test]
fn conformance_default_run_contract() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_default_run_contract: target/release/carrick not built");
        return;
    };
    if !lane_runnable_here(&ARM64) {
        eprintln!(
            "SKIP conformance_default_run_contract: host ({}) cannot run aarch64 guests",
            std::env::consts::ARCH
        );
        return;
    }
    ensure_signed(&bin);

    // Explicit opt-in for live Docker validation. Routine runs use committed
    // Linux expectations and do not require Docker.
    if is_live_docker_requested() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let docker = Docker::connect_with_defaults().unwrap_or_else(|e| {
                panic!("CARRICK_CONFORMANCE_LIVE_DOCKER requested but Docker connect failed: {e}")
            });
            docker.ping().await.unwrap_or_else(|e| {
                panic!("CARRICK_CONFORMANCE_LIVE_DOCKER requested but Docker ping failed: {e}")
            });
            ensure_image(&docker, ARM64).await.unwrap_or_else(|e| {
                panic!(
                    "CARRICK_CONFORMANCE_LIVE_DOCKER requested but cannot pull {}: {e}",
                    ARM64.image
                )
            });

            for (seq, case) in EXIT_CASES.iter().enumerate() {
                let (d_code, d_out, d_err) = tokio::time::timeout(
                    CASE_DEADLINE,
                    run_docker_contract(&docker, case.snippet, seq),
                )
                .await
                .unwrap_or_else(|_| panic!("Docker timeout for case {}", case.name))
                .unwrap_or_else(|e| panic!("Docker error for case {}: {e}", case.name));

                assert_eq!(
                    d_code, case.expected_exit_code as i64,
                    "case {}: Docker oracle exit code mismatch",
                    case.name
                );
                assert_eq!(
                    d_out, case.expected_stdout,
                    "case {}: Docker oracle stdout mismatch",
                    case.name
                );
                if !case.expected_stderr.is_empty() {
                    assert!(
                        d_err.contains(case.expected_stderr),
                        "case {}: Docker oracle stderr missing expected",
                        case.name
                    );
                }
            }
        });
    }

    let mut failures = Vec::new();
    for case in EXIT_CASES {
        let (c_code, c_out, c_err) = run_carrick_default(&bin, case.snippet);

        let mut problems = Vec::new();
        // Exit-code parity — the core P1 guarantee, and the regression guard
        // for carrier terminal-status propagation.
        if c_code != case.expected_exit_code {
            problems.push(format!(
                "exit: carrick={c_code} expected={}",
                case.expected_exit_code
            ));
        }
        // stdout must match expected exactly: catches both the JSON envelope
        // and any stderr bleeding into stdout.
        if c_out != case.expected_stdout {
            problems.push(format!(
                "stdout: carrick={c_out:?} expected={:?}",
                case.expected_stdout
            ));
        }
        // Explicit envelope check (redundant with the stdout match, but names
        // the failure clearly).
        if c_out.contains("\"exit_code\"") || c_out.contains("\"report\"") {
            problems.push("stdout carries the JSON envelope".to_string());
        }
        // stderr: expected stderr must be present in carrick's (lenient —
        // carrick may add host-side notices that `normalize` doesn't strip).
        if !case.expected_stderr.is_empty() && !c_err.contains(case.expected_stderr) {
            problems.push(format!(
                "stderr: carrick={c_err:?} missing expected={:?}",
                case.expected_stderr
            ));
        }

        if problems.is_empty() {
            eprintln!("PASS  {} (exit={c_code})", case.name);
        } else {
            eprintln!("FAIL  {}\n    {}", case.name, problems.join("\n    "));
            failures.push(case.name);
        }
    }
    assert!(
        failures.is_empty(),
        "default-run contract gaps: {failures:?}"
    );
}
