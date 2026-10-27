//! `just smoke-signed` (#893): the fast signed first-boot smoke and its receipt.
//!
//! Deterministic first-boot failures (a bootstrap fatal, a refused root exit,
//! a successor bootstrap that cannot reacquire its predecessor's arenas) die
//! in under a second, yet each used to cost a full director round to find.
//! This runs the `carrick-embed` `smoke_signed` target through the one signed
//! runner (`scripts/test-signed.sh`, which builds, signs, runs, runs the
//! unentitled negative control and reaps by run id) and binds the outcome to
//! the exact HEAD in a machine-checkable receipt. The exit status is the
//! verdict: every required case passed, the binary finished, the negative
//! control passed, every scoped cleanup count is zero, and HEAD and the tracked
//! tree did not move while the smoke ran.
use crate::accept::{ArtifactIdentity, ParsedTestLog, inspect_executable, parse_test_log};
use crate::command::run_checked;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const SCHEMA: &str = "carrick.smoke-signed.v1";
const PACKAGE: &str = "carrick-embed";
const TARGET: &str = "smoke_signed";
const FILTER: &str = "smoke_";
const NEGATIVE: &str = "entitlement_negative::unsigned_executable_maps_hv_denied_to_entitlement";
/// Per-binary execution deadline handed to the runner. The cases need about a
/// second; each also carries its own 30-second watchdog.
const DEADLINE_SECS: &str = "120";

/// Whether a case decides the verdict or is a tracked known-red observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseRole {
    Required,
    Informational,
}

pub struct SmokeCase {
    pub name: &'static str,
    pub covers: &'static str,
    pub role: CaseRole,
}

/// The smoke set. It must equal the `smoke_` tests of
/// `crates/carrick-embed/tests/smoke_signed.rs`: an unlisted or missing test
/// fails the run. Informational cases are `#[ignore]`d there.
pub const CASES: &[SmokeCase] = &[
    SmokeCase {
        name: "smoke_root_exit_then_successor_bootstrap_in_one_carrier",
        covers: "bootstrap, clean root exit, two successor bootstraps in one carrier",
        role: CaseRole::Required,
    },
    SmokeCase {
        name: "smoke_pipe_round_trips_complete",
        covers: "blocking pipe round trips between two guest threads",
        role: CaseRole::Required,
    },
    SmokeCase {
        name: "smoke_exec_replaces_root_image",
        covers: "root shell exec (host route)",
        role: CaseRole::Required,
    },
    SmokeCase {
        name: "smoke_native_child_exec_after_fork_and_wait",
        covers: "fork, child exit, slot reuse, native child execve, waitpid",
        role: CaseRole::Required,
    },
    SmokeCase {
        name: "smoke_fork_pipe_then_wait_reaps_child",
        covers: "fork, cross-process pipe round trips, waitpid",
        role: CaseRole::Informational,
    },
];

#[derive(clap::Args, Debug)]
pub struct SmokeSignedArgs {
    /// Run on a tree with tracked modifications. The receipt then records
    /// `clean_tree: false` and never qualifies, and the exit status is nonzero.
    #[arg(long)]
    pub allow_dirty: bool,
}

#[derive(Debug, Error)]
pub enum SmokeSignedError {
    #[error("{0}")]
    Refused(String),
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("git: {0}")]
    Git(String),
    #[error("receipt: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Passed,
    Failed,
    NotRun,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseResult {
    pub name: String,
    pub covers: String,
    pub role: CaseRole,
    pub status: CaseStatus,
    pub wall_ms: Option<u64>,
    /// A carrier fatal or watchdog line was printed while this case ran.
    pub fatal: bool,
}

/// A carrier fatal or watchdog line, and the case running when it printed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatalLine {
    pub case: Option<String>,
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cleanup {
    pub run_id: String,
    pub remaining: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SmokeReceipt {
    pub schema: String,
    pub passed: bool,
    pub failures: Vec<String>,
    pub head: String,
    pub clean_tree: bool,
    pub run_id: String,
    pub started_unix_s: u64,
    pub total_s: f64,
    pub runner_exit_code: Option<i32>,
    pub cargo_build_s: Option<f64>,
    pub libtest_s: Option<f64>,
    pub fixture_input_identity: Option<String>,
    pub artifact: Option<ArtifactIdentity>,
    pub cases: Vec<CaseResult>,
    pub unexpected_tests: Vec<String>,
    pub negative_control_passed: bool,
    pub fatals: Vec<FatalLine>,
    pub cleanup: Vec<Cleanup>,
    pub log_path: PathBuf,
    /// The runner's own `carrick.signed-embed-test.v1` receipt, published only
    /// when it exits 0; bound to this run by its `carrick_run_id`.
    pub runner_receipt: Option<PathBuf>,
}

/// Everything the verdict is computed from, independent of the host.
pub struct Observed<'a> {
    pub log: &'a str,
    pub runner_exit_code: Option<i32>,
    pub run_id: &'a str,
    pub clean_tree: bool,
    pub tree_unchanged: bool,
}

pub struct Verdict {
    pub passed: bool,
    pub failures: Vec<String>,
    pub cases: Vec<CaseResult>,
    pub unexpected_tests: Vec<String>,
    pub negative_control_passed: bool,
    pub fatals: Vec<FatalLine>,
    pub cleanup: Vec<Cleanup>,
    pub executable: Option<PathBuf>,
}

fn qualified(name: &str) -> String {
    format!("{TARGET}::{name}")
}

/// `smoke-signed: case=<name> wall_ms=<n> panicking=<bool>` from the test's
/// drop guard.
fn case_wall_ms(log: &str, name: &str) -> Option<u64> {
    log.lines().find_map(|line| {
        let rest = line.split_once("smoke-signed: case=")?.1;
        let (case, rest) = rest.split_once(' ')?;
        if case != name {
            return None;
        }
        rest.strip_prefix("wall_ms=")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

/// Every `remaining carrick procs (run-id <id>) = <n>` line kill.sh printed.
pub fn parse_cleanup(log: &str) -> Vec<Cleanup> {
    log.lines()
        .filter_map(|line| {
            let rest = line.split_once("remaining carrick procs (run-id ")?.1;
            let (run_id, count) = rest.split_once(") = ")?;
            Some(Cleanup {
                run_id: run_id.to_string(),
                remaining: count.trim().parse().ok()?,
            })
        })
        .collect()
}

/// Seconds from the first `Finished `release` profile ... in <t>` line.
fn cargo_build_s(log: &str) -> Option<f64> {
    log.lines()
        .filter(|line| line.contains("Finished `release` profile"))
        .find_map(|line| parse_cargo_duration(line.rsplit_once(" in ")?.1.trim()))
}

fn parse_cargo_duration(text: &str) -> Option<f64> {
    let mut total = 0.0;
    for part in text.split_whitespace() {
        if let Some(m) = part.strip_suffix('m') {
            total += m.parse::<f64>().ok()? * 60.0;
        } else if let Some(s) = part.strip_suffix('s') {
            total += s.parse::<f64>().ok()?;
        } else {
            return None;
        }
    }
    Some(total)
}

/// libtest's `finished in <t>s` for the smoke binary's run.
fn libtest_s(log: &str) -> Option<f64> {
    let mut in_smoke = false;
    for line in log.lines() {
        if let Some(rest) = line.split_once("test-signed: running ") {
            in_smoke = rest.1.contains(&format!("/{TARGET}-"));
        } else if line.contains("test-signed: negative control on ") {
            in_smoke = false;
        } else if in_smoke && line.trim_start().starts_with("test result:") {
            return line
                .rsplit_once("finished in ")?
                .1
                .trim()
                .strip_suffix('s')?
                .parse()
                .ok();
        }
    }
    None
}

fn fixture_input_identity(log: &str) -> Option<String> {
    log.lines().find_map(|line| {
        let rest = line.split_once("fixtures: verified ")?.1;
        let id = rest.split_once("by input_identity ")?.1;
        id.split_whitespace().next().map(str::to_string)
    })
}

fn smoke_executable(log: &str) -> Vec<PathBuf> {
    log.lines()
        .filter_map(|line| {
            line.split_once("test-signed: running ")?
                .1
                .split_whitespace()
                .next()
        })
        .filter(|exe| exe.contains(&format!("/{TARGET}-")))
        .map(PathBuf::from)
        .collect()
}

/// A carrier may print a fatal and keep serving (a refused retirement is
/// logged, then the guest's exit still reads as success), so a semantic pass
/// is not enough: every fatal or watchdog line is attributed to the case that
/// was running when it printed (`test <name> ...` opens a case, `test result:`
/// closes the binary).
const FATAL_MARKERS: &[&str] = &["carrick: FATAL:", "carrick fatal [", "WATCHDOG:"];

pub fn fatal_lines(log: &str) -> Vec<FatalLine> {
    let mut current: Option<String> = None;
    let mut found = Vec::new();
    for line in log.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("test ")
            && let Some((name, _)) = rest.split_once(" ...")
        {
            current = CASES
                .iter()
                .find(|case| case.name == name)
                .map(|case| case.name.to_string());
        } else if trimmed.starts_with("test result:")
            || line.contains("test-signed: negative control on ")
        {
            current = None;
        }
        if FATAL_MARKERS.iter().any(|marker| line.contains(marker)) {
            found.push(FatalLine {
                case: current.clone(),
                line: line.chars().take(600).collect(),
            });
        }
    }
    found
}

/// The verdict, computed fail-closed from the runner's full log.
pub fn evaluate(observed: &Observed<'_>) -> Verdict {
    let parsed: ParsedTestLog = parse_test_log(observed.log);
    let mut failures = Vec::new();
    if !observed.clean_tree {
        failures.push("tracked tree is dirty: the artifact is not HEAD".into());
    }
    if !observed.tree_unchanged {
        failures.push("HEAD or the tracked tree changed while the smoke ran".into());
    }

    let executables = smoke_executable(observed.log);
    if executables.len() != 1 {
        failures.push(format!(
            "expected one signed {TARGET} executable run, found {}",
            executables.len()
        ));
    }
    if !parsed.finished_binaries.iter().any(|b| b == TARGET) {
        failures.push(format!(
            "{TARGET} did not finish (crash, deadline or no run)"
        ));
    }
    for unitemized in &parsed.unitemized_failures {
        failures.push(format!("unitemized failure: {unitemized}"));
    }

    let fatals = fatal_lines(observed.log);
    for fatal in fatals.iter().filter(|f| f.case.is_none()) {
        failures.push(format!(
            "carrier fatal outside a smoke case: {}",
            fatal.line
        ));
    }
    let mut cases = Vec::new();
    for case in CASES {
        let key = qualified(case.name);
        let started = parsed.started_tests.contains(&key);
        let failed = parsed.failed_tests.contains(&key);
        let finished = parsed.finished_binaries.iter().any(|b| b == TARGET);
        let fatal = fatals.iter().any(|f| f.case.as_deref() == Some(case.name));
        let status = match (started, failed || fatal, finished) {
            (true, false, true) => CaseStatus::Passed,
            (true, _, _) => CaseStatus::Failed,
            (false, _, _) => CaseStatus::NotRun,
        };
        if case.role == CaseRole::Required && status != CaseStatus::Passed {
            let why = if fatal { " (carrier fatal)" } else { "" };
            failures.push(format!("required case {} {:?}{why}", case.name, status));
        }
        cases.push(CaseResult {
            name: case.name.to_string(),
            covers: case.covers.to_string(),
            role: case.role,
            status,
            wall_ms: case_wall_ms(observed.log, case.name),
            fatal,
        });
    }
    let unexpected_tests: Vec<String> = parsed
        .started_tests
        .iter()
        .filter(|t| t.starts_with(&format!("{TARGET}::")))
        .filter(|t| !CASES.iter().any(|c| qualified(c.name) == **t))
        .cloned()
        .collect();
    if !unexpected_tests.is_empty() {
        failures.push(format!(
            "tests outside the smoke set ran: {}",
            unexpected_tests.join(", ")
        ));
    }

    let negative_control_passed = observed.log.contains("test-signed: negative control on ")
        && parsed.started_tests.iter().any(|t| t == NEGATIVE)
        && !parsed.failed_tests.iter().any(|t| t == NEGATIVE)
        && !observed.log.contains("test-signed: FAIL negative control");
    if !negative_control_passed {
        failures.push("unentitled negative control did not pass".into());
    }

    let cleanup = parse_cleanup(observed.log);
    if !cleanup.iter().any(|c| c.run_id == observed.run_id) {
        failures.push(format!(
            "no scoped cleanup count for run id {}",
            observed.run_id
        ));
    }
    for leak in cleanup.iter().filter(|c| c.remaining != 0) {
        failures.push(format!(
            "scoped cleanup left {} processes for {}",
            leak.remaining, leak.run_id
        ));
    }
    if observed.log.contains("scoped cleanup failed") {
        failures.push("runner reported a scoped cleanup failure".into());
    }

    // A nonzero runner exit is explained only by itemized informational
    // failures; anything else already appears above, but never pass on it.
    let informational_failed = cases
        .iter()
        .any(|c| c.role == CaseRole::Informational && c.status != CaseStatus::Passed);
    match observed.runner_exit_code {
        Some(0) => {}
        Some(_) if informational_failed && failures.is_empty() => {}
        code => failures.push(format!("signed runner exited {code:?}")),
    }

    Verdict {
        passed: failures.is_empty(),
        failures,
        cases,
        unexpected_tests,
        negative_control_passed,
        fatals,
        cleanup,
        executable: executables.into_iter().next(),
    }
}

fn git(root: &Path, args: &[&str]) -> Result<String, SmokeSignedError> {
    run_checked("git", args, Some(root))
        .map(|out| out.stdout.trim().to_string())
        .map_err(|e| SmokeSignedError::Git(e.to_string()))
}

/// HEAD and a digest of the tracked tree state (`git status` for tracked
/// files plus the full tracked diff), so any edit during the run is seen.
fn tree_state(root: &Path) -> Result<(String, bool, String), SmokeSignedError> {
    let head = git(root, &["rev-parse", "HEAD"])?;
    let status = git(root, &["status", "--porcelain", "--untracked-files=no"])?;
    let diff = git(root, &["diff", "HEAD"])?;
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{head}\n{status}\n{diff}").as_bytes())
    );
    Ok((head, status.is_empty(), digest))
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> SmokeSignedError + '_ {
    move |source| SmokeSignedError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The runner's published receipt, if its header names this run.
fn bind_runner_receipt(root: &Path, run_id: &str, dir: &Path) -> Option<PathBuf> {
    let published = root.join(format!(
        "target/test-results/{PACKAGE}-signed-artifacts.jsonl"
    ));
    let text = fs::read_to_string(&published).ok()?;
    let header: serde_json::Value = serde_json::from_str(text.lines().next()?).ok()?;
    if header.get("carrick_run_id")?.as_str()? != run_id {
        return None;
    }
    let copy = dir.join("signed-artifacts.jsonl");
    fs::write(&copy, text).ok()?;
    Some(copy)
}

pub fn run(root: &Path, args: SmokeSignedArgs) -> Result<SmokeReceipt, SmokeSignedError> {
    if !cfg!(target_os = "macos") {
        return Err(SmokeSignedError::Refused(
            "smoke-signed runs signed HVF guests: macOS only".into(),
        ));
    }
    let root = PathBuf::from(git(root, &["rev-parse", "--show-toplevel"])?);
    let (head, clean_tree, before) = tree_state(&root)?;
    if !clean_tree && !args.allow_dirty {
        return Err(SmokeSignedError::Refused(
            "tracked modifications present: a smoke receipt binds the exact HEAD; \
             commit first (or pass --allow-dirty for a non-qualifying run)"
                .into(),
        ));
    }
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let run_id = format!("smoke-{}-{started}", &head[..12]);
    let dir = root.join("target/smoke-signed").join(&run_id);
    fs::create_dir_all(&dir).map_err(io_err(&dir))?;
    let log_path = dir.join("test-signed.log");
    let log_file = fs::File::create(&log_path).map_err(io_err(&log_path))?;
    let err_file = log_file.try_clone().map_err(io_err(&log_path))?;

    println!(
        "smoke-signed: {head} run_id={run_id}\nsmoke-signed: log {}",
        log_path.display()
    );
    let clock = Instant::now();
    let status = Command::new("./scripts/test-signed.sh")
        .args([PACKAGE, FILTER, "--include-ignored", "--nocapture"])
        .current_dir(&root)
        .env("CARRICK_RUN_ID", &run_id)
        .env("CARRICK_TEST_TARGET", TARGET)
        .env("CARRICK_TEST_SIGNED_DEADLINE_SECS", DEADLINE_SECS)
        .env_remove("CARRICK_TEST_SIGNED_FEATURES")
        .stdin(Stdio::null())
        .stdout(log_file)
        .stderr(err_file)
        .status()
        .map_err(io_err(&log_path))?;
    let total_s = clock.elapsed().as_secs_f64();
    let log_bytes = fs::read(&log_path).map_err(io_err(&log_path))?;
    let log = String::from_utf8_lossy(&log_bytes);
    let (head_after, _, after) = tree_state(&root)?;

    let verdict = evaluate(&Observed {
        log: &log,
        runner_exit_code: status.code(),
        run_id: &run_id,
        clean_tree,
        tree_unchanged: head_after == head && after == before,
    });
    let mut failures = verdict.failures;
    let artifact = match verdict.executable.as_deref().map(inspect_executable) {
        Some(Ok(identity)) => {
            if !identity.hypervisor_entitlement || !identity.dof_present {
                failures.push("smoke executable lacks the entitlement or __dof_carrick".into());
            }
            Some(identity)
        }
        Some(Err(error)) => {
            failures.push(format!("artifact identity: {error}"));
            None
        }
        None => None,
    };
    let runner_receipt = bind_runner_receipt(&root, &run_id, &dir);
    if status.code() == Some(0) && runner_receipt.is_none() {
        failures.push("runner exited 0 without a receipt for this run id".into());
    }

    let receipt = SmokeReceipt {
        schema: SCHEMA.into(),
        passed: failures.is_empty(),
        failures,
        head,
        clean_tree,
        run_id,
        started_unix_s: started,
        total_s,
        runner_exit_code: status.code(),
        cargo_build_s: cargo_build_s(&log),
        libtest_s: libtest_s(&log),
        fixture_input_identity: fixture_input_identity(&log),
        artifact,
        cases: verdict.cases,
        unexpected_tests: verdict.unexpected_tests,
        negative_control_passed: verdict.negative_control_passed,
        fatals: verdict.fatals,
        cleanup: verdict.cleanup,
        log_path,
        runner_receipt,
    };
    let json = serde_json::to_string_pretty(&receipt)?;
    let path = dir.join("receipt.json");
    fs::write(&path, format!("{json}\n")).map_err(io_err(&path))?;
    let latest = root.join("target/smoke-signed/receipt.json");
    fs::write(&latest, format!("{json}\n")).map_err(io_err(&latest))?;

    for case in &receipt.cases {
        println!(
            "smoke-signed: {:<56} {:?}/{:?} {}{}",
            case.name,
            case.role,
            case.status,
            case.wall_ms.map_or("-".into(), |ms| format!("{ms} ms")),
            if case.fatal { " CARRIER FATAL" } else { "" }
        );
    }
    for failure in &receipt.failures {
        println!("smoke-signed: FAIL {failure}");
    }
    println!(
        "smoke-signed: {} in {:.1}s; receipt {}",
        if receipt.passed { "PASS" } else { "FAIL" },
        receipt.total_s,
        path.display()
    );
    Ok(receipt)
}
