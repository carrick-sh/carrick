use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::command;
use crate::host_lease::{HostLease, HostLeaseMode, extract_exit_code};

#[derive(clap::Args, Debug, Clone)]
pub struct AcceptArgs {
    #[arg(
        long,
        value_enum,
        default_value = "all",
        help = "Gate phase to run: host, signed, or all"
    )]
    pub phase: AcceptPhase,

    #[arg(
        long,
        value_enum,
        default_value = "no-docker",
        help = "Acceptance profile: no-docker (default for workers) or full (director)"
    )]
    pub profile: AcceptProfile,

    #[arg(
        long,
        help = "Path to write receipt JSON file (defaults to target/el1-gate/<head>/receipt.json)"
    )]
    pub receipt: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcceptPhase {
    Host,
    Signed,
    All,
}

impl fmt::Display for AcceptPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => write!(f, "host"),
            Self::Signed => write!(f, "signed"),
            Self::All => write!(f, "all"),
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcceptProfile {
    NoDocker,
    Full,
}

impl fmt::Display for AcceptProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDocker => write!(f, "no-docker"),
            Self::Full => write!(f, "full"),
        }
    }
}

#[derive(Debug, Error)]
pub enum AcceptError {
    #[error("I/O error at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("git command error: {0}")]
    Git(String),
    #[error("unsupported platform for signed phase: {0}")]
    UnsupportedPlatform(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("gate failed: {0}")]
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StepResult {
    pub name: String,
    pub command: String,
    pub exit_code: Option<i32>,
    pub log_path: PathBuf,
    pub duration_s: f64,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub cdhash: String,
    pub lc_uuid: String,
    pub hypervisor_entitlement: bool,
    pub dof_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct El1Comparison {
    pub failed_tests: Vec<String>,
    pub allowlist: Vec<String>,
    pub unexpected_failures: Vec<String>,
    pub now_passing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeDiff {
    pub step: String,
    pub probe: String,
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupCount {
    pub step: String,
    pub run_id: String,
    pub remaining_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcceptReceipt {
    pub schema_version: u32,
    pub timestamp: String,
    pub head: String,
    pub clean_tree: bool,
    pub phase: String,
    pub profile: String,
    pub overall: String,
    pub steps: Vec<StepResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_steps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub el1: Option<El1Comparison>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probe_diffs: Vec<ProbeDiff>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleanup_counts: Vec<CleanupCount>,
    pub failures: Vec<String>,
}

pub struct StepSpec {
    pub name: &'static str,
    pub program: &'static str,
    pub args: &'static [&'static str],
    pub env: &'static [(&'static str, &'static str)],
    pub log_name: &'static str,
}

pub const HOST_STEPS: &[StepSpec] = &[
    StepSpec {
        name: "test-kernel",
        program: "just",
        args: &["test-kernel"],
        env: &[],
        log_name: "01-test-kernel.log",
    },
    StepSpec {
        name: "test",
        program: "just",
        args: &["test"],
        env: &[],
        log_name: "02-test.log",
    },
    StepSpec {
        name: "vmm-hvf lib",
        program: "cargo",
        args: &["test", "-p", "carrick-vmm-hvf", "--lib"],
        env: &[("RUST_TEST_THREADS", "1")],
        log_name: "03-vmm-hvf.log",
    },
    StepSpec {
        name: "clippy",
        program: "just",
        args: &["clippy"],
        env: &[],
        log_name: "04-clippy.log",
    },
    StepSpec {
        name: "lint-domains",
        program: "just",
        args: &["lint-domains"],
        env: &[],
        log_name: "05-lint-domains.log",
    },
    StepSpec {
        name: "closure-probe-inventory",
        program: "cargo",
        args: &[
            "test",
            "-p",
            "carrick-cli",
            "--test",
            "conformance",
            "closure_probe_inventory",
        ],
        env: &[],
        log_name: "06-closure-probe-inventory.log",
    },
];

pub fn generate_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = now.as_secs();

    let seconds_in_day = total_secs % 86400;
    let days_since_epoch = total_secs / 86400;

    let hour = seconds_in_day / 3600;
    let minute = (seconds_in_day % 3600) / 60;
    let second = seconds_in_day % 60;

    let z = (days_since_epoch as i64) + 719468;
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}{m:02}{d:02}-{hour:02}{minute:02}{second:02}")
}

pub fn check_git_status(status_output: &str) -> (bool, bool) {
    let clean_tree = status_output.trim().is_empty();
    let mut has_tracked_modifications = false;
    for line in status_output.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("??") && !trimmed.is_empty() {
            has_tracked_modifications = true;
            break;
        }
    }
    (clean_tree, has_tracked_modifications)
}

pub fn load_allowlist(path: &Path) -> Result<Vec<String>, io::Error> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        entries.push(trimmed.to_string());
    }
    entries.sort();
    Ok(entries)
}

pub fn parse_el1_failures(log: &str) -> Vec<String> {
    let mut failures = Vec::new();
    let mut in_failures_block = false;

    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed == "failures:" {
            in_failures_block = true;
            continue;
        }

        if in_failures_block {
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("test result:") {
                in_failures_block = false;
                continue;
            }
            if trimmed.starts_with("----") {
                continue;
            }
            let test_name = trimmed.rsplit("::").next().unwrap_or(trimmed);
            if !test_name.is_empty()
                && test_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !failures.contains(&test_name.to_string())
            {
                failures.push(test_name.to_string());
            }
        } else if (trimmed.starts_with("test ") && trimmed.ends_with("FAILED"))
            || trimmed.ends_with("... FAILED")
        {
            let without_failed = trimmed.strip_suffix("FAILED").unwrap_or(trimmed).trim();
            let test_part = without_failed
                .strip_suffix("...")
                .unwrap_or(without_failed)
                .trim();
            let test_part = test_part.strip_prefix("test ").unwrap_or(test_part).trim();
            let test_name = test_part.rsplit("::").next().unwrap_or(test_part);
            if !test_name.is_empty()
                && test_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !failures.contains(&test_name.to_string())
            {
                failures.push(test_name.to_string());
            }
        }
    }

    failures.sort();
    failures
}

pub fn compare_el1_failures(actual_failures: &[String], allowlist: &[String]) -> El1Comparison {
    let mut unexpected_failures = Vec::new();
    for failure in actual_failures {
        if !allowlist.contains(failure) {
            unexpected_failures.push(failure.clone());
        }
    }
    let mut now_passing = Vec::new();
    for allowed in allowlist {
        if !actual_failures.contains(allowed) {
            now_passing.push(allowed.clone());
        }
    }

    unexpected_failures.sort();
    now_passing.sort();
    let mut failed_sorted = actual_failures.to_vec();
    failed_sorted.sort();
    let mut allowlist_sorted = allowlist.to_vec();
    allowlist_sorted.sort();

    El1Comparison {
        failed_tests: failed_sorted,
        allowlist: allowlist_sorted,
        unexpected_failures,
        now_passing,
    }
}

pub fn extract_probe_name_from_diff(line: &str) -> String {
    if let Some(rest) = line.split("DIFF ").nth(1) {
        let first_token = rest.split_whitespace().next().unwrap_or("unknown");
        if first_token.contains(':') {
            return first_token
                .rsplit(':')
                .next()
                .unwrap_or(first_token)
                .to_string();
        }
        for token in rest.split_whitespace() {
            if token.contains(':') {
                return token.rsplit(':').next().unwrap_or(token).to_string();
            }
        }
        return first_token.to_string();
    }
    "unknown".to_string()
}

pub fn extract_probe_name_from_panic(line: &str) -> String {
    if let Some(start) = line.find("thread '") {
        let rest = &line[start + 8..];
        if let Some(end) = rest.find('\'') {
            let name = &rest[..end];
            return name.rsplit("::").next().unwrap_or(name).to_string();
        }
    }
    if let Some(start) = line.find("test ") {
        let rest = &line[start + 5..];
        if let Some(end) = rest.find(" ...") {
            let name = &rest[..end];
            return name.rsplit("::").next().unwrap_or(name).to_string();
        }
    }
    "panic".to_string()
}

pub fn extract_probe_diffs(step_name: &str, log: &str) -> Vec<ProbeDiff> {
    let mut diffs = Vec::new();
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.contains("DIFF ") {
            let probe = extract_probe_name_from_diff(trimmed);
            diffs.push(ProbeDiff {
                step: step_name.to_string(),
                probe,
                line: trimmed.to_string(),
            });
        } else if trimmed.contains("panicked at") {
            let probe = extract_probe_name_from_panic(trimmed);
            diffs.push(ProbeDiff {
                step: step_name.to_string(),
                probe,
                line: trimmed.to_string(),
            });
        }
    }
    diffs
}

pub fn parse_cleanup_count(output: &str) -> Option<u64> {
    output.lines().find_map(|line| {
        let (_, num_str) = line.split_once("remaining carrick procs")?;
        let (_, count_str) = num_str.split_once('=')?;
        count_str.trim().parse::<u64>().ok()
    })
}

pub fn inspect_artifact(root: &Path) -> Result<ArtifactIdentity, String> {
    let bin_path = root.join("target/release/carrick");
    if !bin_path.exists() {
        return Err(format!("release binary '{}' not found", bin_path.display()));
    }

    let bytes = fs::read(&bin_path)
        .map_err(|e| format!("failed to read binary '{}': {e}", bin_path.display()))?;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));

    let bin_str = bin_path.to_string_lossy().to_string();

    let codesign_out = Command::new("/usr/bin/codesign")
        .args(["-dvvv", &bin_str])
        .output()
        .map_err(|e| format!("codesign inspection failed: {e}"))?;
    let codesign_err = String::from_utf8_lossy(&codesign_out.stderr);
    let cdhash = codesign_err
        .lines()
        .find_map(|l| l.strip_prefix("CDHash="))
        .ok_or_else(|| "missing CDHash in codesign output".to_string())?
        .trim()
        .to_string();

    let ent_out = Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", ":-", &bin_str])
        .output()
        .map_err(|e| format!("entitlements inspection failed: {e}"))?;
    let ent_str = String::from_utf8_lossy(&ent_out.stdout);
    let hypervisor_entitlement = ent_str
        .split_once("<key>com.apple.security.hypervisor</key>")
        .is_some_and(|(_, val)| val.trim_start().starts_with("<true/>"));

    let lc_uuid = match Command::new("/usr/bin/dwarfdump")
        .args(["--uuid", &bin_str])
        .output()
    {
        Ok(out) if out.status.success() => {
            let out_str = String::from_utf8_lossy(&out.stdout);
            out_str
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .to_string()
        }
        _ => {
            let otool_out = Command::new("/usr/bin/otool")
                .args(["-l", &bin_str])
                .output()
                .map_err(|e| format!("otool failed: {e}"))?;
            let otool_str = String::from_utf8_lossy(&otool_out.stdout);
            otool_str
                .lines()
                .find_map(|l| {
                    let trimmed = l.trim();
                    trimmed.strip_prefix("uuid ")
                })
                .unwrap_or("unknown")
                .trim()
                .to_string()
        }
    };

    let otool_out = Command::new("/usr/bin/otool")
        .args(["-l", &bin_str])
        .output()
        .map_err(|e| format!("otool -l failed: {e}"))?;
    let otool_str = String::from_utf8_lossy(&otool_out.stdout);
    let dof_present = otool_str.contains("__dof_carrick");

    Ok(ArtifactIdentity {
        path: bin_path,
        sha256,
        cdhash,
        lc_uuid,
        hypervisor_entitlement,
        dof_present,
    })
}

pub fn matches_ltp_suite_pattern(name: &str) -> bool {
    let prefixes = [
        "inotify",
        "fanotify",
        "read",
        "write",
        "lseek",
        "pread",
        "pwrite",
        "fstat",
        "stat",
        "dup",
        "close",
        "open",
        "fsync",
        "ftruncate",
        "truncate",
        "creat",
    ];
    if let Some(rest) = name.strip_prefix("ltp-") {
        for prefix in prefixes {
            let matched = rest.strip_prefix(prefix).is_some_and(|after| {
                after
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            });
            if matched {
                return true;
            }
        }
    }
    false
}

pub fn resolve_ltp_suites(root: &Path) -> io::Result<Vec<String>> {
    let suites_path = root.join("scripts/conformance/suites.toml");
    let content = fs::read_to_string(&suites_path)?;
    let mut suites = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        let matched = trimmed
            .strip_prefix("name = \"")
            .and_then(|r| r.strip_suffix('"'))
            .filter(|n| matches_ltp_suite_pattern(n));
        if let Some(name) = matched {
            suites.push(name.to_string());
        }
    }
    suites.sort();
    suites.dedup();
    Ok(suites)
}

fn run_command_redirect(
    prog: &str,
    args: &[&str],
    env: &[(&str, &str)],
    cwd: &Path,
    log_path: &Path,
) -> io::Result<(Option<i32>, f64)> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let log_file = fs::File::create(log_path)?;
    let err_file = log_file.try_clone()?;

    let mut cmd = Command::new(prog);
    cmd.args(args);
    cmd.current_dir(cwd);
    cmd.stdin(Stdio::null());
    cmd.stdout(log_file);
    cmd.stderr(err_file);

    for (k, v) in env {
        cmd.env(k, v);
    }

    let start = Instant::now();
    let mut child = cmd.spawn()?;
    let status = child.wait()?;
    let duration_s = start.elapsed().as_secs_f64();

    Ok((extract_exit_code(&status).into(), duration_s))
}

pub fn run(root_arg: Option<&Path>, args: AcceptArgs) -> Result<(), AcceptError> {
    let repo_info =
        crate::cli::resolve_repo_info(root_arg).map_err(|e| AcceptError::Git(e.to_string()))?;
    let root = repo_info.repository_root;
    let head = repo_info.head;

    let short_head_out = command::run_checked("git", ["rev-parse", "--short", "HEAD"], Some(&root))
        .map_err(|e| AcceptError::Git(e.to_string()))?;
    let short_head = short_head_out.stdout.trim().to_string();

    let timestamp = generate_timestamp();

    // The output directory is target/el1-gate/<short_head>/
    let run_dir = root.join("target/el1-gate").join(&short_head);
    fs::create_dir_all(&run_dir).map_err(|e| AcceptError::Io {
        path: run_dir.clone(),
        source: e,
    })?;

    let receipt_path = args.receipt.unwrap_or_else(|| run_dir.join("receipt.json"));

    // Check git tree cleanliness
    let git_status_out = command::run_checked("git", ["status", "--porcelain"], Some(&root))
        .map_err(|e| AcceptError::Git(e.to_string()))?;
    let (clean_tree, has_tracked_modifications) = check_git_status(&git_status_out.stdout);

    let mut failures = Vec::new();
    if has_tracked_modifications {
        failures.push("dirty tracked working tree (receipts belong to a commit)".to_string());
    }

    let mut step_results = Vec::new();
    let mut skipped_steps = Vec::new();
    let mut artifact_identity = None;
    let mut el1_summary = None;
    let mut probe_diffs = Vec::new();
    let mut cleanup_counts = Vec::new();

    // 1. Host Phase
    if matches!(args.phase, AcceptPhase::Host | AcceptPhase::All) {
        println!("--- Host phase starting ---");
        for step in HOST_STEPS {
            let log_path = run_dir.join(step.log_name);
            let display_cmd = format!("{} {}", step.program, step.args.join(" "));
            println!("  running: {display_cmd} (log: {})", log_path.display());

            let (exit_code, duration_s) =
                run_command_redirect(step.program, step.args, step.env, &root, &log_path).map_err(
                    |e| AcceptError::Io {
                        path: log_path.clone(),
                        source: e,
                    },
                )?;

            let passed = exit_code == Some(0);
            let error = if !passed {
                let msg = format!(
                    "step '{}' failed with exit code {}",
                    step.name,
                    exit_code.unwrap_or(-1)
                );
                failures.push(msg.clone());
                Some(msg)
            } else {
                None
            };

            step_results.push(StepResult {
                name: step.name.to_string(),
                command: display_cmd,
                exit_code,
                log_path,
                duration_s,
                passed,
                error,
            });
        }
    }

    // 2. Signed Phase
    if matches!(args.phase, AcceptPhase::Signed | AcceptPhase::All) {
        if std::env::consts::OS != "macos" || std::env::consts::ARCH != "aarch64" {
            return Err(AcceptError::UnsupportedPlatform(format!(
                "{}-{} (signed phase requires macOS aarch64)",
                std::env::consts::OS,
                std::env::consts::ARCH
            )));
        }

        println!("--- Signed phase starting (profile: {}) ---", args.profile);

        // Signed Step 1: just build + artifact inspection
        let mut initial_sha = String::new();
        {
            let step_name = "build";
            let run_id = format!("accept-{timestamp}-{step_name}");
            let log_path = run_dir.join("signed-01-build.log");
            let cmd_str = "just build";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let lease = HostLease::acquire(HostLeaseMode::Carrick)
                .map_err(|e| AcceptError::Failed(format!("failed to acquire host lease: {e}")))?;

            let (exit_code, duration_s) = run_command_redirect(
                "just",
                &["build"],
                &[("CARRICK_RUN_ID", &run_id)],
                &root,
                &log_path,
            )
            .map_err(|e| AcceptError::Io {
                path: log_path.clone(),
                source: e,
            })?;

            let reap = command::run_checked("scripts/sudo/kill.sh", [&run_id], Some(&root));
            drop(lease);

            let remaining_count = reap
                .as_ref()
                .ok()
                .and_then(|out| parse_cleanup_count(&out.stdout))
                .unwrap_or(0);
            cleanup_counts.push(CleanupCount {
                step: step_name.to_string(),
                run_id: run_id.clone(),
                remaining_count,
            });

            if remaining_count != 0 {
                failures.push(format!(
                    "step '{step_name}' leaked {remaining_count} processes under run_id '{run_id}'"
                ));
            }

            let mut passed = exit_code == Some(0);
            let mut error = if !passed {
                Some(format!(
                    "build step failed with exit code {}",
                    exit_code.unwrap_or(-1)
                ))
            } else {
                None
            };

            if passed {
                match inspect_artifact(&root) {
                    Ok(identity) => {
                        initial_sha = identity.sha256.clone();
                        let artifact_txt_path = run_dir.join("artifact.txt");
                        let artifact_txt = format!(
                            "head {}\nsha256 {}\nCDHash={}\n    uuid {}\n{}\n{}",
                            short_head,
                            identity.sha256,
                            identity.cdhash,
                            identity.lc_uuid,
                            if identity.hypervisor_entitlement {
                                "com.apple.security.hypervisor"
                            } else {
                                "missing hypervisor entitlement"
                            },
                            if identity.dof_present {
                                "dof present"
                            } else {
                                "missing __dof_carrick"
                            }
                        );
                        let _ = fs::write(&artifact_txt_path, artifact_txt);

                        if !identity.hypervisor_entitlement {
                            passed = false;
                            let msg = "artifact missing com.apple.security.hypervisor entitlement"
                                .to_string();
                            failures.push(msg.clone());
                            error = Some(msg);
                        } else if !identity.dof_present {
                            passed = false;
                            let msg = "artifact missing __dof_carrick section".to_string();
                            failures.push(msg.clone());
                            error = Some(msg);
                        }
                        artifact_identity = Some(identity);
                    }
                    Err(err) => {
                        passed = false;
                        failures.push(err.clone());
                        error = Some(err);
                    }
                }
            } else if let Some(e) = &error {
                failures.push(e.clone());
            }

            step_results.push(StepResult {
                name: step_name.to_string(),
                command: cmd_str.to_string(),
                exit_code,
                log_path,
                duration_s,
                passed,
                error,
            });
        }

        // Signed Step 2: probe binaries check for musl and gnu (in full profile)
        if args.profile == AcceptProfile::Full {
            for target in ["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"] {
                let release_dir = root
                    .join("conformance-probes/target")
                    .join(target)
                    .join("release");
                if !release_dir.is_dir() {
                    let msg = format!(
                        "probe binaries missing for {target}: run scripts/build-probes.sh (Docker)"
                    );
                    failures.push(msg.clone());
                }
            }
        }

        // Signed Step 3: el1-embed (carrick-embed el1_) vs allowlist
        {
            let step_name = "el1-embed";
            let run_id = format!("accept-{timestamp}-el1");
            let log_path = run_dir.join("el1-embed.log");
            let cmd_str = "./scripts/test-signed.sh carrick-embed el1_ --nocapture";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let lease = HostLease::acquire(HostLeaseMode::Carrick)
                .map_err(|e| AcceptError::Failed(format!("failed to acquire host lease: {e}")))?;

            let (exit_code, duration_s) = run_command_redirect(
                "./scripts/test-signed.sh",
                &["carrick-embed", "el1_", "--nocapture"],
                &[("CARRICK_RUN_ID", &run_id)],
                &root,
                &log_path,
            )
            .map_err(|e| AcceptError::Io {
                path: log_path.clone(),
                source: e,
            })?;

            let reap = command::run_checked("scripts/sudo/kill.sh", [&run_id], Some(&root));
            drop(lease);

            let remaining_count = reap
                .as_ref()
                .ok()
                .and_then(|out| parse_cleanup_count(&out.stdout))
                .unwrap_or(0);
            cleanup_counts.push(CleanupCount {
                step: step_name.to_string(),
                run_id: run_id.clone(),
                remaining_count,
            });

            if remaining_count != 0 {
                failures.push(format!(
                    "step '{step_name}' leaked {remaining_count} processes under run_id '{run_id}'"
                ));
            }

            let log_content = fs::read_to_string(&log_path).unwrap_or_default();
            let actual_failures = parse_el1_failures(&log_content);
            let allowlist_path = root.join("scripts/conformance/el1-known-red.txt");
            let allowlist = load_allowlist(&allowlist_path).unwrap_or_default();

            let comparison = compare_el1_failures(&actual_failures, &allowlist);

            if !comparison.now_passing.is_empty() {
                println!(
                    "  [NOTICE] el1 tests now passing, remove from allowlist: {}",
                    comparison.now_passing.join(", ")
                );
            }

            let mut passed = comparison.unexpected_failures.is_empty();
            let mut error = None;

            if !comparison.unexpected_failures.is_empty() {
                let msg = format!(
                    "el1 unexpected failures: {}",
                    comparison.unexpected_failures.join(", ")
                );
                failures.push(msg.clone());
                error = Some(msg);
            } else if exit_code != Some(0) && actual_failures.is_empty() {
                passed = false;
                let msg = format!(
                    "el1 step crashed before executing tests (exit code {})",
                    exit_code.unwrap_or(-1)
                );
                failures.push(msg.clone());
                error = Some(msg);
            }

            el1_summary = Some(comparison);

            step_results.push(StepResult {
                name: step_name.to_string(),
                command: cmd_str.to_string(),
                exit_code,
                log_path,
                duration_s,
                passed,
                error,
            });
        }

        // Signed Step 4: a_fresh_executable_page (i-cache test)
        {
            let step_name = "fresh-executable-page";
            let run_id = format!("accept-{timestamp}-icache");
            let log_path = run_dir.join("fresh-executable-page.log");
            let cmd_str =
                "./scripts/test-signed.sh carrick-embed a_fresh_executable_page --nocapture";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let lease = HostLease::acquire(HostLeaseMode::Carrick)
                .map_err(|e| AcceptError::Failed(format!("failed to acquire host lease: {e}")))?;

            let (exit_code, duration_s) = run_command_redirect(
                "./scripts/test-signed.sh",
                &["carrick-embed", "a_fresh_executable_page", "--nocapture"],
                &[("CARRICK_RUN_ID", &run_id)],
                &root,
                &log_path,
            )
            .map_err(|e| AcceptError::Io {
                path: log_path.clone(),
                source: e,
            })?;

            let reap = command::run_checked("scripts/sudo/kill.sh", [&run_id], Some(&root));
            drop(lease);

            let remaining_count = reap
                .as_ref()
                .ok()
                .and_then(|out| parse_cleanup_count(&out.stdout))
                .unwrap_or(0);
            cleanup_counts.push(CleanupCount {
                step: step_name.to_string(),
                run_id: run_id.clone(),
                remaining_count,
            });

            if remaining_count != 0 {
                failures.push(format!(
                    "step '{step_name}' leaked {remaining_count} processes under run_id '{run_id}'"
                ));
            }

            let passed = exit_code == Some(0);
            let error = if !passed {
                let msg = format!(
                    "fresh executable page step failed with exit code {}",
                    exit_code.unwrap_or(-1)
                );
                failures.push(msg.clone());
                Some(msg)
            } else {
                None
            };

            step_results.push(StepResult {
                name: step_name.to_string(),
                command: cmd_str.to_string(),
                exit_code,
                log_path,
                duration_s,
                passed,
                error,
            });
        }

        // Signed Step 5: generic_probe_shard_
        {
            let step_name = "generic-probe-shards";
            let run_id = format!("accept-{timestamp}-probe-shards");
            let log_path = run_dir.join("generic-probe-shards.log");
            let cmd_str = "./scripts/test-signed.sh carrick-conformance-next generic_probe_shard_ --nocapture";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let lease = HostLease::acquire(HostLeaseMode::Carrick)
                .map_err(|e| AcceptError::Failed(format!("failed to acquire host lease: {e}")))?;

            let (exit_code, duration_s) = run_command_redirect(
                "./scripts/test-signed.sh",
                &[
                    "carrick-conformance-next",
                    "generic_probe_shard_",
                    "--nocapture",
                ],
                &[("CARRICK_RUN_ID", &run_id)],
                &root,
                &log_path,
            )
            .map_err(|e| AcceptError::Io {
                path: log_path.clone(),
                source: e,
            })?;

            let reap = command::run_checked("scripts/sudo/kill.sh", [&run_id], Some(&root));
            drop(lease);

            let remaining_count = reap
                .as_ref()
                .ok()
                .and_then(|out| parse_cleanup_count(&out.stdout))
                .unwrap_or(0);
            cleanup_counts.push(CleanupCount {
                step: step_name.to_string(),
                run_id: run_id.clone(),
                remaining_count,
            });

            if remaining_count != 0 {
                failures.push(format!(
                    "step '{step_name}' leaked {remaining_count} processes under run_id '{run_id}'"
                ));
            }

            let log_content = fs::read_to_string(&log_path).unwrap_or_default();
            let diffs = extract_probe_diffs(step_name, &log_content);
            let mut passed = exit_code == Some(0) && diffs.is_empty();
            let mut error = None;

            if !diffs.is_empty() {
                passed = false;
                let probe_names: Vec<_> = diffs.iter().map(|d| d.probe.as_str()).collect();
                let msg = format!(
                    "generic probe shards contained DIFF or panic: {}",
                    probe_names.join(", ")
                );
                failures.push(msg.clone());
                error = Some(msg);
                probe_diffs.extend(diffs);
            } else if exit_code != Some(0) {
                let msg = format!(
                    "generic probe shards failed with exit code {}",
                    exit_code.unwrap_or(-1)
                );
                failures.push(msg.clone());
                error = Some(msg);
            }

            step_results.push(StepResult {
                name: step_name.to_string(),
                command: cmd_str.to_string(),
                exit_code,
                log_path,
                duration_s,
                passed,
                error,
            });
        }

        // Signed Step 6: case_
        {
            let step_name = "probe-cases";
            let run_id = format!("accept-{timestamp}-probe-cases");
            let log_path = run_dir.join("probe-cases.log");
            let cmd_str = "./scripts/test-signed.sh carrick-conformance-next case_ --nocapture";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let lease = HostLease::acquire(HostLeaseMode::Carrick)
                .map_err(|e| AcceptError::Failed(format!("failed to acquire host lease: {e}")))?;

            let (exit_code, duration_s) = run_command_redirect(
                "./scripts/test-signed.sh",
                &["carrick-conformance-next", "case_", "--nocapture"],
                &[("CARRICK_RUN_ID", &run_id)],
                &root,
                &log_path,
            )
            .map_err(|e| AcceptError::Io {
                path: log_path.clone(),
                source: e,
            })?;

            let reap = command::run_checked("scripts/sudo/kill.sh", [&run_id], Some(&root));
            drop(lease);

            let remaining_count = reap
                .as_ref()
                .ok()
                .and_then(|out| parse_cleanup_count(&out.stdout))
                .unwrap_or(0);
            cleanup_counts.push(CleanupCount {
                step: step_name.to_string(),
                run_id: run_id.clone(),
                remaining_count,
            });

            if remaining_count != 0 {
                failures.push(format!(
                    "step '{step_name}' leaked {remaining_count} processes under run_id '{run_id}'"
                ));
            }

            let log_content = fs::read_to_string(&log_path).unwrap_or_default();
            let diffs = extract_probe_diffs(step_name, &log_content);
            let mut passed = exit_code == Some(0) && diffs.is_empty();
            let mut error = None;

            if !diffs.is_empty() {
                passed = false;
                let probe_names: Vec<_> = diffs.iter().map(|d| d.probe.as_str()).collect();
                let msg = format!(
                    "probe cases contained DIFF or panic: {}",
                    probe_names.join(", ")
                );
                failures.push(msg.clone());
                error = Some(msg);
                probe_diffs.extend(diffs);
            } else if exit_code != Some(0) {
                let msg = format!(
                    "probe cases failed with exit code {}",
                    exit_code.unwrap_or(-1)
                );
                failures.push(msg.clone());
                error = Some(msg);
            }

            step_results.push(StepResult {
                name: step_name.to_string(),
                command: cmd_str.to_string(),
                exit_code,
                log_path,
                duration_s,
                passed,
                error,
            });
        }

        // Full Profile Only: Retained probes, LTP subset, inotify09
        if args.profile == AcceptProfile::Full {
            // Step 7: conformance-probes retained step (may start Docker -> LOCK_EX)
            {
                let step_name = "conformance-probes-retained";
                let run_id = format!("accept-{timestamp}-probes");
                let log_path = run_dir.join("probes.log");
                let cmd_str = "just --no-deps conformance-probes";
                println!("  running: {cmd_str} (run_id: {run_id})");

                let lease = HostLease::acquire(HostLeaseMode::Docker).map_err(|e| {
                    AcceptError::Failed(format!("failed to acquire docker host lease: {e}"))
                })?;

                let (exit_code, duration_s) = run_command_redirect(
                    "just",
                    &["--no-deps", "conformance-probes"],
                    &[("CARRICK_RUN_ID", &run_id)],
                    &root,
                    &log_path,
                )
                .map_err(|e| AcceptError::Io {
                    path: log_path.clone(),
                    source: e,
                })?;

                let reap = command::run_checked("scripts/sudo/kill.sh", [&run_id], Some(&root));
                drop(lease);

                let remaining_count = reap
                    .as_ref()
                    .ok()
                    .and_then(|out| parse_cleanup_count(&out.stdout))
                    .unwrap_or(0);
                cleanup_counts.push(CleanupCount {
                    step: step_name.to_string(),
                    run_id: run_id.clone(),
                    remaining_count,
                });

                let passed = exit_code == Some(0);
                let error = if !passed {
                    let msg = format!(
                        "retained conformance probes failed with exit code {}",
                        exit_code.unwrap_or(-1)
                    );
                    failures.push(msg.clone());
                    Some(msg)
                } else {
                    None
                };

                step_results.push(StepResult {
                    name: step_name.to_string(),
                    command: cmd_str.to_string(),
                    exit_code,
                    log_path,
                    duration_s,
                    passed,
                    error,
                });
            }

            // Step 8: LTP file/inotify suite subset (may start Docker -> LOCK_EX)
            {
                let step_name = "ltp";
                let run_id = format!("accept-{timestamp}-ltp");
                let log_path = run_dir.join("ltp.log");
                let ltp_jsonl_path = run_dir.join("ltp.jsonl");

                let suites = resolve_ltp_suites(&root).unwrap_or_default();
                let mut cmd_args = vec![
                    "run",
                    "-q",
                    "-p",
                    "carrick-conformance",
                    "--",
                    "--tier",
                    "full",
                ];
                for s in &suites {
                    cmd_args.push("--suite");
                    cmd_args.push(s.as_str());
                }
                let ltp_jsonl_str = ltp_jsonl_path.to_string_lossy().to_string();
                cmd_args.push("--jsonl");
                cmd_args.push(&ltp_jsonl_str);

                let display_cmd = format!(
                    "cargo run -q -p carrick-conformance -- --tier full [{} suites] --jsonl {}",
                    suites.len(),
                    ltp_jsonl_path.display()
                );
                println!("  running: {display_cmd} (run_id: {run_id})");

                let lease = HostLease::acquire(HostLeaseMode::Docker).map_err(|e| {
                    AcceptError::Failed(format!("failed to acquire docker host lease: {e}"))
                })?;

                let (exit_code, duration_s) = run_command_redirect(
                    "cargo",
                    &cmd_args,
                    &[("CARRICK_RUN_ID", &run_id)],
                    &root,
                    &log_path,
                )
                .map_err(|e| AcceptError::Io {
                    path: log_path.clone(),
                    source: e,
                })?;

                let reap = command::run_checked("scripts/sudo/kill.sh", [&run_id], Some(&root));
                drop(lease);

                let remaining_count = reap
                    .as_ref()
                    .ok()
                    .and_then(|out| parse_cleanup_count(&out.stdout))
                    .unwrap_or(0);
                cleanup_counts.push(CleanupCount {
                    step: step_name.to_string(),
                    run_id: run_id.clone(),
                    remaining_count,
                });

                let passed = exit_code == Some(0);
                let error = if !passed {
                    let msg = format!(
                        "LTP suites failed with exit code {}",
                        exit_code.unwrap_or(-1)
                    );
                    failures.push(msg.clone());
                    Some(msg)
                } else {
                    None
                };

                step_results.push(StepResult {
                    name: step_name.to_string(),
                    command: display_cmd,
                    exit_code,
                    log_path,
                    duration_s,
                    passed,
                    error,
                });
            }

            // Step 9: inotify09 screen with CARRICK_EL1=1 and =0
            for mode in ["1", "0"] {
                let step_name = format!("inotify09-el{mode}");
                let run_id = format!("el1-gate-{mode}");
                let log_path = run_dir.join(format!("inotify09-{mode}.log"));
                let bin_path = root.join("target/release/carrick");
                let bin_str = bin_path.to_string_lossy().to_string();

                let cmd_str = format!(
                    "CARRICK_EL1={mode} {bin_str} run --rm localhost:5050/ltp:arm64 /bin/sh -c /opt/ltp/testcases/bin/inotify09"
                );
                println!("  running: {cmd_str} (run_id: {run_id})");

                let lease = HostLease::acquire(HostLeaseMode::Docker).map_err(|e| {
                    AcceptError::Failed(format!("failed to acquire docker host lease: {e}"))
                })?;

                let (exit_code, duration_s) = run_command_redirect(
                    &bin_str,
                    &[
                        "run",
                        "--rm",
                        "localhost:5050/ltp:arm64",
                        "/bin/sh",
                        "-c",
                        "/opt/ltp/testcases/bin/inotify09",
                    ],
                    &[("CARRICK_RUN_ID", &run_id), ("CARRICK_EL1", mode)],
                    &root,
                    &log_path,
                )
                .map_err(|e| AcceptError::Io {
                    path: log_path.clone(),
                    source: e,
                })?;

                let reap = command::run_checked("scripts/sudo/kill.sh", [&run_id], Some(&root));
                drop(lease);

                let remaining_count = reap
                    .as_ref()
                    .ok()
                    .and_then(|out| parse_cleanup_count(&out.stdout))
                    .unwrap_or(0);
                cleanup_counts.push(CleanupCount {
                    step: step_name.clone(),
                    run_id: run_id.clone(),
                    remaining_count,
                });

                let log_content = fs::read_to_string(&log_path).unwrap_or_default();
                let has_tpass = log_content.contains("TPASS");
                let passed = exit_code == Some(0) && has_tpass;
                let error = if !passed {
                    let msg = if !has_tpass {
                        format!("inotify09 EL1={mode} did not TPASS")
                    } else {
                        format!(
                            "inotify09 EL1={mode} failed with exit code {}",
                            exit_code.unwrap_or(-1)
                        )
                    };
                    failures.push(msg.clone());
                    Some(msg)
                } else {
                    None
                };

                let artifact_txt_path = run_dir.join("artifact.txt");
                if let Ok(mut f) = fs::OpenOptions::new().append(true).open(&artifact_txt_path) {
                    let _ = writeln!(f, "inotify09 EL1={mode} wall {:.2}", duration_s);
                }

                step_results.push(StepResult {
                    name: step_name,
                    command: cmd_str,
                    exit_code,
                    log_path,
                    duration_s,
                    passed,
                    error,
                });
            }
        } else {
            skipped_steps.push("conformance-probes-retained".to_string());
            skipped_steps.push("ltp".to_string());
            skipped_steps.push("inotify09-el1".to_string());
            skipped_steps.push("inotify09-el0".to_string());
        }

        // Final check: Binary unchanged
        let bin_path = root.join("target/release/carrick");
        if let Ok(bytes) = fs::read(&bin_path) {
            let now_sha = format!("{:x}", Sha256::digest(&bytes));
            if !initial_sha.is_empty() && now_sha != initial_sha {
                let msg = format!(
                    "binary changed during the gate (initial: {initial_sha}, now: {now_sha})"
                );
                failures.push(msg);
            }
        }
    }

    let overall = if failures.is_empty() { "PASS" } else { "FAIL" };

    let receipt = AcceptReceipt {
        schema_version: 1,
        timestamp: timestamp.clone(),
        head,
        clean_tree,
        phase: args.phase.to_string(),
        profile: args.profile.to_string(),
        overall: overall.to_string(),
        steps: step_results,
        skipped_steps: skipped_steps.clone(),
        artifact: artifact_identity,
        el1: el1_summary,
        probe_diffs,
        cleanup_counts,
        failures: failures.clone(),
    };

    if let Some(parent) = receipt_path.parent() {
        fs::create_dir_all(parent).map_err(|e| AcceptError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let json_bytes = serde_json::to_vec_pretty(&receipt)?;
    fs::write(&receipt_path, json_bytes).map_err(|e| AcceptError::Io {
        path: receipt_path.clone(),
        source: e,
    })?;

    // Print summary
    println!("\n==================== ACCEPT GATE SUMMARY ====================");
    println!("Phase:        {}", args.phase);
    println!("Profile:      {}", args.profile);
    println!("Timestamp:    {timestamp}");
    println!("Git HEAD:     {}", receipt.head);
    println!(
        "Working Tree: {}",
        if clean_tree { "Clean" } else { "Dirty" }
    );
    println!("Overall:      {overall}");
    println!("\nSteps:");
    for step in &receipt.steps {
        println!(
            "  [{}] {} ({:.2}s)",
            if step.passed { "PASS" } else { "FAIL" },
            step.name,
            step.duration_s
        );
    }

    if !skipped_steps.is_empty() {
        println!("\nSkipped Steps (profile {}):", args.profile);
        for skipped in &skipped_steps {
            println!("  [SKIP] {skipped}");
        }
    }

    if let Some(el1) = receipt.el1.as_ref().filter(|e| !e.now_passing.is_empty()) {
        println!(
            "\nEL1 now passing (remove from allowlist): {}",
            el1.now_passing.join(", ")
        );
    }

    if !failures.is_empty() {
        println!("\nFailures:");
        for failure in &failures {
            println!("  - {failure}");
        }
    }

    println!("\nReceipt written to: {}", receipt_path.display());
    println!("=============================================================");

    if overall == "FAIL" {
        return Err(AcceptError::Failed(format!(
            "{} failures encountered during accept gate",
            failures.len()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_status_clean_and_dirty() {
        let clean = "";
        let (is_clean, has_tracked) = check_git_status(clean);
        assert!(is_clean);
        assert!(!has_tracked);

        let untracked = "?? scratch.txt\n";
        let (is_clean, has_tracked) = check_git_status(untracked);
        assert!(!is_clean);
        assert!(!has_tracked);

        let modified = " M crates/carrick-xtask/src/main.rs\n";
        let (is_clean, has_tracked) = check_git_status(modified);
        assert!(!is_clean);
        assert!(has_tracked);

        let staged = "M  crates/carrick-xtask/src/main.rs\n";
        let (is_clean, has_tracked) = check_git_status(staged);
        assert!(!is_clean);
        assert!(has_tracked);
    }

    #[test]
    fn test_matches_ltp_suite_pattern() {
        assert!(matches_ltp_suite_pattern("ltp-inotify01"));
        assert!(matches_ltp_suite_pattern("ltp-fanotify10"));
        assert!(matches_ltp_suite_pattern("ltp-read01"));
        assert!(matches_ltp_suite_pattern("ltp-write02"));
        assert!(matches_ltp_suite_pattern("ltp-fstat01"));
        assert!(matches_ltp_suite_pattern("ltp-creat01"));
        assert!(!matches_ltp_suite_pattern("ltp-clock_gettime01"));
        assert!(!matches_ltp_suite_pattern("ltp-futex01"));
        assert!(!matches_ltp_suite_pattern("cpython-socket"));
    }

    #[test]
    fn test_el1_allowlist_matching_and_unexpected() {
        let allowlist = vec![
            "el1_delegated_root_concurrent_vma_ops".to_string(),
            "el1_fork_cow_resolves_in_guest".to_string(),
            "el1_thread_lifecycle_ptrace_traceclone".to_string(),
            "el1_thread_lifecycle_spawn_slope".to_string(),
        ];

        // 1. Exact match
        let actual = allowlist.clone();
        let cmp = compare_el1_failures(&actual, &allowlist);
        assert!(cmp.unexpected_failures.is_empty());
        assert!(cmp.now_passing.is_empty());

        // 2. An allowed test now passes
        let actual = vec![
            "el1_delegated_root_concurrent_vma_ops".to_string(),
            "el1_fork_cow_resolves_in_guest".to_string(),
            "el1_thread_lifecycle_ptrace_traceclone".to_string(),
        ];
        let cmp = compare_el1_failures(&actual, &allowlist);
        assert!(cmp.unexpected_failures.is_empty());
        assert_eq!(
            cmp.now_passing,
            vec!["el1_thread_lifecycle_spawn_slope".to_string()]
        );

        // 3. New unexpected failure
        let actual = vec![
            "el1_delegated_root_concurrent_vma_ops".to_string(),
            "el1_fork_cow_resolves_in_guest".to_string(),
            "el1_thread_lifecycle_ptrace_traceclone".to_string(),
            "el1_thread_lifecycle_spawn_slope".to_string(),
            "el1_unexpected_new_defect".to_string(),
        ];
        let cmp = compare_el1_failures(&actual, &allowlist);
        assert_eq!(
            cmp.unexpected_failures,
            vec!["el1_unexpected_new_defect".to_string()]
        );
        assert!(cmp.now_passing.is_empty());
    }

    #[test]
    fn test_parse_el1_failures_from_log() {
        let sample_log = r#"
running 15 tests
test tests::el1_something_passed ... ok
test tests::el1_fork_cow_resolves_in_guest ... FAILED
test tests::el1_other_passed ... ok
test el1_thread_lifecycle_spawn_slope ... FAILED

failures:

---- tests::el1_fork_cow_resolves_in_guest stdout ----
thread 'tests::el1_fork_cow_resolves_in_guest' panicked at 'assertion failed'

failures:
    tests::el1_fork_cow_resolves_in_guest
    el1_thread_lifecycle_spawn_slope

test result: FAILED. 13 passed; 2 failed; 0 ignored
"#;

        let failures = parse_el1_failures(sample_log);
        assert_eq!(
            failures,
            vec![
                "el1_fork_cow_resolves_in_guest".to_string(),
                "el1_thread_lifecycle_spawn_slope".to_string()
            ]
        );
    }

    #[test]
    fn test_extract_probe_diffs_and_panics() {
        let sample_log = r#"
test shard_0 ... ok
DIFF generic probe shard 0 aarch64-unknown-linux-musl:clockgetres
DIFF core_mount aarch64-unknown-linux-musl:stat
some normal log line
thread 'test_probe_futex' panicked at 'explicit panic', tests/foo.rs:12:5
"#;

        let diffs = extract_probe_diffs("step-test", sample_log);
        assert_eq!(diffs.len(), 3);
        assert_eq!(diffs[0].probe, "clockgetres");
        assert_eq!(diffs[1].probe, "stat");
        assert_eq!(diffs[2].probe, "test_probe_futex");
    }

    #[test]
    fn test_parse_cleanup_count() {
        let sample_zero =
            "pass 1: killing 0 procs\nremaining carrick procs (run-id accept-test) = 0\n";
        assert_eq!(parse_cleanup_count(sample_zero), Some(0));

        let sample_leaked =
            "pass 1: killing 2 procs\nremaining carrick procs (run-id accept-test) = 2\n";
        assert_eq!(parse_cleanup_count(sample_leaked), Some(2));
    }

    #[test]
    fn test_receipt_serialization_round_trip() {
        let receipt = AcceptReceipt {
            schema_version: 1,
            timestamp: "20261002-120000".to_string(),
            head: "0123456789abcdef".to_string(),
            clean_tree: true,
            phase: "host".to_string(),
            profile: "no-docker".to_string(),
            overall: "PASS".to_string(),
            steps: vec![StepResult {
                name: "test-kernel".to_string(),
                command: "just test-kernel".to_string(),
                exit_code: Some(0),
                log_path: PathBuf::from("target/el1-gate/012345678/01-test-kernel.log"),
                duration_s: 1.23,
                passed: true,
                error: None,
            }],
            skipped_steps: vec!["ltp".to_string()],
            artifact: None,
            el1: None,
            probe_diffs: vec![],
            cleanup_counts: vec![],
            failures: vec![],
        };

        let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
        let deserialized: AcceptReceipt = serde_json::from_str(&json).expect("deserialize receipt");
        assert_eq!(receipt, deserialized);
    }
}
