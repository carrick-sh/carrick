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
        overrides_with = "profile",
        help = "Acceptance profile: no-docker (default for workers), linux-portable (host only, no KVM tests), kvm (KVM runner lane, host only), or full (director)"
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
    LinuxPortable,
    /// The trusted KVM runner's lane: every kvm-lane test target, nothing else.
    Kvm,
    Full,
}

impl fmt::Display for AcceptProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDocker => write!(f, "no-docker"),
            Self::LinuxPortable => write!(f, "linux-portable"),
            Self::Kvm => write!(f, "kvm"),
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
    /// Qualified `<test-binary>::<test>` names a step reported FAILED.
    /// `ci-receipt diff` keys NEW/FIXED on these, never on exit codes alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_tests: Vec<String>,
    /// Failures no test name explains: a crashed or signalled test binary, a
    /// compile error, a step killed by a signal, or a `test result: FAILED`
    /// line with empty itemization. Each is its own identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unitemized_failures: Vec<String>,
    /// Qualified `<test-binary>::<test>` names that started (`test <name> ...`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub started_tests: Vec<String>,
    /// Test binaries that printed a `test result:` summary line.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub finished_binaries: Vec<String>,
    /// Test binaries that started or reported `test-signed: FAIL <exe>` without
    /// printing a `test result:` summary line.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unfinished_binaries: Vec<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureBundleReceipt {
    pub source: String,
    pub path: String,
    pub captured_path: String,
    pub identity: String,
    pub archive_sha256: String,
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
    pub fixture_validation: Option<crate::fixtures::ValidationReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub el1: Option<El1Comparison>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probe_diffs: Vec<ProbeDiff>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleanup_counts: Vec<CleanupCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixture_bundle: Option<FixtureBundleReceipt>,
    #[serde(default)]
    pub host_load: crate::host_load::HostLoadReport,
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

/// The CI KVM runner's receipt covers exactly `just test-kvm`; the portable
/// host steps already run on hosted CI.
pub const KVM_STEPS: &[StepSpec] = &[StepSpec {
    name: "kvm-tests",
    program: "just",
    args: &["test-kvm"],
    env: &[],
    log_name: "01-kvm-tests.log",
}];

// Keep the package/target selection identical for both ownership passes.
macro_rules! linux_portable_test_args {
    ($($harness_arg:literal),+ $(,)?) => {
        &[
            "test",
            "--no-fail-fast",
            "-p",
            "carrick-el1",
            "-p",
            "carrick-el1-linux",
            "-p",
            "carrick-el1-abi",
            "-p",
            "carrick-sched-core",
            "-p",
            "carrick-fd-core",
            "-p",
            "carrick-pipe-core",
            "-p",
            "carrick-signal-core",
            "-p",
            "carrick-kernel-example",
            "-p",
            "carrick-x86",
            "-p",
            "carrick-aarch64",
            "-p",
            "carrick-abi",
            "-p",
            "carrick-guest-mem",
            "-p",
            "carrick-mmu-core",
            "-p",
            "carrick-timer-core",
            "-p",
            "carrick-inotify-core",
            "-p",
            "carrick-hal",
            "-p",
            "carrick-portable",
            "-p",
            "carrick-host-linux",
            "-p",
            "carrick-x86-cpl0-host",
            "-p",
            "carrick-signal-linux",
            "-p",
            "carrick-spec",
            "-p",
            "carrick-observability",
            "-p",
            "carrick-conformance-contract",
            "-p",
            "carrick-xtask",
            "--",
            $($harness_arg),+
        ]
    };
}

pub const LINUX_PORTABLE_STEPS: &[StepSpec] = &[
    StepSpec {
        name: "test-kernel",
        program: "just",
        args: &["test-kernel"],
        env: &[],
        log_name: "01-test-kernel.log",
    },
    StepSpec {
        name: "portable-tests",
        program: "cargo",
        args: linux_portable_test_args!("--skip", "serial_host"),
        env: &[],
        log_name: "02-portable-tests.log",
    },
    // Match just test's process-global ownership policy without serializing
    // ordinary tests. Retain the receipt name: baseline comparison unions
    // same-name steps, so moving serial tests into this pass loses no history.
    StepSpec {
        name: "portable-tests",
        program: "cargo",
        args: linux_portable_test_args!("serial_host"),
        env: &[("RUST_TEST_THREADS", "1")],
        log_name: "03-portable-tests-serial-host.log",
    },
    StepSpec {
        name: "clippy-linux",
        program: "cargo",
        args: &[
            "clippy",
            "-p",
            "carrick-cli",
            // Selected explicitly so its unit-test target is linted under the
            // Linux feature closure; as a mere dependency only its lib is.
            "-p",
            "carrick-runtime",
            "-p",
            "carrick-xtask",
            "-p",
            "carrick-el1",
            "-p",
            "carrick-el1-linux",
            "-p",
            "carrick-kernel-example",
            "--no-default-features",
            "--features",
            "carrick-cli/platform-linux,carrick-cli/syscall-shim",
            "--all-targets",
            "--keep-going",
            "--",
            "-D",
            "warnings",
        ],
        env: &[],
        log_name: "04-clippy-linux.log",
    },
    StepSpec {
        name: "fmt-check",
        program: "just",
        args: &["fmt-check"],
        env: &[],
        log_name: "05-fmt-check.log",
    },
    StepSpec {
        name: "lint-domains-source",
        program: "just",
        args: &["lint-domains-source"],
        env: &[],
        log_name: "06-lint-domains-source.log",
    },
    StepSpec {
        name: "host-authority-linux",
        program: "cargo",
        args: &[
            "run",
            "--locked",
            "-p",
            "carrick-xtask",
            "--",
            "authority-debt",
        ],
        env: &[],
        log_name: "07-host-authority-linux.log",
    },
];

pub fn host_steps(profile: AcceptProfile) -> &'static [StepSpec] {
    match profile {
        AcceptProfile::LinuxPortable => LINUX_PORTABLE_STEPS,
        AcceptProfile::Kvm => KVM_STEPS,
        AcceptProfile::NoDocker | AcceptProfile::Full => HOST_STEPS,
    }
}

pub fn profile_phase(
    profile: AcceptProfile,
    phase: AcceptPhase,
) -> Result<AcceptPhase, AcceptError> {
    if matches!(profile, AcceptProfile::LinuxPortable | AcceptProfile::Kvm) {
        if phase == AcceptPhase::Signed {
            return Err(AcceptError::UnsupportedPlatform(format!(
                "{profile} supports the host phase only; use remote-accept --phase signed on the gate Mac"
            )));
        }
        return Ok(AcceptPhase::Host);
    }
    Ok(phase)
}

#[derive(Debug, Deserialize)]
struct LinuxHostTestException {
    test: String,
    reason: String,
}

fn linux_host_failure_details(log: &str, exceptions: &[LinuxHostTestException]) -> String {
    let failed: Vec<_> = log
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("test ")?
                .strip_suffix(" ... FAILED")
        })
        .collect();
    failed
        .into_iter()
        .map(|test| {
            if let Some(exception) = exceptions.iter().find(|entry| entry.test == test) {
                format!("known Linux host exception {test}: {}", exception.reason)
            } else {
                format!("unallowlisted failure {test}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedTestLog {
    pub failed_tests: Vec<String>,
    pub unitemized_failures: Vec<String>,
    pub started_tests: Vec<String>,
    pub finished_binaries: Vec<String>,
    pub unfinished_binaries: Vec<String>,
    pub saw_failed_result: bool,
}

fn binary_stem_from_path(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    let file = match file.rsplit_once(".noent.") {
        Some((stem, pid)) if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) => stem,
        _ => file,
    };
    match file.rsplit_once('-') {
        Some((stem, hash))
            if !stem.is_empty()
                && !hash.is_empty()
                && hash.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            stem.to_string()
        }
        _ => file.to_string(),
    }
}

fn is_valid_test_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(':')
        && !s.ends_with(':')
        && !s.contains(":::")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':')
}

fn qualify_test(binary: &str, name: &str) -> String {
    if binary.is_empty() {
        name.to_string()
    } else {
        format!("{binary}::{name}")
    }
}

fn extract_test_line(line: &str) -> Option<(&str, &str)> {
    let (before_dots, after_dots) = line.split_once(" ...")?;
    if !after_dots.is_empty() && !after_dots.starts_with(' ') {
        return None;
    }
    let before_trimmed = before_dots.trim_start();
    let candidate = if let Some(rest) = before_trimmed.strip_prefix("test ") {
        rest.trim()
    } else if let Some((prefix, rest)) = before_dots.rsplit_once("test ") {
        if prefix
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return None;
        }
        rest.trim()
    } else {
        return None;
    };
    is_valid_test_name(candidate).then_some((candidate, after_dots.trim()))
}

/// Parse a cargo or `test-signed` log into itemized test failures, unitemized
/// binary crashes/compile/parse errors, started test names, and finished vs
/// unfinished test binaries.
pub fn parse_test_log(log: &str) -> ParsedTestLog {
    use std::collections::BTreeSet;

    let mut current_binary = String::new();
    let mut current_run_saw_result = false;
    let mut current_run_failed_result = false;
    let mut current_run_itemized_count = 0usize;
    let mut in_failures_block = false;
    let mut pending_failures: Vec<String> = Vec::new();
    let mut saw_failed_result = false;

    let mut failed_tests = BTreeSet::new();
    let mut unitemized_failures = BTreeSet::new();
    let mut started_tests = BTreeSet::new();
    let mut finished_binaries = BTreeSet::new();
    let mut unfinished_binaries = BTreeSet::new();

    let start_binary = |new_binary: String,
                        current_binary: &mut String,
                        current_run_saw_result: &mut bool,
                        current_run_failed_result: &mut bool,
                        current_run_itemized_count: &mut usize,
                        in_failures_block: &mut bool,
                        pending_failures: &mut Vec<String>,
                        unfinished_binaries: &mut BTreeSet<String>| {
        if !current_binary.is_empty() && !*current_run_saw_result {
            unfinished_binaries.insert(current_binary.clone());
        }
        *current_binary = new_binary;
        *current_run_saw_result = false;
        *current_run_failed_result = false;
        *current_run_itemized_count = 0;
        *in_failures_block = false;
        pending_failures.clear();
    };

    for line in log.lines() {
        let trimmed = line.trim();
        if let Some((_, rest)) = line.split_once("test-signed: running ")
            && let Some(exe) = rest.split_whitespace().next()
        {
            start_binary(
                binary_stem_from_path(exe),
                &mut current_binary,
                &mut current_run_saw_result,
                &mut current_run_failed_result,
                &mut current_run_itemized_count,
                &mut in_failures_block,
                &mut pending_failures,
                &mut unfinished_binaries,
            );
            continue;
        }
        if let Some((_, rest)) = line.split_once("test-signed: negative control on ")
            && let Some(exe) = rest.split_whitespace().next()
        {
            start_binary(
                binary_stem_from_path(exe),
                &mut current_binary,
                &mut current_run_saw_result,
                &mut current_run_failed_result,
                &mut current_run_itemized_count,
                &mut in_failures_block,
                &mut pending_failures,
                &mut unfinished_binaries,
            );
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Running ")
            && !rest.trim_start().starts_with('`')
            && let Some((_, tail)) = rest.rsplit_once('(')
            && let Some(path) = tail.strip_suffix(')')
        {
            start_binary(
                binary_stem_from_path(path),
                &mut current_binary,
                &mut current_run_saw_result,
                &mut current_run_failed_result,
                &mut current_run_itemized_count,
                &mut in_failures_block,
                &mut pending_failures,
                &mut unfinished_binaries,
            );
            continue;
        }

        if let Some((name, status)) = extract_test_line(line) {
            let qualified = qualify_test(&current_binary, name);
            if status != "ignored" && !status.starts_with("ignored,") {
                started_tests.insert(qualified.clone());
            }
            if status == "FAILED" {
                failed_tests.insert(qualified);
                current_run_itemized_count += 1;
            }
        }

        if let Some((_, rest)) = trimmed.split_once("process didn't exit successfully: `") {
            if !trimmed.contains("(exit status: 101)") {
                let program = rest.split([' ', '`']).next().unwrap_or(rest);
                let binary = binary_stem_from_path(program);
                unitemized_failures.insert(format!("crash:{binary}"));
            }
        } else if let Some(rest) = trimmed.strip_prefix("error: could not compile `") {
            let krate = rest.split('`').next().unwrap_or(rest);
            unitemized_failures.insert(format!("compile:{krate}"));
        }

        if let Some((_, rest)) = line.split_once("test-signed: FAIL ")
            && let Some(exe) = rest.split_whitespace().next()
        {
            let fail_bin = binary_stem_from_path(exe);
            let explained = current_binary == fail_bin
                && current_run_saw_result
                && current_run_failed_result
                && current_run_itemized_count > 0;
            if !explained {
                unitemized_failures.insert(format!("crash:{fail_bin}"));
                if current_binary != fail_bin || !current_run_saw_result {
                    unfinished_binaries.insert(fail_bin.clone());
                }
            }
            if current_binary == fail_bin {
                current_binary.clear();
                in_failures_block = false;
                pending_failures.clear();
            }
            continue;
        }

        if trimmed == "failures:" {
            in_failures_block = true;
            pending_failures.clear();
            continue;
        }

        if let Some((_, rest)) = line.split_once("test result:") {
            let rest_trimmed = rest.trim_start();
            if trimmed.starts_with("test result:")
                || rest_trimmed.starts_with("ok.")
                || rest_trimmed.starts_with("FAILED.")
            {
                if in_failures_block {
                    for name in pending_failures.drain(..) {
                        failed_tests.insert(qualify_test(&current_binary, &name));
                        current_run_itemized_count += 1;
                    }
                    in_failures_block = false;
                }
                current_run_saw_result = true;
                if !current_binary.is_empty() {
                    finished_binaries.insert(current_binary.clone());
                }
                if rest_trimmed.starts_with("FAILED") {
                    saw_failed_result = true;
                    current_run_failed_result = true;
                    if current_run_itemized_count == 0 {
                        let tag = if current_binary.is_empty() {
                            "empty-itemization"
                        } else {
                            &current_binary
                        };
                        unitemized_failures.insert(format!("parse-error:{tag}"));
                    }
                }
                continue;
            }
        }

        if in_failures_block {
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("----") {
                in_failures_block = false;
                pending_failures.clear();
            } else if is_valid_test_name(trimmed) {
                pending_failures.push(trimmed.to_string());
            }
        }
    }

    if !current_binary.is_empty() && !current_run_saw_result {
        unfinished_binaries.insert(current_binary);
    }
    if saw_failed_result
        && failed_tests.is_empty()
        && !unitemized_failures
            .iter()
            .any(|u| u.starts_with("parse-error:"))
    {
        unitemized_failures.insert("parse-error:empty-itemization".to_string());
    }

    ParsedTestLog {
        failed_tests: failed_tests.into_iter().collect(),
        unitemized_failures: unitemized_failures.into_iter().collect(),
        started_tests: started_tests.into_iter().collect(),
        finished_binaries: finished_binaries.into_iter().collect(),
        unfinished_binaries: unfinished_binaries.into_iter().collect(),
        saw_failed_result,
    }
}

/// Every failed test from `test <name> ... FAILED` lines and libtest's
/// end-of-binary `failures:` summary blocks, qualified by the test binary
/// announced in `Running ...` or `test-signed: running <exe>`.
pub fn parse_failed_tests(log: &str) -> Vec<String> {
    parse_test_log(log).failed_tests
}

/// Failures in a step's log that no itemized test failure explains: a test
/// binary that crashed or exited non-zero without itemized `test result: FAILED`
/// (`process didn't exit successfully` or `test-signed: FAIL <exe>`), compile
/// errors, and `test result: FAILED` lines with empty itemization.
pub fn parse_unitemized_failures(log: &str) -> Vec<String> {
    parse_test_log(log).unitemized_failures
}

/// The failure text `cleanup_remaining` records for an unproven reap.
pub const CLEANUP_UNKNOWN: &str = "scoped cleanup failed or reported no remaining count";

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
    let mut failures: Vec<String> = parse_test_log(log)
        .failed_tests
        .into_iter()
        .map(|name| name.rsplit("::").next().unwrap_or(&name).to_string())
        .collect();
    failures.sort();
    failures.dedup();
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

/// Evaluate the `el1-embed` step log and exit code against `allowlist`.
/// A non-zero exit passes ONLY when every failure is itemized AND allowlisted
/// AND every started binary finished with a `test result:` summary line.
pub fn evaluate_el1_step(
    exit_code: Option<i32>,
    log_content: &str,
    allowlist: &[String],
) -> (El1Comparison, bool, Option<String>) {
    let parsed = parse_test_log(log_content);
    let actual_failures = parse_el1_failures(log_content);
    let comparison = compare_el1_failures(&actual_failures, allowlist);

    let mut reasons = Vec::new();
    if !comparison.unexpected_failures.is_empty() {
        reasons.push(format!(
            "el1 unexpected failures: {}",
            comparison.unexpected_failures.join(", ")
        ));
    }
    if parsed.saw_failed_result && parsed.failed_tests.is_empty() {
        reasons.push("el1 parse error: test result: FAILED with empty itemization".to_string());
    }
    if !parsed.unitemized_failures.is_empty() {
        reasons.push(format!(
            "el1 unitemized failures: {}",
            parsed.unitemized_failures.join(", ")
        ));
    }
    if !parsed.unfinished_binaries.is_empty() {
        reasons.push(format!(
            "el1 unfinished binaries: {}",
            parsed.unfinished_binaries.join(", ")
        ));
    }
    if exit_code != Some(0)
        && reasons.is_empty()
        && (parsed.failed_tests.is_empty() || parsed.finished_binaries.is_empty())
    {
        reasons.push(format!(
            "el1 step crashed before executing tests (exit code {})",
            exit_code.unwrap_or(-1)
        ));
    }

    if reasons.is_empty() {
        (comparison, true, None)
    } else {
        (comparison, false, Some(reasons.join("; ")))
    }
}

/// Populate `step` from its log and fail closed if the log contains
/// `test result: FAILED` with empty itemization or unitemized/unfinished
/// binary failures.
pub fn populate_step_from_log(step: &mut StepResult, log: &str, failures: &mut Vec<String>) {
    let parsed = parse_test_log(log);
    step.failed_tests = parsed.failed_tests;
    step.unitemized_failures = parsed.unitemized_failures;
    step.started_tests = parsed.started_tests;
    step.finished_binaries = parsed.finished_binaries;
    step.unfinished_binaries = parsed.unfinished_binaries;
    if !step.passed
        && step.exit_code.is_none()
        && !step.unitemized_failures.iter().any(|u| u == "signal")
    {
        step.unitemized_failures.push("signal".into());
    }
    let has_parse_error = (parsed.saw_failed_result && step.failed_tests.is_empty())
        || step
            .unitemized_failures
            .iter()
            .any(|u| u.starts_with("parse-error:"));
    if has_parse_error {
        let msg = format!(
            "step '{}' parse error: test result: FAILED present with empty itemization",
            step.name
        );
        step.passed = false;
        if step.error.is_none() {
            step.error = Some(msg.clone());
        }
        if !failures.iter().any(|f| f.contains("empty itemization")) {
            failures.push(msg);
        }
    } else if step.passed
        && (!step.unitemized_failures.is_empty() || !step.unfinished_binaries.is_empty())
    {
        let mut details = step.unitemized_failures.clone();
        for bin in &step.unfinished_binaries {
            details.push(format!("unfinished:{bin}"));
        }
        let msg = format!(
            "step '{}' had unitemized or unfinished failures: {}",
            step.name,
            details.join(", ")
        );
        step.passed = false;
        if step.error.is_none() {
            step.error = Some(msg.clone());
        }
        failures.push(msg);
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

/// Remaining process count from a scoped `kill.sh` reap. A reap that failed
/// or printed no count is itself a failure: cleanup was not proven.
pub fn cleanup_remaining(
    reap: &Result<command::CommandOutput, command::CommandError>,
    step: &str,
    failures: &mut Vec<String>,
) -> u64 {
    // kill.sh exits non-zero when processes remain; its count is still on
    // stdout and must not be lost with the exit status.
    let stdout = match reap {
        Ok(out) => Some(out.stdout.as_str()),
        Err(error) => error.stdout(),
    };
    match stdout.and_then(parse_cleanup_count) {
        Some(count) => count,
        None => {
            failures.push(format!("step '{step}' {CLEANUP_UNKNOWN}"));
            0
        }
    }
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
    lease: &HostLease,
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
    lease.configure_command(&mut cmd)?;
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

/// Acceptance binds all discoverable build inputs to HEAD, including new files.
/// Focused signed tests deliberately do not use this admission check.
pub fn verify_clean_checkout(root: &Path) -> Result<(), AcceptError> {
    let status = command::run_checked(
        "git",
        [
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        Some(root),
    )
    .map_err(|error| AcceptError::Git(error.to_string()))?;
    if !check_git_status(&status.stdout).0 {
        return Err(AcceptError::Failed("acceptance requires a fully clean checkout (tracked and untracked inputs; gitignored outputs excluded)".into()));
    }
    Ok(())
}

pub fn verify_signed_fixtures(
    root: &Path,
) -> Result<crate::fixtures::ValidationReceipt, AcceptError> {
    verify_clean_checkout(root)?;
    crate::fixtures::verify_installed_receipt(root).map_err(|error| {
        AcceptError::Failed(format!(
            "signed fixture provenance: {error}; restore a bundle whose fixture input identity matches this checkout with xtask fixtures restore --manifest <path>"
        ))
    })
}

pub fn run(root_arg: Option<&Path>, mut args: AcceptArgs) -> Result<(), AcceptError> {
    args.phase = profile_phase(args.profile, args.phase)?;
    // remote-accept holds its checkout lock first. Hold the host lease across
    // host compilation/tests, signing, cleanup, and receipt publication.
    crate::host_load::check().map_err(|e| AcceptError::Failed(e.to_string()))?;
    let gate_lease =
        HostLease::acquire(HostLeaseMode::Gate).map_err(|e| AcceptError::Failed(e.to_string()))?;
    let host_load = crate::host_load::check().map_err(|e| AcceptError::Failed(e.to_string()))?;
    let repo_info =
        crate::cli::resolve_repo_info(root_arg).map_err(|e| AcceptError::Git(e.to_string()))?;
    let root = repo_info.repository_root;
    let head = repo_info.head;
    verify_clean_checkout(&root)?;

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

    let mut clean_tree = true;
    let mut failures = Vec::new();

    let mut step_results = Vec::new();
    let mut skipped_steps = Vec::new();
    let mut artifact_identity = None;
    let mut el1_summary = None;
    let mut probe_diffs = Vec::new();
    let mut cleanup_counts = Vec::new();

    if args.profile == AcceptProfile::LinuxPortable {
        skipped_steps.push("host-authority live compiler profiles macos-*, freebsd-*, netbsd-*: require their respective hosts; lint-domains runs the Linux compiler profiles and source checks here".to_string());
    }

    let linux_exceptions: Vec<LinuxHostTestException> =
        if args.profile == AcceptProfile::LinuxPortable {
            let path = root.join("scripts/linux-host-test-allowlist.json");
            let content =
                fs::read_to_string(&path).map_err(|source| AcceptError::Io { path, source })?;
            let entries: Vec<LinuxHostTestException> = serde_json::from_str(&content)?;
            if entries
                .iter()
                .any(|entry| entry.test.is_empty() || entry.reason.is_empty())
            {
                return Err(AcceptError::Failed(
                    "Linux host test exceptions must name a test and reason".to_string(),
                ));
            }
            entries
        } else {
            Vec::new()
        };

    // 1. Host Phase
    if matches!(args.phase, AcceptPhase::Host | AcceptPhase::All) {
        println!("--- Host phase starting ---");
        for step in host_steps(args.profile) {
            let log_path = run_dir.join(step.log_name);
            let display_cmd = format!("{} {}", step.program, step.args.join(" "));
            println!("  running: {display_cmd} (log: {})", log_path.display());

            let (exit_code, duration_s) = run_command_redirect(
                &gate_lease,
                step.program,
                step.args,
                step.env,
                &root,
                &log_path,
            )
            .map_err(|e| AcceptError::Io {
                path: log_path.clone(),
                source: e,
            })?;

            let passed = exit_code == Some(0);
            let error = if !passed {
                let mut msg = format!(
                    "step '{}' failed with exit code {}",
                    step.name,
                    exit_code.unwrap_or(-1)
                );
                if args.profile == AcceptProfile::LinuxPortable {
                    let log = fs::read_to_string(&log_path).unwrap_or_default();
                    let details = linux_host_failure_details(&log, &linux_exceptions);
                    if !details.is_empty() {
                        msg.push_str(&format!(": {details}"));
                    }
                }
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
                failed_tests: Vec::new(),
                unitemized_failures: Vec::new(),
                started_tests: Vec::new(),
                finished_binaries: Vec::new(),
                unfinished_binaries: Vec::new(),
            });
        }
    }

    // Fail before signing or guest execution, while preserving a FAIL receipt.
    let signed_requested = matches!(args.phase, AcceptPhase::Signed | AcceptPhase::All);
    let mut fixtures_valid = false;
    let mut fixture_validation = None;
    if signed_requested {
        if std::env::consts::OS != "macos" || std::env::consts::ARCH != "aarch64" {
            return Err(AcceptError::UnsupportedPlatform(format!(
                "{}-{} (signed phase requires macOS aarch64)",
                std::env::consts::OS,
                std::env::consts::ARCH
            )));
        }
        let start = Instant::now();
        let result = verify_signed_fixtures(&root);
        fixtures_valid = result.is_ok();
        let error = match result {
            Ok(validation) => {
                fixture_validation = Some(validation);
                None
            }
            Err(error) => Some(error.to_string()),
        };
        let log_path = run_dir.join("signed-00-fixtures.log");
        let message = if let Some(error) = &error {
            failures.push(error.clone());
            error.clone()
        } else {
            let receipt_hash =
                crate::provision::compute_sha256(&root.join(crate::fixtures::INSTALLED_MANIFEST))
                    .map_err(|source| AcceptError::Io {
                    path: root.join(crate::fixtures::INSTALLED_MANIFEST),
                    source,
                })?;
            format!(
                "all signed-tier fixture hashes verified by input_identity for {head}; installed receipt sha256={receipt_hash}"
            )
        };
        fs::write(&log_path, &message).map_err(|source| AcceptError::Io {
            path: log_path.clone(),
            source,
        })?;
        println!("  fixtures: {message}");
        step_results.push(StepResult {
            name: "fixtures".into(),
            command: "xtask fixtures verify".into(),
            exit_code: Some(if fixtures_valid { 0 } else { 1 }),
            log_path,
            duration_s: start.elapsed().as_secs_f64(),
            passed: fixtures_valid,
            error,
            failed_tests: Vec::new(),
            unitemized_failures: Vec::new(),
            started_tests: Vec::new(),
            finished_binaries: Vec::new(),
            unfinished_binaries: Vec::new(),
        });
    }

    // 2. Signed Phase
    if signed_requested && fixtures_valid {
        println!("--- Signed phase starting (profile: {}) ---", args.profile);

        // Signed Step 1: just build + artifact inspection
        let mut initial_sha = String::new();
        {
            let step_name = "build";
            let run_id = format!("accept-{timestamp}-{step_name}");
            let log_path = run_dir.join("signed-01-build.log");
            let cmd_str = "just build";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let (exit_code, duration_s) = run_command_redirect(
                &gate_lease,
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

            let remaining_count = cleanup_remaining(&reap, step_name, &mut failures);
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
                failed_tests: Vec::new(),
                unitemized_failures: Vec::new(),
                started_tests: Vec::new(),
                finished_binaries: Vec::new(),
                unfinished_binaries: Vec::new(),
            });
        }

        // Signed Step 3: el1-embed (carrick-embed el1_) vs allowlist
        {
            let step_name = "el1-embed";
            let run_id = format!("accept-{timestamp}-el1");
            let log_path = run_dir.join("el1-embed.log");
            let cmd_str = "./scripts/test-signed.sh carrick-embed el1_ --nocapture";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let (exit_code, duration_s) = run_command_redirect(
                &gate_lease,
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

            let remaining_count = cleanup_remaining(&reap, step_name, &mut failures);
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
            let allowlist_path = root.join("scripts/conformance/el1-known-red.txt");
            let allowlist = load_allowlist(&allowlist_path).unwrap_or_default();

            let (comparison, passed, error) =
                evaluate_el1_step(exit_code, &log_content, &allowlist);

            if !comparison.now_passing.is_empty() {
                println!(
                    "  [NOTICE] el1 tests now passing, remove from allowlist: {}",
                    comparison.now_passing.join(", ")
                );
            }

            if let Some(msg) = &error {
                failures.push(msg.clone());
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
                failed_tests: Vec::new(),
                unitemized_failures: Vec::new(),
                started_tests: Vec::new(),
                finished_binaries: Vec::new(),
                unfinished_binaries: Vec::new(),
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

            let (exit_code, duration_s) = run_command_redirect(
                &gate_lease,
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

            let remaining_count = cleanup_remaining(&reap, step_name, &mut failures);
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
                failed_tests: Vec::new(),
                unitemized_failures: Vec::new(),
                started_tests: Vec::new(),
                finished_binaries: Vec::new(),
                unfinished_binaries: Vec::new(),
            });
        }

        // Signed Step 5: generic_probe_shard_
        {
            let step_name = "generic-probe-shards";
            let run_id = format!("accept-{timestamp}-probe-shards");
            let log_path = run_dir.join("generic-probe-shards.log");
            let cmd_str = "./scripts/test-signed.sh carrick-conformance-next generic_probe_shard_ --nocapture";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let (exit_code, duration_s) = run_command_redirect(
                &gate_lease,
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

            let remaining_count = cleanup_remaining(&reap, step_name, &mut failures);
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
                failed_tests: Vec::new(),
                unitemized_failures: Vec::new(),
                started_tests: Vec::new(),
                finished_binaries: Vec::new(),
                unfinished_binaries: Vec::new(),
            });
        }

        // Signed Step 6: case_
        {
            let step_name = "probe-cases";
            let run_id = format!("accept-{timestamp}-probe-cases");
            let log_path = run_dir.join("probe-cases.log");
            let cmd_str = "./scripts/test-signed.sh carrick-conformance-next case_ --nocapture";
            println!("  running: {cmd_str} (run_id: {run_id})");

            let (exit_code, duration_s) = run_command_redirect(
                &gate_lease,
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

            let remaining_count = cleanup_remaining(&reap, step_name, &mut failures);
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
                failed_tests: Vec::new(),
                unitemized_failures: Vec::new(),
                started_tests: Vec::new(),
                finished_binaries: Vec::new(),
                unfinished_binaries: Vec::new(),
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

                let (exit_code, duration_s) = run_command_redirect(
                    &gate_lease,
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

                let remaining_count = cleanup_remaining(&reap, step_name, &mut failures);
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
                    failed_tests: Vec::new(),
                    unitemized_failures: Vec::new(),
                    started_tests: Vec::new(),
                    finished_binaries: Vec::new(),
                    unfinished_binaries: Vec::new(),
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

                let (exit_code, duration_s) = run_command_redirect(
                    &gate_lease,
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

                let remaining_count = cleanup_remaining(&reap, step_name, &mut failures);
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
                    failed_tests: Vec::new(),
                    unitemized_failures: Vec::new(),
                    started_tests: Vec::new(),
                    finished_binaries: Vec::new(),
                    unfinished_binaries: Vec::new(),
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

                let (exit_code, duration_s) = run_command_redirect(
                    &gate_lease,
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

                let remaining_count = cleanup_remaining(&reap, &step_name, &mut failures);
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
                    failed_tests: Vec::new(),
                    unitemized_failures: Vec::new(),
                    started_tests: Vec::new(),
                    finished_binaries: Vec::new(),
                    unfinished_binaries: Vec::new(),
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

    if let Err(error) = verify_clean_checkout(&root) {
        clean_tree = false;
        failures.push(error.to_string());
    }
    // Allowlisted failures still count: baseline comparison needs the whole
    // failing set, not only what made this receipt FAIL. Populate step logs
    // before computing `overall` so parse errors and unitemized failures flip
    // the gate verdict to FAIL.
    for step in &mut step_results {
        let log = fs::read_to_string(&step.log_path).unwrap_or_default();
        populate_step_from_log(step, &log, &mut failures);
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
        fixture_validation,
        el1: el1_summary,
        probe_diffs,
        cleanup_counts,
        fixture_bundle: None,
        host_load,
        failures: failures.clone(),
    };

    if let Some(parent) = receipt_path.parent() {
        fs::create_dir_all(parent).map_err(|e| AcceptError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let json_bytes = serde_json::to_vec_pretty(&receipt)?;
    crate::atomic_file::write(&receipt_path, &json_bytes).map_err(|e| AcceptError::Io {
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
    fn linux_exceptions_are_named_and_do_not_hide_unexpected_failures() {
        let exceptions = vec![LinuxHostTestException {
            test: "net::ping".to_string(),
            reason: "host sysctl".to_string(),
        }];
        let details = linux_host_failure_details(
            "test net::ping ... FAILED\ntest fs::memfd ... FAILED\n",
            &exceptions,
        );
        assert!(details.contains("known Linux host exception net::ping: host sysctl"));
        assert!(details.contains("unallowlisted failure fs::memfd"));
    }

    #[test]
    fn linux_portable_steps_and_phase() {
        use clap::Parser;
        let parsed =
            crate::cli::Cli::try_parse_from(["xtask", "accept", "--profile", "linux-portable"]);
        assert!(parsed.is_ok(), "linux-portable must be a CLI profile");
        let steps = host_steps(AcceptProfile::LinuxPortable);
        assert_eq!(
            steps.iter().map(|s| s.name).collect::<Vec<_>>(),
            vec![
                "test-kernel",
                "portable-tests",
                "portable-tests",
                "clippy-linux",
                "fmt-check",
                "lint-domains-source",
                "host-authority-linux",
            ]
        );
        assert_eq!(
            profile_phase(AcceptProfile::LinuxPortable, AcceptPhase::All).unwrap(),
            AcceptPhase::Host
        );
        let refusal = profile_phase(AcceptProfile::LinuxPortable, AcceptPhase::Signed)
            .unwrap_err()
            .to_string();
        assert!(refusal.contains("host phase only"));
        let refusal = run(
            None,
            AcceptArgs {
                phase: AcceptPhase::Signed,
                profile: AcceptProfile::LinuxPortable,
                receipt: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("host phase only"));
        let portable = steps
            .iter()
            .find(|step| step.name == "portable-tests")
            .unwrap();
        for package in [
            "carrick-el1",
            "carrick-el1-linux",
            "carrick-el1-abi",
            "carrick-sched-core",
            "carrick-fd-core",
            "carrick-pipe-core",
            "carrick-signal-core",
            "carrick-kernel-example",
            "carrick-x86",
            "carrick-x86-cpl0-host",
        ] {
            assert!(portable.args.windows(2).any(|pair| pair == ["-p", package]));
        }
        let clippy = steps
            .iter()
            .find(|step| step.name == "clippy-linux")
            .unwrap();
        assert!(clippy.args.contains(&"--no-default-features"));
        assert!(
            clippy
                .args
                .windows(2)
                .any(|pair| pair == ["-p", "carrick-runtime"])
        );
        assert!(
            clippy
                .args
                .contains(&"carrick-cli/platform-linux,carrick-cli/syscall-shim")
        );
        assert!(clippy.args.ends_with(&["--", "-D", "warnings"]));
    }

    #[test]
    fn linux_portable_partitions_serial_host_without_losing_test_targets() {
        let steps = host_steps(AcceptProfile::LinuxPortable);
        let parallel_index = steps
            .iter()
            .position(|s| s.name == "portable-tests")
            .unwrap();
        let parallel = &steps[parallel_index];
        assert!(
            parallel.args.ends_with(&["--", "--skip", "serial_host"]),
            "parallel portable tests must exclude process-global serial_host owners"
        );
        let serial = &steps[parallel_index + 1];
        assert_eq!(
            serial.name, parallel.name,
            "retain baseline receipt identity"
        );
        assert_eq!(parallel.program, "cargo");
        assert_eq!(serial.program, parallel.program);
        assert!(serial.args.ends_with(&["--", "serial_host"]));
        assert_eq!(serial.env, &[("RUST_TEST_THREADS", "1")]);
        assert!(
            parallel.env.is_empty(),
            "ordinary tests retain harness parallelism"
        );
        let selection = &parallel.args[..parallel.args.len() - 3];
        assert_eq!(selection, &serial.args[..serial.args.len() - 2]);
        // Preserve the complete original cargo selection, including implicit
        // integration and doc targets (no --lib/--bins narrowing).
        let mut expected = vec!["test", "--no-fail-fast"];
        for package in [
            "carrick-el1",
            "carrick-el1-linux",
            "carrick-el1-abi",
            "carrick-sched-core",
            "carrick-fd-core",
            "carrick-pipe-core",
            "carrick-signal-core",
            "carrick-kernel-example",
            "carrick-x86",
            "carrick-aarch64",
            "carrick-abi",
            "carrick-guest-mem",
            "carrick-mmu-core",
            "carrick-timer-core",
            "carrick-inotify-core",
            "carrick-hal",
            "carrick-portable",
            "carrick-host-linux",
            "carrick-x86-cpl0-host",
            "carrick-signal-linux",
            "carrick-spec",
            "carrick-observability",
            "carrick-conformance-contract",
            "carrick-xtask",
        ] {
            expected.extend(["-p", package]);
        }
        assert_eq!(selection, expected);
        // Distinct argv/logs expose both passes under one receipt population.
        // The host runner visits every step even after a failed parallel pass.
        assert_ne!(parallel.log_name, serial.log_name);
        assert_eq!(
            steps
                .iter()
                .filter(|s| s.name.starts_with("portable-tests"))
                .count(),
            2
        );
        let logs = steps
            .iter()
            .map(|s| s.log_name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(logs.len(), steps.len());
    }

    #[test]
    fn linux_portable_split_preserves_baseline_population_and_failure_authority() {
        let mut baseline: AcceptReceipt = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "timestamp": "test", "head": "test",
            "clean_tree": true, "phase": "host", "profile": "linux-portable",
            "overall": "PASS", "steps": [], "failures": []
        }))
        .unwrap();
        let steps = host_steps(AcceptProfile::LinuxPortable)
            .iter()
            .filter(|s| s.name == "portable-tests")
            .collect::<Vec<_>>();
        assert_eq!(steps.len(), 2);
        let parallel_log = "Running unittests src/lib.rs (target/debug/deps/carrick_el1_linux-abcdef)\ntest ordinary ... ok\ntest result: ok. 1 passed; 0 failed\n";
        let serial_log = "Running unittests src/lib.rs (target/debug/deps/carrick_el1_linux-abcdef)\ntest serial_host_checkpoint ... ok\ntest result: ok. 1 passed; 0 failed\n";
        let result = |spec: &StepSpec, log: &str, exit_code| {
            let mut step = StepResult {
                name: spec.name.into(),
                command: format!("{} {}", spec.program, spec.args.join(" ")),
                exit_code: Some(exit_code),
                log_path: spec.log_name.into(),
                duration_s: 0.0,
                passed: exit_code == 0,
                error: None,
                failed_tests: vec![],
                unitemized_failures: vec![],
                started_tests: vec![],
                finished_binaries: vec![],
                unfinished_binaries: vec![],
            };
            populate_step_from_log(&mut step, log, &mut vec![]);
            step
        };
        // The old receipt ran both populations in one invocation.
        baseline
            .steps
            .push(result(steps[0], &format!("{parallel_log}{serial_log}"), 0));
        assert_eq!(baseline.steps[0].started_tests.len(), 2);
        let mut candidate = baseline.clone();
        candidate.steps = vec![
            result(steps[0], parallel_log, 0),
            result(steps[1], serial_log, 0),
        ];
        assert_ne!(candidate.steps[0].command, candidate.steps[1].command);
        let round_trip: AcceptReceipt =
            serde_json::from_str(&serde_json::to_string(&candidate).unwrap()).unwrap();
        assert_eq!(candidate, round_trip);
        let diff = crate::ci_receipt::diff(&baseline, &candidate).unwrap();
        assert!(diff.new.is_empty(), "{diff:?}");
        assert!(diff.fixed.is_empty(), "{diff:?}");

        candidate.steps.pop();
        let diff = crate::ci_receipt::diff(&baseline, &candidate).unwrap();
        assert_eq!(
            diff.new,
            ["missing:carrick_el1_linux::serial_host_checkpoint"]
        );
        candidate.steps.push(result(
            steps[1],
            &serial_log
                .replace("... ok", "... FAILED")
                .replace("result: ok", "result: FAILED")
                .replace("1 passed; 0 failed", "0 passed; 1 failed"),
            101,
        ));
        let diff = crate::ci_receipt::diff(&baseline, &candidate).unwrap();
        assert!(
            diff.new
                .iter()
                .any(|key| key == "test:portable-tests:carrick_el1_linux::serial_host_checkpoint"),
            "{diff:?}"
        );
        candidate.steps[1] = result(
            steps[1],
            "Running unittests src/lib.rs (target/debug/deps/carrick_el1_linux-abcdef)\ntest serial_host_checkpoint ...",
            101,
        );
        let diff = crate::ci_receipt::diff(&baseline, &candidate).unwrap();
        assert!(
            diff.new
                .iter()
                .any(|key| key.contains("unfinished:carrick_el1_linux")),
            "{diff:?}"
        );
    }

    #[test]
    fn linux_portable_applies_authority_debt_ceilings_with_live_discovery() {
        let step = host_steps(AcceptProfile::LinuxPortable)
            .iter()
            .find(|step| step.name == "host-authority-linux")
            .unwrap();
        assert_eq!(step.program, "cargo");
        assert_eq!(
            step.args,
            [
                "run",
                "--locked",
                "-p",
                "carrick-xtask",
                "--",
                "authority-debt"
            ]
        );
        // Inherit the caller's CARRICK_AUTHORITY_BASE, as lint-domains does.
        assert!(step.env.is_empty());
    }

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
    fn cleanup_count_survives_a_failing_reap_and_a_missing_count_fails() {
        let mut failures = Vec::new();
        let leaked: Result<command::CommandOutput, command::CommandError> =
            Err(command::CommandError::NonZeroExit {
                program: "scripts/sudo/kill.sh".into(),
                status: std::process::Command::new("false").status().unwrap(),
                stdout: "remaining carrick procs (run-id r) = 2\n".into(),
                stderr: String::new(),
            });
        assert_eq!(cleanup_remaining(&leaked, "build", &mut failures), 2);
        assert!(failures.is_empty());
        let silent: Result<command::CommandOutput, command::CommandError> =
            Err(command::CommandError::Spawn {
                program: "scripts/sudo/kill.sh".into(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            });
        assert_eq!(cleanup_remaining(&silent, "build", &mut failures), 0);
        assert_eq!(failures.len(), 1);
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
                failed_tests: Vec::new(),
                unitemized_failures: Vec::new(),
                started_tests: Vec::new(),
                finished_binaries: Vec::new(),
                unfinished_binaries: Vec::new(),
            }],
            skipped_steps: vec!["ltp".to_string()],
            artifact: None,
            fixture_validation: None,
            el1: None,
            probe_diffs: vec![],
            cleanup_counts: vec![],
            fixture_bundle: None,
            host_load: crate::host_load::HostLoadReport::default(),
            failures: vec![],
        };

        let json = serde_json::to_string_pretty(&receipt).expect("serialize receipt");
        let deserialized: AcceptReceipt = serde_json::from_str(&json).expect("deserialize receipt");
        assert_eq!(receipt, deserialized);
    }
}
