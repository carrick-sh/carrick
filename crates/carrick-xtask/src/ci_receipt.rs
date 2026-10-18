//! Per-SHA trusted-runner baselines over the one `AcceptReceipt` format.
//!
//! `kernel-runtime.yml` uploads each signed-HVF and KVM receipt as the
//! artifact `receipt-<lane>-<sha>`. A merge-group run compares its receipt
//! with the nearest receipt-bearing ancestor of its base on the merge queue
//! chain and fails on any NEW failure. A missing baseline is a failure.

use crate::accept::AcceptReceipt;
use crate::ci_scaler::{KERNEL_RUNTIME_WORKFLOW, REPOSITORY};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Relative path to the PR-scoped retired-tests declaration file.
pub const RETIRED_TESTS_PATH: &str = ".github/retired-tests.toml";

/// One PR-scoped retired or renamed test declaration in `.github/retired-tests.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredTest {
    /// Qualified `<bin>::<test>` identity of the retired test.
    pub test: String,
    /// Why the test was retired or renamed.
    pub reason: String,
    /// Replacement `<bin>::<test>` that must start in the candidate receipt.
    #[serde(default)]
    pub replaced_by: Option<String>,
    /// PR number that retires or renames this test.
    pub pr: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiredTestsDoc {
    #[serde(default, rename = "retired")]
    retired: Vec<RetiredTest>,
}

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("I/O at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("receipt '{path}' is not an accept receipt: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("{0}")]
    Mismatch(String),
    #[error("{0}")]
    Baseline(String),
    #[error("{0}")]
    Retired(String),
    #[error("{count} NEW failure(s) against base {base}")]
    New { count: usize, base: String },
}

/// The trusted-runner lanes that publish a per-SHA receipt.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Hvf,
    Kvm,
}
impl Lane {
    fn name(self) -> &'static str {
        match self {
            Self::Hvf => "hvf",
            Self::Kvm => "kvm",
        }
    }
}

/// The artifact name `kernel-runtime.yml` uploads for one lane, SHA and run
/// attempt. The attempt keeps a re-run from colliding with an earlier upload.
pub fn artifact_name(lane: Lane, sha: &str, attempt: u32) -> String {
    format!("{}{attempt}", artifact_prefix(lane, sha))
}
fn artifact_prefix(lane: Lane, sha: &str) -> String {
    format!("receipt-{}-{sha}-", lane.name())
}
/// The newest attempt's receipt among one run's artifacts, if any.
pub fn newest_receipt(artifacts: &Value, lane: Lane, sha: &str) -> Option<(u32, String)> {
    let prefix = artifact_prefix(lane, sha);
    artifacts["artifacts"]
        .as_array()?
        .iter()
        .filter(|a| a["expired"] == false)
        .filter_map(|a| {
            let name = a["name"].as_str()?;
            let attempt = name.strip_prefix(&prefix)?.parse::<u32>().ok()?;
            Some((attempt, name.to_owned()))
        })
        .max()
}

/// The candidate receipt for a gate run at `attempt`: the newest attempt
/// `<= attempt` among the downloaded artifact directory names. "Re-run
/// failed jobs" re-runs only the gate, at an attempt with no new receipt.
pub fn pick_candidate(names: &[String], lane: Lane, sha: &str, attempt: u32) -> Option<String> {
    let prefix = artifact_prefix(lane, sha);
    names
        .iter()
        .filter_map(|name| {
            let n = name.strip_prefix(&prefix)?.parse::<u32>().ok()?;
            (n <= attempt).then_some((n, name.clone()))
        })
        .max()
        .map(|(_, name)| name)
}

fn candidate_receipt(
    dir: &Path,
    lane: Lane,
    sha: &str,
    attempt: u32,
) -> Result<PathBuf, ReceiptError> {
    let io = |source| ReceiptError::Io {
        path: dir.to_path_buf(),
        source,
    };
    let names: Vec<String> = std::fs::read_dir(dir)
        .map_err(io)?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .collect();
    let name = pick_candidate(&names, lane, sha, attempt).ok_or_else(|| {
        ReceiptError::Baseline(format!(
            "no candidate receipt {}<= {attempt}> under {}",
            artifact_prefix(lane, sha),
            dir.display()
        ))
    })?;
    Ok(dir.join(name).join("receipt.json"))
}

fn test_belongs_to_binary(qualified_test: &str, bin: &str) -> bool {
    qualified_test
        .split_once("::")
        .is_some_and(|(test_bin, _)| test_bin == bin)
}

/// Whether an unfinished or crashed binary `<bin>` in `step_name` should emit
/// `unfinished:<bin>`, `unitemized:<step>:crash:<bin>`, and the `step:<step>`
/// key derived from them when compared against `baseline`.
///
/// Without a baseline (`failure_keys`), every unfinished/crashed binary is
/// included. Against a baseline (`diff`), a crash or unfinished state in
/// `<bin>` is NEW only when the base binary finished (without all its base
/// tests failing), or had at least one passing test that the candidate now
/// fails or misses (or `<bin>` did not run in the base at all). A crash in a
/// binary whose base tests ALL failed is not a new failure.
fn binary_crash_or_unfinished_active(
    baseline: Option<&AcceptReceipt>,
    candidate: &AcceptReceipt,
    step_name: &str,
    bin: &str,
) -> bool {
    let Some(base) = baseline else {
        return true;
    };
    let base_steps: Vec<_> = base.steps.iter().filter(|s| s.name == step_name).collect();
    if base_steps.is_empty() {
        return true;
    }
    let base_started: BTreeSet<&str> = base_steps
        .iter()
        .flat_map(|s| s.started_tests.iter().map(String::as_str))
        .collect();
    let base_failed: BTreeSet<&str> = base_steps
        .iter()
        .flat_map(|s| s.failed_tests.iter().map(String::as_str))
        .collect();
    let base_finished: BTreeSet<&str> = base_steps
        .iter()
        .flat_map(|s| s.finished_binaries.iter().map(String::as_str))
        .collect();
    let base_unfinished: BTreeSet<&str> = base_steps
        .iter()
        .flat_map(|s| s.unfinished_binaries.iter().map(String::as_str))
        .collect();
    let base_crashed = base_steps.iter().any(|s| {
        s.unitemized_failures
            .iter()
            .any(|u| u.strip_prefix("crash:") == Some(bin))
    });
    if base_unfinished.contains(bin) || base_crashed {
        return true;
    }

    let base_bin_started: Vec<&str> = base_started
        .iter()
        .copied()
        .filter(|t| test_belongs_to_binary(t, bin))
        .collect();
    let base_bin_passed: Vec<&str> = base_bin_started
        .iter()
        .copied()
        .filter(|t| !base_failed.contains(*t))
        .collect();

    if !base_bin_started.is_empty() && base_bin_passed.is_empty() {
        return false;
    }
    if base_finished.contains(bin) || base_bin_started.is_empty() {
        return true;
    }

    let cand_started: BTreeSet<&str> = candidate
        .steps
        .iter()
        .filter(|s| s.name == step_name)
        .flat_map(|s| s.started_tests.iter().map(String::as_str))
        .collect();
    let cand_failed: BTreeSet<&str> = candidate
        .steps
        .iter()
        .filter(|s| s.name == step_name)
        .flat_map(|s| s.failed_tests.iter().map(String::as_str))
        .collect();
    base_bin_passed
        .iter()
        .any(|t| !cand_started.contains(*t) || cand_failed.contains(*t))
}

fn receipt_failure_keys(
    receipt: &AcceptReceipt,
    baseline: Option<&AcceptReceipt>,
) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for step in &receipt.steps {
        let probes: Vec<_> = receipt
            .probe_diffs
            .iter()
            .filter(|diff| diff.step == step.name)
            .collect();
        for test in &step.failed_tests {
            keys.insert(format!("test:{}:{test}", step.name));
        }
        for diff in &probes {
            keys.insert(format!("probe:{}:{}", step.name, diff.probe));
        }
        let mut active_unitemized = false;
        for failure in &step.unitemized_failures {
            let active = match failure.strip_prefix("crash:") {
                Some(bin) => binary_crash_or_unfinished_active(baseline, receipt, &step.name, bin),
                None => true,
            };
            if active {
                active_unitemized = true;
                keys.insert(format!("unitemized:{}:{failure}", step.name));
            }
        }
        for bin in &step.unfinished_binaries {
            if binary_crash_or_unfinished_active(baseline, receipt, &step.name, bin) {
                active_unitemized = true;
                keys.insert(format!("unfinished:{bin}"));
            }
        }
        let any_explained = !step.failed_tests.is_empty()
            || !probes.is_empty()
            || !step.unitemized_failures.is_empty()
            || !step.unfinished_binaries.is_empty();
        if (!step.passed && !any_explained) || active_unitemized {
            keys.insert(format!("step:{}", step.name));
        }
    }
    for cleanup in &receipt.cleanup_counts {
        if cleanup.remaining_count != 0 {
            keys.insert(format!("leak:{}", cleanup.step));
        }
    }
    for failure in &receipt.failures {
        if let Some(step) = failure
            .strip_suffix(&format!("' {}", crate::accept::CLEANUP_UNKNOWN))
            .and_then(|head| head.strip_prefix("step '"))
        {
            keys.insert(format!("cleanup-unknown:{step}"));
        }
    }
    if !receipt.clean_tree {
        keys.insert("dirty-checkout".into());
    }
    if receipt
        .failures
        .iter()
        .any(|failure| failure.starts_with("binary changed during the gate"))
    {
        keys.insert("binary-changed".into());
    }
    keys
}

/// Stable failure identities of one receipt: failed tests, probe diffs,
/// unfinished binaries and unitemized failures (crashes, signals, compile
/// errors, empty itemization on `test result: FAILED`) each by name. A step
/// adds its own key whenever anything in it is unitemized or unfinished, or
/// when a failed step has nothing itemized at all, so a crash or aborted
/// binary is never hidden behind a test failure the base also had.
pub fn failure_keys(receipt: &AcceptReceipt) -> BTreeSet<String> {
    receipt_failure_keys(receipt, None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptDiff {
    pub new: Vec<String>,
    pub fixed: Vec<String>,
}

/// Parse `.github/retired-tests.toml` content and validate entry syntax.
pub fn parse_retired_tests(raw: &str, path: &Path) -> Result<Vec<RetiredTest>, ReceiptError> {
    let doc: RetiredTestsDoc = toml::from_str(raw)
        .map_err(|err| ReceiptError::Retired(format!("invalid '{}': {err}", path.display())))?;
    if doc.retired.is_empty() {
        return Err(ReceiptError::Retired(format!(
            "'{}' has no [[retired]] entries; delete the file when empty",
            path.display()
        )));
    }
    validate_retired_entries(&doc.retired)?;
    Ok(doc.retired)
}

/// Load `.github/retired-tests.toml` from `tree_root`, returning an empty list
/// when the file is absent.
pub fn load_retired_tests(tree_root: &Path) -> Result<Vec<RetiredTest>, ReceiptError> {
    let path = tree_root.join(RETIRED_TESTS_PATH);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&path).map_err(|source| ReceiptError::Io {
        path: path.clone(),
        source,
    })?;
    parse_retired_tests(&raw, &path)
}

fn validate_retired_entries(retired: &[RetiredTest]) -> Result<(), ReceiptError> {
    let mut seen = BTreeSet::new();
    for entry in retired {
        let (bin, test_path) = split_qualified_test(&entry.test, "test")?;
        if !seen.insert(entry.test.as_str()) {
            return Err(ReceiptError::Retired(format!(
                "duplicate retired test declaration '{}'",
                entry.test
            )));
        }
        if entry.reason.trim().is_empty() || entry.pr == 0 {
            return Err(ReceiptError::Retired(format!(
                "retired test '{}' requires a non-empty reason and positive PR number",
                entry.test
            )));
        }
        if let Some(replaced_by) = &entry.replaced_by {
            let (repl_bin, repl_test) = split_qualified_test(replaced_by, "replaced_by")?;
            if repl_bin == bin && repl_test == test_path {
                return Err(ReceiptError::Retired(format!(
                    "retired test '{}' cannot name itself as replaced_by",
                    entry.test
                )));
            }
        }
    }
    Ok(())
}

fn split_qualified_test<'a>(
    qualified: &'a str,
    field: &str,
) -> Result<(&'a str, &'a str), ReceiptError> {
    let Some((bin, test_path)) = qualified.split_once("::") else {
        return Err(ReceiptError::Retired(format!(
            "retired-tests {field} '{qualified}' must be '<bin>::<test>'"
        )));
    };
    let identifier = |segment: &str| {
        let mut bytes = segment.bytes();
        bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    if !identifier(bin) || !test_path.split("::").all(identifier) {
        return Err(ReceiptError::Retired(format!(
            "retired-tests {field} '{qualified}' must be '<bin>::<test>' with identifier segments"
        )));
    }
    Ok((bin, test_path))
}

fn receipt_test_matches(receipt_entry: &str, bin: &str, test_path: &str) -> bool {
    receipt_entry
        .strip_prefix(bin)
        .and_then(|rest| rest.strip_prefix("::"))
        == Some(test_path)
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ReceiptError> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)
        .map_err(|source| ReceiptError::Io {
            path: dir.to_path_buf(),
            source,
        })?
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn candidate_crate_dirs(tree_root: &Path) -> Result<Vec<PathBuf>, ReceiptError> {
    let mut dirs = Vec::new();
    let crates_dir = tree_root.join("crates");
    if crates_dir.is_dir() {
        for entry in std::fs::read_dir(&crates_dir)
            .map_err(|source| ReceiptError::Io {
                path: crates_dir,
                source,
            })?
            .filter_map(Result::ok)
        {
            if entry.path().is_dir() {
                dirs.push(entry.path());
            }
        }
    }
    for extra in [
        tree_root.join("conformance-probes"),
        tree_root.to_path_buf(),
    ] {
        if extra.join("tests").is_dir() || extra.join("src").is_dir() {
            dirs.push(extra);
        }
    }
    Ok(dirs)
}

fn crate_matches_bin(crate_dir: &Path, bin: &str) -> bool {
    if crate_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name.replace('-', "_") == bin)
    {
        return true;
    }
    let Ok(raw) = std::fs::read_to_string(crate_dir.join("Cargo.toml")) else {
        return false;
    };
    let Ok(manifest) = toml::from_str::<toml::Value>(&raw) else {
        return false;
    };
    manifest
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(toml::Value::as_str)
        .is_some_and(|name| name.replace('-', "_") == bin)
        || manifest
            .get("test")
            .and_then(toml::Value::as_array)
            .is_some_and(|tests| {
                tests
                    .iter()
                    .any(|t| t.get("name").and_then(toml::Value::as_str) == Some(bin))
            })
}

fn test_target_sources_for_bin(tree_root: &Path, bin: &str) -> Result<Vec<PathBuf>, ReceiptError> {
    let mut files = Vec::new();
    for crate_dir in candidate_crate_dirs(tree_root)? {
        let tests_dir = crate_dir.join("tests");
        let direct_test = tests_dir.join(format!("{bin}.rs"));
        if direct_test.is_file() {
            files.push(direct_test);
        }
        collect_rs_files(&tests_dir.join(bin), &mut files)?;
        if crate_matches_bin(&crate_dir, bin) {
            collect_rs_files(&crate_dir.join("src"), &mut files)?;
            collect_rs_files(&tests_dir, &mut files)?;
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn token_stream_declares_fn(stream: proc_macro2::TokenStream, fn_name: &str) -> bool {
    let mut prev_was_fn = false;
    for tt in stream {
        match tt {
            proc_macro2::TokenTree::Ident(ident) => {
                if prev_was_fn && ident == fn_name {
                    return true;
                }
                prev_was_fn = ident == "fn";
            }
            proc_macro2::TokenTree::Group(group) => {
                prev_was_fn = false;
                if token_stream_declares_fn(group.stream(), fn_name) {
                    return true;
                }
            }
            _ => prev_was_fn = false,
        }
    }
    false
}

/// Whether `tree_root` declares the test function for `<bin>::<test_path>` in
/// `<bin>`'s crate test targets.
pub fn tree_has_test(tree_root: &Path, bin: &str, test_path: &str) -> Result<bool, ReceiptError> {
    let fn_name = test_path.rsplit("::").next().unwrap_or(test_path);
    for file in test_target_sources_for_bin(tree_root, bin)? {
        let source = std::fs::read_to_string(&file)
            .map_err(|source| ReceiptError::Io { path: file, source })?;
        if source.contains(fn_name)
            && source
                .parse::<proc_macro2::TokenStream>()
                .is_ok_and(|stream| token_stream_declares_fn(stream, fn_name))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn binary_runs_in_receipt_lane(tree_root: &Path, bin: &str, receipt: &AcceptReceipt) -> bool {
    let Ok(crate_dirs) = candidate_crate_dirs(tree_root) else {
        return true;
    };
    for crate_dir in crate_dirs {
        if !crate_dir.join("tests").join(format!("{bin}.rs")).is_file()
            && !crate_dir.join("tests").join(bin).is_dir()
            && !crate_matches_bin(&crate_dir, bin)
        {
            continue;
        }
        let Some(lanes) = std::fs::read_to_string(crate_dir.join("Cargo.toml"))
            .ok()
            .and_then(|raw| toml::from_str::<toml::Value>(&raw).ok())
            .and_then(|m| {
                m.get("package")?
                    .get("metadata")?
                    .get("carrick")?
                    .get("test-lanes")?
                    .as_table()
                    .cloned()
            })
        else {
            return true;
        };
        return match lanes
            .get(bin)
            .or_else(|| lanes.get("*"))
            .and_then(toml::Value::as_str)
        {
            Some("kvm") => receipt.profile == "kvm",
            Some("signed-hvf") => receipt.phase == "signed",
            _ => true,
        };
    }
    true
}

/// Compare two receipts of the same gate without retired-test declarations.
pub fn diff(
    baseline: &AcceptReceipt,
    candidate: &AcceptReceipt,
) -> Result<ReceiptDiff, ReceiptError> {
    let empty = Path::new("");
    diff_with_retired(baseline, candidate, &[], empty, empty)
}

/// Compare two receipts while validating `.github/retired-tests.toml` loaded
/// from `candidate_tree` against `base_tree` and `candidate_tree` sources.
pub fn diff_trees(
    baseline: &AcceptReceipt,
    candidate: &AcceptReceipt,
    base_tree: &Path,
    candidate_tree: &Path,
) -> Result<ReceiptDiff, ReceiptError> {
    let retired = load_retired_tests(candidate_tree)?;
    diff_with_retired(baseline, candidate, &retired, base_tree, candidate_tree)
}

/// Compare two receipts with explicit retired-test declarations verified
/// against `base_tree` and `candidate_tree`.
pub fn diff_with_retired(
    baseline: &AcceptReceipt,
    candidate: &AcceptReceipt,
    retired: &[RetiredTest],
    base_tree: &Path,
    candidate_tree: &Path,
) -> Result<ReceiptDiff, ReceiptError> {
    if baseline.phase != candidate.phase || baseline.profile != candidate.profile {
        return Err(ReceiptError::Mismatch(format!(
            "baseline is {}/{}, candidate is {}/{}; receipts of different gates are not comparable",
            baseline.phase, baseline.profile, candidate.phase, candidate.profile
        )));
    }
    validate_retired_entries(retired)?;
    let has_failed = |r: &AcceptReceipt, b: &str, t: &str| {
        r.steps
            .iter()
            .any(|s| s.failed_tests.iter().any(|e| receipt_test_matches(e, b, t)))
    };
    let has_started = |r: &AcceptReceipt, b: &str, t: &str| {
        r.steps.iter().any(|s| {
            s.started_tests
                .iter()
                .any(|e| receipt_test_matches(e, b, t))
        })
    };
    let mut verified_retired: Vec<(&str, &str)> = Vec::with_capacity(retired.len());
    for entry in retired {
        let (bin, test_path) = split_qualified_test(&entry.test, "test")?;
        if has_failed(baseline, bin, test_path) || has_failed(candidate, bin, test_path) {
            return Err(ReceiptError::Retired(format!(
                "failing test '{}' cannot be retired (PR #{})",
                entry.test, entry.pr
            )));
        }
        if tree_has_test(candidate_tree, bin, test_path)? {
            return Err(ReceiptError::Retired(format!(
                "retired test '{}' still exists in candidate source (PR #{})",
                entry.test, entry.pr
            )));
        }
        if !tree_has_test(base_tree, bin, test_path)? {
            return Err(ReceiptError::Retired(format!(
                "stale retired-test declaration '{}': test is already absent in base source (PR #{})",
                entry.test, entry.pr
            )));
        }
        if let Some(replaced_by) = &entry.replaced_by {
            let (repl_bin, repl_test) = split_qualified_test(replaced_by, "replaced_by")?;
            if has_failed(candidate, repl_bin, repl_test) {
                return Err(ReceiptError::Retired(format!(
                    "replacement test '{replaced_by}' for retired test '{}' failed in candidate receipt (PR #{})",
                    entry.test, entry.pr
                )));
            }
            if (has_started(baseline, bin, test_path)
                || binary_runs_in_receipt_lane(candidate_tree, repl_bin, candidate))
                && !has_started(candidate, repl_bin, repl_test)
            {
                return Err(ReceiptError::Retired(format!(
                    "replacement test '{replaced_by}' for retired test '{}' did not start in candidate receipt (PR #{})",
                    entry.test, entry.pr
                )));
            }
        }
        verified_retired.push((bin, test_path));
    }

    let base = failure_keys(baseline);
    let mut next = receipt_failure_keys(candidate, Some(baseline));
    for base_step in &baseline.steps {
        let base_failed: BTreeSet<&str> =
            base_step.failed_tests.iter().map(String::as_str).collect();
        let cand_started: BTreeSet<&str> = candidate
            .steps
            .iter()
            .filter(|s| s.name == base_step.name)
            .flat_map(|s| s.started_tests.iter().map(String::as_str))
            .collect();
        for test in &base_step.started_tests {
            let is_retired = verified_retired
                .iter()
                .any(|(bin, test_path)| receipt_test_matches(test, bin, test_path));
            if !base_failed.contains(test.as_str())
                && !cand_started.contains(test.as_str())
                && !is_retired
            {
                next.insert(format!("missing:{test}"));
            }
        }
        let cand_finished: BTreeSet<&str> = candidate
            .steps
            .iter()
            .filter(|s| s.name == base_step.name)
            .flat_map(|s| s.finished_binaries.iter().map(String::as_str))
            .collect();
        for bin in &base_step.finished_binaries {
            if !cand_finished.contains(bin.as_str())
                && binary_crash_or_unfinished_active(
                    Some(baseline),
                    candidate,
                    &base_step.name,
                    bin,
                )
            {
                next.insert(format!("unfinished:{bin}"));
            }
        }
    }
    Ok(ReceiptDiff {
        new: next.difference(&base).cloned().collect(),
        fixed: base.difference(&next).cloned().collect(),
    })
}

pub fn load(path: &Path) -> Result<AcceptReceipt, ReceiptError> {
    let bytes = std::fs::read(path).map_err(|source| ReceiptError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| ReceiptError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

fn print_diff(base: &str, diff: &ReceiptDiff) {
    println!(
        "receipt diff against {base}: {} NEW, {} FIXED",
        diff.new.len(),
        diff.fixed.len()
    );
    for key in &diff.new {
        println!("NEW   {key}");
    }
    for key in &diff.fixed {
        println!("FIXED {key}");
    }
}

/// A run whose receipts may stand as the baseline of their head SHA: this
/// repository's kernel-runtime workflow on a push to main, an owner dispatch
/// on main (the reseed path), or a merge group for main. A merge group's
/// head becomes main's tip unchanged, so its receipt is a receipt of that
/// same SHA; it is also the only receipt for a queued entry whose base is
/// the entry ahead of it.
pub fn trusted_baseline_run(run: &Value, sha: &str) -> bool {
    let branch = run["head_branch"].as_str().unwrap_or_default();
    run["head_sha"] == sha
        && run["path"] == KERNEL_RUNTIME_WORKFLOW
        && run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
        && (((run["event"] == "push" || run["event"] == "workflow_dispatch") && branch == "main")
            || (run["event"] == "merge_group" && branch.starts_with("gh-readonly-queue/main/")))
}

/// What the baseline search found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Baseline {
    /// Run id and artifact name of the newest receipt.
    Found(u64, String),
    /// No receipt yet, but a trusted run of the SHA is still in progress.
    Pending,
    /// No receipt, and every trusted run of the SHA has finished.
    Missing,
}

/// Decide from the trusted runs of a SHA (newest first) and each run's
/// artifact listing. The newest run with a receipt wins; within a run, the
/// newest attempt.
pub fn baseline_decision(runs: &[(Value, Value)], lane: Lane, sha: &str) -> Baseline {
    let mut trusted: Vec<&(Value, Value)> = runs
        .iter()
        .filter(|(run, _)| trusted_baseline_run(run, sha))
        .collect();
    trusted.sort_by_key(|(run, _)| std::cmp::Reverse(run["id"].as_u64().unwrap_or(0)));
    for (run, artifacts) in &trusted {
        if let (Some(id), Some((_, name))) =
            (run["id"].as_u64(), newest_receipt(artifacts, lane, sha))
        {
            return Baseline::Found(id, name);
        }
    }
    if trusted.iter().any(|(run, _)| run["status"] != "completed") {
        Baseline::Pending
    } else {
        Baseline::Missing
    }
}

fn gh_json(endpoint: &str) -> Result<Value, ReceiptError> {
    let output = Command::new("gh")
        .args(["api", "--method", "GET", endpoint])
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|source| ReceiptError::Io {
            path: PathBuf::from("gh"),
            source,
        })?;
    if !output.status.success() {
        return Err(ReceiptError::Baseline(format!(
            "gh api {endpoint} failed ({})",
            output.status
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(|source| ReceiptError::Parse {
        path: PathBuf::from(endpoint),
        source,
    })
}

fn validate_sha(sha: &str) -> Result<(), ReceiptError> {
    if sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ReceiptError::Baseline(format!(
            "'{sha}' is not a full lowercase commit SHA"
        )))
    }
}

/// One query round: this workflow's runs for the SHA and their artifacts.
struct BaselineObservation {
    decision: Baseline,
    merge_group_run: bool,
}

fn query_baseline(lane: Lane, sha: &str) -> Result<BaselineObservation, ReceiptError> {
    validate_sha(sha)?;
    let workflow = KERNEL_RUNTIME_WORKFLOW
        .rsplit('/')
        .next()
        .unwrap_or(KERNEL_RUNTIME_WORKFLOW);
    let listing = gh_json(&format!(
        "repos/{REPOSITORY}/actions/workflows/{workflow}/runs?head_sha={sha}&per_page=100"
    ))?;
    let runs = listing["workflow_runs"]
        .as_array()
        .ok_or_else(|| ReceiptError::Baseline("run listing has no workflow_runs".into()))?;
    let mut pairs = Vec::new();
    for run in runs.iter().filter(|run| trusted_baseline_run(run, sha)) {
        let Some(id) = run["id"].as_u64() else {
            continue;
        };
        let artifacts = gh_json(&format!(
            "repos/{REPOSITORY}/actions/runs/{id}/artifacts?per_page=100"
        ))?;
        pairs.push((run.clone(), artifacts));
    }
    Ok(BaselineObservation {
        decision: baseline_decision(&pairs, lane, sha),
        merge_group_run: pairs.iter().any(|(run, _)| run["event"] == "merge_group"),
    })
}

/// The queue owns the relationship between each synthetic group head and its
/// base. Commit parents do not describe this relationship.
fn queue_base_chain() -> Result<BTreeMap<String, String>, ReceiptError> {
    let query = "query { repository(owner: \"carrick-sh\", name: \"carrick\") { mergeQueue(branch: \"main\") { entries(first: 100) { pageInfo { hasNextPage } nodes { baseCommit { oid } headCommit { oid } } } } } }";
    let output = Command::new("gh")
        .args(["api", "graphql", "-f", &format!("query={query}")])
        .output()
        .map_err(|source| ReceiptError::Io {
            path: PathBuf::from("gh"),
            source,
        })?;
    let denied = [&output.stdout, &output.stderr].iter().any(|stream| {
        let message = String::from_utf8_lossy(stream).to_ascii_lowercase();
        message.contains("forbidden") || message.contains("resource not accessible")
    });
    if denied {
        return Err(ReceiptError::Baseline(
            "merge queue GraphQL lookup denied (token scope?)".into(),
        ));
    }
    if !output.status.success() {
        return Err(ReceiptError::Baseline(format!(
            "merge queue GraphQL lookup failed ({})",
            output.status
        )));
    }
    let response: Value =
        serde_json::from_slice(&output.stdout).map_err(|source| ReceiptError::Parse {
            path: PathBuf::from("merge queue GraphQL"),
            source,
        })?;
    if response.get("errors").is_some() {
        return Err(ReceiptError::Baseline("merge queue GraphQL errors".into()));
    }
    let entries = &response["data"]["repository"]["mergeQueue"]["entries"];
    if entries["pageInfo"]["hasNextPage"] != false {
        return Err(ReceiptError::Baseline(
            "merge queue listing is incomplete".into(),
        ));
    }
    let nodes = entries["nodes"]
        .as_array()
        .ok_or_else(|| ReceiptError::Baseline("merge queue entries missing".into()))?;
    let mut chain = BTreeMap::new();
    for node in nodes {
        let head = node["headCommit"]["oid"]
            .as_str()
            .ok_or_else(|| ReceiptError::Baseline("merge queue head SHA missing".into()))?
            .to_ascii_lowercase();
        let base = node["baseCommit"]["oid"]
            .as_str()
            .ok_or_else(|| ReceiptError::Baseline("merge queue base SHA missing".into()))?
            .to_ascii_lowercase();
        validate_sha(&head)?;
        validate_sha(&base)?;
        if chain.insert(head, base).is_some() {
            return Err(ReceiptError::Baseline(
                "merge queue has duplicate head SHA".into(),
            ));
        }
    }
    Ok(chain)
}

/// Seeding/reseed instructions named in every missing-baseline error.
fn reseed_hint(sha: &str) -> String {
    format!(
        "seed it with an owner dispatch on main at that SHA: \
         `gh workflow run kernel-runtime.yml --repo {REPOSITORY} --ref main` while main is {sha}, \
         then re-queue"
    )
}

fn download_baseline(
    lane: Lane,
    sha: &str,
    dir: &Path,
    wait: Duration,
    poll: Duration,
) -> Result<(PathBuf, String), ReceiptError> {
    let deadline = Instant::now() + wait;
    let mut ancestor = sha.to_owned();
    let mut chain = None;
    let mut visited = BTreeSet::new();
    let (run_id, name) = loop {
        if !visited.insert(ancestor.clone()) {
            return Err(ReceiptError::Baseline(format!(
                "merge queue base chain cycles at {ancestor}"
            )));
        }
        let observation = query_baseline(lane, &ancestor)?;
        if let Baseline::Found(run, name) = &observation.decision {
            break (*run, name.clone());
        }
        if chain.is_none() {
            chain = Some(queue_base_chain()?);
        }
        if let Some(base) = chain.as_ref().and_then(|links| links.get(&ancestor)) {
            println!(
                "ancestor {ancestor} has no published {} receipt; following merge-queue base {base}",
                lane.name()
            );
            ancestor = base.clone();
            continue;
        }
        if observation.merge_group_run {
            return Err(ReceiptError::Baseline(format!(
                "no baseline: merge-group ancestor {ancestor} has no published {} receipt and no live queue base link",
                lane.name()
            )));
        }
        match observation.decision {
            Baseline::Pending if Instant::now() + poll <= deadline => {
                println!(
                    "receipt-bearing ancestor {ancestor} run in progress; waiting for its receipt"
                );
                visited.remove(&ancestor);
                std::thread::sleep(poll);
            }
            Baseline::Pending => {
                return Err(ReceiptError::Baseline(format!(
                    "no baseline: ancestor {ancestor} did not publish a {} receipt within {} minutes; {}",
                    lane.name(),
                    wait.as_secs() / 60,
                    reseed_hint(&ancestor)
                )));
            }
            Baseline::Missing => {
                return Err(ReceiptError::Baseline(format!(
                    "no baseline: ancestor {ancestor} has no trusted {} receipt and no queue base link; {}",
                    lane.name(),
                    reseed_hint(&ancestor)
                )));
            }
            Baseline::Found(_, _) => unreachable!(),
        }
    };
    // Persistent runner workspaces: never read a previous job's download.
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|source| ReceiptError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    std::fs::create_dir_all(dir).map_err(|source| ReceiptError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    let status = Command::new("gh")
        .args([
            "run",
            "download",
            &run_id.to_string(),
            "--repo",
            REPOSITORY,
            "--name",
            &name,
            "--dir",
        ])
        .arg(dir)
        .status()
        .map_err(|source| ReceiptError::Io {
            path: PathBuf::from("gh"),
            source,
        })?;
    if !status.success() {
        return Err(ReceiptError::Baseline(format!(
            "gh run download {run_id} --name {name} failed ({status})"
        )));
    }
    let receipt = dir.join("receipt.json");
    if !receipt.is_file() {
        return Err(ReceiptError::Baseline(format!(
            "baseline artifact {name} from run {run_id} has no receipt.json"
        )));
    }
    Ok((receipt, ancestor))
}

fn git_object_exists(spec: &str) -> Result<bool, ReceiptError> {
    let status = Command::new("git")
        .args(["cat-file", "-e", spec])
        .status()
        .map_err(|source| ReceiptError::Io {
            path: PathBuf::from("git"),
            source,
        })?;
    Ok(status.success())
}

fn ensure_git_commit(sha: &str) -> Result<(), ReceiptError> {
    let commit_spec = format!("{sha}^{{commit}}");
    if git_object_exists(&commit_spec)? {
        return Ok(());
    }
    let fetch = Command::new("git")
        .args(["fetch", "--no-tags", "--depth=1", "origin", sha])
        .output()
        .map_err(|source| ReceiptError::Io {
            path: PathBuf::from("git"),
            source,
        })?;
    if !fetch.status.success() || !git_object_exists(&commit_spec)? {
        return Err(ReceiptError::Baseline(format!(
            "git fetch origin {sha} failed ({}): {}",
            fetch.status,
            String::from_utf8_lossy(&fetch.stderr).trim()
        )));
    }
    Ok(())
}

fn archive_git_tree(sha: &str) -> Result<tempfile::TempDir, ReceiptError> {
    let temp = tempfile::tempdir().map_err(|source| ReceiptError::Io {
        path: PathBuf::from("tempdir"),
        source,
    })?;
    let output = Command::new("git")
        .args(["archive", "--format=tar", sha])
        .output()
        .map_err(|source| ReceiptError::Io {
            path: PathBuf::from("git"),
            source,
        })?;
    if !output.status.success() {
        return Err(ReceiptError::Baseline(format!(
            "git archive {sha} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    tar::Archive::new(std::io::Cursor::new(output.stdout))
        .unpack(temp.path())
        .map_err(|source| ReceiptError::Io {
            path: temp.path().to_path_buf(),
            source,
        })?;
    Ok(temp)
}

fn diff_for_gate_commits(
    base: &AcceptReceipt,
    candidate: &AcceptReceipt,
    base_sha: &str,
    candidate_sha: &str,
) -> Result<ReceiptDiff, ReceiptError> {
    ensure_git_commit(candidate_sha)?;
    if !git_object_exists(&format!("{candidate_sha}:{RETIRED_TESTS_PATH}"))? {
        return diff(base, candidate);
    }
    ensure_git_commit(base_sha)?;
    let base_tree = archive_git_tree(base_sha)?;
    let candidate_tree = archive_git_tree(candidate_sha)?;
    diff_trees(base, candidate, base_tree.path(), candidate_tree.path())
}

#[derive(clap::Args, Debug)]
pub struct ReceiptArgs {
    #[command(subcommand)]
    pub action: ReceiptAction,
}

#[derive(clap::Subcommand, Debug)]
pub enum ReceiptAction {
    /// Print NEW/FIXED failures of CANDIDATE against BASELINE.
    Diff {
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        /// Optional base source tree for verifying `.github/retired-tests.toml`.
        #[arg(long)]
        base_tree: Option<PathBuf>,
        /// Optional candidate source tree for loading `.github/retired-tests.toml`.
        #[arg(long)]
        candidate_tree: Option<PathBuf>,
        /// Exit non-zero when NEW is non-empty.
        #[arg(long)]
        fail_on_new: bool,
    },
    /// Fetch the nearest published receipt on BASE-SHA's queue ancestry,
    /// diff CANDIDATE against it and fail on NEW. Wait only for an in-progress
    /// terminal ancestor run; an unresolved chain fails closed.
    Gate {
        #[arg(long, value_enum)]
        lane: Lane,
        #[arg(long)]
        base_sha: String,
        /// Directory with one `receipt-<lane>-<sha>-<attempt>` artifact
        /// directory per downloaded candidate attempt.
        #[arg(long)]
        candidate_dir: PathBuf,
        #[arg(long)]
        candidate_sha: String,
        /// The gate's own run attempt; the newest receipt attempt <= it wins.
        #[arg(long)]
        run_attempt: u32,
        #[arg(long, default_value = "target/ci-receipts/baseline")]
        download_dir: PathBuf,
        /// Upper bound on waiting for an in-progress base run's receipt.
        #[arg(long, default_value_t = 90)]
        wait_minutes: u64,
        #[arg(long, default_value_t = 60)]
        poll_seconds: u64,
        /// Optional base source tree override (otherwise unpacked from the selected ancestor SHA).
        #[arg(long)]
        base_tree: Option<PathBuf>,
        /// Optional candidate source tree override (otherwise unpacked from `--candidate-sha`).
        #[arg(long)]
        candidate_tree: Option<PathBuf>,
    },
}

pub fn run(args: ReceiptArgs) -> Result<(), ReceiptError> {
    match args.action {
        ReceiptAction::Diff {
            baseline,
            candidate,
            base_tree,
            candidate_tree,
            fail_on_new,
        } => {
            let base = load(&baseline)?;
            let cand = load(&candidate)?;
            let result = if base_tree.is_some() || candidate_tree.is_some() {
                let base_dir = base_tree.as_deref().unwrap_or_else(|| Path::new("."));
                let cand_dir = candidate_tree.as_deref().unwrap_or_else(|| Path::new("."));
                diff_trees(&base, &cand, base_dir, cand_dir)?
            } else {
                diff(&base, &cand)?
            };
            print_diff(&base.head, &result);
            if fail_on_new && !result.new.is_empty() {
                return Err(ReceiptError::New {
                    count: result.new.len(),
                    base: base.head,
                });
            }
            Ok(())
        }
        ReceiptAction::Gate {
            lane,
            base_sha,
            candidate_dir,
            candidate_sha,
            run_attempt,
            download_dir,
            wait_minutes,
            poll_seconds,
            base_tree,
            candidate_tree,
        } => {
            validate_sha(&candidate_sha)?;
            let candidate = load(&candidate_receipt(
                &candidate_dir,
                lane,
                &candidate_sha,
                run_attempt,
            )?)?;
            let (path, selected_ancestor) = download_baseline(
                lane,
                &base_sha,
                &download_dir,
                Duration::from_secs(wait_minutes * 60),
                Duration::from_secs(poll_seconds.max(1)),
            )?;
            let base = load(&path)?;
            if base.head != selected_ancestor {
                return Err(ReceiptError::Baseline(format!(
                    "baseline receipt records head {} but was published for ancestor {selected_ancestor}",
                    base.head
                )));
            }
            println!(
                "selected baseline ancestor {selected_ancestor} (overall {}, {} recorded failure keys); comparing cumulative group against its published receipt",
                base.overall,
                failure_keys(&base).len()
            );
            let result = if base_tree.is_some() || candidate_tree.is_some() {
                let base_dir = base_tree.as_deref().unwrap_or_else(|| Path::new("."));
                let cand_dir = candidate_tree.as_deref().unwrap_or_else(|| Path::new("."));
                diff_trees(&base, &candidate, base_dir, cand_dir)?
            } else {
                diff_for_gate_commits(&base, &candidate, &selected_ancestor, &candidate_sha)?
            };
            print_diff(&selected_ancestor, &result);
            if result.new.is_empty() {
                Ok(())
            } else {
                Err(ReceiptError::New {
                    count: result.new.len(),
                    base: selected_ancestor,
                })
            }
        }
    }
}
