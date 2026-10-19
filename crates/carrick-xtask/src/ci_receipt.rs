//! Per-SHA trusted-runner baselines over the one `AcceptReceipt` format.
//!
//! `kernel-runtime.yml` uploads each signed-HVF and KVM receipt as the
//! artifact `receipt-<lane>-<sha>-<attempt>`. Trusted pre-push code selects
//! the nearest receipted first-parent ancestor from event.before. The selected
//! baseline's own xtask grades candidate receipt data and fails on NEW.
//! Missing baselines and history/walk errors remain distinct from regressions.

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
    #[error("no baseline: {0}")]
    NoBaseline(String),
    #[error("invalid push history: {0}")]
    InvalidPushHistory(String),
    #[error("baseline walk limit: {0}")]
    BaselineWalkLimit(String),
    #[error("{0}")]
    Retired(String),
    #[error("{count} NEW failure(s) against base {base}")]
    New { count: usize, base: String },
}

/// The trusted-runner lanes that publish a per-SHA receipt.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
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
    /// Inert declarations left over after their retirement landed.
    pub warnings: Vec<String>,
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
    if !regular_path(tree_root, Path::new(RETIRED_TESTS_PATH), false)? {
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

fn source_io(path: &Path, source: std::io::Error) -> ReceiptError {
    ReceiptError::Io {
        path: path.to_path_buf(),
        source,
    }
}

// Inspect each component without following links, including directory links.
fn regular_path(root: &Path, relative: &Path, directory: bool) -> Result<bool, ReceiptError> {
    let mut path = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Ok(false);
        }
        path.push(component);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(source_io(&path, error)),
        };
        if metadata.file_type().is_symlink() {
            return Ok(false);
        }
    }
    let metadata = std::fs::symlink_metadata(&path).map_err(|e| source_io(&path, e))?;
    Ok(if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    })
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ReceiptError> {
    for entry in std::fs::read_dir(dir).map_err(|e| source_io(dir, e))? {
        let entry = entry.map_err(|e| source_io(dir, e))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|e| source_io(&path, e))?;
        if metadata.is_dir() {
            // Git internals cannot be part of an archived source tree.
            if entry.file_name() != ".git" {
                collect_rs_files(&path, out)?;
            }
        } else if metadata.is_file() && path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn candidate_crate_dirs(tree_root: &Path) -> Result<Vec<PathBuf>, ReceiptError> {
    let mut dirs = Vec::new();
    let crates_dir = tree_root.join("crates");
    if regular_path(tree_root, Path::new("crates"), true)? {
        for entry in std::fs::read_dir(&crates_dir).map_err(|e| source_io(&crates_dir, e))? {
            let entry = entry.map_err(|e| source_io(&crates_dir, e))?;
            let path = entry.path();
            if std::fs::symlink_metadata(&path)
                .map_err(|e| source_io(&path, e))?
                .is_dir()
            {
                dirs.push(path);
            }
        }
    }
    if regular_path(tree_root, Path::new("conformance-probes"), true)? {
        dirs.push(tree_root.join("conformance-probes"));
    }
    if regular_path(tree_root, Path::new("tests"), true)?
        || regular_path(tree_root, Path::new("src"), true)?
    {
        dirs.push(tree_root.to_path_buf());
    }
    Ok(dirs)
}

fn crate_manifest(crate_dir: &Path) -> Result<toml::Value, ReceiptError> {
    if !regular_path(crate_dir, Path::new("Cargo.toml"), false)? {
        return Ok(toml::Value::Table(Default::default()));
    }
    let path = crate_dir.join("Cargo.toml");
    let raw = std::fs::read_to_string(&path).map_err(|e| source_io(&path, e))?;
    toml::from_str(&raw)
        .map_err(|e| ReceiptError::Retired(format!("cannot resolve '{}': {e}", path.display())))
}

fn crate_matches_bin(
    crate_dir: &Path,
    manifest: &toml::Value,
    bin: &str,
) -> Result<bool, ReceiptError> {
    let named = |name: &str| name.replace('-', "_") == bin;
    if crate_dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(named)
        || manifest
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .is_some_and(named)
        || manifest
            .get("lib")
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .is_some_and(named)
        || ["test", "bin"].iter().any(|kind| {
            manifest
                .get(kind)
                .and_then(toml::Value::as_array)
                .is_some_and(|targets| {
                    targets.iter().any(|t| {
                        t.get("name")
                            .and_then(toml::Value::as_str)
                            .is_some_and(named)
                    })
                })
        })
    {
        return Ok(true);
    }
    for (path, directory) in [
        (format!("tests/{bin}.rs"), false),
        (format!("tests/{bin}"), true),
        (format!("src/bin/{bin}.rs"), false),
        (format!("src/bin/{bin}/main.rs"), false),
    ] {
        if regular_path(crate_dir, Path::new(&path), directory)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_target_paths(crate_dir: &Path, manifest: &toml::Value) -> Result<(), ReceiptError> {
    let targets = ["test", "bin"]
        .into_iter()
        .flat_map(|kind| {
            manifest
                .get(kind)
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .map(move |target| (kind, target))
        })
        .chain(manifest.get("lib").map(|target| ("lib", target)));
    for (kind, target) in targets {
        if let Some(path) = target.get("path").and_then(toml::Value::as_str) {
            let path = Path::new(path);
            let contained = path
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
            if !contained
                || path.extension().is_none_or(|e| e != "rs")
                || (kind == "test" && !path.starts_with("tests"))
            {
                return Err(ReceiptError::Retired(format!(
                    "cannot resolve {kind} source path '{}' in '{}'; require Rust sources inside the crate and test targets inside tests/",
                    path.display(),
                    crate_dir.display()
                )));
            }
        }
    }
    Ok(())
}

#[derive(Default)]
struct TestSourceScan {
    tests: BTreeSet<String>,
    unresolved: Option<&'static str>,
}

fn meta_has_path(meta: &syn::Meta) -> bool {
    if meta.path().is_ident("path") {
        return true;
    }
    if let syn::Meta::List(list) = meta
        && list.path.is_ident("cfg_attr")
    {
        use syn::parse::Parser;
        return syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
            .parse2(list.tokens.clone())
            .map_or(true, |nested| nested.iter().any(meta_has_path));
    }
    false
}

fn meta_is_test(meta: &syn::Meta) -> bool {
    if meta
        .path()
        .segments
        .last()
        .is_some_and(|s| s.ident == "test")
    {
        return true;
    }
    if let syn::Meta::List(list) = meta
        && list.path.is_ident("cfg_attr")
    {
        use syn::parse::Parser;
        return syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
            .parse2(list.tokens.clone())
            .is_ok_and(|nested| nested.iter().skip(1).any(meta_is_test));
    }
    false
}

impl<'ast> syn::visit::Visit<'ast> for TestSourceScan {
    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        // An imported generator can emit tests without a local macro_rules!.
        self.unresolved = Some("item macro generator");
        syn::visit::visit_item_macro(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if item.attrs.iter().any(|a| meta_is_test(&a.meta)) {
            self.tests.insert(item.sig.ident.to_string());
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if meta_has_path(&attr.meta) {
            self.unresolved = Some("#[path] module");
        }
        syn::visit::visit_attribute(self, attr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(name) = mac.path.segments.last() {
            if name.ident == "macro_rules" {
                self.unresolved = Some("macro_rules! generator");
            } else if name.ident == "include" {
                self.unresolved = Some("include! source");
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

/// Whether the owning crate contains an attributed test function with this
/// name. Absence is authoritative only if every Rust source file parses and
/// there are no unresolved source generators or out-of-tree test targets.
/// Module paths are conservatively over-approximated: a same-named test in
/// another module prevents retirement rather than excusing a missing test.
pub fn tree_has_test(tree_root: &Path, bin: &str, test_path: &str) -> Result<bool, ReceiptError> {
    use syn::visit::Visit;
    let fn_name = test_path.rsplit("::").next().unwrap_or(test_path);
    let mut scan = TestSourceScan::default();
    for crate_dir in candidate_crate_dirs(tree_root)? {
        let manifest = crate_manifest(&crate_dir)?;
        if !crate_matches_bin(&crate_dir, &manifest, bin)? {
            continue;
        }
        check_target_paths(&crate_dir, &manifest)?;
        let mut files = Vec::new();
        collect_rs_files(&crate_dir, &mut files)?;
        for file in files {
            let source = std::fs::read_to_string(&file).map_err(|e| source_io(&file, e))?;
            let syntax = syn::parse_file(&source).map_err(|e| {
                ReceiptError::Retired(format!("cannot parse '{}': {e}", file.display()))
            })?;
            scan.visit_file(&syntax);
            if let Some(reason) = scan.unresolved {
                return Err(ReceiptError::Retired(format!(
                    "cannot resolve {reason} in '{}'; retirement of {bin}::{test_path} refused",
                    file.display()
                )));
            }
        }
    }
    Ok(scan.tests.contains(fn_name))
}

fn binary_runs_in_receipt_lane(
    tree_root: &Path,
    bin: &str,
    receipt: &AcceptReceipt,
) -> Result<bool, ReceiptError> {
    let mut found = false;
    for crate_dir in candidate_crate_dirs(tree_root)? {
        let manifest = crate_manifest(&crate_dir)?;
        if !crate_matches_bin(&crate_dir, &manifest, bin)? {
            continue;
        }
        found = true;
        let declared = manifest
            .get("package")
            .and_then(|p| p.get("metadata"))
            .and_then(|m| m.get("carrick"))
            .and_then(|c| c.get("test-lanes"));
        let lane = declared.and_then(|lanes| lanes.get(bin).or_else(|| lanes.get("*")));
        let lane = lane
            .and_then(|value| {
                value
                    .as_str()
                    .or_else(|| value.get("lane").and_then(toml::Value::as_str))
            })
            .unwrap_or(crate::test_lanes::DEFAULT_LANE);
        let runs = match lane {
            "kvm" => receipt.profile == "kvm",
            "signed-hvf" | "signed-cli" => receipt.phase == "signed",
            "host" | "integration" => receipt.phase == "host" && receipt.profile != "kvm",
            "manual" => false,
            unknown => {
                return Err(ReceiptError::Retired(format!(
                    "unknown test lane '{unknown}' for {bin}"
                )));
            }
        };
        if runs {
            return Ok(true);
        }
    }
    // Unknown ownership cannot prove that a replacement belongs to another lane.
    Ok(!found)
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
    let mut warnings = Vec::new();
    for entry in retired {
        let (bin, test_path) = split_qualified_test(&entry.test, "test")?;
        if !tree_has_test(base_tree, bin, test_path)? {
            warnings.push(format!(
                "stale retired-test declaration '{}': test is already absent in base source (PR #{}); remove the entry",
                entry.test, entry.pr
            ));
            continue;
        }
        if ((has_started(baseline, bin, test_path)
            || binary_runs_in_receipt_lane(base_tree, bin, baseline)?)
            && has_failed(baseline, bin, test_path))
            || ((has_started(candidate, bin, test_path)
                || binary_runs_in_receipt_lane(candidate_tree, bin, candidate)?)
                && has_failed(candidate, bin, test_path))
        {
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
        if let Some(replaced_by) = &entry.replaced_by {
            let (repl_bin, repl_test) = split_qualified_test(replaced_by, "replaced_by")?;
            if has_failed(candidate, repl_bin, repl_test) {
                return Err(ReceiptError::Retired(format!(
                    "replacement test '{replaced_by}' for retired test '{}' failed in candidate receipt (PR #{})",
                    entry.test, entry.pr
                )));
            }
            if (has_started(baseline, bin, test_path)
                || binary_runs_in_receipt_lane(candidate_tree, repl_bin, candidate)?)
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
        warnings,
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
    for warning in &diff.warnings {
        println!("WARNING {warning}");
    }
    for key in &diff.new {
        println!("NEW   {key}");
    }
    for key in &diff.fixed {
        println!("FIXED {key}");
    }
}

/// A main push or owner dispatch of this repository's kernel-runtime workflow.
pub fn trusted_baseline_run(run: &Value, sha: &str) -> bool {
    let branch = run["head_branch"].as_str().unwrap_or_default();
    run["head_sha"] == sha
        && run["path"] == KERNEL_RUNTIME_WORKFLOW
        && run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
        && (run["event"] == "push"
            || (run["event"] == "workflow_dispatch"
                && run["actor"]["login"] == "tjfontaine"
                && run["triggering_actor"]["login"] == "tjfontaine"))
        && branch == "main"
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

fn query_baseline(lane: Lane, sha: &str) -> Result<Baseline, ReceiptError> {
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
    Ok(baseline_decision(&pairs, lane, sha))
}

/// The exact receipted ancestor and observed gaps covered by its comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaselineSelection {
    pub lane: Lane,
    pub baseline_sha: String,
    pub before_sha: String,
    pub pushed_sha: String,
    /// Oldest first; excludes both the baseline and the candidate receipt.
    pub covered_as_range: Vec<String>,
}
impl BaselineSelection {
    pub fn notice(&self) -> String {
        format!(
            "{} baseline {}; covered as a range, not individually: {}",
            self.lane.name(),
            self.baseline_sha,
            if self.covered_as_range.is_empty() {
                "none".into()
            } else {
                self.covered_as_range.join(", ")
            }
        )
    }
    pub fn markdown(&self) -> String {
        format!(
            "## {} receipt comparison\n\nSelected baseline SHA: `{}`\n\nLanded commits without their own receipt — **covered as a range, not individually**:\n\n{}\n",
            self.lane.name().to_uppercase(),
            self.baseline_sha,
            if self.covered_as_range.is_empty() {
                "None.".into()
            } else {
                self.covered_as_range
                    .iter()
                    .map(|sha| format!("- `{sha}`"))
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        )
    }
}

/// One monotonic budget for every ancestor and covered-range lookup.
#[derive(Clone, Copy)]
struct ReceiptWait {
    deadline: Instant,
    poll: Duration,
    limit: Duration,
}
impl ReceiptWait {
    fn new(limit: Duration, poll: Duration) -> Self {
        Self {
            deadline: Instant::now() + limit,
            poll: poll.max(Duration::from_secs(1)),
            limit,
        }
    }
    fn resolve(
        &self,
        lane: Lane,
        sha: &str,
        lookup: &mut impl FnMut(Lane, &str) -> Result<Baseline, ReceiptError>,
    ) -> Result<Baseline, ReceiptError> {
        loop {
            match lookup(lane, sha)? {
                Baseline::Pending if Instant::now() + self.poll <= self.deadline => {
                    println!(
                        "baseline candidate {sha} is in progress; waiting for its {} receipt",
                        lane.name()
                    );
                    std::thread::sleep(self.poll);
                }
                Baseline::Pending => {
                    return Err(ReceiptError::NoBaseline(format!(
                        "baseline commit {sha} remains in progress after the {}-minute wait budget for {}. No regression comparison was made. Seed the current main tip with an owner dispatch: `gh workflow run kernel-runtime.yml --repo {REPOSITORY} --ref main` for subsequent pushes",
                        self.limit.as_secs() / 60,
                        lane.name()
                    )));
                }
                terminal => return Ok(terminal),
            }
        }
    }
}

/// Resolve from the push event's old tip, never from HEAD^1. Receipt lookup
/// waits for Pending runs before deciding absence. The search inspects at most
/// 50 first-parent commits and shares one bounded wait across all lookups.
pub fn select_baseline(
    root: &Path,
    lane: Lane,
    before: &str,
    pushed: &str,
    lookup: impl FnMut(Lane, &str) -> Result<Baseline, ReceiptError>,
) -> Result<BaselineSelection, ReceiptError> {
    select_baseline_waiting(
        root,
        lane,
        before,
        pushed,
        lookup,
        ReceiptWait::new(Duration::from_secs(90 * 60), Duration::from_secs(60)),
    )
}
fn select_baseline_waiting(
    root: &Path,
    lane: Lane,
    before: &str,
    pushed: &str,
    mut lookup: impl FnMut(Lane, &str) -> Result<Baseline, ReceiptError>,
    wait: ReceiptWait,
) -> Result<BaselineSelection, ReceiptError> {
    for sha in [before, pushed] {
        validate_sha(sha).map_err(|e| ReceiptError::InvalidPushHistory(e.to_string()))?;
    }
    if before.bytes().all(|b| b == b'0') || before == pushed {
        return Err(ReceiptError::InvalidPushHistory("before must be a nonzero proper first-parent ancestor of the pushed SHA; force pushes are refused".into()));
    }
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-list", "--first-parent", pushed])
        .output()
        .map_err(|source| ReceiptError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(ReceiptError::InvalidPushHistory(
            "cannot read the pushed commit's first-parent history".into(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let history: Vec<&str> = text.lines().collect();
    let before_index = history.iter().position(|sha| *sha == before).filter(|n| *n > 0)
        .ok_or_else(|| ReceiptError::InvalidPushHistory(format!("before {before} is not a first-parent ancestor of {pushed}; force pushes are refused")))?;
    let mut observed = BTreeMap::new();
    let mut has_receipt = |sha: &str| -> Result<bool, ReceiptError> {
        if let Some(found) = observed.get(sha) {
            return Ok(*found);
        }
        let found = matches!(wait.resolve(lane, sha, &mut lookup)?, Baseline::Found(_, _));
        observed.insert(sha.to_owned(), found);
        Ok(found)
    };
    let candidates = &history[before_index..];
    let mut chosen = None;
    for (offset, sha) in candidates.iter().take(50).enumerate() {
        if has_receipt(sha)? {
            chosen = Some(before_index + offset);
            break;
        }
    }
    let index = match chosen {
        Some(index) => index,
        None if candidates.len() > 50 => {
            return Err(ReceiptError::BaselineWalkLimit(format!(
                "no trusted {} receipt in the first 50 commits from {before}; refusing to search farther",
                lane.name()
            )));
        }
        None => {
            return Err(ReceiptError::NoBaseline(format!(
                "no trusted {} receipt from {before} to the first-parent root. No regression comparison was made. Seed the current main tip with an owner dispatch for subsequent pushes",
                lane.name()
            )));
        }
    };
    let mut covered_as_range = Vec::new();
    for sha in history[1..index].iter().rev() {
        if !has_receipt(sha)? {
            covered_as_range.push((*sha).to_owned());
        }
    }
    Ok(BaselineSelection {
        lane,
        baseline_sha: history[index].to_owned(),
        before_sha: before.to_owned(),
        pushed_sha: pushed.to_owned(),
        covered_as_range,
    })
}

fn append_github_file(variable: &str, body: &str) -> Result<(), ReceiptError> {
    use std::io::Write;
    if let Some(path) = std::env::var_os(variable) {
        let path = PathBuf::from(path);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| ReceiptError::Io {
                path: path.clone(),
                source,
            })?;
        writeln!(file, "{body}").map_err(|source| ReceiptError::Io { path, source })?;
    }
    Ok(())
}

fn report_selection_error(error: &ReceiptError) -> Result<(), ReceiptError> {
    let title = match error {
        ReceiptError::NoBaseline(_) => "No baseline",
        ReceiptError::InvalidPushHistory(_) => "Invalid push history",
        ReceiptError::BaselineWalkLimit(_) => "Baseline walk limit",
        _ => "Baseline selection error",
    };
    println!("::error title={title}::{error}");
    append_github_file("GITHUB_STEP_SUMMARY", &format!("## {title}\n\n{error}\n"))
}

fn download_baseline(
    lane: Lane,
    sha: &str,
    dir: &Path,
    wait: Duration,
    poll: Duration,
) -> Result<(PathBuf, String), ReceiptError> {
    let (run_id, name) = match ReceiptWait::new(wait, poll).resolve(
        lane,
        sha,
        &mut query_baseline,
    )? {
        Baseline::Found(run, name) => (run, name),
        _ => {
            return Err(ReceiptError::NoBaseline(format!(
                "selected baseline commit {sha} has no trusted {} receipt. No regression comparison was made. Seed the current main tip with an owner dispatch: `gh workflow run kernel-runtime.yml --repo {REPOSITORY} --ref main`; subsequent pushes compare against that receipt.",
                lane.name()
            )));
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
    Ok((receipt, sha.to_owned()))
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
    /// Strict signed comparison including populations, with a nonzero FAIL exit.
    SignedDiff {
        #[arg(long)]
        base: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        /// Also write the complete structured comparison as JSON.
        #[arg(long)]
        json: Option<PathBuf>,
    },
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
    /// Select the nearest receipted first-parent ancestor from push event.before.
    /// Emits a notice and job summary; writes sha/reuse to GITHUB_OUTPUT.
    SelectBaseline {
        #[arg(long, value_enum)]
        lane: Lane,
        #[arg(long)]
        before_sha: String,
        #[arg(long)]
        candidate_sha: String,
        #[arg(long, default_value = ".")]
        history_dir: PathBuf,
        /// One shared upper bound for all pending ancestor receipts.
        #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u64).range(0..=90))]
        wait_minutes: u64,
        #[arg(long, default_value_t = 60)]
        poll_seconds: u64,
    },
    /// Fetch the selected BASE-SHA receipt, compare CANDIDATE and fail on NEW.
    /// The workflow runs this command from that baseline's clean checkout.
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
        ReceiptAction::SignedDiff {
            base,
            candidate,
            json,
        } => {
            let result = crate::signed_receipt::compare(&load(&base)?, &load(&candidate)?)?;
            println!("{}", result.markdown());
            if let Some(path) = json {
                let bytes =
                    serde_json::to_vec_pretty(&result).map_err(|source| ReceiptError::Parse {
                        path: path.clone(),
                        source,
                    })?;
                std::fs::write(&path, bytes).map_err(|source| ReceiptError::Io { path, source })?;
            }
            if !result.passed {
                return Err(ReceiptError::New {
                    count: result.new.len(),
                    base: result.base,
                });
            }
            Ok(())
        }
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
        ReceiptAction::SelectBaseline {
            lane,
            before_sha,
            candidate_sha,
            history_dir,
            wait_minutes,
            poll_seconds,
        } => {
            let selected = select_baseline_waiting(
                &history_dir,
                lane,
                &before_sha,
                &candidate_sha,
                query_baseline,
                ReceiptWait::new(
                    Duration::from_secs(wait_minutes * 60),
                    Duration::from_secs(poll_seconds),
                ),
            );
            match selected {
                Ok(selected) => {
                    println!("::notice title=Receipt baseline::{}", selected.notice());
                    append_github_file("GITHUB_STEP_SUMMARY", &selected.markdown())?;
                    append_github_file(
                        "GITHUB_OUTPUT",
                        &format!(
                            "sha={}\nreuse={}",
                            selected.baseline_sha,
                            selected.baseline_sha == before_sha
                        ),
                    )?;
                    Ok(())
                }
                Err(error) => {
                    report_selection_error(&error)?;
                    Err(error)
                }
            }
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
            let baseline = download_baseline(
                lane,
                &base_sha,
                &download_dir,
                Duration::from_secs(wait_minutes * 60),
                Duration::from_secs(poll_seconds.max(1)),
            );
            if let Err(error @ ReceiptError::NoBaseline(_)) = &baseline {
                let label = format!("{} receipt gate: No baseline", lane.name().to_uppercase());
                println!("::error title={label}::{error}");
                if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
                    use std::io::Write;
                    let path = PathBuf::from(path);
                    let mut summary = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                        .map_err(|source| ReceiptError::Io {
                            path: path.clone(),
                            source,
                        })?;
                    writeln!(summary, "## {label}\n\n{error}\n")
                        .map_err(|source| ReceiptError::Io { path, source })?;
                }
            }
            let (path, selected_ancestor) = baseline?;
            let base = load(&path)?;
            if base.head != selected_ancestor {
                return Err(ReceiptError::Baseline(format!(
                    "baseline receipt records head {} but was published for ancestor {selected_ancestor}",
                    base.head
                )));
            }
            println!(
                "selected baseline ancestor {selected_ancestor} (overall {}, {} recorded failure keys); comparing landed commit against its published receipt",
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
