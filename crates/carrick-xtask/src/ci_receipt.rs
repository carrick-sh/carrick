//! Per-SHA trusted-runner baselines over the one `AcceptReceipt` format.
//!
//! `kernel-runtime.yml` uploads each signed-HVF and KVM receipt as the
//! artifact `receipt-<lane>-<sha>`. A merge-group run compares its receipt
//! with the nearest receipt-bearing ancestor of its base on the merge queue
//! chain and fails on any NEW failure. A missing baseline is a failure.

use crate::accept::AcceptReceipt;
use crate::ci_scaler::{KERNEL_RUNTIME_WORKFLOW, REPOSITORY};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use thiserror::Error;

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

/// Compare two receipts of the same gate. Different phases or profiles are
/// different gates; comparing them would invent NEW/FIXED entries. Any test
/// the baseline passed (started and not failed) that the candidate did not
/// start (`missing:<bin>::<test>`) or binary the baseline finished (without
/// all its base tests failing) that the candidate did not finish
/// (`unfinished:<bin>`) is added as a NEW failure key.
pub fn diff(
    baseline: &AcceptReceipt,
    candidate: &AcceptReceipt,
) -> Result<ReceiptDiff, ReceiptError> {
    if baseline.phase != candidate.phase || baseline.profile != candidate.profile {
        return Err(ReceiptError::Mismatch(format!(
            "baseline is {}/{}, candidate is {}/{}; receipts of different gates are not comparable",
            baseline.phase, baseline.profile, candidate.phase, candidate.profile
        )));
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
            if !base_failed.contains(test.as_str()) && !cand_started.contains(test.as_str()) {
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

/// The artifact name `kernel-runtime.yml` `changes` uploads for a SHA.
pub fn ci_class_artifact_name(sha: &str) -> String {
    format!("ci-class-{sha}")
}

/// Find the non-expired `ci-class-<sha>` artifact in a run's artifact listing.
pub fn find_ci_class_artifact(artifacts: &Value, sha: &str) -> Option<String> {
    let target = ci_class_artifact_name(sha);
    artifacts["artifacts"]
        .as_array()?
        .iter()
        .filter(|a| a["expired"] == false)
        .filter_map(|a| a["name"].as_str())
        .find(|name| *name == target || name.starts_with(&format!("{target}-")))
        .map(str::to_owned)
}

/// Verify from a downloaded `ci-class-<sha>.json` payload (`{heavy, hardware, macos}`)
/// that the trusted run was classified as a fast-path skip (`hardware == false`).
pub fn ci_class_proves_fast_path_skip(class_payload: &Value) -> bool {
    class_payload["hardware"].as_bool() == Some(false)
}

fn download_and_verify_ci_class(
    run_id: u64,
    artifact_name: &str,
    sha: &str,
    scratch_root: &Path,
) -> Result<bool, ReceiptError> {
    let dir = scratch_root.join(format!("ci-class-{run_id}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|source| ReceiptError::Io {
            path: dir.clone(),
            source,
        })?;
    }
    std::fs::create_dir_all(&dir).map_err(|source| ReceiptError::Io {
        path: dir.clone(),
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
            artifact_name,
            "--dir",
        ])
        .arg(&dir)
        .status()
        .map_err(|source| ReceiptError::Io {
            path: PathBuf::from("gh"),
            source,
        })?;
    if !status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        return Ok(false);
    }
    let primary = dir.join(format!("ci-class-{sha}.json"));
    let fallback = dir.join("ci-class.json");
    let file_path = if primary.is_file() {
        primary
    } else if fallback.is_file() {
        fallback
    } else {
        let _ = std::fs::remove_dir_all(&dir);
        return Ok(false);
    };
    let bytes = std::fs::read(&file_path).map_err(|source| ReceiptError::Io {
        path: file_path.clone(),
        source,
    })?;
    let _ = std::fs::remove_dir_all(&dir);
    let Ok(payload) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(false);
    };
    Ok(ci_class_proves_fast_path_skip(&payload))
}

/// One query round: this workflow's runs for the SHA and their artifacts.
struct BaselineObservation {
    decision: Baseline,
    merge_group_run: bool,
    fast_path_skip: bool,
    no_runs: bool,
}

fn query_baseline(
    lane: Lane,
    sha: &str,
    scratch_root: &Path,
) -> Result<BaselineObservation, ReceiptError> {
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
    let decision = baseline_decision(&pairs, lane, sha);
    let all_succeeded = !pairs.is_empty()
        && pairs
            .iter()
            .all(|(run, _)| run["status"] == "completed" && run["conclusion"] == "success");
    let mut fast_path_skip = false;
    if decision == Baseline::Missing && all_succeeded {
        fast_path_skip = true;
        for (run, artifacts) in &pairs {
            let (Some(id), Some(class_artifact)) =
                (run["id"].as_u64(), find_ci_class_artifact(artifacts, sha))
            else {
                fast_path_skip = false;
                break;
            };
            if !download_and_verify_ci_class(id, &class_artifact, sha, scratch_root)? {
                fast_path_skip = false;
                break;
            }
        }
    }
    Ok(BaselineObservation {
        decision,
        merge_group_run: pairs.iter().any(|(run, _)| run["event"] == "merge_group"),
        fast_path_skip,
        no_runs: pairs.is_empty(),
    })
}

fn commit_first_parent(sha: &str) -> Result<Option<String>, ReceiptError> {
    let commit = gh_json(&format!("repos/{REPOSITORY}/commits/{sha}"))?;
    let Some(parents) = commit["parents"].as_array() else {
        return Err(ReceiptError::Baseline(format!(
            "commit {sha} response has no parents array"
        )));
    };
    let Some(parent) = parents.first() else {
        return Ok(None);
    };
    let parent_sha = parent["sha"]
        .as_str()
        .ok_or_else(|| ReceiptError::Baseline(format!("commit {sha} parent SHA missing")))?
        .to_ascii_lowercase();
    validate_sha(&parent_sha)?;
    Ok(Some(parent_sha))
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

const MAX_FAST_PATH_PARENTS: usize = 16;

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
    let mut fast_path_hops = 0usize;
    let (run_id, name) = loop {
        if !visited.insert(ancestor.clone()) {
            return Err(ReceiptError::Baseline(format!(
                "merge queue base chain cycles at {ancestor}"
            )));
        }
        let observation = query_baseline(lane, &ancestor, dir)?;
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
            fast_path_hops = 0;
            ancestor = base.clone();
            continue;
        }
        if observation.decision == Baseline::Missing
            && fast_path_hops < MAX_FAST_PATH_PARENTS
            && (observation.fast_path_skip || (fast_path_hops > 0 && observation.no_runs))
            && let Some(parent) = commit_first_parent(&ancestor)?
        {
            println!(
                "ancestor {ancestor} passed trusted-hardware without a {} receipt (docs/CI-only fast path); following first-parent commit {parent}",
                lane.name()
            );
            fast_path_hops += 1;
            ancestor = parent;
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
    },
}

pub fn run(args: ReceiptArgs) -> Result<(), ReceiptError> {
    match args.action {
        ReceiptAction::Diff {
            baseline,
            candidate,
            fail_on_new,
        } => {
            let base = load(&baseline)?;
            let result = diff(&base, &load(&candidate)?)?;
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
            let result = diff(&base, &candidate)?;
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
