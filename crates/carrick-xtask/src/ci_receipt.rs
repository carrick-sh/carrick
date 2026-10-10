//! Per-SHA trusted-runner baselines over the one `AcceptReceipt` format.
//!
//! `kernel-runtime.yml` uploads each signed-HVF and KVM receipt as the
//! artifact `receipt-<lane>-<sha>`. A merge-group run compares its receipt
//! with the receipt of the group's base SHA and fails on any NEW failure. A
//! missing baseline is a failure, never a skip.

use crate::accept::AcceptReceipt;
use crate::ci_scaler::{KERNEL_RUNTIME_WORKFLOW, REPOSITORY};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
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

/// The artifact name `kernel-runtime.yml` uploads for one lane and SHA.
pub fn artifact_name(lane: Lane, sha: &str) -> String {
    format!("receipt-{}-{sha}", lane.name())
}

/// Stable failure identities of one receipt. Itemized test and probe names are
/// preferred; a failed step contributes its own key only when nothing inside
/// it was itemized, so a crash is still a failure.
pub fn failure_keys(receipt: &AcceptReceipt) -> BTreeSet<String> {
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
        if !step.passed && step.failed_tests.is_empty() && probes.is_empty() {
            keys.insert(format!("step:{}", step.name));
        }
    }
    for cleanup in &receipt.cleanup_counts {
        if cleanup.remaining_count != 0 {
            keys.insert(format!("leak:{}", cleanup.step));
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptDiff {
    pub new: Vec<String>,
    pub fixed: Vec<String>,
}

/// Compare two receipts of the same gate. Different phases or profiles are
/// different gates; comparing them would invent NEW/FIXED entries.
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
    let next = failure_keys(candidate);
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
/// repository's kernel-runtime workflow on a push to main or a merge group
/// for main. A merge group's head becomes main's tip unchanged, so its receipt
/// is a receipt of that same SHA; it is also the only receipt that exists
/// for a queued entry whose base is the entry ahead of it.
pub fn trusted_baseline_run(run: &Value, sha: &str) -> bool {
    let branch = run["head_branch"].as_str().unwrap_or_default();
    run["head_sha"] == sha
        && run["path"] == KERNEL_RUNTIME_WORKFLOW
        && run["repository"]["full_name"] == REPOSITORY
        && run["head_repository"]["full_name"] == REPOSITORY
        && ((run["event"] == "push" && branch == "main")
            || (run["event"] == "merge_group" && branch.starts_with("gh-readonly-queue/main/")))
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

/// The newest unexpired receipt artifact for `sha` from a trusted baseline run.
fn find_baseline(lane: Lane, sha: &str) -> Result<Option<(u64, String)>, ReceiptError> {
    validate_sha(sha)?;
    let name = artifact_name(lane, sha);
    let listing = gh_json(&format!(
        "repos/{REPOSITORY}/actions/artifacts?name={name}&per_page=100"
    ))?;
    let artifacts = listing["artifacts"]
        .as_array()
        .ok_or_else(|| ReceiptError::Baseline("artifact listing has no artifacts".into()))?;
    let mut candidates: Vec<(u64, u64)> = artifacts
        .iter()
        .filter(|artifact| {
            artifact["name"] == name.as_str()
                && artifact["expired"] == false
                && artifact["workflow_run"]["head_sha"] == sha
        })
        .filter_map(|artifact| {
            Some((
                artifact["id"].as_u64()?,
                artifact["workflow_run"]["id"].as_u64()?,
            ))
        })
        .collect();
    candidates.sort_unstable();
    for (_, run_id) in candidates.into_iter().rev() {
        let run = gh_json(&format!("repos/{REPOSITORY}/actions/runs/{run_id}"))?;
        if trusted_baseline_run(&run, sha) {
            return Ok(Some((run_id, name)));
        }
    }
    Ok(None)
}

fn download_baseline(lane: Lane, sha: &str, dir: &Path) -> Result<PathBuf, ReceiptError> {
    let Some((run_id, name)) = find_baseline(lane, sha)? else {
        return Err(ReceiptError::Baseline(format!(
            "no baseline: no unexpired '{}' artifact from a push-to-main or merge-group run of {sha}; \
             run kernel-runtime.yml on main at that SHA (workflow_dispatch does not publish baselines) \
             or re-queue onto a base that has one",
            artifact_name(lane, sha)
        )));
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
    Ok(receipt)
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
    /// Fetch BASE-SHA's trusted receipt, diff CANDIDATE against it and fail on
    /// NEW. A missing baseline fails closed.
    Gate {
        #[arg(long, value_enum)]
        lane: Lane,
        #[arg(long)]
        base_sha: String,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long, default_value = "target/ci-receipts/baseline")]
        download_dir: PathBuf,
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
            candidate,
            download_dir,
        } => {
            let candidate = load(&candidate)?;
            let path = download_baseline(lane, &base_sha, &download_dir)?;
            let base = load(&path)?;
            if base.head != base_sha {
                return Err(ReceiptError::Baseline(format!(
                    "baseline receipt records head {} but was published for {base_sha}",
                    base.head
                )));
            }
            let result = diff(&base, &candidate)?;
            print_diff(&base_sha, &result);
            if result.new.is_empty() {
                Ok(())
            } else {
                Err(ReceiptError::New {
                    count: result.new.len(),
                    base: base_sha,
                })
            }
        }
    }
}
