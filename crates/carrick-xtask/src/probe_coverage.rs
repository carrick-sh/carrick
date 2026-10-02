//! Probe coverage ratchet and baseline authority.
//!
//! # Baseline Refresh Lifecycle
//! `conformance-probes/coverage-base.json` is refreshed at each landing, after
//! the landing's probes are added and blessed, as part of the landing commit.
//! The refresh is executed via `just xtask probe-coverage --refresh-base` (or
//! `cargo run -p carrick-xtask -- probe-coverage --refresh-base`).
//!
//! Refresh enforces ratchet invariants: before updating `coverage-base.json`
//! with the current HEAD and current inventory, it validates that no rows have been
//! silently removed or altered without matching entries in
//! `conformance-probes/reviewed-retirements.json`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::command::{self, CommandError};
use crate::probe_inventory::{
    InventoryError, ProbeInventoryRow, is_authorized_runner, load_inventory,
    load_inventory_from_str, read_probe_source_names, validate_source_membership,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeIdentity {
    pub class: String,
    pub runner: String,
    pub excluded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageBase {
    pub schema: String,
    pub base_head: String,
    pub probes: BTreeMap<String, ProbeIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedRetirementRecord {
    pub base_head: String,
    pub probe: String,
    #[serde(alias = "before_identity")]
    pub before: ProbeIdentity,
    #[serde(default, alias = "after_identity")]
    pub after: Option<ProbeIdentity>,
    pub rationale: String,
    #[serde(alias = "owning_work_item")]
    pub work_item: String,
    #[serde(alias = "director_review_reference")]
    pub director_review: String,
}

impl ReviewedRetirementRecord {
    pub fn validate_not_empty(&self) -> Result<(), CoverageError> {
        if self.base_head.trim().is_empty() {
            return Err(CoverageError::InvalidReviewRecord {
                probe: self.probe.clone(),
                reason: "base_head is empty".to_string(),
            });
        }
        if self.probe.trim().is_empty() {
            return Err(CoverageError::InvalidReviewRecord {
                probe: self.probe.clone(),
                reason: "probe name is empty".to_string(),
            });
        }
        if self.rationale.trim().is_empty() {
            return Err(CoverageError::InvalidReviewRecord {
                probe: self.probe.clone(),
                reason: "rationale is empty".to_string(),
            });
        }
        if self.work_item.trim().is_empty() {
            return Err(CoverageError::InvalidReviewRecord {
                probe: self.probe.clone(),
                reason: "owning work item is empty".to_string(),
            });
        }
        if self.director_review.trim().is_empty() {
            return Err(CoverageError::InvalidReviewRecord {
                probe: self.probe.clone(),
                reason: "director review reference is empty".to_string(),
            });
        }
        if self.before.class.trim().is_empty() || self.before.runner.trim().is_empty() {
            return Err(CoverageError::InvalidReviewRecord {
                probe: self.probe.clone(),
                reason: "before identity contains empty fields".to_string(),
            });
        }
        if self
            .after
            .as_ref()
            .is_some_and(|after| after.class.trim().is_empty() || after.runner.trim().is_empty())
        {
            return Err(CoverageError::InvalidReviewRecord {
                probe: self.probe.clone(),
                reason: "after identity contains empty fields".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReviewedRetirementsDoc {
    Wrapped {
        schema: String,
        records: Vec<ReviewedRetirementRecord>,
    },
    List(Vec<ReviewedRetirementRecord>),
}

impl ReviewedRetirementsDoc {
    pub fn records(&self) -> &[ReviewedRetirementRecord] {
        match self {
            Self::Wrapped { records, .. } => records.as_slice(),
            Self::List(records) => records.as_slice(),
        }
    }
}

#[derive(Debug, Error)]
pub enum CoverageError {
    #[error("I/O error at '{}': {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON error at '{}': {source}", path.display())]
    JsonFile {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("inventory error: {0}")]
    Inventory(#[from] InventoryError),
    #[error("command error: {0}")]
    Command(#[from] CommandError),
    #[error(
        "unreviewed probe removal: probe '{probe}' was removed from base {base_head} without a matching review record"
    )]
    UnreviewedRemoval { probe: String, base_head: String },
    #[error(
        "unreviewed probe identity change for '{probe}' (base {base_head}): before={before:?}, after={after:?}"
    )]
    UnreviewedChange {
        probe: String,
        base_head: String,
        before: Box<ProbeIdentity>,
        after: Box<ProbeIdentity>,
    },
    #[error("invalid retirement record for probe '{probe}': {reason}")]
    InvalidReviewRecord { probe: String, reason: String },
    #[error("unauthorized runner '{runner}' for probe '{probe}'")]
    UnauthorizedRunner { probe: String, runner: String },
    #[error(
        "retirement record for '{probe}' has base_head '{record_base}', expected '{expected_base}'"
    )]
    WrongBase {
        probe: String,
        record_base: String,
        expected_base: String,
    },
    #[error("invalid probe class '{class}' for probe '{probe}'")]
    InvalidClass { probe: String, class: String },
    #[error("probe '{probe}' added to inventory but missing from sources")]
    MissingSourceForAddition { probe: String },
}

pub fn load_coverage_base(path: &Path) -> Result<CoverageBase, CoverageError> {
    let raw = std::fs::read_to_string(path).map_err(|e| CoverageError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    serde_json::from_str(&raw).map_err(|e| CoverageError::JsonFile {
        path: path.to_path_buf(),
        source: e,
    })
}

pub fn load_reviewed_retirements(path: &Path) -> Result<ReviewedRetirementsDoc, CoverageError> {
    let raw = std::fs::read_to_string(path).map_err(|e| CoverageError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    serde_json::from_str(&raw).map_err(|e| CoverageError::JsonFile {
        path: path.to_path_buf(),
        source: e,
    })
}

pub fn validate_coverage(
    base_head: &str,
    base_probes: &BTreeMap<String, ProbeIdentity>,
    current_inventory: &BTreeMap<String, ProbeInventoryRow>,
    sources: &BTreeSet<String>,
    retirements: &[ReviewedRetirementRecord],
) -> Result<(), CoverageError> {
    // 1. Validate all retirement records
    for record in retirements {
        record.validate_not_empty()?;
        if record.base_head != base_head {
            return Err(CoverageError::WrongBase {
                probe: record.probe.clone(),
                record_base: record.base_head.clone(),
                expected_base: base_head.to_string(),
            });
        }
    }

    let mut matched_records = BTreeSet::new();

    // 2. Validate all probes in base
    for (name, base_id) in base_probes {
        match current_inventory.get(name) {
            None => {
                // Removal: requires record with after == None
                let match_idx = retirements.iter().enumerate().position(|(idx, r)| {
                    !matched_records.contains(&idx)
                        && r.probe == *name
                        && r.before == *base_id
                        && r.after.is_none()
                });
                match match_idx {
                    Some(idx) => {
                        matched_records.insert(idx);
                    }
                    None => {
                        return Err(CoverageError::UnreviewedRemoval {
                            probe: name.clone(),
                            base_head: base_head.to_string(),
                        });
                    }
                }
            }
            Some(curr_row) => {
                let curr_id = ProbeIdentity {
                    class: curr_row.class.clone(),
                    runner: curr_row.runner.clone(),
                    excluded: curr_row.excluded,
                };
                if &curr_id != base_id {
                    // Identity change (exclusion, class, or runner): requires review record
                    let match_idx = retirements.iter().enumerate().position(|(idx, r)| {
                        !matched_records.contains(&idx)
                            && r.probe == *name
                            && r.before == *base_id
                            && r.after.as_ref() == Some(&curr_id)
                    });
                    match match_idx {
                        Some(idx) => {
                            matched_records.insert(idx);
                        }
                        None => {
                            return Err(CoverageError::UnreviewedChange {
                                probe: name.clone(),
                                base_head: base_head.to_string(),
                                before: Box::new(base_id.clone()),
                                after: Box::new(curr_id),
                            });
                        }
                    }
                }
            }
        }
    }

    // 3. Ensure no spurious/unmatched retirement records
    for (idx, record) in retirements.iter().enumerate() {
        if !matched_records.contains(&idx) {
            return Err(CoverageError::InvalidReviewRecord {
                probe: record.probe.clone(),
                reason: "review record does not correspond to an actual change against baseline"
                    .to_string(),
            });
        }
    }

    // 4. Validate additions: additions require valid inventory and runner authority
    for (name, row) in current_inventory {
        if !base_probes.contains_key(name) {
            if !sources.contains(name) {
                return Err(CoverageError::MissingSourceForAddition {
                    probe: name.clone(),
                });
            }
            if !is_authorized_runner(name, &row.runner) {
                return Err(CoverageError::UnauthorizedRunner {
                    probe: name.clone(),
                    runner: row.runner.clone(),
                });
            }
            if row.class != "conformance" && row.class != "performance" && row.class != "helper" {
                return Err(CoverageError::InvalidClass {
                    probe: name.clone(),
                    class: row.class.clone(),
                });
            }
        }
    }

    Ok(())
}

pub fn validate_coverage_files(
    base_path: &Path,
    retirements_path: &Path,
    current_inventory: &BTreeMap<String, ProbeInventoryRow>,
    sources: &BTreeSet<String>,
) -> Result<(), CoverageError> {
    let base = load_coverage_base(base_path)?;
    let retirements_doc = load_reviewed_retirements(retirements_path)?;
    validate_coverage(
        &base.base_head,
        &base.probes,
        current_inventory,
        sources,
        retirements_doc.records(),
    )
}

pub fn run_probe_coverage(
    root: Option<&Path>,
    base_commit: Option<&str>,
) -> Result<(), CoverageError> {
    let repo_info = crate::cli::resolve_repo_info(root).map_err(|e| match e {
        crate::cli::CliError::Io { path, source } => CoverageError::Io { path, source },
        other => CoverageError::InvalidReviewRecord {
            probe: "repo".to_string(),
            reason: other.to_string(),
        },
    })?;
    let repo_root = &repo_info.repository_root;

    let inv_path = repo_root.join("conformance-probes/probe-inventory.json");
    let current_inventory = load_inventory(&inv_path)?;

    let src_dir = repo_root.join("conformance-probes/src/bin");
    let sources = read_probe_source_names(&src_dir)?;

    let inv_names: BTreeSet<String> = current_inventory.keys().cloned().collect();
    validate_source_membership(&inv_names, &sources)?;

    let ret_path = repo_root.join("conformance-probes/reviewed-retirements.json");
    let retirements_doc = load_reviewed_retirements(&ret_path)?;

    if let Some(commit) = base_commit {
        let git_out = command::run_checked(
            "git",
            [
                "show",
                &format!("{commit}:conformance-probes/probe-inventory.json"),
            ],
            Some(repo_root),
        )?;
        let base_inventory = load_inventory_from_str(&git_out.stdout)?;
        let base_probes: BTreeMap<String, ProbeIdentity> = base_inventory
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    ProbeIdentity {
                        class: v.class,
                        runner: v.runner,
                        excluded: v.excluded,
                    },
                )
            })
            .collect();

        let head_out = command::run_checked("git", ["rev-parse", commit], Some(repo_root))?;
        let resolved_head = head_out.stdout.trim().to_string();

        validate_coverage(
            &resolved_head,
            &base_probes,
            &current_inventory,
            &sources,
            retirements_doc.records(),
        )?;
    } else {
        let base_path = repo_root.join("conformance-probes/coverage-base.json");
        validate_coverage_files(&base_path, &ret_path, &current_inventory, &sources)?;
    }

    Ok(())
}

pub fn refresh_coverage_base(root: Option<&Path>) -> Result<(), CoverageError> {
    let repo_info = crate::cli::resolve_repo_info(root).map_err(|e| match e {
        crate::cli::CliError::Io { path, source } => CoverageError::Io { path, source },
        other => CoverageError::InvalidReviewRecord {
            probe: "repo".to_string(),
            reason: other.to_string(),
        },
    })?;
    let repo_root = &repo_info.repository_root;

    let inv_path = repo_root.join("conformance-probes/probe-inventory.json");
    let current_inventory = load_inventory(&inv_path)?;

    let src_dir = repo_root.join("conformance-probes/src/bin");
    let sources = read_probe_source_names(&src_dir)?;

    let inv_names: BTreeSet<String> = current_inventory.keys().cloned().collect();
    validate_source_membership(&inv_names, &sources)?;

    let ret_path = repo_root.join("conformance-probes/reviewed-retirements.json");
    let base_path = repo_root.join("conformance-probes/coverage-base.json");

    // If an existing coverage-base.json exists, validate current inventory against it first!
    // This refuses to drop a row or alter identity unless listed in reviewed-retirements.json.
    if base_path.exists() {
        validate_coverage_files(&base_path, &ret_path, &current_inventory, &sources)?;
    }

    // Now construct the new CoverageBase using the current HEAD and current inventory.
    let head_out = command::run_checked("git", ["rev-parse", "HEAD"], Some(repo_root))?;
    let current_head = head_out.stdout.trim().to_string();

    let probes: BTreeMap<String, ProbeIdentity> = current_inventory
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                ProbeIdentity {
                    class: v.class,
                    runner: v.runner,
                    excluded: v.excluded,
                },
            )
        })
        .collect();

    let new_base = CoverageBase {
        schema: "carrick-probe-coverage-base-v1".to_string(),
        base_head: current_head,
        probes,
    };

    let mut json_bytes = serde_json::to_vec_pretty(&new_base).map_err(CoverageError::Json)?;
    json_bytes.push(b'\n');

    let temp_path = repo_root.join(format!(
        "conformance-probes/.coverage-base.json.tmp-{}",
        std::process::id()
    ));

    std::fs::write(&temp_path, &json_bytes).map_err(|e| CoverageError::Io {
        path: temp_path.clone(),
        source: e,
    })?;
    std::fs::rename(&temp_path, &base_path).map_err(|e| CoverageError::Io {
        path: base_path.clone(),
        source: e,
    })?;

    Ok(())
}
