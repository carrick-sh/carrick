use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::record::SelectedFailure;
use crate::stage::InvestigationError;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntakeCandidate {
    pub failure: SelectedFailure,
    pub severity: IntakeSeverity,
    pub ratio: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntakeSeverity {
    SemanticRegression,
    CarrickCrash,
    BlockedHang,
    SpinningLivelock,
    HighRatioPathology,
    Other,
}

#[derive(Deserialize)]
struct RawSuiteReport {
    name: String,
    #[serde(default)]
    verdict: serde_json::Value,
    #[serde(default)]
    gating: bool,
    #[serde(default)]
    carrick: Option<RawSideSummary>,
    #[serde(default)]
    docker: Option<RawSideSummary>,
    #[serde(default)]
    carrick_run_id: String,
    #[serde(default)]
    new_diffs: Vec<String>,
    #[serde(default)]
    perf: Option<RawPerfSummary>,
    #[serde(default)]
    timeout_kind: Option<String>,
}

#[derive(Deserialize)]
struct RawSideSummary {
    #[serde(default)]
    result: String,
}

#[derive(Deserialize)]
struct RawPerfSummary {
    carrick_to_oracle_ratio: Option<f64>,
}

pub fn scan_results(path: &Path) -> Result<Vec<IntakeCandidate>, InvestigationError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut candidates = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let report: RawSuiteReport = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let verdict_str = report
            .verdict
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();

        let ratio = report.perf.and_then(|p| p.carrick_to_oracle_ratio);

        let severity = if verdict_str == "regression" {
            Some(IntakeSeverity::SemanticRegression)
        } else if verdict_str == "carrick_crash" || verdict_str == "carrickcrash" {
            Some(IntakeSeverity::CarrickCrash)
        } else if verdict_str == "timeout" {
            if report.timeout_kind.as_deref() == Some("blocked") {
                Some(IntakeSeverity::BlockedHang)
            } else if report.timeout_kind.as_deref() == Some("spinning") {
                Some(IntakeSeverity::SpinningLivelock)
            } else {
                Some(IntakeSeverity::Other)
            }
        } else if verdict_str == "diff" {
            let carrick_failed = report
                .carrick
                .as_ref()
                .map(|c| c.result == "failure")
                .unwrap_or(false);
            let docker_succeeded = report
                .docker
                .as_ref()
                .map(|d| d.result == "success")
                .unwrap_or(false);
            if carrick_failed && docker_succeeded {
                Some(IntakeSeverity::SemanticRegression)
            } else {
                Some(IntakeSeverity::Other)
            }
        } else if let Some(r) = ratio {
            if r >= 5.0 {
                Some(IntakeSeverity::HighRatioPathology)
            } else {
                None
            }
        } else if report.gating {
            Some(IntakeSeverity::Other)
        } else {
            None
        };

        if let Some(sev) = severity {
            let test_id = report
                .new_diffs
                .first()
                .cloned()
                .unwrap_or_else(|| report.name.clone());
            let failure = SelectedFailure {
                suite: report.name,
                test_id,
                run_id: if report.carrick_run_id.is_empty() {
                    "unknown_run_id".to_string()
                } else {
                    report.carrick_run_id
                },
                binary_sha256: "unknown_binary_sha".to_string(),
                details: format!("verdict: {verdict_str}"),
            };

            candidates.push(IntakeCandidate {
                failure,
                severity: sev,
                ratio,
            });
        }
    }

    // Sort by severity (highest priority first)
    candidates.sort_by_key(|c| c.severity);
    Ok(candidates)
}
