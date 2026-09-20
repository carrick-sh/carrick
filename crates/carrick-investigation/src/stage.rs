use std::path::PathBuf;

use carrick_conformance_contract::{CapabilityClass, ContractId, ExecutionLayer};
use serde::{Deserialize, Serialize};

use crate::record::ResourceUsage;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "kebab-case")]
pub enum Stage {
    Queued,
    Classified {
        contract: ContractId,
        capability: CapabilityClass,
    },
    Reducing {
        layer: ExecutionLayer,
        preserved_mechanisms: Vec<String>,
    },
    Diagnosing {
        red_evidence: Vec<String>,
        fixture_active: bool,
    },
    ReviewReady {
        review_package_path: PathBuf,
    },
    Parked {
        prior_stage: Box<Stage>,
        obstruction: String,
        consumed_budget: ResourceUsage,
        resumption_condition: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum InvestigationError {
    #[error("invalid transition from {from:?} to {to:?}: {reason}")]
    InvalidTransition {
        from: String,
        to: String,
        reason: String,
    },
    #[error("diagnosing stage requires at least one piece of meaningful red evidence")]
    MissingRedEvidence,
    #[error("diagnosing stage requires active fixture verification")]
    FixtureNotActive,
    #[error("review-ready stage requires non-empty review package path")]
    MissingReviewPackage,
    #[error("reducing stage requires at least one preserved mechanism")]
    MissingPreservedMechanisms,
    #[error("cannot resume investigation that is not parked (current stage: {0:?})")]
    NotParked(Stage),
    #[error("investigation I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("investigation serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid investigation id: {0}")]
    InvalidId(String),
}

impl Stage {
    pub fn name(&self) -> &'static str {
        match self {
            Stage::Queued => "queued",
            Stage::Classified { .. } => "classified",
            Stage::Reducing { .. } => "reducing",
            Stage::Diagnosing { .. } => "diagnosing",
            Stage::ReviewReady { .. } => "review-ready",
            Stage::Parked { .. } => "parked",
        }
    }

    pub fn validate_transition(from: &Stage, to: &Stage) -> Result<(), InvestigationError> {
        match (from, to) {
            // Queued -> Classified
            (Stage::Queued, Stage::Classified { .. }) => Ok(()),

            // Classified -> Reducing
            (
                Stage::Classified { .. },
                Stage::Reducing {
                    preserved_mechanisms,
                    ..
                },
            ) => {
                if preserved_mechanisms.is_empty() {
                    return Err(InvestigationError::MissingPreservedMechanisms);
                }
                Ok(())
            }

            // Reducing -> Diagnosing
            (
                Stage::Reducing { .. },
                Stage::Diagnosing {
                    red_evidence,
                    fixture_active,
                },
            ) => {
                if red_evidence.is_empty() {
                    return Err(InvestigationError::MissingRedEvidence);
                }
                if !fixture_active {
                    return Err(InvestigationError::FixtureNotActive);
                }
                Ok(())
            }

            // Diagnosing -> Reducing (re-reduction allowed if additional experiments warranted)
            (
                Stage::Diagnosing { .. },
                Stage::Reducing {
                    preserved_mechanisms,
                    ..
                },
            ) => {
                if preserved_mechanisms.is_empty() {
                    return Err(InvestigationError::MissingPreservedMechanisms);
                }
                Ok(())
            }

            // Diagnosing -> ReviewReady
            (
                Stage::Diagnosing { .. },
                Stage::ReviewReady {
                    review_package_path,
                },
            ) => {
                if review_package_path.as_os_str().is_empty() {
                    return Err(InvestigationError::MissingReviewPackage);
                }
                Ok(())
            }

            // Any active stage -> Parked
            (active, Stage::Parked { .. }) if !matches!(active, Stage::Parked { .. }) => Ok(()),

            (from_stage, to_stage) => Err(InvestigationError::InvalidTransition {
                from: from_stage.name().to_string(),
                to: to_stage.name().to_string(),
                reason: format!(
                    "transition from {:?} to {:?} is not permitted",
                    from_stage, to_stage
                ),
            }),
        }
    }
}
