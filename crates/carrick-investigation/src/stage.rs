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
    #[error("invalid evidence: {0}")]
    InvalidEvidence(String),
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
            (Stage::Queued, Stage::Classified { capability, .. }) => {
                let text = match capability {
                    CapabilityClass::VmFreeExisting { capability } => capability,
                    CapabilityClass::VmFreeExtension {
                        capability,
                        rationale,
                    } => {
                        if rationale.trim().is_empty() {
                            return Err(InvestigationError::InvalidEvidence(
                                "missing extension rationale".into(),
                            ));
                        }
                        capability
                    }
                    CapabilityClass::RequiresGuest { rationale } => rationale,
                };
                if text.trim().is_empty() {
                    return Err(InvestigationError::InvalidEvidence(
                        "explicit capability decision required".into(),
                    ));
                }
                Ok(())
            }

            // Classified -> Reducing
            (
                Stage::Classified { capability, .. },
                Stage::Reducing {
                    preserved_mechanisms,
                    layer,
                },
            ) => {
                let vm_free = matches!(
                    capability,
                    CapabilityClass::VmFreeExisting { .. }
                        | CapabilityClass::VmFreeExtension { .. }
                );
                if vm_free != (*layer == ExecutionLayer::VmFree) {
                    return Err(InvestigationError::InvalidEvidence(
                        "reduction layer contradicts capability decision".into(),
                    ));
                }
                if preserved_mechanisms.is_empty() {
                    return Err(InvestigationError::MissingPreservedMechanisms);
                }
                Ok(())
            }

            // Reducing -> Diagnosing
            (
                Stage::Reducing { layer, .. },
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
                for path in red_evidence {
                    let receipt = crate::evidence::validate_red(std::path::Path::new(path))?;
                    if receipt.layer != *layer {
                        return Err(InvestigationError::InvalidEvidence(
                            "evidence layer mismatch".into(),
                        ));
                    }
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
                Stage::Diagnosing { red_evidence, .. },
                Stage::ReviewReady {
                    review_package_path,
                },
            ) => {
                if review_package_path.as_os_str().is_empty() {
                    return Err(InvestigationError::MissingReviewPackage);
                }
                let package: crate::ReviewPackage =
                    serde_json::from_slice(&std::fs::read(review_package_path)?)?;
                package.validate()?;
                for path in red_evidence {
                    if !package.diagnosis.causal_evidence.contains(path) {
                        return Err(InvestigationError::InvalidEvidence(
                            "review must reference every validated receipt".into(),
                        ));
                    }
                    let receipt = crate::evidence::validate_red(std::path::Path::new(path))?;
                    if receipt.contract != package.failing_contract {
                        return Err(InvestigationError::InvalidEvidence(
                            "review contract differs from red evidence".into(),
                        ));
                    }
                    let registry =
                        carrick_conformance_contract::ContractRegistry::load(&receipt.root)
                            .map_err(|e| InvestigationError::InvalidEvidence(e.to_string()))?;
                    if registry
                        .get_claim(&package.failing_claim)
                        .is_none_or(|c| c.contract != package.failing_contract)
                    {
                        return Err(InvestigationError::InvalidEvidence(
                            "review claim is not registered for this contract".into(),
                        ));
                    }
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
