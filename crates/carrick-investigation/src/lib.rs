//! Durable investigation engine for contract-driven conformance investigations.

mod experiment;
mod intake;
mod persistence;
mod record;
mod review;
mod stage;

pub use experiment::{ExperimentPlan, ExperimentResult};
pub use intake::{IntakeCandidate, IntakeSeverity, scan_results};
pub use persistence::{default_dir, load, save};
pub use record::{
    Hypothesis, Investigation, InvestigationHistoryEntry, InvestigationId, ResourceUsage,
    SelectedFailure,
};
pub use review::{Diagnosis, ProposedCorrection, ReviewPackage};
pub use stage::{InvestigationError, Stage};
