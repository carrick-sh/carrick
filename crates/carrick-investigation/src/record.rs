use std::fmt;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::stage::{InvestigationError, Stage};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InvestigationId(String);

impl InvestigationId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvestigationError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if !valid {
            return Err(InvestigationError::InvalidId(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InvestigationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedFailure {
    pub suite: String,
    pub test_id: String,
    pub run_id: String,
    pub binary_sha256: String,
    pub details: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResourceUsage {
    pub experiments_executed: usize,
    pub elapsed_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub statement: String,
    pub tested: bool,
    pub outcome: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InvestigationHistoryEntry {
    pub timestamp: DateTime<Utc>,
    pub from_stage: String,
    pub to_stage: String,
    pub rationale: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Investigation {
    pub id: InvestigationId,
    pub stage: Stage,
    pub selected_failure: SelectedFailure,
    pub hypotheses: Vec<Hypothesis>,
    pub resource_usage: ResourceUsage,
    pub history: Vec<InvestigationHistoryEntry>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Investigation {
    pub fn new(id: InvestigationId, selected_failure: SelectedFailure) -> Self {
        let now = Utc::now();
        Self {
            id,
            stage: Stage::Queued,
            selected_failure,
            hypotheses: Vec::new(),
            resource_usage: ResourceUsage::default(),
            history: vec![InvestigationHistoryEntry {
                timestamp: now,
                from_stage: "none".to_string(),
                to_stage: "queued".to_string(),
                rationale: Some("investigation created".to_string()),
            }],
            created_at: now,
            updated_at: now,
        }
    }

    pub fn transition(&mut self, next: Stage) -> Result<(), InvestigationError> {
        Stage::validate_transition(&self.stage, &next)?;
        let now = Utc::now();
        self.history.push(InvestigationHistoryEntry {
            timestamp: now,
            from_stage: self.stage.name().to_string(),
            to_stage: next.name().to_string(),
            rationale: None,
        });
        self.stage = next;
        self.updated_at = now;
        Ok(())
    }

    pub fn park(
        &mut self,
        obstruction: String,
        resumption_condition: String,
    ) -> Result<(), InvestigationError> {
        let prior = Box::new(self.stage.clone());
        let park_stage = Stage::Parked {
            prior_stage: prior,
            obstruction,
            consumed_budget: self.resource_usage.clone(),
            resumption_condition,
        };
        self.transition(park_stage)
    }

    pub fn resume(&mut self) -> Result<(), InvestigationError> {
        match &self.stage {
            Stage::Parked { prior_stage, .. } => {
                let restored = *prior_stage.clone();
                let now = Utc::now();
                self.history.push(InvestigationHistoryEntry {
                    timestamp: now,
                    from_stage: "parked".to_string(),
                    to_stage: restored.name().to_string(),
                    rationale: Some("resumed from parked state".to_string()),
                });
                self.stage = restored;
                self.updated_at = now;
                Ok(())
            }
            other => Err(InvestigationError::NotParked(other.clone())),
        }
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), InvestigationError> {
        crate::persistence::save(self, path)
    }

    pub fn load_from_file(path: &Path) -> Result<Self, InvestigationError> {
        crate::persistence::load(path)
    }
}
