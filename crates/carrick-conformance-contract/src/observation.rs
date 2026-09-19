use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::evaluate::ContractFailure;
use crate::model::{ContractId, ExecutionLayer, TimingStatistic, WorkMetric};

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ContractObservation {
    pub contract_id: ContractId,
    pub layer: ExecutionLayer,
    pub implementation_revision: String,
    pub fixture_identity: String,
    pub scale: u64,
    pub semantic_assertions: Vec<SemanticAssertion>,
    pub work: Option<WorkSnapshot>,
    pub timing: Option<TimingDistribution>,
    pub completeness: Completeness,
}

impl ContractObservation {
    pub fn work_value(&self, metric: WorkMetric) -> Option<u64> {
        self.work.as_ref().and_then(|w| w.get(metric))
    }

    pub fn validate(&self) -> Result<(), ContractFailure> {
        if self.implementation_revision.trim().is_empty() {
            return Err(ContractFailure::IncompleteMeasurement {
                contract: self.contract_id.clone(),
                reason: "empty implementation revision".into(),
            });
        }
        if self.fixture_identity.trim().is_empty() {
            return Err(ContractFailure::IncompleteMeasurement {
                contract: self.contract_id.clone(),
                reason: "empty fixture identity".into(),
            });
        }

        match &self.completeness {
            Completeness::Complete => {}
            Completeness::Incomplete { reasons } => {
                return Err(ContractFailure::IncompleteMeasurement {
                    contract: self.contract_id.clone(),
                    reason: if reasons.is_empty() {
                        "incomplete observation".into()
                    } else {
                        reasons.join("; ")
                    },
                });
            }
        }

        if let Some(ref work) = self.work {
            if work.dropped_events > 0 {
                return Err(ContractFailure::IncompleteMeasurement {
                    contract: self.contract_id.clone(),
                    reason: format!("dropped events detected: {}", work.dropped_events),
                });
            }
            if !work.unknown_metrics.is_empty() {
                return Err(ContractFailure::IncompleteMeasurement {
                    contract: self.contract_id.clone(),
                    reason: format!("unknown metrics detected: {:?}", work.unknown_metrics),
                });
            }
        }

        // Layer-specific constraints:
        // Instrumented layers (VmFree, EmbedStructural) must not have timing
        if matches!(
            self.layer,
            ExecutionLayer::VmFree | ExecutionLayer::EmbedStructural
        ) && self.timing.is_some()
        {
            return Err(ContractFailure::IncompleteMeasurement {
                contract: self.contract_id.clone(),
                reason: "instrumented layer cannot supply timing evidence".into(),
            });
        }

        // Uninstrumented timing layer (EmbedTiming) must not claim structural completeness or supply work
        if self.layer == ExecutionLayer::EmbedTiming && self.work.is_some() {
            return Err(ContractFailure::IncompleteMeasurement {
                contract: self.contract_id.clone(),
                reason:
                    "uninstrumented timing layer cannot claim structural completeness or supply work"
                        .into(),
            });
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct WorkSnapshot {
    values: BTreeMap<WorkMetric, u64>,
    dropped_events: u64,
    unknown_metrics: Vec<String>,
}

impl Default for WorkSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkSnapshot {
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
            dropped_events: 0,
            unknown_metrics: Vec::new(),
        }
    }

    pub fn with_dropped_events(mut self, dropped_events: u64) -> Self {
        self.dropped_events = dropped_events;
        self
    }

    pub fn with_unknown_metrics(mut self, unknown: Vec<String>) -> Self {
        self.unknown_metrics = unknown;
        self
    }

    pub fn insert(&mut self, metric: WorkMetric, value: u64) -> Result<(), ObservationError> {
        if self.values.insert(metric, value).is_some() {
            return Err(ObservationError::DuplicateMetric(metric));
        }
        Ok(())
    }

    pub fn get(&self, metric: WorkMetric) -> Option<u64> {
        self.values.get(&metric).copied()
    }

    pub fn values(&self) -> &BTreeMap<WorkMetric, u64> {
        &self.values
    }

    pub fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    pub fn unknown_metrics(&self) -> &[String] {
        &self.unknown_metrics
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum Completeness {
    Complete,
    Incomplete { reasons: Vec<String> },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SemanticAssertion {
    pub name: String,
    pub passed: bool,
    pub detail: Option<String>,
}

impl SemanticAssertion {
    pub fn pass(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: true,
            detail: None,
        }
    }

    pub fn fail(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed: false,
            detail: Some(detail.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct TimingDistribution {
    samples: Vec<f64>,
}

impl TimingDistribution {
    pub fn new(mut samples: Vec<f64>) -> Result<Self, ObservationError> {
        if samples.is_empty() {
            return Err(ObservationError::EmptyTimingSamples);
        }
        for &sample in &samples {
            if !sample.is_finite() || sample < 0.0 {
                return Err(ObservationError::InvalidTimingSample(sample));
            }
        }
        samples.sort_by(|a, b| a.total_cmp(b));
        Ok(Self { samples })
    }

    pub fn samples(&self) -> &[f64] {
        &self.samples
    }

    pub fn p50(&self) -> f64 {
        self.percentile(0.50)
    }

    pub fn p95(&self) -> f64 {
        self.percentile(0.95)
    }

    pub fn value(&self, stat: TimingStatistic) -> f64 {
        match stat {
            TimingStatistic::P50 => self.p50(),
            TimingStatistic::P95 => self.p95(),
        }
    }

    fn percentile(&self, p: f64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let len = self.samples.len();
        if len == 1 {
            return self.samples[0];
        }
        let rank = ((len as f64 - 1.0) * p).round() as usize;
        self.samples[rank.min(len - 1)]
    }
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum ObservationError {
    #[error("empty implementation revision")]
    EmptyRevision,
    #[error("empty fixture identity")]
    EmptyFixture,
    #[error("empty timing samples")]
    EmptyTimingSamples,
    #[error("invalid timing sample {0}")]
    InvalidTimingSample(f64),
    #[error("duplicate metric {0:?}")]
    DuplicateMetric(WorkMetric),
    #[error("arithmetic overflow in metric calculation")]
    ArithmeticOverflow,
}
