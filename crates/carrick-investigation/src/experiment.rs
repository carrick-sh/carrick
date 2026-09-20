use carrick_conformance_contract::ExecutionLayer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExperimentPlan {
    pub question: String,
    pub discriminating_outcomes: Vec<String>,
    pub required_layer: ExecutionLayer,
    pub estimated_duration_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExperimentResult {
    pub plan: ExperimentPlan,
    pub observations: Vec<String>,
    pub inferences: Vec<String>,
    pub elapsed_seconds: u64,
    pub success: bool,
}

impl ExperimentResult {
    pub fn new(plan: ExperimentPlan, elapsed_seconds: u64) -> Self {
        Self {
            plan,
            observations: Vec::new(),
            inferences: Vec::new(),
            elapsed_seconds,
            success: false,
        }
    }

    pub fn record_observation(&mut self, obs: impl Into<String>) {
        self.observations.push(obs.into());
    }

    pub fn record_inference(&mut self, inf: impl Into<String>) {
        self.inferences.push(inf.into());
    }
}
