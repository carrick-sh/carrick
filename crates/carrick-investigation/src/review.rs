use carrick_conformance_contract::{ClaimId, ContractId, ExecutionLayer};

use crate::record::Hypothesis;

#[derive(Clone, Debug, PartialEq, ::serde::Serialize, ::serde::Deserialize)]
pub struct Diagnosis {
    pub root_cause: String,
    pub causal_evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, ::serde::Serialize, ::serde::Deserialize)]
pub struct ProposedCorrection {
    pub summary: String,
    pub target_components: Vec<String>,
    pub semantic_neutrality_assessment: String,
}

#[derive(Clone, Debug, PartialEq, ::serde::Serialize, ::serde::Deserialize)]
pub struct ReviewPackage {
    pub failing_contract: ContractId,
    pub failing_claim: ClaimId,
    pub linux_authority: Vec<String>,
    pub diagnosis: Diagnosis,
    pub proposed_correction: ProposedCorrection,
    pub affected_invariants: Vec<String>,
    pub validation_plan: Vec<String>,
    pub open_higher_layer_gates: Vec<ExecutionLayer>,
    pub hypotheses_considered: Vec<Hypothesis>,
}

impl ReviewPackage {
    pub fn validate(&self) -> Result<(), crate::InvestigationError> {
        let lists = [
            &self.linux_authority,
            &self.diagnosis.causal_evidence,
            &self.proposed_correction.target_components,
            &self.affected_invariants,
            &self.validation_plan,
        ];
        if lists
            .iter()
            .any(|items| items.is_empty() || items.iter().any(|v| v.trim().is_empty()))
            || [
                &self.diagnosis.root_cause,
                &self.proposed_correction.summary,
                &self.proposed_correction.semantic_neutrality_assessment,
            ]
            .iter()
            .any(|v| v.trim().is_empty())
            || self.hypotheses_considered.is_empty()
            || !self
                .hypotheses_considered
                .iter()
                .any(|h| h.tested && h.outcome.as_ref().is_some_and(|s| !s.trim().is_empty()))
        {
            return Err(crate::InvestigationError::InvalidEvidence(
                "incomplete review package".into(),
            ));
        }
        Ok(())
    }
}
