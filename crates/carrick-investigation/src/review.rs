use carrick_conformance_contract::{ClaimId, ContractId, ExecutionLayer};
use serde::{Deserialize, Serialize};

use crate::record::Hypothesis;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Diagnosis {
    pub root_cause: String,
    pub causal_evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProposedCorrection {
    pub summary: String,
    pub target_components: Vec<String>,
    pub semantic_neutrality_assessment: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

    pub fn render_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# Conformance Investigation Review Package\n\n");
        md.push_str(&format!(
            "- **Failing Contract:** `{}`\n",
            self.failing_contract
        ));
        md.push_str(&format!(
            "- **Failing Claim:** `{}`\n\n",
            self.failing_claim
        ));

        md.push_str("## Linux Semantic Authority\n\n");
        for auth in &self.linux_authority {
            md.push_str(&format!("- {}\n", auth));
        }
        md.push('\n');

        md.push_str("## Diagnosis\n\n");
        md.push_str(&format!(
            "**Root Cause:** {}\n\n",
            self.diagnosis.root_cause
        ));
        md.push_str("### Causal Evidence\n\n");
        for ev in &self.diagnosis.causal_evidence {
            md.push_str(&format!("- {}\n", ev));
        }
        md.push('\n');

        md.push_str("## Proposed Correction\n\n");
        md.push_str(&format!(
            "**Summary:** {}\n\n",
            self.proposed_correction.summary
        ));
        md.push_str("**Target Components:**\n");
        for comp in &self.proposed_correction.target_components {
            md.push_str(&format!("- {}\n", comp));
        }
        md.push_str(&format!(
            "\n**Semantic Neutrality Assessment:** {}\n\n",
            self.proposed_correction.semantic_neutrality_assessment
        ));

        md.push_str("## Validation Plan\n\n");
        for step in &self.validation_plan {
            md.push_str(&format!("1. {}\n", step));
        }
        md.push('\n');

        md.push_str("## Open Higher-Layer Gates\n\n");
        for gate in &self.open_higher_layer_gates {
            md.push_str(&format!("- `{:?}`\n", gate));
        }
        md.push('\n');

        md
    }
}
