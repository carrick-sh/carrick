use std::collections::{BTreeMap, BTreeSet};

use carrick_abi::syscall::{Authority, SupportLevel, SyscallHandler};
use serde::{Deserialize, Serialize};

use crate::{ClaimId, ContractId, ContractRegistry, CoverageState};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyscallInventoryEntry {
    pub number: u64,
    pub name: String,
    pub group: String,
    pub support: SupportLevel,
    pub handler: SyscallHandler,
    pub authority: Authority,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compat_note: Option<String>,
    pub contracts: Vec<ContractId>,
    pub claims: Vec<ClaimId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncovered_behaviors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySummary {
    pub total_entries: usize,
    pub bring_up: usize,
    pub deferred: usize,
    pub planned: usize,
    pub with_claims: usize,
    pub without_claims: usize,
    pub with_evidence: usize,
    pub with_violation_evidence: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyscallInventory {
    pub summary: InventorySummary,
    pub entries: Vec<SyscallInventoryEntry>,
}

impl SyscallInventory {
    pub fn generate(registry: &ContractRegistry) -> Self {
        let table = carrick_abi::syscall::aarch64_table();

        // Index contracts by syscall surface name (e.g. "futex" from "syscall:futex")
        let mut contracts_by_syscall: BTreeMap<String, BTreeSet<ContractId>> = BTreeMap::new();
        for contract in registry.contracts() {
            for surface in &contract.guest_surfaces {
                if let Some(syscall_name) = surface.strip_prefix("syscall:") {
                    contracts_by_syscall
                        .entry(syscall_name.to_string())
                        .or_default()
                        .insert(contract.id.clone());
                }
            }
        }

        // Index claims by contract ID
        let mut claims_by_contract: BTreeMap<ContractId, Vec<&crate::Claim>> = BTreeMap::new();
        for claim in registry.claims() {
            claims_by_contract
                .entry(claim.contract.clone())
                .or_default()
                .push(claim);
        }

        let mut entries = Vec::with_capacity(table.len());
        let mut bring_up = 0;
        let mut deferred = 0;
        let mut planned = 0;
        let mut with_claims = 0;
        let mut with_evidence = 0;
        let mut with_violation_evidence = 0;

        for sys in table {
            match sys.support {
                SupportLevel::BringUp => bring_up += 1,
                SupportLevel::Deferred => deferred += 1,
                SupportLevel::Planned => planned += 1,
            }

            let matching_contracts: Vec<ContractId> = contracts_by_syscall
                .get(sys.name)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();

            let mut claim_ids = BTreeSet::new();
            let mut has_evidence = false;
            let mut has_violation_evidence = false;

            for contract_id in &matching_contracts {
                if let Some(claims) = claims_by_contract.get(contract_id) {
                    for claim in claims {
                        claim_ids.insert(claim.id.clone());
                        match &claim.coverage {
                            CoverageState::Evidenced { .. } => has_evidence = true,
                            CoverageState::ViolationDemonstrated { .. } => {
                                has_evidence = true;
                                has_violation_evidence = true;
                            }
                            _ => {}
                        }
                    }
                }
            }

            let claims: Vec<ClaimId> = claim_ids.into_iter().collect();
            if !claims.is_empty() {
                with_claims += 1;
            }
            if has_evidence {
                with_evidence += 1;
            }
            if has_violation_evidence {
                with_violation_evidence += 1;
            }

            let mut uncovered = Vec::new();
            if claims.is_empty() {
                match sys.support {
                    SupportLevel::BringUp => {
                        uncovered
                            .push("emulated in bring-up without explicit contract claim".into());
                    }
                    SupportLevel::Planned => {
                        uncovered.push("planned syscall without registered claims".into());
                    }
                    SupportLevel::Deferred => {
                        uncovered.push("deferred refusal behavior unverified by contract".into());
                    }
                }
            }

            entries.push(SyscallInventoryEntry {
                number: sys.number,
                name: sys.name.to_string(),
                group: sys.group.to_string(),
                support: sys.support,
                handler: sys.handler,
                authority: sys.authority,
                compat_note: sys.compat_note.map(ToString::to_string),
                contracts: matching_contracts,
                claims,
                uncovered_behaviors: uncovered,
                aliases: Vec::new(),
            });
        }

        let total_entries = entries.len();
        let without_claims = total_entries.saturating_sub(with_claims);

        let summary = InventorySummary {
            total_entries,
            bring_up,
            deferred,
            planned,
            with_claims,
            without_claims,
            with_evidence,
            with_violation_evidence,
        };

        Self { summary, entries }
    }
}
