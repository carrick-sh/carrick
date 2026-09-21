use crate::model::{ContractId, ExecutionLayer, WorkMetric};

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum ContractFailure {
    #[error("contract {contract}: semantic mismatch: {assertion}")]
    SemanticMismatch {
        contract: ContractId,
        assertion: String,
    },
    #[error(
        "contract {contract}: work budget exceeded for {metric:?}: actual {actual} > maximum {maximum}"
    )]
    WorkBudgetExceeded {
        contract: ContractId,
        metric: WorkMetric,
        actual: u64,
        maximum: u64,
    },
    #[error(
        "contract {contract}: scaling violation for {metric:?} at scale {scale}: actual {actual} > maximum {maximum}"
    )]
    ScalingViolation {
        contract: ContractId,
        metric: WorkMetric,
        scale: u64,
        actual: u64,
        maximum: u64,
    },
    #[error("contract {contract}: incomplete measurement: {reason}")]
    IncompleteMeasurement {
        contract: ContractId,
        reason: String,
    },
    #[error("contract {contract}: fixture mismatch: expected {expected}, actual {actual}")]
    FixtureMismatch {
        contract: ContractId,
        expected: String,
        actual: String,
    },
    #[error(
        "contract {contract}: runtime ratio exceeded: actual {actual:.2} > maximum {maximum:.2}"
    )]
    RuntimeRatioExceeded {
        contract: ContractId,
        actual: f64,
        maximum: f64,
    },
    #[error("contract {contract}: unsupported layer {layer:?}")]
    UnsupportedLayer {
        contract: ContractId,
        layer: ExecutionLayer,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ContractPass {
    pub contract_id: ContractId,
    pub evaluated_scales: Vec<u64>,
}

use crate::model::{Budget, ConformanceContract};
use crate::observation::ContractObservation;

pub fn evaluate(
    contract: &ConformanceContract,
    observations: &[ContractObservation],
) -> Result<ContractPass, ContractFailure> {
    if observations.is_empty() {
        return Err(ContractFailure::IncompleteMeasurement {
            contract: contract.id.clone(),
            reason: "no observations provided".into(),
        });
    }

    let mut sorted_observations = observations.to_vec();
    sorted_observations.sort_by_key(|obs| obs.scale);

    for obs in &sorted_observations {
        obs.validate()?;

        if obs.contract_id != contract.id {
            return Err(ContractFailure::FixtureMismatch {
                contract: contract.id.clone(),
                expected: contract.id.to_string(),
                actual: obs.contract_id.to_string(),
            });
        }

        if obs.fixture_identity != contract.fixture {
            return Err(ContractFailure::FixtureMismatch {
                contract: contract.id.clone(),
                expected: contract.fixture.clone(),
                actual: obs.fixture_identity.clone(),
            });
        }

        let supported = match obs.layer {
            ExecutionLayer::VmFree => contract.bindings.vm_free.is_some(),
            ExecutionLayer::EmbedStructural | ExecutionLayer::EmbedTiming => {
                contract.bindings.embed.is_some()
            }
            ExecutionLayer::Docker => contract.bindings.docker.is_some(),
            ExecutionLayer::Ecosystem => !contract.bindings.ecosystem.is_empty(),
        };
        if !supported {
            return Err(ContractFailure::UnsupportedLayer {
                contract: contract.id.clone(),
                layer: obs.layer,
            });
        }

        for assertion in &obs.semantic_assertions {
            if !assertion.passed {
                return Err(ContractFailure::SemanticMismatch {
                    contract: contract.id.clone(),
                    assertion: assertion
                        .detail
                        .clone()
                        .unwrap_or_else(|| assertion.name.clone()),
                });
            }
        }

        if matches!(
            obs.layer,
            ExecutionLayer::VmFree | ExecutionLayer::EmbedStructural
        ) {
            match &obs.work {
                None => {
                    return Err(ContractFailure::IncompleteMeasurement {
                        contract: contract.id.clone(),
                        reason: format!("layer {:?} missing work snapshot", obs.layer),
                    });
                }
                Some(work) => {
                    for sb in &contract.structural_budgets {
                        if !sb.layers.contains(&obs.layer) {
                            continue;
                        }
                        match &sb.budget {
                            Budget::Exact { metric, value } => {
                                let actual = work.get(*metric).ok_or_else(|| {
                                    ContractFailure::IncompleteMeasurement {
                                        contract: contract.id.clone(),
                                        reason: format!("missing work metric {metric:?}"),
                                    }
                                })?;
                                if actual != *value {
                                    return Err(ContractFailure::WorkBudgetExceeded {
                                        contract: contract.id.clone(),
                                        metric: *metric,
                                        actual,
                                        maximum: *value,
                                    });
                                }
                            }
                            Budget::UpperBound { metric, maximum } => {
                                let actual = work.get(*metric).ok_or_else(|| {
                                    ContractFailure::IncompleteMeasurement {
                                        contract: contract.id.clone(),
                                        reason: format!("missing work metric {metric:?}"),
                                    }
                                })?;
                                if actual > *maximum {
                                    return Err(ContractFailure::WorkBudgetExceeded {
                                        contract: contract.id.clone(),
                                        metric: *metric,
                                        actual,
                                        maximum: *maximum,
                                    });
                                }
                            }
                            Budget::Affine {
                                metric,
                                base,
                                per_unit,
                            } => {
                                let actual = work.get(*metric).ok_or_else(|| {
                                    ContractFailure::IncompleteMeasurement {
                                        contract: contract.id.clone(),
                                        reason: format!("missing work metric {metric:?}"),
                                    }
                                })?;
                                let maximum = per_unit
                                    .checked_mul(obs.scale)
                                    .and_then(|scaled| base.checked_add(scaled))
                                    .ok_or_else(|| ContractFailure::IncompleteMeasurement {
                                        contract: contract.id.clone(),
                                        reason: "arithmetic overflow computing affine budget bound"
                                            .into(),
                                    })?;
                                if actual > maximum {
                                    return Err(ContractFailure::ScalingViolation {
                                        contract: contract.id.clone(),
                                        metric: *metric,
                                        scale: obs.scale,
                                        actual,
                                        maximum,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        if obs.layer == ExecutionLayer::EmbedTiming {
            match &obs.timing {
                None => {
                    return Err(ContractFailure::IncompleteMeasurement {
                        contract: contract.id.clone(),
                        reason: "timing layer missing timing distribution".into(),
                    });
                }
                Some(timing) => {
                    if let Some(ref policy) = contract.runtime_ratio {
                        if timing.samples().len() < policy.minimum_samples {
                            return Err(ContractFailure::IncompleteMeasurement {
                                contract: contract.id.clone(),
                                reason: format!(
                                    "timing samples {} < minimum {}",
                                    timing.samples().len(),
                                    policy.minimum_samples
                                ),
                            });
                        }
                        let actual = timing.value(policy.statistic);
                        if actual > policy.maximum {
                            return Err(ContractFailure::RuntimeRatioExceeded {
                                contract: contract.id.clone(),
                                actual,
                                maximum: policy.maximum,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(ContractPass {
        contract_id: contract.id.clone(),
        evaluated_scales: sorted_observations.iter().map(|o| o.scale).collect(),
    })
}
