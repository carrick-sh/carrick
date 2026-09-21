use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct ContractId(String);

impl ContractId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.split('.').all(|segment| {
                !segment.is_empty()
                    && segment.split('-').all(|part| {
                        !part.is_empty()
                            && part
                                .bytes()
                                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    })
            });
        if !valid {
            return Err(ModelError::InvalidContractId(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContractId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Default for ContractId {
    fn default() -> Self {
        Self("contract.unknown".to_string())
    }
}

impl<'de> Deserialize<'de> for ContractId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionLayer {
    VmFree,
    EmbedStructural,
    EmbedTiming,
    Docker,
    Ecosystem,
}

impl fmt::Display for ExecutionLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionLayer::VmFree => write!(f, "vm_free"),
            ExecutionLayer::EmbedStructural => write!(f, "embed_structural"),
            ExecutionLayer::EmbedTiming => write!(f, "embed_timing"),
            ExecutionLayer::Docker => write!(f, "docker"),
            ExecutionLayer::Ecosystem => write!(f, "ecosystem"),
        }
    }
}

pub use carrick_observability::work_meter::WorkMetric;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Budget {
    Exact {
        metric: WorkMetric,
        value: u64,
    },
    UpperBound {
        metric: WorkMetric,
        maximum: u64,
    },
    Affine {
        metric: WorkMetric,
        base: u64,
        per_unit: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StructuralBudget {
    #[serde(flatten)]
    pub budget: Budget,
    /// Instrumented evidence layers to which this budget applies. An omitted
    /// list preserves the historical behavior: enforce in both structural
    /// layers.
    pub layers: Vec<ExecutionLayer>,
    pub rationale: Option<String>,
}

impl<'de> Deserialize<'de> for StructuralBudget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = StructuralBudgetWire::deserialize(deserializer)?;
        let budget = match wire.kind {
            BudgetKind::Exact => {
                reject_fields::<D::Error>(
                    wire.maximum.is_some() || wire.base.is_some() || wire.per_unit.is_some(),
                    "exact",
                )?;
                Budget::Exact {
                    metric: wire.metric,
                    value: required(wire.value, "value", "exact")?,
                }
            }
            BudgetKind::UpperBound => {
                reject_fields::<D::Error>(
                    wire.value.is_some() || wire.base.is_some() || wire.per_unit.is_some(),
                    "upper-bound",
                )?;
                Budget::UpperBound {
                    metric: wire.metric,
                    maximum: required(wire.maximum, "maximum", "upper-bound")?,
                }
            }
            BudgetKind::Affine => {
                reject_fields::<D::Error>(
                    wire.value.is_some() || wire.maximum.is_some(),
                    "affine",
                )?;
                Budget::Affine {
                    metric: wire.metric,
                    base: required(wire.base, "base", "affine")?,
                    per_unit: required(wire.per_unit, "per_unit", "affine")?,
                }
            }
        };
        Ok(Self {
            budget,
            layers: wire
                .layers
                .unwrap_or_else(|| vec![ExecutionLayer::VmFree, ExecutionLayer::EmbedStructural]),
            rationale: wire.rationale,
        })
    }
}

fn reject_fields<E>(present: bool, kind: &str) -> Result<(), E>
where
    E: serde::de::Error,
{
    if present {
        return Err(E::custom(format_args!(
            "{kind} budget contains fields for another budget kind"
        )));
    }
    Ok(())
}

fn required<E>(value: Option<u64>, field: &str, kind: &str) -> Result<u64, E>
where
    E: serde::de::Error,
{
    value.ok_or_else(|| E::custom(format_args!("{kind} budget requires {field}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuralBudgetWire {
    kind: BudgetKind,
    metric: WorkMetric,
    value: Option<u64>,
    maximum: Option<u64>,
    base: Option<u64>,
    per_unit: Option<u64>,
    #[serde(default)]
    layers: Option<Vec<ExecutionLayer>>,
    #[serde(default)]
    rationale: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum BudgetKind {
    Exact,
    UpperBound,
    Affine,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LayerBindings {
    /// Explicit open binding work. Never authorizes execution or acceptance.
    #[serde(default)]
    pub unresolved: std::collections::BTreeMap<String, String>,
    pub vm_free: Option<String>,
    pub embed: Option<String>,
    pub docker: Option<String>,
    #[serde(default)]
    pub ecosystem: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TimingStatistic {
    P50,
    P95,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRatioPolicy {
    pub maximum: f64,
    pub statistic: TimingStatistic,
    pub minimum_samples: usize,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceContract {
    pub schema_version: u32,
    pub id: ContractId,
    pub title: String,
    pub guest_surfaces: Vec<String>,
    pub semantic_authority: Vec<String>,
    pub fixture: String,
    pub scale_points: Vec<u64>,
    pub bindings: LayerBindings,
    pub structural_budgets: Vec<StructuralBudget>,
    pub runtime_ratio: Option<RuntimeRatioPolicy>,
    pub rationale: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceAssignment {
    pub path: String,
    pub contracts: Vec<ContractId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceRegistry {
    pub schema_version: u32,
    pub surfaces: Vec<SurfaceAssignment>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[serde(transparent)]
pub struct ClaimId(String);

impl ClaimId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.split('.').all(|segment| {
                !segment.is_empty()
                    && segment.split('-').all(|part| {
                        !part.is_empty()
                            && part
                                .bytes()
                                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    })
            });
        if !valid {
            return Err(ModelError::InvalidClaimId(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClaimId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ClaimId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CapabilityClass {
    VmFreeExisting {
        capability: String,
    },
    VmFreeExtension {
        capability: String,
        rationale: String,
    },
    RequiresGuest {
        rationale: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CoverageState {
    Declared,
    Bound {
        layer: ExecutionLayer,
    },
    Evidenced {
        layer: ExecutionLayer,
        revision: String,
    },
    ViolationDemonstrated {
        layer: ExecutionLayer,
        known_bad_revision: String,
    },
}

impl<'de> Deserialize<'de> for CoverageState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
        enum CoverageStateWire {
            Declared,
            Bound {
                layer: ExecutionLayer,
            },
            Evidenced {
                layer: ExecutionLayer,
                revision: String,
            },
            ViolationDemonstrated {
                layer: ExecutionLayer,
                known_bad_revision: String,
            },
        }

        let wire = CoverageStateWire::deserialize(deserializer)?;
        match wire {
            CoverageStateWire::Declared => Ok(CoverageState::Declared),
            CoverageStateWire::Bound { layer } => Ok(CoverageState::Bound { layer }),
            CoverageStateWire::Evidenced { layer, revision } => {
                if revision.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "revision cannot be empty or whitespace",
                    ));
                }
                Ok(CoverageState::Evidenced { layer, revision })
            }
            CoverageStateWire::ViolationDemonstrated {
                layer,
                known_bad_revision,
            } => {
                if known_bad_revision.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "known_bad_revision cannot be empty or whitespace",
                    ));
                }
                Ok(CoverageState::ViolationDemonstrated {
                    layer,
                    known_bad_revision,
                })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub id: ClaimId,
    pub contract: ContractId,
    pub description: String,
    pub linux_authority: Vec<String>,
    #[serde(default)]
    pub fixture_requirements: Vec<String>,
    #[serde(default)]
    pub related_contracts: Vec<ContractId>,
    #[serde(default)]
    pub related_ecosystem_rows: Vec<String>,
    pub capability: CapabilityClass,
    pub coverage: CoverageState,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ModelError {
    #[error("invalid contract id {0:?}")]
    InvalidContractId(String),
    #[error("invalid claim id {0:?}")]
    InvalidClaimId(String),
    #[error("invalid claim {id}: {reason}")]
    InvalidClaim { id: ClaimId, reason: String },
}
