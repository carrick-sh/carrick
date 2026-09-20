//! Typed, fail-closed conformance-contract registry for Carrick development gates.

mod evaluate;
mod inventory;
mod model;
mod observation;
mod registry;

pub use evaluate::{ContractFailure, ContractPass, evaluate};
pub type EvaluationError = ContractFailure;
pub use inventory::{InventorySummary, SyscallInventory, SyscallInventoryEntry};
pub use model::{
    Budget, CapabilityClass, Claim, ClaimId, ConformanceContract, ContractId, CoverageState,
    ExecutionLayer, LayerBindings, ModelError, RuntimeRatioPolicy, StructuralBudget,
    SurfaceAssignment, SurfaceRegistry, TimingStatistic, WorkMetric,
};
pub use observation::{
    Completeness, ContractObservation, ObservationError, SemanticAssertion, TimingDistribution,
    WorkSnapshot,
};
pub use registry::{ContractRegistry, RegistryError};
