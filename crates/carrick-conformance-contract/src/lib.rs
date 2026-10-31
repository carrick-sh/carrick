//! Typed, fail-closed conformance-contract registry for Carrick development gates.

mod binding_resolution;
mod evaluate;
mod inventory;
mod model;
mod observation;
pub mod personality_boundary;
mod registry;

pub use binding_resolution::{BindingResolutionError, BindingResolver};
pub use evaluate::{ContractFailure, ContractPass, evaluate};
pub type EvaluationError = ContractFailure;
pub use inventory::{InventorySummary, SyscallInventory, SyscallInventoryEntry};
pub use model::{
    Budget, CapabilityClass, Claim, ClaimId, ConformanceContract, ContractId, CoverageState,
    ExecutionLayer, LayerBindings, ModelError, RuntimeRatioPolicy, StructuralBudget,
    SurfaceAssignment, SurfaceEntry, SurfaceRegistry, TimingStatistic, WorkMetric,
};
pub use observation::{
    Completeness, ContractObservation, ObservationError, SemanticAssertion, TimingDistribution,
    WorkSnapshot,
};
pub use personality_boundary::{
    BoundaryConfig, BoundaryError, CrateAuditReport, DependencyViolation, SourceViolation,
    check_substrate_boundary,
};
pub use registry::{ContractRegistry, RegistryError};
