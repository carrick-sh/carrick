//! Typed, fail-closed conformance-contract registry for Carrick development gates.

mod evaluate;
mod model;
mod observation;
mod registry;

pub use evaluate::{ContractFailure, ContractPass, evaluate};
pub type EvaluationError = ContractFailure;
pub use model::{
    Budget, ConformanceContract, ContractId, ExecutionLayer, LayerBindings, ModelError,
    RuntimeRatioPolicy, StructuralBudget, SurfaceAssignment, SurfaceRegistry, TimingStatistic,
    WorkMetric,
};
pub use observation::{
    Completeness, ContractObservation, ObservationError, SemanticAssertion, TimingDistribution,
    WorkSnapshot,
};
pub use registry::{ContractRegistry, RegistryError};
