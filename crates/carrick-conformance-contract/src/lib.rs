//! Typed, fail-closed conformance-contract registry for Carrick development gates.

mod model;
mod registry;

pub use model::{
    Budget, ConformanceContract, ContractId, ExecutionLayer, LayerBindings, ModelError,
    RuntimeRatioPolicy, StructuralBudget, SurfaceAssignment, SurfaceRegistry, TimingStatistic,
    WorkMetric,
};
pub use registry::{ContractRegistry, RegistryError};
