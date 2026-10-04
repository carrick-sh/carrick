//! Executor-side quantum accounting for the kernel's continuation model
//! (`carrick_kernel::kernel::continuation`): persistent quantum jobs, task bindings,
//! logical job completions and process drains. This stays in the carrier
//! because it names `crate::hvpatch` and `crate::trap`.

pub mod quantum;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "platform-macos"))]
pub(crate) use self::quantum::HvpatchTaskQuantum;
pub(crate) use self::quantum::{
    ExecutorFailureSettlement, HvpatchTaskBinding, PersistentQuantumJob,
};
pub use self::quantum::{JobId, LogicalJobCompletion, ProcessDrain, QuantumExit};
