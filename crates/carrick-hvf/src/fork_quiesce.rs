//! Stop-the-world barriers for mutating shared guest/VM state while sibling
//! vCPU threads run.
//!
//! Implementation moved to `carrick-thread` (hypervisor-agnostic); re-exported
//! here so all existing `crate::fork_quiesce::*` call sites in carrick-hvf and
//! carrick-runtime compile unchanged.
pub use carrick_thread::fork_quiesce::*;
