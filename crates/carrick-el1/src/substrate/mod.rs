//! EL1 mechanisms. No Linux ABI values or dependencies on personality modules.
#[path = "../file.rs"]
pub mod file;
#[path = "../sched.rs"]
pub mod sched;
pub mod watches;
