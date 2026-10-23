//! Shared owner algorithms; hardware and Linux lowering stay with clients.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
extern crate alloc;
pub use carrick_core_abi::Served;
pub use carrick_sched_core::process::{TaskRusage, TerminationStatus};
pub mod cancellation;
pub mod entry;
pub mod file;
pub mod ipc_permissions;
pub mod lifecycle;
pub mod mm;
pub mod personality;
pub mod terminal;
pub mod wait;
pub use personality::{
    CallContext, CallOrdinal, EntryDecodeError, Personality, PersonalityAbi, ServiceError, TaskId,
    TaskKey, TaskSerial, ThreadKey, UserCopy, UserMemory, UserStackOffset,
};

#[cfg(test)]
extern crate std;

pub mod affinity;
