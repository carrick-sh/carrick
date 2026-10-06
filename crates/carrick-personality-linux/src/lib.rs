//! Linux interpretation of neutral owner records.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod abi;
pub mod dispatch;
pub mod entry;
pub mod mm;
pub mod sched;

pub mod pending_file;

pub mod pending_anonymous;
pub mod pending_lifecycle;
