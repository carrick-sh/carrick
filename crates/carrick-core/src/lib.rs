//! Shared owner algorithms; hardware and Linux lowering stay with clients.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
extern crate alloc;
pub use carrick_core_abi::Served;
pub mod entry;
pub mod lifecycle;
pub mod mm;
pub mod wait;

#[cfg(test)]
extern crate std;
