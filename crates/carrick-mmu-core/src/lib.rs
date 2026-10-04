//! Substrate memory-management unit and page-table management.
//!
//! Provides platform-neutral `no_std` + `alloc` abstractions for hardware
//! page-table construction, walking, modification, and undo journaling.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod aarch64;

mod host_backing;
pub use host_backing::HostBackingIdentity;
pub mod owner_mmu;
pub mod x86;
