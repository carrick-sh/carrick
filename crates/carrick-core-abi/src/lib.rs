//! Neutral owner identities and transport, shared by both ISA images.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod mm;
pub use mm::*;
mod metadata_extent;
pub use metadata_extent::*;

/// Minimum dynamic metadata grant quantum, shared by allocator adapters.
pub const EL1_DYNAMIC_METADATA_EXTENT_SIZE: usize = 512 * 1024;
