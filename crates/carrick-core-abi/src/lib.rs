//! Neutral owner identities and transport, shared by both ISA images.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
extern crate alloc;
pub mod mm;
pub use mm::*;
mod metadata_extent;
pub use metadata_extent::*;
pub mod wait;
pub use wait::*;
pub mod lifecycle;
pub use lifecycle::*;
pub mod entry;
pub use entry::*;

/// Minimum dynamic metadata grant quantum, shared by allocator adapters.
pub const EL1_DYNAMIC_METADATA_EXTENT_SIZE: usize = 512 * 1024;

pub use entry::Served;

mod native_run_failure;
pub use native_run_failure::*;

mod initial_boot;
pub use initial_boot::*;

mod prepare_stock;
pub use prepare_stock::*;

mod executable_publication;
pub use executable_publication::*;

mod root_exit;
pub use root_exit::*;

mod open_lifetime;
pub use open_lifetime::*;

pub mod service;
