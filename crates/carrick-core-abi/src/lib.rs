//! Neutral owner identities and transport, shared by both ISA images.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
pub mod mm;
pub use mm::*;
mod metadata_extent;
pub use metadata_extent::*;
