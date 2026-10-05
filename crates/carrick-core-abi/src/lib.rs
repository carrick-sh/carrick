//! Neutral owner identities and transport, shared by both ISA images.
#![no_std]
pub mod mm;
pub use mm::*;
mod metadata_extent;
pub use metadata_extent::*;
