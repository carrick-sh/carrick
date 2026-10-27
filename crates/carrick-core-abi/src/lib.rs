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

pub mod host_file;
pub mod service;

/// Integrity digest shared by fixed ABI records. This detects torn or
/// mis-sized records; consumers must still authenticate every decoded field
/// against their retained owner ledger.
pub(crate) fn integrity_digest(words: &[u64]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for word in words {
        for byte in word.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}
