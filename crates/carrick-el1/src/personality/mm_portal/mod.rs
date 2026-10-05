//! Typed transfer API over the admitted production EL1 owner.
//! Reservation storage, address spaces, descriptor arenas and physical frame
//! custody remain with their existing production owners.
pub use carrick_el1_abi::{El1MmHandle, ReservationMm};
#[cfg(any(test, feature = "host-test"))]
use core::num::NonZeroU64;
mod edit_wait;
mod fork;
mod maintenance;
pub use edit_wait::park_prepared_edit;
pub use maintenance::*;
pub mod production;
pub use fork::*;
pub use production::*;

pub use carrick_core::mm::transaction::MmError;
pub use carrick_core::mm::transfer::{
    GuestVa, SelectedChunk, TransferContinuation, ValidatedChunk,
};
pub use carrick_personality_linux::mm::MmErrorLinux;

/// Internal reads are confined to the immutable boot control page. They are
/// not a privileged user-copy bypass, and cannot write or name other windows.
pub use carrick_el1_abi::PortalTransferIntent as TransferIntent;

#[cfg(any(test, feature = "host-test"))]
pub mod test_support;
#[cfg(test)]
pub(crate) mod tests;
