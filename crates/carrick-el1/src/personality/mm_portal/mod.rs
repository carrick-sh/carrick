//! Typed transfer API over the admitted production EL1 owner.
//! Reservation storage, address spaces, descriptor arenas and physical frame
//! custody remain with their existing production owners.
use crate::memory::reservations::Refusal;
pub use carrick_el1_abi::{El1MmHandle, ReservationMm};
use carrick_mmu_core::aarch64::PageTableError;
#[cfg(test)]
use core::num::NonZeroU64;
pub mod production;
pub use production::*;

/// Guest address, never a physical extent or a host pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestVa(u64);
impl GuestVa {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmError {
    Fault,
    UnsupportedExecutableCow,
    Stale,
    Busy,
    NoMemory,
    Invalid,
    Core,
    Reservation(Refusal),
    Table(PageTableError),
}
impl MmError {
    pub const fn errno(self) -> u32 {
        match self {
            Self::Fault => 14,
            Self::UnsupportedExecutableCow => 95,
            Self::Stale => 3,
            Self::Busy => 16,
            Self::NoMemory => 12,
            Self::Invalid => 22,
            Self::Core | Self::Reservation(_) | Self::Table(_) => 5,
        }
    }
}
impl From<Refusal> for MmError {
    fn from(e: Refusal) -> Self {
        match e {
            Refusal::Stale => Self::Stale,
            Refusal::Busy => Self::Busy,
            Refusal::Hole | Refusal::Limit => Self::Fault,
            Refusal::MetadataRequired => Self::NoMemory,
            _ => Self::Reservation(e),
        }
    }
}
impl From<PageTableError> for MmError {
    fn from(e: PageTableError) -> Self {
        Self::Table(e)
    }
}

/// Internal reads are confined to the immutable boot control page. They are
/// not a privileged user-copy bypass, and cannot write or name other windows.
pub use carrick_el1_abi::PortalTransferIntent as TransferIntent;

#[cfg(test)]
mod tests;
