//! Typed owner refusal; Linux errno encoding is a client operation.
use crate::mm::reservation::Refusal;
use carrick_mmu_core::aarch64::PageTableError;

impl From<crate::mm::transfer::TransferError> for MmError {
    fn from(error: crate::mm::transfer::TransferError) -> Self {
        match error {
            crate::mm::transfer::TransferError::Stale => Self::Stale,
            crate::mm::transfer::TransferError::Invalid => Self::Invalid,
        }
    }
}

impl From<crate::mm::fork::ForkError> for MmError {
    fn from(e: crate::mm::fork::ForkError) -> Self {
        match e {
            crate::mm::fork::ForkError::Invalid => Self::Invalid,
            crate::mm::fork::ForkError::NoMemory => Self::NoMemory,
            crate::mm::fork::ForkError::Busy => Self::Busy,
            crate::mm::fork::ForkError::Stale => Self::Stale,
            crate::mm::fork::ForkError::Core => Self::Core,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmError {
    Fault,
    UnsupportedExecutableCow,
    Stale,
    Busy,
    Wait(carrick_core_abi::PortalOwnerWait),
    NoMemory,
    MetadataRequired,
    Invalid,
    Core,
    Reservation(Refusal),
    Table(PageTableError),
}
impl From<Refusal> for MmError {
    fn from(e: Refusal) -> Self {
        match e {
            Refusal::Stale => Self::Stale,
            Refusal::Busy | Refusal::PreparedConflict => Self::Busy,
            Refusal::Hole | Refusal::Limit => Self::Fault,
            Refusal::MetadataRequired => Self::MetadataRequired,
            _ => Self::Reservation(e),
        }
    }
}
impl From<PageTableError> for MmError {
    fn from(e: PageTableError) -> Self {
        Self::Table(e)
    }
}
