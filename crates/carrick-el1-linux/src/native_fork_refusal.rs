//! Preserve the native fork operation and its owner refusal until errno encoding.

use carrick_core::mm::{fork::ForkError, reservation::Refusal, transaction::MmError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeForkStage {
    MappingCount,
    SpaceAccess,
    ParentRoot,
    ObserveMappings,
    TransferSequence,
    Census,
    PublishRoot,
    Scratch,
    Prepare,
    Publish,
    Reserve,
    Commit,
    Abort,
    OpenChildSpace,
    StockCrossing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeForkCause {
    Mm(MmError),
    Reservation(Refusal),
    Fork(ForkError),
    StockReservation(carrick_el1_abi::ForkStockRefusal),
    StockCrossing {
        status: u64,
        reply: Option<carrick_el1_abi::ForkStockRefusal>,
    },
}

impl From<MmError> for NativeForkCause {
    fn from(value: MmError) -> Self {
        Self::Mm(value)
    }
}
impl From<Refusal> for NativeForkCause {
    fn from(value: Refusal) -> Self {
        Self::Reservation(value)
    }
}
impl From<ForkError> for NativeForkCause {
    fn from(value: ForkError) -> Self {
        Self::Fork(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeForkRefusal {
    pub stage: NativeForkStage,
    pub cause: NativeForkCause,
}

impl NativeForkRefusal {
    pub fn error(self) -> super::native_process_runtime::NativeProcessError {
        use super::native_process_runtime::NativeProcessError as E;
        use carrick_el1_abi::ForkStockRefusal as R;
        match self.cause {
            NativeForkCause::StockReservation(R::Invalid) => E::Invalid,
            NativeForkCause::StockReservation(R::Stale) => E::Stale,
            NativeForkCause::StockReservation(R::Capacity) => E::Exhausted,
            NativeForkCause::StockReservation(R::Inventory) => E::Busy,
            _ => E::Fault,
        }
    }
}

pub fn refused(
    stage: NativeForkStage,
    cause: impl Into<NativeForkCause>,
) -> super::native_process_runtime::NativeProcessError {
    let refusal = NativeForkRefusal {
        stage,
        cause: cause.into(),
    };
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    emit(format_args!("{refusal:?}"));
    super::native_process_runtime::NativeProcessError::ForkRefused(refusal)
}

/// Error-only alias observation alongside the typed Prepare refusal. It never
/// changes the error, grants memory, or runs on a successful preparation.
pub fn refused_prepare(
    error: MmError,
    request: &carrick_el1_abi::PortalForkRequest,
    alias: Option<(
        carrick_guest_arch::UserVa,
        Result<Option<carrick_guest_arch::FrameGpa>, carrick_mmu_core::owner_mmu::OwnerMmuRefusal>,
    )>,
) -> super::native_process_runtime::NativeProcessError {
    let refusal = NativeForkRefusal {
        stage: NativeForkStage::Prepare,
        cause: NativeForkCause::Mm(error),
    };
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    emit(format_args!(
        "{refusal:?}; child=0x{:x}+0x{:x}; alias={alias:?}",
        request.child_tables.base, request.child_tables.len
    ));
    #[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
    let _ = (request, alias);
    super::native_process_runtime::NativeProcessError::ForkRefused(refusal)
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn emit(arguments: core::fmt::Arguments<'_>) {
    let mut diagnostic = carrick_el1_abi::NativeForkDiagnostic::new();
    // Bounded, allocation-free and failure-only; no verdict depends on this reply.
    let _ = core::fmt::write(&mut diagnostic, arguments);
    carrick_el1::isa::aarch64::cross_hvc_fork_refusal(&diagnostic);
}

#[cfg(test)]
mod tests {
    use super::super::native_process_runtime::NativeProcessError;
    use super::*;

    #[test]
    fn refusal_keeps_stage_and_owner_reason_until_errno_encoding() {
        let error = refused(NativeForkStage::Census, ForkError::Core);
        assert_eq!(
            error,
            NativeProcessError::ForkRefused(NativeForkRefusal {
                stage: NativeForkStage::Census,
                cause: NativeForkCause::Fork(ForkError::Core),
            })
        );
        assert_eq!(error.errno(), -14);
        assert_ne!(error, refused(NativeForkStage::Prepare, ForkError::Core));
        assert_ne!(error, refused(NativeForkStage::Census, ForkError::Stale));
    }

    #[test]
    fn reserve_diagnostics_preserve_each_stock_refusal_encoding() {
        use carrick_el1_abi::ForkStockRefusal as R;
        for (reply, error) in [
            (R::Invalid, NativeProcessError::Invalid),
            (R::Stale, NativeProcessError::Stale),
            (R::Capacity, NativeProcessError::Exhausted),
            (R::Inventory, NativeProcessError::Busy),
        ] {
            let diagnostic = refused(
                NativeForkStage::Reserve,
                NativeForkCause::StockReservation(reply),
            );
            assert_eq!(diagnostic.errno(), error.errno());
            assert_eq!(diagnostic.run_failure_reason(), error.run_failure_reason());
        }
    }
}
