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

pub fn refused(
    stage: NativeForkStage,
    cause: impl Into<NativeForkCause>,
) -> super::native_process_runtime::NativeProcessError {
    let refusal = NativeForkRefusal {
        stage,
        cause: cause.into(),
    };
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let mut diagnostic = carrick_el1_abi::NativeForkDiagnostic::new();
        // Formatting is bounded, allocation-free, and only on refusal. It does
        // not participate in the verdict or change the guest's errno.
        let _ = core::fmt::write(&mut diagnostic, format_args!("{refusal:?}"));
        crate::isa::aarch64::cross_hvc_fork_refusal(&diagnostic);
    }
    super::native_process_runtime::NativeProcessError::ForkRefused(refusal)
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
}
