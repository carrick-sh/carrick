//! Preserve the native fork operation and its owner refusal until errno encoding.

use carrick_core::mm::{fork::ForkError, reservation::Refusal, transaction::MmError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeForkStage {
    ParentLifecycleGate {
        observed: carrick_el1_abi::GateState,
    },
    BirthReservation,
    ParentSpaceEdit,
    ParentForkReady,
    ChildLifecycleClaim,
    ChildControlReset,
    BirthPublication,
    PrepareService,
    ForkFileTable,
    CommitChildService,
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
    Busy,
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
            NativeForkCause::Busy => E::Busy,
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

/// Preserve the existing EAGAIN policy while retaining the exact refusing site.
pub fn busy(stage: NativeForkStage) -> super::native_process_runtime::NativeProcessError {
    refused(stage, NativeForkCause::Busy)
}

/// A service may already have emitted a more precise typed refusal.
pub fn at_busy_site(
    stage: NativeForkStage,
    error: super::native_process_runtime::NativeProcessError,
) -> super::native_process_runtime::NativeProcessError {
    if error == super::native_process_runtime::NativeProcessError::Busy {
        busy(stage)
    } else {
        error
    }
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

/// Observe the final fork error without changing errno or run-failure policy.
pub fn observe_process_error(
    error: super::native_process_runtime::NativeProcessError,
) -> super::native_process_runtime::NativeProcessError {
    observe_process_error_with(error, emit)
}

fn observe_process_error_with(
    error: super::native_process_runtime::NativeProcessError,
    observe: impl FnOnce(core::fmt::Arguments<'_>),
) -> super::native_process_runtime::NativeProcessError {
    // Typed MM refusals already emitted the more specific owner operation.
    if !matches!(
        error,
        super::native_process_runtime::NativeProcessError::ForkRefused(_)
    ) {
        observe(format_args!(
            "ProcessNative::fork error={error:?}; errno={}; run_failure={:?}",
            error.errno(),
            error.run_failure_reason()
        ));
    }
    error
}

/// A missing venue retains the lifecycle fallback; it has no final errno yet.
pub fn observe_process_venue<T>(venue: Option<T>) -> Option<T> {
    observe_process_venue_with(venue, emit)
}

fn observe_process_venue_with<T>(
    venue: Option<T>,
    observe: impl FnOnce(core::fmt::Arguments<'_>),
) -> Option<T> {
    if venue.is_none() {
        observe(format_args!(
            "LifecycleNative::process_fork venue=unavailable; outcome=None"
        ));
    }
    venue
}

#[cfg(not(all(target_os = "none", target_arch = "aarch64")))]
fn emit(_arguments: core::fmt::Arguments<'_>) {}

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
    fn boundary_observes_every_untyped_error_without_changing_policy() {
        use NativeProcessError as E;
        use carrick_core_abi::NativeRunFailureReason as R;
        for (error, errno, reason) in [
            (E::Invalid, -22, R::NativeInvalid),
            (E::Stale, -22, R::NativeStale),
            (E::Exhausted, -11, R::NativeExhausted),
            (E::Fault, -14, R::NativeFault),
            (E::Unsupported, -38, R::NativeUnsupported),
            (E::GroupExitCustody, -38, R::X86GroupExitCustody),
            (E::Busy, -11, R::NativeBusy),
            (E::Quarantined, -5, R::NativeQuarantined),
            (E::NoChild, -10, R::NativeNoChild),
        ] {
            let mut diagnostic = carrick_el1_abi::NativeForkDiagnostic::new();
            let observed = observe_process_error_with(error, |arguments| {
                core::fmt::write(&mut diagnostic, arguments).unwrap();
            });
            assert_eq!(observed, error);
            assert_eq!(observed.errno(), errno);
            assert_eq!(observed.run_failure_reason(), reason);
            assert_eq!(observe_process_error(error), error);
            let expected = std::format!(
                "ProcessNative::fork error={error:?}; errno={errno}; run_failure={reason:?}"
            );
            assert_eq!(diagnostic.message(), Some(expected.as_str()));
        }
    }

    #[test]
    fn boundary_does_not_duplicate_typed_refusals() {
        use carrick_el1_abi::ForkStockRefusal as R;
        for cause in [
            NativeForkCause::Fork(ForkError::Core),
            NativeForkCause::StockReservation(R::Invalid),
            NativeForkCause::StockReservation(R::Stale),
            NativeForkCause::StockReservation(R::Capacity),
            NativeForkCause::StockReservation(R::Inventory),
        ] {
            let error = refused(NativeForkStage::Reserve, cause);
            let observed = observe_process_error_with(error, |_| panic!("duplicate refusal"));
            assert_eq!(observed, error);
            assert_eq!(observed.errno(), error.errno());
            assert_eq!(observed.run_failure_reason(), error.run_failure_reason());
        }
    }

    #[test]
    fn missing_venue_observation_preserves_fallback_and_success_is_silent() {
        let mut diagnostic = carrick_el1_abi::NativeForkDiagnostic::new();
        assert_eq!(
            observe_process_venue_with(None::<u32>, |arguments| {
                core::fmt::write(&mut diagnostic, arguments).unwrap();
            }),
            None
        );
        assert_eq!(
            diagnostic.message(),
            Some("LifecycleNative::process_fork venue=unavailable; outcome=None")
        );
        let venue = 42;
        assert_eq!(
            observe_process_venue_with(Some(&venue), |_| panic!("successful venue")),
            Some(&venue)
        );
        assert_eq!(observe_process_venue(None::<u32>), None);
    }

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
    fn parent_gate_refusal_preserves_observed_state_and_busy_policy() {
        use carrick_el1_abi::GateState;
        for observed in [
            GateState::Open,
            GateState::ForkClosing,
            GateState::Closed,
            GateState::AwaitingExecBinding,
            GateState::HostOnly,
        ] {
            let stage = NativeForkStage::ParentLifecycleGate { observed };
            let error = busy(stage);
            assert_eq!(
                error,
                NativeProcessError::ForkRefused(NativeForkRefusal {
                    stage,
                    cause: NativeForkCause::Busy,
                })
            );
            assert_eq!(error.errno(), -11);
            assert_eq!(
                error.run_failure_reason(),
                carrick_core_abi::NativeRunFailureReason::NativeBusy
            );
            let NativeProcessError::ForkRefused(refusal) = error else {
                unreachable!()
            };
            let mut diagnostic = carrick_el1_abi::NativeForkDiagnostic::new();
            core::fmt::write(&mut diagnostic, format_args!("{refusal:?}")).unwrap();
            let expected = std::format!(
                "NativeForkRefusal {{ stage: ParentLifecycleGate {{ observed: {observed:?} }}, cause: Busy }}"
            );
            assert_eq!(diagnostic.message(), Some(expected.as_str()));
        }
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
