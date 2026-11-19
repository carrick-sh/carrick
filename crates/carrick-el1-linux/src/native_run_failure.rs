//! Terminal native failures retain the exact execution incarnation.
use carrick_core_abi::{ExecutionBinding, NativeRunFailureReason};

/// Recover the native-service error corresponding to a recorded run failure.
pub(crate) const fn native_process_error_from_run_failure(
    reason: NativeRunFailureReason,
) -> crate::native_process_runtime::NativeProcessError {
    use crate::native_process_runtime::NativeProcessError as E;
    use NativeRunFailureReason as R;
    match reason {
        R::X86GroupExitCustody => E::GroupExitCustody,
        R::NativeInvalid => E::Invalid,
        R::NativeStale => E::Stale,
        R::NativeExhausted => E::Exhausted,
        R::NativeFault => E::Fault,
        R::NativeUnsupported => E::Unsupported,
        R::NativeBusy => E::Busy,
        R::NativeQuarantined | R::BirthSettlement | R::ClaimRollback | R::BornEnqueueRefused => {
            E::Quarantined
        }
        R::NativeNoChild => E::NoChild,
    }
}

/// VM-free witness of the production terminal completion boundary.
#[cfg(all(not(target_os = "none"), test))]
#[derive(Debug)]
pub struct NativeRunFailurePanic {
    pub binding: ExecutionBinding,
    pub reason: NativeRunFailureReason,
}

/// A failed native operation cannot become an errno, forwarded call or return.
pub fn complete_native_run_failure(binding: ExecutionBinding, reason: NativeRunFailureReason) -> ! {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    carrick_el1::isa::aarch64::complete_native_run_failure(binding, reason);
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    carrick_el1::isa::x86::complete_native_run_failure(binding, reason);
    #[cfg(all(not(target_os = "none"), test))]
    {
        test_terminal_failure(binding, reason)
    }
    #[cfg(all(not(target_os = "none"), not(test)))]
    {
        let _ = binding;
        crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::PhysicalCustody(
            crate::dispatch::PhysicalCustodyInvariant::NativeRunFailure(reason),
        ))
    }
}

#[cfg(all(not(target_os = "none"), test))]
#[allow(clippy::panic)]
fn test_terminal_failure(binding: ExecutionBinding, reason: NativeRunFailureReason) -> ! {
    std::panic::panic_any(NativeRunFailurePanic { binding, reason })
}
