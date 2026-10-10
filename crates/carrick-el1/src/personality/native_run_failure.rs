//! Terminal native failures retain the exact execution incarnation.
use carrick_el1_abi::{ExecutionBinding, NativeRunFailureReason};

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
    crate::isa::aarch64::complete_native_run_failure(binding, reason);
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    crate::isa::x86::complete_native_run_failure(binding, reason);
    #[cfg(all(not(target_os = "none"), test))]
    {
        test_terminal_failure(binding, reason)
    }
    #[cfg(all(not(target_os = "none"), not(test)))]
    {
        let _ = binding;
        crate::personality::dispatch::invalid_completion(
            crate::personality::dispatch::NativeInvariant::PhysicalCustody(reason.as_str()),
        )
    }
}

#[cfg(all(not(target_os = "none"), test))]
#[allow(clippy::panic)]
fn test_terminal_failure(binding: ExecutionBinding, reason: NativeRunFailureReason) -> ! {
    std::panic::panic_any(NativeRunFailurePanic { binding, reason })
}
