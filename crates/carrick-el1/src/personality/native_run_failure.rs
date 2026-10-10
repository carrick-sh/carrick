//! Terminal native failures retain the exact execution incarnation.
use carrick_el1_abi::{ExecutionBinding, NativeRunFailureReason};

/// VM-free witness of the production terminal completion boundary.
#[cfg(not(target_os = "none"))]
#[derive(Debug)]
pub struct NativeRunFailurePanic {
    pub binding: ExecutionBinding,
    pub reason: NativeRunFailureReason,
}

/// A failed native operation cannot become an errno, forwarded call or return.
pub fn complete_native_run_failure(binding: ExecutionBinding, reason: NativeRunFailureReason) -> ! {
    #[cfg(all(target_os = "none", target_arch = "aarch64"))]
    {
        let record = carrick_el1_abi::NativeRunFailure::new(binding, reason);
        // SAFETY: EL1 owns and retains the initialized aligned stack record until
        // the stopped lane is authenticated and the carrier terminates the run.
        unsafe {
            core::arch::asm!(
                "hvc #3",
                in("x0") carrick_el1_abi::NATIVE_RUN_FAILURE_SENTINEL,
                in("x1") &record as *const _ as u64,
                options(nostack)
            );
        }
        // A refused or spuriously resumed terminal crossing never returns to EL0.
        crate::substrate::sched::hw::fatal_entry_binding();
    }
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    {
        let record = carrick_el1_abi::NativeRunFailure::new(binding, reason);
        // SAFETY: CPL0 retains this initialized supervisor-stack record across
        // the authenticated terminal port crossing, exactly as the entry lane.
        unsafe {
            core::arch::asm!("out dx, al",
                in("dx") carrick_el1_abi::NATIVE_RUN_FAILURE_PORT,
                in("rax") &record as *const _ as u64,
                options(nostack, preserves_flags));
        }
        loop {
            // SAFETY: terminal CPL0 failure may never return to guest execution.
            unsafe {
                core::arch::asm!("cli", "hlt", options(nomem, nostack));
            }
        }
    }
    #[cfg(all(not(target_os = "none"), test))]
    {
        test_terminal_failure(binding, reason)
    }
    #[cfg(all(not(target_os = "none"), not(test)))]
    {
        carrick_fatal::carrick_fatal!(
            "el1::native_run_failure",
            "native run failed: {} ({binding:?})",
            reason.as_str()
        )
    }
}

#[cfg(all(not(target_os = "none"), test))]
#[allow(clippy::panic)]
fn test_terminal_failure(binding: ExecutionBinding, reason: NativeRunFailureReason) -> ! {
    std::panic::panic_any(NativeRunFailurePanic { binding, reason })
}
