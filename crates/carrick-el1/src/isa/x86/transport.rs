//! Native fatal and host-effect transport for CPL0.

use super::X86Backend;
use super::context::native::{FATAL_PORT, YIELD_PORT};
use carrick_guest_arch::{CrossingBackend, FatalReport};

pub fn yield_host_effect() {
    // SAFETY: CPL0 exits to the KVM host through YIELD_PORT. The host
    // resumes this vCPU on the exact next instruction.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") YIELD_PORT,
            in("al") 0u8,
            options(nostack, preserves_flags)
        );
    }
}

/// Non-returning native fatal transport after an entry loses its exact binding.
#[cold]
#[inline(never)]
pub fn fatal_entry_binding() -> ! {
    // SAFETY: CPL0 signals fatal boundary to the host via FATAL_PORT with
    // PANIC_SENTINEL in rax, and enters an infinite halt loop.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            "2: hlt",
            "jmp 2b",
            in("dx") FATAL_PORT,
            in("rax") carrick_el1_abi::PANIC_SENTINEL,
            options(noreturn)
        );
    }
}

impl CrossingBackend for X86Backend {
    fn yield_host_effect(&mut self) -> Result<(), Self::Error> {
        yield_host_effect();
        Ok(())
    }
    fn report_fatal(&mut self, _report: FatalReport) -> ! {
        fatal_entry_binding()
    }
}

/// A CPL0-only fixture syscall that exercises this shared kernel transport.
pub const TRANSPORT_WITNESS: u64 = 0xffff_ffff_ffff_ff20;

pub fn witness(op: u64) -> u64 {
    match op {
        0 => {
            let mut arch = super::kernel_arch();
            use carrick_guest_arch::CrossingArch;
            match arch.yield_host_effect() {
                Ok(()) => 0,
                Err(_) => u64::MAX,
            }
        }
        1 => {
            let mut arch = super::kernel_arch();
            use carrick_guest_arch::CrossingArch;
            arch.report_fatal(FatalReport {
                task: None,
                detail: carrick_guest_arch::FatalCode::new(1),
            });
        }
        _ => u64::MAX,
    }
}
