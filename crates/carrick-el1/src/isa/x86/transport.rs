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
        // A real Rust panic in the ring, through the image's panic handler.
        2 => panic!("transport witness panic {op}"),
        // A carrier invariant refusal, through the carriers' `fatal_boot!`.
        3 => crate::x86_fatal_boot!(),
        _ => u64::MAX,
    }
}

/// Terminal refusal of a broken carrier invariant at `file:line:column`:
/// publish that source site through the fatal port and halt this CPU (#2853).
/// Raise it with [`crate::x86_fatal_boot!`].
#[cold]
#[inline(never)]
pub fn fatal_boot_at(file: &'static str, line: u32, column: u32) -> ! {
    publish_fatal_report(
        carrick_el1_abi::PanicReportKind::FatalSite,
        &carrick_el1_abi::PanicReport::at_site(file, line, column, "fatal_boot"),
    )
}

/// Refuse a broken carrier invariant, naming this raising site.
///
/// A macro, not a `#[track_caller]` function: about a hundred carrier sites
/// raise it, and a tracked caller costs each one a relocated 24-byte
/// `Location` in the CPL0 image's writable data, which must fit the 2 MiB
/// supervisor extent. The site rides as immediates instead.
#[macro_export]
macro_rules! x86_fatal_boot {
    () => {
        $crate::isa::x86::transport::fatal_boot_at(file!(), line!(), column!())
    };
}

/// Publish a ring panic or carrier fatal record through the fatal port, then
/// halt. The words ride in `carrick_x86::PANIC_REPORT_REGS` order.
#[cold]
#[inline(never)]
pub fn publish_fatal_report(
    kind: carrick_el1_abi::PanicReportKind,
    report: &carrick_el1_abi::PanicReport,
) -> ! {
    let words = report.words();
    // SAFETY: terminal CPL0 fatal crossing. The host reads the stopped
    // registers and never resumes this CPU; HLT keeps it from spinning in
    // KVM_RUN if it does.
    unsafe {
        core::arch::asm!("out dx, al", "2: cli", "hlt", "jmp 2b",
            in("dx") FATAL_PORT,
            in("rax") kind.sentinel(),
            in("rdi") words[0], in("rsi") words[1], in("rcx") words[2],
            in("r8") words[3], in("r9") words[4], in("r10") words[5],
            in("r11") words[6], in("r12") words[7], in("r13") words[8],
            in("r14") words[9],
            options(noreturn));
    }
}

/// Retain a supervisor-stack failure record across the declared carrier port.
pub fn complete_native_run_failure(
    binding: carrick_el1_abi::ExecutionBinding,
    cause: carrick_core_abi::NativeRunFailureCause,
) -> ! {
    let record = carrick_core_abi::NativeRunFailure::new(binding, cause);
    // SAFETY: CPL0 retains the initialized record and cannot restore a guest
    // frame after this authenticated terminal crossing, even on refusal.
    unsafe {
        core::arch::asm!("out dx, al", "2: cli", "hlt", "jmp 2b",
            in("dx") carrick_core_abi::NATIVE_RUN_FAILURE_PORT,
            in("rax") &record as *const _ as u64,
            options(noreturn));
    }
}
