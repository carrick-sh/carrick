//! Complete native CPL0 returns from authenticated shared parked state.
//! The caller owns scheduler claims and task binding; this leaf owns only ISA
//! validation, address installation, TLS and the final register return.

use crate::isa::ArchError;
use carrick_guest_arch::{AddressContext, RootGpa};
use carrick_sched_core::ParkedContextWords;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use super::scheduler;
#[cfg(all(test, not(target_os = "none")))]
use crate::x86_context_words_tests::scheduler;

/// Validate every retained machine field that the native return will install.
/// Failure leaves CR3, TLS and the live CPU member untouched.
pub fn prepare_parked_resume(
    words: ParkedContextWords,
    expected: AddressContext<RootGpa>,
) -> Result<scheduler::NativeContext, ArchError> {
    // The bootstrap admits standard XSAVE with XCR0=x87|SSE|AVX only.
    // Refuse faulting MSR/header/MXCSR values before installing any machine
    // state. The reserved-header scan is a fixed 63 bytes, never guest-sized.
    if !canonical_tls(words.fs_base)
        || !canonical_tls(words.gs_base)
        || words.xsave[512] & !7 != 0
        || words.xsave[513..576].iter().any(|byte| *byte != 0)
        || words.xsave[26] != 0
        || words.xsave[27] != 0
    {
        return Err(ArchError::InvalidContext);
    }
    scheduler::restore_native_context(words, expected).ok_or(ArchError::InvalidContext)
}

fn canonical_tls(base: u64) -> bool {
    base >> 47 == 0 || base >> 47 == 0x1_ffff
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".section .text.native_resume, \"ax\"",
    ".global carrick_x86_resume_iret",
    "carrick_x86_resume_iret:",
    "mov eax, 7",
    "xor edx, edx",
    "xrstor64 [rsi]",
    // No Rust or other instruction that can touch xstate follows XRSTOR.
    // NativeContext.frame is the existing InterruptFrame at offset zero.
    "mov rsp, rdi",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rax",
    "pop rcx",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "swapgs",
    "iretq",
);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
unsafe extern "C" {
    fn carrick_x86_resume_iret(
        frame: *const scheduler::InterruptFrame,
        xsave: *const scheduler::XsaveArea,
    ) -> !;
}

/// Install and return a complete parked context on the current physical CPU.
/// Scheduler record selection, claim ownership and CurrentTask binding belong
/// to the caller. This function publishes the native address member through
/// the same X86Backend installation used by ordinary CPL0 entry.
///
/// # Safety
/// The caller runs at CPL0 with IF masked and kernel GS active, owns the exact
/// on-CPU record and has bound CurrentTask to it. The expected root retains all
/// executing supervisor code, stack, binding and context storage. Bootstrap
/// qualified 48-bit addressing, standard 832-byte XSAVE and XCR0=7 on this CPU.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub unsafe fn resume_parked(
    words: ParkedContextWords,
    expected: AddressContext<RootGpa>,
) -> Result<core::convert::Infallible, ArchError> {
    use carrick_guest_arch::MmuBackend;
    let context = prepare_parked_resume(words, expected)?;
    super::super::X86Backend.install_context(context.address)?;
    scheduler::write_tls(scheduler::NativeTlsRegister::Fs, context.fs_base);
    scheduler::write_tls(scheduler::NativeTlsRegister::UserGs, context.gs_base);
    // SAFETY: preparation authenticated the complete IRET/MSR/XSAVE image;
    // the caller retains its root and supervisor stack through this return.
    unsafe { carrick_x86_resume_iret(&context.frame, &context.xsave) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_guest_arch::{ContextGeneration, FrameGpa, MmGeneration};
    use core::num::NonZeroU64;

    fn fixture() -> (ParkedContextWords, AddressContext<RootGpa>) {
        let expected = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(0x6000)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(11).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(7).unwrap()),
        };
        let mut xsave = [0; carrick_sched_core::X86_XSAVE_BYTES];
        xsave[400..416].fill(0xa5);
        xsave[816..832].fill(0x5a);
        xsave[512] = 7;
        // Real IRQ RCX/R11 are independent of RIP/RFLAGS. A syscall-only
        // conversion here would silently replace both with the IRET tail.
        let words = ParkedContextWords::from_parts(
            [
                15, 14, 13, 12, 6, 3, 11, 10, 9, 8, 1, 2, 4, 5, 7, 0x1234, 0x23, 0x1_0302, 0x8000,
                0x1b,
            ],
            expected,
            0x4000,
            0xffff_8000_0000_5000,
            xsave,
        );
        (words, expected)
    }

    #[test]
    fn complete_irq_resume_keeps_all_gprs_tls_and_extended_state() {
        let (words, expected) = fixture();
        let context = prepare_parked_resume(words, expected).unwrap();
        assert_eq!(
            context.frame.gpr,
            [15, 14, 13, 12, 6, 3, 11, 10, 9, 8, 1, 2, 4, 5, 7]
        );
        assert_eq!(
            (
                context.frame.rip,
                context.frame.cs,
                context.frame.flags,
                context.frame.rsp,
                context.frame.ss
            ),
            (0x1234, 0x23, 0x1_0302, 0x8000, 0x1b),
        );
        assert_eq!(context.address, expected);
        assert_eq!(
            (context.fs_base, context.gs_base),
            (0x4000, 0xffff_8000_0000_5000)
        );
        assert_eq!(context.xsave.0, words.xsave);
    }

    #[test]
    fn syscall_resume_retains_architectural_rcx_r11_clobbers() {
        let (mut words, expected) = fixture();
        words.frame[6] = 0x1_0302;
        words.frame[11] = 0x1234;
        let context = prepare_parked_resume(words, expected).unwrap();
        assert_eq!(
            context.frame.gpr,
            [15, 14, 13, 12, 6, 3, 0x1_0302, 10, 9, 8, 1, 0x1234, 4, 5, 7,]
        );
        assert_eq!((context.frame.rip, context.frame.flags), (0x1234, 0x1_0302));
    }

    #[test]
    fn resume_refuses_wrong_owner_and_invalid_iret_before_hardware() {
        let (words, expected) = fixture();
        assert!(matches!(
            prepare_parked_resume(ParkedContextWords::ZERO, expected),
            Err(ArchError::InvalidContext)
        ));
        for wrong in [
            AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(0x7000)).unwrap(),
                ..expected
            },
            AddressContext {
                mm: MmGeneration::new(NonZeroU64::new(12).unwrap()),
                ..expected
            },
            AddressContext {
                generation: ContextGeneration::new(NonZeroU64::new(8).unwrap()),
                ..expected
            },
        ] {
            assert!(matches!(
                prepare_parked_resume(words, wrong),
                Err(ArchError::InvalidContext)
            ));
        }
        for (index, value) in [
            (15, 0),
            (16, 8),
            (17, 0x3002),
            (17, 1 << 20 | 2),
            (18, 1 << 47),
            (19, 16),
        ] {
            let mut invalid = words;
            invalid.frame[index] = value;
            assert!(
                matches!(
                    prepare_parked_resume(invalid, expected),
                    Err(ArchError::InvalidContext)
                ),
                "IRET field {index}"
            );
        }
    }

    #[test]
    fn resume_refuses_wrmsr_and_xrstor_faults_before_hardware() {
        let (words, expected) = fixture();
        for (index, value) in [(512, 8), (520, 1), (528, 1), (575, 1), (26, 1)] {
            let mut invalid = words;
            invalid.xsave[index] = value;
            assert!(
                matches!(
                    prepare_parked_resume(invalid, expected),
                    Err(ArchError::InvalidContext)
                ),
                "XSAVE field {index}"
            );
        }
        for (fs_base, gs_base) in [(1 << 47, 0), (0, 1 << 47), (0xffff_0000_0000_0000, 0)] {
            let invalid = ParkedContextWords::from_parts(
                words.frame,
                expected,
                fs_base,
                gs_base,
                words.xsave,
            );
            assert!(matches!(
                prepare_parked_resume(invalid, expected),
                Err(ArchError::InvalidContext)
            ));
        }
    }
}
