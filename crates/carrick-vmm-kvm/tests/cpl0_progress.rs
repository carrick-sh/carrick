//! Executing CPL0 bindings for kernel.scheduler.runnable-progress and
//! kernel.vcpu.kick-el0-boundary. One vCPU, two shared scheduler records,
//! private CR3s at the same VA, syscall-free compute, real LAPIC preemption.
//! No KVM/image skips, Docker, retries, host task waits or timing claims.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use carrick_vmm_kvm::carrier_interrupts::{KickBoundary, SECOND_ROOT, witness};
use carrick_x86::cpl0_scheduler::*;
use std::path::PathBuf;

// inc [rax]; inc rbx; read distinct FS/GS words; store YMM15 and FP controls.
// AND/OR every control sample so a transient switch leak survives readback.
// Only RCX (already the GS scratch) is additionally clobbered.
// Contains neither SYSCALL nor a control/semantic doorbell.
const COMPUTE: &[u8] = &[
    0x48, 0xff, 0x00, 0x48, 0xff, 0xc3, 0x64, 0x48, 0x8b, 0x14, 0x25, 0x08, 0, 0, 0, 0x48, 0x89,
    0x50, 0x08, 0x65, 0x48, 0x8b, 0x0c, 0x25, 0x10, 0, 0, 0, 0x48, 0x89, 0x48, 0x10, 0xc5, 0x7e,
    0x7f, 0x78, 0x20, 0xd9, 0x78, 0x40, // fnstcw [rax + 64]
    0x0f, 0xae, 0x58, 0x44, // stmxcsr [rax + 68]
    0x0f, 0xb7, 0x48, 0x40, // movzx ecx, word [rax + 64]
    0x21, 0x48, 0x48, // and [rax + 72], ecx
    0x09, 0x48, 0x4c, // or [rax + 76], ecx
    0x8b, 0x48, 0x44, // mov ecx, [rax + 68]
    0x21, 0x48, 0x50, // and [rax + 80], ecx
    0x09, 0x48, 0x54, // or [rax + 84], ecx
    0xeb, 0xbf, // jmp back to inc [rax]
];
fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn control_word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn control_dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[derive(Debug, Eq, PartialEq)]
struct FpControls {
    executed: (u16, u32),
    every_sample_and: (u32, u32),
    every_sample_or: (u32, u32),
    saved: (u16, u32),
}

fn progress(boundary: KickBoundary) {
    let image = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-none/release/carrick-x86-cpl0");
    let mut first = Vec::new();
    // A real common-kernel entry before the syscall-free compute loop.
    for (opcode, value) in [
        ([0x48, 0xb8], 273u64),
        ([0x48, 0xbf], 0xa000),
        ([0x48, 0xbe], 24),
    ] {
        first.extend_from_slice(&opcode);
        first.extend_from_slice(&value.to_le_bytes());
    }
    first.extend_from_slice(&[0x0f, 0x05]);
    // Restore the compute fixture's initial RAX/RDI/RSI/R11 tags; SYSCALL
    // architecturally clobbers RCX/R11 independently of timer preemption.
    for (opcode, value) in [
        ([0x48, 0xb8], PROGRESS_DATA),
        ([0x48, 0xbf], 0xabce),
        ([0x48, 0xbe], 0xabcd),
        ([0x49, 0xbb], 0xabc6),
    ] {
        first.extend_from_slice(&opcode);
        first.extend_from_slice(&value.to_le_bytes());
    }
    first.extend_from_slice(COMPUTE);
    let observed =
        witness(&image, [&first, COMPUTE], boundary).expect("bounded live KVM CPL0 progress");
    for turn in 0..PROGRESS_TURNS {
        assert_eq!(
            observed.order[turn],
            (turn % 2) as u64,
            "shared FIFO alternation"
        );
        assert_eq!(
            observed.roots[turn],
            if turn % 2 == 0 {
                0x60_0000
            } else {
                SECOND_ROOT
            },
            "live hardware CR3"
        );
        assert!(
            observed.iterations[turn]
                > if turn < 2 {
                    0
                } else {
                    observed.iterations[turn - 2]
                },
            "preempted compute retains progress"
        );
    }
    for index in 0..2 {
        let data = &observed.data[index];
        assert!(word(data, 0) > 0, "both same-VA private pages progressed");
        assert_eq!(word(data, 8), 0xf500 + index as u64, "FS task isolation");
        assert_eq!(word(data, 16), 0x6500 + index as u64, "GS task isolation");
        assert_eq!(
            observed.tls[index],
            (
                PROGRESS_DATA + 0x100 + index as u64 * 0x40,
                PROGRESS_DATA + 0x200 + index as u64 * 0x40
            )
        );
        assert_eq!(
            &data[32..64],
            &[0x31 + index as u8; 32],
            "XMM and YMM upper state survive switching"
        );
        assert_eq!(&observed.xsave[index][400..416], &[0x31 + index as u8; 16]);
        assert_eq!(&observed.xsave[index][816..832], &[0x31 + index as u8; 16]);
        for register in [0, 1, 2, 3, 4, 6, 7, 8, 9, 13, 14] {
            assert_eq!(
                observed.frames[index].gpr[register],
                0xabc0 + index as u64 * 0x100 + register as u64,
                "untouched GPR {register}"
            );
        }
        assert_eq!(
            observed.frames[index].rsp,
            0x3_1ff0 + index as u64 * 0x1_0000
        );
    }
    assert_eq!(observed.wakes, 1, "one shared wake ownership transfer");
    assert_eq!(observed.entries, 1);
    assert_eq!(observed.completions, 1);
    assert_eq!(observed.publications, 1);
    assert_eq!(observed.robust_heads, [(0xa000, 24), (0, 0)]);
    assert_eq!(observed.kick_irqs, 1, "one real LAPIC kick IRQ");
    assert_eq!(observed.timer_irqs, PROGRESS_TURNS as u64);
    assert_eq!(observed.preemptions, PROGRESS_TURNS as u64 - 1);
    assert_eq!(
        observed.control_exits, 3,
        "two boundaries and final observation only"
    );
    assert_eq!(observed.semantic_host_forwards, 0);
    assert_eq!(observed.interrupt_host_exits, 0);

    // Check after every original progress/isolation/budget assertion: the
    // negative control must complete all 16 turns, not merely fail boot.
    let controls: [FpControls; 2] = core::array::from_fn(|index| {
        let data = &observed.data[index];
        let xsave = &observed.xsave[index];
        FpControls {
            executed: (control_word(data, 64), control_dword(data, 68)),
            every_sample_and: (control_dword(data, 72), control_dword(data, 80)),
            every_sample_or: (control_dword(data, 76), control_dword(data, 84)),
            saved: (control_word(xsave, 0), control_dword(xsave, 24)),
        }
    });
    let expected = [(0x077f, 0x3f80), (0x0b7f, 0x5f80)].map(|(x87, mxcsr)| FpControls {
        executed: (x87, mxcsr),
        every_sample_and: (u32::from(x87), mxcsr),
        every_sample_or: (u32::from(x87), mxcsr),
        saved: (x87, mxcsr),
    });
    assert_eq!(
        controls, expected,
        "executed and saved x87/MXCSR isolation across all 16 turns"
    );
}

#[test]
fn entry_kick_and_timer_preempt_two_private_contexts() {
    progress(KickBoundary::Entry);
}
#[test]
fn return_kick_and_timer_preempt_two_private_contexts() {
    progress(KickBoundary::Return);
}
