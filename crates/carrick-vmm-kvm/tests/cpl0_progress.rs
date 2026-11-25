//! Executing CPL0 bindings for kernel.scheduler.runnable-progress and
//! kernel.vcpu.kick-el0-boundary. One vCPU, two shared scheduler records,
//! private CR3s at the same VA, syscall-free compute, real LAPIC preemption.
//! No KVM/image skips, Docker, retries, host task waits or timing claims.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "common/physical_inventory.rs"]
mod physical_inventory;
use physical_inventory::physical_inventory;

use carrick_el1_abi::{
    X86_CPL0_SUPERVISOR_IMAGE_BASE, X86_CPL0_SUPERVISOR_IMAGE_EXTENT, X86_CPL0_SUPERVISOR_IMAGE_GPA,
};
use carrick_vmm_kvm::carrier_interrupts::{KickBoundary, SECOND_ROOT, witness};
use carrick_x86::cpl0_scheduler::*;
use std::path::{Path, PathBuf};

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

fn first_program() -> Vec<u8> {
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
    first
}

fn progress(boundary: KickBoundary) {
    progress_with_image(
        &PathBuf::from(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE")),
        boundary,
    );
}

fn progress_with_image(image: &Path, boundary: KickBoundary) {
    let first = first_program();
    let observed = witness(physical_inventory(), image, [&first, COMPUTE], boundary)
        .expect("bounded live KVM CPL0 progress");
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
        if turn >= 2 {
            // A LAPIC interrupt can arrive before the next user instruction;
            // that is a valid preemption, not a lost scheduler turn. The
            // per-task counter must never go backwards across a context save.
            assert!(
                observed.iterations[turn] >= observed.iterations[turn - 2],
                "preempted compute preserves progress: turn {turn}, current {}, previous {}",
                observed.iterations[turn],
                observed.iterations[turn - 2]
            );
        }
    }
    for index in 0..2 {
        let data = &observed.data[index];
        assert!(word(data, 0) > 0, "both same-VA private pages progressed");
        assert!(
            observed
                .order
                .iter()
                .enumerate()
                .any(|(turn, &task)| task == index as u64 && observed.iterations[turn] > 0),
            "each runnable task executes user compute under preemption"
        );
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

fn patched_progress_image(
    dir: &Path,
    high_trampoline: bool,
    override_slot: Option<(usize, u64)>,
) -> (PathBuf, [u64; 3]) {
    let source = PathBuf::from(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"));
    let mut bytes = std::fs::read(&source).expect("read fixture ELF");
    let u16_at = |buf: &[u8], at: usize| u16::from_le_bytes(buf[at..at + 2].try_into().unwrap());
    let u32_at = |buf: &[u8], at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
    let u64_at = |buf: &[u8], at: usize| u64::from_le_bytes(buf[at..at + 8].try_into().unwrap());
    let phoff = usize::try_from(u64_at(&bytes, 0x20)).unwrap();
    let phentsize = usize::from(u16_at(&bytes, 0x36));
    let phnum = usize::from(u16_at(&bytes, 0x38));
    let phdrs: Vec<usize> = (0..phnum).map(|i| phoff + i * phentsize).collect();
    let header_va =
        X86_CPL0_SUPERVISOR_IMAGE_BASE + (PROGRESS_HEADER - X86_CPL0_SUPERVISOR_IMAGE_GPA);
    let hdr_ph = phdrs
        .iter()
        .copied()
        .find(|&p| {
            u32_at(&bytes, p) == 1
                && u64_at(&bytes, p + 0x10) <= header_va
                && header_va + 32 <= u64_at(&bytes, p + 0x10) + u64_at(&bytes, p + 0x20)
        })
        .expect("progress header PT_LOAD");
    let hdr_off = usize::try_from(
        u64_at(&bytes, hdr_ph + 0x08) + (header_va - u64_at(&bytes, hdr_ph + 0x10)),
    )
    .unwrap();
    assert_eq!(u64_at(&bytes, hdr_off), PROGRESS_MAGIC);
    let mut entries = [
        u64_at(&bytes, hdr_off + 8),
        u64_at(&bytes, hdr_off + 16),
        u64_at(&bytes, hdr_off + 24),
    ];
    if high_trampoline {
        // The fixture reserves this slot (`carrick-x86-cpl0/src/progress.rs`,
        // placed last in `.text` by `link.ld`), so patching it moves no
        // segment bounds and depends on no trailing page slack.
        let elf = goblin::elf::Elf::parse(&bytes).expect("fixture ELF symbols");
        let slot = elf
            .syms
            .iter()
            .find(|sym| elf.strtab.get_at(sym.st_name) == Some("carrick_progress_trampoline"))
            .expect("fixture reserves carrick_progress_trampoline");
        let tramp_va = slot.st_value;
        assert_eq!(slot.st_size, 24, "three 8-byte jump stubs");
        assert!(tramp_va >= 0xffff_ffff_800f_0000, "slot above 960 KiB");
        assert!(X86_CPL0_SUPERVISOR_IMAGE_EXTENT.contains(&(tramp_va + 23)));
        let text = elf
            .program_headers
            .iter()
            .find(|p| {
                p.p_type == goblin::elf::program_header::PT_LOAD
                    && p.is_executable()
                    && p.p_vaddr <= tramp_va
                    && tramp_va + 24 <= p.p_vaddr + p.p_filesz
            })
            .expect("slot inside an executable PT_LOAD's file bytes");
        let tramp_off = usize::try_from(text.p_offset + (tramp_va - text.p_vaddr)).unwrap();
        assert_eq!(
            bytes[tramp_off..tramp_off + 24],
            [0xcc; 24],
            "reserved slot is int3 fill"
        );
        for (i, target) in entries.iter_mut().enumerate() {
            let stub_va = tramp_va + (i as u64) * 8;
            let stub_off = tramp_off + i * 8;
            let rel = i32::try_from(*target as i128 - (stub_va as i128 + 5))
                .expect("rel32 jump inside 2 MiB image");
            bytes[stub_off] = 0xe9;
            bytes[stub_off + 1..stub_off + 5].copy_from_slice(&rel.to_le_bytes());
            *target = stub_va;
        }
    }
    if let Some((slot, addr)) = override_slot {
        entries[slot] = addr;
    }
    for (i, addr) in entries.iter().enumerate() {
        bytes[hdr_off + 8 + i * 8..hdr_off + 16 + i * 8].copy_from_slice(&addr.to_le_bytes());
    }
    let out = dir.join("carrick-x86-cpl0-fixture");
    std::fs::write(&out, &bytes).expect("write patched fixture ELF");
    (out, entries)
}

#[test]
fn entry_and_interrupt_handlers_above_960_kib_progress_under_kvm() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (image, entries) = patched_progress_image(dir.path(), true, None);
    for addr in entries {
        assert!(
            addr >= 0xffff_ffff_800f_0000 && X86_CPL0_SUPERVISOR_IMAGE_EXTENT.contains(&addr),
            "expected patched PC in [0xffffffff800f0000, 0xffffffff80200000), got {addr:#x}"
        );
    }
    progress_with_image(&image, KickBoundary::Entry);
}

#[test]
fn exclusive_supervisor_extent_end_is_rejected_before_guest_execution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = first_program();
    let end = X86_CPL0_SUPERVISOR_IMAGE_EXTENT.end;
    for slot in 0..3 {
        let (image, _) = patched_progress_image(dir.path(), false, Some((slot, end)));
        let err = witness(
            physical_inventory(),
            &image,
            [&first, COMPUTE],
            KickBoundary::Entry,
        )
        .expect_err("exclusive ABI extent end must be rejected");
        assert!(
            err.to_string()
                .contains("CPL0 progress header/version/entry mismatch"),
            "slot {slot}: unexpected error: {err}"
        );
    }
}
