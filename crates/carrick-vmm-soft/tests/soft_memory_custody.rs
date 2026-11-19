//! The soft CPU's memory view keeps the slot backings it translates
//! through alive (#671 M1-3 review P0-1). Safe code that swaps two stopped
//! carriers' custodies and drops one must not leave a soft CPU reading
//! freed host memory.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::panic)]

use carrick_guest_arch::FrameGpa;
use carrick_softcpu_x86::SoftMachineExit;
use carrick_vmm_soft::{SoftBootImage, SoftCarrier};
use carrick_x86_cpl0_host::cpl0_boot::{Cpl0BootCarrier, KernelEntry, USER_CODE};

mod common;
use common::inventory;

const FIXTURE: &[u8] = include_bytes!(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"));
const MAX_BLOCKS: u64 = 1_000;
/// `mov edi, 7; mov eax, 231 (exit_group); syscall; ud2`.
const EXIT_SEVEN: &[u8] = &[
    0xbf, 7, 0, 0, 0, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
];

fn boot() -> SoftCarrier {
    boot_with_program(EXIT_SEVEN)
}

fn boot_with_program(program: &[u8]) -> SoftCarrier {
    SoftCarrier::boot(
        inventory(),
        SoftBootImage {
            elf: FIXTURE,
            programs: [program, EXIT_SEVEN],
            initial_extent_bytes: None,
            fixture_image: true,
            ipc: None,
        },
        MAX_BLOCKS,
    )
    .expect("soft fixture boot")
}

#[test]
fn stopped_host_write_replaces_a_cached_instruction() {
    // mov eax, 7; out 0x80, eax; jmp back to mov. Two visits to the same
    // translated block with no intervening ring work to evict it.
    let mut carrier = boot_with_program(&[0xb8, 7, 0, 0, 0, 0xe7, 0x80, 0xeb, 0xf7]);
    carrier
        .enter_kernel(
            0,
            KernelEntry {
                rip: USER_CODE,
                rdi: 0,
                rsp: 0,
                gs_base: 0,
            },
        )
        .expect("enter fixture code at CPL0 for port I/O");
    let assert_exit = |exit, expected| {
        assert!(
            matches!(exit, Some(SoftMachineExit::IoOut { port: 0x80, value, .. }) if value == expected),
            "expected {expected}, got {exit:?}"
        );
    };
    assert_exit(carrier.run(), 7);
    carrier
        .custody_mut()
        .memory_mut()
        .write(FrameGpa::new(USER_CODE + 1), &[9])
        .expect("stopped physical write");
    assert_exit(carrier.run(), 9);
}

/// The slot-0 fixture program, read through the soft CPU's translation.
fn program_bytes(carrier: &mut SoftCarrier) -> [u8; EXIT_SEVEN.len()] {
    let mut bytes = [0; EXIT_SEVEN.len()];
    carrier
        .read_guest_bytes(USER_CODE, &mut bytes)
        .expect("program bytes translate");
    bytes
}

#[test]
fn soft_cpu_memory_outlives_a_swapped_and_dropped_custody() {
    let mut first = boot();
    let mut second = boot();
    assert_eq!(program_bytes(&mut first), EXIT_SEVEN);
    // Safe code may exchange two carriers' custodies through the shared
    // boot seam; `second` now owns the registrations `first`'s CPU uses.
    std::mem::swap(first.custody_mut(), second.custody_mut());
    drop(second);
    assert_eq!(program_bytes(&mut first), EXIT_SEVEN);
}
