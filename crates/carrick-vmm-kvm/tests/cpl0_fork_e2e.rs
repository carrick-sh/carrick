//! Static ELF fork/wait/COW witness through the shared CPL0 kernel.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

use carrick_mem::x86_initial_image::prepare_static_x86_elf;
use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
use carrick_x86::cpl0_entry::OBSERVE_INITIAL_MM;
use std::path::PathBuf;

fn image() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/x86_64-unknown-none/release/carrick-x86-cpl0-fixture")
}

fn fork_wait_elf() -> Vec<u8> {
    let mut bytes = vec![0; 0x110];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0040_00b0_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0x110u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    // x86_64: write 0x5a to the stack, fork(2), child writes 0xa5 and
    // exit_group(3); parent wait4(2)s, checks its COW stack byte, and exits
    // with WEXITSTATUS + 4. The wrong COW value exits 9.
    let code = [
        0xc6, 0x44, 0x24, 0xf0, 0x5a, 0xb8, 0x39, 0, 0, 0, 0x0f, 0x05, 0x85, 0xc0, 0x74, 0x39,
        0x89, 0xc7, 0x48, 0x8d, 0x74, 0x24, 0xf8, 0x31, 0xd2, 0x45, 0x31, 0xd2, 0xb8, 0x3d, 0, 0,
        0, 0x0f, 0x05, 0x80, 0x7c, 0x24, 0xf0, 0x5a, 0x75, 0x13, 0x8b, 0x44, 0x24, 0xf8, 0xc1,
        0xe8, 0x08, 0x83, 0xc0, 0x04, 0x89, 0xc7, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0xbf, 0x09, 0,
        0, 0, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0xc6, 0x44, 0x24, 0xf0, 0xa5, 0xbf, 0x03, 0, 0, 0,
        0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ];
    bytes[0xb0..0xb0 + code.len()].copy_from_slice(&code);
    bytes
}

fn fork_wait_elf_with_nonblocking_probe() -> Vec<u8> {
    let mut bytes = fork_wait_elf();
    let code_start = 0xb0;
    let parent_start = code_start + 16;
    // Preserve fork's child pid in EBX. Linux wait4(child, NULL, WNOHANG)
    // must return zero while that child is still runnable, and must leave
    // the parent's status slot for the later blocking wait untouched.
    let probe = [
        0x89, 0xc3, 0x89, 0xdf, 0x31, 0xf6, 0xba, 1, 0, 0, 0, 0x45, 0x31, 0xd2, 0xb8, 61, 0, 0, 0,
        0x0f, 0x05, 0x85, 0xc0, 0x75, 0,
    ];
    bytes.splice(parent_start..parent_start, probe);
    bytes[parent_start + probe.len() + 1] = 0xdf; // blocking wait pid: EBX
    // The completed blocking wait must consume the zombie. A second wait for
    // that child returns -ECHILD, even with a NULL status address.
    let wait_opcode = [0xb8, 61, 0, 0, 0, 0x0f, 0x05];
    let wait_end = bytes
        .windows(wait_opcode.len())
        .enumerate()
        .filter(|(_, window)| *window == wait_opcode)
        .nth(1)
        .map(|(index, _)| index + wait_opcode.len())
        .expect("blocking wait4 opcode");
    let rewait = [
        0x89, 0xdf, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2, 0xb8, 61, 0, 0, 0, 0x0f, 0x05, 0x83,
        0xf8, 0xf6, 0x75, 0,
    ];
    bytes.splice(wait_end..wait_end, rewait);
    bytes[code_start + 15] = 0x39 + (probe.len() + rewait.len()) as u8;
    let failure = bytes
        .windows(7)
        .position(|window| window == [0xbf, 9, 0, 0, 0, 0xb8, 0xe7])
        .expect("ELF failure exit");
    for jump_end in [parent_start + probe.len(), wait_end + rewait.len()] {
        bytes[jump_end - 1] = (failure - jump_end) as u8;
    }
    let file_size = bytes.len() as u64;
    bytes[96..104].copy_from_slice(&file_size.to_le_bytes());
    bytes
}

#[test]
fn static_elf_fork_child_cow_wait_and_parent_exit_seven() {
    let elf = fork_wait_elf();
    let plan = prepare_static_x86_elf(&elf).expect("shared static ELF plan");
    assert_eq!(plan.entry, 0x4000b0);
    let program = initial_process_program(&elf);
    let mut carrier =
        Cpl0Carrier::boot_lifecycle(&image(), [&program, &program]).expect("real KVM image");
    carrier
        .arm_user_fault_stack_canary()
        .expect("arm vCPU0 fault stack boundary");
    let observed = carrier.observe(0).expect("fork, wait4 and exit");
    assert!(
        carrier
            .user_fault_stack_canary_intact()
            .expect("read fault stack boundary"),
        "user #PF xstate or Rust call crossed the 4 KiB TSS fault stack"
    );
    assert_eq!(observed.result, 7);
    assert_eq!(observed.semantic_host_exits, 0);
    let state = carrier
        .lifecycle_state(0)
        .expect("zone lifecycle after parent exit");
    assert_eq!(state.births, 1);
    assert_eq!(state.retirements, 1);
    assert_eq!(state.wakes, 1);
    assert_eq!(state.live, 1);
}

fn initial_process_program(elf: &[u8]) -> Vec<u8> {
    let mut program = vec![0x48, 0xbf];
    program.extend_from_slice(&0x10100u64.to_le_bytes());
    program.extend_from_slice(&[0x48, 0xbe]);
    program.extend_from_slice(&(elf.len() as u64).to_le_bytes());
    program.extend_from_slice(&[0x48, 0xba]); // mov rdx, fixture process lane
    program.extend_from_slice(&1u64.to_le_bytes());
    program.extend_from_slice(&[0x48, 0xb8]);
    program.extend_from_slice(&OBSERVE_INITIAL_MM.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
    program.resize(0x100, 0x90);
    program.extend_from_slice(elf);
    program
}

#[test]
fn static_elf_wait4_wnohang_reap_then_echild() {
    let elf = fork_wait_elf_with_nonblocking_probe();
    let program = initial_process_program(&elf);
    let mut carrier =
        Cpl0Carrier::boot_lifecycle(&image(), [&program, &program]).expect("real KVM image");
    let observed = carrier.observe(0).expect("nonblocking then blocking wait4");
    assert_eq!(observed.result, 7);
    assert_eq!(observed.semantic_host_exits, 0);
}
