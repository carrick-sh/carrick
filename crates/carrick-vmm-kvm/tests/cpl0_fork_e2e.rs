//! Static ELF fork/wait/COW witness through the shared CPL0 kernel.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

use carrick_mem::x86_initial_image::prepare_static_x86_elf;
use carrick_vmm_kvm::cpl0_boot::{
    Cpl0Carrier, InitialProcessExit, InitialReservationLimits, InitialSyscallDisposition,
};
use carrick_x86::cpl0_entry::OBSERVE_INITIAL_MM;
use std::path::PathBuf;

fn image() -> PathBuf {
    PathBuf::from(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"))
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

#[test]
fn user_cow_fault_clears_poisoned_xsave_header() {
    let elf = fork_wait_elf_with_child_marker();
    let program = initial_process_program(&elf);
    let mut carrier =
        Cpl0Carrier::boot_lifecycle(&image(), [&program, &program]).expect("real KVM image");
    assert_eq!(carrier.observe(0).expect("child before COW").result, 42);
    carrier
        .poison_user_fault_xsave_header(0)
        .expect("poison reserved header words");
    assert_eq!(
        carrier
            .observe(0)
            .expect("resolved COW restores xstate")
            .result,
        7
    );
    assert_eq!(
        carrier.user_fault_state(0).expect("fault guard released").0,
        0
    );
}

fn fork_wait_elf_with_child_marker() -> Vec<u8> {
    let mut elf = fork_wait_elf();
    let child = elf
        .windows(5)
        .position(|bytes| bytes == [0xc6, 0x44, 0x24, 0xf0, 0xa5])
        .expect("child COW store");
    let mut marker = vec![0xbf, 42, 0, 0, 0, 0x48, 0xb8];
    marker.extend_from_slice(&carrick_x86::cpl0_entry::OBSERVE_NATIVE.to_le_bytes());
    marker.extend_from_slice(&[0x0f, 0x05]);
    elf.splice(child..child, marker);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    elf
}

#[test]
fn wait_any_parks_with_the_issued_child_pid_result() {
    let mut elf = fork_wait_elf_with_child_marker();
    // Override the requested selector after mov edi,eax. The saved wait
    // completion must name child 42, never the -1 selection expression.
    elf.splice(0xb0 + 18..0xb0 + 18, [0xbf, 0xff, 0xff, 0xff, 0xff]);
    elf[0xb0 + 15] += 5;
    let wait_end = elf
        .windows(7)
        .position(|bytes| bytes == [0xb8, 61, 0, 0, 0, 0x0f, 0x05])
        .expect("wait4 opcode")
        + 7;
    elf.splice(wait_end..wait_end, [0x83, 0xf8, 42, 0x75, 0]);
    elf[0xb0 + 15] += 5;
    let failure = elf
        .windows(7)
        .position(|bytes| bytes == [0xbf, 9, 0, 0, 0, 0xb8, 0xe7])
        .expect("failure exit");
    elf[wait_end + 4] = (failure - wait_end - 5) as u8;
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    let program = initial_process_program(&elf);
    let mut carrier =
        Cpl0Carrier::boot_lifecycle(&image(), [&program, &program]).expect("real KVM image");
    assert_eq!(carrier.observe(0).expect("child before COW").result, 42);
    assert_eq!(
        carrier
            .lifecycle_state(0)
            .expect("parked parent")
            .parked_parent_result,
        42
    );
    assert_eq!(
        carrier
            .observe(0)
            .expect("wait4(-1) returns the child status")
            .result,
        7
    );
}

#[test]
fn exhausted_fork_spaces_return_eagain_without_host_forwarding() {
    let mut elf = fork_wait_elf();
    let mut code = vec![0xbf, 42, 0, 0, 0, 0x48, 0xb8];
    code.extend_from_slice(&carrick_x86::cpl0_entry::OBSERVE_NATIVE.to_le_bytes());
    code.extend_from_slice(&[
        0x0f, 0x05, 0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0x83, 0xf8, 0xf5, 0x75, 12, 0xbf, 7, 0, 0, 0,
        0xb8, 231, 0, 0, 0, 0x0f, 0x05, 0xbf, 9, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05, 0x0f,
        0x0b,
    ]);
    elf.truncate(0xb0);
    elf.extend_from_slice(&code);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    let program = initial_process_program(&elf);
    for records in [false, true] {
        let mut carrier = Cpl0Carrier::boot_lifecycle(&image(), [&program, &program]).expect("KVM");
        assert_eq!(carrier.observe(0).expect("before fork").result, 42);
        if records {
            carrier
                .exhaust_lifecycle_capacity(false)
                .expect("fill record table");
        } else {
            carrier
                .exhaust_fork_address_spaces()
                .expect("fill MM table");
        }
        let result = carrier.observe(0).expect("explicit fork capacity result");
        assert_eq!(result.result, 7);
        assert_eq!(result.semantic_host_exits, 0);
        assert_eq!(carrier.lifecycle_state(0).expect("no birth").births, 0);
    }
}

#[test]
fn second_fixture_fork_returns_eagain_before_any_mutation() {
    let mut elf = fork_wait_elf();
    let start = 0xb0 + 16;
    let probe = [
        0x89, 0xc3, 0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0x83, 0xf8, 0xf5, 0x75, 0, 0x89, 0xd8,
    ];
    elf.splice(start..start, probe);
    elf[0xb0 + 15] += probe.len() as u8;
    let fail = elf
        .windows(7)
        .position(|b| b == [0xbf, 9, 0, 0, 0, 0xb8, 231])
        .expect("failure exit");
    elf[start + 13] = (fail - start - 14) as u8;
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    let program = initial_process_program(&elf);
    let mut carrier = Cpl0Carrier::boot_lifecycle(&image(), [&program, &program]).expect("KVM");
    let result = carrier.observe(0).expect("bounded repeated fork");
    assert_eq!(result.result, 7);
    assert_eq!(result.semantic_host_exits, 0);
    assert_eq!(carrier.lifecycle_state(0).expect("one birth").births, 1);
}

#[test]
fn exhausted_wait_entries_leave_record_capacity_unchanged() {
    let mut elf = fork_wait_elf();
    // The child stays queued while the parent repeats failed wait enrollment.
    let mut code = vec![0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0x89, 0xc3];
    let report = |code: &mut Vec<u8>| {
        code.extend_from_slice(&[0xbf, 42, 0, 0, 0, 0x48, 0xb8]);
        code.extend_from_slice(&carrick_x86::cpl0_entry::OBSERVE_NATIVE.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05]);
    };
    report(&mut code);
    let mut failures = Vec::new();
    for _ in 0..3 {
        code.extend_from_slice(&[
            0x89, 0xdf, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2, 0xb8, 61, 0, 0, 0, 0x0f, 0x05,
            0x83, 0xf8, 0xf5, 0x75, 0,
        ]);
        failures.push(code.len() - 1);
        report(&mut code);
    }
    code.extend_from_slice(&[0xbf, 7, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05]);
    let failure = code.len();
    code.extend_from_slice(&[0xbf, 9, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05]);
    for branch in failures {
        code[branch] = i8::try_from(failure - branch - 1).expect("short branch") as u8;
    }
    elf.truncate(0xb0);
    elf.extend_from_slice(&code);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    let program = initial_process_program(&elf);
    let mut carrier = Cpl0Carrier::boot_lifecycle(&image(), [&program, &program]).expect("KVM");
    assert_eq!(carrier.observe(0).expect("before wait4").result, 42);
    carrier
        .exhaust_lifecycle_capacity(true)
        .expect("fill wait entries");
    let capacity = carrier
        .lifecycle_record_capacity()
        .expect("initial capacity");
    for _ in 0..3 {
        assert_eq!(carrier.observe(0).expect("wait EAGAIN").result, 42);
        assert_eq!(
            carrier
                .lifecycle_record_capacity()
                .expect("remaining capacity"),
            capacity,
            "failed wait4 must return its unpublished home record"
        );
    }
    let result = carrier.observe(0).expect("explicit wait capacity error");
    assert_eq!(result.result, 7);
    assert_eq!(result.semantic_host_exits, 0);
    assert_eq!(carrier.lifecycle_state(0).expect("no wake").wakes, 0);
}

fn wait_rusage_elf(burn: bool) -> Vec<u8> {
    fn jump(code: &mut Vec<u8>, condition: u8) -> usize {
        code.extend_from_slice(&[0x0f, condition]);
        let patch = code.len();
        code.extend_from_slice(&[0; 4]);
        patch
    }
    fn patch(code: &mut [u8], at: usize, target: usize) {
        let displacement = i32::try_from(target).expect("fixture target")
            - i32::try_from(at + 4).expect("fixture branch");
        code[at..at + 4].copy_from_slice(&displacement.to_le_bytes());
    }
    let mut elf = fork_wait_elf();
    let mut code = vec![0xc6, 0x44, 0x24, 0xf0, 0x5a];
    // Save the elapsed invariant-TSC bound before fork (R13).
    code.extend_from_slice(&[
        0x0f, 0x31, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x49, 0x89, 0xc5,
    ]);
    code.extend_from_slice(&[0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0x85, 0xc0]);
    let fork_failure = jump(&mut code, 0x88);
    let child_jump = jump(&mut code, 0x84);
    code.extend_from_slice(&[
        0x89, 0xc3, 0x48, 0x8d, 0xbc, 0x24, 0, 0xff, 0xff, 0xff, 0xb9, 144, 0, 0, 0, 0xb0, 0xa5,
        0xf3, 0xaa, 0x89, 0xdf, 0x48, 0x8d, 0x74, 0x24, 0xf8, 0x31, 0xd2, 0x4c, 0x8d, 0x94, 0x24,
        0, 0xff, 0xff, 0xff, 0xb8, 61, 0, 0, 0, 0x0f, 0x05,
    ]);
    let mut failures = vec![fork_failure];
    code.extend_from_slice(&[0x85, 0xc0]);
    failures.push(jump(&mut code, 0x8e)); // wait must return a child PID
    // Convert elapsed TSC to microseconds using the existing boot CPUID 15
    // clock calibration (ratio 1:1, ECX = frequency). No host clock forward.
    code.extend_from_slice(&[
        0x0f, 0x31, 0x48, 0xc1, 0xe2, 32, 0x48, 0x09, 0xd0, 0x4c, 0x29, 0xe8, 0x49, 0x89, 0xc5,
        0xb8, 15, 0, 0, 0, 0x31, 0xc9, 0x0f, 0xa2, 0x85, 0xc9,
    ]);
    failures.push(jump(&mut code, 0x84));
    code.extend_from_slice(&[
        0x4c, 0x89, 0xe8, 0xbf, 0x40, 0x42, 0x0f, 0, 0x48, 0xf7, 0xe7, 0x48, 0xf7, 0xf1, 0x49,
        0x89, 0xc5, 0x45, 0x31, 0xe4,
    ]);
    // Both timevals are nonnegative, normalized and bounded by elapsed time.
    for displacement in [0xffff_ff00_u32, 0xffff_ff10_u32] {
        code.extend_from_slice(&[0x48, 0x8b, 0x84, 0x24]);
        code.extend_from_slice(&displacement.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x85, 0xc0]);
        failures.push(jump(&mut code, 0x88));
        code.extend_from_slice(&[0x48, 0x83, 0xf8, 5]);
        failures.push(jump(&mut code, 0x87));
        code.extend_from_slice(&[
            0x48, 0x69, 0xc0, 0x40, 0x42, 0x0f, 0, 0x48, 0x8b, 0x94, 0x24,
        ]);
        code.extend_from_slice(&(displacement + 8).to_le_bytes());
        code.extend_from_slice(&[0x48, 0x81, 0xfa, 0x40, 0x42, 0x0f, 0]);
        failures.push(jump(&mut code, 0x83));
        code.extend_from_slice(&[0x48, 0x01, 0xd0, 0x49, 0x01, 0xc4]);
    }
    code.extend_from_slice(&[0x4d, 0x39, 0xec]);
    failures.push(jump(&mut code, 0x87));
    if burn {
        code.extend_from_slice(&[0x4d, 0x85, 0xe4]);
        failures.push(jump(&mut code, 0x84));
    }
    code.extend_from_slice(&[
        0x48, 0x8d, 0xbc, 0x24, 0x20, 0xff, 0xff, 0xff, 0xb9, 112, 0, 0, 0, 0x31, 0xc0, 0xf3, 0xae,
    ]);
    failures.push(jump(&mut code, 0x85));
    code.extend_from_slice(&[0x80, 0x7c, 0x24, 0xf0, 0x5a]);
    failures.push(jump(&mut code, 0x85));
    code.extend_from_slice(&[0x81, 0x7c, 0x24, 0xf8, 0, 3, 0, 0]);
    failures.push(jump(&mut code, 0x85));
    code.extend_from_slice(&[0xbf, 7, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b]);
    for (index, at) in failures.into_iter().enumerate() {
        let failure = code.len();
        patch(&mut code, at, failure);
        if index <= 1 {
            // A failed wait reports its Linux errno number for diagnosis.
            code.extend_from_slice(&[0x89, 0xc7, 0xf7, 0xdf]);
        } else {
            code.extend_from_slice(&[
                0xbf,
                u8::try_from(20 + index).expect("failure tag"),
                0,
                0,
                0,
            ]);
        }
        code.extend_from_slice(&[0xb8, 231, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b]);
    }
    let child = code.len();
    if burn {
        code.extend_from_slice(&[0xb9]);
        code.extend_from_slice(&1_000_000_u32.to_le_bytes());
        code.extend_from_slice(&[0xf3, 0x90, 0xff, 0xc9, 0x75, 0xfa]);
    }
    code.extend_from_slice(&[
        0xc6, 0x44, 0x24, 0xf0, 0xa5, 0xbf, 3, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    patch(&mut code, child_jump, child);
    elf.truncate(0xb0);
    elf.extend_from_slice(&code);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    elf
}

fn run_production_wait_elf(elf: &[u8]) -> i32 {
    let plan = prepare_static_x86_elf(elf).expect("wait ELF");
    let extent = Cpl0Carrier::initial_extent_bytes_for(&plan, &[], &[]).expect("wait extent");
    let mut carrier = Cpl0Carrier::boot_production(extent).expect("production KVM");
    carrier
        .load_guest_mm(&plan, &[], &[], InitialReservationLimits::UNLIMITED)
        .expect("initial MM");
    let result = carrier
        .run_initial_process(64, |_, _| Ok(InitialSyscallDisposition::Return(-1)))
        .expect("native wait and exit");
    let code = match result {
        InitialProcessExit::Exited { code, .. } => Some(code),
        _ => None,
    }
    .expect("wait guest exits normally");
    assert_eq!(
        carrier.initial_execution_witness().1,
        0,
        "no semantic host forwards"
    );
    code
}

#[test]
fn wait4_normalizes_owned_timevals_and_zeroes_untracked_fields() {
    assert_eq!(run_production_wait_elf(&wait_rusage_elf(false)), 7);
}

#[test]
fn wait4_cpu_burning_child_reports_owned_usage() {
    assert_eq!(run_production_wait_elf(&wait_rusage_elf(true)), 7);
}

#[test]
fn wait4_rejects_unwritable_rusage_without_writing_status() {
    let mut elf = fork_wait_elf();
    let sentinel = [0xc7, 0x44, 0x24, 0xf8, 0xa5, 0xa5, 0xa5, 0xa5];
    elf.splice(0xb0 + 18..0xb0 + 18, sentinel);
    let r10 = elf
        .windows(3)
        .position(|b| b == [0x45, 0x31, 0xd2])
        .expect("rusage argument");
    let mut pointer = vec![0x49, 0xba];
    pointer.extend_from_slice(&0xdead000u64.to_le_bytes());
    elf.splice(r10..r10 + 3, pointer.iter().copied());
    let wait_end = elf
        .windows(7)
        .position(|b| b == [0xb8, 61, 0, 0, 0, 0x0f, 0x05])
        .expect("wait4")
        + 7;
    // EFAULT must preserve the status sentinel and leave the child waitable.
    // Repeat with a null rusage and let the original parent verify exit status.
    let check = [
        0x83, 0xf8, 0xf2, 0x0f, 0x85, 0, 0, 0, 0, 0x81, 0x7c, 0x24, 0xf8, 0xa5, 0xa5, 0xa5, 0xa5,
        0x0f, 0x85, 0, 0, 0, 0, 0x45, 0x31, 0xd2, 0xb8, 61, 0, 0, 0, 0x0f, 0x05,
    ];
    elf.splice(wait_end..wait_end, check);
    elf[0xb0 + 15] += (sentinel.len() + pointer.len() - 3 + check.len()) as u8;
    let failure = elf
        .windows(7)
        .position(|b| b == [0xbf, 9, 0, 0, 0, 0xb8, 231])
        .expect("failure");
    for displacement in [5, 19] {
        let at = wait_end + displacement;
        let relative =
            i32::try_from(failure).expect("target") - i32::try_from(at + 4).expect("branch");
        elf[at..at + 4].copy_from_slice(&relative.to_le_bytes());
    }
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    assert_eq!(run_production_wait_elf(&elf), 7);
}

#[test]
fn wait4_without_an_admitted_child_returns_echild() {
    let mut elf = fork_wait_elf();
    let code = [
        0xbf, 0xff, 0xff, 0xff, 0xff, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2, 0xb8, 61, 0, 0, 0,
        0x0f, 0x05, 0x83, 0xf8, 0xf6, 0x75, 12, 0xbf, 7, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05,
        0xbf, 9, 0, 0, 0, 0xb8, 231, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ];
    elf.truncate(0xb0);
    elf.extend_from_slice(&code);
    let size = elf.len() as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    let program = initial_process_program(&elf);
    let mut carrier = Cpl0Carrier::boot_lifecycle(&image(), [&program, &program]).expect("KVM");
    assert_eq!(carrier.observe(0).expect("no admitted child").result, 7);
    assert_eq!(carrier.lifecycle_state(0).expect("no birth").births, 0);
}
