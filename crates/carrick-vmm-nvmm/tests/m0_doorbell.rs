//! M0 doorbell smoke (NetBSD/NVMM, runs on VM 201 as root).
//!
//! Opens NVMM, creates a machine + vCPU, maps a guest RAM region (userspace
//! HVA → GPA 0x1000), writes a hand-built stub that does `out %al,$0xC5`
//! (then `hlt`), programs a minimal real-mode vCPU context whose RIP points at
//! the stub, runs the vCPU, and asserts the exit is `NVMM_VCPU_EXIT_IO` with
//! `port == 0xC5`. This proves state-programming + the syscall doorbell + the
//! run loop on real nested NVMM.
//!
//! Also records the M1 RIP-advance finding: whether the IO exit hands back a
//! next-PC (`io.npc`) so we can resume past the `out` without manually adding
//! the instruction length.
//!
//! Gated `cfg(target_os = "netbsd")` so the crate compiles to nothing (and the
//! test is absent) on the default macOS/Linux workspace build.
#![cfg(target_os = "netbsd")]

use carrick_vmm_nvmm::nvmm::{
    self, NVMM_PROT_EXEC, NVMM_PROT_READ, NVMM_PROT_WRITE, NVMM_VCPU_EXIT_HALTED,
    NVMM_VCPU_EXIT_IO, NVMM_VCPU_EXIT_NONE, NVMM_X64_GPR_RAX, NVMM_X64_GPR_RIP, NVMM_X64_NSEG,
    NVMM_X64_SEG_CS, NVMM_X64_SEG_DS, NVMM_X64_SEG_ES, NVMM_X64_SEG_FS, NVMM_X64_SEG_GS,
    NVMM_X64_SEG_SS, NVMM_X64_STATE_GPRS, NVMM_X64_STATE_SEGS, NvmmX64StateSeg,
};

/// The doorbell stub at GPA 0x1000:
///   b0 c5         mov  $0xc5, %al
///   e6 c5         out  %al, $0xc5     <- surfaces as NVMM_VCPU_EXIT_IO port 0xC5
///   f4            hlt                 <- if we resume, this halts cleanly
const STUB: &[u8] = &[0xb0, 0xc5, 0xe6, 0xc5, 0xf4];
/// Real mode needs an operand-size prefix to make E7 emit EAX instead of AX.
const EAX_PAYLOAD_STUB: &[u8] = &[0xb8, 0x78, 0x56, 0x34, 0x12, 0x66, 0xe7, 0xc7, 0xf4];

const GUEST_GPA: u64 = 0x1000;
const RAM_SIZE: usize = 0x1000; // one page is enough for the stub

/// Build a flat 16-bit real-mode segment descriptor (base 0, 64K limit).
fn real_mode_seg(selector: u16, attrib: u16) -> NvmmX64StateSeg {
    NvmmX64StateSeg {
        selector,
        attrib,
        limit: 0xFFFF,
        base: 0,
    }
}

/// Present, accessed, readable real-mode code segment.
fn real_mode_code_seg(selector: u16) -> NvmmX64StateSeg {
    // attrib bitfield: type:4, s:1, dpl:2, p:1, avl:1, l:1, def:1, g:1, rsvd:4.
    // type=0b1011 (code, accessed, readable), s=1, dpl=0, p=1 => 0x9B.
    real_mode_seg(selector, 0x009B)
}

/// Present, accessed, writable real-mode data segment.
fn real_mode_data_seg(selector: u16) -> NvmmX64StateSeg {
    // type=0b0011 (data, accessed, writable), s=1, dpl=0, p=1 => 0x93.
    real_mode_seg(selector, 0x0093)
}

fn program_real_mode_stub(stub: &[u8]) -> (nvmm::NvmmMachine, carrick_vmm_nvmm::nvmm::NvmmVcpu) {
    nvmm::init().expect("nvmm_init (modload nvmm if ENXIO; run as root)");

    let mut mach = nvmm::NvmmMachine::create().expect("nvmm_machine_create");
    let hva = mach
        .map_guest_ram(
            GUEST_GPA,
            RAM_SIZE,
            NVMM_PROT_READ | NVMM_PROT_WRITE | NVMM_PROT_EXEC,
        )
        .expect("map_guest_ram (mmap + hva_map + gpa_map)");

    // SAFETY: `hva` points at a live RAM_SIZE region we own; each stub fits.
    unsafe {
        std::ptr::copy_nonoverlapping(stub.as_ptr(), hva, stub.len());
    }

    let mut vcpu = mach.create_vcpu(0).expect("nvmm_vcpu_create");
    let mut state = vcpu
        .get_state(NVMM_X64_STATE_SEGS | NVMM_X64_STATE_GPRS)
        .expect("nvmm_vcpu_getstate (initial)");

    let flat = real_mode_data_seg(0);
    for i in 0..NVMM_X64_NSEG {
        state.segs[i] = flat;
    }
    state.segs[NVMM_X64_SEG_CS] = real_mode_code_seg(0xf000);
    state.segs[NVMM_X64_SEG_SS] = real_mode_data_seg(0);
    state.segs[NVMM_X64_SEG_DS] = real_mode_data_seg(0);
    state.segs[NVMM_X64_SEG_ES] = real_mode_data_seg(0);
    state.segs[NVMM_X64_SEG_FS] = real_mode_data_seg(0);
    state.segs[NVMM_X64_SEG_GS] = real_mode_data_seg(0);
    state.gprs[NVMM_X64_GPR_RIP] = GUEST_GPA;

    vcpu.set_state(&state, NVMM_X64_STATE_SEGS | NVMM_X64_STATE_GPRS)
        .expect("nvmm_vcpu_setstate (segs+gprs)");

    (mach, vcpu)
}

#[test]
fn m0_doorbell_out_0xc5() {
    nvmm::init().expect("nvmm_init (modload nvmm if ENXIO; run as root)");

    let cap = nvmm::capability().expect("nvmm_capability");
    eprintln!(
        "NVMM cap: version={} state_size={} max_machines={} max_vcpus={} max_ram={:#x}",
        cap.version, cap.state_size, cap.max_machines, cap.max_vcpus, cap.max_ram
    );

    let mut mach = nvmm::NvmmMachine::create().expect("nvmm_machine_create");
    eprintln!("machine created: machid={}", mach.machid());

    let hva = mach
        .map_guest_ram(
            GUEST_GPA,
            RAM_SIZE,
            NVMM_PROT_READ | NVMM_PROT_WRITE | NVMM_PROT_EXEC,
        )
        .expect("map_guest_ram (mmap + hva_map + gpa_map)");
    eprintln!(
        "guest RAM mapped: hva={:p} gpa={:#x} size={:#x}",
        hva, GUEST_GPA, RAM_SIZE
    );

    // Write the stub at the start of the mapped page (== GPA 0x1000).
    // SAFETY: `hva` points at a live RAM_SIZE region we own; STUB fits.
    unsafe {
        std::ptr::copy_nonoverlapping(STUB.as_ptr(), hva, STUB.len());
    }

    let mut vcpu = mach.create_vcpu(0).expect("nvmm_vcpu_create");
    eprintln!("vcpu created: cpuid={}", vcpu.cpuid());

    // Program a minimal real-mode context: flat segments (base 0), RIP at the
    // stub. We start from whatever the kernel reset state is, then overwrite
    // the segments + GPRs we care about and push SEGS|GPRS.
    let mut state = vcpu
        .get_state(NVMM_X64_STATE_SEGS | NVMM_X64_STATE_GPRS)
        .expect("nvmm_vcpu_getstate (initial)");

    // Flat real-mode segments so a near fetch at linear == RIP works.
    let flat = real_mode_data_seg(0);
    for i in 0..NVMM_X64_NSEG {
        state.segs[i] = flat;
    }
    // CS/SS/DS/ES/FS/GS all flat base-0 (selectors are cosmetic in real mode).
    state.segs[NVMM_X64_SEG_CS] = real_mode_code_seg(0xf000);
    state.segs[NVMM_X64_SEG_SS] = real_mode_data_seg(0);
    state.segs[NVMM_X64_SEG_DS] = real_mode_data_seg(0);
    state.segs[NVMM_X64_SEG_ES] = real_mode_data_seg(0);
    state.segs[NVMM_X64_SEG_FS] = real_mode_data_seg(0);
    state.segs[NVMM_X64_SEG_GS] = real_mode_data_seg(0);

    // RIP = GPA of the stub (CS.base == 0 → linear == RIP).
    state.gprs[NVMM_X64_GPR_RIP] = GUEST_GPA;

    vcpu.set_state(&state, NVMM_X64_STATE_SEGS | NVMM_X64_STATE_GPRS)
        .expect("nvmm_vcpu_setstate (segs+gprs)");

    eprintln!("vcpu programmed: RIP={:#x}, running...", GUEST_GPA);

    // Run loop: tolerate spurious NONE exits (host-internal); stop on IO.
    let mut saw_io = false;
    let mut io_port: u16 = 0;
    let mut io_npc: u64 = 0;
    let mut rip_at_io: u64 = 0;
    for iter in 0..64 {
        let exit = vcpu.run_until_exit().expect("nvmm_vcpu_run");
        eprintln!("  [iter {iter}] exit reason = {:#x}", exit.reason);
        match exit.reason {
            NVMM_VCPU_EXIT_NONE => {
                // Host-internal exit (e.g. preemption); just resume.
                continue;
            }
            NVMM_VCPU_EXIT_IO => {
                let io = exit.io();
                io_port = io.port;
                io_npc = io.npc;
                eprintln!(
                    "  IO exit: port={:#x} in={} size(operand)={} npc={:#x}",
                    io.port, io.in_, io.operand_size, io.npc
                );
                // Read RIP at the IO exit to compare against npc (the
                // RIP-advance finding for M1).
                let st = vcpu
                    .get_state(NVMM_X64_STATE_GPRS)
                    .expect("getstate at IO exit");
                rip_at_io = st.gprs[NVMM_X64_GPR_RIP];
                saw_io = true;
                break;
            }
            NVMM_VCPU_EXIT_HALTED => {
                panic!("guest HALTED before the IO doorbell (stub mis-fetched?)");
            }
            other => {
                panic!("unexpected exit before IO doorbell: reason={other:#x}");
            }
        }
    }

    assert!(saw_io, "never observed an NVMM_VCPU_EXIT_IO");
    assert_eq!(
        io_port, 0xC5,
        "IO exit port mismatch (want the 0xC5 doorbell)"
    );

    // --- M1 RIP-advance finding -------------------------------------------
    // The stub is: mov $0xc5,%al (2B @ 0x1000) ; out %al,$0xc5 (2B @ 0x1002).
    // The `out` is at 0x1002 and is 2 bytes, so the instruction following it
    // is at 0x1004. If npc == 0x1004, NVMM hands back a usable next-PC and we
    // resume there directly (no manual +inst_len). RIP-at-exit tells us
    // whether RIP still points AT the `out` (so a manual advance would be
    // needed without npc).
    let out_rip = GUEST_GPA + 2; // 0x1002
    let next_rip = GUEST_GPA + 4; // 0x1004
    eprintln!("=== M1 RIP-ADVANCE FINDING ===");
    eprintln!("  out is at {:#x}, next insn at {:#x}", out_rip, next_rip);
    eprintln!("  RIP at IO exit = {:#x}", rip_at_io);
    eprintln!("  io.npc        = {:#x}", io_npc);
    if io_npc == next_rip {
        eprintln!(
            "  => io.npc points PAST the out (next insn). Resume at io.npc; NO manual +inst_len."
        );
    } else if io_npc == out_rip {
        eprintln!("  => io.npc points AT the out. Must advance RIP manually (+2) on resume.");
    } else {
        eprintln!("  => io.npc unexpected value; record raw above for M1 analysis.");
    }
    if rip_at_io == out_rip {
        eprintln!("  RIP-at-exit is AT the out (kernel did not advance it).");
    } else if rip_at_io == next_rip {
        eprintln!("  RIP-at-exit is PAST the out (kernel advanced RIP itself).");
    }

    // Sanity: npc should be a usable resume target (one of the two, almost
    // certainly the next-insn). We assert it is non-zero and within the page
    // so a regression in the binding/layout is caught.
    assert!(
        io_npc == next_rip || io_npc == out_rip,
        "io.npc {io_npc:#x} is neither the out ({out_rip:#x}) nor the next insn ({next_rip:#x}) \
         — exit struct layout may be wrong"
    );

    eprintln!("M0 doorbell smoke PASS: NVMM_VCPU_EXIT_IO port 0xC5 observed.");
}

#[test]
fn m0_out_eax_payload_is_not_in_nvmm_io_exit() {
    let (_mach, mut vcpu) = program_real_mode_stub(EAX_PAYLOAD_STUB);

    for iter in 0..64 {
        let exit = vcpu.run_until_exit().expect("nvmm_vcpu_run");
        eprintln!("  [payload iter {iter}] exit reason = {:#x}", exit.reason);
        match exit.reason {
            NVMM_VCPU_EXIT_NONE => continue,
            NVMM_VCPU_EXIT_IO => {
                let io = exit.io();
                let state = vcpu
                    .get_state(NVMM_X64_STATE_GPRS)
                    .expect("getstate at IO exit");
                assert_eq!(
                    io.port, 0xC7,
                    "payload diagnostic uses the fault doorbell port"
                );
                assert_eq!(io.operand_size, 4, "OUT EAX should report a 4-byte operand");
                eprintln!(
                    "M0 payload diagnostic: NVMM IO exit has port={:#x} operand_size={} \
                     and RAX-at-exit={:#x}; the exit struct has no OUT payload field.",
                    io.port, io.operand_size, state.gprs[NVMM_X64_GPR_RAX] as u32
                );
                return;
            }
            NVMM_VCPU_EXIT_HALTED => panic!("guest HALTED before the IO payload doorbell"),
            other => panic!("unexpected exit before IO payload doorbell: reason={other:#x}"),
        }
    }

    panic!("never observed the IO payload doorbell");
}
