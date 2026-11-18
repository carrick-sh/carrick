//! The first production boot probe (#1236 M2-1): the production EL1 image
//! runs from its ELF entry through the native copy-through engine under a
//! block budget, and prints `boots to PC=... after N blocks / fails at ...`.
//! Set CARRICK_A64_ELF to the freshly built carrick-el1-image
//! OUT_DIR/el1-target/aarch64-unknown-none-softfloat/el1-image/carrick-el1.
//! Linux arm64 only (the hosted arm64 job's `--ignored` step).
//!
//! Start at the image entry, after the vector's handoff: EL1h, DAIF masked,
//! x0 = an EL0 SVC trap frame on slot zero's EL1 stack, x30 = a return
//! sentinel. Physical memory holds the image, vectors, EL1 backing and
//! production bootstrap tables. A second, diagnostic pass backs faulting
//! physical pages on demand and reports where it stops.
#![cfg(all(target_arch = "aarch64", target_os = "linux"))]
// Test helpers outside #[test] fns fail loudly on malformed fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_el1_abi::{
    EL1_DYNAMIC_METADATA_BASE, EL1_DYNAMIC_METADATA_EXTENT_SIZE, EL1_STACK_GUARD_TABLES_BASE,
    TrapFrame, is_el1_stack_guard, stack_slot_top,
};
use carrick_mem::arch_sysregs::{MAIR_EL1_BOOTSTRAP, SCTLR_EL1_BOOTSTRAP, TCR_EL1_BOOTSTRAP};
use carrick_mem::memory::{
    Aarch64SyscallMailbox, El1IrqMode, LINUX_CARRIER_MAINT_ROOT_BASE, LINUX_EL0_TRAMPOLINE_BASE,
    LINUX_EL1_KERNEL_BASE, LINUX_EL1_KERNEL_SIZE, LINUX_EL1_MAINT_BASE, LINUX_EL1_VECTORS_BASE,
    LINUX_FD_CEILING_CONTROL_BASE, LINUX_FD_CEILING_CONTROL_SIZE, LINUX_IDENTITY_PAGE_BASE,
    LINUX_IDENTITY_PAGE_SIZE, LINUX_PAGE_TABLES_BASE, LINUX_STACK_TOP,
    LINUX_SYSCALL_MAILBOX_ARENA_SIZE, LINUX_SYSCALL_MAILBOX_BASE, el0_trampoline_bytes,
    el1_maintenance_bytes, el1_stack_guard_tables, el1_vectors_bytes,
    el1_vectors_bytes_mailbox_clock, stage1_carrier_maintenance_page_tables,
    stage1_hvpatch_page_tables, stage1_identity_page_tables,
};
use carrick_softcpu_aarch64::dispatch::{Report, Stop, run};
use carrick_softcpu_aarch64::handler::{Event, ExclusiveMonitor, GuestMemory, MemoryFault};
use carrick_softcpu_aarch64::state::{
    CpuState, ExceptionLevel, InterruptMasks, ProgramCounter, RegisterValue, SavedPstate, Sctlr,
    StackPointer, StackSelect, SystemValue, VirtualAddress,
};
use carrick_softcpu_aarch64::translate::BlockLimits;
use carrick_softcpu_aarch64::{Gpr, OperandRegister};
use carrick_softcpu_aarch64_host::{HostBlockRunner, HostError};
use std::collections::BTreeMap;

const PAGE: u64 = 4096;
const INITIAL_METADATA_END: u64 =
    EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64;

/// Page-granular guest physical memory: unbacked pages fault.
#[derive(Default)]
struct Pages {
    pages: BTreeMap<u64, Box<[u8; PAGE as usize]>>,
    read_boot_root: bool,
}

impl Pages {
    fn map_zero(&mut self, page: u64) {
        self.pages
            .entry(page & !(PAGE - 1))
            .or_insert_with(|| Box::new([0; PAGE as usize]));
    }
    fn load(&mut self, at: u64, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            let a = at + i as u64;
            self.map_zero(a);
            self.pages.get_mut(&(a & !(PAGE - 1))).unwrap()[(a % PAGE) as usize] = *b;
        }
    }
    fn byte(&mut self, a: u64) -> Result<&mut u8, MemoryFault> {
        self.pages
            .get_mut(&(a & !(PAGE - 1)))
            .map(|p| &mut p[(a % PAGE) as usize])
            .ok_or(MemoryFault {
                address: VirtualAddress(a),
            })
    }
}

impl GuestMemory for Pages {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self.byte(address.0 + i as u64)?;
        }
        if address.0 == LINUX_PAGE_TABLES_BASE && bytes.len() == size_of::<u64>() {
            self.read_boot_root = true;
        }
        Ok(())
    }
    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
        for i in 0..bytes.len() as u64 {
            self.byte(address.0 + i)?;
        }
        for (i, b) in bytes.iter().enumerate() {
            *self.byte(address.0 + i as u64)? = *b;
        }
        Ok(())
    }
}

fn field(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut v = [0u8; 8];
    v[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(v)
}

/// ELF64 program headers per the System V ABI: PT_LOAD file bytes at p_vaddr,
/// zero-filled to p_memsz. Returns e_entry.
fn load_elf(bytes: &[u8], memory: &mut Pages) -> u64 {
    assert_eq!(&bytes[..6], b"\x7fELF\x02\x01");
    assert_eq!(field(bytes, 18, 2), 183, "not AArch64");
    let entry = field(bytes, 24, 8);
    let table = field(bytes, 32, 8) as usize;
    let stride = field(bytes, 54, 2) as usize;
    for i in 0..field(bytes, 56, 2) as usize {
        let h = &bytes[table + i * stride..table + (i + 1) * stride];
        if field(h, 0, 4) != 1 {
            continue;
        }
        let (offset, vaddr) = (field(h, 8, 8) as usize, field(h, 16, 8));
        let (filesz, memsz) = (field(h, 32, 8) as usize, field(h, 40, 8));
        memory.load(vaddr, &bytes[offset..offset + filesz]);
        let mut page = (vaddr + filesz as u64) & !(PAGE - 1);
        while page < vaddr + memsz {
            memory.map_zero(page);
            page += PAGE;
        }
    }
    entry
}

// This probe starts after the vector handoff, so the trampoline page is
// unbacked. It is EL1-executable at stage 1 and stops at the provider fetch.
const RETURN_SENTINEL: u64 = LINUX_EL0_TRAMPOLINE_BASE;
const _: () = assert!(RETURN_SENTINEL == 0x2d_0000_0000);

fn assert_sentinel_return(cpu: &CpuState, strict: &Report<HostError>) {
    assert_eq!(
        strict.pc,
        ProgramCounter(RETURN_SENTINEL),
        "strict probe did not stop at the loader sentinel PC: {strict}"
    );
    assert_eq!(
        strict.stop,
        Stop::Fetch(VirtualAddress(RETURN_SENTINEL)),
        "strict probe did not stop on an instruction fetch from the loader sentinel: {strict}"
    );
    let exit_word = cpu
        .read_operand(OperandRegister::Gpr(Gpr::new(0).unwrap()))
        .0;
    println!("  returned to the loader sentinel: x0 (exit word) = {exit_word:#x}");
    assert_eq!(
        exit_word, 0,
        "strict probe returned non-zero exit word: {strict}"
    );
}

fn set_x(cpu: &mut CpuState, n: u8, v: u64) {
    cpu.write_operand(OperandRegister::Gpr(Gpr::new(n).unwrap()), RegisterValue(v));
}

/// The frame describes `getpid` (aarch64 nr 172 in x8) by SVC #0 from EL0.
fn enter(elf: &[u8]) -> (CpuState, Pages) {
    let mut memory = Pages::default();
    for page in (LINUX_EL1_KERNEL_BASE..LINUX_EL1_KERNEL_BASE + LINUX_EL1_KERNEL_SIZE)
        .step_by(PAGE as usize)
    {
        if !is_el1_stack_guard(page) {
            memory.map_zero(page);
        }
    }
    // Back the first metadata extent touched by the image. Later grants
    // still have to cross the provider boundary.
    for page in (EL1_DYNAMIC_METADATA_BASE..INITIAL_METADATA_END).step_by(PAGE as usize) {
        memory.map_zero(page);
    }
    let entry = load_elf(elf, &mut memory);
    memory.load(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables());
    memory.load(EL1_STACK_GUARD_TABLES_BASE, &el1_stack_guard_tables());
    memory.load(LINUX_EL1_VECTORS_BASE, &el1_vectors_bytes());

    let mut frame = [0u8; size_of::<TrapFrame>()];
    let mut put = |offset: usize, word: u64| {
        frame[offset..offset + size_of::<u64>()].copy_from_slice(&word.to_le_bytes());
    };
    put(
        core::mem::offset_of!(TrapFrame, x) + size_of::<[u64; 8]>(),
        172,
    );
    put(core::mem::offset_of!(TrapFrame, elr), 0x40_1000);
    put(
        core::mem::offset_of!(TrapFrame, esr),
        (0x15 << 26) | (1 << 25),
    );
    let frame_addr = stack_slot_top(0) - frame.len() as u64;
    memory.load(frame_addr, &frame);

    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.pstate.daif = InterruptMasks::ALL;
    cpu.pstate.pan = true;
    cpu.sp_el1 = StackPointer(frame_addr);
    cpu.pc = ProgramCounter(entry);
    cpu.el1.vbar = VirtualAddress(LINUX_EL1_VECTORS_BASE);
    cpu.el1.mair = SystemValue(MAIR_EL1_BOOTSTRAP);
    cpu.el1.tcr = SystemValue(TCR_EL1_BOOTSTRAP);
    cpu.named.ttbr0 = SystemValue(LINUX_PAGE_TABLES_BASE);
    cpu.named.ttbr1 = SystemValue(LINUX_PAGE_TABLES_BASE);
    cpu.el1.sctlr = Sctlr(SCTLR_EL1_BOOTSTRAP);
    set_x(&mut cpu, 0, frame_addr);
    set_x(&mut cpu, 30, RETURN_SENTINEL);
    (cpu, memory)
}

fn probe(
    cpu: &mut CpuState,
    memory: &mut Pages,
    runner: &mut HostBlockRunner,
    budget: u64,
) -> Report<HostError> {
    run(
        cpu,
        &mut ExclusiveMonitor::default(),
        memory,
        runner,
        BlockLimits::default(),
        budget,
    )
}

#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the rebuilt production EL1 ELF"]
fn production_el1_image_boot_probe() {
    let path = std::env::var_os("CARRICK_A64_ELF").expect("set CARRICK_A64_ELF");
    let elf = std::fs::read(path).expect("read the production EL1 ELF");
    let mut runner = HostBlockRunner::new().expect("Linux arm64 host runner");
    const BUDGET: u64 = 1_000_000;

    let (mut cpu, mut memory) = enter(&elf);
    let entry = cpu.pc;
    let strict = probe(&mut cpu, &mut memory, &mut runner, BUDGET);
    println!(
        "boot probe (strict stage-1 memory) from entry {:#x}: {strict}",
        entry.0
    );
    println!(
        "  EL1 stop state: ESR={:#x} FAR={:#x} ELR={:#x}",
        cpu.el1.esr.0, cpu.el1.far.0, cpu.el1.elr.0
    );
    assert_ne!(
        strict.stop,
        Stop::Budget,
        "probe exhausted its block budget"
    );
    assert!(
        memory.read_boot_root,
        "the probe never read its stage-1 root"
    );
    if strict.stop != Stop::Fetch(VirtualAddress(RETURN_SENTINEL)) {
        // Diagnostic pass: demand-zero pages, to show what comes after.
        let (mut cpu, mut memory) = enter(&elf);
        let mut blocks = 0;
        let mut demand = Vec::new();
        let last = loop {
            let report = probe(&mut cpu, &mut memory, &mut runner, BUDGET - blocks);
            blocks += report.blocks;
            match report.stop {
                Stop::Event {
                    event: Event::MemoryFault(fault),
                    ..
                } if demand.len() < 64 => {
                    demand.push((report.pc.0, fault.address.0 & !(PAGE - 1)));
                    memory.map_zero(fault.address.0);
                }
                _ => break report,
            }
        };
        for (pc, page) in &demand {
            println!("  demand-zero page {page:#x} (first touch at PC={pc:#x})");
        }
        println!(
            "boot probe (demand-zero, {} pages) total {blocks} blocks; last run: {last}",
            demand.len()
        );
        if last.stop == Stop::Fetch(VirtualAddress(RETURN_SENTINEL)) {
            println!(
                "  returned to the loader sentinel: x0 (exit word) = {:#x}",
                cpu.read_operand(OperandRegister::Gpr(Gpr::new(0).unwrap()))
                    .0
            );
        }
    }
    assert_sentinel_return(&cpu, &strict);
}

const USER_HELLO_ELF: &[u8] =
    include_bytes!("../../carrick-vmm-kvm/fixtures/hello-aarch64/hello-aarch64");
const ROOT_EL0_ENTRY_SPSR: u64 = 0x3c0;

fn read_u32(memory: &mut Pages, at: u64) -> u32 {
    let mut b = [0u8; 4];
    memory.read(VirtualAddress(at), &mut b).unwrap();
    u32::from_le_bytes(b)
}

fn read_u64(memory: &mut Pages, at: u64) -> u64 {
    let mut b = [0u8; 8];
    memory.read(VirtualAddress(at), &mut b).unwrap();
    u64::from_le_bytes(b)
}

/// Production StagedCpu::initial_root + PersistentExecutor slot-0 handoff:
/// boot at LINUX_EL0_TRAMPOLINE_BASE (0x2d00000000) in EL1h with SP_EL1 bound
/// to slot 0's Aarch64SyscallMailbox, drop via eret to `user_elf` at EL0, trap
/// its `svc #0` through the mailbox/EL1 vector hook into `carrick_el1_syscall`,
/// and reach the first guest-visible carrier exit (`HVC #2`).
fn enter_carrier_root(el1_elf: &[u8], user_elf: &[u8]) -> (CpuState, Pages, u64) {
    let mut memory = Pages::default();
    for page in (LINUX_EL1_KERNEL_BASE..LINUX_EL1_KERNEL_BASE + LINUX_EL1_KERNEL_SIZE)
        .step_by(PAGE as usize)
    {
        if !is_el1_stack_guard(page) {
            memory.map_zero(page);
        }
    }
    for page in (EL1_DYNAMIC_METADATA_BASE..INITIAL_METADATA_END).step_by(PAGE as usize) {
        memory.map_zero(page);
    }
    for (base, size) in [
        (LINUX_IDENTITY_PAGE_BASE, LINUX_IDENTITY_PAGE_SIZE),
        (LINUX_SYSCALL_MAILBOX_BASE, LINUX_SYSCALL_MAILBOX_ARENA_SIZE),
        (LINUX_FD_CEILING_CONTROL_BASE, LINUX_FD_CEILING_CONTROL_SIZE),
        (LINUX_STACK_TOP - 2 * PAGE, 2 * PAGE),
    ] {
        for page in (base..base + size).step_by(PAGE as usize) {
            memory.map_zero(page);
        }
    }

    let _el1_entry = load_elf(el1_elf, &mut memory);
    let user_entry = load_elf(user_elf, &mut memory);
    memory.load(LINUX_EL0_TRAMPOLINE_BASE, &el0_trampoline_bytes());
    memory.load(
        LINUX_EL1_VECTORS_BASE,
        &el1_vectors_bytes_mailbox_clock(true, true, El1IrqMode::Gic),
    );
    memory.load(LINUX_PAGE_TABLES_BASE, &stage1_hvpatch_page_tables());
    memory.load(EL1_STACK_GUARD_TABLES_BASE, &el1_stack_guard_tables());
    memory.load(LINUX_EL1_MAINT_BASE, &el1_maintenance_bytes());
    memory.load(
        LINUX_CARRIER_MAINT_ROOT_BASE,
        &stage1_carrier_maintenance_page_tables(),
    );

    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.pstate.daif = InterruptMasks::ALL;
    cpu.sp_el0 = StackPointer(LINUX_STACK_TOP - 16);
    cpu.sp_el1 = StackPointer(LINUX_SYSCALL_MAILBOX_BASE);
    cpu.pc = ProgramCounter(LINUX_EL0_TRAMPOLINE_BASE);
    cpu.el1.elr = ProgramCounter(user_entry);
    cpu.el1.spsr = SavedPstate(ROOT_EL0_ENTRY_SPSR);
    cpu.el1.vbar = VirtualAddress(LINUX_EL1_VECTORS_BASE);
    cpu.el1.mair = SystemValue(MAIR_EL1_BOOTSTRAP);
    cpu.el1.tcr = SystemValue(TCR_EL1_BOOTSTRAP);
    cpu.named.ttbr0 = SystemValue(LINUX_PAGE_TABLES_BASE);
    cpu.named.ttbr1 = SystemValue(LINUX_PAGE_TABLES_BASE);
    cpu.el1.sctlr = Sctlr(SCTLR_EL1_BOOTSTRAP);
    cpu.el1.cntkctl = SystemValue(3);
    (cpu, memory, user_entry)
}

fn check_forwarded_write_exit(
    report: &Report<HostError>,
    memory: &mut Pages,
    user_entry: u64,
) -> Result<(), String> {
    let Stop::Event {
        instruction,
        event: Event::ProviderExit(exit),
    } = report.stop
    else {
        return Err(format!("expected HVC provider exit, got {report}"));
    };
    if exit.immediate.value() != 2 {
        return Err(format!(
            "expected HVC #2 syscall forward, got HVC #{} at PC={:#x}: {report}",
            exit.immediate.value(),
            instruction.pc().0
        ));
    }
    let mb = LINUX_SYSCALL_MAILBOX_BASE;
    let state = read_u32(
        memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, state) as u64,
    );
    let trap_kind = read_u32(
        memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind) as u64,
    );
    let native_nr = read_u64(
        memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, native_nr) as u64,
    );
    let args_off = mb + core::mem::offset_of!(Aarch64SyscallMailbox, args) as u64;
    let (fd, buf, len) = (
        read_u64(memory, args_off),
        read_u64(memory, args_off + 8),
        read_u64(memory, args_off + 16),
    );
    let resume_pc = read_u64(
        memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc) as u64,
    );
    if state != 1 || trap_kind != 1 {
        return Err(format!(
            "expected published mailbox request (state=1, trap_kind=1), got state={state} trap_kind={trap_kind}"
        ));
    }
    if (native_nr, fd, len, resume_pc) != (64, 1, 3, user_entry + 20) {
        return Err(format!(
            "unexpected forwarded syscall fields: nr={native_nr} fd={fd} len={len} resume_pc={resume_pc:#x}"
        ));
    }
    let mut payload = [0u8; 3];
    memory
        .read(VirtualAddress(buf), &mut payload)
        .map_err(|f| format!("unreadable write buffer {:#x}: {:?}", buf, f))?;
    if &payload != b"ok\n" {
        return Err(format!("unexpected write payload {payload:?}"));
    }
    Ok(())
}

#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the rebuilt production EL1 ELF"]
fn production_el1_image_boots_past_trampoline_to_first_guest_hvc() {
    let path = std::env::var_os("CARRICK_A64_ELF").expect("set CARRICK_A64_ELF");
    let elf = std::fs::read(path).expect("read the production EL1 ELF");
    let mut runner = HostBlockRunner::new().expect("Linux arm64 host runner");
    const BUDGET: u64 = 1_000_000;

    let (mut cpu, mut memory, user_entry) = enter_carrier_root(&elf, USER_HELLO_ELF);
    let boot_pc = cpu.pc.0;
    let report = probe(&mut cpu, &mut memory, &mut runner, BUDGET);
    println!("carrier boot probe from {boot_pc:#x} (user ELF entry {user_entry:#x}): {report}");
    assert!(
        memory.read_boot_root,
        "carrier boot probe never walked the stage-1 root"
    );
    if let Stop::Event {
        instruction,
        event: Event::ProviderExit(exit),
    } = report.stop
    {
        let mb = LINUX_SYSCALL_MAILBOX_BASE;
        let state = read_u32(
            &mut memory,
            mb + core::mem::offset_of!(Aarch64SyscallMailbox, state) as u64,
        );
        let trap_kind = read_u32(
            &mut memory,
            mb + core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind) as u64,
        );
        let native_nr = read_u64(
            &mut memory,
            mb + core::mem::offset_of!(Aarch64SyscallMailbox, native_nr) as u64,
        );
        let args_off = mb + core::mem::offset_of!(Aarch64SyscallMailbox, args) as u64;
        let (fd, buf, len) = (
            read_u64(&mut memory, args_off),
            read_u64(&mut memory, args_off + 8),
            read_u64(&mut memory, args_off + 16),
        );
        let resume_pc = read_u64(
            &mut memory,
            mb + core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc) as u64,
        );
        let mut payload = [0u8; 3];
        let _ = memory.read(VirtualAddress(buf), &mut payload);
        println!(
            "  first guest-visible host call: HVC #{} at PC={:#x} (word {:#010x})",
            exit.immediate.value(),
            instruction.pc().0,
            instruction.word()
        );
        println!(
            "  mailbox[0] @ {mb:#x}: state={state} trap_kind={trap_kind} native_nr={native_nr} args=[{fd:#x}, {buf:#x}, {len:#x}] resume_pc={resume_pc:#x} payload={:?}",
            String::from_utf8_lossy(&payload)
        );
    }
    check_forwarded_write_exit(&report, &mut memory, user_entry).unwrap();

    // Mutation control: an EL0 UDF #0 at user_entry also exits via HVC #2
    // (NotSvc), with mailbox.state == 0; the forwarded-write check must reject it.
    let (mut fault_cpu, mut fault_mem, fault_entry) = enter_carrier_root(&elf, USER_HELLO_ELF);
    fault_mem.load(fault_entry, &0u32.to_le_bytes());
    let fault_report = probe(&mut fault_cpu, &mut fault_mem, &mut runner, BUDGET);
    assert!(
        check_forwarded_write_exit(&fault_report, &mut fault_mem, fault_entry).is_err(),
        "EL0 UDF mutation must not pass as a forwarded SYS_write: {fault_report}"
    );
}
