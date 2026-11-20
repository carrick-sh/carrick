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

use carrick_aarch64::staged_cpu::{RootBootFields, StagedCpu};
use carrick_el1_abi::{
    ContextGeneration, CurrentTask, DELEGATED_FLAG_READABLE, DELEGATED_FLAG_WRITABLE,
    DELEGATED_STATE_GUEST, DelegatedOpenFile, EL1_CURRENT_TASKS_BASE, EL1_DYNAMIC_METADATA_BASE,
    EL1_DYNAMIC_METADATA_EXTENT_SIZE, EL1_FD_MAP_BASE, EL1_OPEN_FILE_TABLE_BASE,
    EL1_STACK_GUARD_TABLES_BASE, El1TaskId, FdMapSlot, HostObjectBinding, SnapshotGeneration,
    TrapFrame, is_el1_stack_guard, stack_slot_top,
};
use carrick_guest_arch::FrameGpa;
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
use carrick_softcpu_aarch64::dispatch::{BlockMemory, ExecuteBlock, Report, RunWork, Stop, run};
use carrick_softcpu_aarch64::handler::{
    CodeGeneration, Event, ExclusiveMonitor, GuestMemory, InlineRam, MemoryFault,
};
use carrick_softcpu_aarch64::state::{
    CpuState, ExceptionLevel, InterruptMasks, ProgramCounter, RegisterValue, SavedPstate, Sctlr,
    StackPointer, StackSelect, SystemValue, VirtualAddress,
};
use carrick_softcpu_aarch64::translate::{
    BlockExit, BlockLimits, ExitReason, InstructionClass, TranslatedBlock,
};
use carrick_softcpu_aarch64::{ExceptionKind, Gpr, OperandRegister};
use carrick_softcpu_aarch64_host::{HostBlockRunner, HostCode, HostError, SoftMemory};
use core::mem::offset_of;
use core::num::NonZeroU64;
use core::sync::atomic::Ordering;
use std::collections::VecDeque;

#[path = "fixtures/dynamic_root.rs"]
mod dynamic_root;
use dynamic_root::{DynamicRoot, FixtureRoot};

const PAGE: u64 = 4096;
const INITIAL_METADATA_END: u64 =
    EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64;

/// Fixture instrumentation and loader helpers around the production RAM owner.
struct Pages {
    memory: SoftMemory,
    read_boot_root: bool,
}

impl Default for Pages {
    fn default() -> Self {
        Self {
            memory: SoftMemory::new().expect("physical inventory"),
            read_boot_root: false,
        }
    }
}

impl Pages {
    fn map_zero(&mut self, address: u64) {
        self.memory
            .map_zero(FrameGpa::new(address & !(PAGE - 1)))
            .expect("fixture page");
    }

    fn load(&mut self, at: u64, bytes: &[u8]) {
        if !bytes.is_empty() {
            let first = at & !(PAGE - 1);
            let last = (at + bytes.len() as u64 - 1) & !(PAGE - 1);
            for page in (first..=last).step_by(PAGE as usize) {
                self.map_zero(page);
            }
            self.write(VirtualAddress(at), bytes)
                .expect("fixture bytes");
        }
    }
}

impl GuestMemory for Pages {
    fn stage1_is_local(&self) -> bool {
        self.memory.stage1_is_local()
    }

    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        self.memory.read(address, bytes)?;
        if address.0 == LINUX_PAGE_TABLES_BASE && bytes.len() == size_of::<u64>() {
            self.read_boot_root = true;
        }
        Ok(())
    }

    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
        self.memory.write(address, bytes)
    }

    fn inline_ram(&mut self, read: Option<FrameGpa>, write: Option<FrameGpa>) -> InlineRam<'_> {
        self.memory.inline_ram(read, write)
    }

    fn invalidate_code_frame(&mut self, frame: FrameGpa) -> Result<bool, MemoryFault> {
        self.memory.invalidate_code_frame(frame)
    }

    fn mark_code_page(&mut self, frame: FrameGpa) -> Option<CodeGeneration> {
        self.memory.mark_code_page(frame)
    }

    fn code_generation(&self, frame: FrameGpa) -> Option<CodeGeneration> {
        self.memory.code_generation(frame)
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

fn x(cpu: &CpuState, n: u8) -> u64 {
    cpu.read_operand(OperandRegister::Gpr(Gpr::new(n).unwrap()))
        .0
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

fn print_work(
    report: &Report<HostError>,
    publication: carrick_host_jit::PublicationWork,
    elapsed: std::time::Duration,
    traced: bool,
) {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let seconds = elapsed.as_secs_f64();
    let work = report.work;
    println!(
        "engine work ({profile}, syscall trace={traced}) PC={:#x} budget_steps={} {work:?} {publication:?} elapsed_ns={} blocks/s={:.0} instr/s={:.0}",
        report.pc.0,
        report.blocks,
        elapsed.as_nanos(),
        work.executed_blocks as f64 / seconds,
        work.retired_instructions as f64 / seconds,
    );
}

fn probe(
    cpu: &mut CpuState,
    memory: &mut Pages,
    runner: &mut HostBlockRunner,
    budget: u64,
) -> Report<HostError> {
    let before = runner.publication_work();
    let start = std::time::Instant::now();
    let report = run(
        cpu,
        &mut ExclusiveMonitor::default(),
        memory,
        runner,
        BlockLimits::default(),
        budget,
    );
    print_work(
        &report,
        runner.publication_work().since(before),
        start.elapsed(),
        false,
    );
    report
}

#[test]
fn resident_loop_translates_only_two_blocks() {
    const PC: u64 = 0x4000;
    let mut counts = Vec::new();
    for iterations in [1, 100, 10_000] {
        let mut memory = Pages::default();
        // subs x0, x0, #1; b.ne back to subs; hvc #2.
        for (index, word) in [0xf100_0400_u32, 0x54ff_ffe1, 0xd400_0042]
            .into_iter()
            .enumerate()
        {
            memory.load(PC + 4 * index as u64, &word.to_le_bytes());
        }
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.pc = ProgramCounter(PC);
        set_x(&mut cpu, 0, iterations);
        let mut runner = HostBlockRunner::new().expect("Linux arm64 host runner");
        let report = probe(&mut cpu, &mut memory, &mut runner, iterations + 2);
        assert!(matches!(
            report.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
        assert_eq!(report.pc, ProgramCounter(PC + 12));
        assert_eq!(report.work.executed_blocks, iterations + 1);
        assert_eq!(report.work.retired_instructions, iterations * 2 + 1);
        let publication = runner.publication_work();
        counts.push((
            report.work.decoded_blocks,
            report.work.emitted_blocks,
            publication.publications,
            publication.mprotect_calls,
            publication.icache_syncs,
        ));
    }
    assert_eq!(counts, [(2, 2, 2, 2, 2); 3]);
}

#[test]
fn translated_memory_loop_walks_each_page_once() {
    const PC: u64 = LINUX_EL1_KERNEL_BASE;
    const SOURCE: u64 = PC + PAGE;
    const DEST: u64 = SOURCE + PAGE;
    const VALUE: u64 = 0x1122_3344_5566_7788;
    let mut work = Vec::new();
    for iterations in [1, 100, 10_000] {
        let mut memory = Pages::default();
        memory.load(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables());
        // ldr x3, [x1]; str x3, [x2]; subs x0, x0, #1; b.ne to ldr; hvc #2.
        for (index, word) in [
            0xf940_0023_u32,
            0xf900_0043,
            0xf100_0400,
            0x54ff_ffa1,
            0xd400_0042,
        ]
        .into_iter()
        .enumerate()
        {
            memory.load(PC + 4 * index as u64, &word.to_le_bytes());
        }
        memory.load(SOURCE, &VALUE.to_le_bytes());
        memory.map_zero(DEST);
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.pc = ProgramCounter(PC);
        cpu.el1.tcr = SystemValue(TCR_EL1_BOOTSTRAP);
        cpu.named.ttbr0 = SystemValue(LINUX_PAGE_TABLES_BASE);
        cpu.el1.sctlr = Sctlr(SCTLR_EL1_BOOTSTRAP);
        set_x(&mut cpu, 0, iterations);
        set_x(&mut cpu, 1, SOURCE);
        set_x(&mut cpu, 2, DEST);
        let mut runner = HostBlockRunner::new().expect("Linux arm64 host runner");
        let report = probe(&mut cpu, &mut memory, &mut runner, 3 * iterations + 2);
        assert!(matches!(
            report.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
        assert_eq!(report.pc, ProgramCounter(PC + 20));
        assert_eq!(read_u64(&mut memory, DEST), VALUE);
        assert_eq!(report.work.retired_instructions, 4 * iterations + 1);
        work.push((
            report.work.stage1_walks,
            report.work.memory_exits,
            report.work.dispatches,
        ));
    }
    assert_eq!(work, [(3, 2, 4), (3, 2, 103), (3, 2, 10_003)]);
}

#[test]
fn marking_code_revokes_the_inline_store_loan() {
    const WRITER: u64 = LINUX_EL1_KERNEL_BASE;
    const TARGET: u64 = WRITER + PAGE;
    let mut memory = Pages::default();
    memory.load(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables());
    // str w1, [x2]; movz w1, #0x42; movk w1, #0xd400, lsl #16; br x2.
    for (index, word) in [0xb900_0041_u32, 0x5280_0841, 0x72ba_8001, 0xd61f_0040]
        .into_iter()
        .enumerate()
    {
        memory.load(WRITER + 4 * index as u64, &word.to_le_bytes());
    }
    memory.load(TARGET, &0xd61f_0060_u32.to_le_bytes()); // br x3.
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.pc = ProgramCounter(WRITER);
    cpu.el1.tcr = SystemValue(TCR_EL1_BOOTSTRAP);
    cpu.named.ttbr0 = SystemValue(LINUX_PAGE_TABLES_BASE);
    cpu.el1.sctlr = Sctlr(SCTLR_EL1_BOOTSTRAP);
    set_x(&mut cpu, 1, 0xd61f_0060);
    set_x(&mut cpu, 2, TARGET);
    set_x(&mut cpu, 3, WRITER);
    let mut runner = HostBlockRunner::new().expect("Linux arm64 host runner");
    let report = probe(&mut cpu, &mut memory, &mut runner, 8);
    let Stop::Event {
        instruction,
        event: Event::ProviderExit(hvc),
    } = report.stop
    else {
        panic!("{report}");
    };
    assert_eq!(instruction.pc(), ProgramCounter(TARGET));
    assert_eq!(hvc.immediate.value(), 2);
    assert_eq!(report.work.memory_exits, 2);
    assert_eq!(
        memory.code_generation(FrameGpa::new(TARGET)),
        Some(CodeGeneration(2))
    );
}

#[test]
fn ic_ivau_recompiles_only_the_target_code_frame() {
    const DRIVER: u64 = 0x4000;
    const TARGET: u64 = 0x5000;
    const PEER: u64 = 0x6000;
    let mut memory = Pages::default();
    // blr x0; blr x1; ic ivau, x0; blr x0; blr x1; hvc #2.
    for (index, word) in [
        0xd63f_0000_u32,
        0xd63f_0020,
        0xd50b_7520,
        0xd63f_0000,
        0xd63f_0020,
        0xd400_0042,
    ]
    .into_iter()
    .enumerate()
    {
        memory.load(DRIVER + 4 * index as u64, &word.to_le_bytes());
    }
    for pc in [TARGET, PEER] {
        memory.load(pc, &0xd65f_03c0_u32.to_le_bytes()); // ret
    }
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.pc = ProgramCounter(DRIVER);
    set_x(&mut cpu, 0, TARGET);
    set_x(&mut cpu, 1, PEER);
    let mut runner = HostBlockRunner::new().expect("Linux arm64 host runner");
    let report = probe(&mut cpu, &mut memory, &mut runner, 10);
    assert!(matches!(
        report.stop,
        Stop::Event {
            event: Event::ProviderExit(_),
            ..
        }
    ));
    assert_eq!(report.work.retired_instructions, 10);
    assert_eq!(report.work.emitted_blocks, 9);
    assert_eq!(
        memory.code_generation(FrameGpa::new(TARGET)),
        Some(CodeGeneration(2))
    );
    assert_eq!(
        memory.code_generation(FrameGpa::new(PEER)),
        Some(CodeGeneration(1))
    );
}

#[test]
fn remap_and_exec_loader_write_advance_code_incarnations() {
    const PC: u64 = 0x4000;
    let frame = FrameGpa::new(PC);
    let mut memory = SoftMemory::new().expect("physical inventory");
    memory.map_zero(frame).unwrap();
    let mut runner = HostBlockRunner::new().expect("Linux arm64 host runner");
    let mut run_at_entry = |memory: &mut SoftMemory| {
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.pc = ProgramCounter(PC);
        run(
            &mut cpu,
            &mut ExclusiveMonitor::default(),
            memory,
            &mut runner,
            BlockLimits::default(),
            2,
        )
    };
    for generation in 1..=3 {
        let word = 0xd400_0002_u32 | (generation as u32) << 5;
        memory
            .write(VirtualAddress(PC), &word.to_le_bytes())
            .unwrap();
        let report = run_at_entry(&mut memory);
        let Stop::Event {
            event: Event::ProviderExit(hvc),
            ..
        } = report.stop
        else {
            panic!("{report}");
        };
        assert_eq!(u64::from(hvc.immediate.value()), generation);
        assert_eq!(
            memory.code_generation(frame),
            Some(CodeGeneration(generation))
        );
        if generation == 1 {
            memory.unmap_frame(frame).unwrap();
            assert_eq!(memory.code_generation(frame), None);
            assert_eq!(
                run_at_entry(&mut memory).stop,
                Stop::Fetch(VirtualAddress(PC))
            );
            memory.map_zero(frame).unwrap();
        }
    }
}

#[test]
fn guest_code_write_replaces_the_resident_translation() {
    const CODE: u64 = 0x4000;
    const WRITER: u64 = 0x5000;
    let mut memory = Pages::default();
    // movz x5, #1; br x3
    memory.load(CODE, &[0x25, 0x00, 0x80, 0xd2, 0x60, 0x00, 0x1f, 0xd6]);
    // str w1, [x2]; br x4
    memory.load(WRITER, &[0x41, 0x00, 0x00, 0xb9, 0x80, 0x00, 0x1f, 0xd6]);
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.pc = ProgramCounter(CODE);
    set_x(&mut cpu, 1, 0xd400_0042); // hvc #2 overwrites movz
    set_x(&mut cpu, 2, CODE);
    set_x(&mut cpu, 3, WRITER);
    set_x(&mut cpu, 4, CODE);
    assert_eq!(memory.code_generation(FrameGpa::new(CODE)), None);
    let mut runner = HostBlockRunner::new().expect("Linux arm64 host runner");
    let report = probe(&mut cpu, &mut memory, &mut runner, 8);
    let Stop::Event {
        instruction,
        event: Event::ProviderExit(hvc),
    } = report.stop
    else {
        panic!("{report}");
    };
    assert_eq!(instruction.pc(), ProgramCounter(CODE));
    assert_eq!(hvc.immediate.value(), 2);
    assert_eq!(
        cpu.read_operand(OperandRegister::Gpr(Gpr::new(5).unwrap())),
        RegisterValue(1)
    );
    assert_eq!(report.work.executed_blocks, 4);
    assert_eq!(report.work.retired_instructions, 5);
    assert_eq!(report.work.emitted_blocks, 4);
    assert_eq!(
        memory.code_generation(FrameGpa::new(CODE)),
        Some(CodeGeneration(2))
    );
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
    let mut user_memory = Pages::default();
    let user_entry = load_elf(user_elf, &mut user_memory);
    let (cpu, mut memory) = enter_carrier(el1_elf, user_entry);
    memory.pages.append(&mut user_memory.pages);
    (cpu, memory, user_entry)
}

fn enter_carrier(el1_elf: &[u8], user_entry: u64) -> (CpuState, Pages) {
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

    let root = StagedCpu::initial_root(&RootBootFields {
        entry: user_entry,
        initial_stack_pointer: Some(LINUX_STACK_TOP - 16),
        el0_trampoline_entry: Some(LINUX_EL0_TRAMPOLINE_BASE),
        el1_vectors_base: Some(LINUX_EL1_VECTORS_BASE),
        stage1_page_tables_base: Some(LINUX_PAGE_TABLES_BASE),
    })
    .snapshot();
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.pstate.daif = InterruptMasks::ALL;
    assert_eq!(cpu.pstate.save().0, root.pstate);
    cpu.sp_el0 = StackPointer(root.sp_el0);
    // The persistent executor supplies this slot-local stack after staging.
    cpu.sp_el1 = StackPointer(LINUX_SYSCALL_MAILBOX_BASE);
    cpu.pc = ProgramCounter(root.pc);
    cpu.el1.elr = ProgramCounter(root.elr_el1);
    cpu.el1.spsr = SavedPstate(root.spsr_el1);
    cpu.el1.vbar = VirtualAddress(root.vbar);
    cpu.el1.mair = SystemValue(root.mair);
    cpu.el1.tcr = SystemValue(root.tcr);
    cpu.named.ttbr0 = SystemValue(root.ttbr0);
    cpu.named.ttbr1 = SystemValue(root.ttbr1);
    cpu.el1.sctlr = Sctlr(root.sctlr);
    cpu.el1.cntkctl = SystemValue(root.cntkctl_el1);
    (cpu, memory)
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

const MAX_RETIRED_BRANCHES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetiredBranch {
    from: u64,
    to: u64,
    lr: u64,
    sp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetiredSyscall {
    pc: u64,
    lr: u64,
    sp: u64,
    nr: u64,
    args: [u64; 6],
    ret: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
struct El0Fault {
    pc: u64,
    esr: u64,
    far: u64,
}

struct TracingRunner {
    inner: HostBlockRunner,
    branches: VecDeque<RetiredBranch>,
    syscalls: Vec<RetiredSyscall>,
    pending_svc: Option<RetiredSyscall>,
    tpidr_writes: Vec<(u64, u64)>,
    first_el0_fault: Option<El0Fault>,
}

impl TracingRunner {
    fn new() -> Result<Self, HostError> {
        Ok(Self {
            inner: HostBlockRunner::new()?,
            branches: VecDeque::with_capacity(MAX_RETIRED_BRANCHES),
            syscalls: Vec::new(),
            pending_svc: None,
            tpidr_writes: Vec::new(),
            first_el0_fault: None,
        })
    }

    fn finish_pending(&mut self) {
        if let Some(svc) = self.pending_svc.take() {
            self.syscalls.push(svc);
        }
    }
}

impl ExecuteBlock for TracingRunner {
    type Error = HostError;
    type Code = HostCode;

    fn retain_blocks(&self) -> bool {
        self.inner.retain_blocks()
    }

    fn retain_stage1(&self) -> bool {
        self.inner.retain_stage1()
    }

    fn inline_memory(&self) -> bool {
        self.inner.inline_memory()
    }

    fn prepare(&mut self, block: &TranslatedBlock) -> Result<HostCode, HostError> {
        self.inner.prepare(block)
    }

    fn execute(
        &mut self,
        block: &TranslatedBlock,
        code: &HostCode,
        cpu: &mut CpuState,
    ) -> Result<usize, HostError> {
        self.execute_with_memory(block, code, cpu, BlockMemory::default())
    }

    fn execute_with_memory(
        &mut self,
        block: &TranslatedBlock,
        code: &HostCode,
        cpu: &mut CpuState,
        memory: BlockMemory<'_>,
    ) -> Result<usize, HostError> {
        let user = cpu.pstate.el == ExceptionLevel::El0;
        // Arm D1.10: 0x400 is the synchronous vector from lower EL in AArch64.
        // Record before the vector runs and HVC overwrites ESR_EL1.
        if !user && cpu.pc.0 == cpu.el1.vbar.0 + 0x400 && (cpu.el1.esr.0 >> 26) & 0x3f != 0x15 {
            self.first_el0_fault.get_or_insert(El0Fault {
                pc: cpu.el1.elr.0,
                esr: cpu.el1.esr.0,
                far: cpu.el1.far.0,
            });
        }
        if user {
            if let Some(mut svc) = self.pending_svc.take() {
                svc.ret = Some(x(cpu, 0) as i64);
                self.syscalls.push(svc);
            } else if let Some(last) = self.syscalls.last_mut()
                && last.ret.is_none()
            {
                last.ret = Some(x(cpu, 0) as i64);
            }
        }
        let exit_idx = self.inner.execute_with_memory(block, code, cpu, memory)?;
        if user {
            let sp = cpu.sp().0;
            let lr = x(cpu, 30);
            match block.exits().get(exit_idx).copied() {
                Some(BlockExit::Continue(target)) => {
                    if let Some(term) = block.guest().terminator()
                        && matches!(term.class(), InstructionClass::Branch(_))
                        && target != block.guest().next_pc()
                    {
                        if self.branches.len() == MAX_RETIRED_BRANCHES {
                            self.branches.pop_front();
                        }
                        self.branches.push_back(RetiredBranch {
                            from: term.pc().0,
                            to: target.0,
                            lr,
                            sp,
                        });
                    }
                }
                Some(BlockExit::Handler(ins)) => {
                    if matches!(
                        ins.class(),
                        InstructionClass::Exit(ExitReason::Exception(ExceptionKind::Svc))
                    ) {
                        self.pending_svc = Some(RetiredSyscall {
                            pc: ins.pc().0,
                            lr,
                            sp,
                            nr: x(cpu, 8),
                            args: core::array::from_fn(|n| x(cpu, n as u8)),
                            ret: None,
                        });
                    } else if ins.word() & 0xffff_ffe0 == 0xd51b_d040 {
                        // DDI0487G.a C6.2.196: MSR TPIDR_EL0, Xt (S3_3_C13_C0_2).
                        let rt = (ins.word() & 31) as u8;
                        let val = if rt == 31 { 0 } else { x(cpu, rt) };
                        self.tpidr_writes.push((ins.pc().0, val));
                    }
                }
                None => {}
            }
        }
        Ok(exit_idx)
    }
}

fn probe_traced(
    cpu: &mut CpuState,
    memory: &mut Pages,
    runner: &mut TracingRunner,
    budget: u64,
) -> Report<HostError> {
    let before = runner.inner.publication_work();
    let start = std::time::Instant::now();
    let report = run(
        cpu,
        &mut ExclusiveMonitor::default(),
        memory,
        runner,
        BlockLimits::default(),
        budget,
    );
    print_work(
        &report,
        runner.inner.publication_work().since(before),
        start.elapsed(),
        true,
    );
    runner.finish_pending();
    report
}

#[repr(C, align(64))]
struct AlignedRecord<const N: usize>([u8; N]);

/// Populate a zero-valid `#[repr(C)]` ABI record through its typed atomic
/// methods and write the resulting bytes into guest physical `Pages`.
fn load_abi_record<T, const N: usize>(memory: &mut Pages, at: u64, init: impl FnOnce(&T)) {
    assert_eq!(N, core::mem::size_of::<T>());
    assert!(core::mem::align_of::<AlignedRecord<N>>() >= core::mem::align_of::<T>());
    let mut buf = AlignedRecord([0u8; N]);
    let ptr = buf.0.as_mut_ptr().cast::<T>();
    // SAFETY: `AlignedRecord<N>` has size `size_of::<T>()` and >=64-byte
    // alignment, and all-zero bytes are the initialized `::new()` state of
    // `CurrentTask`, `DelegatedOpenFile`, and `FdMapSlot`. `ptr` derives
    // mutable provenance over `buf.0`, and the shared borrow ends before
    // `buf.0` is copied into `memory`.
    unsafe { init(&*ptr) };
    memory.load(at, &buf.0);
}

/// Admit slot 0's root task (`CurrentTask[0]`) and bind guest fds 0..=2 to the
/// carrier's stdio streams (`FdMap` + `DelegatedOpenFile`), matching the minimum
/// host publication `PendingFamilies::poll` / `file_write` authenticate before
/// forwarding host-backed stdio crossings via `HVC #2`.
fn admit_root_task_with_stdio(memory: &mut Pages) {
    load_abi_record::<CurrentTask, { core::mem::size_of::<CurrentTask>() }>(
        memory,
        EL1_CURRENT_TASKS_BASE,
        |task| {
            task.mm.thread_generation.store(1, Ordering::Relaxed);
            task.publish_host_loaded(1, ContextGeneration::new(NonZeroU64::new(1).unwrap()));
            task.set(El1TaskId::from_linux_tid(1), SnapshotGeneration::INITIAL, 1);
        },
    );
    for (fd, (flags, binding)) in [
        (0u32, (DELEGATED_FLAG_READABLE, HostObjectBinding::STDIN)),
        (1u32, (DELEGATED_FLAG_WRITABLE, HostObjectBinding::STDOUT)),
        (2u32, (DELEGATED_FLAG_WRITABLE, HostObjectBinding::STDERR)),
    ] {
        bind_host_fixture_fd(memory, fd, flags, binding, false);
    }
}

fn bind_host_fixture_fd(
    memory: &mut Pages,
    fd: u32,
    flags: u32,
    binding: HostObjectBinding,
    cloexec: bool,
) {
    use carrick_mem::linux_abi::LINUX_FD_CLOEXEC;
    let handle = fd + 1;
    load_abi_record::<DelegatedOpenFile, { core::mem::size_of::<DelegatedOpenFile>() }>(
        memory,
        EL1_OPEN_FILE_TABLE_BASE + u64::from(fd) * core::mem::size_of::<DelegatedOpenFile>() as u64,
        |open| {
            open.flags.store(flags, Ordering::Relaxed);
            open.generation.store(1, Ordering::Relaxed);
            open.bind_host_object(binding);
            open.state.store(DELEGATED_STATE_GUEST, Ordering::Release);
        },
    );
    load_abi_record::<FdMapSlot, { core::mem::size_of::<FdMapSlot>() }>(
        memory,
        EL1_FD_MAP_BASE + u64::from(fd) * core::mem::size_of::<FdMapSlot>() as u64,
        |slot| {
            let fd_flags = if cloexec { LINUX_FD_CLOEXEC as u32 } else { 0 };
            slot.set_with_flags(1, fd, handle, 1, fd_flags);
        },
    );
}

fn unbind_host_fixture_fd(memory: &mut Pages, fd: u32) {
    load_abi_record::<FdMapSlot, { size_of::<FdMapSlot>() }>(
        memory,
        EL1_FD_MAP_BASE + u64::from(fd) * size_of::<FdMapSlot>() as u64,
        FdMapSlot::clear,
    );
}

fn complete_mailbox_syscall(memory: &mut Pages, return_value: i64) {
    let mb = LINUX_SYSCALL_MAILBOX_BASE;
    memory.load(
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, return_value) as u64,
        &(return_value as u64).to_le_bytes(),
    );
    memory.load(
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, response_action) as u64,
        &1u32.to_le_bytes(),
    );
    memory.load(
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, state) as u64,
        &2u32.to_le_bytes(),
    );
}

fn read_cstr(memory: &mut Pages, mut at: u64, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < max {
        let mut b = [0u8; 1];
        if memory.read(VirtualAddress(at), &mut b).is_err() || b[0] == 0 {
            break;
        }
        out.push(b[0]);
        at += 1;
    }
    out
}

fn read_initial_stack_auxv(memory: &mut Pages, sp: u64) -> (u64, Vec<u8>, Vec<(u64, u64)>) {
    let argc = read_u64(memory, sp);
    let argv0_ptr = read_u64(memory, sp + 8);
    let argv0 = read_cstr(memory, argv0_ptr, 64);
    let mut cursor = sp + 8 * (1 + argc + 1);
    while read_u64(memory, cursor) != 0 {
        cursor += 8;
    }
    cursor += 8;
    let mut auxv = Vec::new();
    loop {
        let a_type = read_u64(memory, cursor);
        let a_val = read_u64(memory, cursor + 8);
        cursor += 16;
        if a_type == 0 {
            break;
        }
        auxv.push((a_type, a_val));
    }
    (argc, argv0, auxv)
}

#[test]
#[ignore = "requires production CARRICK_A64_ELF and the pinned arm64 musl rust-std target"]
fn production_el1_image_runs_static_musl_hello_to_first_carrier_call() {
    use carrick_mem::{
        elf::plan_elf_load_bytes,
        linux_abi::{
            LINUX_AT_HWCAP, LINUX_AT_HWCAP2, LINUX_AT_PAGESZ, LINUX_AT_RANDOM,
            LINUX_AT_SYSINFO_EHDR,
        },
        memory::{
            LINUX_STACK_SIZE, build_linux_initial_stack, linux_auxv_from_load_plan_with_vdso,
        },
    };
    use carrick_softcpu_aarch64::GUEST_CPU_PROFILE;
    use std::process::Command;

    let elf = std::fs::read(std::env::var_os("CARRICK_A64_ELF").expect("set CARRICK_A64_ELF"))
        .expect("read the production EL1 ELF");
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/musl_hello.rs");
    let out = std::env::temp_dir().join(format!("carrick-musl-hello-{}", std::process::id()));
    let status = Command::new("rustc")
        .args([
            "--target",
            "aarch64-unknown-linux-musl",
            "-C",
            "relocation-model=static",
            "-C",
            "debuginfo=2",
            "-o",
        ])
        .arg(&out)
        .arg(fixture)
        .status()
        .expect("compile static musl hello with the pinned toolchain");
    assert!(status.success());
    let user_elf = std::fs::read(&out).expect("read musl hello");
    std::fs::remove_file(out).expect("remove compiled musl hello");

    assert_eq!(field(&user_elf, 16, 2), 2, "musl hello must be ET_EXEC");
    let build_guest = || {
        let (mut cpu, mut memory, entry) = enter_carrier_root(&elf, &user_elf);
        let plan = plan_elf_load_bytes(&user_elf).unwrap();
        // No vvar/vDSO pages are mapped in this carrier-root fixture.
        let mut auxv = linux_auxv_from_load_plan_with_vdso(&plan, None, false);
        for entry in &mut auxv {
            match entry.a_type {
                LINUX_AT_HWCAP => entry.a_val = GUEST_CPU_PROFILE.hwcap().bits(),
                LINUX_AT_HWCAP2 => entry.a_val = GUEST_CPU_PROFILE.hwcap2().bits(),
                _ => {}
            }
        }
        let (stack, sp, _) = build_linux_initial_stack(
            vec![b"musl-hello".to_vec()],
            Vec::new(),
            &auxv,
            None,
            LINUX_STACK_TOP,
            4 * PAGE,
        )
        .unwrap();
        let (offset, bytes) = stack.shared_initialized_bytes();
        memory.load(stack.start + offset, &bytes);
        cpu.sp_el0 = StackPointer(sp);
        (cpu, memory, entry, sp)
    };

    // 1. Mutation / pre-admission control: when CurrentTask[0] is unissued
    // (all-zero), EL1 refuses every ring-owned syscall in-ring with -ENOSYS
    // (-38): set_tid_address (96), then sanitize_standard_fds's ppoll (73),
    // which causes std::rt::lang_start_internal to call musl abort() and fault
    // on `strb wzr, [x0]` (FAR=0, ESR=0x92000047, mailbox.state=0).
    let (mut unadmitted_cpu, mut unadmitted_mem, _, sp) = build_guest();
    let (argc, argv0, auxv) = read_initial_stack_auxv(&mut unadmitted_mem, sp);
    assert_eq!(argc, 1);
    assert_eq!(argv0, b"musl-hello");
    assert_eq!(
        auxv.iter()
            .find(|(k, _)| *k == LINUX_AT_PAGESZ)
            .map(|(_, v)| *v),
        Some(PAGE)
    );
    assert!(
        auxv.iter()
            .find(|(k, _)| *k == LINUX_AT_RANDOM)
            .is_some_and(|(_, v)| *v != 0)
    );
    for (key, expected) in [
        (LINUX_AT_HWCAP, GUEST_CPU_PROFILE.hwcap().bits()),
        (LINUX_AT_HWCAP2, GUEST_CPU_PROFILE.hwcap2().bits()),
    ] {
        assert_eq!(
            auxv.iter().find(|(k, _)| *k == key).map(|(_, val)| *val),
            Some(expected)
        );
    }
    assert!(
        !auxv.iter().any(|(k, _)| *k == LINUX_AT_SYSINFO_EHDR),
        "AT_SYSINFO_EHDR must not be advertised without mapped vDSO pages"
    );

    let mut unadmitted_trace = TracingRunner::new().expect("Linux arm64 host runner");
    let unadmitted_report = probe_traced(
        &mut unadmitted_cpu,
        &mut unadmitted_mem,
        &mut unadmitted_trace,
        1_000_000,
    );
    let mb = LINUX_SYSCALL_MAILBOX_BASE;
    let unadmitted_state = read_u32(
        &mut unadmitted_mem,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, state) as u64,
    );
    println!(
        "musl hello (unadmitted CurrentTask[0] control): {unadmitted_report}; ESR={:#x} ELR={:#x} FAR={:#x} TPIDR_EL0={:#x} mailbox.state={unadmitted_state}",
        unadmitted_cpu.el1.esr.0,
        unadmitted_cpu.el1.elr.0,
        unadmitted_cpu.el1.far.0,
        unadmitted_cpu.named.tpidrel0.0,
    );
    for (pc, val) in &unadmitted_trace.tpidr_writes {
        println!("  unadmitted MSR TPIDR_EL0 @ {pc:#x} <= {val:#x}");
    }
    for (idx, sc) in unadmitted_trace.syscalls.iter().enumerate() {
        println!(
            "  unadmitted svc[{idx}]: pc={:#x} lr={:#x} nr={} args=[{:#x}, {:#x}, {:#x}, {:#x}] -> {:?}",
            sc.pc, sc.lr, sc.nr, sc.args[0], sc.args[1], sc.args[2], sc.args[3], sc.ret
        );
    }
    let tail_start = unadmitted_trace.branches.len().saturating_sub(16);
    for br in unadmitted_trace.branches.iter().skip(tail_start) {
        println!(
            "  unadmitted el0 branch: {:#x} -> {:#x} (lr={:#x}, sp={:#x})",
            br.from, br.to, br.lr, br.sp
        );
    }
    assert_ne!(unadmitted_cpu.named.tpidrel0.0, 0);
    assert!(!unadmitted_trace.tpidr_writes.is_empty());
    let unadmitted_nrs: Vec<(u64, Option<i64>)> = unadmitted_trace
        .syscalls
        .iter()
        .map(|s| (s.nr, s.ret))
        .collect();
    assert_eq!(
        unadmitted_nrs,
        vec![
            (96, Some(-38)),
            (73, Some(-38)),
            (135, Some(-38)),
            (130, Some(-38)),
            (135, Some(-38)),
            (135, Some(-38)),
            (134, Some(-38)),
            (130, Some(-38)),
            (135, Some(-38)),
        ],
        "unadmitted root task must refuse ring-owned syscalls with -ENOSYS and trigger abort"
    );
    assert_eq!(
        (
            unadmitted_state,
            unadmitted_cpu.el1.esr.0,
            unadmitted_cpu.el1.far.0
        ),
        (0, 0x9200_0047, 0)
    );

    // 2. Admitted root task + stdio fds: set_tid_address (96) is still ignored
    // by __init_tp (-38 without Aarch64NativeProcessService), and
    // sanitize_standard_fds's ppoll([0, 1, 2], 3, {0, 0}, NULL, 8) (nr=73)
    // reaches PendingFamilies::poll and forwards cleanly via HVC #2.
    let (mut cpu, mut memory, entry, _) = build_guest();
    admit_root_task_with_stdio(&mut memory);
    let mut runner = TracingRunner::new().expect("Linux arm64 host runner");
    let report = probe_traced(&mut cpu, &mut memory, &mut runner, 1_000_000);
    let state = read_u32(
        &mut memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, state) as u64,
    );
    let trap_kind = read_u32(
        &mut memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind) as u64,
    );
    let nr = read_u64(
        &mut memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, native_nr) as u64,
    );
    let args_off = mb + core::mem::offset_of!(Aarch64SyscallMailbox, args) as u64;
    let nfds = read_u64(&mut memory, args_off + 8);
    let resume = read_u64(
        &mut memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, resume_pc) as u64,
    );
    println!(
        "musl hello entry {entry:#x}: {report}; ESR={:#x} ELR={:#x} FAR={:#x} TPIDR_EL0={:#x}; mailbox state={state} trap_kind={trap_kind} nr={nr} nfds={nfds} resume_pc={resume:#x}",
        cpu.el1.esr.0, cpu.el1.elr.0, cpu.el1.far.0, cpu.named.tpidrel0.0
    );
    for (idx, sc) in runner.syscalls.iter().enumerate() {
        println!(
            "  admitted svc[{idx}]: pc={:#x} lr={:#x} nr={} args=[{:#x}, {:#x}, {:#x}, {:#x}] -> {:?}",
            sc.pc, sc.lr, sc.nr, sc.args[0], sc.args[1], sc.args[2], sc.args[3], sc.ret
        );
    }
    assert!(memory.read_boot_root);
    assert_ne!(cpu.named.tpidrel0.0, 0);
    assert!(
        matches!(
            report.stop,
            Stop::Event { event: Event::ProviderExit(exit), .. } if exit.immediate.value() == 2
        ),
        "{report}"
    );
    assert_eq!((state, trap_kind, cpu.el1.esr.0), (1, 1, 0x5600_0000));
    assert_eq!(
        (nr, nfds),
        (73, 3),
        "expected first carrier crossing to be SYS_ppoll on stdio [0, 1, 2]"
    );
    assert_eq!(
        runner
            .syscalls
            .iter()
            .map(|s| (s.nr, s.ret))
            .collect::<Vec<_>>(),
        vec![(96, Some(-38)), (73, None)]
    );

    // 3. Diagnostic continuation past SYS_ppoll=0: sanitize_standard_fds
    // succeeds without aborting, and lang_start_internal immediately invokes
    // signal(SIGPIPE, SIG_IGN) -> rt_sigaction(13, ..., 8) (nr=134). With
    // CurrentTask[0] issued but shared-carrier ZoneTables / SignalTable absent,
    // dispatch::dispatch forwards Family::Signal(RtSigaction) via HVC #2
    // (ForwardReason::FamilyFallback) to the host carrier.
    complete_mailbox_syscall(&mut memory, 0);
    let after_ppoll = probe_traced(&mut cpu, &mut memory, &mut runner, 1_000_000);
    let next_state = read_u32(
        &mut memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, state) as u64,
    );
    let next_trap = read_u32(
        &mut memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, trap_kind) as u64,
    );
    let next_nr = read_u64(
        &mut memory,
        mb + core::mem::offset_of!(Aarch64SyscallMailbox, native_nr) as u64,
    );
    let signum = read_u64(&mut memory, args_off);
    let sigsetsize = read_u64(&mut memory, args_off + 24);
    println!(
        "musl hello after ppoll=0: {after_ppoll}; mailbox state={next_state} trap_kind={next_trap} nr={next_nr} signum={signum} sigsetsize={sigsetsize}",
    );
    for (idx, sc) in runner.syscalls.iter().skip(2).enumerate() {
        println!(
            "  post-ppoll svc[{}]: pc={:#x} lr={:#x} nr={} args=[{:#x}, {:#x}, {:#x}, {:#x}] -> {:?}",
            idx + 2,
            sc.pc,
            sc.lr,
            sc.nr,
            sc.args[0],
            sc.args[1],
            sc.args[2],
            sc.args[3],
            sc.ret
        );
    }
    assert!(
        matches!(
            after_ppoll.stop,
            Stop::Event { event: Event::ProviderExit(exit), .. } if exit.immediate.value() == 2
        ),
        "{after_ppoll}"
    );
    assert_eq!((next_state, next_trap, cpu.el1.esr.0), (1, 1, 0x5600_0000));
    assert_eq!(
        (next_nr, signum, sigsetsize),
        (134, 13, 8),
        "expected post-ppoll carrier crossing to be SYS_rt_sigaction(SIGPIPE, ..., 8)"
    );
    assert_eq!(
        runner
            .syscalls
            .iter()
            .map(|s| (s.nr, s.ret))
            .collect::<Vec<_>>(),
        vec![(96, Some(-38)), (73, Some(0)), (134, None)]
    );
}

/// Set CARRICK_A64_DYN_ROOT to a fixture root containing `hello` and its
/// `lib/ld-linux-aarch64.so.1` and `lib/libc.so.6` from the same sysroot. Build
/// `hello` from `fixtures/glibc_hello.c` using `aarch64-linux-gnu-gcc -O1
/// -fno-builtin -Wl,-rpath,/lib` and use the production `CARRICK_A64_ELF`.
#[test]
fn production_el1_image_runs_dynamic_glibc_hello() {
    let Some(root) = std::env::var_os("CARRICK_A64_DYN_ROOT") else {
        return;
    };
    let root = FixtureRoot::new(root.into());
    let hello = root.read("/hello").expect("read dynamic hello");
    let program = carrick_mem::elf::ElfProgram::load(&hello, 183, &|path| {
        assert_eq!(path, "/lib/ld-linux-aarch64.so.1");
        root.read(path).ok()
    })
    .expect("plan glibc hello and its interpreter");
    let (mut cpu, mut memory) = stage_dynamic(&program, vec![b"/hello".to_vec()], Vec::new());
    let mut replies = DynamicRoot::new(root, "/hello");
    let result = run_dynamic_glibc(&mut cpu, &mut memory, &mut replies, 1_000_000);
    assert_eq!(result, Ok(0));
    assert_eq!(replies.stdout, b"dynamic glibc hello\n");
    assert_eq!(replies.report_ifuncs(&mut memory, &program), 3);
}

/// Set CARRICK_A64_PYTHON_ROOT to an extracted linux/arm64 python:3.12-slim
/// filesystem and CARRICK_A64_ELF to the production EL1 image.
#[test]
fn production_el1_image_runs_dynamic_cpython() {
    let Some(root) = std::env::var_os("CARRICK_A64_PYTHON_ROOT") else {
        return;
    };
    let root = FixtureRoot::new(root.into());
    let executable = "/usr/local/bin/python3";
    let python = root.read(executable).expect("read CPython");
    let program = carrick_mem::elf::ElfProgram::load(&python, 183, &|path| root.read(path).ok())
        .expect("plan CPython and its interpreter");
    let (mut cpu, mut memory) = stage_dynamic(
        &program,
        vec![
            executable.as_bytes().to_vec(),
            b"-c".to_vec(),
            b"import sys; print(sys.version.split()[0])".to_vec(),
        ],
        vec![b"HOME=/tmp".to_vec()],
    );
    let mut replies = DynamicRoot::new(root, executable);
    let result = run_dynamic_glibc(&mut cpu, &mut memory, &mut replies, 100_000_000);
    replies.report_ifuncs(&mut memory, &program);
    assert_eq!(result, Ok(0));
    let version = std::str::from_utf8(&replies.stdout).unwrap();
    let patch = version
        .strip_prefix("3.12.")
        .and_then(|v| v.strip_suffix('\n'));
    assert!(
        patch.is_some_and(|v| v.parse::<u32>().is_ok()),
        "{version:?}"
    );
}

fn stage_dynamic(
    program: &carrick_mem::elf::ElfProgram<'_>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
) -> (CpuState, Pages) {
    use carrick_mem::{
        elf::LoadPlan,
        linux_abi::{
            LINUX_AT_BASE, LINUX_AT_ENTRY, LINUX_AT_EXECFN, LINUX_AT_HWCAP, LINUX_AT_HWCAP2,
            LINUX_AT_PAGESZ, LINUX_AT_PHDR, LINUX_AT_PHENT, LINUX_AT_PHNUM, LINUX_AT_RANDOM,
            LINUX_AT_SECURE,
        },
        memory::{
            LINUX_STACK_SIZE, build_linux_initial_stack, linux_auxv_from_load_plan_with_vdso,
        },
    };
    use carrick_softcpu_aarch64::GUEST_CPU_PROFILE;

    let el1 = std::fs::read(std::env::var_os("CARRICK_A64_ELF").expect("set CARRICK_A64_ELF"))
        .expect("read the production EL1 ELF");
    let interpreter = program.interpreter.as_ref().expect("dynamic fixture");
    let (mut cpu, mut memory) = enter_carrier(&el1, program.entry());

    fn map_plan(memory: &mut Pages, plan: &LoadPlan, bytes: &[u8]) {
        for segment in &plan.segments {
            let start = segment.virtual_address;
            let end = start + segment.memory_size;
            for page in (start & !(PAGE - 1)..end).step_by(PAGE as usize) {
                memory.map_zero(page);
            }
            let offset = segment.file_offset as usize;
            memory.load(start, &bytes[offset..offset + segment.file_size as usize]);
        }
    }
    map_plan(&mut memory, &program.executable, program.executable_bytes);
    map_plan(&mut memory, &interpreter.plan, &interpreter.bytes);

    let mut auxv =
        linux_auxv_from_load_plan_with_vdso(&program.executable, program.interpreter_base(), false);
    for entry in &mut auxv {
        match entry.a_type {
            LINUX_AT_HWCAP => entry.a_val = GUEST_CPU_PROFILE.hwcap().bits(),
            LINUX_AT_HWCAP2 => entry.a_val = GUEST_CPU_PROFILE.hwcap2().bits(),
            _ => {}
        }
    }
    let expected_argc = argv.len() as u64;
    let expected_argv0 = argv[0].clone();
    let (stack, sp, _) =
        build_linux_initial_stack(argv, envp, &auxv, None, LINUX_STACK_TOP, LINUX_STACK_SIZE)
            .unwrap();
    let (offset, bytes) = stack.shared_initialized_bytes();
    for page in (stack.start..LINUX_STACK_TOP).step_by(PAGE as usize) {
        memory.map_zero(page);
    }
    memory.load(stack.start + offset, &bytes);
    cpu.sp_el0 = StackPointer(sp);
    let (argc, argv0, auxv) = read_initial_stack_auxv(&mut memory, sp);
    assert_eq!(argc, expected_argc);
    assert_eq!(argv0, expected_argv0);
    let aux = |key| auxv.iter().find(|(tag, _)| *tag == key).unwrap().1;
    assert_eq!(
        aux(LINUX_AT_PHDR),
        program.executable.program_header_address.unwrap()
    );
    assert_eq!(
        aux(LINUX_AT_PHENT),
        u64::from(program.executable.program_header_entry_size)
    );
    assert_eq!(
        aux(LINUX_AT_PHNUM),
        u64::from(program.executable.program_header_count)
    );
    assert_eq!(aux(LINUX_AT_ENTRY), program.executable.entry);
    assert_eq!(aux(LINUX_AT_BASE), interpreter.plan.load_bias);
    assert_eq!(aux(LINUX_AT_PAGESZ), PAGE);
    assert_eq!(aux(LINUX_AT_SECURE), 0);
    assert_eq!(aux(LINUX_AT_HWCAP), GUEST_CPU_PROFILE.hwcap().bits());
    assert_eq!(aux(LINUX_AT_HWCAP2), GUEST_CPU_PROFILE.hwcap2().bits());
    assert_eq!(
        read_cstr(&mut memory, aux(LINUX_AT_EXECFN), 128),
        expected_argv0
    );
    memory
        .read(VirtualAddress(aux(LINUX_AT_RANDOM)), &mut [0; 16])
        .unwrap();
    println!(
        "auxv HWCAP={:#x} HWCAP2={:#x}",
        aux(LINUX_AT_HWCAP),
        aux(LINUX_AT_HWCAP2)
    );

    admit_root_task_with_stdio(&mut memory);
    (cpu, memory)
}

fn run_dynamic_glibc(
    cpu: &mut CpuState,
    memory: &mut Pages,
    replies: &mut DynamicRoot,
    budget: u64,
) -> Result<u64, String> {
    use carrick_mem::linux_abi::syscall::lookup_aarch64;
    let mut runner = TracingRunner::new().unwrap();
    let mut blocks = 0;
    let mut work = RunWork::default();
    let mut undefined = 0;
    let mut traced = 0;
    let mut counts = BTreeMap::<u64, u64>::new();
    let mut forwarded = BTreeMap::<u64, u64>::new();
    let mut monitor = ExclusiveMonitor::default();
    let started = std::time::Instant::now();
    let result = loop {
        let report = run(
            cpu,
            &mut monitor,
            memory,
            &mut runner,
            BlockLimits::default(),
            budget - blocks,
        );
        blocks += report.blocks;
        work.retired_instructions += report.work.retired_instructions;
        work.dispatches += report.work.dispatches;
        work.executed_blocks += report.work.executed_blocks;
        work.decoded_blocks += report.work.decoded_blocks;
        work.emitted_blocks += report.work.emitted_blocks;
        work.stage1_walks += report.work.stage1_walks;
        work.memory_exits += report.work.memory_exits;
        undefined += report.undefined_el0_deliveries;
        runner.finish_pending();
        for svc in &runner.syscalls[traced..] {
            let name = lookup_aarch64(svc.nr).map_or("unknown", |call| call.name);
            println!(
                "  svc {} {name} @ {:#x} args={:x?} ret={:?}",
                svc.nr, svc.pc, svc.args, svc.ret
            );
            *counts.entry(svc.nr).or_default() += 1;
            if name == "close" && svc.ret == Some(0) {
                replies.retire_ring_close(svc.args[0]);
            }
        }
        traced = runner.syscalls.len();
        println!(
            "  {report}; ESR={:#x} ELR={:#x} FAR={:#x}",
            cpu.el1.esr.0, cpu.el1.elr.0, cpu.el1.far.0
        );
        if let Some(El0Fault { pc, esr, far }) = runner.first_el0_fault {
            // The diagnostic image has identity-mapped guest code.
            let mut bytes = [0; 4];
            let word = memory
                .read(VirtualAddress(pc), &mut bytes)
                .ok()
                .map(|()| u32::from_le_bytes(bytes));
            break Err(format!(
                "EL0 sync fault image={:?} ELR={pc:#x} ESR={esr:#x} FAR={far:#x} word={word:08x?}: {report}",
                replies.image_at(pc)
            ));
        }
        if report.undefined_el0_deliveries != 0 {
            break Err(format!(
                "EL0 undefined delivery without a traced vector: {report}"
            ));
        }
        let Stop::Event {
            event: Event::ProviderExit(exit),
            ..
        } = report.stop
        else {
            break Err(format!(
                "EL1 boot probe stopped at PC={:#x} image={:?}: {report}",
                report.pc.0,
                replies.image_at(report.pc.0)
            ));
        };
        if exit.immediate.value() != 2 {
            break Err(format!("unexpected provider exit: {report}"));
        }
        let mb = LINUX_SYSCALL_MAILBOX_BASE;
        let state = read_u32(memory, mb + offset_of!(Aarch64SyscallMailbox, state) as u64);
        let kind = read_u32(
            memory,
            mb + offset_of!(Aarch64SyscallMailbox, trap_kind) as u64,
        );
        let nr = read_u64(
            memory,
            mb + offset_of!(Aarch64SyscallMailbox, native_nr) as u64,
        );
        let args = core::array::from_fn(|i| {
            read_u64(
                memory,
                mb + offset_of!(Aarch64SyscallMailbox, args) as u64 + 8 * i as u64,
            )
        });
        println!("  mailbox state={state} kind={kind} nr={nr} args={args:x?}");
        let Some(svc) = runner.syscalls.last() else {
            break Err(format!("mailbox without an EL0 SVC: {report}"));
        };
        if (state, kind, nr, args) != (1, 1, svc.nr, svc.args) || svc.ret.is_some() {
            break Err(format!("unexpected mailbox for EL0 SVC {svc:?}: {report}"));
        }
        let name = lookup_aarch64(nr).map_or("unknown", |call| call.name);
        *forwarded.entry(nr).or_default() += 1;
        // exit_group is terminal: the mailbox request supplies its status.
        if name == "exit_group" {
            break Ok(args[0]);
        }
        match replies.reply(memory, name, args) {
            Ok(value) => {
                println!("    synthetic {nr} {name} -> {value} ({value:#x})");
                complete_mailbox_syscall(memory, value);
            }
            Err(error) => break Err(format!("{error}, nr={nr} PC={:#x}", svc.pc)),
        }
    };
    let elapsed = started.elapsed().as_secs_f64();
    replies.report_opens();
    println!("engine work={work:?}");
    for (nr, count) in &counts {
        let name = lookup_aarch64(*nr).map_or("unknown", |call| call.name);
        let mailbox = forwarded.get(nr).copied().unwrap_or(0);
        println!("syscall {nr:3} {name:16} total={count:3} mailbox={mailbox:3}");
    }
    println!(
        "dynamic result={result:?} blocks={blocks} retired={} undefined={} syscalls={} elapsed={elapsed:.6}s blocks/s={:.0} instr/s={:.0}",
        work.retired_instructions,
        undefined,
        counts.values().sum::<u64>(),
        blocks as f64 / elapsed,
        work.retired_instructions as f64 / elapsed
    );
    println!(
        "guest stdout={:?}",
        String::from_utf8_lossy(&replies.stdout)
    );
    result
}
