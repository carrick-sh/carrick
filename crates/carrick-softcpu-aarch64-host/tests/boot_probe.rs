//! The first production boot probe (#1236 M2-1): the production EL1 image
//! runs from its ELF entry through the native copy-through engine under a
//! block budget, and prints `boots to PC=... after N blocks / fails at ...`.
//! Set CARRICK_A64_ELF to the freshly built carrick-el1-image
//! OUT_DIR/el1-target/aarch64-unknown-none-softfloat/el1-image/carrick-el1.
//! Linux arm64 only (the hosted arm64 job's `--ignored` step).
//!
//! The image is entered the way the loader's vector code enters it: EL1h,
//! DAIF masked, x0 = a trap frame for an SVC from EL0, x30 = a return
//! sentinel. Memory is flat (no stage-1 walker in this slice): the PT_LOAD
//! segments at their link addresses, one stack and the trap frame. A second,
//! diagnostic pass maps each faulting page as zero and continues, to show
//! what the image touches next; it is reported, never asserted.
#![cfg(all(target_arch = "aarch64", target_os = "linux"))]
// Test helpers outside #[test] fns fail loudly on malformed fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_softcpu_aarch64::dispatch::{Report, Stop, run};
use carrick_softcpu_aarch64::handler::{Event, ExclusiveMonitor, GuestMemory, MemoryFault};
use carrick_softcpu_aarch64::state::{
    CpuState, ExceptionLevel, InterruptMasks, ProgramCounter, RegisterValue, StackPointer,
    StackSelect, VirtualAddress,
};
use carrick_softcpu_aarch64::translate::BlockLimits;
use carrick_softcpu_aarch64::{Gpr, OperandRegister};
use carrick_softcpu_aarch64_host::{HostBlockRunner, HostError};
use std::collections::BTreeMap;

const PAGE: u64 = 4096;

/// Page-granular flat guest memory: unmapped pages fault.
#[derive(Default)]
struct Pages(BTreeMap<u64, Box<[u8; PAGE as usize]>>);

impl Pages {
    fn map_zero(&mut self, page: u64) {
        self.0
            .entry(page & !(PAGE - 1))
            .or_insert_with(|| Box::new([0; PAGE as usize]));
    }
    fn load(&mut self, at: u64, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            let a = at + i as u64;
            self.map_zero(a);
            self.0.get_mut(&(a & !(PAGE - 1))).unwrap()[(a % PAGE) as usize] = *b;
        }
    }
    fn byte(&mut self, a: u64) -> Result<&mut u8, MemoryFault> {
        self.0
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

/// Outside the image, the ABI regions and the user range.
const STACK_TOP: u64 = 0x7e00_0000_0000;
const TRAP_FRAME: u64 = 0x7e00_0001_0000;
const RETURN_SENTINEL: u64 = 0x7e00_dead_0000;

fn set_x(cpu: &mut CpuState, n: u8, v: u64) {
    cpu.write_operand(OperandRegister::Gpr(Gpr::new(n).unwrap()), RegisterValue(v));
}

/// The entry state: `carrick_el1_abi::TrapFrame` is x[31] at 0x000, elr at
/// 0x0f8, spsr 0x100, esr 0x108, slot 0x110, far 0x118. The frame describes
/// `getpid` (aarch64 nr 172 in x8) by SVC #0 from EL0 (ESR EC 0x15, IL).
fn enter(elf: &[u8]) -> (CpuState, Pages) {
    let mut memory = Pages::default();
    let entry = load_elf(elf, &mut memory);
    for page in 0..4 {
        memory.map_zero(STACK_TOP - PAGE * (page + 1));
    }
    let mut frame = [0u8; 0x120];
    frame[8 * 8..8 * 9].copy_from_slice(&172u64.to_le_bytes());
    frame[0xf8..0x100].copy_from_slice(&0x40_1000u64.to_le_bytes());
    frame[0x108..0x110].copy_from_slice(&((0x15u64 << 26) | (1 << 25)).to_le_bytes());
    memory.load(TRAP_FRAME, &frame);
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.pstate.daif = InterruptMasks::ALL;
    cpu.sp_el1 = StackPointer(STACK_TOP);
    cpu.pc = ProgramCounter(entry);
    set_x(&mut cpu, 0, TRAP_FRAME);
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
        "boot probe (strict flat memory) from entry {:#x}: {strict}",
        entry.0
    );
    assert!(strict.blocks > 0, "no block ran: {strict}");

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
