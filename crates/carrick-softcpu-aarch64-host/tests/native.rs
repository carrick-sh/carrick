//! Native execution witnesses for the copy-through engine (#1236). They run
//! only on a Linux arm64 host (the hosted ubuntu-24.04-arm job): guest words
//! go through split -> emit -> publish -> call -> dispatcher exactly as the
//! production `dispatch::run` does, and the results are compared with known
//! answers derived from the Arm ARM DDI0487 C6.2 instruction pseudocode and,
//! for register-only code, with the same words run directly on the host CPU.
#![cfg(all(target_arch = "aarch64", target_os = "linux"))]
// Test helpers outside #[test] fns fail loudly on malformed fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_softcpu_aarch64::dispatch::{ExecuteBlock, Report, Stop, run};
use carrick_softcpu_aarch64::handler::{ExclusiveMonitor, GuestMemory, MemoryFault};
use carrick_softcpu_aarch64::state::{
    CpuState, ExceptionLevel, ProgramCounter, RegisterValue, StackPointer, StackSelect,
    SystemValue, VirtualAddress,
};
use carrick_softcpu_aarch64::translate::{BlockFrame, BlockLimits, TranslatedBlock};
use carrick_softcpu_aarch64::{Gpr, OperandRegister};
use carrick_softcpu_aarch64_host::{HostBlockRunner, HostError};
use std::collections::BTreeMap;

/// Byte-granular flat guest memory: unmapped bytes fault.
#[derive(Default)]
struct Flat(BTreeMap<u64, u8>);

impl Flat {
    fn put_words(&mut self, at: u64, words: &[u32]) {
        for (i, w) in words.iter().enumerate() {
            self.put(at + 4 * i as u64, &w.to_le_bytes());
        }
    }
    fn put(&mut self, at: u64, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            self.0.insert(at + i as u64, *b);
        }
    }
}

impl GuestMemory for Flat {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        for (i, b) in bytes.iter_mut().enumerate() {
            let a = VirtualAddress(address.0 + i as u64);
            *b = *self.0.get(&a.0).ok_or(MemoryFault { address: a })?;
        }
        Ok(())
    }
    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
        for i in 0..bytes.len() as u64 {
            if !self.0.contains_key(&(address.0 + i)) {
                return Err(MemoryFault {
                    address: VirtualAddress(address.0 + i),
                });
            }
        }
        self.put(address.0, bytes);
        Ok(())
    }
}

/// The production runner, recording where each block started.
struct Recording {
    runner: HostBlockRunner,
    starts: Vec<u64>,
}

impl ExecuteBlock for Recording {
    type Error = HostError;
    fn execute(
        &mut self,
        block: &TranslatedBlock,
        frame: &mut BlockFrame,
    ) -> Result<usize, HostError> {
        self.starts.push(block.guest.start.0);
        self.runner.execute(block, frame)
    }
}

fn x(cpu: &CpuState, n: u8) -> u64 {
    cpu.read_operand(OperandRegister::Gpr(Gpr::new(n).unwrap()))
        .0
}

fn set_x(cpu: &mut CpuState, n: u8, v: u64) {
    cpu.write_operand(OperandRegister::Gpr(Gpr::new(n).unwrap()), RegisterValue(v));
}

fn run_at(cpu: &mut CpuState, memory: &mut Flat) -> (Report<HostError>, Vec<u64>) {
    let mut exec = Recording {
        runner: HostBlockRunner::new().expect("Linux arm64 host runner"),
        starts: Vec::new(),
    };
    let report = run(
        cpu,
        &mut ExclusiveMonitor::default(),
        memory,
        &mut exec,
        BlockLimits::default(),
        64,
    );
    (report, exec.starts)
}

/// One register-only snippet, assembled once as words for the engine (the
/// `global_asm!` symbol) and once inline for the host CPU (`asm!`).
macro_rules! register_snippet {
    () => {
        concat!(
            "csel x14, x0, x1, vs\n",
            "adds x2, x0, x1\n",
            "csel x3, x0, x1, cs\n",
            "sub x4, x0, x1, lsl #4\n",
            "subs x5, x1, x0\n",
            "cset x6, mi\n",
            "and x7, x0, #0xff00ff00ff00ff00\n",
            "orr x8, x1, x0, lsl #7\n",
            "eor x9, x0, x1, asr #13\n",
            "movz x10, #0xbeef, lsl #16\n",
            "movk x10, #0xdead, lsl #48\n",
            "movn x11, #0x1234\n",
            "lsr x12, x0, #9\n",
            "ccmp x0, x1, #2, ne\n",
            "csinc x13, x1, x0, hi\n",
            "madd x14, x0, x1, x14\n",
            "bics x15, x1, x0\n",
        )
    };
}

core::arch::global_asm!(
    ".pushsection .text.carrick_register_snippet, \"ax\"",
    ".p2align 2",
    ".globl carrick_register_snippet_start",
    "carrick_register_snippet_start:",
    register_snippet!(),
    ".globl carrick_register_snippet_end",
    "carrick_register_snippet_end:",
    ".popsection",
);

unsafe extern "C" {
    static carrick_register_snippet_start: u32;
    static carrick_register_snippet_end: u32;
}

fn snippet_words() -> Vec<u32> {
    let start = &raw const carrick_register_snippet_start;
    let end = &raw const carrick_register_snippet_end;
    let len = (end as usize - start as usize) / 4;
    // SAFETY: both symbols bound the snippet in this binary's readable text
    // section; `len` words lie between them.
    unsafe { std::slice::from_raw_parts(start, len) }.to_vec()
}

/// The snippet on the host CPU: X0..X15 and NZCV in, X0..X15 and NZCV out.
fn hardware(input: [u64; 16], nzcv: u64) -> ([u64; 16], u64) {
    let mut r = input;
    let mut flags = nzcv;
    // SAFETY: the snippet only computes in X0..X15 and NZCV, all declared
    // as operands; it touches no memory and no stack.
    unsafe {
        core::arch::asm!(
            "msr nzcv, {flags}",
            register_snippet!(),
            "mrs {flags}, nzcv",
            flags = inout(reg) flags,
            inout("x0") r[0], inout("x1") r[1], inout("x2") r[2], inout("x3") r[3],
            inout("x4") r[4], inout("x5") r[5], inout("x6") r[6], inout("x7") r[7],
            inout("x8") r[8], inout("x9") r[9], inout("x10") r[10], inout("x11") r[11],
            inout("x12") r[12], inout("x13") r[13], inout("x14") r[14], inout("x15") r[15],
            options(nomem, nostack),
        );
    }
    (r, flags)
}

/// Known answers from the C6.2 pseudocode (AddWithCarry, ConditionHolds,
/// shifts, logical immediates, move wide), written out by hand.
fn known_answer(a: u64, b: u64, nzcv: u64) -> ([u64; 16], u64) {
    let v_in = nzcv & (1 << 28) != 0;
    let mut r = [0u64; 16];
    r[0] = a;
    r[1] = b;
    let x14 = if v_in { a } else { b };
    let (sum, carry) = a.overflowing_add(b);
    r[2] = sum;
    r[3] = if carry { a } else { b };
    r[4] = a.wrapping_sub(b << 4);
    r[5] = b.wrapping_sub(a);
    r[6] = r[5] >> 63;
    r[7] = a & 0xff00_ff00_ff00_ff00;
    r[8] = b | (a << 7);
    r[9] = a ^ ((b as i64 >> 13) as u64);
    r[10] = (0xbeef << 16) | (0xdead << 48);
    r[11] = !0x1234;
    r[12] = a >> 9;
    // CCMP x0, x1, #2, NE after SUBS x5 = x1 - x0: NE holds iff a != b.
    let (z, c) = if a != b {
        (false, a >= b)
    } else {
        (false, true)
    };
    r[13] = if c && !z { b } else { a.wrapping_add(1) };
    r[14] = a.wrapping_mul(b).wrapping_add(x14);
    r[15] = b & !a;
    let flags = ((r[15] >> 63) << 31) | (u64::from(r[15] == 0) << 30);
    (r, flags)
}

const CODE: u64 = 0x4000_1000;

fn engine(words: &[u32], input: [u64; 16], nzcv: u64) -> ([u64; 16], u64, Report<HostError>) {
    let mut memory = Flat::default();
    memory.put_words(CODE, words);
    let mut cpu = CpuState::default();
    for (n, v) in input.iter().enumerate() {
        set_x(&mut cpu, n as u8, *v);
    }
    cpu.pstate.nzcv = (nzcv >> 28) as u8;
    cpu.pc = ProgramCounter(CODE);
    let (report, _) = run_at(&mut cpu, &mut memory);
    let out = core::array::from_fn(|n| x(&cpu, n as u8));
    (out, u64::from(cpu.pstate.nzcv) << 28, report)
}

#[test]
fn register_only_blocks_match_known_answers_and_the_host_cpu() {
    let words = snippet_words();
    assert_eq!(words.len(), 17, "snippet assembled to an unexpected length");
    let cases = [
        (0x8000_0000_0000_0001, 0x8000_0000_0000_0003, 0x1000_0000),
        (0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321, 0xf000_0000),
        (7, 7, 0),
        (0, u64::MAX, 0x2000_0000),
    ];
    for (a, b, nzcv) in cases {
        let mut input = [0u64; 16];
        input[0] = a;
        input[1] = b;
        for (n, v) in input.iter_mut().enumerate().skip(2) {
            *v = 0x5a5a_0000_0000_0000 | n as u64;
        }
        let (got, got_flags, report) = engine(&words, input, nzcv);
        assert_eq!(
            report.stop,
            Stop::Fetch(VirtualAddress(CODE + 4 * words.len() as u64)),
            "{report}"
        );
        assert_eq!(report.blocks, 1, "{report}");
        let (want, want_flags) = known_answer(a, b, nzcv);
        assert_eq!(got, want, "engine vs known answer for a={a:#x} b={b:#x}");
        assert_eq!(got_flags, want_flags, "NZCV vs known answer");
        let (hw, hw_flags) = hardware(input, nzcv);
        assert_eq!(got, hw, "engine vs host CPU for a={a:#x} b={b:#x}");
        assert_eq!(got_flags, hw_flags, "NZCV vs host CPU");
    }
}

/// SP-naming and PC-relative words cannot run on the host directly (host SP
/// is the engine frame), so they are witnessed against known answers only.
#[test]
fn stack_pointer_and_pc_relative_words_use_guest_values() {
    let words = [
        0x9100_43e0, // add x0, sp, #16
        0xd100_83ff, // sub sp, sp, #32
        0x9100_03e1, // mov x1, sp
        0x1000_0042, // adr x2, .+8
        0xb000_0003, // adrp x3, .+0x1000 (page)
    ];
    let mut memory = Flat::default();
    memory.put_words(CODE, &words);
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.sp_el1 = StackPointer(0xffff_8000_0010_0000);
    cpu.sp_el0 = StackPointer(0x1111);
    cpu.pc = ProgramCounter(CODE);
    let (report, _) = run_at(&mut cpu, &mut memory);
    assert_eq!(report.blocks, 1, "{report}");
    assert_eq!(x(&cpu, 0), 0xffff_8000_0010_0010);
    assert_eq!(cpu.sp_el1, StackPointer(0xffff_8000_000f_ffe0));
    assert_eq!(cpu.sp_el0, StackPointer(0x1111), "the other banked SP");
    assert_eq!(x(&cpu, 1), 0xffff_8000_000f_ffe0);
    assert_eq!(x(&cpu, 2), CODE + 12 + 8);
    assert_eq!(x(&cpu, 3), ((CODE + 16) & !0xfff) + 0x1000);
}

#[test]
fn exits_restart_at_the_exact_pc_and_handlers_resume() {
    let words = [
        0xd280_00a0, // movz x0, #5
        0x9100_0c01, // add x1, x0, #3
        0xd538_d082, // mrs x2, tpidr_el1          -> handler
        0x8b01_0043, // add x3, x2, x1
        0xf940_00a4, // ldr x4, [x5]               -> handler
        0x9100_0486, // add x6, x4, #1
        0xd400_00e1, // svc #7                     -> exception entry
    ];
    const DATA: u64 = 0x4000_8000;
    const VBAR: u64 = 0x4001_0000;
    let mut memory = Flat::default();
    memory.put_words(CODE, &words);
    memory.put(DATA, &0x1111_2222_3333_4444u64.to_le_bytes());
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.el1.tpidr = SystemValue(0x70);
    cpu.el1.vbar = VirtualAddress(VBAR);
    set_x(&mut cpu, 5, DATA);
    cpu.pc = ProgramCounter(CODE);
    let (report, starts) = run_at(&mut cpu, &mut memory);
    // Three blocks: each handler resumes at the word after its exit.
    assert_eq!(starts, [CODE, CODE + 12, CODE + 20], "{report}");
    assert_eq!(report.blocks, 3);
    // SVC from EL1 with SP_EL1 enters the current-EL SPx synchronous vector
    // (D1.10.2, offset 0x200), whose page is unmapped here.
    assert_eq!(
        report.stop,
        Stop::Fetch(VirtualAddress(VBAR + 0x200)),
        "{report}"
    );
    assert_eq!(x(&cpu, 0), 5);
    assert_eq!(x(&cpu, 1), 8);
    assert_eq!(x(&cpu, 2), 0x70);
    assert_eq!(x(&cpu, 3), 0x78);
    assert_eq!(x(&cpu, 4), 0x1111_2222_3333_4444);
    assert_eq!(x(&cpu, 6), 0x1111_2222_3333_4445);
    assert_eq!(cpu.el1.elr, ProgramCounter(CODE + 28));
    assert_eq!(cpu.el1.esr.0 >> 26, 0x15, "EC: SVC from AArch64");
    assert_eq!(cpu.el1.esr.0 & 0xffff, 7, "ISS: the SVC immediate");
}
