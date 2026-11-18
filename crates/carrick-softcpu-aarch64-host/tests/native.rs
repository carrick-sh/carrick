//! Native execution witnesses for the copy-through engine (#1236). They run
//! only on a Linux arm64 host (the hosted ubuntu-24.04-arm job): guest words
//! go through split -> emit -> publish -> call -> dispatcher exactly as the
//! production `dispatch::run` does, and the results are compared with known
//! answers derived from the Arm ARM DDI0487 C6.2 instruction pseudocode and,
//! for register-only code, with the same words run directly on the host CPU.
#![cfg(all(target_arch = "aarch64", target_os = "linux"))]
// Test helpers outside #[test] fns fail loudly on malformed fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_host_jit::JitCodeBuffer;
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

// Arm ARM DDI0487G.a C6.2. The same words run through the translator and
// directly as the body of an AAPCS64 leaf, giving an independent host result.
const SNIPPET: [u32; 17] = [
    0x9a81600e, // csel x14, x0, x1, vs
    0xab010002, // adds x2, x0, x1
    0x9a812003, // csel x3, x0, x1, cs
    0xcb011004, // sub x4, x0, x1, lsl #4
    0xeb000025, // subs x5, x1, x0
    0x9a9f57e6, // cset x6, mi
    0x92089c07, // and x7, x0, #0xff00ff00ff00ff00
    0xaa001c28, // orr x8, x1, x0, lsl #7
    0xca813409, // eor x9, x0, x1, asr #13
    0xd2b7ddea, // movz x10, #0xbeef, lsl #16
    0xf2fbd5aa, // movk x10, #0xdead, lsl #48
    0x9282468b, // movn x11, #0x1234
    0xd349fc0c, // lsr x12, x0, #9
    0xfa411002, // ccmp x0, x1, #2, ne
    0x9a80842d, // csinc x13, x1, x0, hi
    0x9b01380e, // madd x14, x0, x1, x14
    0xea20002f, // bics x15, x1, x0
];

/// Run the unchanged snippet, with X17 pointing to 16 registers and NZCV.
fn hardware(input: [u64; 16], nzcv: u64) -> ([u64; 16], u64) {
    // LDP/STP Xn, Xn+1, [X17, #8*n]: signed imm7 in units of eight bytes.
    let pairs = |opcode: u32| {
        (0..16u32)
            .step_by(2)
            .map(move |n| opcode | (n << 15) | ((n + 1) << 10) | (17 << 5) | n)
    };
    let code: Vec<u8> = [
        0xaa00_03f1u32, // mov x17, x0
        0xf940_4230,    // ldr x16, [x17, #128]
        0xd51b_4210,    // msr nzcv, x16
    ]
    .into_iter()
    .chain(pairs(0xa940_0000))
    .chain(SNIPPET)
    .chain(pairs(0xa900_0000))
    .chain([
        0xd53b_4210, // mrs x16, nzcv
        0xf900_4230, // str x16, [x17, #128]
        0xd65f_03c0, // ret
    ])
    .flat_map(u32::to_le_bytes)
    .collect();
    let mut frame = [0; 17];
    frame[..16].copy_from_slice(&input);
    frame[16] = nzcv;
    let mut jit = JitCodeBuffer::new(code.len()).unwrap();
    let entry = jit.publish(&code).unwrap();
    // SAFETY: this live RX leaf uses only caller-saved registers and NZCV.
    // Its loads and stores stay inside the 17-word frame passed in X0.
    let call = unsafe { std::mem::transmute::<usize, extern "C" fn(*mut u64)>(entry as usize) };
    call(frame.as_mut_ptr());
    (core::array::from_fn(|n| frame[n]), frame[16])
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
    let words = SNIPPET;
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
