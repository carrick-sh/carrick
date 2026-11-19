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
use carrick_softcpu_aarch64::handler::{Event, ExclusiveMonitor, GuestMemory, MemoryFault};
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
        self.starts.push(block.guest().start().0);
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

#[test]
fn native_dispatch_delivers_wait_and_prefetch_traps() {
    const VBAR: u64 = 0x4001_0000;
    for (start, word, il, esr, far, starts) in [
        (
            CODE,
            0xd503207f,
            false,
            0x07e0_0000,
            0,
            &([CODE, VBAR + 0x400])[..],
        ),
        (
            CODE,
            0xd503205f,
            false,
            0x07e0_0001,
            0,
            &([CODE, VBAR + 0x400])[..],
        ),
        (
            CODE,
            0xd28000e0,
            true,
            0x3a00_0000,
            0,
            &([VBAR + 0x400])[..],
        ),
        (
            CODE + 2,
            0xd28000e0,
            true,
            0x8a00_0000,
            CODE + 2,
            &([VBAR + 0x400])[..],
        ),
    ] {
        let mut cpu = CpuState::default();
        cpu.pc = ProgramCounter(start);
        cpu.pstate.il = il;
        cpu.el1.vbar = VirtualAddress(VBAR);
        let mut memory = Flat::default();
        memory.put_words(CODE, &[word]);
        // Read the syndrome in the EL1 vector, then return to the provider.
        memory.put_words(VBAR + 0x400, &[0xd5385201, 0xd4000002]);
        let (report, observed) = run_at(&mut cpu, &mut memory);
        assert_eq!(observed, [starts, &[VBAR + 0x404]].concat(), "{report}");
        assert!(
            matches!(
                report.stop,
                Stop::Event {
                    event: Event::ProviderExit(_),
                    ..
                }
            ),
            "{report}"
        );
        assert_eq!(x(&cpu, 0), 0);
        assert_eq!(x(&cpu, 1), esr);
        assert_eq!(cpu.el1.elr.0, start);
        assert_eq!(cpu.el1.far.0, far);
        assert_eq!(cpu.el1.spsr.0, u64::from(il) << 20);
    }
}

#[test]
fn native_svc_vector_returns_to_el0_and_wakes_one_wfe() {
    const VECTOR: u64 = 0x4001_0400;
    let mut memory = Flat::default();
    // svc #7; wfe; movz x0, #7; wfe
    memory.put_words(CODE, &[0xd40000e1, 0xd503205f, 0xd28000e0, 0xd503205f]);
    // mrs x1, spsr_el1; mrs x2, elr_el1; eret
    memory.put_words(VECTOR, &[0xd5384001, 0xd5384022, 0xd69f03e0]);
    let mut cpu = CpuState::default();
    cpu.pc = ProgramCounter(CODE);
    cpu.pstate.nzcv = 10;
    cpu.pstate.daif.0 = 5;
    cpu.pstate.uao = true;
    cpu.el1.vbar = VirtualAddress(VECTOR & !0x7ff);
    cpu.el1.sctlr.0 = 1 << 18; // nTWE
    let origin = cpu.pstate;
    let (report, starts) = run_at(&mut cpu, &mut memory);
    assert_eq!(
        starts,
        [CODE, VECTOR, VECTOR + 4, VECTOR + 8, CODE + 4, CODE + 8]
    );
    assert!(
        matches!(
            report.stop,
            Stop::Event {
                event: Event::Hint(carrick_softcpu_aarch64::Hint::Wfe),
                ..
            }
        ),
        "{report}"
    );
    assert_eq!(report.pc.0, CODE + 16);
    assert_eq!(
        [x(&cpu, 0), x(&cpu, 1), x(&cpu, 2)],
        [7, 0xa080_0140, CODE + 4]
    );
    assert_eq!(cpu.pstate, origin);
}

#[test]
fn native_dispatch_uses_virtual_sysregs_and_reserved_bit_rules() {
    let mut memory = Flat::default();
    memory.put_words(
        CODE,
        &[
            0xd518d020, // msr contextidr_el1, x0
            0xd538d021, // mrs x1, contextidr_el1
            0xd51b4402, // msr fpcr, x2
            0xd53b4403, // mrs x3, fpcr
            0xd51b4422, // msr fpsr, x2
            0xd53b4424, // mrs x4, fpsr
            0xd53800a5, // mrs x5, mpidr_el1
            0xd53be006, // mrs x6, cntfrq_el0
            0xd4000002, // hvc #0
        ],
    );
    let mut cpu = CpuState::default();
    cpu.pc = ProgramCounter(CODE);
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.named.mpidr = SystemValue(0x1_0002_0304);
    cpu.named.cntfrq = SystemValue(25_000_000);
    set_x(&mut cpu, 0, 0x1234_abcd_9876_5432);
    set_x(&mut cpu, 2, 0xffff_ffff_0440_6081);
    let (report, starts) = run_at(&mut cpu, &mut memory);
    assert!(
        matches!(
            report.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ),
        "{report}"
    );
    assert_eq!(
        starts,
        core::array::from_fn::<_, 9, _>(|n| CODE + 4 * n as u64)
    );
    assert_eq!(x(&cpu, 1), 0x9876_5432);
    assert_eq!(x(&cpu, 3), 0x0440_0000);
    assert_eq!(x(&cpu, 4), 0x81);
    assert_eq!(x(&cpu, 5), 0x1_8002_0304);
    assert_eq!(x(&cpu, 6), 25_000_000);
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

#[test]
fn native_dispatch_refetches_after_isb_and_enters_the_fault_vector() {
    const VECTOR: u64 = 0x4000_8200;
    for (word, esr, far) in [
        (0xd50c_7800, 0x0200_0000, 0),       // at s1e2r, x0: undefined at EL1
        (0xc8df_fc20, 0x9600_0021, 0x10001), // ldar x0, [x1]: alignment fault
    ] {
        let mut memory = Flat::default();
        memory.put_words(
            CODE,
            &[
                0xd280_00e0, // movz x0, #7
                0xd503_3fdf, // isb
                word,
                0xd280_0120, // movz x0, #9 (the fault must prevent this)
            ],
        );
        memory.put_words(
            VECTOR,
            &[
                0xd538_5202, // mrs x2, esr_el1
                0xd538_4023, // mrs x3, elr_el1
                0xd538_6004, // mrs x4, far_el1
                0xd400_0002, // hvc #0
            ],
        );
        let mut cpu = CpuState::default();
        cpu.pc = ProgramCounter(CODE);
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.el1.vbar = VirtualAddress(VECTOR - 0x200);
        set_x(&mut cpu, 1, 0x10001);
        let (report, starts) = run_at(&mut cpu, &mut memory);
        assert!(
            matches!(
                report.stop,
                Stop::Event {
                    event: Event::ProviderExit(_),
                    ..
                }
            ),
            "{report}"
        );
        assert_eq!(
            starts,
            [CODE, CODE + 8, VECTOR, VECTOR + 4, VECTOR + 8, VECTOR + 12]
        );
        assert_eq!(
            (x(&cpu, 0), x(&cpu, 2), x(&cpu, 3), x(&cpu, 4)),
            (7, esr, CODE + 8, far)
        );
    }
}

#[test]
fn native_musl_simd_survives_memory_exits() {
    const DATA: u64 = CODE + 0x100;
    for (fill, expected) in [(0xa5, [0xa5; 16]), (0x1c, [0x1c; 16])] {
        let mut cpu = CpuState::default();
        cpu.pc = ProgramCounter(CODE);
        cpu.el1.sctlr.0 = 1 << 18; // allow EL0 WFE
        set_x(&mut cpu, 0, DATA);
        set_x(&mut cpu, 1, fill);
        let mut memory = Flat::default();
        memory.put(DATA, &[0xff; 16]);
        memory.put_words(
            CODE,
            &[
                0x4e01_0c28, // dup v8.16b, w1
                0x3d80_0008, // str q8, [x0] (handler exit)
                0x3dc0_001f, // ldr q31, [x0] (handler exit)
                0x4e18_3fe2, // umov x2, v31.d[1]
                0xd503_205f, // wfe
            ],
        );

        let (report, starts) = run_at(&mut cpu, &mut memory);
        assert_eq!(starts, [CODE, CODE + 8, CODE + 12], "{report}");
        assert_eq!(report.pc.0, CODE + 20);
        assert_eq!(x(&cpu, 2), u64::from_le_bytes([fill as u8; 8]));
        let mut actual = [0; 16];
        memory.read(VirtualAddress(DATA), &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn native_simd_block_preserves_callee_saved_host_simd() {
    use carrick_softcpu_aarch64::translate::{emit_block, split_span};
    let blocks = split_span(
        ProgramCounter(CODE),
        &[0x4e01_0c28], // dup v8.16b, w1
        BlockLimits::default(),
    );
    let block = emit_block(&blocks[0]).unwrap();
    let bytes: Vec<_> = block.words().iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut jit = JitCodeBuffer::new(bytes.len()).unwrap();
    let entry = jit.publish(&bytes).unwrap();
    // DDI0487G.a encodings for an AAPCS64 caller with a live value in D8.
    let caller_code: Vec<_> = [
        0xa9be_7bfdu32, // stp x29, x30, [sp, #-32]!
        0xfd00_0be8,    // str d8, [sp, #16]
        0x0f03_e668,    // movi v8.8b, #0x73
        0xd63f_0020,    // blr x1
        0x4e08_3d00,    // umov x0, v8.d[0]
        0xfd40_0be8,    // ldr d8, [sp, #16]
        0xa8c2_7bfd,    // ldp x29, x30, [sp], #32
        0xd65f_03c0,    // ret
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let mut caller_jit = JitCodeBuffer::new(caller_code.len()).unwrap();
    let caller_entry = caller_jit.publish(&caller_code).unwrap();
    // SAFETY: this RX function preserves the caller's D8, LR and SP,
    // calls the live RX block in X1 with the frame in X0 and returns in X0.
    let call = unsafe {
        std::mem::transmute::<usize, extern "C" fn(*mut BlockFrame, u64) -> u64>(
            caller_entry as usize,
        )
    };
    let mut region = vec![
        BlockFrame::default();
        carrick_softcpu_aarch64_host::FRAME_REGION_BYTES / size_of::<BlockFrame>()
    ];
    let index = region.len() - 1;
    region[index].slots[1] = 0xa5;
    let frame = region.as_mut_ptr().wrapping_add(index);
    let host_d8 = call(frame, entry);
    assert_eq!(host_d8, u64::from_le_bytes([0x73; 8]));
    assert_eq!(region[index].vectors[8], u128::from_le_bytes([0xa5; 16]));
}

#[test]
fn el0_fp_and_simd_families_match_native() {
    use core::arch::asm;

    macro_rules! compare {
        ($word:expr, $native:literal, $vectors:expr) => {{
            let input: [u128; 2] = $vectors;
            let mut native_vector = 0u128;
            let (native_x0, native_flags): (u64, u64);
            // SAFETY: these fixed instructions use only caller-saved GPRs
            // and vectors. The memory operands point at local arrays.
            unsafe {
                asm!(
                    "ldp q0, q1, [{input}]",
                    "mov x0, xzr",
                    "msr nzcv, xzr",
                    $native,
                    "str q0, [{output}]",
                    "mrs {flags}, nzcv",
                    "mov {result}, x0",
                    input = in(reg) input.as_ptr(),
                    output = in(reg) &mut native_vector,
                    result = lateout(reg) native_x0,
                    flags = lateout(reg) native_flags,
                    out("x0") _, out("v0") _, out("v1") _,
                );
            }
            let mut memory = Flat::default();
            memory.put_words(CODE, &[$word]);
            let mut cpu = CpuState::default();
            cpu.pc = ProgramCounter(CODE);
            cpu.vectors[..2].copy_from_slice(&input);
            let (report, _) = run_at(&mut cpu, &mut memory);
            assert_eq!(report.stop, Stop::Fetch(VirtualAddress(CODE + 4)), "{}", $native);
            assert_eq!(report.blocks, 1, "{}", $native);
            assert_eq!(cpu.vectors[0], native_vector, "{}", $native);
            assert_eq!(x(&cpu, 0), native_x0, "{}", $native);
            assert_eq!(u64::from(cpu.pstate.nzcv) << 28, native_flags, "{}", $native);
        }};
    }

    let floats = [1.5f64.to_bits() as u128, 2.0f64.to_bits() as u128];
    compare!(0x1e61_2800, "fadd d0, d0, d1", floats);
    compare!(0x9e78_0000, "fcvtzs x0, d0", floats);
    compare!(0x1e61_2000, "fcmp d0, d1", floats);
    compare!(0x4e61_d400, "fadd v0.2d, v0.2d, v1.2d", floats);

    let bytes = [
        u128::from_le_bytes(core::array::from_fn(|i| (i + 50) as u8)),
        u128::from_le_bytes(core::array::from_fn(|i| (15 - i) as u8)),
    ];
    compare!(0x4e21_8400, "add v0.16b, v0.16b, v1.16b", bytes);
    compare!(0x4e01_3800, "zip1 v0.16b, v0.16b, v1.16b", bytes);
    compare!(0x4e01_0000, "tbl v0.16b, {{v0.16b}}, v1.16b", bytes);
}

#[test]
fn el0_fp_status_survives_an_exit_and_host_controls_are_preserved() {
    use core::arch::asm;

    let mut memory = Flat::default();
    // FDIV D0,D0,D1; ISB; MRS X0,FPSR; MRS X1,FPCR
    memory.put_words(CODE, &[0x1e61_1800, 0xd503_3fdf, 0xd53b_4420, 0xd53b_4401]);
    let mut cpu = CpuState::default();
    cpu.pc = ProgramCounter(CODE);
    cpu.vectors[0] = 1.0f64.to_bits() as u128;
    cpu.named.fpcr = SystemValue(1 << 22); // round toward positive infinity
    let (fpcr_before, fpsr_before, fpcr_after, fpsr_after): (u64, u64, u64, u64);
    // SAFETY: the four MRS instructions only observe the thread's state.
    unsafe {
        asm!("mrs {0}, fpcr", "mrs {1}, fpsr", out(reg) fpcr_before, out(reg) fpsr_before);
    }
    let (report, _) = run_at(&mut cpu, &mut memory);
    // SAFETY: the MRS instructions only observe the thread's state.
    unsafe {
        asm!("mrs {0}, fpcr", "mrs {1}, fpsr", out(reg) fpcr_after, out(reg) fpsr_after);
    }
    assert_eq!((fpcr_before, fpsr_before), (fpcr_after, fpsr_after));
    assert_eq!(
        report.stop,
        Stop::Fetch(VirtualAddress(CODE + 16)),
        "{report}"
    );
    assert_eq!(x(&cpu, 0), 2); // DZC, with division-by-zero trap disabled
    assert_eq!(x(&cpu, 1), 1 << 22);
    assert_eq!(cpu.vectors[0] as u64, f64::INFINITY.to_bits());

    // 1.0 + 2^-53 is halfway between two doubles. Guest RMode=+Inf
    // changes the arithmetic result relative to the default ties-to-even.
    let mut memory = Flat::default();
    memory.put_words(CODE, &[0x1e61_2800]); // fadd d0, d0, d1
    cpu.pc = ProgramCounter(CODE);
    cpu.vectors[0] = 1.0f64.to_bits() as u128;
    cpu.vectors[1] = (1023u128 - 53) << 52; // 2^-53
    let (report, _) = run_at(&mut cpu, &mut memory);
    assert_eq!(report.stop, Stop::Fetch(VirtualAddress(CODE + 4)));
    assert_eq!(cpu.vectors[0] as u64, 1.0f64.to_bits() + 1);
}

#[test]
fn el0_simd_structure_load_store_matches_native() {
    use core::arch::asm;

    const DATA: u64 = 0x4000_8000;
    let input: [u8; 32] = core::array::from_fn(|i| i as u8 + 3);
    let mut out = [0u8; 32];
    let mut native_vectors = [0u128; 2];
    // SAFETY: both structure accesses address 32-byte local arrays.
    unsafe {
        asm!(
            "ld2 {{v0.16b, v1.16b}}, [{input}]",
            "st2 {{v0.16b, v1.16b}}, [{output}]",
            "stp q0, q1, [{vectors}]",
            input = in(reg) input.as_ptr(),
            output = in(reg) out.as_mut_ptr(),
            vectors = in(reg) native_vectors.as_mut_ptr(),
            out("v0") _, out("v1") _, options(nostack, preserves_flags),
        );
    }
    let mut cpu = CpuState::default();
    cpu.pc = ProgramCounter(CODE);
    set_x(&mut cpu, 0, DATA);
    let mut memory = Flat::default();
    memory.put(DATA, &input);
    memory.put(DATA + 32, &[0; 32]);
    // LD2 (post-index by 32); ST2 (no writeback).
    memory.put_words(CODE, &[0x4cdf_8000, 0x4c00_8000]);
    let (report, _) = run_at(&mut cpu, &mut memory);
    assert_eq!(
        report.stop,
        Stop::Fetch(VirtualAddress(CODE + 8)),
        "{report}"
    );
    assert_eq!(report.blocks, 2);
    assert_eq!(x(&cpu, 0), DATA + 32);
    assert_eq!(cpu.vectors[..2], native_vectors);
    let mut stored = [0; 32];
    memory.read(VirtualAddress(DATA + 32), &mut stored).unwrap();
    assert_eq!(stored, out);
}

#[test]
fn el0_crc32_matches_native_on_crc_hosts() {
    use core::arch::asm;
    if !std::arch::is_aarch64_feature_detected!("crc") {
        return;
    }
    let input = u64::from_le_bytes(*b"12345678");
    for word in [0x9ac1_4c02, 0x9ac1_5c02] {
        let native: u64;
        // SAFETY: CRC32X and CRC32CX operate only on registers. They are
        // executed here only after qualifying the host CRC extension.
        unsafe {
            if word == 0x9ac1_4c02 {
                asm!(".inst 0x9ac14c02", in("x0") u64::MAX, in("x1") input, out("x2") native);
            } else {
                asm!(".inst 0x9ac15c02", in("x0") u64::MAX, in("x1") input, out("x2") native);
            }
        }
        let mut cpu = CpuState::default();
        cpu.pc = ProgramCounter(CODE);
        set_x(&mut cpu, 0, u64::MAX);
        set_x(&mut cpu, 1, input);
        let mut memory = Flat::default();
        memory.put_words(CODE, &[word]);
        let (report, _) = run_at(&mut cpu, &mut memory);
        assert_eq!(
            report.stop,
            Stop::Fetch(VirtualAddress(CODE + 4)),
            "{report}"
        );
        assert_eq!(x(&cpu, 2), native);
    }
}

#[test]
fn el0_simd_register_offset_pair_and_literal_match_native() {
    use core::arch::asm;

    const DATA: u64 = 0x4000_8000;
    let input = [0x0123_4567_89ab_cdefu128, 0xfedc_ba98_7654_3210];
    let mut native_output = [0u128; 3];
    let mut scratch = [0u128; 6];
    scratch[..2].copy_from_slice(&input);
    // SAFETY: load, store and writeback stay inside the scratch and output
    // arrays. The literal is embedded in the asm block and skipped by B.
    unsafe {
        asm!(
            "mov x1, #1",
            "ldr q0, [{base}, x1, lsl #4]",
            "ldr q1, [{base}]",
            "stp q0, q1, [{base}, #32]!",
            "ldp q2, q3, [{base}], #32",
            "ldr q4, 2f",
            "b 3f",
            ".balign 16",
            "2:",
            ".quad 0x1020304050607080, 0x1122334455667788",
            "3:",
            "stp q2, q3, [{output}]",
            "str q4, [{output}, #32]",
            base = inout(reg) scratch.as_mut_ptr() => _,
            output = in(reg) native_output.as_mut_ptr(),
            out("x1") _, out("v0") _, out("v1") _, out("v2") _, out("v3") _, out("v4") _,
            options(nostack, preserves_flags),
        );
    }
    let mut cpu = CpuState::default();
    cpu.pc = ProgramCounter(CODE);
    set_x(&mut cpu, 0, DATA);
    set_x(&mut cpu, 1, 1);
    cpu.vectors[1] = input[0];
    let mut memory = Flat::default();
    memory.put(DATA + 16, &input[1].to_le_bytes());
    memory.put(DATA + 32, &[0; 32]);
    memory.put(
        CODE + 28,
        &0x1122_3344_5566_7788_1020_3040_5060_7080u128.to_le_bytes(),
    );
    memory.put_words(CODE, &[0x3ce1_7800, 0xad81_0400, 0xacc1_0c02, 0x9c00_0084]);
    let (report, _) = run_at(&mut cpu, &mut memory);
    assert_eq!(
        report.stop,
        Stop::Fetch(VirtualAddress(CODE + 16)),
        "{report}"
    );
    assert_eq!(report.blocks, 4);
    assert_eq!(x(&cpu, 0), DATA + 64);
    assert_eq!(cpu.vectors[2..5], native_output);
}
