//! Copy-through translator witnesses: splitter classes, emitted host words and
//! stubs. Expected words are hand-encoded from Arm ARM DDI0487G.a C6.2; with
//! CARRICK_LLVM_OBJDUMP set they are also checked against llvm-objdump text.
// Test helpers outside #[test] fns fail loudly on malformed fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use carrick_softcpu_aarch64::state::{
    CpuState, ExceptionLevel, ProgramCounter, StackSelect, SystemValue,
};
use carrick_softcpu_aarch64::translate::*;
use carrick_softcpu_aarch64::{ExceptionKind, Hint, Instruction, RegisterBranch, SystemDirection};
use std::collections::BTreeMap;
use std::process::Command;

const PC: ProgramCounter = ProgramCounter(0x2d04_0010_0f00);

fn block(words: &[u32]) -> GuestBlock {
    split_block(PC, BlockLimits::default(), |pc| {
        words.get(((pc.0 - PC.0) / 4) as usize).copied()
    })
}

fn class(word: u32) -> InstructionClass {
    GuestInstruction::decode(PC, word).class()
}

fn object(words: &[u32]) -> Vec<u8> {
    let text_end = 64 + 4 * words.len();
    let shoff = (text_end + 7) & !7;
    let mut b = vec![0; shoff + 128];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&1u16.to_le_bytes());
    b[18..20].copy_from_slice(&183u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&2u16.to_le_bytes());
    let section = shoff + 64;
    b[section + 4..section + 8].copy_from_slice(&1u32.to_le_bytes());
    b[section + 8..section + 16].copy_from_slice(&6u64.to_le_bytes());
    b[section + 24..section + 32].copy_from_slice(&64u64.to_le_bytes());
    b[section + 32..section + 40].copy_from_slice(&(4 * words.len() as u64).to_le_bytes());
    b[section + 48..section + 56].copy_from_slice(&4u64.to_le_bytes());
    for (i, w) in words.iter().enumerate() {
        b[64 + 4 * i..68 + 4 * i].copy_from_slice(&w.to_le_bytes());
    }
    b
}

/// llvm-objdump's text for `words`, or None when CARRICK_LLVM_OBJDUMP is unset.
fn objdump(words: &[u32]) -> Option<Vec<String>> {
    let tool = std::env::var_os("CARRICK_LLVM_OBJDUMP")?;
    let path = std::env::temp_dir().join(format!(
        "carrick-a64-translate-{}-{:08x}.o",
        std::process::id(),
        words.iter().fold(0u32, |a, w| a.rotate_left(5) ^ w)
    ));
    std::fs::write(&path, object(words)).expect("write object");
    let output = Command::new(tool)
        .args([
            "-d",
            "-M",
            "no-aliases",
            "--no-print-imm-hex",
            "--no-show-raw-insn",
            "--no-leading-addr",
        ])
        .arg(&path)
        .output()
        .expect("run llvm-objdump");
    std::fs::remove_file(&path).expect("remove object");
    assert!(output.status.success());
    let lines: Vec<String> = String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .filter(|s| s.starts_with(' ') && !s.trim().is_empty())
        .map(|l| {
            l.split("//")
                .next()
                .unwrap_or_default()
                .split(" <")
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    assert_eq!(lines.len(), words.len());
    Some(lines)
}

fn assert_text(words: &[u32], expected: &[&str]) {
    assert_eq!(words.len(), expected.len());
    if let Some(lines) = objdump(words) {
        for (i, (got, want)) in lines.iter().zip(expected).enumerate() {
            assert_eq!(got, want, "word {i} = {:#010x}", words[i]);
        }
    }
}

#[test]
fn register_only_words_copy_through() {
    for word in [
        0x8b020020u32, // add x0, x1, x2
        0xeb02003f,    // subs xzr, x1, x2 (cmp)
        0xab030041,    // adds x1, x2, x3
        0x9a020020,    // adc x0, x1, x2
        0x8a020020,    // and x0, x1, x2
        0xb2400020,    // orr x0, x1, #1
        0xd2800540,    // movz x0, #42
        0xf2a00020,    // movk x0, #1, lsl #16
        0xd3410c20,    // ubfm x0, x1, #1, #3
        0x9a821020,    // csel x0, x1, x2, ne
        0xfa411824,    // ccmp x1, #1, #4, ne
        0x9b027c20,    // madd x0, x1, x2, xzr (mul)
        0x9ac20820,    // udiv x0, x1, x2
        0x9ac22020,    // lslv x0, x1, x2
        0xdac01020,    // clz x0, x1
        0x93c21020,    // extr x0, x1, x2, #4
        0xd503201f,    // nop
        0xd5033bbf,    // dmb ish
    ] {
        assert_eq!(
            class(word),
            InstructionClass::Copy(CopyKind::Verbatim),
            "{word:08x}"
        );
    }
}

#[test]
fn exits_and_branches_classify() {
    let cases = [
        (
            0xd5033fdf,
            InstructionClass::Exit(ExitReason::InstructionSynchronization),
        ), // isb
        (0xf9400020, InstructionClass::Exit(ExitReason::Memory)), // ldr x0, [x1]
        (0xa9bf7bfd, InstructionClass::Exit(ExitReason::Memory)), // stp x29, x30, [sp, #-16]!
        (0xc85f7c20, InstructionClass::Exit(ExitReason::Memory)), // ldxr x0, [x1]
        (0xf8f1021f, InstructionClass::Exit(ExitReason::Memory)), // ldaddal x17, xzr, [x16]
        (0x58000040, InstructionClass::Exit(ExitReason::Memory)), // ldr x0, #8 (literal)
        (
            0xd5381000,
            InstructionClass::Exit(ExitReason::SystemRegister),
        ), // mrs x0, sctlr_el1
        (0xd50342df, InstructionClass::Exit(ExitReason::Pstate)), // msr daifset, #2
        (
            0xd508871f,
            InstructionClass::Exit(ExitReason::SystemOperation),
        ), // tlbi vmalle1
        (
            0xd503305f,
            InstructionClass::Exit(ExitReason::ClearExclusive),
        ),
        (
            0xd4000001,
            InstructionClass::Exit(ExitReason::Exception(ExceptionKind::Svc)),
        ),
        (
            0xd4000022,
            InstructionClass::Exit(ExitReason::Exception(ExceptionKind::Hvc)),
        ),
        (
            0xd4200000,
            InstructionClass::Exit(ExitReason::Exception(ExceptionKind::Brk)),
        ),
        (0xd69f03e0, InstructionClass::Exit(ExitReason::Eret)),
        (
            0xd503207f,
            InstructionClass::Exit(ExitReason::Hint(Hint::Wfi)),
        ),
        (0x00000000, InstructionClass::Exit(ExitReason::Undefined)),
        (
            0x94000002,
            InstructionClass::Branch(BranchKind::Direct { link: true }),
        ),
        (
            0x54000041,
            InstructionClass::Branch(BranchKind::Conditional),
        ), // b.ne +8
        (
            0xd65f03c0,
            InstructionClass::Branch(BranchKind::Indirect(RegisterBranch::Return)),
        ),
    ];
    for (word, expected) in cases {
        assert_eq!(class(word), expected, "{word:08x}");
    }
    assert_eq!(
        class(0x910003e0), // add x0, sp, #0 (mov x0, sp)
        InstructionClass::Copy(CopyKind::StackPointer)
    );
    assert_eq!(
        class(0x90000000), // adrp x0, 0
        InstructionClass::Copy(CopyKind::PcRelative)
    );
}

#[test]
fn splitter_ends_blocks_at_terminators_limits_and_pages() {
    let b = block(&[0xd2800540, 0x8b020020, 0xf9400020, 0xd503201f]);
    assert_eq!(b.instructions().len(), 3);
    assert_eq!(b.terminator().map(|i| i.word()), Some(0xf9400020));
    assert_eq!(b.next_pc(), ProgramCounter(PC.0 + 12));

    let nops = vec![0xd503201fu32; 200];
    let b = split_block(
        PC,
        BlockLimits {
            max_instructions: 5,
        },
        |pc| nops.get(((pc.0 - PC.0) / 4) as usize).copied(),
    );
    assert_eq!((b.instructions().len(), b.terminator()), (5, None));

    let near_end = ProgramCounter(0x1ff8);
    let b = split_block(near_end, BlockLimits::default(), |_| Some(0xd503201f));
    assert_eq!(
        b.instructions().len(),
        2,
        "a block never crosses a code page"
    );

    let b = split_block(PC, BlockLimits::default(), |_| None);
    assert!(b.instructions().is_empty());
    assert_eq!(emit_block(&b), Err(TranslateError::Empty));

    let spans = split_span(
        PC,
        &[0xd503201f, 0xd4000001, 0xd503201f],
        BlockLimits::default(),
    );
    assert_eq!(
        spans
            .iter()
            .map(|b| b.instructions().len())
            .collect::<Vec<_>>(),
        [2, 1]
    );
}

const ENTRY_TEXT: [&str; 27] = [
    "stp x29, x30, [sp, #-96]!",
    "stp x19, x20, [sp, #16]",
    "stp x21, x22, [sp, #32]",
    "stp x23, x24, [sp, #48]",
    "stp x25, x26, [sp, #64]",
    "stp x27, x28, [sp, #80]",
    "add x1, sp, #0",
    "str x1, [x0, #264]",
    "add sp, x0, #0",
    "ldr x1, [sp, #256]",
    "msr NZCV, x1",
    "ldp x0, x1, [sp, #0]",
    "ldp x2, x3, [sp, #16]",
    "ldp x4, x5, [sp, #32]",
    "ldp x6, x7, [sp, #48]",
    "ldp x8, x9, [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x20, x21, [sp, #160]",
    "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]",
    "ldp x26, x27, [sp, #208]",
    "ldp x28, x29, [sp, #224]",
    "ldr x30, [sp, #240]",
];

#[test]
fn entry_stub_is_exact() {
    let words = entry_stub();
    // Hand-encoded anchors: STP pre-index imm7=-12, MSR NZCV (3,3,4,2,0).
    assert_eq!(words[0], 0xa9ba7bfd);
    assert_eq!(words[6], 0x910003e1);
    assert_eq!(words[8], 0x9100001f);
    assert_eq!(words[10], 0xd51b4201);
    assert_eq!(words[11], 0xa94007e0);
    assert_eq!(words[26], 0xf9407bfe);
    assert_text(&words, &ENTRY_TEXT);
}

#[test]
fn common_exit_is_exact() {
    let words = common_exit();
    assert_eq!(words[15], 0xd53b4201, "mrs x1, nzcv");
    assert_eq!(*words.last().unwrap(), 0xd65f03c0, "ret");
    assert_eq!(
        words[words.len() - 2],
        0xa8c67bfd,
        "ldp x29, x30, [sp], #96"
    );
    let mut text: Vec<String> = (2..30)
        .step_by(2)
        .map(|r| format!("stp x{r}, x{}, [sp, #{}]", r + 1, 8 * r))
        .collect();
    text.extend(
        [
            "str x30, [sp, #240]",
            "mrs x1, NZCV",
            "str x1, [sp, #256]",
            "ldr x1, [sp, #264]",
            "add sp, x1, #0",
            "ldp x19, x20, [sp, #16]",
            "ldp x21, x22, [sp, #32]",
            "ldp x23, x24, [sp, #48]",
            "ldp x25, x26, [sp, #64]",
            "ldp x27, x28, [sp, #80]",
            "ldp x29, x30, [sp], #96",
            "ret x30",
        ]
        .map(String::from),
    );
    assert_text(&words, &text.iter().map(String::as_str).collect::<Vec<_>>());
}

fn body(t: &TranslatedBlock) -> &[u32] {
    &t.words()[entry_stub().len()..t.words().len() - common_exit().len()]
}

#[test]
fn copy_through_block_is_verbatim_then_one_fallthrough_exit() {
    let words = [0xd2800540u32, 0x8b020020, 0xeb02003f, 0x9a821020];
    let nops: Vec<u32> = words.iter().copied().chain([0xd503201f; 60]).collect();
    let t = emit_block(&block(&nops)).unwrap();
    assert_eq!(&body(&t)[..4], &words);
    assert_eq!(t.exits().len(), 1);
    assert_eq!(
        t.exits()[0],
        BlockExit::Continue(ProgramCounter(PC.0 + 4 * 64))
    );
    assert_eq!(t.terminator(), Terminator::Fallthrough(0));
    let site = &body(&t)[64..];
    assert_eq!(site[..2], [0xa90007e0, 0xd2800000]); // stp x0, x1, [sp]; movz x0, #0
    // b common_exit: the very next word.
    assert_eq!(site[2], 0x14000001);
}

#[test]
fn handler_exit_keeps_restart_pc_and_index() {
    // movz x0, #42; ldr x1, [x0]: the load does not run in the block.
    let t = emit_block(&block(&[0xd2800540, 0xf9400001])).unwrap();
    assert_eq!(body(&t)[0], 0xd2800540);
    assert_eq!(t.terminator(), Terminator::Handler(0));
    let BlockExit::Handler(i) = t.exits()[0] else {
        panic!("load must exit to its handler");
    };
    assert_eq!((i.pc(), i.word()), (ProgramCounter(PC.0 + 4), 0xf9400001));
    assert_eq!(body(&t)[1..3], [0xa90007e0, 0xd2800000]);
}

#[test]
fn adr_and_adrp_become_immediates() {
    // adr x3, #+0x14 ; adrp x4, #+0x1000 ; svc #0
    let t = emit_block(&block(&[0x100000a3, 0xb0000004, 0xd4000001])).unwrap();
    let adr = PC.0 + 0x14;
    let page = ((PC.0 + 4) & !0xfff) + 0x1000;
    let mut expected = materialize(3, adr);
    expected.extend(materialize(4, page));
    assert_eq!(&body(&t)[..expected.len()], &expected[..]);
    assert_eq!(
        materialize(3, adr),
        [
            0xd2800000 | (((adr & 0xffff) as u32) << 5) | 3,
            0xf2a00000 | ((((adr >> 16) & 0xffff) as u32) << 5) | 3,
            0xf2c00000 | ((((adr >> 32) & 0xffff) as u32) << 5) | 3,
        ]
    );
    assert_text(
        &materialize(3, adr),
        &[
            &format!("mov x3, #{}", adr & 0xffff),
            &format!("movk x3, #{}, lsl #16", (adr >> 16) & 0xffff),
            &format!("movk x3, #{}, lsl #32", (adr >> 32) & 0xffff),
        ],
    );
    // ADR to XZR has no architectural effect and emits nothing.
    let t = emit_block(&block(&[0x1000001f, 0xd4000001])).unwrap();
    assert_eq!(body(&t)[0], 0xa90007e0);
}

#[test]
fn stack_pointer_words_run_against_the_frame_slot() {
    // sub sp, sp, #32 ; add x0, sp, #16 ; svc #0
    let t = emit_block(&block(&[0xd10083ff, 0x910043e0, 0xd4000001])).unwrap();
    let expected = [
        0xf9008bf0u32, // str x16, [sp, #272]
        0xf9407ff0,    // ldr x16, [sp, #248]
        0xd1008210,    // sub x16, x16, #32
        0xf9007ff0,    // str x16, [sp, #248]
        0xf9408bf0,    // ldr x16, [sp, #272]
    ];
    assert_eq!(&body(&t)[..5], &expected);
    let second = &body(&t)[5..9];
    assert_eq!(
        second,
        [0xf9008bf0, 0xf9407ff0, 0x91004200, 0xf9408bf0],
        "add x0, sp, #16 reads guest SP and never writes it back"
    );
    assert_text(
        &body(&t)[..9],
        &[
            "str x16, [sp, #272]",
            "ldr x16, [sp, #248]",
            "sub x16, x16, #32",
            "str x16, [sp, #248]",
            "ldr x16, [sp, #272]",
            "str x16, [sp, #272]",
            "ldr x16, [sp, #248]",
            "add x0, x16, #16",
            "ldr x16, [sp, #272]",
        ],
    );
    // The scratch avoids every operand field: add x16, sp, x16 uses x17.
    let t = emit_block(&block(&[0x8b3063f0, 0xd4000001])).unwrap();
    assert_eq!(
        &body(&t)[..4],
        [0xf9008bf1, 0xf9407ff1, 0x8b306230, 0xf9408bf1]
    );
}

#[test]
fn direct_branches_exit_to_their_targets() {
    // bl +0x40
    let t = emit_block(&block(&[0x94000010])).unwrap();
    let link = PC.0 + 4;
    let m = materialize(30, link);
    assert_eq!(&body(&t)[..m.len()], &m[..]);
    assert_eq!(
        t.exits(),
        [BlockExit::Continue(ProgramCounter(PC.0 + 0x40))]
    );
    // b -8
    let t = emit_block(&block(&[0x17fffffe])).unwrap();
    assert_eq!(t.exits(), [BlockExit::Continue(ProgramCounter(PC.0 - 8))]);
}

#[test]
fn conditional_branches_are_relocated_to_a_local_taken_stub() {
    for (word, relocated, text) in [
        (0x54000801u32, 0x54000081u32, "b.ne 0x10"), // b.ne +0x100
        (0xb4000800, 0xb4000080, "cbz x0, 0x10"),    // cbz x0, +0x100
        (0x37180800, 0x37180080, "tbnz w0, #3, 0x10"), // tbnz w0, #3, +0x100
    ] {
        let t = emit_block(&block(&[0xd2800540, word])).unwrap();
        assert_eq!(body(&t)[1], relocated, "{word:08x}");
        assert_text(&[relocated], &[text]);
        assert_eq!(
            t.exits(),
            [
                BlockExit::Continue(ProgramCounter(PC.0 + 8)),
                BlockExit::Continue(ProgramCounter(PC.0 + 4 + 0x100)),
            ]
        );
        assert_eq!(
            t.terminator(),
            Terminator::Conditional {
                fallthrough: 0,
                taken: 1
            }
        );
        // Taken stub is exactly four words after the branch, and records index 1.
        assert_eq!(body(&t)[5..7], [0xa90007e0, 0xd2800020]);
    }
}

#[test]
fn every_exit_site_branches_to_the_common_exit() {
    let t = emit_block(&block(&[0x54000801])).unwrap();
    let common = t.words().len() - common_exit().len();
    for (index, at) in t
        .words()
        .iter()
        .enumerate()
        .filter(|(_, w)| **w & 0xfc000000 == 0x14000000)
    {
        let offset = ((*at << 6) as i32 >> 6) as i64 * 4;
        assert_eq!(index as i64 * 4 + offset, common as i64 * 4);
    }
}

#[test]
fn frame_round_trips_the_observable_registers() {
    use carrick_softcpu_aarch64::state::*;
    use carrick_softcpu_aarch64::{Gpr, OperandRegister};
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.sp_el1 = StackPointer(0x8000);
    cpu.sp_el0 = StackPointer(0x4000);
    cpu.pstate.nzcv = 0b0110;
    for n in 0..31 {
        cpu.write_operand(
            OperandRegister::Gpr(Gpr::new(n).unwrap()),
            RegisterValue(0x1000 + u64::from(n)),
        );
    }
    let mut f = BlockFrame::from_cpu(&cpu);
    assert_eq!(f.slots[30], 0x101e);
    assert_eq!(f.slots[(frame::GUEST_SP / 8) as usize], 0x8000);
    assert_eq!(f.slots[(frame::NZCV / 8) as usize], 0x6000_0000);
    f.slots[(frame::GUEST_SP / 8) as usize] = 0x7ff0;
    f.slots[(frame::NZCV / 8) as usize] = 0x9000_0000;
    f.slots[5] = 55;
    f.store_to(&mut cpu);
    assert_eq!(
        (cpu.sp_el1, cpu.sp_el0),
        (StackPointer(0x7ff0), StackPointer(0x4000))
    );
    assert_eq!(cpu.pstate.nzcv, 0b1001);
    assert_eq!(
        cpu.read_operand(OperandRegister::Gpr(Gpr::new(5).unwrap())),
        RegisterValue(55)
    );
    assert_eq!(std::mem::size_of::<BlockFrame>(), frame::BYTES);
    assert_eq!(std::mem::align_of::<BlockFrame>(), 16);
}

/// Every copy-classified word in a broad sample never names SP outside the
/// rewritten classes: a verbatim word must not touch host SP.
#[test]
fn verbatim_words_never_name_the_stack_pointer() {
    let mut seen = 0;
    for word in (0..=u32::MAX).step_by(4099) {
        let i = GuestInstruction::decode(PC, word);
        if i.class() == InstructionClass::Copy(CopyKind::Verbatim) {
            let text = format!("{:?}", i.instruction());
            assert!(
                !text.contains("Sp,") && !text.contains("Sp }"),
                "{word:08x} {text}"
            );
            seen += 1;
        }
    }
    assert!(seen > 1000);
}

// ---- production witnesses (env-gated, no pinned counts) -------------------

fn code_spans(bytes: &[u8]) -> Vec<(u64, Vec<u32>)> {
    let u16_at = |o: usize| u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap()) as usize;
    let u32_at = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    assert_eq!(&bytes[..6], b"\x7fELF\x02\x01");
    assert_eq!(u16_at(18), 183, "not AArch64");
    let table = u64_at(bytes, 40) as usize;
    let sections: Vec<&[u8]> = (0..u16_at(60))
        .map(|i| &bytes[table + i * 64..table + (i + 1) * 64])
        .collect();
    let mut marks: BTreeMap<(usize, u64), bool> = BTreeMap::new();
    for s in &sections {
        if u32_at(s, 4) != 2 {
            continue;
        }
        let strings = sections[u32_at(s, 40)];
        let strings = &bytes
            [u64_at(strings, 24) as usize..(u64_at(strings, 24) + u64_at(strings, 32)) as usize];
        let off = u64_at(s, 24) as usize;
        for sym in bytes[off..off + u64_at(s, 32) as usize].chunks_exact(24) {
            let name = &strings[u32_at(sym, 0)..];
            let name = &name[..name.iter().position(|&b| b == 0).unwrap()];
            let code = match name {
                b"$x" => true,
                b"$d" => false,
                n if n.starts_with(b"$x.") => true,
                n if n.starts_with(b"$d.") => false,
                _ => continue,
            };
            let shndx = u16::from_le_bytes(sym[6..8].try_into().unwrap()) as usize;
            marks.insert((shndx, u64_at(sym, 8)), code);
        }
    }
    let mut spans = Vec::new();
    for (index, s) in sections.iter().enumerate() {
        if u64_at(s, 8) & 4 == 0 || u64_at(s, 32) == 0 {
            continue;
        }
        let (start, size, off) = (u64_at(s, 16), u64_at(s, 32), u64_at(s, 24));
        let mut points: Vec<(u64, bool)> = marks
            .range((index, start)..(index, start + size))
            .map(|(&(_, a), &c)| (a, c))
            .collect();
        assert_eq!(
            points.first().map(|p| p.0),
            Some(start),
            "missing mapping symbol"
        );
        points.push((start + size, false));
        for pair in points.windows(2) {
            if pair[0].1 {
                let lo = (off + pair[0].0 - start) as usize;
                let hi = (off + pair[1].0 - start) as usize;
                let words = bytes[lo..hi]
                    .chunks_exact(4)
                    .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
                    .collect();
                spans.push((pair[0].0, words));
            }
        }
    }
    spans
}

fn measure(name: &str, spans: &[(u64, Vec<u32>)]) {
    let mut words = 0usize;
    let mut classes: BTreeMap<String, usize> = BTreeMap::new();
    let mut blocks = 0usize;
    let mut sizes: BTreeMap<usize, usize> = BTreeMap::new();
    let mut emitted = 0usize;
    let mut sysreg_accesses = 0;
    for (base, span) in spans {
        for block in split_span(ProgramCounter(*base), span, BlockLimits::default()) {
            for i in block.instructions() {
                words += 1;
                let key = match i.class() {
                    InstructionClass::Copy(k) => format!("Copy({k:?})"),
                    InstructionClass::Exit(r) => format!("Exit({r:?})"),
                    InstructionClass::Branch(b) => format!("Branch({b:?})"),
                };
                *classes.entry(key).or_default() += 1;
                if let Instruction::SystemAccess(access) = i.instruction() {
                    let mut cpu = CpuState::default();
                    cpu.pstate.el = ExceptionLevel::El1;
                    cpu.pstate.sp = StackSelect::El1;
                    let result = match access.direction {
                        SystemDirection::Read => cpu.mrs(access.encoding, access.rt).map(|_| ()),
                        SystemDirection::Write => {
                            cpu.msr(access.encoding, access.rt, SystemValue(0))
                        }
                    };
                    assert!(
                        result.is_ok(),
                        "{name}: EL1h register bank rejects {access:?} at {:#x}: {result:?}",
                        i.pc().0
                    );
                    sysreg_accesses += 1;
                }
            }
            blocks += 1;
            *sizes.entry(block.instructions().len()).or_default() += 1;
            let t = emit_block(&block).expect("every production block translates");
            emitted += t.words().len();
            // Determinism: translating twice yields the same host words.
            assert_eq!(emit_block(&block).unwrap(), t);
        }
    }
    assert!(words > 0, "no code measured");
    let undefined = classes.get("Exit(Undefined)").copied().unwrap_or(0);
    let max = sizes.keys().last().copied().unwrap_or(0);
    println!(
        "{name}: {words} words, {blocks} blocks, mean {:.2} max {max} guest words/block, \
         {emitted} host words, {sysreg_accesses} EL1h system-register accesses; classes {classes:?}",
        words as f64 / blocks as f64
    );
    assert_eq!(undefined, 0, "{name}: undefined production words");
}

#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the rebuilt production EL1 ELF"]
fn production_el1_code_splits_and_translates_with_no_undefined_word() {
    let path = std::env::var_os("CARRICK_A64_ELF").expect("set CARRICK_A64_ELF");
    let bytes = std::fs::read(path).expect("valid production ELF fixture");
    measure("production EL1 ELF", &code_spans(&bytes));
}

#[test]
#[ignore = "requires CARRICK_A64_LOADER_SPANS generated from production loader/vector builders"]
fn production_loader_vector_spans_split_and_translate_with_no_undefined_word() {
    let path = std::env::var_os("CARRICK_A64_LOADER_SPANS").expect("set CARRICK_A64_LOADER_SPANS");
    let bytes = std::fs::read(path).expect("loader span file");
    assert_eq!(bytes.len() % 4, 0);
    let words = bytes
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
        .collect();
    measure("loader/vector spans", &[(0, words)]);
}

#[test]
fn isb_prevents_fetching_the_following_instruction_in_the_same_block() {
    let mut fetched = Vec::new();
    let block = split_block(PC, BlockLimits::default(), |pc| {
        fetched.push(pc);
        match pc.0 - PC.0 {
            0 => Some(0xd503_3bbf), // dmb ish
            4 => Some(0xd503_3fdf), // isb
            8 => Some(0xd503_201f), // nop
            _ => None,
        }
    });
    assert_eq!(fetched, [PC, ProgramCounter(PC.0 + 4)]);
    assert_eq!(block.next_pc(), ProgramCounter(PC.0 + 8));
    assert!(matches!(
        emit_block(&block).unwrap().exits(),
        [BlockExit::Handler(_)]
    ));
}

#[test]
fn misaligned_block_and_span_do_not_fetch_across_a_code_page() {
    for address in [0x1ffe, 0x1fff] {
        let pc = ProgramCounter(address);
        let mut reads = 0;
        let block = split_block(pc, BlockLimits::default(), |_| {
            reads += 1;
            Some(0xd503_201f)
        });
        assert_eq!(reads, 0);
        assert!(block.instructions().is_empty());
        assert!(split_span(pc, &[0xd503_201f], BlockLimits::default()).is_empty());
    }
}
