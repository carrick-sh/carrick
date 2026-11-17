//! Optional differential oracle. LLVM is a test oracle, never a decode dependency.
//! Invoke with CARRICK_LLVM_OBJDUMP pointing at the Rust-sysroot llvm-objdump.
use carrick_softcpu_aarch64::*;
use std::{collections::BTreeSet, fmt::Write as _, process::Command};

fn reg(r: OperandRegister, width: Width) -> String {
    let prefix = if width == Width::X64 { 'x' } else { 'w' };
    match r {
        OperandRegister::Gpr(r) => format!("{prefix}{}", r.number()),
        OperandRegister::Sp => if width == Width::X64 { "sp" } else { "wsp" }.into(),
        OperandRegister::Zr => format!("{prefix}zr"),
    }
}

fn expected(a: Arithmetic) -> String {
    let mut mnemonic = match (a.op, a.operand) {
        (AddSubtract::Add, ArithmeticOperand::WithCarry { .. }) => "adc",
        (AddSubtract::Subtract, ArithmeticOperand::WithCarry { .. }) => "sbc",
        (AddSubtract::Add, _) => "add",
        (AddSubtract::Subtract, _) => "sub",
    }
    .to_owned();
    if a.set_flags {
        mnemonic.push('s');
    }
    let mut s = format!(
        "{mnemonic} {}, {}, ",
        reg(a.rd, a.width),
        reg(a.rn, a.width)
    );
    match a.operand {
        ArithmeticOperand::Immediate(i) => {
            write!(s, "#0x{:x}", i.encoded()).unwrap();
            if i.shift().value() != 0 {
                s.push_str(", lsl #12");
            }
        }
        ArithmeticOperand::WithCarry { rm } => s.push_str(&reg(rm, a.width)),
        ArithmeticOperand::Shifted { rm, shift, amount } => {
            s.push_str(&reg(rm, a.width));
            if shift != Shift::Lsl || amount.value() != 0 {
                let name = match shift {
                    Shift::Lsl => "lsl",
                    Shift::Lsr => "lsr",
                    Shift::Asr => "asr",
                    Shift::Ror => "ror",
                };
                write!(s, ", {name} #{}", amount.value()).unwrap();
            }
        }
        ArithmeticOperand::Extended { rm, extend, amount } => {
            let width = if a.width == Width::X64 && matches!(extend, Extend::Uxtx | Extend::Sxtx) {
                Width::X64
            } else {
                Width::W32
            };
            let sp_lsl = (a.rn == OperandRegister::Sp || a.rd == OperandRegister::Sp)
                && ((a.width == Width::W32 && extend == Extend::Uxtw)
                    || (a.width == Width::X64 && extend == Extend::Uxtx));
            if sp_lsl {
                s.push_str(&reg(rm, width));
                if amount.value() != 0 {
                    write!(s, ", lsl #{}", amount.value()).unwrap();
                }
                return s;
            }
            let name = match extend {
                Extend::Uxtb => "uxtb",
                Extend::Uxth => "uxth",
                Extend::Uxtw => "uxtw",
                Extend::Uxtx => "uxtx",
                Extend::Sxtb => "sxtb",
                Extend::Sxth => "sxth",
                Extend::Sxtw => "sxtw",
                Extend::Sxtx => "sxtx",
            };
            write!(s, "{}, {name}", reg(rm, width)).unwrap();
            if amount.value() != 0 {
                write!(s, " #{}", amount.value()).unwrap();
            }
        }
    }
    s
}

// Minimal ELF64 relocatable with a single executable section, not an assembler
// or disassembler. Input words are generated independently of the decoder.
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

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_arithmetic_matches_llvm_operands() {
    let llvm =
        std::env::var_os("CARRICK_LLVM_OBJDUMP").expect("set Rust-sysroot CARRICK_LLVM_OBJDUMP");
    let mut words = BTreeSet::new();
    // Every operation/width/flag combination and edge register, with exhaustive
    // shift/extend fields. Include reserved neighbours and instruction bit 23.
    for sf in 0..2u32 {
        for op in 0..2 {
            for flags in 0..2 {
                let head = sf << 31 | op << 30 | flags << 29;
                for rd in [0, 1, 17, 30, 31] {
                    for rn in [0, 2, 19, 30, 31] {
                        for imm in [0, 1, 31, 32, 2047, 4095] {
                            for sh in 0..2 {
                                words.insert(
                                    head | 0x11000000 | sh << 22 | imm << 10 | rn << 5 | rd,
                                );
                            }
                        }
                        for rm in [0, 3, 20, 30, 31] {
                            for shift in 0..4 {
                                for amount in 0..64 {
                                    words.insert(
                                        head | 0x0b000000
                                            | shift << 22
                                            | rm << 16
                                            | amount << 10
                                            | rn << 5
                                            | rd,
                                    );
                                }
                            }
                            for extend in 0..8 {
                                for amount in 0..8 {
                                    words.insert(
                                        head | 0x0b200000
                                            | rm << 16
                                            | extend << 13
                                            | amount << 10
                                            | rn << 5
                                            | rd,
                                    );
                                }
                            }
                            words.insert(head | 0x1a000000 | rm << 16 | rn << 5 | rd);
                        }
                    }
                }
            }
        }
    }
    assert!(words.len() >= 50_000);
    let words: Vec<_> = words.into_iter().collect();
    let path =
        std::env::temp_dir().join(format!("carrick-a64-arithmetic-{}.o", std::process::id()));
    std::fs::write(&path, object(&words)).unwrap();
    let output = Command::new(llvm)
        .args([
            "-D",
            "-M",
            "no-aliases",
            "--no-show-raw-insn",
            "--no-leading-addr",
        ])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(" ") && !s.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), words.len(), "oracle population");
    let mut accepted = 0;
    for (&w, line) in words.iter().zip(lines) {
        if let Instruction::Arithmetic(a) = decode_instruction(w) {
            let actual = line
                .split("//")
                .next()
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(expected(a), actual, "{w:08x}");
            accepted += 1;
        }
    }
    eprintln!(
        "{} distinct arithmetic words, {accepted} accepted; 0 wrong class / operand mismatches",
        words.len()
    );
}

fn branch_expected(b: Branch, pc: u64) -> String {
    let target = |offset: PcOffset| format!("0x{:x}", pc.wrapping_add_signed(offset.bytes()));
    match b {
        Branch::Immediate { link, offset } => {
            format!("{} {}", if link { "bl" } else { "b" }, target(offset))
        }
        Branch::Conditional { condition, offset } => {
            let cond = match condition {
                Condition::Eq => "eq",
                Condition::Ne => "ne",
                Condition::Cs => "hs",
                Condition::Cc => "lo",
                Condition::Mi => "mi",
                Condition::Pl => "pl",
                Condition::Vs => "vs",
                Condition::Vc => "vc",
                Condition::Hi => "hi",
                Condition::Ls => "ls",
                Condition::Ge => "ge",
                Condition::Lt => "lt",
                Condition::Gt => "gt",
                Condition::Le => "le",
                Condition::Al => "al",
                Condition::Nv => "nv",
            };
            format!("b.{cond} {}", target(offset))
        }
        Branch::Compare {
            width,
            nonzero,
            rt,
            offset,
        } => format!(
            "{} {}, {}",
            if nonzero { "cbnz" } else { "cbz" },
            reg(rt, width),
            target(offset)
        ),
        Branch::Test {
            bit,
            nonzero,
            rt,
            offset,
        } => format!(
            "{} {}, #0x{:x}, {}",
            if nonzero { "tbnz" } else { "tbz" },
            reg(
                rt,
                if bit.value() < 32 {
                    Width::W32
                } else {
                    Width::X64
                }
            ),
            bit.value(),
            target(offset)
        ),
        Branch::Register { op, rn } => format!(
            "{} {}",
            match op {
                RegisterBranch::Jump => "br",
                RegisterBranch::Call => "blr",
                RegisterBranch::Return => "ret",
            },
            reg(rn, Width::X64)
        ),
    }
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_branches_match_llvm_operands() {
    let llvm =
        std::env::var_os("CARRICK_LLVM_OBJDUMP").expect("set Rust-sysroot CARRICK_LLVM_OBJDUMP");
    let mut words = BTreeSet::new();
    for i in 0..8192u32 {
        let imm26 = i.wrapping_mul(8191) & 0x3ffffff;
        words.insert(0x14000000 | imm26);
        words.insert(0x94000000 | imm26);
        let imm19 = i.wrapping_mul(257) & 0x7ffff;
        words.insert(0x54000000 | imm19 << 5 | i & 15);
        for sf in 0..2u32 {
            for nz in 0..2 {
                words.insert(0x34000000 | sf << 31 | nz << 24 | imm19 << 5 | i & 31);
                words.insert(
                    0x36000000
                        | sf << 31
                        | nz << 24
                        | (i & 31) << 19
                        | ((i * 7) & 0x3fff) << 5
                        | (i >> 5) & 31,
                );
            }
        }
    }
    for rn in 0..32 {
        for base in [0xd61f0000, 0xd63f0000, 0xd65f0000] {
            words.insert(base | rn << 5);
        }
    }
    assert!(words.len() >= 50_000);
    let words: Vec<_> = words.into_iter().collect();
    let path = std::env::temp_dir().join(format!("carrick-a64-branches-{}.o", std::process::id()));
    std::fs::write(&path, object(&words)).unwrap();
    let output = Command::new(llvm)
        .args([
            "-D",
            "-M",
            "no-aliases",
            "--no-show-raw-insn",
            "--no-leading-addr",
        ])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(" ") && !s.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), words.len());
    for (i, (&w, line)) in words.iter().zip(lines).enumerate() {
        let Instruction::Branch(b) = decode_instruction(w) else {
            panic!("{w:08x} rejected");
        };
        let actual = line
            .split(" <")
            .next()
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(branch_expected(b, i as u64 * 4), actual, "{w:08x}");
    }
    println!(
        "{} distinct branch words; 0 wrong class / operand mismatches",
        words.len()
    );
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn hint_neighbourhood_has_no_false_acceptances() {
    let llvm =
        std::env::var_os("CARRICK_LLVM_OBJDUMP").expect("set Rust-sysroot CARRICK_LLVM_OBJDUMP");
    // Baseline hints have only six distinct encodings. Sweep 65,536 neighbouring
    // words and check every accepted hint against LLVM, including all fixed bits.
    let words: Vec<_> = (0..65536).map(|low| 0xd5030000 | low).collect();
    let path = std::env::temp_dir().join(format!("carrick-a64-hints-{}.o", std::process::id()));
    std::fs::write(&path, object(&words)).unwrap();
    let output = Command::new(llvm)
        .args([
            "-D",
            "-M",
            "no-aliases",
            "--no-show-raw-insn",
            "--no-leading-addr",
        ])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(" ") && !s.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), words.len());
    let mut hints = 0;
    for (w, line) in words.into_iter().zip(lines) {
        if let Instruction::Hint(h) = decode_instruction(w) {
            let actual = line
                .split(" <")
                .next()
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let expected = match h {
                Hint::Nop => "hint #0",
                Hint::Yield => "hint #0x1",
                Hint::Wfe => "hint #0x2",
                Hint::Wfi => "hint #0x3",
                Hint::Sev => "hint #0x4",
                Hint::Sevl => "hint #0x5",
            };
            assert_eq!(actual, expected, "{w:08x}");
            hints += 1;
        }
    }
    assert_eq!(hints, 6);
    println!("65536 distinct hint neighbourhood words; 6 accepted; 0 mismatches");
}
