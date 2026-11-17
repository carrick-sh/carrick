//! Optional differential oracle. LLVM is a test oracle, never a decode dependency.
//! Invoke with CARRICK_LLVM_OBJDUMP pointing at the Rust-sysroot llvm-objdump.
use carrick_softcpu_aarch64::*;
use std::{collections::BTreeSet, process::Command};

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
            s.push_str(&format!("#0x{:x}", i.encoded()));
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
                s.push_str(&format!(", {name} #{}", amount.value()));
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
                    s.push_str(&format!(", lsl #{}", amount.value()));
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
            s.push_str(&format!("{}, {name}", reg(rm, width)));
            if amount.value() != 0 {
                s.push_str(&format!(" #{}", amount.value()));
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
    std::fs::write(&path, object(&words)).expect("valid differential fixture");
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
        .expect("valid differential fixture");
    std::fs::remove_file(path).expect("valid differential fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("valid differential fixture");
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
                .expect("valid differential fixture")
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
    std::fs::write(&path, object(&words)).expect("valid differential fixture");
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
        .expect("valid differential fixture");
    std::fs::remove_file(path).expect("valid differential fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("valid differential fixture");
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
            .expect("valid differential fixture")
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
    std::fs::write(&path, object(&words)).expect("valid differential fixture");
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
        .expect("valid differential fixture");
    std::fs::remove_file(path).expect("valid differential fixture");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("valid differential fixture");
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
                .expect("valid differential fixture")
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

fn memory_expected(m: ScalarMemory, pc: u64) -> String {
    let signed = m.operation == MemoryOperation::LoadSigned;
    let load = m.operation != MemoryOperation::Store;
    let unscaled = matches!(m.address, MemoryAddress::Immediate { unscaled: true, .. });
    let mut name = match (load, unscaled) {
        (true, true) => "ldur",
        (false, true) => "stur",
        (true, false) => "ldr",
        (false, false) => "str",
    }
    .to_owned();
    let r = match m.register {
        MemoryRegister::Integer { register, width } => {
            name.push_str(match (m.size, signed) {
                (MemorySize::Byte, false) => "b",
                (MemorySize::Half, false) => "h",
                (MemorySize::Byte, true) => "sb",
                (MemorySize::Half, true) => "sh",
                (MemorySize::Word, true) => "sw",
                _ => "",
            });
            reg(register, width)
        }
        MemoryRegister::Vector(r) => format!(
            "{}{}",
            match m.size {
                MemorySize::Byte => 'b',
                MemorySize::Half => 'h',
                MemorySize::Word => 's',
                MemorySize::Double => 'd',
                MemorySize::Quad => 'q',
            },
            r.number()
        ),
    };
    let address = match m.address {
        MemoryAddress::Literal(offset) => format!("0x{:x}", pc.wrapping_add_signed(offset.bytes())),
        MemoryAddress::Immediate {
            base,
            offset,
            index,
            ..
        } => {
            let b = reg(base, Width::X64);
            let n = offset.bytes();
            match index {
                MemoryIndex::Post => format!("[{b}], #{n}"),
                MemoryIndex::Pre => format!("[{b}, #{n}]!"),
                MemoryIndex::Offset if n == 0 => format!("[{b}]"),
                MemoryIndex::Offset => format!("[{b}, #{n}]"),
            }
        }
        MemoryAddress::Register {
            base,
            offset,
            extend,
            scaled,
        } => {
            let b = reg(base, Width::X64);
            let r = reg(
                offset,
                if matches!(extend, Extend::Uxtw | Extend::Sxtw) {
                    Width::W32
                } else {
                    Width::X64
                },
            );
            let name = match extend {
                Extend::Uxtw => "uxtw",
                Extend::Uxtx => "lsl",
                Extend::Sxtw => "sxtw",
                Extend::Sxtx => "sxtx",
                _ => unreachable!(),
            };
            if extend == Extend::Uxtx && !scaled {
                format!("[{b}, {r}]")
            } else if scaled {
                format!("[{b}, {r}, {name} #{}]", m.size.bytes().trailing_zeros())
            } else {
                format!("[{b}, {r}, {name}]")
            }
        }
    };
    format!("{name} {r}, {address}")
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_scalar_memory_matches_llvm_operands() {
    let mut words = BTreeSet::new();
    for size in 0..4u32 {
        for v in 0..2 {
            for opc in 0..4 {
                let head = size << 30 | v << 26 | opc << 22;
                for rn in [0, 17, 31] {
                    for rt in [0, 18, 31] {
                        for imm in [0, 1, 255, 256, 511] {
                            for mode in 0..4 {
                                words.insert(
                                    head | 0x38000000 | imm << 12 | mode << 10 | rn << 5 | rt,
                                );
                            }
                        }
                        for imm in [0, 1, 31, 2047, 4095] {
                            words.insert(head | 0x39000000 | imm << 10 | rn << 5 | rt);
                        }
                        for rm in [0, 19, 31] {
                            for option in 0..8 {
                                for low in 0..8 {
                                    words.insert(
                                        head | 0x38200000
                                            | rm << 16
                                            | option << 13
                                            | low << 10
                                            | rn << 5
                                            | rt,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for opc in 0..4u32 {
        for v in 0..2 {
            for imm in [0, 1, 0x3ffff, 0x40000, 0x7ffff] {
                for rt in 0..32 {
                    words.insert(opc << 30 | v << 26 | 0x18000000 | imm << 5 | rt);
                }
            }
        }
    }
    assert!(words.len() >= 50_000);
    let words: Vec<_> = words.into_iter().collect();
    let path = std::env::temp_dir().join(format!("carrick-a64-memory-{}.o", std::process::id()));
    std::fs::write(&path, object(&words)).expect("valid differential fixture");
    let output =
        Command::new(std::env::var_os("CARRICK_LLVM_OBJDUMP").expect("valid differential fixture"))
            .args([
                "-D",
                "--no-print-imm-hex",
                "--no-show-raw-insn",
                "--no-leading-addr",
            ])
            .arg(&path)
            .output()
            .expect("valid differential fixture");
    std::fs::remove_file(path).expect("valid differential fixture");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("valid differential fixture");
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(' ') && !s.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), words.len());
    let mut accepted = 0;
    let mut mismatches = 0;
    for (i, (&w, line)) in words.iter().zip(lines).enumerate() {
        if let Instruction::ScalarMemory(m) = decode_instruction(w) {
            let actual = line
                .split("//")
                .next()
                .expect("valid differential fixture")
                .split(" <")
                .next()
                .expect("valid differential fixture")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if memory_expected(m, i as u64 * 4) != actual {
                if mismatches < 20 {
                    println!(
                        "{w:08x}: {:?} versus {actual}",
                        memory_expected(m, i as u64 * 4)
                    );
                }
                mismatches += 1;
            }
            accepted += 1;
        }
    }
    assert_eq!(mismatches, 0, "oracle mismatches");
    println!(
        "{} distinct scalar memory words; {accepted} accepted; 0 wrong class / operand mismatches",
        words.len()
    );
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_pair_memory_matches_llvm_operands() {
    let mut words = BTreeSet::new();
    for opc in 0..4u32 {
        for v in 0..2 {
            for load in 0..2 {
                for mode in 0..4 {
                    for imm in [0, 1, 31, 63, 64, 127] {
                        for rn in [0, 1, 17, 30, 31] {
                            for rt in [0, 1, 18, 30, 31] {
                                for rt2 in [0, 1, 19, 30, 31] {
                                    words.insert(
                                        0x28000000
                                            | opc << 30
                                            | v << 26
                                            | mode << 23
                                            | load << 22
                                            | imm << 15
                                            | rt2 << 10
                                            | rn << 5
                                            | rt,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // Exhaustive imm7 and all pair modes for distinct additional populations.
    for imm in 0..128u32 {
        for rt in 0..32 {
            for mode in 0..4 {
                words.insert(0xa8400000 | mode << 23 | imm << 15 | 1 << 10 | 2 << 5 | rt);
            }
        }
    }
    assert!(words.len() >= 50_000);
    let words: Vec<_> = words.into_iter().collect();
    let path = std::env::temp_dir().join(format!("carrick-a64-pair-{}.o", std::process::id()));
    std::fs::write(&path, object(&words)).expect("valid fixture");
    let output = Command::new(std::env::var_os("CARRICK_LLVM_OBJDUMP").expect("set LLVM"))
        .args([
            "-D",
            "--no-print-imm-hex",
            "--no-show-raw-insn",
            "--no-leading-addr",
        ])
        .arg(&path)
        .output()
        .expect("valid fixture");
    std::fs::remove_file(path).expect("valid fixture");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("valid fixture");
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(' ') && !s.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), words.len());
    let mut accepted = 0;
    for (&w, line) in words.iter().zip(lines) {
        if let Instruction::PairMemory(m) = decode_instruction(w) {
            let r = |r| match r {
                MemoryRegister::Integer { register, width } => reg(register, width),
                MemoryRegister::Vector(r) => format!(
                    "{}{}",
                    match m.size {
                        MemorySize::Word => 's',
                        MemorySize::Double => 'd',
                        MemorySize::Quad => 'q',
                        _ => unreachable!(),
                    },
                    r.number()
                ),
            };
            let name = match (m.operation, m.non_temporal) {
                (MemoryOperation::Store, false) => "stp",
                (MemoryOperation::Store, true) => "stnp",
                (MemoryOperation::Load, false) => "ldp",
                (MemoryOperation::Load, true) => "ldnp",
                (MemoryOperation::LoadSigned, _) => "ldpsw",
            };
            let b = reg(m.base, Width::X64);
            let n = m.offset.bytes();
            let address = match m.index {
                MemoryIndex::Post => format!("[{b}], #{n}"),
                MemoryIndex::Pre => format!("[{b}, #{n}]!"),
                MemoryIndex::Offset if n == 0 => format!("[{b}]"),
                MemoryIndex::Offset => format!("[{b}, #{n}]"),
            };
            let expected = format!("{name} {}, {}, {address}", r(m.first), r(m.second));
            let actual = line
                .split("//")
                .next()
                .expect("instruction")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(expected, actual, "{w:08x}");
            accepted += 1;
        }
    }
    println!(
        "{} distinct pair words; {accepted} accepted; 0 wrong class / operand mismatches",
        words.len()
    );
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_logical_matches_llvm_operands() {
    let mut words = BTreeSet::new();
    for sf in 0..2u32 {
        for opc in 0..4 {
            let head = sf << 31 | opc << 29;
            for n in 0..2 {
                for r in 0..64 {
                    for s in 0..64 {
                        for (rn, rd) in [(1, 0), (31, 31)] {
                            words.insert(
                                head | 0x12000000 | n << 22 | r << 16 | s << 10 | rn << 5 | rd,
                            );
                        }
                    }
                }
            }
            for shift in 0..4 {
                for invert in 0..2 {
                    for amount in 0..64 {
                        for (rn, rm, rd) in [(1, 2, 0), (31, 31, 31), (17, 18, 19)] {
                            words.insert(
                                head | 0x0a000000
                                    | shift << 22
                                    | invert << 21
                                    | rm << 16
                                    | amount << 10
                                    | rn << 5
                                    | rd,
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(words.len() >= 50_000);
    let words: Vec<_> = words.into_iter().collect();
    let path = std::env::temp_dir().join(format!("carrick-a64-logical-{}.o", std::process::id()));
    std::fs::write(&path, object(&words)).expect("valid fixture");
    let output = Command::new(std::env::var_os("CARRICK_LLVM_OBJDUMP").expect("set LLVM"))
        .args([
            "-D",
            "-M",
            "no-aliases",
            "--no-show-raw-insn",
            "--no-leading-addr",
        ])
        .arg(&path)
        .output()
        .expect("valid fixture");
    std::fs::remove_file(path).expect("valid fixture");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("valid fixture");
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(' ') && !s.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), words.len());
    let mut accepted = 0;
    for (&w, line) in words.iter().zip(lines) {
        if let Instruction::Logical(l) = decode_instruction(w) {
            let invert = matches!(l.operand, LogicalOperand::Shifted { invert: true, .. });
            let name = match (l.operation, invert) {
                (LogicalOperation::And, false) => "and",
                (LogicalOperation::And, true) => "bic",
                (LogicalOperation::Ands, false) => "ands",
                (LogicalOperation::Ands, true) => "bics",
                (LogicalOperation::Orr, false) => "orr",
                (LogicalOperation::Orr, true) => "orn",
                (LogicalOperation::Eor, false) => "eor",
                (LogicalOperation::Eor, true) => "eon",
            };
            let operand = match l.operand {
                LogicalOperand::Immediate(i) => format!("#0x{:x}", i.value()),
                LogicalOperand::Shifted {
                    rm, shift, amount, ..
                } => {
                    let r = reg(rm, l.width);
                    if shift == Shift::Lsl && amount.value() == 0 {
                        r
                    } else {
                        format!(
                            "{r}, {} #{}",
                            match shift {
                                Shift::Lsl => "lsl",
                                Shift::Lsr => "lsr",
                                Shift::Asr => "asr",
                                Shift::Ror => "ror",
                            },
                            amount.value()
                        )
                    }
                }
            };
            let expected = format!(
                "{name} {}, {}, {operand}",
                reg(l.rd, l.width),
                reg(l.rn, l.width)
            );
            let actual = line
                .split("//")
                .next()
                .expect("instruction")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            // LLVM retains the ORR-immediate MOV alias even with no-aliases.
            let expected = if actual.starts_with("mov ")
                && l.operation == LogicalOperation::Orr
                && l.rn == OperandRegister::Zr
                && matches!(l.operand, LogicalOperand::Immediate(_))
            {
                let LogicalOperand::Immediate(imm) = l.operand else {
                    unreachable!()
                };
                let value = if l.width == Width::W32 {
                    imm.value() as u32 as i32 as i64
                } else {
                    imm.value() as i64
                };
                let signed = if value < 0 {
                    format!("#-0x{:x}", value.unsigned_abs())
                } else {
                    format!("#0x{value:x}")
                };
                format!("mov {}, {signed}", reg(l.rd, l.width))
            } else {
                expected
            };
            assert_eq!(expected, actual, "{w:08x}");
            accepted += 1;
        }
    }
    println!(
        "{} distinct logical words; {accepted} accepted; 0 wrong class / operand mismatches",
        words.len()
    );
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_move_wide_matches_llvm_operands() {
    let mut words = BTreeSet::new();
    for sf in 0..2u32 {
        for opc in 0..4 {
            for hw in 0..4 {
                for imm in (0..65536).step_by(127) {
                    for rd in [0, 17, 30, 31] {
                        words.insert(sf << 31 | opc << 29 | 0x12800000 | hw << 21 | imm << 5 | rd);
                    }
                }
            }
        }
    }
    assert!(words.len() >= 50_000);
    let words: Vec<_> = words.into_iter().collect();
    let path = std::env::temp_dir().join(format!("carrick-a64-movewide-{}.o", std::process::id()));
    std::fs::write(&path, object(&words)).expect("valid fixture");
    let output = Command::new(std::env::var_os("CARRICK_LLVM_OBJDUMP").expect("set LLVM"))
        .args([
            "-D",
            "-M",
            "no-aliases",
            "--no-show-raw-insn",
            "--no-leading-addr",
        ])
        .arg(&path)
        .output()
        .expect("valid fixture");
    std::fs::remove_file(path).expect("valid fixture");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("valid fixture");
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(' ') && !s.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), words.len());
    let mut accepted = 0;
    for (&w, line) in words.iter().zip(lines) {
        if let Instruction::MoveWide(m) = decode_instruction(w) {
            let name = match m.operation {
                MoveWideOperation::Not => "movn",
                MoveWideOperation::Zero => "movz",
                MoveWideOperation::Keep => "movk",
            };
            let mut expected = format!("{name} {}, #0x{:x}", reg(m.rd, m.width), m.immediate);
            if m.shift.value() != 0 {
                expected.push_str(&format!(", lsl #{}", m.shift.value()));
            }
            let actual = line
                .split("//")
                .next()
                .expect("instruction")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let expected = if actual.starts_with("mov ") && m.operation != MoveWideOperation::Keep {
                let value = (m.immediate as u64) << m.shift.value();
                let value = if m.operation == MoveWideOperation::Not {
                    !value
                } else {
                    value
                };
                let value = if m.width == Width::W32 {
                    value as u32 as i32 as i64
                } else {
                    value as i64
                };
                let immediate = if value < 0 {
                    format!("#-0x{:x}", value.unsigned_abs())
                } else {
                    format!("#0x{value:x}")
                };
                format!("mov {}, {immediate}", reg(m.rd, m.width))
            } else {
                expected
            };
            assert_eq!(expected, actual, "{w:08x}");
            accepted += 1;
        }
    }
    println!(
        "{} distinct move-wide words; {accepted} accepted; 0 wrong class / operand mismatches",
        words.len()
    );
}

fn oracle_lines(words: &[u32], group: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("carrick-a64-{group}-{}.o", std::process::id()));
    std::fs::write(&path, object(words)).expect("valid fixture");
    let output = Command::new(std::env::var_os("CARRICK_LLVM_OBJDUMP").expect("set LLVM"))
        .args([
            "-D",
            "-M",
            "no-aliases",
            "--no-print-imm-hex",
            "--no-show-raw-insn",
            "--no-leading-addr",
        ])
        .arg(&path)
        .output()
        .expect("valid fixture");
    std::fs::remove_file(path).expect("valid fixture");
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).expect("valid fixture");
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(' ') && !s.trim().is_empty())
        .map(|line| {
            line.split("//")
                .next()
                .expect("instruction")
                .split(" <")
                .next()
                .expect("instruction")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    assert_eq!(lines.len(), words.len());
    lines
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_bitfield_matches_llvm_operands() {
    let mut words = BTreeSet::new();
    for sf in 0..2u32 {
        for opc in 0..4 {
            for n in 0..2 {
                for r in 0..64 {
                    for s in 0..64 {
                        for (rn, rd) in [(1, 0), (31, 31)] {
                            words.insert(
                                sf << 31
                                    | opc << 29
                                    | 0x13000000
                                    | n << 22
                                    | r << 16
                                    | s << 10
                                    | rn << 5
                                    | rd,
                            );
                        }
                    }
                }
            }
        }
    }
    let words: Vec<_> = words.into_iter().collect();
    assert!(words.len() >= 50_000);
    let mut accepted = 0;
    for (&w, actual) in words.iter().zip(oracle_lines(&words, "bitfield")) {
        if let Instruction::Bitfield(b) = decode_instruction(w) {
            let name = match b.operation {
                BitfieldOperation::Signed => "sbfm",
                BitfieldOperation::Merge => "bfm",
                BitfieldOperation::Unsigned => "ubfm",
            };
            let expected = format!(
                "{name} {}, {}, #{}, #{}",
                reg(b.rd, b.width),
                reg(b.rn, b.width),
                b.rotate.value(),
                b.last.value()
            );
            // Arm ARM C6.2.29/234/337 alias relations. LLVM retains these
            // aliases even with no-aliases; compare their exact inverse fields.
            let mnemonic = actual.split_whitespace().next().expect("mnemonic");
            let rd = reg(b.rd, b.width);
            let rn = reg(b.rn, b.width);
            let r = u32::from(b.rotate.value());
            let last = u32::from(b.last.value());
            let width = if b.width == Width::W32 { 32 } else { 64 };
            let expected = match mnemonic {
                "asr" if b.operation == BitfieldOperation::Signed && last == width - 1 => {
                    format!("asr {rd}, {rn}, #{r}")
                }
                "lsr" if b.operation == BitfieldOperation::Unsigned && last == width - 1 => {
                    format!("lsr {rd}, {rn}, #{r}")
                }
                "lsl" if b.operation == BitfieldOperation::Unsigned && last + 1 == r => {
                    format!("lsl {rd}, {rn}, #{}", width - r)
                }
                "sxtb" | "sxth" | "sxtw"
                    if b.operation == BitfieldOperation::Signed
                        && r == 0
                        && last
                            == match mnemonic {
                                "sxtb" => 7,
                                "sxth" => 15,
                                _ => 31,
                            } =>
                {
                    format!("{mnemonic} {rd}, {}", reg(b.rn, Width::W32))
                }
                "uxtb" | "uxth"
                    if b.operation == BitfieldOperation::Unsigned
                        && r == 0
                        && last == if mnemonic == "uxtb" { 7 } else { 15 } =>
                {
                    format!("{mnemonic} {rd}, {}", reg(b.rn, Width::W32))
                }
                "sbfx" | "ubfx" | "bfxil"
                    if last >= r
                        && b.operation
                            == match mnemonic {
                                "sbfx" => BitfieldOperation::Signed,
                                "ubfx" => BitfieldOperation::Unsigned,
                                _ => BitfieldOperation::Merge,
                            } =>
                {
                    format!("{mnemonic} {rd}, {rn}, #{r}, #{}", last - r + 1)
                }
                "sbfiz" | "ubfiz" | "bfi"
                    if last < r
                        && b.operation
                            == match mnemonic {
                                "sbfiz" => BitfieldOperation::Signed,
                                "ubfiz" => BitfieldOperation::Unsigned,
                                _ => BitfieldOperation::Merge,
                            } =>
                {
                    format!("{mnemonic} {rd}, {rn}, #{}, #{}", width - r, last + 1)
                }
                "bfc"
                    if b.operation == BitfieldOperation::Merge
                        && b.rn == OperandRegister::Zr
                        && last < r =>
                {
                    format!("bfc {rd}, #{}, #{}", width - r, last + 1)
                }
                _ => expected,
            };
            assert_eq!(expected, actual, "{w:08x}");
            accepted += 1;
        }
    }
    println!(
        "{} distinct bitfield words; {accepted} accepted; 0 wrong class / operand mismatches",
        words.len()
    );
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_address_matches_llvm_operands() {
    let mut words = BTreeSet::new();
    for page in 0..2u32 {
        for lo in 0..4 {
            for hi in (0..524288).step_by(127) {
                for rd in [0, 17, 31] {
                    words.insert(page << 31 | lo << 29 | 0x10000000 | hi << 5 | rd);
                }
            }
        }
    }
    let words: Vec<_> = words.into_iter().collect();
    assert!(words.len() >= 50_000);
    for (i, (&w, actual)) in words
        .iter()
        .zip(oracle_lines(&words, "address"))
        .enumerate()
    {
        let Instruction::Address(a) = decode_instruction(w) else {
            panic!("missing address {w:08x}")
        };
        let pc = i as u64 * 4;
        let (name, base) = match a.base {
            AddressBase::Pc => ("adr", pc),
            AddressBase::Page => ("adrp", pc & !4095),
        };
        let expected = format!(
            "{name} {}, 0x{:x}",
            reg(a.rd, Width::X64),
            base.wrapping_add_signed(a.offset.bytes())
        );
        assert_eq!(expected, actual, "{w:08x}");
    }
    println!(
        "{} distinct address words; 0 wrong class / operand mismatches",
        words.len()
    );
}

fn condition_name(c: Condition) -> &'static str {
    match c {
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
    }
}

#[test]
#[ignore = "requires Rust-sysroot CARRICK_LLVM_OBJDUMP"]
fn generated_conditional_matches_llvm_operands() {
    let mut words = BTreeSet::new();
    for sf in 0..2u32 {
        for op in 0..2 {
            for cond in 0..16 {
                for rm in 0..32 {
                    for rn in [0, 17, 31] {
                        for low in 0..4 {
                            for rd in [0, 19, 31] {
                                words.insert(
                                    sf << 31
                                        | op << 30
                                        | 0x1a800000
                                        | rm << 16
                                        | cond << 12
                                        | low << 10
                                        | rn << 5
                                        | rd,
                                );
                            }
                        }
                        for imm in 0..2 {
                            for nzcv in 0..16 {
                                words.insert(
                                    sf << 31
                                        | op << 30
                                        | 0x3a400000
                                        | rm << 16
                                        | cond << 12
                                        | imm << 11
                                        | rn << 5
                                        | nzcv,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    let words: Vec<_> = words.into_iter().collect();
    assert!(words.len() >= 50_000);
    let mut accepted = 0;
    for (&w, actual) in words.iter().zip(oracle_lines(&words, "conditional")) {
        let expected = match decode_instruction(w) {
            Instruction::ConditionalSelect(c) => {
                let name = match c.operation {
                    SelectOperation::Select => "csel",
                    SelectOperation::Increment => "csinc",
                    SelectOperation::Invert => "csinv",
                    SelectOperation::Negate => "csneg",
                };
                format!(
                    "{name} {}, {}, {}, {}",
                    reg(c.rd, c.width),
                    reg(c.rn, c.width),
                    reg(c.rm, c.width),
                    condition_name(c.condition)
                )
            }
            Instruction::ConditionalCompare(c) => {
                let name = if c.operation == AddSubtract::Add {
                    "ccmn"
                } else {
                    "ccmp"
                };
                let operand = match c.operand {
                    CompareOperand::Register(r) => reg(r, c.width),
                    CompareOperand::Immediate(i) => format!("#{}", i.value()),
                };
                format!(
                    "{name} {}, {operand}, #{}, {}",
                    reg(c.rn, c.width),
                    c.otherwise.bits(),
                    condition_name(c.condition)
                )
            }
            _ => continue,
        };
        assert_eq!(expected, actual, "{w:08x}");
        accepted += 1;
    }
    println!(
        "{} distinct conditional words; {accepted} accepted; 0 wrong class / operand mismatches",
        words.len()
    );
}
