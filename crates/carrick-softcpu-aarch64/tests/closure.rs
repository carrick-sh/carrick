use carrick_softcpu_aarch64::*;

#[test]
fn barrier_closure_red_witness() {
    for word in [0xd5033f9f, 0xd5033bbf, 0xd5033fdf] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn system_closure_red_witness() {
    for word in [0xd5382000, 0xd5182000, 0xd5034fdf, 0xd50041bf] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn exception_closure_red_witness() {
    for word in [0xd4000001, 0xd4000022, 0xd4000003, 0xd4400000] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn transfer_extract_closure_red_witness() {
    for word in [0xf8400800, 0xf8000800, 0x93c10020] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

use std::process::Command;
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

fn oracle_lines(words: &[u32], group: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("carrick-a64-{group}-{}.o", std::process::id()));
    std::fs::write(&path, object(words))?;
    let output =
        Command::new(std::env::var_os("CARRICK_LLVM_OBJDUMP").ok_or("set CARRICK_LLVM_OBJDUMP")?)
            .args([
                "-D",
                "-M",
                "no-aliases",
                "--no-print-imm-hex",
                "--no-show-raw-insn",
                "--no-leading-addr",
            ])
            .arg(&path)
            .output()?;
    std::fs::remove_file(path)?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    let lines: Vec<_> = text
        .lines()
        .filter(|s| s.starts_with(' ') && !s.trim().is_empty())
        .map(|line| {
            line.split("//")
                .next()
                .unwrap_or_default()
                .split(" <")
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .map(|line: String| {
            line.split_whitespace()
                .map(|part| {
                    if let Some(hex) = part.strip_prefix("#0x") {
                        format!("#{}", u32::from_str_radix(hex, 16).expect("LLVM immediate"))
                    } else {
                        part.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    assert_eq!(lines.len(), words.len());
    Ok(lines)
}

fn count() -> u32 {
    if std::env::var_os("CARRICK_LLVM_OBJDUMP").is_some() {
        65_536
    } else {
        256
    }
}
fn sample(i: u32) -> u32 {
    if count() == 256 { i * 257 } else { i }
}
fn reg(number: u32) -> OperandRegister {
    if number == 31 {
        OperandRegister::Zr
    } else {
        // Obtain an architectural register from an independent known ADD word.
        let Instruction::Arithmetic(a) = decode_instruction(0x91000000 | number) else {
            panic!()
        };
        a.rd
    }
}
fn llvm(words: &[u32], group: &str) -> Option<Vec<String>> {
    std::env::var_os("CARRICK_LLVM_OBJDUMP")?;
    Some(oracle_lines(words, group).expect("LLVM oracle succeeds"))
}

#[test]
fn bounded_barrier_operands_and_reserved_options() {
    let mut words = Vec::new();
    let mut expected = Vec::new();
    for op2 in [4, 5, 6] {
        for option in 0..16 {
            for rt in 0..32 {
                let w = 0xd5033000 | option << 8 | op2 << 5 | rt;
                let valid = rt == 31
                    && if op2 == 6 {
                        option == 15
                    } else {
                        option & 3 != 0
                    };
                if valid {
                    let Instruction::Barrier(b) = decode_instruction(w) else {
                        panic!("{w:08x}")
                    };
                    assert_eq!(b.option.value(), option as u8);
                    assert_eq!(
                        b.kind,
                        [BarrierKind::Dsb, BarrierKind::Dmb, BarrierKind::Isb][(op2 - 4) as usize]
                    );
                    assert_eq!(
                        b.domain,
                        [
                            BarrierDomain::OuterShareable,
                            BarrierDomain::NonShareable,
                            BarrierDomain::InnerShareable,
                            BarrierDomain::FullSystem
                        ][(option >> 2) as usize]
                    );
                    assert_eq!(
                        b.access,
                        [
                            BarrierAccess::Reads,
                            BarrierAccess::Writes,
                            BarrierAccess::All
                        ][(option % 4 - 1) as usize]
                    );
                    words.push(w);
                    let names = [
                        "", "oshld", "oshst", "osh", "", "nshld", "nshst", "nsh", "", "ishld",
                        "ishst", "ish", "", "ld", "st", "sy",
                    ];
                    expected.push(format!(
                        "{} {}",
                        ["dsb", "dmb", "isb"][(op2 - 4) as usize],
                        names[option as usize]
                    ));
                } else {
                    assert_eq!(decode_instruction(w), Instruction::Unallocated, "{w:08x}");
                }
            }
        }
    }
    if let Some(lines) = llvm(&words, "closure-barriers") {
        for ((line, expected), word) in lines.iter().zip(&expected).zip(&words) {
            assert_eq!(line, expected, "{word:08x}");
        }
    }
}

#[test]
fn bounded_system_fields_and_pstate_namespace() {
    let mut words = Vec::new();
    for i in 0..count() {
        let i = sample(i);
        let fields = (i / 2) & 32767;
        let rt = (i * 17) & 31;
        let w = 0xd5100000 | (i & 1) << 21 | fields << 5 | rt;
        let Instruction::SystemAccess(a) = decode_instruction(w) else {
            panic!("{w:08x}")
        };
        assert_eq!(
            a.encoding,
            SystemRegister {
                op0: 2 + ((fields >> 14) & 1) as u8,
                op1: ((fields >> 11) & 7) as u8,
                crn: ((fields >> 7) & 15) as u8,
                crm: ((fields >> 3) & 15) as u8,
                op2: (fields & 7) as u8
            }
        );
        assert_eq!(a.rt, reg(rt));
        assert_eq!(
            a.direction,
            if i & 1 == 1 {
                SystemDirection::Read
            } else {
                SystemDirection::Write
            }
        );
        words.push(w);
    }
    if let Some(lines) = llvm(&words, "closure-system") {
        for (i, line) in lines.iter().enumerate() {
            let mnemonic = if i & 1 == 1 { "mrs " } else { "msr " };
            assert!(line.starts_with(mnemonic), "{line}");
            let r = if words[i] & 31 == 31 {
                "xzr".into()
            } else {
                format!("x{}", words[i] & 31)
            };
            assert!(
                if i & 1 == 1 {
                    line.starts_with(&format!("mrs {r}, "))
                } else {
                    line.ends_with(&format!(", {r}"))
                },
                "{line}"
            );
        }
    }
    for op1 in 0..8 {
        for op2 in 0..8 {
            for immediate in 0..16 {
                let w = 0xd500401f | op1 << 16 | immediate << 8 | op2 << 5;
                let field = match (op1, op2) {
                    (0, 3) => Some(PstateField::Uao),
                    (0, 4) => Some(PstateField::Pan),
                    (0, 5) => Some(PstateField::SpSel),
                    (3, 1) => Some(PstateField::Ssbs),
                    (3, 2) => Some(PstateField::Dit),
                    (3, 4) => Some(PstateField::Tco),
                    (3, 6) => Some(PstateField::DaifSet),
                    (3, 7) => Some(PstateField::DaifClr),
                    _ => None,
                };
                assert_eq!(
                    decode_instruction(w),
                    field.map_or(Instruction::Unallocated, |field| {
                        Instruction::PstateImmediate(PstateImmediate {
                            field,
                            immediate: immediate as u8,
                        })
                    }),
                    "{w:08x}"
                );
                assert_eq!(decode_instruction(w & !1), Instruction::Unallocated);
            }
        }
    }
}

#[test]
fn bounded_exception_immediates() {
    let heads = [
        0xd4000001, 0xd4000002, 0xd4000003, 0xd4200000, 0xd4400000, 0xd4a00001, 0xd4a00002,
        0xd4a00003,
    ];
    let kinds = [
        ExceptionKind::Svc,
        ExceptionKind::Hvc,
        ExceptionKind::Smc,
        ExceptionKind::Brk,
        ExceptionKind::Hlt,
        ExceptionKind::Dcps1,
        ExceptionKind::Dcps2,
        ExceptionKind::Dcps3,
    ];
    let names = ["svc", "hvc", "smc", "brk", "hlt", "dcps1", "dcps2", "dcps3"];
    let mut words = Vec::new();
    let mut expected = Vec::new();
    for (index, head) in heads.into_iter().enumerate() {
        for imm in 0..count() {
            let imm = sample(imm);
            let w = head | imm << 5;
            assert_eq!(
                decode_instruction(w),
                Instruction::ExceptionGeneration(ExceptionGeneration {
                    kind: kinds[index],
                    immediate: imm as u16
                })
            );
            assert_eq!(decode_instruction(w | 4), Instruction::Unallocated);
            words.push(w);
            expected.push(format!("{} #{}", names[index], imm));
        }
    }
    if let Some(lines) = llvm(&words, "closure-exceptions") {
        for ((line, expected), word) in lines.iter().zip(&expected).zip(&words) {
            assert_eq!(line, expected, "{word:08x}");
        }
    }
}

#[test]
fn bounded_extract_fields_and_reserved_widths() {
    let mut words = Vec::new();
    let mut expected = Vec::new();
    for i in 0..count() {
        let i = sample(i);
        let sf = i & 1;
        let rm = (i >> 1) & 31;
        let rn = (i >> 6) & 31;
        let rd = (i >> 11) & 31;
        let lsb = (i * 13 >> 3) & if sf == 1 { 63 } else { 31 };
        let w = 0x13800000 | sf << 31 | sf << 22 | rm << 16 | lsb << 10 | rn << 5 | rd;
        assert_eq!(
            decode_instruction(w),
            Instruction::Extract(Extract {
                width: if sf == 1 { Width::X64 } else { Width::W32 },
                rm: reg(rm),
                rn: reg(rn),
                rd: reg(rd),
                lsb: lsb as u8
            })
        );
        assert_eq!(decode_instruction(w ^ (1 << 22)), Instruction::Unallocated);
        assert_eq!(decode_instruction(w | (1 << 21)), Instruction::Unallocated);
        if sf == 0 {
            assert_eq!(decode_instruction(w | 0x8000), Instruction::Unallocated);
        }
        words.push(w);
        let r = |n| {
            if n == 31 {
                format!("{}zr", if sf == 1 { 'x' } else { 'w' })
            } else {
                format!("{}{n}", if sf == 1 { 'x' } else { 'w' })
            }
        };
        expected.push(format!("extr {}, {}, {}, #{lsb}", r(rd), r(rn), r(rm)));
    }
    if let Some(lines) = llvm(&words, "closure-extract") {
        for ((line, expected), word) in lines.iter().zip(&expected).zip(&words) {
            assert_eq!(line, expected, "{word:08x}");
        }
    }
}

#[test]
fn bounded_unprivileged_transfer_operands() {
    let mut words = Vec::new();
    let mut expected = Vec::new();
    for i in 0..count() {
        let i = sample(i);
        let size = i & 3;
        let opc = (i >> 2) & 3;
        let imm = (i >> 4) & 511;
        let rn = (i >> 13) & 31;
        let rt = (i * 17 >> 7) & 31;
        let w = 0x38000800 | size << 30 | opc << 22 | imm << 12 | rn << 5 | rt;
        if opc == 2 && size == 3 || opc == 3 && size >= 2 {
            assert_eq!(decode_instruction(w), Instruction::Unallocated);
            continue;
        }
        let Instruction::UnprivilegedMemory(m) = decode_instruction(w) else {
            panic!("{w:08x}")
        };
        let width = if opc == 2 || size == 3 {
            Width::X64
        } else {
            Width::W32
        };
        assert_eq!(m.size.bytes(), 1 << size);
        assert_eq!(
            m.operation,
            if opc == 0 {
                MemoryOperation::Store
            } else if opc == 1 {
                MemoryOperation::Load
            } else {
                MemoryOperation::LoadSigned
            }
        );
        assert_eq!(
            m.register,
            MemoryRegister::Integer {
                register: reg(rt),
                width
            }
        );
        let MemoryAddress::Immediate {
            base,
            offset,
            index,
            unscaled,
        } = m.address
        else {
            panic!()
        };
        assert_eq!(
            base,
            if rn == 31 {
                OperandRegister::Sp
            } else {
                reg(rn)
            }
        );
        let signed = ((imm as i32) << 23) >> 23;
        assert_eq!(offset.bytes(), signed);
        assert_eq!(index, MemoryIndex::Offset);
        assert!(unscaled);
        words.push(w);
        let name = match (opc, size) {
            (0, 0) => "sttrb",
            (0, 1) => "sttrh",
            (0, _) => "sttr",
            (1, 0) => "ldtrb",
            (1, 1) => "ldtrh",
            (1, _) => "ldtr",
            (_, 0) => "ldtrsb",
            (_, 1) => "ldtrsh",
            _ => "ldtrsw",
        };
        let target = if rt == 31 {
            format!("{}zr", if width == Width::X64 { 'x' } else { 'w' })
        } else {
            format!("{}{rt}", if width == Width::X64 { 'x' } else { 'w' })
        };
        let base = if rn == 31 {
            "sp".into()
        } else {
            format!("x{rn}")
        };
        expected.push(format!("{name} {target}, [{base}, #{signed}]"));
    }
    if let Some(lines) = llvm(&words, "closure-unprivileged") {
        for ((line, expected), word) in lines.iter().zip(&expected).zip(&words) {
            assert_eq!(line, expected, "{word:08x}");
        }
    }
}

#[test]
fn bounded_pstate_llvm_cross_check() {
    let mut words = Vec::new();
    for (op1, op2) in [
        (0, 3),
        (0, 4),
        (0, 5),
        (3, 1),
        (3, 2),
        (3, 4),
        (3, 6),
        (3, 7),
    ] {
        for immediate in 0..16 {
            words.push(0xd500401f | op1 << 16 | immediate << 8 | op2 << 5);
        }
    }
    if let Some(lines) = llvm(&words, "closure-pstate") {
        for (word, line) in words.iter().zip(lines) {
            assert!(line.starts_with("msr "), "{word:08x}: {line}");
        }
    }
}
