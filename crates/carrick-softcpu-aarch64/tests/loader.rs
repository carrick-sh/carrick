use carrick_softcpu_aarch64::*;

#[test]
fn eret_loader_red_witness() {
    assert_eq!(decode_instruction(0xd69f03e0), Instruction::Eret);
}

#[test]
fn ldadd_loader_red_witness() {
    assert_ne!(decode_instruction(0xf8f1021f), Instruction::Unallocated);
}

#[test]
fn tlbi_loader_red_witness() {
    assert_ne!(decode_instruction(0xd508831f), Instruction::Unallocated);
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
                        u32::from_str_radix(hex, 16)
                            .map_or_else(|_| part.to_owned(), |value| format!("#{value}"))
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

fn reg_text(r: OperandRegister, wide: bool) -> String {
    match r {
        OperandRegister::Sp => "sp".into(),
        OperandRegister::Zr => if wide { "xzr" } else { "wzr" }.into(),
        OperandRegister::Gpr(n) => format!("{}{}", if wide { 'x' } else { 'w' }, n.number()),
    }
}

#[test]
fn ldadd_all_operands_and_reserved_neighbours() {
    let mut words = Vec::new();
    let mut expected = Vec::new();
    let full = std::env::var_os("CARRICK_LLVM_OBJDUMP").is_some();
    for size in 0..4 {
        for ordering in 0..4 {
            for rs in 0..32 {
                for rn in 0..32 {
                    for rt in 0..32 {
                        if !full && (rs != rn || (rt != 0 && rt != 31)) {
                            continue;
                        }
                        let w = 0x38200000 | size << 30 | ordering << 22 | rs << 16 | rn << 5 | rt;
                        let Instruction::AtomicAdd(a) = decode_instruction(w) else {
                            panic!("{w:08x}")
                        };
                        assert_eq!(a.size.bytes(), 1 << size);
                        assert_eq!(a.acquire, ordering & 2 != 0);
                        assert_eq!(a.release, ordering & 1 != 0);
                        assert_eq!(a.acquires(), ordering & 2 != 0 && rt != 31);
                        let wide = size == 3;
                        assert_eq!(
                            reg_text(a.source, wide),
                            if rs == 31 {
                                if wide { "xzr".into() } else { "wzr".into() }
                            } else {
                                format!("{}{rs}", if wide { 'x' } else { 'w' })
                            }
                        );
                        assert_eq!(
                            reg_text(a.destination, wide),
                            if rt == 31 {
                                if wide { "xzr".into() } else { "wzr".into() }
                            } else {
                                format!("{}{rt}", if wide { 'x' } else { 'w' })
                            }
                        );
                        assert_eq!(
                            reg_text(a.base, true),
                            if rn == 31 {
                                "sp".into()
                            } else {
                                format!("x{rn}")
                            }
                        );
                        // C6.2.99–101 fixed V, bit 24, and bits 11:10.
                        for bit in [26, 24, 11, 10] {
                            assert!(
                                !matches!(
                                    decode_instruction(w ^ (1 << bit)),
                                    Instruction::AtomicAdd(_)
                                ),
                                "{w:08x} bit {bit}"
                            );
                        }
                        // Other LSE operations are outside this typed leaf.
                        for opc in 1..16 {
                            assert_eq!(decode_instruction(w | opc << 12), Instruction::Unallocated);
                        }
                        expected.push(format!(
                            "ldadd{}{} {}, {}, [{}]",
                            ["", "l", "a", "al"][ordering as usize],
                            ["b", "h", "", ""][size as usize],
                            reg_text(a.source, wide),
                            reg_text(a.destination, wide),
                            reg_text(a.base, true)
                        ));
                        words.push(w);
                    }
                }
            }
        }
    }
    if full {
        assert_eq!(words.len(), 524_288);
        assert_eq!(oracle_lines(&words, "ldadd").unwrap(), expected);
    }
    println!(
        "LDADD: {} words; zero operand/class mismatches",
        words.len()
    );
}

#[test]
fn eret_exact_encoding_and_neighbours() {
    let words: Vec<_> = (0xd69f0000..=0xd69fffff).collect();
    for &w in &words {
        assert_eq!(
            decode_instruction(w),
            if w == 0xd69f03e0 {
                Instruction::Eret
            } else {
                Instruction::Unallocated
            },
            "{w:08x}"
        );
    }
    if std::env::var_os("CARRICK_LLVM_OBJDUMP").is_some() {
        let lines = oracle_lines(&words, "eret").unwrap();
        assert_eq!(lines.iter().filter(|s| *s == "eret").count(), 1);
        assert_eq!(lines[0x3e0], "eret");
    }
}

#[test]
fn sys_space_tlbi_fields_and_names() {
    // Independent operation names transcribed from C6.2.332, not derived from decoder types.
    let names = [
        (
            0,
            3,
            "vmalle1is vae1is aside1is vaae1is - vale1is - vaale1is",
        ),
        (0, 7, "vmalle1 vae1 aside1 vaae1 - vale1 - vaale1"),
        (4, 0, "- ipas2e1is ripas2e1is - - ipas2le1is ripas2le1is -"),
        (4, 3, "alle2is vae2is - - alle1is vale2is vmalls12e1is -"),
        (
            4,
            4,
            "ipas2e1os ipas2e1 ripas2e1 ripas2e1os ipas2le1os ipas2le1 ripas2le1 ripas2le1os",
        ),
        (4, 7, "alle2 vae2 - - alle1 vale2 vmalls12e1 -"),
        (6, 3, "alle3is vae3is - - - vale3is - -"),
        (6, 7, "alle3 vae3 - - - vale3 - -"),
        (
            0,
            1,
            "vmalle1os vae1os aside1os vaae1os - vale1os - vaale1os",
        ),
        (4, 1, "alle2os vae2os - - alle1os vale2os vmalls12e1os -"),
        (6, 1, "alle3os vae3os - - - vale3os - -"),
        (0, 2, "- rvae1is - rvaae1is - rvale1is - rvaale1is"),
        (0, 5, "- rvae1os - rvaae1os - rvale1os - rvaale1os"),
        (0, 6, "- rvae1 - rvaae1 - rvale1 - rvaale1"),
        (4, 2, "- rvae2is - - - rvale2is - -"),
        (4, 5, "- rvae2os - - - rvale2os - -"),
        (4, 6, "- rvae2 - - - rvale2 - -"),
        (6, 2, "- rvae3is - - - rvale3is - -"),
        (6, 5, "- rvae3os - - - rvale3os - -"),
        (6, 6, "- rvae3 - - - rvale3 - -"),
    ];
    for w in (0xd5008000..=0xd507ffff).chain(0xd5288000..=0xd52fffff) {
        assert_eq!(decode_instruction(w), Instruction::Unallocated, "{w:08x}");
    }
    let words: Vec<_> = (0xd5088000..=0xd50fffff).collect();
    let llvm =
        std::env::var_os("CARRICK_LLVM_OBJDUMP").map(|_| oracle_lines(&words, "sys").unwrap());
    let mut typed = 0;
    for (i, &w) in words.iter().enumerate() {
        let (op1, crn, crm, op2, rt) = (
            (w >> 16) & 7,
            (w >> 12) & 15,
            (w >> 8) & 15,
            (w >> 5) & 7,
            w & 31,
        );
        let name = names
            .iter()
            .find(|r| r.0 == op1 && r.1 == crm && crn == 8)
            .map(|r| r.2.split_whitespace().nth(op2 as usize).unwrap())
            .unwrap_or("-");
        let d = decode_instruction(w);
        if name == "-" {
            if !matches!(d, Instruction::CensusGap(Decoded::AddressTranslate { .. })) {
                assert_eq!(d, Instruction::Unallocated, "{w:08x}");
            }
            continue;
        }
        let Instruction::SystemOperation(s) = d else {
            panic!("{w:08x}")
        };
        assert_eq!(
            (
                u32::from(s.op1),
                u32::from(s.crn),
                u32::from(s.crm),
                u32::from(s.op2)
            ),
            (op1, crn, crm, op2)
        );
        assert_eq!(format!("{:?}", s.operation).to_lowercase(), name);
        assert_eq!(
            reg_text(s.rt, true),
            if rt == 31 {
                "xzr".into()
            } else {
                format!("x{rt}")
            }
        );
        if let Some(lines) = &llvm {
            // LLVM uses either the TLBI alias or SYS for operandless operations
            // with a non-ZR Rt. Both must preserve the exact operation and operand.
            let alias = format!(
                "tlbi {name}{}",
                if rt == 31 && (name.starts_with("vmall") || name.starts_with("alle")) {
                    String::new()
                } else {
                    format!(", {}", reg_text(s.rt, true))
                }
            );
            let sys = format!(
                "sys #{op1}, c{crn}, c{crm}, #{op2}{}",
                if rt == 31 {
                    String::new()
                } else {
                    format!(", x{rt}")
                }
            );
            assert!(
                lines[i] == alias || lines[i] == sys,
                "{w:08x}: {} != {alias} or {sys}",
                lines[i]
            );
        }
        typed += 1;
    }
    assert_eq!(typed, 78 * 32);
    println!(
        "SYS: {} words, {typed} TLBI; zero field/name mismatches",
        words.len()
    );
}

/// Decode concatenated production pages generated by the census's memory builders.
/// Set CARRICK_A64_LOADER_SPANS to the temporary raw span file; no words are stored here.
#[test]
#[ignore = "requires CARRICK_A64_LOADER_SPANS generated from production loader/vector builders"]
fn generated_loader_vector_spans_are_typed() {
    let path = std::env::var_os("CARRICK_A64_LOADER_SPANS").expect("set CARRICK_A64_LOADER_SPANS");
    assert_loader_vector_spans_typed(std::path::Path::new(&path));
}

fn assert_loader_vector_spans_typed(path: &std::path::Path) {
    let bytes = std::fs::read(path).expect("generated production spans");
    assert!(!bytes.is_empty(), "no generated code measured");
    assert_eq!(bytes.len() % 4, 0, "partial instruction in generated spans");
    let mut words = 0;
    for (offset, b) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes(b.try_into().unwrap());
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "offset={:x} word={word:08x}",
            offset * 4
        );
        words += 1;
    }
    println!("typed {words} generated production loader/vector words");
}

#[test]
fn generated_loader_vector_spans_reject_eretaa() {
    let path =
        std::env::temp_dir().join(format!("carrick-a64-negative-{}.bin", std::process::id()));
    std::fs::write(&path, 0xd69f0be0u32.to_le_bytes()).unwrap();
    let result = std::panic::catch_unwind(|| assert_loader_vector_spans_typed(&path));
    std::fs::remove_file(path).unwrap();
    assert!(
        result.is_err(),
        "ERETAA must fail the production span witness"
    );
}
