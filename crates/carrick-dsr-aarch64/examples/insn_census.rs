//! Static instruction census over Linux aarch64 ELF executables.
//!
//! Answers the question that decides whether DIRECT EXECUTION (patch, don't
//! translate) is viable for the native lane: how many instructions in real
//! guest binaries actually need intervention on Darwin?
//!
//! Exactly three things force intervention on a same-ISA host:
//!   - `svc #0`: must reach carrick's dispatcher instead of XNU;
//!   - x18/w18: Darwin's platform register, clobbered by the kernel at
//!     context switch, so a guest value cannot live in the physical register;
//!   - `mrs/msr tpidr_el0`: guest TLS, viable natively only if XNU
//!     context-switches the register (spiked separately).
//!
//! Everything else executes unmodified. If the numbers here are small, the
//! translate-everything architecture is paying its 52.4% emitted-instruction
//! overhead to solve a patch-scale problem.
//!
//! Run: cargo run -p carrick-dsr-aarch64 --example insn_census -- <elf> ...

// A diagnostic example, not shipped runtime: it reads files named on its own
// command line, and dying loudly on a malformed ELF is the correct behaviour
// for a measurement tool - a silent partial parse would give a
// plausible-looking wrong census, the worse failure.
#![allow(clippy::expect_used, clippy::panic, clippy::print_literal)]

fn read_u16(b: &[u8], o: usize) -> u64 {
    u16::from_le_bytes(b[o..o + 2].try_into().expect("u16 slice")) as u64
}
fn read_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("u64 slice"))
}

/// `(file_offset, size, vaddr)` of each SHF_EXECINSTR section.
///
/// Sections, not the PF_X `PT_LOAD`: that segment starts at file offset 0 on
/// every real toolchain binary, so it also covers the ELF header, the program
/// headers and `.note.*`. Decoding those as instructions inflates the x18 tally
/// with ASCII and pointer bytes that merely happen to have 18 in a register
/// field — the earlier revision of this census counted them.
///
/// Empty when the file is fully stripped of section headers; the caller then
/// has nothing it can prove.
fn exec_sections(elf: &[u8]) -> Vec<(usize, usize, u64)> {
    const SHF_EXECINSTR: u64 = 0x4;
    const SHT_NOBITS: u64 = 8;
    let shoff = read_u64(elf, 0x28) as usize;
    let shentsize = read_u16(elf, 0x3a) as usize;
    let shnum = read_u16(elf, 0x3c) as usize;
    if shoff == 0 || shnum == 0 || elf.len() < shoff + shnum * shentsize {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let sh_type = read_u64(elf, sh + 4) & 0xffff_ffff;
        let sh_flags = read_u64(elf, sh + 8);
        if sh_flags & SHF_EXECINSTR == 0 || sh_type == SHT_NOBITS {
            continue;
        }
        out.push((
            read_u64(elf, sh + 0x18) as usize,
            read_u64(elf, sh + 0x20) as usize,
            read_u64(elf, sh + 0x10),
        ));
    }
    out
}

/// `(file_offset, len, vaddr)` of each executable PT_LOAD.
#[allow(dead_code)]
fn exec_segments(elf: &[u8]) -> Vec<(usize, usize, u64)> {
    assert_eq!(&elf[..4], b"\x7fELF", "not an ELF");
    assert_eq!(elf[4], 2, "not ELF64");
    let phoff = read_u64(elf, 0x20) as usize;
    let phentsize = read_u16(elf, 0x36) as usize;
    let phnum = read_u16(elf, 0x38) as usize;
    let mut out = Vec::new();
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(elf[ph..ph + 4].try_into().expect("u32 slice"));
        let p_flags = u32::from_le_bytes(elf[ph + 4..ph + 8].try_into().expect("u32 slice"));
        if p_type == 1 && p_flags & 1 != 0 {
            // PT_LOAD with PF_X
            let offset = read_u64(elf, ph + 0x08) as usize;
            let vaddr = read_u64(elf, ph + 0x10);
            let filesz = read_u64(elf, ph + 0x20) as usize;
            out.push((offset, filesz, vaddr));
        }
    }
    out
}

fn operand_regs(operand: &bad64::Operand) -> Vec<bad64::Reg> {
    use bad64::Operand as O;
    match operand {
        O::Reg { reg, .. } | O::QualReg { reg, .. } | O::ShiftReg { reg, .. } => vec![*reg],
        O::MemReg(reg)
        | O::MemOffset { reg, .. }
        | O::MemPreIdx { reg, .. }
        | O::MemPostIdxImm { reg, .. } => vec![*reg],
        O::MemPostIdxReg(regs) => regs.to_vec(),
        O::MemExt { regs, .. } => regs.to_vec(),
        O::MultiReg { regs, .. } => regs.iter().flatten().copied().collect(),
        _ => Vec::new(),
    }
}

fn main() {
    let mut grand = [0u64; 6];
    println!(
        "{:<44} {:>10} {:>7} {:>7} {:>7} {:>6} {:>6}  {}",
        "file", "insns", "svc", "x18", "tpidr", "bti", "undec", "type/entry"
    );
    for path in std::env::args().skip(1) {
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skip {path}: unreadable");
            continue;
        };
        if bytes.len() < 0x40 || &bytes[..4] != b"\x7fELF" {
            eprintln!("skip {path}: not an ELF");
            continue;
        }
        let e_type = read_u16(&bytes, 0x10); // 2=EXEC 3=DYN
        let entry = read_u64(&bytes, 0x18);
        let (mut insns, mut svc, mut x18, mut tpidr, mut bti, mut undecoded) =
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        for (offset, len, vaddr) in exec_sections(&bytes) {
            let end = (offset + len).min(bytes.len());
            let code = &bytes[offset..end];
            for maybe in bad64::disasm(code, vaddr) {
                let Ok(insn) = maybe else {
                    undecoded += 1;
                    continue;
                };
                insns += 1;
                match insn.op() {
                    bad64::Op::SVC => svc += 1,
                    bad64::Op::BTI => bti += 1,
                    bad64::Op::MRS | bad64::Op::MSR
                        if format!("{insn:?}").contains("TPIDR_EL0") =>
                    {
                        tpidr += 1;
                    }
                    _ => {}
                }
                if insn.operands().iter().any(|operand| {
                    operand_regs(operand)
                        .iter()
                        .any(|reg| matches!(reg, bad64::Reg::X18 | bad64::Reg::W18))
                }) {
                    x18 += 1;
                }
            }
        }
        let kind = if e_type == 2 { "EXEC" } else { "DYN " };
        if insns == 0 {
            eprintln!("note: {path} has no SHF_EXECINSTR sections (stripped?)");
        }
        println!(
            "{:<44} {:>10} {:>7} {:>7} {:>7} {:>6} {:>6}  {kind} 0x{entry:x}",
            path.rsplit('/').next().unwrap_or(&path),
            insns,
            svc,
            x18,
            tpidr,
            bti,
            undecoded
        );
        grand[0] += insns;
        grand[1] += svc;
        grand[2] += x18;
        grand[3] += tpidr;
        grand[4] += bti;
        grand[5] += undecoded;
    }
    println!(
        "{:<44} {:>10} {:>7} {:>7} {:>7} {:>6} {:>6}",
        "TOTAL", grand[0], grand[1], grand[2], grand[3], grand[4], grand[5]
    );
    let pct = |n: u64| 100.0 * n as f64 / grand[0].max(1) as f64;
    println!(
        "\nshares of all instructions: svc {:.4}%  x18 {:.4}%  tpidr {:.4}%",
        pct(grand[1]),
        pct(grand[2]),
        pct(grand[3])
    );
}
