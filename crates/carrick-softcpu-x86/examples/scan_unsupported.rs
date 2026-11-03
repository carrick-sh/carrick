//! Static admission census (not proof that disassembled code is reachable).
//! Usage: scan_unsupported --expect-files 552 ELF...
//! Stdout is a reproducible ceiling file: Code occurrences affected_files.
//! Linear decoding of SHF_EXECINSTR sections includes inline data and deliberate
//! UD2 traps; keep these visible in the residue rather than silently hiding them.
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use carrick_softcpu_x86::{InsnClass, classify};
use goblin::elf::{Elf, header::EM_X86_64, section_header::SHF_EXECINSTR};

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mut expected = None;
    let mut files = BTreeSet::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--expect-files" => {
                expected = Some(args.next().ok_or("missing count")?.parse::<usize>()?)
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}").into()),
            _ => {
                if !files.insert(std::fs::canonicalize(arg)?) {
                    return Err("duplicate input ELF".into());
                }
            }
        }
    }
    if files.is_empty() || expected != Some(files.len()) {
        return Err("--expect-files must match the nonempty, unique ELF population".into());
    }
    let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut instructions = 0usize;
    for path in &files {
        let bytes = std::fs::read(path)?;
        let elf = Elf::parse(&bytes)?;
        if elf.header.e_machine != EM_X86_64 || !elf.is_64 || !elf.little_endian {
            return Err(format!("not a little-endian x86_64 ELF: {}", path.display()).into());
        }
        let mut seen = BTreeSet::new();
        let mut decoded = 0usize;
        for section in &elf.section_headers {
            if section.sh_flags & u64::from(SHF_EXECINSTR) == 0 || section.sh_size == 0 {
                continue;
            }
            let start = usize::try_from(section.sh_offset)?;
            let end = start
                .checked_add(usize::try_from(section.sh_size)?)
                .ok_or("section overflow")?;
            let code = bytes.get(start..end).ok_or("section outside ELF")?;
            let mut offset = 0usize;
            while offset < code.len() {
                let va = section
                    .sh_addr
                    .checked_add(offset as u64)
                    .ok_or("VA overflow")?;
                let insn = classify(&code[offset..], va).ok_or("empty decode")?;
                decoded += 1;
                if insn.class == InsnClass::InvalidOpcode {
                    let key = format!("{:?}", insn.raw.code());
                    counts.entry(key.clone()).or_default().0 += 1;
                    seen.insert(key);
                }
                offset += insn.len;
            }
        }
        if decoded == 0 {
            return Err(format!("no executable section: {}", path.display()).into());
        }
        instructions += decoded;
        for key in seen {
            counts.entry(key).or_default().1 += 1;
        }
    }
    eprintln!(
        "files={} decoded_instructions={} unsupported_encodings={}",
        files.len(),
        instructions,
        counts.len()
    );
    for (code, (occurrences, affected)) in &counts {
        println!("{code}\t{occurrences}\t{affected}");
    }
    if !counts.is_empty() {
        return Err("unsupported instructions remain; census is diagnostic only".into());
    }
    Ok(())
}
