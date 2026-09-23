//! Read-only static compatibility audit; never executes or rewrites the input ELF.
//! Counts are instruction sites, not dynamic frequency or translation support.
use anyhow::{Context, Result, bail, ensure};
use goblin::elf::{Elf, header, program_header};
use native_syscall_slice::classify;
use serde_json::json;
use std::{collections::BTreeMap, path::Path};

fn executable_range(elf: &Elf<'_>, address: u64, size: u64) -> Result<std::ops::Range<usize>> {
    ensure!(
        address.is_multiple_of(4) && size != 0 && size.is_multiple_of(4),
        "symbol has no complete instruction range"
    );
    let end = address.checked_add(size).context("symbol range overflow")?;
    for segment in &elf.program_headers {
        if segment.p_type != program_header::PT_LOAD || !segment.is_executable() {
            continue;
        }
        let file_end = segment
            .p_vaddr
            .checked_add(segment.p_filesz)
            .context("segment overflow")?;
        if address >= segment.p_vaddr && end <= file_end {
            let offset = segment
                .p_offset
                .checked_add(address - segment.p_vaddr)
                .context("file offset overflow")?;
            let limit = offset.checked_add(size).context("file range overflow")?;
            return Ok(usize::try_from(offset)?..usize::try_from(limit)?);
        }
    }
    bail!("symbol is not wholly inside file-backed executable memory")
}

#[expect(
    clippy::disallowed_methods,
    reason = "Read-only non-product audit of an operator-selected host ELF; no guest execution or guest path resolution"
)]
fn load_host_elf(path: &Path) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}

fn audit(path: &Path, names: &[String]) -> Result<()> {
    let bytes = load_host_elf(path).with_context(|| format!("read {}", path.display()))?;
    let elf = Elf::parse(&bytes)?;
    ensure!(
        elf.is_64 && elf.little_endian && elf.header.e_machine == header::EM_AARCH64,
        "requires a little-endian AArch64 ELF64"
    );
    let mut results = Vec::new();
    for name in names {
        let symbol = elf
            .syms
            .iter()
            .find(|symbol| elf.strtab.get_at(symbol.st_name) == Some(name))
            .or_else(|| {
                elf.dynsyms
                    .iter()
                    .find(|symbol| elf.dynstrtab.get_at(symbol.st_name) == Some(name))
            })
            .with_context(|| format!("missing symbol {name}"))?;
        let range = executable_range(&elf, symbol.st_value, symbol.st_size)?;
        let code = bytes.get(range).context("symbol exceeds input file")?;
        let mut accepted = BTreeMap::<String, usize>::new();
        let mut rejected_reasons = BTreeMap::<String, usize>::new();
        let mut rejected_sites = Vec::new();
        let mut instruction_sites = Vec::new();
        let mut run = 0usize;
        let mut longest = 0usize;
        for (index, instruction) in code.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes(instruction.try_into()?);
            instruction_sites.push(json!({
                "address": format!("0x{:x}", symbol.st_value + index as u64 * 4),
                "word": format!("0x{word:08x}"),
            }));
            match classify(word) {
                Ok(kind) => {
                    *accepted.entry(format!("{kind:?}")).or_default() += 1;
                    run += 1;
                    longest = longest.max(run);
                }
                Err(reason) => {
                    *rejected_reasons.entry(reason.into()).or_default() += 1;
                    rejected_sites.push(json!({
                        "address": format!("0x{:x}", symbol.st_value + index as u64 * 4),
                        "word": format!("0x{word:08x}"),
                        "reason": reason,
                    }));
                    run = 0;
                }
            }
        }
        results.push(json!({
            "symbol": name,
            "elf_virtual_address": format!("0x{:x}", symbol.st_value),
            "instruction_sites": code.len() / 4,
            "instructions": instruction_sites,
            "accepted_sites": accepted.values().sum::<usize>(),
            "accepted_classes": accepted,
            "rejected_sites_count": rejected_sites.len(),
            "rejected_reasons": rejected_reasons,
            "rejected_sites": rejected_sites,
            "longest_linear_accepted_run": longest,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "native-slice-static-text-coverage-v1",
            "input": path,
            "limitation": "Static instruction sites only; accepted decoding does not prove linked execution, memory authority, atomic ordering, or workload coverage. Linear runs ignore branch edges.",
            "symbols": results,
        }))?
    );
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().context("usage: text-coverage ELF SYMBOL...")?;
    let names: Vec<_> = args.collect();
    ensure!(!names.is_empty(), "at least one symbol is required");
    audit(Path::new(&path), &names)
}
