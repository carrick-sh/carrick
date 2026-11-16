//! Static A64 census. JSON goes to stdout even when unknown encodings fail
//! the command. ELF mapping symbols are authoritative; flat-image mode is
//! explicitly conservative because it cannot distinguish literal data.
use anyhow::{Context, Result, ensure};
use carrick_softcpu_aarch64::{A64Class, classify};
use goblin::elf::{Elf, header, section_header, sym};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Default)]
struct Census {
    producers: BTreeSet<String>,
    counts: BTreeMap<String, u64>,
    registers: BTreeMap<String, u64>,
    unknown: Vec<Value>,
    spans: Vec<Value>,
}

fn register_name(fields: (u8, u8, u8, u8, u8)) -> &'static str {
    match fields {
        (3, 0, 2, 0, 0) => "TTBR0_EL1",
        (3, 0, 2, 0, 1) => "TTBR1_EL1",
        (3, 0, 2, 0, 2) => "TCR_EL1",
        (3, 0, 12, 0, 0) => "VBAR_EL1",
        (3, 3, 14, 3, 1) => "CNTV_CTL_EL0",
        (3, 3, 14, 3, 2) => "CNTV_CVAL_EL0",
        (3, 3, 14, 0, 2) => "CNTVCT_EL0",
        (3, 3, 14, 0, 0) => "CNTFRQ_EL0",
        (3, 0, 12, 11, 5) => "ICC_SGI1R_EL1",
        (3, 0, 12, 12, 0) => "ICC_IAR1_EL1",
        (3, 0, 12, 12, 1) => "ICC_EOIR1_EL1",
        (3, 0, 1, 0, 0) => "SCTLR_EL1",
        (3, 0, 10, 2, 0) => "MAIR_EL1",
        (3, 0, 4, 0, 0) => "SPSR_EL1",
        (3, 0, 4, 0, 1) => "ELR_EL1",
        (3, 0, 4, 1, 0) => "SP_EL0",
        (3, 0, 5, 2, 0) => "ESR_EL1",
        (3, 0, 6, 0, 0) => "FAR_EL1",
        (3, 0, 7, 4, 0) => "PAR_EL1",
        (3, 0, 13, 0, 4) => "TPIDR_EL1",
        (3, 3, 13, 0, 2) => "TPIDR_EL0",
        (3, 3, 13, 0, 3) => "TPIDRRO_EL0",
        (3, 0, 13, 0, 1) => "CONTEXTIDR_EL1",
        (3, 3, 4, 4, 0) => "FPCR",
        (3, 3, 4, 4, 1) => "FPSR",
        (3, 3, 4, 2, 1) => "DAIF",
        (3, 0, 0, 0, 5) => "MPIDR_EL1",
        _ => "unnamed",
    }
}
impl Census {
    fn span(&mut self, name: &str, address: u64, bytes: &[u8]) -> Result<()> {
        ensure!(
            address.is_multiple_of(4) && bytes.len().is_multiple_of(4),
            "unaligned code span {name}"
        );
        self.spans
            .push(json!({"name":name,"address":address,"bytes":bytes.len(),"sha256":sha(bytes)}));
        for (i, word) in bytes.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            let class = classify(word);
            let class_name = match class {
                A64Class::Mrs(reg) | A64Class::Msr(reg) => {
                    let fields = (reg.op0, reg.op1, reg.crn, reg.crm, reg.op2);
                    let key = format!(
                        "S{}_{}_C{}_C{}_{} ({})",
                        reg.op0,
                        reg.op1,
                        reg.crn,
                        reg.crm,
                        reg.op2,
                        register_name(fields)
                    );
                    *self.registers.entry(key).or_default() += 1;
                    if matches!(class, A64Class::Mrs(_)) {
                        "Mrs".to_owned()
                    } else {
                        "Msr".to_owned()
                    }
                }
                other => format!("{other:?}"),
            };
            *self.counts.entry(class_name).or_default() += 1;
            if class == A64Class::Unknown {
                self.unknown.push(json!({"span":name,"address":address + i as u64 * 4,"encoding":format!("0x{word:08x}")}));
            }
        }
        Ok(())
    }
    fn elf(&mut self, bytes: &[u8]) -> Result<()> {
        let elf = Elf::parse(bytes)?;
        ensure!(
            elf.header.e_machine == header::EM_AARCH64 && elf.little_endian,
            "requires little-endian AArch64 ELF"
        );
        // Producer provenance comes from the input, never from spawning a
        // compiler or reading host environment state. Flat bytes lack this.
        for section in &elf.section_headers {
            if elf.shdr_strtab.get_at(section.sh_name) == Some(".comment") {
                let start = usize::try_from(section.sh_offset)?;
                let end = start
                    .checked_add(usize::try_from(section.sh_size)?)
                    .context("producer section overflow")?;
                for producer in bytes
                    .get(start..end)
                    .context("truncated producer section")?
                    .split(|b| *b == 0)
                {
                    if !producer.is_empty() {
                        self.producers.insert(
                            std::str::from_utf8(producer)
                                .context("non-UTF8 producer string")?
                                .to_owned(),
                        );
                    }
                }
            }
        }
        let mut executable = 0;
        for (index, section) in elf.section_headers.iter().enumerate() {
            if section.sh_flags & u64::from(section_header::SHF_EXECINSTR) == 0
                || section.sh_size == 0
            {
                continue;
            }
            ensure!(
                section.sh_type == section_header::SHT_PROGBITS,
                "executable section has no file bytes"
            );
            executable += 1;
            let start = section.sh_addr;
            let end = start
                .checked_add(section.sh_size)
                .context("section overflow")?;
            let mut boundaries = BTreeMap::new();
            for symbol in &elf.syms {
                if symbol.st_shndx != index {
                    continue;
                }
                let Some(name) = elf.strtab.get_at(symbol.st_name) else {
                    continue;
                };
                let kind = if name == "$x" || name.starts_with("$x.") {
                    Some(true)
                } else if name == "$d" || name.starts_with("$d.") {
                    Some(false)
                } else {
                    None
                };
                if let Some(code) = kind {
                    ensure!(
                        (start..end).contains(&symbol.st_value),
                        "mapping symbol outside section"
                    );
                    if let Some(previous) = boundaries.insert(symbol.st_value, code) {
                        ensure!(previous == code, "conflicting mapping symbols");
                    }
                }
                // Function symbols cannot override $d: they are checked as
                // bounds, not used as a heuristic for literal-pool contents.
                if symbol.st_type() == sym::STT_FUNC {
                    ensure!(
                        symbol.st_value >= start
                            && symbol
                                .st_value
                                .checked_add(symbol.st_size)
                                .is_some_and(|v| v <= end),
                        "function outside executable section"
                    );
                }
            }
            ensure!(
                boundaries.contains_key(&start),
                "executable section lacks initial mapping symbol; refusing to guess code/data"
            );
            boundaries.insert(end, false);
            let points: Vec<_> = boundaries.into_iter().collect();
            let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("?");
            for pair in points.windows(2) {
                if !pair[0].1 {
                    continue;
                }
                let offset = section
                    .sh_offset
                    .checked_add(pair[0].0 - start)
                    .context("offset overflow")?;
                let length = pair[1].0 - pair[0].0;
                let lo = usize::try_from(offset)?;
                let hi = lo
                    .checked_add(usize::try_from(length)?)
                    .context("span overflow")?;
                self.span(
                    section_name,
                    pair[0].0,
                    bytes.get(lo..hi).context("truncated executable span")?,
                )?;
            }
        }
        ensure!(executable != 0, "no executable sections");
        Ok(())
    }
    fn report(&self, input: &[u8], mode: &str) -> Value {
        json!({"schema":"carrick.a64-census.v1", "tool_version":env!("CARGO_PKG_VERSION"),
            "classifier":"hand-authored-a64-v1", "compiler_producers":self.producers, "producer_source":"ELF .comment when present; flat bytes have no producer metadata",
            "scope":"EL1 plus loader; EL0 fixture closure is slice 0b", "input_mode":mode,
            "input_sha256":sha(input), "spans":self.spans,"counts":self.counts,
            "system_registers":self.registers,"unknown_count":self.unknown.len(),"unknown":self.unknown})
    }
    fn finish(&self) -> Result<()> {
        ensure!(
            self.unknown.is_empty(),
            "A64 census contains {} unknown words",
            self.unknown.len()
        );
        Ok(())
    }
}

pub(crate) fn run(input: Option<&Path>) -> Result<()> {
    let mut census = Census::default();
    let bytes = if let Some(path) = input {
        std::fs::read(path).with_context(|| format!("read {}", path.display()))?
    } else {
        carrick_el1_image::IMAGE.to_vec()
    };
    let mode = if input.is_some() {
        census.elf(&bytes)?;
        "ELF mapping symbols"
    } else {
        census.span("embedded-flat-conservative-includes-data", 0, &bytes)?;
        "flat upper bound, includes data"
    };
    use carrick_mem::memory;
    census.span(
        "loader-maintenance",
        memory::LINUX_EL1_MAINT_BASE,
        &memory::el1_maintenance_bytes(),
    )?;
    for (name, bytes) in [
        ("legacy", memory::el1_vectors_bytes()),
        ("legacy-fd", memory::el1_vectors_bytes_fd_ceiling()),
        ("shim", memory::el1_vectors_bytes_shim()),
        ("shim-fd", memory::el1_vectors_bytes_shim_fd_ceiling()),
    ] {
        census.span(name, memory::LINUX_EL1_VECTORS_BASE, &bytes)?;
    }
    for identity in [false, true] {
        for fd in [false, true] {
            for el1 in [false, true] {
                for irq in [memory::El1IrqMode::Masked, memory::El1IrqMode::Gic] {
                    let name = format!("mailbox-identity={identity}-fd={fd}-el1={el1}-irq={irq:?}");
                    census.span(
                        &name,
                        memory::LINUX_EL1_VECTORS_BASE,
                        &memory::el1_vectors_bytes_mailbox_irq(identity, fd, el1, irq),
                    )?;
                }
            }
            for irq in [memory::El1IrqMode::Masked, memory::El1IrqMode::Gic] {
                let name = format!("clock-identity={identity}-fd={fd}-irq={irq:?}");
                census.span(
                    &name,
                    memory::LINUX_EL1_VECTORS_BASE,
                    &memory::el1_vectors_bytes_mailbox_clock(identity, fd, irq),
                )?;
            }
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&census.report(&bytes, mode))?
    );
    census.finish()
}

#[cfg(test)]
mod tests {
    use super::Census;
    use anyhow::Result;
    #[test]
    fn reserved_span_rejected_and_report_deterministic() -> Result<()> {
        let bytes: Vec<u8> = [0xd503201f_u32, 0xffff_ffff]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let mut census = Census::default();
        census.span("negative", 0x1000, &bytes)?;
        assert!(census.finish().is_err());
        let a = serde_json::to_vec_pretty(&census.report(&bytes, "test"))?;
        let mut second = Census::default();
        second.span("negative", 0x1000, &bytes)?;
        assert_eq!(
            a,
            serde_json::to_vec_pretty(&second.report(&bytes, "test"))?
        );
        assert_eq!(census.unknown[0]["address"], 0x1004);
        assert_eq!(census.unknown[0]["encoding"], "0xffffffff");
        Ok(())
    }
}
