use std::fs;
use std::path::Path;

use goblin::elf::Elf;
use goblin::elf::header::{EM_AARCH64, EM_X86_64, ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use serde::Serialize;
use thiserror::Error;

/// Default load base for ET_DYN (PIE) main executables. Picked so it lives
/// well above page zero and well below `LINUX_MMAP_BASE` / `LINUX_HEAP_BASE`,
/// while still being page-aligned for HVF stage-2 mappings.
pub const LINUX_PIE_DEFAULT_BASE: u64 = 0x1_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfEndianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Machine {
    Aarch64,
    X86_64,
    Other(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfType {
    Exec,
    Dyn,
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfMetadata {
    pub class: ElfClass,
    pub endianness: ElfEndianness,
    pub machine: Machine,
    pub entry: u64,
    pub interpreter: Option<String>,
    pub is_dynamic: bool,
    pub program_header_count: usize,
    pub shared_object: bool,
    pub e_type: ElfType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadPlan {
    pub entry: u64,
    pub interpreter: Option<String>,
    pub program_header_address: Option<u64>,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
    pub segments: Vec<LoadSegment>,
    /// The load bias that has already been baked into `entry`, `segments`,
    /// and `program_header_address`. For ET_EXEC this is zero. For ET_DYN
    /// (PIE executables and dynamic interpreters) this is the address where
    /// the runtime intends to place the image.
    pub load_bias: u64,
    pub e_type: ElfType,
}

impl LoadPlan {
    /// Re-rebase the plan so its load bias becomes `new_bias`. Returns a new
    /// plan whose `entry`, segment virtual addresses, and program-header
    /// address have been shifted by `new_bias - self.load_bias`.
    ///
    /// Calling this on an ET_EXEC plan with a non-zero bias is allowed; it
    /// just shifts every address by the requested amount. This is primarily
    /// useful for the dynamic interpreter (ET_DYN), which the runtime maps
    /// at a fixed `LINUX_INTERPRETER_BASE` rather than at the default PIE
    /// base.
    pub fn with_load_bias(mut self, new_bias: u64) -> Self {
        if new_bias == self.load_bias {
            return self;
        }
        let delta = new_bias.wrapping_sub(self.load_bias);
        self.entry = self.entry.wrapping_add(delta);
        if let Some(phdr) = self.program_header_address {
            self.program_header_address = Some(phdr.wrapping_add(delta));
        }
        for segment in &mut self.segments {
            segment.virtual_address = segment.virtual_address.wrapping_add(delta);
        }
        self.load_bias = new_bias;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadSegment {
    pub file_offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
    pub perms: SegmentPerms,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SegmentPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Error)]
pub enum ElfInspectError {
    #[error("failed to read ELF binary: {0}")]
    Io(#[from] std::io::Error),
    #[error("not an ELF binary")]
    NotElf,
    #[error("failed to parse ELF binary: {0}")]
    Parse(#[from] goblin::error::Error),
}

pub fn inspect_elf(path: impl AsRef<Path>) -> Result<ElfMetadata, ElfInspectError> {
    let bytes = fs::read(path)?;
    inspect_elf_bytes(&bytes)
}

pub fn inspect_elf_bytes(bytes: &[u8]) -> Result<ElfMetadata, ElfInspectError> {
    let elf = parse_elf_bytes(bytes)?;
    Ok(metadata_from_elf(&elf))
}

pub fn plan_elf_load(path: impl AsRef<Path>) -> Result<LoadPlan, ElfInspectError> {
    let bytes = fs::read(path)?;
    plan_elf_load_bytes(&bytes)
}

pub fn plan_elf_load_bytes(bytes: &[u8]) -> Result<LoadPlan, ElfInspectError> {
    let elf = parse_elf_bytes(bytes)?;
    Ok(load_plan_from_elf(&elf))
}

fn parse_elf_bytes(bytes: &[u8]) -> Result<Elf<'_>, ElfInspectError> {
    if !bytes.starts_with(b"\x7fELF") {
        return Err(ElfInspectError::NotElf);
    }

    Ok(Elf::parse(bytes)?)
}

fn metadata_from_elf(elf: &Elf<'_>) -> ElfMetadata {
    ElfMetadata {
        class: if elf.is_64 {
            ElfClass::Elf64
        } else {
            ElfClass::Elf32
        },
        endianness: if elf.little_endian {
            ElfEndianness::Little
        } else {
            ElfEndianness::Big
        },
        machine: match elf.header.e_machine {
            EM_AARCH64 => Machine::Aarch64,
            EM_X86_64 => Machine::X86_64,
            other => Machine::Other(other),
        },
        entry: elf.entry,
        interpreter: elf.interpreter.map(str::to_owned),
        is_dynamic: elf.dynamic.is_some(),
        program_header_count: elf.program_headers.len(),
        shared_object: elf.is_lib,
        e_type: elf_type_from(elf.header.e_type),
    }
}

fn elf_type_from(e_type: u16) -> ElfType {
    match e_type {
        ET_EXEC => ElfType::Exec,
        ET_DYN => ElfType::Dyn,
        other => ElfType::Other(other),
    }
}

fn load_plan_from_elf(elf: &Elf<'_>) -> LoadPlan {
    let e_type = elf_type_from(elf.header.e_type);
    let load_bias = match e_type {
        ElfType::Dyn => LINUX_PIE_DEFAULT_BASE,
        ElfType::Exec | ElfType::Other(_) => 0,
    };

    let segments: Vec<LoadSegment> = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
        .map(|header| LoadSegment {
            file_offset: header.p_offset,
            virtual_address: load_bias.wrapping_add(header.p_vaddr),
            file_size: header.p_filesz,
            memory_size: header.p_memsz,
            alignment: header.p_align,
            perms: SegmentPerms {
                read: header.p_flags & PF_R != 0,
                write: header.p_flags & PF_W != 0,
                execute: header.p_flags & PF_X != 0,
            },
        })
        .collect();

    LoadPlan {
        entry: load_bias.wrapping_add(elf.entry),
        interpreter: elf.interpreter.map(str::to_owned),
        program_header_address: program_header_address(elf, &segments),
        program_header_entry_size: elf.header.e_phentsize,
        program_header_count: elf.header.e_phnum,
        segments,
        load_bias,
        e_type,
    }
}

fn program_header_address(elf: &Elf<'_>, segments: &[LoadSegment]) -> Option<u64> {
    let phoff = elf.header.e_phoff;
    let phsize = u64::from(elf.header.e_phentsize).checked_mul(u64::from(elf.header.e_phnum))?;
    let phend = phoff.checked_add(phsize)?;

    segments.iter().find_map(|segment| {
        let file_end = segment.file_offset.checked_add(segment.file_size)?;
        if phoff >= segment.file_offset && phend <= file_end {
            let offset_in_segment = phoff - segment.file_offset;
            segment.virtual_address.checked_add(offset_in_segment)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ET_EXEC_TYPE: u16 = 2;
    const ET_DYN_TYPE: u16 = 3;
    const EM_AARCH64_VALUE: u16 = 183;
    const PT_LOAD_VALUE: u32 = 1;
    const PF_X_VALUE: u32 = 1;
    const PF_R_VALUE: u32 = 4;

    fn synthetic_aarch64_elf(e_type: u16, entry: u64, segment_vaddr: u64) -> Vec<u8> {
        // Layout: ELF header (64) + 1 program header (56) + a one-page LOAD.
        let mut elf = vec![0_u8; 0x1004];

        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&e_type.to_le_bytes());
        elf[18..20].copy_from_slice(&EM_AARCH64_VALUE.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes()); // version
        elf[24..32].copy_from_slice(&entry.to_le_bytes()); // e_entry
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum

        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD_VALUE.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&(PF_R_VALUE | PF_X_VALUE).to_le_bytes());
        elf[ph + 8..ph + 16].copy_from_slice(&0x1000_u64.to_le_bytes()); // p_offset
        elf[ph + 16..ph + 24].copy_from_slice(&segment_vaddr.to_le_bytes()); // p_vaddr
        elf[ph + 24..ph + 32].copy_from_slice(&segment_vaddr.to_le_bytes()); // p_paddr
        elf[ph + 32..ph + 40].copy_from_slice(&4_u64.to_le_bytes()); // p_filesz
        elf[ph + 40..ph + 48].copy_from_slice(&0x1000_u64.to_le_bytes()); // p_memsz
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes()); // p_align

        // Tiny ret instruction at the start of the LOAD segment so the file
        // contents are well-formed.
        elf[0x1000..0x1004].copy_from_slice(b"\x1f\x20\x03\xd5");
        elf
    }

    #[test]
    fn et_exec_plan_uses_zero_load_bias() {
        let bytes = synthetic_aarch64_elf(ET_EXEC_TYPE, 0x400000, 0x400000);
        let plan = plan_elf_load_bytes(&bytes).unwrap();

        assert_eq!(plan.e_type, ElfType::Exec);
        assert_eq!(plan.load_bias, 0);
        assert_eq!(plan.entry, 0x400000);
        assert_eq!(plan.segments.len(), 1);
        assert_eq!(plan.segments[0].virtual_address, 0x400000);
    }

    #[test]
    fn et_dyn_plan_rebases_to_default_pie_base() {
        // p_vaddr == 0, entry == 0x7500 — the same shape Alpine's busybox uses.
        let bytes = synthetic_aarch64_elf(ET_DYN_TYPE, 0x7500, 0);
        let plan = plan_elf_load_bytes(&bytes).unwrap();

        assert_eq!(plan.e_type, ElfType::Dyn);
        assert_eq!(plan.load_bias, LINUX_PIE_DEFAULT_BASE);
        assert_eq!(plan.entry, LINUX_PIE_DEFAULT_BASE + 0x7500);
        assert_eq!(plan.segments.len(), 1);
        assert_eq!(plan.segments[0].virtual_address, LINUX_PIE_DEFAULT_BASE);
    }

    #[test]
    fn with_load_bias_reshifts_a_dyn_plan() {
        let bytes = synthetic_aarch64_elf(ET_DYN_TYPE, 0x120, 0);
        let plan = plan_elf_load_bytes(&bytes).unwrap();
        assert_eq!(plan.load_bias, LINUX_PIE_DEFAULT_BASE);

        let rebased = plan.with_load_bias(0x7000_0000_0000);
        assert_eq!(rebased.load_bias, 0x7000_0000_0000);
        assert_eq!(rebased.entry, 0x7000_0000_0000 + 0x120);
        assert_eq!(rebased.segments[0].virtual_address, 0x7000_0000_0000);
    }
}
