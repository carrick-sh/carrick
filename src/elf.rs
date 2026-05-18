use std::fs;
use std::path::Path;

use goblin::elf::Elf;
use goblin::elf::header::{EM_AARCH64, EM_X86_64};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use serde::Serialize;
use thiserror::Error;

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadPlan {
    pub entry: u64,
    pub interpreter: Option<String>,
    pub program_header_address: Option<u64>,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
    pub segments: Vec<LoadSegment>,
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
    }
}

fn load_plan_from_elf(elf: &Elf<'_>) -> LoadPlan {
    let segments: Vec<LoadSegment> = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
        .map(|header| LoadSegment {
            file_offset: header.p_offset,
            virtual_address: header.p_vaddr,
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
        entry: elf.entry,
        interpreter: elf.interpreter.map(str::to_owned),
        program_header_address: program_header_address(elf, &segments),
        program_header_entry_size: elf.header.e_phentsize,
        program_header_count: elf.header.e_phnum,
        segments,
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
