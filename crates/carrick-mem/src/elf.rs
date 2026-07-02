//! ELF inspection and load-planning helpers for Linux AArch64 executables.

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SegmentPerms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

/// A page-granular guest-VA span that must be READ-ONLY in the guest's own
/// page tables: the pages of an ELF image's non-writable `PT_LOAD` segments
/// (.text / .rodata / RELRO-at-link-time). The host-side region mapping stays
/// merged/escalated (the HVF stage-2 quirk workaround in
/// `memory::regions_from_load_plan`), so per-segment write protection must be
/// re-applied at the STAGE-1/PML4 leaf level from these spans — otherwise a
/// guest store to its own `.rodata` silently succeeds (Go reflect
/// `TestTypeFieldReadOnly`, LTP mmap fault-delivery family).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RoSpan {
    /// Page-aligned guest VA of the first read-only page.
    pub start: u64,
    /// Page-aligned length in bytes (never 0).
    pub len: u64,
    /// Whether the pages stay executable (PF_X text) — read-only either way.
    pub exec: bool,
}

/// Compute the page-granular read-only spans for a load plan: every page
/// covered by a non-writable `PT_LOAD` segment, MINUS any page a writable
/// segment also touches (when an RO and an RW segment share a page, Linux's
/// later RW mapping leaves that page writable — mirror that so the guest's
/// own `.data` head never becomes read-only). 4 KiB pages — the stage-1/PML4
/// leaf granule on both guest ISAs.
pub fn ro_page_spans(plan: &LoadPlan) -> Vec<RoSpan> {
    const PAGE: u64 = 0x1000;
    let floor = |v: u64| v & !(PAGE - 1);
    let ceil = |v: u64| v.checked_add(PAGE - 1).map(|c| c & !(PAGE - 1));

    // Page-rounded extents of every writable segment.
    let writable: Vec<(u64, u64)> = plan
        .segments
        .iter()
        .filter(|seg| seg.perms.write && seg.memory_size > 0)
        .filter_map(|seg| {
            let end = seg.virtual_address.checked_add(seg.memory_size)?;
            Some((floor(seg.virtual_address), ceil(end)?))
        })
        .collect();

    let mut out = Vec::new();
    for seg in &plan.segments {
        if seg.perms.write || !seg.perms.read || seg.memory_size == 0 {
            continue;
        }
        let Some(seg_end) = seg.virtual_address.checked_add(seg.memory_size) else {
            continue;
        };
        let Some(seg_end) = ceil(seg_end) else {
            continue;
        };
        // Subtract each writable page-extent; a clip can split a span in two.
        let mut pieces = vec![(floor(seg.virtual_address), seg_end)];
        for &(w_start, w_end) in &writable {
            let mut next = Vec::with_capacity(pieces.len() + 1);
            for (s, e) in pieces {
                if w_end <= s || w_start >= e {
                    next.push((s, e));
                    continue;
                }
                if s < w_start {
                    next.push((s, w_start));
                }
                if w_end < e {
                    next.push((w_end, e));
                }
            }
            pieces = next;
        }
        for (s, e) in pieces {
            if e > s {
                out.push(RoSpan {
                    start: s,
                    len: e - s,
                    exec: seg.perms.execute,
                });
            }
        }
    }
    // Two adjacent read-only segments (RX text, R rodata) can share a page.
    // Executability must WIN on such a page — marking it NX would fault an
    // instruction fetch from the text tail — so clip every non-exec span
    // against the exec spans' page extents (write-protection is identical
    // either way; only the NX bit differs).
    let exec_extents: Vec<(u64, u64)> = out
        .iter()
        .filter(|s| s.exec)
        .map(|s| (s.start, s.start + s.len))
        .collect();
    let mut resolved = Vec::with_capacity(out.len());
    for span in out {
        if span.exec {
            resolved.push(span);
            continue;
        }
        let mut pieces = vec![(span.start, span.start + span.len)];
        for &(x_start, x_end) in &exec_extents {
            let mut next = Vec::with_capacity(pieces.len() + 1);
            for (s, e) in pieces {
                if x_end <= s || x_start >= e {
                    next.push((s, e));
                    continue;
                }
                if s < x_start {
                    next.push((s, x_start));
                }
                if x_end < e {
                    next.push((x_end, e));
                }
            }
            pieces = next;
        }
        for (s, e) in pieces {
            if e > s {
                resolved.push(RoSpan {
                    start: s,
                    len: e - s,
                    exec: false,
                });
            }
        }
    }
    resolved
}

#[derive(Debug, Error)]
pub enum ElfInspectError {
    #[error("failed to read ELF binary: {0}")]
    Io(#[from] std::io::Error),
    #[error("not an ELF binary")]
    NotElf,
    #[error("failed to parse ELF binary: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("unsupported ELF machine: {0}")]
    UnsupportedMachine(u16),
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
    plan_elf_load_for(path, EM_AARCH64)
}

/// Load-plan a binary at `path`, accepting only the given `machine` type
/// (e.g. `EM_AARCH64 = 183`, `EM_X86_64 = 62` per elf(5)/psABI).
/// The default aarch64 callers use [`plan_elf_load`] which delegates here
/// with `EM_AARCH64`, preserving byte-identical behaviour.
pub fn plan_elf_load_for(
    path: impl AsRef<Path>,
    machine: u16,
) -> Result<LoadPlan, ElfInspectError> {
    let bytes = fs::read(path)?;
    plan_elf_load_bytes_for(&bytes, machine)
}

pub fn plan_elf_load_bytes(bytes: &[u8]) -> Result<LoadPlan, ElfInspectError> {
    plan_elf_load_bytes_for(bytes, EM_AARCH64)
}

/// Load-plan from an in-memory ELF image, accepting only the given `machine`
/// type. `EM_X86_64 = 62` (elf(5)/psABI §4.1 e_machine); `EM_AARCH64 = 183`.
/// The default aarch64 callers use [`plan_elf_load_bytes`] which delegates
/// here with `EM_AARCH64`, preserving byte-identical behaviour.
pub fn plan_elf_load_bytes_for(bytes: &[u8], machine: u16) -> Result<LoadPlan, ElfInspectError> {
    let elf = parse_elf_bytes(bytes)?;
    if elf.header.e_machine != machine {
        return Err(ElfInspectError::UnsupportedMachine(elf.header.e_machine));
    }
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
        .inspect(|_header| {
            // Debug-only LOAD-segment dump, compile-gated behind `trace-elf`.
            #[cfg(feature = "trace-elf")]
            eprintln!(
                "LOAD p_offset=0x{:x} p_vaddr=0x{:x} p_filesz=0x{:x} p_memsz=0x{:x} bias=0x{:x}",
                _header.p_offset, _header.p_vaddr, _header.p_filesz, _header.p_memsz, load_bias
            );
        })
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
    fn load_plan_rejects_non_aarch64_machine() {
        let mut bytes = synthetic_aarch64_elf(ET_EXEC_TYPE, 0x400000, 0x400000);
        bytes[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());

        let err = plan_elf_load_bytes(&bytes).unwrap_err();

        assert!(
            err.to_string().contains("unsupported ELF machine"),
            "unexpected error: {err}",
        );
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

    /// Construct a minimal synthetic ELF header with the given e_machine value.
    /// Clones `synthetic_aarch64_elf` then overwrites bytes [18..20] with
    /// `machine` in little-endian — the e_machine field per elf(5).
    fn synthetic_elf_with_machine(machine: u16) -> Vec<u8> {
        let mut bytes = synthetic_aarch64_elf(ET_EXEC_TYPE, 0x400000, 0x400000);
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    /// `plan_elf_load_bytes_for` with EM_X86_64 (= 62, elf(5)/psABI §4.1)
    /// accepts a synthetic x86_64 ELF header and returns a valid plan.
    #[test]
    fn plan_elf_load_bytes_for_accepts_x86_64() {
        // EM_X86_64 = 62 per elf(5) and the x86-64 psABI §4.1 e_machine field.
        let bytes = synthetic_elf_with_machine(EM_X86_64);
        let plan = plan_elf_load_bytes_for(&bytes, EM_X86_64).unwrap();
        assert_eq!(plan.e_type, ElfType::Exec);
        assert_eq!(plan.load_bias, 0);
        assert_eq!(plan.entry, 0x400000);
        assert_eq!(plan.segments.len(), 1);
    }

    fn plan_with_segments(segments: Vec<LoadSegment>) -> LoadPlan {
        LoadPlan {
            entry: 0x400000,
            interpreter: None,
            program_header_address: None,
            program_header_entry_size: 56,
            program_header_count: segments.len() as u16,
            segments,
            load_bias: 0,
            e_type: ElfType::Exec,
        }
    }

    fn seg(vaddr: u64, memsz: u64, write: bool, exec: bool) -> LoadSegment {
        LoadSegment {
            file_offset: 0,
            virtual_address: vaddr,
            file_size: memsz,
            memory_size: memsz,
            alignment: 0x1000,
            perms: SegmentPerms {
                read: true,
                write,
                execute: exec,
            },
        }
    }

    #[test]
    fn ro_page_spans_cover_readonly_segments_pagewise() {
        // RX text + R rodata + RW data, all page-aligned: the two read-only
        // segments become page-rounded RO spans with their exec bit; the RW
        // segment contributes nothing.
        let plan = plan_with_segments(vec![
            seg(0x400000, 0x2000, false, true),  // text RX
            seg(0x402000, 0x1000, false, false), // rodata R
            seg(0x403000, 0x1000, true, false),  // data RW
        ]);
        let spans = ro_page_spans(&plan);
        assert_eq!(spans.len(), 2);
        assert_eq!(
            (spans[0].start, spans[0].len, spans[0].exec),
            (0x400000, 0x2000, true)
        );
        assert_eq!(
            (spans[1].start, spans[1].len, spans[1].exec),
            (0x402000, 0x1000, false)
        );
    }

    #[test]
    fn ro_page_spans_drop_pages_shared_with_a_writable_segment() {
        // The rodata segment ends mid-page and the data segment starts on the
        // same page: Linux's later RW mapping leaves that page writable, so
        // the RO span must be clipped to the fully-read-only pages.
        let plan = plan_with_segments(vec![
            seg(0x400000, 0x1800, false, false), // R, ends mid-page 0x401xxx
            seg(0x401800, 0x800, true, false),   // RW, starts on that page
        ]);
        let spans = ro_page_spans(&plan);
        assert_eq!(spans.len(), 1);
        assert_eq!((spans[0].start, spans[0].len), (0x400000, 0x1000));
    }

    #[test]
    fn ro_page_spans_exec_wins_on_a_page_shared_by_rx_and_r_segments() {
        // RX text tail and R rodata head share a page: both are read-only, but
        // the shared page must stay EXECUTABLE (NX would fault the text tail).
        let plan = plan_with_segments(vec![
            seg(0x400000, 0x1800, false, true),  // RX, ends mid-page 0x401xxx
            seg(0x401800, 0x1800, false, false), // R, starts on that page
        ]);
        let mut spans = ro_page_spans(&plan);
        spans.sort_by_key(|s| s.start);
        // Every page is read-only; the shared page 0x401000 belongs to an
        // exec span, and the non-exec remainder starts at 0x402000.
        assert!(
            spans
                .iter()
                .any(|s| s.exec && s.start == 0x400000 && s.len == 0x2000)
        );
        assert!(
            spans.iter().all(|s| s.exec || s.start >= 0x402000),
            "non-exec span must not cover the shared text page: {spans:?}"
        );
    }

    #[test]
    fn ro_page_spans_ignore_unreadable_and_empty_segments() {
        let plan = plan_with_segments(vec![
            seg(0x400000, 0, false, false), // empty
            LoadSegment {
                perms: SegmentPerms {
                    read: false,
                    write: false,
                    execute: false,
                },
                ..seg(0x500000, 0x1000, false, false)
            },
        ]);
        assert!(ro_page_spans(&plan).is_empty());
    }

    /// `plan_elf_load_bytes_for` with EM_AARCH64 rejects an x86_64 header —
    /// proving the `machine` parameter gates correctly in both directions.
    #[test]
    fn plan_elf_load_bytes_for_rejects_machine_mismatch() {
        // A header with e_machine = EM_X86_64 must be rejected when the caller
        // requests EM_AARCH64.
        let bytes = synthetic_elf_with_machine(EM_X86_64);
        let err = plan_elf_load_bytes_for(&bytes, EM_AARCH64).unwrap_err();
        assert!(
            err.to_string().contains("unsupported ELF machine"),
            "unexpected error: {err}",
        );
    }
}
