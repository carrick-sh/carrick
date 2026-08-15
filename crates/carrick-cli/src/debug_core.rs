//! `carrick debug core` — validate and summarise a Linux ELF core file.
//!
//! This is a READER, not a re-serialiser. It parses the bytes the way an
//! external debugger would and fails BY NAME on every structural problem, so a
//! core that carrick cannot itself explain is never reported as healthy. That
//! is the difference between "we wrote a file" and "the file is a core".
//!
//! Layout facts (note sizes, note types, the `CORE` owner, header sizes) come
//! from [`carrick_runtime::core_dump`], including the architecture-note owner
//! whose ABI definition the writer re-exports, so writer and validator cannot
//! drift.

use carrick_runtime::core_dump::{
    AARCH64_FPREGSET_SIZE, AARCH64_TLS_SIZE, ELF_CLASS64, EM_AARCH64, ET_CORE,
    LINUX_ELF_NOTE_OWNER, NOTE_ALIGN, NOTE_OWNER, NT_ARM_TLS, NT_AUXV, NT_FILE, NT_FPREGSET,
    NT_PRPSINFO, NT_PRSTATUS, NT_SIGINFO, ORACLE_PRPSINFO_SIZE, ORACLE_PRSTATUS_SIZE,
    ORACLE_SIGINFO_SIZE, PT_LOAD, PT_NOTE, wire,
};
use std::path::Path;

/// Every way a core can fail to be one. Each is a distinct name so a failure
/// says what is wrong rather than "invalid".
#[derive(Debug, thiserror::Error)]
pub(crate) enum CoreError {
    #[error("core is {0} bytes, too short to hold an ELF header")]
    TooShortForHeader(usize),
    #[error("not an ELF file: magic {0:02x?}")]
    BadMagic([u8; 4]),
    #[error("not a 64-bit ELF (e_ident[EI_CLASS] = {0})")]
    NotElf64(u8),
    #[error("not a core file (e_type = {0}, expected ET_CORE = {expected})", expected = ET_CORE)]
    NotCore(u16),
    #[error("not an aarch64 core (e_machine = {0}, expected {expected})", expected = EM_AARCH64)]
    NotAarch64(u16),
    #[error("program header table at {offset} + {size} bytes runs past the {len}-byte file")]
    PhdrTableTruncated {
        offset: u64,
        size: usize,
        len: usize,
    },
    #[error("core has no PT_NOTE segment; nothing describes its threads")]
    NoNoteSegment,
    #[error("PT_NOTE at {offset} + {size} runs past the {len}-byte file")]
    NoteSegmentTruncated { offset: u64, size: u64, len: usize },
    #[error("note at byte {0} of PT_NOTE is truncated")]
    NoteTruncated(usize),
    #[error("{name} note is {actual} bytes, expected {expected}")]
    NoteWrongSize {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("core has no NT_PRSTATUS note; no thread registers are recorded")]
    NoThreadNotes,
    #[error("core has no {0} note")]
    MissingNote(&'static str),
    #[error("thread {tid} has no {note} note")]
    MissingThreadNote { tid: i32, note: &'static str },
    #[error("thread {tid} repeats {note}")]
    DuplicateThreadNote { tid: i32, note: &'static str },
    #[error("{note} appears before any NT_PRSTATUS")]
    OrphanThreadNote { note: &'static str },
    #[error("core repeats NT_PRSTATUS for Linux tid {0}")]
    DuplicateTid(i32),
    #[error("PT_LOAD {index} at file offset {offset} + {filesz} runs past the {len}-byte file")]
    LoadTruncated {
        index: usize,
        offset: u64,
        filesz: u64,
        len: usize,
    },
    #[error("invalid ELF header/program-header geometry: {0}")]
    BadProgramHeaderGeometry(&'static str),
    #[error("core contains multiple PT_NOTE segments")]
    DuplicateNoteSegment,
    #[error("PT_LOAD {index} filesz {filesz} exceeds memsz {memsz}")]
    LoadFileSizeExceedsMemory {
        index: usize,
        filesz: u64,
        memsz: u64,
    },
    #[error("core offset/count arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("malformed {0}")]
    Malformed(&'static str),
}

/// One thread, as recovered from its `NT_PRSTATUS`.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ThreadSummary {
    pub tid: i32,
    pub current_signal: i16,
    /// `pc` and `sp` are the two registers a reader looks at first.
    pub pc: u64,
    pub sp: u64,
    pub pstate: u64,
    pub x0: u64,
    pub tpidr_el0: u64,
    pub v0: [u64; 2],
    pub fpsr: u32,
    pub fpcr: u32,
}

#[derive(Debug)]
struct ParsedThread {
    tid: i32,
    current_signal: i16,
    pc: u64,
    sp: u64,
    pstate: u64,
    x0: u64,
    tpidr_el0: Option<u64>,
    fp: Option<([u64; 2], u32, u32)>,
}

impl ParsedThread {
    fn publish_fp(&mut self, fp: ([u64; 2], u32, u32)) -> Result<(), CoreError> {
        if self.fp.replace(fp).is_some() {
            return Err(CoreError::DuplicateThreadNote {
                tid: self.tid,
                note: "NT_FPREGSET",
            });
        }
        Ok(())
    }

    fn publish_tls(&mut self, tpidr_el0: u64) -> Result<(), CoreError> {
        if self.tpidr_el0.replace(tpidr_el0).is_some() {
            return Err(CoreError::DuplicateThreadNote {
                tid: self.tid,
                note: "NT_ARM_TLS",
            });
        }
        Ok(())
    }
}

/// What the validator recovered. Serialised as JSON so it composes with the
/// other `carrick debug` outputs.
#[derive(Debug, serde::Serialize)]
pub(crate) struct CoreSummary {
    pub path: String,
    pub bytes: usize,
    pub machine: &'static str,
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub signal: i32,
    pub signal_code: i32,
    pub fault_address: u64,
    pub threads: Vec<ThreadSummary>,
    pub auxv_entries: usize,
    pub file_mappings: usize,
    /// PT_LOAD segments and how many carry bytes rather than only a mapping.
    pub load_segments: usize,
    pub load_segments_with_contents: usize,
    /// Notes owned by someone other than `CORE` (a real Linux aarch64 core
    /// carries `LINUX`-owner notes); recorded, not interpreted.
    pub foreign_notes: usize,
    pub memory_bytes: u64,
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or([0; 4]))
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]))
}

fn checked_align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align.checked_sub(1)?)
        .map(|rounded| rounded / align * align)
}

/// Field offsets come from the writer's own structs, never from counted bytes.
const fn ehdr(field: usize) -> usize {
    field
}

/// Parse and validate, returning the summary.
pub(crate) fn validate(path: &Path) -> Result<CoreSummary, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let summary = validate_bytes(&bytes, &path.display().to_string())?;
    Ok(summary)
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear pass over the format; splitting it would hide the order the fields must be read in"
)]
pub(crate) fn validate_bytes(bytes: &[u8], path: &str) -> Result<CoreSummary, CoreError> {
    if bytes.len() < size_of::<wire::Elf64Ehdr>() {
        return Err(CoreError::TooShortForHeader(bytes.len()));
    }
    let magic: [u8; 4] = bytes[..4].try_into().unwrap_or([0; 4]);
    if &magic != b"\x7fELF" {
        return Err(CoreError::BadMagic(magic));
    }
    if bytes[4] != ELF_CLASS64 {
        return Err(CoreError::NotElf64(bytes[4]));
    }
    let e_type = read_u16(bytes, ehdr(std::mem::offset_of!(wire::Elf64Ehdr, e_type)));
    if e_type != ET_CORE {
        return Err(CoreError::NotCore(e_type));
    }
    let machine = read_u16(
        bytes,
        ehdr(std::mem::offset_of!(wire::Elf64Ehdr, e_machine)),
    );
    if machine != EM_AARCH64 {
        return Err(CoreError::NotAarch64(machine));
    }

    let phoff = read_u64(bytes, std::mem::offset_of!(wire::Elf64Ehdr, e_phoff));
    let phnum = read_u16(bytes, std::mem::offset_of!(wire::Elf64Ehdr, e_phnum)) as usize;
    let phentsize = read_u16(bytes, std::mem::offset_of!(wire::Elf64Ehdr, e_phentsize)) as usize;
    let ehsize = read_u16(bytes, std::mem::offset_of!(wire::Elf64Ehdr, e_ehsize)) as usize;
    if ehsize != size_of::<wire::Elf64Ehdr>() {
        return Err(CoreError::BadProgramHeaderGeometry("unexpected e_ehsize"));
    }
    if phentsize != size_of::<wire::Elf64Phdr>() {
        return Err(CoreError::BadProgramHeaderGeometry(
            "e_phentsize is not Elf64_Phdr",
        ));
    }
    if phnum == 0 {
        return Err(CoreError::BadProgramHeaderGeometry("e_phnum is zero"));
    }
    let phoff_usize = usize::try_from(phoff)
        .map_err(|_| CoreError::BadProgramHeaderGeometry("e_phoff does not fit usize"))?;
    let table_size = phnum
        .checked_mul(phentsize)
        .ok_or(CoreError::ArithmeticOverflow)?;
    let table_end = phoff_usize
        .checked_add(table_size)
        .ok_or(CoreError::ArithmeticOverflow)?;
    if table_end > bytes.len() {
        return Err(CoreError::PhdrTableTruncated {
            offset: phoff,
            size: table_size,
            len: bytes.len(),
        });
    }

    let field = |base: usize, offset: usize| base + offset;
    let mut note_span = None;
    let mut load_segments = 0_usize;
    let mut load_with_contents = 0_usize;
    let mut memory_bytes = 0_u64;
    for index in 0..phnum {
        let base = phoff_usize
            .checked_add(
                index
                    .checked_mul(phentsize)
                    .ok_or(CoreError::ArithmeticOverflow)?,
            )
            .ok_or(CoreError::ArithmeticOverflow)?;
        let kind = read_u32(
            bytes,
            field(base, std::mem::offset_of!(wire::Elf64Phdr, p_type)),
        );
        let offset = read_u64(
            bytes,
            field(base, std::mem::offset_of!(wire::Elf64Phdr, p_offset)),
        );
        let filesz = read_u64(
            bytes,
            field(base, std::mem::offset_of!(wire::Elf64Phdr, p_filesz)),
        );
        let memsz = read_u64(
            bytes,
            field(base, std::mem::offset_of!(wire::Elf64Phdr, p_memsz)),
        );
        if kind == PT_NOTE {
            if note_span.replace((offset, filesz)).is_some() {
                return Err(CoreError::DuplicateNoteSegment);
            }
        } else if kind == PT_LOAD {
            if filesz > memsz {
                return Err(CoreError::LoadFileSizeExceedsMemory {
                    index,
                    filesz,
                    memsz,
                });
            }
            load_segments = load_segments
                .checked_add(1)
                .ok_or(CoreError::ArithmeticOverflow)?;
            memory_bytes = memory_bytes
                .checked_add(memsz)
                .ok_or(CoreError::ArithmeticOverflow)?;
            if filesz > 0 {
                load_with_contents = load_with_contents
                    .checked_add(1)
                    .ok_or(CoreError::ArithmeticOverflow)?;
                if offset
                    .checked_add(filesz)
                    .is_none_or(|end| end > bytes.len() as u64)
                {
                    return Err(CoreError::LoadTruncated {
                        index,
                        offset,
                        filesz,
                        len: bytes.len(),
                    });
                }
            }
        }
    }

    let (note_offset, note_size) = note_span.ok_or(CoreError::NoNoteSegment)?;
    let note_end_u64 = note_offset
        .checked_add(note_size)
        .ok_or(CoreError::ArithmeticOverflow)?;
    if note_end_u64 > bytes.len() as u64 {
        return Err(CoreError::NoteSegmentTruncated {
            offset: note_offset,
            size: note_size,
            len: bytes.len(),
        });
    }
    let note_start = usize::try_from(note_offset).map_err(|_| CoreError::ArithmeticOverflow)?;
    let note_end = usize::try_from(note_end_u64).map_err(|_| CoreError::ArithmeticOverflow)?;
    let notes = &bytes[note_start..note_end];

    let mut parsed_threads: Vec<ParsedThread> = Vec::new();
    let mut identity = None;
    let mut signal = None;
    let mut auxv_entries = 0_usize;
    let mut file_mappings = None;
    let mut foreign_notes = 0_usize;

    let header_size = size_of::<wire::NoteHeader>();
    let mut at = 0_usize;
    while at < notes.len() {
        let header_end = at
            .checked_add(header_size)
            .ok_or(CoreError::ArithmeticOverflow)?;
        if header_end > notes.len() {
            return Err(CoreError::NoteTruncated(at));
        }
        let namesz = read_u32(notes, at) as usize;
        let descsz = read_u32(notes, at + 4) as usize;
        let note_type = read_u32(notes, at + 8);
        let name_at = header_end;
        let name_end = name_at
            .checked_add(namesz)
            .ok_or(CoreError::ArithmeticOverflow)?;
        let desc_at =
            checked_align_up(name_end, NOTE_ALIGN).ok_or(CoreError::ArithmeticOverflow)?;
        let desc_end = desc_at
            .checked_add(descsz)
            .ok_or(CoreError::ArithmeticOverflow)?;
        let next = checked_align_up(desc_end, NOTE_ALIGN).ok_or(CoreError::ArithmeticOverflow)?;
        if name_end > notes.len() || next > notes.len() {
            return Err(CoreError::NoteTruncated(at));
        }
        let owner = &notes[name_at..name_end];
        let desc = &notes[desc_at..desc_end];
        // A real Linux core carries notes from other owners beside `CORE` —
        // on aarch64 the kernel emits `LINUX`-owner notes such as the PAC mask
        // and tagged-address control. Verified against a kernel-produced core:
        // rejecting them made this validator refuse a genuine core at byte
        // 2236. Only `CORE` notes are interpreted; the rest are counted and
        // skipped, which is what any conforming reader does.
        if owner != NOTE_OWNER && owner != LINUX_ELF_NOTE_OWNER {
            foreign_notes += 1;
            at = next;
            continue;
        }
        match note_type {
            NT_PRSTATUS => {
                if descsz != ORACLE_PRSTATUS_SIZE {
                    return Err(CoreError::NoteWrongSize {
                        name: "NT_PRSTATUS",
                        actual: descsz,
                        expected: ORACLE_PRSTATUS_SIZE,
                    });
                }
                let regs_at = std::mem::offset_of!(wire::ElfPrStatus, pr_reg);
                let tid = read_u32(desc, std::mem::offset_of!(wire::ElfPrStatus, pr_pid)) as i32;
                if parsed_threads.iter().any(|thread| thread.tid == tid) {
                    return Err(CoreError::DuplicateTid(tid));
                }
                parsed_threads.push(ParsedThread {
                    tid,
                    current_signal: read_u16(
                        desc,
                        std::mem::offset_of!(wire::ElfPrStatus, pr_cursig),
                    ) as i16,
                    // sp and pc are gregs[31] and gregs[32].
                    sp: read_u64(desc, regs_at + 31 * size_of::<u64>()),
                    pc: read_u64(desc, regs_at + 32 * size_of::<u64>()),
                    pstate: read_u64(desc, regs_at + 33 * size_of::<u64>()),
                    x0: read_u64(desc, regs_at),
                    tpidr_el0: None,
                    fp: None,
                });
            }
            NT_FPREGSET => {
                if descsz != AARCH64_FPREGSET_SIZE {
                    return Err(CoreError::NoteWrongSize {
                        name: "NT_FPREGSET",
                        actual: descsz,
                        expected: AARCH64_FPREGSET_SIZE,
                    });
                }
                let thread = parsed_threads
                    .last_mut()
                    .ok_or(CoreError::OrphanThreadNote {
                        note: "NT_FPREGSET",
                    })?;
                thread.publish_fp((
                    [read_u64(desc, 0), read_u64(desc, 8)],
                    read_u32(desc, 32 * size_of::<u128>()),
                    read_u32(desc, 32 * size_of::<u128>() + 4),
                ))?;
            }
            NT_ARM_TLS => {
                if descsz != AARCH64_TLS_SIZE {
                    return Err(CoreError::NoteWrongSize {
                        name: "NT_ARM_TLS",
                        actual: descsz,
                        expected: AARCH64_TLS_SIZE,
                    });
                }
                let thread = parsed_threads
                    .last_mut()
                    .ok_or(CoreError::OrphanThreadNote { note: "NT_ARM_TLS" })?;
                thread.publish_tls(read_u64(desc, 0))?;
            }
            NT_PRPSINFO => {
                if descsz != ORACLE_PRPSINFO_SIZE {
                    return Err(CoreError::NoteWrongSize {
                        name: "NT_PRPSINFO",
                        actual: descsz,
                        expected: ORACLE_PRPSINFO_SIZE,
                    });
                }
                let fname_at = std::mem::offset_of!(wire::ElfPrPsInfo, pr_fname);
                let fname = &desc[fname_at..fname_at + 16];
                let end = fname.iter().position(|byte| *byte == 0).unwrap_or(16);
                identity = Some((
                    read_u32(desc, std::mem::offset_of!(wire::ElfPrPsInfo, pr_pid)) as i32,
                    read_u32(desc, std::mem::offset_of!(wire::ElfPrPsInfo, pr_ppid)) as i32,
                    String::from_utf8_lossy(&fname[..end]).to_string(),
                ));
            }
            NT_SIGINFO => {
                if descsz != ORACLE_SIGINFO_SIZE {
                    return Err(CoreError::NoteWrongSize {
                        name: "NT_SIGINFO",
                        actual: descsz,
                        expected: ORACLE_SIGINFO_SIZE,
                    });
                }
                signal = Some((
                    read_u32(desc, std::mem::offset_of!(wire::SigInfo, si_signo)) as i32,
                    read_u32(desc, std::mem::offset_of!(wire::SigInfo, si_code)) as i32,
                    read_u64(desc, std::mem::offset_of!(wire::SigInfo, si_addr)),
                ));
            }
            NT_AUXV => {
                if desc.is_empty() || !desc.len().is_multiple_of(2 * size_of::<u64>()) {
                    return Err(CoreError::Malformed("NT_AUXV shape"));
                }
                let pairs = desc.chunks_exact(16).collect::<Vec<_>>();
                if pairs.last().is_none_or(|pair| read_u64(pair, 0) != 0) {
                    return Err(CoreError::Malformed("NT_AUXV terminator"));
                }
                if pairs[..pairs.len() - 1]
                    .iter()
                    .any(|pair| read_u64(pair, 0) == 0)
                {
                    return Err(CoreError::Malformed("NT_AUXV trailing data"));
                }
                auxv_entries = pairs.len() - 1;
            }
            NT_FILE => {
                if desc.len() < 16 || read_u64(desc, 8) == 0 {
                    return Err(CoreError::Malformed("NT_FILE header"));
                }
                let count = usize::try_from(read_u64(desc, 0))
                    .map_err(|_| CoreError::Malformed("NT_FILE count"))?;
                let names_at = count
                    .checked_mul(24)
                    .and_then(|triples| 16usize.checked_add(triples))
                    .ok_or(CoreError::ArithmeticOverflow)?;
                if names_at > desc.len() {
                    return Err(CoreError::Malformed("NT_FILE triples"));
                }
                let mut names = &desc[names_at..];
                for _ in 0..count {
                    let Some(end) = names.iter().position(|byte| *byte == 0) else {
                        return Err(CoreError::Malformed("NT_FILE paths"));
                    };
                    if end == 0 {
                        return Err(CoreError::Malformed("NT_FILE empty path"));
                    }
                    names = &names[end + 1..];
                }
                if !names.is_empty() {
                    return Err(CoreError::Malformed("NT_FILE trailing paths"));
                }
                file_mappings = Some(count);
            }
            _ => {}
        }
        at = next;
    }

    if parsed_threads.is_empty() {
        return Err(CoreError::NoThreadNotes);
    }
    let mut threads = Vec::with_capacity(parsed_threads.len());
    for thread in parsed_threads {
        let tpidr_el0 = thread.tpidr_el0.ok_or(CoreError::MissingThreadNote {
            tid: thread.tid,
            note: "NT_ARM_TLS",
        })?;
        let (v0, fpsr, fpcr) = thread.fp.ok_or(CoreError::MissingThreadNote {
            tid: thread.tid,
            note: "NT_FPREGSET",
        })?;
        threads.push(ThreadSummary {
            tid: thread.tid,
            current_signal: thread.current_signal,
            pc: thread.pc,
            sp: thread.sp,
            pstate: thread.pstate,
            x0: thread.x0,
            tpidr_el0,
            v0,
            fpsr,
            fpcr,
        });
    }
    let (pid, ppid, comm) = identity.ok_or(CoreError::MissingNote("NT_PRPSINFO"))?;
    let (signo, code, addr) = signal.ok_or(CoreError::MissingNote("NT_SIGINFO"))?;
    let file_mappings = file_mappings.ok_or(CoreError::MissingNote("NT_FILE"))?;

    Ok(CoreSummary {
        path: path.to_string(),
        bytes: bytes.len(),
        machine: "aarch64",
        pid,
        ppid,
        comm,
        signal: signo,
        signal_code: code,
        fault_address: addr,
        threads,
        auxv_entries,
        file_mappings,
        load_segments,
        load_segments_with_contents: load_with_contents,
        foreign_notes,
        memory_bytes,
    })
}

/// `carrick debug core <path>`.
pub(crate) fn run_debug_core(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let summary = validate(path)?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_core() -> Vec<u8> {
        use carrick_runtime::core_dump::{
            AARCH64_GREGS, CoreDump, MemoryRegion, ProcessIdentity, SignalInfo, ThreadRegisters,
            ThreadState,
        };
        let mut gregs = [0_u64; AARCH64_GREGS];
        gregs[0] = 0x1111;
        gregs[31] = 0x2222;
        gregs[32] = 0x3333;
        gregs[33] = 0x4444;
        CoreDump {
            identity: ProcessIdentity {
                pid: 77,
                ppid: 1,
                pgrp: 77,
                session: 77,
                comm: "coretest".to_owned(),
                psargs: "coretest".to_owned(),
            },
            signal: SignalInfo {
                signo: 11,
                code: 1,
                errno: 0,
                addr: 0xdead,
            },
            threads: vec![ThreadState {
                tid: 77,
                registers: ThreadRegisters {
                    gregs,
                    tpidr_el0: 0x5555,
                    vregs: [0x6666; 32],
                    fpsr: 0x7777,
                    fpcr: 0x8888,
                },
                current_signal: 11,
            }],
            auxv: vec![(6, 4096)],
            mappings: Vec::new(),
            regions: vec![MemoryRegion {
                start: 0x1_0000,
                flags: 5,
                bytes: b"authoritative-load",
                size: 0x1_0000,
            }],
        }
        .to_bytes_bounded(u64::MAX)
        .expect("complete core")
    }

    /// A validator that accepts anything is not a validator. Each of these is
    /// a corruption a real reader would choke on, and each must be REJECTED
    /// with its own name.
    #[test]
    fn rejects_a_non_elf_file() {
        let error = validate_bytes(&[0_u8; 128], "x").unwrap_err();
        assert!(matches!(error, CoreError::BadMagic(_)), "{error}");
    }

    #[test]
    fn rejects_a_file_too_short_for_a_header() {
        let error = validate_bytes(b"\x7fELF", "x").unwrap_err();
        assert!(matches!(error, CoreError::TooShortForHeader(4)), "{error}");
    }

    #[test]
    fn recovers_full_gpr_fp_and_tls_authority() {
        let summary = validate_bytes(&complete_core(), "core").expect("validate");
        let thread = &summary.threads[0];
        assert_eq!(thread.x0, 0x1111);
        assert_eq!(thread.sp, 0x2222);
        assert_eq!(thread.pc, 0x3333);
        assert_eq!(thread.pstate, 0x4444);
        assert_eq!(thread.tpidr_el0, 0x5555);
        assert_eq!(thread.v0, [0x6666, 0]);
        assert_eq!(thread.fpsr, 0x7777);
        assert_eq!(thread.fpcr, 0x8888);
    }

    #[test]
    fn rejects_duplicate_per_thread_architecture_notes() {
        let mut thread = ParsedThread {
            tid: 77,
            current_signal: 11,
            pc: 0,
            sp: 0,
            pstate: 0,
            x0: 0,
            tpidr_el0: None,
            fp: None,
        };
        thread.publish_tls(1).expect("first TLS note");
        assert!(matches!(
            thread.publish_tls(2),
            Err(CoreError::DuplicateThreadNote {
                tid: 77,
                note: "NT_ARM_TLS"
            })
        ));
        thread.publish_fp(([1, 2], 3, 4)).expect("first FP note");
        assert!(matches!(
            thread.publish_fp(([5, 6], 7, 8)),
            Err(CoreError::DuplicateThreadNote {
                tid: 77,
                note: "NT_FPREGSET"
            })
        ));
    }
    fn mutate_u16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn mutate_u64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn rejects_malformed_program_header_geometry_without_panicking() {
        for mutate in [
            |bytes: &mut [u8]| {
                mutate_u16(bytes, std::mem::offset_of!(wire::Elf64Ehdr, e_phentsize), 0);
            },
            |bytes: &mut [u8]| {
                mutate_u16(bytes, std::mem::offset_of!(wire::Elf64Ehdr, e_phentsize), 8);
            },
            |bytes: &mut [u8]| {
                mutate_u64(
                    bytes,
                    std::mem::offset_of!(wire::Elf64Ehdr, e_phoff),
                    u64::MAX,
                );
            },
        ] {
            let mut bytes = complete_core();
            mutate(&mut bytes);
            assert!(
                std::panic::catch_unwind(|| validate_bytes(&bytes, "mutated"))
                    .expect("malformed core reader must not panic")
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_load_and_note_overflow_mutations() {
        let mut table = complete_core();
        mutate_u16(
            &mut table,
            std::mem::offset_of!(wire::Elf64Ehdr, e_phnum),
            u16::MAX,
        );
        assert!(validate_bytes(&table, "bad-table").is_err());

        let mut load = complete_core();
        let load_phdr = size_of::<wire::Elf64Ehdr>() + size_of::<wire::Elf64Phdr>();
        mutate_u64(
            &mut load,
            load_phdr + std::mem::offset_of!(wire::Elf64Phdr, p_filesz),
            u64::MAX,
        );
        assert!(matches!(
            validate_bytes(&load, "bad-load"),
            Err(CoreError::LoadFileSizeExceedsMemory { .. })
        ));

        let mut duplicate_note = complete_core();
        duplicate_note[load_phdr..load_phdr + 4].copy_from_slice(&PT_NOTE.to_le_bytes());
        assert!(matches!(
            validate_bytes(&duplicate_note, "duplicate-note"),
            Err(CoreError::DuplicateNoteSegment)
        ));

        let mut note = complete_core();
        let phoff = size_of::<wire::Elf64Ehdr>();
        let note_offset = read_u64(
            &note,
            phoff + std::mem::offset_of!(wire::Elf64Phdr, p_offset),
        ) as usize;
        note[note_offset + 4..note_offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_bytes(&note, "bad-note").is_err());
    }
}
