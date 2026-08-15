//! Linux ELF core files, written by carrick's kernel rather than by Darwin.
//!
//! A crash dump is process semantics: which threads existed, what their
//! registers held, which signal killed the process, what its address space and
//! file mappings were. Under HVPatch every Linux process is a thread of ONE
//! host process, so a Mach core of that host process describes all of them at
//! once and none of them correctly — the same structural reason `times`/
//! `getrusage` could not be sourced from `proc_pid_rusage`. carrick therefore
//! writes the Linux format itself, from its own kernel objects.
//!
//! # Where the ABI came from
//!
//! Clean-room, from the differential oracle: a real `aarch64` Linux core was
//! produced under native arm64 Docker and its structure read back with
//! `readelf -h/-l/-n`. That run is the authority for every size and ordering
//! decision below, and re-running it is how a suspected layout bug is settled:
//!
//! ```text
//! Elf file type is CORE, 20 program headers, starting at offset 64
//!   NOTE  offset 0x4a0  filesz 0xc04  align 0x4
//!   LOAD  ... R E / R / RW, align 0x1000
//! Notes, owner "CORE", in this order:
//!   NT_PRSTATUS 0x188 (392)   NT_PRPSINFO 0x88 (136)
//!   NT_SIGINFO  0x80  (128)   NT_AUXV     0x150
//!   NT_FILE     0x251        (count, page_size, triples, then names)
//! ```
//!
//! No Linux kernel source was consulted, per the project's clean-room rule.

pub use carrick_abi::LINUX_ELF_NOTE_OWNER;

/// ELF note types. `NT_SIGINFO`/`NT_FILE` spell their own names in ASCII.
pub const NT_PRSTATUS: u32 = 1;
pub const NT_FPREGSET: u32 = 2;
pub const NT_PRPSINFO: u32 = 3;
pub const NT_AUXV: u32 = 6;
/// AArch64 TLS register note (`TPIDR_EL0`).
pub const NT_ARM_TLS: u32 = 0x401;
pub const NT_SIGINFO: u32 = 0x5349_4749;
pub const NT_FILE: u32 = 0x4649_4c45;

/// Standard process/thread notes use `CORE`; AArch64 TLS uses Linux's
/// architecture-note `LINUX` owner.
pub const NOTE_OWNER: &[u8] = b"CORE\0";

/// `readelf` reported `align 0x4` on the oracle's PT_NOTE: note fields are
/// 4-byte aligned even in a 64-bit core.
pub const NOTE_ALIGN: usize = 4;

pub const ELF_CLASS64: u8 = 2;
pub const ELF_DATA_LSB: u8 = 1;
pub const ELF_VERSION_CURRENT: u8 = 1;
pub const ET_CORE: u16 = 4;
pub const EM_AARCH64: u16 = 183;
pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// Note payload sizes the oracle core reported (`readelf -n`). They are the
/// ABI authority the `wire` structs are checked against at compile time.
pub const ORACLE_PRSTATUS_SIZE: usize = 0x188;
pub const ORACLE_PRPSINFO_SIZE: usize = 0x88;
pub const ORACLE_SIGINFO_SIZE: usize = 0x80;
/// `user_fpsimd_state`: V0-V31, FPSR, FPCR.
pub const AARCH64_FPREGSET_SIZE: usize = 0x210;
pub const AARCH64_TLS_SIZE: usize = 0x10;

const EHDR_SIZE: u16 = 64;
const PHDR_SIZE: u16 = 56;

/// Guest page size recorded in `NT_FILE`. The oracle reported 4096; carrick's
/// guests are 4 KiB-paged Linux regardless of the host's 16 KiB pages, and this
/// field describes the GUEST's mapping granularity.
const NT_FILE_PAGE_SIZE: u64 = GUEST_PAGE as u64;

/// Guest page granularity: carrick's guests are 4 KiB-paged Linux regardless
/// of the host's 16 KiB pages, and both `PT_LOAD` alignment and `NT_FILE`'s
/// page size describe the GUEST.
pub const GUEST_PAGE: usize = 4096;

/// `elf_gregset_t` on aarch64: x0-x30, sp, pc, pstate.
pub const AARCH64_GREGS: usize = 34;

/// One thread's register file, in the order `NT_PRSTATUS` stores it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadRegisters {
    /// `x0`-`x30`, then `sp`, `pc`, `pstate`.
    pub gregs: [u64; AARCH64_GREGS],
    /// `TPIDR_EL0`, emitted as `NT_ARM_TLS`.
    pub tpidr_el0: u64,
    /// V0-V31 in architectural order, emitted as `NT_FPREGSET`.
    pub vregs: [u128; 32],
    pub fpsr: u32,
    pub fpcr: u32,
}

impl Default for ThreadRegisters {
    fn default() -> Self {
        Self {
            gregs: [0; AARCH64_GREGS],
            tpidr_el0: 0,
            vregs: [0; 32],
            fpsr: 0,
            fpcr: 0,
        }
    }
}

/// Per-thread note contents. Linux writes one `NT_PRSTATUS` per thread, the
/// crashing thread first, so a reader attributes the fault to the right one.
#[derive(Clone, Copy, Debug)]
pub struct ThreadState {
    pub tid: i32,
    pub registers: ThreadRegisters,
    /// The signal being delivered to this thread, or 0.
    pub current_signal: i32,
}

/// Process identity for `NT_PRPSINFO`, plus the signal identity every core
/// needs to be interpretable.
#[derive(Clone, Debug)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    /// Short command name (`pr_fname`, 16 bytes including NUL).
    pub comm: String,
    /// Argument-list prefix (`pr_psargs`, 80 bytes including NUL).
    pub psargs: String,
}

/// The `siginfo_t` fields a core needs, for `NT_SIGINFO`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SignalInfo {
    pub signo: i32,
    pub code: i32,
    pub errno: i32,
    /// Faulting address for SIGSEGV/SIGBUS (`si_addr`).
    pub addr: u64,
}

/// One `PT_LOAD` region: guest memory to be written into the core.
pub struct MemoryRegion<'a> {
    pub start: u64,
    /// Permissions as `PF_*`.
    pub flags: u32,
    /// Contents. An empty slice records the mapping with `p_filesz = 0` —
    /// which is exactly what Linux does for a region it does not dump (the
    /// oracle's first `LOAD` had `filesz 0`, `memsz 0x20000`).
    pub bytes: &'a [u8],
    /// Size of the mapping in the address space, which may exceed `bytes`.
    pub size: u64,
}

/// One `NT_FILE` entry: a file-backed mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMapping {
    pub start: u64,
    pub end: u64,
    /// Offset within the file, in PAGES (the oracle's third column).
    pub file_page_offset: u64,
    pub path: String,
}

/// Everything needed to write one core file.
pub struct CoreDump<'a> {
    pub identity: ProcessIdentity,
    pub signal: SignalInfo,
    /// Crashing thread FIRST.
    pub threads: Vec<ThreadState>,
    pub auxv: Vec<(u64, u64)>,
    pub mappings: Vec<FileMapping>,
    pub regions: Vec<MemoryRegion<'a>>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CoreDumpError {
    #[error("core snapshot has no threads")]
    NoThreads,
    #[error("core snapshot repeats Linux tid {0}")]
    DuplicateTid(i32),
    #[error("crashing thread is not first (signal {signal})")]
    CrashingThreadNotFirst { signal: i32 },
    #[error("core memory region at {start:#x} has {bytes} bytes for a {size}-byte mapping")]
    RegionContentsTooLarge { start: u64, bytes: usize, size: u64 },
    #[error("core memory regions overlap at {start:#x} (previous end {previous_end:#x})")]
    OverlappingRegions { previous_end: u64, start: u64 },
    #[error("core requires {required} bytes, exceeding RLIMIT_CORE {limit}")]
    LimitExceeded { limit: u64, required: u64 },
    #[error("core has {count} program headers, exceeding ELF64 e_phnum")]
    ProgramHeaderCountOverflow { count: usize },
    #[error("core ELF layout arithmetic overflowed")]
    LayoutOverflow,
    #[error("serialized core failed structural validation: {0}")]
    InvalidSerialized(String),
}

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn checked_align_up(value: usize, align: usize) -> Option<usize> {
    value
        .checked_add(align.checked_sub(1)?)
        .map(|rounded| rounded / align * align)
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Re-read the emitted artifact rather than trusting the in-memory builder.
/// This is the final authority before publication: every table, segment and
/// note must be contained in the actual byte vector and counts must match the
/// snapshot that requested serialization.
fn validate_serialized_core(
    bytes: &[u8],
    expected_loads: usize,
    expected_notes: usize,
) -> Result<(), CoreDumpError> {
    let invalid = |message: &str| CoreDumpError::InvalidSerialized(message.to_owned());
    if bytes.len() < usize::from(EHDR_SIZE) || bytes.get(..4) != Some(b"\x7fELF") {
        return Err(invalid("truncated or invalid ELF header"));
    }
    if bytes[4] != ELF_CLASS64
        || bytes[5] != ELF_DATA_LSB
        || bytes[6] != ELF_VERSION_CURRENT
        || read_u16(bytes, 16) != Some(ET_CORE)
        || read_u16(bytes, 18) != Some(EM_AARCH64)
        || read_u32(bytes, 20) != Some(u32::from(ELF_VERSION_CURRENT))
    {
        return Err(invalid(
            "ELF identity/type/machine is not Linux AArch64 core",
        ));
    }
    let phoff = usize::try_from(read_u64(bytes, 32).ok_or_else(|| invalid("missing e_phoff"))?)
        .map_err(|_| invalid("e_phoff does not fit host usize"))?;
    let ehsize = read_u16(bytes, 52).ok_or_else(|| invalid("missing e_ehsize"))?;
    let phentsize = read_u16(bytes, 54).ok_or_else(|| invalid("missing e_phentsize"))?;
    let phnum = usize::from(read_u16(bytes, 56).ok_or_else(|| invalid("missing e_phnum"))?);
    if ehsize != EHDR_SIZE || phentsize != PHDR_SIZE || phoff != usize::from(EHDR_SIZE) {
        return Err(invalid("non-canonical ELF/program-header geometry"));
    }
    let expected_phnum = expected_loads
        .checked_add(1)
        .ok_or(CoreDumpError::LayoutOverflow)?;
    if phnum != expected_phnum {
        return Err(invalid("program-header count differs from snapshot"));
    }
    let table_bytes = phnum
        .checked_mul(usize::from(phentsize))
        .ok_or(CoreDumpError::LayoutOverflow)?;
    let table_end = phoff
        .checked_add(table_bytes)
        .ok_or(CoreDumpError::LayoutOverflow)?;
    if table_end > bytes.len() {
        return Err(invalid("program-header table extends beyond artifact"));
    }

    let mut note_range = None;
    let mut load_count = 0usize;
    let mut load_vmas = Vec::with_capacity(expected_loads);
    for index in 0..phnum {
        let at = phoff
            .checked_add(
                index
                    .checked_mul(usize::from(phentsize))
                    .ok_or(CoreDumpError::LayoutOverflow)?,
            )
            .ok_or(CoreDumpError::LayoutOverflow)?;
        let kind = read_u32(bytes, at).ok_or_else(|| invalid("truncated program header"))?;
        let offset = usize::try_from(
            read_u64(bytes, at + 8).ok_or_else(|| invalid("missing segment offset"))?,
        )
        .map_err(|_| invalid("segment offset does not fit host usize"))?;
        let filesz = usize::try_from(
            read_u64(bytes, at + 32).ok_or_else(|| invalid("missing segment filesz"))?,
        )
        .map_err(|_| invalid("segment filesz does not fit host usize"))?;
        let memsz = read_u64(bytes, at + 40).ok_or_else(|| invalid("missing segment memsz"))?;
        let end = offset
            .checked_add(filesz)
            .ok_or(CoreDumpError::LayoutOverflow)?;
        if end > bytes.len() {
            return Err(invalid("segment extends beyond artifact"));
        }
        match kind {
            PT_NOTE => {
                if note_range.replace((offset, end)).is_some() {
                    return Err(invalid("multiple PT_NOTE segments"));
                }
            }
            PT_LOAD => {
                load_count = load_count
                    .checked_add(1)
                    .ok_or(CoreDumpError::LayoutOverflow)?;
                if u64::try_from(filesz).map_or(true, |size| size > memsz) {
                    return Err(invalid("PT_LOAD filesz exceeds memsz"));
                }
                let vaddr = read_u64(bytes, at + 16)
                    .ok_or_else(|| invalid("missing PT_LOAD virtual address"))?;
                let vma_end = vaddr
                    .checked_add(memsz)
                    .ok_or_else(|| invalid("PT_LOAD virtual range overflow"))?;
                if memsz != 0 {
                    load_vmas.push((vaddr, vma_end));
                }
            }
            _ => return Err(invalid("unexpected program-header type")),
        }
    }
    if load_count != expected_loads {
        return Err(invalid("PT_LOAD count differs from snapshot"));
    }
    load_vmas.sort_unstable();
    if load_vmas.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid("overlapping PT_LOAD virtual ranges"));
    }
    let (mut cursor, note_end) = note_range.ok_or_else(|| invalid("missing PT_NOTE"))?;
    let mut note_count = 0usize;
    while cursor < note_end {
        let header_end = cursor
            .checked_add(12)
            .ok_or(CoreDumpError::LayoutOverflow)?;
        if header_end > note_end {
            return Err(invalid("truncated note header"));
        }
        let namesz = usize::try_from(read_u32(bytes, cursor).ok_or_else(|| invalid("namesz"))?)
            .map_err(|_| invalid("namesz does not fit usize"))?;
        let descsz = usize::try_from(read_u32(bytes, cursor + 4).ok_or_else(|| invalid("descsz"))?)
            .map_err(|_| invalid("descsz does not fit usize"))?;
        let name_end = header_end
            .checked_add(namesz)
            .ok_or(CoreDumpError::LayoutOverflow)?;
        let desc_start =
            checked_align_up(name_end, NOTE_ALIGN).ok_or(CoreDumpError::LayoutOverflow)?;
        let desc_end = desc_start
            .checked_add(descsz)
            .ok_or(CoreDumpError::LayoutOverflow)?;
        cursor = checked_align_up(desc_end, NOTE_ALIGN).ok_or(CoreDumpError::LayoutOverflow)?;
        if cursor > note_end {
            return Err(invalid("note name or descriptor exceeds PT_NOTE"));
        }
        note_count = note_count
            .checked_add(1)
            .ok_or(CoreDumpError::LayoutOverflow)?;
    }
    if cursor != note_end || (expected_notes != 0 && note_count != expected_notes) {
        return Err(invalid(
            "note count or terminal bound differs from snapshot",
        ));
    }
    Ok(())
}

/// Append one ELF note: `namesz`, `descsz`, `type`, padded name, padded desc.
fn push_note(out: &mut Vec<u8>, note_type: u32, desc: &[u8]) {
    push_note_owned(out, NOTE_OWNER, note_type, desc);
}

fn push_note_owned(out: &mut Vec<u8>, owner: &[u8], note_type: u32, desc: &[u8]) {
    let header = wire::NoteHeader {
        n_namesz: owner.len() as u32,
        n_descsz: desc.len() as u32,
        n_type: note_type,
    };
    out.extend_from_slice(as_bytes(&header));
    out.extend_from_slice(owner);
    out.resize(align_up(out.len(), NOTE_ALIGN), 0);
    out.extend_from_slice(desc);
    out.resize(align_up(out.len(), NOTE_ALIGN), 0);
}

fn fpregset_note(registers: &ThreadRegisters) -> [u8; AARCH64_FPREGSET_SIZE] {
    let mut note = [0_u8; AARCH64_FPREGSET_SIZE];
    for (index, register) in registers.vregs.iter().enumerate() {
        let at = index * size_of::<u128>();
        note[at..at + size_of::<u128>()].copy_from_slice(&register.to_le_bytes());
    }
    let fpsr = 32 * size_of::<u128>();
    note[fpsr..fpsr + 4].copy_from_slice(&registers.fpsr.to_le_bytes());
    note[fpsr + 4..fpsr + 8].copy_from_slice(&registers.fpcr.to_le_bytes());
    note
}

fn push_thread_arch_notes(out: &mut Vec<u8>, thread: &ThreadState) {
    push_note(out, NT_FPREGSET, &fpregset_note(&thread.registers));
    let mut tls = [0_u8; AARCH64_TLS_SIZE];
    tls[..8].copy_from_slice(&thread.registers.tpidr_el0.to_le_bytes());
    // The second word is TPIDR2_EL0. Carrick does not expose SME today, so the
    // architecturally absent register is zero rather than synthesized state.
    push_note_owned(out, LINUX_ELF_NOTE_OWNER, NT_ARM_TLS, &tls);
}

/// Wire structs for the note payloads.
///
/// Every field is explicit, including padding, so the type has NO implicit
/// padding and its byte image is fully initialised — which is what makes
/// [`as_bytes`] sound and lets `size_of` be the authority on layout instead of
/// a hand-counted offset.
pub mod wire {
    /// `struct elf_siginfo` — the three-int summary embedded in prstatus.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ElfSiginfo {
        pub si_signo: i32,
        pub si_code: i32,
        pub si_errno: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Timeval {
        pub tv_sec: i64,
        pub tv_usec: i64,
    }

    /// `struct elf_prstatus`. `pr_pid` carries the THREAD id — that is how a
    /// reader tells threads apart — while the rest describe the process.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ElfPrStatus {
        pub pr_info: ElfSiginfo,
        pub pr_cursig: i16,
        pub _pad0: u16,
        pub pr_sigpend: u64,
        pub pr_sighold: u64,
        pub pr_pid: i32,
        pub pr_ppid: i32,
        pub pr_pgrp: i32,
        pub pr_sid: i32,
        /// Left zero: per-thread CPU is not split finely enough to fill these
        /// honestly, and a fabricated duration is worse than an absent one.
        pub pr_utime: Timeval,
        pub pr_stime: Timeval,
        pub pr_cutime: Timeval,
        pub pr_cstime: Timeval,
        pub pr_reg: [u64; super::AARCH64_GREGS],
        pub pr_fpvalid: i32,
        pub _pad1: u32,
    }

    /// `struct elf_prpsinfo` — process identity.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ElfPrPsInfo {
        pub pr_state: u8,
        pub pr_sname: u8,
        pub pr_zomb: u8,
        pub pr_nice: i8,
        pub _pad0: u32,
        pub pr_flag: u64,
        pub pr_uid: u32,
        pub pr_gid: u32,
        pub pr_pid: i32,
        pub pr_ppid: i32,
        pub pr_pgrp: i32,
        pub pr_sid: i32,
        pub pr_fname: [u8; super::PR_FNAME_LEN],
        pub pr_psargs: [u8; super::PR_PSARGS_LEN],
    }

    /// `siginfo_t` as a core records it: the common header plus the
    /// SIGSEGV/SIGBUS arm of the union, which leads with `si_addr`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct SigInfo {
        pub si_signo: i32,
        pub si_errno: i32,
        pub si_code: i32,
        pub _pad0: u32,
        pub si_addr: u64,
        pub _union_tail: [u8; super::SIGINFO_UNION_TAIL],
    }

    /// The ELF file header.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Elf64Ehdr {
        pub e_ident: [u8; 16],
        pub e_type: u16,
        pub e_machine: u16,
        pub e_version: u32,
        pub e_entry: u64,
        pub e_phoff: u64,
        pub e_shoff: u64,
        pub e_flags: u32,
        pub e_ehsize: u16,
        pub e_phentsize: u16,
        pub e_phnum: u16,
        pub e_shentsize: u16,
        pub e_shnum: u16,
        pub e_shstrndx: u16,
    }

    /// One program header.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Elf64Phdr {
        pub p_type: u32,
        pub p_flags: u32,
        pub p_offset: u64,
        pub p_vaddr: u64,
        pub p_paddr: u64,
        pub p_filesz: u64,
        pub p_memsz: u64,
        pub p_align: u64,
    }

    /// The fixed head of an ELF note, before the padded name and descriptor.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct NoteHeader {
        pub n_namesz: u32,
        pub n_descsz: u32,
        pub n_type: u32,
    }
}

/// `pr_fname` width, including its NUL.
const PR_FNAME_LEN: usize = 16;
/// `pr_psargs` width, including its NUL.
const PR_PSARGS_LEN: usize = 80;
/// Bytes of `siginfo_t` after `si_addr`.
const SIGINFO_UNION_TAIL: usize = ORACLE_SIGINFO_SIZE - 24;

// The oracle's reported note payload sizes are the ABI authority (see the
// module docs). Checking the STRUCTS against them at compile time is what
// turns a layout mistake into a build failure instead of an unreadable core.
const _: () = assert!(size_of::<wire::ElfPrStatus>() == ORACLE_PRSTATUS_SIZE);
const _: () = assert!(size_of::<wire::ElfPrPsInfo>() == ORACLE_PRPSINFO_SIZE);
const _: () = assert!(size_of::<wire::SigInfo>() == ORACLE_SIGINFO_SIZE);
const _: () = assert!(size_of::<wire::Elf64Ehdr>() == EHDR_SIZE as usize);
const _: () = assert!(size_of::<wire::Elf64Phdr>() == PHDR_SIZE as usize);

/// Byte image of a wire struct.
///
/// SAFETY-relevant by construction: every `wire` type is `#[repr(C)]` with
/// explicit padding fields, so it contains no uninitialised padding and its
/// whole size is readable as bytes.
fn as_bytes<T: Copy>(value: &T) -> &[u8] {
    // SAFETY: `T` is a `repr(C)` POD from `wire` with no implicit padding, and
    // the slice borrows `value` for its own lifetime.
    unsafe { std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>()) }
}

/// Copy a `&str` into a fixed-width NUL-terminated field.
fn fixed_field<const N: usize>(value: &str) -> [u8; N] {
    let mut field = [0_u8; N];
    let bytes = value.as_bytes();
    let keep = bytes.len().min(N - 1);
    field[..keep].copy_from_slice(&bytes[..keep]);
    field
}

fn prstatus_note(dump: &CoreDump<'_>, thread: &ThreadState) -> wire::ElfPrStatus {
    wire::ElfPrStatus {
        pr_info: wire::ElfSiginfo {
            si_signo: dump.signal.signo,
            si_code: dump.signal.code,
            si_errno: dump.signal.errno,
        },
        pr_cursig: thread.current_signal as i16,
        _pad0: 0,
        pr_sigpend: 0,
        pr_sighold: 0,
        pr_pid: thread.tid,
        pr_ppid: dump.identity.ppid,
        pr_pgrp: dump.identity.pgrp,
        pr_sid: dump.identity.session,
        pr_utime: wire::Timeval::default(),
        pr_stime: wire::Timeval::default(),
        pr_cutime: wire::Timeval::default(),
        pr_cstime: wire::Timeval::default(),
        pr_reg: thread.registers.gregs,
        pr_fpvalid: 1,
        _pad1: 0,
    }
}

fn prpsinfo_note(identity: &ProcessIdentity) -> wire::ElfPrPsInfo {
    wire::ElfPrPsInfo {
        pr_state: 0,
        pr_sname: b'R',
        pr_zomb: 0,
        pr_nice: 0,
        _pad0: 0,
        pr_flag: 0,
        pr_uid: 0,
        pr_gid: 0,
        pr_pid: identity.pid,
        pr_ppid: identity.ppid,
        pr_pgrp: identity.pgrp,
        pr_sid: identity.session,
        pr_fname: fixed_field(&identity.comm),
        pr_psargs: fixed_field(&identity.psargs),
    }
}

fn siginfo_note(signal: &SignalInfo) -> wire::SigInfo {
    wire::SigInfo {
        si_signo: signal.signo,
        si_errno: signal.errno,
        si_code: signal.code,
        _pad0: 0,
        si_addr: signal.addr,
        _union_tail: [0; SIGINFO_UNION_TAIL],
    }
}

fn auxv_note(auxv: &[(u64, u64)]) -> Vec<u8> {
    let mut note = Vec::with_capacity((auxv.len() + 1) * 16);
    for (key, value) in auxv {
        note.extend_from_slice(&key.to_le_bytes());
        note.extend_from_slice(&value.to_le_bytes());
    }
    // AT_NULL terminator.
    note.extend_from_slice(&0_u64.to_le_bytes());
    note.extend_from_slice(&0_u64.to_le_bytes());
    note
}

/// `NT_FILE`: count, page size, then one (start, end, file page offset) triple
/// per mapping, then the NUL-terminated paths in the same order.
fn file_note(mappings: &[FileMapping]) -> Vec<u8> {
    let mut note = Vec::new();
    note.extend_from_slice(&(mappings.len() as u64).to_le_bytes());
    note.extend_from_slice(&NT_FILE_PAGE_SIZE.to_le_bytes());
    for mapping in mappings {
        note.extend_from_slice(&mapping.start.to_le_bytes());
        note.extend_from_slice(&mapping.end.to_le_bytes());
        note.extend_from_slice(&mapping.file_page_offset.to_le_bytes());
    }
    for mapping in mappings {
        note.extend_from_slice(mapping.path.as_bytes());
        note.push(0);
    }
    note
}

impl CoreDump<'_> {
    fn validate(&self) -> Result<(), CoreDumpError> {
        let Some(crashing) = self.threads.first() else {
            return Err(CoreDumpError::NoThreads);
        };
        if crashing.current_signal != self.signal.signo {
            return Err(CoreDumpError::CrashingThreadNotFirst {
                signal: self.signal.signo,
            });
        }
        let mut tids = std::collections::BTreeSet::new();
        for thread in &self.threads {
            if !tids.insert(thread.tid) {
                return Err(CoreDumpError::DuplicateTid(thread.tid));
            }
        }
        let mut region_vmas = Vec::with_capacity(self.regions.len());
        for region in &self.regions {
            if region.bytes.len() as u64 > region.size {
                return Err(CoreDumpError::RegionContentsTooLarge {
                    start: region.start,
                    bytes: region.bytes.len(),
                    size: region.size,
                });
            }
            let end = region
                .start
                .checked_add(region.size)
                .ok_or(CoreDumpError::LayoutOverflow)?;
            if region.size != 0 {
                region_vmas.push((region.start, end));
            }
        }
        region_vmas.sort_unstable();
        for pair in region_vmas.windows(2) {
            if pair[0].1 > pair[1].0 {
                return Err(CoreDumpError::OverlappingRegions {
                    previous_end: pair[0].1,
                    start: pair[1].0,
                });
            }
        }
        Ok(())
    }

    /// Validate and serialise without ever publishing a prefix. `limit` is
    /// the caller's effective Linux `RLIMIT_CORE`; equality is permitted.
    pub fn to_bytes_bounded(&self, limit: u64) -> Result<Vec<u8>, CoreDumpError> {
        self.validate()?;
        let bytes = self.try_to_bytes()?;
        let required = u64::try_from(bytes.len()).map_err(|_| CoreDumpError::LayoutOverflow)?;
        if required > limit {
            return Err(CoreDumpError::LimitExceeded { limit, required });
        }
        Ok(bytes)
    }

    #[cfg(test)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.validate()
            .and_then(|_| self.try_to_bytes())
            .expect("test core must serialize")
    }

    /// Serialise the whole core file.
    ///
    /// Layout follows the oracle: ELF header, then the program header table,
    /// then `PT_NOTE`'s contents, then each `PT_LOAD`'s bytes page-aligned.
    fn try_to_bytes(&self) -> Result<Vec<u8>, CoreDumpError> {
        let mut notes = Vec::new();
        // Match Linux's note order exactly: the crashing thread's PRSTATUS,
        // process-wide notes, its optional register sets, then each sibling's
        // PRSTATUS and register sets.
        if let Some(thread) = self.threads.first() {
            push_note(
                &mut notes,
                NT_PRSTATUS,
                as_bytes(&prstatus_note(self, thread)),
            );
        }
        push_note(
            &mut notes,
            NT_PRPSINFO,
            as_bytes(&prpsinfo_note(&self.identity)),
        );
        push_note(
            &mut notes,
            NT_SIGINFO,
            as_bytes(&siginfo_note(&self.signal)),
        );
        push_note(&mut notes, NT_AUXV, &auxv_note(&self.auxv));
        push_note(&mut notes, NT_FILE, &file_note(&self.mappings));
        if let Some(thread) = self.threads.first() {
            push_thread_arch_notes(&mut notes, thread);
        }
        for thread in self.threads.iter().skip(1) {
            push_note(
                &mut notes,
                NT_PRSTATUS,
                as_bytes(&prstatus_note(self, thread)),
            );
            push_thread_arch_notes(&mut notes, thread);
        }

        let phnum = self
            .regions
            .len()
            .checked_add(1)
            .ok_or(CoreDumpError::LayoutOverflow)?;
        let phnum_u16 = u16::try_from(phnum)
            .map_err(|_| CoreDumpError::ProgramHeaderCountOverflow { count: phnum })?;
        let phoff = usize::from(EHDR_SIZE);
        let notes_offset = phnum
            .checked_mul(usize::from(PHDR_SIZE))
            .and_then(|table| phoff.checked_add(table))
            .ok_or(CoreDumpError::LayoutOverflow)?;
        let notes_end = notes_offset
            .checked_add(notes.len())
            .ok_or(CoreDumpError::LayoutOverflow)?;
        let mut data_offset =
            checked_align_up(notes_end, GUEST_PAGE).ok_or(CoreDumpError::LayoutOverflow)?;

        let mut ident = [0_u8; 16];
        ident[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        ident[4] = ELF_CLASS64;
        ident[5] = ELF_DATA_LSB;
        ident[6] = ELF_VERSION_CURRENT;
        let header = wire::Elf64Ehdr {
            e_ident: ident,
            e_type: ET_CORE,
            e_machine: EM_AARCH64,
            e_version: 1,
            e_phoff: u64::try_from(phoff).map_err(|_| CoreDumpError::LayoutOverflow)?,
            e_ehsize: EHDR_SIZE,
            e_phentsize: PHDR_SIZE,
            e_phnum: phnum_u16,
            ..wire::Elf64Ehdr::default()
        };
        let mut out = Vec::new();
        out.extend_from_slice(as_bytes(&header));

        out.extend_from_slice(as_bytes(&wire::Elf64Phdr {
            p_type: PT_NOTE,
            p_offset: u64::try_from(notes_offset).map_err(|_| CoreDumpError::LayoutOverflow)?,
            p_filesz: u64::try_from(notes.len()).map_err(|_| CoreDumpError::LayoutOverflow)?,
            p_align: NOTE_ALIGN as u64,
            ..wire::Elf64Phdr::default()
        }));
        for region in &self.regions {
            let filesz =
                u64::try_from(region.bytes.len()).map_err(|_| CoreDumpError::LayoutOverflow)?;
            out.extend_from_slice(as_bytes(&wire::Elf64Phdr {
                p_type: PT_LOAD,
                p_flags: region.flags,
                p_offset: if filesz == 0 {
                    0
                } else {
                    u64::try_from(data_offset).map_err(|_| CoreDumpError::LayoutOverflow)?
                },
                p_vaddr: region.start,
                p_filesz: filesz,
                p_memsz: region.size,
                p_align: GUEST_PAGE as u64,
                ..wire::Elf64Phdr::default()
            }));
            data_offset = data_offset
                .checked_add(
                    checked_align_up(region.bytes.len(), GUEST_PAGE)
                        .ok_or(CoreDumpError::LayoutOverflow)?,
                )
                .ok_or(CoreDumpError::LayoutOverflow)?;
        }
        debug_assert_eq!(out.len(), notes_offset);

        out.extend_from_slice(&notes);
        for region in &self.regions {
            if region.bytes.is_empty() {
                continue;
            }
            out.resize(align_up(out.len(), GUEST_PAGE), 0);
            out.extend_from_slice(region.bytes);
        }
        let expected_notes = self
            .threads
            .len()
            .checked_mul(3)
            .and_then(|count| count.checked_add(4))
            .ok_or(CoreDumpError::LayoutOverflow)?;
        validate_serialized_core(&out, self.regions.len(), expected_notes)?;
        Ok(out)
    }
}

/// The `PF_*` flags for a region, from readable/writable/executable.
pub const fn region_flags(read: bool, write: bool, execute: bool) -> u32 {
    let mut flags = 0;
    if read {
        flags |= PF_R;
    }
    if write {
        flags |= PF_W;
    }
    if execute {
        flags |= PF_X;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CoreDump<'static> {
        CoreDump {
            identity: ProcessIdentity {
                pid: 42,
                ppid: 7,
                pgrp: 42,
                session: 1,
                comm: "crasher".to_string(),
                psargs: "crasher --flag".to_string(),
            },
            signal: SignalInfo {
                signo: 11,
                code: 1,
                errno: 0,
                addr: 0xdead_0000,
            },
            threads: vec![
                ThreadState {
                    tid: 42,
                    registers: ThreadRegisters {
                        gregs: [0x1111; AARCH64_GREGS],
                        tpidr_el0: 0x2222,
                        vregs: [0x3333; 32],
                        fpsr: 0x4444,
                        fpcr: 0x5555,
                    },
                    current_signal: 11,
                },
                ThreadState {
                    tid: 43,
                    registers: ThreadRegisters::default(),
                    current_signal: 0,
                },
            ],
            auxv: vec![(3, 0x4000_0040), (6, 4096)],
            mappings: vec![FileMapping {
                start: 0xaaaa_0000,
                end: 0xaaaa_2000,
                file_page_offset: 0,
                path: "/usr/bin/crasher".to_string(),
            }],
            regions: Vec::new(),
        }
    }

    /// The note payload sizes are the oracle's, and a mismatch means the ABI
    /// drifted — the one thing a reader cannot recover from.
    #[test]
    fn note_payloads_match_the_oracle_sizes() {
        let dump = sample();
        assert_eq!(
            as_bytes(&prstatus_note(&dump, &dump.threads[0])).len(),
            ORACLE_PRSTATUS_SIZE
        );
        assert_eq!(
            as_bytes(&prpsinfo_note(&dump.identity)).len(),
            ORACLE_PRPSINFO_SIZE
        );
        assert_eq!(
            as_bytes(&siginfo_note(&dump.signal)).len(),
            ORACLE_SIGINFO_SIZE
        );
    }

    #[test]
    fn header_declares_an_aarch64_core() {
        let bytes = sample().to_bytes();
        let field = |name: usize, width: usize| &bytes[name..name + width];
        assert_eq!(&bytes[..4], b"\x7fELF");
        assert_eq!(bytes[4], ELF_CLASS64);
        let ty = std::mem::offset_of!(wire::Elf64Ehdr, e_type);
        assert_eq!(
            u16::from_le_bytes(field(ty, 2).try_into().unwrap()),
            ET_CORE
        );
        let machine = std::mem::offset_of!(wire::Elf64Ehdr, e_machine);
        assert_eq!(
            u16::from_le_bytes(field(machine, 2).try_into().unwrap()),
            EM_AARCH64
        );
        // The program header table follows the header, as the oracle's did.
        let phoff = std::mem::offset_of!(wire::Elf64Ehdr, e_phoff);
        assert_eq!(
            u64::from_le_bytes(field(phoff, 8).try_into().unwrap()),
            u64::from(EHDR_SIZE)
        );
    }

    /// Linux writes one NT_PRSTATUS per thread; a reader counts threads by
    /// counting them, so dropping one silently loses a thread.
    #[test]
    fn every_thread_gets_a_prstatus_note() {
        let dump = sample();
        let bytes = dump.to_bytes();
        let found = bytes
            .windows(4)
            .filter(|window| *window == NT_PRSTATUS.to_le_bytes())
            .count();
        assert!(
            found >= dump.threads.len(),
            "expected one NT_PRSTATUS per thread, found {found}"
        );
    }

    /// The crashing thread must come first so a reader attributes the fault
    /// to the right thread.
    #[test]
    fn crashing_thread_is_written_first() {
        let dump = sample();
        let note = prstatus_note(&dump, &dump.threads[0]);
        assert_eq!(note.pr_pid, 42);
        // And it lands where a reader looks for it, by the struct's own offset
        // rather than a counted one.
        let bytes = as_bytes(&note);
        let at = std::mem::offset_of!(wire::ElfPrStatus, pr_pid);
        assert_eq!(
            i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
            42
        );
    }

    #[test]
    fn file_note_carries_triples_then_paths() {
        let dump = sample();
        let note = file_note(&dump.mappings);
        assert_eq!(u64::from_le_bytes(note[0..8].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(note[8..16].try_into().unwrap()),
            NT_FILE_PAGE_SIZE
        );
        assert_eq!(
            u64::from_le_bytes(note[16..24].try_into().unwrap()),
            0xaaaa_0000
        );
        assert!(note.ends_with(b"/usr/bin/crasher\0"));
    }

    /// A region with no dumped bytes still records its mapping, exactly as the
    /// oracle's first PT_LOAD did (filesz 0, memsz 0x20000).
    #[test]
    fn undumped_region_keeps_its_mapping() {
        let mut dump = sample();
        dump.regions.push(MemoryRegion {
            start: 0xaaaa_0000,
            flags: region_flags(true, false, true),
            bytes: &[],
            size: 0x20000,
        });
        let bytes = dump.to_bytes();
        // Second program header: the PT_NOTE comes first.
        let phdr = size_of::<wire::Elf64Ehdr>() + size_of::<wire::Elf64Phdr>();
        let at = |field: usize| phdr + field;
        let kind = at(std::mem::offset_of!(wire::Elf64Phdr, p_type));
        assert_eq!(
            u32::from_le_bytes(bytes[kind..kind + 4].try_into().unwrap()),
            PT_LOAD
        );
        let filesz = at(std::mem::offset_of!(wire::Elf64Phdr, p_filesz));
        assert_eq!(
            u64::from_le_bytes(bytes[filesz..filesz + 8].try_into().unwrap()),
            0,
            "p_filesz"
        );
        let memsz = at(std::mem::offset_of!(wire::Elf64Phdr, p_memsz));
        assert_eq!(
            u64::from_le_bytes(bytes[memsz..memsz + 8].try_into().unwrap()),
            0x20000,
            "p_memsz"
        );
    }

    /// A core is a publication artifact, not a best-effort diagnostic.  The
    /// writer must reject an incomplete generation instead of serialising a
    /// structurally plausible file with no architectural authority.
    #[test]
    fn bounded_writer_rejects_missing_and_duplicate_thread_authority() {
        let mut missing = sample();
        missing.threads.clear();
        assert!(matches!(
            missing.to_bytes_bounded(u64::MAX),
            Err(CoreDumpError::NoThreads)
        ));

        let mut duplicate = sample();
        duplicate.threads[1].tid = duplicate.threads[0].tid;
        assert!(matches!(
            duplicate.to_bytes_bounded(u64::MAX),
            Err(CoreDumpError::DuplicateTid(42))
        ));
    }

    /// RLIMIT_CORE is a hard byte bound: no prefix is a valid publication.
    #[test]
    fn bounded_writer_refuses_a_core_larger_than_the_limit() {
        let dump = sample();
        let required = dump.to_bytes().len() as u64;
        assert!(matches!(
            dump.to_bytes_bounded(required - 1),
            Err(CoreDumpError::LimitExceeded { limit, required: actual })
                if limit == required - 1 && actual == required
        ));
        assert_eq!(
            dump.to_bytes_bounded(required).expect("exact limit"),
            dump.to_bytes()
        );
    }

    #[test]
    fn bounded_writer_rejects_program_header_count_truncation() {
        let mut dump = sample();
        dump.regions = (0..u16::MAX)
            .map(|_| MemoryRegion {
                start: 0,
                flags: 0,
                bytes: &[],
                size: 0,
            })
            .collect();
        assert!(matches!(
            dump.to_bytes_bounded(u64::MAX),
            Err(CoreDumpError::ProgramHeaderCountOverflow { .. })
        ));
    }

    #[test]
    fn serialized_validator_rejects_bad_header_and_segment_bounds() {
        let bytes = sample().to_bytes();

        let mut bad_phentsize = bytes.clone();
        let at = std::mem::offset_of!(wire::Elf64Ehdr, e_phentsize);
        bad_phentsize[at..at + 2].copy_from_slice(&0_u16.to_le_bytes());
        assert!(validate_serialized_core(&bad_phentsize, 0, 0).is_err());

        let mut bad_machine = bytes.clone();
        let at = std::mem::offset_of!(wire::Elf64Ehdr, e_machine);
        bad_machine[at..at + 2].copy_from_slice(&0_u16.to_le_bytes());
        assert!(validate_serialized_core(&bad_machine, 0, 0).is_err());

        let mut bad_note = bytes.clone();
        let phoff = usize::from(EHDR_SIZE);
        let filesz = phoff + std::mem::offset_of!(wire::Elf64Phdr, p_filesz);
        bad_note[filesz..filesz + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(validate_serialized_core(&bad_note, 0, 0).is_err());
    }

    #[test]
    fn writer_and_serialized_validator_reject_overlapping_load_vmas() {
        let mut overlapping = sample();
        overlapping.regions = vec![
            MemoryRegion {
                start: 0x1000,
                flags: region_flags(true, true, false),
                bytes: &[],
                size: 0x2000,
            },
            MemoryRegion {
                start: 0x2000,
                flags: region_flags(true, false, false),
                bytes: &[],
                size: 0x1000,
            },
        ];
        assert!(overlapping.to_bytes_bounded(u64::MAX).is_err());

        let mut partitioned = sample();
        partitioned.regions = vec![
            MemoryRegion {
                start: 0x1000,
                flags: region_flags(true, true, false),
                bytes: &[],
                size: 0x1000,
            },
            MemoryRegion {
                start: 0x2000,
                flags: region_flags(true, false, false),
                bytes: &[],
                size: 0x1000,
            },
        ];
        let mut bytes = partitioned.to_bytes();
        let second_load = usize::from(EHDR_SIZE) + (2 * usize::from(PHDR_SIZE));
        let vaddr = second_load + std::mem::offset_of!(wire::Elf64Phdr, p_vaddr);
        bytes[vaddr..vaddr + 8].copy_from_slice(&0x1800_u64.to_le_bytes());
        assert!(validate_serialized_core(&bytes, 2, 10).is_err());
    }
}

#[cfg(test)]
mod oracle_validation {
    use super::*;

    /// Emit a core to `CARRICK_CORE_EMIT_PATH` so an INDEPENDENT reader can be
    /// pointed at it. Self-consistency proves nothing about a wire format; the
    /// gate is whether `readelf` — which knows nothing about carrick — parses
    /// the header, the program headers, and every note.
    #[test]
    fn emit_core_for_an_independent_reader() {
        let Ok(path) = std::env::var("CARRICK_CORE_EMIT_PATH") else {
            return;
        };
        let dump = CoreDump {
            identity: ProcessIdentity {
                pid: 1234,
                ppid: 1,
                pgrp: 1234,
                session: 1,
                comm: "carrickcore".to_string(),
                psargs: "carrickcore --emit".to_string(),
            },
            signal: SignalInfo {
                signo: 11,
                code: 1,
                errno: 0,
                addr: 0x0000_dead_beef_0000,
            },
            threads: vec![
                ThreadState {
                    tid: 1234,
                    registers: ThreadRegisters {
                        gregs: [0x4142_4344_4546_4748; AARCH64_GREGS],
                        tpidr_el0: 0x5152_5354_5556_5758,
                        vregs: [0x6162_6364_6566_6768; 32],
                        fpsr: 0x7172_7374,
                        fpcr: 0x7576_7778,
                    },
                    current_signal: 11,
                },
                ThreadState {
                    tid: 1235,
                    registers: ThreadRegisters::default(),
                    current_signal: 0,
                },
            ],
            auxv: vec![
                (3, 0x0000_aaaa_0000_0040),
                (6, 4096),
                (25, 0x0000_ffff_0000_0000),
            ],
            mappings: vec![
                FileMapping {
                    start: 0x0000_aaaa_0000_0000,
                    end: 0x0000_aaaa_0002_0000,
                    file_page_offset: 0,
                    path: "/usr/bin/carrickcore".to_string(),
                },
                FileMapping {
                    start: 0x0000_ffff_a000_0000,
                    end: 0x0000_ffff_a019_c000,
                    file_page_offset: 0,
                    path: "/usr/lib/aarch64-linux-gnu/libc.so.6".to_string(),
                },
            ],
            regions: vec![
                MemoryRegion {
                    start: 0x0000_aaaa_0000_0000,
                    flags: region_flags(true, false, true),
                    bytes: &[],
                    size: 0x20000,
                },
                MemoryRegion {
                    start: 0x0000_aaaa_0002_0000,
                    flags: region_flags(true, true, false),
                    bytes: &[0x5a; 0x1000],
                    size: 0x1000,
                },
            ],
        };
        std::fs::write(&path, dump.to_bytes()).expect("emit core");
    }
}
