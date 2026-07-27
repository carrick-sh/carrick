//! Stage 1 of the file-backed AOT translation cache
//! (`docs/superpowers/specs/2026-07-26-file-backed-aot-cache-design.md`):
//! emit translated code as a loadable, ad-hoc-signable Mach-O dylib instead of
//! writing it into `MAP_JIT` memory.
//!
//! # Why this exists
//!
//! `MAP_JIT` is the single largest remaining cost in a guest `fork(2)`.
//! `vm_map_enter` stamps every `entry_for_jit` mapping
//! `MEMORY_OBJECT_COPY_NONE` (`osfmk/vm/vm_map.c:3537`), which routes it to
//! `vm_map_fork`'s **slow** path — `vm_map_copyin_internal_for_entry` →
//! `vm_object_copy_strategically` — that eagerly copies and frees pages rather
//! than resolving copy-on-write lazily. MEASURED on this box, 64 MiB of
//! executable code, otherwise-identical process, fork p50 over 5 round-robin
//! rounds:
//!
//! | mapping                                | fork p50 | delta   |
//! |----------------------------------------|----------|---------|
//! | none                                   | 420 us   | --      |
//! | `dlopen` of an ad-hoc-signed dylib     | 414 us   | **-6**  |
//! | `mmap(MAP_JIT)`                        | 987 us   | **+567**|
//!
//! File-backed executable code is free; `MAP_JIT` is not, and its cost scales
//! with the mapping's VA *range* whether or not we use it.
//!
//! # Why a dylib and not a raw file
//!
//! MEASURED: `mmap(PROT_EXEC)` of an unsigned file fails `EPERM` — AMFI
//! requires a signature to map a file executable. Ad-hoc signing a Mach-O we
//! generated ourselves and loading it with `dlopen` DOES work (carrick is
//! ad-hoc signed without hardened runtime, the configuration that permits it),
//! and yields exactly the mapping we want: `r-x`, `SM=COW`, file-backed.
//!
//! # Scope of this module
//!
//! Emission only. It turns caller-supplied translated arm64 instructions and
//! writable binding cells into the bytes of a dylib with section-aware exports.
//! Signing, the on-disk store, cache keying and translator wiring deliberately
//! live elsewhere.

/// A loadable section in an emitted unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AotSection {
    Text,
    Data,
}

/// A symbol to export from an emitted unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AotExport<'a> {
    /// Exported symbol name, as `dlsym` will see it (no leading underscore —
    /// the emitter adds the Mach-O `_` prefix).
    pub name: &'a str,
    /// Section that owns the exported address.
    pub section: AotSection,
    /// Byte offset within `section`.
    pub offset: u32,
}

/// One AArch64 `ADRP`/`ADD` pair that materializes a data-cell address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AotCodeToDataRelocation {
    pub adrp_offset: u32,
    pub add_offset: u32,
    pub data_offset: u32,
}

/// Complete immutable input to one emitted Mach-O image.
pub struct AotImage<'a> {
    pub code: &'a [u8],
    pub data: &'a [u8],
    pub exports: &'a [AotExport<'a>],
    pub relocations: &'a [AotCodeToDataRelocation],
}

#[derive(Debug, PartialEq, Eq)]
pub enum AotRelocationError {
    CodeOffset {
        adrp_offset: u32,
        add_offset: u32,
        code_len: usize,
    },
    WrongShape {
        adrp: u32,
        add: u32,
    },
    DataOffset {
        data_offset: u32,
        data_len: usize,
    },
    PageDelta {
        delta_pages: i128,
    },
}

/// Why an emission attempt could not produce a loadable unit. Every variant is
/// a reason to fall back to `MAP_JIT`, never to fail the guest.
#[derive(Debug)]
pub enum AotEmitError {
    /// `code` was empty, or not a whole number of 4-byte arm64 instructions.
    CodeNotInstructionAligned(usize),
    /// An export pointed outside its declared section, or was misaligned.
    ExportOutOfRange {
        name: String,
        section: AotSection,
        offset: u32,
        section_len: usize,
    },
    /// A writable cell sidecar is not a whole number of atomic 8-byte cells.
    DataNotCellAligned(usize),
    /// A code-to-data relocation was not safe or representable.
    RelocationInvalid {
        index: usize,
        reason: AotRelocationError,
    },
    /// File-layout arithmetic overflowed before a representable image existed.
    LayoutOverflow { field: &'static str },
    /// A value did not fit the fixed-width Mach-O field that carries it.
    MachOFieldOutOfRange { field: &'static str, value: u64 },
    /// A symbol name cannot be represented in a Mach-O string table.
    SymbolNameUnrepresentable(String),
    /// The Mach-O writer rejected the unit. Kept as a string because the
    /// upstream error is not part of our fallback contract - every variant here
    /// means "fall back to MAP_JIT", not "fail the guest".
    Writer(String),
}

impl std::fmt::Display for AotEmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodeNotInstructionAligned(len) => write!(
                f,
                "translated code must be a nonzero multiple of 4 bytes, got {len}"
            ),
            Self::ExportOutOfRange {
                name,
                section,
                offset,
                section_len,
            } => write!(
                f,
                "export {name:?} at offset {offset} is outside the {section_len}-byte \
                 {section:?} section (or is not section-aligned)"
            ),
            Self::DataNotCellAligned(len) => {
                write!(
                    f,
                    "AOT data must contain whole 8-byte cells, got {len} bytes"
                )
            }
            Self::RelocationInvalid { index, reason } => {
                write!(f, "AOT relocation {index} is invalid: {reason:?}")
            }
            Self::LayoutOverflow { field } => {
                write!(f, "AOT layout overflow while computing {field}")
            }
            Self::MachOFieldOutOfRange { field, value } => {
                write!(f, "AOT {field} value {value} does not fit its Mach-O field")
            }
            Self::SymbolNameUnrepresentable(name) => {
                write!(f, "symbol name {name:?} cannot be encoded (embedded NUL)")
            }
            Self::Writer(msg) => write!(f, "Mach-O writer rejected the unit: {msg}"),
        }
    }
}

impl std::error::Error for AotEmitError {}

/// Validate an emission request. Split out from the writer so the preconditions
/// are testable without producing a file, and so every rejection is a typed
/// fallback reason rather than a panic inside the translator.
pub fn validate(image: &AotImage<'_>) -> Result<(), AotEmitError> {
    if image.code.is_empty() || !image.code.len().is_multiple_of(4) {
        return Err(AotEmitError::CodeNotInstructionAligned(image.code.len()));
    }
    if !image.data.len().is_multiple_of(8) {
        return Err(AotEmitError::DataNotCellAligned(image.data.len()));
    }
    for export in image.exports {
        if export.name.as_bytes().contains(&0) {
            return Err(AotEmitError::SymbolNameUnrepresentable(
                export.name.to_owned(),
            ));
        }
        let (section_len, alignment) = match export.section {
            AotSection::Text => (image.code.len(), 4),
            AotSection::Data => (image.data.len(), 8),
        };
        let offset =
            usize::try_from(export.offset).map_err(|_| AotEmitError::ExportOutOfRange {
                name: export.name.to_owned(),
                section: export.section,
                offset: export.offset,
                section_len,
            })?;
        if offset >= section_len || !offset.is_multiple_of(alignment) {
            return Err(AotEmitError::ExportOutOfRange {
                name: export.name.to_owned(),
                section: export.section,
                offset: export.offset,
                section_len,
            });
        }
    }
    Ok(())
}

/// Mach-O constants. These are published ABI numbers from `<mach-o/loader.h>`,
/// the same category as the Linux syscall numbers `carrick-abi` carries.
mod macho {
    pub const MH_MAGIC_64: u32 = 0xfeed_facf;
    pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
    pub const MH_DYLIB: u32 = 6;
    pub const MH_NOUNDEFS: u32 = 0x1;
    pub const MH_DYLDLINK: u32 = 0x4;
    pub const MH_TWOLEVEL: u32 = 0x80;

    pub const LC_SEGMENT_64: u32 = 0x19;
    pub const LC_SYMTAB: u32 = 0x2;
    pub const LC_DYSYMTAB: u32 = 0xb;
    pub const LC_ID_DYLIB: u32 = 0xd;
    pub const LC_BUILD_VERSION: u32 = 0x32;
    pub const LC_REQ_DYLD: u32 = 0x8000_0000;
    pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;

    pub const VM_PROT_READ: i32 = 0x1;
    pub const VM_PROT_WRITE: i32 = 0x2;
    pub const VM_PROT_EXECUTE: i32 = 0x4;
    pub const PLATFORM_MACOS: u32 = 1;

    /// `N_SECT | N_EXT`: defined in a section, externally visible.
    pub const N_SECT_EXT: u8 = 0x0f;
    /// `S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS`.
    pub const TEXT_SECTION_FLAGS: u32 = 0x8000_0400;

    /// arm64 macOS page size. `__LINKEDIT` must start on a page boundary.
    pub const PAGE: u64 = 16384;
    /// Architectural page size used by AArch64 `ADRP`.
    pub const ADRP_PAGE: u64 = 4096;
    /// Slack between the load commands and the first section.
    ///
    /// Signing APPENDS an `LC_CODE_SIGNATURE` (16 bytes). With a tight header
    /// that grows `sizeofcmds`, the first section slides forward, and every
    /// symbol address we emitted then points 16 bytes short of the real code —
    /// which faults on the first call rather than failing to load. Real linkers
    /// leave slack for exactly this reason.
    pub const HEADER_SLACK: u64 = 256;
}

#[derive(Clone, Copy, Debug)]
struct AotLayoutLengths {
    sizeofcmds: u64,
    code_len: u64,
    data_len: u64,
    trie_len: u64,
    nlists_len: u64,
    strtab_len: u64,
    export_count: u64,
}

#[derive(Clone, Copy, Debug)]
struct AotSectionLayout {
    code_addr: u64,
    text_vmsize: u64,
    data_addr: u64,
    data_vmsize: u64,
    linkedit_off: u64,
}

#[derive(Clone, Copy, Debug)]
struct AotLayout {
    sizeofcmds: u32,
    sizeofcmds_usize: usize,
    code_addr: u64,
    code_start: usize,
    code_fileoff: u32,
    text_vmsize: u64,
    data_addr: u64,
    data_start: Option<usize>,
    data_end: Option<usize>,
    data_fileoff: Option<u32>,
    data_vmsize: u64,
    linkedit_off: u64,
    linkedit_start: usize,
    linkedit_size: u64,
    linkedit_vmsize: u64,
    export_off: u32,
    export_size: u32,
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
    output_len: usize,
}

fn layout_overflow(field: &'static str) -> AotEmitError {
    AotEmitError::LayoutOverflow { field }
}

fn checked_add(left: u64, right: u64, field: &'static str) -> Result<u64, AotEmitError> {
    left.checked_add(right)
        .ok_or_else(|| layout_overflow(field))
}

fn checked_align_up(value: u64, alignment: u64, field: &'static str) -> Result<u64, AotEmitError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| layout_overflow(field))?;
    Ok(checked_add(value, mask, field)? & !mask)
}

fn checked_u32(value: u64, field: &'static str) -> Result<u32, AotEmitError> {
    u32::try_from(value).map_err(|_| AotEmitError::MachOFieldOutOfRange { field, value })
}

fn checked_u8(value: u64, field: &'static str) -> Result<u8, AotEmitError> {
    u8::try_from(value).map_err(|_| AotEmitError::MachOFieldOutOfRange { field, value })
}

fn checked_u64(value: usize, field: &'static str) -> Result<u64, AotEmitError> {
    u64::try_from(value).map_err(|_| layout_overflow(field))
}

fn checked_usize(value: u64, field: &'static str) -> Result<usize, AotEmitError> {
    usize::try_from(value).map_err(|_| AotEmitError::MachOFieldOutOfRange { field, value })
}

fn checked_section_layout(
    sizeofcmds: u64,
    code_len: u64,
    data_len: u64,
) -> Result<AotSectionLayout, AotEmitError> {
    use macho::{HEADER_SLACK, PAGE};

    let header_size = checked_add(
        checked_add(32, sizeofcmds, "header size")?,
        HEADER_SLACK,
        "header size",
    )?;
    let text_end = checked_add(header_size, code_len, "text end")?;
    let text_vmsize = checked_align_up(text_end, PAGE, "text vmsize")?;
    let data_vmsize = if data_len == 0 {
        0
    } else {
        checked_align_up(data_len, PAGE, "data vmsize")?
    };
    let linkedit_off = checked_add(text_vmsize, data_vmsize, "linkedit offset")?;
    Ok(AotSectionLayout {
        code_addr: header_size,
        text_vmsize,
        data_addr: text_vmsize,
        data_vmsize,
        linkedit_off,
    })
}

fn checked_layout(lengths: AotLayoutLengths) -> Result<AotLayout, AotEmitError> {
    use macho::PAGE;

    let sections = checked_section_layout(lengths.sizeofcmds, lengths.code_len, lengths.data_len)?;
    let symoff = checked_add(
        sections.linkedit_off,
        lengths.trie_len,
        "symbol table offset",
    )?;
    let stroff = checked_add(symoff, lengths.nlists_len, "string table offset")?;
    let linkedit_size = checked_add(
        checked_add(lengths.trie_len, lengths.nlists_len, "linkedit size")?,
        lengths.strtab_len,
        "linkedit size",
    )?;
    let linkedit_vmsize = checked_align_up(linkedit_size, PAGE, "linkedit vmsize")?;
    let output_len = checked_add(sections.linkedit_off, linkedit_size, "output length")?;

    let sizeofcmds = checked_u32(lengths.sizeofcmds, "load command size")?;
    let export_off = checked_u32(sections.linkedit_off, "linkedit offset")?;
    let export_size = checked_u32(lengths.trie_len, "export trie size")?;
    let symoff_u32 = checked_u32(symoff, "symbol table offset")?;
    let nsyms = checked_u32(lengths.export_count, "symbol count")?;
    let stroff_u32 = checked_u32(stroff, "string table offset")?;
    let strsize = checked_u32(lengths.strtab_len, "string table size")?;
    let code_fileoff = checked_u32(sections.code_addr, "text section offset")?;
    let data_fileoff = if lengths.data_len == 0 {
        None
    } else {
        Some(checked_u32(sections.data_addr, "data section offset")?)
    };

    let data_end = if lengths.data_len == 0 {
        None
    } else {
        Some(checked_usize(
            checked_add(sections.data_addr, lengths.data_len, "data section end")?,
            "data section end",
        )?)
    };

    Ok(AotLayout {
        sizeofcmds,
        sizeofcmds_usize: checked_usize(lengths.sizeofcmds, "load command size")?,
        code_addr: sections.code_addr,
        code_start: checked_usize(sections.code_addr, "text section offset")?,
        code_fileoff,
        text_vmsize: sections.text_vmsize,
        data_addr: sections.data_addr,
        data_start: data_fileoff
            .map(|_| checked_usize(sections.data_addr, "data section offset"))
            .transpose()?,
        data_end,
        data_fileoff,
        data_vmsize: sections.data_vmsize,
        linkedit_off: sections.linkedit_off,
        linkedit_start: checked_usize(sections.linkedit_off, "linkedit offset")?,
        linkedit_size,
        linkedit_vmsize,
        export_off,
        export_size,
        symoff: symoff_u32,
        nsyms,
        stroff: stroff_u32,
        strsize,
        output_len: checked_usize(output_len, "output length")?,
    })
}

fn patch_code_to_data_relocations(
    code: &mut [u8],
    code_vmaddr: u64,
    data_vmaddr: u64,
    data_len: usize,
    relocations: &[AotCodeToDataRelocation],
) -> Result<(), AotEmitError> {
    use macho::ADRP_PAGE;

    const ADRP_X15: u32 = 0x9000_000f;
    const ADD_X15_X15_0: u32 = 0x9100_01ef;
    const ADRP_MIN_PAGES: i128 = -(1 << 20);
    const ADRP_MAX_PAGES: i128 = (1 << 20) - 1;

    let mut patches = Vec::with_capacity(relocations.len());
    for (index, relocation) in relocations.iter().copied().enumerate() {
        let invalid_code_offset = || AotEmitError::RelocationInvalid {
            index,
            reason: AotRelocationError::CodeOffset {
                adrp_offset: relocation.adrp_offset,
                add_offset: relocation.add_offset,
                code_len: code.len(),
            },
        };
        let adrp_offset =
            usize::try_from(relocation.adrp_offset).map_err(|_| invalid_code_offset())?;
        let add_offset =
            usize::try_from(relocation.add_offset).map_err(|_| invalid_code_offset())?;
        let adrp_end = adrp_offset.checked_add(4);
        let add_end = add_offset.checked_add(4);
        if !adrp_offset.is_multiple_of(4)
            || !add_offset.is_multiple_of(4)
            || adrp_end.is_none_or(|end| end > code.len())
            || add_end.is_none_or(|end| end > code.len())
        {
            return Err(invalid_code_offset());
        }
        let adrp_bytes: [u8; 4] = code
            .get(adrp_offset..adrp_end.ok_or_else(invalid_code_offset)?)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(invalid_code_offset)?;
        let add_bytes: [u8; 4] = code
            .get(add_offset..add_end.ok_or_else(invalid_code_offset)?)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(invalid_code_offset)?;
        let adrp = u32::from_le_bytes(adrp_bytes);
        let add = u32::from_le_bytes(add_bytes);
        if adrp != ADRP_X15 || add != ADD_X15_X15_0 {
            return Err(AotEmitError::RelocationInvalid {
                index,
                reason: AotRelocationError::WrongShape { adrp, add },
            });
        }

        let invalid_data_offset = || AotEmitError::RelocationInvalid {
            index,
            reason: AotRelocationError::DataOffset {
                data_offset: relocation.data_offset,
                data_len,
            },
        };
        let data_offset =
            usize::try_from(relocation.data_offset).map_err(|_| invalid_data_offset())?;
        if !data_offset.is_multiple_of(8)
            || data_offset.checked_add(8).is_none_or(|end| end > data_len)
        {
            return Err(invalid_data_offset());
        }

        let pc = code_vmaddr.checked_add(u64::from(relocation.adrp_offset));
        let target = data_vmaddr.checked_add(u64::from(relocation.data_offset));
        let (Some(pc), Some(target)) = (pc, target) else {
            return Err(AotEmitError::RelocationInvalid {
                index,
                reason: AotRelocationError::PageDelta {
                    delta_pages: i128::MAX,
                },
            });
        };
        let pc_page = pc & !(ADRP_PAGE - 1);
        let target_page = target & !(ADRP_PAGE - 1);
        let delta_pages = (i128::from(target_page) - i128::from(pc_page)) / i128::from(ADRP_PAGE);
        if !(ADRP_MIN_PAGES..=ADRP_MAX_PAGES).contains(&delta_pages) {
            return Err(AotEmitError::RelocationInvalid {
                index,
                reason: AotRelocationError::PageDelta { delta_pages },
            });
        }

        let encoded_delta = if delta_pages < 0 {
            delta_pages + (1 << 21)
        } else {
            delta_pages
        };
        let immediate =
            u32::try_from(encoded_delta).map_err(|_| AotEmitError::RelocationInvalid {
                index,
                reason: AotRelocationError::PageDelta { delta_pages },
            })?;
        let patched_adrp = ADRP_X15 | ((immediate & 0x3) << 29) | ((immediate >> 2) << 5);
        let low_twelve = u32::try_from(target & (ADRP_PAGE - 1)).map_err(|_| {
            AotEmitError::RelocationInvalid {
                index,
                reason: AotRelocationError::PageDelta { delta_pages },
            }
        })?;
        let patched_add = ADD_X15_X15_0 | (low_twelve << 10);
        patches.push((
            adrp_offset,
            adrp_end.ok_or_else(invalid_code_offset)?,
            patched_adrp,
            add_offset,
            add_end.ok_or_else(invalid_code_offset)?,
            patched_add,
        ));
    }

    // The validation loop above is intentionally complete before this first
    // write: one malformed late record must leave every earlier pair pristine.
    for (adrp_offset, adrp_end, adrp, add_offset, add_end, add) in patches {
        code[adrp_offset..adrp_end].copy_from_slice(&adrp.to_le_bytes());
        code[add_offset..add_end].copy_from_slice(&add.to_le_bytes());
    }
    Ok(())
}

fn uleb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        out.push(if value != 0 { byte | 0x80 } else { byte });
        if value == 0 {
            return;
        }
    }
}

/// Build the dyld export trie: a root node with one edge per export, each edge
/// carrying the complete symbol name and pointing at a terminal node.
///
/// The child offsets are a fixed point — an offset's own ULEB length changes the
/// root's length, which changes the offsets. Solve by iterating to stability.
/// A spike that searched too narrow a range silently emitted offset 7 for a true
/// offset of 21, which sent dyld into the middle of a symbol name and trapped
/// inside `mach_o::ExportsTrie::valid`.
fn export_trie(exports: &[(String, u64)]) -> Result<Vec<u8>, AotEmitError> {
    let export_count = checked_u64(exports.len(), "export trie child count")?;
    let child_count = checked_u8(export_count, "export trie child count")?;
    // Terminal node per export: terminal_size, flags(0 = regular), address,
    // then a zero child count.
    let terminals: Vec<Vec<u8>> = exports
        .iter()
        .map(|(_, addr)| {
            let mut payload = Vec::new();
            uleb128(0, &mut payload); // EXPORT_SYMBOL_FLAGS_KIND_REGULAR
            uleb128(*addr, &mut payload);
            let mut node = Vec::new();
            uleb128(
                checked_u64(payload.len(), "export trie terminal size")?,
                &mut node,
            );
            node.extend_from_slice(&payload);
            node.push(0); // no children
            Ok(node)
        })
        .collect::<Result<_, AotEmitError>>()?;

    let mut offsets: Vec<u64> = vec![0; exports.len()];
    let mut root = Vec::new();
    for _ in 0..16 {
        root.clear();
        uleb128(0, &mut root); // root is not itself terminal
        root.push(child_count);
        for (i, (name, _)) in exports.iter().enumerate() {
            // The trie stores the MACH-O name, i.e. with the leading
            // underscore; `dlsym("foo")` looks up `_foo`.
            root.push(b'_');
            root.extend_from_slice(name.as_bytes());
            root.push(0);
            uleb128(offsets[i], &mut root);
        }
        let mut cursor = checked_u64(root.len(), "export trie offset")?;
        let mut next = Vec::with_capacity(exports.len());
        for terminal in &terminals {
            next.push(cursor);
            cursor = checked_add(
                cursor,
                checked_u64(terminal.len(), "export trie offset")?,
                "export trie offset",
            )?;
        }
        if next == offsets {
            let mut trie = root;
            for terminal in &terminals {
                trie.extend_from_slice(terminal);
            }
            while !trie.len().is_multiple_of(8) {
                trie.push(0);
            }
            return Ok(trie);
        }
        offsets = next;
    }
    Err(AotEmitError::Writer(
        "export trie offsets did not converge".to_owned(),
    ))
}

/// Emit a complete, loadable arm64 `MH_DYLIB` for `image`.
///
/// Written directly rather than emitted as a relocatable object and linked:
/// SPIKED AND PROVEN that dyld loads a hand-built dylib with **no
/// `LC_LOAD_DYLIB` at all**. `ld` refuses to produce one ("dylibs must link with
/// libSystem.dylib") but that is a linker policy, not a dyld requirement, and a
/// translated unit is genuinely self-contained. Emitting directly removes an
/// `ld` process spawn from the per-unit cost.
///
/// The result is NOT signed. AMFI refuses to map an unsigned file executable
/// (MEASURED: `mmap(PROT_EXEC)` -> `EPERM`), so a caller must sign before
/// `dlopen`.
pub fn emit_dylib(image: &AotImage<'_>) -> Result<Vec<u8>, AotEmitError> {
    use macho::*;
    validate(image)?;

    const SEG_CMD: u64 = 72;
    const SECT: u64 = 80;
    const SYMTAB_CMD: u64 = 24;
    const DYSYMTAB_CMD: u64 = 80;
    const DYLD_INFO_CMD: u64 = 48;
    const BUILD_VERSION_CMD: u64 = 24; // 24 when ntools == 0; declaring 32 left
    // eight bytes of garbage in the command stream and dyld rejected the whole
    // image with a bare "not a mach-o".

    let install_name = b"@rpath/carrick_aot.dylib";
    let has_data = !image.data.is_empty();
    let install_name_size = checked_add(
        checked_u64(install_name.len(), "install name size")?,
        1,
        "install name size",
    )?;
    let id_dylib_cmd = checked_add(
        24,
        checked_align_up(install_name_size, 8, "install name size")?,
        "install-name command size",
    )?;
    let mut sizeofcmds = 0;
    for command_size in [
        SEG_CMD + SECT,
        if has_data { SEG_CMD + SECT } else { 0 },
        SEG_CMD,
        id_dylib_cmd,
        DYLD_INFO_CMD,
        SYMTAB_CMD,
        DYSYMTAB_CMD,
        BUILD_VERSION_CMD,
    ] {
        sizeofcmds = checked_add(sizeofcmds, command_size, "load command size")?;
    }
    let code_len = checked_u64(image.code.len(), "code length")?;
    let data_len = checked_u64(image.data.len(), "data length")?;
    let export_count = checked_u64(image.exports.len(), "symbol count")?;
    let sections = checked_section_layout(sizeofcmds, code_len, data_len)?;

    // `__TEXT` has vmaddr 0 and covers the header, so a section's vmaddr and its
    // file offset are the same number.
    let mut code = image.code.to_vec();
    patch_code_to_data_relocations(
        &mut code,
        sections.code_addr,
        sections.data_addr,
        image.data.len(),
        image.relocations,
    )?;

    let resolved: Vec<(String, AotSection, u64)> = image
        .exports
        .iter()
        .map(|export| {
            let section_addr = match export.section {
                AotSection::Text => sections.code_addr,
                AotSection::Data => sections.data_addr,
            };
            Ok((
                export.name.to_owned(),
                export.section,
                checked_add(section_addr, u64::from(export.offset), "export address")?,
            ))
        })
        .collect::<Result<_, AotEmitError>>()?;
    let trie_exports = resolved
        .iter()
        .map(|(name, _, addr)| (name.clone(), *addr))
        .collect::<Vec<_>>();
    let trie = export_trie(&trie_exports)?;

    // String table: a leading NUL, then each `_name`.
    let mut strtab = vec![0u8];
    let mut name_offsets = Vec::with_capacity(image.exports.len());
    for export in image.exports {
        name_offsets.push(strtab.len());
        strtab.push(b'_');
        strtab.extend_from_slice(export.name.as_bytes());
        strtab.push(0);
    }
    while !strtab.len().is_multiple_of(8) {
        strtab.push(0);
    }

    let trie_len = checked_u64(trie.len(), "export trie size")?;
    let nlists_len = export_count
        .checked_mul(16)
        .ok_or_else(|| layout_overflow("symbol table size"))?;
    let strtab_len = checked_u64(strtab.len(), "string table size")?;
    let layout = checked_layout(AotLayoutLengths {
        sizeofcmds,
        code_len,
        data_len,
        trie_len,
        nlists_len,
        strtab_len,
        export_count,
    })?;

    let mut nlists = Vec::new();
    for (i, (_, section, addr)) in resolved.iter().enumerate() {
        let name_offset = checked_u32(
            checked_u64(name_offsets[i], "string table name offset")?,
            "string table name offset",
        )?;
        nlists.extend_from_slice(&name_offset.to_le_bytes());
        nlists.push(N_SECT_EXT);
        nlists.push(match section {
            AotSection::Text => 1,
            AotSection::Data => 2,
        });
        nlists.extend_from_slice(&0u16.to_le_bytes());
        nlists.extend_from_slice(&addr.to_le_bytes());
    }
    debug_assert!(u64::try_from(nlists.len()).ok() == Some(nlists_len));

    let mut cmds: Vec<u8> = Vec::with_capacity(layout.sizeofcmds_usize);
    let segment_command_size = checked_u32(SEG_CMD, "segment command size")?;
    let segment_section_command_size = checked_u32(SEG_CMD + SECT, "segment command size")?;
    let id_dylib_command_size = checked_u32(id_dylib_cmd, "install-name command size")?;
    let id_dylib_command_size_usize = checked_usize(id_dylib_cmd, "install-name command size")?;
    let dyld_info_command_size = checked_u32(DYLD_INFO_CMD, "dyld info command size")?;
    let symtab_command_size = checked_u32(SYMTAB_CMD, "symbol table command size")?;
    let dysymtab_command_size = checked_u32(DYSYMTAB_CMD, "dynamic symbol command size")?;
    let build_version_command_size = checked_u32(BUILD_VERSION_CMD, "build-version command size")?;
    let seg = |name: &[u8],
               vmaddr: u64,
               vmsize: u64,
               off: u64,
               fsize: u64,
               prot: i32,
               nsects: i32,
               cmdsize: u32,
               out: &mut Vec<u8>| {
        out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
        out.extend_from_slice(&cmdsize.to_le_bytes());
        let mut padded = [0u8; 16];
        padded[..name.len()].copy_from_slice(name);
        out.extend_from_slice(&padded);
        for v in [vmaddr, vmsize, off, fsize] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in [prot, prot, nsects, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    };

    seg(
        b"__TEXT",
        0,
        layout.text_vmsize,
        0,
        layout.text_vmsize,
        VM_PROT_READ | VM_PROT_EXECUTE,
        1,
        segment_section_command_size,
        &mut cmds,
    );
    // section_64 for __text
    let mut sect_name = [0u8; 16];
    sect_name[..6].copy_from_slice(b"__text");
    let mut seg_name = [0u8; 16];
    seg_name[..6].copy_from_slice(b"__TEXT");
    cmds.extend_from_slice(&sect_name);
    cmds.extend_from_slice(&seg_name);
    cmds.extend_from_slice(&layout.code_addr.to_le_bytes());
    cmds.extend_from_slice(&code_len.to_le_bytes());
    cmds.extend_from_slice(&layout.code_fileoff.to_le_bytes());
    cmds.extend_from_slice(&2u32.to_le_bytes()); // align 2^2 = 4, the arm64 instruction size
    for v in [0u32, 0, TEXT_SECTION_FLAGS, 0, 0, 0] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }

    if has_data {
        let Some(data_fileoff) = layout.data_fileoff else {
            return Err(layout_overflow("data section offset"));
        };
        seg(
            b"__DATA",
            layout.data_addr,
            layout.data_vmsize,
            layout.data_addr,
            data_len,
            VM_PROT_READ | VM_PROT_WRITE,
            1,
            segment_section_command_size,
            &mut cmds,
        );
        // section_64 for __data. Its segment begins on a 16 KiB boundary;
        // align=3 records the stronger 8-byte atomic-cell alignment contract.
        let mut sect_name = [0u8; 16];
        sect_name[..6].copy_from_slice(b"__data");
        let mut seg_name = [0u8; 16];
        seg_name[..6].copy_from_slice(b"__DATA");
        cmds.extend_from_slice(&sect_name);
        cmds.extend_from_slice(&seg_name);
        cmds.extend_from_slice(&layout.data_addr.to_le_bytes());
        cmds.extend_from_slice(&data_len.to_le_bytes());
        cmds.extend_from_slice(&data_fileoff.to_le_bytes());
        cmds.extend_from_slice(&3u32.to_le_bytes()); // align 2^3 = 8-byte cells
        for value in [0u32; 6] {
            cmds.extend_from_slice(&value.to_le_bytes());
        }
    }

    seg(
        b"__LINKEDIT",
        layout.linkedit_off,
        layout.linkedit_vmsize,
        layout.linkedit_off,
        layout.linkedit_size,
        VM_PROT_READ,
        0,
        segment_command_size,
        &mut cmds,
    );

    // LC_ID_DYLIB. The name is a NUL-TERMINATED string padded out to the
    // command's declared size; aligning `cmds` to 8 instead happened to land on
    // a shorter length than declared and desynchronised `sizeofcmds`.
    let id_start = cmds.len();
    cmds.extend_from_slice(&LC_ID_DYLIB.to_le_bytes());
    cmds.extend_from_slice(&id_dylib_command_size.to_le_bytes());
    for v in [24u32, 0, 0x1_0000, 0x1_0000] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }
    cmds.extend_from_slice(install_name);
    while (cmds.len() - id_start) < id_dylib_command_size_usize {
        cmds.push(0);
    }

    // LC_DYLD_INFO_ONLY: rebase/bind/weak/lazy all empty, export = the trie.
    // The trie MUST land in the export pair; a spike that put it in the
    // lazy-bind pair made dyld read trie bytes as bind opcodes.
    cmds.extend_from_slice(&LC_DYLD_INFO_ONLY.to_le_bytes());
    cmds.extend_from_slice(&dyld_info_command_size.to_le_bytes());
    for v in [0u32, 0, 0, 0, 0, 0, 0, 0] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }
    cmds.extend_from_slice(&layout.export_off.to_le_bytes());
    cmds.extend_from_slice(&layout.export_size.to_le_bytes());

    // LC_SYMTAB
    cmds.extend_from_slice(&LC_SYMTAB.to_le_bytes());
    cmds.extend_from_slice(&symtab_command_size.to_le_bytes());
    for v in [layout.symoff, layout.nsyms, layout.stroff, layout.strsize] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }

    // LC_DYSYMTAB. dyld ENFORCES `iundefsym == iextdefsym + nextdefsym`;
    // violating it rejects the image with "indirect symbol table
    // iundefsym != iextdefsym+nextdefsym".
    let n = layout.nsyms;
    cmds.extend_from_slice(&LC_DYSYMTAB.to_le_bytes());
    cmds.extend_from_slice(&dysymtab_command_size.to_le_bytes());
    for v in [0u32, 0, 0, n, n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }

    // LC_BUILD_VERSION, ntools = 0.
    cmds.extend_from_slice(&LC_BUILD_VERSION.to_le_bytes());
    cmds.extend_from_slice(&build_version_command_size.to_le_bytes());
    for v in [PLATFORM_MACOS, 11 << 16, 11 << 16, 0] {
        cmds.extend_from_slice(&v.to_le_bytes());
    }

    debug_assert_eq!(cmds.len(), layout.sizeofcmds_usize);

    let mut out = Vec::with_capacity(layout.output_len);
    out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    out.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    out.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
    out.extend_from_slice(&MH_DYLIB.to_le_bytes());
    out.extend_from_slice(&(if has_data { 8u32 } else { 7u32 }).to_le_bytes());
    out.extend_from_slice(&layout.sizeofcmds.to_le_bytes());
    out.extend_from_slice(&(MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&cmds);
    out.resize(layout.code_start, 0); // HEADER_SLACK
    out.extend_from_slice(&code);
    out.resize(layout.linkedit_start, 0);
    if has_data {
        let (Some(data_start), Some(data_end)) = (layout.data_start, layout.data_end) else {
            return Err(layout_overflow("data section offset"));
        };
        out[data_start..data_end].copy_from_slice(image.data);
    }
    out.extend_from_slice(&trie);
    out.extend_from_slice(&nlists);
    out.extend_from_slice(&strtab);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// `mov w0, #42 ; ret` — the smallest blob whose execution proves the whole
    /// pipeline (emit -> sign -> dlopen -> dlsym -> call) actually works.
    const MOV42_RET: [u8; 8] = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
    const ADRP_X15: u32 = 0x9000_000f;
    const ADD_X15_X15_0: u32 = 0x9100_01ef;

    #[derive(Debug)]
    struct SectionView {
        name: String,
        addr: u64,
        size: u64,
        offset: u32,
        align: u32,
    }

    #[derive(Debug)]
    struct SegmentView {
        name: String,
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        maxprot: i32,
        initprot: i32,
        sections: Vec<SectionView>,
    }

    fn read_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
    }

    fn read_i32(bytes: &[u8], offset: usize) -> i32 {
        i32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("i32 field"))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
    }

    fn fixed_name(bytes: &[u8]) -> String {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end])
            .expect("ASCII Mach-O name")
            .to_owned()
    }

    fn load_commands(bytes: &[u8]) -> Vec<(u32, usize, usize)> {
        let mut commands = Vec::new();
        let mut offset = 32;
        for _ in 0..read_u32(bytes, 16) {
            let command = read_u32(bytes, offset);
            let size = read_u32(bytes, offset + 4) as usize;
            assert!(size >= 8, "load command must include its header");
            commands.push((command, offset, size));
            offset += size;
        }
        assert_eq!(offset, 32 + read_u32(bytes, 20) as usize);
        commands
    }

    fn segments(bytes: &[u8]) -> Vec<SegmentView> {
        load_commands(bytes)
            .into_iter()
            .filter_map(|(command, offset, size)| {
                if command != macho::LC_SEGMENT_64 {
                    return None;
                }
                let nsects = read_u32(bytes, offset + 64) as usize;
                assert_eq!(size, 72 + nsects * 80);
                let sections = (0..nsects)
                    .map(|index| {
                        let section = offset + 72 + index * 80;
                        SectionView {
                            name: fixed_name(&bytes[section..section + 16]),
                            addr: read_u64(bytes, section + 32),
                            size: read_u64(bytes, section + 40),
                            offset: read_u32(bytes, section + 48),
                            align: read_u32(bytes, section + 52),
                        }
                    })
                    .collect();
                Some(SegmentView {
                    name: fixed_name(&bytes[offset + 8..offset + 24]),
                    vmaddr: read_u64(bytes, offset + 24),
                    vmsize: read_u64(bytes, offset + 32),
                    fileoff: read_u64(bytes, offset + 40),
                    filesize: read_u64(bytes, offset + 48),
                    maxprot: read_i32(bytes, offset + 56),
                    initprot: read_i32(bytes, offset + 60),
                    sections,
                })
            })
            .collect()
    }

    fn section<'a>(segments: &'a [SegmentView], segment: &str) -> &'a SectionView {
        let segment = segments
            .iter()
            .find(|candidate| candidate.name == segment)
            .expect("declared segment");
        assert_eq!(segment.sections.len(), 1);
        &segment.sections[0]
    }

    fn read_uleb(bytes: &[u8], cursor: &mut usize) -> u64 {
        let mut value = 0_u64;
        let mut shift = 0;
        loop {
            let byte = bytes[*cursor];
            *cursor += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
            assert!(shift < 64, "ULEB128 value overflow");
        }
    }

    fn exported_addresses(bytes: &[u8]) -> BTreeMap<String, u64> {
        let (_, command, _) = load_commands(bytes)
            .into_iter()
            .find(|(kind, _, _)| *kind == macho::LC_DYLD_INFO_ONLY)
            .expect("LC_DYLD_INFO_ONLY");
        let export_offset = read_u32(bytes, command + 40) as usize;
        let export_size = read_u32(bytes, command + 44) as usize;
        let trie = &bytes[export_offset..export_offset + export_size];
        let mut cursor = 0;
        assert_eq!(read_uleb(trie, &mut cursor), 0, "root is not terminal");
        let child_count = trie[cursor] as usize;
        cursor += 1;
        let mut children = Vec::with_capacity(child_count);
        for _ in 0..child_count {
            let name_start = cursor;
            let name_len = trie[name_start..]
                .iter()
                .position(|byte| *byte == 0)
                .expect("terminated export edge");
            let name = std::str::from_utf8(&trie[name_start + 1..name_start + name_len])
                .expect("ASCII export")
                .to_owned();
            cursor = name_start + name_len + 1;
            let child_offset = read_uleb(trie, &mut cursor) as usize;
            children.push((name, child_offset));
        }
        children
            .into_iter()
            .map(|(name, mut child)| {
                let terminal_size = read_uleb(trie, &mut child);
                assert!(terminal_size >= 2);
                assert_eq!(read_uleb(trie, &mut child), 0, "regular export");
                (name, read_uleb(trie, &mut child))
            })
            .collect()
    }

    fn symbols(bytes: &[u8]) -> BTreeMap<String, (u8, u64)> {
        let (_, command, _) = load_commands(bytes)
            .into_iter()
            .find(|(kind, _, _)| *kind == macho::LC_SYMTAB)
            .expect("LC_SYMTAB");
        let symoff = read_u32(bytes, command + 8) as usize;
        let nsyms = read_u32(bytes, command + 12) as usize;
        let stroff = read_u32(bytes, command + 16) as usize;
        (0..nsyms)
            .map(|index| {
                let nlist = symoff + index * 16;
                let name_offset = read_u32(bytes, nlist) as usize;
                let name_start = stroff + name_offset + 1;
                let name_len = bytes[name_start..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .expect("terminated symbol");
                let name = std::str::from_utf8(&bytes[name_start..name_start + name_len])
                    .expect("ASCII symbol")
                    .to_owned();
                (name, (bytes[nlist + 5], read_u64(bytes, nlist + 8)))
            })
            .collect()
    }

    fn placeholder_code(pair_count: usize) -> Vec<u8> {
        let mut code = Vec::with_capacity(pair_count * 8);
        for _ in 0..pair_count {
            code.extend_from_slice(&ADRP_X15.to_le_bytes());
            code.extend_from_slice(&ADD_X15_X15_0.to_le_bytes());
        }
        code
    }

    fn decode_code_to_data_address(code: &[u8], adrp_offset: u32, code_addr: u64) -> u64 {
        let adrp_offset = adrp_offset as usize;
        let adrp = read_u32(code, adrp_offset);
        let add = read_u32(code, adrp_offset + 4);
        let imm21 = (((adrp >> 5) & 0x7ffff) << 2) | ((adrp >> 29) & 0x3);
        let page_delta = i64::from(((imm21 << 11) as i32) >> 11);
        let pc_page = (code_addr + adrp_offset as u64) & !0xfff;
        let target_page = (i128::from(pc_page) + i128::from(page_delta) * 4096) as u64;
        target_page + u64::from((add >> 10) & 0xfff)
    }

    fn text_export(name: &str, offset: u32) -> AotExport<'_> {
        AotExport {
            name,
            section: AotSection::Text,
            offset,
        }
    }

    #[test]
    fn rejects_code_that_is_not_whole_instructions() {
        // A truncated blob would emit a dylib that faults on entry rather than
        // failing here, so this must be caught before anything is written.
        let truncated = AotImage {
            code: &MOV42_RET[..5],
            data: &[],
            exports: &[],
            relocations: &[],
        };
        assert!(matches!(
            validate(&truncated),
            Err(AotEmitError::CodeNotInstructionAligned(5))
        ));
        let empty = AotImage {
            code: &[],
            data: &[],
            exports: &[],
            relocations: &[],
        };
        assert!(matches!(
            validate(&empty),
            Err(AotEmitError::CodeNotInstructionAligned(0))
        ));
    }

    #[test]
    fn rejects_exports_outside_the_code_blob() {
        let past_end = AotExport {
            name: "carrick_aot_entry",
            section: AotSection::Text,
            offset: 8,
        };
        let image = AotImage {
            code: &MOV42_RET,
            data: &[],
            exports: &[past_end],
            relocations: &[],
        };
        assert!(matches!(
            validate(&image),
            Err(AotEmitError::ExportOutOfRange { offset: 8, .. })
        ));
        let misaligned = AotExport {
            name: "carrick_aot_entry",
            section: AotSection::Text,
            offset: 2,
        };
        let image = AotImage {
            code: &MOV42_RET,
            data: &[],
            exports: &[misaligned],
            relocations: &[],
        };
        assert!(matches!(
            validate(&image),
            Err(AotEmitError::ExportOutOfRange { offset: 2, .. })
        ));
    }

    #[test]
    fn emits_text_data_and_linkedit_with_exact_protections() {
        let data = [0x5a; 16];
        let exports = [
            text_export("carrick_aot_entry", 0),
            AotExport {
                name: "carrick_aot_data",
                section: AotSection::Data,
                offset: 0,
            },
        ];
        let bytes = emit_dylib(&AotImage {
            code: &MOV42_RET,
            data: &data,
            exports: &exports,
            relocations: &[],
        })
        .expect("emit text and writable data");
        let segments = segments(&bytes);
        assert_eq!(
            segments
                .iter()
                .map(|segment| segment.name.as_str())
                .collect::<Vec<_>>(),
            ["__TEXT", "__DATA", "__LINKEDIT"]
        );

        let text = &segments[0];
        let data_segment = &segments[1];
        let linkedit = &segments[2];
        assert_eq!((text.maxprot, text.initprot), (5, 5), "text must be r-x");
        assert_eq!(
            (data_segment.maxprot, data_segment.initprot),
            (3, 3),
            "data must be rw-"
        );
        assert_eq!(
            (linkedit.maxprot, linkedit.initprot),
            (1, 1),
            "linkedit must be r--"
        );
        assert_eq!(data_segment.maxprot & macho::VM_PROT_EXECUTE, 0);
        assert_eq!(data_segment.vmaddr % macho::PAGE, 0);
        assert_eq!(data_segment.fileoff % macho::PAGE, 0);
        assert_eq!(data_segment.filesize, data.len() as u64);
        assert_eq!(data_segment.vmsize, macho::PAGE);
        assert_eq!(linkedit.vmaddr, data_segment.vmaddr + data_segment.vmsize);
        assert_eq!(linkedit.fileoff, data_segment.fileoff + data_segment.vmsize);

        let text_section = section(&segments, "__TEXT");
        let data_section = section(&segments, "__DATA");
        assert_eq!(text_section.name, "__text");
        assert_eq!(text_section.align, 2);
        assert_eq!(data_section.name, "__data");
        assert_eq!(data_section.align, 3);
        assert_eq!(data_section.addr % 8, 0);
        assert_eq!(data_section.offset % 8, 0);
        assert_eq!(data_section.size, data.len() as u64);
        assert_eq!(
            &bytes[data_section.offset as usize..data_section.offset as usize + data.len()],
            &data
        );
    }

    #[test]
    fn exports_resolve_to_their_declared_sections() {
        let data = [0x11; 16];
        let exports = [
            text_export("text_entry", 4),
            AotExport {
                name: "data_cell",
                section: AotSection::Data,
                offset: 8,
            },
        ];
        let bytes = emit_dylib(&AotImage {
            code: &MOV42_RET,
            data: &data,
            exports: &exports,
            relocations: &[],
        })
        .expect("emit section-aware exports");
        let segments = segments(&bytes);
        let text_addr = section(&segments, "__TEXT").addr;
        let data_addr = section(&segments, "__DATA").addr;
        let nlists = symbols(&bytes);
        assert_eq!(nlists["text_entry"], (1, text_addr + 4));
        assert_eq!(nlists["data_cell"], (2, data_addr + 8));

        let trie = exported_addresses(&bytes);
        assert_eq!(trie["text_entry"], text_addr + 4);
        assert_eq!(trie["data_cell"], data_addr + 8);
    }

    #[test]
    fn patches_positive_and_negative_adrp_displacements() {
        let code = placeholder_code(1);
        let data = [0; 16];
        let relocations = [AotCodeToDataRelocation {
            adrp_offset: 0,
            add_offset: 4,
            data_offset: 8,
        }];
        let bytes = emit_dylib(&AotImage {
            code: &code,
            data: &data,
            exports: &[],
            relocations: &relocations,
        })
        .expect("patch positive relocation");
        let segments = segments(&bytes);
        let text = section(&segments, "__TEXT");
        let data = section(&segments, "__DATA");
        let emitted_code = &bytes[text.offset as usize..text.offset as usize + text.size as usize];
        assert_eq!(
            decode_code_to_data_address(emitted_code, 0, text.addr),
            data.addr + 8
        );

        // Exercise the signed half of ADRP encoding directly: conventional
        // Mach-O layout places data after text, while the instruction encoding
        // must still preserve the full signed architectural range.
        let mut negative_code = placeholder_code(1);
        patch_code_to_data_relocations(&mut negative_code, 0x9000, 0x2000, 16, &relocations)
            .expect("patch negative relocation");
        assert_eq!(
            decode_code_to_data_address(&negative_code, 0, 0x9000),
            0x2008
        );
    }

    #[test]
    fn rejects_unaligned_out_of_range_or_wrong_shape_relocations() {
        fn assert_emit_rejected(code: &[u8], data: &[u8], relocation: AotCodeToDataRelocation) {
            let image = AotImage {
                code,
                data,
                exports: &[],
                relocations: &[relocation],
            };
            assert!(
                matches!(
                    emit_dylib(&image),
                    Err(AotEmitError::RelocationInvalid { .. })
                ),
                "relocation must be rejected: {relocation:?}"
            );
        }

        let code = placeholder_code(1);
        let data = [0; 16];
        assert_emit_rejected(
            &code,
            &data,
            AotCodeToDataRelocation {
                adrp_offset: 2,
                add_offset: 4,
                data_offset: 0,
            },
        );
        assert_emit_rejected(
            &code,
            &data,
            AotCodeToDataRelocation {
                adrp_offset: 0,
                add_offset: code.len() as u32,
                data_offset: 0,
            },
        );
        let mut wrong_adrp = code.clone();
        wrong_adrp[..4].copy_from_slice(&0xd503_201f_u32.to_le_bytes());
        assert_emit_rejected(
            &wrong_adrp,
            &data,
            AotCodeToDataRelocation {
                adrp_offset: 0,
                add_offset: 4,
                data_offset: 0,
            },
        );
        let mut wrong_add = code.clone();
        wrong_add[4..8].copy_from_slice(&(ADD_X15_X15_0 | (1 << 10)).to_le_bytes());
        assert_emit_rejected(
            &wrong_add,
            &data,
            AotCodeToDataRelocation {
                adrp_offset: 0,
                add_offset: 4,
                data_offset: 0,
            },
        );
        for data_offset in [1, data.len() as u32] {
            assert_emit_rejected(
                &code,
                &data,
                AotCodeToDataRelocation {
                    adrp_offset: 0,
                    add_offset: 4,
                    data_offset,
                },
            );
        }

        let mut too_far = code.clone();
        let original = too_far.clone();
        let error =
            patch_code_to_data_relocations(&mut too_far, 0, 1_u64 << 32, 16, &[relocations()[0]])
                .expect_err("positive 2^20-page displacement is out of range");
        assert!(matches!(error, AotEmitError::RelocationInvalid { .. }));
        assert_eq!(too_far, original, "rejected patch must not mutate code");

        let mut too_far = code.clone();
        let original = too_far.clone();
        let error = patch_code_to_data_relocations(
            &mut too_far,
            (1_u64 << 32) + 4096,
            0,
            16,
            &[relocations()[0]],
        )
        .expect_err("negative displacement below -2^20 pages is out of range");
        assert!(matches!(error, AotEmitError::RelocationInvalid { .. }));
        assert_eq!(too_far, original, "rejected patch must not mutate code");

        let mut all_or_nothing = placeholder_code(2);
        all_or_nothing[12..16].copy_from_slice(&0xd503_201f_u32.to_le_bytes());
        let original = all_or_nothing.clone();
        let relocations = [
            AotCodeToDataRelocation {
                adrp_offset: 0,
                add_offset: 4,
                data_offset: 0,
            },
            AotCodeToDataRelocation {
                adrp_offset: 8,
                add_offset: 12,
                data_offset: 8,
            },
        ];
        patch_code_to_data_relocations(&mut all_or_nothing, 0, 0x4000, 16, &relocations)
            .expect_err("late wrong-shape relocation must reject the whole set");
        assert_eq!(
            all_or_nothing, original,
            "no relocation may patch until the complete set validates"
        );
    }

    fn relocations() -> [AotCodeToDataRelocation; 1] {
        [AotCodeToDataRelocation {
            adrp_offset: 0,
            add_offset: 4,
            data_offset: 0,
        }]
    }

    #[test]
    fn rejects_overflowing_layout_and_linkedit_offsets_without_allocating() {
        fn lengths(code_len: u64, data_len: u64) -> AotLayoutLengths {
            AotLayoutLengths {
                sizeofcmds: if data_len == 0 { 456 } else { 608 },
                code_len,
                data_len,
                trie_len: 0,
                nlists_len: 0,
                strtab_len: 0,
                export_count: 0,
            }
        }

        fn assert_overflow(input: AotLayoutLengths, field: &'static str) {
            assert!(
                matches!(
                    checked_layout(input),
                    Err(AotEmitError::LayoutOverflow {
                        field: actual
                    }) if actual == field
                ),
                "{field} must reject arithmetic overflow"
            );
        }

        fn assert_narrowing(input: AotLayoutLengths, field: &'static str) {
            assert!(
                matches!(
                    checked_layout(input),
                    Err(AotEmitError::MachOFieldOutOfRange {
                        field: actual,
                        ..
                    }) if actual == field
                ),
                "{field} must reject u32 truncation"
            );
        }

        // With data, the fixed command layout puts code at byte 896.
        assert_overflow(lengths(8, u64::MAX), "data vmsize");
        let last_u64_page = !(macho::PAGE - 1);
        assert_overflow(lengths(last_u64_page - 896, macho::PAGE), "linkedit offset");
        let mut output_length = lengths(8, 0);
        output_length.strtab_len = last_u64_page;
        assert_overflow(output_length, "output length");

        // With no data, the fixed command layout puts code at byte 744.
        assert_narrowing(lengths(u64::from(u32::MAX) + 1 - 744, 0), "linkedit offset");
        let last_u32_page = u64::from(u32::MAX) & !(macho::PAGE - 1);
        let code_len = last_u32_page - 744;

        let mut symoff = lengths(code_len, 0);
        symoff.trie_len = macho::PAGE;
        assert_narrowing(symoff, "symbol table offset");

        let mut stroff = lengths(code_len, 0);
        stroff.trie_len = 8;
        stroff.nlists_len = macho::PAGE - 8;
        assert_narrowing(stroff, "string table offset");

        let mut trie_size = lengths(8, 0);
        trie_size.trie_len = u64::from(u32::MAX) + 1;
        assert_narrowing(trie_size, "export trie size");

        let mut string_size = lengths(8, 0);
        string_size.strtab_len = u64::from(u32::MAX) + 1;
        assert_narrowing(string_size, "string table size");

        let mut symbol_count = lengths(8, 0);
        symbol_count.export_count = u64::from(u32::MAX) + 1;
        assert_narrowing(symbol_count, "symbol count");
    }

    #[test]
    fn rejects_an_export_trie_child_count_that_does_not_fit() {
        let exports = (0..=u8::MAX)
            .map(|index| (format!("symbol_{index}"), u64::from(index)))
            .collect::<Vec<_>>();
        assert!(matches!(
            export_trie(&exports),
            Err(AotEmitError::MachOFieldOutOfRange {
                field: "export trie child count",
                value: 256,
            })
        ));
    }

    #[test]
    fn rejects_a_data_export_when_no_data_section_exists() {
        let export = AotExport {
            name: "missing_data",
            section: AotSection::Data,
            offset: 0,
        };
        let image = AotImage {
            code: &MOV42_RET,
            data: &[],
            exports: &[export],
            relocations: &[],
        };
        assert!(matches!(
            emit_dylib(&image),
            Err(AotEmitError::ExportOutOfRange {
                section: AotSection::Data,
                ..
            })
        ));
    }

    /// THE stage-1 proof: emit -> ad-hoc sign -> `dlopen` -> `dlsym` -> CALL.
    ///
    /// Nothing short of executing the code proves the emitted Mach-O is real.
    /// A structurally-plausible-but-wrong dylib fails at `dlopen` or faults on
    /// entry, and both are exactly the bugs this stage exists to catch.
    ///
    /// There is deliberately NO linker step: `emit_dylib` produces `MH_DYLIB`
    /// directly. Signing still shells out to `codesign` here because the test is
    /// proving the FORMAT; replacing it with an in-process signer is a separate
    /// decision (measured: `codesign` costs 0.03 s at 16 MiB — fine for a test,
    /// too slow for a hot path).
    #[test]
    fn emitted_dylib_is_signable_loadable_and_executable() {
        let entry = text_export("carrick_aot_entry", 0);
        let bytes = emit_dylib(&AotImage {
            code: &MOV42_RET,
            data: &[],
            exports: &[entry],
            relocations: &[],
        })
        .expect("emit a one-instruction unit");

        let dir = std::env::temp_dir().join(format!("carrick-aot-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("unit.dylib");
        std::fs::write(&path, &bytes).expect("write the emitted unit");

        // AMFI refuses to map an unsigned file executable, so an unsigned unit
        // would fail `dlopen` no matter how correct the Mach-O is.
        let signed = std::process::Command::new("/usr/bin/codesign")
            .args(["-s", "-"])
            .arg(&path)
            .output()
            .expect("run codesign");
        assert!(
            signed.status.success(),
            "ad-hoc signing the emitted unit failed: {}",
            String::from_utf8_lossy(&signed.stderr)
        );

        let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("cstring");
        // SAFETY: `c_path` is a live NUL-terminated path to a file this test
        // just wrote and signed.
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW) };
        assert!(
            !handle.is_null(),
            "dlopen of the emitted unit failed: {}",
            // SAFETY: dlerror returns a static NUL-terminated string or null.
            unsafe {
                let e = libc::dlerror();
                if e.is_null() {
                    "(no dlerror)".to_owned()
                } else {
                    std::ffi::CStr::from_ptr(e).to_string_lossy().into_owned()
                }
            }
        );

        let sym = std::ffi::CString::new(entry.name).expect("cstring");
        // SAFETY: `handle` is a live dlopen handle; the symbol was exported by
        // `emit_dylib` at offset 0 of the code blob.
        let addr = unsafe { libc::dlsym(handle, sym.as_ptr()) };
        assert!(!addr.is_null(), "dlsym({:?}) found nothing", entry.name);

        // SAFETY: the symbol addresses `mov w0,#42; ret` - a leaf function
        // taking no arguments and returning an int, matching this signature.
        let f: extern "C" fn() -> i32 = unsafe { std::mem::transmute(addr) };
        assert_eq!(f(), 42, "executed the emitted unit but got the wrong value");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn accepts_a_well_formed_unit() {
        let entry = text_export("carrick_aot_entry", 0);
        let image = AotImage {
            code: &MOV42_RET,
            data: &[],
            exports: &[entry],
            relocations: &[],
        };
        assert!(validate(&image).is_ok());
    }
}
