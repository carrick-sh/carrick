//! One linked CPL0 image's loaded span against its supervisor extent.
//!
//! Shared by `cpl0_build.rs` (the build-time budget report) and
//! `tests/cpl0_image_inputs.rs` (its witness), both by `#[path]`.
//!
//! What it guarantees: it never panics, and it reads a budget only from
//! structures that lie whole in the file. The header must be ELF64
//! little-endian; each table it reads (program headers, section headers, a
//! symbol table) is checked whole against the file before any entry is
//! read; every `PT_LOAD`'s file bytes lie in the file and within its memory
//! size; and every symbol name ends inside its string table. Anything else
//! is `None`. It is a report, not an ELF validator: fields it does not use
//! (such as `EI_VERSION`) are not checked, and `link.ld`'s assert stays the
//! enforcement of the extent.

/// The image's own extent symbol: `carrick-x86-carrier` defines it from
/// `X86_CPL0_SUPERVISOR_IMAGE_BASE + X86_CPL0_SUPERVISOR_IMAGE_SIZE`, and
/// `link.ld` asserts against it. Reading it back from the linked image keeps
/// the report on that one constant.
pub const EXTENT_END_SYMBOL: &[u8] = b"CARRICK_X86_CPL0_IMAGE_END";

const PT_LOAD: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const PHDR_LEN: usize = 56;
const SHDR_LEN: usize = 64;
const SYM_LEN: usize = 24;

/// One linked image's loaded span and extent, measured from its lowest
/// loaded address.
#[derive(Debug, PartialEq, Eq)]
pub struct ImageBudget {
    pub loaded: u64,
    pub extent: u64,
}

/// Little-endian field reads from one bounded slice: a header, a table
/// entry, or the whole file.
#[derive(Clone, Copy)]
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn bytes<const N: usize>(self, at: usize) -> Option<[u8; N]> {
        self.0.get(at..at.checked_add(N)?)?.try_into().ok()
    }
    fn u16(self, at: usize) -> Option<usize> {
        Some(usize::from(u16::from_le_bytes(self.bytes(at)?)))
    }
    fn u32(self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(at)?))
    }
    fn u64(self, at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(at)?))
    }
    fn offset(self, at: usize) -> Option<usize> {
        usize::try_from(self.u64(at)?).ok()
    }
    /// The bytes `[offset, offset + len)`, wholly inside this slice.
    fn span(self, offset: usize, len: usize) -> Option<&'a [u8]> {
        self.0.get(offset..offset.checked_add(len)?)
    }
    /// A table of `count` entries of `entsize` bytes at `offset`, wholly
    /// inside this slice, each at least `min` bytes long.
    fn table(self, offset: usize, entsize: usize, count: usize, min: usize) -> Option<Vec<Self>> {
        if entsize < min {
            return None;
        }
        let table = self.span(offset, entsize.checked_mul(count)?)?;
        Some(table.chunks_exact(entsize).map(Fields).collect())
    }
}

impl ImageBudget {
    /// Read the lowest and highest loaded addresses (`PT_LOAD` memory
    /// size, so `.bss` counts) and [`EXTENT_END_SYMBOL`]'s value from an
    /// ELF64 little-endian image.
    pub fn of(image: &[u8]) -> Option<Self> {
        let elf = Fields(image);
        // ELFMAG, ELFCLASS64, ELFDATA2LSB.
        if image.get(..6)? != b"\x7fELF\x02\x01" {
            return None;
        }
        let programs = elf.table(elf.offset(0x20)?, elf.u16(0x36)?, elf.u16(0x38)?, PHDR_LEN)?;
        let sections = elf.table(elf.offset(0x28)?, elf.u16(0x3a)?, elf.u16(0x3c)?, SHDR_LEN)?;
        let (mut base, mut end) = (u64::MAX, 0_u64);
        for header in programs {
            if header.u32(0)? != PT_LOAD {
                continue;
            }
            // Every load segment's file bytes lie inside the file and
            // within its memory size, empty or not; only `.bss` may extend
            // past them.
            let (offset, filesz, memsz) =
                (header.offset(0x08)?, header.u64(0x20)?, header.u64(0x28)?);
            if filesz > memsz {
                return None;
            }
            elf.span(offset, usize::try_from(filesz).ok()?)?;
            if memsz != 0 {
                let start = header.u64(0x10)?;
                base = base.min(start);
                end = end.max(start.checked_add(memsz)?);
            }
        }
        let mut extent_end = None;
        for symtab in sections.iter().filter(|s| s.u32(4) == Some(SHT_SYMTAB)) {
            let strtab = sections.get(usize::try_from(symtab.u32(0x28)?).ok()?)?;
            if strtab.u32(4)? != SHT_STRTAB {
                return None;
            }
            let names = Fields(elf.span(strtab.offset(0x18)?, strtab.offset(0x20)?)?);
            let (size, entsize) = (symtab.offset(0x20)?, symtab.offset(0x38)?);
            // A declared size that is not a whole number of entries is a
            // malformed table, not a table with a short tail.
            if entsize == 0 || size % entsize != 0 {
                return None;
            }
            let symbols = elf.table(symtab.offset(0x18)?, entsize, size / entsize, SYM_LEN)?;
            for symbol in symbols {
                let name = names.0.get(usize::try_from(symbol.u32(0)?).ok()?..)?;
                // The name must end inside its string table.
                let name = &name[..name.iter().position(|&byte| byte == 0)?];
                if name == EXTENT_END_SYMBOL {
                    extent_end = Some(symbol.u64(8)?);
                }
            }
        }
        let extent_end = extent_end?;
        (base <= end && base <= extent_end).then(|| Self {
            loaded: end - base,
            extent: extent_end - base,
        })
    }
}
