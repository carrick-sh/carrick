//! One linked CPL0 image's loaded span against its supervisor extent.
//!
//! Shared by `cpl0_build.rs` (the build-time budget report) and
//! `tests/cpl0_image_inputs.rs` (its witness), both by `#[path]`. Every read
//! and every offset is checked: a truncated or malformed image is `None`,
//! never a panic.

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

struct Elf<'a>(&'a [u8]);

impl Elf<'_> {
    fn bytes<const N: usize>(&self, at: usize) -> Option<[u8; N]> {
        self.0.get(at..at.checked_add(N)?)?.try_into().ok()
    }
    fn u16(&self, at: usize) -> Option<usize> {
        Some(usize::from(u16::from_le_bytes(self.bytes(at)?)))
    }
    fn u32(&self, at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(at)?))
    }
    fn u64(&self, at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(at)?))
    }
    fn offset(&self, at: usize) -> Option<usize> {
        usize::try_from(self.u64(at)?).ok()
    }
    /// The `index`th fixed-size entry of a table at `base`.
    fn entry(base: usize, index: usize, len: usize) -> Option<usize> {
        base.checked_add(index.checked_mul(len)?)
    }
}

impl ImageBudget {
    /// Read the lowest and highest loaded addresses (`PT_LOAD` memory
    /// size, so `.bss` counts) and [`EXTENT_END_SYMBOL`]'s value from an
    /// ELF64 little-endian image.
    pub fn of(image: &[u8]) -> Option<Self> {
        let elf = Elf(image);
        // ELFMAG, ELFCLASS64, ELFDATA2LSB.
        if image.get(..6)? != b"\x7fELF\x02\x01" {
            return None;
        }
        let (phoff, phentsize, phnum) = (elf.offset(0x20)?, elf.u16(0x36)?, elf.u16(0x38)?);
        let (shoff, shentsize, shnum) = (elf.offset(0x28)?, elf.u16(0x3a)?, elf.u16(0x3c)?);
        if phentsize < PHDR_LEN || shentsize < SHDR_LEN {
            return None;
        }
        let (mut base, mut end) = (u64::MAX, 0_u64);
        for index in 0..phnum {
            let header = Elf::entry(phoff, index, phentsize)?;
            let memsz = elf.u64(header.checked_add(0x28)?)?;
            if elf.u32(header)? == PT_LOAD && memsz != 0 {
                let start = elf.u64(header.checked_add(0x10)?)?;
                base = base.min(start);
                end = end.max(start.checked_add(memsz)?);
            }
        }
        let section = |index: usize| Elf::entry(shoff, index, shentsize);
        let mut extent_end = None;
        for index in 0..shnum {
            let symtab = section(index)?;
            if elf.u32(symtab.checked_add(4)?)? != SHT_SYMTAB {
                continue;
            }
            let link = usize::try_from(elf.u32(symtab.checked_add(0x28)?)?).ok()?;
            if link >= shnum {
                return None;
            }
            let strtab = section(link)?;
            if elf.u32(strtab.checked_add(4)?)? != SHT_STRTAB {
                return None;
            }
            let names = elf.offset(strtab.checked_add(0x18)?)?;
            let names =
                image.get(names..names.checked_add(elf.offset(strtab.checked_add(0x20)?)?)?)?;
            let symbols = elf.offset(symtab.checked_add(0x18)?)?;
            let size = elf.offset(symtab.checked_add(0x20)?)?;
            let entsize = elf.offset(symtab.checked_add(0x38)?)?;
            if entsize < SYM_LEN {
                return None;
            }
            for symbol in 0..size / entsize {
                let symbol = Elf::entry(symbols, symbol, entsize)?;
                let name = usize::try_from(elf.u32(symbol)?).ok()?;
                let name = names.get(name..)?.split(|&byte| byte == 0).next()?;
                if name == EXTENT_END_SYMBOL {
                    extent_end = Some(elf.u64(symbol.checked_add(8)?)?);
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
