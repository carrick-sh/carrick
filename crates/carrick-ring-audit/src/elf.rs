//! A ring image's loaded data words, as `llvm-objdump` prints them.
//!
//! The x86_64 ring image calls through `[rip + disp]` slots whose contents
//! the linker fixed to function addresses; the frame audit reads those words
//! to recover the direct callee. The audit reads the image only through the
//! toolchain's `llvm-objdump`, never the file system.

use crate::frames::Arch;

/// The loaded data sections of a ring image.
pub struct ElfData {
    pub arch: Arch,
    sections: Vec<(u64, Vec<u8>)>,
}

/// The architecture named by `llvm-objdump`'s `file format` line.
pub fn arch_of(objdump_output: &str) -> Result<Arch, String> {
    let format = objdump_output
        .lines()
        .find_map(|line| {
            line.split_once("file format ")
                .map(|(_, format)| format.trim())
        })
        .ok_or("llvm-objdump printed no file format")?;
    match format {
        "elf64-littleaarch64" => Ok(Arch::Aarch64),
        "elf64-x86-64" => Ok(Arch::X86_64),
        other => Err(format!("not a ring image format: {other}")),
    }
}

/// The names of the loaded data sections in `llvm-objdump -h` output.
pub fn data_sections(headers: &str) -> Vec<String> {
    headers
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() == 5 && fields[4] == "DATA" && fields[0].parse::<u32>().is_ok())
                .then(|| fields[1].to_owned())
        })
        .collect()
}

impl ElfData {
    /// Parse `llvm-objdump -s` output for the data sections.
    pub fn parse(arch: Arch, contents: &str) -> Result<Self, String> {
        let mut sections: Vec<(u64, Vec<u8>)> = Vec::new();
        for line in contents.lines() {
            if line.starts_with("Contents of section ") {
                sections.push((0, Vec::new()));
                continue;
            }
            let Some(rest) = line.strip_prefix(' ') else {
                continue;
            };
            let Some((section_base, bytes)) = sections.last_mut() else {
                continue;
            };
            let mut fields = rest.split_whitespace();
            let Some(address) = fields.next().and_then(|a| u64::from_str_radix(a, 16).ok()) else {
                continue;
            };
            if bytes.is_empty() {
                *section_base = address;
            }
            // Up to four groups of eight hex digits, then the ASCII column.
            for group in fields.take(4) {
                if group.len() % 2 != 0 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
                    break;
                }
                for pair in group.as_bytes().chunks_exact(2) {
                    let text = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
                    bytes.push(u8::from_str_radix(text, 16).map_err(|e| e.to_string())?);
                }
            }
        }
        Ok(Self { arch, sections })
    }

    /// The little-endian word the image loads at `address`, if any section
    /// holds all eight bytes.
    pub fn word_at(&self, address: u64) -> Option<u64> {
        self.sections.iter().find_map(|(base, data)| {
            let offset = usize::try_from(address.checked_sub(*base)?).ok()?;
            let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
            Some(u64::from_le_bytes(bytes))
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn objdump_section_dumps_yield_little_endian_words() {
        let headers = "x:\tfile format elf64-x86-64\n\nSections:\n\
            Idx Name Size VMA Type\n  3 .text 000e896f ffffffff80003000 TEXT\n\
            \x20 4 .rodata 00000010 ffffffff800ec000 DATA\n  6 .bss 00001a10 ffffffff800fc000 BSS\n";
        assert_eq!(arch_of(headers).expect("format"), Arch::X86_64);
        assert_eq!(data_sections(headers), [".rodata"]);
        let contents = "Contents of section .rodata:\n\
            \x20ffffffff800ec000 50330080 ffffffff 01020304 05060708  P3..............\n";
        let data = ElfData::parse(Arch::X86_64, contents).expect("contents");
        assert_eq!(
            data.word_at(0xffff_ffff_800e_c000),
            Some(0xffff_ffff_8000_3350)
        );
        assert_eq!(data.word_at(0xffff_ffff_800e_c009), None);
    }
}
