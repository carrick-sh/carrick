//! A kernel source site carried across a terminal crossing as plain words.
//!
//! A terminal crossing (a ring panic, a carrier fatal, a native run failure)
//! ends the run, so the host has one chance to name where it was raised. The
//! site is the crate-relative tail of the file path, the line and the column,
//! packed into [`SOURCE_SITE_WORDS`] words that any wire record can carry.

use core::fmt;

/// Bytes of a site's file path kept (its tail: the crate-relative end).
pub const SOURCE_SITE_FILE_TAIL_BYTES: usize = 24;
/// Words in the wire image of one [`SourceSite`].
pub const SOURCE_SITE_WORDS: usize = 1 + SOURCE_SITE_FILE_TAIL_BYTES / 8;

/// Where a terminal crossing was raised: `file_tail:line:column`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSite {
    line: u32,
    column: u32,
    file_tail: [u8; SOURCE_SITE_FILE_TAIL_BYTES],
}

impl SourceSite {
    /// The caller's source site (through every `#[track_caller]` frame).
    #[track_caller]
    pub fn caller() -> Self {
        let location = core::panic::Location::caller();
        Self::new(location.file(), location.line(), location.column())
    }

    /// The site `file:line:column`, keeping the tail of `file`.
    pub fn new(file: &str, line: u32, column: u32) -> Self {
        let bytes = file.as_bytes();
        let tail = &bytes[bytes.len().saturating_sub(SOURCE_SITE_FILE_TAIL_BYTES)..];
        let mut file_tail = [0; SOURCE_SITE_FILE_TAIL_BYTES];
        file_tail[..tail.len()].copy_from_slice(tail);
        Self {
            line,
            column,
            file_tail,
        }
    }

    pub const fn line(&self) -> u32 {
        self.line
    }

    pub const fn column(&self) -> u32 {
        self.column
    }

    /// The wire image: line and column, then the file tail.
    pub fn words(&self) -> [u64; SOURCE_SITE_WORDS] {
        let mut words = [0; SOURCE_SITE_WORDS];
        words[0] = (u64::from(self.line) << 32) | u64::from(self.column);
        for (word, chunk) in words[1..].iter_mut().zip(self.file_tail.chunks_exact(8)) {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(chunk);
            *word = u64::from_le_bytes(bytes);
        }
        words
    }

    /// Decode a wire image. Every image decodes; the file is shown lossily.
    pub fn from_words(words: [u64; SOURCE_SITE_WORDS]) -> Self {
        let mut site = Self {
            line: (words[0] >> 32) as u32,
            column: words[0] as u32,
            file_tail: [0; SOURCE_SITE_FILE_TAIL_BYTES],
        };
        for (chunk, word) in site.file_tail.chunks_exact_mut(8).zip(&words[1..]) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        site
    }
}

/// Write NUL-terminated wire text, showing foreign bytes as `?`.
pub fn write_wire_text(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    use fmt::Write;
    for &byte in bytes.iter().take_while(|&&byte| byte != 0) {
        f.write_char(if byte == b' ' || byte.is_ascii_graphic() {
            char::from(byte)
        } else {
            '?'
        })?;
    }
    Ok(())
}

impl fmt::Display for SourceSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_wire_text(f, &self.file_tail)?;
        write!(f, ":{}:{}", self.line, self.column)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::ToString;

    #[test]
    fn a_source_site_round_trips_through_its_wire_image() {
        let site = SourceSite::new("crates/carrick-el1/src/alloc.rs", 41, 9);
        let decoded = SourceSite::from_words(site.words());
        assert_eq!(decoded, site);
        assert_eq!(decoded.to_string(), "carrick-el1/src/alloc.rs:41:9");
        let line = line!() + 1;
        let here = SourceSite::caller();
        assert_eq!(here.line(), line);
        assert!(
            here.to_string()
                .ends_with(&std::format!("src/source_site.rs:{line}:20"))
        );
        let mut words = [0; SOURCE_SITE_WORDS];
        words[1] = u64::from_le_bytes([b'x', 0xff, 0x07, b'y', 0, 0, 0, 0]);
        assert_eq!(SourceSite::from_words(words).to_string(), "x??y:0:0");
    }
}
