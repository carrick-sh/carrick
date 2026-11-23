//! The ring's Rust-panic record, carried in registers across a fatal crossing.
//!
//! A ring panic has no memory it can trust to publish through, so the record
//! is a fixed set of words: the source location and the head of the message.
//! The ring builds it in its panic handler and the host decodes it at the
//! stopped fatal exit, so a panic ends the run with a named site instead of a
//! halted CPU nobody wakes.

use core::fmt;

/// Bytes of the panic location's file path kept (its tail: the crate-relative end).
pub const PANIC_FILE_TAIL_BYTES: usize = 24;
/// Bytes of the formatted panic message kept (its head).
pub const PANIC_MESSAGE_BYTES: usize = 48;
/// Words in the register image of one [`PanicReport`].
pub const PANIC_REPORT_WORDS: usize = 1 + PANIC_FILE_TAIL_BYTES / 8 + PANIC_MESSAGE_BYTES / 8;

/// What raised a [`PanicReport`]: the first word of its fatal crossing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanicReportKind {
    /// A Rust panic in the ring, at its panic location.
    Panic,
    /// A carrier refusing a broken invariant (`fatal_boot`), at its raising site.
    FatalSite,
}

impl PanicReportKind {
    /// The crossing's first word for this kind.
    pub const fn sentinel(self) -> u64 {
        match self {
            Self::Panic => PanicReport::SENTINEL,
            Self::FatalSite => PanicReport::FATAL_SITE_SENTINEL,
        }
    }

    /// The kind a crossing's first word names, if it carries a record.
    pub const fn from_sentinel(word: u64) -> Option<Self> {
        match word {
            PanicReport::SENTINEL => Some(Self::Panic),
            PanicReport::FATAL_SITE_SENTINEL => Some(Self::FatalSite),
            _ => None,
        }
    }
}

/// One ring panic or carrier fatal: where it was raised and how its message starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanicReport {
    line: u32,
    column: u32,
    file_tail: [u8; PANIC_FILE_TAIL_BYTES],
    message: [u8; PANIC_MESSAGE_BYTES],
}

impl PanicReport {
    /// First word of the fatal crossing that carries a panic record. It is
    /// distinct from [`crate::PANIC_SENTINEL`], whose other fatal crossings
    /// carry no record.
    pub const SENTINEL: u64 = 0xDEAD_CAFE_9A41_C0DE;
    /// First word of the fatal crossing that carries a carrier fatal's
    /// raising site ([`PanicReportKind::FatalSite`]).
    pub const FATAL_SITE_SENTINEL: u64 = 0xDEAD_CAFE_9A41_F5E5;

    /// A record for the caller's source site, with `what` as its message.
    #[track_caller]
    pub fn at_caller(what: &str) -> Self {
        use fmt::Write;
        let location = core::panic::Location::caller();
        let mut report = Self::new(location.file(), location.line(), location.column());
        let _ = report.message_writer().write_str(what);
        report
    }

    /// A record for a panic raised at `file:line:column`, with an empty message.
    pub fn new(file: &str, line: u32, column: u32) -> Self {
        let bytes = file.as_bytes();
        let tail = &bytes[bytes.len().saturating_sub(PANIC_FILE_TAIL_BYTES)..];
        let mut file_tail = [0; PANIC_FILE_TAIL_BYTES];
        file_tail[..tail.len()].copy_from_slice(tail);
        Self {
            line,
            column,
            file_tail,
            message: [0; PANIC_MESSAGE_BYTES],
        }
    }

    /// Format the panic message into the record. Text past its capacity is dropped.
    pub fn message_writer(&mut self) -> PanicMessageWriter<'_> {
        PanicMessageWriter {
            message: &mut self.message,
            used: 0,
        }
    }

    pub const fn line(&self) -> u32 {
        self.line
    }

    pub const fn column(&self) -> u32 {
        self.column
    }

    /// The register image: line and column, then the file tail, then the message.
    pub fn words(&self) -> [u64; PANIC_REPORT_WORDS] {
        let mut words = [0; PANIC_REPORT_WORDS];
        words[0] = (u64::from(self.line) << 32) | u64::from(self.column);
        let text = self
            .file_tail
            .chunks_exact(8)
            .chain(self.message.chunks_exact(8));
        for (word, chunk) in words[1..].iter_mut().zip(text) {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(chunk);
            *word = u64::from_le_bytes(bytes);
        }
        words
    }

    /// Decode a register image. Every image decodes; the text is shown lossily.
    pub fn from_words(words: [u64; PANIC_REPORT_WORDS]) -> Self {
        let mut report = Self {
            line: (words[0] >> 32) as u32,
            column: words[0] as u32,
            file_tail: [0; PANIC_FILE_TAIL_BYTES],
            message: [0; PANIC_MESSAGE_BYTES],
        };
        let text = report
            .file_tail
            .chunks_exact_mut(8)
            .chain(report.message.chunks_exact_mut(8));
        for (chunk, word) in text.zip(&words[1..]) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        report
    }
}

fn write_text(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
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

impl fmt::Display for PanicReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_text(f, &self.file_tail)?;
        write!(f, ":{}:{}: ", self.line, self.column)?;
        write_text(f, &self.message)
    }
}

/// Bounded `fmt::Write` over a [`PanicReport`]'s message. It never fails, so
/// formatting a panic message cannot itself panic on capacity.
pub struct PanicMessageWriter<'a> {
    message: &'a mut [u8; PANIC_MESSAGE_BYTES],
    used: usize,
}

impl fmt::Write for PanicMessageWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let room = &mut self.message[self.used..];
        let kept = text.len().min(room.len());
        room[..kept].copy_from_slice(&text.as_bytes()[..kept]);
        self.used += kept;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::fmt::Write;
    use std::string::ToString;

    #[test]
    fn panic_report_round_trips_through_its_register_image() {
        let mut report = PanicReport::new("crates/carrick-el1/src/alloc.rs", 41, 9);
        write!(
            report.message_writer(),
            "memory allocation of {} bytes failed",
            115_343_360
        )
        .unwrap();
        let decoded = PanicReport::from_words(report.words());
        assert_eq!(decoded, report);
        assert_eq!(
            decoded.to_string(),
            "carrick-el1/src/alloc.rs:41:9: memory allocation of 115343360 bytes failed"
        );
    }

    #[test]
    fn a_fatal_site_record_names_its_caller_and_kind() {
        let line = line!() + 1;
        let report = PanicReport::at_caller("fatal_boot");
        assert_eq!(report.line(), line);
        assert!(
            report
                .to_string()
                .ends_with(&std::format!("src/panic_report.rs:{line}:22: fatal_boot")),
            "{report}"
        );
        for kind in [PanicReportKind::Panic, PanicReportKind::FatalSite] {
            assert_eq!(PanicReportKind::from_sentinel(kind.sentinel()), Some(kind));
        }
        assert_eq!(PanicReportKind::from_sentinel(crate::PANIC_SENTINEL), None);
    }

    #[test]
    fn panic_report_truncates_a_long_message_and_shows_foreign_bytes_lossily() {
        let mut report = PanicReport::new("a.rs", 1, 2);
        let mut writer = report.message_writer();
        for _ in 0..10 {
            write!(writer, "0123456789").unwrap();
        }
        assert_eq!(
            report.to_string(),
            "a.rs:1:2: 012345678901234567890123456789012345678901234567"
        );
        let mut words = [0; PANIC_REPORT_WORDS];
        words[1] = u64::from_le_bytes([b'x', 0xff, 0x07, b'y', 0, 0, 0, 0]);
        assert_eq!(PanicReport::from_words(words).to_string(), "x??y:0:0: ");
    }
}
