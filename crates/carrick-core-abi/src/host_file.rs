//! Typed host-file crossing record for ring-owned (native) processes.
//!
//! A native process keeps one descriptor namespace, the ring's. When a call
//! genuinely crosses to the host (a host-backed descriptor or a host path),
//! the ring stages one contiguous record in its own memory: a fixed header,
//! the input bytes it copied from user memory, and an output area. The
//! carrier reads the header and input, performs the operation with the
//! caller's authority, and writes only the reply words and output area
//! before acknowledging the service ticket. The ring copies the output back
//! to user memory itself, so user-memory fault policy never leaves the ring.
//!
//! The record names descriptors by the caller's ring table and fd number; the
//! carrier resolves and pins them under that table at service time, which is
//! when Linux resolves a descriptor for an in-progress call.

/// Operations the carrier venue serves. Values are wire encodings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HostFileOp {
    /// `write`/`writev` of the staged input bytes to a host-backed descriptor.
    Write = 1,
    /// `fstat` of a host-backed descriptor; the output is a Linux `struct stat`.
    Fstat = 2,
    /// `openat` of the staged path (`args[0]` open flags, `args[1]` mode); a
    /// non-negative result is the new descriptor in the caller's table.
    Openat = 3,
    /// `faccessat2` of the staged path (`args[0]` mode, `flags` AT flags).
    Faccessat = 4,
    /// `newfstatat` of the staged path (`flags` AT flags); output `struct stat`.
    Newfstatat = 5,
    /// `statx` of the staged path, or of the descriptor for an empty path
    /// (`flags` AT flags, `args[0]` mask); output `struct statx`.
    Statx = 6,
    /// `read` of at most the output capacity at the description offset.
    Read = 7,
    /// `pread64` of at most the output capacity at `args[0]`.
    Pread = 8,
    /// `lseek` (`args[0]` offset as `i64`, `args[1]` whence).
    Lseek = 9,
    /// `getdents64` of at most the output capacity.
    Getdents64 = 10,
}

impl HostFileOp {
    const fn decode(raw: u16) -> Option<Self> {
        Some(match raw {
            1 => Self::Write,
            2 => Self::Fstat,
            3 => Self::Openat,
            4 => Self::Faccessat,
            5 => Self::Newfstatat,
            6 => Self::Statx,
            7 => Self::Read,
            8 => Self::Pread,
            9 => Self::Lseek,
            10 => Self::Getdents64,
            _ => return None,
        })
    }

    /// Whether the operation resolves a path, and therefore needs the
    /// caller's filesystem authority (credentials, cwd, root).
    pub const fn resolves_path(self) -> bool {
        matches!(
            self,
            Self::Openat | Self::Faccessat | Self::Newfstatat | Self::Statx
        )
    }
}

/// Header fields chosen by the ring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostFileHeader {
    pub op: HostFileOp,
    /// The caller's ring descriptor table: the `fd-core` raw table id words
    /// (authority, index, generation).
    pub table: [u64; 3],
    pub fd: i32,
    /// Operation-specific flags (for example `AT_*` flags).
    pub flags: u32,
    /// Operation-specific scalar arguments.
    pub args: [u64; 4],
}

const MAGIC: u32 = u32::from_le_bytes(*b"CHFR");
const VERSION: u16 = 1;
/// Fixed header, including the reply words.
pub const HOST_FILE_HEADER_BYTES: usize = 96;
/// Largest input or output area one record carries. Larger transfers are
/// split by the ring continuation.
pub const HOST_FILE_CHUNK_BYTES: usize = 64 * 1024;
/// Largest complete record.
pub const MAX_HOST_FILE_RECORD_BYTES: u64 =
    (HOST_FILE_HEADER_BYTES + 2 * HOST_FILE_CHUNK_BYTES) as u64;

// Header layout (little-endian byte offsets).
const OP: usize = 6;
const TABLE: usize = 8;
const FD: usize = 32;
const FLAGS: usize = 36;
const ARGS: usize = 40;
const INPUT_LEN: usize = 72;
const OUTPUT_CAP: usize = 76;
const RESULT: usize = 80;
const OUTPUT_LEN: usize = 88;
const STATE: usize = 92;

const REPLY_PENDING: u32 = 0;
const REPLY_WRITTEN: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostFileRecordError {
    Invalid,
    TooLarge,
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Total record length for `input_len` staged bytes and `output_cap` reply
/// bytes, or `None` when either exceeds one chunk.
pub const fn record_len(input_len: usize, output_cap: usize) -> Option<usize> {
    if input_len > HOST_FILE_CHUNK_BYTES || output_cap > HOST_FILE_CHUNK_BYTES {
        return None;
    }
    Some(HOST_FILE_HEADER_BYTES + input_len + output_cap)
}

/// Encode a record into `bytes`, whose length must be exactly
/// [`record_len`]`(input.len(), output_cap)`. The reply starts pending.
pub fn encode(
    bytes: &mut [u8],
    header: HostFileHeader,
    input: &[u8],
    output_cap: usize,
) -> Result<(), HostFileRecordError> {
    let expected = record_len(input.len(), output_cap).ok_or(HostFileRecordError::TooLarge)?;
    if bytes.len() != expected {
        return Err(HostFileRecordError::Invalid);
    }
    bytes.fill(0);
    bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
    bytes[OP..OP + 2].copy_from_slice(&(header.op as u16).to_le_bytes());
    for (index, word) in header.table.iter().enumerate() {
        let offset = TABLE + index * 8;
        bytes[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
    }
    bytes[FD..FD + 4].copy_from_slice(&header.fd.to_le_bytes());
    bytes[FLAGS..FLAGS + 4].copy_from_slice(&header.flags.to_le_bytes());
    for (index, arg) in header.args.iter().enumerate() {
        let offset = ARGS + index * 8;
        bytes[offset..offset + 8].copy_from_slice(&arg.to_le_bytes());
    }
    bytes[INPUT_LEN..INPUT_LEN + 4].copy_from_slice(&(input.len() as u32).to_le_bytes());
    bytes[OUTPUT_CAP..OUTPUT_CAP + 4].copy_from_slice(&(output_cap as u32).to_le_bytes());
    bytes[STATE..STATE + 4].copy_from_slice(&REPLY_PENDING.to_le_bytes());
    bytes[HOST_FILE_HEADER_BYTES..HOST_FILE_HEADER_BYTES + input.len()].copy_from_slice(input);
    Ok(())
}

/// A validated record, as the carrier sees it.
#[derive(Debug)]
pub struct HostFileRequestView<'a> {
    bytes: &'a mut [u8],
    header: HostFileHeader,
    input_len: usize,
    output_cap: usize,
}

impl<'a> HostFileRequestView<'a> {
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self, HostFileRecordError> {
        let invalid = HostFileRecordError::Invalid;
        if read_u32(bytes, 0) != Some(MAGIC) || read_u16(bytes, 4) != Some(VERSION) {
            return Err(invalid);
        }
        let op = HostFileOp::decode(read_u16(bytes, OP).ok_or(invalid)?).ok_or(invalid)?;
        let mut table = [0u64; 3];
        for (index, word) in table.iter_mut().enumerate() {
            *word = read_u64(bytes, TABLE + index * 8).ok_or(invalid)?;
        }
        let fd = read_u32(bytes, FD).ok_or(invalid)? as i32;
        let flags = read_u32(bytes, FLAGS).ok_or(invalid)?;
        let mut args = [0u64; 4];
        for (index, arg) in args.iter_mut().enumerate() {
            *arg = read_u64(bytes, ARGS + index * 8).ok_or(invalid)?;
        }
        let input_len = read_u32(bytes, INPUT_LEN).ok_or(invalid)? as usize;
        let output_cap = read_u32(bytes, OUTPUT_CAP).ok_or(invalid)? as usize;
        if read_u32(bytes, STATE) != Some(REPLY_PENDING)
            || record_len(input_len, output_cap) != Some(bytes.len())
        {
            return Err(invalid);
        }
        Ok(Self {
            bytes,
            header: HostFileHeader {
                op,
                table,
                fd,
                flags,
                args,
            },
            input_len,
            output_cap,
        })
    }

    pub fn header(&self) -> HostFileHeader {
        self.header
    }

    pub fn input(&self) -> &[u8] {
        &self.bytes[HOST_FILE_HEADER_BYTES..HOST_FILE_HEADER_BYTES + self.input_len]
    }

    pub fn output_capacity(&self) -> usize {
        self.output_cap
    }

    /// Write the reply once. `output` must fit the ring's output area; a
    /// Linux errno result carries no output.
    pub fn reply(self, result: i64, output: &[u8]) -> Result<(), HostFileRecordError> {
        if output.len() > self.output_cap || (result < 0 && !output.is_empty()) {
            return Err(HostFileRecordError::Invalid);
        }
        let start = HOST_FILE_HEADER_BYTES + self.input_len;
        self.bytes[start..start + output.len()].copy_from_slice(output);
        self.bytes[RESULT..RESULT + 8].copy_from_slice(&result.to_le_bytes());
        self.bytes[OUTPUT_LEN..OUTPUT_LEN + 4]
            .copy_from_slice(&(output.len() as u32).to_le_bytes());
        self.bytes[STATE..STATE + 4].copy_from_slice(&REPLY_WRITTEN.to_le_bytes());
        Ok(())
    }
}

/// The reply the ring reads back after acknowledgment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostFileReply<'a> {
    pub result: i64,
    pub output: &'a [u8],
}

/// Read the carrier's reply. `None` when no reply was written (refused or
/// cancelled service) or the record is inconsistent.
pub fn reply(bytes: &[u8]) -> Option<HostFileReply<'_>> {
    if read_u32(bytes, 0)? != MAGIC || read_u32(bytes, STATE)? != REPLY_WRITTEN {
        return None;
    }
    let input_len = read_u32(bytes, INPUT_LEN)? as usize;
    let output_cap = read_u32(bytes, OUTPUT_CAP)? as usize;
    if record_len(input_len, output_cap)? != bytes.len() {
        return None;
    }
    let output_len = read_u32(bytes, OUTPUT_LEN)? as usize;
    if output_len > output_cap {
        return None;
    }
    let result = read_u64(bytes, RESULT)? as i64;
    let start = HOST_FILE_HEADER_BYTES + input_len;
    Some(HostFileReply {
        result,
        output: &bytes[start..start + output_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    fn header(op: HostFileOp) -> HostFileHeader {
        HostFileHeader {
            op,
            table: [7, 8, 9],
            fd: 1,
            flags: 0,
            args: [1, 2, 3, 4],
        }
    }

    #[test]
    fn record_round_trips_input_and_reply() {
        let mut bytes = vec![0u8; record_len(5, 16).unwrap()];
        encode(&mut bytes, header(HostFileOp::Write), b"hello", 16).unwrap();
        assert_eq!(reply(&bytes), None, "a fresh record has no reply");
        let view = HostFileRequestView::parse(&mut bytes).unwrap();
        assert_eq!(view.header(), header(HostFileOp::Write));
        assert_eq!(view.input(), b"hello");
        assert_eq!(view.output_capacity(), 16);
        view.reply(5, b"out").unwrap();
        assert_eq!(
            reply(&bytes),
            Some(HostFileReply {
                result: 5,
                output: b"out"
            })
        );
        // A written record is never served a second time.
        assert!(HostFileRequestView::parse(&mut bytes).is_err());
    }

    #[test]
    fn record_rejects_oversized_output_and_errno_output() {
        let mut bytes = vec![0u8; record_len(0, 4).unwrap()];
        encode(&mut bytes, header(HostFileOp::Fstat), &[], 4).unwrap();
        let view = HostFileRequestView::parse(&mut bytes).unwrap();
        assert_eq!(view.reply(0, b"12345"), Err(HostFileRecordError::Invalid));
        let view = HostFileRequestView::parse(&mut bytes).unwrap();
        assert_eq!(view.reply(-9, b"1"), Err(HostFileRecordError::Invalid));
        assert!(record_len(HOST_FILE_CHUNK_BYTES + 1, 0).is_none());
    }
}
