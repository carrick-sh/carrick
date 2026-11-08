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
    /// `args[0]` is the writer's own `RLIMIT_FSIZE` soft limit (`u64::MAX`
    /// is unlimited), stamped by the ring that owns the writer's limits.
    Write = 1,
    /// `fstat` of a host-backed descriptor; the output is a Linux `struct stat`.
    Fstat = 2,
    /// `openat` of the staged path (`args[0]` open flags, `args[1]` mode); a
    /// non-negative result is the new descriptor in the caller's table.
    Openat = 3,
    /// `faccessat2` of the staged path (`args[0]` mode, `flags` AT flags).
    Faccessat = 4,
    /// `newfstatat` of the staged path (`flags` AT flags); output `struct stat`.
    /// With a reply area larger than `struct stat` it is a ring task's chdir
    /// lookup: the carrier runs the chdir lookup (a searchable directory)
    /// and replies with its `struct stat` followed by its cwd spelling.
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
    /// Retain the descriptor's file as a private-mapping byte source for the
    /// caller's MM; output is the source identity ([`MapSourceReply`]). The
    /// ring then maps it with its own reservation owner. Input is the list of
    /// sources the caller's owner retired, which the carrier releases first.
    MapPrivate = 11,
    /// A non-blocking readiness snapshot of a `ppoll` set whose every live
    /// entry names a host-backed description (or no descriptor). Input and
    /// output are the caller's `struct pollfd` array ([`POLLFD_BYTES`] per
    /// entry); the reply is that array with `revents` filled and the ready
    /// count as the result. `args[0]` is a [`PollWait`] word: for
    /// [`PollWait::Snapshot`] (a zero timeout) the empty snapshot is the
    /// answer; for [`PollWait::MayWait`] the carrier, which never blocks,
    /// refuses an empty snapshot (counted ENOSYS) and writes no `revents`.
    /// The header `fd` is unused (`-1`); each entry is pinned in the
    /// caller's table.
    Poll = 12,
    /// Read the staged link path into the bounded output, without a NUL.
    Readlinkat = 13,
}

/// Bytes of one Linux `struct pollfd` (`int fd; short events, revents`).
pub const POLLFD_BYTES: usize = 8;
/// [`HostFileOp::Poll`] `args[0]`: whether the caller would wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum PollWait {
    /// A zero timeout: the snapshot is the answer, even an empty one.
    Snapshot = 0,
    /// The caller would wait: an empty snapshot is refused rather than
    /// reported as a timeout.
    MayWait = 1,
}

impl PollWait {
    pub const fn raw(self) -> u64 {
        self as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Snapshot),
            1 => Some(Self::MayWait),
            _ => None,
        }
    }
}

/// The `ordinal` a refused host-file record reports through the
/// `hvpatch-native-crossing-refused` probe: this base plus the record's
/// [`HostFileOp`] wire value (the base alone for a record that does not
/// parse). It sits above every syscall number, so a refused venue
/// operation never reads as syscall 0 (`io_setup`).
pub const HOST_FILE_REFUSAL_ORDINAL_BASE: u64 = 0x1_0000;

/// The refusal probe ordinal of one staged record
/// ([`HOST_FILE_REFUSAL_ORDINAL_BASE`] + op).
pub fn refusal_ordinal(bytes: &[u8]) -> u64 {
    HOST_FILE_REFUSAL_ORDINAL_BASE
        + request_parts(bytes).map_or(0, |(header, _, _)| header.op as u16 as u64)
}

/// The byte-source identity a [`HostFileOp::MapPrivate`] reply carries: the
/// carrier-minted handle and generation of the retained source. The ring
/// adds the mapping's file offset itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapSourceReply {
    pub handle: core::num::NonZeroU64,
    pub generation: core::num::NonZeroU64,
}

/// Little-endian wire layout of a [`MapSourceReply`].
#[derive(zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
struct MapSourceWire {
    handle: zerocopy::little_endian::U64,
    generation: zerocopy::little_endian::U64,
}

impl MapSourceReply {
    pub const BYTES: usize = core::mem::size_of::<MapSourceWire>();

    pub fn encode(self) -> [u8; Self::BYTES] {
        let wire = MapSourceWire {
            handle: self.handle.get().into(),
            generation: self.generation.get().into(),
        };
        let mut bytes = [0u8; Self::BYTES];
        bytes.copy_from_slice(zerocopy::IntoBytes::as_bytes(&wire));
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let wire = <MapSourceWire as zerocopy::FromBytes>::read_from_bytes(bytes).ok()?;
        Some(Self {
            handle: core::num::NonZeroU64::new(wire.handle.get())?,
            generation: core::num::NonZeroU64::new(wire.generation.get())?,
        })
    }

    /// The released sources a [`HostFileOp::MapPrivate`] request carries as
    /// its input: at most [`MAX_MAP_RELEASES`] whole records, or `None`.
    pub fn decode_releases(input: &[u8]) -> Option<impl Iterator<Item = Self> + '_> {
        if !input.len().is_multiple_of(Self::BYTES) || input.len() / Self::BYTES > MAX_MAP_RELEASES
        {
            return None;
        }
        let all = input
            .chunks_exact(Self::BYTES)
            .all(|bytes| Self::decode(bytes).is_some());
        all.then(|| input.chunks_exact(Self::BYTES).filter_map(Self::decode))
    }
}

/// Byte sources one [`HostFileOp::MapPrivate`] request may release: those
/// the caller's reservation owner retired since its last request (their last
/// node unmapped, or no node ever consumed them).
pub const MAX_MAP_RELEASES: usize = 8;

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
            11 => Self::MapPrivate,
            12 => Self::Poll,
            13 => Self::Readlinkat,
            _ => return None,
        })
    }

    /// Whether the operation resolves a path. Its input then leads with
    /// the caller's [`AccessContext`] (credentials, umask, cwd, root),
    /// followed by the path.
    pub const fn resolves_path(self) -> bool {
        matches!(
            self,
            Self::Openat | Self::Faccessat | Self::Newfstatat | Self::Statx | Self::Readlinkat
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

    /// Replace the header's scalar arguments: the ring's own stamp of a
    /// value only it knows (for example a `Write`'s file-size limit) on a
    /// record it staged.
    pub fn set_args(&mut self, args: [u64; 4]) {
        for (index, arg) in args.iter().enumerate() {
            let offset = ARGS + index * 8;
            self.bytes[offset..offset + 8].copy_from_slice(&arg.to_le_bytes());
        }
        self.header.args = args;
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

/// The caller's own filesystem access context, carried by value in every
/// crossing that resolves a path (and in the exec payload): its credentials,
/// file-mode creation mask, supplementary groups, working directory and root.
/// The ring task row owns these values; the carrier resolves against them in
/// a transient scope and keeps nothing.
///
/// Paths are the absolute, normalized spellings the host VFS uses. `root` is
/// `None` until the caller (or an ancestor) has called `chroot`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessContext<'a> {
    pub ids: AccessIds,
    pub umask: u32,
    /// `None`: the launch identity's groups (no `setgroups` ran). `Some`,
    /// even empty, is the complete list `setgroups` installed.
    groups: Option<&'a [u8]>,
    pub cwd: &'a [u8],
    pub root: Option<&'a [u8]>,
}

/// The caller's real, effective, saved and filesystem user and group ids.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccessIds {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
}

/// Largest supplementary group list an access context carries.
pub const ACCESS_MAX_GROUPS: usize = 1024;
/// Largest cwd or root spelling an access context carries (Linux `PATH_MAX`).
pub const ACCESS_MAX_PATH_BYTES: usize = 4096;
/// Fixed prefix: eight ids, umask, group count, cwd length, root length.
const ACCESS_FIXED_BYTES: usize = 12 * 4;
const ACCESS_NO_ROOT: u32 = u32::MAX;
const ACCESS_LAUNCH_GROUPS: u32 = u32::MAX;

impl<'a> AccessContext<'a> {
    /// The encoded size, or `None` when a field exceeds its bound.
    pub fn encoded_len(groups: usize, cwd: &[u8], root: Option<&[u8]>) -> Option<usize> {
        let root_len = root.map_or(0, <[u8]>::len);
        if groups > ACCESS_MAX_GROUPS
            || cwd.is_empty()
            || cwd.len() > ACCESS_MAX_PATH_BYTES
            || root_len > ACCESS_MAX_PATH_BYTES
            || root.is_some_and(<[u8]>::is_empty)
        {
            return None;
        }
        Some(ACCESS_FIXED_BYTES + groups * 4 + cwd.len() + root_len)
    }

    /// Append the encoded context to `out`.
    pub fn encode_into(
        out: &mut alloc::vec::Vec<u8>,
        ids: AccessIds,
        umask: u32,
        groups: Option<&[u32]>,
        cwd: &[u8],
        root: Option<&[u8]>,
    ) -> Result<(), HostFileRecordError> {
        let group_count = groups.map_or(ACCESS_LAUNCH_GROUPS, |groups| groups.len() as u32);
        let groups = groups.unwrap_or(&[]);
        let len =
            Self::encoded_len(groups.len(), cwd, root).ok_or(HostFileRecordError::TooLarge)?;
        out.try_reserve(len)
            .map_err(|_| HostFileRecordError::TooLarge)?;
        let root_len = root.map_or(ACCESS_NO_ROOT, |root| root.len() as u32);
        for word in [
            ids.ruid,
            ids.euid,
            ids.suid,
            ids.fsuid,
            ids.rgid,
            ids.egid,
            ids.sgid,
            ids.fsgid,
            umask,
            group_count,
            cwd.len() as u32,
            root_len,
        ] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        for group in groups {
            out.extend_from_slice(&group.to_le_bytes());
        }
        out.extend_from_slice(cwd);
        if let Some(root) = root {
            out.extend_from_slice(root);
        }
        Ok(())
    }

    /// Split an encoded context from the front of `bytes`, returning it and
    /// the bytes that follow it.
    pub fn decode(bytes: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let word = |index: usize| read_u32(bytes, index * 4);
        let ids = AccessIds {
            ruid: word(0)?,
            euid: word(1)?,
            suid: word(2)?,
            fsuid: word(3)?,
            rgid: word(4)?,
            egid: word(5)?,
            sgid: word(6)?,
            fsgid: word(7)?,
        };
        let umask = word(8)?;
        let group_count = word(9)?;
        let installed = group_count != ACCESS_LAUNCH_GROUPS;
        let groups = if installed { group_count as usize } else { 0 };
        let cwd_len = word(10)? as usize;
        let root_len = word(11)?;
        let root = (root_len != ACCESS_NO_ROOT).then_some(root_len as usize);
        if groups > ACCESS_MAX_GROUPS
            || cwd_len == 0
            || cwd_len > ACCESS_MAX_PATH_BYTES
            || root.is_some_and(|len| len == 0 || len > ACCESS_MAX_PATH_BYTES)
        {
            return None;
        }
        let groups_end = ACCESS_FIXED_BYTES + groups * 4;
        let cwd_end = groups_end + cwd_len;
        let end = cwd_end + root.unwrap_or(0);
        let rest = bytes.get(end..)?;
        Some((
            Self {
                ids,
                umask,
                groups: match bytes.get(ACCESS_FIXED_BYTES..groups_end)? {
                    groups if installed => Some(groups),
                    _ => None,
                },
                cwd: bytes.get(groups_end..cwd_end)?,
                root: root.map(|_| &bytes[cwd_end..end]),
            },
            rest,
        ))
    }

    /// The supplementary groups `setgroups` installed, in its order, or
    /// `None` for the launch identity's groups.
    pub fn groups(&self) -> Option<impl ExactSizeIterator<Item = u32> + 'a> {
        self.groups.map(|groups| {
            groups
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        })
    }
}

/// The header, staged input and output capacity of an unserved record, read
/// without a mutable view (the ring re-stages a record with its caller's
/// access context in front of the input).
pub fn request_parts(bytes: &[u8]) -> Option<(HostFileHeader, &[u8], usize)> {
    if read_u32(bytes, 0) != Some(MAGIC)
        || read_u16(bytes, 4) != Some(VERSION)
        || read_u32(bytes, STATE) != Some(REPLY_PENDING)
    {
        return None;
    }
    let op = HostFileOp::decode(read_u16(bytes, OP)?)?;
    let mut table = [0u64; 3];
    for (index, word) in table.iter_mut().enumerate() {
        *word = read_u64(bytes, TABLE + index * 8)?;
    }
    let mut args = [0u64; 4];
    for (index, arg) in args.iter_mut().enumerate() {
        *arg = read_u64(bytes, ARGS + index * 8)?;
    }
    let input_len = read_u32(bytes, INPUT_LEN)? as usize;
    let output_cap = read_u32(bytes, OUTPUT_CAP)? as usize;
    if record_len(input_len, output_cap) != Some(bytes.len()) {
        return None;
    }
    Some((
        HostFileHeader {
            op,
            table,
            fd: read_u32(bytes, FD)? as i32,
            flags: read_u32(bytes, FLAGS)?,
            args,
        },
        &bytes[HOST_FILE_HEADER_BYTES..HOST_FILE_HEADER_BYTES + input_len],
        output_cap,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn access_context_round_trips_and_splits_the_path() {
        let ids = AccessIds {
            ruid: 1,
            euid: 2,
            suid: 3,
            fsuid: 4,
            rgid: 5,
            egid: 6,
            sgid: 7,
            fsgid: 8,
        };
        let mut bytes = alloc::vec::Vec::new();
        AccessContext::encode_into(
            &mut bytes,
            ids,
            0o027,
            Some(&[10, 20]),
            b"/tmp/sub",
            Some(b"/jail"),
        )
        .unwrap();
        bytes.extend_from_slice(b"rel/path");
        let (context, rest) = AccessContext::decode(&bytes).unwrap();
        assert_eq!(context.ids, ids);
        assert_eq!(context.umask, 0o027);
        assert_eq!(
            context.groups().unwrap().collect::<alloc::vec::Vec<_>>(),
            [10, 20]
        );
        assert_eq!(context.cwd, b"/tmp/sub");
        assert_eq!(context.root, Some(&b"/jail"[..]));
        assert_eq!(rest, b"rel/path");

        let mut bytes = alloc::vec::Vec::new();
        AccessContext::encode_into(&mut bytes, ids, 0o022, None, b"/", None).unwrap();
        let (context, rest) = AccessContext::decode(&bytes).unwrap();
        assert_eq!(
            (context.root, rest, context.groups().is_none()),
            (None, &[][..], true)
        );
        // An explicitly empty list (`setgroups(0, NULL)`) stays distinct
        // from the launch identity's groups.
        let mut bytes = alloc::vec::Vec::new();
        AccessContext::encode_into(&mut bytes, ids, 0o022, Some(&[]), b"/", None).unwrap();
        let (context, _) = AccessContext::decode(&bytes).unwrap();
        assert_eq!(context.groups().map(|groups| groups.len()), Some(0));
        assert!(AccessContext::decode(&bytes[..bytes.len() - 1]).is_none());
        assert!(AccessContext::encode_into(&mut bytes, ids, 0, None, b"", None).is_err());
    }

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
    fn set_args_restamps_only_the_scalar_arguments() {
        let mut bytes = vec![0u8; record_len(5, 0).unwrap()];
        encode(&mut bytes, header(HostFileOp::Write), b"hello", 0).unwrap();
        let mut view = HostFileRequestView::parse(&mut bytes).unwrap();
        view.set_args([u64::MAX, 2, 3, 4]);
        let view = HostFileRequestView::parse(&mut bytes).unwrap();
        let mut expected = header(HostFileOp::Write);
        expected.args[0] = u64::MAX;
        assert_eq!(view.header(), expected);
        assert_eq!(view.input(), b"hello");
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
