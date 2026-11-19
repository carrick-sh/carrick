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
    /// answer; for [`PollWait::MayWait`] the caller waits on its
    /// host-readiness queue for the set's host objects, or until `args[1]`
    /// milliseconds (as `i64`; negative: no timeout) after its first empty
    /// snapshot, when the answer is 0 (#231). A carrier that cannot wait
    /// refuses an empty snapshot (counted ENOSYS) and writes no `revents`.
    /// The header `fd` is unused (`-1`); each entry is pinned in the
    /// caller's table.
    Poll = 12,
    /// `mkdirat` of the staged path (`args[0]` mode).
    Mkdirat = 13,
    /// `unlinkat` of the staged path (`flags` may contain `AT_REMOVEDIR`).
    Unlinkat = 14,
    /// `symlinkat`: input is the verbatim target, NUL, then the link path.
    Symlinkat = 15,
    /// `linkat`: input is the source path, NUL, then the target path;
    /// `flags` carries the Linux `AT_*` flags.
    Linkat = 16,
    /// `utimensat` of the staged path; four scalar words are the two
    /// Linux timespecs, retaining `UTIME_NOW` and `UTIME_OMIT`.
    Utimensat = 17,
    /// `utimensat(fd, NULL, ...)` with the same timespec words.
    SetFdTimes = 18,
    /// `truncate` of the staged path (`args[0]` signed length,
    /// `args[1]` caller's RLIMIT_FSIZE soft limit).
    Truncate = 19,
    /// `ftruncate` with the same length and limit words.
    Ftruncate = 20,
    /// `renameat`/`renameat2`: source path, NUL, target path;
    /// `flags` carries the Linux rename flags.
    Renameat = 21,
    /// `fchdir` of a host-backed descriptor: the chdir lookup of the
    /// directory it names, searchable by the caller. The input is the
    /// caller's [`AccessContext`] alone (no path); the reply area is laid
    /// out as [`HostFileOp::Newfstatat`]'s chdir lookup: `struct stat`, then
    /// the cwd spelling.
    Fchdir = 22,
    /// Read the staged link path into the bounded output, without a NUL.
    Readlinkat = 23,
    /// `fchmod` of a host-backed descriptor (`args[0]` mode). The input is
    /// the caller's [`AccessContext`] alone: only the file's owner (or a
    /// privileged caller) may change its mode.
    Fchmod = 24,
    /// `fchown` of a host-backed descriptor (`args[0]` owner, `args[1]`
    /// group, each `u32::MAX` for unchanged). The input is the caller's
    /// [`AccessContext`] alone, whose credentials decide EPERM.
    Fchown = 25,
    /// `fchmodat`/`fchmodat2` of the staged path (`args[0]` mode; `flags`
    /// may carry `AT_SYMLINK_NOFOLLOW`, from `fchmodat2` only).
    Fchmodat = 26,
    /// `fchownat` of the staged path (`args[0]` owner, `args[1]` group as
    /// for [`HostFileOp::Fchown`]; `flags` may carry `AT_SYMLINK_NOFOLLOW`).
    Fchownat = 27,
    /// One call of the host network socket family (#231), served by the
    /// carrier's one socket implementation on the caller's own descriptors.
    /// The input is a [`NetCall`]: the canonical syscall, its arguments and
    /// the user memory the ring staged for it; the output is the staged
    /// output segments' written extents ([`NetCall::encode_written`]). The
    /// header `fd` is the descriptor argument (`-1` for `socket`).
    NetSyscall = 28,
    /// Flush a file's data and metadata for fsync or fdatasync.
    Fsync = 30,
    /// Flush the filesystem containing the descriptor.
    Syncfs = 31,
    /// Best-effort range flush. The arguments are offset, length and flags.
    SyncFileRange = 32,
    /// Query the filesystem of the staged path.
    Statfs = 33,
    /// Query the filesystem of the descriptor.
    Fstatfs = 34,
    /// Allocate a region of the descriptor. The arguments are mode, offset and length.
    Fallocate = 35,
    /// Positional write of staged bytes. `args[0]` is the signed offset,
    /// and `args[1]` is the writer's ring-owned RLIMIT_FSIZE.
    Pwrite = 36,
    /// Query an extended attribute. The path and name are NUL-delimited.
    GetXattr = 37,
    /// Return the filesystem's NUL-delimited attribute names.
    ListXattr = 38,
    /// Set an attribute; the path and name delimit the value bytes.
    SetXattr = 39,
    /// A Linux request from the native host-description allowlist.
    Ioctl = 40,
}

/// A staged user-memory range of a [`HostFileOp::NetSyscall`] record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetSegment {
    pub address: u64,
    pub len: u32,
    /// The call reads the range: its bytes are staged in the record.
    pub input: bool,
    /// The call may write the range: the reply carries its written extent.
    pub output: bool,
}

/// Largest staged bytes of one segment.
pub const NET_SEGMENT_MAX_BYTES: usize = HOST_FILE_CHUNK_BYTES;
/// The argument word of a `sendmsg` [`NetCall`] (one no message call has)
/// that carries [`NET_MESSAGE_UNSTAGED`].
pub const NET_MESSAGE_UNSTAGED_ARG: usize = 5;
/// A `sendmsg` whose data does not fit one record stages its header and
/// iovecs but none of its data. The carrier answers EMSGSIZE for a
/// datagram socket, whose largest datagram one record always holds, and
/// refuses the call (a counted ENOSYS) for any other socket.
pub const NET_MESSAGE_UNSTAGED: u64 = 1;

/// Most segments one call stages: as many as the record's framing area
/// holds. A message call (`sendmsg`, `recvmmsg`, ...) stages each header,
/// iovec array, buffer and socket address as its own segment.
pub const NET_SEGMENTS_MAX: usize = HOST_FILE_FRAMING_BYTES / NET_SEGMENT_BYTES;
const NET_CALL_FIXED_BYTES: usize = 8 + 6 * 8 + 4;
const NET_SEGMENT_BYTES: usize = 16;
const NET_SEGMENT_INPUT: u32 = 1;
const NET_SEGMENT_OUTPUT: u32 = 2;

/// A [`HostFileOp::NetSyscall`] request: the canonical syscall number, its
/// six argument words, and the user ranges it may touch. The ring stages
/// exactly the ranges Linux's call reads or writes; any other user access
/// faults as Linux's would.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetCall<'a> {
    pub canonical: u64,
    pub args: [u64; 6],
    segments: alloc::vec::Vec<NetSegment>,
    bytes: &'a [u8],
}

impl<'a> NetCall<'a> {
    /// Encode a request input. `inputs` holds each input segment's staged
    /// bytes, in segment order.
    pub fn encode(
        canonical: u64,
        args: [u64; 6],
        segments: &[NetSegment],
        inputs: &[&[u8]],
    ) -> Option<alloc::vec::Vec<u8>> {
        if segments.len() > NET_SEGMENTS_MAX {
            return None;
        }
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(&canonical.to_le_bytes());
        for arg in args {
            out.extend_from_slice(&arg.to_le_bytes());
        }
        out.extend_from_slice(&(segments.len() as u32).to_le_bytes());
        let mut staged = inputs.iter();
        let mut payload = alloc::vec::Vec::new();
        for segment in segments {
            if segment.len as usize > NET_SEGMENT_MAX_BYTES {
                return None;
            }
            out.extend_from_slice(&segment.address.to_le_bytes());
            out.extend_from_slice(&segment.len.to_le_bytes());
            let flags = (u32::from(segment.input) * NET_SEGMENT_INPUT)
                | (u32::from(segment.output) * NET_SEGMENT_OUTPUT);
            out.extend_from_slice(&flags.to_le_bytes());
            if segment.input {
                let bytes = staged.next()?;
                if bytes.len() != segment.len as usize {
                    return None;
                }
                payload.extend_from_slice(bytes);
            }
        }
        if staged.next().is_some() {
            return None;
        }
        out.extend_from_slice(&payload);
        Some(out)
    }

    pub fn decode(input: &'a [u8]) -> Option<Self> {
        let canonical = read_u64(input, 0)?;
        let mut args = [0u64; 6];
        for (index, arg) in args.iter_mut().enumerate() {
            *arg = read_u64(input, 8 + index * 8)?;
        }
        let count = read_u32(input, 56)? as usize;
        if count > NET_SEGMENTS_MAX {
            return None;
        }
        let mut segments = alloc::vec::Vec::with_capacity(count);
        let mut staged = 0usize;
        for index in 0..count {
            let at = NET_CALL_FIXED_BYTES + index * NET_SEGMENT_BYTES;
            let flags = read_u32(input, at + 12)?;
            if flags & !(NET_SEGMENT_INPUT | NET_SEGMENT_OUTPUT) != 0 {
                return None;
            }
            let segment = NetSegment {
                address: read_u64(input, at)?,
                len: read_u32(input, at + 8)?,
                input: flags & NET_SEGMENT_INPUT != 0,
                output: flags & NET_SEGMENT_OUTPUT != 0,
            };
            if segment.len as usize > NET_SEGMENT_MAX_BYTES {
                return None;
            }
            if segment.input {
                staged = staged.checked_add(segment.len as usize)?;
            }
            segments.push(segment);
        }
        let start = NET_CALL_FIXED_BYTES + count * NET_SEGMENT_BYTES;
        let bytes = input.get(start..)?;
        if bytes.len() != staged {
            return None;
        }
        Some(Self {
            canonical,
            args,
            segments,
            bytes,
        })
    }

    pub fn segments(&self) -> &[NetSegment] {
        &self.segments
    }

    /// The encoded input length of a request with `segments`: its framing
    /// and every input segment's staged bytes.
    pub fn input_len(segments: &[NetSegment]) -> usize {
        NET_CALL_FIXED_BYTES
            + segments.len() * NET_SEGMENT_BYTES
            + segments
                .iter()
                .filter(|segment| segment.input)
                .map(|segment| segment.len as usize)
                .sum::<usize>()
    }

    /// Each segment with its staged bytes (`None` for an output-only one).
    pub fn staged(&self) -> impl Iterator<Item = (NetSegment, Option<&'a [u8]>)> + '_ {
        let mut cursor = 0usize;
        self.segments.iter().map(move |segment| {
            if segment.input {
                let bytes = &self.bytes[cursor..cursor + segment.len as usize];
                cursor += segment.len as usize;
                (*segment, Some(bytes))
            } else {
                (*segment, None)
            }
        })
    }

    /// The reply area a request with `segments` needs: the call's
    /// [`NetTransferFacts`], then each output segment's written extent.
    pub fn output_capacity(segments: &[NetSegment]) -> usize {
        NET_TRANSFER_FACTS_BYTES
            + segments
                .iter()
                .filter(|segment| segment.output)
                .map(|segment| 8 + segment.len as usize)
                .sum::<usize>()
    }

    /// Encode the call's `facts` and the written extent `[start, end)` of
    /// each output segment, in segment order, as the reply output.
    pub fn encode_written(
        facts: NetTransferFacts,
        extents: &[(u32, &[u8])],
    ) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(&facts.raw().to_le_bytes());
        for (start, bytes) in extents {
            out.extend_from_slice(&start.to_le_bytes());
            out.extend_from_slice(&(*start + bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Decode a reply output against the request's segments: the call's
    /// facts and each output segment's written `(address, bytes)`, in
    /// segment order. `None` for a reply that writes outside its segment.
    #[allow(clippy::type_complexity)]
    pub fn decode_written<'r>(
        segments: &[NetSegment],
        reply: &'r [u8],
    ) -> Option<(NetTransferFacts, alloc::vec::Vec<(u64, &'r [u8])>)> {
        let facts = NetTransferFacts::from_raw(read_u64(reply, 0)?)?;
        let mut out = alloc::vec::Vec::new();
        let mut cursor = NET_TRANSFER_FACTS_BYTES;
        for segment in segments.iter().filter(|segment| segment.output) {
            let start = read_u32(reply, cursor)?;
            let end = read_u32(reply, cursor + 4)?;
            if start > end || end > segment.len {
                return None;
            }
            let bytes = reply.get(cursor + 8..cursor + 8 + (end - start) as usize)?;
            cursor += 8 + bytes.len();
            out.push((segment.address.checked_add(u64::from(start))?, bytes));
        }
        (cursor == reply.len()).then_some((facts, out))
    }
}

/// What the carrier observed of the socket a [`HostFileOp::NetSyscall`]
/// call ran on, leading its reply output (#2414). The ring's transfer
/// continuation needs both: a stream transfer continues past a short record
/// where a datagram never does, and a blocking one waits for the rest where
/// a non-blocking one returns what moved.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NetTransferFacts {
    /// The socket is a byte stream (`SOCK_STREAM`).
    pub stream: bool,
    /// The call could wait: neither the description's `O_NONBLOCK` nor
    /// the call's `MSG_DONTWAIT` was set.
    pub blocking: bool,
}

const NET_TRANSFER_FACTS_BYTES: usize = 8;
const NET_FACT_STREAM: u64 = 1;
const NET_FACT_BLOCKING: u64 = 2;

impl NetTransferFacts {
    pub const fn raw(self) -> u64 {
        (self.stream as u64 * NET_FACT_STREAM) | (self.blocking as u64 * NET_FACT_BLOCKING)
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw & !(NET_FACT_STREAM | NET_FACT_BLOCKING) != 0 {
            return None;
        }
        Some(Self {
            stream: raw & NET_FACT_STREAM != 0,
            blocking: raw & NET_FACT_BLOCKING != 0,
        })
    }
}

/// The calling member of one [`HostFileOp::NetSyscall`] record (#231): the
/// identity Linux's socket calls consult (capabilities for a raw socket, the
/// credentials and pid a socket records), from the member's own ring task
/// row. The ring stamps it ahead of the [`NetCall`]; the carrier runs the
/// call under it, never under the run root's identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetCaller {
    /// The member's ring task.
    pub task: carrick_sched_core::process::TaskKey,
    /// The member's pid as its own pid namespace sees it (`getpid(2)`).
    pub ns_pid: core::num::NonZeroU32,
    pub ids: AccessIds,
    /// The member's effective capability set (Linux capability bits).
    pub cap_effective: u64,
}

/// Little-endian wire layout of a [`NetCaller`].
#[derive(zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::Immutable, zerocopy::KnownLayout)]
#[repr(C)]
struct NetCallerWire {
    task_id: zerocopy::little_endian::I32,
    ns_pid: zerocopy::little_endian::U32,
    task_serial: zerocopy::little_endian::U64,
    /// ruid, euid, suid, fsuid, rgid, egid, sgid, fsgid.
    ids: [zerocopy::little_endian::U32; 8],
    cap_effective: zerocopy::little_endian::U64,
}

/// Encoded bytes of a [`NetCaller`].
pub const NET_CALLER_BYTES: usize = core::mem::size_of::<NetCallerWire>();

/// Largest data range one [`HostFileOp::NetSyscall`] record stages (a
/// `send`'s bytes or a `recv`'s buffer): one whole chunk, beside the caller,
/// call, segment framing and socket address the record area also carries
/// ([`HOST_FILE_FRAMING_BYTES`]). Every inet datagram fits it (an IP
/// datagram's total length is 16 bits), so a datagram is always one
/// transfer; a stream transfer larger than one record continues in the
/// ring's owned transfer continuation.
pub const NET_TRANSFER_MAX_BYTES: usize = HOST_FILE_CHUNK_BYTES;

impl NetCaller {
    pub fn encode(&self) -> [u8; NET_CALLER_BYTES] {
        let ids = self.ids;
        let wire = NetCallerWire {
            task_id: self.task.id.raw().into(),
            ns_pid: self.ns_pid.get().into(),
            task_serial: self.task.serial.raw().into(),
            ids: [
                ids.ruid, ids.euid, ids.suid, ids.fsuid, ids.rgid, ids.egid, ids.sgid, ids.fsgid,
            ]
            .map(Into::into),
            cap_effective: self.cap_effective.into(),
        };
        let mut bytes = [0u8; NET_CALLER_BYTES];
        bytes.copy_from_slice(zerocopy::IntoBytes::as_bytes(&wire));
        bytes
    }

    /// Split a stamped [`HostFileOp::NetSyscall`] input into its caller and
    /// the [`NetCall`] bytes. `None` for an unstamped or malformed input.
    pub fn split(input: &[u8]) -> Option<(Self, &[u8])> {
        let (head, call) = input.split_at_checked(NET_CALLER_BYTES)?;
        let wire = <NetCallerWire as zerocopy::FromBytes>::read_from_bytes(head).ok()?;
        let id = core::num::NonZeroI32::new(wire.task_id.get()).filter(|id| id.get() > 0)?;
        let task = carrick_sched_core::process::TaskKey {
            id: carrick_sched_core::process::TaskId::from_registry_allocation(id),
            serial: carrick_sched_core::process::TaskSerial::from_raw_u64(wire.task_serial.get())?,
        };
        let [ruid, euid, suid, fsuid, rgid, egid, sgid, fsgid] = wire.ids.map(|id| id.get());
        Some((
            Self {
                task,
                ns_pid: core::num::NonZeroU32::new(wire.ns_pid.get())?,
                ids: AccessIds {
                    ruid,
                    euid,
                    suid,
                    fsuid,
                    rgid,
                    egid,
                    sgid,
                    fsgid,
                },
                cap_effective: wire.cap_effective.get(),
            },
            call,
        ))
    }
}

/// Bytes of one Linux `struct pollfd` (`int fd; short events, revents`).
pub const POLLFD_BYTES: usize = 8;
/// Timestamp request flag distinguishing NULL times from two explicit NOWs.
pub const UTIMENS_NULL_TIMES: u32 = 1 << 31;
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

/// [`HostFileOp::Poll`] `args[2]`: the poll call's ring serial
/// ([`HostCallSerial`]).
pub const POLL_CALL_SERIAL_ARG: usize = 2;

/// One poll call's identity across the records its ring publishes for it
/// (#2414 review P0-2). The ring stamps a new serial on a call's first
/// record, at the call's own entry, and keeps it on every record it
/// publishes again for that call after a host-readiness wake; the carrier
/// keys the call's deadline on the member and this serial. A new call,
/// including one issued again after an interrupted one, has a new serial,
/// so it never inherits another call's deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct HostCallSerial(core::num::NonZeroU64);

impl HostCallSerial {
    pub const fn new(raw: core::num::NonZeroU64) -> Self {
        Self(raw)
    }

    /// `None` for an unstamped record (0).
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match core::num::NonZeroU64::new(raw) {
            Some(raw) => Some(Self(raw)),
            None => None,
        }
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
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
            13 => Self::Mkdirat,
            14 => Self::Unlinkat,
            15 => Self::Symlinkat,
            16 => Self::Linkat,
            17 => Self::Utimensat,
            18 => Self::SetFdTimes,
            19 => Self::Truncate,
            20 => Self::Ftruncate,
            21 => Self::Renameat,
            22 => Self::Fchdir,
            23 => Self::Readlinkat,
            24 => Self::Fchmod,
            25 => Self::Fchown,
            26 => Self::Fchmodat,
            27 => Self::Fchownat,
            28 => Self::NetSyscall,
            30 => Self::Fsync,
            31 => Self::Syncfs,
            32 => Self::SyncFileRange,
            33 => Self::Statfs,
            34 => Self::Fstatfs,
            35 => Self::Fallocate,
            36 => Self::Pwrite,
            37 => Self::GetXattr,
            38 => Self::ListXattr,
            39 => Self::SetXattr,
            40 => Self::Ioctl,
            _ => return None,
        })
    }

    /// Whether the operation resolves a path, or acts on a descriptor with
    /// the caller's own authority: [`HostFileOp::Fchdir`] checks its access
    /// to a directory, [`HostFileOp::Fchmod`] and [`HostFileOp::Fchown`]
    /// its ownership and privilege. Its input then leads with the caller's
    /// [`AccessContext`] (credentials, umask, cwd, root), followed by the
    /// path, if any.
    pub const fn resolves_path(self) -> bool {
        matches!(
            self,
            Self::Openat
                | Self::Faccessat
                | Self::Newfstatat
                | Self::Statx
                | Self::Mkdirat
                | Self::Unlinkat
                | Self::Symlinkat
                | Self::Linkat
                | Self::Utimensat
                | Self::Truncate
                | Self::Renameat
                | Self::Fchdir
                | Self::Readlinkat
                | Self::Fchmod
                | Self::Fchown
                | Self::Fchmodat
                | Self::Fchownat
                | Self::Statfs
                | Self::GetXattr
                | Self::ListXattr
                | Self::SetXattr
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
    /// Descriptor operand or the first pathname's base.
    pub fd: i32,
    /// Operation-specific flags (for example `AT_*` flags).
    pub flags: u32,
    /// Operation-specific scalar arguments.
    pub args: [u64; 4],
}

/// Rename and link encode the second pathname's descriptor in `args[0]`.
/// Zero denotes the caller's cwd. Other words carry the 32-bit fd plus one,
/// leaving descriptor zero distinguishable from the default.
pub const fn encode_second_path_fd(fd: Option<i32>) -> u64 {
    match fd {
        None => 0,
        Some(fd) => fd as u32 as u64 + 1,
    }
}

/// Decode the second path base. The outer option validates the wire word.
pub const fn decode_second_path_fd(word: u64) -> Option<Option<i32>> {
    match word.checked_sub(1) {
        None => Some(None),
        Some(fd) if fd <= u32::MAX as u64 => Some(Some(fd as i32)),
        Some(_) => None,
    }
}

const MAGIC: u32 = u32::from_le_bytes(*b"CHFR");
const VERSION: u16 = 1;
/// A native xattr record names a descriptor; the encoded pathname is empty.
pub const XATTR_DESCRIPTOR: u32 = 1;
/// A path xattr operates on the link itself.
pub const XATTR_NOFOLLOW: u32 = 2;

/// The Linux 64-bit statfs reply, identical on AArch64 and x86-64.
pub const STATFS_BYTES: usize = 120;

/// Fixed header, including the reply words.
pub const HOST_FILE_HEADER_BYTES: usize = 96;
/// Largest data chunk one record carries. Larger transfers are split by the
/// ring continuation.
pub const HOST_FILE_CHUNK_BYTES: usize = 64 * 1024;
/// Framing a record area carries beside one chunk of data: a network call's
/// caller, call and segment table, and its socket address.
pub const HOST_FILE_FRAMING_BYTES: usize = 4096;
/// Largest input or output area one record carries: one chunk and its
/// framing.
pub const HOST_FILE_AREA_BYTES: usize = HOST_FILE_CHUNK_BYTES + HOST_FILE_FRAMING_BYTES;
/// Largest complete record.
pub const MAX_HOST_FILE_RECORD_BYTES: u64 =
    (HOST_FILE_HEADER_BYTES + 2 * HOST_FILE_AREA_BYTES) as u64;

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
/// bytes, or `None` when either exceeds one area.
pub const fn record_len(input_len: usize, output_cap: usize) -> Option<usize> {
    if input_len > HOST_FILE_AREA_BYTES || output_cap > HOST_FILE_AREA_BYTES {
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

/// The staged input of a record whose reply was written: a reply's
/// meaning can depend on the request it answers ([`NetCall`]).
pub fn replied_input(bytes: &[u8]) -> Option<&[u8]> {
    if read_u32(bytes, 0)? != MAGIC || read_u32(bytes, STATE)? != REPLY_WRITTEN {
        return None;
    }
    let input_len = read_u32(bytes, INPUT_LEN)? as usize;
    let output_cap = read_u32(bytes, OUTPUT_CAP)? as usize;
    if record_len(input_len, output_cap)? != bytes.len() {
        return None;
    }
    bytes.get(HOST_FILE_HEADER_BYTES..HOST_FILE_HEADER_BYTES + input_len)
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
    record_parts(bytes, REPLY_PENDING)
}

/// [`request_parts`] of a record whose reply was written: the request a
/// reply answers, for the ring to continue the call with its next record
/// (#2414).
pub fn replied_parts(bytes: &[u8]) -> Option<(HostFileHeader, &[u8], usize)> {
    record_parts(bytes, REPLY_WRITTEN)
}

fn record_parts(bytes: &[u8], state: u32) -> Option<(HostFileHeader, &[u8], usize)> {
    if read_u32(bytes, 0) != Some(MAGIC)
        || read_u16(bytes, 4) != Some(VERSION)
        || read_u32(bytes, STATE) != Some(state)
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
    fn a_net_caller_round_trips_ahead_of_its_call() {
        let caller = NetCaller {
            task: carrick_sched_core::process::TaskKey {
                id: carrick_sched_core::process::TaskId::from_registry_allocation(
                    core::num::NonZeroI32::new(41).unwrap(),
                ),
                serial: carrick_sched_core::process::TaskSerial::from_raw_u64(9).unwrap(),
            },
            ns_pid: core::num::NonZeroU32::new(7).unwrap(),
            ids: AccessIds {
                ruid: 1000,
                euid: 1001,
                suid: 1002,
                fsuid: 1003,
                rgid: 2000,
                egid: 2001,
                sgid: 2002,
                fsgid: 2003,
            },
            cap_effective: 1 << 13,
        };
        let call = NetCall::encode(41, [2, 3, 0, 0, 0, 0], &[], &[]).unwrap();
        let mut input = caller.encode().to_vec();
        input.extend_from_slice(&call);
        let (decoded, rest) = NetCaller::split(&input).unwrap();
        assert_eq!(decoded, caller);
        assert_eq!(NetCall::decode(rest).unwrap().args[..2], [2, 3]);
        // An unstamped call is not a caller.
        assert!(NetCaller::split(&call).is_none());
        // The largest staged transfer, its address and framing fit a record.
        let data = alloc::vec![0u8; NET_TRANSFER_MAX_BYTES];
        let address = [0u8; 128];
        let segments = [
            NetSegment {
                address: 0x1000,
                len: NET_TRANSFER_MAX_BYTES as u32,
                input: true,
                output: false,
            },
            NetSegment {
                address: 0x2000,
                len: 128,
                input: true,
                output: false,
            },
        ];
        let send = NetCall::encode(44, [0; 6], &segments, &[&data, &address]).unwrap();
        assert!(NET_CALLER_BYTES + send.len() <= HOST_FILE_AREA_BYTES);
        let recv = [
            NetSegment {
                address: 0x1000,
                len: NET_TRANSFER_MAX_BYTES as u32,
                input: false,
                output: true,
            },
            NetSegment {
                address: 0x2000,
                len: 4,
                input: true,
                output: true,
            },
            NetSegment {
                address: 0x3000,
                len: 128,
                input: false,
                output: true,
            },
        ];
        assert!(NetCall::output_capacity(&recv) <= HOST_FILE_AREA_BYTES);
        // The largest inet datagram (65,535 bytes of IP datagram) is one
        // transfer.
        const { assert!(NET_TRANSFER_MAX_BYTES >= 65_535) };
    }

    #[test]
    fn net_call_round_trips_segments_and_written_extents() {
        let segments = [
            NetSegment {
                address: 0x1000,
                len: 4,
                input: true,
                output: true,
            },
            NetSegment {
                address: 0x2000,
                len: 16,
                input: false,
                output: true,
            },
            NetSegment {
                address: 0x3000,
                len: 2,
                input: true,
                output: false,
            },
        ];
        let input =
            NetCall::encode(207, [3, 4, 5, 6, 7, 8], &segments, &[b"\x10\0\0\0", b"ab"]).unwrap();
        let call = NetCall::decode(&input).unwrap();
        assert_eq!((call.canonical, call.args), (207, [3, 4, 5, 6, 7, 8]));
        assert_eq!(call.segments(), segments);
        let staged: alloc::vec::Vec<_> = call.staged().map(|(_, bytes)| bytes).collect();
        assert_eq!(staged, [Some(&b"\x10\0\0\0"[..]), None, Some(&b"ab"[..])]);
        assert_eq!(NetCall::output_capacity(&segments), 8 + 8 + 4 + 8 + 16);
        // Mismatched staged inputs are refused.
        assert!(NetCall::encode(207, [0; 6], &segments, &[b"ab"]).is_none());
        assert!(NetCall::decode(&input[..input.len() - 1]).is_none());

        let facts = NetTransferFacts {
            stream: true,
            blocking: false,
        };
        let reply = NetCall::encode_written(facts, &[(0, b"\x08\0\0\0"), (0, b"12345678")]);
        assert_eq!(
            NetCall::decode_written(&segments, &reply).unwrap(),
            (
                facts,
                alloc::vec![(0x1000, &b"\x08\0\0\0"[..]), (0x2000, &b"12345678"[..])]
            )
        );
        // Facts round-trip; an unknown fact is refused.
        for raw in 0..4 {
            assert_eq!(NetTransferFacts::from_raw(raw).unwrap().raw(), raw);
        }
        assert!(NetTransferFacts::from_raw(4).is_none());
        // An extent past its segment, or a trailing byte, is refused.
        let past = NetCall::encode_written(facts, &[(2, b"123"), (0, b"")]);
        assert!(NetCall::decode_written(&segments, &past).is_none());
        let mut trailing = reply.clone();
        trailing.push(0);
        assert!(NetCall::decode_written(&segments, &trailing).is_none());
    }

    #[test]
    fn record_rejects_oversized_output_and_errno_output() {
        let mut bytes = vec![0u8; record_len(0, 4).unwrap()];
        encode(&mut bytes, header(HostFileOp::Fstat), &[], 4).unwrap();
        let view = HostFileRequestView::parse(&mut bytes).unwrap();
        assert_eq!(view.reply(0, b"12345"), Err(HostFileRecordError::Invalid));
        let view = HostFileRequestView::parse(&mut bytes).unwrap();
        assert_eq!(view.reply(-9, b"1"), Err(HostFileRecordError::Invalid));
        assert!(record_len(HOST_FILE_AREA_BYTES + 1, 0).is_none());
    }
}
