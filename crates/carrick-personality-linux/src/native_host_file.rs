//! Linux routing and staging for a native process's host-file crossings.
//!
//! A ring-owned (native) process has one descriptor namespace, the ring's.
//! Calls on in-zone objects (pipes, eventfds, epoll, guest sockets) are
//! served in ring and never leave it. A call whose descriptor names a
//! host-backed open description, or that resolves a host path, genuinely
//! crosses: the ring stages a typed [`carrick_core_abi::host_file`] record
//! and the carrier serves it with the caller's authority. This module is the
//! single routing decision and the single staging step for both ISAs;
//! transports only carry the record.
extern crate alloc;

use crate::abi::entry::SyscallResult;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use carrick_core_abi::host_file::{
    self, HOST_FILE_CHUNK_BYTES, HostFileHeader, HostFileOp, record_len,
};
use carrick_guest_arch::Access;
use carrick_syscall_abi::{CanonicalNr, LinuxErrno};

/// Size of the aarch64 Linux `struct stat` (`asm-generic/stat.h`).
pub const LINUX_STAT_BYTES: usize = core::mem::size_of::<carrick_syscall_abi::LinuxStat>();
/// Size of Linux `struct statx`.
pub const LINUX_STATX_BYTES: usize = core::mem::size_of::<carrick_syscall_abi::LinuxStatx>();
/// Linux `UIO_MAXIOV`.
pub const LINUX_UIO_MAXIOV: u64 = 1024;
/// Linux `PATH_MAX`, including the terminating NUL.
pub const LINUX_PATH_MAX: usize = 4096;
/// Linux `AT_FDCWD`.
pub const LINUX_AT_FDCWD: i32 = -100;
/// Linux `AT_EMPTY_PATH`.
pub const LINUX_AT_EMPTY_PATH: u32 = 0x1000;
const IOVEC_BYTES: usize = 16;
const PAGE_BYTES: u64 = 4096;

/// Access mode of the open description a descriptor names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptionAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
    /// `O_PATH`: no data access.
    Path,
}

impl DescriptionAccess {
    const fn writable(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }
    const fn readable(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }
}

/// The in-zone object kinds the ring owns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InZoneKind {
    Pipe,
    EventFd,
    Epoll,
}

/// What the caller's descriptor names, resolved in its own ring table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDescriptor {
    /// An in-zone object; the ring owns every operation on it.
    InZone(InZoneKind),
    /// A host-backed open description.
    HostBacked { access: DescriptionAccess },
    /// No open descriptor with this number.
    Absent,
}

/// The caller's complete ring namespace: its table id (the fd-core raw
/// table words) and a resolver for its descriptors. A resolver answer of
/// `None` means the table is contended or unpublished.
pub struct NativeNamespace<'a> {
    pub table: [u64; 3],
    pub resolve: &'a mut dyn FnMut(i32) -> Option<NativeDescriptor>,
}

/// A host-file call the native venue knows, decoded from canonical
/// arguments. Pointers are still untrusted user addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostFileCall {
    Write {
        fd: i32,
        buf: u64,
        count: u64,
    },
    Writev {
        fd: i32,
        iov: u64,
        iovcnt: u64,
    },
    Fstat {
        fd: i32,
        statbuf: u64,
    },
    Openat {
        dirfd: i32,
        path: u64,
        flags: u64,
        mode: u64,
    },
    Faccessat {
        dirfd: i32,
        path: u64,
        mode: u64,
        flags: u64,
    },
    Newfstatat {
        dirfd: i32,
        path: u64,
        statbuf: u64,
        flags: u64,
    },
    Statx {
        dirfd: i32,
        path: u64,
        flags: u64,
        mask: u64,
        buf: u64,
    },
    Read {
        fd: i32,
        buf: u64,
        count: u64,
    },
    Pread {
        fd: i32,
        buf: u64,
        count: u64,
        offset: u64,
    },
    Lseek {
        fd: i32,
        offset: u64,
        whence: u64,
    },
    Getdents64 {
        fd: i32,
        dirp: u64,
        count: u64,
    },
    Ioctl {
        fd: i32,
        request: u64,
    },
    /// A private file mapping (`mmap` without `MAP_ANONYMOUS`/`MAP_SHARED`).
    MapPrivate(NativeMapKey),
}

/// The exact arguments of a private file `mmap`. The carrier retains the
/// file as a byte source; the ring's reservation owner then maps it when the
/// same call is retried with exactly these arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeMapKey {
    pub address: u64,
    pub length: u64,
    pub prot: u64,
    pub flags: u64,
    pub fd: i32,
    pub offset: u64,
}

impl NativeMapKey {
    /// The key of an `mmap` call's six arguments.
    pub const fn of(args: &[u64; 6]) -> Self {
        Self {
            address: args[0],
            length: args[1],
            prot: args[2],
            flags: args[3],
            fd: args[4] as i32,
            offset: args[5],
        }
    }
}

/// Linux aarch64 `mmap` (canonical number).
pub const LINUX_NR_MMAP: CanonicalNr = CanonicalNr(222);
/// Linux `MAP_SHARED`, `MAP_PRIVATE`, `MAP_ANONYMOUS`.
pub const LINUX_MAP_SHARED: u64 = 0x01;
pub const LINUX_MAP_PRIVATE: u64 = 0x02;
pub const LINUX_MAP_ANONYMOUS: u64 = 0x20;

impl HostFileCall {
    /// Decode a canonical syscall the venue may serve. `None` for every
    /// other call, which keeps its existing in-ring or unrouted handling.
    pub fn decode(canonical: CanonicalNr, args: &[u64; 6]) -> Option<Self> {
        use crate::crossing::nr;
        let fd = args[0] as i32;
        Some(match canonical {
            c if c == nr::WRITE => Self::Write {
                fd,
                buf: args[1],
                count: args[2],
            },
            c if c == nr::WRITEV => Self::Writev {
                fd,
                iov: args[1],
                iovcnt: args[2],
            },
            c if c == nr::FSTAT => Self::Fstat {
                fd,
                statbuf: args[1],
            },
            c if c == nr::OPENAT => Self::Openat {
                dirfd: fd,
                path: args[1],
                flags: args[2],
                mode: args[3],
            },
            c if c == nr::FACCESSAT => Self::Faccessat {
                dirfd: fd,
                path: args[1],
                mode: args[2],
                flags: 0,
            },
            c if c == nr::FACCESSAT2 => Self::Faccessat {
                dirfd: fd,
                path: args[1],
                mode: args[2],
                flags: args[3],
            },
            c if c == nr::NEWFSTATAT => Self::Newfstatat {
                dirfd: fd,
                path: args[1],
                statbuf: args[2],
                flags: args[3],
            },
            c if c == nr::STATX => Self::Statx {
                dirfd: fd,
                path: args[1],
                flags: args[2],
                mask: args[3],
                buf: args[4],
            },
            c if c == nr::READ => Self::Read {
                fd,
                buf: args[1],
                count: args[2],
            },
            c if c == nr::PREAD64 => Self::Pread {
                fd,
                buf: args[1],
                count: args[2],
                offset: args[3],
            },
            c if c == nr::LSEEK => Self::Lseek {
                fd,
                offset: args[1],
                whence: args[2],
            },
            c if c == nr::GETDENTS64 => Self::Getdents64 {
                fd,
                dirp: args[1],
                count: args[2],
            },
            c if c == nr::IOCTL => Self::Ioctl {
                fd,
                request: args[1],
            },
            c if c == LINUX_NR_MMAP
                && args[3] & (LINUX_MAP_ANONYMOUS | LINUX_MAP_SHARED | LINUX_MAP_PRIVATE)
                    == LINUX_MAP_PRIVATE =>
            {
                Self::MapPrivate(NativeMapKey::of(args))
            }
            _ => return None,
        })
    }
}

/// User memory as the staging step needs it. Before a request with output
/// crosses, its whole output range must already be writable, so the reply's
/// copy-out cannot need a page the ring would have to supply mid-completion:
/// staging asks for fault supply first and retries the exact call, and a
/// refused supply is EFAULT, as Linux reports a bad buffer.
pub trait HostFileUser {
    fn copy_in(&mut self, dst: &mut [u8], src: u64) -> bool;
    /// Contiguous bytes from `dst` that user mode can write now.
    fn writable(&mut self, dst: u64, len: usize) -> usize;
}

/// User output the ring copies back after the carrier replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostFileOutput {
    pub address: u64,
    pub len: usize,
}

/// The ring's routing decision for one decoded call.
#[derive(Debug, Eq, PartialEq)]
pub enum HostFileStage {
    /// An in-zone object this venue does not serve: the call stays with its
    /// ring owner (counted ENOSYS until that owner serves it) and never
    /// builds a host request.
    InRing,
    /// Answered in ring without crossing.
    Returned(SyscallResult),
    /// Answered in ring with user output: the ring copies `bytes` to
    /// `output` itself and returns 0. Staging has already proved the
    /// destination writable.
    InRingReply {
        output: HostFileOutput,
        bytes: Box<[u8]>,
    },
    /// A user page must be supplied before staging can continue; the ring
    /// retries the exact call afterwards.
    Fault { address: u64, access: Access },
    /// A host crossing: the staged record and where its output goes.
    Request {
        record: Box<[u8]>,
        output: Option<HostFileOutput>,
        /// The carrier resolves a path, so the caller's credentials must
        /// be the authority it uses.
        resolves_path: bool,
        /// A private file mapping: the reply is a byte source the ring maps
        /// on the exact retried call, not a syscall result.
        map: Option<NativeMapKey>,
    },
}

/// `fstat`/`statx` of an in-zone object, answered in ring with the record
/// the dispatcher reports for the same kind of object: both encode one
/// shared [`carrick_syscall_abi::LinuxStatFields`].
fn in_zone_stat(op: HostFileOp, kind: InZoneKind, output: HostFileOutput) -> HostFileStage {
    let fields = match kind {
        InZoneKind::Pipe => carrick_syscall_abi::LinuxStatFields::CARRICK_PIPE,
        InZoneKind::EventFd => carrick_syscall_abi::LinuxStatFields::CARRICK_EVENTFD,
        InZoneKind::Epoll => carrick_syscall_abi::LinuxStatFields::CARRICK_EPOLL,
    };
    let bytes: Box<[u8]> = match op {
        HostFileOp::Statx => {
            zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxStatx::from_fields(&fields))
                .into()
        }
        _ => zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxStat::from_fields(&fields))
            .into(),
    };
    HostFileStage::InRingReply { output, bytes }
}

fn errno(errno: LinuxErrno) -> HostFileStage {
    HostFileStage::Returned(SyscallResult::from_errno(errno))
}

/// Linux terminal requests (the `'T'` ioctl group): on a pipe or eventfd
/// they are `ENOTTY`.
fn is_terminal_request(request: u64) -> bool {
    (request & 0xff00) == 0x5400
}

enum Path {
    Bytes(Vec<u8>),
    Stage(HostFileStage),
}

/// Copy a NUL-terminated user path without reading past its terminator's
/// page. The result excludes the NUL.
fn copy_path(user: &mut dyn HostFileUser, address: u64) -> Path {
    let mut bytes = Vec::new();
    let mut cursor = address;
    loop {
        let room = (PAGE_BYTES - cursor % PAGE_BYTES) as usize;
        let take = room.min(LINUX_PATH_MAX - bytes.len());
        let mut chunk = vec![0u8; take];
        if !user.copy_in(&mut chunk, cursor) {
            // Retry the exact call after supply; a refused supply is EFAULT.
            return Path::Stage(HostFileStage::Fault {
                address: cursor,
                access: Access::Read,
            });
        }
        if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Path::Bytes(bytes);
        }
        bytes.extend_from_slice(&chunk);
        if bytes.len() >= LINUX_PATH_MAX {
            return Path::Stage(errno(carrick_syscall_abi::LINUX_ENAMETOOLONG));
        }
        cursor = match cursor.checked_add(take as u64) {
            Some(next) => next,
            None => return Path::Stage(errno(carrick_syscall_abi::LINUX_EFAULT)),
        };
    }
}

struct Staging<'n, 'u> {
    namespace: &'n mut NativeNamespace<'u>,
}

impl Staging<'_, '_> {
    fn request(
        &self,
        op: HostFileOp,
        fd: i32,
        flags: u32,
        args: [u64; 4],
        input: &[u8],
        output: Option<HostFileOutput>,
    ) -> HostFileStage {
        let output_cap = output.map_or(0, |output| output.len);
        self.request_with_reply(op, fd, flags, args, input, output, output_cap)
    }

    /// A request whose reply area (`output_cap`) is not copied to the user:
    /// the ring itself consumes it (a private mapping's byte source).
    #[allow(clippy::too_many_arguments)]
    fn request_with_reply(
        &self,
        op: HostFileOp,
        fd: i32,
        flags: u32,
        args: [u64; 4],
        input: &[u8],
        output: Option<HostFileOutput>,
        output_cap: usize,
    ) -> HostFileStage {
        let Some(len) = record_len(input.len(), output_cap) else {
            return errno(carrick_syscall_abi::LINUX_EINVAL);
        };
        let mut record = vec![0u8; len].into_boxed_slice();
        let header = HostFileHeader {
            op,
            table: self.namespace.table,
            fd,
            flags,
            args,
        };
        if host_file::encode(&mut record, header, input, output_cap).is_err() {
            return errno(carrick_syscall_abi::LINUX_EINVAL);
        }
        HostFileStage::Request {
            record,
            output,
            resolves_path: op.resolves_path(),
            map: None,
        }
    }

    fn descriptor(&mut self, fd: i32) -> Option<NativeDescriptor> {
        (self.namespace.resolve)(fd)
    }

    /// Route a path call's `dirfd`. A relative path through a descriptor
    /// other than `AT_FDCWD` needs that directory as the base, which a
    /// later slice serves; until then it is a counted ENOSYS, never a guess.
    fn path_base(&mut self, dirfd: i32, path: &[u8]) -> Option<Option<HostFileStage>> {
        if dirfd == LINUX_AT_FDCWD || path.first() == Some(&b'/') {
            return Some(None);
        }
        Some(Some(match self.descriptor(dirfd)? {
            NativeDescriptor::InZone(_) => errno(carrick_syscall_abi::LINUX_ENOTDIR),
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { .. } => errno(carrick_syscall_abi::LINUX_ENOSYS),
        }))
    }

    /// Stage `fstat`/`statx` of a descriptor (`AT_EMPTY_PATH` or `fstat`).
    fn descriptor_stat(
        &mut self,
        op: HostFileOp,
        fd: i32,
        flags: u32,
        args: [u64; 4],
        output: HostFileOutput,
    ) -> Option<HostFileStage> {
        Some(match self.descriptor(fd)? {
            NativeDescriptor::InZone(kind) => in_zone_stat(op, kind, output),
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { .. } => {
                self.request(op, fd, flags, args, &[], Some(output))
            }
        })
    }

    fn write(
        &mut self,
        fd: i32,
        user: &mut dyn HostFileUser,
        gather: impl FnOnce(&mut dyn HostFileUser) -> Result<Vec<u8>, HostFileStage>,
    ) -> Option<HostFileStage> {
        Some(match self.descriptor(fd)? {
            NativeDescriptor::InZone(_) => HostFileStage::InRing,
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { access } if !access.writable() => {
                errno(carrick_syscall_abi::LINUX_EBADF)
            }
            NativeDescriptor::HostBacked { .. } => match gather(user) {
                Ok(input) if input.is_empty() => HostFileStage::Returned(SyscallResult::new(0)),
                Ok(input) => self.request(HostFileOp::Write, fd, 0, [0; 4], &input, None),
                Err(stage) => stage,
            },
        })
    }
}

fn chunk(count: u64) -> usize {
    (count as usize).min(HOST_FILE_CHUNK_BYTES)
}

/// Gather `writev` vectors into one bounded chunk, in order.
fn gather_vectors(
    user: &mut dyn HostFileUser,
    iov: u64,
    iovcnt: u64,
) -> Result<Vec<u8>, HostFileStage> {
    if iovcnt > LINUX_UIO_MAXIOV {
        return Err(errno(carrick_syscall_abi::LINUX_EINVAL));
    }
    let mut vectors = vec![0u8; iovcnt as usize * IOVEC_BYTES];
    if !vectors.is_empty() && !user.copy_in(&mut vectors, iov) {
        return Err(HostFileStage::Fault {
            address: iov,
            access: Access::Read,
        });
    }
    // Linux rejects a negative total before any transfer.
    let mut total: u64 = 0;
    let mut segments = Vec::with_capacity(iovcnt as usize);
    for vector in vectors.chunks_exact(IOVEC_BYTES) {
        let base = u64::from_le_bytes(vector[0..8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(vector[8..16].try_into().unwrap_or([0; 8]));
        total = match total.checked_add(len) {
            Some(total) if total <= i64::MAX as u64 => total,
            _ => return Err(errno(carrick_syscall_abi::LINUX_EINVAL)),
        };
        segments.push((base, len));
    }
    let mut input = Vec::with_capacity(chunk(total));
    for (base, len) in segments {
        let room = HOST_FILE_CHUNK_BYTES - input.len();
        if room == 0 {
            break;
        }
        let take = (len as usize).min(room);
        let start = input.len();
        input.resize(start + take, 0);
        if !user.copy_in(&mut input[start..], base) {
            // Supply first and retry the exact call; a refused supply
            // completes as EFAULT.
            return Err(HostFileStage::Fault {
                address: base,
                access: Access::Read,
            });
        }
    }
    Ok(input)
}

/// Route and stage one decoded call. `None` keeps the call on its existing
/// route (a contended or unpublished namespace, or a call this venue does
/// not own).
pub fn stage(
    call: HostFileCall,
    namespace: &mut NativeNamespace<'_>,
    user: &mut dyn HostFileUser,
) -> Option<HostFileStage> {
    let staged = stage_call(call, namespace, user)?;
    if let HostFileStage::Request {
        output: Some(output),
        ..
    }
    | HostFileStage::InRingReply { output, .. } = &staged
    {
        let writable = user.writable(output.address, output.len);
        if writable < output.len {
            return Some(HostFileStage::Fault {
                address: output.address.saturating_add(writable as u64),
                access: Access::Write,
            });
        }
    }
    Some(staged)
}

fn stage_call(
    call: HostFileCall,
    namespace: &mut NativeNamespace<'_>,
    user: &mut dyn HostFileUser,
) -> Option<HostFileStage> {
    let mut staging = Staging { namespace };
    Some(match call {
        HostFileCall::Write { fd, buf, count } => {
            return staging.write(fd, user, |user| {
                let mut input = vec![0u8; chunk(count)];
                if !input.is_empty() && !user.copy_in(&mut input, buf) {
                    return Err(HostFileStage::Fault {
                        address: buf,
                        access: Access::Read,
                    });
                }
                Ok(input)
            });
        }
        HostFileCall::Writev { fd, iov, iovcnt } => {
            return staging.write(fd, user, |user| gather_vectors(user, iov, iovcnt));
        }
        HostFileCall::Fstat { fd, statbuf } => staging.descriptor_stat(
            HostFileOp::Fstat,
            fd,
            0,
            [0; 4],
            HostFileOutput {
                address: statbuf,
                len: LINUX_STAT_BYTES,
            },
        )?,
        HostFileCall::Openat {
            dirfd,
            path,
            flags,
            mode,
        } => {
            let path = match copy_path(user, path) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            if path.is_empty() {
                return Some(errno(carrick_syscall_abi::LINUX_ENOENT));
            }
            if let Some(answer) = staging.path_base(dirfd, &path)? {
                return Some(answer);
            }
            staging.request(
                HostFileOp::Openat,
                LINUX_AT_FDCWD,
                0,
                [flags, mode, 0, 0],
                &path,
                None,
            )
        }
        HostFileCall::Faccessat {
            dirfd,
            path,
            mode,
            flags,
        } => {
            let path = match copy_path(user, path) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            if path.is_empty() {
                // An AT_EMPTY_PATH descriptor check needs the descriptor's
                // inode, which a later slice serves.
                return Some(errno(if flags as u32 & LINUX_AT_EMPTY_PATH != 0 {
                    carrick_syscall_abi::LINUX_ENOSYS
                } else {
                    carrick_syscall_abi::LINUX_ENOENT
                }));
            }
            if let Some(answer) = staging.path_base(dirfd, &path)? {
                return Some(answer);
            }
            staging.request(
                HostFileOp::Faccessat,
                LINUX_AT_FDCWD,
                flags as u32,
                [mode, 0, 0, 0],
                &path,
                None,
            )
        }
        HostFileCall::Newfstatat {
            dirfd,
            path,
            statbuf,
            flags,
        } => {
            let path = match copy_path(user, path) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            let output = HostFileOutput {
                address: statbuf,
                len: LINUX_STAT_BYTES,
            };
            if path.is_empty() {
                if flags as u32 & LINUX_AT_EMPTY_PATH == 0 {
                    return Some(errno(carrick_syscall_abi::LINUX_ENOENT));
                }
                if dirfd != LINUX_AT_FDCWD {
                    return staging.descriptor_stat(HostFileOp::Fstat, dirfd, 0, [0; 4], output);
                }
            }
            if let Some(answer) = staging.path_base(dirfd, &path)? {
                return Some(answer);
            }
            let path: &[u8] = if path.is_empty() { b"." } else { &path };
            staging.request(
                HostFileOp::Newfstatat,
                LINUX_AT_FDCWD,
                flags as u32,
                [0; 4],
                path,
                Some(output),
            )
        }
        HostFileCall::Statx {
            dirfd,
            path,
            flags,
            mask,
            buf,
        } => {
            let path = match copy_path(user, path) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            let output = HostFileOutput {
                address: buf,
                len: LINUX_STATX_BYTES,
            };
            if path.is_empty() {
                if flags as u32 & LINUX_AT_EMPTY_PATH == 0 {
                    return Some(errno(carrick_syscall_abi::LINUX_ENOENT));
                }
                if dirfd != LINUX_AT_FDCWD {
                    return staging.descriptor_stat(
                        HostFileOp::Statx,
                        dirfd,
                        flags as u32,
                        [mask, 0, 0, 0],
                        output,
                    );
                }
            }
            if let Some(answer) = staging.path_base(dirfd, &path)? {
                return Some(answer);
            }
            let path: &[u8] = if path.is_empty() { b"." } else { &path };
            staging.request(
                HostFileOp::Statx,
                LINUX_AT_FDCWD,
                flags as u32,
                [mask, 0, 0, 0],
                path,
                Some(output),
            )
        }
        HostFileCall::Read { fd, buf, count } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(_) => HostFileStage::InRing,
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { access } if !access.readable() => {
                errno(carrick_syscall_abi::LINUX_EBADF)
            }
            NativeDescriptor::HostBacked { .. } => staging.request(
                HostFileOp::Read,
                fd,
                0,
                [0; 4],
                &[],
                Some(HostFileOutput {
                    address: buf,
                    len: chunk(count),
                }),
            ),
        },
        HostFileCall::Pread {
            fd,
            buf,
            count,
            offset,
        } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(InZoneKind::Pipe) => errno(carrick_syscall_abi::LINUX_ESPIPE),
            NativeDescriptor::InZone(_) => HostFileStage::InRing,
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { access } if !access.readable() => {
                errno(carrick_syscall_abi::LINUX_EBADF)
            }
            NativeDescriptor::HostBacked { .. } if (offset as i64) < 0 => {
                errno(carrick_syscall_abi::LINUX_EINVAL)
            }
            NativeDescriptor::HostBacked { .. } => staging.request(
                HostFileOp::Pread,
                fd,
                0,
                [offset, 0, 0, 0],
                &[],
                Some(HostFileOutput {
                    address: buf,
                    len: chunk(count),
                }),
            ),
        },
        HostFileCall::Lseek { fd, offset, whence } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(InZoneKind::Pipe) => errno(carrick_syscall_abi::LINUX_ESPIPE),
            NativeDescriptor::InZone(_) => HostFileStage::InRing,
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { .. } => {
                staging.request(HostFileOp::Lseek, fd, 0, [offset, whence, 0, 0], &[], None)
            }
        },
        HostFileCall::Getdents64 { fd, dirp, count } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(_) => errno(carrick_syscall_abi::LINUX_ENOTDIR),
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { .. } => staging.request(
                HostFileOp::Getdents64,
                fd,
                0,
                [0; 4],
                &[],
                Some(HostFileOutput {
                    address: dirp,
                    len: chunk(count),
                }),
            ),
        },
        HostFileCall::Ioctl { fd, request } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(InZoneKind::Pipe | InZoneKind::EventFd)
                if is_terminal_request(request) =>
            {
                errno(carrick_syscall_abi::LINUX_ENOTTY)
            }
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            // Other requests, and host-backed terminals, keep their route.
            _ => return None,
        },
        HostFileCall::MapPrivate(key) => match staging.descriptor(key.fd)? {
            // Linux: a pipe, eventfd or epoll has no mmap operation.
            NativeDescriptor::InZone(_) => errno(carrick_syscall_abi::LINUX_ENODEV),
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { access } if !access.readable() => {
                errno(carrick_syscall_abi::LINUX_EACCES)
            }
            NativeDescriptor::HostBacked { .. }
                if key.length == 0 || key.offset % PAGE_BYTES != 0 =>
            {
                errno(carrick_syscall_abi::LINUX_EINVAL)
            }
            NativeDescriptor::HostBacked { .. } => match staging.request_with_reply(
                HostFileOp::MapPrivate,
                key.fd,
                0,
                [key.offset, key.length, 0, 0],
                &[],
                None,
                host_file::MapSourceReply::BYTES,
            ) {
                HostFileStage::Request {
                    record,
                    output,
                    resolves_path,
                    ..
                } => HostFileStage::Request {
                    record,
                    output,
                    resolves_path,
                    map: Some(key),
                },
                other => other,
            },
        },
    })
}

/// The byte source a private-mapping reply carries, or the syscall result
/// that replaces the mapping (an errno, or EIO for a missing reply).
pub fn map_source(record: &[u8]) -> Result<host_file::MapSourceReply, SyscallResult> {
    let Some(reply) = host_file::reply(record) else {
        return Err(SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO));
    };
    if reply.result < 0 {
        return Err(SyscallResult::new(reply.result));
    }
    host_file::MapSourceReply::decode(reply.output)
        .ok_or(SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO))
}

/// Map the carrier's reply to the syscall result, copying any output back
/// through the ring's own user copy.
pub fn complete(
    record: &[u8],
    output: Option<HostFileOutput>,
    copy_out: &mut dyn FnMut(u64, &[u8]) -> bool,
) -> SyscallResult {
    let Some(reply) = host_file::reply(record) else {
        return SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO);
    };
    if reply.result < 0 {
        return SyscallResult::new(reply.result);
    }
    if let Some(output) = output {
        if reply.output.len() > output.len {
            return SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO);
        }
        if !reply.output.is_empty() && !copy_out(output.address, reply.output) {
            return SyscallResult::from_errno(carrick_syscall_abi::LINUX_EFAULT);
        }
    }
    SyscallResult::new(reply.result)
}

#[cfg(test)]
mod tests;
