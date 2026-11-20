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

pub use carrick_syscall_abi::{LinuxPipeIdentity, LinuxSocketIdentity};

use crate::abi::entry::SyscallResult;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use carrick_core_abi::host_file::{
    self, HOST_FILE_CHUNK_BYTES, HostFileHeader, HostFileOp, record_len,
};
use carrick_core_abi::service::ServiceOrigin;
use carrick_guest_arch::Access;
use carrick_syscall_abi::{CanonicalNr, LinuxErrno};

/// Size of the aarch64 Linux `struct stat` (`asm-generic/stat.h`).
pub const LINUX_STAT_BYTES: usize = core::mem::size_of::<carrick_syscall_abi::LinuxStat>();
/// Size of Linux `struct statx`.
pub const LINUX_STATX_BYTES: usize = core::mem::size_of::<carrick_syscall_abi::LinuxStatx>();
/// Linux x86_64 `struct stat` size.
pub const X8664_STAT_BYTES: usize = core::mem::size_of::<carrick_syscall_abi::LinuxX8664Stat>();
/// Linux `UIO_MAXIOV`.
pub const LINUX_UIO_MAXIOV: u64 = 1024;
/// Linux `PATH_MAX`, including the terminating NUL.
pub const LINUX_PATH_MAX: usize = 4096;
/// Linux `AT_FDCWD`.
pub const LINUX_AT_FDCWD: i32 = -100;
/// Linux `AT_EMPTY_PATH`.
pub const LINUX_AT_EMPTY_PATH: u32 = 0x1000;
const IOVEC_BYTES: usize = 16;

mod socket;
pub use socket::{
    NetTransfer, NetTransferStep, SocketCall, is_net_transfer, net_caller, net_transfer_record,
    net_transfer_step, stamp_net_caller,
};
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
    Pipe(LinuxPipeIdentity),
    EventFd,
    Epoll,
    /// One end of a ring `AF_UNIX` stream pair.
    Stream(LinuxSocketIdentity),
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
    /// Pops the byte sources the caller's reservation owner retired into
    /// the slice and returns how many; called only when a private-mapping
    /// request is built, which carries them to the carrier for release.
    pub releases: &'a mut dyn FnMut(&mut [host_file::MapSourceReply]) -> usize,
}

/// Signed Linux readlink buffer size, decoded from the syscall int argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadlinkSize(pub i32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrOperand {
    Path { address: u64, follow: bool },
    Description(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrCall {
    Get {
        name: u64,
        output: u64,
        size: u64,
    },
    List {
        output: u64,
        size: u64,
    },
    Set {
        name: u64,
        value: u64,
        size: u64,
        flags: u64,
    },
}

/// A host-file call the native venue knows, decoded from canonical
/// arguments. Pointers are still untrusted user addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostFileCall {
    Xattr {
        operand: XattrOperand,
        call: XattrCall,
    },
    Fsync {
        fd: i32,
    },
    Syncfs {
        fd: i32,
    },
    SyncFileRange {
        fd: i32,
        offset: u64,
        length: u64,
        flags: u64,
    },
    Statfs {
        path: u64,
        output: u64,
    },
    Fstatfs {
        fd: i32,
        output: u64,
    },
    Fallocate {
        fd: i32,
        mode: u64,
        offset: u64,
        length: u64,
    },
    Pwrite64 {
        fd: i32,
        buf: u64,
        count: u64,
        offset: i64,
    },
    Pwritev {
        fd: i32,
        iov: u64,
        iovcnt: u64,
        offset: i64,
    },
    Readv {
        fd: i32,
        iov: u64,
        iovcnt: u64,
        offset: Option<i64>,
    },
    Readlinkat {
        dirfd: carrick_fd_core::Fd,
        path: carrick_guest_arch::UserVa,
        buf: carrick_guest_arch::UserVa,
        bufsiz: ReadlinkSize,
    },
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
        layout: StatLayout,
    },
    Openat {
        dirfd: i32,
        path: u64,
        flags: u64,
        mode: u64,
    },
    Mkdirat {
        dirfd: i32,
        path: u64,
        mode: u64,
    },
    Unlinkat {
        dirfd: i32,
        path: u64,
        flags: u64,
    },
    Symlinkat {
        target: u64,
        dirfd: i32,
        path: u64,
    },
    Linkat {
        olddirfd: i32,
        oldpath: u64,
        newdirfd: i32,
        newpath: u64,
        flags: u64,
    },
    Utimensat {
        dirfd: i32,
        path: u64,
        times: u64,
        flags: u64,
    },
    Renameat {
        olddirfd: i32,
        oldpath: u64,
        newdirfd: i32,
        newpath: u64,
        flags: u64,
    },
    Truncate {
        path: u64,
        length: u64,
    },
    Ftruncate {
        fd: i32,
        length: u64,
    },
    Fchmod {
        fd: i32,
        mode: u64,
    },
    Fchown {
        fd: i32,
        owner: u64,
        group: u64,
    },
    /// `fchmodat` (whose `flags` Linux ignores, decoded as 0) or
    /// `fchmodat2`.
    Fchmodat {
        dirfd: i32,
        path: u64,
        mode: u64,
        flags: u64,
    },
    Fchownat {
        dirfd: i32,
        path: u64,
        owner: u64,
        group: u64,
        flags: u64,
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
        layout: StatLayout,
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
        arg: u64,
    },
    /// A private file mapping (`mmap` without `MAP_ANONYMOUS`/`MAP_SHARED`).
    MapPrivate(NativeMapKey),
    /// `chdir(2)`: one chdir lookup crossing, then the ring updates the
    /// caller's task row (#1392).
    Chdir {
        path: u64,
    },
    /// `fchdir(2)`: the chdir lookup of the directory a descriptor names,
    /// completed as [`HostFileCall::Chdir`] is (#2206).
    Fchdir {
        fd: i32,
    },
    /// `ppoll(2)` that its in-ring owner left unrouted. Only a set whose
    /// every live entry is host-backed (or absent) and that installs no
    /// signal mask crosses, as a non-blocking readiness snapshot
    /// ([`HostFileOp::Poll`]); every other set keeps its route (#1051).
    Ppoll {
        fds: u64,
        nfds: u64,
        timeout: u64,
        sigmask: u64,
    },
    /// x86_64 `poll(2)` ([`HostFileCall::decode_native`]):
    /// [`HostFileCall::Ppoll`] with an int millisecond timeout (negative:
    /// none) and no signal mask.
    Poll {
        fds: u64,
        nfds: u64,
        timeout_ms: i32,
    },
    /// The host network socket family (#231): AF_INET and AF_INET6 sockets
    /// are host objects, and every call on one crosses.
    Socket(SocketCall),
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
    /// These native-child mutations (of the namespace, or of the caller's
    /// cwd for `fchdir`) reuse host syscall cores. The initial task keeps
    /// its existing host-task route and publication authority.
    pub const fn uses_child_mutation_venue(self) -> bool {
        matches!(
            self,
            Self::Mkdirat { .. }
                | Self::Fchdir { .. }
                | Self::Unlinkat { .. }
                | Self::Symlinkat { .. }
                | Self::Linkat { .. }
                | Self::Renameat { .. }
                | Self::Utimensat { .. }
                | Self::Truncate { .. }
                | Self::Ftruncate { .. }
                | Self::Fchmodat { .. }
                | Self::Fchownat { .. }
        )
    }

    /// Calls only a native child stages: the initial task keeps its existing
    /// host route for them (its host-task namespace mutations, and its host
    /// network sockets).
    pub const fn child_venue_only(self) -> bool {
        self.uses_child_mutation_venue() || matches!(self, Self::Socket(_))
    }

    /// Mutations with a directory operand from the CPL0 ring table.
    fn uses_ring_path_base(self) -> bool {
        match self {
            Self::Mkdirat { dirfd, .. }
            | Self::Unlinkat { dirfd, .. }
            | Self::Symlinkat { dirfd, .. }
            | Self::Utimensat { dirfd, .. }
            | Self::Fchmodat { dirfd, .. }
            | Self::Fchownat { dirfd, .. } => dirfd != LINUX_AT_FDCWD,
            Self::Renameat {
                olddirfd, newdirfd, ..
            }
            | Self::Linkat {
                olddirfd, newdirfd, ..
            } => olddirfd != LINUX_AT_FDCWD || newdirfd != LINUX_AT_FDCWD,
            _ => false,
        }
    }

    /// Whether the CPL0 venue stages this decoded call for `origin`.
    /// `delegated(fd)` says whether the carrier's file table delegates `fd` to
    /// a host object (the run's stdio streams).
    ///
    /// - Path opens, access checks and stats, descriptor stats, and reads,
    ///   seeks and directory reads are staged for every task: the descriptor
    ///   an open installs lives in the caller's ring namespace, so every later
    ///   call on it must resolve there too (#1714).
    /// - A read, seek or `write` of a delegated stdio descriptor keeps its
    ///   host route, which owns the terminal and blocking-read semantics.
    ///   `writev` has no host route, so it is staged for every descriptor.
    /// - Cwd-based mutations stay child-scoped. A path mutation naming a
    ///   directory descriptor follows that descriptor's owner. Descriptor
    ///   mutations such as `ftruncate`, `fchmod` and `fchown` also follow the
    ///   descriptor: the root's staged `openat` installs into the ring table
    ///   (#2157 B1, #231).
    /// - The initial task's cwd-based readlink keeps its existing route.
    ///   Descendants stage readlink through their own executable custody.
    ///   A directory operand follows the ring descriptor it names.
    /// - A child's host network calls and its polls of host objects are
    ///   staged (#231); the initial task keeps its routes for both.
    pub fn admitted_for(self, origin: ServiceOrigin, delegated: impl FnOnce(i32) -> bool) -> bool {
        match self {
            Self::Chdir { .. } => origin != ServiceOrigin::Initial,
            // A child's set of host objects (its host network sockets) waits
            // on its host-readiness queue (#231); the initial task's polls
            // keep their route.
            Self::Ppoll { .. } | Self::Poll { .. } => origin != ServiceOrigin::Initial,
            Self::Ftruncate { fd, .. } | Self::Fchmod { fd, .. } | Self::Fchown { fd, .. }
                if origin == ServiceOrigin::Initial =>
            {
                !delegated(fd)
            }
            Self::Xattr { operand, .. } => match operand {
                XattrOperand::Path { .. } => origin != ServiceOrigin::Initial,
                XattrOperand::Description(fd) => origin != ServiceOrigin::Initial || !delegated(fd),
            },
            Self::Ioctl { fd, .. } => origin != ServiceOrigin::Initial || !delegated(fd),
            Self::Pwrite64 { fd, .. } | Self::Pwritev { fd, .. } | Self::Readv { fd, .. } => {
                origin != ServiceOrigin::Initial || !delegated(fd)
            }
            Self::Fsync { fd }
            | Self::Syncfs { fd }
            | Self::SyncFileRange { fd, .. }
            | Self::Fstatfs { fd, .. }
            | Self::Fallocate { fd, .. } => origin != ServiceOrigin::Initial || !delegated(fd),
            Self::Statfs { .. } => origin != ServiceOrigin::Initial,
            Self::Readlinkat { dirfd, .. } => {
                origin != ServiceOrigin::Initial || dirfd.0 != LINUX_AT_FDCWD
            }
            call if call.child_venue_only() => {
                origin != ServiceOrigin::Initial || call.uses_ring_path_base()
            }
            // A descendant's descriptor lives in its ring namespace.
            Self::Fchmod { .. } | Self::Fchown { .. } => true,
            Self::Openat { .. }
            | Self::Faccessat { .. }
            | Self::Statx { .. }
            | Self::Newfstatat { .. }
            | Self::Fstat { .. }
            | Self::Getdents64 { .. }
            | Self::Writev { .. } => true,
            // A child's write has no host route; it is staged for every
            // descriptor.
            Self::Write { .. } if origin != ServiceOrigin::Initial => true,
            Self::Write { fd, .. }
            | Self::Read { fd, .. }
            | Self::Pread { fd, .. }
            | Self::Lseek { fd, .. } => !delegated(fd),
            _ => false,
        }
    }

    /// [`Self::decode`] of an ISA's native call. x86_64 `poll(2)` shares
    /// canonical `ppoll`'s number but passes an int millisecond timeout
    /// where `ppoll` passes a timespec pointer, so its native number alone
    /// tells the two apart.
    pub fn decode_native(
        isa: carrick_guest_arch::GuestIsa,
        native: carrick_guest_arch::NativeOrdinal,
        canonical: CanonicalNr,
        args: &[u64; 6],
    ) -> Option<Self> {
        if isa == carrick_guest_arch::GuestIsa::X86_64
            && native.raw() == carrick_syscall_abi::syscall_x86_64::X86_POLL.raw()
        {
            return Some(Self::Poll {
                fds: args[0],
                nfds: args[1],
                timeout_ms: args[2] as i32,
            });
        }
        Self::decode(canonical, args)
    }

    /// Decode a canonical syscall the venue may serve. `None` for every
    /// other call, which keeps its existing in-ring or unrouted handling.
    pub fn decode(canonical: CanonicalNr, args: &[u64; 6]) -> Option<Self> {
        use crate::crossing::nr;
        let fd = args[0] as i32;
        Some(match canonical {
            c if c == nr::GETXATTR || c == nr::LGETXATTR || c == nr::FGETXATTR => Self::Xattr {
                operand: if c == nr::FGETXATTR {
                    XattrOperand::Description(fd)
                } else {
                    XattrOperand::Path {
                        address: args[0],
                        follow: c != nr::LGETXATTR,
                    }
                },
                call: XattrCall::Get {
                    name: args[1],
                    output: args[2],
                    size: args[3],
                },
            },
            c if c == nr::LISTXATTR || c == nr::LLISTXATTR || c == nr::FLISTXATTR => Self::Xattr {
                operand: if c == nr::FLISTXATTR {
                    XattrOperand::Description(fd)
                } else {
                    XattrOperand::Path {
                        address: args[0],
                        follow: c != nr::LLISTXATTR,
                    }
                },
                call: XattrCall::List {
                    output: args[1],
                    size: args[2],
                },
            },
            c if c == nr::SETXATTR || c == nr::LSETXATTR || c == nr::FSETXATTR => Self::Xattr {
                operand: if c == nr::FSETXATTR {
                    XattrOperand::Description(fd)
                } else {
                    XattrOperand::Path {
                        address: args[0],
                        follow: c != nr::LSETXATTR,
                    }
                },
                call: XattrCall::Set {
                    name: args[1],
                    value: args[2],
                    size: args[3],
                    flags: args[4],
                },
            },
            c if c == nr::PWRITE64 => Self::Pwrite64 {
                fd,
                buf: args[1],
                count: args[2],
                offset: args[3] as i64,
            },
            c if c == nr::PWRITEV => Self::Pwritev {
                fd,
                iov: args[1],
                iovcnt: args[2],
                offset: args[3] as i64,
            },
            c if c == nr::READV || c == nr::PREADV => Self::Readv {
                fd,
                iov: args[1],
                iovcnt: args[2],
                offset: (c == nr::PREADV).then_some(args[3] as i64),
            },
            c if c == nr::FSYNC || c == nr::FDATASYNC => Self::Fsync { fd },
            c if c == nr::SYNCFS => Self::Syncfs { fd },
            c if c == nr::SYNC_FILE_RANGE => Self::SyncFileRange {
                fd,
                offset: args[1],
                length: args[2],
                flags: args[3],
            },
            c if c == nr::STATFS => Self::Statfs {
                path: args[0],
                output: args[1],
            },
            c if c == nr::FSTATFS => Self::Fstatfs {
                fd,
                output: args[1],
            },
            c if c == nr::FALLOCATE => Self::Fallocate {
                fd,
                mode: args[1],
                offset: args[2],
                length: args[3],
            },
            c if c == nr::READLINKAT => Self::Readlinkat {
                dirfd: carrick_fd_core::Fd(args[0] as i32),
                path: carrick_guest_arch::UserVa::new(args[1]),
                buf: carrick_guest_arch::UserVa::new(args[2]),
                bufsiz: ReadlinkSize(args[3] as i32),
            },
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
                layout: StatLayout::Generic,
            },
            c if c.raw() == carrick_syscall_abi::CARRICK_PRIVATE_X86_FSTAT => Self::Fstat {
                fd,
                statbuf: args[1],
                layout: StatLayout::X8664,
            },
            c if c == nr::OPENAT => Self::Openat {
                dirfd: fd,
                path: args[1],
                flags: args[2],
                mode: args[3],
            },
            c if c == nr::RENAMEAT || c == nr::RENAMEAT2 => Self::Renameat {
                olddirfd: fd,
                oldpath: args[1],
                newdirfd: args[2] as i32,
                newpath: args[3],
                flags: if c == nr::RENAMEAT { 0 } else { args[4] },
            },
            c if c == nr::TRUNCATE => Self::Truncate {
                path: args[0],
                length: args[1],
            },
            c if c == nr::FTRUNCATE => Self::Ftruncate {
                fd,
                length: args[1],
            },
            c if c == nr::FCHMOD => Self::Fchmod { fd, mode: args[1] },
            c if c == nr::FCHOWN => Self::Fchown {
                fd,
                owner: args[1],
                group: args[2],
            },
            // fchmodat takes three arguments: Linux ignores the fourth
            // register, which glibc may leave holding AT_SYMLINK_NOFOLLOW.
            c if c == nr::FCHMODAT || c == nr::FCHMODAT2 => Self::Fchmodat {
                dirfd: fd,
                path: args[1],
                mode: args[2],
                flags: if c == nr::FCHMODAT { 0 } else { args[3] },
            },
            c if c == nr::FCHOWNAT => Self::Fchownat {
                dirfd: fd,
                path: args[1],
                owner: args[2],
                group: args[3],
                flags: args[4],
            },
            c if c == nr::UTIMENSAT => Self::Utimensat {
                dirfd: fd,
                path: args[1],
                times: args[2],
                flags: args[3],
            },
            c if c == nr::MKDIRAT => Self::Mkdirat {
                dirfd: fd,
                path: args[1],
                mode: args[2],
            },
            c if c == nr::UNLINKAT => Self::Unlinkat {
                dirfd: fd,
                path: args[1],
                flags: args[2],
            },
            c if c == nr::SYMLINKAT => Self::Symlinkat {
                target: args[0],
                dirfd: args[1] as i32,
                path: args[2],
            },
            c if c == nr::LINKAT => Self::Linkat {
                olddirfd: fd,
                oldpath: args[1],
                newdirfd: args[2] as i32,
                newpath: args[3],
                flags: args[4],
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
                layout: StatLayout::Generic,
            },
            c if c.raw() == carrick_syscall_abi::CARRICK_PRIVATE_X86_NEWFSTATAT => {
                Self::Newfstatat {
                    dirfd: fd,
                    path: args[1],
                    statbuf: args[2],
                    flags: args[3],
                    layout: StatLayout::X8664,
                }
            }
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
                request: u64::from(args[1] as u32),
                arg: args[2],
            },
            c if c == nr::CHDIR => Self::Chdir { path: args[0] },
            c if c == nr::FCHDIR => Self::Fchdir { fd },
            c if c == nr::PPOLL => Self::Ppoll {
                fds: args[0],
                nfds: args[1],
                timeout: args[2],
                sigmask: args[3],
            },
            c if c == LINUX_NR_MMAP
                && args[3] & (LINUX_MAP_ANONYMOUS | LINUX_MAP_SHARED | LINUX_MAP_PRIVATE)
                    == LINUX_MAP_PRIVATE =>
            {
                Self::MapPrivate(NativeMapKey::of(args))
            }
            _ => return SocketCall::decode(canonical, args).map(Self::Socket),
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
    /// Contiguous bytes from `src` that user mode can read now: one probe
    /// byte per page, without staging the range.
    fn readable(&mut self, src: u64, len: usize) -> usize {
        let mut done = 0;
        while done < len {
            let Some(address) = src.checked_add(done as u64) else {
                return done;
            };
            if !self.copy_in(&mut [0u8], address) {
                return done;
            }
            done += ((PAGE_BYTES - address % PAGE_BYTES) as usize).min(len - done);
        }
        len
    }
}

/// User output the ring copies back after the carrier replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostFileOutput {
    pub address: u64,
    /// The bytes the caller's user buffer holds.
    pub len: usize,
    /// How the carrier's reply is encoded for the caller's ABI.
    pub layout: OutputLayout,
}

/// The caller's encoding of a carrier reply. The carrier always replies in
/// the canonical (asm-generic) layout; the ring that owns the caller's ABI
/// re-encodes it on completion, as the ring's own stat writers do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputLayout {
    /// The reply's bytes, unchanged.
    Bytes,
    /// An asm-generic `struct stat` reply the caller reads as x86_64's
    /// 144-byte `struct stat` (`fstat`/`newfstatat` on x86_64).
    X8664Stat,
    /// A network call's written extents, copied back to each user range its
    /// record's segment table names; `len` is the reply capacity.
    Net,
    /// Scatter the record's flat read into the staged Linux iovec regions.
    Vector,
}

impl HostFileOutput {
    /// `len` bytes copied back unchanged.
    pub const fn bytes(address: u64, len: usize) -> Self {
        Self {
            address,
            len,
            layout: OutputLayout::Bytes,
        }
    }

    /// A `struct stat` in the caller's `layout`.
    pub const fn stat(address: u64, layout: StatLayout) -> Self {
        match layout {
            StatLayout::Generic => Self::bytes(address, LINUX_STAT_BYTES),
            StatLayout::X8664 => Self {
                address,
                len: X8664_STAT_BYTES,
                layout: OutputLayout::X8664Stat,
            },
        }
    }

    /// The reply area the carrier fills: the canonical record's size,
    /// whatever the caller's encoding.
    pub const fn reply_capacity(self) -> usize {
        match self.layout {
            OutputLayout::Bytes | OutputLayout::Net | OutputLayout::Vector => self.len,
            OutputLayout::X8664Stat => LINUX_STAT_BYTES,
        }
    }

    /// Re-encode a canonical reply for the caller. `None` for a reply this
    /// layout cannot hold.
    fn encode(self, reply: &[u8]) -> Option<alloc::borrow::Cow<'_, [u8]>> {
        match self.layout {
            OutputLayout::Bytes => {
                (reply.len() <= self.len).then_some(alloc::borrow::Cow::Borrowed(reply))
            }
            // Completed per staged range by `socket::complete`.
            OutputLayout::Net | OutputLayout::Vector => None,
            OutputLayout::X8664Stat => {
                let stat =
                    <carrick_syscall_abi::LinuxStat as zerocopy::FromBytes>::read_from_bytes(reply)
                        .ok()?;
                Some(alloc::borrow::Cow::Owned(
                    zerocopy::IntoBytes::as_bytes(
                        &carrick_syscall_abi::LinuxX8664Stat::from_generic(&stat),
                    )
                    .to_vec(),
                ))
            }
        }
    }
}

/// Which `struct stat` a decoded `fstat`/`newfstatat` writes: the canonical
/// asm-generic record, or x86_64's legacy-order record its private ordinals
/// name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatLayout {
    Generic,
    X8664,
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
    /// A host crossing's declared output page must be supplied before the
    /// crossing runs (its venue cannot supply one); the ring retries the exact
    /// call afterwards. A refused supply is no error: the result may be
    /// shorter than the declared bound, and a page it does touch fails in the
    /// crossing as it does in Linux ([`HostFileStage::Crossing`]).
    PrepareOutput { address: u64 },
    /// Nothing is staged: the call crosses to the host unchanged.
    Crossing,
    /// A write gathered `prefix`'s bytes before the user read at `address`
    /// stopped it, or a message batch staged the entries before one whose
    /// `access` at `address` faults (#2418). The ring supplies `address`
    /// and retries the exact call, as for [`HostFileStage::Fault`]; if the
    /// supply is refused, the call completes as the staged `prefix` record
    /// instead, with its `output`: the short count Linux returns when its
    /// user copy faults after some bytes, or the entries a batch moved
    /// before the one that failed ([`HostFileStage::refused`]).
    FaultAfterPrefix {
        address: u64,
        access: Access,
        prefix: Box<[u8]>,
        output: Option<HostFileOutput>,
    },
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
        /// A chdir lookup: on success the ring stores the reply's directory
        /// spelling as the caller's cwd ([`chdir_target`]).
        chdir: bool,
    },
}

impl HostFileStage {
    /// The user access the ring must supply before this call can stage.
    pub fn fault(&self) -> Option<(u64, Access)> {
        match self {
            Self::Fault { address, access } => Some((*address, *access)),
            Self::PrepareOutput { address } => Some((*address, Access::Write)),
            Self::FaultAfterPrefix {
                address, access, ..
            } => Some((*address, *access)),
            _ => None,
        }
    }

    /// What the call completes as when the owner refuses [`Self::fault`]'s
    /// supply: Linux's user copy reports EFAULT only when no byte was
    /// copied, and a write that copied a prefix returns that short count.
    pub fn refused(self) -> Self {
        match self {
            Self::Fault { .. } => errno(carrick_syscall_abi::LINUX_EFAULT),
            Self::PrepareOutput { .. } => Self::Crossing,
            Self::FaultAfterPrefix { prefix, output, .. } => Self::Request {
                record: prefix,
                output,
                resolves_path: false,
                map: None,
                chdir: false,
            },
            stage => stage,
        }
    }
}

/// `fstat`/`statx` of an in-zone object, answered in ring with the record
/// the dispatcher reports for the same kind of object: both encode one
/// shared [`carrick_syscall_abi::LinuxStatFields`].
fn in_zone_stat(op: HostFileOp, kind: InZoneKind, output: HostFileOutput) -> HostFileStage {
    let fields = match kind {
        InZoneKind::Pipe(identity) => identity.stat_fields(),
        InZoneKind::Stream(identity) => identity.stat_fields(),
        InZoneKind::EventFd => carrick_syscall_abi::LinuxStatFields::CARRICK_EVENTFD,
        InZoneKind::Epoll => carrick_syscall_abi::LinuxStatFields::CARRICK_EPOLL,
    };
    let bytes: Box<[u8]> = match op {
        HostFileOp::Statx => {
            zerocopy::IntoBytes::as_bytes(&carrick_syscall_abi::LinuxStatx::from_fields(&fields))
                .into()
        }
        _ if output.layout == OutputLayout::X8664Stat => zerocopy::IntoBytes::as_bytes(
            &carrick_syscall_abi::LinuxX8664Stat::from_fields(&fields),
        )
        .into(),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostIoctl {
    Get(usize),
    Set(usize),
}

// Only these Linux requests can cross as a native host file ioctl. The carrier
// checks the same table and translates the request and layout before using libc.
pub fn host_ioctl(request: u64) -> Option<HostIoctl> {
    use carrick_syscall_abi::{
        LINUX_FIONBIO, LINUX_FIONREAD, LINUX_TCGETA, LINUX_TCGETS, LINUX_TCGETS2, LINUX_TCSETA,
        LINUX_TCSETAF, LINUX_TCSETAW, LINUX_TCSETS, LINUX_TCSETS2, LINUX_TCSETSF, LINUX_TCSETSF2,
        LINUX_TCSETSW, LINUX_TCSETSW2, LINUX_TERMIO_SIZE, LINUX_TERMIOS_KERNEL_SIZE,
        LINUX_TERMIOS2_SIZE, LINUX_TIOCGWINSZ, LINUX_TIOCSWINSZ,
    };
    Some(match request {
        LINUX_TCGETS => HostIoctl::Get(LINUX_TERMIOS_KERNEL_SIZE),
        LINUX_TCGETS2 => HostIoctl::Get(LINUX_TERMIOS2_SIZE),
        LINUX_TCGETA => HostIoctl::Get(LINUX_TERMIO_SIZE),
        LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => HostIoctl::Set(LINUX_TERMIOS_KERNEL_SIZE),
        LINUX_TCSETS2 | LINUX_TCSETSW2 | LINUX_TCSETSF2 => HostIoctl::Set(LINUX_TERMIOS2_SIZE),
        LINUX_TCSETA | LINUX_TCSETAW | LINUX_TCSETAF => HostIoctl::Set(LINUX_TERMIO_SIZE),
        LINUX_TIOCGWINSZ => HostIoctl::Get(8),
        LINUX_TIOCSWINSZ => HostIoctl::Set(8),
        LINUX_FIONREAD => HostIoctl::Get(4),
        LINUX_FIONBIO => HostIoctl::Set(4),
        _ => return None,
    })
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

/// The mode bits `chmod` applies: permissions, set-id and sticky.
const CHMOD_MODE_BITS: u64 = 0o7777;

/// `chown`'s owner and group words as a record's scalar arguments: each a
/// Linux `uid_t`/`gid_t`, `u32::MAX` (-1) for unchanged.
fn chown_ids(owner: u64, group: u64) -> [u64; 4] {
    [u64::from(owner as u32), u64::from(group as u32), 0, 0]
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
        let output_cap = output.map_or(0, HostFileOutput::reply_capacity);
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
            chdir: false,
        }
    }

    /// The caller's retired byte sources, encoded as a release list.
    fn releases(&mut self) -> alloc::vec::Vec<u8> {
        let placeholder = host_file::MapSourceReply {
            handle: core::num::NonZeroU64::MIN,
            generation: core::num::NonZeroU64::MIN,
        };
        let mut released = [placeholder; host_file::MAX_MAP_RELEASES];
        let taken = (self.namespace.releases)(&mut released).min(released.len());
        released[..taken]
            .iter()
            .flat_map(|release| release.encode())
            .collect()
    }

    fn descriptor(&mut self, fd: i32) -> Option<NativeDescriptor> {
        (self.namespace.resolve)(fd)
    }

    /// Keep a relative path's directory operand in the record. The
    /// carrier pins that directory in the caller's ring table at service
    /// time. Absolute paths must ignore even an invalid descriptor.
    fn path_base(&mut self, dirfd: i32, path: &[u8]) -> Option<Result<i32, HostFileStage>> {
        if dirfd == LINUX_AT_FDCWD || path.first() == Some(&b'/') {
            return Some(Ok(LINUX_AT_FDCWD));
        }
        Some(match self.descriptor(dirfd)? {
            NativeDescriptor::InZone(_) => Err(errno(carrick_syscall_abi::LINUX_ENOTDIR)),
            NativeDescriptor::Absent => Err(errno(carrick_syscall_abi::LINUX_EBADF)),
            NativeDescriptor::HostBacked { .. } => Ok(dirfd),
        })
    }

    fn path_input(
        &mut self,
        user: &mut dyn HostFileUser,
        dirfd: i32,
        address: u64,
    ) -> Option<Result<(i32, Vec<u8>), HostFileStage>> {
        let path = match copy_path(user, address) {
            Path::Bytes(path) => path,
            Path::Stage(stage) => return Some(Err(stage)),
        };
        if path.is_empty() {
            return Some(Err(errno(carrick_syscall_abi::LINUX_ENOENT)));
        }
        Some(self.path_base(dirfd, &path)?.map(|base| (base, path)))
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

    fn xattr(
        &mut self,
        operand: XattrOperand,
        call: XattrCall,
        user: &mut dyn HostFileUser,
    ) -> Option<HostFileStage> {
        let (fd, flags, mut input) = match operand {
            XattrOperand::Description(fd) => match self.descriptor(fd)? {
                NativeDescriptor::Absent
                | NativeDescriptor::HostBacked {
                    access: DescriptionAccess::Path,
                } => {
                    return Some(errno(carrick_syscall_abi::LINUX_EBADF));
                }
                NativeDescriptor::InZone(_) => {
                    return Some(errno(carrick_syscall_abi::LINUX_EOPNOTSUPP));
                }
                NativeDescriptor::HostBacked { .. } => {
                    (fd, host_file::XATTR_DESCRIPTOR, Vec::new())
                }
            },
            XattrOperand::Path { address, follow } => {
                let (base, path) = match self.path_input(user, LINUX_AT_FDCWD, address)? {
                    Ok(resolved) => resolved,
                    Err(stage) => return Some(stage),
                };
                (
                    base,
                    if follow { 0 } else { host_file::XATTR_NOFOLLOW },
                    path,
                )
            }
        };
        input.push(0);
        let (op, name, output) = match call {
            XattrCall::List { output, size } => (HostFileOp::ListXattr, None, Some((output, size))),
            XattrCall::Get { name, output, size } => {
                (HostFileOp::GetXattr, Some(name), Some((output, size)))
            }
            XattrCall::Set { name, .. } => (HostFileOp::SetXattr, Some(name), None),
        };
        if let Some(name) = name {
            match copy_path(user, name) {
                Path::Bytes(name) => input.extend_from_slice(&name),
                Path::Stage(stage) => return Some(stage),
            }
            input.push(0);
        }
        let mut args = [0; 4];
        if let XattrCall::Set {
            value, size, flags, ..
        } = call
        {
            if size > HOST_FILE_CHUNK_BYTES as u64 {
                return Some(errno(carrick_syscall_abi::LINUX_E2BIG));
            }
            args[0] = flags;
            if let Err(address) = gather_user(user, &mut input, value, size as usize) {
                return Some(HostFileStage::Fault {
                    address,
                    access: Access::Read,
                });
            }
        }
        Some(self.request(
            op,
            fd,
            flags,
            args,
            &input,
            output.and_then(|(address, size)| {
                (size > 0).then(|| HostFileOutput::bytes(address, chunk(size)))
            }),
        ))
    }

    /// A descriptor operation that shares the carrier's file-description core.
    fn file_operation(
        &mut self,
        op: HostFileOp,
        fd: i32,
        args: [u64; 4],
        output: Option<HostFileOutput>,
    ) -> Option<HostFileStage> {
        Some(match self.descriptor(fd)? {
            NativeDescriptor::Absent
            | NativeDescriptor::HostBacked {
                access: DescriptionAccess::Path,
            } if op != HostFileOp::Fstatfs => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { .. } => self.request(op, fd, 0, args, &[], output),
            NativeDescriptor::InZone(_) => match op {
                HostFileOp::Fsync => errno(carrick_syscall_abi::LINUX_EINVAL),
                HostFileOp::Fallocate | HostFileOp::SyncFileRange => {
                    errno(carrick_syscall_abi::LINUX_ESPIPE)
                }
                HostFileOp::Syncfs => HostFileStage::Returned(SyscallResult::new(0)),
                _ => HostFileStage::InRing,
            },
        })
    }

    fn write(
        &mut self,
        fd: i32,
        offset: Option<i64>,
        user: &mut dyn HostFileUser,
        gather: impl FnOnce(&mut dyn HostFileUser) -> Result<Vec<u8>, Gathered>,
    ) -> Option<HostFileStage> {
        let (op, args) = match offset {
            Some(offset) if offset < 0 => return Some(errno(carrick_syscall_abi::LINUX_EINVAL)),
            Some(offset) => (HostFileOp::Pwrite, [offset as u64, 0, 0, 0]),
            None => (HostFileOp::Write, [0; 4]),
        };
        Some(match self.descriptor(fd)? {
            NativeDescriptor::InZone(_) if offset.is_some() => {
                errno(carrick_syscall_abi::LINUX_ESPIPE)
            }
            NativeDescriptor::InZone(_) => HostFileStage::InRing,
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { access } if !access.writable() => {
                errno(carrick_syscall_abi::LINUX_EBADF)
            }
            NativeDescriptor::HostBacked { .. } => match gather(user) {
                Ok(input) if input.is_empty() => HostFileStage::Returned(SyscallResult::new(0)),
                Ok(input) => self.request(op, fd, 0, args, &input, None),
                Err(Gathered::Answer(stage)) => stage,
                // Nothing copied: supply first, EFAULT if refused.
                Err(Gathered::Fault { prefix, address }) if prefix.is_empty() => {
                    HostFileStage::Fault {
                        address,
                        access: Access::Read,
                    }
                }
                // Supply first; a refused supply writes the prefix.
                Err(Gathered::Fault { prefix, address }) => {
                    match self.request(op, fd, 0, args, &prefix, None) {
                        HostFileStage::Request { record, .. } => HostFileStage::FaultAfterPrefix {
                            address,
                            access: Access::Read,
                            prefix: record,
                            output: None,
                        },
                        stage => stage,
                    }
                }
            },
        })
    }

    fn read_vectors(
        &mut self,
        fd: i32,
        iov: u64,
        iovcnt: u64,
        offset: Option<i64>,
        user: &mut dyn HostFileUser,
    ) -> Option<HostFileStage> {
        if offset.is_some_and(|offset| offset < 0) {
            return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
        }
        Some(match self.descriptor(fd)? {
            NativeDescriptor::InZone(_) if offset.is_some() => {
                errno(carrick_syscall_abi::LINUX_ESPIPE)
            }
            NativeDescriptor::InZone(_) => HostFileStage::InRing,
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { access } if !access.readable() => {
                errno(carrick_syscall_abi::LINUX_EBADF)
            }
            NativeDescriptor::HostBacked { .. } => {
                let (vectors, total) = match stage_iovecs(user, iov, iovcnt) {
                    Ok(staged) => staged,
                    Err(Gathered::Answer(answer)) => return Some(answer),
                    Err(Gathered::Fault { address, .. }) => {
                        return Some(HostFileStage::Fault {
                            address,
                            access: Access::Read,
                        });
                    }
                };
                let capacity = chunk(total);
                if capacity == 0 {
                    return Some(HostFileStage::Returned(SyscallResult::new(0)));
                }
                let mut left = capacity;
                let mut fault = None;
                for iov in vectors.chunks_exact(IOVEC_BYTES) {
                    let (address, len) = iovec_words(iov);
                    let len = (len as usize).min(left);
                    let writable = user.writable(address, len);
                    if writable < len {
                        fault = Some(address.saturating_add(writable as u64));
                        left -= writable;
                        break;
                    }
                    left -= len;
                    if left == 0 {
                        break;
                    }
                }
                let available = capacity - left;
                if let Some(address) = fault
                    && available == 0
                {
                    return Some(HostFileStage::Fault {
                        address,
                        access: Access::Write,
                    });
                }
                let (op, args) = match offset {
                    Some(offset) => (HostFileOp::Pread, [offset as u64, 0, 0, 0]),
                    None => (HostFileOp::Read, [0; 4]),
                };
                let request = self.request(
                    op,
                    fd,
                    0,
                    args,
                    &vectors,
                    Some(HostFileOutput {
                        address: 0,
                        len: available,
                        layout: OutputLayout::Vector,
                    }),
                );
                match (fault, request) {
                    (Some(address), HostFileStage::Request { record, output, .. }) => {
                        HostFileStage::FaultAfterPrefix {
                            address,
                            access: Access::Write,
                            prefix: record,
                            output,
                        }
                    }
                    (_, request) => request,
                }
            }
        })
    }
}

/// Where a write's user gather stopped short of its whole input.
enum Gathered {
    /// The call is answered before any byte (a bad vector count or total).
    Answer(HostFileStage),
    /// The user read at `address` failed after `prefix` was copied.
    Fault { prefix: Vec<u8>, address: u64 },
}

/// Append `len` user bytes from `base` to `input` one page at a time, so a
/// fault keeps every byte before it. `Err` names the first page the user
/// could not read; `input` then ends just before it.
fn gather_user(
    user: &mut dyn HostFileUser,
    input: &mut Vec<u8>,
    base: u64,
    len: usize,
) -> Result<(), u64> {
    let mut done = 0;
    while done < len {
        let address = base.checked_add(done as u64).ok_or(base)?;
        let take = ((PAGE_BYTES - address % PAGE_BYTES) as usize).min(len - done);
        let start = input.len();
        input.resize(start + take, 0);
        if !user.copy_in(&mut input[start..], address) {
            input.truncate(start);
            return Err(address);
        }
        done += take;
    }
    Ok(())
}

fn chunk(count: u64) -> usize {
    (count as usize).min(HOST_FILE_CHUNK_BYTES)
}

fn path_pair(first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(first.len() + 1 + second.len());
    input.extend_from_slice(first);
    input.push(0);
    input.extend_from_slice(second);
    input
}

fn iovec_words(bytes: &[u8]) -> (u64, u64) {
    (
        u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8])),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8])),
    )
}

fn stage_iovecs(
    user: &mut dyn HostFileUser,
    iov: u64,
    iovcnt: u64,
) -> Result<(Vec<u8>, u64), Gathered> {
    if iovcnt > LINUX_UIO_MAXIOV {
        return Err(Gathered::Answer(errno(carrick_syscall_abi::LINUX_EINVAL)));
    }
    let mut vectors = Vec::with_capacity(iovcnt as usize * IOVEC_BYTES);
    // An unreadable vector array copies no byte: supply, else EFAULT.
    gather_user(user, &mut vectors, iov, iovcnt as usize * IOVEC_BYTES).map_err(|address| {
        Gathered::Fault {
            prefix: Vec::new(),
            address,
        }
    })?;
    // Linux rejects a negative total before any transfer.
    let mut total: u64 = 0;
    for vector in vectors.chunks_exact(IOVEC_BYTES) {
        let (_, len) = iovec_words(vector);
        total = match total.checked_add(len) {
            Some(total) if total <= i64::MAX as u64 => total,
            _ => return Err(Gathered::Answer(errno(carrick_syscall_abi::LINUX_EINVAL))),
        };
    }
    Ok((vectors, total))
}

/// Gather `writev` vectors into one bounded chunk, in order. A fault in a
/// later vector keeps every byte the earlier ones (and its own readable
/// head) supplied, as Linux's `writev` returns the bytes before the fault.
fn gather_vectors(user: &mut dyn HostFileUser, iov: u64, iovcnt: u64) -> Result<Vec<u8>, Gathered> {
    let (vectors, total) = stage_iovecs(user, iov, iovcnt)?;
    let mut input = Vec::with_capacity(chunk(total));
    for vector in vectors.chunks_exact(IOVEC_BYTES) {
        let (base, len) = iovec_words(vector);
        let room = HOST_FILE_CHUNK_BYTES - input.len();
        if room == 0 {
            break;
        }
        let take = (len as usize).min(room);
        if let Err(address) = gather_user(user, &mut input, base, take) {
            return Err(Gathered::Fault {
                prefix: input,
                address,
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
    // The retained ring copyout for these queries prepares only the bytes
    // returned by the carrier. Failures and size queries write nothing.
    if matches!(
        call,
        HostFileCall::Readlinkat { .. } | HostFileCall::Ioctl { .. } | HostFileCall::Xattr { .. }
    ) {
        return Some(staged);
    }
    if let HostFileStage::Request {
        output: Some(output),
        ..
    }
    | HostFileStage::InRingReply { output, .. } = &staged
        && !matches!(output.layout, OutputLayout::Net | OutputLayout::Vector)
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

/// Stage the declared guest output of a host crossing `set` allows. A
/// crossing copies its result out through a venue that cannot supply a page,
/// so the ring makes every page of the output writable first, through the
/// owner fault path a staged call uses (T3, #2157): the first page
/// `writable` does not cover is a [`HostFileStage::PrepareOutput`]. `None`:
/// nothing to prepare, the crossing proceeds.
pub fn crossing_output_stage(
    set: crate::crossing::HostCrossingSet,
    canonical: CanonicalNr,
    args: &[u64; 6],
    mut writable: impl FnMut(u64, usize) -> usize,
) -> Option<HostFileStage> {
    use crate::crossing::{AllowedHostCrossing, HostCrossingSet};
    let crossing = match set {
        HostCrossingSet::X86 => AllowedHostCrossing::from_canonical_x86(canonical),
        HostCrossingSet::Aarch64 => AllowedHostCrossing::from_canonical_aarch64(canonical),
    }?;
    for (address, length) in crossing.operand_spec().output_ranges(
        args,
        match set {
            HostCrossingSet::Aarch64 => carrick_guest_arch::GuestIsa::Aarch64,
            HostCrossingSet::X86 => carrick_guest_arch::GuestIsa::X86_64,
        },
    ) {
        let covered = writable(address, usize::try_from(length).ok()?) as u64;
        if covered < length {
            return Some(HostFileStage::PrepareOutput {
                address: address.wrapping_add(covered),
            });
        }
    }
    None
}

/// Decode and admit a call for `origin`'s CPL0 venue. `Err` keeps the call
/// on its existing route, whether the venue does not know it or does not
/// admit it for this origin: when that route is a host crossing in `set`,
/// the answer is its [`crossing_output_stage`], so a declared output is
/// writable before the crossing runs (such as a root's
/// `readlinkat(AT_FDCWD, ...)`, #2201).
pub fn admit_or_cross(
    set: crate::crossing::HostCrossingSet,
    native: carrick_guest_arch::NativeOrdinal,
    canonical: CanonicalNr,
    args: &[u64; 6],
    origin: ServiceOrigin,
    delegated: impl FnOnce(i32) -> bool,
    writable: impl FnMut(u64, usize) -> usize,
) -> Result<HostFileCall, Option<HostFileStage>> {
    let isa = match set {
        crate::crossing::HostCrossingSet::Aarch64 => carrick_guest_arch::GuestIsa::Aarch64,
        crate::crossing::HostCrossingSet::X86 => carrick_guest_arch::GuestIsa::X86_64,
    };
    match HostFileCall::decode_native(isa, native, canonical, args) {
        Some(call) if call.admitted_for(origin, delegated) => Ok(call),
        _ => Err(crossing_output_stage(set, canonical, args, writable)),
    }
}

fn stage_call(
    call: HostFileCall,
    namespace: &mut NativeNamespace<'_>,
    user: &mut dyn HostFileUser,
) -> Option<HostFileStage> {
    let mut staging = Staging { namespace };
    Some(match call {
        HostFileCall::Xattr { operand, call } => return staging.xattr(operand, call, user),
        HostFileCall::Pwrite64 {
            fd,
            buf,
            count,
            offset,
        } => {
            return staging.write(fd, Some(offset), user, |user| {
                let mut input = Vec::with_capacity(chunk(count));
                match gather_user(user, &mut input, buf, chunk(count)) {
                    Ok(()) => Ok(input),
                    Err(address) => Err(Gathered::Fault {
                        prefix: input,
                        address,
                    }),
                }
            });
        }
        HostFileCall::Pwritev {
            fd,
            iov,
            iovcnt,
            offset,
        } => {
            return staging.write(fd, Some(offset), user, |user| {
                gather_vectors(user, iov, iovcnt)
            });
        }
        HostFileCall::Readv {
            fd,
            iov,
            iovcnt,
            offset,
        } => {
            return staging.read_vectors(fd, iov, iovcnt, offset, user);
        }
        HostFileCall::Fsync { fd } => {
            return staging.file_operation(HostFileOp::Fsync, fd, [0; 4], None);
        }
        HostFileCall::Syncfs { fd } => {
            return staging.file_operation(HostFileOp::Syncfs, fd, [0; 4], None);
        }
        HostFileCall::SyncFileRange {
            fd,
            offset,
            length,
            flags,
        } => {
            return staging.file_operation(
                HostFileOp::SyncFileRange,
                fd,
                [offset, length, flags, 0],
                None,
            );
        }
        HostFileCall::Statfs { path, output } => {
            let (base, path) = match staging.path_input(user, LINUX_AT_FDCWD, path)? {
                Ok(resolved) => resolved,
                Err(stage) => return Some(stage),
            };
            staging.request(
                HostFileOp::Statfs,
                base,
                0,
                [0; 4],
                &path,
                Some(HostFileOutput::bytes(output, host_file::STATFS_BYTES)),
            )
        }
        HostFileCall::Fstatfs { fd, output } => {
            return staging.file_operation(
                HostFileOp::Fstatfs,
                fd,
                [0; 4],
                Some(HostFileOutput::bytes(output, host_file::STATFS_BYTES)),
            );
        }
        HostFileCall::Fallocate {
            fd,
            mode,
            offset,
            length,
        } => {
            return staging.file_operation(
                HostFileOp::Fallocate,
                fd,
                [mode, offset, length, 0],
                None,
            );
        }
        HostFileCall::Write { fd, buf, count } => {
            return staging.write(fd, None, user, |user| {
                let mut input = Vec::with_capacity(chunk(count));
                match gather_user(user, &mut input, buf, chunk(count)) {
                    Ok(()) => Ok(input),
                    Err(address) => Err(Gathered::Fault {
                        prefix: input,
                        address,
                    }),
                }
            });
        }
        HostFileCall::Writev { fd, iov, iovcnt } => {
            return staging.write(fd, None, user, |user| gather_vectors(user, iov, iovcnt));
        }
        HostFileCall::Fstat {
            fd,
            statbuf,
            layout,
        } => staging.descriptor_stat(
            HostFileOp::Fstat,
            fd,
            0,
            [0; 4],
            HostFileOutput::stat(statbuf, layout),
        )?,
        HostFileCall::Renameat {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
        } => {
            if flags
                & !(carrick_syscall_abi::LINUX_RENAME_NOREPLACE
                    | carrick_syscall_abi::LINUX_RENAME_EXCHANGE)
                != 0
                || flags
                    == (carrick_syscall_abi::LINUX_RENAME_NOREPLACE
                        | carrick_syscall_abi::LINUX_RENAME_EXCHANGE)
            {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let old = match copy_path(user, oldpath) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            let new = match copy_path(user, newpath) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            if old.is_empty() || new.is_empty() {
                return Some(errno(carrick_syscall_abi::LINUX_ENOENT));
            }
            let olddirfd = match staging.path_base(olddirfd, &old)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            let newdirfd = match staging.path_base(newdirfd, &new)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            staging.request(
                HostFileOp::Renameat,
                olddirfd,
                flags as u32,
                [
                    host_file::encode_second_path_fd(
                        (newdirfd != LINUX_AT_FDCWD).then_some(newdirfd),
                    ),
                    0,
                    0,
                    0,
                ],
                &path_pair(&old, &new),
                None,
            )
        }
        HostFileCall::Truncate { path, length } => {
            if (length as i64) < 0 {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let (dirfd, path) = match staging.path_input(user, LINUX_AT_FDCWD, path)? {
                Ok(resolved) => resolved,
                Err(stage) => return Some(stage),
            };
            staging.request(
                HostFileOp::Truncate,
                dirfd,
                0,
                [length, 0, 0, 0],
                &path,
                None,
            )
        }
        HostFileCall::Ftruncate { fd, length } => {
            if (length as i64) < 0 {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            match staging.descriptor(fd)? {
                NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
                NativeDescriptor::InZone(_) => errno(carrick_syscall_abi::LINUX_EINVAL),
                NativeDescriptor::HostBacked { .. } => {
                    staging.request(HostFileOp::Ftruncate, fd, 0, [length, 0, 0, 0], &[], None)
                }
            }
        }
        HostFileCall::Fchmod { fd, mode } => match staging.descriptor(fd)? {
            NativeDescriptor::Absent
            | NativeDescriptor::HostBacked {
                access: DescriptionAccess::Path,
            } => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { .. } => staging.request(
                HostFileOp::Fchmod,
                fd,
                0,
                [mode & CHMOD_MODE_BITS, 0, 0, 0],
                &[],
                None,
            ),
            // An in-zone object's inode mode keeps its route.
            NativeDescriptor::InZone(_) => return None,
        },
        HostFileCall::Fchown { fd, owner, group } => match staging.descriptor(fd)? {
            NativeDescriptor::Absent
            | NativeDescriptor::HostBacked {
                access: DescriptionAccess::Path,
            } => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { .. } => staging.request(
                HostFileOp::Fchown,
                fd,
                0,
                chown_ids(owner, group),
                &[],
                None,
            ),
            NativeDescriptor::InZone(_) => return None,
        },
        HostFileCall::Fchmodat {
            dirfd,
            path,
            mode,
            flags,
        } => {
            if flags & !carrick_syscall_abi::LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let (dirfd, path) = match staging.path_input(user, dirfd, path)? {
                Ok(resolved) => resolved,
                Err(stage) => return Some(stage),
            };
            staging.request(
                HostFileOp::Fchmodat,
                dirfd,
                flags as u32,
                [mode & CHMOD_MODE_BITS, 0, 0, 0],
                &path,
                None,
            )
        }
        HostFileCall::Fchownat {
            dirfd,
            path,
            owner,
            group,
            flags,
        } => {
            let empty_path = u64::from(LINUX_AT_EMPTY_PATH);
            if flags & !(carrick_syscall_abi::LINUX_AT_SYMLINK_NOFOLLOW | empty_path) != 0 {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let ids = chown_ids(owner, group);
            let path = match copy_path(user, path) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            // `AT_EMPTY_PATH` with an empty path names `dirfd` itself, which
            // may be an O_PATH descriptor (chown(2)), or the cwd.
            if path.is_empty() && flags & empty_path != 0 && dirfd != LINUX_AT_FDCWD {
                return Some(match staging.descriptor(dirfd)? {
                    NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
                    NativeDescriptor::HostBacked { .. } => {
                        staging.request(HostFileOp::Fchown, dirfd, 0, ids, &[], None)
                    }
                    NativeDescriptor::InZone(_) => return None,
                });
            }
            let path = match path.as_slice() {
                b"" if flags & empty_path != 0 => b".".to_vec(),
                b"" => return Some(errno(carrick_syscall_abi::LINUX_ENOENT)),
                _ => path,
            };
            let dirfd = match staging.path_base(dirfd, &path)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            staging.request(
                HostFileOp::Fchownat,
                dirfd,
                (flags & carrick_syscall_abi::LINUX_AT_SYMLINK_NOFOLLOW) as u32,
                ids,
                &path,
                None,
            )
        }
        HostFileCall::Utimensat {
            dirfd,
            path,
            times,
            flags,
        } => {
            if flags & !carrick_syscall_abi::LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let words = if times == 0 {
                [
                    0,
                    carrick_syscall_abi::LINUX_UTIME_NOW as u64,
                    0,
                    carrick_syscall_abi::LINUX_UTIME_NOW as u64,
                ]
            } else {
                let mut bytes = [0u8; 32];
                if !user.copy_in(&mut bytes, times) {
                    return Some(HostFileStage::Fault {
                        address: times,
                        access: Access::Read,
                    });
                }
                let mut words = [0; 4];
                for (word, bytes) in words.iter_mut().zip(bytes.chunks_exact(8)) {
                    let Ok(bytes) = bytes.try_into() else {
                        return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
                    };
                    *word = u64::from_le_bytes(bytes);
                }
                let valid = |nsec: i64| {
                    (0..1_000_000_000).contains(&nsec)
                        || nsec == carrick_syscall_abi::LINUX_UTIME_NOW
                        || nsec == carrick_syscall_abi::LINUX_UTIME_OMIT
                };
                if !valid(words[1] as i64) || !valid(words[3] as i64) {
                    return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
                }
                words
            };
            let flags = flags as u32
                | if times == 0 {
                    host_file::UTIMENS_NULL_TIMES
                } else {
                    0
                };
            if path == 0 {
                if dirfd == LINUX_AT_FDCWD {
                    return Some(errno(carrick_syscall_abi::LINUX_EFAULT));
                }
                return Some(match staging.descriptor(dirfd)? {
                    NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
                    NativeDescriptor::InZone(_) => HostFileStage::Returned(SyscallResult::new(0)),
                    NativeDescriptor::HostBacked { .. } => {
                        staging.request(HostFileOp::SetFdTimes, dirfd, flags, words, &[], None)
                    }
                });
            }
            let (dirfd, path) = match staging.path_input(user, dirfd, path)? {
                Ok(resolved) => resolved,
                Err(stage) => return Some(stage),
            };
            staging.request(HostFileOp::Utimensat, dirfd, flags, words, &path, None)
        }
        HostFileCall::Mkdirat { dirfd, path, mode } => {
            let (dirfd, path) = match staging.path_input(user, dirfd, path)? {
                Ok(resolved) => resolved,
                Err(stage) => return Some(stage),
            };
            staging.request(HostFileOp::Mkdirat, dirfd, 0, [mode, 0, 0, 0], &path, None)
        }
        HostFileCall::Unlinkat { dirfd, path, flags } => {
            if flags & !carrick_syscall_abi::LINUX_AT_REMOVEDIR != 0 {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let (dirfd, path) = match staging.path_input(user, dirfd, path)? {
                Ok(resolved) => resolved,
                Err(stage) => return Some(stage),
            };
            staging.request(
                HostFileOp::Unlinkat,
                dirfd,
                flags as u32,
                [0; 4],
                &path,
                None,
            )
        }
        HostFileCall::Symlinkat {
            target,
            dirfd,
            path,
        } => {
            let target = match copy_path(user, target) {
                Path::Bytes(target) if target.is_empty() => {
                    return Some(errno(carrick_syscall_abi::LINUX_ENOENT));
                }
                Path::Bytes(target) => target,
                Path::Stage(stage) => return Some(stage),
            };
            let (dirfd, path) = match staging.path_input(user, dirfd, path)? {
                Ok(resolved) => resolved,
                Err(stage) => return Some(stage),
            };
            staging.request(
                HostFileOp::Symlinkat,
                dirfd,
                0,
                [0; 4],
                &path_pair(&target, &path),
                None,
            )
        }
        HostFileCall::Linkat {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
        } => {
            if flags
                & !(carrick_syscall_abi::LINUX_AT_SYMLINK_FOLLOW | u64::from(LINUX_AT_EMPTY_PATH))
                != 0
            {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let old = match copy_path(user, oldpath) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            let new = match copy_path(user, newpath) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            if new.is_empty() {
                return Some(errno(carrick_syscall_abi::LINUX_ENOENT));
            }
            if old.is_empty() {
                return Some(errno(if flags & u64::from(LINUX_AT_EMPTY_PATH) != 0 {
                    carrick_syscall_abi::LINUX_ENOSYS
                } else {
                    carrick_syscall_abi::LINUX_ENOENT
                }));
            }
            let olddirfd = match staging.path_base(olddirfd, &old)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            let newdirfd = match staging.path_base(newdirfd, &new)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            staging.request(
                HostFileOp::Linkat,
                olddirfd,
                flags as u32,
                [
                    host_file::encode_second_path_fd(
                        (newdirfd != LINUX_AT_FDCWD).then_some(newdirfd),
                    ),
                    0,
                    0,
                    0,
                ],
                &path_pair(&old, &new),
                None,
            )
        }
        HostFileCall::Readlinkat {
            dirfd,
            path,
            buf,
            bufsiz,
        } => {
            // Linux takes an int, including on the 64-bit syscall ABI.
            let size = bufsiz.0;
            if size <= 0 {
                return Some(errno(carrick_syscall_abi::LINUX_EINVAL));
            }
            let path = match copy_path(user, path.raw()) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            let dirfd = match staging.path_base(dirfd.0, &path)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            staging.request(
                HostFileOp::Readlinkat,
                dirfd,
                0,
                [0; 4],
                &path,
                Some(HostFileOutput::bytes(
                    buf.raw(),
                    (size as usize).min(HOST_FILE_CHUNK_BYTES),
                )),
            )
        }
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
            let dirfd = match staging.path_base(dirfd, &path)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            staging.request(
                HostFileOp::Openat,
                dirfd,
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
            let dirfd = match staging.path_base(dirfd, &path)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            staging.request(
                HostFileOp::Faccessat,
                dirfd,
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
            layout,
        } => {
            let path = match copy_path(user, path) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            let output = HostFileOutput::stat(statbuf, layout);
            if path.is_empty() {
                if flags as u32 & LINUX_AT_EMPTY_PATH == 0 {
                    return Some(errno(carrick_syscall_abi::LINUX_ENOENT));
                }
                if dirfd != LINUX_AT_FDCWD {
                    return staging.descriptor_stat(HostFileOp::Fstat, dirfd, 0, [0; 4], output);
                }
            }
            let dirfd = match staging.path_base(dirfd, &path)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            let path: &[u8] = if path.is_empty() { b"." } else { &path };
            staging.request(
                HostFileOp::Newfstatat,
                dirfd,
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
            let output = HostFileOutput::bytes(buf, LINUX_STATX_BYTES);
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
            let dirfd = match staging.path_base(dirfd, &path)? {
                Ok(base) => base,
                Err(answer) => return Some(answer),
            };
            let path: &[u8] = if path.is_empty() { b"." } else { &path };
            staging.request(
                HostFileOp::Statx,
                dirfd,
                flags as u32,
                [mask, 0, 0, 0],
                path,
                Some(output),
            )
        }
        HostFileCall::Read { fd, buf, count } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(
                InZoneKind::Pipe(_) | InZoneKind::Stream(_) | InZoneKind::EventFd,
            ) => {
                let len = chunk(count);
                let writable = user.writable(buf, len);
                if writable < len {
                    HostFileStage::Fault {
                        address: buf.saturating_add(writable as u64),
                        access: Access::Write,
                    }
                } else {
                    HostFileStage::InRing
                }
            }
            NativeDescriptor::InZone(InZoneKind::Epoll) => HostFileStage::InRing,
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
                Some(HostFileOutput::bytes(buf, chunk(count))),
            ),
        },
        HostFileCall::Pread {
            fd,
            buf,
            count,
            offset,
        } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(InZoneKind::Pipe(_) | InZoneKind::Stream(_)) => {
                errno(carrick_syscall_abi::LINUX_ESPIPE)
            }
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
                Some(HostFileOutput::bytes(buf, chunk(count))),
            ),
        },
        HostFileCall::Lseek { fd, offset, whence } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(InZoneKind::Pipe(_) | InZoneKind::Stream(_)) => {
                errno(carrick_syscall_abi::LINUX_ESPIPE)
            }
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
                Some(HostFileOutput::bytes(dirp, chunk(count))),
            ),
        },
        HostFileCall::Ioctl { fd, request, arg } => match staging.descriptor(fd)? {
            NativeDescriptor::InZone(
                InZoneKind::Pipe(_) | InZoneKind::Stream(_) | InZoneKind::EventFd,
            ) if is_terminal_request(request)
                && !matches!(
                    request,
                    carrick_syscall_abi::LINUX_FIONREAD | carrick_syscall_abi::LINUX_FIONBIO
                ) =>
            {
                errno(carrick_syscall_abi::LINUX_ENOTTY)
            }
            NativeDescriptor::Absent
            | NativeDescriptor::HostBacked {
                access: DescriptionAccess::Path,
            } => errno(carrick_syscall_abi::LINUX_EBADF),
            NativeDescriptor::HostBacked { .. } => {
                // A request outside the allowlist is NOT served: ENOTTY would be
                // the wrong answer for job control (TIOCGPGRP, TCSBRK, FIOASYNC)
                // on a terminal and would hide the gap from the ring-first
                // counters. Leave it unrouted: a counted ENOSYS on both sides.
                let shape = host_ioctl(request)?;
                let mut bytes = [0; carrick_syscall_abi::LINUX_TERMIOS2_SIZE];
                let (input, output): (&[u8], _) = match shape {
                    HostIoctl::Get(len) => (&[], Some(HostFileOutput::bytes(arg, len))),
                    HostIoctl::Set(len) => {
                        if !user.copy_in(&mut bytes[..len], arg) {
                            return Some(HostFileStage::Fault {
                                address: arg,
                                access: Access::Read,
                            });
                        }
                        (&bytes[..len], None)
                    }
                };
                staging.request(HostFileOp::Ioctl, fd, 0, [request, 0, 0, 0], input, output)
            }
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
            NativeDescriptor::HostBacked { .. } => {
                let releases = staging.releases();
                let staged = staging.request_with_reply(
                    HostFileOp::MapPrivate,
                    key.fd,
                    0,
                    [key.offset, key.length, 0, 0],
                    &releases,
                    None,
                    host_file::MapSourceReply::BYTES,
                );
                match staged {
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
                        chdir: false,
                    },
                    other => other,
                }
            }
        },
        HostFileCall::Ppoll {
            fds,
            nfds,
            timeout,
            sigmask,
        } => {
            if sigmask != 0 {
                return None;
            }
            let timeout_ms = if timeout == 0 {
                -1
            } else {
                let mut spec = [0u8; 16];
                if !user.copy_in(&mut spec, timeout) {
                    return Some(HostFileStage::Fault {
                        address: timeout,
                        access: Access::Read,
                    });
                }
                let seconds = i64::from_le_bytes(spec[..8].try_into().unwrap_or([0; 8]));
                let nanoseconds = i64::from_le_bytes(spec[8..].try_into().unwrap_or([0; 8]));
                match ppoll_timeout_ms(seconds, nanoseconds) {
                    Ok(milliseconds) => milliseconds,
                    Err(errno) => {
                        return Some(HostFileStage::Returned(SyscallResult::from_errno(errno)));
                    }
                }
            };
            return stage_ppoll(&mut staging, user, fds, nfds, timeout_ms);
        }
        HostFileCall::Poll {
            fds,
            nfds,
            timeout_ms,
        } => return stage_ppoll(&mut staging, user, fds, nfds, timeout_ms.max(-1)),
        HostFileCall::Socket(call) => return socket::stage(call, &mut staging, user),
        HostFileCall::Chdir { path } => {
            let path = match copy_path(user, path) {
                Path::Bytes(path) => path,
                Path::Stage(stage) => return Some(stage),
            };
            if path.is_empty() {
                return Some(errno(carrick_syscall_abi::LINUX_ENOENT));
            }
            // The reply area holds the directory's `struct stat` and then
            // its cwd spelling: the carrier's chdir lookup.
            chdir_lookup(staging.request_with_reply(
                HostFileOp::Newfstatat,
                LINUX_AT_FDCWD,
                0,
                [0; 4],
                &path,
                None,
                CHDIR_REPLY_BYTES,
            ))
        }
        HostFileCall::Fchdir { fd } => match staging.descriptor(fd)? {
            NativeDescriptor::Absent => errno(carrick_syscall_abi::LINUX_EBADF),
            // Pipes, eventfds and epoll instances are never directories.
            NativeDescriptor::InZone(_) => errno(carrick_syscall_abi::LINUX_ENOTDIR),
            NativeDescriptor::HostBacked { .. } => chdir_lookup(staging.request_with_reply(
                HostFileOp::Fchdir,
                fd,
                0,
                [0; 4],
                &[],
                None,
                CHDIR_REPLY_BYTES,
            )),
        },
    })
}

/// A staged chdir lookup: on success the ring stores the reply's directory
/// spelling as the caller's cwd ([`chdir_target`]).
fn chdir_lookup(staged: HostFileStage) -> HostFileStage {
    match staged {
        HostFileStage::Request {
            record,
            resolves_path,
            ..
        } => HostFileStage::Request {
            record,
            output: None,
            resolves_path,
            map: None,
            chdir: true,
        },
        other => other,
    }
}

/// Linux `ppoll` timespec validation and conversion to whole milliseconds,
/// rounded up and saturated at `i32::MAX`: EINVAL for a negative second
/// count or nanoseconds outside `0..1e9`. The one validator the in-ring
/// poll body and the native venue's staging share.
pub fn ppoll_timeout_ms(seconds: i64, nanoseconds: i64) -> Result<i32, LinuxErrno> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(carrick_syscall_abi::LINUX_EINVAL);
    }
    let milliseconds = seconds
        .saturating_mul(1_000)
        .saturating_add((nanoseconds + 999_999) / 1_000_000);
    Ok(milliseconds.min(i64::from(i32::MAX)) as i32)
}

/// Stage a `ppoll` its in-ring owner left unrouted as one non-blocking
/// host readiness snapshot. The ring owner has already answered every
/// argument error, every all-in-zone set and `nfds == 0`; what reaches here
/// is a set that names a host-backed description, which only the carrier
/// can observe. Scope (#894, #1051):
/// - a signal mask, an in-zone member (a mixed set) or a set larger than
///   one record keeps its route (`None`, counted ENOSYS): answering part
///   of a set would misreport its one ready count;
/// - a caller that would wait (a non-zero timeout) on an empty snapshot
///   waits on its own host-readiness queue for the set's host objects, or
///   until its timeout (#231); a carrier without that wait refuses it,
///   never reporting a fake timeout.
///
/// Divergence from Linux: a zero-timeout set with nothing ready returns 0
/// even while an unblocked signal is pending, where Linux returns EINTR;
/// the signal is delivered on return. #1051 owns poll's signal semantics.
fn stage_ppoll(
    staging: &mut Staging<'_, '_>,
    user: &mut dyn HostFileUser,
    fds: u64,
    nfds: u64,
    timeout_ms: i32,
) -> Option<HostFileStage> {
    use host_file::{POLLFD_BYTES, PollWait};
    if nfds == 0 || nfds > (HOST_FILE_CHUNK_BYTES / POLLFD_BYTES) as u64 {
        return None;
    }
    let wait = if timeout_ms == 0 {
        PollWait::Snapshot
    } else {
        PollWait::MayWait
    };
    let len = nfds as usize * POLLFD_BYTES;
    let mut entries = vec![0u8; len];
    if !user.copy_in(&mut entries, fds) {
        return Some(HostFileStage::Fault {
            address: fds,
            access: Access::Read,
        });
    }
    let mut host_backed = false;
    for entry in entries.chunks_exact(POLLFD_BYTES) {
        let fd = i32::from_le_bytes(entry[..4].try_into().unwrap_or([0; 4]));
        if fd < 0 {
            continue;
        }
        match staging.descriptor(fd)? {
            NativeDescriptor::HostBacked { .. } => host_backed = true,
            NativeDescriptor::Absent => {}
            // A mixed set waits on a guest-owned producer the carrier
            // cannot observe (#1051).
            NativeDescriptor::InZone(_) => return None,
        }
    }
    if !host_backed {
        return None;
    }
    Some(staging.request(
        HostFileOp::Poll,
        -1,
        0,
        [wait.raw(), i64::from(timeout_ms) as u64, 0, 0],
        &entries,
        Some(HostFileOutput::bytes(fds, len)),
    ))
}

/// A chdir lookup's reply area: `struct stat`, then at most `PATH_MAX` bytes
/// of the directory's spelling.
pub const CHDIR_REPLY_BYTES: usize = LINUX_STAT_BYTES + LINUX_PATH_MAX;

/// The directory a served chdir lookup names, or the syscall result that
/// replaces the change (the carrier's errno, or EIO for a reply that is not
/// a directory spelling).
pub fn chdir_target(record: &[u8]) -> Result<crate::task_fs::TaskPath, SyscallResult> {
    let eio = SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO);
    let reply = host_file::reply(record).ok_or(eio)?;
    if reply.result < 0 {
        return Err(SyscallResult::new(reply.result));
    }
    let (stat, name) = reply.output.split_at_checked(LINUX_STAT_BYTES).ok_or(eio)?;
    let stat = <carrick_syscall_abi::LinuxStat as zerocopy::FromBytes>::read_from_bytes(stat)
        .map_err(|_| eio)?;
    if stat.st_mode & carrick_syscall_abi::LINUX_S_IFMT != carrick_syscall_abi::LINUX_S_IFDIR {
        return Err(eio);
    }
    crate::task_fs::TaskPath::new(name).ok_or(eio)
}

/// Re-stage a path record with its caller's encoded access context leading
/// the input (the ring task row's values, which only the ring owner holds).
/// Any other record is returned as staged. `None` when the record is not a
/// well-formed unserved request or the context does not fit one record.
pub fn stamp_access_context(record: &[u8], access: &[u8]) -> Option<Box<[u8]>> {
    let (header, input, output_cap) = host_file::request_parts(record)?;
    if !header.op.resolves_path() {
        return Some(record.into());
    }
    let mut staged = Vec::new();
    staged.try_reserve_exact(access.len() + input.len()).ok()?;
    staged.extend_from_slice(access);
    staged.extend_from_slice(input);
    let len = record_len(staged.len(), output_cap)?;
    let mut restaged = vec![0u8; len].into_boxed_slice();
    host_file::encode(&mut restaged, header, &staged, output_cap).ok()?;
    Some(restaged)
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
    if let Some(output) = output
        && output.layout == OutputLayout::Net
    {
        return host_file::replied_input(record)
            .and_then(|input| socket::complete(reply.result, input, reply.output, copy_out))
            .unwrap_or(SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO));
    }
    if output.is_some_and(|output| output.layout == OutputLayout::Vector) {
        let eio = SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO);
        let Some(vectors) = host_file::replied_input(record) else {
            return eio;
        };
        let mut bytes = reply.output;
        for vector in vectors.chunks_exact(IOVEC_BYTES) {
            let (address, len) = iovec_words(vector);
            let len = (len as usize).min(bytes.len());
            if len > 0 && !copy_out(address, &bytes[..len]) {
                let delivered = reply.output.len() - bytes.len();
                return if delivered == 0 {
                    SyscallResult::from_errno(carrick_syscall_abi::LINUX_EFAULT)
                } else {
                    SyscallResult::new(delivered as i64)
                };
            }
            bytes = &bytes[len..];
            if bytes.is_empty() {
                return SyscallResult::new(reply.result);
            }
        }
        return eio;
    }
    if let Some(output) = output {
        let Some(bytes) = output.encode(reply.output) else {
            return SyscallResult::from_errno(carrick_syscall_abi::LINUX_EIO);
        };
        if !bytes.is_empty() && !copy_out(output.address, &bytes) {
            return SyscallResult::from_errno(carrick_syscall_abi::LINUX_EFAULT);
        }
    }
    SyscallResult::new(reply.result)
}

/// Whether a served record's EPIPE owes its caller SIGPIPE (Linux's
/// `write(2)` to a pipe or socket, and `send`, `sendmsg` or `sendmmsg`
/// without `MSG_NOSIGNAL`). The
/// carrier serves with the signal suppressed; the ring, which owns the
/// caller's signals, raises it.
pub fn sigpipe_on_epipe(record: &[u8]) -> bool {
    let Some(input) = host_file::replied_input(record) else {
        return false;
    };
    let Some(reply) = host_file::reply(record) else {
        return false;
    };
    if reply.result != carrick_syscall_abi::LINUX_EPIPE.guest_retval() {
        return false;
    }
    let op = record
        .get(6..8)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
    if op == Some(HostFileOp::Write as u16) {
        return true;
    }
    op == Some(HostFileOp::NetSyscall as u16)
        && socket::staged_call(input).is_some_and(|call| {
            use crate::crossing::nr;
            let flags = match call.canonical {
                c if c == nr::SENDTO.raw() || c == nr::SENDMMSG.raw() => call.args[3],
                c if c == nr::SENDMSG.raw() => call.args[2],
                _ => return false,
            };
            flags & LINUX_MSG_NOSIGNAL == 0
        })
}

/// Linux `MSG_NOSIGNAL`.
const LINUX_MSG_NOSIGNAL: u64 = 0x4000;

/// Stamp a staged `Write` record with its writer's own `RLIMIT_FSIZE` soft
/// limit (`args[0]` for Write, `args[1]` for Truncate/Ftruncate,
/// `u64::MAX` unlimited), which only the caller's ring owns. The carrier
/// grows a regular file only for an unlimited caller, so an unstamped
/// record (0) fails closed. Other records remain as staged and never
/// consult `soft_limit`.
pub fn stamp_write_file_size_limit<E>(
    record: &mut [u8],
    soft_limit: impl FnOnce() -> Result<u64, E>,
) -> Result<(), E> {
    let Ok(mut view) = host_file::HostFileRequestView::parse(record) else {
        // A malformed record is the carrier's to refuse.
        return Ok(());
    };
    let mut args = view.header().args;
    let index = match view.header().op {
        HostFileOp::Write => 0,
        HostFileOp::Truncate | HostFileOp::Ftruncate | HostFileOp::Pwrite => 1,
        _ => return Ok(()),
    };
    args[index] = soft_limit()?;
    view.set_args(args);
    Ok(())
}

/// The same request as `record` with its reply cleared, for the ring to
/// publish again once the host object its call would have blocked on is
/// ready (#2414): the record made no effect, and its staged input, header
/// and stamps are the call's own. `None` for a malformed record.
pub fn request_again(record: &[u8]) -> Option<Box<[u8]>> {
    let (header, input, output_cap) = host_file::request_parts(record)?;
    let mut again = vec![0u8; record_len(input.len(), output_cap)?].into_boxed_slice();
    host_file::encode(&mut again, header, input, output_cap).ok()?;
    Some(again)
}

/// Whether Linux restarts `record`'s call under `SA_RESTART` when a signal
/// interrupts it before any effect (signal(7)): a socket call, a read or a
/// write of a slow object, never a poll. The canonical number is the
/// record's own, whatever the caller's ISA.
pub fn restarts_after_interrupt(record: &[u8]) -> bool {
    let Some((header, input, _)) = host_file::request_parts(record) else {
        return false;
    };
    let canonical = match header.op {
        HostFileOp::NetSyscall => match socket::staged_call(input) {
            Some(call) => call.canonical,
            None => return false,
        },
        HostFileOp::Read => crate::crossing::nr::READ.raw(),
        HostFileOp::Write => crate::crossing::nr::WRITE.raw(),
        _ => return false,
    };
    carrick_signal_core::is_native_restartable_syscall(canonical)
}

/// Stamp a staged `Poll` record with its call's ring serial (#2414 review
/// P0-2): the carrier keys the call's deadline on it, so a record the ring
/// publishes again for the same call keeps the call's deadline and a new
/// call starts its own. Any other record is left as staged. `false` for a
/// malformed record.
pub fn stamp_poll_call(record: &mut [u8], serial: host_file::HostCallSerial) -> bool {
    let Ok(mut view) = host_file::HostFileRequestView::parse(record) else {
        return false;
    };
    if view.header().op != HostFileOp::Poll {
        return true;
    }
    let mut args = view.header().args;
    args[host_file::POLL_CALL_SERIAL_ARG] = serial.raw();
    view.set_args(args);
    true
}

#[cfg(test)]
mod tests;
