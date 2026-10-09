//! Shared host crossing table for Linux personality.
//!
//! Governs which syscalls may cross the guest-to-host boundary via
//! `CompletionRoute::Forward`. Used by both ARM EL1 and x86 CPL0.
//!
//! Syscalls outside this table must not reach the host when strict ring-first
//! enforcement is active; they are answered with counted `-ENOSYS`.

use carrick_syscall_abi::{CanonicalNr, LinuxErrno};

/// Linux ENOSYS errno in typed domain.
pub const LINUX_ENOSYS: LinuxErrno = LinuxErrno::new(38);

/// Canonical syscall identities permitted to cross to host.
pub mod nr {
    use carrick_syscall_abi::CanonicalNr;

    // Host file contents & filesystem metadata (73 syscalls):
    pub const SETXATTR: CanonicalNr = CanonicalNr(5);
    pub const LSETXATTR: CanonicalNr = CanonicalNr(6);
    pub const FSETXATTR: CanonicalNr = CanonicalNr(7);
    pub const GETXATTR: CanonicalNr = CanonicalNr(8);
    pub const LGETXATTR: CanonicalNr = CanonicalNr(9);
    pub const FGETXATTR: CanonicalNr = CanonicalNr(10);
    pub const LISTXATTR: CanonicalNr = CanonicalNr(11);
    pub const LLISTXATTR: CanonicalNr = CanonicalNr(12);
    pub const FLISTXATTR: CanonicalNr = CanonicalNr(13);
    pub const REMOVEXATTR: CanonicalNr = CanonicalNr(14);
    pub const LREMOVEXATTR: CanonicalNr = CanonicalNr(15);
    pub const FREMOVEXATTR: CanonicalNr = CanonicalNr(16);
    pub const GETCWD: CanonicalNr = CanonicalNr(17);
    pub const IOCTL: CanonicalNr = CanonicalNr(29);
    pub const FLOCK: CanonicalNr = CanonicalNr(32);
    pub const MKNODAT: CanonicalNr = CanonicalNr(33);
    pub const MKDIRAT: CanonicalNr = CanonicalNr(34);
    pub const UNLINKAT: CanonicalNr = CanonicalNr(35);
    pub const SYMLINKAT: CanonicalNr = CanonicalNr(36);
    pub const LINKAT: CanonicalNr = CanonicalNr(37);
    pub const RENAMEAT: CanonicalNr = CanonicalNr(38);
    pub const STATFS: CanonicalNr = CanonicalNr(43);
    pub const FSTATFS: CanonicalNr = CanonicalNr(44);
    pub const TRUNCATE: CanonicalNr = CanonicalNr(45);
    pub const FTRUNCATE: CanonicalNr = CanonicalNr(46);
    pub const FALLOCATE: CanonicalNr = CanonicalNr(47);
    pub const FACCESSAT: CanonicalNr = CanonicalNr(48);
    pub const CHDIR: CanonicalNr = CanonicalNr(49);
    pub const FCHDIR: CanonicalNr = CanonicalNr(50);
    pub const CHROOT: CanonicalNr = CanonicalNr(51);
    pub const FCHMOD: CanonicalNr = CanonicalNr(52);
    pub const FCHMODAT: CanonicalNr = CanonicalNr(53);
    pub const FCHOWNAT: CanonicalNr = CanonicalNr(54);
    pub const FCHOWN: CanonicalNr = CanonicalNr(55);
    pub const OPENAT: CanonicalNr = CanonicalNr(56);
    pub const GETDENTS64: CanonicalNr = CanonicalNr(61);
    pub const LSEEK: CanonicalNr = CanonicalNr(62);
    pub const READ: CanonicalNr = CanonicalNr(63);
    pub const WRITE: CanonicalNr = CanonicalNr(64);
    pub const READV: CanonicalNr = CanonicalNr(65);
    pub const WRITEV: CanonicalNr = CanonicalNr(66);
    pub const PREAD64: CanonicalNr = CanonicalNr(67);
    pub const PWRITE64: CanonicalNr = CanonicalNr(68);
    pub const PREADV: CanonicalNr = CanonicalNr(69);
    pub const PWRITEV: CanonicalNr = CanonicalNr(70);
    pub const SENDFILE: CanonicalNr = CanonicalNr(71);
    pub const PSELECT6: CanonicalNr = CanonicalNr(72);
    pub const PPOLL: CanonicalNr = CanonicalNr(73);
    pub const VMSPLICE: CanonicalNr = CanonicalNr(75);
    pub const SPLICE: CanonicalNr = CanonicalNr(76);
    pub const TEE: CanonicalNr = CanonicalNr(77);
    pub const READLINKAT: CanonicalNr = CanonicalNr(78);
    pub const NEWFSTATAT: CanonicalNr = CanonicalNr(79);
    pub const FSTAT: CanonicalNr = CanonicalNr(80);
    pub const SYNC: CanonicalNr = CanonicalNr(81);
    pub const FSYNC: CanonicalNr = CanonicalNr(82);
    pub const FDATASYNC: CanonicalNr = CanonicalNr(83);
    pub const SYNC_FILE_RANGE: CanonicalNr = CanonicalNr(84);
    pub const UTIMENSAT: CanonicalNr = CanonicalNr(88);
    pub const EXECVE: CanonicalNr = CanonicalNr(221);
    pub const MSYNC: CanonicalNr = CanonicalNr(227);
    pub const MLOCK: CanonicalNr = CanonicalNr(228);
    pub const MUNLOCK: CanonicalNr = CanonicalNr(229);
    pub const MINCORE: CanonicalNr = CanonicalNr(232);
    pub const MADVISE: CanonicalNr = CanonicalNr(233);
    pub const SYNCFS: CanonicalNr = CanonicalNr(267);
    pub const RENAMEAT2: CanonicalNr = CanonicalNr(276);
    pub const MLOCK2: CanonicalNr = CanonicalNr(284);
    pub const COPY_FILE_RANGE: CanonicalNr = CanonicalNr(285);
    pub const PREADV2: CanonicalNr = CanonicalNr(286);
    pub const PWRITEV2: CanonicalNr = CanonicalNr(287);
    pub const STATX: CanonicalNr = CanonicalNr(291);
    pub const OPENAT2: CanonicalNr = CanonicalNr(437);
    pub const FACCESSAT2: CanonicalNr = CanonicalNr(439);
    pub const FCHMODAT2: CanonicalNr = CanonicalNr(452);

    // Host network & BSD sockets (18 syscalls):
    pub const SOCKET: CanonicalNr = CanonicalNr(198);
    pub const SOCKETPAIR: CanonicalNr = CanonicalNr(199);
    pub const BIND: CanonicalNr = CanonicalNr(200);
    pub const LISTEN: CanonicalNr = CanonicalNr(201);
    pub const ACCEPT: CanonicalNr = CanonicalNr(202);
    pub const CONNECT: CanonicalNr = CanonicalNr(203);
    pub const GETSOCKNAME: CanonicalNr = CanonicalNr(204);
    pub const GETPEERNAME: CanonicalNr = CanonicalNr(205);
    pub const SENDTO: CanonicalNr = CanonicalNr(206);
    pub const RECVFROM: CanonicalNr = CanonicalNr(207);
    pub const SETSOCKOPT: CanonicalNr = CanonicalNr(208);
    pub const GETSOCKOPT: CanonicalNr = CanonicalNr(209);
    pub const SHUTDOWN: CanonicalNr = CanonicalNr(210);
    pub const SENDMSG: CanonicalNr = CanonicalNr(211);
    pub const RECVMSG: CanonicalNr = CanonicalNr(212);
    pub const ACCEPT4: CanonicalNr = CanonicalNr(242);
    pub const RECVMMSG: CanonicalNr = CanonicalNr(243);
    pub const SENDMMSG: CanonicalNr = CanonicalNr(269);

    // Host clock & hardware time (6 syscalls):
    pub const NANOSLEEP: CanonicalNr = CanonicalNr(101);
    pub const CLOCK_GETTIME: CanonicalNr = CanonicalNr(113);
    pub const CLOCK_GETRES: CanonicalNr = CanonicalNr(114);
    pub const CLOCK_NANOSLEEP: CanonicalNr = CanonicalNr(115);
    pub const TIMES: CanonicalNr = CanonicalNr(153);
    pub const GETTIMEOFDAY: CanonicalNr = CanonicalNr(169);

    // Host hardware entropy (1 syscall):
    pub const GETRANDOM: CanonicalNr = CanonicalNr(278);

    // Temporary-forward compat-zone fd rows (16 syscalls):
    pub const EVENTFD2: CanonicalNr = CanonicalNr(19);
    pub const EPOLL_CREATE1: CanonicalNr = CanonicalNr(20);
    pub const EPOLL_CTL: CanonicalNr = CanonicalNr(21);
    pub const EPOLL_PWAIT: CanonicalNr = CanonicalNr(22);
    pub const DUP: CanonicalNr = CanonicalNr(23);
    pub const DUP3: CanonicalNr = CanonicalNr(24);
    pub const FCNTL: CanonicalNr = CanonicalNr(25);
    pub const INOTIFY_INIT1: CanonicalNr = CanonicalNr(26);
    pub const CLOSE: CanonicalNr = CanonicalNr(57);
    pub const PIPE2: CanonicalNr = CanonicalNr(59);
    pub const SIGNALFD4: CanonicalNr = CanonicalNr(74);
    pub const TIMERFD_CREATE: CanonicalNr = CanonicalNr(85);
    pub const TIMERFD_SETTIME: CanonicalNr = CanonicalNr(86);
    pub const TIMERFD_GETTIME: CanonicalNr = CanonicalNr(87);
    pub const CLOSE_RANGE: CanonicalNr = CanonicalNr(436);
    pub const EPOLL_PWAIT2: CanonicalNr = CanonicalNr(441);

    // x86-only host exit crossings (Wire-in-ring on ARM):
    pub const EXIT: CanonicalNr = CanonicalNr(93);
    pub const EXIT_GROUP: CanonicalNr = CanonicalNr(94);
}

/// Identifies syscalls permitted to cross to the host carrier.
///
/// Keyed on canonical syscall identities ([`CanonicalNr`]), which map to
/// Linux asm-generic / AArch64 numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum AllowedHostCrossing {
    // Host file contents & filesystem metadata (73 syscalls):
    Setxattr = nr::SETXATTR.raw(),
    Lsetxattr = nr::LSETXATTR.raw(),
    Fsetxattr = nr::FSETXATTR.raw(),
    Getxattr = nr::GETXATTR.raw(),
    Lgetxattr = nr::LGETXATTR.raw(),
    Fgetxattr = nr::FGETXATTR.raw(),
    Listxattr = nr::LISTXATTR.raw(),
    Llistxattr = nr::LLISTXATTR.raw(),
    Flistxattr = nr::FLISTXATTR.raw(),
    Removexattr = nr::REMOVEXATTR.raw(),
    Lremovexattr = nr::LREMOVEXATTR.raw(),
    Fremovexattr = nr::FREMOVEXATTR.raw(),
    Getcwd = nr::GETCWD.raw(),
    Ioctl = nr::IOCTL.raw(),
    Flock = nr::FLOCK.raw(),
    Mknodat = nr::MKNODAT.raw(),
    Mkdirat = nr::MKDIRAT.raw(),
    Unlinkat = nr::UNLINKAT.raw(),
    Symlinkat = nr::SYMLINKAT.raw(),
    Linkat = nr::LINKAT.raw(),
    Renameat = nr::RENAMEAT.raw(),
    Statfs = nr::STATFS.raw(),
    Fstatfs = nr::FSTATFS.raw(),
    Truncate = nr::TRUNCATE.raw(),
    Ftruncate = nr::FTRUNCATE.raw(),
    Fallocate = nr::FALLOCATE.raw(),
    Faccessat = nr::FACCESSAT.raw(),
    Chdir = nr::CHDIR.raw(),
    Fchdir = nr::FCHDIR.raw(),
    Chroot = nr::CHROOT.raw(),
    Fchmod = nr::FCHMOD.raw(),
    Fchmodat = nr::FCHMODAT.raw(),
    Fchownat = nr::FCHOWNAT.raw(),
    Fchown = nr::FCHOWN.raw(),
    Openat = nr::OPENAT.raw(),
    Getdents64 = nr::GETDENTS64.raw(),
    Lseek = nr::LSEEK.raw(),
    Read = nr::READ.raw(),
    Write = nr::WRITE.raw(),
    Readv = nr::READV.raw(),
    Writev = nr::WRITEV.raw(),
    Pread64 = nr::PREAD64.raw(),
    Pwrite64 = nr::PWRITE64.raw(),
    Preadv = nr::PREADV.raw(),
    Pwritev = nr::PWRITEV.raw(),
    Sendfile = nr::SENDFILE.raw(),
    Pselect6 = nr::PSELECT6.raw(),
    Ppoll = nr::PPOLL.raw(),
    Vmsplice = nr::VMSPLICE.raw(),
    Splice = nr::SPLICE.raw(),
    Tee = nr::TEE.raw(),
    Readlinkat = nr::READLINKAT.raw(),
    Newfstatat = nr::NEWFSTATAT.raw(),
    Fstat = nr::FSTAT.raw(),
    Sync = nr::SYNC.raw(),
    Fsync = nr::FSYNC.raw(),
    Fdatasync = nr::FDATASYNC.raw(),
    SyncFileRange = nr::SYNC_FILE_RANGE.raw(),
    Utimensat = nr::UTIMENSAT.raw(),
    Execve = nr::EXECVE.raw(),
    Msync = nr::MSYNC.raw(),
    Mlock = nr::MLOCK.raw(),
    Munlock = nr::MUNLOCK.raw(),
    Mincore = nr::MINCORE.raw(),
    Madvise = nr::MADVISE.raw(),
    Syncfs = nr::SYNCFS.raw(),
    Renameat2 = nr::RENAMEAT2.raw(),
    Mlock2 = nr::MLOCK2.raw(),
    CopyFileRange = nr::COPY_FILE_RANGE.raw(),
    Preadv2 = nr::PREADV2.raw(),
    Pwritev2 = nr::PWRITEV2.raw(),
    Statx = nr::STATX.raw(),
    Openat2 = nr::OPENAT2.raw(),
    Faccessat2 = nr::FACCESSAT2.raw(),
    Fchmodat2 = nr::FCHMODAT2.raw(),

    // Host network & BSD sockets (18 syscalls):
    Socket = nr::SOCKET.raw(),
    Socketpair = nr::SOCKETPAIR.raw(),
    Bind = nr::BIND.raw(),
    Listen = nr::LISTEN.raw(),
    Accept = nr::ACCEPT.raw(),
    Connect = nr::CONNECT.raw(),
    Getsockname = nr::GETSOCKNAME.raw(),
    Getpeername = nr::GETPEERNAME.raw(),
    Sendto = nr::SENDTO.raw(),
    Recvfrom = nr::RECVFROM.raw(),
    Setsockopt = nr::SETSOCKOPT.raw(),
    Getsockopt = nr::GETSOCKOPT.raw(),
    Shutdown = nr::SHUTDOWN.raw(),
    Sendmsg = nr::SENDMSG.raw(),
    Recvmsg = nr::RECVMSG.raw(),
    Accept4 = nr::ACCEPT4.raw(),
    Recvmmsg = nr::RECVMMSG.raw(),
    Sendmmsg = nr::SENDMMSG.raw(),

    // Host clock & hardware time (6 syscalls):
    Nanosleep = nr::NANOSLEEP.raw(),
    ClockGettime = nr::CLOCK_GETTIME.raw(),
    ClockGetres = nr::CLOCK_GETRES.raw(),
    ClockNanosleep = nr::CLOCK_NANOSLEEP.raw(),
    Times = nr::TIMES.raw(),
    Gettimeofday = nr::GETTIMEOFDAY.raw(),

    // Host hardware entropy (1 syscall):
    Getrandom = nr::GETRANDOM.raw(),

    // Temporary-forward compat-zone fd rows (16 syscalls):
    Eventfd2 = nr::EVENTFD2.raw(),
    EpollCreate1 = nr::EPOLL_CREATE1.raw(),
    EpollCtl = nr::EPOLL_CTL.raw(),
    EpollPwait = nr::EPOLL_PWAIT.raw(),
    Dup = nr::DUP.raw(),
    Dup3 = nr::DUP3.raw(),
    Fcntl = nr::FCNTL.raw(),
    InotifyInit1 = nr::INOTIFY_INIT1.raw(),
    Close = nr::CLOSE.raw(),
    Pipe2 = nr::PIPE2.raw(),
    Signalfd4 = nr::SIGNALFD4.raw(),
    TimerfdCreate = nr::TIMERFD_CREATE.raw(),
    TimerfdSettime = nr::TIMERFD_SETTIME.raw(),
    TimerfdGettime = nr::TIMERFD_GETTIME.raw(),
    CloseRange = nr::CLOSE_RANGE.raw(),
    EpollPwait2 = nr::EPOLL_PWAIT2.raw(),

    // x86-only host exit crossings (Wire-in-ring on ARM):
    Exit = nr::EXIT.raw(),
    ExitGroup = nr::EXIT_GROUP.raw(),
}

impl AllowedHostCrossing {
    /// Canonical identity of this crossing.
    #[inline]
    pub const fn canonical(self) -> CanonicalNr {
        CanonicalNr::new(self as u64)
    }

    /// Match an allowed host crossing for x86 CPL0.
    ///
    /// Preserves exactly the eight historical x86 host crossings:
    /// read, write, lseek, pread64, pwrite64, exit, exit_group, epoll_pwait.
    pub const fn from_canonical_x86(canonical: CanonicalNr) -> Option<Self> {
        match canonical {
            nr::READ => Some(Self::Read),
            nr::WRITE => Some(Self::Write),
            nr::LSEEK => Some(Self::Lseek),
            nr::PREAD64 => Some(Self::Pread64),
            nr::PWRITE64 => Some(Self::Pwrite64),
            nr::EXIT => Some(Self::Exit),
            nr::EXIT_GROUP => Some(Self::ExitGroup),
            nr::EPOLL_PWAIT => Some(Self::EpollPwait),
            _ => None,
        }
    }

    /// Match an allowed host crossing for AArch64 ARM EL1.
    ///
    /// Covers the 100 Forward-Allowlist rows (host files, network, clock,
    /// entropy) and the 16 Temporary-forward fd rows. Excludes in-ring
    /// handlers (such as exit, exit_group).
    pub const fn from_canonical_aarch64(canonical: CanonicalNr) -> Option<Self> {
        match canonical {
            nr::SETXATTR => Some(Self::Setxattr),
            nr::LSETXATTR => Some(Self::Lsetxattr),
            nr::FSETXATTR => Some(Self::Fsetxattr),
            nr::GETXATTR => Some(Self::Getxattr),
            nr::LGETXATTR => Some(Self::Lgetxattr),
            nr::FGETXATTR => Some(Self::Fgetxattr),
            nr::LISTXATTR => Some(Self::Listxattr),
            nr::LLISTXATTR => Some(Self::Llistxattr),
            nr::FLISTXATTR => Some(Self::Flistxattr),
            nr::REMOVEXATTR => Some(Self::Removexattr),
            nr::LREMOVEXATTR => Some(Self::Lremovexattr),
            nr::FREMOVEXATTR => Some(Self::Fremovexattr),
            nr::GETCWD => Some(Self::Getcwd),
            nr::EVENTFD2 => Some(Self::Eventfd2),
            nr::EPOLL_CREATE1 => Some(Self::EpollCreate1),
            nr::EPOLL_CTL => Some(Self::EpollCtl),
            nr::EPOLL_PWAIT => Some(Self::EpollPwait),
            nr::DUP => Some(Self::Dup),
            nr::DUP3 => Some(Self::Dup3),
            nr::FCNTL => Some(Self::Fcntl),
            nr::INOTIFY_INIT1 => Some(Self::InotifyInit1),
            nr::IOCTL => Some(Self::Ioctl),
            nr::FLOCK => Some(Self::Flock),
            nr::MKNODAT => Some(Self::Mknodat),
            nr::MKDIRAT => Some(Self::Mkdirat),
            nr::UNLINKAT => Some(Self::Unlinkat),
            nr::SYMLINKAT => Some(Self::Symlinkat),
            nr::LINKAT => Some(Self::Linkat),
            nr::RENAMEAT => Some(Self::Renameat),
            nr::STATFS => Some(Self::Statfs),
            nr::FSTATFS => Some(Self::Fstatfs),
            nr::TRUNCATE => Some(Self::Truncate),
            nr::FTRUNCATE => Some(Self::Ftruncate),
            nr::FALLOCATE => Some(Self::Fallocate),
            nr::FACCESSAT => Some(Self::Faccessat),
            nr::CHDIR => Some(Self::Chdir),
            nr::FCHDIR => Some(Self::Fchdir),
            nr::CHROOT => Some(Self::Chroot),
            nr::FCHMOD => Some(Self::Fchmod),
            nr::FCHMODAT => Some(Self::Fchmodat),
            nr::FCHOWNAT => Some(Self::Fchownat),
            nr::FCHOWN => Some(Self::Fchown),
            nr::OPENAT => Some(Self::Openat),
            nr::CLOSE => Some(Self::Close),
            nr::PIPE2 => Some(Self::Pipe2),
            nr::GETDENTS64 => Some(Self::Getdents64),
            nr::LSEEK => Some(Self::Lseek),
            nr::READ => Some(Self::Read),
            nr::WRITE => Some(Self::Write),
            nr::READV => Some(Self::Readv),
            nr::WRITEV => Some(Self::Writev),
            nr::PREAD64 => Some(Self::Pread64),
            nr::PWRITE64 => Some(Self::Pwrite64),
            nr::PREADV => Some(Self::Preadv),
            nr::PWRITEV => Some(Self::Pwritev),
            nr::SENDFILE => Some(Self::Sendfile),
            nr::PSELECT6 => Some(Self::Pselect6),
            nr::PPOLL => Some(Self::Ppoll),
            nr::SIGNALFD4 => Some(Self::Signalfd4),
            nr::VMSPLICE => Some(Self::Vmsplice),
            nr::SPLICE => Some(Self::Splice),
            nr::TEE => Some(Self::Tee),
            nr::READLINKAT => Some(Self::Readlinkat),
            nr::NEWFSTATAT => Some(Self::Newfstatat),
            nr::FSTAT => Some(Self::Fstat),
            nr::SYNC => Some(Self::Sync),
            nr::FSYNC => Some(Self::Fsync),
            nr::FDATASYNC => Some(Self::Fdatasync),
            nr::SYNC_FILE_RANGE => Some(Self::SyncFileRange),
            nr::TIMERFD_CREATE => Some(Self::TimerfdCreate),
            nr::TIMERFD_SETTIME => Some(Self::TimerfdSettime),
            nr::TIMERFD_GETTIME => Some(Self::TimerfdGettime),
            nr::UTIMENSAT => Some(Self::Utimensat),
            nr::NANOSLEEP => Some(Self::Nanosleep),
            nr::CLOCK_GETTIME => Some(Self::ClockGettime),
            nr::CLOCK_GETRES => Some(Self::ClockGetres),
            nr::CLOCK_NANOSLEEP => Some(Self::ClockNanosleep),
            nr::TIMES => Some(Self::Times),
            nr::GETTIMEOFDAY => Some(Self::Gettimeofday),
            nr::SOCKET => Some(Self::Socket),
            nr::SOCKETPAIR => Some(Self::Socketpair),
            nr::BIND => Some(Self::Bind),
            nr::LISTEN => Some(Self::Listen),
            nr::ACCEPT => Some(Self::Accept),
            nr::CONNECT => Some(Self::Connect),
            nr::GETSOCKNAME => Some(Self::Getsockname),
            nr::GETPEERNAME => Some(Self::Getpeername),
            nr::SENDTO => Some(Self::Sendto),
            nr::RECVFROM => Some(Self::Recvfrom),
            nr::SETSOCKOPT => Some(Self::Setsockopt),
            nr::GETSOCKOPT => Some(Self::Getsockopt),
            nr::SHUTDOWN => Some(Self::Shutdown),
            nr::SENDMSG => Some(Self::Sendmsg),
            nr::RECVMSG => Some(Self::Recvmsg),
            nr::EXECVE => Some(Self::Execve),
            nr::MSYNC => Some(Self::Msync),
            nr::MLOCK => Some(Self::Mlock),
            nr::MUNLOCK => Some(Self::Munlock),
            nr::MINCORE => Some(Self::Mincore),
            nr::MADVISE => Some(Self::Madvise),
            nr::ACCEPT4 => Some(Self::Accept4),
            nr::RECVMMSG => Some(Self::Recvmmsg),
            nr::SYNCFS => Some(Self::Syncfs),
            nr::SENDMMSG => Some(Self::Sendmmsg),
            nr::RENAMEAT2 => Some(Self::Renameat2),
            nr::GETRANDOM => Some(Self::Getrandom),
            nr::MLOCK2 => Some(Self::Mlock2),
            nr::COPY_FILE_RANGE => Some(Self::CopyFileRange),
            nr::PREADV2 => Some(Self::Preadv2),
            nr::PWRITEV2 => Some(Self::Pwritev2),
            nr::STATX => Some(Self::Statx),
            nr::CLOSE_RANGE => Some(Self::CloseRange),
            nr::OPENAT2 => Some(Self::Openat2),
            nr::FACCESSAT2 => Some(Self::Faccessat2),
            nr::EPOLL_PWAIT2 => Some(Self::EpollPwait2),
            nr::FCHMODAT2 => Some(Self::Fchmodat2),
            _ => None,
        }
    }

    /// Whether this canonical identity is an allowed host crossing on x86 CPL0.
    #[inline]
    pub const fn is_allowed_x86(canonical: CanonicalNr) -> bool {
        Self::from_canonical_x86(canonical).is_some()
    }

    /// Whether this canonical identity is an allowed host crossing on AArch64 ARM EL1.
    #[inline]
    pub const fn is_allowed_aarch64(canonical: CanonicalNr) -> bool {
        Self::from_canonical_aarch64(canonical).is_some()
    }
}

/// The exact 8 canonical syscalls permitted to cross to host on x86 CPL0.
pub const X86_HOST_CROSSINGS: [CanonicalNr; 8] = [
    nr::EPOLL_PWAIT,
    nr::LSEEK,
    nr::READ,
    nr::WRITE,
    nr::PREAD64,
    nr::PWRITE64,
    nr::EXIT,
    nr::EXIT_GROUP,
];

/// The exact 116 canonical syscalls permitted to cross to host on AArch64 ARM EL1.
pub const AARCH64_HOST_CROSSINGS: [CanonicalNr; 116] = [
    nr::SETXATTR,
    nr::LSETXATTR,
    nr::FSETXATTR,
    nr::GETXATTR,
    nr::LGETXATTR,
    nr::FGETXATTR,
    nr::LISTXATTR,
    nr::LLISTXATTR,
    nr::FLISTXATTR,
    nr::REMOVEXATTR,
    nr::LREMOVEXATTR,
    nr::FREMOVEXATTR,
    nr::GETCWD,
    nr::EVENTFD2,
    nr::EPOLL_CREATE1,
    nr::EPOLL_CTL,
    nr::EPOLL_PWAIT,
    nr::DUP,
    nr::DUP3,
    nr::FCNTL,
    nr::INOTIFY_INIT1,
    nr::IOCTL,
    nr::FLOCK,
    nr::MKNODAT,
    nr::MKDIRAT,
    nr::UNLINKAT,
    nr::SYMLINKAT,
    nr::LINKAT,
    nr::RENAMEAT,
    nr::STATFS,
    nr::FSTATFS,
    nr::TRUNCATE,
    nr::FTRUNCATE,
    nr::FALLOCATE,
    nr::FACCESSAT,
    nr::CHDIR,
    nr::FCHDIR,
    nr::CHROOT,
    nr::FCHMOD,
    nr::FCHMODAT,
    nr::FCHOWNAT,
    nr::FCHOWN,
    nr::OPENAT,
    nr::CLOSE,
    nr::PIPE2,
    nr::GETDENTS64,
    nr::LSEEK,
    nr::READ,
    nr::WRITE,
    nr::READV,
    nr::WRITEV,
    nr::PREAD64,
    nr::PWRITE64,
    nr::PREADV,
    nr::PWRITEV,
    nr::SENDFILE,
    nr::PSELECT6,
    nr::PPOLL,
    nr::SIGNALFD4,
    nr::VMSPLICE,
    nr::SPLICE,
    nr::TEE,
    nr::READLINKAT,
    nr::NEWFSTATAT,
    nr::FSTAT,
    nr::SYNC,
    nr::FSYNC,
    nr::FDATASYNC,
    nr::SYNC_FILE_RANGE,
    nr::TIMERFD_CREATE,
    nr::TIMERFD_SETTIME,
    nr::TIMERFD_GETTIME,
    nr::UTIMENSAT,
    nr::NANOSLEEP,
    nr::CLOCK_GETTIME,
    nr::CLOCK_GETRES,
    nr::CLOCK_NANOSLEEP,
    nr::TIMES,
    nr::GETTIMEOFDAY,
    nr::SOCKET,
    nr::SOCKETPAIR,
    nr::BIND,
    nr::LISTEN,
    nr::ACCEPT,
    nr::CONNECT,
    nr::GETSOCKNAME,
    nr::GETPEERNAME,
    nr::SENDTO,
    nr::RECVFROM,
    nr::SETSOCKOPT,
    nr::GETSOCKOPT,
    nr::SHUTDOWN,
    nr::SENDMSG,
    nr::RECVMSG,
    nr::EXECVE,
    nr::MSYNC,
    nr::MLOCK,
    nr::MUNLOCK,
    nr::MINCORE,
    nr::MADVISE,
    nr::ACCEPT4,
    nr::RECVMMSG,
    nr::SYNCFS,
    nr::SENDMMSG,
    nr::RENAMEAT2,
    nr::GETRANDOM,
    nr::MLOCK2,
    nr::COPY_FILE_RANGE,
    nr::PREADV2,
    nr::PWRITEV2,
    nr::STATX,
    nr::CLOSE_RANGE,
    nr::OPENAT2,
    nr::FACCESSAT2,
    nr::EPOLL_PWAIT2,
    nr::FCHMODAT2,
];

/// Target ISA whose crossing allowlist governs host forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCrossingSet {
    Aarch64,
    X86,
}

impl HostCrossingSet {
    /// Whether this canonical syscall is permitted to cross to host.
    #[inline]
    pub const fn is_allowed(self, canonical: CanonicalNr) -> bool {
        match self {
            Self::Aarch64 => AllowedHostCrossing::from_canonical_aarch64(canonical).is_some(),
            Self::X86 => AllowedHostCrossing::from_canonical_x86(canonical).is_some(),
        }
    }

    /// Map a native syscall number to its refusal counter bucket (0..=512).
    #[inline]
    pub fn refusal_bucket(self, native: Option<u64>) -> usize {
        match self {
            Self::Aarch64 => match native {
                Some(nr) if nr < 512 => nr as usize,
                _ => 512,
            },
            Self::X86 => match native {
                Some(nr) if nr < 512 => {
                    match carrick_syscall_abi::syscall_x86_64::lookup_x86_64(nr) {
                        Some(entry)
                            if !matches!(
                                entry.remap,
                                carrick_syscall_abi::syscall_x86_64::SyscallRemap::Unknown
                                    | carrick_syscall_abi::syscall_x86_64::SyscallRemap::Private(_)
                            ) =>
                        {
                            nr as usize
                        }
                        _ => 512,
                    }
                }
                _ => 512,
            },
        }
    }
}

/// The outcome of evaluating a potential host crossing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCrossingDecision {
    /// The syscall is permitted to leave the guest for host handling.
    Forward,
    /// The syscall was refused at the fast path; -ENOSYS has been installed and counted.
    Refused,
}

/// The single shared host crossing refusal decision for ARM EL1 and x86 CPL0.
///
/// If strict ring-first mode is disabled (`!strict`), or if `canonical` is present
/// and allowed in `set`, returns [`HostCrossingDecision::Forward`].
///
/// Otherwise, the call is refused:
/// 1. Its refusal bucket is calculated and counted in `counters` (if provided).
/// 2. `install_result` is invoked with `LINUX_ENOSYS.guest_retval()` (-38).
/// 3. Returns [`HostCrossingDecision::Refused`].
pub fn evaluate_host_crossing<F>(
    set: HostCrossingSet,
    strict: bool,
    canonical: Option<CanonicalNr>,
    native: Option<u64>,
    counters: Option<&[core::sync::atomic::AtomicU64]>,
    install_result: F,
) -> HostCrossingDecision
where
    F: FnOnce(i64),
{
    if !strict {
        return HostCrossingDecision::Forward;
    }
    if let Some(canonical) = canonical
        && set.is_allowed(canonical)
    {
        return HostCrossingDecision::Forward;
    }
    let bucket = set.refusal_bucket(native);
    if let Some(counters) = counters
        && bucket < counters.len()
    {
        counters[bucket].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    install_result(LINUX_ENOSYS.guest_retval());
    HostCrossingDecision::Refused
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_crossings_exact() {
        assert_eq!(X86_HOST_CROSSINGS.len(), 8);
        for nr in X86_HOST_CROSSINGS {
            assert!(
                AllowedHostCrossing::is_allowed_x86(nr),
                "expected canonical {nr:?} to be allowed on x86"
            );
        }
        // Known non-crossing calls on x86
        for non_crossing in [
            CanonicalNr(0),   // io_setup
            CanonicalNr(17),  // getcwd
            CanonicalNr(48),  // faccessat
            CanonicalNr(56),  // openat
            CanonicalNr(113), // clock_gettime
            CanonicalNr(148), // getresuid
            CanonicalNr(174), // getuid
            CanonicalNr(214), // brk
            CanonicalNr(220), // clone
            CanonicalNr(222), // mmap
            CanonicalNr(999), // out-of-range
        ] {
            assert!(
                !AllowedHostCrossing::is_allowed_x86(non_crossing),
                "expected canonical {non_crossing:?} to NOT be allowed on x86"
            );
        }
    }

    #[test]
    fn test_aarch64_crossings_exact() {
        assert_eq!(AARCH64_HOST_CROSSINGS.len(), 116);
        for nr in AARCH64_HOST_CROSSINGS {
            assert!(
                AllowedHostCrossing::is_allowed_aarch64(nr),
                "expected canonical {nr:?} to be allowed on aarch64"
            );
        }

        // Wire-in-ring calls must NOT forward on ARM
        for wire_in_ring in [
            CanonicalNr(27),  // inotify_add_watch
            CanonicalNr(28),  // inotify_rm_watch
            CanonicalNr(93),  // exit
            CanonicalNr(94),  // exit_group
            CanonicalNr(98),  // futex
            CanonicalNr(99),  // set_robust_list
            CanonicalNr(132), // sigaltstack
            CanonicalNr(135), // rt_sigprocmask
            CanonicalNr(172), // getpid
            CanonicalNr(178), // gettid
            CanonicalNr(214), // brk
            CanonicalNr(215), // munmap
            CanonicalNr(216), // mremap
            CanonicalNr(220), // clone
            CanonicalNr(222), // mmap
            CanonicalNr(226), // mprotect
            CanonicalNr(260), // wait4
        ] {
            assert!(
                !AllowedHostCrossing::is_allowed_aarch64(wire_in_ring),
                "wire-in-ring {wire_in_ring:?} must not be in aarch64 host crossing allowlist"
            );
        }

        // Counted-ENOSYS calls must NOT forward on ARM
        for counted_enosys in [
            CanonicalNr(0),   // io_setup
            CanonicalNr(90),  // capget
            CanonicalNr(91),  // capset
            CanonicalNr(117), // ptrace
            CanonicalNr(129), // kill
            CanonicalNr(134), // rt_sigaction
            CanonicalNr(144), // setgid
            CanonicalNr(146), // setuid
            CanonicalNr(148), // getresuid
            CanonicalNr(174), // getuid
            CanonicalNr(175), // geteuid
            CanonicalNr(176), // getgid
            CanonicalNr(177), // getegid
            CanonicalNr(277), // seccomp
            CanonicalNr(999), // out-of-range
        ] {
            assert!(
                !AllowedHostCrossing::is_allowed_aarch64(counted_enosys),
                "counted-enosys {counted_enosys:?} must not be in aarch64 host crossing allowlist"
            );
        }
    }

    #[test]
    fn test_unknown_calls_refused_and_counted() {
        let refused = [const { core::sync::atomic::AtomicU64::new(0) }; 513];
        let mut installed_result: Option<i64> = None;

        // Unknown / non-allowlisted call under strict mode (getuid = 174)
        let decision = evaluate_host_crossing(
            HostCrossingSet::Aarch64,
            true,
            Some(CanonicalNr(174)),
            Some(174),
            Some(&refused),
            |ret| installed_result = Some(ret),
        );
        assert_eq!(decision, HostCrossingDecision::Refused);
        assert_eq!(refused[174].load(core::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(installed_result, Some(LINUX_ENOSYS.guest_retval()));

        // Allowlisted call under strict mode (write = 64)
        let decision = evaluate_host_crossing(
            HostCrossingSet::Aarch64,
            true,
            Some(nr::WRITE),
            Some(nr::WRITE.raw()),
            Some(&refused),
            |_| panic!("should not install on forward"),
        );
        assert_eq!(decision, HostCrossingDecision::Forward);
        assert_eq!(refused[64].load(core::sync::atomic::Ordering::Relaxed), 0);

        // Unknown call with hatch off (strict = false) -> forwards
        let decision = evaluate_host_crossing(
            HostCrossingSet::Aarch64,
            false,
            Some(CanonicalNr(174)),
            Some(174),
            Some(&refused),
            |_| panic!("should not install on forward"),
        );
        assert_eq!(decision, HostCrossingDecision::Forward);
        assert_eq!(refused[174].load(core::sync::atomic::Ordering::Relaxed), 1); // unchanged
    }

    #[test]
    fn test_x86_refusal_routing() {
        let refused = [const { core::sync::atomic::AtomicU64::new(0) }; 513];
        let mut installed_result: Option<i64> = None;

        // Non-crossing call on x86: getuid (canonical 174, x86 native 102)
        let decision = evaluate_host_crossing(
            HostCrossingSet::X86,
            true,
            Some(CanonicalNr(174)),
            Some(102),
            Some(&refused),
            |ret| installed_result = Some(ret),
        );
        assert_eq!(decision, HostCrossingDecision::Refused);
        assert_eq!(refused[102].load(core::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(installed_result, Some(LINUX_ENOSYS.guest_retval()));

        // Undecoded fallback (None, None)
        let decision = evaluate_host_crossing(
            HostCrossingSet::X86,
            true,
            None,
            None,
            Some(&refused),
            |ret| installed_result = Some(ret),
        );
        assert_eq!(decision, HostCrossingDecision::Refused);
        assert_eq!(refused[512].load(core::sync::atomic::Ordering::Relaxed), 1);

        // Allowed crossing on x86: write (canonical 64, x86 native 1)
        let decision = evaluate_host_crossing(
            HostCrossingSet::X86,
            true,
            Some(nr::WRITE),
            Some(1),
            Some(&refused),
            |_| panic!("should not install on forward"),
        );
        assert_eq!(decision, HostCrossingDecision::Forward);
        assert_eq!(refused[1].load(core::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn test_host_aperture_control_honours_zero_and_default() {
        let aperture = carrick_el1_abi::ApertureControl::new();
        // Default / strict:
        aperture.set_strict(true);
        assert!(aperture.is_strict());

        let refused = [const { core::sync::atomic::AtomicU64::new(0) }; 513];
        let mut installed_result = None;

        // When strict is true, getuid (174) is refused
        let decision = evaluate_host_crossing(
            HostCrossingSet::Aarch64,
            aperture.is_strict(),
            Some(CanonicalNr(174)),
            Some(174),
            Some(&refused),
            |ret| installed_result = Some(ret),
        );
        assert_eq!(decision, HostCrossingDecision::Refused);
        assert_eq!(refused[174].load(core::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(installed_result, Some(LINUX_ENOSYS.guest_retval()));

        // When hatch = 0 (strict = false), getuid (174) forwards
        aperture.set_strict(false);
        assert!(!aperture.is_strict());

        let decision = evaluate_host_crossing(
            HostCrossingSet::Aarch64,
            aperture.is_strict(),
            Some(CanonicalNr(174)),
            Some(174),
            Some(&refused),
            |_| panic!("should not install on forward"),
        );
        assert_eq!(decision, HostCrossingDecision::Forward);
        // Counter unchanged
        assert_eq!(refused[174].load(core::sync::atomic::Ordering::Relaxed), 1);
    }
}
