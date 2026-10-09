//! Shared host crossing table for Linux personality.
//!
//! Governs which syscalls may cross the guest-to-host boundary via
//! `CompletionRoute::Forward`. Used by both ARM EL1 and x86 CPL0.
//!
//! Syscalls outside this table must not reach the host when strict ring-first
//! enforcement is active; they are answered with counted `-ENOSYS`.

use crate::abi::entry::SyscallResult;
use carrick_syscall_abi::CanonicalNr;
pub use carrick_syscall_abi::LINUX_ENOSYS;
pub use carrick_syscall_abi::NativeNr;

/// Canonical syscall identities permitted to cross to host.
pub mod nr {
    use carrick_syscall_abi::CanonicalNr;

    // Canonical file/fd/memory identities. Authority is classified in the table:
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

    // Network and guest socketpair identities:
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

    // Compat-zone fd identities:
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

    pub const READAHEAD: CanonicalNr = CanonicalNr(213);
    pub const FADVISE64: CanonicalNr = CanonicalNr(223);
    pub const EXECVEAT: CanonicalNr = CanonicalNr(281);
    pub const MLOCKALL: CanonicalNr = CanonicalNr(230);
    pub const MUNLOCKALL: CanonicalNr = CanonicalNr(231);
    pub const RT_SIGRETURN: CanonicalNr = CanonicalNr(139);

    // Terminal carrier notifications when the native process owner declines:
    pub const EXIT: CanonicalNr = CanonicalNr(93);
    pub use carrick_syscall_abi::nr::EXIT_GROUP;
}

/// Census authority of an admitted ARM crossing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCrossingKind {
    Permanent,
    Temporary,
    Terminal,
}

// One declaration generates the identity enum and constant-time dense lookup.
// No separately maintained match or ordinal array can drift from this table.
macro_rules! host_crossings {
    ($( $variant:ident = $canonical:path, $x86:literal, $kind:ident; )+) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u64)]
        pub enum AllowedHostCrossing { $( $variant = $canonical.raw(), )+ }
        const HOST_CROSSINGS: [Option<(AllowedHostCrossing, bool, HostCrossingKind)>; 513] = {
            let mut table = [None; 513];
            $( table[$canonical.raw() as usize] = Some((AllowedHostCrossing::$variant, $x86, HostCrossingKind::$kind)); )+
            table
        };
    };
}

host_crossings! {
    Setxattr = nr::SETXATTR, false, Permanent;
    Lsetxattr = nr::LSETXATTR, false, Permanent;
    Fsetxattr = nr::FSETXATTR, false, Permanent;
    Getxattr = nr::GETXATTR, false, Permanent;
    Lgetxattr = nr::LGETXATTR, false, Permanent;
    Fgetxattr = nr::FGETXATTR, false, Permanent;
    Listxattr = nr::LISTXATTR, false, Permanent;
    Llistxattr = nr::LLISTXATTR, false, Permanent;
    Flistxattr = nr::FLISTXATTR, false, Permanent;
    Removexattr = nr::REMOVEXATTR, false, Permanent;
    Lremovexattr = nr::LREMOVEXATTR, false, Permanent;
    Fremovexattr = nr::FREMOVEXATTR, false, Permanent;
    Getcwd = nr::GETCWD, false, Permanent;
    Ioctl = nr::IOCTL, false, Permanent;
    Flock = nr::FLOCK, false, Permanent;
    Mknodat = nr::MKNODAT, false, Permanent;
    Mkdirat = nr::MKDIRAT, false, Permanent;
    Unlinkat = nr::UNLINKAT, false, Permanent;
    Symlinkat = nr::SYMLINKAT, false, Permanent;
    Linkat = nr::LINKAT, false, Permanent;
    Renameat = nr::RENAMEAT, false, Permanent;
    Statfs = nr::STATFS, false, Permanent;
    Fstatfs = nr::FSTATFS, false, Permanent;
    Truncate = nr::TRUNCATE, false, Permanent;
    Ftruncate = nr::FTRUNCATE, false, Permanent;
    Fallocate = nr::FALLOCATE, false, Permanent;
    Faccessat = nr::FACCESSAT, false, Permanent;
    Chdir = nr::CHDIR, false, Permanent;
    Fchdir = nr::FCHDIR, false, Permanent;
    Chroot = nr::CHROOT, false, Permanent;
    Fchmod = nr::FCHMOD, false, Permanent;
    Fchmodat = nr::FCHMODAT, false, Permanent;
    Fchownat = nr::FCHOWNAT, false, Permanent;
    Fchown = nr::FCHOWN, false, Permanent;
    Openat = nr::OPENAT, false, Permanent;
    Getdents64 = nr::GETDENTS64, false, Permanent;
    Lseek = nr::LSEEK, true, Permanent;
    Read = nr::READ, true, Permanent;
    Write = nr::WRITE, true, Permanent;
    Readv = nr::READV, false, Permanent;
    Writev = nr::WRITEV, false, Permanent;
    Pread64 = nr::PREAD64, true, Permanent;
    Pwrite64 = nr::PWRITE64, true, Permanent;
    Preadv = nr::PREADV, false, Permanent;
    Pwritev = nr::PWRITEV, false, Permanent;
    Sendfile = nr::SENDFILE, false, Permanent;
    Pselect6 = nr::PSELECT6, false, Temporary;
    Ppoll = nr::PPOLL, false, Temporary;
    Vmsplice = nr::VMSPLICE, false, Temporary;
    Splice = nr::SPLICE, false, Temporary;
    Tee = nr::TEE, false, Temporary;
    Readlinkat = nr::READLINKAT, false, Permanent;
    Newfstatat = nr::NEWFSTATAT, false, Permanent;
    Fstat = nr::FSTAT, false, Permanent;
    Sync = nr::SYNC, false, Permanent;
    Fsync = nr::FSYNC, false, Permanent;
    Fdatasync = nr::FDATASYNC, false, Permanent;
    SyncFileRange = nr::SYNC_FILE_RANGE, false, Permanent;
    Utimensat = nr::UTIMENSAT, false, Permanent;
    Execve = nr::EXECVE, false, Permanent;
    Msync = nr::MSYNC, false, Permanent;
    Mlock = nr::MLOCK, false, Temporary;
    Munlock = nr::MUNLOCK, false, Temporary;
    Mincore = nr::MINCORE, false, Temporary;
    Madvise = nr::MADVISE, false, Temporary;
    Syncfs = nr::SYNCFS, false, Permanent;
    Renameat2 = nr::RENAMEAT2, false, Permanent;
    Mlock2 = nr::MLOCK2, false, Temporary;
    CopyFileRange = nr::COPY_FILE_RANGE, false, Permanent;
    Preadv2 = nr::PREADV2, false, Permanent;
    Pwritev2 = nr::PWRITEV2, false, Permanent;
    Statx = nr::STATX, false, Permanent;
    Openat2 = nr::OPENAT2, false, Permanent;
    Faccessat2 = nr::FACCESSAT2, false, Permanent;
    Fchmodat2 = nr::FCHMODAT2, false, Permanent;
    Socket = nr::SOCKET, false, Permanent;
    Socketpair = nr::SOCKETPAIR, false, Temporary;
    Bind = nr::BIND, false, Permanent;
    Listen = nr::LISTEN, false, Permanent;
    Accept = nr::ACCEPT, false, Permanent;
    Connect = nr::CONNECT, false, Permanent;
    Getsockname = nr::GETSOCKNAME, false, Permanent;
    Getpeername = nr::GETPEERNAME, false, Permanent;
    Sendto = nr::SENDTO, false, Permanent;
    Recvfrom = nr::RECVFROM, false, Permanent;
    Setsockopt = nr::SETSOCKOPT, false, Permanent;
    Getsockopt = nr::GETSOCKOPT, false, Permanent;
    Shutdown = nr::SHUTDOWN, false, Permanent;
    Sendmsg = nr::SENDMSG, false, Permanent;
    Recvmsg = nr::RECVMSG, false, Permanent;
    Accept4 = nr::ACCEPT4, false, Permanent;
    Recvmmsg = nr::RECVMMSG, false, Permanent;
    Sendmmsg = nr::SENDMMSG, false, Permanent;
    Nanosleep = nr::NANOSLEEP, false, Permanent;
    ClockGettime = nr::CLOCK_GETTIME, false, Permanent;
    ClockGetres = nr::CLOCK_GETRES, false, Permanent;
    ClockNanosleep = nr::CLOCK_NANOSLEEP, false, Permanent;
    Times = nr::TIMES, false, Permanent;
    Gettimeofday = nr::GETTIMEOFDAY, false, Permanent;
    Getrandom = nr::GETRANDOM, false, Permanent;
    Eventfd2 = nr::EVENTFD2, false, Temporary;
    EpollCreate1 = nr::EPOLL_CREATE1, false, Temporary;
    EpollCtl = nr::EPOLL_CTL, false, Temporary;
    EpollPwait = nr::EPOLL_PWAIT, true, Temporary;
    Dup = nr::DUP, false, Temporary;
    Dup3 = nr::DUP3, false, Temporary;
    Fcntl = nr::FCNTL, false, Temporary;
    InotifyInit1 = nr::INOTIFY_INIT1, false, Temporary;
    Close = nr::CLOSE, false, Temporary;
    Pipe2 = nr::PIPE2, false, Temporary;
    Signalfd4 = nr::SIGNALFD4, false, Temporary;
    TimerfdCreate = nr::TIMERFD_CREATE, false, Temporary;
    TimerfdSettime = nr::TIMERFD_SETTIME, false, Temporary;
    TimerfdGettime = nr::TIMERFD_GETTIME, false, Temporary;
    CloseRange = nr::CLOSE_RANGE, false, Temporary;
    EpollPwait2 = nr::EPOLL_PWAIT2, false, Temporary;
    Readahead = nr::READAHEAD, false, Permanent;
    Fadvise64 = nr::FADVISE64, false, Permanent;
    Execveat = nr::EXECVEAT, false, Permanent;
    Mlockall = nr::MLOCKALL, false, Temporary;
    Munlockall = nr::MUNLOCKALL, false, Temporary;
    RtSigreturn = nr::RT_SIGRETURN, false, Temporary;
    Exit = nr::EXIT, true, Terminal;
    ExitGroup = nr::EXIT_GROUP, true, Terminal;
}

impl AllowedHostCrossing {
    pub const fn canonical(self) -> CanonicalNr {
        CanonicalNr::new(self as u64)
    }
    pub const fn kind(self) -> Option<HostCrossingKind> {
        match HOST_CROSSINGS[self as usize] {
            Some((_, _, kind)) => Some(kind),
            None => None,
        }
    }
    const fn from_canonical(canonical: CanonicalNr, x86: bool) -> Option<Self> {
        if canonical.raw() > 512 {
            return None;
        }
        match HOST_CROSSINGS[canonical.raw() as usize] {
            Some((crossing, allowed_x86, _)) if !x86 || allowed_x86 => Some(crossing),
            _ => None,
        }
    }
    pub const fn from_canonical_x86(canonical: CanonicalNr) -> Option<Self> {
        Self::from_canonical(canonical, true)
    }
    pub const fn from_canonical_aarch64(canonical: CanonicalNr) -> Option<Self> {
        Self::from_canonical(canonical, false)
    }
    pub const fn is_allowed_x86(canonical: CanonicalNr) -> bool {
        Self::from_canonical_x86(canonical).is_some()
    }
    pub const fn is_allowed_aarch64(canonical: CanonicalNr) -> bool {
        Self::from_canonical_aarch64(canonical).is_some()
    }
}

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
    pub fn refusal_bucket(self, native: Option<NativeNr>) -> usize {
        match self {
            Self::Aarch64 => match native {
                Some(nr) if nr.raw() < 512 => nr.raw() as usize,
                _ => 512,
            },
            Self::X86 => match native {
                Some(nr) if nr.raw() < 512 => {
                    match carrick_syscall_abi::syscall_x86_64::lookup_x86_64(nr.raw()) {
                        Some(entry)
                            if !matches!(
                                entry.remap,
                                carrick_syscall_abi::syscall_x86_64::SyscallRemap::Unknown
                                    | carrick_syscall_abi::syscall_x86_64::SyscallRemap::Private(_)
                            ) =>
                        {
                            nr.raw() as usize
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
    native: Option<NativeNr>,
    counters: Option<&[core::sync::atomic::AtomicU64]>,
    install_result: F,
) -> HostCrossingDecision
where
    F: FnOnce(SyscallResult),
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
    install_result(SyscallResult::from_errno(LINUX_ENOSYS));
    HostCrossingDecision::Refused
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn ring_first_census_host_files_and_signal_return_are_admitted() {
        for ordinal in [213, 223, 281, 139, 230, 231] {
            assert!(
                HostCrossingSet::Aarch64.is_allowed(CanonicalNr::new(ordinal)),
                "ARM fallback ordinal={ordinal}"
            );
            assert!(!HostCrossingSet::X86.is_allowed(CanonicalNr::new(ordinal)));
        }
    }

    #[test]
    fn ring_first_census_guest_fd_and_memory_rows_are_temporary() {
        for ordinal in [72, 73, 75, 76, 77, 199, 228, 229, 232, 233, 284] {
            assert_eq!(
                AllowedHostCrossing::from_canonical_aarch64(CanonicalNr::new(ordinal))
                    .and_then(AllowedHostCrossing::kind),
                Some(HostCrossingKind::Temporary),
                "ordinal={ordinal}"
            );
        }
    }

    #[test]
    fn both_sets_match_the_exhaustive_census_through_512() {
        let mut arm = [None; 513];
        for row in include_str!("../../../docs/design/arm-ring-first-flip.tsv")
            .lines()
            .skip(1)
        {
            let columns: std::vec::Vec<_> = row.split('\t').collect();
            let ordinal: usize = columns[0].parse().unwrap();
            arm[ordinal] = match columns[9] {
                "Forward-Allowlist" => Some(HostCrossingKind::Permanent),
                "Temporary-forward" => Some(HostCrossingKind::Temporary),
                _ => None,
            };
        }
        arm[93] = Some(HostCrossingKind::Terminal);
        arm[94] = Some(HostCrossingKind::Terminal);
        for (ordinal, expected) in arm.into_iter().enumerate() {
            let canonical = CanonicalNr::new(ordinal as u64);
            let crossing = AllowedHostCrossing::from_canonical_aarch64(canonical);
            assert_eq!(
                crossing.and_then(AllowedHostCrossing::kind),
                expected,
                "ARM ordinal={ordinal}"
            );
            assert_eq!(
                HostCrossingSet::Aarch64.is_allowed(canonical),
                expected.is_some()
            );
            assert_eq!(
                HostCrossingSet::X86.is_allowed(canonical),
                matches!(ordinal, 22 | 62 | 63 | 64 | 67 | 68 | 93 | 94),
                "x86 canonical={ordinal}"
            );
        }
    }

    #[test]
    fn test_x86_crossings_exact() {
        assert_eq!(
            HOST_CROSSINGS
                .iter()
                .flatten()
                .filter(|(_, x86, _)| *x86)
                .count(),
            8
        );
        for (crossing, _, _) in HOST_CROSSINGS.iter().flatten().filter(|(_, x86, _)| *x86) {
            let nr = crossing.canonical();
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
        assert_eq!(HOST_CROSSINGS.iter().flatten().count(), 124);
        for (crossing, _, _) in HOST_CROSSINGS.iter().flatten() {
            let nr = crossing.canonical();
            assert!(
                AllowedHostCrossing::is_allowed_aarch64(nr),
                "expected canonical {nr:?} to be allowed on aarch64"
            );
        }

        // Implemented families are not unported crossings. Their explicit declines
        // use typed family fallback and bypass this unported-call table.
        for wire_in_ring in [
            CanonicalNr(27),  // inotify_add_watch
            CanonicalNr(28),  // inotify_rm_watch
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
            Some(NativeNr(174)),
            Some(&refused),
            |ret| installed_result = Some(ret.raw()),
        );
        assert_eq!(decision, HostCrossingDecision::Refused);
        assert_eq!(refused[174].load(core::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(installed_result, Some(LINUX_ENOSYS.guest_retval()));

        // Allowlisted call under strict mode (write = 64)
        let decision = evaluate_host_crossing(
            HostCrossingSet::Aarch64,
            true,
            Some(nr::WRITE),
            Some(NativeNr(nr::WRITE.raw())),
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
            Some(NativeNr(174)),
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
            Some(NativeNr(102)),
            Some(&refused),
            |ret| installed_result = Some(ret.raw()),
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
            |ret| installed_result = Some(ret.raw()),
        );
        assert_eq!(decision, HostCrossingDecision::Refused);
        assert_eq!(refused[512].load(core::sync::atomic::Ordering::Relaxed), 1);

        // Allowed crossing on x86: write (canonical 64, x86 native 1)
        let decision = evaluate_host_crossing(
            HostCrossingSet::X86,
            true,
            Some(nr::WRITE),
            Some(NativeNr(1)),
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
            Some(NativeNr(174)),
            Some(&refused),
            |ret| installed_result = Some(ret.raw()),
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
            Some(NativeNr(174)),
            Some(&refused),
            |_| panic!("should not install on forward"),
        );
        assert_eq!(decision, HostCrossingDecision::Forward);
        // Counter unchanged
        assert_eq!(refused[174].load(core::sync::atomic::Ordering::Relaxed), 1);
    }
}
