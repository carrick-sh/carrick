//! Shared host crossing table for Linux personality.
//!
//! Governs which syscalls may cross the guest-to-host boundary via
//! `CompletionRoute::Forward`. Used by both ARM EL1 and x86 CPL0.
//!
//! Syscalls outside this table must not reach the host when strict ring-first
//! enforcement is active; they are answered with counted `-ENOSYS` (-38).

use carrick_syscall_abi::CanonicalNr;

/// Identifies syscalls permitted to cross to the host carrier.
///
/// Keyed on canonical syscall identities ([`CanonicalNr`]), which map to
/// Linux asm-generic / AArch64 numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u64)]
pub enum AllowedHostCrossing {
    // Host file contents & filesystem metadata (73 syscalls):
    Setxattr = 5,
    Lsetxattr = 6,
    Fsetxattr = 7,
    Getxattr = 8,
    Lgetxattr = 9,
    Fgetxattr = 10,
    Listxattr = 11,
    Llistxattr = 12,
    Flistxattr = 13,
    Removexattr = 14,
    Lremovexattr = 15,
    Fremovexattr = 16,
    Getcwd = 17,
    Ioctl = 29,
    Flock = 32,
    Mknodat = 33,
    Mkdirat = 34,
    Unlinkat = 35,
    Symlinkat = 36,
    Linkat = 37,
    Renameat = 38,
    Statfs = 43,
    Fstatfs = 44,
    Truncate = 45,
    Ftruncate = 46,
    Fallocate = 47,
    Faccessat = 48,
    Chdir = 49,
    Fchdir = 50,
    Chroot = 51,
    Fchmod = 52,
    Fchmodat = 53,
    Fchownat = 54,
    Fchown = 55,
    Openat = 56,
    Getdents64 = 61,
    Lseek = 62,
    Read = 63,
    Write = 64,
    Readv = 65,
    Writev = 66,
    Pread64 = 67,
    Pwrite64 = 68,
    Preadv = 69,
    Pwritev = 70,
    Sendfile = 71,
    Pselect6 = 72,
    Ppoll = 73,
    Vmsplice = 75,
    Splice = 76,
    Tee = 77,
    Readlinkat = 78,
    Newfstatat = 79,
    Fstat = 80,
    Sync = 81,
    Fsync = 82,
    Fdatasync = 83,
    SyncFileRange = 84,
    Utimensat = 88,
    Execve = 221,
    Msync = 227,
    Mlock = 228,
    Munlock = 229,
    Mincore = 232,
    Madvise = 233,
    Syncfs = 267,
    Renameat2 = 276,
    Mlock2 = 284,
    CopyFileRange = 285,
    Preadv2 = 286,
    Pwritev2 = 287,
    Statx = 291,
    Openat2 = 437,
    Faccessat2 = 439,
    Fchmodat2 = 452,

    // Host network & BSD sockets (18 syscalls):
    Socket = 198,
    Socketpair = 199,
    Bind = 200,
    Listen = 201,
    Accept = 202,
    Connect = 203,
    Getsockname = 204,
    Getpeername = 205,
    Sendto = 206,
    Recvfrom = 207,
    Setsockopt = 208,
    Getsockopt = 209,
    Shutdown = 210,
    Sendmsg = 211,
    Recvmsg = 212,
    Accept4 = 242,
    Recvmmsg = 243,
    Sendmmsg = 269,

    // Host clock & hardware time (6 syscalls):
    Nanosleep = 101,
    ClockGettime = 113,
    ClockGetres = 114,
    ClockNanosleep = 115,
    Times = 153,
    Gettimeofday = 169,

    // Host hardware entropy (1 syscall):
    Getrandom = 278,

    // Temporary-forward compat-zone fd rows (16 syscalls):
    Eventfd2 = 19,
    EpollCreate1 = 20,
    EpollCtl = 21,
    EpollPwait = 22,
    Dup = 23,
    Dup3 = 24,
    Fcntl = 25,
    InotifyInit1 = 26,
    Close = 57,
    Pipe2 = 59,
    Signalfd4 = 74,
    TimerfdCreate = 85,
    TimerfdSettime = 86,
    TimerfdGettime = 87,
    CloseRange = 436,
    EpollPwait2 = 441,

    // x86-only host exit crossings (Wire-in-ring on ARM):
    Exit = 93,
    ExitGroup = 94,
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
    /// read (63), write (64), lseek (62), pread64 (67), pwrite64 (68),
    /// exit (93), exit_group (94), epoll_pwait (22).
    pub const fn from_canonical_x86(canonical: CanonicalNr) -> Option<Self> {
        match canonical.raw() {
            63 => Some(Self::Read),
            64 => Some(Self::Write),
            62 => Some(Self::Lseek),
            67 => Some(Self::Pread64),
            68 => Some(Self::Pwrite64),
            93 => Some(Self::Exit),
            94 => Some(Self::ExitGroup),
            22 => Some(Self::EpollPwait),
            _ => None,
        }
    }

    /// Match an allowed host crossing for AArch64 ARM EL1.
    ///
    /// Covers the 100 Forward-Allowlist rows (host files, network, clock,
    /// entropy) and the 16 Temporary-forward fd rows. Excludes in-ring
    /// handlers (such as exit=93, exit_group=94).
    pub const fn from_canonical_aarch64(canonical: CanonicalNr) -> Option<Self> {
        match canonical.raw() {
            5 => Some(Self::Setxattr),
            6 => Some(Self::Lsetxattr),
            7 => Some(Self::Fsetxattr),
            8 => Some(Self::Getxattr),
            9 => Some(Self::Lgetxattr),
            10 => Some(Self::Fgetxattr),
            11 => Some(Self::Listxattr),
            12 => Some(Self::Llistxattr),
            13 => Some(Self::Flistxattr),
            14 => Some(Self::Removexattr),
            15 => Some(Self::Lremovexattr),
            16 => Some(Self::Fremovexattr),
            17 => Some(Self::Getcwd),
            19 => Some(Self::Eventfd2),
            20 => Some(Self::EpollCreate1),
            21 => Some(Self::EpollCtl),
            22 => Some(Self::EpollPwait),
            23 => Some(Self::Dup),
            24 => Some(Self::Dup3),
            25 => Some(Self::Fcntl),
            26 => Some(Self::InotifyInit1),
            29 => Some(Self::Ioctl),
            32 => Some(Self::Flock),
            33 => Some(Self::Mknodat),
            34 => Some(Self::Mkdirat),
            35 => Some(Self::Unlinkat),
            36 => Some(Self::Symlinkat),
            37 => Some(Self::Linkat),
            38 => Some(Self::Renameat),
            43 => Some(Self::Statfs),
            44 => Some(Self::Fstatfs),
            45 => Some(Self::Truncate),
            46 => Some(Self::Ftruncate),
            47 => Some(Self::Fallocate),
            48 => Some(Self::Faccessat),
            49 => Some(Self::Chdir),
            50 => Some(Self::Fchdir),
            51 => Some(Self::Chroot),
            52 => Some(Self::Fchmod),
            53 => Some(Self::Fchmodat),
            54 => Some(Self::Fchownat),
            55 => Some(Self::Fchown),
            56 => Some(Self::Openat),
            57 => Some(Self::Close),
            59 => Some(Self::Pipe2),
            61 => Some(Self::Getdents64),
            62 => Some(Self::Lseek),
            63 => Some(Self::Read),
            64 => Some(Self::Write),
            65 => Some(Self::Readv),
            66 => Some(Self::Writev),
            67 => Some(Self::Pread64),
            68 => Some(Self::Pwrite64),
            69 => Some(Self::Preadv),
            70 => Some(Self::Pwritev),
            71 => Some(Self::Sendfile),
            72 => Some(Self::Pselect6),
            73 => Some(Self::Ppoll),
            74 => Some(Self::Signalfd4),
            75 => Some(Self::Vmsplice),
            76 => Some(Self::Splice),
            77 => Some(Self::Tee),
            78 => Some(Self::Readlinkat),
            79 => Some(Self::Newfstatat),
            80 => Some(Self::Fstat),
            81 => Some(Self::Sync),
            82 => Some(Self::Fsync),
            83 => Some(Self::Fdatasync),
            84 => Some(Self::SyncFileRange),
            85 => Some(Self::TimerfdCreate),
            86 => Some(Self::TimerfdSettime),
            87 => Some(Self::TimerfdGettime),
            88 => Some(Self::Utimensat),
            101 => Some(Self::Nanosleep),
            113 => Some(Self::ClockGettime),
            114 => Some(Self::ClockGetres),
            115 => Some(Self::ClockNanosleep),
            153 => Some(Self::Times),
            169 => Some(Self::Gettimeofday),
            198 => Some(Self::Socket),
            199 => Some(Self::Socketpair),
            200 => Some(Self::Bind),
            201 => Some(Self::Listen),
            202 => Some(Self::Accept),
            203 => Some(Self::Connect),
            204 => Some(Self::Getsockname),
            205 => Some(Self::Getpeername),
            206 => Some(Self::Sendto),
            207 => Some(Self::Recvfrom),
            208 => Some(Self::Setsockopt),
            209 => Some(Self::Getsockopt),
            210 => Some(Self::Shutdown),
            211 => Some(Self::Sendmsg),
            212 => Some(Self::Recvmsg),
            221 => Some(Self::Execve),
            227 => Some(Self::Msync),
            228 => Some(Self::Mlock),
            229 => Some(Self::Munlock),
            232 => Some(Self::Mincore),
            233 => Some(Self::Madvise),
            242 => Some(Self::Accept4),
            243 => Some(Self::Recvmmsg),
            267 => Some(Self::Syncfs),
            269 => Some(Self::Sendmmsg),
            276 => Some(Self::Renameat2),
            278 => Some(Self::Getrandom),
            284 => Some(Self::Mlock2),
            285 => Some(Self::CopyFileRange),
            286 => Some(Self::Preadv2),
            287 => Some(Self::Pwritev2),
            291 => Some(Self::Statx),
            436 => Some(Self::CloseRange),
            437 => Some(Self::Openat2),
            439 => Some(Self::Faccessat2),
            441 => Some(Self::EpollPwait2),
            452 => Some(Self::Fchmodat2),
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
    CanonicalNr(22), // epoll_pwait
    CanonicalNr(62), // lseek
    CanonicalNr(63), // read
    CanonicalNr(64), // write
    CanonicalNr(67), // pread64
    CanonicalNr(68), // pwrite64
    CanonicalNr(93), // exit
    CanonicalNr(94), // exit_group
];

/// The exact 116 canonical syscalls permitted to cross to host on AArch64 ARM EL1.
pub const AARCH64_HOST_CROSSINGS: [CanonicalNr; 116] = [
    CanonicalNr(5),   // setxattr
    CanonicalNr(6),   // lsetxattr
    CanonicalNr(7),   // fsetxattr
    CanonicalNr(8),   // getxattr
    CanonicalNr(9),   // lgetxattr
    CanonicalNr(10),  // fgetxattr
    CanonicalNr(11),  // listxattr
    CanonicalNr(12),  // llistxattr
    CanonicalNr(13),  // flistxattr
    CanonicalNr(14),  // removexattr
    CanonicalNr(15),  // lremovexattr
    CanonicalNr(16),  // fremovexattr
    CanonicalNr(17),  // getcwd
    CanonicalNr(19),  // eventfd2
    CanonicalNr(20),  // epoll_create1
    CanonicalNr(21),  // epoll_ctl
    CanonicalNr(22),  // epoll_pwait
    CanonicalNr(23),  // dup
    CanonicalNr(24),  // dup3
    CanonicalNr(25),  // fcntl
    CanonicalNr(26),  // inotify_init1
    CanonicalNr(29),  // ioctl
    CanonicalNr(32),  // flock
    CanonicalNr(33),  // mknodat
    CanonicalNr(34),  // mkdirat
    CanonicalNr(35),  // unlinkat
    CanonicalNr(36),  // symlinkat
    CanonicalNr(37),  // linkat
    CanonicalNr(38),  // renameat
    CanonicalNr(43),  // statfs
    CanonicalNr(44),  // fstatfs
    CanonicalNr(45),  // truncate
    CanonicalNr(46),  // ftruncate
    CanonicalNr(47),  // fallocate
    CanonicalNr(48),  // faccessat
    CanonicalNr(49),  // chdir
    CanonicalNr(50),  // fchdir
    CanonicalNr(51),  // chroot
    CanonicalNr(52),  // fchmod
    CanonicalNr(53),  // fchmodat
    CanonicalNr(54),  // fchownat
    CanonicalNr(55),  // fchown
    CanonicalNr(56),  // openat
    CanonicalNr(57),  // close
    CanonicalNr(59),  // pipe2
    CanonicalNr(61),  // getdents64
    CanonicalNr(62),  // lseek
    CanonicalNr(63),  // read
    CanonicalNr(64),  // write
    CanonicalNr(65),  // readv
    CanonicalNr(66),  // writev
    CanonicalNr(67),  // pread64
    CanonicalNr(68),  // pwrite64
    CanonicalNr(69),  // preadv
    CanonicalNr(70),  // pwritev
    CanonicalNr(71),  // sendfile
    CanonicalNr(72),  // pselect6
    CanonicalNr(73),  // ppoll
    CanonicalNr(74),  // signalfd4
    CanonicalNr(75),  // vmsplice
    CanonicalNr(76),  // splice
    CanonicalNr(77),  // tee
    CanonicalNr(78),  // readlinkat
    CanonicalNr(79),  // newfstatat
    CanonicalNr(80),  // fstat
    CanonicalNr(81),  // sync
    CanonicalNr(82),  // fsync
    CanonicalNr(83),  // fdatasync
    CanonicalNr(84),  // sync_file_range
    CanonicalNr(85),  // timerfd_create
    CanonicalNr(86),  // timerfd_settime
    CanonicalNr(87),  // timerfd_gettime
    CanonicalNr(88),  // utimensat
    CanonicalNr(101), // nanosleep
    CanonicalNr(113), // clock_gettime
    CanonicalNr(114), // clock_getres
    CanonicalNr(115), // clock_nanosleep
    CanonicalNr(153), // times
    CanonicalNr(169), // gettimeofday
    CanonicalNr(198), // socket
    CanonicalNr(199), // socketpair
    CanonicalNr(200), // bind
    CanonicalNr(201), // listen
    CanonicalNr(202), // accept
    CanonicalNr(203), // connect
    CanonicalNr(204), // getsockname
    CanonicalNr(205), // getpeername
    CanonicalNr(206), // sendto
    CanonicalNr(207), // recvfrom
    CanonicalNr(208), // setsockopt
    CanonicalNr(209), // getsockopt
    CanonicalNr(210), // shutdown
    CanonicalNr(211), // sendmsg
    CanonicalNr(212), // recvmsg
    CanonicalNr(221), // execve
    CanonicalNr(227), // msync
    CanonicalNr(228), // mlock
    CanonicalNr(229), // munlock
    CanonicalNr(232), // mincore
    CanonicalNr(233), // madvise
    CanonicalNr(242), // accept4
    CanonicalNr(243), // recvmmsg
    CanonicalNr(267), // syncfs
    CanonicalNr(269), // sendmmsg
    CanonicalNr(276), // renameat2
    CanonicalNr(278), // getrandom
    CanonicalNr(284), // mlock2
    CanonicalNr(285), // copy_file_range
    CanonicalNr(286), // preadv2
    CanonicalNr(287), // pwritev2
    CanonicalNr(291), // statx
    CanonicalNr(436), // close_range
    CanonicalNr(437), // openat2
    CanonicalNr(439), // faccessat2
    CanonicalNr(441), // epoll_pwait2
    CanonicalNr(452), // fchmodat2
];

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
        fn record_routing(
            ordinal: u64,
            strict: bool,
            refused: &mut [u64; 513],
            forwarded: &mut [u64; 513],
            installed_result: &mut Option<i64>,
        ) -> bool {
            let canonical = CanonicalNr::new(ordinal);
            let bucket = if ordinal < 512 { ordinal as usize } else { 512 };
            if strict && !AllowedHostCrossing::is_allowed_aarch64(canonical) {
                refused[bucket] += 1;
                *installed_result = Some(-38);
                true // served directly with -ENOSYS
            } else {
                forwarded[bucket] += 1;
                false // forwarded to host
            }
        }

        let mut refused = [0u64; 513];
        let mut forwarded = [0u64; 513];
        let mut installed_result: Option<i64> = None;

        // Unknown / non-allowlisted call under strict mode
        assert!(record_routing(
            174,
            true,
            &mut refused,
            &mut forwarded,
            &mut installed_result
        )); // getuid
        assert_eq!(refused[174], 1);
        assert_eq!(forwarded[174], 0);
        assert_eq!(installed_result, Some(-38));

        // Allowlisted call under strict mode
        assert!(!record_routing(
            64,
            true,
            &mut refused,
            &mut forwarded,
            &mut installed_result
        )); // write
        assert_eq!(refused[64], 0);
        assert_eq!(forwarded[64], 1);

        // Unknown call with hatch off (strict = false) -> forwards
        assert!(!record_routing(
            174,
            false,
            &mut refused,
            &mut forwarded,
            &mut installed_result
        ));
        assert_eq!(refused[174], 1); // unchanged
        assert_eq!(forwarded[174], 1); // now forwarded
    }
}
