use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    BringUp,
    Planned,
    Deferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallHandler {
    BootstrapStub,
    Credentials,
    Filesystem,
    Lifecycle,
    Memory,
    Network,
    Process,
    Signal,
    ThreadLocal,
    Time,
    Unimplemented,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Syscall {
    pub number: u64,
    pub name: &'static str,
    pub group: &'static str,
    #[serde(skip_serializing)]
    pub subsystem: &'static str,
    pub support: SupportLevel,
    pub handler: SyscallHandler,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compat_note: Option<&'static str>,
}

pub fn lookup_aarch64(number: u64) -> Option<&'static Syscall> {
    AARCH64_SYSCALLS
        .binary_search_by_key(&number, |syscall| syscall.number)
        .ok()
        .map(|index| &AARCH64_SYSCALLS[index])
}

pub fn aarch64_table() -> &'static [Syscall] {
    AARCH64_SYSCALLS
}

const fn syscall(
    number: u64,
    name: &'static str,
    group: &'static str,
    support: SupportLevel,
) -> Syscall {
    Syscall {
        number,
        name,
        group,
        subsystem: group,
        support,
        handler: handler_for_aarch64(number),
        compat_note: compat_note_for_aarch64(number),
    }
}

pub const fn handler_for_aarch64(number: u64) -> SyscallHandler {
    match number {
        5..=17
        | 23..=25
        | 29
        | 32..=38
        | 43..=50
        | 52..=57
        | 59
        | 61..=71
        | 76
        | 78..=83
        | 88
        | 267
        | 276
        | 285
        | 291
        | 436
        | 437
        | 439
        | 452 => SyscallHandler::Filesystem,
        19..=22 | 72 | 73 | 198..=212 | 242 | 243 | 269 => SyscallHandler::Network,
        85..=87 | 101..=103 | 112..=115 | 153 | 165 | 169..=171 | 179 | 261 | 266 => {
            SyscallHandler::Time
        }
        214..=216 | 222 | 223 | 226..=233 | 283 => SyscallHandler::Memory,
        90 | 91 | 140 | 141 | 143..=152 | 158 | 159 | 166 | 174..=177 => {
            SyscallHandler::Credentials
        }
        92 | 95 | 117 | 123 | 142 | 154..=157 | 160..=162 | 167 | 168 | 172 | 173 | 278 | 293 => {
            SyscallHandler::Process
        }
        93 | 94 | 220 | 221 | 260 | 435 => SyscallHandler::Lifecycle,
        129..=139 => SyscallHandler::Signal,
        96 | 98 | 99 | 124 | 178 => SyscallHandler::ThreadLocal,
        74 | 75 | 77 => SyscallHandler::BootstrapStub,
        _ => SyscallHandler::Unimplemented,
    }
}

pub const fn compat_note_for_aarch64(number: u64) -> Option<&'static str> {
    match number {
        14..=16 => Some("xattr removal is reported as unsupported for bring-up compatibility"),
        74 => Some("signalfd4 is an explicit bootstrap ENOSYS stub"),
        75 => Some("vmsplice is an explicit bootstrap ENOSYS stub"),
        77 => Some("tee is an explicit bootstrap ENOSYS stub"),
        281 => Some("execveat remains planned and currently routes to unimplemented ENOSYS"),
        435 => Some("clone3 is partially handled for the clone/fork modes Carrick supports"),
        _ => None,
    }
}

const AARCH64_SYSCALLS: &[Syscall] = &[
    syscall(0, "io_setup", "io", SupportLevel::Deferred),
    syscall(1, "io_destroy", "io", SupportLevel::Deferred),
    syscall(2, "io_submit", "io", SupportLevel::Deferred),
    syscall(3, "io_cancel", "io", SupportLevel::Deferred),
    syscall(4, "io_getevents", "io", SupportLevel::Deferred),
    syscall(5, "setxattr", "fs", SupportLevel::BringUp),
    syscall(6, "lsetxattr", "fs", SupportLevel::BringUp),
    syscall(7, "fsetxattr", "fs", SupportLevel::BringUp),
    syscall(8, "getxattr", "fs", SupportLevel::BringUp),
    syscall(9, "lgetxattr", "fs", SupportLevel::BringUp),
    syscall(10, "fgetxattr", "fs", SupportLevel::BringUp),
    syscall(11, "listxattr", "fs", SupportLevel::BringUp),
    syscall(12, "llistxattr", "fs", SupportLevel::BringUp),
    syscall(13, "flistxattr", "fs", SupportLevel::BringUp),
    syscall(14, "removexattr", "fs", SupportLevel::BringUp),
    syscall(15, "lremovexattr", "fs", SupportLevel::BringUp),
    syscall(16, "fremovexattr", "fs", SupportLevel::BringUp),
    syscall(17, "getcwd", "fs", SupportLevel::BringUp),
    syscall(18, "lookup_dcookie", "fs", SupportLevel::Deferred),
    syscall(19, "eventfd2", "ipc", SupportLevel::BringUp),
    syscall(20, "epoll_create1", "net", SupportLevel::BringUp),
    syscall(21, "epoll_ctl", "net", SupportLevel::BringUp),
    syscall(22, "epoll_pwait", "net", SupportLevel::BringUp),
    syscall(23, "dup", "fs", SupportLevel::BringUp),
    syscall(24, "dup3", "fs", SupportLevel::BringUp),
    syscall(25, "fcntl", "fs", SupportLevel::BringUp),
    syscall(26, "inotify_init1", "fs", SupportLevel::Deferred),
    syscall(27, "inotify_add_watch", "fs", SupportLevel::Deferred),
    syscall(28, "inotify_rm_watch", "fs", SupportLevel::Deferred),
    syscall(29, "ioctl", "fs", SupportLevel::BringUp),
    syscall(30, "ioprio_set", "sched", SupportLevel::Deferred),
    syscall(31, "ioprio_get", "sched", SupportLevel::Deferred),
    syscall(32, "flock", "fs", SupportLevel::BringUp),
    syscall(33, "mknodat", "fs", SupportLevel::BringUp),
    syscall(34, "mkdirat", "fs", SupportLevel::BringUp),
    syscall(35, "unlinkat", "fs", SupportLevel::BringUp),
    syscall(36, "symlinkat", "fs", SupportLevel::BringUp),
    syscall(37, "linkat", "fs", SupportLevel::BringUp),
    syscall(38, "renameat", "fs", SupportLevel::BringUp),
    syscall(39, "umount2", "fs", SupportLevel::Deferred),
    syscall(40, "mount", "fs", SupportLevel::Deferred),
    syscall(41, "pivot_root", "fs", SupportLevel::Deferred),
    syscall(42, "nfsservctl", "fs", SupportLevel::Deferred),
    syscall(43, "statfs", "fs", SupportLevel::BringUp),
    syscall(44, "fstatfs", "fs", SupportLevel::BringUp),
    syscall(45, "truncate", "fs", SupportLevel::BringUp),
    syscall(46, "ftruncate", "fs", SupportLevel::BringUp),
    syscall(47, "fallocate", "fs", SupportLevel::BringUp),
    syscall(48, "faccessat", "fs", SupportLevel::BringUp),
    syscall(49, "chdir", "fs", SupportLevel::BringUp),
    syscall(50, "fchdir", "fs", SupportLevel::BringUp),
    syscall(51, "chroot", "fs", SupportLevel::Deferred),
    syscall(52, "fchmod", "fs", SupportLevel::BringUp),
    syscall(53, "fchmodat", "fs", SupportLevel::BringUp),
    syscall(452, "fchmodat2", "fs", SupportLevel::BringUp),
    syscall(54, "fchownat", "fs", SupportLevel::BringUp),
    syscall(55, "fchown", "fs", SupportLevel::BringUp),
    syscall(56, "openat", "fs", SupportLevel::BringUp),
    syscall(57, "close", "fs", SupportLevel::BringUp),
    syscall(58, "vhangup", "tty", SupportLevel::Deferred),
    syscall(59, "pipe2", "fs", SupportLevel::BringUp),
    syscall(60, "quotactl", "fs", SupportLevel::Deferred),
    syscall(61, "getdents64", "fs", SupportLevel::BringUp),
    syscall(62, "lseek", "fs", SupportLevel::BringUp),
    syscall(63, "read", "fs", SupportLevel::BringUp),
    syscall(64, "write", "fs", SupportLevel::BringUp),
    syscall(65, "readv", "fs", SupportLevel::BringUp),
    syscall(66, "writev", "fs", SupportLevel::BringUp),
    syscall(67, "pread64", "fs", SupportLevel::BringUp),
    syscall(68, "pwrite64", "fs", SupportLevel::BringUp),
    syscall(69, "preadv", "fs", SupportLevel::BringUp),
    syscall(70, "pwritev", "fs", SupportLevel::BringUp),
    syscall(71, "sendfile", "fs", SupportLevel::BringUp),
    syscall(72, "pselect6", "fs", SupportLevel::BringUp),
    syscall(73, "ppoll", "fs", SupportLevel::BringUp),
    syscall(74, "signalfd4", "signal", SupportLevel::BringUp),
    syscall(75, "vmsplice", "fs", SupportLevel::BringUp),
    syscall(76, "splice", "fs", SupportLevel::BringUp),
    syscall(77, "tee", "fs", SupportLevel::BringUp),
    syscall(78, "readlinkat", "fs", SupportLevel::BringUp),
    syscall(79, "newfstatat", "fs", SupportLevel::BringUp),
    syscall(80, "fstat", "fs", SupportLevel::BringUp),
    syscall(81, "sync", "fs", SupportLevel::BringUp),
    syscall(82, "fsync", "fs", SupportLevel::BringUp),
    syscall(83, "fdatasync", "fs", SupportLevel::BringUp),
    syscall(84, "sync_file_range", "fs", SupportLevel::Deferred),
    syscall(85, "timerfd_create", "time", SupportLevel::BringUp),
    syscall(86, "timerfd_settime", "time", SupportLevel::BringUp),
    syscall(87, "timerfd_gettime", "time", SupportLevel::BringUp),
    syscall(88, "utimensat", "fs", SupportLevel::BringUp),
    syscall(89, "acct", "process", SupportLevel::Deferred),
    syscall(90, "capget", "process", SupportLevel::BringUp),
    syscall(91, "capset", "process", SupportLevel::BringUp),
    syscall(92, "personality", "process", SupportLevel::BringUp),
    syscall(93, "exit", "process", SupportLevel::BringUp),
    syscall(94, "exit_group", "process", SupportLevel::BringUp),
    syscall(95, "waitid", "process", SupportLevel::BringUp),
    syscall(96, "set_tid_address", "process", SupportLevel::BringUp),
    syscall(98, "futex", "process", SupportLevel::BringUp),
    syscall(99, "set_robust_list", "process", SupportLevel::BringUp),
    syscall(101, "nanosleep", "time", SupportLevel::BringUp),
    syscall(102, "getitimer", "time", SupportLevel::BringUp),
    syscall(103, "setitimer", "time", SupportLevel::BringUp),
    syscall(112, "clock_settime", "time", SupportLevel::BringUp),
    syscall(113, "clock_gettime", "time", SupportLevel::BringUp),
    syscall(114, "clock_getres", "time", SupportLevel::BringUp),
    syscall(115, "clock_nanosleep", "time", SupportLevel::BringUp),
    syscall(117, "ptrace", "process", SupportLevel::BringUp),
    syscall(123, "sched_getaffinity", "sched", SupportLevel::BringUp),
    syscall(124, "sched_yield", "sched", SupportLevel::BringUp),
    syscall(129, "kill", "signal", SupportLevel::BringUp),
    syscall(130, "tkill", "signal", SupportLevel::BringUp),
    syscall(131, "tgkill", "signal", SupportLevel::BringUp),
    syscall(132, "sigaltstack", "signal", SupportLevel::BringUp),
    syscall(133, "rt_sigsuspend", "signal", SupportLevel::BringUp),
    syscall(134, "rt_sigaction", "signal", SupportLevel::BringUp),
    syscall(135, "rt_sigprocmask", "signal", SupportLevel::BringUp),
    syscall(136, "rt_sigpending", "signal", SupportLevel::BringUp),
    syscall(137, "rt_sigtimedwait", "signal", SupportLevel::BringUp),
    syscall(138, "rt_sigqueueinfo", "signal", SupportLevel::BringUp),
    syscall(139, "rt_sigreturn", "signal", SupportLevel::BringUp),
    syscall(140, "setpriority", "sched", SupportLevel::BringUp),
    syscall(141, "getpriority", "sched", SupportLevel::BringUp),
    syscall(142, "reboot", "process", SupportLevel::BringUp),
    syscall(143, "setregid", "process", SupportLevel::BringUp),
    syscall(144, "setgid", "process", SupportLevel::BringUp),
    syscall(145, "setreuid", "process", SupportLevel::BringUp),
    syscall(146, "setuid", "process", SupportLevel::BringUp),
    syscall(147, "setresuid", "process", SupportLevel::BringUp),
    syscall(148, "getresuid", "process", SupportLevel::BringUp),
    syscall(149, "setresgid", "process", SupportLevel::BringUp),
    syscall(150, "getresgid", "process", SupportLevel::BringUp),
    syscall(151, "setfsuid", "process", SupportLevel::BringUp),
    syscall(152, "setfsgid", "process", SupportLevel::BringUp),
    syscall(153, "times", "time", SupportLevel::BringUp),
    syscall(154, "setpgid", "process", SupportLevel::BringUp),
    syscall(155, "getpgid", "process", SupportLevel::BringUp),
    syscall(156, "getsid", "process", SupportLevel::BringUp),
    syscall(157, "setsid", "process", SupportLevel::BringUp),
    syscall(158, "getgroups", "process", SupportLevel::BringUp),
    syscall(159, "setgroups", "process", SupportLevel::BringUp),
    syscall(160, "uname", "process", SupportLevel::BringUp),
    syscall(161, "sethostname", "process", SupportLevel::BringUp),
    syscall(162, "setdomainname", "process", SupportLevel::BringUp),
    syscall(165, "getrusage", "process", SupportLevel::BringUp),
    syscall(166, "umask", "process", SupportLevel::BringUp),
    syscall(167, "prctl", "process", SupportLevel::BringUp),
    syscall(168, "getcpu", "sched", SupportLevel::BringUp),
    syscall(169, "gettimeofday", "time", SupportLevel::BringUp),
    syscall(170, "settimeofday", "time", SupportLevel::BringUp),
    syscall(171, "adjtimex", "time", SupportLevel::BringUp),
    syscall(172, "getpid", "process", SupportLevel::BringUp),
    syscall(173, "getppid", "process", SupportLevel::BringUp),
    syscall(174, "getuid", "process", SupportLevel::BringUp),
    syscall(175, "geteuid", "process", SupportLevel::BringUp),
    syscall(176, "getgid", "process", SupportLevel::BringUp),
    syscall(177, "getegid", "process", SupportLevel::BringUp),
    syscall(178, "gettid", "process", SupportLevel::BringUp),
    syscall(179, "sysinfo", "process", SupportLevel::BringUp),
    syscall(198, "socket", "net", SupportLevel::BringUp),
    syscall(199, "socketpair", "net", SupportLevel::BringUp),
    syscall(200, "bind", "net", SupportLevel::BringUp),
    syscall(201, "listen", "net", SupportLevel::BringUp),
    syscall(202, "accept", "net", SupportLevel::BringUp),
    syscall(203, "connect", "net", SupportLevel::BringUp),
    syscall(204, "getsockname", "net", SupportLevel::BringUp),
    syscall(205, "getpeername", "net", SupportLevel::BringUp),
    syscall(206, "sendto", "net", SupportLevel::BringUp),
    syscall(207, "recvfrom", "net", SupportLevel::BringUp),
    syscall(208, "setsockopt", "net", SupportLevel::BringUp),
    syscall(209, "getsockopt", "net", SupportLevel::BringUp),
    syscall(210, "shutdown", "net", SupportLevel::BringUp),
    syscall(211, "sendmsg", "net", SupportLevel::BringUp),
    syscall(212, "recvmsg", "net", SupportLevel::BringUp),
    syscall(214, "brk", "mm", SupportLevel::BringUp),
    syscall(215, "munmap", "mm", SupportLevel::BringUp),
    syscall(216, "mremap", "mm", SupportLevel::BringUp),
    syscall(220, "clone", "process", SupportLevel::BringUp),
    syscall(221, "execve", "process", SupportLevel::BringUp),
    syscall(222, "mmap", "mm", SupportLevel::BringUp),
    syscall(223, "fadvise64", "mm", SupportLevel::BringUp),
    syscall(226, "mprotect", "mm", SupportLevel::BringUp),
    syscall(227, "msync", "mm", SupportLevel::BringUp),
    syscall(228, "mlock", "mm", SupportLevel::BringUp),
    syscall(229, "munlock", "mm", SupportLevel::BringUp),
    syscall(230, "mlockall", "mm", SupportLevel::BringUp),
    syscall(231, "munlockall", "mm", SupportLevel::BringUp),
    syscall(232, "mincore", "mm", SupportLevel::BringUp),
    syscall(233, "madvise", "mm", SupportLevel::BringUp),
    syscall(242, "accept4", "net", SupportLevel::BringUp),
    syscall(243, "recvmmsg", "net", SupportLevel::BringUp),
    syscall(260, "wait4", "process", SupportLevel::BringUp),
    syscall(261, "prlimit64", "process", SupportLevel::BringUp),
    syscall(266, "clock_adjtime", "time", SupportLevel::BringUp),
    syscall(267, "syncfs", "fs", SupportLevel::BringUp),
    syscall(269, "sendmmsg", "net", SupportLevel::BringUp),
    syscall(276, "renameat2", "fs", SupportLevel::BringUp),
    syscall(278, "getrandom", "random", SupportLevel::BringUp),
    syscall(281, "execveat", "process", SupportLevel::Planned),
    syscall(283, "membarrier", "process", SupportLevel::BringUp),
    syscall(285, "copy_file_range", "fs", SupportLevel::BringUp),
    syscall(291, "statx", "fs", SupportLevel::BringUp),
    syscall(293, "rseq", "process", SupportLevel::BringUp),
    syscall(435, "clone3", "process", SupportLevel::Planned),
    syscall(436, "close_range", "fs", SupportLevel::BringUp),
    syscall(437, "openat2", "fs", SupportLevel::BringUp),
    syscall(439, "faccessat2", "fs", SupportLevel::BringUp),
];
