//! Static AArch64 syscall metadata used for dispatch grouping, coverage
//! reporting, and compatibility summaries.

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
        | 23..=29
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
        214..=216 | 222 | 223 | 226..=233 | 283 | 425 | 426 => SyscallHandler::Memory,
        90 | 91 | 140 | 141 | 143..=152 | 158 | 159 | 166 | 174..=177 => {
            SyscallHandler::Credentials
        }
        30..=31
        | 58
        | 92
        | 95
        | 117
        | 122
        | 123
        | 142
        | 154..=157
        | 160..=162
        | 167
        | 168
        | 172
        | 173
        | 277
        | 278
        | 293
        | 424
        | 434
        | 186..=197 => SyscallHandler::Process,
        93 | 94 | 220 | 221 | 260 | 435 => SyscallHandler::Lifecycle,
        74 | 129..=139 => SyscallHandler::Signal,
        96 | 98 | 99 | 124 | 178 => SyscallHandler::ThreadLocal,
        75 | 77 => SyscallHandler::BootstrapStub,
        _ => SyscallHandler::Unimplemented,
    }
}

pub const fn compat_note_for_aarch64(number: u64) -> Option<&'static str> {
    match number {
        14..=16 => Some("xattr removal is reported as unsupported for bring-up compatibility"),
        75 => Some("vmsplice is an explicit bootstrap ENOSYS stub"),
        77 => Some("tee is an explicit bootstrap ENOSYS stub"),
        281 => Some("execveat remains planned and currently routes to unimplemented ENOSYS"),
        435 => Some("clone3 is partially handled for the clone/fork modes Carrick supports"),
        _ => None,
    }
}

// The complete Linux generic (aarch64) syscall table per the kernel
// `include/uapi/asm-generic/unistd.h` (v6.12). Every assigned aarch64 number
// is listed so `lookup_aarch64` can name *any* syscall a guest issues; numbers
// Carrick does not yet emulate are `SupportLevel::Deferred` with the
// `Unimplemented` handler, so the compat reporter shows a real name (e.g.
// "io_uring_setup") instead of "unknown 425". Gaps (244..=259, 295..=402, 415)
// are unassigned on aarch64 and intentionally absent. MUST stay sorted by
// number for the binary search in `lookup_aarch64`.
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
    syscall(26, "inotify_init1", "fs", SupportLevel::BringUp),
    syscall(27, "inotify_add_watch", "fs", SupportLevel::BringUp),
    syscall(28, "inotify_rm_watch", "fs", SupportLevel::BringUp),
    syscall(29, "ioctl", "fs", SupportLevel::BringUp),
    syscall(30, "ioprio_set", "sched", SupportLevel::BringUp),
    syscall(31, "ioprio_get", "sched", SupportLevel::BringUp),
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
    syscall(54, "fchownat", "fs", SupportLevel::BringUp),
    syscall(55, "fchown", "fs", SupportLevel::BringUp),
    syscall(56, "openat", "fs", SupportLevel::BringUp),
    syscall(57, "close", "fs", SupportLevel::BringUp),
    syscall(58, "vhangup", "tty", SupportLevel::BringUp),
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
    syscall(97, "unshare", "process", SupportLevel::BringUp),
    syscall(98, "futex", "process", SupportLevel::BringUp),
    syscall(99, "set_robust_list", "process", SupportLevel::BringUp),
    syscall(100, "get_robust_list", "process", SupportLevel::Deferred),
    syscall(101, "nanosleep", "time", SupportLevel::BringUp),
    syscall(102, "getitimer", "time", SupportLevel::BringUp),
    syscall(103, "setitimer", "time", SupportLevel::BringUp),
    syscall(104, "kexec_load", "process", SupportLevel::Deferred),
    syscall(105, "init_module", "process", SupportLevel::Deferred),
    syscall(106, "delete_module", "process", SupportLevel::Deferred),
    syscall(107, "timer_create", "time", SupportLevel::Deferred),
    syscall(108, "timer_gettime", "time", SupportLevel::Deferred),
    syscall(109, "timer_getoverrun", "time", SupportLevel::Deferred),
    syscall(110, "timer_settime", "time", SupportLevel::Deferred),
    syscall(111, "timer_delete", "time", SupportLevel::Deferred),
    syscall(112, "clock_settime", "time", SupportLevel::BringUp),
    syscall(113, "clock_gettime", "time", SupportLevel::BringUp),
    syscall(114, "clock_getres", "time", SupportLevel::BringUp),
    syscall(115, "clock_nanosleep", "time", SupportLevel::BringUp),
    syscall(116, "syslog", "process", SupportLevel::Deferred),
    syscall(117, "ptrace", "process", SupportLevel::BringUp),
    syscall(118, "sched_setparam", "sched", SupportLevel::Deferred),
    syscall(119, "sched_setscheduler", "sched", SupportLevel::Deferred),
    syscall(120, "sched_getscheduler", "sched", SupportLevel::Deferred),
    syscall(121, "sched_getparam", "sched", SupportLevel::Deferred),
    syscall(122, "sched_setaffinity", "sched", SupportLevel::BringUp),
    syscall(123, "sched_getaffinity", "sched", SupportLevel::BringUp),
    syscall(124, "sched_yield", "sched", SupportLevel::BringUp),
    syscall(
        125,
        "sched_get_priority_max",
        "sched",
        SupportLevel::Deferred,
    ),
    syscall(
        126,
        "sched_get_priority_min",
        "sched",
        SupportLevel::Deferred,
    ),
    syscall(
        127,
        "sched_rr_get_interval",
        "sched",
        SupportLevel::Deferred,
    ),
    syscall(128, "restart_syscall", "signal", SupportLevel::Deferred),
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
    syscall(163, "getrlimit", "process", SupportLevel::Deferred),
    syscall(164, "setrlimit", "process", SupportLevel::Deferred),
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
    syscall(180, "mq_open", "ipc", SupportLevel::Deferred),
    syscall(181, "mq_unlink", "ipc", SupportLevel::Deferred),
    syscall(182, "mq_timedsend", "ipc", SupportLevel::Deferred),
    syscall(183, "mq_timedreceive", "ipc", SupportLevel::Deferred),
    syscall(184, "mq_notify", "ipc", SupportLevel::Deferred),
    syscall(185, "mq_getsetattr", "ipc", SupportLevel::Deferred),
    syscall(186, "msgget", "ipc", SupportLevel::BringUp),
    syscall(187, "msgctl", "ipc", SupportLevel::BringUp),
    syscall(188, "msgrcv", "ipc", SupportLevel::BringUp),
    syscall(189, "msgsnd", "ipc", SupportLevel::BringUp),
    syscall(190, "semget", "ipc", SupportLevel::BringUp),
    syscall(191, "semctl", "ipc", SupportLevel::BringUp),
    syscall(192, "semtimedop", "ipc", SupportLevel::BringUp),
    syscall(193, "semop", "ipc", SupportLevel::BringUp),
    syscall(194, "shmget", "ipc", SupportLevel::BringUp),
    syscall(195, "shmctl", "ipc", SupportLevel::BringUp),
    syscall(196, "shmat", "ipc", SupportLevel::BringUp),
    syscall(197, "shmdt", "ipc", SupportLevel::BringUp),
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
    syscall(213, "readahead", "fs", SupportLevel::Deferred),
    syscall(214, "brk", "mm", SupportLevel::BringUp),
    syscall(215, "munmap", "mm", SupportLevel::BringUp),
    syscall(216, "mremap", "mm", SupportLevel::BringUp),
    syscall(217, "add_key", "process", SupportLevel::Deferred),
    syscall(218, "request_key", "process", SupportLevel::Deferred),
    syscall(219, "keyctl", "process", SupportLevel::Deferred),
    syscall(220, "clone", "process", SupportLevel::BringUp),
    syscall(221, "execve", "process", SupportLevel::BringUp),
    syscall(222, "mmap", "mm", SupportLevel::BringUp),
    syscall(223, "fadvise64", "mm", SupportLevel::BringUp),
    syscall(224, "swapon", "mm", SupportLevel::Deferred),
    syscall(225, "swapoff", "mm", SupportLevel::Deferred),
    syscall(226, "mprotect", "mm", SupportLevel::BringUp),
    syscall(227, "msync", "mm", SupportLevel::BringUp),
    syscall(228, "mlock", "mm", SupportLevel::BringUp),
    syscall(229, "munlock", "mm", SupportLevel::BringUp),
    syscall(230, "mlockall", "mm", SupportLevel::BringUp),
    syscall(231, "munlockall", "mm", SupportLevel::BringUp),
    syscall(232, "mincore", "mm", SupportLevel::BringUp),
    syscall(233, "madvise", "mm", SupportLevel::BringUp),
    syscall(234, "remap_file_pages", "mm", SupportLevel::Deferred),
    syscall(235, "mbind", "mm", SupportLevel::Deferred),
    syscall(236, "get_mempolicy", "mm", SupportLevel::Deferred),
    syscall(237, "set_mempolicy", "mm", SupportLevel::Deferred),
    syscall(238, "migrate_pages", "mm", SupportLevel::Deferred),
    syscall(239, "move_pages", "mm", SupportLevel::Deferred),
    syscall(240, "rt_tgsigqueueinfo", "signal", SupportLevel::Deferred),
    syscall(241, "perf_event_open", "process", SupportLevel::Deferred),
    syscall(242, "accept4", "net", SupportLevel::BringUp),
    syscall(243, "recvmmsg", "net", SupportLevel::BringUp),
    syscall(260, "wait4", "process", SupportLevel::BringUp),
    syscall(261, "prlimit64", "process", SupportLevel::BringUp),
    syscall(262, "fanotify_init", "fs", SupportLevel::Deferred),
    syscall(263, "fanotify_mark", "fs", SupportLevel::Deferred),
    syscall(264, "name_to_handle_at", "fs", SupportLevel::Deferred),
    syscall(265, "open_by_handle_at", "fs", SupportLevel::Deferred),
    syscall(266, "clock_adjtime", "time", SupportLevel::BringUp),
    syscall(267, "syncfs", "fs", SupportLevel::BringUp),
    syscall(268, "setns", "process", SupportLevel::Deferred),
    syscall(269, "sendmmsg", "net", SupportLevel::BringUp),
    syscall(270, "process_vm_readv", "process", SupportLevel::Deferred),
    syscall(271, "process_vm_writev", "process", SupportLevel::Deferred),
    syscall(272, "kcmp", "process", SupportLevel::Deferred),
    syscall(273, "finit_module", "process", SupportLevel::Deferred),
    syscall(274, "sched_setattr", "sched", SupportLevel::Deferred),
    syscall(275, "sched_getattr", "sched", SupportLevel::Deferred),
    syscall(276, "renameat2", "fs", SupportLevel::BringUp),
    syscall(277, "seccomp", "process", SupportLevel::BringUp),
    syscall(278, "getrandom", "random", SupportLevel::BringUp),
    syscall(279, "memfd_create", "fs", SupportLevel::Deferred),
    syscall(280, "bpf", "process", SupportLevel::Deferred),
    syscall(281, "execveat", "process", SupportLevel::Planned),
    syscall(282, "userfaultfd", "mm", SupportLevel::Deferred),
    syscall(283, "membarrier", "process", SupportLevel::BringUp),
    syscall(284, "mlock2", "mm", SupportLevel::Deferred),
    syscall(285, "copy_file_range", "fs", SupportLevel::BringUp),
    syscall(286, "preadv2", "fs", SupportLevel::Deferred),
    syscall(287, "pwritev2", "fs", SupportLevel::Deferred),
    syscall(288, "pkey_mprotect", "mm", SupportLevel::Deferred),
    syscall(289, "pkey_alloc", "mm", SupportLevel::Deferred),
    syscall(290, "pkey_free", "mm", SupportLevel::Deferred),
    syscall(291, "statx", "fs", SupportLevel::BringUp),
    syscall(292, "io_pgetevents", "io", SupportLevel::Deferred),
    syscall(293, "rseq", "process", SupportLevel::BringUp),
    syscall(294, "kexec_file_load", "process", SupportLevel::Deferred),
    syscall(403, "clock_gettime64", "time", SupportLevel::Deferred),
    syscall(404, "clock_settime64", "time", SupportLevel::Deferred),
    syscall(405, "clock_adjtime64", "time", SupportLevel::Deferred),
    syscall(406, "clock_getres_time64", "time", SupportLevel::Deferred),
    syscall(
        407,
        "clock_nanosleep_time64",
        "time",
        SupportLevel::Deferred,
    ),
    syscall(408, "timer_gettime64", "time", SupportLevel::Deferred),
    syscall(409, "timer_settime64", "time", SupportLevel::Deferred),
    syscall(410, "timerfd_gettime64", "time", SupportLevel::Deferred),
    syscall(411, "timerfd_settime64", "time", SupportLevel::Deferred),
    syscall(412, "utimensat_time64", "fs", SupportLevel::Deferred),
    syscall(413, "pselect6_time64", "fs", SupportLevel::Deferred),
    syscall(414, "ppoll_time64", "fs", SupportLevel::Deferred),
    syscall(416, "io_pgetevents_time64", "io", SupportLevel::Deferred),
    syscall(417, "recvmmsg_time64", "net", SupportLevel::Deferred),
    syscall(418, "mq_timedsend_time64", "ipc", SupportLevel::Deferred),
    syscall(419, "mq_timedreceive_time64", "ipc", SupportLevel::Deferred),
    syscall(420, "semtimedop_time64", "ipc", SupportLevel::Deferred),
    syscall(
        421,
        "rt_sigtimedwait_time64",
        "signal",
        SupportLevel::Deferred,
    ),
    syscall(422, "futex_time64", "process", SupportLevel::Deferred),
    syscall(
        423,
        "sched_rr_get_interval_time64",
        "sched",
        SupportLevel::Deferred,
    ),
    syscall(424, "pidfd_send_signal", "process", SupportLevel::BringUp),
    syscall(425, "io_uring_setup", "io", SupportLevel::BringUp),
    syscall(426, "io_uring_enter", "io", SupportLevel::BringUp),
    syscall(427, "io_uring_register", "io", SupportLevel::Deferred),
    syscall(428, "open_tree", "fs", SupportLevel::Deferred),
    syscall(429, "move_mount", "fs", SupportLevel::Deferred),
    syscall(430, "fsopen", "fs", SupportLevel::Deferred),
    syscall(431, "fsconfig", "fs", SupportLevel::Deferred),
    syscall(432, "fsmount", "fs", SupportLevel::Deferred),
    syscall(433, "fspick", "fs", SupportLevel::Deferred),
    syscall(434, "pidfd_open", "process", SupportLevel::BringUp),
    syscall(435, "clone3", "process", SupportLevel::Planned),
    syscall(436, "close_range", "fs", SupportLevel::BringUp),
    syscall(437, "openat2", "fs", SupportLevel::BringUp),
    syscall(438, "pidfd_getfd", "process", SupportLevel::Deferred),
    syscall(439, "faccessat2", "fs", SupportLevel::BringUp),
    syscall(440, "process_madvise", "mm", SupportLevel::Deferred),
    syscall(441, "epoll_pwait2", "net", SupportLevel::Deferred),
    syscall(442, "mount_setattr", "fs", SupportLevel::Deferred),
    syscall(443, "quotactl_fd", "fs", SupportLevel::Deferred),
    syscall(
        444,
        "landlock_create_ruleset",
        "process",
        SupportLevel::Deferred,
    ),
    syscall(445, "landlock_add_rule", "process", SupportLevel::Deferred),
    syscall(
        446,
        "landlock_restrict_self",
        "process",
        SupportLevel::Deferred,
    ),
    syscall(447, "memfd_secret", "mm", SupportLevel::Deferred),
    syscall(448, "process_mrelease", "process", SupportLevel::Deferred),
    syscall(449, "futex_waitv", "process", SupportLevel::Deferred),
    syscall(450, "set_mempolicy_home_node", "mm", SupportLevel::Deferred),
    syscall(451, "cachestat", "fs", SupportLevel::Deferred),
    syscall(452, "fchmodat2", "fs", SupportLevel::BringUp),
    syscall(453, "map_shadow_stack", "mm", SupportLevel::Deferred),
    syscall(454, "futex_wake", "process", SupportLevel::Deferred),
    syscall(455, "futex_wait", "process", SupportLevel::Deferred),
    syscall(456, "futex_requeue", "process", SupportLevel::Deferred),
    syscall(457, "statmount", "fs", SupportLevel::Deferred),
    syscall(458, "listmount", "fs", SupportLevel::Deferred),
    syscall(459, "lsm_get_self_attr", "process", SupportLevel::Deferred),
    syscall(460, "lsm_set_self_attr", "process", SupportLevel::Deferred),
    syscall(461, "lsm_list_modules", "process", SupportLevel::Deferred),
    syscall(462, "mseal", "mm", SupportLevel::Deferred),
];
