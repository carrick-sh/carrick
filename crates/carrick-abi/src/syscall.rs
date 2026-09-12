//! Static AArch64 syscall metadata used for dispatch grouping, coverage
//! reporting, and compatibility summaries.
//!
//! THEORY OF OPERATION
//!
//! This is a compile-time table — `AARCH64_SYSCALLS`, kept sorted by number so
//! [`crate::syscall::lookup_aarch64`] can binary-search it — that maps each Linux/aarch64 syscall
//! number to its name, the [`crate::syscall::SyscallHandler`] subsystem that owns it, a
//! [`crate::syscall::SupportLevel`] (`BringUp`/`Planned`/`Deferred`), and an optional compat
//! note. It is pure metadata: it does NOT dispatch anything itself. Two
//! consumers read it. The compat reporter cross-references it to turn
//! raw event counters into a coverage report ("of the N syscalls a real kernel
//! exposes, which has carrick actually serviced, and at what support level").
//! And the handler grouping ([`crate::syscall::handler_for_aarch64`]) is the canonical
//! number→subsystem partition that keeps the report's buckets aligned with how
//! the dispatcher is actually carved up.
//!
//! `handler_for_aarch64` is written as `const` range matches rather than a
//! per-syscall annotation precisely because the aarch64 numbering is dense and
//! contiguous within a subsystem; the ranges are the compact expression of that
//! structure. Keep this table in sync with the dispatcher: a syscall that gains
//! a handler but stays `Deferred`/`Unimplemented` here will under-report
//! coverage, and the reverse over-reports it.

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
#[serde(rename_all = "snake_case")]
pub enum Authority {
    /// 100% guest kernel state: MUST NEVER make host process/identity/signal calls.
    Guest,
    /// Real hardware/host I/O (file byte I/O, INET wire sockets, physical pages, CPU time).
    Host,
    /// Hybrid: metadata & synchronization in guest, physical storage/pages on host.
    Hybrid,
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
    pub authority: Authority,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compat_note: Option<&'static str>,
}

pub fn lookup_aarch64(number: u64) -> Option<&'static Syscall> {
    AARCH64_SYSCALLS
        .binary_search_by_key(&number, |syscall| syscall.number)
        .ok()
        .map(|index| &AARCH64_SYSCALLS[index])
}

pub fn lookup_aarch64_by_name(name: &str) -> Option<&'static Syscall> {
    AARCH64_SYSCALLS.iter().find(|syscall| syscall.name == name)
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
        authority: authority_for_aarch64(number),
        compat_note: compat_note_for_aarch64(number),
    }
}

pub const fn authority_for_aarch64(number: u64) -> Authority {
    match number {
        // sched_yield: yields hardware vCPU / CPU cycle
        124 => Authority::Host,

        // SysV msg queues and shared memory:
        186..=189 | 194..=197 => Authority::Hybrid,

        // Clocks & time sources:
        // Monotonic hardware clocks / gettime:
        113 | 114 | 169 | 171 | 266 | 403 | 405 | 406 => Authority::Hybrid,
        // Sleep operations:
        101 | 115 | 407 => Authority::Host,

        // Memory mappings (Stage-1 guest metadata + Stage-2 host pages):
        214..=216
        | 222..=239
        | 282
        | 284
        | 288..=290
        | 425
        | 426
        | 427
        | 440
        | 447
        | 450
        | 453
        | 462 => Authority::Hybrid,

        // Real Network Sockets & Wire Traffic:
        198..=212 | 242 | 243 | 269 | 417 | 441 => Authority::Host,

        // Real File I/O & Host FS:
        0..=18
        | 23..=29
        | 32..=57
        | 59..=73
        | 75..=84
        | 88
        | 213
        | 262..=265
        | 267
        | 276
        | 279
        | 285..=287
        | 291
        | 292
        | 412..=414
        | 416
        | 428..=433
        | 436
        | 437
        | 439
        | 442
        | 443
        | 451
        | 452
        | 457
        | 458 => Authority::Host,

        // Random entropy source:
        278 => Authority::Host,

        // All process, credentials, lifecycle, signals, futex, timers, synthetic IPC, POSIX mqueues, semaphores, keyrings, ptrace, namespaces:
        _ => Authority::Guest,
    }
}

pub const fn handler_for_aarch64(number: u64) -> SyscallHandler {
    match number {
        0..=17
        | 23..=29
        | 32..=38
        | 43..=50
        | 52..=57
        | 59
        | 61..=71
        | 75..=77
        | 78..=83
        | 88
        // 262/263 fanotify_init/fanotify_mark: fs handlers in
        // `dispatch/fs.rs`, backed by `crate::fanotify`.
        | 262
        | 263
        | 267
        | 276
        | 285
        | 291
        | 279
        | 428..=433
        | 436
        | 437
        | 439
        | 442
        | 447
        | 452 => SyscallHandler::Filesystem,
        19..=22 | 72 | 73 | 198..=212 | 242 | 243 | 269 => SyscallHandler::Network,
        85..=87 | 101..=103 | 112..=115 | 153 | 165 | 169..=171 | 179 | 261 | 266 => {
            SyscallHandler::Time
        }
        213..=216 | 222 | 223 | 226..=233 | 282..=284 | 425 | 426 => SyscallHandler::Memory,
        90 | 91 | 140 | 141 | 143..=152 | 158 | 159 | 166 | 174..=177 => {
            SyscallHandler::Credentials
        }
        30..=31
        | 58
        | 92
        | 95
        | 97
        | 116
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
        | 217..=219
        | 270
        | 271
        | 277
        | 278
        | 280
        // perf_event_open: the counters live in `dispatch::perf`, which the
        // Process handler owns. Flipping 241 to BringUp without listing it
        // here left it Unimplemented in the manifest — the same gap bpf(280)
        // had, caught by `bringup_manifest_entries_have_a_handler_owner`.
        | 241
        | 293
        | 424
        | 434
        | 180..=197 => SyscallHandler::Process,
        93 | 94 | 220 | 221 | 260 | 435 => SyscallHandler::Lifecycle,
        74 | 129..=139 => SyscallHandler::Signal,
        96 | 98 | 99 | 124 | 178 => SyscallHandler::ThreadLocal,
        _ => SyscallHandler::Unimplemented,
    }
}

pub const fn compat_note_for_aarch64(number: u64) -> Option<&'static str> {
    match number {
        14..=16 => Some("xattr removal is reported as unsupported for bring-up compatibility"),
        281 => Some("execveat remains planned and currently routes to unimplemented ENOSYS"),
        282 => Some(
            "container policy only: EPERM without CAP_SYS_PTRACE (Docker-default caps), ENOSYS with it — no userfaultfd emulation",
        ),
        447 => Some(
            "guest-visible ABI (fd, MAP_SHARED-only mmap, EINVAL file I/O, /proc mem hiding); host direct-map removal and mlock accounting are not modeled",
        ),
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
macro_rules! define_aarch64_syscall_table {
    ($(
        ($const_name:ident, $nr:literal, $name:literal, $subsys:literal, $level:expr);
    )*) => {
        pub mod nr {
            use $crate::CanonicalNr;

            $(
                #[doc = concat!("Canonical AArch64 syscall number for `", $name, "` (`", stringify!($nr), "`).")]
                pub const $const_name: CanonicalNr = CanonicalNr($nr);
            )*

            // Internal x86 normalized syscall numbers wrapped as CanonicalNr for routing:
            pub const CARRICK_PRIVATE_X86_DUP2: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_DUP2);
            pub const CARRICK_PRIVATE_X86_STAT: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_STAT);
            pub const CARRICK_PRIVATE_X86_FSTAT: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_FSTAT);
            pub const CARRICK_PRIVATE_X86_LSTAT: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_LSTAT);
            pub const CARRICK_PRIVATE_X86_NEWFSTATAT: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_NEWFSTATAT);
            pub const CARRICK_PRIVATE_X86_UNSUPPORTED: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_UNSUPPORTED);
            pub const CARRICK_PRIVATE_X86_UTIME: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_UTIME);
            pub const CARRICK_PRIVATE_X86_UTIMES: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_UTIMES);
            pub const CARRICK_PRIVATE_X86_POLL: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_POLL);
            pub const CARRICK_PRIVATE_X86_SELECT: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_SELECT);
            pub const CARRICK_PRIVATE_X86_EPOLL_CREATE: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_EPOLL_CREATE);
            pub const CARRICK_PRIVATE_X86_ALARM: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_ALARM);
            pub const CARRICK_PRIVATE_X86_TIME: CanonicalNr =
                CanonicalNr($crate::CARRICK_PRIVATE_X86_TIME);
        }

        const AARCH64_SYSCALLS: &[Syscall] = &[
            $(
                syscall(nr::$const_name.raw(), $name, $subsys, $level),
            )*
        ];

        #[cfg(test)]
        const GENERATED_CONSTANTS: &[(&'static str, $crate::CanonicalNr)] = &[
            $(
                ($name, nr::$const_name),
            )*
        ];
    };
}

define_aarch64_syscall_table! {
    (IO_SETUP, 0, "io_setup", "io", SupportLevel::BringUp);
    (IO_DESTROY, 1, "io_destroy", "io", SupportLevel::BringUp);
    (IO_SUBMIT, 2, "io_submit", "io", SupportLevel::BringUp);
    (IO_CANCEL, 3, "io_cancel", "io", SupportLevel::BringUp);
    (IO_GETEVENTS, 4, "io_getevents", "io", SupportLevel::BringUp);
    (SETXATTR, 5, "setxattr", "fs", SupportLevel::BringUp);
    (LSETXATTR, 6, "lsetxattr", "fs", SupportLevel::BringUp);
    (FSETXATTR, 7, "fsetxattr", "fs", SupportLevel::BringUp);
    (GETXATTR, 8, "getxattr", "fs", SupportLevel::BringUp);
    (LGETXATTR, 9, "lgetxattr", "fs", SupportLevel::BringUp);
    (FGETXATTR, 10, "fgetxattr", "fs", SupportLevel::BringUp);
    (LISTXATTR, 11, "listxattr", "fs", SupportLevel::BringUp);
    (LLISTXATTR, 12, "llistxattr", "fs", SupportLevel::BringUp);
    (FLISTXATTR, 13, "flistxattr", "fs", SupportLevel::BringUp);
    (REMOVEXATTR, 14, "removexattr", "fs", SupportLevel::BringUp);
    (LREMOVEXATTR, 15, "lremovexattr", "fs", SupportLevel::BringUp);
    (FREMOVEXATTR, 16, "fremovexattr", "fs", SupportLevel::BringUp);
    (GETCWD, 17, "getcwd", "fs", SupportLevel::BringUp);
    (LOOKUP_DCOOKIE, 18, "lookup_dcookie", "fs", SupportLevel::Deferred);
    (EVENTFD2, 19, "eventfd2", "ipc", SupportLevel::BringUp);
    (EPOLL_CREATE1, 20, "epoll_create1", "net", SupportLevel::BringUp);
    (EPOLL_CTL, 21, "epoll_ctl", "net", SupportLevel::BringUp);
    (EPOLL_PWAIT, 22, "epoll_pwait", "net", SupportLevel::BringUp);
    (DUP, 23, "dup", "fs", SupportLevel::BringUp);
    (DUP3, 24, "dup3", "fs", SupportLevel::BringUp);
    (FCNTL, 25, "fcntl", "fs", SupportLevel::BringUp);
    (INOTIFY_INIT1, 26, "inotify_init1", "fs", SupportLevel::BringUp);
    (INOTIFY_ADD_WATCH, 27, "inotify_add_watch", "fs", SupportLevel::BringUp);
    (INOTIFY_RM_WATCH, 28, "inotify_rm_watch", "fs", SupportLevel::BringUp);
    (IOCTL, 29, "ioctl", "fs", SupportLevel::BringUp);
    (IOPRIO_SET, 30, "ioprio_set", "sched", SupportLevel::BringUp);
    (IOPRIO_GET, 31, "ioprio_get", "sched", SupportLevel::BringUp);
    (FLOCK, 32, "flock", "fs", SupportLevel::BringUp);
    (MKNODAT, 33, "mknodat", "fs", SupportLevel::BringUp);
    (MKDIRAT, 34, "mkdirat", "fs", SupportLevel::BringUp);
    (UNLINKAT, 35, "unlinkat", "fs", SupportLevel::BringUp);
    (SYMLINKAT, 36, "symlinkat", "fs", SupportLevel::BringUp);
    (LINKAT, 37, "linkat", "fs", SupportLevel::BringUp);
    (RENAMEAT, 38, "renameat", "fs", SupportLevel::BringUp);
    (UMOUNT2, 39, "umount2", "fs", SupportLevel::Deferred);
    (MOUNT, 40, "mount", "fs", SupportLevel::Deferred);
    (PIVOT_ROOT, 41, "pivot_root", "fs", SupportLevel::Deferred);
    (NFSSERVCTL, 42, "nfsservctl", "fs", SupportLevel::Deferred);
    (STATFS, 43, "statfs", "fs", SupportLevel::BringUp);
    (FSTATFS, 44, "fstatfs", "fs", SupportLevel::BringUp);
    (TRUNCATE, 45, "truncate", "fs", SupportLevel::BringUp);
    (FTRUNCATE, 46, "ftruncate", "fs", SupportLevel::BringUp);
    (FALLOCATE, 47, "fallocate", "fs", SupportLevel::BringUp);
    (FACCESSAT, 48, "faccessat", "fs", SupportLevel::BringUp);
    (CHDIR, 49, "chdir", "fs", SupportLevel::BringUp);
    (FCHDIR, 50, "fchdir", "fs", SupportLevel::BringUp);
    (CHROOT, 51, "chroot", "fs", SupportLevel::Deferred);
    (FCHMOD, 52, "fchmod", "fs", SupportLevel::BringUp);
    (FCHMODAT, 53, "fchmodat", "fs", SupportLevel::BringUp);
    (FCHOWNAT, 54, "fchownat", "fs", SupportLevel::BringUp);
    (FCHOWN, 55, "fchown", "fs", SupportLevel::BringUp);
    (OPENAT, 56, "openat", "fs", SupportLevel::BringUp);
    (CLOSE, 57, "close", "fs", SupportLevel::BringUp);
    (VHANGUP, 58, "vhangup", "tty", SupportLevel::BringUp);
    (PIPE2, 59, "pipe2", "fs", SupportLevel::BringUp);
    (QUOTACTL, 60, "quotactl", "fs", SupportLevel::Deferred);
    (GETDENTS64, 61, "getdents64", "fs", SupportLevel::BringUp);
    (LSEEK, 62, "lseek", "fs", SupportLevel::BringUp);
    (READ, 63, "read", "fs", SupportLevel::BringUp);
    (WRITE, 64, "write", "fs", SupportLevel::BringUp);
    (READV, 65, "readv", "fs", SupportLevel::BringUp);
    (WRITEV, 66, "writev", "fs", SupportLevel::BringUp);
    (PREAD64, 67, "pread64", "fs", SupportLevel::BringUp);
    (PWRITE64, 68, "pwrite64", "fs", SupportLevel::BringUp);
    (PREADV, 69, "preadv", "fs", SupportLevel::BringUp);
    (PWRITEV, 70, "pwritev", "fs", SupportLevel::BringUp);
    (SENDFILE, 71, "sendfile", "fs", SupportLevel::BringUp);
    (PSELECT6, 72, "pselect6", "fs", SupportLevel::BringUp);
    (PPOLL, 73, "ppoll", "fs", SupportLevel::BringUp);
    (SIGNALFD4, 74, "signalfd4", "signal", SupportLevel::BringUp);
    (VMSPLICE, 75, "vmsplice", "fs", SupportLevel::BringUp);
    (SPLICE, 76, "splice", "fs", SupportLevel::BringUp);
    (TEE, 77, "tee", "fs", SupportLevel::BringUp);
    (READLINKAT, 78, "readlinkat", "fs", SupportLevel::BringUp);
    (NEWFSTATAT, 79, "newfstatat", "fs", SupportLevel::BringUp);
    (FSTAT, 80, "fstat", "fs", SupportLevel::BringUp);
    (SYNC, 81, "sync", "fs", SupportLevel::BringUp);
    (FSYNC, 82, "fsync", "fs", SupportLevel::BringUp);
    (FDATASYNC, 83, "fdatasync", "fs", SupportLevel::BringUp);
    (SYNC_FILE_RANGE, 84, "sync_file_range", "fs", SupportLevel::Deferred);
    (TIMERFD_CREATE, 85, "timerfd_create", "time", SupportLevel::BringUp);
    (TIMERFD_SETTIME, 86, "timerfd_settime", "time", SupportLevel::BringUp);
    (TIMERFD_GETTIME, 87, "timerfd_gettime", "time", SupportLevel::BringUp);
    (UTIMENSAT, 88, "utimensat", "fs", SupportLevel::BringUp);
    (ACCT, 89, "acct", "process", SupportLevel::Deferred);
    (CAPGET, 90, "capget", "process", SupportLevel::BringUp);
    (CAPSET, 91, "capset", "process", SupportLevel::BringUp);
    (PERSONALITY, 92, "personality", "process", SupportLevel::BringUp);
    (EXIT, 93, "exit", "process", SupportLevel::BringUp);
    (EXIT_GROUP, 94, "exit_group", "process", SupportLevel::BringUp);
    (WAITID, 95, "waitid", "process", SupportLevel::BringUp);
    (SET_TID_ADDRESS, 96, "set_tid_address", "process", SupportLevel::BringUp);
    (UNSHARE, 97, "unshare", "process", SupportLevel::BringUp);
    (FUTEX, 98, "futex", "process", SupportLevel::BringUp);
    (SET_ROBUST_LIST, 99, "set_robust_list", "process", SupportLevel::BringUp);
    (GET_ROBUST_LIST, 100, "get_robust_list", "process", SupportLevel::Deferred);
    (NANOSLEEP, 101, "nanosleep", "time", SupportLevel::BringUp);
    (GETITIMER, 102, "getitimer", "time", SupportLevel::BringUp);
    (SETITIMER, 103, "setitimer", "time", SupportLevel::BringUp);
    (KEXEC_LOAD, 104, "kexec_load", "process", SupportLevel::Deferred);
    (INIT_MODULE, 105, "init_module", "process", SupportLevel::Deferred);
    (DELETE_MODULE, 106, "delete_module", "process", SupportLevel::Deferred);
    (TIMER_CREATE, 107, "timer_create", "time", SupportLevel::Deferred);
    (TIMER_GETTIME, 108, "timer_gettime", "time", SupportLevel::Deferred);
    (TIMER_GETOVERRUN, 109, "timer_getoverrun", "time", SupportLevel::Deferred);
    (TIMER_SETTIME, 110, "timer_settime", "time", SupportLevel::Deferred);
    (TIMER_DELETE, 111, "timer_delete", "time", SupportLevel::Deferred);
    (CLOCK_SETTIME, 112, "clock_settime", "time", SupportLevel::BringUp);
    (CLOCK_GETTIME, 113, "clock_gettime", "time", SupportLevel::BringUp);
    (CLOCK_GETRES, 114, "clock_getres", "time", SupportLevel::BringUp);
    (CLOCK_NANOSLEEP, 115, "clock_nanosleep", "time", SupportLevel::BringUp);
    (SYSLOG, 116, "syslog", "process", SupportLevel::BringUp);
    (PTRACE, 117, "ptrace", "process", SupportLevel::BringUp);
    (SCHED_SETPARAM, 118, "sched_setparam", "sched", SupportLevel::Deferred);
    (SCHED_SETSCHEDULER, 119, "sched_setscheduler", "sched", SupportLevel::Deferred);
    (SCHED_GETSCHEDULER, 120, "sched_getscheduler", "sched", SupportLevel::Deferred);
    (SCHED_GETPARAM, 121, "sched_getparam", "sched", SupportLevel::Deferred);
    (SCHED_SETAFFINITY, 122, "sched_setaffinity", "sched", SupportLevel::BringUp);
    (SCHED_GETAFFINITY, 123, "sched_getaffinity", "sched", SupportLevel::BringUp);
    (SCHED_YIELD, 124, "sched_yield", "sched", SupportLevel::BringUp);
    (SCHED_GET_PRIORITY_MAX, 125, "sched_get_priority_max", "sched", SupportLevel::Deferred);
    (SCHED_GET_PRIORITY_MIN, 126, "sched_get_priority_min", "sched", SupportLevel::Deferred);
    (SCHED_RR_GET_INTERVAL, 127, "sched_rr_get_interval", "sched", SupportLevel::Deferred);
    (RESTART_SYSCALL, 128, "restart_syscall", "signal", SupportLevel::Deferred);
    (KILL, 129, "kill", "signal", SupportLevel::BringUp);
    (TKILL, 130, "tkill", "signal", SupportLevel::BringUp);
    (TGKILL, 131, "tgkill", "signal", SupportLevel::BringUp);
    (SIGALTSTACK, 132, "sigaltstack", "signal", SupportLevel::BringUp);
    (RT_SIGSUSPEND, 133, "rt_sigsuspend", "signal", SupportLevel::BringUp);
    (RT_SIGACTION, 134, "rt_sigaction", "signal", SupportLevel::BringUp);
    (RT_SIGPROCMASK, 135, "rt_sigprocmask", "signal", SupportLevel::BringUp);
    (RT_SIGPENDING, 136, "rt_sigpending", "signal", SupportLevel::BringUp);
    (RT_SIGTIMEDWAIT, 137, "rt_sigtimedwait", "signal", SupportLevel::BringUp);
    (RT_SIGQUEUEINFO, 138, "rt_sigqueueinfo", "signal", SupportLevel::BringUp);
    (RT_SIGRETURN, 139, "rt_sigreturn", "signal", SupportLevel::BringUp);
    (SETPRIORITY, 140, "setpriority", "sched", SupportLevel::BringUp);
    (GETPRIORITY, 141, "getpriority", "sched", SupportLevel::BringUp);
    (REBOOT, 142, "reboot", "process", SupportLevel::BringUp);
    (SETREGID, 143, "setregid", "process", SupportLevel::BringUp);
    (SETGID, 144, "setgid", "process", SupportLevel::BringUp);
    (SETREUID, 145, "setreuid", "process", SupportLevel::BringUp);
    (SETUID, 146, "setuid", "process", SupportLevel::BringUp);
    (SETRESUID, 147, "setresuid", "process", SupportLevel::BringUp);
    (GETRESUID, 148, "getresuid", "process", SupportLevel::BringUp);
    (SETRESGID, 149, "setresgid", "process", SupportLevel::BringUp);
    (GETRESGID, 150, "getresgid", "process", SupportLevel::BringUp);
    (SETFSUID, 151, "setfsuid", "process", SupportLevel::BringUp);
    (SETFSGID, 152, "setfsgid", "process", SupportLevel::BringUp);
    (TIMES, 153, "times", "time", SupportLevel::BringUp);
    (SETPGID, 154, "setpgid", "process", SupportLevel::BringUp);
    (GETPGID, 155, "getpgid", "process", SupportLevel::BringUp);
    (GETSID, 156, "getsid", "process", SupportLevel::BringUp);
    (SETSID, 157, "setsid", "process", SupportLevel::BringUp);
    (GETGROUPS, 158, "getgroups", "process", SupportLevel::BringUp);
    (SETGROUPS, 159, "setgroups", "process", SupportLevel::BringUp);
    (UNAME, 160, "uname", "process", SupportLevel::BringUp);
    (SETHOSTNAME, 161, "sethostname", "process", SupportLevel::BringUp);
    (SETDOMAINNAME, 162, "setdomainname", "process", SupportLevel::BringUp);
    (GETRLIMIT, 163, "getrlimit", "process", SupportLevel::Deferred);
    (SETRLIMIT, 164, "setrlimit", "process", SupportLevel::Deferred);
    (GETRUSAGE, 165, "getrusage", "process", SupportLevel::BringUp);
    (UMASK, 166, "umask", "process", SupportLevel::BringUp);
    (PRCTL, 167, "prctl", "process", SupportLevel::BringUp);
    (GETCPU, 168, "getcpu", "sched", SupportLevel::BringUp);
    (GETTIMEOFDAY, 169, "gettimeofday", "time", SupportLevel::BringUp);
    (SETTIMEOFDAY, 170, "settimeofday", "time", SupportLevel::BringUp);
    (ADJTIMEX, 171, "adjtimex", "time", SupportLevel::BringUp);
    (GETPID, 172, "getpid", "process", SupportLevel::BringUp);
    (GETPPID, 173, "getppid", "process", SupportLevel::BringUp);
    (GETUID, 174, "getuid", "process", SupportLevel::BringUp);
    (GETEUID, 175, "geteuid", "process", SupportLevel::BringUp);
    (GETGID, 176, "getgid", "process", SupportLevel::BringUp);
    (GETEGID, 177, "getegid", "process", SupportLevel::BringUp);
    (GETTID, 178, "gettid", "process", SupportLevel::BringUp);
    (SYSINFO, 179, "sysinfo", "process", SupportLevel::BringUp);
    (MQ_OPEN, 180, "mq_open", "ipc", SupportLevel::BringUp);
    (MQ_UNLINK, 181, "mq_unlink", "ipc", SupportLevel::BringUp);
    (MQ_TIMEDSEND, 182, "mq_timedsend", "ipc", SupportLevel::BringUp);
    (MQ_TIMEDRECEIVE, 183, "mq_timedreceive", "ipc", SupportLevel::BringUp);
    (MQ_NOTIFY, 184, "mq_notify", "ipc", SupportLevel::BringUp);
    (MQ_GETSETATTR, 185, "mq_getsetattr", "ipc", SupportLevel::BringUp);
    (MSGGET, 186, "msgget", "ipc", SupportLevel::BringUp);
    (MSGCTL, 187, "msgctl", "ipc", SupportLevel::BringUp);
    (MSGRCV, 188, "msgrcv", "ipc", SupportLevel::BringUp);
    (MSGSND, 189, "msgsnd", "ipc", SupportLevel::BringUp);
    (SEMGET, 190, "semget", "ipc", SupportLevel::BringUp);
    (SEMCTL, 191, "semctl", "ipc", SupportLevel::BringUp);
    (SEMTIMEDOP, 192, "semtimedop", "ipc", SupportLevel::BringUp);
    (SEMOP, 193, "semop", "ipc", SupportLevel::BringUp);
    (SHMGET, 194, "shmget", "ipc", SupportLevel::BringUp);
    (SHMCTL, 195, "shmctl", "ipc", SupportLevel::BringUp);
    (SHMAT, 196, "shmat", "ipc", SupportLevel::BringUp);
    (SHMDT, 197, "shmdt", "ipc", SupportLevel::BringUp);
    (SOCKET, 198, "socket", "net", SupportLevel::BringUp);
    (SOCKETPAIR, 199, "socketpair", "net", SupportLevel::BringUp);
    (BIND, 200, "bind", "net", SupportLevel::BringUp);
    (LISTEN, 201, "listen", "net", SupportLevel::BringUp);
    (ACCEPT, 202, "accept", "net", SupportLevel::BringUp);
    (CONNECT, 203, "connect", "net", SupportLevel::BringUp);
    (GETSOCKNAME, 204, "getsockname", "net", SupportLevel::BringUp);
    (GETPEERNAME, 205, "getpeername", "net", SupportLevel::BringUp);
    (SENDTO, 206, "sendto", "net", SupportLevel::BringUp);
    (RECVFROM, 207, "recvfrom", "net", SupportLevel::BringUp);
    (SETSOCKOPT, 208, "setsockopt", "net", SupportLevel::BringUp);
    (GETSOCKOPT, 209, "getsockopt", "net", SupportLevel::BringUp);
    (SHUTDOWN, 210, "shutdown", "net", SupportLevel::BringUp);
    (SENDMSG, 211, "sendmsg", "net", SupportLevel::BringUp);
    (RECVMSG, 212, "recvmsg", "net", SupportLevel::BringUp);
    (READAHEAD, 213, "readahead", "fs", SupportLevel::BringUp);
    (BRK, 214, "brk", "mm", SupportLevel::BringUp);
    (MUNMAP, 215, "munmap", "mm", SupportLevel::BringUp);
    (MREMAP, 216, "mremap", "mm", SupportLevel::BringUp);
    (ADD_KEY, 217, "add_key", "process", SupportLevel::BringUp);
    (REQUEST_KEY, 218, "request_key", "process", SupportLevel::BringUp);
    (KEYCTL, 219, "keyctl", "process", SupportLevel::BringUp);
    (CLONE, 220, "clone", "process", SupportLevel::BringUp);
    (EXECVE, 221, "execve", "process", SupportLevel::BringUp);
    (MMAP, 222, "mmap", "mm", SupportLevel::BringUp);
    (FADVISE64, 223, "fadvise64", "mm", SupportLevel::BringUp);
    (SWAPON, 224, "swapon", "mm", SupportLevel::Deferred);
    (SWAPOFF, 225, "swapoff", "mm", SupportLevel::Deferred);
    (MPROTECT, 226, "mprotect", "mm", SupportLevel::BringUp);
    (MSYNC, 227, "msync", "mm", SupportLevel::BringUp);
    (MLOCK, 228, "mlock", "mm", SupportLevel::BringUp);
    (MUNLOCK, 229, "munlock", "mm", SupportLevel::BringUp);
    (MLOCKALL, 230, "mlockall", "mm", SupportLevel::BringUp);
    (MUNLOCKALL, 231, "munlockall", "mm", SupportLevel::BringUp);
    (MINCORE, 232, "mincore", "mm", SupportLevel::BringUp);
    (MADVISE, 233, "madvise", "mm", SupportLevel::BringUp);
    (REMAP_FILE_PAGES, 234, "remap_file_pages", "mm", SupportLevel::Deferred);
    (MBIND, 235, "mbind", "mm", SupportLevel::Deferred);
    (GET_MEMPOLICY, 236, "get_mempolicy", "mm", SupportLevel::Deferred);
    (SET_MEMPOLICY, 237, "set_mempolicy", "mm", SupportLevel::Deferred);
    (MIGRATE_PAGES, 238, "migrate_pages", "mm", SupportLevel::Deferred);
    (MOVE_PAGES, 239, "move_pages", "mm", SupportLevel::Deferred);
    (RT_TGSIGQUEUEINFO, 240, "rt_tgsigqueueinfo", "signal", SupportLevel::Deferred);
    (PERF_EVENT_OPEN, 241, "perf_event_open", "process", SupportLevel::BringUp);
    (ACCEPT4, 242, "accept4", "net", SupportLevel::BringUp);
    (RECVMMSG, 243, "recvmmsg", "net", SupportLevel::BringUp);
    (WAIT4, 260, "wait4", "process", SupportLevel::BringUp);
    (PRLIMIT64, 261, "prlimit64", "process", SupportLevel::BringUp);
    (FANOTIFY_INIT, 262, "fanotify_init", "fs", SupportLevel::BringUp);
    (FANOTIFY_MARK, 263, "fanotify_mark", "fs", SupportLevel::BringUp);
    (NAME_TO_HANDLE_AT, 264, "name_to_handle_at", "fs", SupportLevel::Deferred);
    (OPEN_BY_HANDLE_AT, 265, "open_by_handle_at", "fs", SupportLevel::Deferred);
    (CLOCK_ADJTIME, 266, "clock_adjtime", "time", SupportLevel::BringUp);
    (SYNCFS, 267, "syncfs", "fs", SupportLevel::BringUp);
    (SETNS, 268, "setns", "process", SupportLevel::Deferred);
    (SENDMMSG, 269, "sendmmsg", "net", SupportLevel::BringUp);
    (PROCESS_VM_READV, 270, "process_vm_readv", "process", SupportLevel::BringUp);
    (PROCESS_VM_WRITEV, 271, "process_vm_writev", "process", SupportLevel::BringUp);
    (KCMP, 272, "kcmp", "process", SupportLevel::Deferred);
    (FINIT_MODULE, 273, "finit_module", "process", SupportLevel::Deferred);
    (SCHED_SETATTR, 274, "sched_setattr", "sched", SupportLevel::Deferred);
    (SCHED_GETATTR, 275, "sched_getattr", "sched", SupportLevel::Deferred);
    (RENAMEAT2, 276, "renameat2", "fs", SupportLevel::BringUp);
    (SECCOMP, 277, "seccomp", "process", SupportLevel::BringUp);
    (GETRANDOM, 278, "getrandom", "random", SupportLevel::BringUp);
    (MEMFD_CREATE, 279, "memfd_create", "fs", SupportLevel::BringUp);
    (BPF, 280, "bpf", "process", SupportLevel::BringUp);
    (EXECVEAT, 281, "execveat", "process", SupportLevel::Planned);
    (USERFAULTFD, 282, "userfaultfd", "mm", SupportLevel::BringUp);
    (MEMBARRIER, 283, "membarrier", "process", SupportLevel::BringUp);
    (MLOCK2, 284, "mlock2", "mm", SupportLevel::BringUp);
    (COPY_FILE_RANGE, 285, "copy_file_range", "fs", SupportLevel::BringUp);
    (PREADV2, 286, "preadv2", "fs", SupportLevel::Deferred);
    (PWRITEV2, 287, "pwritev2", "fs", SupportLevel::Deferred);
    (PKEY_MPROTECT, 288, "pkey_mprotect", "mm", SupportLevel::Deferred);
    (PKEY_ALLOC, 289, "pkey_alloc", "mm", SupportLevel::Deferred);
    (PKEY_FREE, 290, "pkey_free", "mm", SupportLevel::Deferred);
    (STATX, 291, "statx", "fs", SupportLevel::BringUp);
    (IO_PGETEVENTS, 292, "io_pgetevents", "io", SupportLevel::Deferred);
    (RSEQ, 293, "rseq", "process", SupportLevel::BringUp);
    (KEXEC_FILE_LOAD, 294, "kexec_file_load", "process", SupportLevel::Deferred);
    (CLOCK_GETTIME64, 403, "clock_gettime64", "time", SupportLevel::Deferred);
    (CLOCK_SETTIME64, 404, "clock_settime64", "time", SupportLevel::Deferred);
    (CLOCK_ADJTIME64, 405, "clock_adjtime64", "time", SupportLevel::Deferred);
    (CLOCK_GETRES_TIME64, 406, "clock_getres_time64", "time", SupportLevel::Deferred);
    (CLOCK_NANOSLEEP_TIME64, 407, "clock_nanosleep_time64", "time", SupportLevel::Deferred);
    (TIMER_GETTIME64, 408, "timer_gettime64", "time", SupportLevel::Deferred);
    (TIMER_SETTIME64, 409, "timer_settime64", "time", SupportLevel::Deferred);
    (TIMERFD_GETTIME64, 410, "timerfd_gettime64", "time", SupportLevel::Deferred);
    (TIMERFD_SETTIME64, 411, "timerfd_settime64", "time", SupportLevel::Deferred);
    (UTIMENSAT_TIME64, 412, "utimensat_time64", "fs", SupportLevel::Deferred);
    (PSELECT6_TIME64, 413, "pselect6_time64", "fs", SupportLevel::Deferred);
    (PPOLL_TIME64, 414, "ppoll_time64", "fs", SupportLevel::Deferred);
    (IO_PGETEVENTS_TIME64, 416, "io_pgetevents_time64", "io", SupportLevel::Deferred);
    (RECVMMSG_TIME64, 417, "recvmmsg_time64", "net", SupportLevel::Deferred);
    (MQ_TIMEDSEND_TIME64, 418, "mq_timedsend_time64", "ipc", SupportLevel::Deferred);
    (MQ_TIMEDRECEIVE_TIME64, 419, "mq_timedreceive_time64", "ipc", SupportLevel::Deferred);
    (SEMTIMEDOP_TIME64, 420, "semtimedop_time64", "ipc", SupportLevel::Deferred);
    (RT_SIGTIMEDWAIT_TIME64, 421, "rt_sigtimedwait_time64", "signal", SupportLevel::Deferred);
    (FUTEX_TIME64, 422, "futex_time64", "process", SupportLevel::Deferred);
    (SCHED_RR_GET_INTERVAL_TIME64, 423, "sched_rr_get_interval_time64", "sched", SupportLevel::Deferred);
    (PIDFD_SEND_SIGNAL, 424, "pidfd_send_signal", "process", SupportLevel::BringUp);
    (IO_URING_SETUP, 425, "io_uring_setup", "io", SupportLevel::BringUp);
    (IO_URING_ENTER, 426, "io_uring_enter", "io", SupportLevel::BringUp);
    (IO_URING_REGISTER, 427, "io_uring_register", "io", SupportLevel::Deferred);
    (OPEN_TREE, 428, "open_tree", "fs", SupportLevel::BringUp);
    (MOVE_MOUNT, 429, "move_mount", "fs", SupportLevel::BringUp);
    (FSOPEN, 430, "fsopen", "fs", SupportLevel::BringUp);
    (FSCONFIG, 431, "fsconfig", "fs", SupportLevel::BringUp);
    (FSMOUNT, 432, "fsmount", "fs", SupportLevel::BringUp);
    (FSPICK, 433, "fspick", "fs", SupportLevel::BringUp);
    (PIDFD_OPEN, 434, "pidfd_open", "process", SupportLevel::BringUp);
    (CLONE3, 435, "clone3", "process", SupportLevel::Planned);
    (CLOSE_RANGE, 436, "close_range", "fs", SupportLevel::BringUp);
    (OPENAT2, 437, "openat2", "fs", SupportLevel::BringUp);
    (PIDFD_GETFD, 438, "pidfd_getfd", "process", SupportLevel::Deferred);
    (FACCESSAT2, 439, "faccessat2", "fs", SupportLevel::BringUp);
    (PROCESS_MADVISE, 440, "process_madvise", "mm", SupportLevel::Deferred);
    (EPOLL_PWAIT2, 441, "epoll_pwait2", "net", SupportLevel::Deferred);
    (MOUNT_SETATTR, 442, "mount_setattr", "fs", SupportLevel::BringUp);
    (QUOTACTL_FD, 443, "quotactl_fd", "fs", SupportLevel::Deferred);
    (LANDLOCK_CREATE_RULESET, 444, "landlock_create_ruleset", "process", SupportLevel::Deferred);
    (LANDLOCK_ADD_RULE, 445, "landlock_add_rule", "process", SupportLevel::Deferred);
    (LANDLOCK_RESTRICT_SELF, 446, "landlock_restrict_self", "process", SupportLevel::Deferred);
    (MEMFD_SECRET, 447, "memfd_secret", "mm", SupportLevel::BringUp);
    (PROCESS_MRELEASE, 448, "process_mrelease", "process", SupportLevel::Deferred);
    (FUTEX_WAITV, 449, "futex_waitv", "process", SupportLevel::Deferred);
    (SET_MEMPOLICY_HOME_NODE, 450, "set_mempolicy_home_node", "mm", SupportLevel::Deferred);
    (CACHESTAT, 451, "cachestat", "fs", SupportLevel::Deferred);
    (FCHMODAT2, 452, "fchmodat2", "fs", SupportLevel::BringUp);
    (MAP_SHADOW_STACK, 453, "map_shadow_stack", "mm", SupportLevel::Deferred);
    (FUTEX_WAKE, 454, "futex_wake", "process", SupportLevel::Deferred);
    (FUTEX_WAIT, 455, "futex_wait", "process", SupportLevel::Deferred);
    (FUTEX_REQUEUE, 456, "futex_requeue", "process", SupportLevel::Deferred);
    (STATMOUNT, 457, "statmount", "fs", SupportLevel::Deferred);
    (LISTMOUNT, 458, "listmount", "fs", SupportLevel::Deferred);
    (LSM_GET_SELF_ATTR, 459, "lsm_get_self_attr", "process", SupportLevel::Deferred);
    (LSM_SET_SELF_ATTR, 460, "lsm_set_self_attr", "process", SupportLevel::Deferred);
    (LSM_LIST_MODULES, 461, "lsm_list_modules", "process", SupportLevel::Deferred);
    (MSEAL, 462, "mseal", "mm", SupportLevel::Deferred);
}

// Compile-time guard: `lookup_aarch64` binary-searches this table, so it MUST
// stay sorted by `number` with no duplicate numbers. A strictly-increasing
// check proves BOTH invariants at once — sortedness (so the binary search is
// valid) and uniqueness (so no syscall number is shadowed by an out-of-order
// twin). A bad insert or a duplicate fails the BUILD with this message rather
// than silently degrading `lookup_aarch64` to "unknown syscall" at runtime
// (the very binary-search degradation the table exists to prevent). Evaluated
// by the compiler; never reachable at runtime, so the no-panic gate is unaffected.
const _: () = {
    let mut i = 1;
    while i < AARCH64_SYSCALLS.len() {
        assert!(
            AARCH64_SYSCALLS[i - 1].number < AARCH64_SYSCALLS[i].number,
            "AARCH64_SYSCALLS must stay strictly sorted by syscall number \
             (binary_search validity + number uniqueness)",
        );
        i += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_constants_round_trip_through_table() {
        assert_eq!(GENERATED_CONSTANTS.len(), AARCH64_SYSCALLS.len());
        for &(name, nr) in GENERATED_CONSTANTS {
            // Name -> Number
            let sc_by_name = lookup_aarch64_by_name(name);
            assert!(sc_by_name.is_some(), "missing entry for {name}");
            if let Some(sc) = sc_by_name {
                assert_eq!(sc.number, nr.raw(), "mismatched number for {name}");
            }

            // Number -> Name
            let sc_by_nr = lookup_aarch64(nr.raw());
            assert!(sc_by_nr.is_some(), "missing entry for number {}", nr.raw());
            if let Some(sc) = sc_by_nr {
                assert_eq!(sc.name, name, "mismatched name for number {}", nr.raw());
            }
        }

        // Canonical 0..=500 consistency: every assigned number round-trips by name
        for nr in 0..=500 {
            if let Some(sc) = lookup_aarch64(nr) {
                assert_eq!(sc.number, nr, "mismatched number for {}", sc.name);
                let sc_by_name = lookup_aarch64_by_name(sc.name);
                assert!(
                    sc_by_name.is_some(),
                    "missing by-name entry for {}",
                    sc.name
                );
                if let Some(sc2) = sc_by_name {
                    assert_eq!(sc2.number, nr, "name lookup yielded different number");
                }
            }
        }
    }
}
