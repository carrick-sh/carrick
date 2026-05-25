use carrick_runtime::syscall::{SupportLevel, SyscallHandler, aarch64_table, lookup_aarch64};

#[test]
fn aarch64_syscall_table_is_sorted_for_binary_search() {
    for pair in aarch64_table().windows(2) {
        assert!(
            pair[0].number < pair[1].number,
            "syscall table must remain strictly sorted: {} then {}",
            pair[0].number,
            pair[1].number
        );
    }
}

#[test]
fn names_linux_aarch64_bringup_syscalls() {
    let getcwd = lookup_aarch64(17).unwrap();
    let faccessat = lookup_aarch64(48).unwrap();
    let chdir = lookup_aarch64(49).unwrap();
    let fchdir = lookup_aarch64(50).unwrap();
    let openat = lookup_aarch64(56).unwrap();
    let close = lookup_aarch64(57).unwrap();
    let getdents64 = lookup_aarch64(61).unwrap();
    let lseek = lookup_aarch64(62).unwrap();
    let read = lookup_aarch64(63).unwrap();
    let write = lookup_aarch64(64).unwrap();
    let readv = lookup_aarch64(65).unwrap();
    let writev = lookup_aarch64(66).unwrap();
    let pread64 = lookup_aarch64(67).unwrap();
    let preadv = lookup_aarch64(69).unwrap();
    let readlinkat = lookup_aarch64(78).unwrap();
    let newfstatat = lookup_aarch64(79).unwrap();
    let fstat = lookup_aarch64(80).unwrap();
    let exit = lookup_aarch64(93).unwrap();
    let exit_group = lookup_aarch64(94).unwrap();
    let brk = lookup_aarch64(214).unwrap();
    let munmap = lookup_aarch64(215).unwrap();
    let mmap = lookup_aarch64(222).unwrap();
    let mprotect = lookup_aarch64(226).unwrap();
    let madvise = lookup_aarch64(233).unwrap();

    assert_eq!(getcwd.name, "getcwd");
    assert_eq!(getcwd.support, SupportLevel::BringUp);
    assert_eq!(faccessat.name, "faccessat");
    assert_eq!(faccessat.support, SupportLevel::BringUp);
    assert_eq!(chdir.name, "chdir");
    assert_eq!(chdir.support, SupportLevel::BringUp);
    assert_eq!(fchdir.name, "fchdir");
    assert_eq!(fchdir.support, SupportLevel::BringUp);
    assert_eq!(openat.name, "openat");
    assert_eq!(openat.support, SupportLevel::BringUp);
    assert_eq!(close.name, "close");
    assert_eq!(close.support, SupportLevel::BringUp);
    assert_eq!(getdents64.name, "getdents64");
    assert_eq!(getdents64.support, SupportLevel::BringUp);
    assert_eq!(lseek.name, "lseek");
    assert_eq!(lseek.support, SupportLevel::BringUp);
    assert_eq!(read.name, "read");
    assert_eq!(read.support, SupportLevel::BringUp);
    assert_eq!(write.name, "write");
    assert_eq!(write.support, SupportLevel::BringUp);
    assert_eq!(readv.name, "readv");
    assert_eq!(readv.support, SupportLevel::BringUp);
    assert_eq!(writev.name, "writev");
    assert_eq!(writev.support, SupportLevel::BringUp);
    assert_eq!(pread64.name, "pread64");
    assert_eq!(pread64.support, SupportLevel::BringUp);
    assert_eq!(preadv.name, "preadv");
    assert_eq!(preadv.support, SupportLevel::BringUp);
    assert_eq!(readlinkat.name, "readlinkat");
    assert_eq!(readlinkat.support, SupportLevel::BringUp);
    assert_eq!(newfstatat.name, "newfstatat");
    assert_eq!(newfstatat.support, SupportLevel::BringUp);
    assert_eq!(fstat.name, "fstat");
    assert_eq!(fstat.support, SupportLevel::BringUp);
    assert_eq!(exit.name, "exit");
    assert_eq!(exit_group.name, "exit_group");
    assert_eq!(exit_group.support, SupportLevel::BringUp);
    assert_eq!(brk.name, "brk");
    assert_eq!(brk.support, SupportLevel::BringUp);
    assert_eq!(munmap.name, "munmap");
    assert_eq!(munmap.support, SupportLevel::BringUp);
    assert_eq!(mmap.name, "mmap");
    assert_eq!(mmap.support, SupportLevel::BringUp);
    assert_eq!(mprotect.name, "mprotect");
    assert_eq!(mprotect.support, SupportLevel::BringUp);
    assert_eq!(madvise.name, "madvise");
    assert_eq!(madvise.support, SupportLevel::BringUp);

    for (number, name) in [
        (5, "setxattr"),
        (6, "lsetxattr"),
        (7, "fsetxattr"),
        (8, "getxattr"),
        (9, "lgetxattr"),
        (10, "fgetxattr"),
        (11, "listxattr"),
        (12, "llistxattr"),
        (13, "flistxattr"),
        (14, "removexattr"),
        (15, "lremovexattr"),
        (16, "fremovexattr"),
        (19, "eventfd2"),
        (20, "epoll_create1"),
        (21, "epoll_ctl"),
        (22, "epoll_pwait"),
        (23, "dup"),
        (24, "dup3"),
        (25, "fcntl"),
        (32, "flock"),
        (33, "mknodat"),
        (34, "mkdirat"),
        (35, "unlinkat"),
        (36, "symlinkat"),
        (37, "linkat"),
        (38, "renameat"),
        (52, "fchmod"),
        (53, "fchmodat"),
        (54, "fchownat"),
        (55, "fchown"),
        (29, "ioctl"),
        (43, "statfs"),
        (44, "fstatfs"),
        (45, "truncate"),
        (46, "ftruncate"),
        (47, "fallocate"),
        (59, "pipe2"),
        (71, "sendfile"),
        (72, "pselect6"),
        (73, "ppoll"),
        (68, "pwrite64"),
        (70, "pwritev"),
        (74, "signalfd4"),
        (75, "vmsplice"),
        (76, "splice"),
        (77, "tee"),
        (81, "sync"),
        (82, "fsync"),
        (83, "fdatasync"),
        (85, "timerfd_create"),
        (86, "timerfd_settime"),
        (87, "timerfd_gettime"),
        (88, "utimensat"),
        (90, "capget"),
        (91, "capset"),
        (92, "personality"),
        (95, "waitid"),
        (96, "set_tid_address"),
        (98, "futex"),
        (99, "set_robust_list"),
        (101, "nanosleep"),
        (102, "getitimer"),
        (103, "setitimer"),
        (112, "clock_settime"),
        (113, "clock_gettime"),
        (114, "clock_getres"),
        (115, "clock_nanosleep"),
        (117, "ptrace"),
        (123, "sched_getaffinity"),
        (124, "sched_yield"),
        (129, "kill"),
        (130, "tkill"),
        (131, "tgkill"),
        (132, "sigaltstack"),
        (133, "rt_sigsuspend"),
        (134, "rt_sigaction"),
        (135, "rt_sigprocmask"),
        (137, "rt_sigtimedwait"),
        (138, "rt_sigqueueinfo"),
        (139, "rt_sigreturn"),
        (153, "times"),
        (140, "setpriority"),
        (141, "getpriority"),
        (142, "reboot"),
        (154, "setpgid"),
        (155, "getpgid"),
        (156, "getsid"),
        (157, "setsid"),
        (160, "uname"),
        (161, "sethostname"),
        (162, "setdomainname"),
        (165, "getrusage"),
        (166, "umask"),
        (179, "sysinfo"),
        (167, "prctl"),
        (168, "getcpu"),
        (169, "gettimeofday"),
        (170, "settimeofday"),
        (171, "adjtimex"),
        (172, "getpid"),
        (173, "getppid"),
        (174, "getuid"),
        (175, "geteuid"),
        (176, "getgid"),
        (177, "getegid"),
        (178, "gettid"),
        (216, "mremap"),
        (227, "msync"),
        (228, "mlock"),
        (229, "munlock"),
        (230, "mlockall"),
        (231, "munlockall"),
        (232, "mincore"),
        (260, "wait4"),
        (261, "prlimit64"),
        (266, "clock_adjtime"),
        (278, "getrandom"),
        (283, "membarrier"),
        (291, "statx"),
        (293, "rseq"),
        (437, "openat2"),
        (439, "faccessat2"),
    ] {
        let syscall = lookup_aarch64(number).unwrap();
        assert_eq!(syscall.name, name);
        assert_eq!(syscall.support, SupportLevel::BringUp);
    }
}

#[test]
fn unknown_syscalls_are_explicit() {
    assert!(lookup_aarch64(9999).is_none());
}

#[test]
fn manifest_records_group_handler_and_compatibility_notes() {
    let pselect6 = lookup_aarch64(72).unwrap();
    assert_eq!(pselect6.group, "fs");
    assert_eq!(pselect6.subsystem, "fs");
    assert_eq!(pselect6.handler, SyscallHandler::Network);
    assert_eq!(pselect6.compat_note, None);

    let signalfd4 = lookup_aarch64(74).unwrap();
    assert_eq!(signalfd4.group, "signal");
    assert_eq!(signalfd4.handler, SyscallHandler::BootstrapStub);
    assert!(
        signalfd4
            .compat_note
            .is_some_and(|note| note.contains("ENOSYS")),
        "bootstrap stubs must carry an explicit compatibility note",
    );

    let getrusage = lookup_aarch64(165).unwrap();
    assert_eq!(getrusage.group, "process");
    assert_eq!(getrusage.handler, SyscallHandler::Time);

    let execveat = lookup_aarch64(281).unwrap();
    assert_eq!(execveat.support, SupportLevel::Planned);
    assert_eq!(execveat.handler, SyscallHandler::Unimplemented);
    assert!(execveat.compat_note.is_some());

    let clone3 = lookup_aarch64(435).unwrap();
    assert_eq!(clone3.support, SupportLevel::Planned);
    assert_eq!(clone3.handler, SyscallHandler::Lifecycle);
    assert!(clone3.compat_note.is_some());
}

#[test]
fn bringup_manifest_entries_have_a_handler_owner() {
    for syscall in aarch64_table() {
        if syscall.support == SupportLevel::BringUp {
            assert_ne!(
                syscall.handler,
                SyscallHandler::Unimplemented,
                "bring-up syscall {} ({}) has no manifest handler owner",
                syscall.number,
                syscall.name,
            );
        }
    }
}

#[test]
fn dispatch_declares_no_abi_constants() {
    // The dispatcher now lives in a `src/dispatch/` module directory split
    // by subsystem. Every file in it must import top-level ABI constants from
    // linux_abi.rs, never declare them. We check module-level (column-0) items
    // only; function-body `const` locals (e.g. ad-hoc SYS_* inside a probe fn)
    // are not module ABI and are intentionally allowed.
    let sources = [
        include_str!("../src/dispatch/mod.rs"),
        include_str!("../src/dispatch/fs.rs"),
        include_str!("../src/dispatch/mem.rs"),
        include_str!("../src/dispatch/signal.rs"),
        include_str!("../src/dispatch/creds.rs"),
        include_str!("../src/dispatch/net.rs"),
        include_str!("../src/dispatch/time.rs"),
        include_str!("../src/dispatch/proc.rs"),
    ];
    for src in sources {
        for line in src.lines() {
            assert!(
                !(line.starts_with("pub const LINUX_")
                    || line.starts_with("const LINUX_")
                    || line.starts_with("pub const SYS_")
                    || line.starts_with("const SYS_")),
                "top-level ABI constant declared in dispatch module — move it to linux_abi.rs: {line}",
            );
        }
    }
}
