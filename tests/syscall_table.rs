use carrick::syscall::{SupportLevel, lookup_aarch64};

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
    let readlinkat = lookup_aarch64(78).unwrap();
    let newfstatat = lookup_aarch64(79).unwrap();
    let fstat = lookup_aarch64(80).unwrap();
    let exit = lookup_aarch64(93).unwrap();
    let exit_group = lookup_aarch64(94).unwrap();
    let brk = lookup_aarch64(214).unwrap();
    let munmap = lookup_aarch64(215).unwrap();
    let mmap = lookup_aarch64(222).unwrap();
    let mprotect = lookup_aarch64(226).unwrap();

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

    for (number, name) in [
        (19, "eventfd2"),
        (20, "epoll_create1"),
        (21, "epoll_ctl"),
        (22, "epoll_pwait"),
        (23, "dup"),
        (24, "dup3"),
        (25, "fcntl"),
        (29, "ioctl"),
        (43, "statfs"),
        (44, "fstatfs"),
        (59, "pipe2"),
        (73, "ppoll"),
        (85, "timerfd_create"),
        (86, "timerfd_settime"),
        (87, "timerfd_gettime"),
        (96, "set_tid_address"),
        (99, "set_robust_list"),
        (113, "clock_gettime"),
        (114, "clock_getres"),
        (134, "rt_sigaction"),
        (135, "rt_sigprocmask"),
        (160, "uname"),
        (169, "gettimeofday"),
        (172, "getpid"),
        (173, "getppid"),
        (174, "getuid"),
        (175, "geteuid"),
        (176, "getgid"),
        (177, "getegid"),
        (178, "gettid"),
        (261, "prlimit64"),
        (278, "getrandom"),
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
