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
    let newfstatat = lookup_aarch64(79).unwrap();
    let fstat = lookup_aarch64(80).unwrap();
    let exit = lookup_aarch64(93).unwrap();

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
    assert_eq!(newfstatat.name, "newfstatat");
    assert_eq!(newfstatat.support, SupportLevel::BringUp);
    assert_eq!(fstat.name, "fstat");
    assert_eq!(fstat.support, SupportLevel::BringUp);
    assert_eq!(exit.name, "exit");
}

#[test]
fn unknown_syscalls_are_explicit() {
    assert!(lookup_aarch64(9999).is_none());
}
