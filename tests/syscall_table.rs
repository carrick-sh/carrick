use carrick::syscall::{SupportLevel, lookup_aarch64};

#[test]
fn names_linux_aarch64_bringup_syscalls() {
    let openat = lookup_aarch64(56).unwrap();
    let close = lookup_aarch64(57).unwrap();
    let read = lookup_aarch64(63).unwrap();
    let write = lookup_aarch64(64).unwrap();
    let exit = lookup_aarch64(93).unwrap();

    assert_eq!(openat.name, "openat");
    assert_eq!(openat.support, SupportLevel::BringUp);
    assert_eq!(close.name, "close");
    assert_eq!(close.support, SupportLevel::BringUp);
    assert_eq!(read.name, "read");
    assert_eq!(read.support, SupportLevel::BringUp);
    assert_eq!(write.name, "write");
    assert_eq!(write.support, SupportLevel::BringUp);
    assert_eq!(exit.name, "exit");
}

#[test]
fn unknown_syscalls_are_explicit() {
    assert!(lookup_aarch64(9999).is_none());
}
