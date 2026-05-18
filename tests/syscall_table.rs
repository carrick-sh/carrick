use carrick::syscall::{SupportLevel, lookup_aarch64};

#[test]
fn names_linux_aarch64_bringup_syscalls() {
    let write = lookup_aarch64(64).unwrap();
    let exit = lookup_aarch64(93).unwrap();

    assert_eq!(write.name, "write");
    assert_eq!(write.support, SupportLevel::BringUp);
    assert_eq!(exit.name, "exit");
}

#[test]
fn unknown_syscalls_are_explicit() {
    assert!(lookup_aarch64(9999).is_none());
}
