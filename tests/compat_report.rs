use carrick::compat::{CompatEvent, CompatReportFormat, CompatReporter, SyscallArgs};

#[test]
fn aggregates_unhandled_syscalls_by_name_and_number() {
    let mut reporter = CompatReporter::default();

    reporter.record(CompatEvent::unhandled_syscall(
        56,
        "openat",
        SyscallArgs::from([1, 2, 3, 4, 5, 6]),
    ));
    reporter.record(CompatEvent::unhandled_syscall(
        56,
        "openat",
        SyscallArgs::from([6, 5, 4, 3, 2, 1]),
    ));
    reporter.record(CompatEvent::unhandled_ioctl(3, 0x5413, 0));

    let report = reporter.finish();

    assert_eq!(report.unhandled_syscalls[0].number, 56);
    assert_eq!(report.unhandled_syscalls[0].name, "openat");
    assert_eq!(report.unhandled_syscalls[0].count, 2);
    assert_eq!(report.unhandled_ioctls[0].request, 0x5413);
}

#[test]
fn renders_machine_parseable_json() {
    let mut reporter = CompatReporter::default();
    reporter.record(CompatEvent::proc_read_unimplemented("/proc/self/maps"));

    let report = reporter.finish();
    let json = report.render(CompatReportFormat::Json).unwrap();

    assert!(json.contains("\"proc_read_unimplemented\""));
    assert!(json.contains("/proc/self/maps"));
}
