use carrick_runtime::compat::{CompatEvent, CompatReportFormat, CompatReporter, SyscallArgs};

#[test]
fn syscall_entry_name_is_borrowed_not_allocated() {
    use std::borrow::Cow;
    let ev = carrick_runtime::compat::CompatEvent::SyscallEntry {
        number: 64,
        name: Cow::Borrowed("write"), // &'static str, zero alloc
        args: carrick_runtime::compat::SyscallArgs([0; 6]),
    };
    match ev {
        carrick_runtime::compat::CompatEvent::SyscallEntry { name, .. } => {
            assert!(matches!(name, Cow::Borrowed("write")));
        }
        _ => unreachable!(),
    }
}

#[test]
fn aggregates_unhandled_syscalls_by_name_and_number() {
    let reporter = CompatReporter::default();

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
    let reporter = CompatReporter::default();
    reporter.record(CompatEvent::proc_read_unimplemented("/proc/self/maps"));

    let report = reporter.finish();
    let json = report.render(CompatReportFormat::Json).unwrap();

    assert!(json.contains("\"proc_read_unimplemented\""));
    assert!(json.contains("/proc/self/maps"));
}

#[test]
fn summary_counts_invocations_and_distinct_categories() {
    let reporter = CompatReporter::default();

    let args = SyscallArgs::from([0, 0, 0, 0, 0, 0]);
    reporter.record(CompatEvent::SyscallEntry {
        number: 64,
        name: "write".into(),
        args,
    });
    reporter.record(CompatEvent::SyscallReturn {
        number: 64,
        name: "write".into(),
        retval: 5,
        errno: None,
    });
    reporter.record(CompatEvent::SyscallEntry {
        number: 56,
        name: "openat".into(),
        args,
    });
    reporter.record(CompatEvent::SyscallReturn {
        number: 56,
        name: "openat".into(),
        retval: -2,
        errno: Some(2),
    });
    reporter.record(CompatEvent::unhandled_syscall(999, "imaginary", args));
    reporter.record(CompatEvent::unhandled_syscall(999, "imaginary", args));
    reporter.record(CompatEvent::unhandled_syscall(1000, "another", args));
    reporter.record(CompatEvent::unhandled_ioctl(3, 0x5413, 0));
    reporter.record(CompatEvent::proc_read_unimplemented("/proc/self/io"));
    reporter.record(CompatEvent::sys_read_unimplemented("/sys/block"));

    let report = reporter.finish();
    let s = &report.summary;

    assert_eq!(s.syscall_invocations, 2);
    assert_eq!(s.syscall_returns_ok, 1);
    assert_eq!(s.syscall_returns_errno, 1);
    assert_eq!(s.distinct_unhandled_syscalls, 2);
    assert_eq!(s.unhandled_syscall_invocations, 3);
    assert_eq!(s.distinct_unhandled_ioctls, 1);
    assert_eq!(s.unhandled_ioctl_invocations, 1);
    assert_eq!(s.distinct_proc_read_unimplemented, 1);
    assert_eq!(s.distinct_sys_read_unimplemented, 1);

    let text = report.render(CompatReportFormat::Text).unwrap();
    assert!(text.contains("Summary:"));
    assert!(text.contains("syscalls observed: 2"));
    assert!(text.contains("unhandled syscalls: 2 distinct, 3 invocations"));
}
