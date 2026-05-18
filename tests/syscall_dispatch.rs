use carrick::compat::{CompatReporter, SyscallArgs};
use carrick::dispatch::{
    Aarch64SyscallFrame, DispatchOutcome, GuestMemory, LinearMemory, SyscallDispatcher,
    SyscallRequest,
};

#[test]
fn write_syscall_reads_guest_memory_and_writes_stdout() {
    let memory = LinearMemory::new(0x4000, b"hello from linux\n".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new(&memory);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0])),
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 17 });
    assert_eq!(dispatcher.stdout(), b"hello from linux\n");
    assert!(dispatcher.stderr().is_empty());

    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
}

#[test]
fn write_syscall_rejects_bad_guest_pointer_with_efault() {
    let memory = LinearMemory::new(0x4000, b"short".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new(&memory);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x5000, 5, 0, 0, 0])),
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 14 });
    assert!(dispatcher.stdout().is_empty());
}

#[test]
fn exit_syscall_requests_process_exit() {
    let memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new(&memory);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(93, SyscallArgs::from([42, 0, 0, 0, 0, 0])),
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 42 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn unknown_syscall_returns_enosys_and_records_report_entry() {
    let memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new(&memory);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(9999, SyscallArgs::from([1, 2, 3, 4, 5, 6])),
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 38 });
    let report = reporter.finish();
    assert_eq!(report.unhandled_syscalls[0].number, 9999);
    assert_eq!(report.unhandled_syscalls[0].name, "unknown");
    assert_eq!(report.unhandled_syscalls[0].count, 1);
}

#[test]
fn syscall_request_can_be_built_from_aarch64_register_frame() {
    let frame = Aarch64SyscallFrame {
        x0: 1,
        x1: 0x4000,
        x2: 17,
        x3: 0,
        x4: 0,
        x5: 0,
        x8: 64,
    };

    assert_eq!(
        SyscallRequest::from_aarch64_frame(frame),
        SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0]))
    );
}

#[test]
fn linear_memory_bounds_reads() {
    let memory = LinearMemory::new(0x1000, b"abcdef".to_vec());

    assert_eq!(memory.read_bytes(0x1002, 3).unwrap(), b"cde");
    assert!(memory.read_bytes(0x1004, 3).is_err());
}
