//! Time and clock syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

#[test]
fn clock_gettime_writes_packed_linux_timespec() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxTimespec>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(113, SyscallArgs::from([0, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let timespec = read_timespec(&memory, 0x4000);
    let sec = timespec.tv_sec;
    let nsec = timespec.tv_nsec;
    assert!(sec > 0);
    assert!((0..1_000_000_000).contains(&nsec));
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn clock_getres_writes_packed_linux_timespec() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxTimespec>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(114, SyscallArgs::from([1, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let timespec = read_timespec(&memory, 0x4000);
    let sec = timespec.tv_sec;
    assert_eq!(sec, 0);
    let nsec = timespec.tv_nsec;
    assert!(nsec > 0);
    assert!(nsec < 1_000_000_000);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn nanosleep_accepts_packed_timespec_and_rejects_invalid_inputs() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    memory
        .write_bytes(0x4000, LinuxTimespec::new(0, 0).as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(101, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(101, SyscallArgs::from([0x5000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );

    memory
        .write_bytes(0x4010, LinuxTimespec::new(0, 1_000_000_000).as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(101, SyscallArgs::from([0x4010, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn clock_nanosleep_accepts_relative_and_absolute_timespecs() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    memory
        .write_bytes(0x4000, LinuxTimespec::new(0, 0).as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    115,
                    SyscallArgs::from([LINUX_CLOCK_MONOTONIC, 0, 0x4000, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    115,
                    SyscallArgs::from([
                        LINUX_CLOCK_MONOTONIC,
                        LINUX_TIMER_ABSTIME,
                        0x4000,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(115, SyscallArgs::from([99, 0, 0x4000, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    115,
                    SyscallArgs::from([LINUX_CLOCK_MONOTONIC, 2, 0x4000, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    115,
                    SyscallArgs::from([LINUX_CLOCK_MONOTONIC, 0, 0x5000, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn clock_settime_bootstrap_returns_eperm_for_realtime_and_einval_for_unknown() {
    const LINUX_CLOCK_REALTIME: u64 = 0;
    const LINUX_CLOCK_MONOTONIC: u64 = 1;
    const LINUX_EPERM: i32 = 1;
    const LINUX_EFAULT: i32 = 14;
    const LINUX_EINVAL: i32 = 22;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    memory
        .write_bytes(0x4000, LinuxTimespec::new(1_700_000_000, 0).as_bytes())
        .unwrap();

    // CLOCK_REALTIME with a valid timespec: we are unprivileged.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    112,
                    SyscallArgs::from([LINUX_CLOCK_REALTIME, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_EPERM }
    );

    // CLOCK_MONOTONIC is not settable.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    112,
                    SyscallArgs::from([LINUX_CLOCK_MONOTONIC, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    // Unknown clock id.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(112, SyscallArgs::from([99, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    // Bad timespec pointer → EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    112,
                    SyscallArgs::from([LINUX_CLOCK_REALTIME, 0x9000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT
        }
    );

    // Invalid tv_nsec → EINVAL.
    memory
        .write_bytes(0x4010, LinuxTimespec::new(0, 1_000_000_000).as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    112,
                    SyscallArgs::from([LINUX_CLOCK_REALTIME, 0x4010, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn getitimer_setitimer_bootstrap_validate_args_and_zero_output() {
    const LINUX_EFAULT: i32 = 14;
    const LINUX_EINVAL: i32 = 22;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // Stamp non-zero bytes so we can confirm getitimer zeroes the output.
    memory.write_bytes(0x4000, &[0xaa; 32]).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(102, SyscallArgs::from([0, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let curr = read_itimerval(&memory, 0x4000);
    assert_eq!(curr, LinuxItimerval::zeroed());

    // getitimer with NULL output pointer → EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(102, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT
        }
    );

    // getitimer with invalid which → EINVAL.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(102, SyscallArgs::from([99, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    // setitimer: provide a valid new value, and confirm old_value is zeroed.
    let new_value = LinuxItimerval::new(
        LinuxTimeval::new(0, 0),
        LinuxTimeval::new(1, 500_000),
    );
    memory.write_bytes(0x4040, new_value.as_bytes()).unwrap();
    memory.write_bytes(0x4080, &[0xbb; 32]).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(103, SyscallArgs::from([0, 0x4040, 0x4080, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let old = read_itimerval(&memory, 0x4080);
    assert_eq!(old, LinuxItimerval::zeroed());

    // setitimer with invalid which → EINVAL.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(103, SyscallArgs::from([99, 0x4040, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    // setitimer with invalid tv_usec → EINVAL.
    let bad_value = LinuxItimerval::new(
        LinuxTimeval::new(0, 0),
        LinuxTimeval::new(0, 1_000_000),
    );
    memory.write_bytes(0x40c0, bad_value.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(103, SyscallArgs::from([0, 0x40c0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    // setitimer with NULL new_value and NULL old_value is still accepted.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(103, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    let setitimer_partial = report
        .partial_syscalls
        .iter()
        .find(|entry| entry.number == 103)
        .expect("setitimer should record a partial_syscall event");
    assert_eq!(setitimer_partial.name, "setitimer");
    assert!(
        setitimer_partial.reason.contains("SIGALRM"),
        "expected reason to mention SIGALRM, got {:?}",
        setitimer_partial.reason,
    );
}


#[test]
fn adjtimex_and_clock_adjtime_return_eperm() {
    const LINUX_CLOCK_REALTIME: u64 = 0;
    const LINUX_CLOCK_MONOTONIC: u64 = 1;
    const LINUX_EPERM: i32 = 1;
    const LINUX_EFAULT: i32 = 14;
    const LINUX_EINVAL: i32 = 22;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // 256 bytes is plenty to cover any plausible timex layout.
    memory.write_bytes(0x4000, &[0; 256]).unwrap();

    // adjtimex with a valid pointer → EPERM.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(171, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_EPERM }
    );

    // adjtimex with NULL pointer → EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(171, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT
        }
    );

    // adjtimex with bad pointer → EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(171, SyscallArgs::from([0x9000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT
        }
    );

    // clock_adjtime with CLOCK_REALTIME and valid pointer → EPERM.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    266,
                    SyscallArgs::from([LINUX_CLOCK_REALTIME, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: LINUX_EPERM }
    );

    // clock_adjtime with CLOCK_MONOTONIC → EINVAL.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    266,
                    SyscallArgs::from([LINUX_CLOCK_MONOTONIC, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL
        }
    );

    // clock_adjtime with valid clock but bad pointer → EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    266,
                    SyscallArgs::from([LINUX_CLOCK_REALTIME, 0x9000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT
        }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn gettimeofday_writes_packed_linux_timeval_and_timezone() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(169, SyscallArgs::from([0x4000, 0x4020, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let timeval = read_timeval(&memory, 0x4000);
    let sec = timeval.tv_sec;
    let usec = timeval.tv_usec;
    assert!(sec > 0);
    assert!((0..1_000_000).contains(&usec));
    let timezone = read_timezone(&memory, 0x4020);
    let minuteswest = timezone.tz_minuteswest;
    let dsttime = timezone.tz_dsttime;
    assert_eq!(minuteswest, 0);
    assert_eq!(dsttime, 0);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}


#[test]
fn times_bootstrap_writes_zero_tms_and_returns_monotonic_clock() {
    let mut memory = LinearMemory::new(0x4000, vec![0xff; core::mem::size_of::<LinuxTms>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // Valid buffer: write zeroed tms, return positive clock value.
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(153, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    let clock_with_buf = match outcome {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected Returned, got {other:?}"),
    };
    assert!(clock_with_buf > 0);
    let tms = read_tms(&memory, 0x4000);
    let utime = tms.tms_utime;
    let stime = tms.tms_stime;
    let cutime = tms.tms_cutime;
    let cstime = tms.tms_cstime;
    assert_eq!(utime, 0);
    assert_eq!(stime, 0);
    assert_eq!(cutime, 0);
    assert_eq!(cstime, 0);

    // NULL buffer: just return the clock value, nothing written.
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(153, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    let clock_null = match outcome {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected Returned, got {other:?}"),
    };
    assert!(clock_null > 0);

    // Bad pointer: EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(153, SyscallArgs::from([0xdead_0000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

