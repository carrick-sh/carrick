//! Credentials, scheduling, and process-control syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

#[test]
fn process_identity_syscalls_return_bootstrap_ids() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let pid = std::process::id() as i64;

    for (number, expected) in [
        (172, pid),
        (173, 1),
        (174, 0),
        (175, 0),
        (176, 0),
        (177, 0),
        (178, pid),
    ] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: expected }
        );
    }
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn capget_writes_empty_bootstrap_capability_sets() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    write_capability_header(&mut memory, 0x4000, LINUX_CAPABILITY_VERSION_3, 0);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(90, SyscallArgs::from([0x4000, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        read_capability_data(&memory, 0x4080, 2),
        vec![(0, 0, 0), (0, 0, 0)]
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn capset_accepts_empty_sets_and_rejects_nonempty_sets() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    write_capability_header(&mut memory, 0x4000, LINUX_CAPABILITY_VERSION_3, 0);
    write_capability_data(&mut memory, 0x4080, [(0, 0, 0), (0, 0, 0)]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(91, SyscallArgs::from([0x4000, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    write_capability_data(&mut memory, 0x4080, [(1, 0, 0), (0, 0, 0)]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(91, SyscallArgs::from([0x4000, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 1 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn personality_query_and_set_round_trip_bootstrap_flags() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    92,
                    SyscallArgs::from([LINUX_PERSONALITY_QUERY, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    92,
                    SyscallArgs::from([LINUX_ADDR_NO_RANDOMIZE, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    92,
                    SyscallArgs::from([LINUX_PERSONALITY_QUERY, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_ADDR_NO_RANDOMIZE as i64
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn prctl_handles_bootstrap_process_controls() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"carrick-prctl\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    167,
                    SyscallArgs::from([LINUX_PR_GET_DUMPABLE, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    167,
                    SyscallArgs::from([LINUX_PR_SET_DUMPABLE, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    167,
                    SyscallArgs::from([LINUX_PR_GET_DUMPABLE, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    167,
                    SyscallArgs::from([LINUX_PR_SET_NAME, 0x4000, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    167,
                    SyscallArgs::from([LINUX_PR_GET_NAME, 0x4040, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        memory.read_bytes(0x4040, 16).unwrap(),
        b"carrick-prctl\0\0\0"
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    167,
                    SyscallArgs::from([LINUX_PR_SET_DUMPABLE, 99, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    167,
                    SyscallArgs::from([LINUX_PR_SET_NAME, 0x5000, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(167, SyscallArgs::from([999, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn getcpu_writes_bootstrap_cpu_and_numa_node() {
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x20]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(168, SyscallArgs::from([0x4000, 0x4004, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(memory.read_bytes(0x4000, 4).unwrap(), 0u32.to_ne_bytes());
    assert_eq!(memory.read_bytes(0x4004, 4).unwrap(), 0u32.to_ne_bytes());
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(168, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(168, SyscallArgs::from([0x5000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn set_tid_address_and_robust_list_are_bootstrap_successes() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let pid = std::process::id() as i64;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(96, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: pid }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(99, SyscallArgs::from([0x4000, 24, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn rseq_reports_clean_bootstrap_fallback() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(293, SyscallArgs::from([0x4000, 32, 0, 0x5305_3053, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 38 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn membarrier_query_reports_no_bootstrap_commands() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    283,
                    SyscallArgs::from([LINUX_MEMBARRIER_CMD_QUERY, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    283,
                    SyscallArgs::from([
                        LINUX_MEMBARRIER_CMD_QUERY,
                        LINUX_MEMBARRIER_CMD_FLAG_CPU,
                        0,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    283,
                    SyscallArgs::from([LINUX_MEMBARRIER_CMD_GLOBAL, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn scheduler_bootstrap_yields_and_writes_current_affinity() {
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x20]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let pid = std::process::id() as u64;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(124, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    123,
                    SyscallArgs::from([0, LINUX_BOOTSTRAP_AFFINITY_BYTES as u64, 0x4000, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_BOOTSTRAP_AFFINITY_BYTES as i64
        }
    );
    assert_eq!(
        memory
            .read_bytes(0x4000, LINUX_BOOTSTRAP_AFFINITY_BYTES)
            .unwrap(),
        [1, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(123, SyscallArgs::from([pid, 4, 0x4000, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    123,
                    SyscallArgs::from([
                        pid + 10_000,
                        LINUX_BOOTSTRAP_AFFINITY_BYTES as u64,
                        0x4000,
                        0,
                        0,
                        0
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 3 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn futex_wait_and_wake_cover_bootstrap_private_operations() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    memory.write_bytes(0x4000, &7u32.to_ne_bytes()).unwrap();
    memory
        .write_bytes(0x4010, LinuxTimespec::new(0, 0).as_bytes())
        .unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    98,
                    SyscallArgs::from([
                        0x4000,
                        LINUX_FUTEX_WAKE | LINUX_FUTEX_PRIVATE_FLAG,
                        1,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    98,
                    SyscallArgs::from([
                        0x4000,
                        LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG,
                        8,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    98,
                    SyscallArgs::from([
                        0x4000,
                        LINUX_FUTEX_WAIT | LINUX_FUTEX_PRIVATE_FLAG,
                        7,
                        0x4010,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 110 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    98,
                    SyscallArgs::from([
                        0x5000,
                        LINUX_FUTEX_WAKE | LINUX_FUTEX_PRIVATE_FLAG,
                        1,
                        0,
                        0,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 14 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn uname_writes_packed_linux_utsname() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxUtsname>()]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(160, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let utsname = read_utsname(&memory, 0x4000);
    assert_eq!(linux_c_string(utsname.sysname), "Linux");
    assert_eq!(linux_c_string(utsname.machine), "aarch64");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn prlimit64_writes_packed_rlimit() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxRlimit>()]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(261, SyscallArgs::from([0, 3, 0, 0x4000, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let rlimit = read_rlimit(&memory, 0x4000);
    let current = rlimit.rlim_cur;
    let maximum = rlimit.rlim_max;
    // RLIMIT_STACK (resource 3) has a finite soft limit and an unlimited
    // (RLIM_INFINITY) hard limit on real Linux, so soft and hard differ.
    // The kernel invariant is rlim_cur <= rlim_max, not equality.
    assert!(current <= maximum);
    assert!(current > 0);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn getrusage_bootstrap_zeros_rusage_for_self_and_validates_who() {
    const LINUX_RUSAGE_SELF: u64 = 0;
    const LINUX_RUSAGE_CHILDREN: u64 = (-1_i64) as u64;
    const LINUX_EINVAL: i32 = 22;
    const LINUX_EFAULT: i32 = 14;

    let mut memory = LinearMemory::new(0x4000, vec![0xff; core::mem::size_of::<LinuxRusage>()]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // RUSAGE_SELF with valid pointer -> zeroed rusage, returns 0.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    165,
                    SyscallArgs::from([LINUX_RUSAGE_SELF, 0x4000, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(read_rusage(&memory, 0x4000), LinuxRusage::zeroed());

    // RUSAGE_CHILDREN with valid pointer -> same.
    // Pre-poison the buffer so we can prove the handler zeroed it.
    memory
        .write_bytes(0x4000, &vec![0xaa; core::mem::size_of::<LinuxRusage>()])
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    165,
                    SyscallArgs::from([LINUX_RUSAGE_CHILDREN, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(read_rusage(&memory, 0x4000), LinuxRusage::zeroed());

    // who = 99 -> EINVAL.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(165, SyscallArgs::from([99, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        }
    );

    // Valid who, bad pointer -> EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    165,
                    SyscallArgs::from([LINUX_RUSAGE_SELF, 0xdead_0000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    );

    // Valid who, NULL pointer -> EFAULT.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(165, SyscallArgs::from([LINUX_RUSAGE_SELF, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn umask_setpriority_getpriority_sysinfo_bootstrap_stubs() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // umask: default 0o022, returns previous value when changed.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(166, SyscallArgs::from([0o077, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0o022 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(166, SyscallArgs::from([0o644, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0o077 }
    );

    // setpriority: prio out of range -> EINVAL; which out of range -> EINVAL.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    140,
                    SyscallArgs::from([0, 0, 21_u64.wrapping_neg(), 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(140, SyscallArgs::from([99, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    // setpriority for our pid succeeds.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(140, SyscallArgs::from([0, 0, 5_u64, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    // setpriority for an unknown pid -> ESRCH.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(140, SyscallArgs::from([0, 42, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 3 }
    );

    // getpriority returns 20 (nice = 0) for our pid.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(141, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 20 }
    );

    // sysinfo populates a 64-bit-aligned struct at the provided address.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(179, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let bytes = memory.read_bytes(0x4000, 8).unwrap();
    let uptime = i64::from_le_bytes(bytes.try_into().unwrap());
    assert!(uptime >= 0);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}
