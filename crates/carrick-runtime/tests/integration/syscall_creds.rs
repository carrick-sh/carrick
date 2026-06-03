//! Credentials, scheduling, and process-control syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

use carrick_runtime::linux_abi::LINUX_EACCES;

/// Serializes the capability tests. `capget`/`capset` both read/mutate the
/// process-global modeled capability set (`namespace::process::caps()`), which
/// is shared across the whole test binary and is NOT reset between tests.
/// Holding this lock for each test's body keeps them from interleaving (capset's
/// record would otherwise race capget's read in the parallel harness).
static CAPS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Establish a deterministic baseline: the Docker-default modeled cap set a
/// fresh carrick process starts with. Call under `CAPS_TEST_LOCK`.
fn reset_modeled_caps_to_docker_default() {
    use carrick_runtime::namespace::process::{CapabilitySet, set_caps};
    set_caps(CapabilitySet::docker_default());
}

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
fn capget_writes_docker_default_capability_sets() {
    let _guard = CAPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_modeled_caps_to_docker_default();

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
    // A default container root reports the Docker-default capability set
    // (effective=permitted=0xa80425fb, inheritable=0), NOT an empty set —
    // matching `docker run debian` /proc/self/status and capget(2) on arm64.
    assert_eq!(
        read_capability_data(&memory, 0x4080, 2),
        vec![(0xa804_25fb, 0xa804_25fb, 0), (0, 0, 0)]
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn capset_accepts_empty_sets_and_rejects_nonempty_sets() {
    let _guard = CAPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_modeled_caps_to_docker_default();

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
    let mut expected_affinity = vec![0u8; LINUX_BOOTSTRAP_AFFINITY_BYTES];
    for cpu in 0..carrick_runtime::host_facts::logical_cpu_count().min(expected_affinity.len() * 8)
    {
        expected_affinity[cpu / 8] |= 1 << (cpu % 8);
    }
    assert_eq!(
        memory
            .read_bytes(0x4000, LINUX_BOOTSTRAP_AFFINITY_BYTES)
            .unwrap(),
        expected_affinity
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
    let rusage = read_rusage(&memory, 0x4000);
    #[cfg(not(target_os = "macos"))]
    assert_eq!(rusage, LinuxRusage::zeroed());
    #[cfg(target_os = "macos")]
    {
        assert!(rusage.ru_utime.tv_sec >= 0);
        assert!(rusage.ru_utime.tv_usec >= 0);
        assert!(rusage.ru_stime.tv_sec >= 0);
        assert!(rusage.ru_stime.tv_usec >= 0);
        assert!(rusage.ru_maxrss >= 0);
    }

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
    let rusage_children = read_rusage(&memory, 0x4000);
    #[cfg(not(target_os = "macos"))]
    assert_eq!(rusage_children, LinuxRusage::zeroed());
    #[cfg(target_os = "macos")]
    {
        assert_eq!(rusage_children.ru_utime, LinuxTimeval::new(0, 0));
        assert_eq!(rusage_children.ru_stime, LinuxTimeval::new(0, 0));
        assert!(rusage_children.ru_maxrss >= 0);
    }

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

    // setpriority: an out-of-range prio is CLAMPED, not rejected (Linux
    // set_user_nice clamps to [-20,19]; EINVAL is reserved for a bad `which`).
    // prio=-21 clamps to -20; as full-capability root (euid 0) lowering nice
    // succeeds -> 0. (Docker oracle returns EPERM only because it drops
    // CAP_SYS_NICE; carrick models unrestricted root.)
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
        DispatchOutcome::Returned { value: 0 }
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

    // getpriority returns the raw kernel ABI `20 - nice`. setpriority now
    // persists the nice value (process-global static); the last successful
    // setpriority above stored nice=5, so this reports 20-5=15.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(141, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 15 }
    );
    let current_pid = std::process::id() as u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(141, SyscallArgs::from([0, current_pid, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 15 }
    );

    // setpriority returns EACCES, not EPERM, when the target exists but an
    // unprivileged caller tries to lower its nice value (raise priority).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(140, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(146, SyscallArgs::from([1000, 0, 0, 0, 0, 0])),
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
                    140,
                    SyscallArgs::from([0, 0, 20_u64.wrapping_neg(), 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LINUX_EACCES
        }
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

/// `prctl(167)` syscall number; shared by the prctl option tests below.
const PRCTL: u64 = 167;

/// Issue a `prctl(option, arg2, arg3)` and unwrap the outcome.
#[allow(clippy::unwrap_used)]
fn prctl(
    d: &mut SyscallDispatcher,
    m: &mut LinearMemory,
    r: &CompatReporter,
    option: u64,
    arg2: u64,
    arg3: u64,
) -> DispatchOutcome {
    d.dispatch(
        SyscallRequest::new(PRCTL, SyscallArgs::from([option, arg2, arg3, 0, 0, 0])),
        m,
        r,
    )
    .unwrap()
}

/// H1: the common sandboxing/init prctl options must round-trip (set→get),
/// not return EINVAL. PR_SET_NO_NEW_PRIVS in particular is the precondition
/// for unprivileged seccomp (Docker/systemd/Go/Chrome sandboxes).
#[test]
fn prctl_no_new_privs_keepcaps_subreaper_timerslack_round_trip() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    const PR_GET_KEEPCAPS: u64 = 7;
    const PR_SET_KEEPCAPS: u64 = 8;
    const PR_GET_SECCOMP: u64 = 21;
    const PR_SET_TIMERSLACK: u64 = 29;
    const PR_GET_TIMERSLACK: u64 = 30;
    const PR_SET_CHILD_SUBREAPER: u64 = 36;
    const PR_GET_CHILD_SUBREAPER: u64 = 37;
    const PR_SET_NO_NEW_PRIVS: u64 = 38;
    const PR_GET_NO_NEW_PRIVS: u64 = 39;
    let returned = |v: i64| DispatchOutcome::Returned { value: v };

    // NO_NEW_PRIVS: starts 0, set→1, reads back 1 (one-way latch).
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_NO_NEW_PRIVS,
            0,
            0
        ),
        returned(0)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_SET_NO_NEW_PRIVS,
            1,
            0
        ),
        returned(0)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_NO_NEW_PRIVS,
            0,
            0
        ),
        returned(1)
    );
    // Bad args → EINVAL (arg2 != 1, or arg3..arg5 nonzero).
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_SET_NO_NEW_PRIVS,
            1,
            7
        ),
        DispatchOutcome::Errno { errno: 22 }
    );

    // KEEPCAPS: 0 → set 1 → 1; arg2 > 1 → EINVAL.
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_KEEPCAPS,
            0,
            0
        ),
        returned(0)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_SET_KEEPCAPS,
            1,
            0
        ),
        returned(0)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_KEEPCAPS,
            0,
            0
        ),
        returned(1)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_SET_KEEPCAPS,
            2,
            0
        ),
        DispatchOutcome::Errno { errno: 22 }
    );

    // TIMERSLACK: default 50000 ns → set 120000 → reads back 120000;
    // set 0 resets to the default.
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_TIMERSLACK,
            0,
            0
        ),
        returned(50_000)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_SET_TIMERSLACK,
            120_000,
            0
        ),
        returned(0)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_TIMERSLACK,
            0,
            0
        ),
        returned(120_000)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_SET_TIMERSLACK,
            0,
            0
        ),
        returned(0)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_TIMERSLACK,
            0,
            0
        ),
        returned(50_000)
    );

    // CHILD_SUBREAPER: set 1 (return-value form), GET writes the value to *arg2.
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_SET_CHILD_SUBREAPER,
            1,
            0
        ),
        returned(0)
    );
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_CHILD_SUBREAPER,
            0x4000,
            0
        ),
        returned(0)
    );
    let got = i32::from_le_bytes(memory.read_bytes(0x4000, 4).unwrap().try_into().unwrap());
    assert_eq!(got, 1);

    // SECCOMP: no filter installed → mode 0.
    assert_eq!(
        prctl(
            &mut dispatcher,
            &mut memory,
            &reporter,
            PR_GET_SECCOMP,
            0,
            0
        ),
        returned(0)
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

/// H2: `setrlimit`/`prlimit64`/`getrlimit` must round-trip per resource —
/// a value set for RLIMIT_STACK/AS/NPROC must read back (not a hardcoded
/// default), and resources must be independent of each other.
#[test]
fn prlimit64_and_getrlimit_round_trip_per_resource() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    const PRLIMIT64: u64 = 261;
    const GETRLIMIT: u64 = 163;
    const RLIMIT_STACK: u64 = 3;
    const RLIMIT_AS: u64 = 9;
    let new = 0x4000u64;
    let old = 0x4040u64;
    let returned0 = DispatchOutcome::Returned { value: 0 };

    let write_rlim = |m: &mut LinearMemory, addr: u64, cur: u64, max: u64| {
        m.write_bytes(addr, &cur.to_le_bytes()).unwrap();
        m.write_bytes(addr + 8, &max.to_le_bytes()).unwrap();
    };
    let read_rlim = |m: &LinearMemory, addr: u64| -> (u64, u64) {
        let cur = u64::from_le_bytes(m.read_bytes(addr, 8).unwrap().try_into().unwrap());
        let max = u64::from_le_bytes(m.read_bytes(addr + 8, 8).unwrap().try_into().unwrap());
        (cur, max)
    };

    // setrlimit(RLIMIT_STACK, {64 MiB, INFINITY}) via prlimit64.
    write_rlim(&mut memory, new, 64 * 1024 * 1024, u64::MAX);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    PRLIMIT64,
                    SyscallArgs::from([0, RLIMIT_STACK, new, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        returned0
    );
    // prlimit64 read-back (new=0) writes the CURRENT limit to *old.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    PRLIMIT64,
                    SyscallArgs::from([0, RLIMIT_STACK, 0, old, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        returned0
    );
    assert_eq!(read_rlim(&memory, old), (64 * 1024 * 1024, u64::MAX));

    // 2-arg getrlimit(163) must agree.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    GETRLIMIT,
                    SyscallArgs::from([RLIMIT_STACK, old, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        returned0
    );
    assert_eq!(read_rlim(&memory, old), (64 * 1024 * 1024, u64::MAX));

    // A different resource is independent: RLIMIT_AS set to a distinct value.
    write_rlim(&mut memory, new, 0x1234_0000, 0x5678_0000);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(PRLIMIT64, SyscallArgs::from([0, RLIMIT_AS, new, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        returned0
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(PRLIMIT64, SyscallArgs::from([0, RLIMIT_AS, 0, old, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        returned0
    );
    assert_eq!(read_rlim(&memory, old), (0x1234_0000, 0x5678_0000));
    // STACK is unaffected by the AS set.
    dispatcher
        .dispatch(
            SyscallRequest::new(
                GETRLIMIT,
                SyscallArgs::from([RLIMIT_STACK, old, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(read_rlim(&memory, old), (64 * 1024 * 1024, u64::MAX));

    // rlim_cur > rlim_max is still rejected.
    write_rlim(&mut memory, new, 100, 50);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(PRLIMIT64, SyscallArgs::from([0, RLIMIT_AS, new, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}
