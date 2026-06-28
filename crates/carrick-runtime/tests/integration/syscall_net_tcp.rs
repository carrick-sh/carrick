//! Networking / I/O multiplexing syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

// clippy's allow-unwrap-in-tests heuristic does not cover helper functions in
// integration test crates. The no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

#[test]
fn socket_syscalls_dispatch_to_real_host_handlers() {
    // Now that the BSD socket family is wired through to libc, syscall
    // numbers 198..=212 / 242 must NOT come back as ENOSYS. We don't
    // care which specific errno the all-zero argument vector produces —
    // we only require that the dispatcher answered itself rather than
    // falling through to the "unhandled syscall" branch (which would
    // set ENOSYS and record an entry in `unhandled_syscalls`).
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let numbers: &[u64] = &[
        198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 242,
    ];

    for number in numbers {
        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(*number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        if let DispatchOutcome::Errno { errno } = outcome {
            assert_ne!(
                errno, 38,
                "socket syscall {number} returned ENOSYS — handler not installed"
            );
        }
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn signalfd4_and_tee_return_einval_not_enosys_stub() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // signalfd4 (nr 74) is implemented. With sizemask=0 (!= sizeof(sigset_t)=8)
    // Linux rejects with EINVAL(22) before touching the mask pointer
    // (fs/signalfd.c: `if (sizemask != sizeof(sigset_t)) return -EINVAL`),
    // verified against docker linux/arm64.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(74, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 },
        "signalfd4 with sizemask != 8 should return EINVAL"
    );

    // tee (77) is implemented (host tee(2) passthrough on Linux). With non-pipe
    // fds — fd_in/fd_out=0 here are not registered guest pipe ends — it rejects
    // with EINVAL before any host call, matching Linux tee(2) (LTP tee01/tee02).
    // vmsplice (nr 75) is likewise implemented now, so neither is the ENOSYS
    // bootstrap stub this assertion once covered.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(77, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 },
        "tee with non-pipe fds should return EINVAL"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn netlink_getsockopt_so_type_reports_guest_type_not_hardcoded_raw() {
    // M6: a SOCK_DGRAM netlink socket must report SOCK_DGRAM via getsockopt(
    // SO_TYPE), not a hardcoded SOCK_RAW.
    const AF_NETLINK: u64 = 16;
    const SOCK_DGRAM: u64 = 2;
    const SOCK_RAW: u64 = 3;
    const SOL_SOCKET: u64 = 1;
    const SO_TYPE: u64 = 3;
    const NETLINK_ROUTE: u64 = 0;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let call = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    // socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE) -> fd.
    let fd = match call(
        &mut dispatcher,
        &mut memory,
        198,
        [AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("socket(AF_NETLINK): {o:?}"),
    };
    // optlen = 4 at 0x4008.
    memory.write_bytes(0x4008, &4u32.to_ne_bytes()).unwrap();
    // getsockopt(fd, SOL_SOCKET, SO_TYPE, 0x4000, 0x4008).
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            209,
            [fd, SOL_SOCKET, SO_TYPE, 0x4000, 0x4008, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let ty = u32::from_ne_bytes(memory.read_bytes(0x4000, 4).unwrap().try_into().unwrap());
    assert_eq!(
        ty as u64, SOCK_DGRAM,
        "netlink SO_TYPE must report the guest type"
    );
    assert_ne!(ty as u64, SOCK_RAW);
}

#[cfg(target_os = "macos")]
#[test]
fn so_reuseport_and_bufsize_report_guest_values_not_host_widening() {
    // M4: getsockopt(SO_REUSEPORT) must report what the guest set (default 0),
    // NOT the host SO_REUSEPORT carrick turns on to emulate UDP wildcard-rebind
    // from SO_REUSEADDR. M5: getsockopt(SO_RCVBUF/SNDBUF) must report Linux's
    // doubled (2x) value of what was set, not the host's actual buffer.
    const AF_INET: u64 = 2;
    const SOCK_DGRAM: u64 = 2;
    const SOL_SOCKET: u64 = 1;
    const SO_REUSEADDR: u64 = 2;
    const SO_REUSEPORT: u64 = 15;
    const SO_RCVBUF: u64 = 8;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let call = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };
    let geti32 = |m: &LinearMemory, at: u64| {
        i32::from_ne_bytes(m.read_bytes(at, 4).unwrap().try_into().unwrap())
    };

    let fd = match call(
        &mut dispatcher,
        &mut memory,
        198,
        [AF_INET, SOCK_DGRAM, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("socket(AF_INET,SOCK_DGRAM): {o:?}"),
    };

    // setsockopt(SO_REUSEADDR, 1) — carrick widens host SO_REUSEPORT for UDP.
    memory.write_bytes(0x4000, &1i32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            208,
            [fd, SOL_SOCKET, SO_REUSEADDR, 0x4000, 4, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    // getsockopt(SO_REUSEPORT) — guest never set it, so 0 (not the host's 1).
    memory.write_bytes(0x4010, &4u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            209,
            [fd, SOL_SOCKET, SO_REUSEPORT, 0x4020, 0x4010, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        geti32(&memory, 0x4020),
        0,
        "SO_REUSEPORT must report guest value (0), not host widening"
    );

    // setsockopt(SO_RCVBUF, 8192); getsockopt -> 16384 (Linux doubles).
    memory.write_bytes(0x4000, &8192i32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            208,
            [fd, SOL_SOCKET, SO_RCVBUF, 0x4000, 4, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    memory.write_bytes(0x4010, &4u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            209,
            [fd, SOL_SOCKET, SO_RCVBUF, 0x4020, 0x4010, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        geti32(&memory, 0x4020),
        16384,
        "SO_RCVBUF must report 2x the set value"
    );

    // An explicit setsockopt(SO_REUSEPORT, 1) IS reflected.
    memory.write_bytes(0x4000, &1i32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            208,
            [fd, SOL_SOCKET, SO_REUSEPORT, 0x4000, 4, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    memory.write_bytes(0x4010, &4u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            209,
            [fd, SOL_SOCKET, SO_REUSEPORT, 0x4020, 0x4010, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        geti32(&memory, 0x4020),
        1,
        "explicit SO_REUSEPORT must read back"
    );
}
