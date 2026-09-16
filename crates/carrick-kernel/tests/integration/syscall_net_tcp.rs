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
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(*number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        if let DispatchOutcome::Errno { errno } = outcome {
            assert_ne!(
                errno,
                LinuxErrno::new(38),
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
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(74, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(22)
        },
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
                &dispatcher.capture_one_task_context().unwrap(),
                SyscallRequest::new(77, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno {
            errno: LinuxErrno::new(22)
        },
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
            &d.capture_one_task_context().unwrap(),
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
/// `IPV6_MULTICAST_IF` with interface index 0 is Linux's "clear the multicast
/// interface, let routing choose". Darwin rejects index 0 with EINVAL and has
/// no clear operation at all (measured on macOS 27: 0 as `u32`, 0 as `int`, and
/// a zero-length optval all EINVAL, and the readback keeps the previous index).
///
/// libuv's `uv_udp_set_multicast_interface(handle, NULL)` sends exactly index 0
/// on an IPv6 handle, so forwarding it made `udp_multicast_interface6` die on
/// `ASSERT_OK`. Carrick answers index 0 itself and serves the readback from the
/// guest's value.
#[test]
fn ipv6_multicast_if_index_zero_is_accepted_and_reads_back() {
    const AF_INET6: u64 = 10;
    const SOCK_DGRAM: u64 = 2;
    const SOL_IPV6: u64 = 41;
    const IPV6_MULTICAST_IF: u64 = 17;

    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let call = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            &d.capture_one_task_context().unwrap(),
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };
    let getu32 = |m: &LinearMemory, at: u64| {
        u32::from_ne_bytes(m.read_bytes(at, 4).unwrap().try_into().unwrap())
    };

    let fd = match call(
        &mut dispatcher,
        &mut memory,
        198,
        [AF_INET6, SOCK_DGRAM, 0, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        // A host without IPv6 cannot exercise this; nothing to assert.
        DispatchOutcome::Errno { .. } => return,
        o => panic!("socket(AF_INET6,SOCK_DGRAM): {o:?}"),
    };

    // Index 0 must SUCCEED, not EINVAL through to the host.
    memory.write_bytes(0x4000, &0u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            208,
            [fd, SOL_IPV6, IPV6_MULTICAST_IF, 0x4000, 4, 0]
        ),
        DispatchOutcome::Returned { value: 0 },
        "IPV6_MULTICAST_IF index 0 is Linux's 'clear'; it must not surface Darwin's EINVAL"
    );
    memory.write_bytes(0x4010, &4u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            209,
            [fd, SOL_IPV6, IPV6_MULTICAST_IF, 0x4020, 0x4010, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(getu32(&memory, 0x4020), 0, "cleared interface reads back 0");

    // A non-zero index still round-trips through the guest-visible value.
    memory.write_bytes(0x4000, &1u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            208,
            [fd, SOL_IPV6, IPV6_MULTICAST_IF, 0x4000, 4, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    memory.write_bytes(0x4010, &4u32.to_ne_bytes()).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            209,
            [fd, SOL_IPV6, IPV6_MULTICAST_IF, 0x4020, 0x4010, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(getu32(&memory, 0x4020), 1);
}

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
            &d.capture_one_task_context().unwrap(),
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

#[test]
fn loopback_tcp_echo_round_trip() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x2000]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let call = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            &d.capture_one_task_context().unwrap(),
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    // 1. Create listener socket: socket(AF_INET, SOCK_STREAM, 0)
    let listen_fd = match call(&mut dispatcher, &mut memory, 198, [2, 1, 0, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("socket(AF_INET, SOCK_STREAM): {o:?}"),
    };

    // 2. Bind to 127.0.0.1:0
    let bind_addr_ptr = 0x4000;
    let mut sockaddr = [0u8; 16];
    sockaddr[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
    sockaddr[2..4].copy_from_slice(&0u16.to_be_bytes()); // port 0
    sockaddr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    memory.write_bytes(bind_addr_ptr, &sockaddr).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            200,
            [listen_fd, bind_addr_ptr, 16, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    // 3. Listen with backlog 16
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            201,
            [listen_fd, 16, 0, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );

    // 4. getsockname to find bound port
    let gsn_addr_ptr = 0x4100;
    let gsn_len_ptr = 0x4120;
    memory
        .write_bytes(gsn_len_ptr, &16u32.to_ne_bytes())
        .unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            204,
            [listen_fd, gsn_addr_ptr, gsn_len_ptr, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let gsn_bytes = memory.read_bytes(gsn_addr_ptr, 16).unwrap();
    let port = u16::from_be_bytes([gsn_bytes[2], gsn_bytes[3]]);
    assert_ne!(port, 0, "listener must have bound a non-zero port");

    // 5. Create client socket: socket(AF_INET, SOCK_STREAM, 0)
    let client_fd = match call(&mut dispatcher, &mut memory, 198, [2, 1, 0, 0, 0, 0]) {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("client socket: {o:?}"),
    };

    // 6. Connect client to 127.0.0.1:port
    let connect_addr_ptr = 0x4200;
    let mut connect_sa = [0u8; 16];
    connect_sa[0..2].copy_from_slice(&2u16.to_ne_bytes());
    connect_sa[2..4].copy_from_slice(&port.to_be_bytes());
    connect_sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
    memory.write_bytes(connect_addr_ptr, &connect_sa).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            203,
            [client_fd, connect_addr_ptr, 16, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 },
        "connect to in-zone listener should succeed immediately"
    );

    // 7. Accept on listener
    let accept_peer_ptr = 0x4300;
    let accept_len_ptr = 0x4320;
    memory
        .write_bytes(accept_len_ptr, &16u32.to_ne_bytes())
        .unwrap();
    let accepted_fd = match call(
        &mut dispatcher,
        &mut memory,
        202,
        [listen_fd, accept_peer_ptr, accept_len_ptr, 0, 0, 0],
    ) {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("accept: {o:?}"),
    };

    // Verify accept returned client's address
    let peer_bytes = memory.read_bytes(accept_peer_ptr, 16).unwrap();
    let peer_port = u16::from_be_bytes([peer_bytes[2], peer_bytes[3]]);
    assert_ne!(
        peer_port, 0,
        "accepted peer port must be non-zero ephemeral port"
    );
    assert_eq!(&peer_bytes[4..8], &[127, 0, 0, 1]);

    // 8. Client writes "ping in-zone tcp"
    let send_buf_ptr = 0x4400;
    let ping_msg = b"ping in-zone tcp";
    memory.write_bytes(send_buf_ptr, ping_msg).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            64, // write
            [client_fd, send_buf_ptr, ping_msg.len() as u64, 0, 0, 0]
        ),
        DispatchOutcome::Returned {
            value: ping_msg.len() as i64
        }
    );

    // 9. Accepted reads "ping in-zone tcp"
    let recv_buf_ptr = 0x4500;
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            63, // read
            [accepted_fd, recv_buf_ptr, 128, 0, 0, 0]
        ),
        DispatchOutcome::Returned {
            value: ping_msg.len() as i64
        }
    );
    assert_eq!(
        &memory.read_bytes(recv_buf_ptr, ping_msg.len()).unwrap()[..],
        ping_msg
    );

    // 10. Accepted writes echo back: "pong in-zone tcp"
    let pong_msg = b"pong in-zone tcp";
    memory.write_bytes(send_buf_ptr, pong_msg).unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            64,
            [accepted_fd, send_buf_ptr, pong_msg.len() as u64, 0, 0, 0]
        ),
        DispatchOutcome::Returned {
            value: pong_msg.len() as i64
        }
    );

    // 11. Client reads echo back
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            63,
            [client_fd, recv_buf_ptr, 128, 0, 0, 0]
        ),
        DispatchOutcome::Returned {
            value: pong_msg.len() as i64
        }
    );
    assert_eq!(
        &memory.read_bytes(recv_buf_ptr, pong_msg.len()).unwrap()[..],
        pong_msg
    );

    // 12. getsockname(client) == getpeername(accepted)
    let client_gsn_ptr = 0x4600;
    let client_gsn_len = 0x4620;
    memory
        .write_bytes(client_gsn_len, &16u32.to_ne_bytes())
        .unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            204,
            [client_fd, client_gsn_ptr, client_gsn_len, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let client_sockname = memory.read_bytes(client_gsn_ptr, 16).unwrap();

    let accepted_gpn_ptr = 0x4700;
    let accepted_gpn_len = 0x4720;
    memory
        .write_bytes(accepted_gpn_len, &16u32.to_ne_bytes())
        .unwrap();
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            205,
            [accepted_fd, accepted_gpn_ptr, accepted_gpn_len, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    let accepted_peername = memory.read_bytes(accepted_gpn_ptr, 16).unwrap();
    assert_eq!(client_sockname, accepted_peername);

    // 13. Clean close
    assert_eq!(
        call(&mut dispatcher, &mut memory, 57, [client_fd, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        call(
            &mut dispatcher,
            &mut memory,
            57,
            [accepted_fd, 0, 0, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        call(&mut dispatcher, &mut memory, 57, [listen_fd, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
}
