//! TCP and UNIX socket close and epoll readiness conformance tests.
//!
//! Authorities:
//! - Local `shutdown(SHUT_RD)` / `shutdown(SHUT_RDWR)`: Linux kernel `tcp_poll` / `unix_poll`, LTP `epoll_wait05`
//! - Peer `shutdown(SHUT_WR)` / peer close: man 7 epoll (`EPOLLRDHUP`), man 2 shutdown, man 2 close

use carrick_abi::syscall::nr;
use carrick_abi::{CanonicalNr, LINUX_AF_INET, LINUX_EPOLLIN, LINUX_EPOLLRDHUP, LINUX_SOCK_STREAM};
use carrick_kernel_example::{
    Expect, Operand, ScriptedBackend, Step, Syscall, await_parked, last_child, slot, sys,
};

pub const LINUX_SHUT_RD: i32 = 0;
pub const LINUX_SHUT_WR: i32 = 1;
pub const LINUX_SHUT_RDWR: i32 = 2;

fn call(label: &'static str, nr: CanonicalNr, args: [Operand; 6]) -> Syscall {
    Syscall {
        label,
        nr,
        args,
        saves: Vec::new(),
        expect: Expect::Any,
    }
}

fn socket(domain: i32, type_: i32, protocol: i32) -> Syscall {
    call(
        "socket",
        nr::SOCKET,
        [
            (domain as i64).into(),
            (type_ as i64).into(),
            (protocol as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

fn sockaddr_in_bytes(port: u16) -> Vec<u8> {
    let mut addr = vec![0u8; 16];
    addr[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
    addr[2..4].copy_from_slice(&port.to_be_bytes());
    addr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    addr
}

fn bind(fd: impl Into<Operand>, port: u16) -> Syscall {
    let addr = sockaddr_in_bytes(port);
    call(
        "bind",
        nr::BIND,
        [
            fd.into(),
            Operand::Bytes(addr),
            16.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

fn listen(fd: impl Into<Operand>, backlog: i32) -> Syscall {
    call(
        "listen",
        nr::LISTEN,
        [
            fd.into(),
            (backlog as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

fn connect(fd: impl Into<Operand>, port: u16) -> Syscall {
    let addr = sockaddr_in_bytes(port);
    call(
        "connect",
        nr::CONNECT,
        [
            fd.into(),
            Operand::Bytes(addr),
            16.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

fn accept(fd: impl Into<Operand>) -> Syscall {
    call(
        "accept",
        nr::ACCEPT,
        [fd.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
    )
}

#[test]
fn tcp_local_shut_rd_wakes_epoll_with_epollrdhup() {
    // LTP epoll_wait05 reduction:
    // A connected TCP socket shutdown locally with SHUT_RD must report EPOLLRDHUP to epoll.
    // Asserted in root task with peer held live by a control pipe, using a zero-timeout
    // epoll_pwait so pre-fix fails decisively with expected ret 1 vs actual ret 0 in 0.00s.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 4)
                .save_out_i32(0, 1, 5),
        ),
        Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(0)),
        Step::Sys(bind(slot(0), 32770).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect(slot(1), 32770).ret(0)),
            // Keep child peer live until parent finishes assertions
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(4)).ret(0)),
        Step::Sys(accept(slot(0)).save(2)),
        Step::Sys(sys::epoll_create1(0).save(3)),
        Step::Sys(sys::epoll_ctl_add(slot(3), slot(2), LINUX_EPOLLRDHUP, 0xcafe_babe_u64).ret(0)),
        // Local SHUT_RD on root task's accepted socket
        Step::Sys(sys::shutdown(slot(2), LINUX_SHUT_RD).ret(0)),
        // Immediate zero-timeout poll in root task must return 1 event with EPOLLRDHUP
        Step::Sys(sys::epoll_pwait(slot(3), 1, 0, 0).ret(1)),
        // Unblock child
        Step::Sys(sys::write(slot(5), b"K").ret(1)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::close(slot(5)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        1,
        "immediate readiness without parking"
    );

    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & LINUX_EPOLLRDHUP,
        0,
        "man 7 epoll: EPOLLRDHUP reported on local TCP shutdown(SHUT_RD)"
    );
    assert_eq!(
        event_data, 0xcafe_babe_u64,
        "man 7 epoll: event.data matches registered u64"
    );
}

#[test]
fn tcp_local_shut_rd_with_in_and_rdhup_interest() {
    // When registered with EPOLLIN | EPOLLRDHUP, local SHUT_RD reports both bits.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 4)
                .save_out_i32(0, 1, 5),
        ),
        Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(0)),
        Step::Sys(bind(slot(0), 32771).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect(slot(1), 32771).ret(0)),
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(4)).ret(0)),
        Step::Sys(accept(slot(0)).save(2)),
        Step::Sys(sys::epoll_create1(0).save(3)),
        Step::Sys(
            sys::epoll_ctl_add(
                slot(3),
                slot(2),
                LINUX_EPOLLIN | LINUX_EPOLLRDHUP,
                0x1122_3344_u64,
            )
            .ret(0),
        ),
        Step::Sys(sys::shutdown(slot(2), LINUX_SHUT_RD).ret(0)),
        Step::Sys(sys::epoll_pwait(slot(3), 1, 0, 0).ret(1)),
        Step::Sys(sys::write(slot(5), b"K").ret(1)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::close(slot(5)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        1,
        "immediate readiness without parking"
    );

    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & LINUX_EPOLLIN,
        0,
        "EPOLLIN reported on local TCP shutdown(SHUT_RD)"
    );
    assert_ne!(
        event_mask & LINUX_EPOLLRDHUP,
        0,
        "EPOLLRDHUP reported on local TCP shutdown(SHUT_RD)"
    );
    assert_eq!(
        event_data, 0x1122_3344_u64,
        "event.data matches registered u64"
    );
}

#[test]
fn tcp_local_shut_rdwr_wakes_epoll_with_epollrdhup() {
    // Local SHUT_RDWR also shuts down read half and must report EPOLLRDHUP.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 4)
                .save_out_i32(0, 1, 5),
        ),
        Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(0)),
        Step::Sys(bind(slot(0), 32772).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect(slot(1), 32772).ret(0)),
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(4)).ret(0)),
        Step::Sys(accept(slot(0)).save(2)),
        Step::Sys(sys::epoll_create1(0).save(3)),
        Step::Sys(sys::epoll_ctl_add(slot(3), slot(2), LINUX_EPOLLRDHUP, 0xfeed_face_u64).ret(0)),
        // Local SHUT_RDWR
        Step::Sys(sys::shutdown(slot(2), LINUX_SHUT_RDWR).ret(0)),
        Step::Sys(sys::epoll_pwait(slot(3), 1, 0, 0).ret(1)),
        Step::Sys(sys::write(slot(5), b"K").ret(1)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::close(slot(5)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        1,
        "immediate readiness without parking"
    );

    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & LINUX_EPOLLRDHUP,
        0,
        "man 7 epoll: EPOLLRDHUP reported on local TCP shutdown(SHUT_RDWR)"
    );
    assert_eq!(
        event_data, 0xfeed_face_u64,
        "man 7 epoll: event.data matches registered u64"
    );
}

#[test]
fn tcp_local_shut_wr_negative_control_no_rdhup() {
    // Negative control: local shutdown(SHUT_WR) shuts down write half, not read half.
    // While the peer connection is live, local socket must NOT report EPOLLRDHUP.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 4)
                .save_out_i32(0, 1, 5),
        ),
        Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(0)),
        Step::Sys(bind(slot(0), 32773).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect(slot(1), 32773).ret(0)),
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(4)).ret(0)),
        Step::Sys(accept(slot(0)).save(2)),
        Step::Sys(sys::epoll_create1(0).save(3)),
        Step::Sys(sys::epoll_ctl_add(slot(3), slot(2), LINUX_EPOLLRDHUP, 0x9988_7766_u64).ret(0)),
        // Local SHUT_WR only
        Step::Sys(sys::shutdown(slot(2), LINUX_SHUT_WR).ret(0)),
        // Immediate zero-timeout poll in root task must return 0 events (no RDHUP)
        Step::Sys(sys::epoll_pwait(slot(3), 1, 0, 0).ret(0)),
        Step::Sys(sys::write(slot(5), b"K").ret(1)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::close(slot(5)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        1,
        "immediate zero-timeout poll returns without events"
    );
}

#[test]
fn tcp_local_shut_rd_dup_alias_lifecycle() {
    // Duplicating a connected descriptor before shutdown:
    // Closing the original descriptor retains the open file description in the dup alias,
    // and local SHUT_RD on the dup alias triggers EPOLLRDHUP on the epoll instance.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 4)
                .save_out_i32(0, 1, 5),
        ),
        Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(0)),
        Step::Sys(bind(slot(0), 32774).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect(slot(1), 32774).ret(0)),
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(4)).ret(0)),
        Step::Sys(accept(slot(0)).save(2)),
        // Duplicate descriptor in root task
        Step::Sys(sys::dup3(slot(2), 10, 0).ret(10).save(6)),
        Step::Sys(sys::epoll_create1(0).save(3)),
        Step::Sys(sys::epoll_ctl_add(slot(3), slot(2), LINUX_EPOLLRDHUP, 0xdead_beef_u64).ret(0)),
        // Close original descriptor (epoll registration survives via underlying open description)
        Step::Sys(sys::close(slot(2)).ret(0)),
        // Local SHUT_RD on dup alias
        Step::Sys(sys::shutdown(slot(6), LINUX_SHUT_RD).ret(0)),
        Step::Sys(sys::epoll_pwait(slot(3), 1, 0, 0).ret(1)),
        Step::Sys(sys::write(slot(5), b"K").ret(1)),
        Step::Sys(sys::close(slot(6)).ret(0)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::close(slot(5)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        1,
        "immediate readiness on dup alias"
    );

    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & LINUX_EPOLLRDHUP,
        0,
        "EPOLLRDHUP reported across dup alias lifecycle"
    );
    assert_eq!(
        event_data, 0xdead_beef_u64,
        "event.data matches registered u64"
    );
}

#[test]
fn unix_socketpair_local_shut_rd_wakes_epoll_with_epollrdhup() {
    // UNIX domain stream socket local SHUT_RD must report EPOLLRDHUP.
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::epoll_create1(0).save(2)),
        Step::Sys(sys::epoll_ctl_add(slot(2), slot(0), LINUX_EPOLLRDHUP, 0xbeef_cafe_u64).ret(0)),
        Step::Sys(sys::shutdown(slot(0), LINUX_SHUT_RD).ret(0)),
        Step::Sys(sys::epoll_pwait(slot(2), 1, 0, 0).ret(1)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        1,
        "immediate readiness without parking"
    );

    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & LINUX_EPOLLRDHUP,
        0,
        "man 7 epoll: EPOLLRDHUP reported on local UNIX socketpair shutdown(SHUT_RD)"
    );
    assert_eq!(
        event_data, 0xbeef_cafe_u64,
        "man 7 epoll: event.data matches registered u64"
    );
}

#[test]
fn tcp_peer_close_wakes_epoll_with_epollrdhup() {
    // Authority: man 7 epoll
    // When stream peer closes its write end (or whole socket), EPOLLRDHUP is delivered.
    let script = vec![
        Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(0)),
        Step::Sys(bind(slot(0), 32768).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect(slot(1), 32768).ret(0)),
            await_parked(1, "epoll_pwait"),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(accept(slot(0)).save(2)),
        Step::Sys(sys::epoll_create1(0).save(3)),
        Step::Sys(sys::epoll_ctl_add(slot(3), slot(2), LINUX_EPOLLRDHUP, 0x1234_5678_u64).ret(0)),
        Step::Sys(sys::epoll_pwait(slot(3), 1, 5000, 0).ret(1)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        2,
        "a parked epoll_pwait is dispatched exactly twice"
    );

    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & LINUX_EPOLLRDHUP,
        0,
        "man 7 epoll: EPOLLRDHUP reported on TCP peer close"
    );
    assert_eq!(
        event_data, 0x1234_5678_u64,
        "man 7 epoll: event.data matches registered u64"
    );
}

#[test]
fn tcp_peer_shut_wr_live_peer_handshake() {
    // Authority: man 2 shutdown, man 7 epoll
    // shutdown(SHUT_WR) sends FIN and causes EPOLLRDHUP on the peer without closing the socket.
    // The child peer remains LIVE (parked on reading a control pipe) while parent confirms
    // EPOLLRDHUP and EOF, proving true half-close rather than full peer teardown.
    let script = vec![
        // Control pipe for synchronizing child exit after parent confirms RDHUP
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 4)
                .save_out_i32(0, 1, 5),
        ),
        Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(0)),
        Step::Sys(bind(slot(0), 32769).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)), // Close control pipe write end
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect(slot(1), 32769).ret(0)),
            await_parked(1, "epoll_pwait"),
            // Child shuts down write side (sends FIN)
            Step::Sys(sys::shutdown(slot(1), LINUX_SHUT_WR).ret(0)),
            // Child stays live, parked on control pipe read until parent signals
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(4)).ret(0)), // Close control pipe read end
        Step::Sys(accept(slot(0)).save(2)),
        Step::Sys(sys::epoll_create1(0).save(3)),
        Step::Sys(sys::epoll_ctl_add(slot(3), slot(2), LINUX_EPOLLRDHUP, 0x8765_4321_u64).ret(0)),
        Step::Sys(sys::epoll_pwait(slot(3), 1, 5000, 0).ret(1)),
        // Parent confirms reading socket yields EOF (0 bytes) while peer is still alive
        Step::Sys(sys::read(slot(2), 16).ret(0)),
        // Parent releases child by writing to control pipe
        Step::Sys(sys::write(slot(5), b"K").ret(1)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::close(slot(5)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    assert_eq!(
        run.dispatches_for(1, "epoll_pwait"),
        2,
        "a parked epoll_pwait is dispatched exactly twice"
    );

    let events_bytes = run.output_tagged("events");
    let event_mask = u32::from_le_bytes(events_bytes[0..4].try_into().unwrap());
    let event_data = u64::from_le_bytes(events_bytes[8..16].try_into().unwrap());
    assert_ne!(
        event_mask & LINUX_EPOLLRDHUP,
        0,
        "man 7 epoll: EPOLLRDHUP reported on TCP peer SHUT_WR with live peer"
    );
    assert_eq!(
        event_data, 0x8765_4321_u64,
        "man 7 epoll: event.data matches registered u64"
    );
}
