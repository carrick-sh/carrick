//! TCP and UNIX socket close and epoll readiness conformance tests.
//!
//! Authorities:
//! - Local `shutdown(SHUT_RD)` / `shutdown(SHUT_RDWR)`: Linux kernel `tcp_poll` / `unix_poll`, LTP `epoll_wait05`
//! - Peer `shutdown(SHUT_WR)` / peer close: man 7 epoll (`EPOLLRDHUP`), man 2 shutdown, man 2 close

use carrick_abi::syscall::nr;
use carrick_abi::{CanonicalNr, LINUX_AF_INET, LINUX_EPOLLIN, LINUX_EPOLLRDHUP, LINUX_SOCK_STREAM};
use carrick_kernel_example::{
    Expect, Operand, ScriptedBackend, Step, Syscall, alloc_buffer, await_parked, last_child, slot,
    sys,
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

/// `bind` to the sockaddr held in `addr_slot`'s buffer.
fn bind_addr(fd: impl Into<Operand>, addr_slot: usize) -> Syscall {
    call(
        "bind",
        nr::BIND,
        [
            fd.into(),
            slot(addr_slot),
            16.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `connect` to the sockaddr held in `addr_slot`'s buffer.
fn connect_addr(fd: impl Into<Operand>, addr_slot: usize) -> Syscall {
    call(
        "connect",
        nr::CONNECT,
        [
            fd.into(),
            slot(addr_slot),
            16.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `getsockname`, writing the resolved sockaddr back into `addr_slot`'s buffer
/// (the same address `bind_addr`/`connect_addr` read from) in place.
fn getsockname_addr(fd: impl Into<Operand>, addr_slot: usize) -> Syscall {
    call(
        "getsockname",
        nr::GETSOCKNAME,
        [
            fd.into(),
            slot(addr_slot),
            Operand::InOut(16u32.to_ne_bytes().to_vec()),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

// Every test below binds its listener with this pattern:
//   alloc_buffer(ADDR_SLOT, sockaddr_in_bytes(0)),        // port 0 = OS picks one
//   Step::Sys(bind_addr(slot(LISTENER), ADDR_SLOT).ret(0)),
//   Step::Sys(getsockname_addr(slot(LISTENER), ADDR_SLOT).ret(0)),  // resolves the port
//   ...
//   Step::Sys(connect_addr(slot(CLIENT), ADDR_SLOT).ret(0)),
//
// This suite dials real loopback TCP sockets. A literal port number (this
// file previously hardcoded 32768-32774, the low end of the Linux ephemeral
// range) collides under concurrent runs of this suite on the same host --
// e.g. two worktree gates or CI jobs running at once, which is routine for
// this project -- and the resulting EADDRINUSE is not a semantic bug in
// carrick's socket emulation, it is a resource-hygiene defect in the test.
// Asking the OS for an ephemeral port removes the whole collision class
// deterministically, rather than retrying or widening a timeout. Slot 20 is
// otherwise unused by any test in this file and holds the shared sockaddr
// buffer that `bind_addr`/`getsockname_addr`/`connect_addr` all read/write.
const ADDR_SLOT: usize = 20;

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
        alloc_buffer(ADDR_SLOT, sockaddr_in_bytes(0)),
        Step::Sys(bind_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(getsockname_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect_addr(slot(1), ADDR_SLOT).ret(0)),
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
        alloc_buffer(ADDR_SLOT, sockaddr_in_bytes(0)),
        Step::Sys(bind_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(getsockname_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect_addr(slot(1), ADDR_SLOT).ret(0)),
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
        alloc_buffer(ADDR_SLOT, sockaddr_in_bytes(0)),
        Step::Sys(bind_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(getsockname_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect_addr(slot(1), ADDR_SLOT).ret(0)),
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
        alloc_buffer(ADDR_SLOT, sockaddr_in_bytes(0)),
        Step::Sys(bind_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(getsockname_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect_addr(slot(1), ADDR_SLOT).ret(0)),
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
        alloc_buffer(ADDR_SLOT, sockaddr_in_bytes(0)),
        Step::Sys(bind_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(getsockname_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect_addr(slot(1), ADDR_SLOT).ret(0)),
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
        alloc_buffer(ADDR_SLOT, sockaddr_in_bytes(0)),
        Step::Sys(bind_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(getsockname_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect_addr(slot(1), ADDR_SLOT).ret(0)),
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
        alloc_buffer(ADDR_SLOT, sockaddr_in_bytes(0)),
        Step::Sys(bind_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(getsockname_addr(slot(0), ADDR_SLOT).ret(0)),
        Step::Sys(listen(slot(0), 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(5)).ret(0)), // Close control pipe write end
            Step::Sys(socket(LINUX_AF_INET, LINUX_SOCK_STREAM, 0).save(1)),
            Step::Sys(connect_addr(slot(1), ADDR_SLOT).ret(0)),
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
