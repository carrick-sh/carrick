//! Socket receive semantics conformance tests: MSG_ERRQUEUE on in-memory sockets,
//! sockaddr length precedence in recvfrom, msghdr copy-in precedence, and msghdr controllen/flags writeback.
//!
//! Authorities: man 7 ip, man 2 recv, man 2 recvfrom, man 2 recvmsg, man 3 cmsg,
//! Docker oracle receipts in target/conformance/eco-20260917/{socket-contract-oracle.txt,receive-precedence-oracle.txt,receive-output-oracle.txt}.

use carrick_abi::syscall::nr;
use carrick_abi::{
    LINUX_AF_INET, LINUX_EAGAIN, LINUX_EFAULT, LINUX_EINVAL, LINUX_IPPROTO_SCTP,
    LINUX_MSG_CMSG_CLOEXEC, LINUX_MSG_DONTWAIT, LINUX_MSG_ERRQUEUE, LINUX_SOCK_STREAM,
};
use carrick_kernel_example::{
    Layout, Operand, RelocWidth, ScriptedBackend, Step, Syscall, alloc_buffer, slot, sys,
};

/// Helper to build a `recvfrom` syscall with a custom label.
fn recvfrom_labeled(
    label: &'static str,
    fd: impl Into<Operand>,
    len: usize,
    flags: i32,
) -> Syscall {
    Syscall::new(
        label,
        nr::RECVFROM,
        [
            fd.into(),
            Operand::Out(len),
            (len as i64).into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// Helper to build a `recvfrom` syscall with explicit `src_addr` and `addrlen` operands.
fn recvfrom_with_addr(
    label: &'static str,
    fd: impl Into<Operand>,
    len: usize,
    flags: i32,
    src_addr: impl Into<Operand>,
    addrlen: impl Into<Operand>,
) -> Syscall {
    Syscall::new(
        label,
        nr::RECVFROM,
        [
            fd.into(),
            Operand::Out(len),
            (len as i64).into(),
            (flags as i64).into(),
            src_addr.into(),
            addrlen.into(),
        ],
    )
}

/// Helper to build a `recvmsg` syscall with a custom label, tagged iov, and optional control buffer.
fn recvmsg_stream_labeled(
    label: &'static str,
    iov_tag: &'static str,
    msghdr_tag: &'static str,
    fd: impl Into<Operand>,
    iov_len: usize,
    control_len: usize,
    flags: i32,
) -> Syscall {
    let iov_buf = Operand::TaggedOut(iov_tag, iov_len);
    let iov_layout = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, iov_buf)
        .with_u64(8, iov_len as u64);
    let mut msghdr = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov_layout)
        .with_u64(24, 1)
        .with_i32(48, 0x12345678)
        .with_capture(true)
        .with_tag(msghdr_tag);
    if control_len > 0 {
        let control_buf = Operand::TaggedOut("control", control_len);
        msghdr = msghdr
            .with_reloc(32, RelocWidth::U64, control_buf)
            .with_u64(40, control_len as u64);
    }
    Syscall::new(
        label,
        nr::RECVMSG,
        [
            fd.into(),
            msghdr.into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// Helper to set up a connected AF_INET TCP stream socket pair via loopback.
/// Client socket fd is saved in `client_slot`, server accepted socket fd in `server_slot`.
fn setup_tcp_pair(server_slot: usize, client_slot: usize) -> Vec<Step> {
    setup_stream_pair(server_slot, client_slot, 0)
}

fn setup_stream_pair(server_slot: usize, client_slot: usize, protocol: i32) -> Vec<Step> {
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_le_bytes());
    sa[4..8].copy_from_slice(&[127, 0, 0, 1]);

    vec![
        alloc_buffer(11, sa.to_vec()),
        // 1. Create listener socket (slot 10)
        Step::Sys(
            Syscall::new(
                "socket_listen",
                nr::SOCKET,
                [
                    (LINUX_AF_INET as i64).into(),
                    (LINUX_SOCK_STREAM as i64).into(),
                    (protocol as i64).into(),
                    0.into(),
                    0.into(),
                    0.into(),
                ],
            )
            .save(10),
        ),
        // Bind an available loopback port and retain its exact sockaddr for connect.
        Step::Sys(
            Syscall::new(
                "bind_listen",
                nr::BIND,
                [slot(10), slot(11), 16.into(), 0.into(), 0.into(), 0.into()],
            )
            .ret(0),
        ),
        Step::Sys(
            Syscall::new(
                "listener_name",
                nr::GETSOCKNAME,
                [
                    slot(10),
                    slot(11),
                    Operand::InOut(16u32.to_ne_bytes().to_vec()),
                    0.into(),
                    0.into(),
                    0.into(),
                ],
            )
            .ret(0),
        ),
        // 3. Listen on socket
        Step::Sys(
            Syscall::new(
                "listen",
                nr::LISTEN,
                [slot(10), 5.into(), 0.into(), 0.into(), 0.into(), 0.into()],
            )
            .ret(0),
        ),
        // 4. Create client socket (slot client_slot)
        Step::Sys(
            Syscall::new(
                "socket_client",
                nr::SOCKET,
                [
                    (LINUX_AF_INET as i64).into(),
                    (LINUX_SOCK_STREAM as i64).into(),
                    (protocol as i64).into(),
                    0.into(),
                    0.into(),
                    0.into(),
                ],
            )
            .save(client_slot),
        ),
        // Connect to the port allocated by bind.
        Step::Sys(
            Syscall::new(
                "connect_client",
                nr::CONNECT,
                [
                    slot(client_slot),
                    slot(11),
                    16.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                ],
            )
            .ret(0),
        ),
        // 6. Accept incoming connection on listener socket (slot server_slot)
        Step::Sys(
            Syscall::new(
                "accept_server",
                nr::ACCEPT,
                [slot(10), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
            )
            .save(server_slot),
        ),
        // 7. Close listener socket (slot 10)
        Step::Sys(sys::close(slot(10)).ret(0)),
    ]
}

// Native Linux's SCTP SOCK_STREAM returns a source sockaddr, unlike TCP.
// See stream-protocol-output-oracle.txt in the discovery evidence directory.
// This pins the protocol boundary only; SCTP record completion is a separate gap.
#[allow(clippy::expect_used)] // Shared assertion helper for the two tests below.
fn assert_sctp_source(use_recvmsg: bool) {
    let payload = b"sctp source";
    let mut script = setup_stream_pair(0, 1, LINUX_IPPROTO_SCTP);
    script.push(Step::Sys(
        Syscall::new(
            "peer_name",
            nr::GETPEERNAME,
            [
                slot(0),
                Operand::TaggedOut("peer", 16),
                Operand::InOut(16u32.to_ne_bytes().to_vec()),
                0.into(),
                0.into(),
                0.into(),
            ],
        )
        .ret(0),
    ));
    script.push(Step::Sys(
        sys::write(slot(1), payload).ret(payload.len() as i64),
    ));
    let receive = if use_recvmsg {
        let iov = Layout::new(16)
            .with_reloc(0, RelocWidth::U64, Operand::TaggedOut("payload", 64))
            .with_u64(8, 64);
        let header = Layout::new(56)
            .with_reloc(0, RelocWidth::U64, Operand::TaggedOut("source", 128))
            .with_u32(8, 128)
            .with_reloc(16, RelocWidth::U64, iov)
            .with_u64(24, 1)
            .with_capture(true)
            .with_tag("header");
        sys::recvmsg(slot(0), header, 0)
    } else {
        recvfrom_with_addr(
            "sctp_recvfrom",
            slot(0),
            64,
            0,
            Operand::TaggedOut("source", 128),
            Operand::TaggedInOut("source_len", 128u32.to_ne_bytes().to_vec()),
        )
    };
    script.extend([
        Step::Sys(receive.ret(payload.len() as i64)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("SCTP source receive");
    let length = if use_recvmsg {
        &run.output_tagged("header")[8..12]
    } else {
        run.output_tagged("source_len")
    };
    assert_eq!(length, &16u32.to_ne_bytes());
    assert_eq!(
        &run.output_tagged("source")[..16],
        run.output_tagged("peer")
    );
    let received = if use_recvmsg {
        run.output_tagged("payload")
    } else {
        run.output("sctp_recvfrom")
    };
    assert_eq!(&received[..payload.len()], payload);
}

#[test]
fn sctp_recvfrom_preserves_source_address() {
    assert_sctp_source(false);
}

#[test]
fn sctp_recvmsg_preserves_source_address() {
    assert_sctp_source(true);
}

#[test]
fn sctp_recvmsg_message_boundaries_and_eor() {
    let mut script = setup_stream_pair(0, 1, LINUX_IPPROTO_SCTP);

    // 1. Full message receive sets MSG_EOR
    let msg1 = b"full message 1";
    script.push(Step::Sys(
        sys::sendto(slot(1), msg1, 0).ret(msg1.len() as i64),
    ));
    let iov1 = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, Operand::TaggedOut("payload1", 64))
        .with_u64(8, 64);
    let header1 = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov1)
        .with_u64(24, 1)
        .with_capture(true)
        .with_tag("header1");
    script.push(Step::Sys(
        sys::recvmsg(slot(0), header1, 0).ret(msg1.len() as i64),
    ));

    // 2. Partial reads: short read omits EOR, completing read sets EOR
    let msg2 = b"0123456789"; // 10 bytes
    script.push(Step::Sys(
        sys::sendto(slot(1), msg2, 0).ret(msg2.len() as i64),
    ));
    let iov2_part1 = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, Operand::TaggedOut("payload2_1", 4))
        .with_u64(8, 4);
    let header2_part1 = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov2_part1)
        .with_u64(24, 1)
        .with_capture(true)
        .with_tag("header2_1");
    script.push(Step::Sys(sys::recvmsg(slot(0), header2_part1, 0).ret(4)));

    let iov2_part2 = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, Operand::TaggedOut("payload2_2", 64))
        .with_u64(8, 64);
    let header2_part2 = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov2_part2)
        .with_u64(24, 1)
        .with_capture(true)
        .with_tag("header2_2");
    script.push(Step::Sys(sys::recvmsg(slot(0), header2_part2, 0).ret(6)));

    // 3. Two queued messages retain two separate boundaries
    let msg3_a = b"first"; // 5 bytes
    let msg3_b = b"second"; // 6 bytes
    script.push(Step::Sys(
        sys::sendto(slot(1), msg3_a, 0).ret(msg3_a.len() as i64),
    ));
    script.push(Step::Sys(
        sys::sendto(slot(1), msg3_b, 0).ret(msg3_b.len() as i64),
    ));

    let iov3_a = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, Operand::TaggedOut("payload3_a", 64))
        .with_u64(8, 64);
    let header3_a = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov3_a)
        .with_u64(24, 1)
        .with_capture(true)
        .with_tag("header3_a");
    script.push(Step::Sys(sys::recvmsg(slot(0), header3_a, 0).ret(5)));

    let iov3_b = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, Operand::TaggedOut("payload3_b", 64))
        .with_u64(8, 64);
    let header3_b = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov3_b)
        .with_u64(24, 1)
        .with_capture(true)
        .with_tag("header3_b");
    script.push(Step::Sys(sys::recvmsg(slot(0), header3_b, 0).ret(6)));

    script.extend([
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("SCTP EOR run");

    assert_eq!(run.exit_code(), 0);

    // 1. Verify full message EOR
    let flags1 = u32::from_ne_bytes(run.output_tagged("header1")[48..52].try_into().unwrap());
    assert_ne!(
        flags1 & carrick_abi::LINUX_MSG_EOR as u32,
        0,
        "full message recvmsg must set MSG_EOR"
    );
    assert_eq!(&run.output_tagged("payload1")[..msg1.len()], msg1);

    // 2. Verify partial read EOR
    let flags2_1 = u32::from_ne_bytes(run.output_tagged("header2_1")[48..52].try_into().unwrap());
    assert_eq!(
        flags2_1 & carrick_abi::LINUX_MSG_EOR as u32,
        0,
        "partial recvmsg before record end must NOT set MSG_EOR"
    );
    assert_eq!(&run.output_tagged("payload2_1")[..4], b"0123");

    let flags2_2 = u32::from_ne_bytes(run.output_tagged("header2_2")[48..52].try_into().unwrap());
    assert_ne!(
        flags2_2 & carrick_abi::LINUX_MSG_EOR as u32,
        0,
        "completing recvmsg at record end must set MSG_EOR"
    );
    assert_eq!(&run.output_tagged("payload2_2")[..6], b"456789");

    // 3. Verify two queued messages retain separate boundaries
    let flags3_a = u32::from_ne_bytes(run.output_tagged("header3_a")[48..52].try_into().unwrap());
    assert_ne!(
        flags3_a & carrick_abi::LINUX_MSG_EOR as u32,
        0,
        "first queued message must set MSG_EOR"
    );
    assert_eq!(&run.output_tagged("payload3_a")[..5], msg3_a);

    let flags3_b = u32::from_ne_bytes(run.output_tagged("header3_b")[48..52].try_into().unwrap());
    assert_ne!(
        flags3_b & carrick_abi::LINUX_MSG_EOR as u32,
        0,
        "second queued message must set MSG_EOR"
    );
    assert_eq!(&run.output_tagged("payload3_b")[..6], msg3_b);
}

#[test]
fn tcp_recvfrom_ignores_source_pointer_for_payload_and_eof() {
    let mut script = setup_tcp_pair(0, 1);
    script.extend([
        Step::Sys(sys::write(slot(1), b"abc").ret(3)),
        Step::Sys(
            recvfrom_with_addr(
                "payload",
                slot(0),
                8,
                0,
                1,
                Operand::TaggedInOut("payload_len", 128u32.to_ne_bytes().to_vec()),
            )
            .ret(3),
        ),
        Step::Sys(sys::shutdown(slot(1), 1).ret(0)),
        Step::Sys(
            recvfrom_with_addr(
                "eof",
                slot(0),
                8,
                0,
                1,
                Operand::TaggedInOut("eof_len", 128u32.to_ne_bytes().to_vec()),
            )
            .ret(0),
        ),
        Step::Sys(sys::exit_group(0)),
    ]);
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("TCP source pointer");
    assert_eq!(&run.output("payload")[..3], b"abc");
    assert_eq!(run.output_tagged("payload_len"), &0u32.to_ne_bytes());
    assert_eq!(run.output_tagged("eof_len"), &0u32.to_ne_bytes());
}

#[test]
fn tcp_recvmsg_ignores_source_pointer() {
    let mut script = setup_tcp_pair(0, 1);
    let iov = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, Operand::TaggedOut("payload", 8))
        .with_u64(8, 8);
    let header = Layout::new(56)
        .with_u64(0, 1)
        .with_u32(8, 128)
        .with_reloc(16, RelocWidth::U64, iov)
        .with_u64(24, 1)
        .with_capture(true)
        .with_tag("header");
    script.extend([
        Step::Sys(sys::write(slot(1), b"abc").ret(3)),
        Step::Sys(sys::recvmsg(slot(0), header, 0).ret(3)),
        Step::Sys(sys::exit_group(0)),
    ]);
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("TCP recvmsg source pointer");
    assert_eq!(&run.output_tagged("payload")[..3], b"abc");
    assert_eq!(&run.output_tagged("header")[8..12], &0u32.to_ne_bytes());
}

#[test]
fn sctp_connect_preserves_client_and_accepted_protocol_identity() {
    let mut script = setup_stream_pair(0, 1, LINUX_IPPROTO_SCTP);
    for (fd, tag) in [(0, "accepted_protocol"), (1, "client_protocol")] {
        script.push(Step::Sys(
            Syscall::new(
                "protocol",
                nr::GETSOCKOPT,
                [
                    slot(fd),
                    1.into(),
                    38.into(),
                    Operand::TaggedOut(tag, 4),
                    Operand::InOut(4u32.to_ne_bytes().to_vec()),
                    0.into(),
                ],
            )
            .ret(0),
        ));
    }
    script.push(Step::Sys(sys::exit_group(0)));
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("SCTP identity");
    for tag in ["accepted_protocol", "client_protocol"] {
        assert_eq!(run.output_tagged(tag), &LINUX_IPPROTO_SCTP.to_ne_bytes());
    }
}

#[test]
fn sctp_unread_close_preserves_peer_reset() {
    // Both native Linux and the previous transport return ECONNRESET here.
    // Retaining SCTP identity must not switch its carrier to Unix close rules.
    let mut script = setup_stream_pair(0, 1, LINUX_IPPROTO_SCTP);
    script.extend([
        Step::Sys(sys::write(slot(1), b"unread").ret(6)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(
            recvfrom_labeled("reset", slot(1), 8, LINUX_MSG_DONTWAIT)
                .errno(carrick_abi::LINUX_ECONNRESET),
        ),
        Step::Sys(sys::exit_group(0)),
    ]);
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("SCTP unread close");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn tcp_recv_empty_errqueue_returns_eagain_and_preserves_stream_payload() {
    // man 7 ip / man 2 recv / target/conformance/eco-20260917/socket-contract-oracle.txt:
    // On TCP (AF_INET), MSG_ERRQUEUE returns EAGAIN when error queue is empty.
    // Ordinary stream data must NOT be returned or consumed by MSG_ERRQUEUE.
    let payload = b"stream data for tcp errqueue test";
    let mut script = setup_tcp_pair(0, 1);
    script.extend(vec![
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        Step::Sys(
            recvfrom_labeled("recv_errqueue", slot(0), 64, LINUX_MSG_ERRQUEUE).errno(LINUX_EAGAIN),
        ),
        Step::Sys(recvfrom_labeled("recv_data", slot(0), 64, 0).ret(payload.len() as i64)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(
        &run.output("recv_data")[..payload.len()],
        payload,
        "man 2 recv / man 7 ip: MSG_ERRQUEUE must not consume or corrupt normal stream payload"
    );
}

#[test]
fn tcp_recv_empty_errqueue_on_eof_returns_eagain_then_regular_recv_returns_zero() {
    // man 7 ip / man 2 recv:
    // When peer closes connection, empty error queue returns EAGAIN, subsequent recv returns 0.
    let mut script = setup_tcp_pair(0, 1);
    script.extend(vec![
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(
            recvfrom_labeled("recv_errqueue", slot(0), 64, LINUX_MSG_ERRQUEUE).errno(LINUX_EAGAIN),
        ),
        Step::Sys(recvfrom_labeled("recv_eof", slot(0), 64, 0).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn tcp_recvmsg_empty_errqueue_returns_eagain_and_preserves_stream_payload() {
    // man 7 ip / man 2 recvmsg / LTP recvmsg01:
    // recvmsg with MSG_ERRQUEUE on TCP returns EAGAIN on empty error queue
    // and preserves stream bytes for subsequent recvmsg.
    let payload = b"recvmsg tcp errqueue stream data";
    let mut script = setup_tcp_pair(0, 1);
    script.extend(vec![
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        Step::Sys(
            recvmsg_stream_labeled(
                "recvmsg_errqueue",
                "iov_errqueue",
                "msghdr_errqueue",
                slot(0),
                64,
                0,
                LINUX_MSG_ERRQUEUE,
            )
            .errno(LINUX_EAGAIN),
        ),
        Step::Sys(
            recvmsg_stream_labeled("recvmsg_data", "iov_data", "msghdr_data", slot(0), 64, 0, 0)
                .ret(payload.len() as i64),
        ),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(&run.output_tagged("iov_data")[..payload.len()], payload);
}

#[test]
fn tcp_recvmsg_long_ancillary_buffer_zeroes_msg_controllen_and_msg_flags() {
    // man 2 recvmsg / man 3 cmsg / CPython test_socket.RecvmsgTCPTest.testRecvmsgLongAncillaryBuf / target/conformance/eco-20260917/receive-output-oracle.txt:
    // When TCP recvmsg receives data without ancillary messages, msg_controllen must be written back to 0,
    // msg_flags must be written back to 0 (overwriting nonzero sentinel).
    let payload = b"cpython tcp recvmsg test";
    let iov_buf = Operand::TaggedOut("iov", 64);
    let iov_layout = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, iov_buf)
        .with_u64(8, 64);
    let control_buf = Operand::TaggedOut("control", 4096);
    let msghdr = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov_layout)
        .with_u64(24, 1)
        .with_reloc(32, RelocWidth::U64, control_buf)
        .with_u64(40, 4096)
        .with_i32(48, 0x12345678) // Nonzero sentinel to verify overwrite
        .with_capture(true)
        .with_tag("msghdr");

    let mut script = setup_tcp_pair(0, 1);
    script.extend(vec![
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        Step::Sys(
            Syscall::new(
                "recvmsg_long_ctrl",
                nr::RECVMSG,
                [
                    slot(0),
                    msghdr.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                ],
            )
            .ret(payload.len() as i64),
        ),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(&run.output_tagged("iov")[..payload.len()], payload);

    let msghdr_bytes = run.output_tagged("msghdr");
    assert_eq!(msghdr_bytes.len(), 56, "msghdr buffer captured");
    let msg_controllen = u64::from_le_bytes(msghdr_bytes[40..48].try_into().unwrap());
    let msg_flags = u32::from_le_bytes(msghdr_bytes[48..52].try_into().unwrap());
    assert_eq!(
        msg_controllen, 0,
        "man 2 recvmsg: msg_controllen must be set to 0 when no ancillary data is returned"
    );
    assert_eq!(
        msg_flags, 0,
        "man 2 recvmsg: msg_flags must be overwritten to 0 for standard stream receive (sentinel cleared)"
    );
}

#[test]
fn tcp_recvmsg_cmsg_cloexec_echoes_in_msg_flags() {
    // man 2 recvmsg / target/conformance/eco-20260917/receive-output-oracle.txt:
    // MSG_CMSG_CLOEXEC (0x40000000 = 1073741824) is echoed in msg_flags upon return.
    let payload = b"tcp cloexec test";
    let mut script = setup_tcp_pair(0, 1);
    script.extend(vec![
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        Step::Sys(
            recvmsg_stream_labeled(
                "recvmsg_cloexec",
                "iov",
                "msghdr",
                slot(0),
                64,
                4096,
                LINUX_MSG_CMSG_CLOEXEC,
            )
            .ret(payload.len() as i64),
        ),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    let msghdr_bytes = run.output_tagged("msghdr");
    let msg_flags = u32::from_le_bytes(msghdr_bytes[48..52].try_into().unwrap());
    assert_eq!(
        msg_flags, LINUX_MSG_CMSG_CLOEXEC as u32,
        "man 2 recvmsg: MSG_CMSG_CLOEXEC must be echoed in msg_flags and sentinel overwritten"
    );
}

#[test]
fn tcp_recvmsg_bad_iovec_pointer_returns_efault_before_errqueue() {
    // target/conformance/eco-20260917/receive-precedence-oracle.txt (lines 19-20):
    // On TCP recvmsg with MSG_ERRQUEUE, an invalid iovec pointer (e.g. 0/1 with iovlen 1)
    // returns EFAULT during copy-in BEFORE MSG_ERRQUEUE EAGAIN.
    let msghdr = Layout::new(56)
        .with_u64(0, 0) // msg_name = NULL
        .with_u32(8, 0) // msg_namelen = 0
        .with_u64(16, 0) // msg_iov = NULL (invalid)
        .with_u64(24, 1); // msg_iovlen = 1
    let mut script = setup_tcp_pair(0, 1);
    script.extend(vec![
        Step::Sys(sys::recvmsg(slot(0), msghdr, LINUX_MSG_ERRQUEUE).errno(LINUX_EFAULT)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn af_unix_recv_errqueue_ignores_flag_and_returns_payload() {
    // target/conformance/eco-20260917/socket-contract-oracle.txt:
    // Linux AF_UNIX ignores MSG_ERRQUEUE; stream payload is returned directly,
    // and subsequent nonblocking recv returns EAGAIN.
    let payload = b"unix socketpair payload";
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        Step::Sys(
            recvfrom_labeled("recv_unix_errqueue", slot(0), 64, LINUX_MSG_ERRQUEUE)
                .ret(payload.len() as i64),
        ),
        Step::Sys(
            recvfrom_labeled("recv_unix_nonblock", slot(0), 64, LINUX_MSG_DONTWAIT)
                .errno(LINUX_EAGAIN),
        ),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(
        &run.output("recv_unix_errqueue")[..payload.len()],
        payload,
        "AF_UNIX: MSG_ERRQUEUE must be ignored and return stream payload"
    );
}

#[test]
fn af_unix_recv_errqueue_on_eof_ignores_flag_and_returns_zero() {
    // Linux AF_UNIX ignores MSG_ERRQUEUE at EOF and returns 0 (EOF).
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(recvfrom_labeled("recv_unix_eof", slot(0), 64, LINUX_MSG_ERRQUEUE).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn recvfrom_empty_socket_invalid_addrlen_returns_eagain() {
    // target/conformance/eco-20260917/receive-precedence-oracle.txt (lines 1-4, 11-14):
    // On an empty nonblocking socket, negative or null addrlen returns EAGAIN
    // because receive fails before attempting copyout.
    let neg_addrlen = (-1i32).to_le_bytes().to_vec();
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        // Empty socket with negative addrlen -> EAGAIN
        Step::Sys(
            recvfrom_with_addr(
                "recv_empty_neg_len",
                slot(0),
                64,
                LINUX_MSG_DONTWAIT,
                Operand::Out(128),
                Operand::InOut(neg_addrlen),
            )
            .errno(LINUX_EAGAIN),
        ),
        // Empty socket with NULL addrlen -> EAGAIN
        Step::Sys(
            recvfrom_with_addr(
                "recv_empty_null_len",
                slot(0),
                64,
                LINUX_MSG_DONTWAIT,
                Operand::Out(128),
                0,
            )
            .errno(LINUX_EAGAIN),
        ),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn recvfrom_queued_data_negative_addrlen_returns_einval_and_consumes_data() {
    // target/conformance/eco-20260917/receive-precedence-oracle.txt (lines 5, 15):
    // When data is queued, negative addrlen causes copyout failure -> EINVAL,
    // and the stream data is consumed so a subsequent nonblocking recv returns EAGAIN.
    let payload = b"negative addrlen test";
    let neg_addrlen = (-1i32).to_le_bytes().to_vec();
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        Step::Sys(
            recvfrom_with_addr(
                "recv_queued_neg_len",
                slot(0),
                64,
                LINUX_MSG_DONTWAIT,
                Operand::Out(128),
                Operand::InOut(neg_addrlen),
            )
            .errno(LINUX_EINVAL),
        ),
        // Subsequent recv observes empty buffer -> EAGAIN
        Step::Sys(
            recvfrom_labeled("recv_after_einval", slot(0), 64, LINUX_MSG_DONTWAIT)
                .errno(LINUX_EAGAIN),
        ),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn recvfrom_queued_data_null_addrlen_returns_efault_and_consumes_data() {
    // target/conformance/eco-20260917/receive-precedence-oracle.txt (lines 6, 16):
    // When data is queued and src_addr != NULL, addrlen == NULL causes copyout failure -> EFAULT,
    // and the stream data is consumed so a subsequent nonblocking recv returns EAGAIN.
    let payload = b"null addrlen test";
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        Step::Sys(
            recvfrom_with_addr(
                "recv_queued_null_len",
                slot(0),
                64,
                LINUX_MSG_DONTWAIT,
                Operand::Out(128),
                0,
            )
            .errno(LINUX_EFAULT),
        ),
        // Subsequent recv observes empty buffer -> EAGAIN
        Step::Sys(
            recvfrom_labeled("recv_after_efault", slot(0), 64, LINUX_MSG_DONTWAIT)
                .errno(LINUX_EAGAIN),
        ),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn tcp_recvfrom_queued_data_errqueue_with_invalid_addrlen_returns_eagain_and_preserves_data() {
    // target/conformance/eco-20260917/receive-precedence-oracle.txt (lines 17-18):
    // On TCP with queued data, MSG_ERRQUEUE returns EAGAIN regardless of invalid addrlen,
    // and the queued stream data is preserved!
    let payload = b"tcp errqueue invalid addrlen";
    let neg_addrlen = (-1i32).to_le_bytes().to_vec();
    let mut script = setup_tcp_pair(0, 1);
    script.extend(vec![
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        // TCP MSG_ERRQUEUE with negative addrlen returns EAGAIN
        Step::Sys(
            recvfrom_with_addr(
                "recv_tcp_errqueue_neg_len",
                slot(0),
                64,
                LINUX_MSG_ERRQUEUE | LINUX_MSG_DONTWAIT,
                Operand::Out(128),
                Operand::InOut(neg_addrlen),
            )
            .errno(LINUX_EAGAIN),
        ),
        // Subsequent ordinary recv reads the preserved stream payload
        Step::Sys(recvfrom_labeled("recv_tcp_preserved", slot(0), 64, 0).ret(payload.len() as i64)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(
        &run.output("recv_tcp_preserved")[..payload.len()],
        payload,
        "TCP MSG_ERRQUEUE must preserve stream data even with invalid addrlen"
    );
}

#[test]
fn recvmsg_invalid_namelen_precedence_over_errqueue_returns_einval() {
    // man 2 recvmsg / LTP recvmsg01 case 8 & 14 / target/conformance/eco-20260917/recvmsg-header-oracle.txt:
    // With non-null msg_name, negative msg_namelen is validated during copy-in and returns EINVAL before checking MSG_ERRQUEUE.
    let iov_buf = Operand::Out(64);
    let iov_layout = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, iov_buf)
        .with_u64(8, 64);
    let name_buf = Operand::Out(128);
    let msghdr = Layout::new(56)
        .with_reloc(0, RelocWidth::U64, name_buf) // msg_name != NULL
        .with_i32(8, -1) // msg_namelen = -1 (invalid)
        .with_reloc(16, RelocWidth::U64, iov_layout)
        .with_u64(24, 1);
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::recvmsg(slot(0), msghdr, LINUX_MSG_ERRQUEUE).errno(LINUX_EINVAL)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn tcp_recvmsg_null_name_negative_namelen_errqueue_returns_eagain() {
    // target/conformance/eco-20260917/recvmsg-header-oracle.txt:
    // With msg_name == NULL, msg_namelen is ignored and TCP recvmsg with MSG_ERRQUEUE returns EAGAIN.
    let iov_buf = Operand::Out(64);
    let iov_layout = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, iov_buf)
        .with_u64(8, 64);
    let msghdr = Layout::new(56)
        .with_u64(0, 0) // msg_name = NULL
        .with_i32(8, -1) // msg_namelen = -1 (ignored when name is NULL)
        .with_reloc(16, RelocWidth::U64, iov_layout)
        .with_u64(24, 1);
    let mut script = setup_tcp_pair(0, 1);
    script.extend(vec![
        Step::Sys(sys::recvmsg(slot(0), msghdr, LINUX_MSG_ERRQUEUE).errno(LINUX_EAGAIN)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn recvfrom_unnamed_socketpair_updates_addrlen_to_zero() {
    // target/conformance/eco-20260917/receive-output-oracle.txt:
    // When receiving from an unnamed Unix socketpair, addrlen is updated to 0.
    let payload = b"socketpair addrlen update";
    let init_addrlen = 128u32.to_le_bytes().to_vec();
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::write(slot(1), payload).ret(payload.len() as i64)),
        Step::Sys(
            recvfrom_with_addr(
                "recvfrom_zero_len",
                slot(0),
                64,
                0,
                Operand::Out(128),
                Operand::TaggedInOut("addrlen", init_addrlen),
            )
            .ret(payload.len() as i64),
        ),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    let updated_addrlen_bytes = run.output_tagged("addrlen");
    let updated_addrlen = u32::from_le_bytes(updated_addrlen_bytes[0..4].try_into().unwrap());
    assert_eq!(
        updated_addrlen, 0,
        "target/conformance/eco-20260917/receive-output-oracle.txt: Unix socketpair recvfrom sets addrlen to 0"
    );
}
