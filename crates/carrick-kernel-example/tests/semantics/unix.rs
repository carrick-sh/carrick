//! AF_UNIX semantics conformance tests: SCM_RIGHTS, SCM_CREDENTIALS, SO_PEERCRED, EOF, EPIPE.
//!
//! Authorities: man 7 unix, man 3 cmsg, man 7 socket, man 2 send, man 2 recvmsg, man 2 getsockopt.

use carrick_abi::{
    LINUX_CMSGHDR_LEN, LINUX_EPERM, LINUX_EPIPE, LINUX_MSG_CTRUNC, LINUX_MSG_NOSIGNAL,
    LINUX_MSG_PEEK, LINUX_SCM_CREDENTIALS, LINUX_SCM_RIGHTS, LINUX_SIGPIPE, LINUX_SO_PASSCRED,
    LINUX_SOL_SOCKET,
};
use carrick_kernel_example::{
    Layout, Operand, RelocWidth, ScriptedBackend, Step, await_parked, last_child, slot, sys,
};

#[test]
fn a_descriptor_passed_over_scm_rights_reads_the_same_pipe() {
    // man 7 unix: "Passing file descriptors": SCM_RIGHTS passes open file descriptions.
    // The received descriptor is allocated as if by dup(2), i.e. the lowest unused file descriptor in the receiver.
    let script = vec![
        // Parent creates a pipe: slot 0 (read end), slot 1 (write end)
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        // Parent creates a UNIX domain socketpair: slot 2 (parent end), slot 3 (child end)
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 2)
                .save_out_i32(3, 1, 3),
        ),
        // Send fd 10; the receiver must allocate its own lowest free fd 3.
        Step::Sys(sys::dup3(slot(0), 10, 0).ret(10).save(5)),
        // Parent writes data to the pipe write end
        Step::Sys(sys::write(slot(1), b"hello SCM_RIGHTS").ret(16)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Close both inherited pipe readers and the socketpair parent end.
            Step::Sys(sys::close(slot(5)).ret(0)),
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(2)).ret(0)),
            // Child receives the passed pipe read descriptor over socketpair end (slot 3)
            // Control message length for 1 passed fd: 16 (header) + 4 (fd) = 20 (or 24 aligned)
            Step::Sys(
                sys::recvmsg_stream(slot(3), 7, 24, 0)
                    .ret(7)
                    .save_tagged_out_i32("control", LINUX_CMSGHDR_LEN, 4),
            ),
            // Child reads from the received descriptor (slot 4)
            Step::Sys(sys::read(slot(4), 16).ret(16)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(3)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Parent closes socketpair child end (slot 3)
        Step::Sys(sys::close(slot(3)).ret(0)),
        // Parent sends descriptor 10 to the child over slot 2.
        Step::Sys(sys::sendmsg_fds(slot(2), &[slot(5)], b"payload", 0).ret(7)),
        Step::Sys(sys::close(slot(5)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // man 7 unix / man 3 cmsg: validate cmsghdr header and control buffer fields
    let control_bytes = run.output_tagged("control");
    assert!(
        control_bytes.len() >= 20,
        "control message must contain cmsghdr + fd"
    );
    let cmsg_len = u64::from_le_bytes(control_bytes[0..8].try_into().unwrap());
    let cmsg_level = i32::from_le_bytes(control_bytes[8..12].try_into().unwrap());
    let cmsg_type = i32::from_le_bytes(control_bytes[12..16].try_into().unwrap());
    assert_eq!(cmsg_len, 20, "cmsg_len == sizeof(cmsghdr) + sizeof(i32)");
    assert_eq!(cmsg_level, LINUX_SOL_SOCKET, "cmsg_level == SOL_SOCKET");
    assert_eq!(cmsg_type, LINUX_SCM_RIGHTS, "cmsg_type == SCM_RIGHTS");

    // msghdr controllen and flags validation
    let msghdr_bytes = run.output_tagged("msghdr");
    let msg_controllen = u64::from_le_bytes(msghdr_bytes[40..48].try_into().unwrap());
    let msg_flags = u32::from_le_bytes(msghdr_bytes[48..52].try_into().unwrap());
    assert!(msg_controllen >= 20, "msg_controllen reflected in msghdr");
    assert_eq!(
        msg_flags & (LINUX_MSG_CTRUNC as u32),
        0,
        "man 2 recvmsg: MSG_CTRUNC must NOT be set when control buffer has sufficient capacity"
    );

    // man 7 unix: received descriptor is the lowest unused descriptor in the receiver.
    // Stdio occupies 0..2. The child closed its pipe reader (3), socketpair
    // parent end (5), and inherited duplicate (10). Pipe writer (4) and its
    // socketpair end (6) remain open. Thus the new descriptor is 3, not the
    // sender's descriptor 10.
    let received_fd = i32::from_le_bytes(
        control_bytes[LINUX_CMSGHDR_LEN..LINUX_CMSGHDR_LEN + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        received_fd, 3,
        "man 7 unix: received fd in child is lowest free descriptor (fd 3)"
    );

    // Complete byte payload comparison
    assert_eq!(run.output("read"), b"hello SCM_RIGHTS");
    assert_eq!(run.output_tagged("iov"), b"payload");
}

#[test]
fn scm_credentials_carry_the_senders_pid_uid_gid() {
    // man 7 unix / man 3 cmsg: SCM_CREDENTIALS ancillary message carries struct ucred { pid, uid, gid }.
    // When SO_PASSCRED is enabled on the receiver, recvmsg synthesizes the sender's credentials.
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        // Enable SO_PASSCRED on parent's receiving socket (slot 0)
        Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            // Child sends a single byte payload to slot 1
            Step::Sys(sys::sendto(slot(1), b"C", 0).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // Parent receives the byte and ancillary SCM_CREDENTIALS message (cmsg_len = 16 + 12 = 28 bytes)
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    let control_bytes = run.output_tagged("control");
    assert!(
        control_bytes.len() >= 28,
        "control message must contain cmsghdr + ucred"
    );

    // man 3 cmsg / man 7 unix: cmsghdr fields
    let cmsg_len = u64::from_le_bytes(control_bytes[0..8].try_into().unwrap());
    let cmsg_level = i32::from_le_bytes(control_bytes[8..12].try_into().unwrap());
    let cmsg_type = i32::from_le_bytes(control_bytes[12..16].try_into().unwrap());
    assert_eq!(cmsg_len, 28, "cmsg_len == sizeof(cmsghdr) + sizeof(ucred)");
    assert_eq!(cmsg_level, LINUX_SOL_SOCKET, "cmsg_level == SOL_SOCKET");
    assert_eq!(
        cmsg_type, LINUX_SCM_CREDENTIALS,
        "cmsg_type == SCM_CREDENTIALS"
    );

    // struct ucred { pid_t pid; uid_t uid; gid_t gid; }
    let pid = i32::from_le_bytes(control_bytes[16..20].try_into().unwrap());
    let uid = u32::from_le_bytes(control_bytes[20..24].try_into().unwrap());
    let gid = u32::from_le_bytes(control_bytes[24..28].try_into().unwrap());

    // The sender is child (PID 2 in harness numbering), root credentials (0, 0)
    assert_eq!(
        pid, 2,
        "man 7 unix: ucred.pid reflects sender's Linux task pid"
    );
    assert_eq!(uid, 0, "ucred.uid == 0");
    assert_eq!(gid, 0, "ucred.gid == 0");
}

#[test]
fn scm_credentials_tracks_multiple_forked_senders_and_preserves_so_peercred() {
    // man 7 unix / man 7 socket:
    // SCM_CREDENTIALS tracks the exact sender process per message across forks,
    // while SO_PEERCRED remains stable to the socketpair creator identity (parent PID 1).
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        // Enable SO_PASSCRED on parent's receiving socket (slot 0)
        Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
        // Fork child 1 (PID 2)
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"1", 0).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Fork child 2 (PID 3)
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"2", 0).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Parent closes child end
        Step::Sys(sys::close(slot(1)).ret(0)),
        // Verify SO_PEERCRED before any recvmsg returns creator PID 1
        Step::Sys(sys::getsockopt_so_peercred(slot(0)).ret(0)),
        // Parent receives the first message (either child may send first)
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1)),
        // Verify SO_PEERCRED between recvmsgs still returns creator PID 1
        Step::Sys(sys::getsockopt_so_peercred(slot(0)).ret(0)),
        // Parent receives the second message (from the other child)
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1)),
        // Verify SO_PEERCRED after all recvmsgs still returns creator PID 1
        Step::Sys(sys::getsockopt_so_peercred(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(-1, 0)),
        Step::Sys(sys::wait4(-1, 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // Verify SO_PEERCRED results: all 3 queries must return creator PID 1
    let optval_outputs = run.outputs_for("getsockopt");
    let peercred_outputs: Vec<_> = optval_outputs
        .into_iter()
        .filter(|o| o.tag == Some("optval"))
        .collect();
    assert_eq!(peercred_outputs.len(), 3);
    for out in peercred_outputs {
        let pid = i32::from_le_bytes(out.bytes[0..4].try_into().unwrap());
        let uid = u32::from_le_bytes(out.bytes[4..8].try_into().unwrap());
        let gid = u32::from_le_bytes(out.bytes[8..12].try_into().unwrap());
        assert_eq!(pid, 1, "SO_PEERCRED must remain creator PID 1");
        assert_eq!(uid, 0);
        assert_eq!(gid, 0);
    }

    // Verify SCM_CREDENTIALS results: match each received payload byte (tag iov)
    // with credentials from that SAME recvmsg (tag control).
    // Child 1 (PID 2) sent b"1", Child 2 (PID 3) sent b"2". Both must be present
    // regardless of arrival order.
    let recvmsg_outputs = run.outputs_for("recvmsg");
    let iov_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .filter(|o| o.tag == Some("iov"))
        .collect();
    let control_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .filter(|o| o.tag == Some("control"))
        .collect();
    assert_eq!(iov_outputs.len(), 2, "must receive exactly 2 messages");
    assert_eq!(
        control_outputs.len(),
        2,
        "must receive exactly 2 control headers"
    );

    let mut seen_child1 = false;
    let mut seen_child2 = false;

    for (iov, control) in iov_outputs.iter().zip(control_outputs.iter()) {
        assert_eq!(iov.bytes.len(), 1);
        let pid = i32::from_le_bytes(control.bytes[16..20].try_into().unwrap());
        let uid = u32::from_le_bytes(control.bytes[20..24].try_into().unwrap());
        let gid = u32::from_le_bytes(control.bytes[24..28].try_into().unwrap());
        assert_eq!(uid, 0, "ucred.uid must be 0");
        assert_eq!(gid, 0, "ucred.gid must be 0");

        match iov.bytes[0] {
            b'1' => {
                assert_eq!(
                    pid, 2,
                    "Message carrying payload '1' credentials must reflect Child 1 (PID 2)"
                );
                seen_child1 = true;
            }
            b'2' => {
                assert_eq!(
                    pid, 3,
                    "Message carrying payload '2' credentials must reflect Child 2 (PID 3)"
                );
                seen_child2 = true;
            }
            other => panic!("Unexpected payload byte: {other}"),
        }
    }

    assert!(
        seen_child1,
        "Must have received message from Child 1 (PID 2)"
    );
    assert!(
        seen_child2,
        "Must have received message from Child 2 (PID 3)"
    );
}

#[test]
fn scm_credentials_synthesized_for_plain_write() {
    // man 7 unix / man 7 socket: When SO_PASSCRED is enabled on the receiver,
    // SCM_CREDENTIALS is synthesized even if the sender used ordinary write(2).
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::write(slot(1), b"W").ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    let control_bytes = run.output_tagged("control");
    assert!(control_bytes.len() >= 28);
    let pid = i32::from_le_bytes(control_bytes[16..20].try_into().unwrap());
    let uid = u32::from_le_bytes(control_bytes[20..24].try_into().unwrap());
    let gid = u32::from_le_bytes(control_bytes[24..28].try_into().unwrap());
    assert_eq!(
        pid, 2,
        "SCM_CREDENTIALS on plain write reflects child sender PID 2"
    );
    assert_eq!(uid, 0);
    assert_eq!(gid, 0);
    assert_eq!(run.output_tagged("iov"), b"W");
}

#[test]
fn scm_credentials_peek_does_not_consume() {
    // man 2 recvmsg / man 7 unix: MSG_PEEK returns data and ancillary credentials without consuming them from the queue.
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"P", 0).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // First recvmsg with MSG_PEEK
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, LINUX_MSG_PEEK).ret(1)),
        // Second recvmsg without MSG_PEEK
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    let recvmsg_outputs = run.outputs_for("recvmsg");
    let control_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .copied()
        .filter(|o| o.tag == Some("control"))
        .collect();
    assert_eq!(
        control_outputs.len(),
        2,
        "both peek and non-peek received control message"
    );

    let pid_peek = i32::from_le_bytes(control_outputs[0].bytes[16..20].try_into().unwrap());
    let pid_nonpeek = i32::from_le_bytes(control_outputs[1].bytes[16..20].try_into().unwrap());
    assert_eq!(pid_peek, 2, "peek received sender PID 2");
    assert_eq!(pid_nonpeek, 2, "subsequent non-peek received sender PID 2");

    let iov_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .copied()
        .filter(|o| o.tag == Some("iov"))
        .collect();
    assert_eq!(iov_outputs.len(), 2);
    assert_eq!(iov_outputs[0].bytes, b"P");
    assert_eq!(iov_outputs[1].bytes, b"P");
}

#[test]
fn so_peercred_names_the_peer_process() {
    // man 7 socket / man 7 unix: SO_PEERCRED returns the credentials of the peer socket as set at creation time.
    // For a socketpair created in the parent before fork, both ends reflect the creator's identity (parent pid).
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Child queries SO_PEERCRED on slot 1
            Step::Sys(sys::getsockopt_so_peercred(slot(1)).ret(0)),
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Parent queries SO_PEERCRED on slot 0
        Step::Sys(sys::getsockopt_so_peercred(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    let optval_outputs = run.outputs_for("getsockopt");
    let matching_outputs: Vec<_> = optval_outputs
        .into_iter()
        .filter(|o| o.tag == Some("optval"))
        .collect();
    assert_eq!(
        matching_outputs.len(),
        2,
        "both parent and child called getsockopt"
    );

    for output in matching_outputs {
        let pid = i32::from_le_bytes(output.bytes[0..4].try_into().unwrap());
        let uid = u32::from_le_bytes(output.bytes[4..8].try_into().unwrap());
        let gid = u32::from_le_bytes(output.bytes[8..12].try_into().unwrap());
        // Creator of both ends of the socketpair is the parent (PID 1)
        assert_eq!(
            pid, 1,
            "man 7 socket: SO_PEERCRED on socketpair reflects creator identity"
        );
        assert_eq!(uid, 0);
        assert_eq!(gid, 0);
    }
}

#[test]
fn recv_on_a_stream_socket_whose_peer_closed_returns_zero() {
    // man 2 recv / man 7 unix: When a stream socket peer has performed an orderly shutdown or closed, read/recv returns 0 (EOF).
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        // Child closed its end; read on slot 0 must return 0 immediately
        Step::Sys(sys::read(slot(0), 10).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn send_after_peer_close_is_epipe_with_msg_nosignal() {
    // man 2 send: EPIPE is returned when the local socket is shut down or peer is closed, and MSG_NOSIGNAL suppresses SIGPIPE.
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        // Peer is closed; send with MSG_NOSIGNAL returns EPIPE without signal termination
        Step::Sys(sys::sendto(slot(0), b"ping", LINUX_MSG_NOSIGNAL).errno(LINUX_EPIPE)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn send_after_peer_close_without_msg_nosignal_terminates_with_sigpipe() {
    // man 2 sendmsg / man 7 unix: When a stream socket peer is closed, sending data without MSG_NOSIGNAL
    // raises SIGPIPE, terminating a non-init process with default signal disposition.
    let iov_data = Operand::Bytes(b"ping".to_vec());
    let iov_layout = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, iov_data)
        .with_u64(8, 4);
    let msghdr = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov_layout)
        .with_u64(24, 1);

    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            // Await parent closing its ends
            await_parked(1, "wait4"),
            // Peer is closed; sendmsg without MSG_NOSIGNAL dies by SIGPIPE (13)
            Step::Sys(sys::sendmsg(slot(1), msghdr, 0).death(LINUX_SIGPIPE)),
        ]),
        // Parent closes its end (slot 0) and socketpair child end (slot 1)
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // Child died by SIGPIPE (13)
    assert_eq!(run.deaths(), &[(2, LINUX_SIGPIPE)]);

    // man 2 wait4: WTERMSIG is 13 (encoded in status & 0x7f)
    let status_bytes = run.output("wait4");
    let status = i32::from_le_bytes(status_bytes[0..4].try_into().unwrap());
    assert_eq!(
        status & 0x7f,
        LINUX_SIGPIPE,
        "man 2 wait4: WTERMSIG is SIGPIPE"
    );
}

#[test]
fn recvmsg_control_truncation_sets_msg_ctrunc() {
    // man 2 recvmsg / man 3 cmsg: If the ancillary buffer is too small to hold all control messages,
    // the MSG_CTRUNC flag is set in msghdr.msg_flags.
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"T", 0).ret(1)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // SCM_CREDENTIALS requires 28 bytes, but we pass control buffer of only 8 bytes
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 8, 0).ret(1)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // Check msg_flags at offset 48 of struct msghdr
    let msghdr_bytes = run.output_tagged("msghdr");
    assert_eq!(msghdr_bytes.len(), 56);
    let msg_flags = u32::from_le_bytes(msghdr_bytes[48..52].try_into().unwrap());
    assert_ne!(
        msg_flags & (LINUX_MSG_CTRUNC as u32),
        0,
        "man 2 recvmsg: MSG_CTRUNC must be set when control buffer is truncated"
    );
}

#[test]
fn scm_credentials_deferred_read_after_sender_exit_and_reap() {
    // Sender writes "ab", then exits and is reaped; parent queries SO_PEERCRED (still creator PID 1),
    // peeks byte "a" (SCM_CREDENTIALS sender PID 2), calls plain read(1) to consume "a",
    // and calls recvmsg(1) for "b" which still carries sender PID 2.
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"ab", 0).ret(2)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // Wait and reap child
        Step::Sys(sys::wait4(last_child(), 0)),
        // SO_PEERCRED remains creator PID 1
        Step::Sys(sys::getsockopt_so_peercred(slot(0)).ret(0)),
        // Peek byte "a"
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, LINUX_MSG_PEEK).ret(1)),
        // Consume byte "a" with plain read
        Step::Sys(sys::read(slot(0), 1).ret(1)),
        // Receive byte "b" with recvmsg; must still carry SCM_CREDENTIALS for sender PID 2
        Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // SO_PEERCRED is PID 1
    let optval_outputs = run.outputs_for("getsockopt");
    let peercred_out = optval_outputs
        .into_iter()
        .find(|o| o.tag == Some("optval"))
        .unwrap();
    let peercred_pid = i32::from_le_bytes(peercred_out.bytes[0..4].try_into().unwrap());
    assert_eq!(peercred_pid, 1, "SO_PEERCRED must remain creator PID 1");

    // recvmsg outputs
    let recvmsg_outputs = run.outputs_for("recvmsg");
    let control_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .copied()
        .filter(|o| o.tag == Some("control"))
        .collect();
    assert_eq!(control_outputs.len(), 2);

    let pid_peek = i32::from_le_bytes(control_outputs[0].bytes[16..20].try_into().unwrap());
    let pid_b = i32::from_le_bytes(control_outputs[1].bytes[16..20].try_into().unwrap());
    assert_eq!(pid_peek, 2, "peek of 'a' carries sender Child PID 2");
    assert_eq!(
        pid_b, 2,
        "recvmsg of 'b' after plain read of 'a' carries sender Child PID 2"
    );

    let iov_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .copied()
        .filter(|o| o.tag == Some("iov"))
        .collect();
    assert_eq!(iov_outputs.len(), 2);
    assert_eq!(iov_outputs[0].bytes, b"a");
    assert_eq!(iov_outputs[1].bytes, b"b");

    let read_outputs = run.outputs_for("read");
    assert_eq!(read_outputs[0].bytes, b"a");
}

#[test]
fn scm_credentials_stream_read_capping_across_multiple_senders() {
    // When SO_PASSCRED is enabled on a stream socket, recvmsg caps the read length
    // at the front sender's chunk boundary, preventing merging data across different senders.
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
        // Child 1 (PID 2) writes "AA"
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"AA", 0).ret(2)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        // Child 2 (PID 3) writes "BB"
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"BB", 0).ret(2)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // Parent requests 4 bytes in recvmsg, but it must be capped to 2 bytes (Child 1's chunk)
        Step::Sys(sys::recvmsg_stream(slot(0), 4, 32, 0).ret(2)),
        // Next recvmsg returns the remaining 2 bytes (Child 2's chunk)
        Step::Sys(sys::recvmsg_stream(slot(0), 4, 32, 0).ret(2)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    let recvmsg_outputs = run.outputs_for("recvmsg");
    let control_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .copied()
        .filter(|o| o.tag == Some("control"))
        .collect();
    assert_eq!(control_outputs.len(), 2);

    let pid1 = i32::from_le_bytes(control_outputs[0].bytes[16..20].try_into().unwrap());
    let pid2 = i32::from_le_bytes(control_outputs[1].bytes[16..20].try_into().unwrap());
    assert_eq!(pid1, 2, "First recvmsg returned Child 1 (PID 2)");
    assert_eq!(pid2, 3, "Second recvmsg returned Child 2 (PID 3)");

    let iov_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .copied()
        .filter(|o| o.tag == Some("iov"))
        .collect();
    assert_eq!(iov_outputs.len(), 2);
    assert_eq!(&iov_outputs[0].bytes[..2], b"AA");
    assert_eq!(&iov_outputs[1].bytes[..2], b"BB");
}

#[test]
fn scm_credentials_explicit_unprivileged_forgery_returns_eperm() {
    // man 7 unix: An unprivileged process that passes SCM_CREDENTIALS specifying a PID/UID/GID
    // it does not own without the required capability receives EPERM.
    let script = vec![
        Step::Sys(
            sys::socketpair_stream()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            // Child (unprivileged non-init task) tries to forge PID 9999
            Step::Sys(sys::sendmsg_creds(slot(1), 9999, 0, 0, b"forged", 0).errno(LINUX_EPERM)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn scm_credentials_zero_length_datagram_and_subsequent_datagram() {
    // Zero-length datagrams queue and consume credential records.
    let script = vec![
        Step::Sys(
            sys::socketpair_dgram()
                .ret(0)
                .save_out_i32(3, 0, 0)
                .save_out_i32(3, 1, 1),
        ),
        Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
        // Child 1 sends 0-byte datagram
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"", 0).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        // Child 2 sends 5-byte datagram "hello"
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::sendto(slot(1), b"hello", 0).ret(5)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // Parent receives 0-byte datagram from Child 1 (PID 2)
        Step::Sys(sys::recvmsg_stream(slot(0), 0, 32, 0).ret(0)),
        // Parent receives 5-byte datagram from Child 2 (PID 3)
        Step::Sys(sys::recvmsg_stream(slot(0), 5, 32, 0).ret(5)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    let recvmsg_outputs = run.outputs_for("recvmsg");
    let control_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .copied()
        .filter(|o| o.tag == Some("control"))
        .collect();
    assert_eq!(control_outputs.len(), 2);

    let pid1 = i32::from_le_bytes(control_outputs[0].bytes[16..20].try_into().unwrap());
    let pid2 = i32::from_le_bytes(control_outputs[1].bytes[16..20].try_into().unwrap());
    assert_eq!(pid1, 2, "0-byte datagram carried Child 1 (PID 2)");
    assert_eq!(pid2, 3, "Second datagram carried Child 2 (PID 3)");

    let iov_outputs: Vec<_> = recvmsg_outputs
        .iter()
        .copied()
        .filter(|o| o.tag == Some("iov"))
        .collect();
    assert_eq!(iov_outputs.len(), 2);
    assert_eq!(iov_outputs[0].bytes, b"");
    assert_eq!(iov_outputs[1].bytes, b"hello");
}
