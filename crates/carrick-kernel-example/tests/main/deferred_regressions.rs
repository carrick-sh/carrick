//! Cross-checks for deferred lifecycle and credential defects through the public backend.

use carrick_abi::{
    LINUX_ECHILD, LINUX_MSG_PEEK, LINUX_SA_NOCLDWAIT, LINUX_SCM_CREDENTIALS, LINUX_SIGCHLD,
    LINUX_SO_PASSCRED, LINUX_SOL_SOCKET,
};
use carrick_kernel_example::{ScriptedBackend, Step, Syscall, await_parked, last_child, slot, sys};

fn parked_parent_observes_autoreap(
    action: Syscall,
) -> Result<(), carrick_kernel_example::ExampleError> {
    let report = ScriptedBackend::new().run_root(vec![
        Step::Sys(action.ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            await_parked(1, "wait4"),
            Step::Sys(sys::exit_group(7)),
        ]),
        // wait(2), NOTES: with SIG_IGN or SA_NOCLDWAIT, wait blocks until
        // the children terminate, then fails with ECHILD.
        Step::Sys(sys::wait4(-1, 0).errno(LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0)),
    ])?;
    assert_eq!(report.exit_code(), 0);
    // The enrollment handshake proves this was a blocked wait, not a poll.
    assert_eq!(report.dispatches_for_tid(1, "wait4"), 2);
    Ok(())
}

#[test]
fn ignored_sigchld_wakes_an_already_parked_parent() {
    parked_parent_observes_autoreap(sys::rt_sigaction_ign(LINUX_SIGCHLD))
        .expect("ignored SIGCHLD wakes parent");
}

#[test]
fn nocldwait_wakes_an_already_parked_parent() {
    let mut action = [0u8; 32];
    action[8..16].copy_from_slice(&LINUX_SA_NOCLDWAIT.to_le_bytes());
    parked_parent_observes_autoreap(sys::rt_sigaction(LINUX_SIGCHLD, &action[..], 0, 8))
        .expect("SA_NOCLDWAIT wakes parent");
}

#[test]
fn sender_credentials_survive_peek_partial_read_and_sender_exit() {
    let mut peek = sys::recvmsg_stream(slot(0), 1, 32, LINUX_MSG_PEEK).ret(1);
    peek.label = "peek";
    let mut remaining = sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1);
    remaining.label = "remaining";
    let report = ScriptedBackend::new()
        .run_root(vec![
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
                Step::Sys(sys::write(slot(1), b"ab").ret(2)),
                Step::Sys(sys::exit_group(0)),
            ]),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::wait4(last_child(), 0)),
            Step::Sys(sys::getsockopt_so_peercred(slot(0)).ret(0)),
            Step::Sys(peek),
            Step::Sys(sys::read(slot(0), 1).ret(1)),
            Step::Sys(remaining),
            Step::Sys(sys::exit_group(0)),
        ])
        .expect("receive data from a reaped sender");
    // unix(7), SO_PEERCRED: identity at socketpair creation, unchanged by fork.
    let peer = report.output("getsockopt");
    assert_eq!(i32::from_le_bytes(peer[..4].try_into().unwrap()), 1);
    // recv(2), MSG_PEEK does not remove the first byte; read(2) consumes it.
    assert_eq!(report.output("read"), b"a");
    for (label, payload) in [("peek", b"a"), ("remaining", b"b")] {
        let outputs = report.outputs_for(label);
        let data = outputs.iter().find(|out| out.tag == Some("iov")).unwrap();
        assert_eq!(data.bytes, payload);
        let control = &outputs
            .iter()
            .find(|out| out.tag == Some("control"))
            .unwrap()
            .bytes;
        // unix(7), SCM_CREDENTIALS: credentials belong to the sender of these
        // bytes, even after its exit, rather than to the socket creator.
        assert_eq!(
            i32::from_le_bytes(control[8..12].try_into().unwrap()),
            LINUX_SOL_SOCKET
        );
        assert_eq!(
            i32::from_le_bytes(control[12..16].try_into().unwrap()),
            LINUX_SCM_CREDENTIALS
        );
        assert_eq!(i32::from_le_bytes(control[16..20].try_into().unwrap()), 2);
    }
}

#[test]
fn default_message_credentials_use_real_gid() {
    use carrick_abi::syscall::nr;
    let report = ScriptedBackend::new()
        .run_root(vec![
            Step::Sys(
                sys::socketpair_stream()
                    .ret(0)
                    .save_out_i32(3, 0, 0)
                    .save_out_i32(3, 1, 1),
            ),
            Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
            Step::Sys(
                Syscall::new(
                    "setresgid",
                    nr::SETRESGID,
                    [
                        303.into(),
                        404.into(),
                        0.into(),
                        0.into(),
                        0.into(),
                        0.into(),
                    ],
                )
                .ret(0),
            ),
            Step::Sys(sys::write(slot(1), b"x").ret(1)),
            Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1)),
            Step::Sys(sys::exit_group(0)),
        ])
        .expect("send credentials after changing real and effective group IDs");
    let control = report.output_tagged("control");
    // unix(7), SO_PASSCRED: default credentials contain the sender's real
    // group ID, unlike connection-time SO_PEERCRED's effective group ID.
    assert_eq!(u32::from_le_bytes(control[24..28].try_into().unwrap()), 303);
}

#[test]
fn stream_receive_stops_at_a_sender_credential_boundary() {
    let mut first = sys::recvmsg_stream(slot(0), 2, 32, 0).ret(1);
    first.label = "first_sender";
    let mut second = sys::recvmsg_stream(slot(0), 2, 32, 0).ret(1);
    second.label = "second_sender";
    let report = ScriptedBackend::new()
        .run_root(vec![
            Step::Sys(
                sys::socketpair_stream()
                    .ret(0)
                    .save_out_i32(3, 0, 0)
                    .save_out_i32(3, 1, 1),
            ),
            Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
            Step::Sys(sys::fork()),
            Step::ChildMarker(vec![
                Step::Sys(sys::write(slot(1), b"a").ret(1)),
                Step::Sys(sys::exit_group(0)),
            ]),
            Step::Sys(sys::wait4(last_child(), 0)),
            Step::Sys(sys::write(slot(1), b"b").ret(1)),
            Step::Sys(first),
            Step::Sys(second),
            Step::Sys(sys::exit_group(0)),
        ])
        .expect("different senders cannot share one credential message");
    for (label, payload, sender) in [("first_sender", b"a", 2), ("second_sender", b"b", 1)] {
        let outputs = report.outputs_for(label);
        assert_eq!(
            &outputs
                .iter()
                .find(|out| out.tag == Some("iov"))
                .unwrap()
                .bytes[..payload.len()],
            payload
        );
        let control = &outputs
            .iter()
            .find(|out| out.tag == Some("control"))
            .unwrap()
            .bytes;
        assert_eq!(
            i32::from_le_bytes(control[16..20].try_into().unwrap()),
            sender
        );
    }
}

#[test]
fn failed_copyout_does_not_leave_stale_sender_credentials() {
    use carrick_abi::{LINUX_EFAULT, syscall::nr};
    let report = ScriptedBackend::new()
        .run_root(vec![
            Step::Sys(
                sys::socketpair_stream()
                    .ret(0)
                    .save_out_i32(3, 0, 0)
                    .save_out_i32(3, 1, 1),
            ),
            Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
            Step::Sys(sys::fork()),
            Step::ChildMarker(vec![
                Step::Sys(sys::write(slot(1), b"a").ret(1)),
                Step::Sys(sys::exit_group(0)),
            ]),
            Step::Sys(sys::wait4(last_child(), 0)),
            Step::Sys(sys::write(slot(1), b"b").ret(1)),
            // The host read consumes 'a' before the invalid guest copyout.
            Step::Sys(
                Syscall::new(
                    "read_bad_pointer",
                    nr::READ,
                    [slot(0), 1.into(), 1.into(), 0.into(), 0.into(), 0.into()],
                )
                .errno(LINUX_EFAULT),
            ),
            Step::Sys(sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1)),
            Step::Sys(sys::exit_group(0)),
        ])
        .expect("failed copyout must not desynchronize bytes and sender metadata");
    assert_eq!(report.output_tagged("iov"), b"b");
    let control = report.output_tagged("control");
    assert_eq!(i32::from_le_bytes(control[16..20].try_into().unwrap()), 1);
}

#[test]
fn blocked_socket_write_retains_sender_after_partial_progress() {
    use carrick_abi::LINUX_SO_SNDBUF;
    let payload = vec![b'x'; 131072];
    let mut tail = sys::write(slot(1), b"y").ret(1);
    tail.label = "blocked_tail";
    let mut first = sys::recvmsg_stream(slot(0), payload.len(), 32, 0);
    first.label = "initial_segment";
    let mut last = sys::recvmsg_stream(slot(0), 1, 32, 0).ret(1);
    last.label = "resumed_segment";
    let report = ScriptedBackend::new()
        .run_root(vec![
            Step::Sys(
                sys::socketpair_stream()
                    .ret(0)
                    .save_out_i32(3, 0, 0)
                    .save_out_i32(3, 1, 1),
            ),
            Step::Sys(sys::setsockopt_int(slot(0), LINUX_SOL_SOCKET, LINUX_SO_PASSCRED, 1).ret(0)),
            Step::Sys(sys::setsockopt_int(slot(1), LINUX_SOL_SOCKET, LINUX_SO_SNDBUF, 4096).ret(0)),
            Step::Sys(sys::fork()),
            Step::ChildMarker(vec![
                Step::Sys(sys::close(slot(0)).ret(0)),
                // Socket writes may return a short positive result. The next write
                // must wait for space; its sender must survive that redispatch.
                Step::Sys(sys::write(slot(1), &payload)),
                Step::Sys(tail),
                Step::Sys(sys::exit_group(0)),
            ]),
            Step::Sys(sys::close(slot(1)).ret(0)),
            await_parked(2, "blocked_tail"),
            Step::Sys(first),
            Step::Sys(last),
            Step::Sys(sys::wait4(last_child(), 0)),
            Step::Sys(sys::exit_group(0)),
        ])
        .expect("drain the blocked socket sender");
    let first_write = report
        .completions()
        .iter()
        .find(|c| c.pid == 2 && c.label == "write")
        .unwrap()
        .result
        .unwrap();
    assert!(first_write > 0 && first_write < payload.len() as i64);
    assert_eq!(
        report
            .completions()
            .iter()
            .find(|c| c.label == "initial_segment")
            .unwrap()
            .result,
        Ok(first_write)
    );
    for label in ["initial_segment", "resumed_segment"] {
        let outputs = report.outputs_for(label);
        let control = &outputs
            .iter()
            .find(|o| o.tag == Some("control"))
            .unwrap()
            .bytes;
        assert_eq!(i32::from_le_bytes(control[16..20].try_into().unwrap()), 2);
    }
    assert_eq!(
        report
            .outputs_for("resumed_segment")
            .iter()
            .find(|o| o.tag == Some("iov"))
            .unwrap()
            .bytes,
        b"y"
    );
    assert_eq!(report.dispatches_for_tid(2, "blocked_tail"), 2);
}
