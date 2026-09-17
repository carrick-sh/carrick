//! pidfd semantics conformance tests: exit readiness polling, pidfd_send_signal, reap lifecycle, waitid(P_PIDFD).
//!
//! Authorities: man 2 pidfd_open, man 2 pidfd_send_signal, man 2 poll, man 2 ppoll, man 2 waitid.

use carrick_abi::{LINUX_ESRCH, LINUX_P_PIDFD, LINUX_POLLIN, LINUX_SIGCHLD, LINUX_WEXITED};
use carrick_kernel_example::{ScriptedBackend, Step, await_parked, last_child, slot, sys};

/// `CLD_EXITED` si_code per man 2 sigaction / man 2 waitid.
const CLD_EXITED: i32 = 1;

#[test]
fn a_pidfd_becomes_readable_when_the_process_exits() {
    // man 2 pidfd_open: "A pidfd can be monitored using poll(2), select(2), and epoll(7).
    // When the process that it refers to terminates, these interfaces indicate the file descriptor as readable (POLLIN)."
    // Polling readiness must precede wait4 and does not consume the zombie.
    let script = vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            await_parked(1, "ppoll"),
            Step::Sys(sys::exit_group(42)),
        ]),
        // Parent opens pidfd for child
        Step::Sys(sys::pidfd_open(last_child(), 0).save(0)),
        // Parent polls on the pidfd: parks until child terminates, returns 1
        Step::Sys(sys::ppoll_one(slot(0), LINUX_POLLIN, None).ret(1)),
        // Polling readiness does not reap the zombie; wait4 still succeeds and retrieves the exit code
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // ppoll parked on wait service and completed on child termination: dispatched exactly twice
    assert_eq!(
        run.dispatches_for(1, "ppoll"),
        2,
        "a parked ppoll is dispatched exactly twice"
    );

    // struct pollfd { int fd; short events; short revents; }
    let pfd_bytes = run.output_tagged("pollfd");
    let revents = i16::from_le_bytes(pfd_bytes[6..8].try_into().unwrap());
    assert_ne!(
        revents & LINUX_POLLIN,
        0,
        "man 2 pidfd_open: POLLIN reported on child exit"
    );

    // man 2 wait4: WEXITSTATUS(status) == 42
    let status_bytes = run.output("wait4");
    let status = i32::from_le_bytes(status_bytes[0..4].try_into().unwrap());
    assert_eq!((status >> 8) & 0xff, 42, "wait4 reaps child exit status 42");
}

#[test]
fn pidfd_send_signal_kills_the_child() {
    // man 2 pidfd_send_signal: send signal `sig` to the target process referenced by `pidfd`.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(1)).ret(0)),
            // Child parks waiting for input in read, then dies by SIGKILL (9)
            Step::Sys(sys::read(slot(0), 10).death(9)),
        ]),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::pidfd_open(last_child(), 0).save(2)),
        // Await child parking in read
        await_parked(last_child(), "read"),
        // Send SIGKILL (9) via pidfd
        Step::Sys(sys::pidfd_send_signal(slot(2), 9, 0, 0).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // Child died by SIGKILL (9)
    assert_eq!(run.deaths(), &[(2, 9)]);

    // man 2 wait4: WTERMSIG(status) == 9 (encoded in status & 0x7f)
    let status_bytes = run.output("wait4");
    let status = i32::from_le_bytes(status_bytes[0..4].try_into().unwrap());
    assert_eq!(status & 0x7f, 9, "man 2 wait4: WTERMSIG is 9");
}

#[test]
fn pidfd_open_on_a_reaped_pid_is_esrch() {
    // man 2 pidfd_open: ESRCH is returned if the process identified by pid does not exist.
    let script = vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]),
        // Reap child
        Step::Sys(sys::wait4(last_child(), 0)),
        // Child is already reaped and no longer exists -> ESRCH
        Step::Sys(sys::pidfd_open(last_child(), 0).errno(LINUX_ESRCH)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

#[test]
fn waitid_p_pidfd_reaps_through_the_descriptor() {
    // man 2 waitid: idtype == P_PIDFD waits for the child process referred to by the pidfd.
    let script = vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(99))]),
        Step::Sys(sys::pidfd_open(last_child(), 0).save(0)),
        Step::Sys(sys::waitid(LINUX_P_PIDFD as i32, slot(0), LINUX_WEXITED as i32).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // man 2 waitid / man 2 sigaction: siginfo_t layout:
    // offset 0..4: si_signo (SIGCHLD = 17)
    // offset 8..12: si_code (CLD_EXITED = 1)
    // offset 16..20: si_pid (child pid = 2)
    // offset 24..28: si_status (exit code = 99)
    let siginfo_bytes = run.output_tagged("siginfo");
    let si_signo = i32::from_le_bytes(siginfo_bytes[0..4].try_into().unwrap());
    let si_code = i32::from_le_bytes(siginfo_bytes[8..12].try_into().unwrap());
    let si_pid = i32::from_le_bytes(siginfo_bytes[16..20].try_into().unwrap());
    let si_status = i32::from_le_bytes(siginfo_bytes[24..28].try_into().unwrap());

    assert_eq!(si_signo, LINUX_SIGCHLD, "si_signo == SIGCHLD");
    assert_eq!(si_code, CLD_EXITED, "si_code == CLD_EXITED");
    assert_eq!(si_pid, 2, "si_pid == child pid (2)");
    assert_eq!(si_status, 99, "si_status == exit code (99)");
}
