//! The example backend's one end-to-end proof: a Linux process pipes, forks,
//! reads what its child wrote, reaps it and exits -- through
//! `carrick_kernel::dispatch::SyscallDispatcher`, with no VM, no host fork and
//! no guest code. Everything the backend does to make that true is built from
//! `pub` items of `carrick-kernel`, `carrick-hal`, `carrick-guest-mem` and
//! `carrick-abi` alone; this test is red the moment one of them regresses.

use std::time::Instant;

use carrick_abi::{LINUX_EBADF, LINUX_EINVAL};
use carrick_kernel_example::{
    ExampleError, Layout, RelocWidth, ScriptedBackend, Step, WAIT_BOUND, await_parked, in_out,
    last_child, slot, sys, tagged_out,
};

#[test]
fn fork_pipe_wait_through_the_public_surface() {
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::write(slot(1), b"hi").ret(2)),
            Step::Sys(sys::exit_group(7)),
        ]),
        Step::Sys(sys::read(slot(0), 2).ret(2)), // man 7 pipe: read returns the bytes written
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("read"), b"hi");
    assert_eq!(
        run.output("wait4")[0..4],
        7u32.wrapping_shl(8).to_le_bytes()
    ); // man 2 wait4: WEXITSTATUS in bits 8..16
    assert_eq!(run.tasks_started(), 2);
}

/// Two live Linux processes are worth more than any number of single-process
/// cases: the forked child's dispatcher -- itself forked from the root's --
/// forks again, and each level reaps the one below through the kernel graph.
#[test]
fn a_forked_task_can_fork_again() {
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::fork()),
            Step::ChildMarker(vec![
                Step::Sys(sys::write(slot(1), b"deep").ret(4)),
                Step::Sys(sys::exit_group(5)),
            ]),
            Step::Sys(sys::wait4(last_child(), 0)),
            Step::Sys(sys::exit_group(6)),
        ]),
        Step::Sys(sys::read(slot(0), 4).ret(4)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("read"), b"deep");
    // The child's and the root's wait4 complete on different threads; only
    // the set is deterministic.
    let mut statuses: Vec<i32> = run
        .outputs()
        .iter()
        .filter(|o| o.label == "wait4")
        .map(|o| i32::from_le_bytes(o.bytes[0..4].try_into().unwrap()))
        .collect();
    statuses.sort_unstable();
    assert_eq!(statuses, vec![5 << 8, 6 << 8]);
    assert_eq!(run.tasks_started(), 3);
}

/// A lost wake is a failed run, not a hang: the child reads a pipe nobody
/// writes (`WaitOnFds`, re-dispatched) and the parent waits for a child that
/// never exits (`WaitOnHvpatchChild`, re-dispatched). Both must stop at the
/// bound. This test costs `WAIT_BOUND` (5 s) by construction.
#[test]
fn a_lost_wake_fails_inside_the_bound() {
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::read(slot(0), 1).ret(1)),
            Step::Sys(sys::exit_group(1)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let started = Instant::now();
    let error = ScriptedBackend::new()
        .run_root(script)
        .expect_err("a lost wake must fail the run");
    let elapsed = started.elapsed();
    assert!(
        matches!(error, ExampleError::WaitTimedOut("wait4")),
        "expected the parent's wait4 to time out, got: {error}"
    );
    assert!(
        elapsed >= WAIT_BOUND && elapsed < WAIT_BOUND * 3,
        "the bound fired at {elapsed:?}"
    );
}

#[test]
fn successful_errno_expectation_matches() {
    let script = vec![
        Step::Sys(sys::close(999).errno(LINUX_EBADF)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("errno expectation should match");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.completions().len(), 2);
    assert_eq!(run.completions()[0].label, "close");
    assert_eq!(run.completions()[0].result, Err(LINUX_EBADF));
}

#[test]
fn wrong_return_diagnostic_reports_label_pid_and_values() {
    let script = vec![
        Step::Sys(sys::getpid().ret(9999)),
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("wrong return value must fail");
    assert!(
        matches!(
            err,
            ExampleError::Expectation {
                pid: 1,
                label: "getpid",
                ref expected,
                ref actual,
            } if expected == "return value 9999" && actual == "return value 1"
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn wrong_errno_diagnostic_reports_label_pid_and_errnos() {
    let script = vec![
        Step::Sys(sys::close(999).errno(LINUX_EINVAL)),
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("wrong errno must fail");
    assert!(
        matches!(
            err,
            ExampleError::Expectation {
                pid: 1,
                label: "close",
                ref expected,
                ref actual,
            } if expected == "errno 22" && actual == "errno 9"
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn exit_expectation_mismatch_fails() {
    let script = vec![Step::Sys(sys::exit_group(0).ret(999))];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("exit expectation mismatch must fail");
    assert!(
        matches!(
            err,
            ExampleError::Expectation {
                pid: 1,
                label: "exit_group",
                ref expected,
                ref actual,
            } if expected == "return value 999" && actual == "exit code 0"
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn saved_return_reused_as_operand() {
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::getpid().save(2)),
        Step::Sys(sys::write(slot(1), b"ping").ret(4)),
        Step::Sys(sys::read(slot(0), 4).ret(4)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::wait4(slot(2), 1).errno(carrick_abi::LINUX_ECHILD)), // cannot wait on self
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("reused slot should succeed");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("read"), b"ping");
}

#[test]
fn save_ret_on_failed_syscall_rejects() {
    let script = vec![
        Step::Sys(sys::close(999).errno(LINUX_EBADF).save(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("cannot save return on errno");
    assert!(
        matches!(err, ExampleError::Script(msg) if msg.contains("cannot save return value on failed syscall close"))
    );
}

#[test]
fn save_out_i32_out_of_bounds_rejects() {
    let script = vec![
        Step::Sys(sys::pipe2(0).ret(0).save_out_i32(0, 2, 0)), // pipe2 only has 8 bytes (indices 0 and 1)
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("out of bounds save_out_i32 must fail");
    assert!(matches!(err, ExampleError::Script(msg) if msg.contains("exceeds out buffer len 8")));
}

#[test]
fn a_blocked_read_is_dispatched_exactly_twice_when_the_writer_arrives() {
    // Parking, not polling: the read parks once, the kernel wakes it on the write, it restarts once.
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            await_parked(1, "read"),
            Step::Sys(sys::write(slot(1), b"late").ret(4)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::read(slot(0), 4).ret(4)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.output("read"), b"late");
    assert_eq!(
        run.dispatches_for(1, "read"),
        2,
        "a parked read is dispatched exactly twice"
    );
}

#[test]
fn blocking_write_over_pipe_capacity_completes_byte_exact() {
    let payload: Vec<u8> = (0..131072).map(|i| (i % 251) as u8).collect();
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            await_parked(1, "write"),
            // Drain pipe dynamically without hardcoding specific chunk size
            Step::Sys(sys::read(slot(0), 131072)),
            Step::Sys(sys::read(slot(0), 131072)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::write(slot(1), &payload).ret(131072)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    let mut received = Vec::new();
    for (completion, output) in run
        .completions()
        .iter()
        .filter(|c| c.label == "read")
        .zip(run.outputs().iter().filter(|o| o.label == "read"))
    {
        let bytes_read = completion.result.expect("read succeeded") as usize;
        received.extend_from_slice(&output.bytes[..bytes_read]);
    }
    assert_eq!(received.len(), 131072);
    assert_eq!(received, payload);
}

#[test]
fn pselect6_timeout_zeroes_non_null_fd_set() {
    let mut initial_readfds = [0u8; 8];
    initial_readfds[0] = 0x08; // bit 3 set (fd 3)

    let mut timeout = [0u8; 16];
    timeout[8..16].copy_from_slice(&10_000_000u64.to_le_bytes()); // 10ms

    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::pselect6(4, in_out(&initial_readfds), 0, 0, &timeout[..], 0).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("pselect6"), &[0u8; 8]);
}

#[test]
fn sigkill_from_the_parent_terminates_the_child_and_wait4_reports_the_signal() {
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::read(slot(0), 10).death(9))]),
        await_parked(last_child(), "read"),
        Step::Sys(sys::kill(last_child(), 9).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.deaths(), &[(2, 9)]);
    // man 2 wait4: WIFSIGNALED(status) is true and WTERMSIG(status) == 9 (encoded in status & 0x7f)
    assert_eq!(run.output("wait4")[0..4], 9u32.to_le_bytes());
}

#[test]
fn sig_ign_drops_signal_without_terminating() {
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // man 2 rt_sigaction: set SIGUSR1 (10) disposition to SIG_IGN
            Step::Sys(sys::rt_sigaction_ign(10).ret(0)),
            Step::Sys(sys::read(slot(0), 2).ret(2)),
            Step::Sys(sys::exit_group(0)),
        ]),
        await_parked(last_child(), "read"),
        Step::Sys(sys::kill(last_child(), 10).ret(0)),
        Step::Sys(sys::write(slot(1), b"ok").ret(2)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("read"), b"ok");
    // man 2 wait4: child exited normally with exit code 0
    assert_eq!(run.output("wait4")[0..4], 0u32.to_le_bytes());
}

#[test]
fn sigprocmask_blocked_signal_received_by_sigtimedwait() {
    let sigusr1_mask = 1u64 << 9; // SIGUSR1 is signal 10, bit 9
    let script = vec![
        // Block SIGUSR1 on the parent before fork (child inherits mask)
        Step::Sys(sys::rt_sigprocmask_block(sigusr1_mask).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Child waits synchronously for SIGUSR1
            Step::Sys(
                sys::rt_sigtimedwait(sigusr1_mask.to_le_bytes().as_slice(), 0, 0, 8).ret(10), // man 2 rt_sigtimedwait: returns signal number on success
            ),
            Step::Sys(sys::exit_group(0)),
        ]),
        await_parked(last_child(), "rt_sigtimedwait"),
        Step::Sys(sys::kill(last_child(), 10).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("wait4")[0..4], 0u32.to_le_bytes());
}

#[test]
fn sigprocmask_blocked_signal_received_by_signalfd4() {
    let sigusr1_mask = 1u64 << 9; // SIGUSR1 is signal 10, bit 9
    let script = vec![
        // Block SIGUSR1
        Step::Sys(sys::rt_sigprocmask_block(sigusr1_mask).ret(0)),
        Step::Sys(
            sys::signalfd4(-1, sigusr1_mask.to_le_bytes().as_slice(), 8, 0)
                .ret(3)
                .save(0),
        ),
        // Send SIGUSR1 to self (it remains pending because it is blocked)
        Step::Sys(sys::kill(1, 10).ret(0)),
        // Drain the pending blocked signal from the signalfd
        Step::Sys(sys::read(slot(0), 128).ret(128)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    let sfd_bytes = run.output("read");
    assert_eq!(sfd_bytes.len(), 128);
    let ssi_signo = u32::from_le_bytes(sfd_bytes[0..4].try_into().unwrap());
    assert_eq!(ssi_signo, 10); // man 2 signalfd: ssi_signo is signal number
}

#[test]
fn nanosleep_completes_after_its_interval_with_zero_remaining() {
    let start = Instant::now();
    let script = vec![
        Step::Sys(sys::nanosleep_ms(10).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(
        run.dispatches_for(1, "nanosleep"),
        1,
        "sleep completion must not restart the interval"
    );
    assert!(
        start.elapsed() >= std::time::Duration::from_millis(10),
        "nanosleep should sleep for at least requested duration"
    );
}

#[test]
fn clock_nanosleep_completes_after_its_interval() {
    let start = Instant::now();
    let script = vec![
        Step::Sys(sys::clock_nanosleep_ms(carrick_abi::LINUX_CLOCK_MONOTONIC as i32, 0, 10).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(
        run.dispatches_for(1, "clock_nanosleep"),
        1,
        "sleep completion must not restart the interval"
    );
    assert!(
        start.elapsed() >= std::time::Duration::from_millis(10),
        "clock_nanosleep should sleep for at least requested duration"
    );
}

#[test]
fn a_timerfd_read_parks_until_the_timer_fires() {
    let script = vec![
        Step::Sys(
            sys::timerfd_create(carrick_abi::LINUX_CLOCK_MONOTONIC as i32, 0)
                .ret(3)
                .save(0),
        ),
        Step::Sys(sys::timerfd_settime_ms(slot(0), 0, 100, 0).ret(0)),
        Step::Sys(sys::read(slot(0), 8).ret(8)), // man 2 timerfd_create: read returns an 8-byte unsigned integer
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    let count_bytes = run.output("read");
    assert_eq!(count_bytes.len(), 8);
    let expirations = u64::from_le_bytes(count_bytes[0..8].try_into().unwrap());
    assert_eq!(expirations, 1, "man 2 timerfd_create: one-shot expiration");
    assert_eq!(
        run.dispatches_for(1, "read"),
        1,
        "owned TimerFdRead completion must not redispatch"
    );
}

#[test]
fn child_write_to_broken_pipe_terminates_with_sigpipe() {
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        // Remove every reader before fork, so scheduling cannot hide SIGPIPE.
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // man 7 pipe: a write with no readers generates SIGPIPE.
            Step::Sys(sys::write(slot(1), b"hello").death(carrick_abi::LINUX_SIGPIPE)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    // Child terminated with SIGPIPE (13); wait status for WTERMSIG is (13 & 0x7f) = 13
    assert_eq!(
        run.output("wait4")[0..4],
        (carrick_abi::LINUX_SIGPIPE as u32).to_le_bytes()
    );
}

#[test]
fn sigprocmask_blocked_sigchld_received_by_sigtimedwait_with_pid_and_status() {
    const CLD_EXITED: i32 = 1;
    let sigchld_mask = 1u64 << (carrick_abi::LINUX_SIGCHLD - 1);
    let script = vec![
        // Block SIGCHLD on parent
        Step::Sys(sys::rt_sigprocmask_block(sigchld_mask).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            await_parked(1, "rt_sigtimedwait"),
            Step::Sys(sys::exit_group(42)),
        ]),
        // Parent waits synchronously for SIGCHLD via rt_sigtimedwait
        Step::Sys(
            sys::rt_sigtimedwait_siginfo(sigchld_mask).ret(carrick_abi::LINUX_SIGCHLD as i64),
        ),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    let siginfo_bytes = run.output("rt_sigtimedwait");
    assert_eq!(siginfo_bytes.len(), 128);
    let si_signo = i32::from_le_bytes(siginfo_bytes[0..4].try_into().unwrap());
    let si_code = i32::from_le_bytes(siginfo_bytes[8..12].try_into().unwrap());
    let si_pid = i32::from_le_bytes(siginfo_bytes[16..20].try_into().unwrap());
    let si_status = i32::from_le_bytes(siginfo_bytes[24..28].try_into().unwrap());
    assert_eq!(si_signo, carrick_abi::LINUX_SIGCHLD);
    assert_eq!(si_code, CLD_EXITED);
    assert_eq!(si_pid, 2); // child pid is 2
    assert_eq!(si_status, 42); // child exited with code 42
}

#[test]
fn sigprocmask_blocked_sigchld_received_by_signalfd4_with_pid_and_status() {
    const CLD_EXITED: i32 = 1;
    let sigchld_mask = 1u64 << (carrick_abi::LINUX_SIGCHLD - 1);
    let script = vec![
        // Block SIGCHLD on parent
        Step::Sys(sys::rt_sigprocmask_block(sigchld_mask).ret(0)),
        Step::Sys(
            sys::signalfd4(-1, sigchld_mask.to_le_bytes().as_slice(), 8, 0)
                .ret(3)
                .save(0),
        ),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(42))]),
        // Reap child first so child has exited and exit signal/info is published to parent
        Step::Sys(sys::wait4(last_child(), 0)),
        // Drain the pending blocked SIGCHLD from the signalfd
        Step::Sys(sys::read(slot(0), 128).ret(128)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    let sfd_bytes = run.output("read");
    assert_eq!(sfd_bytes.len(), 128);
    let ssi_signo = u32::from_le_bytes(sfd_bytes[0..4].try_into().unwrap());
    let ssi_code = i32::from_le_bytes(sfd_bytes[8..12].try_into().unwrap());
    let ssi_pid = u32::from_le_bytes(sfd_bytes[12..16].try_into().unwrap());
    assert_eq!(ssi_signo, carrick_abi::LINUX_SIGCHLD as u32); // 17
    assert_eq!(ssi_code, CLD_EXITED);
    assert_eq!(ssi_pid, 2); // child pid is 2
}

#[test]
fn layout_relocation_offset_overflow_rejects() {
    let script = vec![
        Step::Sys(sys::sendmsg(1, Layout::new(16).with_u32(usize::MAX, 42), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("offset overflow must return Script error");
    match err {
        ExampleError::Script(msg) => assert!(
            msg.contains("offset overflow"),
            "unexpected error message: {msg}"
        ),
        other => panic!("expected ExampleError::Script, got {other:?}"),
    }
}

#[test]
fn layout_write_outside_layout_bounds_rejects() {
    let script = vec![
        Step::Sys(sys::sendmsg(1, Layout::new(8).with_u32(10, 42), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("OOB write must return Script error");
    match err {
        ExampleError::Script(msg) => assert!(
            msg.contains("exceeds layout size"),
            "unexpected error message: {msg}"
        ),
        other => panic!("expected ExampleError::Script, got {other:?}"),
    }
}

#[test]
fn layout_narrow_integer_overflow_rejects() {
    let script = vec![
        Step::Sys(sys::sendmsg(
            1,
            Layout::new(8).with_reloc(0, RelocWidth::U8, 300),
            0,
        )),
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("narrow integer overflow must return Script error");
    match err {
        ExampleError::Script(msg) => assert!(
            msg.contains("does not fit in width"),
            "unexpected error message: {msg}"
        ),
        other => panic!("expected ExampleError::Script, got {other:?}"),
    }
}

#[test]
fn tagged_save_out_of_bounds_rejects() {
    let script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_tagged_out_i32("missing_tag", 0, 0),
        ),
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("missing tag must return Script error");
    match err {
        ExampleError::Script(msg) => assert!(
            msg.contains("no out buffer with tag"),
            "unexpected error message: {msg}"
        ),
        other => panic!("expected ExampleError::Script, got {other:?}"),
    }

    let script_oob = vec![
        Step::Sys(
            sys::pselect6(0, 0, 0, 0, tagged_out("timespec", 16), 0)
                .ret(0)
                .save_tagged_out_i32("timespec", 32, 0),
        ),
        Step::Sys(sys::exit_group(0)),
    ];
    let err_oob = ScriptedBackend::new()
        .run_root(script_oob)
        .expect_err("tagged out OOB offset must return Script error");
    match err_oob {
        ExampleError::Script(msg) => assert!(
            msg.contains("exceeds out buffer len"),
            "unexpected error message: {msg}"
        ),
        other => panic!("expected ExampleError::Script, got {other:?}"),
    }
}

#[test]
fn duplicate_capture_tags_in_one_syscall_rejects() {
    let script = vec![
        Step::Sys(sys::pselect6(
            0,
            tagged_out("dup_tag", 8),
            tagged_out("dup_tag", 8),
            0,
            0,
            0,
        )),
        Step::Sys(sys::exit_group(0)),
    ];
    let err = ScriptedBackend::new()
        .run_root(script)
        .expect_err("duplicate capture tag in one syscall must return Script error");
    match err {
        ExampleError::Script(msg) => assert!(
            msg.contains("duplicate capture tag 'dup_tag'"),
            "unexpected error message: {msg}"
        ),
        other => panic!("expected ExampleError::Script, got {other:?}"),
    }
}

#[test]
fn layout_integer_signedness_is_checked_before_dispatch() {
    for (width, value) in [
        (RelocWidth::U8, -1i64),
        (RelocWidth::U16, -1),
        (RelocWidth::U32, -1),
        (RelocWidth::I16, i16::MAX as i64 + 1),
        (RelocWidth::I32, i32::MAX as i64 + 1),
    ] {
        let error = ScriptedBackend::new()
            .run_root(vec![Step::Sys(sys::sendmsg(
                1,
                Layout::new(8).with_reloc(0, width, value),
                0,
            ))])
            .expect_err("out-of-range typed integer must fail before syscall dispatch");
        assert!(
            matches!(error, ExampleError::Script(ref message) if message.contains("does not fit in width")),
            "{width:?}: {error}"
        );
    }
}
