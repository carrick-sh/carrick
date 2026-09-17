//! The example backend's one end-to-end proof: a Linux process pipes, forks,
//! reads what its child wrote, reaps it and exits -- through
//! `carrick_kernel::dispatch::SyscallDispatcher`, with no VM, no host fork and
//! no guest code. Everything the backend does to make that true is built from
//! `pub` items of `carrick-kernel`, `carrick-hal`, `carrick-guest-mem` and
//! `carrick-abi` alone; this test is red the moment one of them regresses.

use std::time::Instant;

use carrick_abi::{LINUX_EBADF, LINUX_EINVAL};
use carrick_kernel_example::{
    ExampleError, ScriptedBackend, Step, WAIT_BOUND, await_parked, host_sleep_ms, last_child, slot,
    sys,
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
fn host_sleep_step_executes() {
    let script = vec![host_sleep_ms(1), Step::Sys(sys::exit_group(0))];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}
