//! The example backend's one end-to-end proof: a Linux process pipes, forks,
//! reads what its child wrote, reaps it and exits -- through
//! `carrick_kernel::dispatch::SyscallDispatcher`, with no VM, no host fork and
//! no guest code. Everything the backend does to make that true is built from
//! `pub` items of `carrick-kernel`, `carrick-hal`, `carrick-guest-mem` and
//! `carrick-abi` alone; this test is red the moment one of them regresses.

use std::time::Instant;

use carrick_kernel_example::{
    ExampleError, ScriptedBackend, Step, WAIT_BOUND, last_child, slot, sys,
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
