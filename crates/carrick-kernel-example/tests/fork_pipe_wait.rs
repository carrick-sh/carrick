//! The example backend's one end-to-end proof: a Linux process pipes, forks,
//! reads what its child wrote, reaps it and exits -- through
//! `carrick_kernel::dispatch::SyscallDispatcher`, with no VM, no host fork and
//! no guest code. Everything the backend does to make that true is built from
//! `pub` items of `carrick-kernel`, `carrick-hal`, `carrick-guest-mem` and
//! `carrick-abi` alone; this test is red the moment one of them regresses.

use std::time::Instant;

use carrick_kernel_example::{ExampleError, ScriptedBackend, Step, Sys, WAIT_BOUND};

#[test]
fn fork_pipe_wait_through_the_public_surface() {
    // Parent: pipe2 -> fork -> (child: write "hi", exit 7) -> read -> wait4 -> exit.
    let script = vec![
        Step::sys(Sys::Pipe2 { flags: 0 }), // returns fds into slot 0/1
        Step::sys(Sys::Fork),               // child continues at Step::child_marker
        Step::child_marker(vec![
            Step::sys(Sys::Write {
                fd: Step::slot(1),
                data: b"hi".to_vec(),
            }),
            Step::sys(Sys::ExitGroup { code: 7 }),
        ]),
        Step::sys(Sys::Read {
            fd: Step::slot(0),
            len: 2,
        }), // expect "hi"
        Step::sys(Sys::Wait4 {
            pid: Step::last_child(),
            options: 0,
        }),
        Step::sys(Sys::ExitGroup { code: 0 }),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.read_results(), vec![b"hi".to_vec()]);
    assert_eq!(run.wait_statuses(), vec![7 << 8]); // WEXITSTATUS(7)
    assert_eq!(run.tasks_started(), 2);
}

/// Two live Linux processes are worth more than any number of single-process
/// cases: the forked child's dispatcher -- itself forked from the root's --
/// forks again, and each level reaps the one below through the kernel graph.
#[test]
fn a_forked_task_can_fork_again() {
    let script = vec![
        Step::sys(Sys::Pipe2 { flags: 0 }),
        Step::sys(Sys::Fork),
        Step::child_marker(vec![
            Step::sys(Sys::Fork),
            Step::child_marker(vec![
                Step::sys(Sys::Write {
                    fd: Step::slot(1),
                    data: b"deep".to_vec(),
                }),
                Step::sys(Sys::ExitGroup { code: 5 }),
            ]),
            Step::sys(Sys::Wait4 {
                pid: Step::last_child(),
                options: 0,
            }),
            Step::sys(Sys::ExitGroup { code: 6 }),
        ]),
        Step::sys(Sys::Read {
            fd: Step::slot(0),
            len: 4,
        }),
        Step::sys(Sys::Wait4 {
            pid: Step::last_child(),
            options: 0,
        }),
        Step::sys(Sys::ExitGroup { code: 0 }),
    ];
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.read_results(), vec![b"deep".to_vec()]);
    // The child's and the root's wait4 complete on different threads; only
    // the set is deterministic.
    let mut statuses = run.wait_statuses().to_vec();
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
        Step::sys(Sys::Pipe2 { flags: 0 }),
        Step::sys(Sys::Fork),
        Step::child_marker(vec![
            Step::sys(Sys::Read {
                fd: Step::slot(0),
                len: 1,
            }),
            Step::sys(Sys::ExitGroup { code: 1 }),
        ]),
        Step::sys(Sys::Wait4 {
            pid: Step::last_child(),
            options: 0,
        }),
        Step::sys(Sys::ExitGroup { code: 0 }),
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
