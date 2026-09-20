//! Exit liveness when a process that owns live threads forks, and both the
//! child and the thread group then terminate.
//!
//! CPython's `test_asyncio.test_unix_events.TestFork.test_fork_asyncio_subprocess`
//! wedges Carrick's carrier under this shape: a multiprocessing `Manager`
//! process with server threads, a forked child running an event loop that
//! itself forks a grandchild, and everyone exiting. The per-task syscall flow
//! (`scripts/dtrace/hvpatch-guest-syscall-flow.d`) showed one task entering
//! `exit_group` and never returning, two more stuck in `exit`, and a joiner
//! re-entering a one-second `FUTEX_WAIT_BITSET` forever. The oracle runs the
//! same module in 0.89 s.
//!
//! Linux authority:
//! - `man 2 exit_group`: terminates every thread in the calling process's
//!   thread group. It does not wait on another process.
//! - `man 2 exit`: terminates the calling thread; the last thread's exit ends
//!   the process.
//! - `man 2 fork`: the child has exactly one thread, whatever the parent had.
//! - `man 2 wait4`: reports each child once.
//!
//! Carrick structural invariant: a terminating task never waits on a task that
//! cannot itself make progress, so every one of these scripts retires with a
//! bounded number of dispatches and no task parked at the end.

use carrick_kernel_example::{ScriptedBackend, Step, await_parked, last_child, slot, sys};

/// A process with two live sibling threads forks; the child exits, the parent
/// reaps it, its siblings exit, and the leader calls `exit_group`.
#[test]
fn fork_from_a_threaded_process_retires_every_task() {
    let mut script = vec![Step::Sys(
        sys::pipe2(0)
            .ret(0)
            .save_out_i32(0, 0, 0)
            .save_out_i32(0, 1, 1),
    )];

    // Two siblings park on the pipe so the fork below happens while the thread
    // group genuinely has other live threads, as the Manager's server does.
    for _ in 0..2 {
        script.push(Step::Sys(sys::clone_thread(0)));
        script.push(Step::ChildMarker(vec![
            Step::Sys(sys::read(slot(0), 1).ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]));
    }
    script.push(await_parked(3, "read"));

    // The forked child owns exactly one thread and exits immediately.
    script.push(Step::Sys(sys::fork()));
    script.push(Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]));
    script.push(Step::Sys(sys::wait4(last_child(), 0)));

    // Release both siblings, then end the thread group.
    script.push(Step::Sys(sys::write(slot(1), b"gg").ret(2)));
    script.push(Step::Sys(sys::exit_group(0)));

    let report = ScriptedBackend::new()
        .run_root(script)
        .expect("a threaded process that forks, reaps and exits must retire");
    assert_eq!(report.exit_code(), 0, "leader exit_group must report 0");
}

/// The shape the asyncio test actually builds: the forked child is itself
/// threaded and forks a grandchild before the whole tree exits.
#[test]
fn a_forked_child_that_threads_and_forks_again_retires_every_task() {
    let mut script = vec![Step::Sys(
        sys::pipe2(0)
            .ret(0)
            .save_out_i32(0, 0, 0)
            .save_out_i32(0, 1, 1),
    )];

    script.push(Step::Sys(sys::clone_thread(0)));
    script.push(Step::ChildMarker(vec![
        Step::Sys(sys::read(slot(0), 1).ret(1)),
        Step::Sys(sys::exit_thread(0)),
    ]));
    script.push(await_parked(2, "read"));

    script.push(Step::Sys(sys::fork()));
    script.push(Step::ChildMarker(vec![
        // The child runs its own event loop thread, forks a grandchild that
        // exits, reaps it, and only then ends its own thread group.
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![Step::Sys(sys::exit_thread(0))]),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ]));
    script.push(Step::Sys(sys::wait4(last_child(), 0)));

    script.push(Step::Sys(sys::write(slot(1), b"g").ret(1)));
    script.push(Step::Sys(sys::exit_group(0)));

    let report = ScriptedBackend::new()
        .run_root(script)
        .expect("a threaded child that forks a grandchild must retire the whole tree");
    assert_eq!(report.exit_code(), 0, "leader exit_group must report 0");
}
