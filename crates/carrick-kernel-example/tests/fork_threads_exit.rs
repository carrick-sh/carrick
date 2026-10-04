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

use carrick_kernel_example::operand::ScriptCheckpoint;
use carrick_kernel_example::{ScriptedBackend, Step, await_parked, last_child, slot, sys};

/// Contract `kernel.fd.wait-admission-retirement`.
/// Linux authority: fork(2) copies slots referencing the same descriptions;
/// close(2) retains an admitted blocking operation's description; exit_group(2)
/// terminates every sibling, so the parked read never returns to the guest.
/// Budget: exactly one read admission, no redispatch or retry after retirement.
#[test]
fn fork_parent_exit_between_pipe_wait_admission_and_continuation_build() {
    admitted_pipe_wait_after_parent_exit(sys::read(slot(0), 1).ret(1), false);
}

#[test]
fn fork_parent_exit_between_pipe_write_admission_and_continuation_build() {
    admitted_pipe_wait_after_parent_exit(sys::write(slot(1), b"x").ret(1), true);
}

#[test]
fn fork_parent_exit_between_pipe_readv_admission_and_continuation_build() {
    use carrick_kernel_example::{Layout, Operand, RelocWidth, Syscall};
    let iov = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, Operand::Out(1))
        .with_u64(8, 1);
    let readv = Syscall::new(
        "readv",
        carrick_abi::syscall::nr::READV,
        [slot(0), iov.into(), 1.into(), 0.into(), 0.into(), 0.into()],
    )
    .ret(1);
    admitted_pipe_wait_after_parent_exit(readv, false);
}

fn admitted_pipe_wait_after_parent_exit(wait: carrick_kernel_example::Syscall, fill: bool) {
    let admitted = ScriptCheckpoint::default();
    let resume = ScriptCheckpoint::default();
    let child_live = ScriptCheckpoint::default();
    let child_exit = ScriptCheckpoint::default();
    let retired = ScriptCheckpoint::default();
    let label = wait.label;
    let mut script = vec![Step::Sys(
        sys::pipe2(0)
            .ret(0)
            .save_out_i32(0, 0, 0)
            .save_out_i32(0, 1, 1),
    )];
    if fill {
        script.push(Step::Sys(
            sys::write(slot(1), &vec![0x33; 65536]).ret(65536),
        ));
    }
    script.extend([
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            Step::SysBeforeContinuation {
                syscall: wait,
                admitted: admitted.clone(),
                resume: resume.clone(),
            },
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::AwaitCheckpoint(admitted),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::SignalCheckpoint(child_live.clone()),
            Step::AwaitCheckpoint(child_exit.clone()),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Both processes are live, sharing descriptions but separate fd tables.
        Step::AwaitCheckpoint(child_live),
        Step::SignalCheckpoint(child_exit),
        Step::Sys(sys::wait4(last_child(), 0)),
        // Retire the last fd-table owners while the sibling holds its outcome.
        Step::Sys(sys::exit_group(0)),
    ]);
    let handle = std::thread::spawn({
        let retired = retired.clone();
        move || {
            ScriptedBackend::new()
                .with_root_exit_checkpoint(retired)
                .run_root(script)
        }
    });
    let exited = retired.wait();
    // Release even if a harness failure hit the bound, so the thread is joined.
    resume.signal();
    let result = handle.join().expect("join scripted backend");
    assert!(
        exited,
        "root must publish exit before continuation construction"
    );
    let report = result.expect("retired sibling must cancel, never return Unsupported");
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.tasks_started(), 3);
    assert_eq!(report.dispatches_for_tid(2, label), 1);
    assert!(
        report
            .completions()
            .iter()
            .all(|row| row.tid != 2 || row.label != label),
        "exit_group tears down the admitted I/O instead of returning a guest result"
    );
}

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
