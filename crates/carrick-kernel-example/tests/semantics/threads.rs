//! Thread semantics suite for carrick-kernel.
//!
//! Verifies thread clone, shared address space / fd table, single thread exit
//! vs exit_group, and independent wait4 reporting.
//!
//! Citations:
//! - `man 2 clone` (CLONE_VM, CLONE_FILES, CLONE_FS, CLONE_THREAD, CLONE_SIGHAND)
//! - `man 2 exit_group` (terminates all threads in calling process's thread group)
//! - `man 2 exit` (terminates only calling thread when siblings live)
//! - `man 2 wait4` (reaps zombie and reports exit status in bits 8..16)
//! - `man 2 set_tid_address` (clear_child_tid clears address and wakes futex on thread exit)

use crate::common::*;

/// `clone` with thread flags shares the fd table and memory with its process;
/// `exit_group` from the thread terminates the entire process and reports its status
/// to the waiting parent process.
///
/// Topology: 3 task actors (parent process + child process leader + child sibling thread).
#[test]
fn clone_thread_shares_the_fd_table_and_memory_and_exit_group_ends_every_thread() {
    let script = vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Child process allocates a shared memory word at slot 0 (initialized to 111).
            alloc_word(0, 111),
            // Child process opens a pipe; read end in slot 1, write end in slot 2.
            pipe_to_slots(1, 2),
            // Child process spawns a thread.
            Step::Sys(sys::clone_thread(0)),
            Step::ChildMarker(vec![
                // Sibling thread mutates the shared memory buffer at slot 0 to 222 BEFORE pipe notification.
                Step::WriteBuffer {
                    slot: 0,
                    bytes: 222i32.to_le_bytes().to_vec(),
                },
                // Sibling thread writes to write end of pipe (slot 2).
                Step::Sys(sys::write(slot(2), b"thread-pipe").ret(11)),
                // Deterministically await the child leader parking on its second blocking read.
                await_parked(2, "leader_second_read"),
                // Sibling thread issues exit_group(42).
                Step::Sys(sys::exit_group(42)),
            ]),
            // Process leader reads from read end of pipe (slot 1).
            Step::Sys(sys::read(slot(1), 11).ret(11)),
            // Leader writes the 4-byte shared word from slot 0 address into pipe.
            Step::Sys(
                call(
                    "write_shared_mem",
                    nr::WRITE,
                    [slot(2), slot(0), 4.into(), 0.into(), 0.into(), 0.into()],
                )
                .ret(4),
            ),
            // Leader reads the 4-byte shared word from pipe into captured output.
            Step::Sys(
                call(
                    "read_shared_mem",
                    nr::READ,
                    [
                        slot(1),
                        Operand::Out(4),
                        4.into(),
                        0.into(),
                        0.into(),
                        0.into(),
                    ],
                )
                .ret(4),
            ),
            // Leader blocks on a uniquely labeled second read; sibling's exit_group cancels it.
            Step::Sys(call(
                "leader_second_read",
                nr::READ,
                [
                    slot(1),
                    Operand::Out(1),
                    1.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                ],
            )),
            // Post-cancel sentinel syscall that should never execute.
            Step::Sys(call(
                "never_reached_sentinel",
                nr::GETPID,
                [0.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
            )),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Parent waits for child process.
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    // 3 actors: parent process, child process leader, child process thread.
    assert_eq!(run.tasks_started(), 3);
    assert_eq!(run.output("read"), b"thread-pipe");
    assert_eq!(run.output("read_shared_mem"), &222i32.to_le_bytes());
    let status = wait_status(&run, "wait4");
    assert!(wifexited(status));
    assert_eq!(wexitstatus(status), 42);
    assert_eq!(run.dispatches_for_tid(2, "never_reached_sentinel"), 0);
}

/// A thread exiting alone via `exit(2)` retires only that thread and leaves
/// the process running.
///
/// Topology: 2 task actors (root process leader + root sibling thread).
#[test]
fn a_thread_exiting_alone_leaves_the_process_running() {
    let script = vec![
        // Allocate word at slot 0 for clear_child_tid futex handshake (initial 100).
        alloc_word(0, 100),
        // Open pipe; read end in slot 1, write end in slot 2.
        pipe_to_slots(1, 2),
        // Spawn sibling thread.
        Step::Sys(sys::clone_thread(0).save(3)),
        Step::ChildMarker(vec![
            Step::Sys(sys::gettid().ret(2)),
            // Set clear_child_tid on slot 0.
            Step::Sys(sys::set_tid_address(slot(0)).ret(2)),
            Step::Sys(sys::write(slot(2), b"done").ret(4)),
            // Await root thread parking on futex_wait before exiting.
            await_parked(1, "wait_sibling_exit"),
            // exit(2) retires just this thread, clearing slot 0 and waking futex.
            Step::Sys(sys::exit_thread(0)),
        ]),
        // Root reads message written by sibling thread.
        Step::Sys(sys::read(slot(1), 4).ret(4)),
        // Root waits on slot 0 until sibling thread exit clears and wakes it.
        Step::Sys(sys::futex_wait_labeled("wait_sibling_exit", slot(0), 100).ret(0)),
        // Verify root process is still alive and operational after sibling retired.
        Step::Sys(sys::getpid().ret(1)),
        Step::Sys(sys::exit_group(10)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 10);
    assert_eq!(run.tasks_started(), 2);
    assert_eq!(run.output("read"), b"done");
    assert_eq!(run.ret("wait_sibling_exit"), 0);
    assert_eq!(run.ret("getpid"), 1);
}

/// Single root thread exit via `exit(2)` retires the process with that thread's exit code.
///
/// Topology: 1 task actor (root single thread).
#[test]
fn single_root_thread_exit_retires_process_with_exit_code() {
    let script = vec![Step::Sys(sys::exit_thread(77))];

    let run = run(script);
    assert_eq!(run.exit_code(), 77);
    assert_eq!(run.tasks_started(), 1);
}

/// Thread group leader exits first via `exit(2)` while sibling thread lives;
/// process remains running until final sibling thread exits, which retires the process.
///
/// Topology: 3 task actors (parent process + child leader + child sibling thread).
#[test]
fn leader_exits_first_and_final_sibling_exit_retires_process() {
    let script = vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Child allocates word at slot 0 for clear_child_tid (initial 88).
            alloc_word(0, 88),
            // Pipe for synchronization: read slot 1, write slot 2.
            pipe_to_slots(1, 2),
            // Leader registers clear_child_tid on slot 0.
            Step::Sys(sys::set_tid_address(slot(0)).ret(2)),
            // Spawn sibling thread.
            Step::Sys(sys::clone_thread(0).save(3)),
            Step::ChildMarker(vec![
                // Sibling signals leader that it's ready.
                Step::Sys(sys::write(slot(2), b"s").ret(1)),
                // Sibling waits on slot 0 until leader exits and clears it.
                Step::Sys(sys::futex_wait_labeled("wait_leader_exit", slot(0), 88).ret(0)),
                // Verify process is still alive with parent PID 1.
                Step::Sys(sys::getppid().ret(1)),
                // Last thread exits with code 55, retiring the process.
                Step::Sys(sys::exit_thread(55)),
            ]),
            // Leader reads byte from sibling.
            Step::Sys(sys::read(slot(1), 1).ret(1)),
            // Await sibling parking on wait_leader_exit before leader exits.
            await_parked(3, "wait_leader_exit"),
            // Leader exits first with code 0; sibling is still running.
            Step::Sys(sys::exit_thread(0)),
        ]),
        // Parent waits for child process to retire.
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 3);
    let status = wait_status(&run, "wait4");
    assert!(wifexited(status));
    assert_eq!(wexitstatus(status), 55);
}

/// Root process leader parks on a blocking read while a sibling thread calls `exit_group(42)`;
/// the entire process terminates with exit code 42 and the parked leader does not execute further.
///
/// Topology: 2 task actors (root leader + root sibling thread).
#[test]
fn root_leader_parked_and_sibling_exit_group_terminates_with_exit_code() {
    let script = vec![
        // Open pipe; read end in slot 1, write end in slot 2.
        pipe_to_slots(1, 2),
        // Spawn sibling thread.
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            // Deterministically await the root leader parking on its blocking read.
            await_parked(1, "root_parked_read"),
            // Sibling thread issues exit_group(42).
            Step::Sys(sys::exit_group(42)),
        ]),
        // Root leader blocks on an empty pipe read; sibling's exit_group cancels it.
        Step::Sys(call(
            "root_parked_read",
            nr::READ,
            [
                slot(1),
                Operand::Out(1),
                1.into(),
                0.into(),
                0.into(),
                0.into(),
            ],
        )),
        // Post-cancel sentinel syscall that should never execute.
        Step::Sys(call(
            "never_reached_sentinel",
            nr::GETPID,
            [0.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
        )),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 42);
    assert_eq!(run.tasks_started(), 2);
    assert_eq!(run.dispatches_for_tid(1, "never_reached_sentinel"), 0);
}
