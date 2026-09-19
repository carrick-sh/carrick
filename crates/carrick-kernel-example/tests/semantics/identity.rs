//! Identity and credential syscall semantics suite.
//!
//! Verifies `getpid`, `getppid`, `gettid`, `getuid`, `geteuid`, `getgid`, `getegid`
//! behavior across root init, child fork, thread clone, and orphan reparenting.
//!
//! Citations:
//! - `man 2 getpid` (returns process ID of calling process)
//! - `man 2 getppid` (returns process ID of parent of calling process; init is 1 or 0 for init itself)
//! - `man 2 gettid` (returns caller's thread ID; single-threaded matches getpid)
//! - `man 2 getuid`, `man 2 geteuid`, `man 2 getgid`, `man 2 getegid` (credentials inherited across fork)

use crate::common::*;

/// `getpid` returns 1 and `getppid` returns 0 for the root container process (PID 1).
#[test]
fn getpid_and_getppid_for_init_process() {
    let script = vec![
        Step::Sys(sys::getpid().ret(1)),
        Step::Sys(sys::getppid().ret(0)),
        Step::Sys(sys::gettid().ret(1)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.ret("getpid"), 1);
    assert_eq!(run.ret("getppid"), 0);
    assert_eq!(run.ret("gettid"), 1);
}

/// After fork, child's `getppid` matches parent's `getpid`, and `getpid` matches child PID.
#[test]
fn getppid_returns_parent_pid_after_fork() {
    let script = vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::getpid().ret(2)),
            Step::Sys(sys::getppid().ret(1)),
            Step::Sys(sys::gettid().ret(2)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.ret("getpid"), 2);
    assert_eq!(run.ret("getppid"), 1);
    assert_eq!(run.ret("gettid"), 2);
}

/// In a multithreaded process, `gettid` returns the distinct thread ID while `getpid` matches the process.
#[test]
fn gettid_differs_from_parent_tid_in_thread() {
    let script = vec![
        pipe_to_slots(0, 1),
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            Step::Sys(sys::getpid().ret(1)),
            Step::Sys(sys::gettid().ret(2)),
            Step::Sys(sys::write(slot(1), b"T").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::Sys(sys::read(slot(0), 1).ret(1)),
        Step::Sys(sys::getpid().ret(1)),
        Step::Sys(sys::gettid().ret(1)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
}

/// When a parent process dies, its child is reparented to init (PID 1), and `getppid` updates.
///
/// Authority: `man 2 getppid` (if parent terminates, child is reparented to init).
#[test]
fn getppid_updates_on_reparenting_to_init() {
    let script = vec![
        pipe_to_slots(0, 1), // Sync: grandchild -> root
        pipe_to_slots(2, 3), // Sync: root -> grandchild
        // Root forks Process A (PID 2)
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Process A forks Grandchild (PID 3)
            Step::Sys(sys::fork()),
            Step::ChildMarker(vec![
                // Grandchild notifies root it has started
                Step::Sys(sys::write(slot(1), b"G").ret(1)),
                // Grandchild waits until Process A has exited and been reaped
                Step::Sys(sys::read(slot(2), 1).ret(1)),
                // Grandchild checks getppid: parent (PID 2) is dead, should be reparented to 1
                Step::Sys(sys::getppid().ret(1)),
                Step::Sys(sys::exit_group(0)),
            ]),
            // Process A exits immediately
            Step::Sys(sys::exit_group(0)),
        ]),
        // Root waits for Grandchild to be alive
        Step::Sys(sys::read(slot(0), 1).ret(1)),
        // Root reaps Process A (PID 2)
        Step::Sys(sys::wait4(2, 0)),
        // Root unblocks Grandchild
        Step::Sys(sys::write(slot(3), b"K").ret(1)),
        // Root reaps adopted Grandchild (PID 3)
        Step::Sys(sys::wait4(3, 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.ret("getppid"), 1);
}

/// Identity and credential syscalls return consistent initial credentials across fork.
#[test]
fn identity_and_credential_syscalls_are_consistent_across_fork() {
    let script = vec![
        Step::Sys(sys::getuid().ret(0)),
        Step::Sys(sys::geteuid().ret(0)),
        Step::Sys(sys::getgid().ret(0)),
        Step::Sys(sys::getegid().ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::getuid().ret(0)),
            Step::Sys(sys::geteuid().ret(0)),
            Step::Sys(sys::getgid().ret(0)),
            Step::Sys(sys::getegid().ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.ret("getuid"), 0);
    assert_eq!(run.ret("geteuid"), 0);
    assert_eq!(run.ret("getgid"), 0);
    assert_eq!(run.ret("getegid"), 0);
}
