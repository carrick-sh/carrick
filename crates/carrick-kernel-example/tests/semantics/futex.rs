//! Futex wait, wake, and requeue semantics suite for carrick-kernel.
//!
//! Verifies futex wait/wake between sibling threads, stale word EAGAIN,
//! wake counts, requeue behavior, and private futex non-sharing across fork.
//!
//! Citations:
//! - `man 2 futex` (FUTEX_WAIT, FUTEX_WAKE, FUTEX_REQUEUE, FUTEX_PRIVATE_FLAG, EAGAIN, ETIMEDOUT)

use crate::common::*;

/// `futex_wait` parks on the futex table and is woken by a `futex_wake` from a sibling thread.
/// Assert ONE syscall dispatch + explicit parked/woken handshake.
#[test]
fn futex_wait_parks_and_a_wake_from_the_sibling_thread_resumes_it() {
    let script = vec![
        alloc_word(0, 1),
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            // Deterministic handshake: wait until root task is parked in futex_wait.
            await_parked(1, "wait_root"),
            Step::Sys(sys::futex_wake_labeled("wake_root", slot(0), 1).ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::Sys(sys::futex_wait_labeled("wait_root", slot(0), 1).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 2);
    // Shared continuation completes owned FutexWait with Return(0) directly without redispatch.
    assert_eq!(run.dispatches_for_tid(1, "wait_root"), 1);
    assert_eq!(run.ret("wait_root"), 0);
    assert_eq!(run.ret("wake_root"), 1);
}

/// `futex_wait` where the word does not match expected value fails immediately with `EAGAIN`.
#[test]
fn futex_wait_with_a_stale_value_is_eagain() {
    let script = vec![
        alloc_word(0, 100),
        // Expected value is 200 != actual value 100.
        Step::Sys(sys::futex_wait_labeled("wait_stale", slot(0), 200).errno(LINUX_EAGAIN)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.dispatches_for_tid(1, "wait_stale"), 1);
}

/// `futex_wake` returns the exact number of waiters woken.
/// Waiter acknowledgment via pipe byte ensures completion before process exit.
#[test]
fn futex_wake_returns_the_number_woken() {
    let script = vec![
        alloc_word(0, 42),
        // Shared acknowledgment pipe: FUTEX_WAKE makes no waiter-order guarantee.
        pipe_to_slots(1, 2),
        // No waiters: returns 0.
        Step::Sys(sys::futex_wake_labeled("wake_empty_initial", slot(0), 5).ret(0)),
        Step::Sys(sys::clone_thread(0).save(5)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait1", slot(0), 42).ret(0)),
            Step::Sys(sys::write(slot(2), b"1").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(5), "wait1"),
        Step::Sys(sys::clone_thread(0).save(6)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait2", slot(0), 42).ret(0)),
            Step::Sys(sys::write(slot(2), b"2").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(6), "wait2"),
        // Wake 1 of 2 waiters -> returns 1.
        Step::Sys(sys::futex_wake_labeled("wake_first", slot(0), 1).ret(1)),
        // Await either selected waiter before waking the remaining one.
        Step::Sys(sys::read(slot(1), 1).ret(1)),
        // Wake remaining 1 waiter -> returns 1.
        Step::Sys(sys::futex_wake_labeled("wake_second", slot(0), 1).ret(1)),
        // Await the other waiter; no FIFO selection assumption.
        Step::Sys(sys::read(slot(1), 1).ret(1)),
        // No remaining waiters -> returns 0.
        Step::Sys(sys::futex_wake_labeled("wake_empty", slot(0), 1).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 3);
    assert_eq!(run.ret("wake_empty_initial"), 0);
    assert_eq!(run.ret("wake_first"), 1);
    assert_eq!(run.ret("wake_second"), 1);
    assert_eq!(run.ret("wake_empty"), 0);
    assert_eq!(run.ret("wait1"), 0);
    assert_eq!(run.ret("wait2"), 0);
    assert_eq!(run.dispatches_for_tid(2, "wait1"), 1);
    assert_eq!(run.dispatches_for_tid(3, "wait2"), 1);
}

/// `futex_requeue` moves waiters from one futex word to another without waking them immediately.
#[test]
fn futex_requeue_moves_waiters_without_waking_them() {
    let script = vec![
        alloc_word(0, 1),
        alloc_word(1, 2),
        // Pipe for waiter ack: read slot 2, write slot 3.
        pipe_to_slots(2, 3),
        Step::Sys(sys::clone_thread(0).save(4)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait_word0", slot(0), 1).ret(0)),
            Step::Sys(sys::write(slot(3), b"w").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(4), "wait_word0"),
        // Requeue 1 waiter from word 0 to word 1 with 0 direct wakes (Linux returns woken + requeued = 1).
        Step::Sys(sys::futex_requeue_labeled("requeue", slot(0), 0, 1, slot(1)).ret(1)),
        // Waking word 0 wakes 0 (the waiter was moved!).
        Step::Sys(sys::futex_wake_labeled("wake_word0", slot(0), 1).ret(0)),
        // Waking word 1 wakes the requeued waiter.
        Step::Sys(sys::futex_wake_labeled("wake_word1", slot(1), 1).ret(1)),
        // Await waiter completion via pipe byte.
        Step::Sys(sys::read(slot(2), 1).ret(1)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 2);
    assert_eq!(run.ret("requeue"), 1);
    assert_eq!(run.ret("wake_word0"), 0);
    assert_eq!(run.ret("wake_word1"), 1);
    assert_eq!(run.ret("wait_word0"), 0);
    assert_eq!(run.dispatches_for_tid(2, "wait_word0"), 1);
}

/// A PRIVATE futex is not shared across fork: child's wake on the same guest VA
/// does not wake the parent, and the parent times out with `ETIMEDOUT` from its
/// own syscall timeout.
#[test]
fn a_private_futex_is_not_shared_across_fork() {
    let script = vec![
        alloc_word(0, 99),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            await_parked(1, "wait_parent"),
            // Child attempts to wake word 0 in its own private table: 0 waiters.
            Step::Sys(sys::futex_wake_labeled("child_wake", slot(0), 1).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // Parent waits on private futex with 50ms timeout; times out with ETIMEDOUT.
        Step::Sys(
            sys::futex_wait_timeout_labeled("wait_parent", slot(0), 99, 50).errno(LINUX_ETIMEDOUT),
        ),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 2);
    assert_eq!(run.ret("child_wake"), 0);
    assert_eq!(run.dispatches_for_tid(1, "wait_parent"), 1);
}
