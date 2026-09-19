//! Futex contention, requeue, and timeout edge case semantics suite.
//!
//! Citations:
//! - `man 2 futex` (FUTEX_WAIT, FUTEX_WAKE, FUTEX_CMP_REQUEUE, FUTEX_LOCK_PI, FUTEX_UNLOCK_PI, EAGAIN, ETIMEDOUT, EDEADLK, EPERM)

use crate::common::*;

/// `futex_wait` with zero relative timeout expires immediately with `ETIMEDOUT`.
///
/// Authority: `man 2 futex` (a timeout of zero expires immediately).
#[test]
fn futex_wait_zero_timeout_returns_etimedout_immediately() {
    let script = vec![
        alloc_word(0, 100),
        Step::Sys(
            sys::futex_wait_timeout_labeled("wait_zero", slot(0), 100, 0).errno(LINUX_ETIMEDOUT),
        ),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.dispatches_for_tid(1, "wait_zero"), 1);
}

/// `FUTEX_CMP_REQUEUE` wakes `nr_wake` waiters and moves up to `nr_requeue` waiters to `uaddr2`.
///
/// Authority: `man 2 futex` (FUTEX_CMP_REQUEUE returns total woken + requeued).
#[test]
fn futex_cmp_requeue_moves_and_wakes_the_correct_counts() {
    let script = vec![
        alloc_word(0, 10),   // uaddr1
        alloc_word(1, 20),   // uaddr2
        pipe_to_slots(2, 3), // ack pipe: read 2, write 3
        // Spawn 3 threads waiting on word 0
        Step::Sys(sys::clone_thread(0).save(4)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait1", slot(0), 10).ret(0)),
            Step::Sys(sys::write(slot(3), b"1").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(4), "wait1"),
        Step::Sys(sys::clone_thread(0).save(5)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait2", slot(0), 10).ret(0)),
            Step::Sys(sys::write(slot(3), b"2").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(5), "wait2"),
        Step::Sys(sys::clone_thread(0).save(6)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait3", slot(0), 10).ret(0)),
            Step::Sys(sys::write(slot(3), b"3").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(6), "wait3"),
        // Requeue: wake 1, requeue up to 2 to word 1. Expected val3 is 10 (matches *uaddr1).
        // Returns 1 (woken) + 2 (requeued) = 3.
        Step::Sys(sys::futex_cmp_requeue_labeled("cmp_requeue", slot(0), 1, 2, slot(1), 10).ret(3)),
        // Read ack from the 1 directly woken thread
        Step::Sys(sys::read(slot(2), 1).ret(1)),
        // Waking word 0 now should wake 0 remaining waiters
        Step::Sys(sys::futex_wake_labeled("wake_word0_empty", slot(0), 5).ret(0)),
        // Waking word 1 should wake the 2 requeued waiters
        Step::Sys(sys::futex_wake_labeled("wake_word1_requeued", slot(1), 5).ret(2)),
        // Read 2 remaining acks
        Step::Sys(sys::read(slot(2), 1).ret(1)),
        Step::Sys(sys::read(slot(2), 1).ret(1)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.ret("cmp_requeue"), 3);
    assert_eq!(run.ret("wake_word0_empty"), 0);
    assert_eq!(run.ret("wake_word1_requeued"), 2);
}

/// `FUTEX_CMP_REQUEUE` durability: requeued waiters remain on destination address even after signal broadcast.
///
/// Authority: Linux moves requeued waiters to uaddr2's queue and only a wake on uaddr2 releases them;
/// signal delivery / broadcast must not lose or misplace requeued waiters back to uaddr1.
#[test]
fn futex_requeue_durability_across_signal_broadcast() {
    let script = vec![
        alloc_word(0, 10),   // uaddr1
        alloc_word(1, 20),   // uaddr2
        pipe_to_slots(2, 3), // ack pipe: read 2, write 3
        Step::Sys(sys::rt_sigaction_ign(LINUX_SIGUSR1).ret(0)),
        // Spawn 3 threads waiting on word 0
        Step::Sys(sys::clone_thread(0).save(4)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait1", slot(0), 10).ret(0)),
            Step::Sys(sys::write(slot(3), b"1").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(4), "wait1"),
        Step::Sys(sys::clone_thread(0).save(5)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait2", slot(0), 10).ret(0)),
            Step::Sys(sys::write(slot(3), b"2").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(5), "wait2"),
        Step::Sys(sys::clone_thread(0).save(6)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("wait3", slot(0), 10).ret(0)),
            Step::Sys(sys::write(slot(3), b"3").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        await_parked(slot(6), "wait3"),
        // Requeue all 3 waiters from word 0 to word 1 (0 woken, 3 requeued)
        Step::Sys(
            sys::futex_cmp_requeue_labeled("cmp_requeue_all", slot(0), 0, 3, slot(1), 10).ret(3),
        ),
        // Send ignored signal to self; this triggers signal handling / broadcast poke
        Step::Sys(sys::kill(1, LINUX_SIGUSR1).ret(0)),
        // Word 0 should have 0 waiters
        Step::Sys(sys::futex_wake_labeled("wake_word0_empty", slot(0), 5).ret(0)),
        // Word 1 must retain all 3 requeued waiters
        Step::Sys(sys::futex_wake_labeled("wake_word1_requeued", slot(1), 5).ret(3)),
        // Read 3 acks
        Step::Sys(sys::read(slot(2), 1).ret(1)),
        Step::Sys(sys::read(slot(2), 1).ret(1)),
        Step::Sys(sys::read(slot(2), 1).ret(1)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.ret("cmp_requeue_all"), 3);
    assert_eq!(run.ret("wake_word0_empty"), 0);
    assert_eq!(run.ret("wake_word1_requeued"), 3);
}

/// `FUTEX_CMP_REQUEUE` where `*uaddr1 != val3` returns `EAGAIN` without waking or requeueing.
///
/// Authority: `man 2 futex` (FUTEX_CMP_REQUEUE returns EAGAIN if *uaddr != val3).
#[test]
fn futex_cmp_requeue_with_stale_val3_returns_eagain() {
    let script = vec![
        alloc_word(0, 50),
        alloc_word(1, 60),
        // Expected val3 is 99 != actual 50 -> EAGAIN
        Step::Sys(
            sys::futex_cmp_requeue_labeled("cmp_requeue_stale", slot(0), 1, 1, slot(1), 99)
                .errno(LINUX_EAGAIN),
        ),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.dispatches_for_tid(1, "cmp_requeue_stale"), 1);
}

/// Private futex tables are isolated across fork: child wake on identical VA returns 0.
///
/// Authority: `man 2 futex` (private futexes are per-process and not shared across fork).
#[test]
fn futex_wake_of_unshared_address_across_fork_is_zero() {
    let script = vec![
        alloc_word(0, 77),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Child wakes word 0: parent is not in child's futex table
            Step::Sys(sys::futex_wake_labeled("child_wake_zero", slot(0), 5).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.ret("child_wake_zero"), 0);
}

/// Priority inheritance: `FUTEX_LOCK_PI`, `FUTEX_TRYLOCK_PI`, `FUTEX_UNLOCK_PI`.
///
/// Authority: `man 2 futex` (LOCK_PI, TRYLOCK_PI, UNLOCK_PI; self-lock returns EDEADLK; non-owner unlock returns EPERM).
#[test]
fn futex_pi_lock_unlock_deadlock_detection() {
    let script = vec![
        alloc_word(0, 0),    // Unlocked word
        pipe_to_slots(1, 2), // Pipe A: thread 2 (write 2) -> root (read 1)
        pipe_to_slots(3, 4), // Pipe B: root (write 4) -> thread 2 (read 3)
        // Lock uncontended word by root task (TID 1)
        Step::Sys(sys::futex_lock_pi_labeled("lock_pi_init", slot(0)).ret(0)),
        // Trylock on already-held word by same thread -> EDEADLK
        Step::Sys(
            sys::futex_trylock_pi_labeled("trylock_pi_deadlock", slot(0)).errno(LINUX_EDEADLK),
        ),
        // Unlock by owner -> success
        Step::Sys(sys::futex_unlock_pi_labeled("unlock_pi_init", slot(0)).ret(0)),
        // Spawn thread 2 to acquire the lock
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            Step::Sys(sys::futex_lock_pi_labeled("t2_lock", slot(0)).ret(0)),
            // Notify parent that lock is held
            Step::Sys(sys::write(slot(2), b"L").ret(1)),
            // Wait for parent's failed unlock attempt via Pipe B
            Step::Sys(sys::read(slot(3), 1).ret(1)),
            Step::Sys(sys::futex_unlock_pi_labeled("t2_unlock", slot(0)).ret(0)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        // Wait for thread 2 to acquire lock via Pipe A
        Step::Sys(sys::read(slot(1), 1).ret(1)),
        // Attempt unlock from root task (non-owner) -> EPERM
        Step::Sys(sys::futex_unlock_pi_labeled("non_owner_unlock", slot(0)).errno(LINUX_EPERM)),
        // Notify thread 2 that parent failed unlock via Pipe B
        Step::Sys(sys::write(slot(4), b"U").ret(1)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.ret("lock_pi_init"), 0);
    assert_eq!(run.ret("unlock_pi_init"), 0);
}
