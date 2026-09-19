//! Fork population-scaling semantics tests.
//!
//! Verifies that process fork completes and scales predictably when many children
//! are already parked or alive in the kernel graph.
//!
//! Citations:
//! - `man 2 fork` (fork creates a new process duplicating calling process)
//! - `man 2 clone` (CLONE with SIGCHLD)
//! - `man 2 wait4` (reaps zombies and reports exit status)

use crate::common::*;

/// Fork with 32 live children parked on a pipe completes cleanly.
#[test]
fn fork_with_32_parked_children_completes() {
    let mut script = vec![pipe_to_slots(0, 1)];

    for _ in 0..32 {
        script.push(Step::Sys(sys::fork()));
        script.push(Step::ChildMarker(vec![
            Step::Sys(sys::read(slot(0), 1).ret(1)),
            Step::Sys(sys::exit_group(0)),
        ]));
    }

    // Await child 32 (PID 33) is parked before forking the final child.
    script.push(await_parked(33, "read"));

    // Fork child 33 (PID 34) while 32 children are parked.
    script.push(Step::Sys(
        call(
            "fork_final",
            nr::CLONE,
            [
                (LINUX_SIGCHLD as i64).into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
            ],
        )
        .ret(34),
    ));
    script.push(Step::ChildMarker(vec![Step::Sys(sys::exit_group(42))]));

    // Reap child 34 specifically.
    script.push(Step::Sys(wait4_labeled("wait4_final", 34, 0)));

    // Wake all 32 parked children by writing 32 bytes to the pipe.
    script.push(Step::Sys(sys::write(slot(1), &[1u8; 32]).ret(32)));

    // Reap all remaining 32 children.
    for _ in 0..32 {
        script.push(Step::Sys(sys::wait4(-1, 0)));
    }

    script.push(Step::Sys(sys::exit_group(0)));

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 34); // Root + 32 parked + 1 final
    assert_eq!(wexitstatus(wait_status(&run, "wait4_final")), 42);
    assert_eq!(run.dispatches_for_pid(1, "fork_final"), 1);
}

/// Fork with 64 live children parked on a pipe completes cleanly within wait bounds.
#[test]
fn fork_with_64_parked_children_completes() {
    let mut script = vec![pipe_to_slots(0, 1)];

    for _ in 0..64 {
        script.push(Step::Sys(sys::fork()));
        script.push(Step::ChildMarker(vec![
            Step::Sys(sys::read(slot(0), 1).ret(1)),
            Step::Sys(sys::exit_group(0)),
        ]));
    }

    // Await child 64 (PID 65) parked.
    script.push(await_parked(65, "read"));

    // Fork final child (PID 66)
    script.push(Step::Sys(
        call(
            "fork_final_64",
            nr::CLONE,
            [
                (LINUX_SIGCHLD as i64).into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
                0.into(),
            ],
        )
        .ret(66),
    ));
    script.push(Step::ChildMarker(vec![Step::Sys(sys::exit_group(88))]));

    script.push(Step::Sys(wait4_labeled("wait4_final_64", 66, 0)));

    // Wake all 64 parked children by writing 64 bytes.
    script.push(Step::Sys(sys::write(slot(1), &[1u8; 64]).ret(64)));

    for _ in 0..64 {
        script.push(Step::Sys(sys::wait4(-1, 0)));
    }

    script.push(Step::Sys(sys::exit_group(0)));

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 66);
    assert_eq!(wexitstatus(wait_status(&run, "wait4_final_64")), 88);
    assert_eq!(run.dispatches_for_pid(1, "fork_final_64"), 1);
}

/// A private futex is not shared across fork even when 8 sibling children exist.
#[test]
fn fork_children_receive_independent_futex_table_under_population() {
    let mut script = vec![alloc_word(0, 99)];

    // Fork 8 children.
    for _ in 0..8 {
        script.push(Step::Sys(sys::fork()));
        script.push(Step::ChildMarker(vec![
            // Each child attempts to wake word 0 in its own private table -> 0 waiters.
            Step::Sys(
                call(
                    "child_wake",
                    nr::FUTEX,
                    [
                        slot(0),
                        (carrick_abi::LINUX_FUTEX_WAKE as i64).into(),
                        1.into(),
                        0.into(),
                        0.into(),
                        0.into(),
                    ],
                )
                .ret(0),
            ),
            Step::Sys(sys::exit_group(0)),
        ]));
    }

    // Parent waits on private futex with 20ms timeout; times out with ETIMEDOUT.
    script.push(Step::Sys(
        sys::futex_wait_timeout_labeled("wait_parent", slot(0), 99, 20)
            .errno(carrick_abi::LINUX_ETIMEDOUT),
    ));

    for _ in 0..8 {
        script.push(Step::Sys(sys::wait4(-1, 0)));
    }
    script.push(Step::Sys(sys::exit_group(0)));

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 9);
    assert_eq!(run.dispatches_for_tid(1, "wait_parent"), 1);
}

/// Process fork dispatch count scales sub-linearly with existing process population.
///
/// Authority: fork creates a child process in O(1) dispatches regardless of population;
/// dispatch count per child must not explode quadratically with population (asserting
/// per-child dispatch ratio between n=8 and n=64 is <= 4.0x to gate any ProcessSpec O(N) scan).
#[test]
fn fork_dispatch_count_does_not_grow_linearly_with_population() {
    fn run_population(n: usize) -> (usize, usize) {
        let mut script = vec![pipe_to_slots(0, 1)];
        for _ in 0..n {
            script.push(Step::Sys(sys::fork()));
            script.push(Step::ChildMarker(vec![
                Step::Sys(sys::read(slot(0), 1).ret(1)),
                Step::Sys(sys::exit_group(0)),
            ]));
        }
        let probe_pid = (n + 2) as i32;
        script.push(Step::Sys(
            call(
                "fork_probe",
                nr::CLONE,
                [
                    (LINUX_SIGCHLD as i64).into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                    0.into(),
                ],
            )
            .ret(probe_pid as i64),
        ));
        script.push(Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]));
        script.push(Step::Sys(wait4_labeled("wait4_probe", probe_pid, 0)));
        script.push(Step::Sys(
            sys::write(slot(1), vec![1u8; n].as_slice()).ret(n as i64),
        ));
        for _ in 0..n {
            script.push(Step::Sys(sys::wait4(-1, 0)));
        }
        script.push(Step::Sys(sys::exit_group(0)));
        let run = run(script);
        assert_eq!(run.exit_code(), 0);
        let probe_dispatches = run.dispatches_for_pid(1, "fork_probe");
        (run.dispatches(), probe_dispatches)
    }

    let (d8, p8) = run_population(8);
    let (d64, p64) = run_population(64);

    assert_eq!(
        p8, 1,
        "probe fork under n=8 population must take 1 dispatch"
    );
    assert_eq!(
        p64, 1,
        "probe fork under n=64 population must take 1 dispatch"
    );

    // Per-child dispatch overhead across the whole run: (d64 / 64) / (d8 / 8)
    let per_child_8 = d8 as f64 / 8.0;
    let per_child_64 = d64 as f64 / 64.0;
    let ratio = per_child_64 / per_child_8;
    assert!(
        ratio <= 4.0,
        "per-child dispatch count grew too fast: ratio {ratio:.2} (d8={d8}, d64={d64})"
    );
}
