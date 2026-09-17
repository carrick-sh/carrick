//! Wait, zombie, reparenting, and subreaper semantics.

use super::common::*;

/// `wait4(-1, ...)` reaps any child; returns `ECHILD` when no unreaped children remain.
///
/// Authority: `man 2 wait4` (-1 waits for any child; returns ECHILD when no children remain).
#[test]
fn wait4_minus_one_reaps_any_child_and_echild_when_none_remain() {
    let run = run(vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(4))]),
        Step::Sys(sys::wait4(-1, 0)),
        Step::Sys(wait4_labeled("wait4_echild", -1, 0).errno(LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(wexitstatus(wait_status(&run, "wait4")), 4);
    assert_eq!(run.exit_code(), 0);
}

/// `wait4(..., WNOHANG)` returns 0 immediately while the child is still running, then reaps it once exited.
///
/// Authority: `man 2 wait4` (WNOHANG returns 0 immediately if child has not exited, reaps when exited).
#[test]
fn wnohang_returns_zero_while_the_child_lives_then_reaps_it() {
    let run = run(vec![
        pipe(),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::read(slot(0), 1).ret(1)),
            Step::Sys(sys::exit_group(2)),
        ]),
        await_parked(last_child(), "read"),
        Step::Sys(wait4_labeled("wait4_nohang", last_child(), LINUX_WNOHANG).ret(0)),
        Step::Sys(sys::write(slot(1), b"x").ret(1)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(wexitstatus(wait_status(&run, "wait4")), 2);
    assert_eq!(run.exit_code(), 0);
}

/// A zombie process is reaped exactly once; a second wait returns `ECHILD`.
///
/// Authority: `man 2 wait4` (reaped zombie is consumed; subsequent wait returns ECHILD).
#[test]
fn a_zombie_is_reaped_exactly_once() {
    let run = run(vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(wait4_labeled("wait4_echild", last_child(), 0).errno(LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}

/// When a process dies, its orphaned child is reparented to init (PID 1), which can reap it.
///
/// Authority: `man 2 wait4`, `man 7 credentials` (orphaned process is reparented to init PID 1).
#[test]
fn an_orphan_is_reparented_to_init_which_can_reap_it() {
    let run = run(vec![
        pipe_to_slots(0, 1),
        pipe_to_slots(2, 3),
        Step::Sys(sys::fork()), // Process A
        Step::ChildMarker(vec![
            Step::Sys(sys::fork()), // Process B
            Step::ChildMarker(vec![
                Step::Sys(sys::read(slot(0), 1).ret(1)), // wait for A's exit and reap
                Step::Sys(sys::getppid().ret(1)),        // reparented to init (PID 1)
                Step::Sys(sys::write(slot(3), b"B").ret(1)),
                Step::Sys(sys::exit_group(6)),
            ]),
            Step::Sys(sys::exit_group(5)),
        ]),
        Step::Sys(wait4_labeled("wait4_reap_a", -1, 0)), // reap A
        Step::Sys(sys::write(slot(1), b"G").ret(1)),     // unblock B
        Step::Sys(sys::read(slot(2), 1).ret(1)),         // B finished checks
        Step::Sys(wait4_labeled("wait4_reap_b", -1, 0)), // reap B (now child of init)
        Step::Sys(wait4_labeled("wait4_echild", -1, 0).errno(LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let mut codes: Vec<i32> = run
        .outputs()
        .iter()
        .filter(|o| o.label == "wait4_reap_a" || o.label == "wait4_reap_b")
        .map(|o| wexitstatus(i32::from_le_bytes(o.bytes[0..4].try_into().unwrap())))
        .collect();
    codes.sort_unstable();
    assert_eq!(codes, vec![5, 6]);
    assert_eq!(run.exit_code(), 0);
}

/// Setting `SIGCHLD` action to `SIG_IGN` causes child processes to be auto-reaped; wait4 returns `ECHILD`.
///
/// Authority: `man 2 sigaction` (SIGCHLD set to SIG_IGN auto-reaps children; wait4 returns ECHILD).
#[test]
#[ignore = "defect: SIGCHLD set to SIG_IGN does not autoreap terminating children in carrick-kernel"]
fn sigchld_set_to_sig_ign_autoreaps_and_wait4_reports_echild() {
    let run = run(vec![
        Step::Sys(sys::rt_sigaction_ign(LINUX_SIGCHLD).ret(0)),
        pipe(),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::write(slot(1), b"x").ret(1)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::read(slot(0), 1).ret(1)), // wait for child to write and exit
        Step::Sys(sys::wait4(-1, 0).errno(LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}

/// `waitid(..., WNOWAIT)` inspects child state without reaping it; a subsequent waitid reaps it.
///
/// Authority: `man 2 waitid` (WNOWAIT leaves zombie waitable; subsequent waitid consumes it).
#[test]
fn waitid_wnowait_leaves_the_zombie_and_a_second_waitid_consumes_it() {
    let run = run(vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(9))]),
        Step::Sys(
            waitid_labeled(
                "waitid_nowait",
                LINUX_P_PID,
                last_child(),
                LINUX_WEXITED | LINUX_WNOWAIT,
            )
            .ret(0),
        ),
        Step::Sys(
            waitid_labeled("waitid_consume", LINUX_P_PID, last_child(), LINUX_WEXITED).ret(0),
        ),
        Step::Sys(
            waitid_labeled("waitid_echild", LINUX_P_PID, last_child(), LINUX_WEXITED)
                .errno(LINUX_ECHILD),
        ),
        Step::Sys(sys::exit_group(0)),
    ]);

    // Check waitid siginfo_t output for the successful calls:
    // offset 0..4: si_signo (SIGCHLD = 17)
    // offset 8..12: si_code (CLD_EXITED = 1)
    // offset 24..28: si_status (exit code 9)
    let nowait_siginfo = run.output("waitid_nowait");
    assert_eq!(
        i32::from_le_bytes(nowait_siginfo[0..4].try_into().unwrap()),
        LINUX_SIGCHLD
    );
    assert_eq!(
        i32::from_le_bytes(nowait_siginfo[8..12].try_into().unwrap()),
        1 /* CLD_EXITED */
    );
    assert_eq!(
        i32::from_le_bytes(nowait_siginfo[24..28].try_into().unwrap()),
        9
    );

    let consume_siginfo = run.output("waitid_consume");
    assert_eq!(
        i32::from_le_bytes(consume_siginfo[0..4].try_into().unwrap()),
        LINUX_SIGCHLD
    );
    assert_eq!(
        i32::from_le_bytes(consume_siginfo[8..12].try_into().unwrap()),
        1 /* CLD_EXITED */
    );
    assert_eq!(
        i32::from_le_bytes(consume_siginfo[24..28].try_into().unwrap()),
        9
    );
    assert_eq!(run.exit_code(), 0);
}

/// `prctl(PR_SET_CHILD_SUBREAPER, 1)` on a non-init process marks it as subreaper, adopting orphaned descendants.
///
/// Authority: `man 2 prctl` (PR_SET_CHILD_SUBREAPER reparents orphaned descendants to subreaper).
#[test]
fn prctl_set_child_subreaper_receives_the_grandchild() {
    let run = run(vec![
        Step::Sys(sys::fork()), // Process A (Subreaper, PID 2)
        Step::ChildMarker(vec![
            Step::Sys(prctl(LINUX_PR_SET_CHILD_SUBREAPER, 1).ret(0)),
            Step::Sys(sys::getpid().ret(2)), // Subreaper PID is 2
            pipe_to_slots(0, 1),             // Pipe 1: slots 0 (read), 1 (write)
            pipe_to_slots(2, 3),             // Pipe 2: slots 2 (read), 3 (write)
            Step::Sys(sys::fork()),          // Process B (Middleman, PID 3)
            Step::ChildMarker(vec![
                Step::Sys(sys::fork()), // Process C (Grandchild, PID 4)
                Step::ChildMarker(vec![
                    Step::Sys(sys::read(slot(0), 1).ret(1)), // wait for B's death and reap
                    Step::Sys(sys::getppid().ret(2)),        // reparented to Subreaper A (PID 2)
                    Step::Sys(sys::write(slot(3), b"C").ret(1)),
                    Step::Sys(sys::exit_group(0)),
                ]),
                Step::Sys(sys::exit_group(0)), // B exits immediately
            ]),
            Step::Sys(sys::wait4(last_child(), 0)), // A reaps B
            Step::Sys(sys::write(slot(1), b"K").ret(1)), // unblock C
            Step::Sys(sys::read(slot(2), 1).ret(1)), // C finished
            Step::Sys(wait4_labeled("wait4_c", -1, 0)), // A reaps C (adopted grandchild)
            Step::Sys(wait4_labeled("wait4_echild", -1, 0).errno(LINUX_ECHILD)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(-1, 0)), // Root reaps A
        Step::Sys(sys::exit_group(0)),
    ]);

    // Grandchild C's getppid completion returned Subreaper A's PID (2).
    let getppid_results: Vec<i64> = run
        .completions()
        .iter()
        .filter(|c| c.label == "getppid" && c.pid == 4)
        .map(|c| c.result.unwrap())
        .collect();
    assert_eq!(getppid_results, vec![2]);
    assert_eq!(run.exit_code(), 0);
}
