//! Process groups, sessions, and group signaling semantics.

use super::common::*;

/// `setpgid(0, 0)` makes the calling process a process group leader with PGID equal to its PID.
///
/// Authority: `man 2 setpgid` (setpgid(0, 0) sets PGID to caller's PID).
#[test]
fn setpgid_zero_zero_makes_the_caller_a_group_leader() {
    let run = run(vec![
        Step::Sys(sys::fork()), // Child (PID 2)
        Step::ChildMarker(vec![
            Step::Sys(sys::getpid().ret(2)),
            Step::Sys(setpgid(0, 0).ret(0)),
            Step::Sys(getpgrp().save(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let getpgrp_val = run
        .completions()
        .iter()
        .find(|c| c.label == "getpgid" && c.pid == 2)
        .unwrap()
        .result
        .unwrap();
    assert_eq!(getpgrp_val, 2);
    assert_eq!(run.exit_code(), 0);
}

/// A parent may move a child into the parent's process group before or during execution.
///
/// Authority: `man 2 setpgid` (parent can set child's PGID to existing group before exec).
#[test]
fn a_parent_may_move_a_child_into_the_parents_group_before_exec() {
    let run = run(vec![
        Step::Sys(sys::fork()), // Child A (PID 2)
        Step::ChildMarker(vec![
            Step::Sys(setpgid(0, 0).ret(0)), // Child A leads group 2
            Step::Sys(getpgid(0).save(0)),   // slot 0 = 2 (Child A's PGID)
            pipe_to_slots(1, 2),             // Pipe 1: slots 1 (read), 2 (write)
            pipe_to_slots(3, 4),             // Pipe 2: slots 3 (read), 4 (write)
            Step::Sys(sys::fork()),          // Grandchild B (PID 3)
            Step::ChildMarker(vec![
                Step::Sys(sys::read(slot(1), 1).ret(1)), // wait for A to setpgid
                Step::Sys(getpgid(0).save(5)),           // should be in group 2
                Step::Sys(sys::write(slot(4), b"B").ret(1)),
                Step::Sys(sys::exit_group(0)),
            ]),
            Step::Sys(setpgid(last_child(), slot(0)).ret(0)), // move B into group 2 (slot 0)
            Step::Sys(sys::write(slot(2), b"G").ret(1)),      // unblock B
            Step::Sys(sys::read(slot(3), 1).ret(1)),          // B finished
            Step::Sys(sys::wait4(last_child(), 0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let grandchild_pgid = run
        .completions()
        .iter()
        .find(|c| c.label == "getpgid" && c.pid == 3)
        .unwrap()
        .result
        .unwrap();
    assert_eq!(grandchild_pgid, 2);
    assert_eq!(run.exit_code(), 0);
}

/// `setpgid` on a child in a different session fails with `EPERM`.
///
/// Authority: `man 2 setpgid` (moving a process into a group in another session yields EPERM).
#[test]
fn setpgid_on_a_child_in_another_session_is_eperm() {
    let run = run(vec![
        Step::Sys(sys::fork()), // Child A (PID 2)
        Step::ChildMarker(vec![
            Step::Sys(setpgid(0, 0).ret(0)),
            Step::Sys(getpgid(0).save(0)), // slot 0 = 2
            pipe_to_slots(1, 2),           // Pipe 1: A (write 2) -> B (read 1)
            pipe_to_slots(3, 4),           // Pipe 2: B (write 4) -> A (read 3)
            Step::Sys(sys::fork()),        // Grandchild B (PID 3)
            Step::ChildMarker(vec![
                Step::Sys(setsid().ret(3)), // Grandchild B creates new session 3
                Step::Sys(sys::write(slot(4), b"S").ret(1)), // notify A
                Step::Sys(sys::read(slot(1), 1).ret(1)), // wait for A
                Step::Sys(sys::exit_group(0)),
            ]),
            Step::Sys(sys::read(slot(3), 1).ret(1)), // wait for B's setsid
            Step::Sys(setpgid(last_child(), slot(0)).errno(LINUX_EPERM)), // EPERM: different session
            Step::Sys(sys::write(slot(2), b"X").ret(1)),                  // unblock B
            Step::Sys(sys::wait4(last_child(), 0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}

/// `setsid` by a process group leader fails with `EPERM`.
///
/// Authority: `man 2 setsid` (setsid by existing process group leader yields EPERM).
#[test]
fn setsid_by_a_group_leader_is_eperm() {
    let run = run(vec![
        Step::Sys(sys::fork()), // Child A (PID 2)
        Step::ChildMarker(vec![
            Step::Sys(setpgid(0, 0).ret(0)), // Become group leader
            Step::Sys(setsid().errno(LINUX_EPERM)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}

/// `kill(-pgid, sig)` sends the signal to every process in the target process group,
/// and `kill(0, sig)` sends the signal to every process in the caller's process group.
///
/// Authority: `man 2 kill` (kill(-pgid, sig) signals group members; kill(0, sig) signals caller's group).
#[test]
fn kill_minus_pgid_reaches_every_member_and_kill_zero_reaches_the_callers_group() {
    // 1. Test kill(-pgid, sig) from parent to target group 2
    let run_neg_pgid = run(vec![
        pipe_to_slots(0, 1), // park pipe for target group members (A and B read slot 0)
        pipe_to_slots(2, 3), // sync pipe: Child A/B (write 3) -> Root (read 2)
        pipe_to_slots(4, 5), // release pipe for Child C: Root (write 5) -> Child C (read 4)
        Step::Sys(sys::fork()), // Child A (PID 2)
        Step::ChildMarker(vec![
            Step::Sys(setpgid(0, 0).ret(0)), // group leader of PGID 2
            Step::Sys(sys::fork()),          // Grandchild B (PID 3) - inherits group 2
            Step::ChildMarker(vec![
                Step::Sys(sys::write(slot(3), b"B").ret(1)),
                Step::Sys(sys::read(slot(0), 10).death(LINUX_SIGKILL)),
            ]),
            Step::Sys(sys::write(slot(3), b"A").ret(1)),
            Step::Sys(sys::read(slot(0), 10).death(LINUX_SIGKILL)),
        ]),
        Step::Sys(sys::read(slot(2), 1).ret(1)), // wait for Grandchild B fork
        Step::Sys(sys::read(slot(2), 1).ret(1)), // wait for Child A fork
        await_parked(2, "read"),
        await_parked(3, "read"),
        Step::Sys(sys::fork()), // Child C (PID 4) - separate process group
        Step::ChildMarker(vec![
            Step::Sys(setpgid(0, 0).ret(0)), // Child C leads group 4 (unaffected)
            Step::Sys(sys::read(slot(4), 1).ret(1)), // wait for root release
            Step::Sys(sys::exit_group(0)),
        ]),
        await_parked(4, "read"),
        Step::Sys(sys::kill(-2, LINUX_SIGKILL).ret(0)), // kill PGID 2
        Step::Sys(wait4_labeled("wait4_a", 2, 0)),
        Step::Sys(wait4_labeled("wait4_b", 3, 0)), // B reparented to Root upon A's death
        Step::Sys(sys::write(slot(5), b"c").ret(1)), // unblock Child C
        Step::Sys(wait4_labeled("wait4_c", 4, 0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    assert_eq!(
        wtermsig(wait_status(&run_neg_pgid, "wait4_a")),
        LINUX_SIGKILL
    );
    assert_eq!(
        wtermsig(wait_status(&run_neg_pgid, "wait4_b")),
        LINUX_SIGKILL
    );
    assert!(wifexited(wait_status(&run_neg_pgid, "wait4_c")));
    assert_eq!(wexitstatus(wait_status(&run_neg_pgid, "wait4_c")), 0);
    assert!(run_neg_pgid.deaths().contains(&(2, LINUX_SIGKILL)));
    assert!(run_neg_pgid.deaths().contains(&(3, LINUX_SIGKILL)));
    assert!(!run_neg_pgid.deaths().iter().any(|(pid, _)| *pid == 4));
    assert_eq!(run_neg_pgid.exit_code(), 0);

    // 2. Test kill(0, sig) from a non-init group member
    let run_kill_zero = run(vec![
        Step::Sys(sys::fork()), // Process A (PID 2)
        Step::ChildMarker(vec![
            Step::Sys(setpgid(0, 0).ret(0)), // establish group 2
            pipe_to_slots(0, 1),             // park pipe for Worker 3
            pipe_to_slots(2, 3),             // sync pipe: Worker (write 3) -> Process A (read 2)
            Step::Sys(sys::fork()),          // Worker (PID 3)
            Step::ChildMarker(vec![
                Step::Sys(sys::write(slot(3), b"W").ret(1)),
                Step::Sys(sys::read(slot(0), 10).death(LINUX_SIGKILL)),
            ]),
            Step::Sys(sys::read(slot(2), 1).ret(1)), // wait for Worker 3 to be alive
            await_parked(3, "read"),
            Step::Sys(sys::fork()), // Sender (PID 4)
            Step::ChildMarker(vec![
                Step::Sys(sys::kill(0, LINUX_SIGKILL).death(LINUX_SIGKILL)), // kill own group (group 2)
            ]),
            Step::Sys(sys::read(slot(0), 10).death(LINUX_SIGKILL)),
        ]),
        Step::Sys(wait4_labeled("wait4_1", -1, 0)), // Root reaps A
        Step::Sys(wait4_labeled("wait4_2", -1, 0)), // Root reaps adopted child
        Step::Sys(wait4_labeled("wait4_3", -1, 0)), // Root reaps adopted child
        Step::Sys(sys::exit_group(0)),
    ]);

    assert_eq!(
        wtermsig(wait_status(&run_kill_zero, "wait4_1")),
        LINUX_SIGKILL
    );
    assert_eq!(
        wtermsig(wait_status(&run_kill_zero, "wait4_2")),
        LINUX_SIGKILL
    );
    assert_eq!(
        wtermsig(wait_status(&run_kill_zero, "wait4_3")),
        LINUX_SIGKILL
    );
    assert!(run_kill_zero.deaths().contains(&(2, LINUX_SIGKILL)));
    assert!(run_kill_zero.deaths().contains(&(3, LINUX_SIGKILL)));
    assert!(run_kill_zero.deaths().contains(&(4, LINUX_SIGKILL)));
    assert_eq!(run_kill_zero.exit_code(), 0);
}

/// `kill` on a non-existent PID fails with `ESRCH`.
///
/// Authority: `man 2 kill` (signaling non-existent PID yields ESRCH).
#[test]
fn kill_of_a_non_existent_pid_is_esrch() {
    let run = run(vec![
        Step::Sys(sys::kill(99999, 0).errno(LINUX_ESRCH)),
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}

/// `kill(pid, 0)` probes the existence of a live process and a zombie process, and returns `ESRCH` after reap.
///
/// Authority: `man 2 kill` (signal 0 probes process existence; zombie processes remain probeable).
#[test]
fn kill_signal_zero_probes_existence() {
    let run = run(vec![
        pipe_to_slots(0, 1), // sync pipe: parent (write 1) -> child (read 0)
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::read(slot(0), 1).ret(1)), // wait for parent's live probe
            Step::Sys(sys::exit_group(0)),
        ]),
        await_parked(last_child(), "read"),
        Step::Sys(sys::kill(last_child(), 0).ret(0)), // probe live child
        Step::Sys(sys::write(slot(1), b"x").ret(1)),  // unblock child
        Step::Sys(waitid(LINUX_P_PID, last_child(), LINUX_WEXITED | LINUX_WNOWAIT).ret(0)), // establish zombie
        Step::Sys(sys::kill(last_child(), 0).ret(0)), // probe zombie child before reap
        Step::Sys(sys::wait4(last_child(), 0)),       // reap child
        Step::Sys(sys::kill(last_child(), 0).errno(LINUX_ESRCH)), // probed after reap -> ESRCH
        Step::Sys(sys::exit_group(0)),
    ]);
    assert_eq!(run.exit_code(), 0);
}
