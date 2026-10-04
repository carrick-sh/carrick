//! Deterministic reductions of embed-el1-sched's fork-storm shape.
//!
//! Linux authority: fork(2) copies only the calling thread and gives the child
//! its own descriptor table referring to the same open descriptions; clone(2)
//! with CLONE_FILES shares the table; pipe(7)/poll(2) preserve unread bytes and
//! level readiness; set_tid_address(2) clears/wakes the joining thread;
//! wait(2) reports an exited child once even if exit precedes wait enrollment.
//! These tests exercise host kernel operations, not EL1 births or VM scheduling.

use carrick_abi::LINUX_ECHILD;
use carrick_kernel_example::{
    RunReport, ScriptCheckpoint, ScriptPausePoint, ScriptedBackend, Step, Syscall, alloc_word,
    await_parked, last_child, slot, sys,
};

const REPORT: &[u8; 8] = b"report08";

fn labeled(mut call: Syscall, label: &'static str) -> Syscall {
    call.label = label;
    call
}

fn pipe() -> Step {
    Step::Sys(
        sys::pipe2(0)
            .ret(0)
            .save_out_i32(0, 0, 0)
            .save_out_i32(0, 1, 1),
    )
}

/// The child performs a real clear_child_tid join before reporting. Enrollment
/// history, not a host sleep, makes its sibling exit after the join has parked.
fn child_join() -> Vec<Step> {
    vec![
        Step::Sys(sys::getpid().save(3)),
        alloc_word(4, 100),
        Step::Sys(labeled(sys::clone_thread(0), "child_clone")),
        Step::ChildMarker(vec![
            Step::Sys(sys::set_tid_address(slot(4))),
            await_parked(slot(3), "child_join"),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::Sys(sys::futex_wait_labeled("child_join", slot(4), 100).ret(0)),
    ]
}

fn collect_report() -> Vec<Step> {
    vec![
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(labeled(sys::ppoll_one(slot(0), 1, None), "report_poll").ret(1)),
        Step::Sys(labeled(sys::read(slot(0), 8), "report_read").ret(8)),
        Step::Sys(labeled(sys::wait4(last_child(), 0), "reap")),
        Step::Sys(sys::wait4(last_child(), 1).errno(LINUX_ECHILD)),
        Step::Sys(sys::close(slot(0)).ret(0)),
    ]
}

fn assert_report(run: &RunReport) {
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("report_read"), REPORT);
    assert_eq!(run.output("reap"), &[0; 4]);
    assert!(run.ret("reap") > 1);
    assert_eq!(run.dispatches_for_tid(1, "report_read"), 1);
    assert_eq!(
        run.dispatches_for_pid(run.ret("reap") as i32, "child_join"),
        1
    );
    assert_eq!(run.deaths(), &[]);
}

#[test]
/// Rules out losing the fresh pipe or its closes through a host clone's
/// claim/preparation overlapping fork; does not cover runtime zone switching.
fn fork_report_and_reap_while_parent_sibling_clone_is_reserved() {
    for point in [
        ScriptPausePoint::AfterCloneReservation,
        ScriptPausePoint::AfterClonePreparation,
    ] {
        let reached = ScriptCheckpoint::default();
        let resume = ScriptCheckpoint::default();
        let shared_close_checked = ScriptCheckpoint::default();
        let mut script = vec![
            // Retain numeric pipe slots in the storm thread, then reuse the
            // same numbers for the fresh report pipe while its clone pauses.
            pipe(),
            alloc_word(2, 100),
            Step::Sys(labeled(sys::clone_thread(0), "storm_start")),
            Step::ChildMarker(vec![
                Step::Sys(sys::set_tid_address(slot(2))),
                Step::Sys(labeled(sys::clone_thread(0), "storm_clone")),
                Step::ChildMarker(vec![
                    // CLONE_FILES must see the leader's later closes. A
                    // copied table would keep a writer live here.
                    Step::Sys(
                        labeled(sys::write(slot(1), b"x"), "storm_shared_close")
                            .errno(carrick_abi::LINUX_EBADF),
                    ),
                    Step::SignalCheckpoint(shared_close_checked.clone()),
                    Step::Sys(sys::exit_thread(0)),
                ]),
                Step::AwaitCheckpoint(shared_close_checked),
                await_parked(1, "storm_join"),
                Step::Sys(sys::exit_thread(0)),
            ]),
            Step::AwaitCheckpoint(reached.clone()),
            Step::Sys(sys::close(slot(0)).ret(0)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            // Create the fresh report pipe AFTER the sibling captured its
            // resources. Its CLONE_FILES table must still be the live table.
            pipe(),
            Step::Sys(sys::fork()),
        ];
        let mut child = vec![Step::Sys(sys::close(slot(0)).ret(0))];
        child.extend(child_join());
        child.extend([
            await_parked(1, "report_poll"),
            Step::Sys(sys::write(slot(1), REPORT).ret(8)),
            Step::Sys(sys::exit_group(0)),
        ]);
        script.push(Step::ChildMarker(child));
        script.extend(collect_report());
        script.extend([
            Step::SignalCheckpoint(resume.clone()),
            Step::Sys(sys::futex_wait_labeled("storm_join", slot(2), 100).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]);
        let run = ScriptedBackend::new()
            .with_pause("storm_clone", point, reached, resume)
            .run_root(script)
            .unwrap_or_else(|error| panic!("{point:?}: {error}"));
        assert_report(&run);
        assert_eq!(run.tasks_started(), 5);
        assert_eq!(run.dispatches_for_tid(1, "storm_join"), 1);
        assert_eq!(run.dispatches_for_tid(1, "report_poll"), 2);
        assert_eq!(
            run.completions()
                .iter()
                .filter(|c| c.label == "storm_shared_close"
                    && c.result == Err(carrick_abi::LINUX_EBADF))
                .count(),
            1
        );
    }
}

#[test]
/// Rules out ignoring durable unread bytes when poll starts after the write.
fn unread_child_report_is_ready_before_poll_starts() {
    let written = ScriptCheckpoint::default();
    let mut child = vec![Step::Sys(sys::close(slot(0)).ret(0))];
    child.extend(child_join());
    child.extend([
        Step::Sys(sys::write(slot(1), REPORT).ret(8)),
        Step::SignalCheckpoint(written.clone()),
        Step::Sys(sys::exit_group(0)),
    ]);
    let mut script = vec![
        pipe(),
        Step::Sys(sys::fork()),
        Step::ChildMarker(child),
        Step::AwaitCheckpoint(written),
    ];
    script.extend(collect_report());
    script.push(Step::Sys(sys::exit_group(0)));
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("poll must see already-written bytes");
    assert_report(&run);
    assert_eq!(run.dispatches_for_tid(1, "report_poll"), 1);
}

#[test]
/// Rules out a childless exit depending on the parent's prepared fork release.
fn child_exit_while_parent_has_another_prepared_fork() {
    let fork_prepared = ScriptCheckpoint::default();
    let child_exited = ScriptCheckpoint::default();
    let fork_finished = ScriptCheckpoint::default();
    let mut child = vec![Step::Sys(sys::close(slot(0)).ret(0))];
    child.extend(child_join());
    child.extend([
        await_parked(1, "report_poll"),
        Step::Sys(sys::write(slot(1), REPORT).ret(8)),
        Step::AwaitCheckpoint(fork_prepared.clone()),
        Step::Sys(labeled(sys::exit_group(0), "first_child_exit")),
    ]);
    let script = vec![
        pipe(),
        Step::Sys(sys::fork().save(5)),
        Step::ChildMarker(child),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(labeled(sys::ppoll_one(slot(0), 1, None), "report_poll").ret(1)),
        Step::Sys(labeled(sys::read(slot(0), 8), "report_read").ret(8)),
        Step::Sys(labeled(sys::fork(), "second_fork").save(6)),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]),
        Step::SignalCheckpoint(fork_finished.clone()),
        Step::Sys(labeled(sys::wait4(slot(5), 0), "reap")),
        Step::Sys(sys::wait4(slot(5), 1).errno(LINUX_ECHILD)),
        Step::Sys(sys::wait4(slot(6), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .with_pause(
            "second_fork",
            ScriptPausePoint::AfterForkPreparation,
            fork_prepared,
            child_exited.clone(),
        )
        .with_pause(
            "first_child_exit",
            ScriptPausePoint::AfterProcessExit,
            child_exited,
            fork_finished,
        )
        .run_root(script)
        .expect("child exit must not wait on an unrelated parent fork transaction");
    assert_report(&run);
    assert_eq!(run.dispatches_for_tid(1, "reap"), 1);
}

#[test]
/// Rules out losing default SIGCHLD/zombie publication while the parent's
/// exact task is reserved for sibling publication.
fn child_exit_while_parent_holds_sibling_clone_publication_reservation() {
    let clone_reserved = ScriptCheckpoint::default();
    let child_exited = ScriptCheckpoint::default();
    let clone_finished = ScriptCheckpoint::default();
    let mut child = vec![Step::Sys(sys::close(slot(0)).ret(0))];
    child.extend(child_join());
    child.extend([
        await_parked(1, "report_poll"),
        Step::Sys(sys::write(slot(1), REPORT).ret(8)),
        Step::AwaitCheckpoint(clone_reserved.clone()),
        Step::Sys(labeled(sys::exit_group(0), "child_exit")),
    ]);
    let script = vec![
        pipe(),
        Step::Sys(sys::fork()),
        Step::ChildMarker(child),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(labeled(sys::ppoll_one(slot(0), 1, None), "report_poll").ret(1)),
        Step::Sys(labeled(sys::read(slot(0), 8), "report_read").ret(8)),
        Step::Sys(labeled(sys::clone_thread(0), "parent_clone")),
        Step::ChildMarker(vec![Step::Sys(sys::exit_thread(0))]),
        Step::SignalCheckpoint(clone_finished.clone()),
        Step::Sys(labeled(sys::wait4(last_child(), 0), "reap")),
        Step::Sys(sys::wait4(last_child(), 1).errno(LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .with_pause(
            "parent_clone",
            ScriptPausePoint::AfterClonePublicationReservation,
            clone_reserved,
            child_exited.clone(),
        )
        .with_pause(
            "child_exit",
            ScriptPausePoint::AfterProcessExit,
            child_exited,
            clone_finished,
        )
        .run_root(script)
        .expect("child exit notification must survive the parent's reserved clone publication");
    assert_report(&run);
    assert_eq!(run.dispatches_for_tid(1, "reap"), 1);
}

#[test]
/// Rules out losing pipe readiness between admission's check and enrollment.
fn child_report_between_poll_readiness_check_and_enrollment() {
    let reached = ScriptCheckpoint::default();
    let resume = ScriptCheckpoint::default();
    let mut child = vec![Step::Sys(sys::close(slot(0)).ret(0))];
    child.extend(child_join());
    child.extend([
        Step::AwaitCheckpoint(reached.clone()),
        Step::Sys(sys::write(slot(1), REPORT).ret(8)),
        Step::SignalCheckpoint(resume.clone()),
        Step::Sys(sys::exit_group(0)),
    ]);
    let mut script = vec![pipe(), Step::Sys(sys::fork()), Step::ChildMarker(child)];
    script.extend(collect_report());
    script.push(Step::Sys(sys::exit_group(0)));
    let run = ScriptedBackend::new()
        .with_pause(
            "report_poll",
            ScriptPausePoint::BeforeWaitEnrollment,
            reached,
            resume,
        )
        .run_root(script)
        .expect("unread child report must remain ready across enrollment");
    assert_report(&run);
    assert_eq!(run.dispatches_for_tid(1, "report_poll"), 2);
}

#[test]
/// Rules out losing a host pipe write edge after the parent poller enrolls.
fn child_report_after_poll_enrollment() {
    let mut child = vec![Step::Sys(sys::close(slot(0)).ret(0))];
    child.extend(child_join());
    child.extend([
        await_parked(1, "report_poll"),
        Step::Sys(sys::write(slot(1), REPORT).ret(8)),
        Step::Sys(sys::exit_group(0)),
    ]);
    let mut script = vec![pipe(), Step::Sys(sys::fork()), Step::ChildMarker(child)];
    script.extend(collect_report());
    script.push(Step::Sys(sys::exit_group(0)));
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("enrolled poller must wake");
    assert_report(&run);
    assert_eq!(run.dispatches_for_tid(1, "report_poll"), 2);
}

#[test]
/// Rules out losing a durable exit between the child scan and subscription,
/// including default SIGCHLD and one-time zombie consumption.
fn child_exit_between_wait_scan_and_enrollment() {
    let reached = ScriptCheckpoint::default();
    let resume = ScriptCheckpoint::default();
    let mut child = child_join();
    child.extend([
        Step::AwaitCheckpoint(reached.clone()),
        Step::Sys(sys::exit_group(0)),
    ]);
    // A sibling observer consumes no zombie. Once waitid(WNOWAIT) has seen
    // the exit, it releases the leader's not-yet-enrolled wait. SIGCHLD's
    // default disposition must neither auto-reap nor interrupt the wait.
    let script = vec![
        Step::Sys(sys::fork().save(5)),
        Step::ChildMarker(child),
        Step::Sys(labeled(sys::clone_thread(0), "observer_clone")),
        Step::ChildMarker(vec![
            Step::Sys(sys::waitid(1, slot(5), 4 | 0x0100_0000)),
            Step::SignalCheckpoint(resume.clone()),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::Sys(labeled(sys::wait4(slot(5), 0), "reap")),
        Step::Sys(sys::wait4(slot(5), 1).errno(LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .with_pause(
            "reap",
            ScriptPausePoint::BeforeWaitEnrollment,
            reached,
            resume,
        )
        .run_root(script)
        .expect("exit before enrollment must be durable and reapable once");
    assert_eq!(run.output("reap"), &[0; 4]);
    assert_eq!(run.dispatches_for_tid(1, "reap"), 2);
}
