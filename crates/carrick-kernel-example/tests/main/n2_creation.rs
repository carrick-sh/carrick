//! Landing A of N2: Linux semantics plus deterministic creation work.
//!
//! Authority: https://man7.org/linux/man-pages/man2/{fork,vfork,clone,wait,execve}.2.html
//! and https://man7.org/linux/man-pages/man7/pipe.7.html. Fork copies slots and
//! memory, threads share memory, short pipe reads preserve bytes, wait consumes
//! one status, and a failed exec must not release a vfork parent.
//!
//! The zero-semantic-dispatch budget reds are a separate follow-on commit on
//! work/n2a-witness, retained for the N2 ownership landing. This commit contains
//! green semantic witnesses and current-path work accounting only; it does not
//! accept the N2 zero-dispatch budget or provide a total exit census.
//!
//! No executor/slot override is installed. ScriptedBackend uses a host thread
//! per actor, not the runtime's bounded executor: default-pool exhaustion is
//! UNSUPPORTED here. It also rejects vfork/exec outcomes, so that composition
//! uses public kernel transactions and concrete Example MM backends below.
//! It proves graph cutover/rollback, not ELF loading or guest execution.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use carrick_abi::syscall::nr;
use carrick_abi::{LINUX_ECHILD, LinuxCloneFlags};
use carrick_hal::{NullHostSignalBridge, ThreadId};
use carrick_kernel::kernel::{
    ClonePlan, ExecError, KernelFailpoint, LinuxWaitStatus, VforkReleaseReason, WaitMode,
    WaitOutcome,
};
use carrick_kernel_example::operand::ScriptCheckpoint;
use carrick_kernel_example::{
    AddressSpace, AsidAllocator, ExampleProcess, RunReport, ScriptedBackend, Step, Syscall,
    alloc_word, await_parked, slot, sys, write_word,
};
use carrick_observability::work_meter::{WorkMeter, WorkMetric};

fn named(mut call: Syscall, label: &'static str) -> Step {
    call.label = label;
    Step::Sys(call)
}

fn pipe(read: usize, write: usize) -> Step {
    Step::Sys(
        sys::pipe2(0)
            .ret(0)
            .save_out_i32(0, 0, read)
            .save_out_i32(0, 1, write),
    )
}

fn write_marker() -> Step {
    named(
        Syscall::new(
            "marker",
            nr::WRITE,
            [slot(1), slot(12), 4.into(), 0.into(), 0.into(), 0.into()],
        )
        .ret(4),
        "marker",
    )
}

fn fork_creator(admitted: ScriptCheckpoint) -> Vec<Step> {
    let closed = ScriptCheckpoint::default();
    vec![
        write_word(12, 22),
        pipe(0, 1),
        write_marker(),
        named(sys::read(slot(0), 4).ret(4), "private_marker"),
        Step::Sys(sys::getpid().save(3)),
        named(sys::fork().save(2), "creation"),
        Step::ChildMarker(vec![
            Step::Sys(sys::close(slot(0)).ret(0)),
            await_parked(slot(3), "source_prefix"),
            Step::Sys(sys::write(slot(1), b"hi").ret(2)),
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::SignalCheckpoint(closed.clone()),
            // Ensure the parent's wait owns one park/resume episode.
            await_parked(slot(3), "child_wait"),
            Step::Sys(sys::exit_group(7)),
        ]),
        Step::SignalCheckpoint(admitted),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // fd 4 is reused, but the child's fd 4 still names the old pipe OFD.
        pipe(4, 5),
        Step::Sys(sys::write(slot(5), b"new").ret(3)),
        named(sys::read(slot(4), 3).ret(3), "reused_fd"),
        named(sys::read(slot(0), 4).ret(2), "source_prefix"),
        Step::AwaitCheckpoint(closed),
        named(sys::read(slot(0), 4).ret(0), "source_eof"),
        named(sys::wait4(slot(2), 0), "child_wait"),
        Step::Sys(sys::wait4(slot(2), 0).errno(LINUX_ECHILD)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(4)).ret(0)),
        Step::Sys(sys::close(slot(5)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]
}

fn thread_creator(admitted: ScriptCheckpoint) -> Vec<Step> {
    vec![
        pipe(0, 1),
        Step::Sys(sys::getpid().save(3)),
        alloc_word(6, 100),
        named(sys::clone_thread(0).save(2), "creation"),
        Step::ChildMarker(vec![
            Step::Sys(sys::set_tid_address(slot(6))),
            write_word(12, 22),
            // Shared file slots: close/reuse before the leader observes them.
            Step::Sys(sys::close(slot(1)).ret(0)),
            Step::Sys(sys::dup(slot(0)).ret(4)),
            await_parked(slot(3), "thread_join"),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::SignalCheckpoint(admitted),
        named(
            sys::futex_wait_labeled("thread_join", slot(6), 100).ret(0),
            "thread_join",
        ),
        // A pipe read end at reused fd 4 is still a read end after thread exit.
        Step::Sys(sys::write(4, b"x").errno(carrick_abi::LINUX_EBADF)),
        // The join observed clear_child_tid; the sibling's memory write survives.
        pipe(7, 1),
        write_marker(),
        named(sys::read(slot(7), 4).ret(4), "shared_marker"),
        named(
            Syscall::new(
                "cleared_tid",
                nr::WRITE,
                [slot(1), slot(6), 4.into(), 0.into(), 0.into(), 0.into()],
            )
            .ret(4),
            "cleared_tid",
        ),
        named(sys::read(slot(7), 4).ret(4), "joined_zero"),
        Step::Sys(sys::exit_group(0)),
    ]
}

/// All N creators are live before one release; each is a separate MM at the
/// same inherited VA. Root's marker remains 11 while creators observe 22.
fn composed(n: usize, threads: bool) -> RunReport {
    let go = ScriptCheckpoint::default();
    let mut script = vec![alloc_word(12, 11)];
    let mut ready = Vec::new();
    let mut admissions = Vec::new();
    for _ in 0..n {
        let checkpoint = ScriptCheckpoint::default();
        let admitted = ScriptCheckpoint::default();
        let mut creator = vec![
            Step::SignalCheckpoint(checkpoint.clone()),
            Step::AwaitCheckpoint(go.clone()),
        ];
        creator.extend(if threads {
            thread_creator(admitted.clone())
        } else {
            fork_creator(admitted.clone())
        });
        script.push(Step::Sys(sys::fork()));
        script.push(Step::ChildMarker(creator));
        ready.push(checkpoint);
        admissions.push(admitted);
    }
    script.extend(ready.into_iter().map(Step::AwaitCheckpoint));
    script.push(Step::SignalCheckpoint(go));
    // Each inner fork/clone publishes one admission. Waiting for all N here
    // makes the unchanged checkpoint bound apply to one creator's progress,
    // not the cumulative time until any creator happens to exit.
    script.extend(admissions.into_iter().map(Step::AwaitCheckpoint));
    // Root stays alive until every creator is reaped.
    for _ in 0..n {
        script.push(named(sys::wait4(-1, 0), "creator_wait"));
    }
    script.extend([
        pipe(0, 1),
        write_marker(),
        named(sys::read(slot(0), 4).ret(4), "root_marker"),
        Step::Sys(sys::wait4(-1, 0).errno(LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0)),
    ]);
    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("composed creation");
    assert_eq!(run.work_snapshot().dropped_events(), 0);
    assert!(run.work_snapshot().unknown_metrics().is_empty());
    assert_eq!(
        run.work_snapshot().get(WorkMetric::KernelDispatches),
        Some(run.dispatches() as u64)
    );
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.tasks_started(), 1 + 2 * n);
    assert_eq!(run.outputs_for("creator_wait").len(), n);
    for output in run.outputs_for("creator_wait") {
        assert_eq!(&output.bytes[..4], &0i32.to_le_bytes());
    }
    assert_eq!(run.outputs_for("root_marker")[0].bytes, 11i32.to_le_bytes());
    let marker = if threads {
        "shared_marker"
    } else {
        "private_marker"
    };
    assert_eq!(run.outputs_for(marker).len(), n);
    for output in run.outputs_for(marker) {
        assert_eq!(output.bytes, 22i32.to_le_bytes());
    }
    let creations: Vec<_> = run
        .completions()
        .iter()
        .filter(|c| c.label == "creation")
        .collect();
    assert_eq!(creations.len(), n);
    for creation in creations {
        assert!(creation.result.unwrap() > i64::from(creation.pid));
        assert_eq!(run.dispatches_for_pid(creation.pid, "creation"), 1);
        if threads {
            assert_eq!(run.dispatches_for_pid(creation.pid, "thread_join"), 1);
        } else {
            assert_eq!(run.dispatches_for_pid(creation.pid, "source_prefix"), 2);
            assert_eq!(run.dispatches_for_pid(creation.pid, "child_wait"), 2);
            let waited = run
                .completions()
                .iter()
                .find(|c| c.pid == creation.pid && c.label == "child_wait")
                .unwrap();
            assert_eq!(waited.result, creation.result);
            let pipes: Vec<_> = run
                .outputs_for("pipe2")
                .into_iter()
                .filter(|o| o.pid == creation.pid)
                .collect();
            assert_eq!(pipes.len(), 2);
            assert_eq!(
                &pipes[1].bytes[..4],
                &pipes[0].bytes[4..8],
                "reuse the exact closed writer fd"
            );
        }
        let labels: std::collections::HashSet<_> =
            run.completions().iter().map(|c| c.label).collect();
        let parent_work: usize = labels
            .iter()
            .map(|label| run.dispatches_for_pid(creation.pid, label))
            .sum();
        let child_work: usize = if threads {
            0
        } else {
            let child = i32::try_from(creation.result.unwrap()).unwrap();
            labels
                .iter()
                .map(|label| run.dispatches_for_pid(child, label))
                .sum()
        };
        assert_eq!(
            parent_work + child_work,
            if threads { 15 } else { 23 },
            "one completed creation operation, including its deterministic resumes"
        );
    }
    if threads {
        assert_eq!(run.outputs_for("joined_zero").len(), n);
        for output in run.outputs_for("joined_zero") {
            assert_eq!(output.bytes, 0i32.to_le_bytes());
        }
    } else {
        for output in run.outputs_for("source_prefix") {
            assert_eq!(output.bytes, b"hi\0\0");
        }
        for output in run.outputs_for("reused_fd") {
            assert_eq!(output.bytes, b"new");
        }
        for output in run.outputs_for("child_wait") {
            assert_eq!(&output.bytes[..4], &(7i32 << 8).to_le_bytes());
        }
    }
    // Include all scaffolding, not only successful calls. At most one restart
    // per blocking read/wait, with one owned futex completion for each join.
    assert!(
        run.dispatches() <= (if threads { 18 } else { 26 }) * n + 5,
        "dispatch work: {}",
        run.dispatches()
    );
    run
}

#[test]
fn fork_pipe_wait_at_1_8_32() {
    for n in [1, 8, 32] {
        composed(n, false);
    }
}

#[test]
fn thread_create_join_at_1_8_32() {
    for n in [1, 8, 32] {
        composed(n, true);
    }
}

#[test]
fn vfork_failed_prepare_exec_wait_at_1_8_32() {
    for n in [1, 8, 32] {
        let asids = AsidAllocator::new();
        let (_, root) = ExampleProcess::boot_root(
            1,
            "n2-root",
            Arc::new(NullHostSignalBridge::default()),
            AddressSpace::allocate(&asids).unwrap(),
        )
        .unwrap();
        let kernel = Arc::clone(root.kernel());
        let mut creators = Vec::new();
        for i in 0..n {
            let current = kernel
                .context(root.task().key().id, root.thread().key().tid)
                .unwrap();
            let child = kernel
                .reserve_fork(
                    &current,
                    ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
                    "n2-creator".into(),
                    None,
                )
                .unwrap()
                .prepare_with_mm_backend(
                    AddressSpace::allocate(&asids).unwrap().mm_backend(),
                    ThreadId::from_guest_supplied_tid(100 + i as i32),
                )
                .unwrap()
                .commit()
                .unwrap()
                .start_child()
                .unwrap();
            assert_ne!(child.context().shared().mm().id(), root.shared().mm().id());
            creators.push(child.into_parts().0);
        }
        // Scope only the measured vfork operations, after parent scaffolding.
        // Empty file tables cost one 96-byte fork header per operation; a
        // failed image prepare must not cause another fork copy/publication.
        let meter = WorkMeter::default();
        let work = meter.new_scope();
        kernel.set_work_scope(work.clone());
        let go = ScriptCheckpoint::default();
        std::thread::scope(|scope| {
            let handles: Vec<_> = creators
                .into_iter()
                .enumerate()
                .map(|(i, parent)| {
                    let kernel = Arc::clone(&kernel);
                    let go = go.clone();
                    let backend = AddressSpace::allocate(&asids).unwrap().mm_backend();
                    scope.spawn(move || {
                        assert!(go.wait());
                        let child = kernel
                            .reserve_fork(
                                &parent,
                                ClonePlan::from_flags(LinuxCloneFlags::VM | LinuxCloneFlags::VFORK)
                                    .unwrap(),
                                "n2-vfork".into(),
                                None,
                            )
                            .unwrap()
                            .prepare_shared_mm(ThreadId::from_guest_supplied_tid(200 + i as i32))
                            .unwrap()
                            .commit()
                            .unwrap()
                            .start_child()
                            .unwrap();
                        let (child, wait) = child.into_parts();
                        let wait = wait.unwrap();
                        let old_mm = parent.shared().mm().id();
                        assert_eq!(child.shared().mm().id(), old_mm);
                        assert_eq!(wait.released_reason(), None);
                        assert!(matches!(
                            kernel.prepare_exec_with_mm_backend(
                                &child,
                                Arc::clone(&backend),
                                Some(KernelFailpoint::AfterBackendPrepare)
                            ),
                            Err(ExecError::Injected(KernelFailpoint::AfterBackendPrepare))
                        ));
                        assert_eq!(wait.released_reason(), None);
                        assert_eq!(child.shared().mm().id(), old_mm);
                        let prepared = kernel
                            .prepare_exec_with_mm_backend(&child, backend, None)
                            .unwrap();
                        assert_ne!(prepared.replacement_mm_id(), old_mm);
                        let successor = kernel.commit_exec(prepared, None).unwrap();
                        assert_eq!(wait.released_reason(), Some(VforkReleaseReason::Exec));
                        assert_ne!(successor.shared().mm().id(), old_mm);
                        assert_eq!(parent.shared().mm().id(), old_mm);
                        kernel
                            .exit_task(
                                successor.task().key().id,
                                LinuxWaitStatus::from_wait_encoding(7 << 8),
                                None,
                            )
                            .unwrap();
                        // Exit must not change the already consumed exec release.
                        assert_eq!(wait.released_reason(), Some(VforkReleaseReason::Exec));
                        let pid = parent.task().key().id;
                        let target = Some(successor.task().key().id);
                        let WaitOutcome::Exited(zombie) =
                            kernel.wait_child(pid, target, WaitMode::Consume).unwrap()
                        else {
                            unreachable!("child must be a zombie");
                        };
                        assert_eq!(zombie.status, LinuxWaitStatus::from_wait_encoding(7 << 8));
                        assert!(matches!(
                            kernel.wait_child(pid, target, WaitMode::Consume).unwrap(),
                            WaitOutcome::NoChild
                        ));
                        kernel
                            .exit_task(pid, LinuxWaitStatus::from_wait_encoding(0), None)
                            .unwrap();
                    })
                })
                .collect();
            go.signal();
            for handle in handles {
                handle.join().unwrap();
            }
        });
        for _ in 0..n {
            assert!(matches!(
                kernel
                    .wait_child(root.task().key().id, None, WaitMode::Consume)
                    .unwrap(),
                WaitOutcome::Exited(_)
            ));
        }
        let snapshot = work.snapshot().unwrap();
        assert_eq!(snapshot.dropped_events(), 0);
        assert!(snapshot.unknown_metrics().is_empty());
        assert_eq!(
            snapshot.get(WorkMetric::GuestMemoryCopyBytes),
            Some(96 * n as u64)
        );
        assert!(matches!(
            kernel
                .wait_child(root.task().key().id, None, WaitMode::Consume)
                .unwrap(),
            WaitOutcome::NoChild
        ));
    }
}
