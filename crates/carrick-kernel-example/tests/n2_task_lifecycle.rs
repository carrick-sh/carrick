//! D-prep bindings for creation-native-path, child exit notification and
//! thread-lifecycle. No product routing or ownership changes.
//!
//! The scripts enter the real host dispatcher. Its measured birth/exit/wait
//! entries are a necessary subset of host task-service work, as in landing A,
//! not a fabricated EL1 service counter or a complete exit census. The ignored
//! *_budget_red bindings run all semantic assertions before demanding zero.
//! Execute them explicitly with `--ignored --nocapture` during landing D.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use carrick_abi::{LINUX_ECHILD, LINUX_SA_NOCLDWAIT, LINUX_SIGCHLD, LINUX_WNOHANG};
use carrick_kernel_example::{
    RunReport, ScriptCheckpoint, ScriptedBackend, Step, Syscall, await_parked, slot, sys,
};
use carrick_observability::work_meter::WorkMetric;

fn call(mut syscall: Syscall, label: &'static str) -> Step {
    syscall.label = label;
    Step::Sys(syscall)
}

fn birth(save: usize) -> Step {
    call(sys::fork().save(save), "d_birth")
}

fn exit(code: i32) -> Step {
    call(sys::exit_group(code), "d_exit")
}

fn wait(target: impl Into<carrick_kernel_example::Operand>, options: i32) -> Step {
    call(sys::wait4(target, options), "d_wait")
}

fn checked(run: RunReport) -> RunReport {
    assert_eq!(run.exit_code(), 0);
    assert!(run.deaths().is_empty());
    let snapshot = run.work_snapshot();
    assert_eq!(snapshot.dropped_events(), 0);
    assert!(snapshot.unknown_metrics().is_empty());
    assert_eq!(
        snapshot.get(WorkMetric::KernelDispatches),
        Some(run.dispatches() as u64)
    );
    run
}

/// Both independently owned parents are live before release; N children or
/// sibling threads share each parent's task graph. Root remains a third live
/// process until the measured operations and both parent reaps complete.
fn two_parents(
    n: usize,
    make: impl Fn(Vec<ScriptCheckpoint>, ScriptCheckpoint) -> Vec<Step>,
    status: i32,
) -> RunReport {
    let go = ScriptCheckpoint::default();
    let population_go = ScriptCheckpoint::default();
    let mut script = Vec::new();
    let mut ready = Vec::new();
    let mut populations = Vec::new();
    for index in 0..2 {
        let reached = ScriptCheckpoint::default();
        let progress = (0..n)
            .map(|_| ScriptCheckpoint::default())
            .collect::<Vec<_>>();
        let mut parent = vec![
            Step::SignalCheckpoint(reached.clone()),
            Step::AwaitCheckpoint(go.clone()),
        ];
        parent.extend(make(progress.clone(), population_go.clone()));
        script.push(call(sys::fork().save(index), "scaffold_birth"));
        script.push(Step::ChildMarker(parent));
        ready.push(reached);
        populations.extend(progress);
    }
    script.extend(ready.into_iter().map(Step::AwaitCheckpoint));
    script.push(Step::SignalCheckpoint(go));
    script.extend(populations.into_iter().map(Step::AwaitCheckpoint));
    script.push(Step::SignalCheckpoint(population_go));
    for index in 0..2 {
        script.push(call(sys::wait4(slot(index), 0), "scaffold_reap"));
    }
    script.push(call(sys::exit_group(0), "scaffold_exit"));
    let run = checked(
        ScriptedBackend::new()
            .run_root(script)
            .expect("two live parents"),
    );
    for output in run.outputs_for("scaffold_reap") {
        assert_eq!(&output.bytes[..4], &(status << 8).to_le_bytes());
    }
    run
}

fn attempts(run: &RunReport, label: &str) -> usize {
    let pids: BTreeSet<_> = run.completions().iter().map(|c| c.pid).collect();
    pids.into_iter()
        .map(|pid| run.dispatches_for_pid(pid, label))
        .sum()
}

/// Actual dispatcher attempts, including restarts and failed/ECHILD calls.
/// Do not count only successful completions and call them service work.
fn task_services(run: &RunReport) -> usize {
    let pids: BTreeSet<_> = run.completions().iter().map(|c| c.pid).collect();
    pids.into_iter()
        .map(|pid| {
            ["d_birth", "d_exit", "d_wait", "d_nohang", "d_echild"]
                .into_iter()
                .map(|label| run.dispatches_for_pid(pid, label))
                .sum::<usize>()
        })
        .sum()
}

fn wait_scenario(n: usize, autoreap: bool) -> RunReport {
    let run = two_parents(
        n,
        |progress, population_go| {
            let release = ScriptCheckpoint::default();
            let mut parent = vec![Step::Sys(sys::getpid().save(4))];
            if autoreap {
                // sigaction(2), SA_NOCLDWAIT: no zombie; wait eventually gives
                // ECHILD after all live children terminate. Linux still generates
                // SIGCHLD; that delivery is a separate C/signed binding.
                // https://man7.org/linux/man-pages/man2/sigaction.2.html
                let mut action = [0u8; 32];
                action[8..16].copy_from_slice(&LINUX_SA_NOCLDWAIT.to_le_bytes());
                parent.push(Step::Sys(
                    sys::rt_sigaction(LINUX_SIGCHLD, &action[..], 0, 8).ret(0),
                ));
            }
            for i in 0..n {
                parent.push(birth(10 + i));
                parent.push(Step::ChildMarker(vec![
                    Step::AwaitCheckpoint(release.clone()),
                    // Normal wait's first child exits after wait has parked.
                    // SA_NOCLDWAIT's wait also waits until no child is alive.
                    await_parked(slot(4), "d_wait"),
                    exit(7),
                ]));
                parent.push(Step::SignalCheckpoint(progress[i].clone()));
            }
            parent.push(Step::AwaitCheckpoint(population_go));
            // wait4(2) refers to wait(2): WNOHANG is zero for a live child,
            // positive only for a waitable event, ECHILD after consumption.
            // https://man7.org/linux/man-pages/man2/wait4.2.html
            for i in 0..n {
                parent.push(call(
                    sys::wait4(slot(10 + i), LINUX_WNOHANG as i32).ret(0),
                    "d_nohang",
                ));
            }
            parent.push(Step::SignalCheckpoint(release));
            if autoreap {
                parent.push(call(sys::wait4(-1, 0).errno(LINUX_ECHILD), "d_wait"));
            } else {
                for i in 0..n {
                    parent.push(wait(slot(10 + i), 0));
                    parent.push(call(
                        sys::wait4(slot(10 + i), 0).errno(LINUX_ECHILD),
                        "d_echild",
                    ));
                }
            }
            parent.push(exit(0));
            parent
        },
        0,
    );
    assert_eq!(run.tasks_started(), 3 + 2 * n);
    assert_eq!(
        run.completions()
            .iter()
            .filter(|c| c.label == "d_nohang")
            .count(),
        2 * n
    );
    if !autoreap {
        let born: BTreeSet<_> = run
            .completions()
            .iter()
            .filter(|c| c.label == "d_birth")
            .map(|c| c.result.unwrap())
            .collect();
        let reaped: BTreeSet<_> = run
            .completions()
            .iter()
            .filter(|c| c.label == "d_wait")
            .map(|c| c.result.unwrap())
            .collect();
        assert_eq!(born.len(), 2 * n);
        assert_eq!(
            reaped, born,
            "each exact child consumed once by its own parent"
        );
        let by_parent = |label| {
            let mut children = BTreeMap::<_, BTreeSet<_>>::new();
            for completion in run.completions().iter().filter(|c| c.label == label) {
                children
                    .entry(completion.pid)
                    .or_default()
                    .insert(completion.result.unwrap());
            }
            children
        };
        let born = by_parent("d_birth");
        assert_eq!(born.len(), 2);
        assert!(born.values().all(|children| children.len() == n));
        assert_eq!(by_parent("d_wait"), born, "cross-parent child consumption");
        for output in run.outputs_for("d_wait") {
            assert_eq!(&output.bytes[..4], &(7i32 << 8).to_le_bytes());
        }
    } else {
        let waits: Vec<_> = run
            .completions()
            .iter()
            .filter(|c| c.label == "d_wait")
            .collect();
        assert_eq!(waits.len(), 2);
        assert!(waits.iter().all(|c| c.result == Err(LINUX_ECHILD)));
    }
    assert_eq!(attempts(&run, "d_birth"), 2 * n);
    assert_eq!(attempts(&run, "d_exit"), 2 * n + 2);
    assert_eq!(attempts(&run, "d_nohang"), 2 * n);
    run
}

fn group_scenario(n: usize) -> RunReport {
    let run = two_parents(
        n,
        |progress, population_go| {
            let mut parent = vec![Step::Sys(
                sys::pipe2(0)
                    .ret(0)
                    .save_out_i32(0, 0, 0)
                    .save_out_i32(0, 1, 1),
            )];
            for i in 0..n {
                parent.push(call(sys::clone_thread(0).save(10 + i), "d_birth"));
                parent.push(Step::ChildMarker(vec![
                    call(sys::read(slot(0), 1), "sibling_read"),
                    call(sys::getpid(), "must_not_run"),
                    exit(99),
                ]));
            }
            // exit_group(2): terminate every thread of this group, including
            // parked siblings. The other live parent is an independent group.
            // https://man7.org/linux/man-pages/man2/exit_group.2.html
            for i in 0..n {
                parent.push(await_parked(slot(10 + i), "sibling_read"));
                parent.push(Step::SignalCheckpoint(progress[i].clone()));
            }
            parent.push(Step::AwaitCheckpoint(population_go));
            parent.push(exit(37));
            parent
        },
        37,
    );
    assert_eq!(run.tasks_started(), 3 + 2 * n);
    assert!(!run.completions().iter().any(|c| c.label == "must_not_run"));
    for birth in run.completions().iter().filter(|c| c.label == "d_birth") {
        let tid = i32::try_from(birth.result.unwrap()).unwrap();
        assert_eq!(run.dispatches_for_tid(tid, "sibling_read"), 1);
        assert_eq!(run.dispatches_for_tid(tid, "must_not_run"), 0);
    }
    assert_eq!(task_services(&run), 2 * n + 2);
    run
}

fn reparent_scenario(n: usize) -> RunReport {
    let born = ScriptCheckpoint::default();
    let go = ScriptCheckpoint::default();
    let adopted = ScriptCheckpoint::default();
    let mut script = Vec::new();
    let mut ready = Vec::new();
    let mut populated = Vec::new();
    for p in 0..2 {
        let reached = ScriptCheckpoint::default();
        let mut parent = vec![
            Step::SignalCheckpoint(reached.clone()),
            Step::AwaitCheckpoint(go.clone()),
        ];
        for i in 0..n {
            parent.push(birth(10 + i));
            parent.push(Step::ChildMarker(vec![
                Step::AwaitCheckpoint(adopted.clone()),
                // wait(2), orphan adoption by namespace init; no subreaper.
                // https://man7.org/linux/man-pages/man2/wait.2.html
                Step::Sys(sys::getppid().ret(1)),
                exit(6),
            ]));
        }
        let population_ready = ScriptCheckpoint::default();
        parent.extend([
            Step::SignalCheckpoint(population_ready.clone()),
            Step::AwaitCheckpoint(born.clone()),
            exit(5),
        ]);
        script.push(call(sys::fork().save(p), "scaffold_birth"));
        script.push(Step::ChildMarker(parent));
        ready.push(reached);
        populated.push(population_ready);
    }
    script.extend(ready.into_iter().map(Step::AwaitCheckpoint));
    script.push(Step::SignalCheckpoint(go));
    script.extend(populated.into_iter().map(Step::AwaitCheckpoint));
    script.push(Step::SignalCheckpoint(born));
    for p in 0..2 {
        script.push(wait(slot(p), 0));
    }
    script.push(Step::SignalCheckpoint(adopted));
    for _ in 0..2 * n {
        script.push(wait(-1, 0));
    }
    script.push(call(sys::wait4(-1, 0).errno(LINUX_ECHILD), "d_echild"));
    script.push(call(sys::exit_group(0), "scaffold_exit"));
    let run = checked(ScriptedBackend::new().run_root(script).unwrap());
    assert_eq!(run.tasks_started(), 3 + 2 * n);
    let statuses: Vec<_> = run
        .outputs_for("d_wait")
        .into_iter()
        .map(|o| i32::from_le_bytes(o.bytes[..4].try_into().unwrap()))
        .collect();
    assert_eq!(statuses.iter().filter(|s| **s == 5 << 8).count(), 2);
    assert_eq!(statuses.iter().filter(|s| **s == 6 << 8).count(), 2 * n);
    assert_eq!(
        run.completions()
            .iter()
            .filter(|c| c.label == "getppid")
            .count(),
        2 * n
    );
    assert_eq!(attempts(&run, "d_birth"), 2 * n);
    assert_eq!(attempts(&run, "d_exit"), 2 * n + 2);
    run
}

macro_rules! binding {
    ($semantic:ident, $budget:ident, $scenario:expr) => {
        #[test]
        fn $semantic() {
            for n in [1, 8, 32] {
                ($scenario)(n);
            }
        }
        #[test]
        #[ignore = "N2 D-prep red: host task birth/exit/wait still enters the dispatcher; enable with ownership move"]
        fn $budget() {
            let measured: Vec<_> = [1, 8, 32].into_iter().map(|n| task_services(&($scenario)(n))).collect();
            assert_eq!(measured, vec![0; 3], "zero host birth/exit/wait service entries at 1/8/32");
        }
    };
}

binding!(
    wnohang_echild_two_parents_at_1_8_32,
    wnohang_echild_budget_red,
    |n| wait_scenario(n, false)
);
binding!(
    sa_nocldwait_two_parents_at_1_8_32,
    sa_nocldwait_budget_red,
    |n| wait_scenario(n, true)
);
binding!(
    exit_group_parked_siblings_at_1_8_32,
    exit_group_budget_red,
    group_scenario
);
binding!(
    reparent_reap_two_parents_at_1_8_32,
    reparent_reap_budget_red,
    reparent_scenario
);
