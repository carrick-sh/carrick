//! N2 rows 5/8 semantic and work reds through the public dispatcher.
//! Linux authority: sched_setaffinity(2): pid selects a thread, not the caller.
//! These operation schedules retain two live processes. They do not exercise
//! the runtime executor pool or establish an EL1 ownership result.
#![cfg(debug_assertions)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use carrick_abi::{LinuxCloneFlags, syscall::nr};
use carrick_hal::{CpuAffinity, NullGuestTimerBridge, NullHostSignalBridge, ThreadId};
use carrick_kernel::{
    compat::{CompatReporter, SyscallArgs},
    dispatch::{CarrierBridges, DispatchOutcome, LinearMemory, SyscallDispatcher, SyscallRequest},
    kernel::{CarrierProcess, ClonePlan, KernelContext, schedule::Point},
};
use carrick_kernel_example::{
    Schedule, ScheduleReceipt,
    process::{AddressSpace, AsidAllocator, ExampleProcess},
};
use parking_lot::Mutex;

const SEEDS: [u64; 3] = [3, 7, 19];

fn sibling(parent: &KernelContext, tid: i32) -> KernelContext {
    parent
        .kernel()
        .reserve_thread_clone(
            parent,
            ClonePlan::from_flags(
                LinuxCloneFlags::THREAD | LinuxCloneFlags::VM | LinuxCloneFlags::SIGHAND,
            )
            .unwrap(),
            None,
        )
        .unwrap()
        .prepare(ThreadId::from_guest_supplied_tid(tid))
        .unwrap()
        .commit()
        .unwrap()
        .into_context()
        .unwrap()
}

fn run(schedule: &Schedule, scale: usize, nonleader: bool) -> (ScheduleReceipt, Vec<String>) {
    let asids = AsidAllocator::new();
    let (process, root) = ExampleProcess::boot_root(
        1,
        "n2-l3-affinity",
        Arc::new(NullHostSignalBridge::default()),
        AddressSpace::allocate(&asids).unwrap(),
    )
    .unwrap();
    let kernel = Arc::clone(root.kernel());
    let remote = kernel
        .reserve_fork(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
            "n2-l3-remote".into(),
            None,
        )
        .unwrap()
        .prepare_with_mm_backend(
            AddressSpace::allocate(&asids).unwrap().mm_backend(),
            ThreadId::from_guest_supplied_tid(100),
        )
        .unwrap()
        .commit()
        .unwrap()
        .start_child()
        .unwrap()
        .into_parts()
        .0;
    assert_ne!(root.task().key(), remote.task().key());
    assert_ne!(root.shared().mm().id(), remote.shared().mm().id());
    let target = if nonleader {
        sibling(&remote, 101)
    } else {
        kernel
            .context(remote.task().key().id, remote.thread().key().tid)
            .unwrap()
    };
    // Distinct online masks distinguish target publication from caller mutation.
    assert!(
        carrick_kernel::kernel::scheduler::guest_cpu_count() >= 2,
        "fixture requires two exposed guest CPUs"
    );
    let initial = CpuAffinity::from_words(&[3]);
    target.thread().set_affinity(initial);
    root.thread().set_affinity(CpuAffinity::from_words(&[2]));
    let contexts = [root, remote];
    let process = Arc::new(process) as Arc<dyn CarrierProcess>;
    let failures = Mutex::new(Vec::new());
    let receipt = schedule.run_operations(
        &kernel, &format!("n2-l3-remote-affinity/nonleader={nonleader}/n={scale}"), scale, &contexts,
        |index, lane| {
            if index == 1 {
                for _ in 0..scale { lane.point(Point::BeforeLock); }
                return;
            }
            let mut dispatcher = SyscallDispatcher::with_bridges(CarrierBridges {
                host_signal: Arc::new(NullHostSignalBridge::default()),
                timers: Arc::new(NullGuestTimerBridge::default()),
            });
            dispatcher.bind_hvpatch_process(Arc::clone(&process));
            let reporter = CompatReporter::default();
            let mut memory = LinearMemory::new(0x4000, 1u64.to_le_bytes().to_vec());
            for iteration in 0..scale {
                lane.point(Point::BeforeLock);
                let outcome = dispatcher.dispatch(
                    &contexts[0], SyscallRequest::new(nr::SCHED_SETAFFINITY.raw(),
                        SyscallArgs::new([target.thread().key().tid.raw() as u64, 8, 0x4000, 0, 0, 0])),
                    &mut memory, &reporter,
                ).unwrap();
                if outcome != (DispatchOutcome::Returned { value: 0 }) ||
                    target.thread().affinity().words()[0] != 1 ||
                    contexts[0].thread().affinity().words()[0] != 2 {
                    failures.lock().push(format!("iteration={iteration} outcome={outcome:?} target_mask={} caller_mask={} expected=1/2",
                        target.thread().affinity().words()[0], contexts[0].thread().affinity().words()[0]));
                }
            }
        },
    ).unwrap();
    kernel.validate_invariants().unwrap();
    (receipt, failures.into_inner())
}

fn witness(nonleader: bool) {
    let mut first = None;
    for scale in [32, 8, 1] {
        for seed in SEEDS {
            let (receipt, failures) = run(
                &Schedule::explore(seed).max_transitions(512),
                scale,
                nonleader,
            );
            println!(
                "n2-l3 affinity nonleader={nonleader} scale={scale} seed={seed}: {failures:?}"
            );
            if first.is_none() && !failures.is_empty() {
                first = Some((receipt, failures));
            }
        }
    }
    if let Some((receipt, failures)) = first {
        let (replayed, replay_failures) =
            run(&Schedule::replay(receipt.clone()), receipt.scale, nonleader);
        assert_eq!(receipt.decisions, replayed.decisions);
        assert_eq!(failures, replay_failures);
        println!(
            "first failing receipt (seeds={SEEDS:?}): {}",
            serde_json::to_string(&receipt).unwrap()
        );
        let mut minimal = receipt;
        for scale in [8, 1] {
            let (candidate, candidate_failures) = run(
                &Schedule::explore(minimal.seed).max_transitions(512),
                scale,
                nonleader,
            );
            if !candidate_failures.is_empty() {
                minimal = candidate;
            }
        }
        let (replayed, reduced_failures) =
            run(&Schedule::replay(minimal.clone()), minimal.scale, nonleader);
        assert_eq!(minimal.decisions, replayed.decisions);
        assert!(!reduced_failures.is_empty());
        assert_eq!(minimal.scale, 1);
        // Removing the last operation would remove the syscall under test.
        println!(
            "shrunk one-operation receipt: {}",
            serde_json::to_string(&minimal).unwrap()
        );
        panic!(
            "N2 row 5: remote affinity must update the exact live target: {}",
            failures[0]
        );
    }
}

#[test]
#[ignore = "N2 red witness: row 5: live remote nonleader tid is rejected"]
fn remote_affinity_selects_exact_live_thread() {
    witness(true);
}

#[test]
#[ignore = "N2 red witness: row 5: remote process leader affinity is not updated"]
fn remote_affinity_selects_exact_live_process_leader() {
    witness(false);
}

fn ppoll_enrollment(before: bool) {
    use carrick_kernel_example::{
        Layout, RelocWidth, ScriptCheckpoint, ScriptPausePoint, ScriptedBackend, Step,
        await_parked, slot, sys,
    };
    use carrick_observability::work_meter::WorkMetric;

    let mut failures = Vec::new();
    for scale in [1, 8, 32] {
        let reached = ScriptCheckpoint::default();
        let resume = ScriptCheckpoint::default();
        let completed = ScriptCheckpoint::default();
        let mut script = Vec::new();
        let mut fds = Layout::new(8 * scale).with_capture(true);
        for index in 0..scale {
            script.push(Step::Sys(
                sys::pipe2(0)
                    .ret(0)
                    .save_out_i32(0, 0, 2 * index)
                    .save_out_i32(0, 1, 2 * index + 1),
            ));
            fds = fds
                .with_reloc(8 * index, RelocWidth::I32, slot(2 * index))
                .with_i16(8 * index + 4, carrick_abi::LINUX_POLLIN);
        }
        script.push(Step::Sys(sys::fork()));
        let gate = if before {
            Step::AwaitCheckpoint(reached.clone())
        } else {
            await_parked(1, "ppoll")
        };
        script.push(Step::ChildMarker(vec![
            gate,
            Step::Sys(sys::write(slot(2 * scale - 1), b"x").ret(1)),
            Step::SignalCheckpoint(resume.clone()),
            // Keep the second process and its descriptors live through return.
            Step::AwaitCheckpoint(completed.clone()),
            Step::Sys(sys::exit_group(0)),
        ]));
        script.extend([
            Step::Sys(sys::ppoll(fds, scale, 0, 0).ret(1)),
            Step::SignalCheckpoint(completed),
            Step::Sys(sys::exit_group(0)),
        ]);
        let backend = ScriptedBackend::new();
        let backend = if before {
            backend.with_pause(
                "ppoll",
                ScriptPausePoint::BeforeWaitEnrollment,
                reached,
                resume,
            )
        } else {
            backend
        };
        let report = backend.run_root(script).unwrap();
        let output = report.output("ppoll");
        for index in 0..scale {
            let revents =
                i16::from_le_bytes(output[8 * index + 6..8 * index + 8].try_into().unwrap());
            assert_eq!(
                revents,
                if index + 1 == scale {
                    carrick_abi::LINUX_POLLIN
                } else {
                    0
                }
            );
        }
        assert_eq!(report.tasks_started(), 2);
        let work = report.work_snapshot();
        assert_eq!(work.dropped_events(), 0);
        assert!(work.unknown_metrics().is_empty());
        let dispatches = report.dispatches_for_pid(1, "ppoll");
        println!(
            "n2-l3 ppoll before_enrollment={before} scale={scale} dispatches={dispatches} work={work:?}"
        );
        // Completed readiness owns the result: no second Linux decode/copyout
        // pass. Each episode owns one enrollment, park and resume.
        if dispatches != 1 {
            failures.push(format!(
                "scale={scale} ppoll dispatches={dispatches} expected=1"
            ));
        }
        for metric in [
            WorkMetric::ContinuationEnrollments,
            WorkMetric::ContinuationParks,
            WorkMetric::ContinuationResumes,
            WorkMetric::WakePublications,
        ] {
            if work.get(metric) != Some(1) {
                failures.push(format!(
                    "scale={scale} {metric:?}={:?} expected=1",
                    work.get(metric)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "N2 row 8: {}", failures.join("; "));
}

#[test]
#[ignore = "N2 red witness: row 8: pre-enrollment readiness redispatches ppoll"]
fn ppoll_readiness_before_enrollment_has_one_owned_completion() {
    ppoll_enrollment(true);
}

#[test]
#[ignore = "N2 red witness: row 8: post-enrollment readiness redispatches ppoll"]
fn ppoll_readiness_after_enrollment_has_one_owned_completion() {
    ppoll_enrollment(false);
}
