//! Recorded ordering witness for fork/close/exit_group and strict replay.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use carrick_kernel_example::{
    ExampleError, Schedule, ScheduleReceipt, ScriptedBackend, Step, slot, sys,
};

fn scenario() -> Vec<Step> {
    vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            Step::Sys(sys::read(slot(0), 1).ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]),
        Step::Sys(sys::exit_group(0)),
    ]
}

fn run(
    schedule: &Schedule,
) -> (
    Result<carrick_kernel_example::RunReport, ExampleError>,
    ScheduleReceipt,
) {
    let result = ScriptedBackend::new()
        .with_schedule(schedule.clone())
        .run_root(scenario());
    let summary = result
        .as_ref()
        .map(|r| {
            format!(
                "exit={} tasks={} dispatches={}",
                r.exit_code(),
                r.tasks_started(),
                r.dispatches()
            )
        })
        .unwrap_or_else(|error| error.to_string());
    let work = result.as_ref().ok().map(|r| r.work_snapshot().clone());
    let receipt = schedule.receipt(summary, work).expect("complete schedule");
    (result, receipt)
}

fn assert_fd_pin_conformance(result: &Result<carrick_kernel_example::RunReport, ExampleError>) {
    let report = result
        .as_ref()
        .expect("retired sibling must cancel without fd-pin Unsupported");
    assert_eq!(report.tasks_started(), 3);
    assert_eq!(report.dispatches_for_tid(2, "read"), 1);
    assert!(
        report
            .completions()
            .iter()
            .all(|c| c.tid != 2 || c.label != "read")
    );
    use carrick_observability::work_meter::WorkMetric;
    let work = report.work_snapshot();
    assert_eq!(work.dropped_events, 0);
    assert!(work.unknown_metrics.is_empty());
    assert_eq!(work.get(WorkMetric::KernelDispatches), Some(6));
    assert_eq!(work.get(WorkMetric::KernelRedispatches), Some(0));
    assert_eq!(work.get(WorkMetric::ContinuationParks), Some(0));
}

#[test]
fn seeded_fd_pin_schedule_records_and_replays() {
    let seed = std::env::var("VMFREE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let (result, receipt) = run(&Schedule::explore(seed).max_transitions(128));
    if let Ok(path) = std::env::var("VMFREE_TRACE") {
        std::fs::write(path, serde_json::to_vec_pretty(&receipt).unwrap()).expect("write trace");
    }
    // The retained fixtures are historical evidence. Only an explicit
    // VMFREE_REPLAY request uses them; this default check replays its own run.
    let (replayed, replay_receipt) = run(&Schedule::replay(receipt.clone()));
    assert_eq!(receipt.decisions, replay_receipt.decisions);
    assert_eq!(format!("{result:?}"), format!("{replayed:?}"));
    assert_fd_pin_conformance(&result);

    if let Ok(path) = std::env::var("VMFREE_REPLAY") {
        let retained: ScheduleReceipt =
            serde_json::from_slice(&std::fs::read(path).expect("read replay"))
                .expect("parse replay");
        let expected_source = retained.source_hash.clone();
        let schedule = if let Ok(fixed_source) = std::env::var("VMFREE_ALLOW_FIXED_SOURCE") {
            Schedule::replay(retained.clone()).allow_source_pair(&expected_source, &fixed_source)
        } else {
            Schedule::replay(retained.clone())
        };
        let (replayed, replay_receipt) = run(&schedule);
        assert_eq!(retained.decisions, replay_receipt.decisions);
        assert_fd_pin_conformance(&replayed);
    }
}

#[test]
#[ignore = "explicit VMFREE_TRACE is required to record a historical revision"]
fn record_fd_pin_schedule_on_historical_revision() {
    let path = std::env::var("VMFREE_TRACE").expect("set VMFREE_TRACE to a receipt path");
    let seed = std::env::var("VMFREE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    let (_, receipt) = run(&Schedule::explore(seed).max_transitions(128));
    std::fs::write(path, serde_json::to_vec_pretty(&receipt).unwrap()).expect("write trace");
}

fn expect_replay_rejection(
    mut receipt: ScheduleReceipt,
    change: impl FnOnce(&mut ScheduleReceipt),
) {
    change(&mut receipt);
    let schedule = Schedule::replay(receipt);
    let result = ScriptedBackend::new()
        .with_schedule(schedule.clone())
        .run_root(scenario());
    let rejection = match result {
        Err(ExampleError::Schedule(reason)) => reason,
        Err(ExampleError::Task { error, .. }) => match *error {
            ExampleError::Schedule(reason) => reason,
            other => schedule.receipt(other.to_string(), None).unwrap_err(),
        },
        other => schedule.receipt(format!("{other:?}"), None).unwrap_err(),
    };
    assert!(rejection.contains("replay"), "{rejection}");
}

#[test]
fn replay_rejects_runnable_actor_generation_fixture_and_suffix_drift() {
    let (_, receipt) = run(&Schedule::explore(5).max_transitions(128));
    expect_replay_rejection(receipt.clone(), |r| r.decisions[4].runnable.clear());
    expect_replay_rejection(receipt.clone(), |r| r.decisions[4].next = None);
    expect_replay_rejection(receipt.clone(), |r| {
        r.decisions[4].actor.execution_generation += 1
    });
    expect_replay_rejection(receipt.clone(), |r| r.fixture_hash.push('0'));
    expect_replay_rejection(receipt.clone(), |r| r.source_hash.push('0'));
    expect_replay_rejection(receipt.clone(), |r| {
        r.decisions.push(r.decisions[0].clone())
    });
}
