//! Recorded ordering witness for fork/close/exit_group and strict replay.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use carrick_kernel_example::{
    ExampleError, Point, Schedule, ScheduleReceipt, ScriptedBackend, Step, alloc_word,
    await_parked, slot, sys,
};

fn futex_scenario() -> Vec<Step> {
    vec![
        alloc_word(0, 1),
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            await_parked(1, "wait_root"),
            Step::Sys(sys::futex_wake_labeled("wake_root", slot(0), 1).ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::Sys(sys::futex_wait_labeled("wait_root", slot(0), 1).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]
}

fn futex_acknowledged_scenario() -> Vec<Step> {
    vec![
        alloc_word(0, 1),
        alloc_word(1, 1),
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            await_parked(1, "wait_root"),
            Step::Sys(sys::futex_wake_labeled("wake_root", slot(0), 1).ret(1)),
            await_parked(1, "wait_ack"),
            Step::Sys(sys::futex_wake_labeled("wake_ack", slot(1), 1).ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::Sys(sys::futex_wait_labeled("wait_root", slot(0), 1).ret(0)),
        Step::Sys(sys::futex_wait_labeled("wait_ack", slot(1), 1).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]
}

fn run_futex(
    schedule: &Schedule,
) -> (
    Result<carrick_kernel_example::RunReport, ExampleError>,
    ScheduleReceipt,
) {
    let result = ScriptedBackend::new()
        .with_schedule(schedule.clone())
        .run_root(futex_scenario());
    let summary = result
        .as_ref()
        .map(|report| {
            format!(
                "wake-completed={}",
                report
                    .completions()
                    .iter()
                    .any(|completion| completion.label == "wake_root")
            )
        })
        .unwrap_or_else(|error| error.to_string());
    let work = result
        .as_ref()
        .ok()
        .map(|report| report.work_snapshot().clone());
    let receipt = schedule.receipt(summary, work);
    assert!(
        receipt.is_ok(),
        "complete futex schedule: {receipt:?}; run result: {result:?}"
    );
    let receipt = receipt.expect("checked complete futex schedule");
    (result, receipt)
}

#[test]
fn futex_wake_exit_receipt_replays() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/futex-wake-exit-seed637.json"
    );
    let retained: ScheduleReceipt = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(retained.backend, "kernel-example/portable");
    let enrolled = retained
        .decisions
        .iter()
        .position(|decision| decision.point == Point::WaitEnrolled)
        .expect("futex wait enrollment must be recorded");
    let published = retained
        .decisions
        .iter()
        .position(|decision| decision.point == Point::FutexWakePublished)
        .expect("in-zone wake admission must be recorded");
    let resumed = retained
        .decisions
        .iter()
        .position(|decision| decision.point == Point::WaitResumed)
        .expect("futex continuation resume must be recorded");
    assert!(enrolled < published && published < resumed);
    assert_eq!(retained.decisions[published].runnable.len(), 2);
    let schedule = Schedule::replay(retained.clone());
    let (result, replayed) = run_futex(&schedule);
    assert_eq!(retained.decisions, replayed.decisions);
    let report = result.expect("historical futex pair completes");
    assert_eq!(report.ret("wait_root"), 0);
    assert!(
        !report
            .completions()
            .iter()
            .any(|completion| completion.label == "wake_root"),
        "historical receipt must show the waker being retired before return"
    );
}

#[test]
fn scheduled_external_readiness_fails_closed() {
    let schedule = Schedule::explore(0);
    let result = ScriptedBackend::new()
        .with_schedule(schedule.clone())
        .run_root(vec![
            Step::Sys(
                sys::pipe2(0)
                    .ret(0)
                    .save_out_i32(0, 0, 0)
                    .save_out_i32(0, 1, 1),
            ),
            Step::Sys(sys::read(slot(0), 1).ret(1)),
        ]);
    assert!(
        matches!(result, Err(ExampleError::Schedule(ref reason)) if reason.contains("external readiness")),
        "{result:?}"
    );
    assert!(
        schedule
            .receipt("external wait rejected", None)
            .unwrap_err()
            .contains("external readiness")
    );
}

#[test]
fn futex_wake_acknowledgment_survives_explored_schedules() {
    for seed in 0..200 {
        let report = ScriptedBackend::new()
            .with_schedule(Schedule::explore(seed))
            .run_root(futex_acknowledged_scenario())
            .unwrap_or_else(|error| panic!("seed {seed}: {error:?}"));
        assert_eq!(report.ret("wait_root"), 0, "seed {seed}");
        assert_eq!(report.ret("wake_root"), 1, "seed {seed}");
    }
}

#[test]
#[ignore = "VMFREE_TRACE must name the retained receipt output"]
fn record_futex_wake_exit_receipt() {
    let seed = std::env::var("VMFREE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(637);
    let (_, receipt) = run_futex(&Schedule::explore(seed));
    std::fs::write(
        std::env::var("VMFREE_TRACE").expect("VMFREE_TRACE is required"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}

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
