//! Recorded ordering witness for fork/close/exit_group and strict replay.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use carrick_kernel_example::{
    ExampleError, Point, ReplayExpectation, Schedule, ScheduleReceipt, ScriptedBackend, Step,
    alloc_word, await_parked, slot, sys,
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
    let schedule = Schedule::replay(retained.clone(), ReplayExpectation::Exact);
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
    let (replayed, replay_receipt) =
        run(&Schedule::replay(receipt.clone(), ReplayExpectation::Exact));
    assert_eq!(receipt.decisions, replay_receipt.decisions);
    assert_eq!(format!("{result:?}"), format!("{replayed:?}"));
    assert_fd_pin_conformance(&result);

    if let Ok(path) = std::env::var("VMFREE_REPLAY") {
        let retained: ScheduleReceipt =
            serde_json::from_slice(&std::fs::read(path).expect("read replay"))
                .expect("parse replay");
        let schedule = Schedule::replay(retained.clone(), ReplayExpectation::Exact);
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

fn replay_result(schedule: &Schedule) -> Result<ScheduleReceipt, String> {
    let result = ScriptedBackend::new()
        .with_schedule(schedule.clone())
        .run_root(scenario());
    if let Err(ExampleError::Schedule(reason)) = &result {
        return Err(reason.clone());
    }
    let summary = result
        .as_ref()
        .map(|report| {
            format!(
                "exit={} tasks={} dispatches={}",
                report.exit_code(),
                report.tasks_started(),
                report.dispatches()
            )
        })
        .unwrap_or_else(|error| error.to_string());
    let work = result
        .as_ref()
        .ok()
        .map(|report| report.work_snapshot().clone());
    schedule.receipt(summary, work)
}

fn expect_replay_rejection(
    mut receipt: ScheduleReceipt,
    change: impl FnOnce(&mut ScheduleReceipt),
    reason: &str,
) {
    change(&mut receipt);
    let rejection =
        replay_result(&Schedule::replay(receipt, ReplayExpectation::Exact)).unwrap_err();
    assert!(rejection.contains(reason), "{rejection}");
}

#[test]
fn replay_rejects_runnable_actor_generation_fixture_and_suffix_drift() {
    let (_, receipt) = run(&Schedule::explore(5).max_transitions(128));
    // The unmodified control must complete, including its actual result/work.
    assert_eq!(
        replay_result(&Schedule::replay(receipt.clone(), ReplayExpectation::Exact)).unwrap(),
        receipt
    );
    expect_replay_rejection(
        receipt.clone(),
        |r| r.decisions[4].runnable.clear(),
        "runnable-set",
    );
    expect_replay_rejection(
        receipt.clone(),
        |r| r.decisions[4].next = None,
        "ineligible",
    );
    expect_replay_rejection(
        receipt.clone(),
        |r| {
            let decision = &mut r.decisions[4];
            decision.next = decision
                .runnable
                .iter()
                .copied()
                .find(|actor| Some(*actor) != decision.next);
        },
        "replay",
    );
    expect_replay_rejection(
        receipt.clone(),
        |r| r.decisions[4].actor.execution_generation += 1,
        "actor",
    );
    expect_replay_rejection(
        receipt.clone(),
        |r| r.decisions[4].actor.task_serial += 1,
        "actor",
    );
    expect_replay_rejection(
        receipt.clone(),
        |r| r.decisions[4].actor.thread_serial += 1,
        "actor",
    );
    expect_replay_rejection(receipt.clone(), |r| r.decisions[4].visit += 1, "visit");
    expect_replay_rejection(
        receipt.clone(),
        |r| r.decisions[4].point = Point::Finish,
        "point",
    );
    expect_replay_rejection(receipt.clone(), |r| r.fixture_hash.push('0'), "fixture");
    expect_replay_rejection(receipt.clone(), |r| r.schema_version += 1, "schema");
    expect_replay_rejection(receipt.clone(), |r| r.generator_version += 1, "schema");
    expect_replay_rejection(receipt.clone(), |r| r.backend.push('0'), "backend");
    expect_replay_rejection(receipt.clone(), |r| r.scale += 1, "scale");
    expect_replay_rejection(
        receipt.clone(),
        |r| r.decisions.push(r.decisions[0].clone()),
        "suffix",
    );
    expect_replay_rejection(
        receipt.clone(),
        |r| {
            r.decisions.pop();
        },
        "exhausted",
    );
    expect_replay_rejection(receipt.clone(), |r| r.result.push('0'), "result");
    expect_replay_rejection(
        receipt.clone(),
        |r| r.work_snapshot.as_mut().unwrap().dropped_events += 1,
        "work snapshot",
    );
    expect_replay_rejection(
        receipt.clone(),
        |r| {
            *r.work_snapshot
                .as_mut()
                .unwrap()
                .values
                .get_mut(&carrick_observability::work_meter::WorkMetric::KernelDispatches)
                .unwrap() += 1;
        },
        "work snapshot",
    );
    expect_replay_rejection(receipt, |r| r.work_snapshot = None, "work snapshot");
}

#[test]
fn receipts_bind_scenarios_without_ambient_kernel_sources() {
    let (_, receipt) = run(&Schedule::explore(5));
    let json = serde_json::to_value(&receipt).unwrap();
    assert!(
        json.get("source_hash").is_none(),
        "ambient kernel binding must be retired"
    );
    assert!(!receipt.fixture_hash.is_empty());
}

#[test]
fn regression_replay_checks_explicit_current_result_and_work() {
    let (_, fixed) = run(&Schedule::explore(5));
    // A controlled bad observation isolates the expectation mechanism. The
    // real retained regressions below keep their original trace identities.
    let mut historical = fixed.clone();
    historical.result = "continuation build failed: failed to pin an exact fd description".into();
    historical.work_snapshot = None;
    assert!(
        replay_result(&Schedule::replay(
            historical.clone(),
            ReplayExpectation::Exact
        ))
        .unwrap_err()
        .contains("result or work")
    );
    let expectation = ReplayExpectation::Regression {
        result: fixed.result.clone(),
        work_snapshot: fixed.work_snapshot.clone(),
    };
    assert_eq!(
        replay_result(&Schedule::replay(historical.clone(), expectation)).unwrap(),
        fixed
    );
    // A Regression changes only the observation, never actor/transition authority.
    expect_regression_rejection(
        &historical,
        &fixed,
        |r| r.decisions[4].runnable.clear(),
        "runnable-set",
    );
    for mutate_work in [false, true] {
        let mut expected = fixed.clone();
        if mutate_work {
            expected.work_snapshot.as_mut().unwrap().dropped_events += 1;
        } else {
            expected.result.push('0');
        }
        let expectation = ReplayExpectation::Regression {
            result: expected.result,
            work_snapshot: expected.work_snapshot,
        };
        assert!(
            replay_result(&Schedule::replay(historical.clone(), expectation))
                .unwrap_err()
                .contains("result or work")
        );
    }
    assert!(
        replay_result(&Schedule::replay(
            fixed.clone(),
            ReplayExpectation::Regression {
                result: fixed.result,
                work_snapshot: fixed.work_snapshot
            }
        ))
        .unwrap_err()
        .contains("must differ")
    );
}

fn expect_regression_rejection(
    historical: &ScheduleReceipt,
    fixed: &ScheduleReceipt,
    change: impl FnOnce(&mut ScheduleReceipt),
    reason: &str,
) {
    let mut receipt = historical.clone();
    change(&mut receipt);
    let schedule = Schedule::replay(
        receipt,
        ReplayExpectation::Regression {
            result: fixed.result.clone(),
            work_snapshot: fixed.work_snapshot.clone(),
        },
    );
    assert!(replay_result(&schedule).unwrap_err().contains(reason));
}

#[test]
fn historical_fd_pin_receipts_keep_their_exact_generation_and_bad_result() {
    for json in [
        include_str!("fixtures/fdpin-seed5.json"),
        include_str!("fixtures/fdpin-seed5-main-prefx.json"),
    ] {
        let retained: ScheduleReceipt = serde_json::from_str(json).unwrap();
        assert_eq!(retained.seed, 5);
        assert_eq!(retained.generator_version, 2);
        assert_eq!(retained.decisions.len(), 22);
        assert!(
            retained
                .result
                .contains("failed to pin an exact fd description")
        );
        let rejection = replay_result(&Schedule::replay(
            retained.clone(),
            ReplayExpectation::Exact,
        ))
        .unwrap_err();
        assert!(rejection.contains("schema"));
        let expectation = ReplayExpectation::Regression {
            result: "fixed".into(),
            work_snapshot: None,
        };
        assert!(
            replay_result(&Schedule::replay(retained, expectation))
                .unwrap_err()
                .contains("schema")
        );
    }
}
