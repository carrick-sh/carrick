//! Seed sweep and deterministic reproduction for the futex wake / exit race.
//!
//! Investigates whether the intermittent futex wake failure ("no successful completion
//! for label wake_root") can be deterministically reproduced under seeded schedules.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use carrick_kernel_example::{
    ExampleError, Schedule, ScheduleReceipt, ScriptedBackend, Step, alloc_word, await_parked, slot,
    sys,
};

fn pipe_to_slots(read_slot: usize, write_slot: usize) -> Step {
    Step::Sys(
        sys::pipe2(0)
            .ret(0)
            .save_out_i32(0, 0, read_slot)
            .save_out_i32(0, 1, write_slot),
    )
}

/// Scenario as written in `tests/semantics/futex.rs` with pipe acknowledgment.
/// Under a deterministic schedule, descriptor waits fail closed before enrollment
/// with `external readiness: scheduled runs support only untimed private futex waits`
/// on any schedule where the waiter runs before the waker writes to the pipe.
fn semantics_pipe_futex_scenario() -> Vec<Step> {
    vec![
        alloc_word(0, 1),
        pipe_to_slots(1, 2),
        Step::Sys(sys::clone_thread(0)),
        Step::ChildMarker(vec![
            await_parked(1, "wait_root"),
            Step::Sys(sys::futex_wake_labeled("wake_root", slot(0), 1).ret(1)),
            Step::Sys(sys::write(slot(2), b"w").ret(1)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        Step::Sys(sys::futex_wait_labeled("wait_root", slot(0), 1).ret(0)),
        Step::Sys(sys::read(slot(1), 1).ret(1)),
        Step::Sys(sys::exit_group(0)),
    ]
}

/// Scenario without pipe acknowledgment (as in `tests/schedule_replay.rs::futex_scenario`).
/// When the root resumes from `futex_wait` and calls `exit_group(0)` before the waker thread
/// records completion for `wake_root`, the waker is retired via process termination,
/// resulting in "no successful completion for label wake_root".
fn unacknowledged_futex_scenario() -> Vec<Step> {
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

/// Demonstrates that the pipe-acknowledged scenario cannot run cleanly under a seeded
/// schedule because pipes are external readiness boundaries.
#[test]
#[ignore = "diagnostic seed sweep for pipe scenario"]
fn sweep_semantics_pipe_scenario_seeds() {
    let mut external_readiness_count = 0;
    let mut ok_count = 0;
    for seed in 0..200 {
        let schedule = Schedule::explore(seed);
        let result = ScriptedBackend::new()
            .with_schedule(schedule.clone())
            .run_root(semantics_pipe_futex_scenario());
        match result {
            Ok(_) => ok_count += 1,
            Err(ExampleError::Schedule(ref reason)) if reason.contains("external readiness") => {
                external_readiness_count += 1;
            }
            Err(e) => panic!("seed {seed} unexpected error: {e:?}"),
        }
    }
    println!(
        "pipe scenario over seeds 0..200: {ok_count} passed, {external_readiness_count} rejected due to external readiness"
    );
}

/// Sweeps seeds 0..200 for the unacknowledged futex scenario, finds the first failing seed,
/// generates the failure receipt, and verifies strict replay.
#[test]
#[ignore = "diagnostic seed sweep for unacknowledged futex scenario"]
fn sweep_unacknowledged_futex_seeds_and_report_first_failure() {
    let mut first_failing: Option<(u64, ScheduleReceipt)> = None;
    let mut failing_seeds = Vec::new();

    for seed in 0..200 {
        let schedule = Schedule::explore(seed);
        let result = ScriptedBackend::new()
            .with_schedule(schedule.clone())
            .run_root(unacknowledged_futex_scenario());

        let wake_completed = match &result {
            Ok(report) => report
                .completions()
                .iter()
                .any(|c| c.label == "wake_root" && c.result.is_ok()),
            Err(_) => false,
        };

        if !wake_completed {
            failing_seeds.push(seed);
            if first_failing.is_none() {
                let summary = result
                    .as_ref()
                    .map(|report| {
                        format!(
                            "wake-completed={}",
                            report.completions().iter().any(|c| c.label == "wake_root")
                        )
                    })
                    .unwrap_or_else(|error| error.to_string());
                let work = result
                    .as_ref()
                    .ok()
                    .map(|report| report.work_snapshot().clone());
                let receipt = schedule
                    .receipt(summary, work)
                    .expect("complete schedule receipt");
                first_failing = Some((seed, receipt));
            }
        }
    }

    let (seed, receipt) = first_failing.expect("expected at least one failing seed in 0..200");
    println!("TOTAL_FAILING_SEEDS_COUNT={}", failing_seeds.len());
    println!("FIRST_FAILING_SEED={seed}");
    println!(
        "FIRST_FAILING_RECEIPT={}",
        serde_json::to_string_pretty(&receipt).expect("valid json receipt")
    );

    // Verify deterministic replay of the first failing seed
    let replay_schedule = Schedule::replay(receipt.clone());
    let replay_result = ScriptedBackend::new()
        .with_schedule(replay_schedule.clone())
        .run_root(unacknowledged_futex_scenario());
    let replay_report = replay_result.expect("replayed run must succeed in driver execution");
    assert_eq!(replay_report.ret("wait_root"), 0);
    assert!(
        !replay_report
            .completions()
            .iter()
            .any(|c| c.label == "wake_root"),
        "replayed run must reproduce missing wake_root completion"
    );
}

/// Directly demonstrates the panic on seed 5 matching the intermittent issue:
/// `panicked at ... 'no successful completion for label wake_root'`.
#[test]
#[should_panic(expected = "no successful completion for label wake_root")]
#[ignore = "reproduces exact panic for seed 5"]
fn seed_5_reproduces_missing_wake_completion_panic() {
    let schedule = Schedule::explore(5);
    let report = ScriptedBackend::new()
        .with_schedule(schedule)
        .run_root(unacknowledged_futex_scenario())
        .expect("run completes");
    assert_eq!(report.ret("wait_root"), 0);
    // This panics with "no successful completion for label wake_root"
    assert_eq!(report.ret("wake_root"), 1);
}
