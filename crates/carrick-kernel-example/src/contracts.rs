//! Conformance contract bindings and scenarios for `carrick-kernel-example`.

use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ExecutionLayer, SemanticAssertion,
};
use carrick_observability::work_meter::WorkMetric;

use crate::operand::{Step, alloc_word, await_parked, slot};
use crate::scripted::{ExampleError, ScriptedBackend};
use crate::sys;

/// Run a futex contention scenario with the specified waiter counts and wake count.
///
/// Allocates:
/// - Slot 0: target futex word (initialized to 42)
/// - Slot 1: unrelated futex word (initialized to 99)
/// - Slots 2..: child TIDs
pub fn futex_contention_scenario(
    waiters: usize,
    wake_count: usize,
    unrelated_waiters: usize,
) -> Result<ContractObservation, ExampleError> {
    let mut script = Vec::new();

    script.push(alloc_word(0, 42));
    script.push(alloc_word(1, 99));

    for i in 0..waiters {
        let child_slot = 2 + i;
        script.push(Step::Sys(sys::clone_thread(0).save(child_slot)));
        script.push(Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("target_wait", slot(0), 42).ret(0)),
            Step::Sys(sys::exit_thread(0)),
        ]));
        script.push(await_parked(slot(child_slot), "target_wait"));
    }

    for j in 0..unrelated_waiters {
        let child_slot = 2 + waiters + j;
        script.push(Step::Sys(sys::clone_thread(0).save(child_slot)));
        script.push(Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("unrelated_wait", slot(1), 99).ret(0)),
            Step::Sys(sys::exit_thread(0)),
        ]));
        script.push(await_parked(slot(child_slot), "unrelated_wait"));
    }

    let expected_woken = wake_count.min(waiters);
    script.push(Step::Sys(
        sys::futex_wake_labeled("target_wake", slot(0), wake_count as u32)
            .ret(expected_woken as i64),
    ));

    script.push(Step::Sys(sys::exit_group(0)));

    let report = ScriptedBackend::new().run_root(script)?;

    let mut snapshot = report.work_snapshot().clone();

    #[cfg(any(test, debug_assertions))]
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() == Ok("extra-futex-visit")
        && let Some(visits) = snapshot.values.get_mut(&WorkMetric::FutexQueueVisits)
    {
        *visits += (waiters as u64).max(1);
    }

    let mut semantic_assertions = Vec::new();

    let wake_ret = report.ret("target_wake");
    if wake_ret == expected_woken as i64 {
        semantic_assertions.push(SemanticAssertion::pass("exact_wake_count"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "exact_wake_count",
            format!("expected wake return {expected_woken}, got {wake_ret}"),
        ));
    }

    if expected_woken > 0 {
        let mut all_completed = true;
        for i in 0..expected_woken {
            let child_tid = 2 + i as i32;
            if report.dispatches_for_tid(child_tid, "target_wait") != 1 {
                all_completed = false;
                break;
            }
        }
        if all_completed {
            semantic_assertions.push(SemanticAssertion::pass("all_awakened_waiters_completed"));
        } else {
            semantic_assertions.push(SemanticAssertion::fail(
                "all_awakened_waiters_completed",
                "not all awakened waiters completed single dispatch",
            ));
        }
    } else {
        semantic_assertions.push(SemanticAssertion::pass("all_awakened_waiters_completed"));
    }

    let redispatches = snapshot.get(WorkMetric::KernelRedispatches).unwrap_or(0);
    if redispatches == 0 {
        semantic_assertions.push(SemanticAssertion::pass(
            "zero_repeated_redispatch_while_parked",
        ));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "zero_repeated_redispatch_while_parked",
            format!("redispatches while parked = {redispatches}"),
        ));
    }

    if report.exit_code() == 0 {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code was {}", report.exit_code()),
        ));
    }

    let contract_id = ContractId::new("kernel.futex.contention")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexpingpong".to_string(),
        scale: waiters as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.futex.contention` at execution layer `VmFree`.
pub fn futex_contention_contract(
    scale: usize,
    unrelated_waiters: usize,
) -> Result<ContractObservation, ExampleError> {
    futex_contention_scenario(scale, scale, unrelated_waiters)
}

/// Run a futex requeue scenario with `waiters` parked on word 0.
///
/// Allocates:
/// - Slot 0: source futex word (initialized to 10)
/// - Slot 1: destination futex word (initialized to 20)
/// - Slots 2..: child TIDs
pub fn futex_requeue_scenario(
    waiters: usize,
    wake_count: usize,
    requeue_count: usize,
) -> Result<ContractObservation, ExampleError> {
    let mut script = Vec::new();

    script.push(alloc_word(0, 10));
    script.push(alloc_word(1, 20));

    for i in 0..waiters {
        let child_slot = 2 + i;
        script.push(Step::Sys(sys::clone_thread(0).save(child_slot)));
        script.push(Step::ChildMarker(vec![
            Step::Sys(sys::futex_wait_labeled("requeue_wait", slot(0), 10).ret(0)),
            Step::Sys(sys::exit_thread(0)),
        ]));
        script.push(await_parked(slot(child_slot), "requeue_wait"));
    }

    let expected_woken = wake_count.min(waiters);
    let expected_requeued = requeue_count.min(waiters.saturating_sub(expected_woken));
    let expected_total = expected_woken + expected_requeued;

    script.push(Step::Sys(
        sys::futex_cmp_requeue_labeled(
            "cmp_requeue",
            slot(0),
            wake_count as u32,
            requeue_count as u32,
            slot(1),
            10,
        )
        .ret(expected_total as i64),
    ));

    if expected_requeued > 0 {
        script.push(Step::Sys(
            sys::futex_wake_labeled("dest_wake", slot(1), expected_requeued as u32)
                .ret(expected_requeued as i64),
        ));
    }

    script.push(Step::Sys(sys::exit_group(0)));

    let report = ScriptedBackend::new().run_root(script)?;

    let mut snapshot = report.work_snapshot().clone();

    #[cfg(any(test, debug_assertions))]
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() == Ok("extra-futex-requeue-visit")
        && let Some(visits) = snapshot.values.get_mut(&WorkMetric::FutexQueueVisits)
    {
        *visits += (waiters as u64).max(2);
    }

    let mut semantic_assertions = Vec::new();

    let requeue_ret = report.ret("cmp_requeue");
    if requeue_ret == expected_total as i64 {
        semantic_assertions.push(SemanticAssertion::pass("exact_requeue_total"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "exact_requeue_total",
            format!("expected {expected_total}, got {requeue_ret}"),
        ));
    }

    if expected_requeued > 0 {
        let dest_ret = report.ret("dest_wake");
        if dest_ret == expected_requeued as i64 {
            semantic_assertions.push(SemanticAssertion::pass("destination_wake_matches_requeued"));
        } else {
            semantic_assertions.push(SemanticAssertion::fail(
                "destination_wake_matches_requeued",
                format!("expected {expected_requeued}, got {dest_ret}"),
            ));
        }
    } else {
        semantic_assertions.push(SemanticAssertion::pass("destination_wake_matches_requeued"));
    }

    let redispatches = snapshot.get(WorkMetric::KernelRedispatches).unwrap_or(0);
    if redispatches == 0 {
        semantic_assertions.push(SemanticAssertion::pass(
            "zero_repeated_redispatch_while_parked",
        ));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "zero_repeated_redispatch_while_parked",
            format!("redispatches while parked = {redispatches}"),
        ));
    }

    if report.exit_code() == 0 {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code was {}", report.exit_code()),
        ));
    }

    let contract_id = ContractId::new("kernel.futex.requeue")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:futexrequeue".to_string(),
        scale: waiters as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.futex.requeue` at execution layer `VmFree`.
pub fn futex_requeue_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    let wake_count = if scale > 0 { 1 } else { 0 };
    let requeue_count = scale.saturating_sub(wake_count);
    futex_requeue_scenario(scale, wake_count, requeue_count)
}
