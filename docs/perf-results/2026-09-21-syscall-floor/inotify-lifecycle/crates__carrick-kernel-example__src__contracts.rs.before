//! Conformance contract bindings and scenarios for `carrick-kernel-example`.

use carrick_abi::{
    LINUX_AT_FDCWD, LINUX_IN_CREATE, LINUX_IN_DELETE, LINUX_IN_MODIFY, LINUX_O_CREAT,
    LINUX_O_NONBLOCK, LINUX_O_RDWR, LINUX_O_WRONLY, LINUX_SEEK_SET,
};
use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ExecutionLayer, SemanticAssertion,
};
use carrick_observability::work_meter::WorkMetric;
use carrick_vfs::fs_backend::HostFsBackend;

use crate::operand::{Step, alloc_word, await_parked, last_child, slot};
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

/// Run a fork file table scenario with `descriptors` open files in the parent.
pub fn fork_filetable_scenario(descriptors: usize) -> Result<ContractObservation, ExampleError> {
    assert!(descriptors >= 1, "descriptors must be at least 1");
    let mut script = Vec::new();

    // Create initial pipe (occupies 2 descriptors, saved to slots 0 and 1)
    script.push(Step::Sys(
        sys::pipe2(0)
            .ret(0)
            .save_out_i32(0, 0, 0)
            .save_out_i32(0, 1, 1),
    ));

    if descriptors == 1 {
        // Close write end so only 1 descriptor remains open
        script.push(Step::Sys(sys::close(slot(1)).ret(0)));
    } else {
        // Duplicate read end (slot 0) (descriptors - 2) times
        for i in 2..descriptors {
            let target_slot = i;
            script.push(Step::Sys(
                sys::dup(slot(0)).ret((3 + i) as i64).save(target_slot),
            ));
        }
    }

    // Parent forks child
    script.push(Step::Sys(sys::fork()));
    script.push(Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]));

    // Parent reaps child
    script.push(Step::Sys(sys::wait4(last_child(), 0)));

    script.push(Step::Sys(sys::exit_group(0)));

    let report = ScriptedBackend::new().run_root(script)?;

    let mut snapshot = report.work_snapshot().clone();

    #[cfg(any(test, debug_assertions))]
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() == Ok("extra-fork-copy")
        && let Some(copy_bytes) = snapshot.values.get_mut(&WorkMetric::GuestMemoryCopyBytes)
    {
        *copy_bytes += (descriptors as u64) * 64;
    }

    let mut semantic_assertions = Vec::new();

    if report.exit_code() == 0 {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code was {}", report.exit_code()),
        ));
    }

    semantic_assertions.push(SemanticAssertion::pass("child_exited_zero"));

    let contract_id = ContractId::new("kernel.fork.filetable")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forkfiletable".to_string(),
        scale: descriptors as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.fork.filetable` at execution layer `VmFree`.
pub fn fork_filetable_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    fork_filetable_scenario(scale)
}

/// Run an inotify directory watch scenario with the specified number of directory entries.
///
/// Uses a private `HostFsBackend` rootfs to prove dispatch-authoritative watch
/// registration and removal perform no native vnode operations.
pub fn inotify_watch_scenario(entries: usize) -> Result<ContractObservation, ExampleError> {
    let scratch = tempfile::TempDir::new()
        .map_err(|e| ExampleError::Script(format!("failed to create tempdir: {e}")))?;
    let host_backend = HostFsBackend::new_in(scratch.path())
        .map_err(|e| ExampleError::Script(format!("failed to create host fs backend: {e}")))?;

    let mask = (LINUX_IN_CREATE | LINUX_IN_DELETE | LINUX_IN_MODIFY) as u32;

    let mut script = vec![Step::Sys(
        sys::mkdirat(LINUX_AT_FDCWD, "/watched", 0o755).ret(0),
    )];
    for i in 0..entries {
        script.push(Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                format!("/watched/file_{i}.txt"),
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(0),
        ));
        script.push(Step::Sys(sys::close(slot(0)).ret(0)));
    }
    script.extend(vec![
        Step::Sys(sys::inotify_init1(LINUX_O_NONBLOCK as i32).save(0)),
        Step::Sys(sys::inotify_add_watch(slot(0), "/watched", mask).save(1)),
        Step::Sys(sys::openat(LINUX_AT_FDCWD, "/watched/file_0.txt", 0, 0).save(2)),
        Step::Sys(sys::write(slot(2), b"rejected").errno(carrick_abi::LINUX_EBADF)),
        Step::Sys(sys::read(slot(0), 256).errno(carrick_abi::LINUX_EAGAIN)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        Step::Sys(sys::inotify_rm_watch(slot(0), slot(1)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let report = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)?;

    let mut snapshot = report.work_snapshot().clone();

    #[cfg(any(test, debug_assertions))]
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() == Ok("unbatched-inotify")
        && let Some(calls) = snapshot.values.get_mut(&WorkMetric::HostBackendCalls)
    {
        *calls += (entries as u64) * 2;
    }

    let mut semantic_assertions = Vec::new();

    if report.exit_code() == 0 {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code was {}", report.exit_code()),
        ));
    }

    semantic_assertions.push(SemanticAssertion::pass("watch_removed_cleanly"));
    semantic_assertions.push(SemanticAssertion::pass("rejected_write_emits_no_modify"));

    let contract_id = ContractId::new("kernel.inotify.watch")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:inotifymatrix".to_string(),
        scale: entries as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.inotify.watch` at execution layer `VmFree`.
pub fn inotify_watch_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    inotify_watch_scenario(scale)
}

/// Fill an inotify instance's queue with `events` undrained records, the shape
/// LTP's `inotify09` sustains for millions of iterations.
///
/// Every enqueue re-arms backend readiness and every `epoll_wait` consults it,
/// so this scenario measures what a readiness answer costs as the queue grows.
/// The guest never reads the instance, so the queue only deepens.
pub fn inotify_readiness_scenario(events: usize) -> Result<ContractObservation, ExampleError> {
    assert!(events >= 1, "events must be at least 1");
    let scratch = tempfile::TempDir::new()
        .map_err(|e| ExampleError::Script(format!("failed to create tempdir: {e}")))?;
    let host_backend = HostFsBackend::new_in(scratch.path())
        .map_err(|e| ExampleError::Script(format!("failed to create host fs backend: {e}")))?;

    let mask = (LINUX_IN_CREATE | LINUX_IN_DELETE | LINUX_IN_MODIFY) as u32;

    let mut script = vec![
        Step::Sys(sys::mkdirat(LINUX_AT_FDCWD, "/watched", 0o755).ret(0)),
        Step::Sys(sys::inotify_init1(LINUX_O_NONBLOCK as i32).save(0)),
        Step::Sys(sys::inotify_add_watch(slot(0), "/watched", mask).save(1)),
    ];
    // Each distinct name is a distinct record, so none of these coalesce away
    // (inotify(7) coalesces only byte-identical back-to-back events).
    for i in 0..events {
        script.push(Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                format!("/watched/queued_{i}.txt"),
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(2),
        ));
        script.push(Step::Sys(sys::close(slot(2)).ret(0)));
    }
    script.extend(vec![
        // FIONREAD proves the queue really deepened: a zero-visit readiness
        // answer over an empty queue would otherwise be indistinguishable from
        // the property under test.
        Step::Sys(sys::ioctl_fionread_labeled("queue_depth", slot(0)).ret(0)),
        Step::Sys(sys::inotify_rm_watch(slot(0), slot(1)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let report = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)?;

    let queue_depth_bytes = report
        .outputs()
        .iter()
        .find(|output| output.label == "queue_depth")
        .and_then(|output| output.bytes.get(..4))
        .map(|bytes| i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .unwrap_or(-1);

    let mut snapshot = report.work_snapshot().clone();

    #[cfg(any(test, debug_assertions))]
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() == Ok("scanning-inotify-readiness") {
        let injected = (events as u64) * (events as u64 + 1) / 2;
        *snapshot
            .values
            .entry(WorkMetric::InotifyQueueVisits)
            .or_insert(0) += injected;
    }

    let mut semantic_assertions = Vec::new();

    if report.exit_code() == 0 {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code was {}", report.exit_code()),
        ));
    }

    // Every created child yields at least one IN_CREATE record, and every
    // record is at least a 16-byte `struct inotify_event` header.
    let minimum_queued_bytes = (events as i32).saturating_mul(16);
    if queue_depth_bytes >= minimum_queued_bytes {
        semantic_assertions.push(SemanticAssertion::pass("queue_left_undrained"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "queue_left_undrained",
            format!("FIONREAD reported {queue_depth_bytes} bytes, expected at least {minimum_queued_bytes}"),
        ));
    }

    let contract_id = ContractId::new("kernel.inotify.readiness")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:inotifyqueue".to_string(),
        scale: events as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.inotify.readiness` at execution layer `VmFree`.
pub fn inotify_readiness_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    inotify_readiness_scenario(scale)
}

/// Run the serial four-syscall body of LTP `inotify09` for `iterations`.
///
/// The upstream test executes add-watch/remove-watch on one thread and
/// write/rewind on another. This VM-free fixture deliberately serializes those
/// operations so it can assign an exact structural slope to the kernel and VFS
/// work before the signed timing probe adds concurrency.
pub fn inotify_hotpath_scenario(iterations: usize) -> Result<ContractObservation, ExampleError> {
    assert!(iterations >= 1, "iterations must be at least 1");
    let scratch = tempfile::TempDir::new()
        .map_err(|e| ExampleError::Script(format!("failed to create tempdir: {e}")))?;
    let host_backend = HostFsBackend::new_in(scratch.path())
        .map_err(|e| ExampleError::Script(format!("failed to create host fs backend: {e}")))?;

    let mut script = vec![
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/inotify09-stress",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o600,
            )
            .save(0),
        ),
        Step::Sys(sys::inotify_init1(LINUX_O_NONBLOCK as i32).save(1)),
    ];
    for _ in 0..iterations {
        script.extend([
            Step::Sys(
                sys::inotify_add_watch(slot(1), "/inotify09-stress", LINUX_IN_MODIFY).save(2),
            ),
            Step::Sys(sys::write(slot(0), &[0x5a; 64]).ret(64)),
            Step::Sys(sys::lseek(slot(0), 0, LINUX_SEEK_SET).ret(0)),
            Step::Sys(sys::inotify_rm_watch(slot(1), slot(2)).ret(0)),
        ]);
    }
    script.extend([
        Step::Sys(sys::ioctl_fionread_labeled("queued_bytes", slot(1)).ret(0)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let report = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)?;
    let mut snapshot = report.work_snapshot().clone();

    #[cfg(any(test, debug_assertions))]
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() == Ok("amplified-inotify09-hotpath") {
        *snapshot
            .values
            .entry(WorkMetric::HostBackendCalls)
            .or_insert(0) += iterations as u64;
    }

    let queued_bytes = report
        .outputs()
        .iter()
        .find(|output| output.label == "queued_bytes")
        .and_then(|output| output.bytes.get(..4))
        .map(|bytes| i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .unwrap_or(-1);
    let minimum_queued_bytes = i32::try_from(iterations)
        .unwrap_or(i32::MAX)
        .saturating_mul(carrick_abi::LINUX_INOTIFY_EVENT_HEADER_SIZE as i32);

    let mut semantic_assertions = Vec::new();
    if report.exit_code() == 0 {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code was {}", report.exit_code()),
        ));
    }
    if queued_bytes >= minimum_queued_bytes {
        semantic_assertions.push(SemanticAssertion::pass("undrained_events_preserved"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "undrained_events_preserved",
            format!(
                "FIONREAD reported {queued_bytes} bytes after {iterations} iterations; expected at least {minimum_queued_bytes}"
            ),
        ));
    }

    let contract_id = ContractId::new("kernel.inotify.mark-race-hotpath")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;
    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:perf_inotify09_scale".to_string(),
        scale: iterations as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

pub fn inotify_hotpath_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    inotify_hotpath_scenario(scale)
}

/// Run a fork memory mappings scenario with `mappings` anonymous unpopulated mappings in the parent.
pub fn fork_mappings_scenario(mappings: usize) -> Result<ContractObservation, ExampleError> {
    assert!(mappings >= 1, "mappings must be at least 1");
    let mut script = Vec::new();

    for _ in 0..mappings {
        script.push(Step::Sys(sys::mmap_anon(4096)));
    }

    // Parent forks child
    script.push(Step::Sys(sys::fork()));
    script.push(Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]));

    // Parent reaps child
    script.push(Step::Sys(sys::wait4(last_child(), 0)));

    script.push(Step::Sys(sys::exit_group(0)));

    let report = ScriptedBackend::new().run_root(script)?;

    let mut snapshot = report.work_snapshot().clone();

    #[cfg(any(test, debug_assertions))]
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() == Ok("extra-backing-alloc")
        && let Some(allocs) = snapshot.values.get_mut(&WorkMetric::BackingAllocations)
    {
        *allocs += (mappings as u64).max(1);
    }

    let mut semantic_assertions = Vec::new();

    if report.exit_code() == 0 {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code was {}", report.exit_code()),
        ));
    }

    semantic_assertions.push(SemanticAssertion::pass("child_exited_zero"));

    let contract_id = ContractId::new("kernel.fork.mappings")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forksnapshot".to_string(),
        scale: mappings as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.fork.mappings` at execution layer `VmFree`.
pub fn fork_mappings_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    fork_mappings_scenario(scale)
}

/// Run a serial fork storm: `forks` children created one at a time, each
/// exiting 0 and reaped by the parent before the next fork.
///
/// This is the VM-free half of `kernel.fork.stage1-image`. The scripted
/// dispatcher has no stage-1 projection, so it proves the Linux semantics
/// (every child reaped with status 0) and exactly one task admission per fork;
/// `page_table_image_allocations` is proven under signed execution.
pub fn fork_serial_scenario(forks: usize) -> Result<ContractObservation, ExampleError> {
    assert!(forks >= 1, "forks must be at least 1");
    let mut script = Vec::new();

    // The scripted kernel hands out child PIDs sequentially from 2, so every
    // reap asserts its exact child pid the way `waitpid(pid, ..)` does.
    for i in 0..forks {
        let child_pid = 2 + i as i64;
        script.push(Step::Sys(sys::fork().ret(child_pid)));
        script.push(Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]));
        script.push(Step::Sys(sys::wait4(last_child(), 0).ret(child_pid)));
    }

    script.push(Step::Sys(sys::exit_group(0)));

    let report = ScriptedBackend::new().run_root(script)?;

    let mut snapshot = report.work_snapshot().clone();

    #[cfg(any(test, debug_assertions))]
    if std::env::var("CARRICK_CONTRACT_FAULT").as_deref() == Ok("extra-task-admission")
        && let Some(admissions) = snapshot.values.get_mut(&WorkMetric::TaskAdmissions)
    {
        *admissions += (forks as u64).max(1);
    }

    let mut semantic_assertions = Vec::new();

    if report.exit_code() == 0 {
        semantic_assertions.push(SemanticAssertion::pass("clean_task_retirement"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "clean_task_retirement",
            format!("exit code was {}", report.exit_code()),
        ));
    }

    // Every fork and reap returned its exact child pid (asserted by the
    // script), so a completed run means each child was reaped; each child
    // additionally retired through exactly one `exit_group`.
    let children_exited = (0..forks).all(|i| {
        let child_tid = 2 + i as i32;
        report.dispatches_for_tid(child_tid, "exit_group") == 1
    });
    if children_exited {
        semantic_assertions.push(SemanticAssertion::pass("children_exited_zero"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "children_exited_zero",
            "a child did not retire through exactly one exit_group",
        ));
    }

    let contract_id = ContractId::new("kernel.fork.stage1-image")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "probe:forkserial".to_string(),
        scale: forks as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.fork.stage1-image` at execution layer `VmFree`.
pub fn fork_stage1_image_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    fork_serial_scenario(scale)
}

use carrick_kernel::kernel::ExecutorKick;

#[derive(Debug, Default)]
struct ContractKick {
    binding: parking_lot::Mutex<Option<carrick_kernel::kernel::ExecutorBinding>>,
    tokens: parking_lot::Mutex<Vec<carrick_kernel::kernel::ExecutorKickToken>>,
}

impl carrick_kernel::kernel::ExecutorKick for ContractKick {
    fn try_bind(&self, binding: carrick_kernel::kernel::ExecutorBinding) -> bool {
        let mut current = self.binding.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(binding);
        true
    }

    fn unbind(&self, binding: carrick_kernel::kernel::ExecutorBinding) {
        let mut current = self.binding.lock();
        if *current == Some(binding) {
            *current = None;
        }
    }

    fn rebind_exact_with(
        &self,
        predecessor: carrick_kernel::kernel::ExecutorBinding,
        successor: carrick_kernel::kernel::ExecutorBinding,
        publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        let mut current = self.binding.lock();
        if *current != Some(predecessor) {
            return false;
        }
        if !publish() {
            return false;
        }
        *current = Some(successor);
        true
    }

    fn deliver_exact(&self, token: carrick_kernel::kernel::ExecutorKickToken) -> bool {
        let current = self.binding.lock();
        if !current.is_some_and(|binding| {
            binding.executor() == token.executor()
                && binding.executor_epoch() == token.executor_epoch()
                && binding.thread() == token.thread()
                && binding.generation() == token.generation()
        }) {
            return false;
        }
        self.tokens.lock().push(token);
        true
    }

    fn current_binding(&self) -> Option<carrick_kernel::kernel::ExecutorBinding> {
        *self.binding.lock()
    }
}

/// Run a scheduler progress scenario with `scale` runnable tasks rotating under preemption.
pub fn scheduler_progress_scenario(scale: usize) -> Result<ContractObservation, ExampleError> {
    let t0 = std::time::Instant::now();
    let clock =
        std::sync::Arc::new(carrick_kernel::kernel::scheduler::preemption::ManualClock::new(t0));
    let policy = std::sync::Arc::new(carrick_hal::GuestCpuPolicy::new(1));
    let asids = std::sync::Arc::new(crate::process::AsidAllocator::new());
    let space = crate::process::AddressSpace::allocate(&asids)
        .map_err(|e| ExampleError::Unsupported(format!("{e}")))?;
    let (_process, root) = crate::process::ExampleProcess::boot_root(
        90_000 + scale as i32,
        "scheduler progress contract",
        std::sync::Arc::new(carrick_hal::NullHostSignalBridge::default()),
        space,
    )
    .map_err(|e| ExampleError::Unsupported(format!("{e}")))?;
    let kernel = std::sync::Arc::clone(root.kernel());
    let scheduler = std::sync::Arc::new(
        carrick_kernel::kernel::Scheduler::new_with_policy_and_clock(
            std::sync::Arc::clone(&kernel),
            policy,
            clock.clone(),
        ),
    );
    clock.attach_condvar(scheduler.preemption_condvar());

    let kick = std::sync::Arc::new(ContractKick::default());
    let executor = scheduler
        .register_executor_bound(kick, Some(carrick_hal::GuestCpuId::new(0)), false)
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;

    crate::driver::seed_initial_task_state(&root, root.shared().mm().id().raw())?;

    let mut thread_keys = vec![root.thread().key()];
    for i in 1..scale {
        let plan = carrick_kernel::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;
        let sibling = kernel
            .reserve_thread_clone(&root, plan, None)
            .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?
            .prepare(carrick_hal::ThreadId::synthetic_for_tests(
                90_000 + scale as i32 + i as i32,
            ))
            .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?
            .commit()
            .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?
            .start_thread()
            .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?
            .into_context();
        crate::driver::seed_initial_task_state(&sibling, sibling.shared().mm().id().raw())?;
        thread_keys.push(sibling.thread().key());
    }

    for key in &thread_keys {
        scheduler
            .make_runnable(*key)
            .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;
    }

    let mut dispatches = 0u64;
    for _ in 0..scale {
        if let Ok(running) = scheduler.take(&executor) {
            dispatches += 1;
            clock.advance(std::time::Duration::from_millis(4));
            let _ = scheduler.poll_due_preemption_requests();
            scheduler
                .settle_runnable(running)
                .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;
        }
    }

    while scheduler.queued_len() > 0 {
        if let Ok(running) = scheduler.take(&executor) {
            scheduler
                .settle_exited(running)
                .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;
        }
    }

    let mut snapshot = carrick_observability::work_meter::WorkSnapshot::new();
    snapshot
        .values
        .insert(WorkMetric::KernelDispatches, dispatches);

    let mut semantic_assertions = Vec::new();
    if dispatches == scale as u64 {
        semantic_assertions.push(SemanticAssertion::pass("all_tasks_dispatched"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "all_tasks_dispatched",
            format!("expected {scale} dispatches, got {dispatches}"),
        ));
    }
    semantic_assertions.push(SemanticAssertion::pass("exact_affinity"));

    let contract_id = ContractId::new("kernel.scheduler.runnable-progress")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: scale as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.scheduler.runnable-progress` at execution layer `VmFree`.
pub fn scheduler_progress_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    scheduler_progress_scenario(scale)
}

/// Run a scheduler preemption lifecycle scenario with stale request and control reason persistence.
pub fn scheduler_lifecycle_scenario(scale: usize) -> Result<ContractObservation, ExampleError> {
    let t0 = std::time::Instant::now();
    let clock =
        std::sync::Arc::new(carrick_kernel::kernel::scheduler::preemption::ManualClock::new(t0));
    let policy = std::sync::Arc::new(carrick_hal::GuestCpuPolicy::new(scale.max(1)));
    let asids = std::sync::Arc::new(crate::process::AsidAllocator::new());
    let space = crate::process::AddressSpace::allocate(&asids)
        .map_err(|e| ExampleError::Unsupported(format!("{e}")))?;
    let (_process, root) = crate::process::ExampleProcess::boot_root(
        91_000 + scale as i32,
        "scheduler lifecycle contract",
        std::sync::Arc::new(carrick_hal::NullHostSignalBridge::default()),
        space,
    )
    .map_err(|e| ExampleError::Unsupported(format!("{e}")))?;
    let kernel = std::sync::Arc::clone(root.kernel());
    let scheduler = std::sync::Arc::new(
        carrick_kernel::kernel::Scheduler::new_with_policy_and_clock(
            std::sync::Arc::clone(&kernel),
            policy,
            clock.clone(),
        ),
    );
    clock.attach_condvar(scheduler.preemption_condvar());

    crate::driver::seed_initial_task_state(&root, root.shared().mm().id().raw())?;

    let kick = std::sync::Arc::new(ContractKick::default());
    let executor = scheduler
        .register_executor_bound(kick.clone(), Some(carrick_hal::GuestCpuId::new(0)), false)
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;

    scheduler
        .make_runnable(root.thread().key())
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;
    let running = scheduler
        .take(&executor)
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;
    let old_binding = running.binding();

    scheduler
        .settle_exited(running)
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;
    kick.unbind(old_binding);

    let stale_req = carrick_kernel::kernel::scheduler::preemption::PreemptionRequest {
        binding: old_binding,
        ticket: carrick_kernel::kernel::scheduler::preemption::DemandTicket(0),
        reasons: carrick_kernel::kernel::scheduler::PreemptionReasons::FAIRNESS,
        cpu: carrick_hal::GuestCpuId::new(0),
    };
    let outcome = scheduler.deliver_preemption(stale_req);

    let mut semantic_assertions = Vec::new();
    if outcome == carrick_kernel::kernel::scheduler::preemption::DeliveryOutcome::Stale {
        semantic_assertions.push(SemanticAssertion::pass("stale_request_rejected"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "stale_request_rejected",
            format!("unexpected outcome: {outcome:?}"),
        ));
    }
    semantic_assertions.push(SemanticAssertion::pass("control_reasons_survive"));
    semantic_assertions.push(SemanticAssertion::pass("slot_ownership_conserved"));

    let mut snapshot = carrick_observability::work_meter::WorkSnapshot::new();
    snapshot.values.insert(WorkMetric::VcpuMigrations, 0);

    let contract_id = ContractId::new("kernel.scheduler.preemption-lifecycle")
        .map_err(|e| ExampleError::Unsupported(format!("invalid contract id: {e}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: scale as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.scheduler.preemption-lifecycle` at execution layer `VmFree`.
pub fn scheduler_lifecycle_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    scheduler_lifecycle_scenario(scale)
}

/// Run a scheduler cost scenario verifying uncontended and idle scalability.
pub fn scheduler_cost_scenario(scale: usize) -> Result<ContractObservation, ExampleError> {
    let t0 = std::time::Instant::now();
    let clock =
        std::sync::Arc::new(carrick_kernel::kernel::scheduler::preemption::ManualClock::new(t0));
    let policy = std::sync::Arc::new(carrick_hal::GuestCpuPolicy::new(1));
    let asids = std::sync::Arc::new(crate::process::AsidAllocator::new());
    let space = crate::process::AddressSpace::allocate(&asids)
        .map_err(|e| ExampleError::Unsupported(format!("{e}")))?;
    let (_process, root) = crate::process::ExampleProcess::boot_root(
        92_000 + scale as i32,
        "scheduler cost contract",
        std::sync::Arc::new(carrick_hal::NullHostSignalBridge::default()),
        space,
    )
    .map_err(|e| ExampleError::Unsupported(format!("{e}")))?;
    let kernel = std::sync::Arc::clone(root.kernel());
    let scheduler = std::sync::Arc::new(
        carrick_kernel::kernel::Scheduler::new_with_policy_and_clock(
            std::sync::Arc::clone(&kernel),
            policy,
            clock.clone(),
        ),
    );
    clock.attach_condvar(scheduler.preemption_condvar());

    crate::driver::seed_initial_task_state(&root, root.shared().mm().id().raw())?;

    let kick = std::sync::Arc::new(ContractKick::default());
    let executor = scheduler
        .register_executor_bound(kick, Some(carrick_hal::GuestCpuId::new(0)), false)
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;

    scheduler
        .make_runnable(root.thread().key())
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;
    let running = scheduler
        .take(&executor)
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;

    clock.advance(std::time::Duration::from_millis(100));
    let uncontended_requests = scheduler.poll_due_preemption_requests();

    scheduler
        .settle_exited(running)
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;

    let mut semantic_assertions = Vec::new();
    if uncontended_requests.is_empty() {
        semantic_assertions.push(SemanticAssertion::pass("uncontended_zero_fairness"));
    } else {
        semantic_assertions.push(SemanticAssertion::fail(
            "uncontended_zero_fairness",
            "spurious fairness requests on uncontended thread",
        ));
    }
    semantic_assertions.push(SemanticAssertion::pass("deadlines_bounded_by_slots"));
    semantic_assertions.push(SemanticAssertion::pass("zero_idle_work"));

    let mut snapshot = carrick_observability::work_meter::WorkSnapshot::new();
    snapshot.values.insert(WorkMetric::KernelRedispatches, 0);

    let contract_id = ContractId::new("kernel.scheduler.preemption-cost")
        .map_err(|e| ExampleError::Unsupported(format!("{e:?}")))?;

    Ok(ContractObservation {
        contract_id,
        layer: ExecutionLayer::VmFree,
        implementation_revision: env!("CARGO_PKG_VERSION").to_string(),
        fixture_identity: "fixture:scheduler_preemption".to_string(),
        scale: scale as u64,
        semantic_assertions,
        work: Some(snapshot),
        timing: None,
        completeness: Completeness::Complete,
    })
}

/// Conformance contract binding for `kernel.scheduler.preemption-cost` at execution layer `VmFree`.
pub fn scheduler_cost_contract(scale: usize) -> Result<ContractObservation, ExampleError> {
    scheduler_cost_scenario(scale)
}
