use super::*;
use crate::dispatch::mm_quiesce::{
    PtPauseBudget, PtPauseTryError, acquire_pt_pause, try_acquire_pt_pause_for_test,
};
use crate::kernel::mm_access::test_support::execution_lease;
use std::time::Duration;

static_assertions::assert_not_impl_any!(NativeExecutor: Send, Sync, Clone, Copy);
static_assertions::assert_not_impl_any!(NativeExecution<'static>: Send, Sync, Clone, Copy);

fn fixture(marker: u64) -> (SyscallDispatcher, KernelContext, ThreadExecutionLease) {
    let dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let lease = execution_lease(&context, marker);
    (dispatcher, context, lease)
}
fn settle(context: &KernelContext, executor: NativeExecutor, lease: ThreadExecutionLease) {
    drop(executor);
    context.thread().yield_from_executor(lease).unwrap();
}

#[test]
fn stop_request_does_not_acknowledge_running_and_entry_takes_no_occupancy_lock() {
    let (dispatcher, context, mut lease) = fixture(19401);
    let mut executor = dispatcher.admit_native_executor(&context, &lease).unwrap();
    let interrupt = executor.interrupt_handle();
    let census = dispatcher.mm_occupancy_probe();
    for _ in 0..128 {
        // Holding the MM's fence election here makes any hidden entry-time
        // pause acquisition deadlock. Its occupancy already admits us.
        let barrier = executor.participant.pt_quiesce().clone();
        assert!(barrier.try_become_coordinator());
        let held = dispatcher.mm_residents_for_test();
        let scope = dispatcher
            .enter_native_execution(&mut executor, &context, &mut lease)
            .unwrap();
        assert!(held.any_in_guest());
        interrupt.request_stop();
        assert!(scope.stop_requested());
        assert!(held.any_in_guest());
        held.kick_all_in_guest();
        assert!(held.any_in_guest());
        drop(scope);
        assert!(!held.any_in_guest());
        drop(held);
        barrier.end();
        assert!(executor.take_stop_request());
    }
    settle(&context, executor, lease);
    assert_eq!(census(), 0);
}

#[test]
fn raised_pause_refuses_entry_and_rolls_back_running() {
    let (dispatcher, context, mut lease) = fixture(19402);
    let mut executor = dispatcher.admit_native_executor(&context, &lease).unwrap();
    let barrier = executor.participant.pt_quiesce().clone();
    assert!(barrier.try_become_coordinator());
    barrier.set_quiescing();
    assert!(matches!(
        dispatcher.enter_native_execution(&mut executor, &context, &mut lease),
        Err(NativeExecutionError::ControlPending)
    ));
    assert!(!executor.state.is_running());
    barrier.end();
    drop(
        dispatcher
            .enter_native_execution(&mut executor, &context, &mut lease)
            .unwrap(),
    );
    settle(&context, executor, lease);
}

#[test]
fn real_mutation_drain_cannot_pass_until_execution_scope_ends() {
    let (dispatcher, context, mut lease) = fixture(19403);
    let mut executor = dispatcher.admit_native_executor(&context, &lease).unwrap();
    let barrier = executor.participant.pt_quiesce().clone();
    let mm = executor.participant.mm_id();
    let tid = ThreadId::synthetic_for_tests(19404);
    let scope = dispatcher
        .enter_native_execution(&mut executor, &context, &mut lease)
        .unwrap();
    let result = try_acquire_pt_pause_for_test(
        &barrier,
        mm,
        tid,
        PtPauseBudget {
            election: Duration::ZERO,
        },
    );
    assert!(matches!(result, Err(PtPauseTryError::SiblingInGuest)));
    drop(result);
    assert!(scope.stop_requested());
    assert!(!barrier.is_quiescing()); // refusal rolls back the mutation request
    assert!(dispatcher.mm_residents_for_test().any_in_guest());
    drop(scope);
    let pause = acquire_pt_pause(&barrier, mm, tid, PtPauseBudget::DEFAULT).unwrap();
    assert!(barrier.is_quiescing());
    assert!(matches!(
        dispatcher.enter_native_execution(&mut executor, &context, &mut lease),
        Err(NativeExecutionError::ControlPending)
    ));
    drop(pause);
    assert!(executor.take_stop_request());
    drop(
        dispatcher
            .enter_native_execution(&mut executor, &context, &mut lease)
            .unwrap(),
    );
    settle(&context, executor, lease);
}

#[test]
fn wrong_context_and_transferred_lease_cannot_reuse_admission() {
    let (dispatcher, context, mut lease) = fixture(19405);
    let (other, other_context, mut other_lease) = fixture(19406);
    assert!(
        dispatcher
            .admit_native_executor(&context, &other_lease)
            .is_err()
    );
    let mut executor = dispatcher.admit_native_executor(&context, &lease).unwrap();
    assert!(
        other
            .enter_native_execution(&mut executor, &context, &mut lease)
            .is_err()
    );
    assert!(
        dispatcher
            .enter_native_execution(&mut executor, &other_context, &mut other_lease)
            .is_err()
    );
    context.thread().yield_from_executor(lease).unwrap();
    let mut successor = context
        .thread()
        .claim_runnable(ExecutorId::synthetic_for_tests(19407))
        .unwrap();
    assert!(matches!(
        dispatcher.enter_native_execution(&mut executor, &context, &mut successor),
        Err(NativeExecutionError::ChangedExecutionLease)
    ));
    let stale_interrupt = executor.interrupt_handle();
    drop(executor);
    let mut successor_executor = dispatcher
        .admit_native_executor(&context, &successor)
        .unwrap();
    stale_interrupt.request_stop();
    let scope = dispatcher
        .enter_native_execution(&mut successor_executor, &context, &mut successor)
        .unwrap();
    assert!(!scope.stop_requested());
    drop(scope);
    settle(&context, successor_executor, successor);
    other_context
        .thread()
        .yield_from_executor(other_lease)
        .unwrap();
}

#[test]
fn unwind_clears_running_before_admission_is_removed() {
    let (dispatcher, context, mut lease) = fixture(19408);
    let mut executor = dispatcher.admit_native_executor(&context, &lease).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _scope = dispatcher
            .enter_native_execution(&mut executor, &context, &mut lease)
            .unwrap();
        panic!("bounded unwind test");
    }));
    assert!(result.is_err());
    assert!(!executor.state.is_running());
    settle(&context, executor, lease);
    assert_eq!(dispatcher.mm_occupancy_probe()(), 0);
}

#[test]
fn replacing_dispatch_participation_cannot_detach_native_running_authority() {
    let (dispatcher, context, mut lease) = fixture(19409);
    let mut executor = dispatcher.admit_native_executor(&context, &lease).unwrap();
    // The ordinary dispatch interface accepts a mutable participation. Moving
    // another admissible token into that slot must never authenticate native
    // execution whose private flag is absent from the replacement slot's port.
    let replacement_slot = crate::kernel::HostExecutionSlot::allocate().unwrap();
    let replacement = dispatcher
        .enter_mm_executor_for_thread(
            None,
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            ThreadId::synthetic_for_tests(19410),
            replacement_slot.slot(),
        )
        .unwrap();
    let original = std::mem::replace(executor.dispatch_participation(), replacement);
    drop(original);
    assert!(
        dispatcher
            .enter_native_execution(&mut executor, &context, &mut lease)
            .is_err()
    );
    assert!(!executor.state.is_running());
    settle(&context, executor, lease);
}

#[test]
fn same_mm_readers_remain_simultaneously_admitted_at_all_scales() {
    for scale in [1, 8, 32, 128] {
        let (dispatcher, root, root_lease) = fixture(19500 + scale);
        let mut contexts = Vec::new();
        for index in 0..scale {
            let plan = crate::kernel::ClonePlan::from_flags(
                carrick_abi::LinuxCloneFlags::THREAD
                    | carrick_abi::LinuxCloneFlags::VM
                    | carrick_abi::LinuxCloneFlags::SIGHAND,
            )
            .unwrap();
            contexts.push(
                root.kernel()
                    .reserve_thread_clone(&root, plan, None)
                    .unwrap()
                    .prepare(ThreadId::synthetic_for_tests(20000 + index as i32))
                    .unwrap()
                    .commit()
                    .unwrap()
                    .into_context()
                    .unwrap(),
            );
        }
        let mut leases: Vec<_> = contexts
            .iter()
            .enumerate()
            .map(|(i, context)| execution_lease(context, 21000 + i as u64))
            .collect();
        let mut executors: Vec<_> = contexts
            .iter()
            .zip(&leases)
            .map(|(context, lease)| dispatcher.admit_native_executor(context, lease).unwrap())
            .collect();
        let census = dispatcher.mm_occupancy_probe();
        let mut scopes = Vec::new();
        for ((executor, context), lease) in executors.iter_mut().zip(&contexts).zip(&mut leases) {
            scopes.push(
                dispatcher
                    .enter_native_execution(executor, context, lease)
                    .unwrap(),
            );
        }
        let held = dispatcher.mm_residents_for_test();
        assert_eq!(held.len(), scale as usize);
        assert_eq!(held.tids().len(), scale as usize);
        assert!(held.hardware_invalidation_tids().is_empty());
        assert!(held.any_in_guest());
        held.kick_all_in_guest();
        assert!(scopes.iter().all(NativeExecution::stop_requested));
        drop(scopes);
        assert!(!held.any_in_guest());
        drop(held);
        for ((context, executor), lease) in contexts.iter().zip(executors).zip(leases) {
            settle(context, executor, lease);
        }
        assert_eq!(census(), 0);
        root.thread().yield_from_executor(root_lease).unwrap();
    }
}

#[test]
fn memory_control_preserves_external_stops_and_rejects_wrong_lease() {
    let (dispatcher, context, mut lease) = fixture(22_000);
    let mut executor = dispatcher.admit_native_executor(&context, &lease).unwrap();
    for scale in [1, 8, 32, 128] {
        for _ in 0..scale {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &context, &mut lease)
                .unwrap();
            dispatcher.mm_residents_for_test().kick_all_in_guest();
            assert!(scope.stop_requested());
            drop(scope);
            assert!(executor.memory_pause_pending());
            // A memory pause may finish (or roll back) before its owner returns.
            // Service still clears the sticky memory request at that safe point.
            executor.interrupt_handle().request_stop();
            dispatcher
                .service_native_memory_control(&mut executor, &context, &lease)
                .unwrap();
            assert!(!executor.memory_pause_pending());
            assert!(matches!(
                dispatcher.enter_native_execution(&mut executor, &context, &mut lease),
                Err(NativeExecutionError::ControlPending)
            ));
            assert!(executor.take_stop_request(), "external stop was swallowed");
        }
    }
    context.thread().yield_from_executor(lease).unwrap();
    let successor = context
        .thread()
        .claim_runnable(ExecutorId::synthetic_for_tests(22001))
        .unwrap();
    executor.state.request_memory_pause();
    assert!(matches!(
        dispatcher.service_native_memory_control(&mut executor, &context, &successor),
        Err(NativeExecutionError::ChangedExecutionLease)
    ));
    assert!(
        executor.memory_pause_pending(),
        "wrong lease cleared a request"
    );
    settle(&context, executor, successor);
}

#[test]
fn native_memory_service_parks_until_the_exact_pause_ends() {
    use std::sync::mpsc;
    let (ready_tx, ready_rx) = mpsc::sync_channel(0);
    let (start_tx, start_rx) = mpsc::sync_channel(0);
    let (done_tx, done_rx) = mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        let (dispatcher, context, lease) = fixture(22_002);
        let mut executor = dispatcher.admit_native_executor(&context, &lease).unwrap();
        let barrier = executor.participant.pt_quiesce().clone();
        ready_tx.send(barrier.clone()).unwrap();
        start_rx.recv().unwrap();
        dispatcher
            .service_native_memory_control(&mut executor, &context, &lease)
            .unwrap();
        assert!(
            !barrier.is_quiescing(),
            "native service escaped a live memory pause"
        );
        assert!(!executor.state.is_running());
        done_tx.send(()).unwrap();
        settle(&context, executor, lease);
    });
    let barrier = ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(barrier.try_become_coordinator());
    barrier.set_quiescing();
    // RAII releases the worker even if the bounded negative assertion fails.
    let pause = barrier.pause_guard(ThreadId::synthetic_for_tests(22003));
    start_tx.send(()).unwrap();
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(10)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    drop(pause);
    done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    worker.join().unwrap();
}
