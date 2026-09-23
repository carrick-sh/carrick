#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_conformance_contract::{
    Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
    SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
};
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge, ThreadId};
use carrick_kernel::{
    dispatch::{CarrierBridges, SyscallDispatcher},
    kernel::{CarrierProcess, objects::ExecutorId},
};
use carrick_kernel_example::{
    driver::seed_initial_task_state,
    process::{AddressSpace, AsidAllocator, ExampleProcess},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::Arc,
};

thread_local! { static ALLOCATIONS: Cell<Option<u64>> = const { Cell::new(None) }; }
struct CountingAllocator;
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
fn allocated() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(n) = count.get() {
            count.set(Some(n.checked_add(1).unwrap()));
        }
    });
}
// SAFETY: forwards every layout, pointer and size unchanged to System. The
// observation cell uses const TLS and performs no allocations itself.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocated();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocated();
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[test]
fn native_execution_scope_contract() {
    ALLOCATIONS.set(Some(0));
    let positive = std::hint::black_box(vec![std::hint::black_box(42u8); 64]);
    assert!(ALLOCATIONS.replace(None).unwrap() > 0);
    drop(positive);

    let bridges = CarrierBridges {
        host_signal: Arc::new(NullHostSignalBridge::default()),
        timers: Arc::new(NullGuestTimerBridge::default()),
    };
    let tid = ThreadId::from_guest_supplied_tid(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
    let (process, context) = ExampleProcess::boot_root(
        tid.raw(),
        "native-scope-contract",
        bridges.host_signal.clone(),
        AddressSpace::allocate(&AsidAllocator::new()).unwrap(),
    )
    .unwrap();
    let process = Arc::new(process);
    let dispatcher = SyscallDispatcher::with_bridges(bridges);
    dispatcher.bind_hvpatch_process(process.clone() as Arc<dyn CarrierProcess>);
    assert!(process.take_bind_failure().is_none());
    seed_initial_task_state(&context, process.asid_generation()).unwrap();
    let mut execution = context
        .thread()
        .claim_runnable(ExecutorId::for_transitional_thread(tid).unwrap())
        .unwrap();
    let mut executor = dispatcher
        .admit_native_executor(&context, &execution)
        .unwrap();
    let interrupt = executor.interrupt_handle();
    drop(
        dispatcher
            .enter_native_execution(&mut executor, &context, &mut execution)
            .unwrap(),
    );
    let mut observations = Vec::new();
    for scale in [1, 8, 32, 128] {
        let mut completed = 0;
        let mut exact = true;
        ALLOCATIONS.set(Some(0));
        for _ in 0..scale {
            let scope = dispatcher
                .enter_native_execution(&mut executor, &context, &mut execution)
                .unwrap();
            exact &= !scope.stop_requested();
            interrupt.request_stop();
            exact &= scope.stop_requested();
            // Requesting a stop never drops membership or acknowledges running.
            drop(scope);
            dispatcher
                .service_native_memory_control(&mut executor, &context, &execution)
                .unwrap();
            exact &= executor.take_stop_request();
            completed += 1;
        }
        let allocations = ALLOCATIONS.replace(None).unwrap();
        let mut work = WorkSnapshot::new();
        work.insert(WorkMetric::HostHeapAllocations, allocations)
            .unwrap();
        observations.push(ContractObservation {
            contract_id: ContractId::new("kernel.mm.native-execution-scope").unwrap(),
            layer: ExecutionLayer::VmFree,
            implementation_revision: std::env::var("CARRICK_NATIVE_SCOPE_REVISION")
                .unwrap_or_else(|_| "unarchived-working-tree".into()),
            fixture_identity: "unit:native-execution-scope".into(),
            scale,
            semantic_assertions: vec![
                SemanticAssertion {
                    name: "exact_completed_scopes_and_sticky_interrupt".into(),
                    passed: exact && completed == scale,
                    detail: Some(format!("completed={completed}")),
                },
                SemanticAssertion::pass("allocator_positive_control_fired"),
            ],
            work: Some(work),
            timing: None,
            completeness: Completeness::Complete,
        });
    }
    if let Some(dir) = std::env::var_os("CARRICK_NATIVE_SCOPE_RECEIPT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            std::path::Path::new(&dir).join("observations.json"),
            serde_json::to_vec_pretty(&observations).unwrap(),
        )
        .unwrap();
    }
    drop(executor);
    context.thread().yield_from_executor(execution).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = ContractRegistry::load(root).unwrap();
    evaluate(
        registry
            .require("kernel.mm.native-execution-scope")
            .unwrap(),
        &observations,
    )
    .unwrap();
}
