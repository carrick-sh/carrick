//! Release-only attribution of the actual carrier-backed syscall entry path.
//! These are independent host controls, not additive wall-time samples or a
//! substitute for the unchanged Linux ELF and signed carrier gates.
use super::*;
use carrick_kernel::{
    compat::{CompatEvent, CompatReporter, SyscallArgs},
    dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest, ThreadCtx},
    kernel::mm_access::MmAccessTarget,
    thread::{FutexTable, ThreadRegistry},
};
use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
use native_syscall_slice::carrier_memory::CarrierCopyMemory;

#[test]
#[ignore = "release-only carrier syscall floor attribution"]
#[expect(
    clippy::assertions_on_constants,
    reason = "ignored diagnostic refuses debug execution"
)]
fn carrier_checkpoint_component_cost() {
    assert!(!cfg!(debug_assertions));
    const COUNT: u32 = 65536;
    let (kernel, root) = bootstrap(39_000);
    let tid = ThreadId::synthetic_for_tests(39_001);
    let fixture = real_production_cow_fixture(
        &kernel,
        &root,
        39_001,
        0x9a00_f000_0000,
        0x9b00_f000_0000,
        tid,
    );
    let mut execution = execution_lease(&fixture.child, 39001);
    let authority = carrick_kernel::kernel::MmAccessAuthority::new();
    let current = fixture.child.current_mm(&execution).unwrap();
    let range = current
        .access_token()
        .write_range(GuestVa(TEST_VA), 4096)
        .unwrap()
        .unwrap();
    let mut prepared = authority
        .with_current_mutation(&current, tid, |mutation| {
            let mut cow = authority.break_foreign_cow(mutation, &current, range)?;
            Ok(fixture
                .child
                .borrow_current_native_data(&execution, &mut cow)?
                .prepare_for_execution())
        })
        .unwrap();
    drop(current);
    let dispatcher = SyscallDispatcher::with_native_mm_for_test(fixture.dispatch_mm.clone());
    let mut executor = dispatcher
        .admit_native_executor(&fixture.child, &execution)
        .unwrap();
    let registry = ThreadRegistry::new(tid);
    let futex = FutexTable::new();
    let reporter = CompatReporter::default();
    let names = [
        "authenticate",
        "adapter",
        "entry_activation",
        "checkpoint_control",
        "dispatch_reused_adapter",
        "dispatch_fresh_adapter",
        "whole_host_path",
        "prepare_policy",
        "syscall_metadata",
        "entry_return_reporter",
        "capture_resources",
    ];
    let mut run = |arm: usize, count: u32| {
        let start = Instant::now();
        for _ in 0..count {
            for number in [27, 28] {
                if arm == 10 {
                    carrick_kernel::dispatch::resources::with_dirty_captured_resources_for_executor_test(&fixture.child, || std::hint::black_box(()));
                    continue;
                }
                if arm == 7 {
                    std::hint::black_box(
                        dispatcher
                            .prepare_syscall(
                                &fixture.child,
                                SyscallRequest::new(
                                    std::hint::black_box(number),
                                    SyscallArgs::from([u64::MAX, TEST_VA, 2, 0, 0, 0]),
                                ),
                                &reporter,
                            )
                            .unwrap(),
                    );
                    continue;
                }
                if arm == 8 {
                    std::hint::black_box(
                        carrick_abi::syscall::lookup_aarch64(std::hint::black_box(number)).unwrap(),
                    );
                    continue;
                }
                if arm == 9 {
                    reporter.record(CompatEvent::SyscallEntry {
                        number,
                        name: "diagnostic".into(),
                        args: SyscallArgs::from([u64::MAX, TEST_VA, 2, 0, 0, 0]),
                    });
                    reporter.record(CompatEvent::SyscallReturn {
                        number,
                        name: "diagnostic".into(),
                        retval: -9,
                        errno: Some(9),
                    });
                    continue;
                }
                if arm == 0 {
                    fixture
                        .child
                        .validate_current_execution_mm(std::hint::black_box(&execution))
                        .unwrap();
                    continue;
                }
                if arm == 2 || arm == 6 {
                    let scope = dispatcher
                        .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                        .unwrap();
                    let active = prepared.activate(&scope).unwrap();
                    std::hint::black_box(active.len());
                }
                if arm == 3 || arm == 6 {
                    assert!(!executor.memory_pause_pending());
                    assert!(!executor.take_stop_request());
                    assert!(
                        dispatcher
                            .take_deliverable_pending_from(&fixture.child, tid)
                            .is_none()
                    );
                }
                if arm == 1 || arm == 5 || arm == 6 {
                    let mut memory = CarrierCopyMemory::new(&fixture.child, &execution).unwrap();
                    std::hint::black_box(&memory);
                    if arm != 1 {
                        dispatch_invalid(
                            number,
                            &dispatcher,
                            &fixture.child,
                            executor.dispatch_participation(),
                            &mut memory,
                            &reporter,
                            ThreadCtx::new(tid, &registry, &futex),
                        );
                    }
                }
                if arm == 4 {
                    // Constructor deliberately excluded; dispatch itself cannot
                    // read a buffer because this valid syscall has an invalid fd.
                    // A separate arm below keeps one adapter across the batch.
                    unreachable!();
                }
            }
        }
        start.elapsed().as_nanos() as f64 / f64::from(count)
    };
    let mut rows = Vec::new();
    for sample in 0..10 {
        let order: Vec<_> = if sample % 2 == 0 {
            (0..names.len()).collect()
        } else {
            (0..names.len()).rev().collect()
        };
        for arm in order.into_iter().filter(|n| *n != 4) {
            rows.push((sample, arm, run(arm, if sample == 0 { 128 } else { COUNT })));
        }
    }
    // Same requests, reporter and exact carrier identity, but the adapter is
    // prepared once so this control exposes dispatch without admission work.
    let mut memory = CarrierCopyMemory::new(&fixture.child, &execution).unwrap();
    for sample in 0..10 {
        let count = if sample == 0 { 128 } else { COUNT };
        let start = Instant::now();
        for _ in 0..count {
            for number in [27, 28] {
                dispatch_invalid(
                    number,
                    &dispatcher,
                    &fixture.child,
                    executor.dispatch_participation(),
                    &mut memory,
                    &reporter,
                    ThreadCtx::new(tid, &registry, &futex),
                );
            }
        }
        rows.push((
            sample,
            4,
            start.elapsed().as_nanos() as f64 / f64::from(count),
        ));
    }
    for (sample, arm, ns) in rows {
        println!(
            "native_checkpoint_cost {}",
            serde_json::json!({
                "arm": names[arm], "sample": sample, "warmup": sample == 0,
                "pair_ns": ns, "iterations": if sample == 0 {128} else {COUNT},
                "runtime_conformance_metrics": cfg!(feature = "conformance-metrics"),
                "workload_timing_eligible": false,
            })
        );
    }
    drop(executor);
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
}

fn dispatch_invalid(
    number: u64,
    dispatcher: &SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
    executor: &mut carrick_kernel::dispatch::MmExecutorParticipation,
    memory: &mut CarrierCopyMemory<'_>,
    reporter: &CompatReporter,
    thread: ThreadCtx<'_>,
) {
    let outcome = dispatcher
        .dispatch_threaded_with_mm_executor(
            executor,
            context,
            SyscallRequest::new(number, SyscallArgs::from([u64::MAX, TEST_VA, 2, 0, 0, 0])),
            memory,
            reporter,
            thread,
        )
        .unwrap();
    assert!(matches!(outcome, DispatchOutcome::Errno { errno } if errno.guest_retval() == -9));
    reporter.record(CompatEvent::SyscallReturn {
        number,
        name: carrick_abi::syscall::lookup_aarch64(number)
            .unwrap()
            .name
            .into(),
        retval: -9,
        errno: Some(9),
    });
}

#[test]
fn native_data_demand_contract() {
    use carrick_conformance_contract::{
        Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
        SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
    };
    use native_syscall_slice::{
        Memory,
        native::{Code, State},
    };
    let (kernel, root) = bootstrap(39_100);
    let tid = ThreadId::synthetic_for_tests(39_101);
    let fixture = real_production_cow_fixture(
        &kernel,
        &root,
        39_101,
        0x9a00_f100_0000,
        0x9b00_f100_0000,
        tid,
    );
    let mut execution = execution_lease(&fixture.child, 39101);
    let authority = carrick_kernel::kernel::MmAccessAuthority::new();
    let current = fixture.child.current_mm(&execution).unwrap();
    let range = current
        .access_token()
        .write_range(GuestVa(TEST_VA), 8)
        .unwrap()
        .unwrap();
    let mut prepared = authority
        .with_current_mutation(&current, tid, |mutation| {
            let mut cow = authority.break_foreign_cow(mutation, &current, range)?;
            Ok(fixture
                .child
                .borrow_current_native_data(&execution, &mut cow)?
                .prepare_for_execution())
        })
        .unwrap();
    drop(current);
    let dispatcher = SyscallDispatcher::with_native_mm_for_test(fixture.dispatch_mm.clone());
    let mut executor = dispatcher
        .admit_native_executor(&fixture.child, &execution)
        .unwrap();
    let (memory, image) =
        Memory::load_elf(&native_carrier_elf(&[0x91000400, 0xd4000001], TEST_VA)).unwrap();
    let code = Code::publish(&image, &memory).unwrap();
    let mut observations = Vec::new();
    for scale in [1, 8, 32, 128] {
        let mut state = State::new(image.entry());
        state.x[17] = 0x1234_5678;
        state.nzcv = 0xa0000000;
        state.vectors = std::array::from_fn(|n| ((n as u128) + 1) << 64);
        let vectors = state.vectors;
        let mut activations = 0;
        for _ in 0..scale {
            state.pc = image.entry();
            let scope = dispatcher
                .enter_native_execution(&mut executor, &fixture.child, &mut execution)
                .unwrap();
            activations += u64::from(
                code.run_scoped_carrier_until_checkpoint(
                    &image,
                    &memory,
                    &mut prepared,
                    &scope,
                    &mut state,
                    false,
                )
                .unwrap(),
            );
            assert_eq!(state.pc, image.entry() + 4);
        }
        assert_eq!(state.x[0], scale);
        assert_eq!(state.x[17], 0x1234_5678);
        assert_eq!(state.nzcv, 0xa0000000);
        assert_eq!(state.vectors, vectors);
        let mut work = WorkSnapshot::new();
        work.insert(WorkMetric::NativeDataActivations, activations)
            .unwrap();
        observations.push(ContractObservation {
            contract_id: ContractId::new("kernel.execution.native-data-demand").unwrap(),
            layer: ExecutionLayer::VmFree,
            implementation_revision: std::env::var("CARRICK_NATIVE_SCOPE_REVISION")
                .unwrap_or_else(|_| "unarchived-working-tree".into()),
            fixture_identity: "unit:native-data-demand".into(),
            scale,
            semantic_assertions: vec![SemanticAssertion::pass(
                "completed_all_intervals_with_registers_flags_vectors_preserved",
            )],
            work: Some(work),
            timing: None,
            completeness: Completeness::Complete,
        });
    }
    // Real native load: data demand must perform exactly one activation.
    let (memory, image) =
        Memory::load_elf(&native_carrier_elf(&[0xf9400020, 0xd4000001], TEST_VA)).unwrap();
    let code = Code::publish(&image, &memory).unwrap();
    let mut state = State::new(image.entry());
    state.x[1] = TEST_VA;
    let scope = dispatcher
        .enter_native_execution(&mut executor, &fixture.child, &mut execution)
        .unwrap();
    assert!(
        code.run_scoped_carrier_until_checkpoint(
            &image,
            &memory,
            &mut prepared,
            &scope,
            &mut state,
            false
        )
        .unwrap()
    );
    assert_eq!(state.x[0] as u32, u32::from_le_bytes(*b"same"));
    drop(scope);
    // Revocation still rejects an interval that may read data, before executing
    // its first instruction. A proven register interval has no such authority.
    fixture
        .dispatch_mm
        .set_foreign_cow_vma_access_for_test(VmaAccess {
            readable: false,
            writable: false,
            executable: false,
            kernel_visible: true,
        });
    let scope = dispatcher
        .enter_native_execution(&mut executor, &fixture.child, &mut execution)
        .unwrap();
    state.pc = image.entry();
    let before = state.x;
    assert!(
        code.run_scoped_carrier_until_checkpoint(
            &image,
            &memory,
            &mut prepared,
            &scope,
            &mut state,
            false
        )
        .is_err()
    );
    assert_eq!(state.x, before);
    let (mut registers, ri) =
        Memory::load_elf(&native_carrier_elf(&[0x91000400, 0xd4000001], TEST_VA)).unwrap();
    let rc = Code::publish(&ri, &registers).unwrap();
    let mut rs = State::new(ri.entry());
    assert!(
        !rc.run_scoped_carrier_until_checkpoint(
            &ri,
            &registers,
            &mut prepared,
            &scope,
            &mut rs,
            false
        )
        .unwrap()
    );
    assert_eq!(rs.x[0], 1);
    rs.pc = ri.entry();
    assert!(
        rc.run_scoped_carrier_until_checkpoint(
            &ri,
            &registers,
            &mut prepared,
            &scope,
            &mut rs,
            true
        )
        .is_err()
    );
    assert!(
        rc.run_scoped_carrier_until_checkpoint(
            &image,
            &memory,
            &mut prepared,
            &scope,
            &mut rs,
            false
        )
        .is_err()
    );
    registers.protect(ri.base(), 6).unwrap();
    assert!(
        rc.run_scoped_carrier_until_checkpoint(
            &ri,
            &registers,
            &mut prepared,
            &scope,
            &mut rs,
            false
        )
        .is_err()
    );
    drop(scope);
    for observation in &mut observations {
        observation
            .semantic_assertions
            .push(SemanticAssertion::pass(
                "native_memory_positive_control_activated_and_read_carrier",
            ));
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = ContractRegistry::load(root).unwrap();
    println!(
        "native_data_demand_observations {}",
        serde_json::to_string(&observations).unwrap()
    );
    if let Ok(path) = std::env::var("CARRICK_NATIVE_DATA_DEMAND_OBSERVATIONS") {
        std::fs::write(path, serde_json::to_vec_pretty(&observations).unwrap()).unwrap();
    }
    evaluate(
        registry
            .require("kernel.execution.native-data-demand")
            .unwrap(),
        &observations,
    )
    .unwrap();
    drop(executor);
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
}

#[test]
fn native_code_density_contract() {
    use carrick_conformance_contract::{
        Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
        SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
    };
    use native_syscall_slice::{
        Memory,
        native::{Code, Layout, State},
    };
    let mut observations = Vec::new();
    for scale in [1u64, 8, 32, 128] {
        let mut words = vec![0x91000400; scale as usize];
        words.push(0xd4000001);
        let (mut memory, image) = Memory::load_elf(&native_carrier_elf(&words, TEST_VA)).unwrap();
        let code = Code::publish_with_layout(&image, &memory, Layout::Compact).unwrap();
        let mut state = State::new(image.entry());
        state.x = std::array::from_fn(|n| n as u64 * 37);
        state.nzcv = 0xa0000000;
        state.vectors = std::array::from_fn(|n| (n as u128 + 1) << 64);
        let original = state.x;
        let vectors = state.vectors;
        let mut checkpoints = 0;
        code.run(&image, &mut memory, &mut state, &mut |_, _| {
            checkpoints += 1;
            Ok(false)
        })
        .unwrap();
        assert_eq!(checkpoints, 1);
        assert_eq!(state.pc, image.base() + scale * 4);
        assert_eq!(state.x[0], scale);
        assert_eq!(state.x[1..], original[1..]);
        assert_eq!(state.nzcv, 0xa0000000);
        assert_eq!(state.vectors, vectors);
        let mut work = WorkSnapshot::new();
        work.insert(WorkMetric::NativeCodeWords, code.emitted_words() as u64)
            .unwrap();
        observations.push(ContractObservation {
            contract_id: ContractId::new("kernel.execution.native-code-density").unwrap(),
            layer: ExecutionLayer::VmFree,
            implementation_revision: std::env::var("CARRICK_NATIVE_SCOPE_REVISION")
                .unwrap_or_else(|_| "unarchived-working-tree".into()),
            fixture_identity: "unit:native-code-density".into(),
            scale,
            semantic_assertions: vec![SemanticAssertion::pass(
                "exact_adds_and_checkpoint_with_complete_state_preserved",
            )],
            work: Some(work),
            timing: None,
            completeness: Completeness::Complete,
        });
    }
    println!(
        "native_code_density_observations {}",
        serde_json::to_string(&observations).unwrap()
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry = ContractRegistry::load(root).unwrap();
    evaluate(
        registry
            .require("kernel.execution.native-code-density")
            .unwrap(),
        &observations,
    )
    .unwrap();
}
