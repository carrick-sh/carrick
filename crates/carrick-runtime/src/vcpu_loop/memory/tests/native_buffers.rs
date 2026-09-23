//! Carrier-backed syscall buffer composition; private ELF bytes are decoys.
use super::*;
use carrick_kernel::{
    compat::{CompatReporter, SyscallArgs},
    dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest, ThreadCtx},
    thread::{FutexTable, ThreadRegistry},
};
use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;
use native_syscall_slice::Memory;

#[test]
fn syscall_copyout_updates_carrier_not_private_elf_data() {
    let (kernel, root) = bootstrap(38_000);
    let root_lease = execution_lease(&root, 38000);
    let tid = ThreadId::synthetic_for_tests(38_001);
    let fixture = real_production_cow_fixture(
        &kernel,
        &root,
        38_001,
        0x9a00_d000_0000,
        0x9b00_d000_0000,
        tid,
    );
    let original = fixture.carrier.pin_original_data_for_test().unwrap();
    let execution = execution_lease(&fixture.child, 38001);
    let dispatcher = SyscallDispatcher::with_native_mm_for_test(fixture.dispatch_mm.clone());
    let mut executor = dispatcher
        .admit_native_executor(&fixture.child, &execution)
        .unwrap();
    // Keep unrelated ELF data as a decoy; only the carrier may receive output.
    let mut elf = native_carrier_elf(&[0xd4000001], TEST_VA);
    // A clock result is sixteen bytes. Keep the same exact guest data address.
    for at in [64 + 56 + 32, 64 + 56 + 40] {
        elf[at..at + 8].copy_from_slice(&16u64.to_le_bytes());
    }
    let (private, _) = Memory::load_elf(&elf).unwrap();
    let registry = ThreadRegistry::new(tid);
    let futex = FutexTable::new();
    let reporter = CompatReporter::default();
    let outcome = dispatcher
        .dispatch_threaded_with_mm_executor(
            executor.dispatch_participation(),
            &fixture.child,
            SyscallRequest::new(113, SyscallArgs::from([1, TEST_VA, 0, 0, 0, 0])),
            &mut native_syscall_slice::carrier_memory::CarrierCopyMemory::new(
                &fixture.child,
                &execution,
            )
            .unwrap(),
            &reporter,
            ThreadCtx::new(tid, &registry, &futex),
        )
        .unwrap();
    assert!(matches!(outcome, DispatchOutcome::Returned { value: 0 }));
    let foreign = foreign_mm(&kernel, &root, &root_lease, fixture.child.task().key());
    let read = foreign.read_range(GuestVa(TEST_VA), 16).unwrap().unwrap();
    let mut actual = [0; 16];
    carrick_kernel::kernel::MmAccessAuthority::new()
        .read_foreign(&foreign, read, &mut actual)
        .unwrap();
    let mut decoy = [0; 16];
    carrick_guest_mem::GuestMemory::read_into(&private, TEST_VA, &mut decoy).unwrap();
    assert_eq!(
        decoy, [0; 16],
        "syscall output escaped into private ELF backing"
    );
    assert_ne!(
        actual[..4],
        *b"same",
        "carrier bytes did not receive clock result"
    );
    assert!(u64::from_le_bytes(actual[..8].try_into().unwrap()) > 0);
    assert!(u64::from_le_bytes(actual[8..].try_into().unwrap()) < 1_000_000_000);
    assert_eq!(original.prefix(), *b"same");
    drop(executor);
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
    root.thread().yield_from_executor(root_lease).unwrap();
}

/// Runs a prebuilt, unchanged Linux ELF. Explicit opt-in keeps cross-compilation
/// and research code publication out of the ordinary VM-free unit-test gate.
#[test]
#[ignore = "requires CARRICK_NATIVE_BUFFER_ELF and a bounded research ELF"]
fn carrier_buffer_elf_control() {
    use carrick_guest_mem::GuestMemory;
    use carrick_kernel::{compat::CompatEvent, kernel::mm_access::MmAccessTarget};
    use carrick_vmm_hvf::trap::foreign_cow_test_support::FixtureShape;
    use native_syscall_slice::{
        Instruction,
        carrier_memory::CarrierCopyMemory,
        classify, emulate,
        native::{Code, State},
    };
    use sha2::{Digest, Sha256};
    let path = std::env::var("CARRICK_NATIVE_BUFFER_ELF").unwrap();
    let elf = std::fs::read(&path).unwrap();
    let (private, image) = Memory::load_elf(&elf).unwrap();
    let (data_va, initial) = private.writable_data().unwrap();
    let data_end = data_va.checked_add(initial.len() as u64).unwrap();
    let granule = carrick_guest_mem::HOST_PAGE_GRANULE;
    let physical_start = data_va & !(granule - 1);
    let physical_end = (data_end + granule - 1) & !(granule - 1);
    let shape = FixtureShape::with_data(
        Gpa(0x9a00_e000_0000),
        Gpa(0x9b00_e000_0000),
        physical_start,
        physical_end - physical_start,
    )
    .unwrap();
    let (kernel, root) = bootstrap(38_100);
    let root_execution = execution_lease(&root, 38100);
    let tid = ThreadId::synthetic_for_tests(38_101);
    let fixture =
        production_cow_fixture_with_shape(&kernel, &root, 38_101, tid, shape, data_va..data_end);
    let original = fixture.carrier.pin_original_data_for_test().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let mut dispatcher = SyscallDispatcher::with_native_mm_for_test(fixture.dispatch_mm.clone());
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::new_in(scratch.path()).unwrap(),
    ));
    dispatcher
        .activate_file_authority(fixture.child.resources().files())
        .unwrap();
    let mut execution = execution_lease(&fixture.child, 38101);
    let mut executor = dispatcher
        .admit_native_executor(&fixture.child, &execution)
        .unwrap();
    fixture
        .child
        .copy_current_from(&execution, GuestVa(data_va), initial)
        .unwrap();
    // The physical compound includes a prefix before ELF data. Its presence in
    // stage-1 does not grant semantic access to the private code publication.
    assert!(
        fixture
            .child
            .copy_current_into(&execution, GuestVa(image.base()), &mut [0; 4])
            .is_err()
    );
    let authority = carrick_kernel::kernel::MmAccessAuthority::new();
    let current = fixture.child.current_mm(&execution).unwrap();
    // An already-private write witness covers one guest page. Wider ELF
    // accesses checkpoint and use the same authenticated copy interface.
    let window_len = (0x1000 - data_va % 0x1000).min(data_end - data_va) as usize;
    let range = current
        .access_token()
        .write_range(GuestVa(data_va), window_len)
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
    let layout = if std::env::var("CARRICK_NATIVE_CODE_LAYOUT").as_deref() == Ok("compact") {
        native_syscall_slice::native::Layout::Compact
    } else {
        native_syscall_slice::native::Layout::Slots
    };
    let code = Code::publish_with_layout(&image, &private, layout).unwrap();
    let mut state = State::new(image.entry());
    let registry = ThreadRegistry::new(tid);
    let futex = FutexTable::new();
    let reporter = CompatReporter::default();
    let mut requests = 0u64;
    let mut completions = 0u64;
    let mut errors = 0u64;
    let mut transitions = 0u64;
    let mut memory_checkpoints = 0u64;
    let mut data_activations = 0u64;
    let force_data = std::env::var("CARRICK_NATIVE_DATA_DEMAND").as_deref() == Ok("0");
    let read_cache =
        std::cell::RefCell::new(carrick_kernel::kernel::mm_access::CurrentReadCache::default());
    let reuse_reads = std::env::var("CARRICK_NATIVE_BUFFER_READ_CACHE").as_deref() != Ok("0");
    let started = Instant::now();
    let exit_code = loop {
        transitions += 1;
        assert!(
            transitions <= 100_000_000 && started.elapsed() < std::time::Duration::from_secs(40),
            "bounded ELF execution"
        );
        let scope = dispatcher
            .enter_native_execution(&mut executor, &fixture.child, &mut execution)
            .unwrap();
        data_activations += u64::from(
            code.run_scoped_carrier_until_checkpoint(
                &image,
                &private,
                &mut prepared,
                &scope,
                &mut state,
                force_data,
            )
            .unwrap(),
        );
        drop(scope);
        if executor.memory_pause_pending() {
            dispatcher
                .service_native_memory_control(&mut executor, &fixture.child, &execution)
                .unwrap();
        }
        assert!(
            !executor.take_stop_request(),
            "unhandled external control request"
        );
        assert!(
            dispatcher
                .take_deliverable_pending_from(&fixture.child, tid)
                .is_none(),
            "unhandled guest signal"
        );
        let index = usize::try_from(state.pc.checked_sub(image.base()).unwrap() / 4).unwrap();
        let word = image.words()[index];
        let mut memory = if reuse_reads {
            CarrierCopyMemory::with_read_cache(&fixture.child, &execution, &read_cache)
        } else {
            CarrierCopyMemory::new(&fixture.child, &execution)
        }
        .unwrap();
        if classify(word).unwrap() != Instruction::Syscall {
            memory_checkpoints += 1;
            emulate(word, &mut state, &mut memory).unwrap();
            continue;
        }
        let number = state.x[8];
        assert!(matches!(
            number,
            26 | 27 | 28 | 29 | 56 | 57 | 63 | 64 | 93 | 113
        ));
        requests += 1;
        let outcome = dispatcher
            .dispatch_threaded_with_mm_executor(
                executor.dispatch_participation(),
                &fixture.child,
                SyscallRequest::new(
                    number,
                    SyscallArgs::from([
                        state.x[0], state.x[1], state.x[2], state.x[3], state.x[4], state.x[5],
                    ]),
                ),
                &mut memory,
                &reporter,
                ThreadCtx::new(tid, &registry, &futex),
            )
            .unwrap();
        let (value, errno) = match outcome {
            DispatchOutcome::Returned { value } => (value, None),
            DispatchOutcome::Errno { errno } => {
                errors += 1;
                (errno.guest_retval(), Some(-errno.guest_retval() as i32))
            }
            DispatchOutcome::Exit { code } => break code,
            other => panic!("unsupported synchronous outcome: {other:?}"),
        };
        completions += 1;
        reporter.record(CompatEvent::SyscallReturn {
            number,
            name: carrick_abi::syscall::lookup_aarch64(number)
                .unwrap()
                .name
                .into(),
            retval: value,
            errno,
        });
        state.x[0] = value as u64;
        state.pc += 4;
    };
    let output = dispatcher.stdout();
    assert_eq!(
        exit_code,
        0,
        "guest rejected semantics at pc={:#x}, output_len={}",
        state.pc,
        output.len()
    );
    assert_eq!(output.len(), 560);
    let mut elapsed_ns = Vec::new();
    for record in output.chunks_exact(56) {
        let words: Vec<u64> = record
            .chunks_exact(8)
            .map(|n| u64::from_le_bytes(n.try_into().unwrap()))
            .collect();
        assert!(words[0] <= 4);
        assert_eq!(
            words[0],
            u64::from_le_bytes(initial[..8].try_into().unwrap())
        );
        assert_eq!(
            words[1],
            u64::from_le_bytes(initial[8..16].try_into().unwrap())
        );
        assert_eq!(
            words[6],
            if words[0] == 2 {
                (words[1] * 16).min(262160)
            } else {
                0
            }
        );
        elapsed_ns
            .push((words[4] * 1_000_000_000 + words[5]) - (words[2] * 1_000_000_000 + words[3]));
    }
    assert_eq!(requests, completions + 1);
    let report = reporter.snapshot();
    assert_eq!(report.summary.syscall_invocations, requests);
    assert_eq!(report.summary.syscall_returns_ok, completions - errors);
    assert_eq!(report.summary.syscall_returns_errno, errors);
    assert_eq!(original.prefix(), *b"same");
    let mut decoy = vec![0; initial.len()];
    private.read_into(data_va, &mut decoy).unwrap();
    assert_eq!(decoy, initial, "ELF private data was mutated");
    let result = serde_json::json!({
        "elf":path,"elf_sha256":format!("{:x}",Sha256::digest(&elf)),
        "phase":u64::from_le_bytes(initial[..8].try_into().unwrap()),
        "scale":u64::from_le_bytes(initial[8..16].try_into().unwrap()),
        "exit":exit_code,"requests":requests,"completions":completions,
        "errno_returns":errors,"transitions":transitions,"memory_checkpoints":memory_checkpoints,
        "elapsed_ns":elapsed_ns,"wall_ms":started.elapsed().as_millis(),
        "read_window_reuse":reuse_reads,
        "data_demand_enabled":!force_data,"data_activations":data_activations,
        "carrier_data_and_buffers":true,"private_data_unchanged":true,"original_cow_unchanged":true,
        "code_layout":format!("{layout:?}"),"emitted_words":code.emitted_words(),
        "private_code_publication":true,"mock_stage2":true,"product_acceptance":false,
    });
    println!("{result}");
    if let Ok(path) = std::env::var("CARRICK_NATIVE_BUFFER_RESULT") {
        std::fs::write(format!("{path}.out"), &output).unwrap();
        std::fs::write(
            format!("{path}.json"),
            serde_json::to_vec_pretty(&result).unwrap(),
        )
        .unwrap();
    }
    drop(executor);
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
    root.thread().yield_from_executor(root_execution).unwrap();
}

#[test]
fn repeated_copyout_crosses_private_guest_pages() {
    let (kernel, root) = bootstrap(38_200);
    let fixture = real_production_cow_fixture(
        &kernel,
        &root,
        38_201,
        0x9a00_f000_0000,
        0x9b00_f000_0000,
        ThreadId::synthetic_for_tests(38_201),
    );
    let original = fixture.carrier.pin_original_data_for_test().unwrap();
    let execution = execution_lease(&fixture.child, 38201);
    let first = [0x52; 8193];
    let second = [0xa7; 8193];
    fixture
        .child
        .copy_current_from(&execution, GuestVa(TEST_VA + 1), &first)
        .unwrap();
    fixture
        .child
        .copy_current_from(&execution, GuestVa(TEST_VA + 1), &second)
        .unwrap();
    let mut actual = [0; 8193];
    fixture
        .child
        .copy_current_into(&execution, GuestVa(TEST_VA + 1), &mut actual)
        .unwrap();
    assert_eq!(actual, second);
    assert_eq!(original.prefix(), *b"same");
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
}

#[test]
fn current_copies_reject_wrong_lease_and_invalid_ranges() {
    use carrick_guest_mem::GuestMemory;
    use native_syscall_slice::carrier_memory::CarrierCopyMemory;
    let (kernel, root) = bootstrap(38_300);
    let wrong = execution_lease(&root, 38300);
    let fixture = real_production_cow_fixture(
        &kernel,
        &root,
        38_301,
        0x9a01_1000_0000,
        0x9b01_1000_0000,
        ThreadId::synthetic_for_tests(38_301),
    );
    let execution = execution_lease(&fixture.child, 38301);
    assert!(CarrierCopyMemory::new(&fixture.child, &wrong).is_err());
    assert!(
        fixture
            .child
            .copy_current_into(&wrong, GuestVa(TEST_VA), &mut [])
            .is_err()
    );
    assert!(
        fixture
            .child
            .copy_current_from(&wrong, GuestVa(TEST_VA), &[])
            .is_err()
    );
    let mut memory = CarrierCopyMemory::new(&fixture.child, &execution).unwrap();
    assert!(memory.read_bytes_raw(u64::MAX, usize::MAX).is_err());
    assert!(memory.write_bytes_raw(TEST_VA - 1, &[1, 2]).is_err());
    assert!(memory.read_into_raw(TEST_VA - 1, &mut [0; 2]).is_err());
    // Whole semantic-range rejection precedes the first output byte.
    assert!(memory.write_bytes_raw(TEST_VA + 16383, &[1, 2]).is_err());
    let mut unchanged = [1];
    memory
        .read_into_raw(TEST_VA + 16383, &mut unchanged)
        .unwrap();
    assert_eq!(unchanged, [0]);
    let mut prefix = [0; 4];
    memory.read_into_raw(TEST_VA, &mut prefix).unwrap();
    assert_eq!(prefix, *b"same");
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
    root.thread().yield_from_executor(wrong).unwrap();
}

#[test]
fn current_copies_honor_vma_read_write_and_executable_permissions() {
    for mode in 0..3 {
        let id = 38_400 + mode;
        let (kernel, root) = bootstrap(id);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            id + 100,
            0x9a01_2000_0000 + mode as u64 * 0x100_0000,
            0x9b01_2000_0000 + mode as u64 * 0x100_0000,
            ThreadId::synthetic_for_tests(id + 100),
        );
        let execution = execution_lease(&fixture.child, id as u64);
        fixture
            .dispatch_mm
            .set_foreign_cow_vma_access_for_test(VmaAccess {
                readable: mode != 0,
                writable: mode == 2,
                executable: mode == 2,
                kernel_visible: true,
            });
        let mut bytes = [0; 4];
        let read = fixture
            .child
            .copy_current_into(&execution, GuestVa(TEST_VA), &mut bytes);
        assert_eq!(read.is_ok(), mode != 0);
        if mode != 0 {
            assert_eq!(bytes, *b"same");
        }
        assert!(
            fixture
                .child
                .copy_current_from(&execution, GuestVa(TEST_VA), b"oops")
                .is_err(),
            "mode {mode} permitted forbidden copy"
        );
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
    }
}

#[test]
fn current_copyout_rechecks_live_leaf_and_protection_tracker() {
    for mode in 0..3 {
        let id = 38_600 + mode;
        let (kernel, root) = bootstrap(id);
        let tid = ThreadId::synthetic_for_tests(id + 100);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            id + 100,
            0x9a01_3000_0000 + mode as u64 * 0x100_0000,
            0x9b01_3000_0000 + mode as u64 * 0x100_0000,
            tid,
        );
        let original = fixture.carrier.pin_original_data_for_test().unwrap();
        let execution = execution_lease(&fixture.child, id as u64);
        fixture
            .child
            .copy_current_from(&execution, GuestVa(TEST_VA), b"live")
            .unwrap();
        let current = fixture.child.current_mm(&execution).unwrap();
        carrick_kernel::kernel::MmAccessAuthority::new()
            .with_current_mutation(&current, tid, |_| {
                fixture
                    .carrier
                    .deny_native_data_for_test(TEST_VA, mode as u8)
                    .unwrap();
                Ok(())
            })
            .unwrap();
        assert!(
            fixture
                .child
                .copy_current_from(&execution, GuestVa(TEST_VA), b"oops")
                .is_err(),
            "mode {mode} permitted forbidden copy"
        );
        assert_eq!(original.prefix(), *b"same");
        drop(current);
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
    }
}

#[test]
fn current_copies_cross_compounds_and_preserve_source() {
    use carrick_vmm_hvf::trap::foreign_cow_test_support::FixtureShape;
    let (kernel, root) = bootstrap(38_800);
    let shape =
        FixtureShape::with_data(Gpa(0x9a01_4000_0000), Gpa(0x9b01_4000_0000), TEST_VA, 32768)
            .unwrap();
    let fixture = production_cow_fixture_with_shape(
        &kernel,
        &root,
        38_801,
        ThreadId::synthetic_for_tests(38_801),
        shape,
        TEST_VA..TEST_VA + 32768,
    );
    let original = fixture.carrier.pin_original_data_for_test().unwrap();
    let execution = execution_lease(&fixture.child, 38801);
    let bytes: Vec<u8> = (0..20001).map(|n| (n % 251) as u8).collect();
    fixture
        .child
        .copy_current_from(&execution, GuestVa(TEST_VA + 17), &bytes)
        .unwrap();
    fixture
        .child
        .copy_current_from(&execution, GuestVa(TEST_VA + 17), &bytes)
        .unwrap();
    let mut actual = vec![0; bytes.len()];
    fixture
        .child
        .copy_current_into(&execution, GuestVa(TEST_VA + 17), &mut actual)
        .unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(original.prefix(), *b"same");
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
}

#[test]
#[cfg(feature = "conformance-metrics")]
fn current_buffer_invalid_fd_cost_contract() {
    use carrick_conformance_contract::{
        Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
        SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
    };
    use native_syscall_slice::carrier_memory::CarrierCopyMemory;
    let (kernel, root) = bootstrap(38_900);
    let tid = ThreadId::synthetic_for_tests(38_901);
    let fixture = real_production_cow_fixture(
        &kernel,
        &root,
        38_901,
        0x9a01_5000_0000,
        0x9b01_5000_0000,
        tid,
    );
    let execution = execution_lease(&fixture.child, 38901);
    let dispatcher = SyscallDispatcher::with_native_mm_for_test(fixture.dispatch_mm.clone());
    let mut executor = dispatcher
        .admit_native_executor(&fixture.child, &execution)
        .unwrap();
    let registry = ThreadRegistry::new(tid);
    let futex = FutexTable::new();
    let reporter = CompatReporter::default();
    activation_allocator::ALLOCATIONS.set(Some(0));
    let allocated = std::hint::black_box(vec![std::hint::black_box(1u8); 64]);
    assert!(activation_allocator::ALLOCATIONS.replace(None).unwrap() > 0);
    drop(allocated);
    let mut observations = Vec::new();
    for scale in [0, 1, 8, 32, 128] {
        let before = reporter.snapshot().summary.syscall_invocations;
        let mut completed = 0;
        let mut dispatched = 0;
        activation_allocator::ALLOCATIONS.set(Some(0));
        for _ in 0..scale.max(1) {
            for number in [27, 28] {
                let mut memory = CarrierCopyMemory::new(&fixture.child, &execution).unwrap();
                dispatched += 1;
                let outcome = dispatcher
                    .dispatch_threaded_with_mm_executor(
                        executor.dispatch_participation(),
                        &fixture.child,
                        SyscallRequest::new(
                            number,
                            SyscallArgs::from([u64::MAX, u64::MAX, 2, 0, 0, 0]),
                        ),
                        &mut memory,
                        &reporter,
                        ThreadCtx::new(tid, &registry, &futex),
                    )
                    .unwrap();
                assert!(
                    matches!(outcome, DispatchOutcome::Errno { errno } if errno == carrick_abi::LINUX_EBADF)
                );
                completed += 1;
            }
        }
        let allocations = activation_allocator::ALLOCATIONS.replace(None).unwrap();
        let requests = reporter.snapshot().summary.syscall_invocations - before;
        if scale == 0 {
            continue;
        }
        let mut work = WorkSnapshot::new();
        work.insert(WorkMetric::HostHeapAllocations, allocations)
            .unwrap();
        work.insert(WorkMetric::KernelDispatches, dispatched)
            .unwrap();
        observations.push(ContractObservation {
            contract_id: ContractId::new("kernel.mm.native-syscall-buffers").unwrap(),
            layer: ExecutionLayer::VmFree,
            implementation_revision: std::env::var("CARRICK_NATIVE_SCOPE_REVISION")
                .unwrap_or_else(|_| "unarchived-working-tree".into()),
            fixture_identity: "unit:native-syscall-buffers".into(),
            scale,
            semantic_assertions: vec![
                SemanticAssertion {
                    name: "exact_requests_and_ebadf_completions".into(),
                    passed: requests == 2 * scale
                        && completed == requests
                        && dispatched == requests,
                    detail: None,
                },
                SemanticAssertion::pass("allocator_positive_control_fired"),
            ],
            work: Some(work),
            timing: None,
            completeness: Completeness::Complete,
        });
    }
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let contracts = ContractRegistry::load(repository).unwrap();
    evaluate(
        contracts
            .require("kernel.mm.native-syscall-buffers")
            .unwrap(),
        &observations,
    )
    .unwrap();
    println!(
        "native_buffer_observations {}",
        serde_json::to_string(&observations).unwrap()
    );
    if let Ok(path) = std::env::var("CARRICK_NATIVE_BUFFER_OBSERVATIONS") {
        std::fs::write(path, serde_json::to_vec_pretty(&observations).unwrap()).unwrap();
    }
    drop(executor);
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
}

#[test]
#[cfg(feature = "conformance-metrics")]
fn current_read_reuse_cost_contract() {
    use carrick_conformance_contract::{
        Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
        SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
    };
    use carrick_kernel::kernel::mm_access::copy_work_for_test;
    use carrick_vmm_hvf::trap::foreign_cow_test_support::FixtureShape;
    let mut observations = Vec::new();
    activation_allocator::ALLOCATIONS.set(Some(0));
    let positive = std::hint::black_box(vec![std::hint::black_box(1u8); 64]);
    assert!(activation_allocator::ALLOCATIONS.replace(None).unwrap() > 0);
    drop(positive);
    for scale in [1u64, 8, 32, 128] {
        let (kernel, root) = bootstrap(39_000);
        let shape = FixtureShape::with_data(
            Gpa(0x9a02_1000_0000),
            Gpa(0x9b02_1000_0000),
            TEST_VA,
            scale * 16384,
        )
        .unwrap();
        let fixture = production_cow_fixture_with_shape(
            &kernel,
            &root,
            39_001,
            ThreadId::synthetic_for_tests(39_001),
            shape,
            TEST_VA..TEST_VA + shape.data_len,
        );
        let execution = execution_lease(&fixture.child, 39001);
        // One independent COW frame per compound; only the first is read in
        // the measured window. Setup never enters a measured window.
        for n in 0..scale {
            fixture
                .child
                .copy_current_from(&execution, GuestVa(TEST_VA + n * 16384), b"data")
                .unwrap_or_else(|e| panic!("setup scale={scale} compound={n}: {e:?}"));
        }
        let mut cache = carrick_kernel::kernel::mm_access::CurrentReadCache::default();
        let mut bytes = [0; 256];
        fixture
            .child
            .copy_current_into_cached(&execution, GuestVa(TEST_VA), &mut bytes, &mut cache)
            .unwrap();
        let snapshots_before = copy_work_for_test::snapshots();
        let pins_before = fixture.carrier.copy_owner_pins_for_test();
        activation_allocator::ALLOCATIONS.set(Some(0));
        for _ in 0..16 {
            fixture
                .child
                .copy_current_into_cached(&execution, GuestVa(TEST_VA), &mut bytes, &mut cache)
                .unwrap();
            assert_eq!(bytes[..4], *b"data");
            assert!(bytes[4..].iter().all(|b| *b == 0));
        }
        let allocations = activation_allocator::ALLOCATIONS.replace(None).unwrap();
        let mut work = WorkSnapshot::new();
        work.insert(WorkMetric::HostHeapAllocations, allocations)
            .unwrap();
        work.insert(
            WorkMetric::MmSnapshotCollections,
            copy_work_for_test::snapshots() - snapshots_before,
        )
        .unwrap();
        work.insert(
            WorkMetric::ForeignOwnerPins,
            fixture.carrier.copy_owner_pins_for_test() - pins_before,
        )
        .unwrap();
        observations.push(ContractObservation {
            contract_id: ContractId::new("kernel.mm.current-read-reuse").unwrap(),
            layer: ExecutionLayer::VmFree,
            implementation_revision: std::env::var("CARRICK_NATIVE_SCOPE_REVISION")
                .unwrap_or_else(|_| "unarchived-working-tree".into()),
            fixture_identity: "unit:current-read-reuse".into(),
            scale,
            semantic_assertions: vec![
                SemanticAssertion::pass("sixteen_exact_live_256_byte_reads"),
                SemanticAssertion::pass("allocator_positive_control_fired"),
            ],
            work: Some(work),
            timing: None,
            completeness: Completeness::Complete,
        });
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
    }
    println!(
        "current_read_reuse_observations {}",
        serde_json::to_string(&observations).unwrap()
    );
    if let Ok(path) = std::env::var("CARRICK_CURRENT_READ_OBSERVATIONS") {
        std::fs::write(path, serde_json::to_vec_pretty(&observations).unwrap()).unwrap();
    }
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let contracts = ContractRegistry::load(repository).unwrap();
    evaluate(
        contracts.require("kernel.mm.current-read-reuse").unwrap(),
        &observations,
    )
    .unwrap();
}

#[test]
fn current_read_window_rechecks_live_carrier_authorities() {
    for mode in [0u8, 1, 2, 3, 4, 5, 7] {
        let id = 39_200 + i32::from(mode);
        let (kernel, root) = bootstrap(id);
        let tid = ThreadId::synthetic_for_tests(id + 100);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            id + 100,
            0x9a03_0000_0000 + u64::from(mode) * 0x100_0000,
            0x9b03_0000_0000 + u64::from(mode) * 0x100_0000,
            tid,
        );
        let execution = execution_lease(&fixture.child, id as u64);
        fixture
            .child
            .copy_current_from(&execution, GuestVa(TEST_VA), b"live")
            .unwrap();
        let window = fixture
            .child
            .prepare_current_read_window(&execution, GuestVa(TEST_VA), 256)
            .unwrap();
        let current = fixture.child.current_mm(&execution).unwrap();
        carrick_kernel::kernel::MmAccessAuthority::new()
            .with_current_mutation(&current, tid, |_| {
                fixture
                    .carrier
                    .deny_native_data_for_test(TEST_VA, mode)
                    .unwrap();
                Ok(())
            })
            .unwrap();
        let mut bytes = [0; 4];
        let result = window.copy_into(&fixture.child, &execution, GuestVa(TEST_VA), &mut bytes);
        // Read-only leaves and write-only denial preserve readable input. A
        // distinct page-table authority with readable leaves is also valid.
        assert_eq!(
            result.is_ok(),
            matches!(mode, 0 | 1 | 4),
            "mode={mode}: {result:?}"
        );
        if result.is_ok() {
            assert_eq!(bytes, *b"live");
        } else {
            assert_eq!(bytes, [0; 4]);
        }
        drop(current);
        fixture
            .child
            .thread()
            .yield_from_executor(execution)
            .unwrap();
    }
}

#[test]
fn current_read_window_observes_changed_bytes_and_rejects_other_ranges_and_leases() {
    let (kernel, root) = bootstrap(39_400);
    let fixture = real_production_cow_fixture(
        &kernel,
        &root,
        39_401,
        0x9a04_0000_0000,
        0x9b04_0000_0000,
        ThreadId::synthetic_for_tests(39_401),
    );
    let execution = execution_lease(&fixture.child, 39401);
    fixture
        .child
        .copy_current_from(&execution, GuestVa(TEST_VA), b"live")
        .unwrap();
    let window = fixture
        .child
        .prepare_current_read_window(&execution, GuestVa(TEST_VA), 256)
        .unwrap();
    fixture
        .child
        .copy_current_from(&execution, GuestVa(TEST_VA), b"next")
        .unwrap();
    let mut bytes = [0; 4];
    window
        .copy_into(&fixture.child, &execution, GuestVa(TEST_VA), &mut bytes)
        .unwrap();
    assert_eq!(bytes, *b"next", "window must never cache bytes");
    for va in [TEST_VA - 1, TEST_VA + 253, u64::MAX - 1] {
        assert!(
            window
                .copy_into(&fixture.child, &execution, GuestVa(va), &mut bytes)
                .is_err()
        );
    }
    let wrong = execution_lease(&root, 39400);
    assert!(
        window
            .copy_into(&root, &wrong, GuestVa(TEST_VA), &mut bytes)
            .is_err()
    );
    assert!(
        window
            .copy_into(&fixture.child, &wrong, GuestVa(TEST_VA), &mut bytes)
            .is_err()
    );
    root.thread().yield_from_executor(wrong).unwrap();
    let executor_id = execution.executor();
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
    let next = fixture.child.thread().claim_runnable(executor_id).unwrap();
    assert!(
        window
            .copy_into(&fixture.child, &next, GuestVa(TEST_VA), &mut bytes)
            .is_err()
    );
    let mut cache = carrick_kernel::kernel::mm_access::CurrentReadCache::default();
    fixture
        .child
        .copy_current_into_cached(&next, GuestVa(TEST_VA), &mut bytes, &mut cache)
        .unwrap();
    assert_eq!(bytes, *b"next");
    fixture.child.thread().yield_from_executor(next).unwrap();
}

#[test]
fn current_read_window_rejects_vma_revocation_and_cow_replacement() {
    let (kernel, root) = bootstrap(39_500);
    let fixture = real_production_cow_fixture(
        &kernel,
        &root,
        39_501,
        0x9a05_0000_0000,
        0x9b05_0000_0000,
        ThreadId::synthetic_for_tests(39_501),
    );
    let execution = execution_lease(&fixture.child, 39501);
    let old = fixture
        .child
        .prepare_current_read_window(&execution, GuestVa(TEST_VA), 256)
        .unwrap();
    fixture
        .child
        .copy_current_from(&execution, GuestVa(TEST_VA), b"cow!")
        .unwrap();
    let mut bytes = [0; 4];
    assert!(
        old.copy_into(&fixture.child, &execution, GuestVa(TEST_VA), &mut bytes)
            .is_err()
    );
    let window = fixture
        .child
        .prepare_current_read_window(&execution, GuestVa(TEST_VA), 256)
        .unwrap();
    let mut cache = carrick_kernel::kernel::mm_access::CurrentReadCache::default();
    fixture
        .child
        .copy_current_into_cached(&execution, GuestVa(TEST_VA), &mut bytes, &mut cache)
        .unwrap();
    assert_eq!(bytes, *b"cow!");
    for readable in [false, true] {
        fixture
            .dispatch_mm
            .set_foreign_cow_vma_access_for_test(VmaAccess {
                readable,
                writable: true,
                executable: false,
                kernel_visible: true,
            });
        assert!(
            window
                .copy_into(&fixture.child, &execution, GuestVa(TEST_VA), &mut bytes)
                .is_err()
        );
        let result = fixture.child.copy_current_into_cached(
            &execution,
            GuestVa(TEST_VA),
            &mut bytes,
            &mut cache,
        );
        assert_eq!(result.is_ok(), readable);
    }
    // A multi-leaf request exercises the original copy fallback unchanged.
    let mut crossing = [0; 4097];
    fixture
        .child
        .copy_current_into_cached(&execution, GuestVa(TEST_VA), &mut crossing, &mut cache)
        .unwrap();
    assert_eq!(&crossing[..4], b"cow!");
    assert!(crossing[4..].iter().all(|b| *b == 0));
    fixture
        .child
        .thread()
        .yield_from_executor(execution)
        .unwrap();
}
