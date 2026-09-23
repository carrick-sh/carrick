from pathlib import Path
p=Path('crates/carrick-vmm-hvf/src/trap/foreign_mm.rs'); s=p.read_text()
s=s.replace('pub(crate) struct MmAccessState {','''pub(crate) struct MmAccessState {
    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    native_activation_leaf_checks: std::sync::atomic::AtomicU64,''',1)
s=s.replace('identity: parking_lot::RwLock::new(None),','''#[cfg(any(test, feature = "foreign-cow-test-support"))]
            native_activation_leaf_checks: std::sync::atomic::AtomicU64::new(0),
            identity: parking_lot::RwLock::new(None),''',1)
start=s.index('    fn validate_native_activation('); stop=s.index('    unsafe fn as_mut_ptr',start)
chunk=s[start:stop].replace('while cursor < end {','''while cursor < end {
                    #[cfg(any(test, feature = "foreign-cow-test-support"))]
                    self.state.native_activation_leaf_checks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);''',1)
s=s[:start]+chunk+s[stop:]
pos=s.index('        pub fn deny_native_data_for_test')
s=s[:pos]+'''        /// Counts actual terminal-leaf validations performed during activation.
        pub fn native_activation_leaf_checks_for_test(&self) -> u64 {
            self.state.native_activation_leaf_checks.load(std::sync::atomic::Ordering::Relaxed)
        }

'''+s[pos:];p.write_text(s)
p=Path('crates/carrick-observability/src/work_meter.rs');s=p.read_text().replace('    HostHeapAllocations,','''    HostHeapAllocations,
    /// Terminal leaves validated while activating a retained native data span.
    NativeActivationLeafChecks,''',1).replace('COUNT: usize = 34','COUNT: usize = 35').replace('        Self::HostHeapAllocations,','        Self::HostHeapAllocations,\n        Self::NativeActivationLeafChecks,',1);p.write_text(s)
p=Path('crates/carrick-runtime/Cargo.toml');s=p.read_text().replace('[dev-dependencies]','[dev-dependencies]\ncarrick-conformance-contract = { path = "../carrick-conformance-contract" }',1);p.write_text(s)
p=Path('crates/carrick-runtime/src/vcpu_loop/memory.rs');s=p.read_text();start=s.index('    #[test]\n    fn native_data_activation_outlives');end=s.index('    #[test]\n    fn native_data_activation_rejects',start)
test=s[start:end].replace('    #[test]','    #[cfg(feature = "conformance-metrics")]\n    #[test]',1).replace('fn native_data_activation_outlives_mutation_but_not_execution()', 'fn native_data_activation_cost_contract()')
test=test.replace('32_180','34_180').replace('32_181','34_181').replace('32181','34181').replace('32180','34180').replace('0x9a00_6b00_0000','0x9a00_cb00_0000').replace('0x9b00_6b00_0000','0x9b00_cb00_0000')
test=test.replace('        let mut completed = 0u32;', '''        use carrick_conformance_contract::{Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer, SemanticAssertion, WorkMetric, WorkSnapshot, evaluate};
        // Qualify both instruments outside the measured reuse windows.
        activation_allocator::ALLOCATIONS.set(Some(0));
        let allocation = std::hint::black_box(vec![std::hint::black_box(42u8); 64]);
        assert!(activation_allocator::ALLOCATIONS.replace(None).unwrap() > 0);
        drop(allocation);
        let leaves_before = fixture.carrier.native_activation_leaf_checks_for_test();
        {
            let scope = dispatcher.enter_native_execution(&mut executor, &fixture.child, &mut execution).unwrap();
            let _active = prepared.activate(&scope).unwrap();
        }
        assert!(fixture.carrier.native_activation_leaf_checks_for_test() > leaves_before);
        let mut observations = Vec::new();
        let mut completed = 0u32;''')
test=test.replace('        for scale in [1, 8, 32, 128] {','''        for scale in [1, 8, 32, 128] {
            let before = fixture.carrier.native_activation_leaf_checks_for_test();
            let completed_before = completed;
            activation_allocator::ALLOCATIONS.set(Some(0));''',1)
test=test.replace('                completed += 1;\n            }\n        }','''                completed += 1;
            }
            let allocations = activation_allocator::ALLOCATIONS.replace(None).unwrap();
            let leaves = fixture.carrier.native_activation_leaf_checks_for_test() - before;
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::HostHeapAllocations, allocations).unwrap();
            work.insert(WorkMetric::NativeActivationLeafChecks, leaves).unwrap();
            observations.push(ContractObservation {
                contract_id: ContractId::new("kernel.mm.native-data-activation").unwrap(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: std::env::var("CARRICK_NATIVE_SCOPE_REVISION").unwrap_or_else(|_| "unarchived-working-tree".into()),
                fixture_identity: "unit:native-data-activation".into(), scale: scale as u64,
                semantic_assertions: vec![SemanticAssertion {name: "exact_completed_native_stores".into(), passed: completed - completed_before == scale, detail: None}, SemanticAssertion::pass("allocator_and_leaf_positive_controls_fired")],
                work: Some(work), timing: None, completeness: Completeness::Complete,
            });
        }''',1)
# Evaluate only after exact backing and source-preservation assertions succeed.
test=test.replace('        root.thread().yield_from_executor(root_execution).unwrap();','''        root.thread().yield_from_executor(root_execution).unwrap();
        println!("native_activation_observations {}", serde_json::to_string(&observations).unwrap());
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let registry = ContractRegistry::load(root).unwrap();
        evaluate(registry.require("kernel.mm.native-data-activation").unwrap(), &observations).unwrap();''',1)
allocator='''    #[cfg(feature = "conformance-metrics")]
    mod activation_allocator {
        use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell};
        thread_local! { pub(super) static ALLOCATIONS: Cell<Option<u64>> = const { Cell::new(None) }; }
        struct CountingAllocator;
        #[global_allocator]
        static ALLOCATOR: CountingAllocator = CountingAllocator;
        fn allocated() {
            let _ = ALLOCATIONS.try_with(|count| {
                if let Some(n) = count.get() { count.set(Some(n.checked_add(1).unwrap())); }
            });
        }
        // SAFETY: every allocator argument is forwarded unchanged to System.
        // The const TLS counter allocates nothing and observes only this thread.
        unsafe impl GlobalAlloc for CountingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 { allocated(); unsafe { System.alloc(layout) } }
            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 { allocated(); unsafe { System.alloc_zeroed(layout) } }
            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 { allocated(); unsafe { System.realloc(ptr, layout, size) } }
            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) { unsafe { System.dealloc(ptr, layout) } }
        }
    }

'''
s=s[:end]+allocator+test+s[end:];p.write_text(s)
Path('conformance-contracts/contracts/native-data-activation.toml').write_text('''schema_version = 1
id = "kernel.mm.native-data-activation"
title = "Unchanged native carrier data activation reuses authenticated validation"
guest_surfaces = ["kernel:current-mm", "execution:linux-aarch64", "syscall:mprotect", "syscall:munmap", "syscall:fork"]
semantic_authority = ["Carrick exact-MM execution and COW authority", "man 2 mprotect", "man 2 munmap", "man 2 fork"]
fixture = "unit:native-data-activation"
scale_points = [1, 8, 32, 128]
rationale = "After full validation and before any mutation, repeated native data activation must allocate nothing and walk no leaves. Reuse must revoke after changes in exact stage-1 authority, backend, VMA, inventory, mapping, owner or protection. This host CPU fixture uses production carrier COW and a real scope but executes no guest ELF."

[bindings]
vm_free = "carrick-runtime::vcpu_loop::memory::tests::native_data_activation_cost_contract (conformance-metrics)"

[bindings.unresolved]
embed_structural = "Carrier-backed ELF, control tickets, code publication and revocation are not integrated."
embed_timing = "Host fixture cost is diagnostic only; no native workload acceptance."
docker = "Internal activation invariant. Guest mapping, fork and common-workload differentials remain required."

[[structural_budgets]]
kind = "exact"
metric = "host_heap_allocations"
value = 0
layers = ["vm-free"]
rationale = "Counts real allocator calls on the executing thread, with a positive control."

[[structural_budgets]]
kind = "exact"
metric = "native_activation_leaf_checks"
value = 0
layers = ["vm-free"]
rationale = "Counts actual terminal-leaf validations in production activation. Initial validation must fire the instrument; unchanged re-entry reuses its proof."
''')
