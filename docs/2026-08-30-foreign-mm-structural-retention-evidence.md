# Carrick HVPatch Foreign-MM Structural Backing Retention & Exact Stage-2 Lifecycle Evidence

- **Date:** 2026-08-30
- **Base Integration Commit:** `ef8ec9157` (`chore(runtime): reconcile k1 file authority inventory`)
- **Worktree:** `/Volumes/CaseSensitive/carrick/.worktrees/agy-rx-retention-foundation-v3`
- **Branch:** `agy/rx-retention-foundation-v3`
- **Target Subsystems:** `carrick-vmm-hvf` (HVPatch Task-Only Spec Conversion, Frame Inventory Synchronization, Foreign-MM Retention, Structural Backing Lifecycle, Hypervisor Stage-2 Auditing) and `carrick-runtime` (Foreign MM Access Race Outcomes)

---

## 1. Concrete Architecture and Production Repairs

1. **Mandatory Declaration & Drop Order (`_lease` before `_mapping`):**
   - `GlobalFrameHostOwner` declares `_lease: GlobalFrameStage2Lease` *before* `_mapping: OwnedHostMapping`.
   - `StructuralBackingOwner` declares `_stage2_lease: GlobalFrameStage2Lease` *before* `mapping: OwnedHostMapping`.
   - `ProcessMappingDesc` declares `stage2_lease: Option<GlobalFrameStage2Lease>` *before* `host: ProcessMappingHost`.
   - Struct field declaration order in Rust guarantees that the stage-2 hypervisor unmap (`GlobalFrameStage2Lease::drop`) executes *strictly before* host virtual memory deallocation (`OwnedHostMapping::drop` / `munmap`), completely closing any window where unmapped host memory could remain accessible via stage 2.
   - Enforced by both a runtime instrumented test (`global_frame_host_owner_exact_drop_order` verifying host memory is live at stage-2 unmap) and a static source audit test (`all_owner_structs_declare_stage2_lease_before_host_mapping_static_audit`).

2. **Instrumented Stage-2 Backend Audit & Reusable Lifecycle:**
   - Extended `ScopedStage2MapTestStub` with thread-local `Stage2TestAuditState` tracking `mapped_extents: BTreeSet<(u64, usize)>` and recorded `events: Vec<Stage2BackendEvent>`.
   - `inventory_hv_vm_map` and `inventory_hv_vm_unmap` record real stage-2 map and unmap events and maintain mapped extents.
   - `releasable_stage2_lease_lifecycle_and_deterministic_allocator_reuse` exercises the full lifecycle:
     - Mapped in stage-2 before holder retention (`is_mapped == true`, recorded `Map` event).
     - Proves that intermediate reservation attempts fail while intermediate holders exist.
     - Host backing and stage-2 mapping kept live across intermediate holder releases while any holder remains.
     - Unmapped from stage-2 on final drop *before* host mapping deallocation (`drop_backing_audit`).
     - Allocator deterministically reuses the released IPA only after final holder drop.

3. **Production Public Conversion Boundary (`ProcessSpec`):**
   - Eliminated test-only bypass helper `prepare_task_only_for_test` and test-only carrier state bypass.
   - Acceptance test constructs a real `ProcessSpec::new(create_test_vm_instance(), plan)` and calls `HvfVmState::prepare_task_only_process_spec(spec)`.
   - Asserts concrete `HvpatchCarrierTaskState::Process { vm, stage2_leases }` and concrete `VirtualMachineInstance<GicDisabled>` invariants without `Option<VM>` weakening.

4. **Complete Dispositions & Owner Relations Across All 5 Classes:**
   - `production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle` validates all 5 dispositions:
     1. `IndependentPageTables` (`LINUX_PAGE_TABLES_BASE`, child root slot base `0x9a00_0000_0000`) - independent structural owner with non-zero generation matching `pt_epoch.raw()`.
     2. `IndependentKernelState` (EL1 vectors at `LINUX_EL1_VECTORS_BASE` and Mailbox arena at `LINUX_SYSCALL_MAILBOX_BASE`) - planned control dispositions with exact permissions and physical IPAs verified.
     3. Shared Executable / RX segment at `0x0040_0000` (`GlobalShared`, `ReadExec`) - readback matches payload and parent owner generation.
     4. Shared Writable User segment at `0x0060_0000` (`GlobalShared`, `ReadWrite`) - readback matches payload and parent owner generation.
     5. Private COW User segment at `0x0080_0000` (`Private`, `ReadWrite`, in `cow_ranges`) - readback matches payload and parent owner generation.
   - Child snapshot mapping IDs and readback through `RetainedForeignMmBacking` verify structural and user mappings.

5. **Boundary Failure Injection & Rollback:**
   - `foreign_mm_failure_injection_at_composition_boundaries` exercises real composition boundaries:
     1. Reversible stage-2 map failure: `_stage2_stub.set_fail_next_map(true)` through production `ProcessSpec` returns `ChildMapFailed` and rolls back stage-2 mappings, leaving 0 live mappings.
     2. Real inventory staging failure: `plan_stage_fail` populates `inventory_mappings` with `ProcessInventoryDesc` and invokes `Self::stage_mapping`, returning hypervisor error and rolling back to 0 live mappings.
     3. Real directory publication failure: `plan_pub_fail` prepared through `prepare_task_only_process_spec` and failing during `directory.publish_inner(..., failpoint: 1)`, rolling back to 0 published states.
     4. Real retirement/unmap failure semantics: `GlobalFrameHostOwner::try_retire` with `fail_next_unmap` asserting mapped extent preservation, error return, and clean subsequent retry unmap.
     5. Transport lookup failure: missing snapshot returns `MissingBinding`.
     6. Transport retention timeout: expired deadline returns `TimedOut`.

6. **Static Census Audit for Test Locks:**
   - `FOREIGN_MM_TEST_LOCK.lock()` acquired across all 27 tests to isolate global stage-2 allocator and audit state.
   - `all_foreign_mm_tests_acquire_test_lock_census_audit` audits all foreign-MM tests.

---

## 2. Red-First Failure Evidence

### Test Overlay Against Pre-Fix Base `ef8ec9157`

Command:
```bash
cargo test -p carrick-vmm-hvf --lib foreign_mm_tests
```

Failure Receipt under Pre-Fix Base:
```
running 27 tests
test trap::foreign_mm_tests::all_owner_structs_declare_stage2_lease_before_host_mapping_static_audit ... FAILED
test trap::foreign_mm_tests::global_frame_host_owner_exact_drop_order ... FAILED

failures:

---- trap::foreign_mm_tests::all_owner_structs_declare_stage2_lease_before_host_mapping_static_audit stdout ----
thread 'trap::foreign_mm_tests::all_owner_structs_declare_stage2_lease_before_host_mapping_static_audit' panicked at crates/carrick-vmm-hvf/src/trap.rs:2001:9:
GlobalFrameHostOwner must declare _lease before _mapping for safe drop order

---- trap::foreign_mm_tests::global_frame_host_owner_exact_drop_order stdout ----
thread 'trap::foreign_mm_tests::global_frame_host_owner_exact_drop_order' panicked at crates/carrick-vmm-hvf/src/trap.rs:1980:9:
host mapping must be unmapped after stage-2 lease release

failures:
    trap::foreign_mm_tests::all_owner_structs_declare_stage2_lease_before_host_mapping_static_audit
    trap::foreign_mm_tests::global_frame_host_owner_exact_drop_order

test result: FAILED. 25 passed; 2 failed; 0 ignored; 0 measured; finished in 1.58s
```

Duration: 1.58s. Exit code: 101.

---

## 3. Green Verification Evidence

### Foreign MM Test Suite (27/27 Passing)

Command:
```bash
cargo test -p carrick-vmm-hvf --lib foreign_mm_tests
```

Output:
```
running 27 tests
test trap::foreign_mm_tests::foreign_cow_commit_cannot_be_reported_as_retryable_by_final_snapshot_contention ... ok
test trap::foreign_mm_tests::concurrent_foreign_cow_from_same_snapshot_allows_exactly_one_commit ... ok
test trap::foreign_mm_tests::all_owner_structs_declare_stage2_lease_before_host_mapping_static_audit ... ok
test trap::foreign_mm_tests::all_foreign_mm_tests_acquire_test_lock_census_audit ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_in_span_leaf_discontinuity ... ok
test trap::foreign_mm_tests::foreign_cow_each_reversible_boundary_restores_exact_stage1_inventory_and_owner_set ... ok
test trap::foreign_mm_tests::foreign_cow_invalidation_failure_rolls_back_and_republishes_the_old_stage1 ... ok
test trap::foreign_mm_tests::foreign_cow_one_compound_authorizes_distinct_subrange_writes ... ok
test trap::foreign_mm_tests::foreign_cow_failpoint_leaves_lease_at_sn_and_retry_succeeds ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_out_of_span_alias ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_semantic_span_end_plus_one ... ok
test trap::foreign_mm_tests::foreign_cow_write_keeps_the_shared_parent_owner_unchanged ... ok
test trap::foreign_mm_tests::foreign_mm_failure_injection_at_composition_boundaries ... ok
test trap::foreign_mm_tests::foreign_mm_read_deadline_bounds_mutation_coordinator_contention ... ok
test trap::foreign_mm_tests::foreign_mm_read_rejects_a_missing_descriptor_owner ... ok
test trap::foreign_mm_tests::foreign_mm_read_rejects_reused_owner_generation ... ok
test trap::foreign_mm_tests::foreign_mm_read_retries_each_stale_revision_domain ... ok
test trap::foreign_mm_tests::foreign_mm_read_walks_the_target_root_not_the_caller_root ... ok
test trap::foreign_mm_tests::foreign_mm_retain_deadline_bounds_directory_inventory_and_owner_contention ... ok
test trap::foreign_mm_tests::global_frame_host_owner_exact_drop_order ... ok
test trap::foreign_mm_tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle ... ok
test trap::foreign_mm_tests::releasable_stage2_lease_lifecycle_and_deterministic_allocator_reuse ... ok
test trap::foreign_mm_tests::retained_foreign_lease_advances_across_two_compound_cow_commits ... ok
test trap::foreign_mm_tests::retained_foreign_lease_rejects_unrelated_or_tampered_successor_snapshot ... ok
test trap::foreign_mm_tests::retained_old_token_keeps_physical_backing_after_production_retirement_and_binding_reuse ... ok
test trap::foreign_mm_tests::structural_backing_owner_invalid_arguments_and_exact_drop_order ... ok
test trap::foreign_mm_tests::structural_backing_owner_lifecycle_and_retained_backing ... ok

test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 269 filtered out; finished in 1.61s
```

Duration: 1.61s. Exit code: 0.

### Full HVF Unit Suite (296/296 Passing)

Command:
```bash
cargo test -p carrick-vmm-hvf --lib -- --test-threads=1
```

Output:
```
test result: ok. 296 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.29s
```

Duration: 5.29s. Exit code: 0.

### Full Workspace Gate Suites

- `just fmt-check`: Passed (exit code 0).
- `just clippy`: Passed (exit code 0, 0 warnings across all targets).
- `just doc`: Passed (exit code 0).
- `just test`: Passed (exit code 0, 2160 passed in `carrick-runtime`, 296 passed in `carrick-vmm-hvf`, 0 failures).
- `just test-integration`: Passed (exit code 0, all 4 integration suites green).
- `just check-matrix`: Passed (exit code 0).
- `python3 scripts/migrate/check-runtime-global-state.py --check`: Passed (exit code 0).
- `python3 scripts/migrate/check-runtime-aborts.py --check`: Passed (exit code 0).
- `python3 scripts/migrate/check-task-participant-witnesses.py --check`: Passed (exit code 0).
- `python3 scripts/migrate/check-mm-authority.py --check`: Passed (exit code 0).
- `python3 scripts/migrate/check-dispatch-lock-authority.py --check`: Passed (exit code 0).
- `python3 scripts/migrate/check-k1-file-authority-inventory.py`: Passed (exit code 0).
- `python3 scripts/migrate/check-k1-file-authority-taxonomy.py`: Passed (exit code 0).
- `python3 scripts/migrate/check-k1-burndown.py`: Passed (exit code 0).

