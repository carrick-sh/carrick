# Carrick HVPatch Foreign-MM Structural Backing Retention & Exact Stage-2 Lifecycle Evidence

- **Date:** 2026-08-30
- **Base Integration Commit:** `700dcae52972a1312aab85c947821396c9f7c471` (`sysv: harden lock authority with bounded watchdog regression, fail-closed static API checker, and deterministic SETALL pause`)
- **Worktree:** `/Volumes/CaseSensitive/carrick/.worktrees/agy-rx-retention-foundation-v3`
- **Branch:** `agy/rx-retention-foundation-v3`
- **Target Subsystems:** `carrick-vmm-hvf` (HVPatch Task-Only Spec Conversion, Frame Inventory Synchronization, Foreign-MM Retention, Structural Backing Lifecycle) and `carrick-runtime` (Foreign MM Access Race Outcomes)

---

## 1. Concrete Architecture and Production Repairs

1. **Reverted Production VM Weakening (Concrete Invariants Restored):**
   - Restored concrete `VirtualMachineInstance<GicDisabled>` on `ProcessSpec.vm`, `HvpatchCarrierTaskState::Sibling { vm }`, `HvpatchCarrierTaskState::SharedProcess { vm }`, `HvpatchCarrierTaskState::Process { vm, stage2_leases }`, and `HvpatchCarrierMmAuthority::Live._vm`. Production execution types remain strictly concrete and non-optional.
   - Introduced `ProcessSpecPlan` to decouple spec plan descriptors (`mappings`, `inventory_mappings`, `protections`, `mailbox_slots`, `syscall_transport`, `persistent_vm_lifecycle`, `mm_root_slot`, `container_root`, `frame_inventory`, `cow_armed`, `carrier_foreign_mm_transport`) from VM binding during planning and staging.
   - Extracted shared conversion logic into `HvfVmState::prepare_task_only_plan(plan: ProcessSpecPlan) -> Result<(Vec<GlobalFrameStage2Lease>, HvpatchPreparedTaskAuthority), TrapError>`, utilized by production `HvfVmState::prepare_task_only_process_spec(spec: ProcessSpec)` and test helper `HvfVmState::prepare_task_only_for_test(plan, rollbacks, order)`.

2. **Mandatory Non-Option `GlobalFrameStage2Lease` & Exact Drop Order:**
   - `StructuralBackingOwner` enforces a mandatory `_stage2_lease: GlobalFrameStage2Lease` declared *before* `mapping: OwnedHostMapping`.
   - Struct declaration order enforces that `_stage2_lease` drops and unmaps stage-2 hypervisor mappings *before* `mapping` invokes `munmap`, eliminating any window where unmapped host memory could remain accessible via Stage 2.
   - `StructuralBackingOwner::new` validates that the lease key matches `(physical_ipa, physical_size as u64)`.

3. **Authentic Production Spec Building & Conversion:**
   - The acceptance test enters through `HvfTaskState::build_process_plan` directly with full request parameters (`ProcessForkRequest`), genuine rebased stage-1 `PageTableManager`, declared fork COW ranges, and carrier foreign MM transport.
   - Proves that `prepare_task_only_plan` correctly mints nonzero structural epochs for independent extents (`IndependentPageTables`, `IndependentKernelState`), registers and syncs `StructuralBackingOwner` identities with `HvpatchFrameInventory`, and installs structural owners into `MmAccessState`.

4. **Foreign MM Endpoint & Binding Authentication:**
   - Exercised via `carrick_hal::ForeignMmEndpoint::for_carrier(carrier_foreign_mm_transport)` and `CarrierForeignMmTransport::state_for`.
   - Verified fail-closed rejection of tampered ASIDs (`MissingBinding`), tampered stage-1 roots (`MissingBinding`), and stale/tampered owner generations (`OwnerStale`).
   - Verified successful retention and payload verification through `ForeignMmEndpoint::retain` for authentic snapshots.

5. **Multi-Holder Lifecycle and Deterministic Allocator Reuse:**
   - Fixed-extent structural lifecycle: proven in `production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle` across ancestor, child, and retained foreign backing references.
   - Reusable-extent allocator reuse: proven in `releasable_stage2_lease_lifecycle_and_deterministic_allocator_reuse` with `release_ipa = true`, verifying that the stage-2 IPA remains mapped while holders exist, and on final drop is unmapped and deterministically reallocated by the global frame IPA allocator.

6. **Failure Injection at Composition Boundaries:**
   - Exercised in `foreign_mm_failure_injection_at_composition_boundaries`: verifies reversible rollback of staged inventory reservations on allocation failure, missing binding rejection on unregistered identities, and deadline expiration timeout.

7. **Strict Concurrency Safety in Tests:**
   - Every test under `mod foreign_mm_tests` acquires `let _guard = FOREIGN_MM_TEST_LOCK.lock();` at entry to prevent global frame / alias directory mutation contention during multi-threaded test runs.

---

## 2. Red-First Failure Evidence

1. **Pre-fix Baseline Reproduction:**
   - On base revision `700dcae52972a1312aab85c947821396c9f7c471`, `prepare_task_only_process_spec` stamped `generation = 0` on structural inventory entries.
   - Attempting to retain structural backing returned `Err(ForeignMmTransportError::OwnerStale)`:
     ```
     thread 'trap::foreign_mm_tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle' panicked at:
     retain_physical_backing must succeed for authentic structural extents: OwnerStale
     ```
2. **Missing Lease / Unmapped Lease Rejections:**
   - Registering an unmapped lease or a lease with mismatched dimensions fails closed with `Hypervisor("global frame host owner lease/backing mismatch: ... mapped=false")`.

---

## 3. Green Verification Evidence

### Foreign MM Test Suite (24/24 Passing)

```bash
cargo test -p carrick-vmm-hvf --lib foreign_mm_tests
```

Output:
```
running 24 tests
test trap::foreign_mm_tests::foreign_cow_invalidation_failure_rolls_back_and_republishes_the_old_stage1 ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_semantic_span_end_plus_one ... ok
test trap::foreign_mm_tests::foreign_cow_commit_cannot_be_reported_as_retryable_by_final_snapshot_contention ... ok
test trap::foreign_mm_tests::foreign_cow_failpoint_leaves_lease_at_sn_and_retry_succeeds ... ok
test trap::foreign_mm_tests::foreign_cow_write_keeps_the_shared_parent_owner_unchanged ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_out_of_span_alias ... ok
test trap::foreign_mm_tests::concurrent_foreign_cow_from_same_snapshot_allows_exactly_one_commit ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_in_span_leaf_discontinuity ... ok
test trap::foreign_mm_tests::foreign_cow_one_compound_authorizes_distinct_subrange_writes ... ok
test trap::foreign_mm_tests::foreign_cow_each_reversible_boundary_restores_exact_stage1_inventory_and_owner_set ... ok
test trap::foreign_mm_tests::foreign_mm_failure_injection_at_composition_boundaries ... ok
test trap::foreign_mm_tests::retained_foreign_lease_advances_across_two_compound_cow_commits ... ok
test trap::foreign_mm_tests::foreign_mm_read_rejects_a_missing_descriptor_owner ... ok
test trap::foreign_mm_tests::foreign_mm_read_rejects_reused_owner_generation ... ok
test trap::foreign_mm_tests::foreign_mm_read_retries_each_stale_revision_domain ... ok
test trap::foreign_mm_tests::foreign_mm_read_walks_the_target_root_not_the_caller_root ... ok
test trap::foreign_mm_tests::foreign_mm_retain_deadline_bounds_directory_inventory_and_owner_contention ... ok
test trap::foreign_mm_tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle ... ok
test trap::foreign_mm_tests::releasable_stage2_lease_lifecycle_and_deterministic_allocator_reuse ... ok
test trap::foreign_mm_tests::foreign_mm_read_deadline_bounds_mutation_coordinator_contention ... ok
test trap::foreign_mm_tests::retained_foreign_lease_rejects_unrelated_or_tampered_successor_snapshot ... ok
test trap::foreign_mm_tests::retained_old_token_keeps_physical_backing_after_production_retirement_and_binding_reuse ... ok
test trap::foreign_mm_tests::structural_backing_owner_invalid_arguments_and_exact_drop_order ... ok
test trap::foreign_mm_tests::structural_backing_owner_lifecycle_and_retained_backing ... ok

test result: ok. 24 passed; 0 failed; 0 ignored; 0 measured; 269 filtered out; finished in 1.58s
```

### Full HVF Unit Suite (293/293 Passing)

```bash
cargo test -p carrick-vmm-hvf --lib
```

Output:
```
test result: ok. 293 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.42s
```

### Full Workspace Gate Suites

- `just fmt-check`: Passed (exit code 0).
- `just clippy`: Passed (exit code 0, 0 warnings across all crates).
- `just doc`: Passed (exit code 0, all documentation valid).
- `just test`: Passed (exit code 0, 2160 passed in `carrick-runtime`, 293 in `carrick-vmm-hvf`, 0 failures).
- `just test-integration`: Passed (exit code 0, all integration suites green).
- `python3 scripts/migrate/check-runtime-aborts.py --check`: Passed (exit code 0, all shards valid).
- `python3 scripts/migrate/check-runtime-global-state.py --check`: Passed (exit code 0).
- `python3 scripts/migrate/check-host-authority-transitions.py --static`: Passed (exit code 0).
- `python3 scripts/migrate/check-task-participant-witnesses.py --check`: Passed (exit code 0).
- `python3 scripts/migrate/check-mm-authority.py --check`: Passed (exit code 0).
