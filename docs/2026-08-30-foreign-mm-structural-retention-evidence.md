# Carrick HVPatch Foreign-MM Structural Backing Retention & Exact Stage-2 Lifecycle Evidence

- **Date:** 2026-08-30
- **Base Integration Commit:** `700dcae52972a1312aab85c947821396c9f7c471` (`sysv: harden lock authority with bounded watchdog regression, fail-closed static API checker, and deterministic SETALL pause`)
- **Worktree:** `/Volumes/CaseSensitive/carrick/.worktrees/agy-rx-retention-foundation-v3`
- **Branch:** `agy/rx-retention-foundation-v3`
- **Target Subsystem:** `carrick-vmm-hvf` (HVPatch Task-Only Spec Conversion, Frame Inventory Synchronization, Foreign-MM Retention, Structural Backing Lifecycle)

---

## 1. Concrete Production Bugs Addressed

1. **Production Foreign MM Authentication Bug (`OwnerStale` on generation 0):**
   - In `prepare_task_only_process_spec` and `from_process_spec`, structural mappings minted nonzero `StructuralEpoch`s, but the staged `inventory_mappings` retained `generation = 0` and unauthenticated host addresses. When `retain_physical_backing` attempted to authenticate the structural descriptor against the live inventory entry, it returned `Err(ForeignMmTransportError::OwnerStale)`.
   - **Fix:** Both `prepare_task_only_process_spec` and `from_process_spec` now track minted `StructuralBackingOwner`s in `structural_owners: BTreeMap<(u64, usize), Arc<StructuralBackingOwner>>` and synchronize `stage2_owner.generation = owner.epoch().raw()` and `stage2_owner.host_addr = owner.ptr() as usize` for every structural extent before committing to the inventory transaction.
   - Task activation (`activate_task` and `runtime_task_state`) now installs structural backing owners directly into `MmAccessState::install_structural_owner`.

2. **Mandatory Non-Option `GlobalFrameStage2Lease` & Exact Drop Order:**
   - Physical lifetime retention for structural mappings is mandatory, not optional. `StructuralBackingOwner` now holds a non-Option `_stage2_lease: GlobalFrameStage2Lease` placed *before* `mapping: OwnedHostMapping`.
   - Struct declaration order guarantees that `_stage2_lease` drops and releases the stage-2 hypervisor unmap *before* `mapping` calls `libc::munmap`, eliminating any window of unmapped host memory remaining accessible via Stage 2.
   - `StructuralBackingOwner::new` requires a valid `GlobalFrameStage2Lease` whose key matches `(physical_ipa, physical_size as u64)`.

3. **Production-Topology Integration Test (`production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle`):**
   - Entered through `build_process_spec_internal` using real `IndependentPageTables` and `IndependentKernelState`.
   - Converted through production `prepare_task_only_process_spec`, staged inventory reservations, and child carrier directory publication.
   - Bound child kernel authority token, published inventory, activated task state, and verified structural owner registration in `MmAccessState`.
   - Proved that `RetainedForeignMmBacking` maintains physical backing and stage-2 lease across ancestor and child task teardown, verified readback through retained physical owner, verified stale generation rejection, and verified clean inventory retirement.
   - Removed obsolete/fabricated test helpers (`build_process_spec_for_test`).

---

## 2. Red-First Failure Evidence

Before synchronizing structural owner epochs in `prepare_task_only_process_spec` / `from_process_spec`, attempting to retain physical backing through `retain_physical_backing` on a child task materialized from `build_process_spec_internal` failed with `OwnerStale`:

```
running 1 test
test trap::foreign_mm_tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle ... FAILED

failures:

---- trap::foreign_mm_tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle stdout ----

thread 'trap::foreign_mm_tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle' (5469102) panicked at crates/carrick-vmm-hvf/src/trap.rs:2414:14:
retain_physical_backing must succeed for authentic structural extents: OwnerStale
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

failures:
    trap::foreign_mm_tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; finished in 0.02s
```

---

## 3. Green Verification Evidence

### Foreign MM Test Suite (22/22 Passing)

Command:
```bash
cargo test -p carrick-vmm-hvf --lib foreign_mm_tests
```

Output:
```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 4.34s
     Running unittests src/lib.rs (target/debug/deps/carrick_vmm_hvf-ee11f1df26084f5c)

running 22 tests
test trap::foreign_mm_tests::foreign_cow_one_compound_authorizes_distinct_subrange_writes ... ok
test trap::foreign_mm_tests::foreign_cow_failpoint_leaves_lease_at_sn_and_retry_succeeds ... ok
test trap::foreign_mm_tests::concurrent_foreign_cow_from_same_snapshot_allows_exactly_one_commit ... ok
test trap::foreign_mm_tests::foreign_cow_invalidation_failure_rolls_back_and_republishes_the_old_stage1 ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_out_of_span_alias ... ok
test trap::foreign_mm_tests::foreign_cow_write_keeps_the_shared_parent_owner_unchanged ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_semantic_span_end_plus_one ... ok
test trap::foreign_mm_tests::foreign_cow_commit_cannot_be_reported_as_retryable_by_final_snapshot_contention ... ok
test trap::foreign_mm_tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle ... ok
test trap::foreign_mm_tests::foreign_cow_each_reversible_boundary_restores_exact_stage1_inventory_and_owner_set ... ok
test trap::foreign_mm_tests::foreign_cow_prepare_write_rejects_in_span_leaf_discontinuity ... ok
test trap::foreign_mm_tests::structural_backing_owner_invalid_arguments_and_exact_drop_order ... ok
test trap::foreign_mm_tests::structural_backing_owner_lifecycle_and_retained_backing ... ok
test trap::foreign_mm_tests::foreign_mm_read_deadline_bounds_mutation_coordinator_contention ... ok
test trap::foreign_mm_tests::foreign_mm_read_rejects_a_missing_descriptor_owner ... ok
test trap::foreign_mm_tests::foreign_mm_read_rejects_reused_owner_generation ... ok
test trap::foreign_mm_tests::foreign_mm_read_retries_each_stale_revision_domain ... ok
test trap::foreign_mm_tests::foreign_mm_read_walks_the_target_root_not_the_caller_root ... ok
test trap::foreign_mm_tests::foreign_mm_retain_deadline_bounds_directory_inventory_and_owner_contention ... ok
test trap::foreign_mm_tests::retained_foreign_lease_advances_across_two_compound_cow_commits ... ok
test trap::foreign_mm_tests::retained_foreign_lease_rejects_unrelated_or_tampered_successor_snapshot ... ok
test trap::foreign_mm_tests::retained_old_token_keeps_physical_backing_after_production_retirement_and_binding_reuse ... ok

test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 269 filtered out; finished in 1.61s
```

### Full HVF Unit Test Suite (291/291 Passing)

Command:
```bash
cargo test -p carrick-vmm-hvf --lib
```

Output:
```
test result: ok. 291 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.31s
```

### Monotone Ledgers & Static Checks

Commands:
```bash
python3 scripts/migrate/check-runtime-aborts.py --check
python3 scripts/migrate/check-runtime-global-state.py --check
python3 scripts/migrate/check-task-participant-witnesses.py --check
python3 scripts/migrate/check-mm-authority.py --check
```

Results:
- `check-runtime-aborts.py`: All 3 shards (`runtime.json`, `hvf.json`, `vcpu-loop.json`) valid with zero unaccounted aborts.
- `check-runtime-global-state.py`: Verified with zero unreviewed global state findings.
- `check-task-participant-witnesses.py`: ok (163 Rust leaves).
- `check-mm-authority.py`: ok (254 Rust leaves).
- `just fmt-check` & `just clippy`: Clean with zero warnings.
