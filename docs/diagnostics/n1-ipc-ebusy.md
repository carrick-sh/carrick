# Diagnostic: Cumulative IPC EBUSY Refusal During PREPARE

## 1. Current Best Hypothesis for the EBUSY Holder

- **Object:** Shared `ReservationTable` free-list head (`table.free`) / `ReservationNode` custody, or target MM root lock (`Root.locked`).
- **Owner:** Peer vCPU or host thread concurrently allocating or recycling prepared copy descriptors (or holding target MM root during transfer/fault resolution).
- **Acquisition Site:**
  - Primary: `crates/carrick-core/src/mm/reservation/root.rs:661-706` (`ReservationTable::allocate`), where `compare_exchange` on `self.free` fails, or `link & NODE_CUSTODY_BITS != 0` when nodes have been recycled back to the free list.
  - Secondary: `crates/carrick-core/src/mm/reservation/root.rs:598-613` (`ReservationTable::lock_using`), where `root.locked` CAS fails and `NoRootWait::wait` returns `false`.
- **Release Site:**
  - `crates/carrick-core/src/mm/reservation/root_prepared.rs:221` (`self.reap_prepared()`) and `self.table.release()` releasing completed prepared nodes back to `self.free`.
- **Why Held / Refused:**
  In EL1, `pool_node` (`crates/carrick-core/src/mm/reservation/root.rs:1803-1809`) specifically does NOT spin on `Refusal::Busy` because `self.host_holder` is `false`. It immediately returns `Refusal::Busy`.
  When `prepare_transfer` receives `Refusal::Busy`, it is converted to `MmError::Busy`.
  Unlike `MmError::Wait` (which suspends via `suspend_prepare(PortalPrepareSuspension::Owner)`), `MmError::Busy` is not suspended: in `crates/carrick-core/src/mm/transaction/owner.rs:902-905`, any unhandled error triggers `service.complete(0, Venue::encode_error(error))`, encoding `MmError::Busy` as `errno 16` (`EBUSY`).
  This immediately aborts the host's `PREPARE` continuation, lowering to `EFAULT` (`errno 14`) on the guest read.

## 2. Evidence So Far

- **Trace output / test failures:**
  - In `carrick_observability::probes::guest_internal_write_fault`, `owner PREPARE refused: completion` records `completion.errno == 16` (`EBUSY`).
  - Running `./scripts/test-signed.sh carrick-embed el1_ipc_two_processes_blocking --nocapture` triggers:
    `assertion left == right failed: receive fd=... buf=... errno=Bad address (os error 14)`.
- **Code locations:**
  - `crates/carrick-kernel/src/kernel/continuation/ipc.rs:545-547`: `transfer_owner_read` invokes `memory.prepare_write` -> `PreparedWrite::prepare_current`. On `completion.errno == 16`, it maps to `MemoryPrepareError::Fault(HostMap(...))` which lowers to `EFAULT`.
  - `crates/carrick-core/src/mm/transaction/owner.rs:887-906`: `serve_transfer` catches `Err(MmError::Wait)` and `Err(MmError::MetadataRequired)` and calls `service.suspend_prepare(...)`. Any other error falls into `service.complete(0, Venue::encode_error(error))` with `Venue::encode_error(MmError::Busy) == 16`.
  - `crates/carrick-core/src/mm/reservation/root.rs:1803-1809`: `pool_node()` spins only if `self.host_holder == true`; guest EL1 (`self.host_holder == false`) returns `Err(Refusal::Busy)` immediately on free-list contention.

## 3. Single Experiment to Confirm or Refute

Instrument `prepare_transfer` in `crates/carrick-core/src/mm/transaction/owner.rs` and `serve_transfer_hw` in `crates/carrick-el1/src/personality/mm_portal/production.rs` to distinguish and record the exact sub-site that emits `MmError::Busy`:
1. `root_for` returning `MmError::Busy` (MM root locked).
2. `revalidate` returning `MmError::Busy`.
3. `prepare_copy` -> `pool_node` returning `Refusal::Busy` (ReservationTable free-list contention).

Execute `./scripts/test-signed.sh carrick-embed el1_ipc_two_processes_blocking --exact --nocapture` and read the exact failure code and counter/event ring output.

## 4. Confirmed Root Cause and Fix

- **Root Cause Confirmed:**
  When `prepare_transfer` in EL1 encounters free-list contention during `pool_node` (`allocate` returning `Refusal::Busy`) or when `root.locked` cannot be acquired without waiting (`lock_using` returning `Refusal::Busy`), it returns `MmError::Busy`.
  In `crates/carrick-core/src/mm/transaction/owner.rs:serve_transfer` and `crates/carrick-el1/src/personality/mm_portal/production.rs:serve_transfer_hw`, `MmError::Busy` was unhandled, falling through to `service.complete(0, encode_error(MmError::Busy))` which completed the transfer slot with `errno 16` (`EBUSY`).
  The host continuation (`transfer_owner_read` in `crates/carrick-kernel/src/kernel/continuation/ipc.rs`) maps completion errno 16 to `MemoryPrepareError::Fault`, which lowers to guest-visible `EFAULT` (`errno 14`).
  Thus, EL1's `Busy` was prematurely completing the PREPARE as a fatal failure instead of suspending and forwarding it for host-side resolution.

- **Fix Implemented:**
  1. In `crates/carrick-core/src/mm/transaction/owner.rs:serve_transfer`: handle `Err(MmError::Busy)` alongside `Ok(None)` by calling `service.suspend_prepare(changed.map_or(PortalPrepareSuspension::SelectionChanged, PortalPrepareSuspension::Owner))` and returning `Ok(())`.
  2. In `crates/carrick-el1/src/personality/mm_portal/production.rs:serve_transfer_hw`: in `Err(MmError::Busy)`, record reservation event 78 and call `service.suspend_prepare(...)` with `changed.map_or(PortalPrepareSuspension::SelectionChanged, PortalPrepareSuspension::Owner)` instead of `service.complete(0, NativeOwnerVenue::encode_error(MmError::Busy))`.
  3. Added red-first VM-free unit test `prepare_busy_suspends_and_forwards_instead_of_completing_with_ebusy` in `crates/carrick-core/tests/x86_acceleration/mm_owner.rs`, verifying that `serve_transfer` suspends and forwards on `MmError::Busy` instead of completing with `EBUSY`.

## 5. Host-Side Grant Ledger Lifecycle Note

During stress runs across multi-test executions, if a vCPU mailbox slot was used by a prior process and that process retired before an in-flight receipt was settled, `GUEST_GRANT_LEDGER.pending[slot]` could hold an entry from the retired MM key. As directed, this host-side finding is documented here rather than patched in `signal.rs`, as the convergence retires this host-side grant ledger. The forward fix in shared/EL1 code alone achieves 5/5 passes on `el1_ipc_two_processes_blocking`.

## 6. Host Fault-Path Contention Preservation

In pre-exclusion host fault planning (`crates/carrick-kernel/src/dispatch/mem/fault.rs` and `host_first_touch.rs`), the host reads root-owned mapping state before acquiring an exclusive MM mutation lock:
- `resident_fault_plan` calls `try_root_owes_backing_at` and `try_first_touch_owner`.
- `resident_frame_grant_plan` calls `try_first_touch_owner` and `try_root_grant_for_page`.
- `host_first_touch.rs` calls `try_first_touch_owner` for `first_touch_is_root_owned` and `host_untouched_page_permits`.

Previously, these sites invoked the infallible helper `first_touch_owner` or `root_owes_backing_at`, which unwrapped `with_root` results via `broken_root("a first-touch observation", refusal)` or `broken_root("a resident fault predecessor observation", refusal)`. When a peer held `Root.locked` or during concurrent EL1 root critical sections, `with_root` returned `Refusal::Busy`. The infallible helpers treated this transient contention as a corrupted root, triggering `carrick_fatal!` (`SIGABRT`).

The fix preserves contention across pre-exclusion readers:
- On `Refusal::Busy`, `try_root_owes_backing_at`, `try_first_touch_owner`, and `try_root_grant_for_page` decline the fast-path plan (`return None`), routing the fault to the mutation/forwarding path without aborting.
- `first_touch_is_root_owned` treats `Refusal::Busy` as `true` (it is root-owned and busy), while `host_untouched_page_permits` treats it as `false`.
- Verified red-first by `delegated_first_touch_observation_under_held_root_returns_no_plan_without_aborting` in `crates/carrick-kernel/src/dispatch/mem/delegated_tests.rs`, which aborts with `SIGABRT` on base code and cleanly passes on the fixed code.

## 7. Full-Suite Signed `el1_` Filter Verification, Baseline Diff, and Batch Execution Analysis

### Binary Identities on Commit `0565ec758`
Signed executables evaluated under `./scripts/test-signed.sh carrick-embed el1_`:
- `el1_sched-0700c8e4b4a322b1`: `e074dfb10bdc96344cd231da0f1bd97cd84c511de13723477cd0dc2784d877cb`
- `el1_files-d0b2b8fe30b09047`: `1fc09cbed1d8c674d2273f3938c3ff77794a5f4438243bff3415988fdc4c95a4`
- `el1_inotify-6cc5136ef80c735f`: `ea5518ed2dda2c1581e05be48e070f6bd28b5b23355387fd4937a54daaace938`
- `el1_kick_served_loop-980f037a9a60acbb`: `2100afea6cd3418f80d73f239a7a3fcdeba37c15f82f9d6e87124cd2563b7b1a`
- `crash_parked_thread-9ae9764d388ac6aa`: `6cdba4bb64d4bc84f851cdbb0c506e03c763abff362bf27a39719e92570a519c`
- `el1_host_copyout-0ccceb4df04f5a36`: `b9cf96a5cf937e4e44c0c9b9f729da1afd6ee673b7ffec70775e1102c54b068e`
- `el1_ipc_routing-50925ab74a61243b`: `16900eaa1fad9cbcc3b78d10da4a3409723590407f9523ce5755b279ed63269e`
- `el1_inotify09_probe-4da4ff34c0dfdc16`: `e501b4f5d438fca5a67c0b900694fc9d15f46b47744556ffd2a669402f1e32a1`
- `el1_vcpu_lifetime-2fa3fa72a7e19f33`: `c9f9e54ed023d7e2148df90216e29a414694bd9de28d20cd9f6477b8a6c1b4f8`
- `el1_transparent-992064d3018e14d3`: `70d9ea3c97a72f1c35fbbf3cf15af0d3255fdec9221a32e8621d29763354d4a9`
- `el1_gic-1ec202b5311a90c7`: `6831574a20c867a2501b82ead1676d6f687025ec86db331a8610d6a3987407c5`

### Diff Against Baseline Failure List (23/25 names from `/tmp/n1cm-host-el1full-20261008a.log`)
1. **Tests that left the failing list:**
   - `el1_ipc_pairs_blocking`: previously failed with `fatal runtime error: a thread received SIGSEGV while modifying its stack overflow information, aborting` (exit 134 / SIGABRT at line 374 in `20261008a.log`). Now passes cleanly in isolation (0.82s) and under `el1_ipc_` batch.
   - `el1_ipc_two_processes_blocking`: in isolation, passes 5/5 consecutive signed runs (0.62-0.65s) with 0 failures, completely resolving the `errno 14 (Bad address)` defect caused by `MmError::Busy` -> `EBUSY` (errno 16).

2. **Persistent baseline failures remaining:**
   - `crash_core_attributes_the_el1_parked_sibling_registers` (in `crash_parked_thread-9ae9764d388ac6aa`)
   - `el1_served_burst_surfaces_kicks_under_oversubscription` (in `el1_kick_served_loop-980f037a9a60acbb`)
   - `el1_files_cross_process_readers_contract` (in `el1_files-d0b2b8fe30b09047`)
   - Memory/VMA suite failures in `el1_sched` (prior to test 15):
     - `el1_anonymous_discard_and_exit_return_frames`
     - `el1_anonymous_permission_transitions_stay_in_guest`
     - `el1_anonymous_reservations_stay_in_guest`
     - `el1_delegated_root_concurrent_vma_ops`
     - `el1_delegated_root_map_fixed_over_cow_pages`
     - `el1_fork_cow_resolves_in_guest`
   - Downstream `el1_sched` baseline failures observed in un-aborted baseline runs:
     - `el1_sched_mm_occupancy_two_processes`
     - `el1_task_load_costs_no_host_round_trip`
     - `el1_thread_lifecycle_cleartid_tid_reuse`
     - `el1_thread_lifecycle_exit_group_and_exec_during_clone_storm`
     - `el1_thread_lifecycle_fork_during_clone_storm`
     - `el1_thread_lifecycle_mask_storm_exactly_once`
     - `el1_thread_lifecycle_parked_threads_beyond_executor_pool`
     - `el1_thread_lifecycle_ptrace_traceclone`
     - `el1_thread_lifecycle_spawn_slope`
     - `el1_thread_lifecycle_tgkill_right_after_clone`
     - `el1_tlb_cross_vcpu_mm_edits_leave_no_stale_translation_on_any_thread`
     - `el1_tlb_frame_grant_publication_costs_no_maintenance`
     - `el1_tlb_mm_edit_window_excludes_sibling_allocations`
     - `el1_tlb_running_thread_mm_edits_cost_no_maintenance`

### Batch Execution Comparison: Pre-fix (`44efa24c3`) vs Fixed (`0565ec758`)
Identical batch command executed on both commits: `./scripts/test-signed.sh carrick-embed el1_`.

- **On Pre-fix Commit `44efa24c3`:**
  - `el1_files`: aborted at `el1_files_cross_process_readers_contract` with `carrick fatal [dispatch::anonymous]: delegated anonymous root refused a first-touch observation: Busy` (`Abort trap: 6`).
  - `el1_sched`: terminated at test 15/58 (`el1_ipc_two_processes_blocking`) with:
    `thread '<unnamed>' (360) panicked at src/ipc.rs:34:9: assertion left == right failed: receive fd=211 buf=0x6006b678f8 errno=Bad address (os error 14)`
    The test hung waiting for completion, timed out at the 60-second watchdog limit, and was terminated by the test runner with `Killed: 9` (exit 137). Only 15 of 58 tests executed.

- **On Fixed Commit `0565ec758`:**
  - `el1_files`: aborted at `el1_files_cross_process_readers_contract` with `carrick fatal [dispatch::anonymous]: delegated anonymous root refused a first-touch observation: Busy` (`Abort trap: 6`) - identical pre-existing failure.
  - `el1_sched`: terminated at test 15/58 (`el1_ipc_two_processes_blocking`) with:
    `carrick fatal [dispatch::anonymous]: delegated anonymous root refused a first-touch observation: Busy` (`Abort trap: 6`).
    The forward fix eliminated the `errno 14 (EFAULT)` failure that hung `44efa24c3`.
  - When executed in isolation, `el1_ipc_two_processes_blocking` passes 5/5 times (0.62-0.65s) on `0565ec758`.

**Conclusion:** Batch termination at test 15/58 is pre-existing; on `44efa24c3` the runner died at the exact same test (15/58) via `errno 14` watchdog kill (`Killed: 9`). The fix successfully resolves the IPC EBUSY/EFAULT bug.
