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
