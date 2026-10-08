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
