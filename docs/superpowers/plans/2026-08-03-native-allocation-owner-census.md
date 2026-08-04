# Native Allocation-Owner Census Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a diagnostic-only, lifecycle-complete tagged system allocator
that attributes cumulative allocation requests across every Darwin/AArch64
native cold-build process image, validates them against NATIVEPERF, and emits a
ranked portfolio of non-overlapping owners whose normal-binary opportunity is at
least 10%.

**Architecture:** A portable wire module in `carrick-dsr-aarch64` owns the
closed owner/reason vocabulary and strict `ALLOCOWNER1` parser. A feature-gated
sibling module owns the `System`-delegating allocator, TLS scopes, relaxed
atomics, fork/exec/exit state machine, and atomic exports; the runtime inserts
only feature-gated lifecycle calls and semantic scopes. Focused CLI modules
parse NATIVEPERF process-image authority, join every allocation fragment by
`(pid, exec_epoch)`, validate lineage and coverage, and calculate the
non-overlapping 10% portfolio without treating feature timing as evidence.

**Tech Stack:** Rust, `std::alloc::GlobalAlloc`, relaxed atomics, const/no-drop
TLS, serde/serde_json, sha2, existing NATIVEPERF v5 frames, Carrick signed-build
and native-fault tooling.

## Global Constraints

- Scope is Darwin/aarch64 native DSR (`--exec-backend native`, the shipped
  default). VMM/HVF/KVM/bhyve/FreeBSD/NetBSD behavior does not change.
- `alloc-owner-census` and DHAT `alloc-census` are mutually exclusive,
  non-default diagnostic features.
- The ordinary allocator and hot path contain no tagged-allocator state check,
  TLS lookup, atomic update, lifecycle call, environment read, or alternate
  product behavior. Instrumentation statements compile out when the feature is
  absent.
- The diagnostic allocator delegates the original `Layout`, pointer, and size
  unchanged to `std::alloc::System`; guest ABI behavior cannot change.
- Allocator callbacks do not allocate, format, lock, read environment
  variables, write files, initialize dropping TLS, or perform lifecycle work.
- Count only successful `alloc`, `alloc_zeroed`, and `realloc` requests.
  Reallocation charges the full new requested size. `dealloc` delegates but
  does not claim live/peak ownership.
- Counters are cumulative requested bytes/calls, never live bytes, retained
  bytes, peak heap, timing, or fault counts. Overflow invalidates a record.
- Fork-child counter/TLS reset is the first statement inside the selected child
  branch, before the child exec stamp and every barrier/dispatcher/translator
  repair.
- Host self-reexec counts capsule serialization and fd preparation, drains only
  at the final pre-`execve` seam, and rearms the same epoch when `execve`
  returns.
- In-process exec advances the owner epoch at the same translator commit that
  advances NATIVEPERF. Existing diagnostic serializers run under a no-drain
  observer pause.
- Core decoding and eager whole-image translation remain deferred. Export-only
  natural captures are the v1 authority; JIT-on-JIT remains in scope for later
  production candidates.
- Feature-binary wall/CPU time is unusable and discarded. Owner shares bind to
  separate ordinary signed-binary NFAULT/CPU evidence from identical source.
- A carried portfolio item is semantic, non-overlapping, correctness-preserving,
  and at least 10% of current normal-binary total CPU in both bindings. Retain
  production changes one at a time by ordinary-binary ABBA, then remeasure and
  rebase remaining items; do not compound projections into a promise.
- Use the exact cold `go build` command and locked persistent store recorded in
  `handoff.md`. Performance knobs are host environment variables. Carrick and
  Docker never run concurrently.
- Power/adapter state is receipt metadata, not a gate. Core class, source,
  binary, image, workload, store, and lifecycle receipts are gates.
- Tier D remains default-off. No task in this plan touches its default.
- Use red-first tests, narrow commits, `apply_patch` for edits, and
  `RUST_TEST_THREADS=1 just ci` before accepting evidence.

## Deferred future improvement: eager translation amortization

Evaluate a separate mode that translates a complete eligible image up front
and amortizes that cost over later execution. This is explicitly deferred until
the current export-only owner portfolio is bound to normal-binary opportunity.
It cannot replace this work: JIT-on-JIT workloads, dynamically generated code,
late-loaded images, exec successors, and invalidation still require correct and
efficient runtime translation.

---

## File map

- Create `crates/carrick-dsr-aarch64/src/alloc_owner_wire.rs`: closed owner and
  flush vocabularies; `ALLOCOWNER1` record, deterministic render, checksum, and
  strict parser. Portable and allocation-observer-free.
- Create `crates/carrick-dsr-aarch64/src/alloc_owner_census.rs`: feature-gated
  tagged allocator, TLS scope, atomics, lifecycle state, export authority, and
  test support.
- Modify the three relevant `Cargo.toml` files and
  `carrick-dsr-aarch64/src/lib.rs`: feature chain and module exposure.
- Modify `crates/carrick-runtime/src/lib.rs`: typed wire re-export and
  feature-gated allocator/lifecycle facade.
- Modify `crates/carrick-cli/src/main.rs`: diagnostic global allocator,
  mutual-exclusion/target guards, main-entry arm, and atexit registration.
- Modify `crates/carrick-runtime/src/native_darwin.rs`: fork-first reset,
  process-exit drain, and observer pauses at the existing exec exporters.
- Modify `crates/carrick-runtime/src/native_exec_capsule.rs`: feature-only next
  epoch transport and final pre-`execve` attempt guard.
- Modify `crates/carrick-dsr-aarch64/src/translator.rs`: in-process epoch
  transition, publication/shared-support tags, and exact lifecycle tests.
- Modify `crates/carrick-dsr-aarch64/src/{block,emit,gateway,shared_cache}.rs`:
  semantic owner scopes at the source-authoritative allocation boundaries.
- Create `crates/carrick-cli/src/native_perf_epochs.rs`: strict subset parser
  for complete NATIVEPERF core/resolver-process/supervisor authority.
- Create `crates/carrick-cli/src/debug_alloc_owner.rs`: file discovery,
  fragment/epoch join, coverage checks, opportunity calculation, and versioned
  JSON report.
- Modify `crates/carrick-cli/src/{args,commands,debug,main}.rs`: portable
  `carrick debug alloc-owner-census` surface.
- Create `docs/perf-results/2026-08-03-native-allocation-owner-census.md` and
  modify `docs/perf-results/native-dsr-shape-census.jsonl`, `handoff.md`, and
  this plan with final receipts and the ranked carry/stop portfolio.

---

### Task 1: Define the closed ALLOCOWNER1 wire authority

**Files:**
- Create: `crates/carrick-dsr-aarch64/src/alloc_owner_wire.rs`
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`

**Interfaces:**
- Produces:
  `AllocationOwner::{ALL,COUNT,token,from_token}`,
  `AllocationFlushReason::{token,from_token}`,
  `OwnerSnapshot`, and
  `AllocationOwnerCensusFile::{render,parse,total_bytes,total_calls}`.
- Wire identity is exactly `(pid: i32, exec_epoch: u64,
  fragment_sequence: u64)`.
- Every file contains exactly eight owner rows in enum order and a SHA-256
  footer over every preceding byte.

- [x] **Step 1: Add the red vocabulary round-trip test**

Create the module and add this literal test before defining the types:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_tokens_are_closed_and_stable() {
        let expected = [
            "other",
            "publication-map",
            "publication-recovery",
            "block-assembler-transient",
            "decode-read-buffers",
            "indirect-target-cache",
            "shared-translation-support",
            "publication-indexes",
        ];
        assert_eq!(AllocationOwner::COUNT, expected.len());
        for (owner, token) in AllocationOwner::ALL.into_iter().zip(expected) {
            assert_eq!(owner.token(), token);
            assert_eq!(AllocationOwner::from_token(token), Some(owner));
        }
        assert_eq!(AllocationOwner::from_token("future-owner"), None);
    }
}
```

- [x] **Step 2: Run the test and prove red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 alloc_owner_wire::tests::owner_tokens_are_closed_and_stable -- --exact --nocapture
```

Expected: compile failure because `AllocationOwner` is not defined.

- [x] **Step 3: Add the exact typed vocabulary**

Implement these public types and exhaustive token matches:

```rust
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub enum AllocationOwner {
    Other = 0,
    PublicationMap = 1,
    PublicationRecovery = 2,
    BlockAssemblerTransient = 3,
    DecodeReadBuffers = 4,
    IndirectTargetCache = 5,
    SharedTranslationSupport = 6,
    PublicationIndexes = 7,
}

impl AllocationOwner {
    pub const ALL: [Self; 8] = [
        Self::Other,
        Self::PublicationMap,
        Self::PublicationRecovery,
        Self::BlockAssemblerTransient,
        Self::DecodeReadBuffers,
        Self::IndirectTargetCache,
        Self::SharedTranslationSupport,
        Self::PublicationIndexes,
    ];
    pub const COUNT: usize = Self::ALL.len();
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AllocationFlushReason {
    HostSelfReexecAttempt,
    InProcessExec,
    ProcessExit,
    AtexitBackstop,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnerSnapshot {
    pub requested_bytes: u64,
    pub alloc_calls: u64,
    pub zeroed_calls: u64,
    pub realloc_calls: u64,
}
```

The token matches must use exactly the strings from the design; no fallback
variant is permitted.

- [x] **Step 4: Add red deterministic-record and rejection tests**

Construct one `AllocationOwnerCensusFile` with literal owner counts and assert:

```rust
#[test]
fn record_round_trip_is_deterministic_and_checked() {
    let mut owners = [OwnerSnapshot::default(); AllocationOwner::COUNT];
    owners[AllocationOwner::PublicationMap as usize] = OwnerSnapshot {
        requested_bytes: 4096,
        alloc_calls: 2,
        zeroed_calls: 1,
        realloc_calls: 3,
    };
    let file = AllocationOwnerCensusFile {
        pid: 42,
        exec_epoch: 3,
        fragment_sequence: 1,
        reason: AllocationFlushReason::ProcessExit,
        overflow: false,
        lifecycle_error: false,
        owners,
    };
    let first = file.render().expect("render fixture");
    let second = file.render().expect("render fixture twice");
    assert_eq!(first, second);
    assert_eq!(AllocationOwnerCensusFile::parse(&first).unwrap(), file);
    assert_eq!(file.total_bytes().unwrap(), 4096);
    assert_eq!(file.total_calls().unwrap(), 6);
}
```

Add one table-driven rejection test that mutates a valid record and requires an
error for: unknown header field, unknown owner, duplicate owner, missing owner,
reordered owner, mismatched total, changed payload with stale checksum,
truncated footer, `overflow=1`, and `lifecycle_error=1`.

- [x] **Step 5: Run the record tests and prove red**

Run:

```bash
cargo test -p carrick-dsr-aarch64 alloc_owner_wire::tests -- --nocapture
```

Expected: compile failure because `AllocationOwnerCensusFile` is absent.

- [x] **Step 6: Implement deterministic render and strict parse**

Use this exact line grammar:

```text
ALLOCOWNER1|pid=<i32>|exec_epoch=<u64>|fragment=<u64>|reason=<token>|armed_at=main-entry|overflow=<0|1>|lifecycle_error=<0|1>
OWNER|name=<token>|bytes=<u64>|alloc=<u64>|zeroed=<u64>|realloc=<u64>
TOTAL|bytes=<u64>|calls=<u64>
END|sha256=<64 lowercase hex characters>
```

The parser must split every line into an exact field count and exact key order,
require one row for every `AllocationOwner::ALL` item in order, use checked sums,
and compare the footer to `Sha256::digest` of all bytes through the `TOTAL`
newline. `overflow=1` and `lifecycle_error=1` parse as typed fields but return a
validation error from `parse`, so no caller can accidentally aggregate them.

- [x] **Step 7: Expose the single Rust authority and run green**

Add:

```rust
pub mod alloc_owner_wire;
```

to `carrick-dsr-aarch64/src/lib.rs`, and:

```rust
pub use carrick_dsr_aarch64::alloc_owner_wire;
```

beside the existing `xlat_census` re-export in `carrick-runtime/src/lib.rs`.
Then run:

```bash
cargo test -p carrick-dsr-aarch64 alloc_owner_wire::tests -- --nocapture
cargo clippy -p carrick-dsr-aarch64 -p carrick-runtime --all-targets -- -D warnings
```

Expected: all tests pass and clippy is clean.

- [x] **Step 8: Commit the wire authority**

```bash
git add crates/carrick-dsr-aarch64/src/alloc_owner_wire.rs crates/carrick-dsr-aarch64/src/lib.rs crates/carrick-runtime/src/lib.rs
git commit -m "diagnostics(native): define allocation owner wire"
```

---

### Task 2: Implement the tagged System allocator and lifecycle core

**Files:**
- Create: `crates/carrick-dsr-aarch64/src/alloc_owner_census.rs`
- Modify: `crates/carrick-dsr-aarch64/Cargo.toml`
- Modify: `crates/carrick-dsr-aarch64/src/lib.rs`
- Modify: `crates/carrick-runtime/Cargo.toml`
- Modify: `crates/carrick-runtime/src/lib.rs`
- Modify: `crates/carrick-cli/Cargo.toml`

**Interfaces:**
- Produces `TaggedSystem`, `scope(AllocationOwner) -> OwnerScope`,
  `init_main_from_environment() -> Result<bool, CensusError>`,
  `register_atexit_backstop()`, `reset_after_fork_child_first_action()`,
  `observer_pause() -> ObserverPause`,
  `drain_terminal(AllocationFlushReason)`,
  `begin_host_exec_attempt(u64) -> HostExecAttempt`, and
  `begin_in_process_exec(u64) -> InProcessExecTransition`.
- `HostExecAttempt::drop` resets and rearms the same epoch only when host
  `execve` returns.
- `InProcessExecTransition::rearm_successor()` resets and arms the supplied next
  epoch.
- The internal operation vocabulary is closed and literal:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllocationOperation {
    Alloc,
    AllocZeroed,
    Realloc,
}
```

`CensusError` is the single typed error for invalid configuration, lifecycle
transition, checked identity overflow, collision, partial write, sync, and
rename failure. `OwnerScope`, `ObserverPause`, `HostExecAttempt`, and
`InProcessExecTransition` are no-drop-state stack guards: their `Drop`
implementations restore only already-initialized atomic/TLS state and never
allocate.

- [x] **Step 1: Wire the non-default feature chain**

Add exact features:

```toml
# carrick-dsr-aarch64/Cargo.toml
alloc-owner-census = []

# carrick-runtime/Cargo.toml
alloc-owner-census = ["carrick-dsr-aarch64/alloc-owner-census"]

# carrick-cli/Cargo.toml
alloc-owner-census = ["carrick-runtime/alloc-owner-census"]
```

Declare and re-export the feature module only under
`cfg(feature = "alloc-owner-census")` in the DSR crate and runtime facade.

- [x] **Step 2: Add red scope and accounting tests**

Inside the new module, serialize stateful tests with a test-only static mutex.
Add literal tests for nested restoration and operation semantics:

```rust
#[test]
fn nested_scope_restores_the_prior_owner() {
    let _test = test_lock();
    reset_for_test();
    set_armed_for_test(7);
    assert_eq!(current_owner_for_test(), AllocationOwner::Other);
    {
        let _outer = scope(AllocationOwner::DecodeReadBuffers);
        assert_eq!(current_owner_for_test(), AllocationOwner::DecodeReadBuffers);
        {
            let _inner = scope(AllocationOwner::PublicationMap);
            assert_eq!(current_owner_for_test(), AllocationOwner::PublicationMap);
        }
        assert_eq!(current_owner_for_test(), AllocationOwner::DecodeReadBuffers);
    }
    assert_eq!(current_owner_for_test(), AllocationOwner::Other);
}

#[test]
fn realloc_charges_the_full_new_request() {
    let _test = test_lock();
    reset_for_test();
    set_armed_for_test(0);
    record_success_for_test(AllocationOperation::Realloc, 8192);
    let row = snapshot_for_test()[AllocationOwner::Other as usize];
    assert_eq!(row.requested_bytes, 8192);
    assert_eq!(row.realloc_calls, 1);
    assert_eq!(row.alloc_calls, 0);
}
```

Also test that a null result records zero, `alloc_zeroed` increments only
`zeroed_calls`, `dealloc` records zero, nested scope restores during unwind, and
overflow sets the invalid bit instead of remaining apparently valid. Add a
two-thread barrier fixture whose threads hold distinct owner scopes and perform
known successful allocations; after both join, assert the process-global rows
contain the exact per-owner deltas and neither thread inherited the other's TLS
owner. Use a test-only delegating allocator hook or operation recorder to prove
the success/null/dealloc cases without relying on an allocator failure that the
host may not reproduce naturally.

- [x] **Step 3: Run the core tests and prove red**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-dsr-aarch64 --features alloc-owner-census alloc_owner_census::tests -- --nocapture
```

Expected: compile failure because the allocator and lifecycle state are absent.

- [x] **Step 4: Implement the const TLS and relaxed counters**

Use one fixed counter array and a no-drop TLS cell:

```rust
thread_local! {
    static CURRENT_OWNER: std::cell::Cell<AllocationOwner> =
        const { std::cell::Cell::new(AllocationOwner::Other) };
}

struct OwnerCounters {
    requested_bytes: std::sync::atomic::AtomicU64,
    alloc_calls: std::sync::atomic::AtomicU64,
    zeroed_calls: std::sync::atomic::AtomicU64,
    realloc_calls: std::sync::atomic::AtomicU64,
}

static COUNTERS: [OwnerCounters; AllocationOwner::COUNT] =
    [const { OwnerCounters::new() }; AllocationOwner::COUNT];
static OVERFLOW: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
```

`OwnerScope` stores the prior enum and restores it in `Drop`. Every counter add
uses `fetch_add(Ordering::Relaxed)` and sets `OVERFLOW` when
`old.checked_add(delta).is_none()`.

- [x] **Step 5: Implement all four GlobalAlloc operations**

Use the original request unchanged and account only after a non-null result:

```rust
pub struct TaggedSystem;

unsafe impl std::alloc::GlobalAlloc for TaggedSystem {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let ptr = unsafe { std::alloc::System.alloc(layout) };
        record_non_null(ptr, AllocationOperation::Alloc, layout.size());
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        let ptr = unsafe { std::alloc::System.alloc_zeroed(layout) };
        record_non_null(ptr, AllocationOperation::AllocZeroed, layout.size());
        ptr
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: std::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        let next = unsafe { std::alloc::System.realloc(ptr, layout, new_size) };
        record_non_null(next, AllocationOperation::Realloc, new_size);
        next
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) };
    }
}
```

Import `GlobalAlloc as _` so method resolution is explicit. `record_non_null`
must do nothing unless state is exactly `Armed`.

- [x] **Step 6: Add red lifecycle transition tests**

Test this complete matrix under the state lock:

- disabled observer pause is a no-op;
- `Armed -> ObserverPaused -> Armed` preserves counters and epoch;
- terminal drain makes atexit idempotent;
- host-exec attempt leaves the state unarmed until guard drop, then resets and
  rearms the same epoch with `fragment + 1`;
- forgetting the host-attempt guard (simulated with `mem::forget`) leaves the
  old image terminal;
- in-process transition remains unarmed until `rearm_successor`, then resets
  counters and uses `next_epoch, fragment 0`;
- attempted epoch/fragment overflow marks lifecycle invalid;
- `reset_after_fork_child_first_action` clears counters/TLS/overflow and arms
  epoch 0, fragment 0 without touching the output path;
- a forced filename collision is reported, does not overwrite the existing
  file, and leaves no apparently valid replacement;
- an injected short write/sync/rename failure is reported and leaves a
  discoverable `.tmp` truncation marker for the strict aggregator; and
- the exported record excludes every allocation performed by its own
  snapshot/render/path/write machinery.

- [x] **Step 7: Implement lifecycle state and atomic export**

Represent state with an `AtomicU8` closed over
`Disabled`, `Armed`, `ObserverPaused`, `Transition`, and `Terminal`. Store the
immutable output directory in `OnceLock<PathBuf>`, the current epoch and
fragment in atomics, and transition failures in `LIFECYCLE_ERROR`.

`drain` must:

1. atomically leave `Armed`;
2. snapshot the fixed counter array;
3. construct `AllocationOwnerCensusFile` while counting is off;
4. write `alloc-owner-<pid>-<monotonic>-<epoch>-<fragment>.txt.tmp` with
   `OpenOptions::create_new(true)`;
5. `write_all`, `sync_all`, and rename to `.txt` without overwriting; and
6. leave the caller-selected transition state even when export returns an
   error.

`init_main_from_environment` reads only
`CARRICK_ALLOC_OWNER_CENSUS_DIR` and the internal
`CARRICK_ALLOC_OWNER_EXEC_EPOCH`, defaults the initial epoch to 0, performs all
path/string setup while disabled, then arms. A malformed internal epoch is an
error. Environment access never occurs in `GlobalAlloc`.

- [x] **Step 8: Run the focused feature gates**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-dsr-aarch64 --features alloc-owner-census alloc_owner_census::tests -- --nocapture
cargo clippy -p carrick-dsr-aarch64 -p carrick-runtime --all-targets --features alloc-owner-census -- -D warnings
```

Expected: lifecycle, overflow, allocator, and export tests pass.

- [x] **Step 9: Commit the allocator core**

```bash
git add crates/carrick-dsr-aarch64/Cargo.toml crates/carrick-dsr-aarch64/src/lib.rs crates/carrick-dsr-aarch64/src/alloc_owner_census.rs crates/carrick-runtime/Cargo.toml crates/carrick-runtime/src/lib.rs crates/carrick-cli/Cargo.toml
git commit -m "diagnostics(native): add tagged allocation census"
```

---

### Task 3: Integrate fork, exec, exit, and main-entry authority

**Files:**
- Modify: `crates/carrick-cli/src/main.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Modify: `crates/carrick-runtime/src/native_exec_capsule.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`

**Interfaces:**
- Consumes every Task 2 lifecycle API.
- Produces one or more contiguous allocation fragments for every NATIVEPERF
  `(pid, exec_epoch)` and excludes allocations made by existing diagnostic
  serializers.

- [x] **Step 1: Add red feature-guard and main-entry tests**

Add compile guards in `main.rs` tests/fixture coverage and assert:

```rust
#[cfg(all(feature = "alloc-census", feature = "alloc-owner-census"))]
compile_error!("alloc-census and alloc-owner-census install competing global allocators");

#[cfg(all(
    feature = "alloc-owner-census",
    not(all(target_os = "macos", target_arch = "aarch64"))
))]
compile_error!("alloc-owner-census is supported only on macOS/aarch64 native DSR");
```

Add a unit-testable `start_alloc_owner_census()` wrapper and require that it is
called immediately after `ExecStampPhase::MainEntry`, before
`record_top_level_pid`, environment configuration, probe registration, or CLI
parse. Add a source-order assertion next to the existing main-entry contract.

- [x] **Step 2: Add red fork-child ordering test**

Extend the existing native fork child event vocabulary with
`AllocationOwnerReset` and assert the first child-only event is exactly:

```rust
assert_eq!(
    events.first(),
    Some(&NativeForkChildResumeEvent::AllocationOwnerReset)
);
```

The source mutation caught is placing the reset in
`ThreadTranslator::after_fork_child`, after stamps/barrier/dispatcher work has
already allocated. In the same fork fixture, seed the parent with a known
`PublicationMap` delta before `fork`, let the child execute the reset hook, and
assert through the existing parent/child result channel that the parent retains
its exact epoch, fragment, and counter delta while the child starts at epoch 0,
fragment 0 with zero inherited counts.

- [x] **Step 3: Add red host-exec and in-process transition tests**

In `native_exec_capsule.rs`, extend the injectable `exec_capsule_with` tests to
assert:

- capsule payload, argv, environment, and fd preparation allocations happen
  before `HostSelfReexecAttempt` drain;
- the internal epoch environment entry appears exactly once and replaces an
  inherited prior value;
- the attempt guard rearms the same epoch when injected `invoke_exec` returns;
- success simulation by forgetting the guard does not rearm.

In `translator.rs`, use `PreparedThreadExecHandoff::commit_with_sink` to assert
the allocation transition is unarmed while the NATIVEPERF sink formats frames,
then armed at `exec_epoch + 1` after commit.

Add an atexit-backstop unit fixture that invokes the registered callback
directly: an armed process exports exactly one `atexit-backstop` record, while a
prior terminal runtime drain makes the callback a no-op. Add an observer-pause
fixture that performs known allocations inside and after the pause and proves
only the post-pause production allocation reaches the outgoing record.

- [x] **Step 4: Run lifecycle tests and prove red**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --features alloc-owner-census native_fork_child -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --features alloc-owner-census native_exec_capsule -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-dsr-aarch64 --features alloc-owner-census exec_handoff -- --nocapture
```

Expected: failures because the lifecycle calls and ordering events are absent.

- [x] **Step 5: Install the CLI allocator and atexit backstop**

Add:

```rust
#[cfg(feature = "alloc-owner-census")]
#[global_allocator]
static ALLOC_OWNER_CENSUS: carrick_runtime::alloc_owner_census::TaggedSystem =
    carrick_runtime::alloc_owner_census::TaggedSystem;
```

`start_alloc_owner_census()` calls `init_main_from_environment`; when it returns
`true`, register the module's atexit backstop. Invalid requested configuration
returns an `anyhow::Error` and fails the diagnostic invocation before product
dispatch.

- [x] **Step 6: Install the fork-first and process-exit boundaries**

In the `if child == 0` arm immediately after `libc::fork`, make the first
statement:

```rust
#[cfg(feature = "alloc-owner-census")]
{
    carrick_dsr_aarch64::alloc_owner_census::reset_after_fork_child_first_action();
    #[cfg(test)]
    record_native_fork_child_resume_event(
        NativeForkChildResumeEvent::AllocationOwnerReset,
    );
}
```

In `finalize_native_process_exit`, preserve production publication first, then
drain allocation ownership before `maybe_dump_code_snapshot`, NATIVEPERF
finalization, and xlat-census flush. Log export errors with `tracing::warn!` and
continue the existing exit path.

- [x] **Step 7: Exclude existing diagnostic serializers without draining**

At host self-reexec, wrap `translator.finalize_profile_epoch()` and
`xlat_census::flush(HostSelfReexec)` in one `observer_pause()` guard, drop it,
then enter `begin_guest_exec` with the original owner counters intact.

At in-process exec, wrap only the existing early
`xlat_census::flush(InProcessExec)` call in an observer-pause guard. Image
replacement, dispatcher reset, and translator preparation remain armed under
the outgoing epoch.

- [x] **Step 8: Move host-exec allocation drain to the real pre-exec seam**

In `exec_capsule_with`, read `guest.profile_exec_epoch` as the next owner epoch.
Filter any inherited `CARRICK_ALLOC_OWNER_EXEC_EPOCH` from the regular host
environment. Build the ordinary environment and pointer vectors while armed;
under a short observer pause, create the replacement internal entry and reserve
and append its one pointer so observer transport does not inflate `other`.

After `HostSelfReexecBegin` and `ExecStampPhase::PreExec`, create:

```rust
#[cfg(feature = "alloc-owner-census")]
let _allocation_attempt =
    carrick_dsr_aarch64::alloc_owner_census::begin_host_exec_attempt(next_exec_epoch);
```

Keep the guard live across `invoke_exec`. Its destructor is the only failed
host-exec rearm path.

- [x] **Step 9: Align in-process owner and NATIVEPERF epochs**

Inside `PreparedThreadExecHandoff::commit_with_sink`:

1. compute the same checked next epoch NATIVEPERF will install;
2. call `begin_in_process_exec(next_exec_epoch)` before
   `thread.take_profile_frames()`;
3. render/write frames while allocation counting is off;
4. perform the existing process swap and `thread.start_next_profile_epoch()`;
5. call `rearm_successor()` before returning.

An overflowed NATIVEPERF epoch leaves the allocation record invalid; it never
wraps to epoch 0.

- [x] **Step 10: Run lifecycle tests green**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --features alloc-owner-census native_fork_child -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --features alloc-owner-census native_exec_capsule -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-dsr-aarch64 --features alloc-owner-census exec_handoff -- --nocapture
cargo clippy -p carrick-cli -p carrick-runtime -p carrick-dsr-aarch64 --all-targets --features alloc-owner-census -- -D warnings
```

Expected: all lifecycle/order tests pass and clippy is clean.

- [x] **Step 11: Commit lifecycle integration**

```bash
git add crates/carrick-cli/src/main.rs crates/carrick-runtime/src/native_darwin.rs crates/carrick-runtime/src/native_exec_capsule.rs crates/carrick-dsr-aarch64/src/translator.rs
git commit -m "diagnostics(native): close allocation census lifecycle"
```

---

### Task 4: Tag the source-authoritative semantic owners

**Files:**
- Modify: `crates/carrick-dsr-aarch64/src/block.rs`
- Modify: `crates/carrick-dsr-aarch64/src/emit.rs`
- Modify: `crates/carrick-dsr-aarch64/src/gateway.rs`
- Modify: `crates/carrick-dsr-aarch64/src/shared_cache.rs`
- Modify: `crates/carrick-dsr-aarch64/src/translator.rs`

**Interfaces:**
- Every successful allocation has exactly one innermost owner.
- Outer translation scopes are overridden only by the retained map/recovery
  helpers; owners cannot overlap.
- Feature-off statements compile away under `cfg(feature =
  "alloc-owner-census")`.

- [x] **Step 1: Enable the tagged allocator only for the DSR unit-test binary**

In `alloc_owner_census.rs`, add this crate-local test allocator so semantic
tests observe real `Vec`/`Box` allocations without defining a second allocator
in production:

```rust
#[cfg(test)]
#[global_allocator]
static TEST_ALLOC_OWNER_CENSUS: TaggedSystem = TaggedSystem;
```

All tests that arm/reset global census state must hold the Task 2 test lock and
compare snapshot deltas, not absolute harness totals.

- [x] **Step 2: Add red source-owner tests**

Add focused tests that execute one existing fixture per owner and assert a
positive delta only in the named row:

- `plan_superblock_with_reader_for_counter_plan` with 32 copied instructions:
  `DecodeReadBuffers`;
- `assemble_block_inner` on `copy_plan()`: positive
  `BlockAssemblerTransient`, `PublicationMap`, and `PublicationRecovery`;
- `IndirectTargetCache::new()`: `IndirectTargetCache`;
- `PendingTranslationUnit::pack` plus metadata encode/decode:
  `SharedTranslationSupport`;
- `publish_emitted_with_metadata` using an existing publication fixture:
  `PublicationIndexes`.

The emitter test must also assert that map/recovery bytes are not charged to
`BlockAssemblerTransient` by measuring each collection's known requested
capacity delta separately.

- [x] **Step 3: Run semantic tests and prove red**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-dsr-aarch64 --features alloc-owner-census allocation_owner -- --nocapture
```

Expected: assertions fail because every allocation is still `other`.

- [x] **Step 4: Tag decode/read and transient assembly scopes**

At the first statement of
`plan_superblock_with_reader_for_counter_plan`, install a
`DecodeReadBuffers` scope. It covers instruction vectors and the runtime reader
closure, including `read_bytes_raw` allocations on the same thread.

At the first statement of `assemble_block_inner`, install a
`BlockAssemblerTransient` scope. It covers `VecAssembler`, dynasm labels and
relocations, emitted bytes, direct links, `EmitItem`, and pending-edge staging.

- [x] **Step 5: Give map and recovery their exact inner scopes**

Wrap the initial `entries = Vec::with_capacity(...)` in a `PublicationMap`
scope. Add one helper:

```rust
#[inline]
fn push_recovery(recovery: &mut Vec<RecoveryEntry>, entry: RecoveryEntry) {
    #[cfg(feature = "alloc-owner-census")]
    let _owner = crate::alloc_owner_census::scope(
        crate::alloc_owner_wire::AllocationOwner::PublicationRecovery,
    );
    recovery.push(entry);
}
```

Replace all 47 production `recovery.push(RecoveryEntry { ... })` sites in
`emit.rs` with `push_recovery(recovery, RecoveryEntry { ... })`, using
`&mut recovery` where the local is owned and `recovery` where the helper already
has a mutable reference. Do not alter the entry values or loop bounds.

Put a `PublicationMap` scope inside `map_next` around its sole `entries.push` so
capacity growth beyond the estimate remains correctly owned.

- [x] **Step 6: Tag indirect cache, shared support, and publication indexes**

Install:

- `IndirectTargetCache` around all of `IndirectTargetCache::new`;
- `SharedTranslationSupport` around
  `ProcessTranslator::publish_shared_candidates`, the store load/attach portion
  of `try_load_shared_unit`, `PendingTranslationUnit::pack_with_recovery_runs`,
  `encode_translation_unit_metadata`, and
  `decode_translation_unit_metadata`;
- `PublicationIndexes` around all of
  `ProcessState::publish_emitted_with_metadata`.

These scopes include relevant callees and library internals; do not tag
individual BTreeMap or serializer allocation sites.

- [x] **Step 7: Run semantic tests green and inspect feature-off codegen**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-dsr-aarch64 --features alloc-owner-census allocation_owner -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-dsr-aarch64 --lib -- --nocapture
cargo clippy -p carrick-dsr-aarch64 --all-targets --features alloc-owner-census -- -D warnings
cargo clippy -p carrick-dsr-aarch64 --all-targets -- -D warnings
```

Expected: feature tests show positive disjoint owner deltas; ordinary tests and
both clippy modes pass.

- [x] **Step 8: Commit semantic tags**

```bash
git add crates/carrick-dsr-aarch64/src/block.rs crates/carrick-dsr-aarch64/src/emit.rs crates/carrick-dsr-aarch64/src/gateway.rs crates/carrick-dsr-aarch64/src/shared_cache.rs crates/carrick-dsr-aarch64/src/translator.rs crates/carrick-dsr-aarch64/src/alloc_owner_census.rs
git commit -m "diagnostics(native): tag allocation owners"
```

---

### Task 5: Build the strict NATIVEPERF join and portfolio report

**Files:**
- Create: `crates/carrick-cli/src/native_perf_epochs.rs`
- Create: `crates/carrick-cli/src/debug_alloc_owner.rs`
- Modify: `crates/carrick-cli/src/main.rs`
- Modify: `crates/carrick-cli/src/args.rs`
- Modify: `crates/carrick-cli/src/commands.rs`
- Modify: `crates/carrick-cli/src/debug.rs`

**Interfaces:**
- `NativePerfEpochAuthority::parse(&str) -> anyhow::Result<Self>` produces
  unique process-image epochs, PID/thread counts, all-thread translations, and
  supervisor total CPU.
- `run_alloc_owner_census(&AllocOwnerCensusRequest) -> anyhow::Result<()>`
  prints schema `carrick.alloc-owner-census.v1` and exits nonzero after printing
  whenever any file, lifecycle, coverage, overflow, duplicate, or `other` gate
  fails.
- The request and authority types are exact:

```rust
struct AllocOwnerCensusRequest {
    dir: PathBuf,
    native_perf: PathBuf,
    expected_process_epochs: u64,
    expected_pids: u64,
    normal_host_allocation_opportunity_share: Option<f64>,
    qualification_share_of_total: f64,
}

struct NativePerfEpochAuthority {
    process_epochs: BTreeSet<(i32, u64)>,
    pids: BTreeSet<i32>,
    threads: u64,
    all_thread_translations: u64,
    supervisor_total_cpu_ns: u64,
}
```

The JSON root is a serialized `AllocOwnerCensusReport` with literal
`schema: "carrick.alloc-owner-census.v1"`, sorted owner rows, identity and
flush counts, NATIVEPERF coverage, `H`, `P`, `Q`, authority label, `other`
verdict, candidate rows, and one top-level `valid` bit. It is rendered through
one pretty-JSON function used by both fixtures and the command.

- [x] **Step 1: Add red NATIVEPERF authority tests**

Use literal complete core/resolver/supervisor lines for two PIDs, one exec
successor, and one worker thread. Assert:

```rust
assert_eq!(authority.process_epochs.len(), 3);
assert_eq!(authority.pids.len(), 2);
assert_eq!(authority.threads, 4);
assert_eq!(authority.all_thread_translations, 35);
assert_eq!(authority.supervisor_total_cpu_ns, 23_000);
```

Add independent rejection fixtures for duplicate core, missing
resolver-process, `complete=0`, `overflowed=1`, gateway/reconciled mismatch,
duplicate supervisor, missing supervisor, non-contiguous exec epochs, unknown
required numeric field, and checked-sum overflow.

- [x] **Step 2: Run the parser tests and prove red**

```bash
cargo test -p carrick-cli native_perf_epochs -- --nocapture
```

Expected: compile failure because `NativePerfEpochAuthority` is absent.

- [x] **Step 3: Implement exact NATIVEPERF group parsing**

Group complete thread frames by `(pid, tid, era)`. Require exactly one `core`
and one `resolver-process` frame per group. Read `exec_epoch` and
`thread_cpu_ns` from core; read `translations` from resolver-process. Process
epochs are unique main-thread `(pid, exec_epoch)` pairs where `tid == pid`.
Require each PID's epochs to start at 0 and be contiguous. Parse exactly one:

```text
NATIVEPERF1|supervisor|self_cpu_ns=<u64>|children_cpu_ns=<u64>
```

Use checked sums for translations, thread counts, and supervisor total CPU.
Other recognized NATIVEPERF frames may be ignored only after their common
identity fields parse; `invalid` frames are fatal.

- [x] **Step 4: Add the CLI request with explicit workload authority**

Add this `DebugCommand` variant:

```rust
AllocOwnerCensus {
    dir: PathBuf,
    #[arg(long = "native-perf")]
    native_perf: PathBuf,
    #[arg(long = "expected-process-epochs")]
    expected_process_epochs: u64,
    #[arg(long = "expected-pids")]
    expected_pids: u64,
    #[arg(long = "normal-host-allocation-opportunity-share")]
    normal_host_allocation_opportunity_share: Option<f64>,
    #[arg(long = "qualification-share-of-total", default_value_t = 0.10)]
    qualification_share_of_total: f64,
}
```

Wire it in both macOS `debug::run_debug` and the portable non-HVF debug match.
Declare both new modules in `main.rs`.

- [x] **Step 5: Add red fragment/lifecycle/portfolio fixtures**

Create temporary `ALLOCOWNER1` files with Task 1's renderer and a literal
NATIVEPERF stream. The accepted fixture must contain:

- PID 10 epoch 0 fragments `host-self-reexec-attempt` sequence 0 and
  `process-exit` sequence 1, plus PID 10 epoch 1 terminal successor;
- PID 20 epoch 0 `in-process-exec`, plus epoch 1 terminal successor;
- all eight owners, with `publication-recovery = 40%`,
  `block-assembler-transient = 20%`, and `other = 5%`;
- normal host-allocation opportunity share 0.30 and qualification share 0.10,
  making required owner share `Q = 1/3` and only publication recovery carried.

Assert exact candidate ordering and shares. Add rejection fixtures for missing
epoch, extra record, fragment sequence gap, duplicate identity, final host
attempt without successor, in-process handoff without successor, terminal with
successor, 139/140 expected epochs, 70/71 expected PIDs, `other >= Q`, malformed
file, and invalid share outside `(0, 1]`.

Check the accepted report against a complete literal golden JSON string,
including stable schema, owner order, flush counts, coverage counts, `H =
0.30`, `P = 0.10`, `Q = 1/3`, carried candidate, and `valid = true`. Re-render
the same fixture twice and require byte-identical JSON; never snapshot-update
this golden as part of the implementation command.

- [x] **Step 6: Run aggregator tests and prove red**

```bash
cargo test -p carrick-cli debug_alloc_owner -- --nocapture
```

Expected: compile failure because the aggregator/report is absent.

- [x] **Step 7: Implement strict discovery, join, and report**

Discover only `alloc-owner-*.txt`; a matching temp file is a truncation error.
Parse every discovered file or fail. Key fragments by
`(pid, exec_epoch, fragment_sequence)`, require sequences from zero with no gap,
then group by `(pid, exec_epoch)` and validate final disposition:

- `process-exit` or `atexit-backstop`: no same-PID next epoch;
- `in-process-exec`: exactly one same-PID next epoch;
- final `host-self-reexec-attempt`: exactly one same-PID next epoch;
- a non-final host attempt is a returned `execve` and must be followed by the
  next same-epoch fragment.

Join the exact group-key set to `NativePerfEpochAuthority.process_epochs`.
Require the supplied expected epoch/PID counts, and report NATIVEPERF thread and
all-thread translation totals.

Aggregate each owner with checked sums. Let `H` be the supplied normal
host-allocation opportunity share and `P` the qualification share. If `H` is
present, `Q = P / H`; otherwise `Q = P` and authority is
`strict-fallback-no-normal-binding`. Invalid/non-finite `H` or `P` and
`other_share >= Q` invalidate the report. `Q > 1` is valid and means the entire
normal host-allocation pot is below the pursuit threshold, so the report emits
an explicit STOP with no carried candidate. When `H` is absent, owner rows may
be labeled `coverage_candidate` when `owner_share >= P`, but projected shares
are `null` and `carried` is always false: fallback authority closes coverage,
not opportunity. When `H` is present, a candidate is carried only when
`owner_share * H >= P`; candidate rows are sorted by projected total-CPU share,
then owner token. Because allocator events have one innermost owner, candidate
shares are non-overlapping and their sum may not exceed `H`.

- [x] **Step 8: Run CLI tests green**

```bash
cargo test -p carrick-cli native_perf_epochs -- --nocapture
cargo test -p carrick-cli debug_alloc_owner -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-cli --bin carrick
cargo clippy -p carrick-cli --all-targets -- -D warnings
```

Expected: strict parser, lifecycle, coverage, opportunity, and CLI tests pass.

- [x] **Step 9: Commit the aggregator**

```bash
git add crates/carrick-cli/src/native_perf_epochs.rs crates/carrick-cli/src/debug_alloc_owner.rs crates/carrick-cli/src/main.rs crates/carrick-cli/src/args.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/src/debug.rs
git commit -m "diagnostics(debug): aggregate allocation owners"
```

---

### Task 6: Prove feature closure and signed lifecycle behavior

**Files:**
- Modify only implementation files whose focused tests expose a defect.
- Update: `docs/superpowers/plans/2026-08-03-native-allocation-owner-census.md`

**Interfaces:**
- Produces one ordinary signed binary receipt and one feature signed binary
  lifecycle smoke. Neither is campaign evidence yet.

- [x] **Step 1: Run the full source gate before a guest**

```bash
RUST_TEST_THREADS=1 just ci
```

Expected: fmt, clippy, typed-domain lint, deny, check-matrix, check, doc, host
tests, and integration tests all pass.

- [x] **Step 2: Build/sign the ordinary binary and prove no runtime instrument**

```bash
just build
shasum -a 256 target/release/carrick
dwarfdump --uuid target/release/carrick
codesign -d --entitlements :- target/release/carrick
otool -l target/release/carrick | rg '__dof_carrick'
strings -a target/release/carrick | rg 'CARRICK_ALLOC_OWNER_(CENSUS_DIR|EXEC_EPOCH)' && exit 1 || true
nm -m target/release/carrick | rg 'TaggedSystem|begin_host_exec_attempt|reset_after_fork_child_first_action' && exit 1 || true
```

Expected: signed ordinary binary with DOF, and both negative instrumentation
searches empty. The portable debug parser may remain linked; runtime allocator
and lifecycle markers may not.

- [x] **Step 3: Build/sign the feature binary and run a lifecycle smoke**

```bash
just build --features alloc-owner-census
rm -rf target/perf/alloc-owner-smoke
mkdir -p target/perf/alloc-owner-smoke/owners
CARRICK_RUN_ID=alloc-owner-smoke \
CARRICK_ALLOC_OWNER_CENSUS_DIR="$PWD/target/perf/alloc-owner-smoke/owners" \
CARRICK_DSR_PROFILE=1 \
CARRICK_DSR_STORE_DIR="$PWD/target/perf/native-fault-current-d48be196/store" \
target/release/carrick run --exec-backend native --pull never \
  -e CARRICK_RUN_ID=alloc-owner-smoke \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'set -eu; /bin/true; echo BUILD_OK' \
  >target/perf/alloc-owner-smoke/workload.stdout \
  2>target/perf/alloc-owner-smoke/nativeperf.stderr
target/release/carrick debug alloc-owner-census \
  target/perf/alloc-owner-smoke/owners \
  --native-perf target/perf/alloc-owner-smoke/nativeperf.stderr \
  --expected-process-epochs 1 --expected-pids 1 \
  >target/perf/alloc-owner-smoke/report.json
```

Before accepting the final command, parse `nativeperf.stderr` with the focused
`NativePerfEpochAuthority` test/helper and record its process-epoch and PID
counts. If the `/bin/true` topology is not 1/1, rerun only the aggregation with
those independently derived exact counts; never weaken the join, guess a count,
or edit a record to fit an assumption.

- [x] **Step 4: Inspect the smoke and restore the ordinary binary**

Require one `BUILD_OK`, rc 0, no `*.tmp`, every record parseable, contiguous
fragments, exact NATIVEPERF join, nonzero cumulative bytes, no overflow/lifecycle
error, and zero run-id-scoped survivors. Then:

```bash
scripts/sudo/kill.sh alloc-owner-smoke
just build
git status --short
```

Expected: no survivors, ordinary signed binary restored, and only intended
source/docs changes.

- [x] **Step 5: Record verification in the plan and commit any test-driven fix**

Mark completed steps and append literal command results. If the smoke exposed a
source defect, fix it red-first, rerun Steps 1-4, and commit only the affected
implementation files with:

```bash
git commit -m "fix(native): close allocation census lifecycle gap"
```

Do not create an empty commit when no fix was needed.

#### Task 6 verification (2026-08-03)

- `RUST_TEST_THREADS=1 just ci`: PASS. The authoritative source gate completed
  fmt, clippy, typed-domain lint, deny, check-matrix, check, doc, host tests, and
  integration tests; the runtime results included 1,160 unit tests passing with
  5 ignored and 296 integration tests passing.
- Ordinary signed binary: SHA-256
  `a02a5296228a7ec84f5424e483253a56c9c073df384d1bf86b65dd8faf3e1b68`,
  Mach-O UUID `17001A3C-07E3-39BB-801E-4810B1B9D18E`. The hypervisor
  entitlement and `__dof_carrick` were present. Both allocator-environment and
  lifecycle-symbol negative searches were empty. `xcrun dwarfdump --uuid` was
  used because the unqualified `dwarfdump` on this host is the GNU tool.
- Feature signed binary: SHA-256
  `7c3d242aec7717c1867a7006021d004e5a2be5aac84eaf6f0556c68efab803ec`,
  Mach-O UUID `360426F9-1A2B-344E-8DC2-6A9DB57C97FC`; entitlement and DOF
  checks passed.
- The first smoke exposed a real lifecycle defect: the launch supervisor
  exported a record with no NATIVEPERF epoch, and the initial native child
  inherited supervisor counters. Red tests covered both failures. The fix makes
  only DSR process images participants and resets the initial native fork child
  before its first fd close. It is commit `592c76dd` (`fix(native): close
  allocation census lifecycle gap`).
- Post-fix focused authority: 26/26 allocator-census tests passed; the complete
  feature-on runtime suite passed 1,163 tests with 5 ignored; all 204 CLI unit
  tests passed; feature-on runtime and CLI clippy passed with warnings denied.
- Signed smoke: rc 0, exactly one `BUILD_OK`, exactly 3 final records, 0 temp
  files, 0 overflow/lifecycle flags, and 0 run-id-scoped survivors. Strict
  NATIVEPERF independently reported 3 process epochs, 2 PIDs, 3 threads, 505
  translations, and 367,880,000 ns supervisor CPU. Allocation authority joined
  the same 3 epochs and 2 PIDs, with 33,593,764 cumulative requested bytes and
  flushes `{host-self-reexec-attempt: 1, process-exit: 2}`.
- The default `P=0.1` report correctly failed coverage because `other` was
  0.5403341524933021 of this tiny smoke. No performance claim was accepted. A
  second explicit lifecycle-only aggregation with `P=1.0` returned valid with
  the same exact join; it validates export plumbing only.
- The pre-fix failure evidence remains recoverable at
  `target/perf/alloc-owner-smoke.pre-fix`; the corrected smoke is at
  `target/perf/alloc-owner-smoke`. The ordinary release binary was restored and
  reproduced its exact SHA-256, UUID, entitlement, DOF, and negative marker
  checks.
- An extra non-authoritative `cargo test -p carrick-cli --features
  alloc-owner-census` entered guest-running `run-elf` fixtures outside the
  accepted `just ci` lane. Its representative signal-10-before-first-trap
  failure reproduced with the ordinary feature-off binary and is not caused by
  the census change; it was excluded rather than mislabeled green.

---

### Task 7: Capture twice, bind normal fault/CPU opportunity, and publish the portfolio

**Files:**
- Create: `docs/perf-results/2026-08-03-native-allocation-owner-census.md`
- Modify: `docs/perf-results/native-dsr-shape-census.jsonl`
- Modify: `handoff.md`
- Modify: `docs/superpowers/plans/2026-08-03-native-allocation-owner-census.md`

**Interfaces:**
- Consumes two feature allocation/NATIVEPERF captures and two source-identical
  ordinary-binary NFAULT plus untraced NATIVEPERF bindings.
- Produces a ranked list of every non-overlapping owner that clears 10% in both
  bindings, or a measured STOP when none do.
- Does not implement a production optimization or change the official 10.4446x
  ratio.

- [ ] **Step 1: Freeze source, store, workload, and binaries**

Use the locked persistent store:

```text
target/perf/native-fault-current-d48be196/store
```

Record `git rev-parse HEAD`, `git status --porcelain`, image digest
`localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`,
host topology/core counts, thermal/power metadata, and a normalized store
manifest. The source must be clean except target-only receipts. Build/sign the
feature binary, then record its SHA-256, UUID, signature, and DOF.

- [ ] **Step 2: Run feature captures A and B sequentially**

For `arm=A` and `arm=B`, use a fresh output directory and unique run ID. Run
this exact workload with the arm substituted literally:

```bash
rm -rf target/perf/alloc-owner-current/A target/perf/alloc-owner-current/B
mkdir -p target/perf/alloc-owner-current/A/owners target/perf/alloc-owner-current/B/owners
CARRICK_RUN_ID=alloc-owner-A \
CARRICK_ALLOC_OWNER_CENSUS_DIR="$PWD/target/perf/alloc-owner-current/A/owners" \
CARRICK_DSR_PROFILE=1 \
CARRICK_DSR_STORE_DIR="$PWD/target/perf/native-fault-current-d48be196/store" \
target/release/carrick run --exec-backend native --pull never \
  -e CARRICK_RUN_ID=alloc-owner-A -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'set -eu; cd /tmp; rm -rf "gc-$CARRICK_RUN_ID"; printf "package main\nfunc main(){println(\"ok\")}\n" > h.go; w0=$(date +%s%N); GOCACHE="/tmp/gc-$CARRICK_RUN_ID" /usr/local/go/bin/go build -o h ./h.go; ./h; w1=$(date +%s%N); echo "WORKLOAD_NS=$((w1-w0))"; echo BUILD_OK' \
  >target/perf/alloc-owner-current/A/workload.stdout \
  2>target/perf/alloc-owner-current/A/nativeperf.stderr
```

Repeat with every `A` changed to `B`. Do not run the arms concurrently. Require
rc 0, exactly one positive `WORKLOAD_NS`, exactly one `BUILD_OK`, 140
independently parsed NATIVEPERF process epochs, 71 PIDs, all-thread translation
totals, no temp/invalid/overflow/lifecycle records, unchanged normalized store,
and zero survivors before accepting either arm. Discard feature wall/CPU time.

- [ ] **Step 3: Aggregate feature captures without opportunity claims**

Run the ordinary parser surface after each capture with no normal opportunity
argument:

```bash
target/release/carrick debug alloc-owner-census \
  target/perf/alloc-owner-current/A/owners \
  --native-perf target/perf/alloc-owner-current/A/nativeperf.stderr \
  --expected-process-epochs 140 --expected-pids 71 \
  >target/perf/alloc-owner-current/A/report-prebinding.json
```

Repeat for B. Require both reports valid except for the explicitly named
strict-fallback opportunity authority. Owner shares and all-thread translation
totals must be reported separately, not pooled.

- [ ] **Step 4: Fail closed and expand tags if `other` can hide a candidate**

Compute each run's fallback `Q = 0.10`. If either run has `other_share >= Q`,
the capture is **INVALID**, not STOP. Return to Task 4, use the DHAT stack table
only to name the largest remaining semantic boundary, add one closed owner with
a bumped wire/report schema, add red source-owner tests, rerun `just ci`, and
repeat feature captures A/B from clean output directories. Do not interpret a
large `other` bucket.

- [ ] **Step 5: Restore and authenticate the ordinary binary**

```bash
just build
shasum -a 256 target/release/carrick
dwarfdump --uuid target/release/carrick
codesign -d --entitlements :- target/release/carrick
otool -l target/release/carrick | rg '__dof_carrick'
```

Record the ordinary binary receipt and prove runtime instrumentation markers are
absent as in Task 6.

- [ ] **Step 6: Run ordinary NFAULT bindings N1 and N2**

For each binding, use the existing authenticated Rust-owned native-fault
profile, the same workload/store, a unique run ID, fresh raw and summary paths,
and natural completion:

```bash
rm -rf target/perf/alloc-owner-current/N1 target/perf/alloc-owner-current/N2
mkdir -p target/perf/alloc-owner-current/N1 target/perf/alloc-owner-current/N2
CARRICK_RUN_ID=alloc-owner-normal-N1 \
CARRICK_DSR_STORE_DIR="$PWD/target/perf/native-fault-current-d48be196/store" \
target/release/carrick trace --profile native-fault \
  --trace-out target/perf/alloc-owner-current/N1/raw.trace \
  --summary-jsonl target/perf/alloc-owner-current/N1/fault-summary.jsonl \
  -- run --exec-backend native --pull never \
  -e CARRICK_RUN_ID=alloc-owner-normal-N1 -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'set -eu; cd /tmp; rm -rf "gc-$CARRICK_RUN_ID"; printf "package main\nfunc main(){println(\"ok\")}\n" > h.go; w0=$(date +%s%N); GOCACHE="/tmp/gc-$CARRICK_RUN_ID" /usr/local/go/bin/go build -o h ./h.go; ./h; w1=$(date +%s%N); echo "WORKLOAD_NS=$((w1-w0))"; echo BUILD_OK'
```

Repeat as N2. Require natural NFAULT2 completion, rc 0, exactly one workload
marker and `BUILD_OK`, all DTrace loss/error/lifecycle/catalog counters zero,
every sampled page joined, unchanged store, and zero survivors. Traced elapsed
time remains perturbation only.

- [ ] **Step 7: Run ordinary untraced CPU bindings C1 and C2**

Run the exact workload twice more under only `CARRICK_DSR_PROFILE=1`, with
unique run IDs and separate stderr:

```bash
rm -rf target/perf/alloc-owner-current/C1 target/perf/alloc-owner-current/C2
mkdir -p target/perf/alloc-owner-current/C1 target/perf/alloc-owner-current/C2
CARRICK_RUN_ID=alloc-owner-normal-C1 \
CARRICK_DSR_PROFILE=1 \
CARRICK_DSR_STORE_DIR="$PWD/target/perf/native-fault-current-d48be196/store" \
target/release/carrick run --exec-backend native --pull never \
  -e CARRICK_RUN_ID=alloc-owner-normal-C1 -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'set -eu; cd /tmp; rm -rf "gc-$CARRICK_RUN_ID"; printf "package main\nfunc main(){println(\"ok\")}\n" > h.go; w0=$(date +%s%N); GOCACHE="/tmp/gc-$CARRICK_RUN_ID" /usr/local/go/bin/go build -o h ./h.go; ./h; w1=$(date +%s%N); echo "WORKLOAD_NS=$((w1-w0))"; echo BUILD_OK' \
  >target/perf/alloc-owner-current/C1/workload.stdout \
  2>target/perf/alloc-owner-current/C1/nativeperf.stderr
```

Repeat with every `C1` changed to `C2`. Parse each stderr through
`NativePerfEpochAuthority`. Require rc 0, one positive `WORKLOAD_NS`, one
`BUILD_OK`, exactly one supervisor record, 140 process epochs, 71 PIDs,
complete thread/resolver pairs, and a positive checked
`supervisor_self_cpu_ns + supervisor_children_cpu_ns`. Do not run alongside
NFAULT, Docker, or another Carrick workload.

- [ ] **Step 8: Derive two explicit normal opportunity shares**

For binding 1, combine feature A owner shares, N1's exact zfod total and sampled
host-other zfod share, and C1's supervisor total CPU. For binding 2, combine B,
N2, and C2. Use the already committed deliberately favorable fault cost input
of 3,840 ns per host zfod event, and record the formula:

```text
host_other_zfod = exact_zfod * sampled_host_other_zfod_share
host_allocation_cpu_ns = host_other_zfod * 3840
H = host_allocation_cpu_ns / ordinary_supervisor_total_cpu_ns
owner_projected_total_cpu_share = owner_requested_byte_share * H
```

Keep exact measured counts, sampled share, cost-model input, proportional
projection, and favorable ceiling in separate fields. Reject `H <= 0`, `H > 1`,
overflow, or a non-finite result.

- [ ] **Step 9: Re-run reports with each normal binding**

Pass each computed `H` through
`--normal-host-allocation-opportunity-share`. Require the printed `Q = 0.10/H`,
`other < Q`, and candidate list. A portfolio owner is **CARRY** only when its
proportional projected total-CPU share is at least 0.10 in both reports. Rank
qualifiers by the smaller of the two projections. Do not add owner percentages
or favorable ceilings that reuse the same fault pot.

- [ ] **Step 10: Write durable evidence and update the controller**

The evidence document must include:

- source, feature and ordinary binary, UUID/signature/DOF, image, host/core,
  workload, store, run, raw/report hashes, and survivor receipts;
- corrected DHAT coverage (36.8376% / 41.6574%) labeled discovery-only;
- feature A/B epoch/PID/thread/all-thread translation coverage;
- per-owner bytes/calls/shares for A and B;
- N1/N2 exact/sample fault inputs and C1/C2 ordinary CPU denominators;
- the two `H`, `Q`, `other` verdicts, and every owner projection;
- a ranked non-overlapping CARRY portfolio or explicit STOP;
- explicit statements that feature timing is discarded, no production
  optimization was tested, eager translation/core decoding remain deferred,
  Tier D remains off, and official cold build remains 10.4446x.

Append one typed ledger row, update `handoff.md` with the next highest-ranked
candidate or next bucket, and mark this plan's executed results.

- [ ] **Step 11: Run final gates and commit evidence**

```bash
git diff --check
RUST_TEST_THREADS=1 just ci
git add docs/perf-results/2026-08-03-native-allocation-owner-census.md docs/perf-results/native-dsr-shape-census.jsonl handoff.md docs/superpowers/plans/2026-08-03-native-allocation-owner-census.md
git commit -m "docs(perf): rank native allocation owners"
```

If at least one owner is carried, the next action is a new single-variable
production design and ABBA plan for the top-ranked owner. If none qualify, move
to the next non-guest CPU/amplification bucket without changing product code or
the official ratio.
