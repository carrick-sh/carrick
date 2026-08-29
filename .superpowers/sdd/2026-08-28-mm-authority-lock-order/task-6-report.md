# Task 6 report — structural `PtPause -> HostAlias` mutation authority

## Scope and architecture correction

Implemented Task 6 only on base `97bcd5f4de8d78a5dab54c104eb2acf5a8e32ed2`.
Tasks 7 and 8 remain untouched; the expected Task-8 foreign-current-memory
finding remains.

The plan sentence requiring a mutation guard in every `SyscallCtx` contradicted
the real hot path: ordinary syscalls do not own `PtPauseGuard` or
`Stage1Exclusive`, and manufacturing either would turn a type claim into fake
authority or pause every syscall. The approved correction is implemented as a
static split at the normalized resolver:

- ordinary handlers receive `SyscallCtx`, which cannot name or obtain a
  `HostAliasPermit`;
- the exact 17-entry mutation table receives `MutationSyscallCtx` containing a
  real `&mut MmMutationGuard`;
- the threaded route constructs that guard from the actual pre-dispatch
  `PtPauseGuard`, or from `Stage1Exclusive` only when the executor census proves
  sole execution;
- the non-threaded route uses the sealed single-executor issuer at its outer
  boundary; focused tests use the same issuer through cfg(test)-only helpers;
- synchronous grow-down/residency faults use a separate, read-classified
  mutation route at the trap boundary, also backed by real pause/exclusive
  authority.

There is no optional guard, runtime authority enum, public/default/fake
constructor, or thread-local observation used as authority. The classifier,
`syscall_takes_pre_dispatch_pt_pause`, and `syscall_edits_stage1` share one
source, and a fail-closed census test compares that source to the mutation
handler tables for every syscall number through 512.

## RED evidence

Baseline source census before implementation:

- self-test: 20 negative and 17 positive fixtures passed;
- 4 production findings: one `foreign-current-memory`, one
  `legacy-lock-order`, and two `unpermitted-host-alias` findings.

The baseline focused memory suite was load-sensitive under its default parallel
runner: 2 ordering tests failed in the combined run but both passed alone; the
serial baseline was 126/126. Required verification below therefore records the
serial run, consistent with Carrick's process-wide test serialization rules.

The first production compile was deliberately run after adding only the typed
contracts/tests. `RUSTC_WRAPPER= cargo test -p carrick-runtime mm_mutation
--no-run` failed with unresolved `MmMutationCoordinator`, `MmMutationGuard`,
`HostAliasPermit`, and `test_support`, proving the tests could not pass against
the pre-Task-6 implementation. The compile-fail doctests additionally reject:

- direct guard construction (private fields);
- cloning a guard;
- cloning a permit;
- returning a permit beyond its guard borrow.

## Authority construction graph

```text
threaded syscall classifier (exact mutation table)
  -> real PtPauseGuard when peers exist
     OR sole-executor Stage1Exclusive
  -> non-cloneable MmMutationGuard for the exact per-MM coordinator
  -> MutationSyscallCtx only
  -> borrow-bound HostAliasPermit
  -> HostAliasTransactions::begin_dispatch
  -> coordinator alias guard transfers through Pending -> Installing
  -> permit-required HostAliasTransaction::claim
  -> backend install/rollback/commit while outer authority remains live

ordinary classifier
  -> SyscallCtx (no mutation field and no permit path)

non-threaded outer boundary / cfg(test) helper
  -> sealed, non-Send single-executor issuer
  -> same MmMutationGuard -> permit chain

retained Task-5 foreign read
  -> deadline-bounded coordinator snapshot read guard
  -> mutually exclusive with alias work, without impersonating mutation
```

The coordinator concurrency test holds alias work while another thread enters
the alias queue and proves the inner phase has zero API/path for waiting on
page-table exclusion. Snapshot readers and alias work now share this real
per-MM observation point. The deleted thread-local `LockLevel` validator and
executor fake acquisitions no longer exist.

## Changed files

- `crates/carrick-runtime/src/dispatch/mm_mutation.rs` (new)
- `crates/carrick-runtime/src/dispatch/mod.rs`
- `crates/carrick-runtime/src/dispatch/abi_args.rs`
- `crates/carrick-runtime/src/dispatch/fs.rs`
- `crates/carrick-runtime/src/dispatch/fs/tests.rs`
- `crates/carrick-runtime/src/dispatch/mem.rs`
- `crates/carrick-runtime/src/dispatch/mem/tests.rs`
- `crates/carrick-runtime/src/dispatch/sysv.rs`
- `crates/carrick-runtime/src/dispatch/tests.rs`
- `crates/carrick-runtime/src/dispatch/lock_order.rs` (deleted)
- `crates/carrick-runtime/src/runtime.rs`
- `crates/carrick-runtime/src/hvpatch/mod.rs` (test issuer migration only)
- `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`
- `crates/carrick-runtime/src/vcpu_loop/signal.rs`
- `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- this report

## GREEN evidence and exact census

- `python3 scripts/migrate/check-mm-authority.py --self-test` — PASS, 20
  negative and 17 positive fixtures.
- `python3 scripts/migrate/check-mm-authority.py --check` — expected census:
  exactly 1 production finding,
  `crates/carrick-runtime/src/dispatch/proc.rs:4425 foreign-current-memory`.
  Counts: `legacy-lock-order=0`, `unpermitted-host-alias=0`,
  `foreign-current-memory=1`.
- `RUSTC_WRAPPER= cargo test -p carrick-runtime mm_mutation` — PASS, 2/2
  focused unit tests; all other test binaries filtered cleanly.
- `RUST_TEST_THREADS=1 RUSTC_WRAPPER= cargo test -p carrick-runtime
  dispatch::mem::tests --lib` — PASS, 126/126.
- `RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf frame_cow` — PASS, 1/1
  focused unit test; all other test binaries filtered cleanly.
- `RUSTC_WRAPPER= cargo check --workspace` — PASS.
- `RUSTC_WRAPPER= cargo clippy -p carrick-runtime -p carrick-vmm-hvf
  --all-targets -- -D warnings` — PASS.
- `cargo fmt --check` — PASS.
- `git diff --check` — PASS (the repository fsmonitor emitted its known IPC
  warning but the gate returned success).

## Self-review

- All permit-bearing fields and constructors are private to `mm_mutation`;
  public consumers can borrow a permit only from a live guard.
- `MmMutationGuard` and `HostAliasPermit` are statically non-Clone/non-Copy;
  the single-executor issuer is non-Clone and non-Send.
- Real alias entry, pending transaction ownership, install claim, fault
  materialization, rollback, and commit remain under the same coordinator and
  real outer authority.
- Read-only proc/VMA snapshots no longer enter alias work. Task 5's
  revision/deadline semantics are retained by the coordinator's snapshot-read
  side, which excludes alias work without granting mutation authority.
- The mutation classifier is exact and fail-closed against the typed handler
  tables; ordinary dispatch cannot resolve a mutation handler.
- The Task-5 per-MM state, retained foreign-read authority, deadlines, and
  endpoint capability boundary remain intact.

## Remaining concerns

The source checker intentionally remains non-zero because Task 8 owns the
single retained `foreign-current-memory` finding. No Task-6 correctness or
gate concern remains. The default-parallel focused memory suite has the
documented pre-existing load-sensitive ordering behavior; the authoritative
serial run is green.
