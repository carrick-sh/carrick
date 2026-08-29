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
- the non-threaded route and the explicit public threaded single-executor API
  require an exclusive `&mut SyscallDispatcher` outer-boundary witness and
  claim the real `Stage1Exclusive`; normalized handlers receive only `&self`;
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

Repair round 1 also preserved red-first evidence for every reviewed defect:

- `concurrency_contracts::shared_dispatcher_services_memory_state` reproduced
  the public threaded `brk` regression as `ENOSYS`; after changing the test to
  the explicit sole-executor API it compile-failed until that structural outer
  boundary existed.
- `cargo test -p carrick-runtime --doc mm_mutation` failed because the original
  clone doctest cloned `&MmMutationGuard` rather than the owned guard.
- the proc snapshot regression compile-failed until `mem_snapshot_until`
  existed, then proved a snapshot cannot clone `MemState` during Installing.
- while propagating the lifetime-bearing install type, rustc rejected the old
  vCPU shape with E0597 because both `mutation` and `permit` died before the
  stored install guard. The repaired consumer completes install/rollback inside
  the permit scope; this is direct compiler evidence for the reviewed lifetime.

## Authority construction graph

```text
threaded syscall classifier (exact mutation table)
  -> real PtPauseGuard when peers exist
     OR sole-executor Stage1Exclusive
  -> non-cloneable MmMutationGuard for the exact per-MM coordinator
  -> MutationSyscallCtx only
  -> borrow-bound HostAliasPermit
  -> HostAliasTransactions::begin_dispatch
  -> dispatch alias phase ends before an owned Pending outcome escapes
  -> permit-required HostAliasTransaction::claim re-enters alias exclusion
  -> lifetime-bearing HostAliasInstallGuard<'permit>
  -> backend install/rollback/commit while outer authority remains live

ordinary classifier
  -> SyscallCtx (no mutation field and no permit path)

non-threaded or explicit single-executor outer boundary / cfg(test) helper
  -> exclusive dispatcher witness -> real Stage1Exclusive
  -> same MmMutationGuard -> permit chain

retained Task-5 foreign read
  -> deadline-bounded coordinator snapshot read guard
  -> mutually exclusive with alias work, without impersonating mutation
```

The coordinator concurrency test uses a real `PtPauseGuard` for both editors.
The second editor remains at the outer pause election and cannot appear in the
inner alias queue until the first editor releases both alias work and its real
pause. Snapshot readers and alias work share the per-MM observation point. The
deleted thread-local `LockLevel` validator, fake issuers, tautological
`outer_waiters`, and executor fake acquisitions no longer exist.

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
- `crates/carrick-runtime/src/hvpatch/mod.rs` (test authority migration only)
- `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- `crates/carrick-runtime/src/vcpu_loop/exec.rs`
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`
- `crates/carrick-runtime/src/vcpu_loop/signal.rs`
- `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- `crates/carrick-runtime/tests/integration/concurrency_contracts.rs`
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
- `RUSTC_WRAPPER= cargo test -p carrick-runtime
  mutation_classifier_exactly_matches_the_typed_handler_tables -- --nocapture`
  — PASS, 1/1; the exact 17-entry classifier agrees with both typed mutation
  handler tables for every syscall number through 512.
- `RUST_TEST_THREADS=1 RUSTC_WRAPPER= cargo test -p carrick-runtime
  dispatch::mem::tests --lib` — PASS, 127/127.
- `RUSTC_WRAPPER= cargo test -p carrick-runtime --test integration
  concurrency_contracts::shared_dispatcher_services_memory_state` — PASS,
  1/1; both `brk` calls return their Linux values through the explicit real
  single-executor route.
- `RUSTC_WRAPPER= cargo test -p carrick-runtime --doc mm_mutation` — PASS,
  3/3 compile-fail doctests.
- `RUSTC_WRAPPER= cargo test -p carrick-runtime
  proc_mem_snapshot_waits_for_install_and_returns_one_coherent_generation` —
  PASS, 1/1.
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
  no single-executor issuer or constructor remains.
- An owned pending transaction contains no alias guard. Claim re-enters the
  exact-MM coordinator and returns `HostAliasInstallGuard<'permit>`, so safe
  code cannot move install/rollback beyond the live permit and outer guard.
- Each `DispatchMmAuthority` and mutation coordinator carries its exact
  `MmId`; permit validation requires matching permit MM, authority MM,
  coordinator MM, and coordinator `Arc` identity.
- Read-only proc/VMA snapshots no longer enter alias work. Both fs proc-open
  snapshots and `synthetic_proc_context` clone one exact authority's `MemState`
  through the deadline-bounded coordinator read side, which excludes Installing
  without granting mutation authority.
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
