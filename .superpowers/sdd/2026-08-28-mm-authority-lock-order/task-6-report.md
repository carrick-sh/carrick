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
  `PtPauseGuard`, or from a sealed `SoleMmStage1` only while the executor census
  owned by the exact `DispatchMmAuthority` proves sole execution;
- CLONE_VM dispatchers share that exact-MM census through their shared authority
  Arc. The sole proof holds the census election locked for its whole lifetime,
  so a peer cannot enter after it is minted;
- the non-threaded route and explicit public threaded route must first enter an
  opaque `MmExecutorParticipation`; neither `&mut SyscallDispatcher` nor a
  thread-local stage-1 marker is mutation authority;
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
- cloning an owned guard;
- returning a permit beyond its guard borrow.

Permit non-clonability is covered by the static
`assert_not_impl_any!(HostAliasPermit<'static>: Clone, Copy)` assertion rather
than a fourth doctest.

Repair round 1 also preserved red-first evidence for every reviewed defect:

- `concurrency_contracts::shared_dispatcher_services_memory_state` reproduced
  the public threaded `brk` regression as `ENOSYS`; after changing the test to
  the first explicit sole-executor API it compile-failed until that boundary
  existed. Repair round 2 superseded its invalid `&mut SyscallDispatcher`
  witness with the exact-MM census participation described below.
- `cargo test -p carrick-runtime --doc mm_mutation` failed because the original
  clone doctest cloned `&MmMutationGuard` rather than the owned guard.
- the proc snapshot regression compile-failed until `mem_snapshot_until`
  existed, then proved a snapshot cannot clone `MemState` during Installing.
- while propagating the lifetime-bearing install type, rustc rejected the old
  vCPU shape with E0597 because both `mutation` and `permit` died before the
  stored install guard. The repaired consumer completes install/rollback inside
  the permit scope; this is direct compiler evidence for the reviewed lifetime.

Repair round 2 added
`clone_vm_distinct_dispatcher_cannot_claim_sole_mm_with_peer_active` before the
exact-MM participation API existed. Its RED compile failed with E0599 for the
missing `enter_mm_executor` and `dispatch_threaded_with_mm_executor` methods and
for the missing fail-closed peer error. The GREEN test creates distinct
CLONE_VM dispatchers sharing one authority, admits both executors, proves
mutation cannot mint sole authority with the peer live, then drops the peer and
proves the same request is admitted. It also holds the sealed sole authority
while a new peer attempts admission, proves that admission remains blocked, and
then proves it completes after the authority releases.

## Authority construction graph

```text
threaded syscall classifier (exact mutation table)
  -> real PtPauseGuard when peers exist
     OR exact DispatchMmAuthority census participation
        -> locked sole election -> sealed SoleMmStage1
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

non-threaded or explicit public threaded boundary
  -> opaque exact-MM participation -> locked sole election -> SoleMmStage1
  -> same MmMutationGuard -> permit chain

cfg(test) alias helpers
  -> real PtPauseGuard (never a synthetic sole-executor claim)

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
- `crates/carrick-runtime/src/kernel/guest_execution.rs`
- `crates/carrick-runtime/src/kernel/mod.rs`
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
- `RUSTC_WRAPPER= cargo test -p carrick-runtime
  clone_vm_distinct_dispatcher_cannot_claim_sole_mm_with_peer_active --
  --nocapture` — PASS, 1/1; two distinct CLONE_VM dispatchers cannot mint sole
  mutation authority while both exact-MM executor participations are live, and
  a new peer cannot enter while the sole election is held.
- `RUSTC_WRAPPER= cargo test -p carrick-runtime
  production_registration_keeps_census_before_registry_publication --
  --nocapture` — PASS, 1/1; production registration admits the exact-MM census
  before publishing the vCPU registry entry.
- `RUSTC_WRAPPER= cargo test -p carrick-runtime
  kernel::guest_execution::tests --lib` — PASS, 8/8 exact-MM census lifecycle,
  unwind, and sole-election tests.
- `RUST_TEST_THREADS=1 RUSTC_WRAPPER= cargo test -p carrick-runtime
  dispatch::mem::tests --lib` — PASS, 127/127.
- `RUSTC_WRAPPER= cargo test -p carrick-runtime --test integration
  concurrency_contracts::shared_dispatcher_services_memory_state` — PASS,
  1/1; both `brk` calls return their Linux values through an opaque exact-MM
  participation and the public census-authorized threaded route.
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
  no unscoped single-executor issuer or constructor remains.
- `&mut SyscallDispatcher` is not authority. The only sole path borrows an
  opaque participation tied by Arc identity to the exact current
  `DispatchMmAuthority`, then holds that shared census locked while the sealed
  `SoleMmStage1` and its mutation guard are live.
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
