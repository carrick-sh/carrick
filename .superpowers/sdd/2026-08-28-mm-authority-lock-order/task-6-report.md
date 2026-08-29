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
- each executor owns one linear `MmExecutorParticipation`: the token is
  `Send` but structurally `!Sync`, is never stored in an `Arc`, and sole/pause
  dispatch requires an exclusive `&mut` borrow of that exact token;
- each exact-MM census entry registered by the production vCPU path carries an
  opaque pause endpoint for that executor's real registry and thread identity.
  A multi-executor pause keeps exact-MM admission locked while it kicks and
  drains every registered endpoint, including peers owned by distinct
  CLONE_VM dispatchers and distinct registries;
- the non-threaded route and explicit public threaded route must first enter an
  opaque `MmExecutorParticipation`; neither `&mut SyscallDispatcher` nor a
  thread-local stage-1 marker is mutation authority;
- synchronous grow-down/residency faults use a separate, read-classified
  mutation route at the trap boundary, also backed by real pause/exclusive
  authority.
- standalone frame-COW quiescence uses the same lifetime-held exact-MM census
  election: it either holds the sole census witness until the frame operation
  ends or performs the same all-endpoint pause and drain. There is no unlocked
  `has_peer_executor` check followed by a separately minted exclusive guard.

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

Repair round 3 began with compile-only regressions for the reviewed authority
gaps. `cargo test -p carrick-runtime --no-run` failed because the then-current
`MmExecutorParticipation` was still `Sync` and failed the new `!Sync` assertion,
and because the
new distinct-registry regression referenced the not-yet-implemented
`enter_with_pause_endpoint` and exact-MM pause API. Production was changed only
after that RED. The GREEN regression holds a real peer in guest execution in a
second `GenericVcpuRegistry`, observes a real kick, proves pause cannot complete
while that peer remains in guest, and proves exact-MM admission stays blocked
until the pause guard drops. A standalone frame-COW regression additionally
proves its sole witness keeps peer admission blocked for the witness lifetime;
this closes the source-review finding that the old unlocked peer check could
not provide.

Final self-review found that the production loop's documented Dekker re-entry
half was absent: it published `in_guest` and entered the engine without
re-checking `PtQuiesce::is_quiescing`. The regression was added first and failed
to compile with E0425 for the missing `enter_guest_or_park`. The implementation
now publishes `in_guest`, performs the SeqCst pause re-check, withdraws the
publication and parks when raised, and enters the engine only on the false
branch. This prevents an already-admitted or just-drained executor from
re-entering while the census-held pause guard remains live.

## Codex-owned final review closure

Independent review of `32ae993ec` rejected Task 6 on three remaining defects:
the frame-COW nested path still trusted an MM-agnostic thread-local boolean,
five focused mutation tests still entered the ordinary route, and one
registration source contract named the superseded helper. Codex closed those
findings locally after the delegated implementer reached its repair-turn cap.

The exact-MM nested path now upgrades a same-thread `Weak` to a non-`Send`,
non-`Sync` `Rc<ExactMmStage1Lease>` keyed by the exact `MmId`. The lease owns
the real lifetime-held census election or pause guard plus the stage-1 marker;
the nested frame-COW guard owns a clone, so dropping the outer wrapper cannot
release the underlying exclusion. A regression drops the outer pause first and
proves the nested lease keeps the real barrier raised until its own drop.

The full serialized runtime gate then exposed four additional deterministic
closure defects that narrower filters had missed:

- boot/VMA publication lost its alias transaction and therefore stopped
  advancing the VMA revision; initial and integration-test publication now mint
  exact-MM mutation authority before entering the VMA transaction;
- copied-MM relation coverage predated the retained-transport requirement and
  supplied neither an endpoint nor complete typed revision domains; its fixture
  now carries both without exercising a raw read path;
- the continuation source contract split at the wrapper rather than the live
  executor dispatch body;
- deleting the legacy lock-order boundary left its retired numeric dirty-state
  mode in the executor audit test; the test now enumerates the exact surviving
  prohibited modes.

The same broad gate also made the fork-install exclusion race reproducible.
Task 6 had removed the old untyped alias guard without replacing it. Production
fork publication now borrows the forking thread's exact-MM census
participation after the process barrier has drained siblings, mints sealed sole
stage-1 authority, and requires its permit for the complete dispatcher-MM
install. Direct tests use the real test pause issuer. The race-sensitive test,
17 process-fork tests, and the full 2,083-test serialized runtime suite are
green with that structural path.

## Authority construction graph

```text
threaded syscall classifier (exact mutation table)
  -> exclusive borrow of this executor's linear exact-MM participation
  -> lock exact DispatchMmAuthority census admission
     -> one participant: keep locked sole election -> sealed SoleMmStage1
     -> multiple participants: keep admission locked, kick every registered
        real per-executor registry endpoint, drain every exact peer
        -> real PtPauseGuard
        -> every executor publishes in-guest then re-checks PtQuiesce;
           a raised pause withdraws the publication and parks before engine entry
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
  -> exclusive borrow of opaque exact-MM participation
  -> same locked sole-or-all-endpoint election
  -> same MmMutationGuard -> permit chain

standalone frame COW
  -> same exact-MM census lock
  -> lifetime-held sole witness OR all-endpoint PtPause drain
  -> frame-COW guard; peer admission cannot race the decision

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

- `Cargo.toml` (`parking_lot` owned lock support for lifetime-held census proof)
- `crates/carrick-hal/src/threaded.rs`
- `crates/carrick-hal/src/pump_fork_coord.rs`
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
- `crates/carrick-runtime/src/kernel/operations.rs` (typed foreign-MM fixture)
- `crates/carrick-runtime/src/kernel/guest_execution.rs`
- `crates/carrick-runtime/src/kernel/mod.rs`
- `crates/carrick-runtime/src/vcpu_loop/continuation.rs` (source contract)
- `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- `crates/carrick-runtime/src/vcpu_loop/exec.rs`
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`
- `crates/carrick-runtime/src/vcpu_loop/signal.rs`
- `crates/carrick-runtime/src/vcpu_loop/executor.rs`
- `crates/carrick-runtime/tests/integration/concurrency_contracts.rs`
- `crates/carrick-runtime/tests/integration/common/syscall_support.rs`
- `crates/carrick-runtime/tests/integration/syscall_mem.rs`
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
- `RUST_TEST_THREADS=1 RUSTC_WRAPPER= cargo test -p carrick-runtime
  vcpu_loop::quiesce::pt_pause_tests --lib -- --nocapture` — PASS, 16/16.
  This includes two real, distinct `GenericVcpuRegistry` endpoints: the pause
  issues a real kick, cannot complete until the peer leaves guest execution,
  and blocks a third exact-MM admission until the guard releases. It also
  includes the standalone frame-COW sole-witness admission regression and the
  run-loop re-entry handshake that parks until the live pause releases.
- `RUSTC_WRAPPER= cargo test -p carrick-runtime
  kernel::guest_execution::tests --lib` — PASS, 8/8 exact-MM census lifecycle,
  unwind, distinct executor identity, and sole-election tests. Static
  assertions prove `MmExecutorParticipation: Send` and
  `MmExecutorParticipation: !Sync + !Clone + !Copy`.
- `RUSTC_WRAPPER= cargo test -p carrick-hal threaded` — PASS, 13/13, including
  exact per-thread `is_in_guest` registry observation.
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
  -p carrick-hal --all-targets -- -D warnings` — PASS.
- `RUST_TEST_THREADS=1 RUSTC_WRAPPER= cargo test -p carrick-runtime --lib`
  — PASS, 2,083/2,083.
- `RUSTC_WRAPPER= just test` — PASS, full repository host-test recipe.
- `cargo fmt --check` — PASS.
- `git diff --check` — PASS (the repository fsmonitor emitted its known IPC
  warning but the gate returned success).

## Self-review

- All permit-bearing fields and constructors are private to `mm_mutation`;
  public consumers can borrow a permit only from a live guard.
- `MmMutationGuard` and `HostAliasPermit` are statically non-Clone/non-Copy;
  no unscoped single-executor issuer or constructor remains.
- `&mut SyscallDispatcher` is not authority. The only sole path borrows an
  opaque linear participation tied by Arc identity to the exact current
  `DispatchMmAuthority`, then holds that shared census locked while the sealed
  `SoleMmStage1` and its mutation guard are live. The token cannot be shared by
  reference across threads and every dispatch/sole claim requires `&mut`.
- A peer count is not treated as quiescence. Every production vCPU census entry
  carries its real registry endpoint, and the multi-peer path keeps admission
  locked while it kicks and observes every exact peer out of guest execution.
  Each engine entry then re-checks the raised pause after publishing its exact
  in-guest flag, so a drained executor cannot immediately re-enter. Frame COW
  uses this same witness/drain path, so it has no check-then-claim window.
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
