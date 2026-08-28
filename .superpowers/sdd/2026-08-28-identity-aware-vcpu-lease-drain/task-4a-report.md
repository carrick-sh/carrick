# Task 4A report — process-fork identity lease acquisition

Date: 2026-08-28

Base: `5f8ab31cc7a4f3f7488b15a42ffdf5c663a52974`

Scope: Task 4 Steps 1-4 only. The repetitive post-`into_parts` exit-path
rewrite in Task 4 Step 5 was deliberately not performed.

## RED receipts

The bounded production source contract was added and run before the release
type or fork implementation changed:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork_uses_identity_lease_subscription --lib -- --nocapture
exit 101
assertion failed: prepare.contains("subscribe_lease_drain")
test result: FAILED. 0 passed; 1 failed; 2034 filtered out
```

The release-order behavior test was then added and failed on the missing
production authority:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime fork_release_lowers_barriers_before_thaw_callback --lib -- --nocapture
exit 101
error[E0433]: use of undeclared type `ProcessForkRelease`
error: could not compile `carrick-runtime` (lib test) due to 1 previous error
```

The plan's literal thread command initially exited zero with `running 0 tests`
because the existing public test names did not contain `fork_quiesce_stress`.
The two public tests were renamed so the prescribed filter is a real gate. The
identity-set fixture then ran 2/2 rather than treating a zero-test invocation as
evidence:

```text
RUSTC_WRAPPER= cargo test -p carrick-thread fork_quiesce_stress --lib -- --nocapture
exit 0
test result: ok. 2 passed; 0 failed; 49 filtered out
```

## Implementation checkpoint

- `prepare_in_process_fork` now atomically calls `subscribe_lease_drain`.
  `Waiting` retains the registry membership subscription, nudges exact sibling
  release channels, and returns `ProcessForkRetrySubscription::Lease`; `Busy`
  retains the thaw subscription without inventing a member identity; `Frozen`
  transfers the unique guard into the coordinator.
- The old `subscribe_quiesced_progress` fork drain and scalar `kicker.count()`
  decision are absent from the bounded production function.
- `ProcessForkCoordinator` retains the guard until `into_parts`, and its own
  cancellation `Drop` lowers `end_quiesce`, lowers `end_fork`, and only then
  drops any acquired guard.
- `ProcessForkRelease` is the post-handoff RAII authority. Its `release` and
  `Drop` order is `end_quiesce -> end_fork -> drop guard`, and release is
  idempotent.
- To reach the required compile-clean Step-4 checkpoint without performing the
  Antigravity-owned Step-5 rewrite, the legacy local `process_barrier` name is
  shadowed with `&mut ProcessForkRelease`. Its temporary `end_quiesce` bridge
  defers work and its `end_fork` bridge calls the single `release` method. Thus
  all existing repetitive exits route through the RAII authority without
  double-publishing a barrier release. Step 5 should delete this bridge while
  replacing those call sites with direct release ownership.
- Direct test registrations in `quiesce.rs` use `subscribe_register` and assert
  `Registered`.
- The hermetic stress fixture now owns a `BTreeSet<ThreadId>` plus one optional
  freeze owner. Non-owner re-registration remains denied until the winner has
  lowered both barriers and thawed the freeze.
- After the first full `process_fork` run passed 16/17, the controller
  explicitly authorized the exact test-only update in `continuation.rs`: its
  stale source contract now requires `subscribe_lease_drain` instead of the
  retired progress subscription. No other continuation change was made.

## Lifetime self-review

1. Before freeze acquisition, a retry owns the active coordinator and exactly
   one registry subscription. Dropping a retry cancels an unclaimed listener;
   dropping its coordinator releases only the barrier state it owns.
2. A `Frozen` enrollment is installed only when `coordinator.drain` is empty.
   No diagnostic `Complete` poll authorizes protected work.
3. `into_parts` requires and removes that exact guard, then places it in
   `ProcessForkRelease` alongside the barrier state while returning both
   admission permits.
4. Every legacy explicit exit after the handoff reaches the release authority.
   Any `?`, panic unwind, or missed legacy exit instead reaches its `Drop`.
5. Backend rollback, topology work, kernel publication, and child activation
   all occur while `process_fork_release` remains in scope. The existing
   success release point calls through the same authority before dropping clone
   and process-fork admission permits.
6. Registration thaw callbacks cannot observe a raised quiesce barrier: both
   barriers are lowered before the guard is taken and dropped. The focused
   callback test retains its subscription through guard drop and observes
   `is_quiescing() == false`.
7. Exact-owner production re-registration remains independent of the raised
   barrier and preserves `RetryProcessFork` phase state; the retained Task 3
   test is green.

## GREEN receipts

Fresh final runs on the formatted Step-4A source:

```text
RUSTC_WRAPPER= just fmt-check
exit 0

RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork --lib -- --nocapture
exit 0; 17 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime fork_release_lowers_barriers_before_thaw_callback --lib -- --nocapture
exit 0; 1 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime fork_lease --lib -- --nocapture
exit 0; 1 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime fork_owner_registration_ignores_raised_barrier_and_preserves_phase --lib -- --nocapture
exit 0; 1 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-thread fork_quiesce --lib -- --nocapture
exit 0; 10 passed; 0 failed

RUSTC_WRAPPER= cargo check -p carrick-runtime
exit 0

git -c core.fsmonitor=false diff --check
exit 0
```

The remaining `kicker.count()` matches in `quiesce.rs` are the separate
page-table diagnostic site and the bounded test's rejection string; Task 6 owns
that diagnostic migration. No direct `.register(` call, production
`subscribe_quiesced_progress`, or `ProcessForkRetrySubscription::Progress`
remains in this file.

## Deliberately deferred

Task 4 Step 5 must perform and review the repetitive exit-path rewrite, then
remove the temporary bridge described above. Task 4 Steps 6-8 and Tasks 5-7
remain unclaimed by this checkpoint.
