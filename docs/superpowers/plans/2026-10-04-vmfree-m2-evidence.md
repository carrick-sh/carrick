# VM-free M2 evidence and remaining bindings

## Production fd atomic models

`just test-loom` runs two bounded models of the real `carrick-fd-core`
implementation: one table/description, two actors, at most two preemptions.
Only the unit-test target substitutes Loom atomics; production layout and
atomics remain unchanged, including when the feature is selected.

- `table_sequence_publishes_a_complete_pair`: a reader may reject a concurrent
  change, but an accepted sequence cannot publish a torn extent/capacity pair.
- `pin_racing_last_reference_releases_once_and_rejects_reuse`: final close and
  a temporary pin release exactly once; a stale pin cannot resolve a reused
  description record.

Mutation checks were run in the detached scratch worktree
`/tmp/vmfree-m2-evidence`, then reverted before the green run:

1. Change `TableRecord::end_write`'s sequence store from Release to Relaxed.
   The model fails: sequence 2 accepts `(0, 0)` instead of `(7, 8)`.
2. Change `Authority::free_ofd`'s generation increment from 1 to 0.
   The model fails: the stale pin resolves backing 9 instead of `StalePin`.

Restoring the production source passes both models. The ordinary fd-core suite
also passes (38 tests). These are bounded witnesses, not an exhaustive proof of
the kernel or an ABI layout check.

## Pipe atomic model: N1 handoff

`carrick-pipe-core` is a caller-locked state machine with no atomic protocol to
substitute. The real pipe lock/wake protocol spans `carrick-el1-abi/src/ipc.rs`
(`ObjectRecord`, `IpcView::lock`, `ObjectGuard` and deferred wake effects) and
`carrick-sched-core/src/object_wait.rs` (epoch snapshot, enrollment, notify,
unlink and object lock release). Both source trees remain N1-owned.

The director confirmed the fence and the handoff on 2026-10-04. After N1 lands,
substitute atomics in that actual wrapper and model failed-lock enrollment
against unlock/notify, plus object generation reuse. A mutation that omits the
epoch change or weakens publication must permit a missed wake/stale completion
and fail the model. Do not implement a separate pipe protocol for the test.
