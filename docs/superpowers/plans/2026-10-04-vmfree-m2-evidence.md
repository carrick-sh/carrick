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

## Admission/wake witnesses

Contract `kernel.credentials.birth-admission` owns the setid surface;
the other witnesses refine the existing `kernel.el1.thread-lifecycle`,
`kernel.futex.contention` and `kernel.el1.deferred-handback-identity` families.
These are VM-free semantic/count assertions, with no signed, runtime-ratio or
registered structural observation promotion.

`admission_interleavings` drives real public kernel operations on exact actors
through the graph-owned typed hook. The shared hook has no callbacks, field or
argument evaluation in release builds. Credential publication under a registry
guard and asynchronous wake publication are observation-only. Other seams
suspend before acquisition or after release. Object queue scenarios instrument
the public caller boundary; no N1-owned implementation is copied or edited.

- Held sibling birth: 1/8/32 valid setresuid calls return 0, with exactly one
  dispatcher entry and publication per call, one birth, one admission release,
  and the sibling's inherited credentials preserved.
- Conflicting publication reservation: one internal admission park/resume,
  no credential redispatch; 1/8/32 updates finish once.
- Exec publication: a late born ledger entry is retired, with an independent
  process still live. This is **not** a reproduction of the runtime member race.
- Check/enroll/wake: an epoch change before enrollment rejects the stale
  snapshot and preserves the operation; a fresh enrollment wakes exactly once.
- Claim/reuse: actual host claims detach queues before reuse; old record/object
  generations cannot target replacements. Notify visits exactly 1/8/32 affected
  waiters while 32 unrelated waiters remain parked.
- CarrierWaitService: a real blocked nanosleep registration retains a transport
  wake published before enrollment; the wake does not authorize nanosleep
  completion. Cancellation drains it and rejects late publication.
- Replay accepts the exact authority/scale trace and rejects changed authority
  generations or scale.

Historical setid source is exactly
`c1ea66b636998418fd1584f94cb184715aa065b4` (`800247419^`). In a detached scratch
worktree, `git checkout 800247419^ --
crates/carrick-kernel/src/kernel/operations/identity.rs` supplies the entire
unmodified old file. Seed 0, scale 1 fails with `LinuxErrno(11)` versus
`Returned { value: 0 }`. Restoring the current implementation passes. Retained
receipts under the example test fixtures include source/fixture hashes and
exact decision authority. Old source lacks the new credential points, so these
are paired historical receipts, not a claim of cross-source trace equality.

## Runtime exec admission: M3 handoff

The director confirmed this dependency on 2026-10-04. Fix `c1ea66b63` is in
`carrick-runtime/src/vcpu_loop/terminal.rs::CloneAdmissionGate` and
`thread_adoption.rs::adopt_thread_runtime`, not kernel ledger retirement.
Existing private witnesses are
`abi_first_entry_after_exec_close_cannot_acquire_a_runtime_owner` and
`abi_first_entry_before_terminal_close_remains_in_the_admission_drain`.

M3's real executor adapter must expose the existing process-owned gate's
close/enroll boundary and custody held from successful born-thread admission
through runtime registration, member enrollment and activation. Schedule exec
close before a delayed first entry, and the reverse ordering with admission
held during the terminal census. The independent process must stay admitted.
Emit typed events with exact task/thread/execution generation after gate unlock,
never suspend with `CloneAdmissionState` locked. Check out the exact pre-fix
runtime files from `c1ea66b63^` in a scratch worktree for the historical red.
Do not expose or implement a second gate.

The generic failed-lock adapter also remains an N1 dependency: expose one
failed acquisition as a dependency parked until the real unlock notification.
The current unlocked caller seams do not claim to model interior lock contention
or replace that adapter with polling.

## Batch 4 scheduler integration

Rebased M2 onto `origin/land/batch4` (`bb1c8bad0`), dropping the two
copied futex commits. The merged coordinator retains the version-3 portable
backend, per-actor/point visit map, address-indexed futex parking, recorded
wake-publication decisions and fail-closed rejection of external readiness.
Admission dependencies and passive authority observations remain graph-local.
Admission waiters are distinct from futex and dependency waiters; the real
reservation owner publishes release through the shared hook, naming the exact
waiter before the scheduler can grant that actor a permit. Condvar delivery
cannot add an actor to the runnable set.

The current futex and fixed setid receipts were re-recorded on the merged
source. The futex decision sequence is unchanged; the receipt's source hash
changes. Historical version-2 fd-pin receipts retain their original provenance
and remain deliberately rejected by the version-3 replayer.

The batch 4 setid red was re-run in `/tmp/vmfree-m2-batch4-red` at the
merged receipt commit, checking out only `800247419^`'s entire `identity.rs`.
The scratch file's Git blob matches the historical file exactly. Seed 0 at
scale 1 still returns `LinuxErrno(11)` and fails the expected return 0
assertion. The historical receipt was re-recorded with generator version 3
and the merged surrounding source. The current fixed receipt records return
0 for the same fixture and seed. Scratch build artifacts use a separate target
directory so they cannot leave root build-script paths pointing at a removed
worktree.
