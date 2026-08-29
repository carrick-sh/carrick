# Task Participant Witnesses and Executor Identity Census

**Date:** 2026-08-28

**Status:** Approved design; awaiting written-spec review

**Design-time source:** `d294262103193c453f9c6760e15c7042e9baf867`

**Controlling audits:**
[`identity-and-scope-domains.md`](../../identity-and-scope-domains.md) item 1 and
[`runtime-abstraction-audit-2026-08-27.md`](../../runtime-abstraction-audit-2026-08-27.md)
Part 2 item 3

## Goal

Make every remaining thread-population decision name exact participant
identities and the purpose for which those identities were selected. Delete raw
population arithmetic from production fork, crash, core, thread-exit, and
stage-1 pause authority without adding a second lifecycle state beside the
kernel's existing `ThreadExecutionState`.

This milestone completes the population/lifecycle requirement of the runtime
abstraction audit. It does not complete the audit's separate foreign-MM or
structural lock-order requirements.

## Current authority and the remaining defect

Carrick already has the explicit lifecycle type the 2026-08-16 identity audit
requested. `ThreadExecutionState` is scheduler-owned and records
`Uninitialized`, `Runnable`, `Running`, `SwitchingOut`, `Blocked`, `Exited`, and
`Failed` with generation and executor identity where applicable. It must remain
the sole run-state authority. A second `ThreadRunState` would duplicate
transitions and recreate the drift this milestone is meant to prevent.

The remaining production decisions are still scalar or untyped:

- process fork uses `Task::threads().len().saturating_sub(1)`;
- crash barrier admission uses `Task::threads().len() > 1`;
- core diagnostics convert `Task::threads().len()` directly into a probe count;
- non-final thread exit uses `Task::live_thread_count() <= 1`;
- crash quorum iterates the generic `Task::threads()` projection; and
- `GuestExecutorCensus` stores an `AtomicUsize`, exposes `live() -> usize`, and
  decides page-table quiescence with `live() > 1`.

These expressions happen to answer today's cases, but their types do not say
which population they represent. They allow a future author to substitute live
vCPU leases for durable task membership, task membership for crash responders,
or an executor count for logical thread identity while the code continues to
compile.

## Governing invariants

1. `ThreadExecutionState` is the only kernel thread run-state type. This change
   projects that authority; it does not mirror it.
2. Every population value is purpose-specific. There is no public or
   crate-visible generic `TaskParticipants` wrapper.
3. Every authoritative population retains exact `ThreadKey` identities. A
   boolean decision may be exposed, but it must be derived from that identity
   set rather than a stored scalar.
4. No witness exposes `usize`, implements `Len`, `Sub`, `Deref` to a collection,
   or supports comparison with an integer.
5. Numeric population values are allowed only as named observability
   projections at the final probe boundary. They never authorize behavior.
6. Fork and crash barriers use durable task membership, including blocked or
   currently lease-less siblings, because those siblings may wake while the
   transaction is active.
7. Crash register collection remains dynamic. It re-mints its purpose-specific
   roster on every poll so a retired thread stops being owed and a current live
   participant is never silently omitted.
8. Stage-1 pause authority uses active or admitting executor participation,
   including the pre-registry interval. It does not use durable task membership
   or current registry leases.
9. Guest-executor admission remains census-before-registry. Failed census
   admission performs no registry publication.
10. Crash-safe-point participation remains RAII and shares the exact lifetime
    of an admitted guest-executor quantum. Raw set/clear calls are not production
    APIs.
11. A missing exact owner or departing `ThreadKey` fails closed with a typed
    error. It is never interpreted as an empty peer set.
12. Production source gates reject the deleted scalar shapes so the old defect
    cannot return under a new spelling.

## Task-minted witness types

`Task` mints separate opaque types from one lock acquisition over its
authoritative thread map. The implementations may share a private helper that
copies exact keys, but no generic helper type escapes `objects.rs`.

### `ForkBarrierParticipants`

```rust
pub(crate) fn fork_barrier_participants(
    &self,
    owner: ThreadKey,
) -> Result<ForkBarrierParticipants, TaskParticipantError>;

impl ForkBarrierParticipants {
    pub(crate) fn requires_quiesce(&self) -> bool;
    pub(crate) fn contains_sibling(&self, key: ThreadKey) -> bool;
}
```

The exact owner must be a current task member. The witness contains every other
current `ThreadKey`, regardless of execution state. `requires_quiesce()` is true
exactly when that identity set is non-empty. The witness is consumed only by
the process-fork barrier decision; it is not reused by crash or exit.

### `CrashBarrierParticipants`

```rust
pub(crate) fn crash_barrier_participants(
    &self,
    fatal_owner: ThreadKey,
) -> Result<CrashBarrierParticipants, TaskParticipantError>;

impl CrashBarrierParticipants {
    pub(crate) fn requires_quiesce(&self) -> bool;
    pub(crate) fn contains_sibling(&self, key: ThreadKey) -> bool;
}
```

This has the same current selection rule as the fork witness but remains a
different type. That duplication is deliberate: a future crash-specific rule
cannot silently alter fork semantics, and vice versa.

### `ThreadExitParticipants`

```rust
pub(super) fn thread_exit_participants(
    &self,
    departing: ThreadKey,
) -> Result<ThreadExitParticipants, TaskParticipantError>;

impl ThreadExitParticipants {
    pub(super) fn permits_nonfinal_exit(&self) -> bool;
    pub(super) fn contains_survivor(&self, key: ThreadKey) -> bool;
}
```

The witness authenticates the exact departing identity and retains every other
current member. A non-final thread exit is permitted only when at least one
survivor identity exists. Task-exit remains the only path for the final member.

### `CrashCaptureParticipants`

```rust
pub(crate) fn crash_capture_participants(&self) -> CrashCaptureParticipants;

impl CrashCaptureParticipants {
    pub(crate) fn into_threads(self) -> impl Iterator<Item = ThreadRef>;
}
```

This projection retains `ThreadKey -> ThreadRef` identity and is minted anew on
every `CrashQuorum::poll`. The quorum remains responsible for interpreting
`CrashRegisterVote`, crash-safe-point participation, and parked registers. The
roster type only prevents it from accepting the generic all-thread vector.

### `CoreNoteParticipants`

```rust
pub(crate) fn core_note_participants(&self) -> CoreNoteParticipants;

impl CoreNoteParticipants {
    pub(crate) fn required_note_count_for_probe(&self) -> u64;
}
```

This witness retains exact live identities. Its sole numeric method is named
for the final observability boundary and performs checked conversion with the
existing saturating fallback. It may not be used for barrier admission, quorum
completion, or control flow.

### Typed owner failures

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TaskParticipantError {
    #[error("thread {thread:?} is not a current member of task {task:?}")]
    UnknownThread { task: TaskKey, thread: ThreadKey },
}
```

Fork and crash map this into their existing typed runtime error paths. Thread
exit maps it to `KernelOperationError::UnknownThread`. No new raw abort is
needed for caller-controlled or stale identity.

## Identity-aware guest-executor census

The stage-1 census is a different population from task membership and cannot be
replaced with a `Task` witness. It nevertheless must stop being scalar.

`GuestExecutorCensus` stores an exact identity set under its existing
process-local authority:

```rust
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum GuestExecutorIdentity {
    Thread(ThreadKey),
    Anonymous(NonZeroU64),
}

struct GuestExecutorCensusState {
    participants: BTreeSet<GuestExecutorIdentity>,
    next_anonymous: u64,
}
```

Canonical HVPatch participation always uses `Thread(ThreadKey)`. The anonymous
variant preserves the non-kernel-thread adapter and hermetic tests without
pretending an executor slot is a Linux identity; each anonymous admission gets
one never-reused process-local token.

`GuestExecutorCensus::enter` returns
`Result<GuestExecutorParticipation, GuestExecutorCensusError>`. Duplicate exact
thread admission and anonymous-token exhaustion are typed failures. The guard
owns the exact identity and removes that identity on drop. A missing identity at
drop is an internal carrier invariant and is classified in the abort ledger.

`live() -> usize` is deleted. Authority becomes:

```rust
pub fn has_peer_executor(&self) -> bool;
pub(crate) fn participant_count_for_probe(&self) -> i32;
```

`has_peer_executor` asks whether the identity set contains more than the caller
represented by the current admitted quantum; it does not expose the scalar.
`participant_count_for_probe` is the only numeric projection and exists solely
to preserve the four-position `pt-pause-begin` probe ABI.

## Crash-safe-point RAII

`Thread::enter_crash_safe_point_participation` becomes a minting operation over
`Arc<Thread>` and returns a non-cloneable `CrashSafePointParticipation` guard.
The guard is stored inside `GuestExecutorParticipation`; its `Drop` clears the
thread flag. Direct `leave_crash_safe_point_participation` is private to the
guard and retirement cleanup.

`GuestExecutorParticipation::drop` preserves the current publication order:
first clear crash-safe-point participation, then remove the exact executor
identity from the census. This keeps crash collection from waiting for a
quantum that has already ceased to participate.

The existing `ThreadExecutionState` continues to describe runnable, running,
blocked, terminal, and failed lifecycle. Crash-safe-point participation remains
an orthogonal capability: a blocked thread may have parked registers, while a
published but never-started thread is `Uninitialized` and never claims the
guard.

## Consumer migrations

The migration is complete only when production code contains none of these
authority shapes:

```text
task().threads().len()
task.threads().len()
live_thread_count()
GuestExecutorCensus::live
census.live()
```

The required replacements are:

- `vcpu_loop/quiesce.rs`: `ForkBarrierParticipants::requires_quiesce`;
- `vcpu_loop/mod.rs`: `CrashBarrierParticipants::requires_quiesce`,
  `CoreNoteParticipants::required_note_count_for_probe`, identity-census entry,
  and the named probe-only census projection;
- `kernel/operations.rs`: `ThreadExitParticipants::permits_nonfinal_exit`;
- `kernel/crash_capture.rs`: freshly minted
  `CrashCaptureParticipants::into_threads` on every poll; and
- tests and source-contract assertions: semantic witness names rather than old
  source strings.

Test-only cardinality assertions may inspect purpose-specific test helpers, but
production APIs and production source may not recover generic counts.

## Mechanical enforcement

Add a fail-closed checker under `scripts/migrate/` and wire it into
`just lint-domains`. It scans production Rust leaves, not comments or tests, and
rejects:

- raw `.threads().len()` or `.threads().iter().count()` control decisions;
- production calls to `live_thread_count`;
- a `GuestExecutorCensus` scalar storage field or `live() -> usize`; and
- reintroduction of direct crash-safe-point set/clear calls outside their
  owning module.

The checker includes negative fixtures for every rejected shape and positive
fixtures for each named witness and probe-only projection. A baseline is not
appropriate: this milestone deletes every accepted production occurrence.

## TDD and milestone sequence

1. Commit source-contract RED tests that fail on the current scalar shapes.
2. Commit kernel RED tests for exact owner authentication, sibling identity,
   non-final exit, dynamic crash roster refresh, duplicate executor admission,
   unwind cleanup, and probe-only cardinality saturation.
3. Implement the Codex-owned witness types in `kernel/objects.rs`, the identity
   census and crash RAII in `kernel/guest_execution.rs`, and the dynamic roster
   seam in `kernel/crash_capture.rs`.
4. Integrate and verify the thread-exit consumer in `kernel/operations.rs`.
5. Delegate the file-disjoint fork consumer migration
   (`vcpu_loop/quiesce.rs` plus its source-contract assertions) to one isolated
   Antigravity worktree.
6. Delegate the file-disjoint crash/core/probe migration (`vcpu_loop/mod.rs`)
   to a second isolated Antigravity worktree.
7. Codex reviews both actual diffs, reruns their exact gates, and sends findings
   back to the same conversations for at most three repair rounds.
8. Run focused tests, `fmt-check`, `clippy`, `lint-domains`, `doc`, `test`, and
   `test-integration`. Record any known host-authority position-only drift as
   `changed=[]`; do not rebaseline unrelated inventory.
9. Obtain independent review, record the partial runtime-audit receipt, and
   fast-forward the independently reviewed GREEN milestone to `main`.

## Delegation boundaries

Codex owns all architecture, public/crate-visible interfaces, kernel object
state, errors, RAII lifetimes, source gate, acceptance tests, and final review.
Antigravity receives only the two named consumer migrations after the interfaces
and RED tests are committed. Workers may not alter `kernel/objects.rs`,
`kernel/guest_execution.rs`, `kernel/crash_capture.rs`, audit documents, or the
source checker. If a consumer cannot compile without an interface change, the
worker reports the exact need and stops rather than inventing an API.

## Acceptance criteria

The milestone is complete only when all of the following are true on one exact
reviewed commit:

1. Every production population decision listed above uses its named witness.
2. `GuestExecutorCensus` stores identities and exposes no authority-bearing
   scalar count.
3. `ThreadExecutionState` remains the sole run-state authority; no parallel
   lifecycle enum exists.
4. Fork and crash barriers include blocked and lease-less durable siblings.
5. Crash quorum dynamically re-reads exact current membership and preserves
   published votes, withdrawals, parked-register fallback, and retirement.
6. Thread exit cannot retire the exact final member or accept a stale identity.
7. Census admission remains before registry publication and every unwind or
   suspension removes the exact participant once.
8. The four-position page-table pause probe ABI is unchanged and its numeric
   population is observability-only.
9. The new source gate fails on every old shape and passes the final tree.
10. All focused and repository-wide gates have exact recorded outcomes.
11. Both Antigravity migrations pass Codex review and any findings are repaired
    through their original conversations.
12. Independent review is green and `main` is fast-forwarded to the exact
    milestone commit with `main...canonical` equal to `0 0`.

