# Atomic Exec-to-Terminal Handoff Design

**Date:** 2026-09-01

**Status:** Approved.

**Extends:** [`2026-08-30-carrier-concurrency-and-syscall-interception-design.md`](2026-08-30-carrier-concurrency-and-syscall-interception-design.md) and the Task 4 implementation in [`../plans/2026-08-30-typed-syscall-interception.md`](../plans/2026-08-30-typed-syscall-interception.md).

## Goal

Close the final Task 4 race without adding a second synchronization protocol or
unmeasured overhead. A suspended exec that fails during resume must transfer its
exact clone-admission close directly into process-terminal ownership. No other
exec, fork, clone, or exit may observe an open admission window; the original
error must remain the terminal result; and the transition must not poison later
terminal ownership.

The implementation must be demonstrated by real observations:

1. deterministic, channel-driven concurrency tests that observe the competing
   exec at the exact handoff boundary; and
2. release-mode paired performance measurements tied to exact source and binary
   identities.

## Defect Being Closed

`PreparedExecve` retains an `ExecCloneAdmission`. On a fallible pending-exec
resume boundary, `take_pending_exec_terminal_context` currently drops that
owner before `begin_persistent_process_terminal` calls
`try_claim_persistent_process_exit`.

Dropping the owner changes `CloneAdmissionClose::Exec` to `None`. A competing
exec can acquire the gate in that interval. The failing thread then first wins
the separate `persistent_exit_owner` atomic but subsequently observes the new
exec close and receives `ProcessExitClaim::LostToExec`. That path converts the
original runtime error into successful `ThreadDone` and leaves the atomic exit
owner claimed by a thread that did not become terminal owner.

The deeper problem is dual authority: terminal identity lives in an atomic,
while clone-admission closure lives behind a mutex. No ordering between them can
make a destructor-driven `Exec -> None -> Exit` sequence atomic.

## Decisions

| Question | Decision |
| --- | --- |
| Terminal-owner authority | `CloneAdmissionGate` is the single authority for both admission closure and process-terminal ownership. |
| Exit state | `CloneAdmissionClose::Exit { owner: ThreadId }`; the owner is protected by the existing gate mutex. |
| Old atomic | Remove `KernelState::persistent_exit_owner`. |
| Exec failure handoff | Consume the exact `ExecCloneAdmission` and replace its matching `Exec { owner, generation }` state directly with `Exit { owner }` while holding the gate mutex. |
| Normal process exit | Claim or retry `Exit { owner }` under the same mutex; never publish an owner before checking for an active exec. |
| Pending exec ownership | Extract a typed terminal handoff from `PreparedExecveDrain`; do not drop its exec-admission owner at the error boundary. |
| Error preservation | The original pending-exec error remains `PersistentTerminal::Error`; a genuine invariant mismatch fails closed and reports both the original and handoff errors. |
| Hot-path cost | No allocation, clock read, probe emission, measurement callback, wait, or additional lock acquisition in the production handoff; existing gate listeners are notified only when already registered. |
| Performance proof | Release-mode host reducer, paired ABBA comparison, exact commit and executable identity, no concurrent guest/Docker workload. |

## State Model

The gate retains its existing mutex, condition variable, generation, in-flight
count, and listener epoch. Only the close state changes:

```rust
enum CloneAdmissionClose {
    Exec { owner: ThreadId, generation: u64 },
    Fork { owner: ThreadId, generation: u64 },
    Exit { owner: ThreadId },
}
```

The following transitions are valid:

```text
None ------------------------------------> Exec(owner, generation)
None ------------------------------------> Fork(owner, generation)
None ------------------------------------> Exit(owner)
Fork(owner, generation) -----------------> Exec(other, same generation)
Fork(owner, generation) -----------------> Exit(exit_owner)
Exec(owner, generation) -- exact owner --> Exit(owner)
Exit(owner) ------------------------------> Exit(owner)       (retry)
```

These transitions are rejected:

```text
Exec(owner, generation) -- generic exit --> LostToExec
Exec(owner, generation) -- other exec ----> error
Exit(owner) ------------ -- other owner --> AlreadyOwned
Exit(owner) ------------ -- exec/fork ----> admission closed
```

There is no `Exec -> None -> Exit` transition. Ordinary `ExecCloneAdmission`
drop still reopens admission for a recoverable exec failure that returns to the
old image. The new consuming handoff changes the state to `Exit { owner }`
before the guard is destroyed, so its `Drop` implementation becomes a no-op.

## Typed Ownership

`PreparedExecveDrain` already owns the prepared image, sibling drain,
completion ownership, and the nested `ExecCloneAdmission`. It gains a consuming
operation that separates terminal authority from resources that must roll back:

```rust
pub(super) struct ExecTerminalHandoff {
    clone_admission: ExecCloneAdmission,
}

impl PreparedExecveDrain {
    pub(super) fn into_terminal_handoff(self) -> ExecTerminalHandoff;
}
```

The operation drops or rolls back the prepared image, sibling-drain owner, MM
reservation, and syscall completion ownership while retaining the exact
clone-admission guard. It must not fabricate a syscall return or leave a guest
completion token in `ThreadRuntimeState`.

The pending phase extraction returns both authorities:

```rust
struct PendingExecTerminal {
    context: crate::kernel::KernelContext,
    handoff: ExecTerminalHandoff,
}
```

`ProductionHvpatchLoopPoll::poll` passes this value to a dedicated terminal
entry that performs the exact handoff before running any fallible terminal
suffix.

## Gate Operations

### Generic exit claim

`CloneAdmissionGate::try_claim_process_exit(owner)` performs the entire claim
under `state.lock()`:

- `Exec { .. }` returns `LostToExec` without recording an exit owner.
- `Fork { .. }` and `None` become `Exit { owner }`.
- `Exit { owner: same }` is an idempotent retry.
- `Exit { owner: other }` returns `AlreadyOwned`.
- the result is `Owner` when `in_flight == 0`, otherwise `Pending`.

`KernelState::try_claim_persistent_process_exit` delegates to this operation.
It sets `process_exiting` only for `Owner`. The removed atomic can no longer be
poisoned by a `LostToExec` result.

### Exact exec-to-exit handoff

`ExecTerminalHandoff::claim_process_exit` consumes itself and locks the same
gate. It validates all of the following before changing state:

- the gate pointer is the one captured by the guard;
- `closing` is exactly `Exec { owner, generation }` from the guard; and
- the terminal claimant is that same `owner`.

It then writes `Exit { owner }`, increments the change epoch exactly once,
notifies existing listeners/condition waiters exactly once, and returns
`Owner` or `Pending` from the existing `in_flight` count. It never stores
`None` and never reacquires the mutex.

The exact exec close has already drained clone permits before it is returned,
so production should normally receive `Owner`. Retaining the `Pending` result
keeps the state machine correct if admission mechanics evolve; it follows the
existing terminal retry path without reopening admission.

## Terminal Entry and Error Semantics

`begin_persistent_process_terminal` is split into:

1. a generic claimant used by ordinary exit, fatal signal, and non-exec
   internal errors; and
2. an exec-handoff claimant that consumes `PendingExecTerminal`.

Both feed one common terminal suffix after producing a typed
`ProcessExitClaim`. The suffix remains responsible for owner settlement,
sibling drain, core/fatal selection, MM retirement, runtime withdrawal, and
result publication.

For an exec-resume error:

1. retain the exact `KernelContext`;
2. extract `ExecTerminalHandoff` without dropping clone admission;
3. atomically convert the exact exec close to the same owner's exit close;
4. restore only the context needed by terminal cleanup;
5. enter the common terminal suffix with `PersistentTerminal::Error(original)`;
6. publish no guest syscall return or compatibility return.

An exact-owner or generation mismatch is an internal authority violation, not
a recoverable guest error. The runtime logs the original error and transition
failure and fails closed rather than guessing which owner may tear down the
process.

## Concurrency Observations

Correctness tests use channels and barriers, never sleeps or scheduler luck.
The test seam invokes a closure after the exact exec state has been validated
and while the gate mutex remains held. The closure releases a competing exec
thread, waits until that thread has attempted gate acquisition, then permits
the handoff to publish `Exit { owner }` and unlock.

The observation must prove:

- the contender cannot acquire `Exec` during the handoff;
- after unlock it observes `Exit { owner }` and is rejected;
- no clone or process-fork permit is admitted;
- a generic exit from another owner reports `AlreadyOwned`, not `LostToExec`;
- the original pending-exec error is the terminal result;
- `persistent_exit_owner` no longer exists;
- guest and internal-control exec completion ownership are consumed once;
- no syscall/compat return is published; and
- terminal settlement and later retries retain the same owner.

The production-path test drives `ProductionHvpatchLoopPoll::poll` through an
injected pending-resume failure. A lower-level gate test exhaustively covers
normal exit, fork-to-exit, exec-to-exit, same-owner retry, different-owner loss,
and guard drop after transfer.

## Performance Design and Measurement

### Production cost constraints

The normal terminal claim currently performs an atomic compare-exchange and
then locks `CloneAdmissionGate`. The new design performs only the existing gate
lock and state match. The exec-error handoff performs one gate lock, one exact
state comparison, one state write, and the existing notification. It adds no
work to ordinary syscall dispatch, successful exec, fork, or clone admission.

The implementation must not add:

- `Arc` cloning or heap allocation inside either claim operation;
- `Instant::now`, logging, USDT emission, or event-ring writes on the measured
  production path;
- a second mutex or atomic ownership field;
- a blocking wait while holding the gate mutex; or
- an extra listener notification relative to the state change.

### Host reducer

A test-only release reducer exercises two operations with a reused gate and no
guest/VMM startup:

1. uncontended generic `None -> Exit(owner)` claim plus test-only reset; and
2. closed `Exec(owner, generation) -> Exit(owner)` terminal handoff plus
   test-only reset.

The reducer performs five warm-up samples followed by thirty measured samples
of at least 100,000 transitions each. It emits machine-readable JSONL with
operation name, iteration count, elapsed nanoseconds, nanoseconds per
transition, and contender rejection counts. Test-only reset and observation
helpers are excluded from the timed interval.

### Paired comparison

The reducer is first committed and run against the still-broken ownership
implementation to establish the baseline shape. After the fix, the same
logical operations are measured from an isolated checkout in ABBA order:

```text
baseline A -> fixed B -> fixed B -> baseline A
```

Every arm records:

- source commit;
- executable SHA-256 and Mach-O UUID;
- Rust toolchain, host OS/build, architecture, and CPU model;
- exact command and reducer parameters;
- foreign Carrick/Docker/benchmark process census; and
- raw samples plus median and p95.

Carrick guests and the Docker oracle do not run concurrently with these arms.
An arm with foreign workload, thermal/power-mode change, sample cardinality
drift, or executable-identity mismatch is invalid and rerun.

Acceptance requires:

- fixed generic-claim median no worse than 1.05x the paired baseline median;
- fixed generic-claim p95 no worse than 1.10x the paired baseline p95;
- no unbounded tail or lock convoy in the contended handoff observation;
- zero successful competing exec admissions during the handoff; and
- a checked-in receipt under `docs/perf-results/` that clearly labels this as
  a host state-machine measurement, not guest workload or <=2x Docker proof.

If the timing threshold fails, the change is not accepted merely because the
race test is green. The reducer is profiled or the ownership design is revised.

## Validation Gates

Validation proceeds in this order:

1. red-first deterministic competing-exec test against the broken code;
2. focused gate state-machine tests;
3. focused production pending-exec error tests for guest and internal-control
   origins;
4. release ABBA host reducer and evidence receipt;
5. `just fmt-check`;
6. focused `RUST_TEST_THREADS=1` runtime tests;
7. complete serialized runtime library tests;
8. `just clippy`, `just lint-domains`, and `just ci` as repository state permits;
9. independent task review of the exact remediation range.

These are host state-machine and performance observations. They are not signed
guest/HVF, KVM, bhyve, NVMM, Docker-oracle, conformance, or shipped-performance
proof. Those remain in the original plan's later closure tasks.

## Scope

Expected implementation files:

- `crates/carrick-runtime/src/vcpu_loop/mod.rs`
- `crates/carrick-runtime/src/vcpu_loop/exec.rs`
- one focused host measurement runner under `scripts/perf/`
- one machine-readable evidence receipt under `docs/perf-results/`

The change does not redesign general exec, process teardown, MM retirement,
interceptor APIs, carrier APIs, or guest-visible behavior beyond preserving the
correct original terminal error. Task 5 remains blocked until this remediation
passes review.
