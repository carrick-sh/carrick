# Conformance contracts

Carrick treats Linux semantics and non-pathological operational complexity as
one correctness obligation. A syscall that returns the expected value by
polling, copying unbounded data, serializing unrelated work, or using a worse
complexity class is not conformant.

This guide is normative for every change that can affect guest-visible behavior
or cost. Use the
[`carrick-conformance-contract`](../.agents/skills/carrick-conformance-contract/SKILL.md)
skill before planning or implementation.

## Definition of correctness

A guest-visible operation is correct only when all applicable claims hold:

- return values, errors, ordering, blocking, wakeups, and lifecycle match Linux;
- host work follows the intended bounded complexity and resource amplification;
- signed execution preserves those properties through guest memory, scheduling,
  signals, carrier lifecycle, and the active VMM; and
- end-to-end performance stays inside the accepted same-workload Docker ratio.

A semantic pass cannot excuse a structural or timing failure. A valid completing
case at or above 10x Docker returns immediately to correctness triage. A case
that finishes exactly on its timeout budget is a hang or refusal, not a timing
sample.

## Evidence ladder

Use the cheapest layer that can prove the claim, then add higher-layer evidence:

1. Compile-time ABI checks prove byte layouts and static invariants.
2. `just test-kernel` proves VM-free kernel semantics and deterministic work.
3. Signed `carrick-embed` proves real guest execution and runtime integration.
4. Pinned same-image Docker supplies Linux output and timing authority.
5. CLI, probe, and ecosystem gates prove composition and release acceptance.

Higher layers add evidence; they never turn a lower-layer failure green. The
VM-free backend cannot prove guest instruction execution, page-table projection,
guest signal handlers, or VMM behavior, so contracts name unsupported layers
explicitly rather than implying coverage.

Routine reduction uses committed, source-hash-validated Docker results. Refresh
the oracle deliberately, with every Carrick phase stopped before Docker starts.
Never run Carrick and Docker concurrently.

## Contract descriptor

Every contract has a stable ID and records:

- the guest surfaces it owns;
- Linux semantic authority;
- exact fixture and scale points;
- VM-free, signed embed, Docker, and optional ecosystem bindings;
- structural budgets and their architectural rationales; and
- the applicable runtime ratio and statistic.

Scenario implementations remain typed Rust. The descriptor links different
proofs; it does not pretend that a scripted dispatcher trace and a guest ELF are
the same execution.

Each completed runner emits an observation containing the contract ID, layer,
source revision, fixture identity, semantic assertions, structural snapshot or
timing distribution, and measurement completeness. Missing identities, unknown
counters, overflow, dropped events, or absent required bindings fail closed.

## Work budgets

The VM-free loop uses deterministic units rather than elapsed time. The initial
taxonomy covers dispatch and redispatch, continuation enrollment/park/wake/resume,
guest-memory bytes, backend calls, VFS visits, page-table work, backing
allocation, task/vCPU transitions, and subsystem-specific stable units.

Budgets have three forms:

- Exact: `guest_memory_copy_bytes == 0`.
- Upper bound: `host_backend_calls <= 2`.
- Affine scaling: `queue_visits(n) <= base + per_unit * n`.

Use at least three deterministic scale points for a scaling claim. Prefer a
formula justified by the intended algorithm over a fixed ceiling that allows a
small fixture to hide quadratic behavior.

Counters are scoped to one kernel graph, container, or execution generation.
Never infer them from process-global deltas. Instrumented structural runs do not
supply timing evidence. Timing runs use an uninstrumented release build and do
not claim structural completeness.

## Failure classes

Contract evaluation reports one of these typed failures:

- `SemanticMismatch`: Linux-visible output or ordering differs.
- `WorkBudgetExceeded`: an exact or upper-bound work limit failed.
- `ScalingViolation`: the smallest failing scale exceeded its formula.
- `IncompleteMeasurement`: required evidence is missing, dropped, or unknown.
- `FixtureMismatch`: source, image, probe, lane, or oracle identity differs.
- `RuntimeRatioExceeded`: the selected distribution statistic exceeds policy.
- `UnsupportedLayer`: a required layer has no approved binding.

An absent binary, missing oracle, unknown counter, or unsupported unregistered
layer is not a skip.

## Red-first workflow

1. Read `AGENTS.md`, this guide, the active controller, and the applicable
   contract.
2. State the Linux semantic authority and Carrick structural invariant.
3. Add or extend the cheapest capable binding.
4. Run it against the known-bad implementation and retain the semantic or
   structural failure.
5. Fix the underlying ownership, algorithm, or lifecycle seam.
6. Rerun the focused contract and `just test-kernel`.
7. Run the signed embed binding and applicable Docker differential.
8. Promote the same final signed artifact through probe, smoke, and full gates.
9. Record exact receipts, cleanup, and every higher-layer gate still open.

A generated schedule records its seed and shrinks to a deterministic regression.
A timing-only regression first needs a semantic or structural reduction; a wider
timeout is not a reduction.

## Changing a budget

Budget changes are architecture reviews, not baseline refreshes. Increasing or
removing a limit requires a rationale explaining why the intended algorithm
changed, red evidence proving the old contract is no longer the right one, and
fresh evidence for every applicable layer. A measurement tool may refresh
observations; it must never rewrite a limit.

Do not close a failure with retries, longer timeouts, reduced concurrency,
polling, symptom serialization, or an instrumented timing comparison.

## Exemptions

Only changes proven not to alter guest-visible behavior or cost qualify:

- byte-identical moves;
- comments and documentation;
- mechanical generated-inventory rebinding; or
- host-only code outside the guest execution path.

An exemption names exact paths, revisions, affected contract families, and the
reason no semantic or work expectation changed. Broad globs and statements that
performance is out of scope are invalid. If classification is uncertain, add or
run the contract.

## Commands

Use the repository recipes; they preserve signing, serialization, and test
partitioning:

```sh
just test-kernel
just test
just ci

just test-embed
just conformance-probes
just --no-deps conformance smoke
just --no-deps conformance
```

The final three promotion rungs use one exact signed artifact. Record source
HEAD, SHA-256, CDHash, LC_UUID, hypervisor entitlement, `__dof_carrick`, and
run-ID-scoped cleanup. A focused contract proves only its named family; it does
not close the frozen suite or ecosystem denominator.

## Futex example

`kernel.futex.contention` is the first vertical contract. Its VM-free binding
checks exact wake cardinality, no lost wake, one continuation enrollment and
park per blocking episode, no redispatch while parked, and queue work
proportional to affected waiters rather than historical population. It runs at
1, 8, 32, and 128 waiters.

The signed binding reuses Carrick's futex probes to prove guest execution. A
separate uninstrumented release run compares the pinned futex distribution with
same-image Docker. The existing tests remain until the contract has demonstrated
equivalent or stronger failure detection.
