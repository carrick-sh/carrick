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

## Fork stage-1 image example

`kernel.fork.stage1-image` is the first contract whose structural budget lives
entirely in the VMM layer. Every forked child owns a private stage-1
page-table software image (a 1.75 MiB arena set) for its lifetime; `ltp-fork14`
creates 16k children this way, and allocating a fresh image per fork produced
~28 GiB of host `mmap`/`madvise(MADV_FREE_REUSABLE)` churn. The fixture is
`forkserial <n>`: `n` serial fork/`_exit(0)`/`waitpid` rounds from one parent.

- Linux authority: `man 2 fork`, `man 2 wait4`. Every child exits 0 and each
  `waitpid` returns its own child's pid.
- Structural invariant: `task_admissions` is exactly one per fork, and
  `page_table_image_allocations` (fresh image allocations, counted where the
  parent clones its image for the child) is bounded by the number of
  concurrently live child images, `2 + 0·n`, never by the fork count. Retired
  images return to the process tree's bounded `Stage1ImagePool` and the next
  fork clones into a recycled buffer. `host_mapping_allocations` (fresh host
  `mmap`s for the child's per-mm backing) is `0 + 1·n`: the root tables come
  from the carrier's pre-mapped root-slot pool and only the child's private
  EL1 kernel-state page is still a per-fork host mapping.
  `fork_projection_rows_visited` is `32 + 24·n`: the COW projection scans the
  process's own rows, and rows superseded by earlier COW splits (the parent's
  post-fork stack and data writes) are pruned before the scan, so the work per
  fork never grows with the forks already performed (before the prune the
  fixture visited 15455 rows at 128 forks; after it, 2430).
- Layers: the VM-free binding has no stage-1 projection, so it proves the
  semantics and the admission budget and reports the image metric as an
  exact zero. The signed embed structural binding runs the probe on the
  runtime's own work scope at 1, 8, 32 and 128 forks. The timing binding reads
  the probe's per-fork p50 from an uninstrumented signed run against the
  pinned same-image Docker measurement recorded beside the binding.
- Status (2026-09-20): structural bindings green at 1/8/32/128. The timing
  binding is red: 205 µs per serial fork under the signed carrier versus
  88 µs under Docker (2.33x against the 2.0x policy), and `ltp-fork14` sits at
  3.7x (6.0 s versus 1.6 s; it was 15.4x), `ltp-epoll-ltp` (the same serial
  fork shape: 12,468 clone/exit/wait rounds) at 3.5x from 11.5x, and
  `ltp-fork09` at 1.6x from 3.2x. The root-slot pool is now created at VM
  creation and an exec'd image's root table is drawn from it too, so the
  `sh -c` launch shape every harness LTP row uses no longer pays a 2 MiB host
  `mmap` per fork (the `via_shell` structural binding proves it). Named
  remaining levers: the executor boundary audit issues about five
  `pthread_sigmask` and four `thread_selfusage` host calls per fork, and the
  parent's post-fork COW splits cost about 15% of carrier CPU. The timing
  gate stays red until the ratio meets policy; it is not widened.
- A pre-mapped carrier pool owns its whole IPA range. Once the root-slot pool
  is created at VM creation, every consumer of that arena — a forked child's
  root table, an exec'd image's root table, and a live stage-1 extension
  arena — must take its slot from the pool, and a retiring owner must hand
  the slot back at its retirement proof rather than at its last reference.
  A missed consumer maps private backing over the pre-map, and that
  `HV_ERROR` reaches the guest as a SIGSEGV: CPython's
  `test_compiler_recursion_limit` died that way while Docker passed. The
  `pagetablegrow` probe and the `kernel.fork.stage1-image` bindings are the
  standing guards; `scripts/dtrace/hvpatch-stage1-faults.d` names the exact
  refused mapping when one slips through.
