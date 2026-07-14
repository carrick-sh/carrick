# Native Default Conformance and Performance Handoff

Date: 2026-07-14

Integration state: `codex/native-conformance-quality` was fast-forwarded onto
`main` from `3cb0c7b8` through `8941ee5a` (48 commits). The branch worktree is
intentionally retained because it contains an interrupted, uncommitted second
review-fix wave described below.

## Goal and honest status

Make the Darwin-native backend the quality-first default, run the same real
conformance and workload ladders expected of the release backend, remove
stability/load blockers, and reach a full measured bless. HVF/VMM performance
is out of scope. Native performance is correctness: a workload that is tens or
hundreds of times slower than the Linux oracle is not ready to bless.

**Current status: NOT BLESSED.** Prepared-image/self-reexec correctness has
advanced substantially and Node content parity is green, but Task 8 stopped on
a pathological Go compiler/import workload. The performance measurement
interlude has a reviewed profiler and a substantial runner/analyzer, but its
second independent review remains rejected. No Task 3 measurement campaign has
run and no optimization slice has been selected.

Authoritative tracked documents:

- [native-default campaign ledger](docs/native-default-conformance-campaign.md)
- [prepared-image implementation plan](docs/superpowers/plans/2026-07-13-native-prepared-image-reexec.md)
- [prepared-image design](docs/superpowers/specs/2026-07-13-native-prepared-image-reexec-design.md)
- [compiler performance budget design](docs/superpowers/specs/2026-07-14-native-compiler-performance-budget-design.md)
- [compiler performance measurement plan](docs/superpowers/plans/2026-07-14-native-compiler-performance-measurement.md)

The detailed controller ledger is local and git-ignored at
`.superpowers/sdd/progress.md`. The Task 8 evidence report is retained in the
feature worktree at
`.worktrees/codex-native-conformance/.superpowers/sdd/task-8-report.md`.

## Measured correctness ladder

| Rung | Current authority |
| --- | --- |
| Artifact/signing and exact prepared-image reducers | GREEN; 431 musl and 431 GNU native-PIE probes rebuilt, signed binary verified, exact static/dynamic/shebang/fd/process-state/fork-exec-thread reducers green |
| Complete native probe gate | 372 PASS / 9 FAIL initially; three state-restoration failures fixed; six deliberate post-fork-without-exec pthread-guard gaps remain |
| Node full ecosystem | 3/3 content MATCH; Carrick/Docker ratios 29.33x, 23.01x, and 18.96x |
| Go full ecosystem | INCOMPLETE; first run reached row 99/194, then exact c94 became the stopping performance authority |
| CPython serial | NOT RUN after the Go blocker |
| workers=4 smoke and load | NOT RUN after the Go blocker |
| full candidate/bless/post-bless | NOT ATTEMPTED |

The six explicit guard gaps are `exitgroupthreads`,
`futexforkwakegroups`, `mtsigrelease`, `procladder_epollmgr`,
`procladder_mixed`, and `procladder_mt`. Each tries to create a pthread after
fork without exec and reaches the intentional Darwin/libdispatch safety guard
with `EAGAIN`. They are accepted as lower-priority esoteric gaps for now, but
the probe gate remains honestly red.

Task 8 landed fixes for prepared self-reexec state transport, futex signal lock
ordering, and SIMD/GPR DSR writeback. Exact reducers and Node show that the
ordinary prepared-image path works. This does not substitute for the missing
Go, CPython, load, and full-bless rungs.

## Current performance and cause

The stopping real workload is `go-go_internal_srcimporter` c94:

- Carrick was scoped-stopped after 1,392.649 seconds versus a 2.696-second
  Docker oracle: **516.56x**.
- It had 42 scoped processes, 19 runnable, and about 856-950% aggregate CPU.
- Compiler children were active rather than deadlocked, but none completed.
- The exact `TestImplicitsInfo` reducer reaches the typed 1,000,000-gateway
  ceiling after 15.90 seconds.

This is dominated by DSR execution shape, not a missing rebuild and not yet a
proven AOT-cache problem. Current framed W1 evidence reaches 1,000,000 gateway
entries in 20.02 seconds under profiling. On its hottest thread, sensitive
exits are 85.56% of gateway entries, with exclusive emulation alone at 57.91%;
direct plus indirect resolution is 14.37%. The representative W2 hottest
thread has 65.16% sensitive exits (47.93% exclusive) and 34.49% resolution.
However, W2 aggregate counts instead show about 21.94% sensitive and 56.58%
resolution. That disagreement is one reason the analyzer is not approved: the
selection denominator and thread scope must be explicit before choosing the
first optimization.

A persistent/AOT DSR cache remains a plausible later slice because many child
processes rebuild cold state. It is not yet selected: recurring sensitive exits
and per-thread/aggregate resolver behavior may dominate, and a safe cache must
also bind guest content, page profile, translator ABI, host ISA/features, and
relocation assumptions.

DTrace overhead is accepted. Its wall time is inflated, but counts, ordering,
exit mix, and relative distribution are proportional evidence. Signed untraced
runs remain the only absolute wall/CPU authority.

## Performance interlude implementation state

### Task 1: native in-process profiler — approved

`NATIVEPERF1` now emits framed, typed per-thread records with exact gateway-exit
reconciliation and exclusive phase accounting. Profile-off code retains the
specialized no-timer path. Signed W1 off/on controls preserved the same typed
one-million-trap result; the on run produced 70 complete unique thread records
and zero invalid records. Fork, cross-thread signal, and exec-thread reducers
reassembled complete unique eras with zero invalid frames. The integrated
workspace gate is green.

### Task 2: immutable workloads and analyzer — implemented, review rejected

Committed through `8941ee5a`:

- immutable W1/W2 manifests and the exact W2 fixture;
- strict tagged run/decision records and typed outcomes;
- engine-major Carrick-then-Docker baseline scheduling;
- warmup-inclusive Plane B ABBA scheduling;
- scoped run IDs and cleanup receipts;
- Docker-only preflight/replay receipts;
- durable Plane C capture with per-PID reconciliation;
- fixes for DTrace kind ordinals and diagnostic leakage onto guest stdout.

The latest signed W2 Plane C proof completed naturally with byte-empty stdout,
the expected work product, zero incomplete pairs/drops, 23 reconciled per-PID
totals, and clean scoped cleanup. Retained proof:
`target/native-compiler-task2-review/w2-plane-c-artifacts/nativeperf-w2-internal-runtime-atomic-3-c0459f8d/`.

The second independent review of `7c87e60f..8941ee5a` rejected the tranche with
0 Critical, 7 Important, and 3 Minor findings. The Important blockers are:

1. Plane C cannot round-trip all of its emitted record shapes, does not preserve
   raw temporal ordering, and does not bind the raw artifact path/hash into the
   record.
2. `analyze --check` validates ABBA rows but not all baseline/Plane C
   cross-field combinations.
3. W2 Docker replay is still fail-open because the generated shell lacks
   fail-fast semantics.
4. Workload selection uses hottest-thread evidence while analysis aggregates
   all threads, which changes the decision-rule result.
5. The decision ladder returns on count evidence before validating the
   additive duration model and does not use `blocked_ns`.
6. Durable W1 evidence is self-asserted: the checked-in summary is not
   validated against a checked-in, parsed, hashed raw artifact.
7. Untraced W1 loses its typed max-traps ceiling because the marker is parsed
   only when a profile is present.

Minor follow-ups: reject unknown flattened-profile value keys and reconcile
phase-sensitive counts; align the plan's obsolete status-125 wording with the
observed top-level exit 2; rewrite the three fix commit bodies that contain
literal `\n\n` text if history is cleaned up later.

### Interrupted second review-fix wave — preserved, not integrated

The feature worktree contains partial uncommitted work and must not be removed:

- modified `scripts/perf/test_native_compiler_budget.py` (only the initial gzip
  evidence-test imports/root so far);
- `scripts/perf/evidence/native-compiler-w1-current-profile-v1.log.gz`;
- `scripts/perf/evidence/native-compiler-w2-representative-profile-v1.log.gz`;
- `scripts/perf/evidence/real-plane-c-v1/` with compressed record, raw trace,
  summary, and stderr artifacts.

These files are evidence/fix inputs, not an approved commit. Continue from
`/Volumes/CaseSensitive/carrick/.worktrees/codex-native-conformance` and inspect
the diff before editing.

## Exact next steps

1. Finish the seven Important Task 2 review fixes with red-first hermetic tests.
2. Prove strict parsing and hash binding against the retained raw W1/W2/Plane C
   artifacts; rerun the real W2 Docker replay and signed Plane C path.
3. Run the 50+ Python tests, strict manifest loads, analyzer checks, shell
   syntax, `just ci`, and signed live proof; return to the same reviewer until
   Critical/Important/Minor findings are zero.
4. Run Task 3 only after Task 2 approval: untraced Plane A, profile-off/on ABBA
   Plane B, proportional Plane C, W1/W2 and one-thread controls. Reconcile
   hottest-thread and aggregate scopes before selecting a slice.
5. Implement the selected dominant-term repair and require the reduced
   compiler/import workload to complete naturally below 20x Docker, targeting
   10x or better. Do not raise timeouts or `max_traps`.
6. Resume at exact c94, finish Go and classify its existing differences, then
   run CPython serial, three workers=4 smoke repeats, the full candidate,
   overlay bless, post-bless run, and a live real-workload demonstration.

## Operational constraints

- Rebuild and sign with `just build` before every guest run; after runtime
  changes, confirm the CLI was relinked and contains the expected marker.
- Never overlap Carrick and Docker oracle phases.
- Stamp every Carrick run with a unique `CARRICK_RUN_ID` and reap only with
  `sudo -n scripts/sudo/kill.sh <run-id>`; verify zero descendants.
- Preserve exact workload/input/output hashes and do not weaken work, fan-out,
  timeouts, trap ceilings, AArch64 exclusive semantics, or signal semantics.
- Keep measured results separate from projections. Task 8 is incomplete,
  Task 2 is not review-approved, Task 3 has not run, and no optimization is
  selected.
