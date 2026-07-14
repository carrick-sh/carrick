# Native Default Conformance and Performance Handoff

Date: 2026-07-14

Integration state: `codex/native-conformance-quality` carries the completed
second review-fix wave (`5b45cc01`, `7a475d18`), the review closeout, the W2
one-thread control manifest, and the Task 3 measurement evidence; main is
fast-forwarded to the branch head. The feature worktree at
`.worktrees/codex-native-conformance` is clean and retained as the campaign
working copy.

## Goal and honest status

Make the Darwin-native backend the quality-first default, run the same real
conformance and workload ladders expected of the release backend, remove
stability/load blockers, and reach a full measured bless. HVF/VMM performance
is out of scope. Native performance is correctness: a workload that is tens or
hundreds of times slower than the Linux oracle is not ready to bless.

**Current status: NOT BLESSED.** Prepared-image/self-reexec correctness has
advanced substantially and Node content parity is green. Task 8 remains
stopped on the pathological Go compiler/import workload. The performance
measurement interlude is review-approved (Tasks 1 and 2) and the Task 3
measurement campaign HAS RUN (2026-07-14, signed, evidence in
`docs/perf-results/`). Its honest outcome: the committed analyzer FAILS
CLOSED — the additive CPU model reconciles only 23-43 percent of measured
CPU (gate error `0.653181` vs the 2 percent limit) and the count scopes
disagree (hottest-thread exclusive 47.1 percent vs aggregate 21.7 percent) —
so NO optimization slice is selected. The measured unaccounted term tracks
blocked wall (55.0 percent of untraced wall) and is system-time dominated;
the profile cannot yet distinguish per-syscall wait-machinery cost from
per-process startup. The follow-on plan
(`docs/superpowers/plans/2026-07-14-native-compiler-selected-slice.md`) adds
typed attribution (blocked-CPU split, per-process startup, helper-thread
CPU), extends the additive model, and re-runs the campaign to a typed
decision row before any optimization.

Fresh untraced authority: W2 completes at **16.00x** Docker (p50 3.520 s vs
0.220 s, 5/5); W1 is ceiling-truncated (5/5 typed `max-traps` at p50
19.360 s vs Docker 1.600 s). ABBA profile tax is 1.13 percent. A W2
one-thread control manifest exists
(`scripts/perf/manifests/native-compiler-w2-one-thread-v1.json`) with
byte-identical output to W2.

Authoritative tracked documents:

- [native-default campaign ledger](docs/native-default-conformance-campaign.md)
- [prepared-image implementation plan](docs/superpowers/plans/2026-07-13-native-prepared-image-reexec.md)
- [prepared-image design](docs/superpowers/specs/2026-07-13-native-prepared-image-reexec-design.md)
- [compiler performance budget design](docs/superpowers/specs/2026-07-14-native-compiler-performance-budget-design.md)
- [compiler performance measurement plan](docs/superpowers/plans/2026-07-14-native-compiler-performance-measurement.md)

The detailed controller ledger is local and git-ignored at
`.superpowers/sdd/progress.md` in the feature worktree. The Task 8 evidence
report is retained in the feature worktree at
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

## Current performance and cause

The stopping real workload is `go-go_internal_srcimporter` c94:

- Carrick was scoped-stopped after 1,392.649 seconds versus a 2.696-second
  Docker oracle: **516.56x**.
- The exact `TestImplicitsInfo` reducer reaches the typed 1,000,000-gateway
  ceiling after 15.90 seconds.

This is dominated by DSR execution shape. On the W1 hottest thread, sensitive
exits are 85.56% of gateway entries (exclusive emulation alone 57.91%);
direct plus indirect resolution is 14.37%. The W2 hottest thread has 65.16%
sensitive exits (47.93% exclusive) while the W2 aggregate across all threads
shows 41.2% sensitive and 56.6% resolution. That scope disagreement is now a
first-class analyzer concept: count evidence carries an explicit
hottest-thread/aggregate-threads scope, the decision ladder evaluates both and
fails closed when they disagree, and every decision names its denominator in a
typed `scope` field. Task 3 must reconcile the scopes on measured evidence
before any slice is selected — not by weakening the gate.

DTrace overhead is accepted as proportional shape evidence only; signed
untraced runs remain the only absolute wall/CPU authority. A persistent/AOT
DSR cache remains unselectable until recurring-PC and first-resolution proof
exist; the resolver rung is deliberately dead until Plane C supplies
source-PC recurrence.

## Performance interlude implementation state

### Task 1: native in-process profiler — approved

`NATIVEPERF1` emits framed, typed per-thread records with exact gateway-exit
reconciliation and exclusive phase accounting; profile-off keeps the
specialized no-timer path. Signed off/on controls preserved the typed
one-million-trap result.

### Task 2: immutable workloads and analyzer — APPROVED

The second independent review confirmed all seven Important findings fixed
with red-first tests and independently re-verified hash chains; the delta
commit closed its one new Important finding and all actionable Minors, with a
final "Ready to merge: Yes". What the fix waves (`5b45cc01`, `7a475d18`)
added:

- Plane C ordering derived from the raw DTrace temporal sample stream, with
  `dtrace.raw` name+SHA-256 bound into the typed record, raw/summary count and
  completion reconciliation, and exact round-trip of every emitted shape.
- Cross-field validation (engine x plane x preflight x cleanup x
  profile/dtrace presence x gateway reconciliation x schedule-label forms) on
  every wire row consumed by `analyze --check`.
- Fail-fast (`set -eu`) W2 Docker replay script with an executable-sentinel
  proof that exec is unreachable after failed materialization.
- Explicit count-evidence thread scope with fail-closed reconciliation and a
  typed `scope` field on every decision.
- Unconditional additive duration-model validation before any decision and a
  blocked/off-CPU rung (>=30% of untraced wall, saturation named in the
  basis).
- Durable W1 evidence: the gzipped raw profile is checked in and manifest
  load decompresses, hashes, parses, and reconciles it (140 thread groups,
  hottest counters, identity, max-traps marker); evidence paths cannot escape
  the evidence root.
- Untraced runs keep a typed max-traps outcome from the stderr marker without
  profile identity; forged markers rejected.
- Checked-in real artifacts under `scripts/perf/evidence/` (W1 raw profile,
  W2 representative profile, and the post-fix Plane C run
  `nativeperf-w2-internal-runtime-atomic-1-4472f5b0`) are parsed,
  hash-verified, and round-tripped by the hermetic suite (71 tests).

Verification on record: 71 hermetic tests, `sh -n`, `py_compile`, CLI
`analyze --input --check` exit 0 with scoped decision, `just fmt-check`, full
`just ci`, regenerated W1/W2 Docker preflight receipts, two real W2 Docker
replays reproducing work product `5db57566...` through the fail-fast script,
and a fresh signed Plane C live run with clean scoped cleanup, 23 reconciled
per-PID totals, and zero drops.

One deferred pre-existing follow-up (reviewer-accepted, ledgered): make the
evidence-to-W1-manifest hash link mandatory when `native-compiler-w1-v1.json`
is absent next to the manifest.

## Exact next steps

1. Execute the attribution plan
   (`docs/superpowers/plans/2026-07-14-native-compiler-selected-slice.md`):
   Task 1 adds `phase_blocked_cpu_ns`, a one-per-process `startup` frame, and
   a `host-threads` helper-CPU frame to `NATIVEPERF1` (red-first, profile-off
   path unchanged); Task 2 extends `derive_additive_cpu_evidence`/`analyze`
   to consume them with the unchanged 2 percent gate.
2. Re-run the measurement campaign (same frozen procedure as
   `docs/perf-results/native-compiler-*-v1.jsonl`) to
   `native-compiler-budget-v2.jsonl`; require `analyze --check` to emit
   exactly one typed decision row or fail closed on a *named* term.
3. Implement the selected repair red-first (candidates and their
   design-committed prescriptions are enumerated in the plan's Task 4);
   require the reduced compiler/import workload to complete naturally below
   20x Docker, targeting 10x or better. Do not raise timeouts or `max_traps`.
4. Resume at exact c94, finish Go and classify its existing differences, then
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
  Task 3 has not run, and no optimization is selected.
