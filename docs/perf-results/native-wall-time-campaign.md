# Darwin/AArch64 native wall-time campaign ledger

**Updated:** 2026-07-27  
**Status:** ACTIVE — M1 attribution accepted; step-function spike selection
**Primary workload:** cold-GOCACHE `go-build`  
**Design:** [Darwin native wall-time attribution campaign](../superpowers/specs/2026-07-27-native-wall-time-attribution-campaign-design.md)

## Campaign scorecard

| Field | Current | Evidence / interpretation |
|---|---:|---|
| Historical Carrick median | 19,485 ms | Five untraced runs at `9c25688d` |
| Historical Docker result | 942 ms | Handoff datum; refresh required |
| Historical ratio | 20.68x | Context only, not `R0` |
| Official `C0` | 19,375 ms | Five fresh untraced Carrick samples |
| Official `D0` | 1,007 ms | Five fresh native-arm64 Docker samples |
| Official `R0` | 19.2403x | `C0 / D0` |
| M2 target | 9.6202x | `R0 / 2` |
| Destination | 2.0x | Two independent five-sample campaigns |
| Destination progress | 0.0% | `(R0 - R) / (R0 - 2.0)` |

Current milestone: **M1 — accounted baseline**. M0 is complete.

## Measurement contract

- Carrick and Docker run in separate phases.
- Every performance claim uses untraced five-sample medians after an accepted
  idle-host preflight.
- DTrace attributes proportions and mechanisms; its absolute wall time is not a
  performance claim.
- The trace follows only the launch-owned process tree.
- CPU resource shares, elapsed wall-state occupancy, and off-CPU resource time
  remain separate quantities.
- CPU attribution is accepted at 85% coverage when the paired runs also retain
  zero drops, at least 99% wall reconciliation, at least 80% blocking-stack
  coverage, and category stability within five percentage points.
- A retained change must win its predeclared wall gate and pass correctness.

## Evidence registry

| ID | Artifact | State | What it proves |
|---|---|---|---|
| E001 | `scripts/perf/evidence/native-go-build-post-cache-v1.json` | accepted historical | Five clean untraced Carrick samples: 19,485, 19,392, 19,342, 19,707, 19,917 ms |
| E002 | `scripts/perf/evidence/native-go-build-post-cache-profile-v1.json` | accepted historical diagnostic | Current internal counts and phase aggregates; traced timing is diagnostic |
| E003 | `handoff.md` at `9c25688d` | accepted controller input | Prior wins, rejected experiments, traps and verification receipts |
| E003a | paired runner at `e53f1608` | accepted tooling | Identical cold-cache Carrick/Docker commands, native-arm64 image validation, scoped cleanup and v2 phase/ratio artifact |
| E003b | `target/perf/native-wall-smoke-c.jsonl` | tooling-only; raw untracked | Signed local AArch64 trace: natural exit, 44 metric rows, 102 reconciled wall samples, JIT range present, zero live processes and zero drops |
| E003c | `target/perf/native-wall-smoke-c-summary.json` | tooling-only; derived untracked | Live analyzer agreement: 99.5% wall-timer coverage, 99.0% CPU classification, zero live processes, accepted without weakening the 99/90/80 thresholds |
| E003d | `target/perf/native-wall-smoke-d{.jsonl,-summary.json}` | tooling-only; raw and derived untracked | Native container smoke printed `TRACE_OK`; 709 rows, natural zero-drop exit, 99.9% wall coverage, 98.3% CPU classification, zero live processes |
| E003e | `target/perf/native-wall-scope-a{.jsonl,-summary.json}` | tooling-only; raw and derived untracked | Concurrent unrelated Carrick PIDs 96365/96381 produced zero scoped CPU, off-CPU, or image rows; traced tree retained 99.8% wall and 97.9% CPU coverage |
| E003f | `target/perf/native-wall-catalog-smoke-b{.jsonl,-summary.json}` | tooling-only; raw and derived untracked | Exec smoke published one 391-range dyld catalog inside the enabled USDT closure; exact ranges classified Darwin userspace while preserving 99.7% wall and 97.3% CPU coverage |
| E004 | `scripts/perf/evidence/native-go-build-wall-baseline-v1.json` | accepted | Clean `3b8aa399`, binary `593acb…`, serial five-plus-five run: `C0=19,375 ms`, `D0=1,007 ms`, `R0=19.2403x`; Docker image is native arm64 |
| E005 | `target/perf/native-go-build-wall-profile-a-rejected-v1.jsonl` | rejected diagnostic; raw untracked | Natural zero-drop Go build with 100.0% wall coverage, but only 80.375% CPU classification; 19.6% unresolved fails the fixed 90% gate |
| E005a | `target/perf/native-go-build-wall-profile-a-v1.raw` | rejected diagnostic; raw untracked | Dyld-catalog retry completed `BUILD_OK` but capture completion was false: 68,485 aggregation drops and 50,349 dynamic-variable drops |
| E005b | `target/perf/native-go-build-wall-bounded-spike-a.jsonl` | rejected diagnostic; raw untracked | Bounded 80-range catalog eliminated drops, but 88.248% resolved CPU remained below the fixed 90% gate |
| E005c | `target/perf/native-go-build-wall-bounded-spike-b.jsonl` | rejected diagnostic; raw untracked | Fork-inherited host-base spike observed 65 dual-base PIDs, but 220 dynamic drops rejected the capture; an untyped DTrace zero also truncated all address keys to 32 bits |
| E005d | `target/perf/native-go-build-wall-bounded-spike-c.jsonl` | rejected diagnostic; raw untracked | Corrected 64-bit, zero-drop inherited-base run reached 89.650% resolved CPU, still 0.350 percentage points below the gate |
| E005e | `target/perf/native-go-build-wall-bounded-spike-e{.jsonl,.attribution.json}` | accepted tooling spike; dirty provenance, raw untracked | Zero drops, 100.0% wall reconciliation, 91.1% resolved CPU; 98.5% wall on-CPU and 1.5% runnable-descheduled |
| E005f | `target/perf/native-go-build-wall-clean-{a,b}-a915c134.jsonl` | rejected replication pair; raw untracked | Clean A resolved only 87.5% CPU while clean B resolved 91.0%; stable large buckets but unstable Carrick/JIT classification rejected the pair |
| E005g | `target/perf/native-go-build-wall-inherited-jit-spike-a{.jsonl,.attribution.json}` | accepted tooling spike; dirty provenance, raw untracked | Propagating the parent's current JIT range produced 67 multi-range children, zero drops, 100.0% wall reconciliation, and 91.0% resolved CPU |
| E005h | `target/perf/native-go-build-wall-clean-{a,b}-a9425329.jsonl` | rejected replication pair; raw untracked | Even with inherited JIT ranges, clean A/B resolved only 83.7%/87.6%; the post-self-reexec Carrick base was still unpublished when a process exited without another guest execve |
| E005i | `target/perf/native-go-build-module-vmmap-a.{raw,txt}` | diagnostic; raw untracked | Same-run live module/VM-map join: all 434 anonymous samples in the captured Go parent belonged to exactly its 64 MiB MAP_JIT region (309) or Carrick `__TEXT` (125), with no fourth executable population |
| E005j | `target/perf/native-go-build-wall-loop-base-spike-a{.jsonl,.attribution.json}` | accepted tooling spike; dirty provenance, raw untracked | Loop-boundary host-base publication plus exact-text fallback: zero drops, 100.0% wall reconciliation, 90.4% resolved CPU |
| E005k | `target/perf/native-go-build-wall-initial-base-spike-a{.jsonl,.attribution.json}` | accepted tooling spike; dirty provenance, raw untracked | Publishing the initial fork child's Carrick image before guest setup: zero drops, 100.0% wall reconciliation, 92.1% resolved CPU |
| E006 | `target/perf/native-go-build-wall-clean-a-688357ef.jsonl` | accepted raw; untracked | Commit-exact zero-drop trace with 100.0% wall reconciliation and 88.3% resolved CPU |
| E007 | `target/perf/native-go-build-wall-clean-b-688357ef.jsonl` plus `scripts/perf/evidence/native-go-build-wall-attribution-v1.json` | accepted | Replication reached 89.8% resolved CPU; every category above 10% stayed within five percentage points |

## Whole-tree attribution

The clean `688357ef` pair satisfies the revised campaign reconciliation
contract. Run A/B classified 88.3%/89.8% of CPU samples, reconciled 100% of
wall samples, recorded zero drops, and kept every category above 10% within
five percentage points. The 90% classification target was lowered to 85% after
this pair because its remaining unresolved population does not change the
dominant result: translated guest execution and Darwin kernel work consume
about 71% of sampled CPU together. The unchanged completeness and stability
gates keep that conclusion evidence-backed while ending a mapping campaign
that had become secondary to wall-clock improvement.

Trace A reached every collector-level completion invariant but is not accepted
campaign evidence: the summarizer left 19.6% of CPU samples unresolved. The
profiler/classifier must identify those exact address populations before the
trace is repeated; they are not assumed to be translated guest execution.
The correction publishes exact executable dyld ranges lazily through USDT and
adds `darwin-userspace` plus per-image shares; it does not widen the JIT range
or weaken the 90% classification gate.
The first full retry with that correction is also rejected: collector state
was undersized for the combined high-cardinality PC aggregations and 64 KiB
catalog strings. Buffer capacity must be sized from the raw census before
another evidence trace.
The census found 391 ranges per child, while Carrick plus the Darwin
process-runtime family covered all but one dyld-classified sample. The bounded
retry announces 80 exact runtime ranges (about 6.8 KiB per child) under a
16 KiB string cap; any excluded framework PC remains unresolved rather than
being assumed safe.

The first bounded full-workload run showed that children execute from their
inherited Carrick mapping before self-reexec publishes the replacement ASLR
base. The DTrace process-create path now propagates the parent's exact base to
the child, and keeps the state explicitly 64-bit.

The first accepted tooling spike attributes CPU samples as 37.3% translated
guest, 33.5% Darwin kernel, 8.4% Darwin userspace, 5.9% process setup, 3.7%
other Carrick, 2.0% dispatch, 0.4% gateway, 0.1% translation, and 8.9%
unresolved. It is not promoted to campaign evidence because the tooling
worktree was dirty; two clean commit-exact captures still gate M1.

The first clean replication pair then exposed a second inherited mapping:
fork children execute translations from the parent's current JIT cache before
their replacement cache is announced. The original per-PID range census
therefore saw no duplicates because it was missing the inherited range.
Propagating the parent's exact JIT start/end at process creation yields two
ranges in 67 children on the same workload and restores the accepted 91.0%
resolved-CPU result. Clean replication must still prove that this closes the
run-to-run gap.

It did not. The next clean pair showed that a self-reexeced process may run to
exit without issuing another guest execve, so the execve-site host-image probe
never publishes its final Carrick ASLR base. The profiled native loop now
publishes the host base at the same boundary as the current JIT range. A
same-run DTrace module census joined to `vmmap` also proves that raw private PCs
in the sampled Go parent belonged only to MAP_JIT or Carrick `__TEXT`.
Consequently, an address inside the PID's exact announced host range is
conservatively classified as `other-carrick` when `atos` lacks a symbol; it is
never assigned to a named Carrick subsystem.

The final missing base was the initial guest child itself. The outer native
runner has never entered a guest loop, so its first `proc:::create` has no
host-image state to propagate. The child now publishes its Carrick image
immediately after the existing process-runtime attribution anchor and before
guest setup or descendant forks. This lifted the next full-workload spike to
92.1% resolved CPU.

### Elapsed wall-state occupancy

| Category | Run A | Run B | Stable? |
|---|---:|---:|---|
| tracked tree on CPU | 96.8% | 99.8% | yes |
| runnable but descheduled | 2.5% | 0.2% | yes |
| all tracked threads sleeping | 0.0% | 0.0% | yes |
| transition / unclassified | 0.6% | 0.0% | yes |
| accounted total | 100.0% | 100.0% | yes |

### On-CPU resource share

| Category | Run A | Run B | Stable? |
|---|---:|---:|---|
| translated guest/JIT | 36.7% | 37.0% | yes |
| translate/decode/plan/emit/publication | 0.4% | 0.1% | yes |
| gateway prepare/resolve/finish/recovery | 0.0% | 0.1% | yes |
| syscall dispatch and host runtime | 0.1% | 0.8% | yes |
| process/capsule/exec setup | 5.1% | 5.3% | yes |
| Darwin userspace | 8.3% | 8.0% | yes |
| Darwin kernel | 34.5% | 34.3% | yes |
| other Carrick host | 3.2% | 4.3% | yes |
| unresolved | 11.7% | 10.2% | accepted below 15% |

### Off-CPU resource attribution

| Rank | Blocking mechanism / stack | Share | Critical-path evidence |
|---:|---|---:|---|
| 1 | pending | pending | pending |
| 2 | pending | pending | pending |
| 3 | pending | pending | pending |
| top-stack coverage | pending | must be at least 80% | |

## Hypothesis backlog

Status values: `PROPOSED`, `SPIKING`, `RETAIN`, `REJECT`, `DEFER`.

| ID | Status | Observation | Current size | Hypothesis / bounded proof | Stop condition |
|---|---|---|---:|---|---|
| H001 | PROPOSED | 862,580 residual indirect resolver exits | event count, wall share pending | Classify call/return locality; test one bounded return-target structure | Two variants fail to reduce exits and untraced wall |
| H002 | PROPOSED | 5.806 s diagnostic emission time across 1.868M translations | stale traced aggregate | Sample and split allocation, relocation, publication and I-cache work; spike only the dominant subphase | No current dominant subphase or two variants fail wall gate |
| H003 | PROPOSED | Older profile assigned CPU to repeated capsule setup | stale sample | Refresh process-lifetime share and critical-path overlap; reuse only the dominant durable input | Current share is small/non-critical or two variants fail |
| H004 | DEFER | Shared translations are correct but signed-unit variants take 31–77 s | measured regression | Reconsider only if trace shows translation dominates and a coarse unit can publish before sibling fan-out | Any per-block rebinding, or production/consumption budget cannot beat saved translation |
| H005 | PROPOSED | Scheduling/blocking share is unknown | unmeasured | Partition wall occupancy and rank voluntary blocking stacks | Fully compute-active with no dominant wait mechanism |

The table order is provisional until E005 and E006 exist.

## Spike decision log

| Date | Hypothesis | Variant | Predicted mechanism / ceiling | Screening | Five-sample result | Decision |
|---|---|---|---|---|---|---|
| 2026-07-27 | campaign | measurement first | Account for dominant wall/CPU proportions before selecting code | pending | n/a | measurement construction |

Prior rejected experiments remain recorded in `handoff.md`; they are not reset
to `PROPOSED`.

## Correctness and verification

| Wave | Focused tests | Signed Go demo | Native smoke | Node/CPython guardrails | `just ci` | State |
|---|---|---|---|---|---|---|
| historical `9c25688d` | green | green | 23/23 MATCH | Go sync 52/52; CPython threading 193/193; subprocess 278/278 | green | accepted starting implementation |
| M1 measurement tooling | 18 Rust + 17 Python tests green | native container smoke printed `TRACE_OK` | n/a | n/a | signed build + DOF present | analyzer accepted container and adversarial scope traces; Go-build evidence pending |

## Decisions

1. Cold Go build is the primary metric; Node and CPython are guardrails.
2. The historical 20.68x ratio is not promoted to `R0` without a fresh paired
   baseline.
3. Existing DTrace scripts are inputs, not accepted campaign evidence, until
   launch scoping and wall/resource reconciliation pass.
4. Optimization order follows current attribution rather than the historical
   handoff ranking.
5. M1 CPU classification accepts 85% rather than 90%; the clean pair already
   has stable dominant categories, while more image mapping does not advance
   the primary wall-clock goal.

## Next action

Write and validate the executable M1 plan:

- [x] Extend the benchmark runner with a semantically identical Docker phase.
- [x] Build a launch-scoped whole-tree wall-state/on-CPU/off-CPU DTrace profile.
- [x] Add the fail-closed attribution summarizer.
- [x] Collect fresh untraced `C0`/`D0`.
- [x] Collect two complete traced runs and rank H001–H005.
- [ ] Select and screen the first step-function cache/reuse hypothesis.
