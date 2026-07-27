# Darwin/AArch64 native wall-time campaign ledger

**Updated:** 2026-07-27  
**Status:** ACTIVE — M1 evidence collection
**Primary workload:** cold-GOCACHE `go-build`  
**Design:** [Darwin native wall-time attribution campaign](../superpowers/specs/2026-07-27-native-wall-time-attribution-campaign-design.md)

## Campaign scorecard

| Field | Current | Evidence / interpretation |
|---|---:|---|
| Historical Carrick median | 19,485 ms | Five untraced runs at `9c25688d` |
| Historical Docker result | 942 ms | Handoff datum; refresh required |
| Historical ratio | 20.68x | Context only, not `R0` |
| Official `C0` | 19,249 ms | Five fresh untraced Carrick samples |
| Official `D0` | 1,029 ms | Five fresh native-arm64 Docker samples |
| Official `R0` | 18.7065x | `C0 / D0` |
| M2 target | 9.3533x | `R0 / 2` |
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
| E004 | `scripts/perf/evidence/native-go-build-wall-baseline-v1.json` | accepted | Clean, idle-host, serial five-plus-five run: `C0=19,249 ms`, `D0=1,029 ms`, `R0=18.7065x`; Docker image is native arm64 |
| E005 | whole-tree attribution run A | pending | First reconciled current-state proportions |
| E006 | whole-tree attribution run B | pending | Stability and dominant-rank replication |

## Whole-tree attribution

No current trace satisfies the campaign reconciliation contract yet.

### Elapsed wall-state occupancy

| Category | Run A | Run B | Stable? |
|---|---:|---:|---|
| tracked tree on CPU | pending | pending | pending |
| runnable but descheduled | pending | pending | pending |
| all tracked threads sleeping | pending | pending | pending |
| transition / unclassified | pending | pending | pending |
| accounted total | pending | pending | must be at least 99% |

### On-CPU resource share

| Category | Run A | Run B | Stable? |
|---|---:|---:|---|
| translated guest/JIT | pending | pending | pending |
| translate/decode/plan/emit/publication | pending | pending | pending |
| gateway prepare/resolve/finish/recovery | pending | pending | pending |
| syscall dispatch and host runtime | pending | pending | pending |
| process/capsule/exec setup | pending | pending | pending |
| Darwin kernel | pending | pending | pending |
| other Carrick host | pending | pending | pending |
| unresolved | pending | pending | must be at most 10% |

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

## Next action

Write and validate the executable M1 plan:

- [x] Extend the benchmark runner with a semantically identical Docker phase.
- [x] Build a launch-scoped whole-tree wall-state/on-CPU/off-CPU DTrace profile.
- [x] Add the fail-closed attribution summarizer.
- [x] Collect fresh untraced `C0`/`D0`.
- [ ] Collect two complete traced runs and rank H001–H005.
