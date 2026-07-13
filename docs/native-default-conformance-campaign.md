# Native-Default Conformance Campaign Ledger

**Started:** 2026-07-13

**Controller design:**
[`docs/superpowers/specs/2026-07-13-native-default-conformance-quality-design.md`](superpowers/specs/2026-07-13-native-default-conformance-quality-design.md)

## Campaign rules

- Record measurements only after the command completes.
- Keep projections and desired outcomes in `Target`, never in `Measured`.
- Do not bless crashes, timeouts, load instability, unexplained regressions, or
  real-workload blockers.
- Keep Carrick and Docker phases separate and use scoped run IDs.
- Preserve raw logs, JSONL, LLDB output, and cores under `target/conformance/`;
  this ledger records the durable path and conclusion.

## Starting manifest

| Ecosystem | Suites | Smoke | Full-only |
| --- | ---: | ---: | ---: |
| CPython | 438 | 6 | 432 |
| Go | 194 | 5 | 189 |
| Node | 3 | 2 | 1 |
| LTP | 1,492 | 10 | 1,482 |
| **Total** | **2,127** | **23** | **2,104** |

The ecosystem counts come from the checked-in suite manifest at campaign
start. Smoke/full membership remains authoritative in
`scripts/conformance/suites.toml`.

## Measured ladder

| Date | Revision | Gate | Workers | Measured | Artifact | Classification / next action |
| --- | --- | --- | ---: | --- | --- | --- |
| 2026-07-13 | `df43c414` | `smoke --lane macos-native-dsr --force` | 4 | 15 MATCH; 4 REGRESSION; 3 TIMEOUT; 1 CARRICK_CRASH | `target/conformance/native-default-goal-smoke-20260713.jsonl` | Starting baseline. Split into exec reservation, fork-lock, and post-fork-thread clusters. |
| 2026-07-13 | `df43c414` | `go-runtime`, `go-sync` isolated | 1 | deterministic failure | `target/conformance/native-default-go-isolated-r1-20260713.jsonl` | `pthread_create` receives deliberate `EOPNOTSUPP` after fork-to-exec. Real-workload blocker; fix forward. |
| 2026-07-13 | `df43c414` | `cpython-threading` isolated | 1 | TIMEOUT at 300.265 s | `target/conformance/native-default-cpython-threading-isolated-r1-20260713.jsonl` | LLDB captured fork child in inherited `THREAD_WAITERS` mutex. Add contended-fork red test. |
| 2026-07-13 | `df43c414` | one CPython shutdown method | 1 | PASS; 0.683 s method, 3.0 s total | `target/conformance/logs/lldb-runs/native-goal-cpython-threading-one.guest.log` | Falsified the first method-level attribution; full-file failure is lifecycle/load related. |
| 2026-07-13 | `df43c414` | unbuffered `test_threading` diagnostic | 1 | completed in 33.5 s with 19 failures | `target/conformance/logs/lldb-runs/native-goal-cpython-threading-unbuffered.guest.log` | Nineteen child interpreters cannot create threads after fork-to-exec. Separate from the inherited-lock timeout. |
| 2026-07-13 | `df43c414` | `go-build` LLDB deadline | 1 | TIMEOUT at 45 s | `target/conformance/logs/lldb-runs/native-goal-go-build.lldb.txt` | Compiler child is still executing with one host thread; capture the exact clone/guard interaction before changing lifecycle code. |
| 2026-07-13 | `6d3cf627` | contended `THREAD_WAITERS` fork reducer | 1 | RED at 2 s before fix; GREEN in 0.07 s after fix | `host_signal::tests::fork_child_resets_contended_thread_waiters` | Deterministically proved copied parking-lot contention. Child now publishes a preallocated empty backing without touching the inherited queue. |
| 2026-07-13 | `6d3cf627` | `cpython-threading` isolated | 1 | REGRESSION; 175/194 pass, 19 fail, 1 skip; no timeout/crash | `target/conformance/native-waiter-cpython-threading-serial.jsonl` | Originating 300 s waiter timeout is gone. Remaining failures are the separately tracked post-fork thread rejection. |
| 2026-07-13 | `6d3cf627` | `cpython-threading` repeat stability | configured 4; 1 selected suite | 3/3 REGRESSION; each 175/194 pass, 19 fail, 1 skip; no timeout/crash | `target/conformance/native-waiter-cpython-threading-repeat-r{1,2,3}.jsonl` | Repeat-stable single-suite result. Not counted as concurrent load evidence; multi-suite smoke remains required. |

## Active failure clusters

| Priority | Cluster | Authority | Current status | Target |
| ---: | --- | --- | --- | --- |
| P0 | `THREAD_WAITERS` remains locked in a fork child | live LLDB stack plus deterministic contended-fork reducer | fixed in `6d3cf627`; four signed single-suite runs complete, multi-suite load proof pending | no CPython timeout in workers=4 smoke repeats |
| P0 | Direct-exec target reservation rejects split dyld range | native smoke raw logs for gzip and Node | root cause localized; no fix yet | exact non-overwriting reservation plus Node/gzip live passes |
| P1 | Post-fork exec child cannot create guest threads | Go/CPython raw output and explicit runtime guard | deliberate rejection; architecture repair required | `execthreads`, `go-build`, Go runtime/sync, CPython threading/subprocess all complete |
| P2 | Remaining ecosystem/LTP differences | no fresh full native run yet | unknown | classify from measured full run after P0/P1 blockers clear |

## Bless checklist

- [ ] `just ci`
- [ ] signed native conformance probes
- [ ] smoke serial
- [ ] smoke workers=4, three consecutive runs
- [ ] Node full ecosystem
- [ ] Go full ecosystem
- [ ] CPython full ecosystem
- [ ] LTP full ecosystem
- [ ] complete candidate run, workers=1
- [ ] complete load run, workers=4
- [ ] every non-MATCH row diagnosed and reviewed
- [ ] full unfiltered native overlay bless
- [ ] post-bless full run with no gating regression
- [ ] live real-workload demonstration

## Current next action

Execute the remaining independent P0 plan,
[`native-direct-exec-reservation`](superpowers/plans/2026-07-13-native-direct-exec-reservation.md):
pin the split-range collision red, switch to exact non-overwriting Mach
allocation, and repeat the originating Node/eventfd lanes. Then run multi-suite
smoke at four workers to provide the actual load proof for both P0 fixes.

Keep the post-fork thread guard fail-closed until these P0 fixes land and the
diagnostic lifecycle experiment is captured and classified.
