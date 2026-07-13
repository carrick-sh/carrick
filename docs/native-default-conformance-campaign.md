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
| 2026-07-13 | `2a7d3046` | Node-sized split Direct range reducer | 1 | RED `Redirected` to `0x7000000000`; GREEN segment-wise | `host_proc::imp::direct_vm_reservation_tests::fork_child_split_canonical_range_is_accepted_segmentwise` | Measured target crosses adjacent delegated dyld-empty regions, not one region plus a vacant tail. Every genuine gap is now owned exactly. |
| 2026-07-13 | `2a7d3046` | `ltp-eventfd01` isolated | 1 | MATCH; carrick 4/4, oracle 4/4 | `target/conformance/native-direct-reservation-eventfd01-mach2-060.jsonl` | Originating gzip exec collision is fixed end-to-end. |
| 2026-07-13 | `2a7d3046` | Node app/V8 smoke isolated | 1 | 2 REGRESSION; both complete wrapper and abort `rc=134`, no reservation collision | `target/conformance/native-direct-reservation-node-mach2-060.jsonl` | Direct reducer reaches Node startup assertion on `uv_thread_create`; this is the P1 post-fork thread rejection, not a mapping failure. |
| 2026-07-13 | worktree | `forkexecpthread` staged reducer | 1 | Production RED: stage2 reached, `pthread_create_errno=11`; unsafe diagnostic GREEN; Docker GREEN | `conformance-probes/src/bin/forkexecpthread.rs` | The blanket guard is real, but one post-fork pthread is not enough to prove Apple runtime safety. |
| 2026-07-13 | worktree | Node app/V8 with unsafe post-fork threads | 1 | app REGRESSION; V8 MATCH | `target/conformance/native-postfork-node-unsafe.jsonl` | V8 closes its originating `uv_thread_create` failure. App reaches a repeatable host `SIGTRAP` inside libdispatch. |
| 2026-07-13 | worktree | Go build/runtime/sync with unsafe post-fork threads | 1 | build TIMEOUT; runtime CARRICK_CRASH 17/18; sync REGRESSION 51/52 | `target/conformance/native-postfork-go-unsafe.jsonl` | Subprocess tests reach the same libdispatch trap. Runtime also exposes a separate user-arena memory fault for P2 triage. |
| 2026-07-13 | worktree | CPython threading with unsafe post-fork threads | 1 | REGRESSION; 174/194 pass, 20 fail, 1 skip; 21 fatal trap records | `target/conformance/native-postfork-cpython-threading-unsafe.jsonl` | Unsafe thread creation replaces `EOPNOTSUPP` with deterministic libdispatch failures; not a viable production repair. |
| 2026-07-13 | worktree | common host-trap symbolication | 1 | PC `0x1877f2410` = libdispatch deduplicated trap +36; LR `0x1877be4b8` = `_dispatch_sema4_wait+56` | `target/conformance/raw/conf-{63249,64365,69065}-*.err` | Apple libdispatch fork-of-multithreaded-parent state is the first common failure boundary. Select PID-preserving host self-reexec. |

## Active failure clusters

| Priority | Cluster | Authority | Current status | Target |
| ---: | --- | --- | --- | --- |
| P0 | `THREAD_WAITERS` remains locked in a fork child | live LLDB stack plus deterministic contended-fork reducer | fixed in `6d3cf627`; four signed single-suite runs complete, multi-suite load proof pending | no CPython timeout in workers=4 smoke repeats |
| P0 | Direct-exec target reservation rejects split dyld range | red/green Node-sized reducer plus signed eventfd/Node runs | fixed in `2a7d3046`; eventfd MATCH, Node reaches downstream thread guard; multi-suite load proof pending | no reservation collision in workers=4 smoke repeats |
| P1 | Post-fork exec child cannot create guest threads | red/green staged reducer plus Node/Go/CPython unsafe samples and libdispatch symbolication | one pthread can start, but real subprocesses trap in inherited libdispatch state; self-reexec architecture selected | `forkexecpthread`, Node, Go, and CPython run after PID-preserving host self-reexec |
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

Write the measured PID-preserving self-reexec design and implementation plan.
Keep the production guard fail-closed and retain the exact-value diagnostic
only until the handoff path replaces it. After P1, run multi-suite smoke at four
workers to provide the actual load proof for both P0 fixes.
