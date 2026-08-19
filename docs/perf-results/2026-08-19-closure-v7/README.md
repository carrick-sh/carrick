# Closure checkpoint — post lease-generation

**Date:** 2026-08-19
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest

## Artifact

| | |
|---|---|
| HEAD | `2cf018d33` |
| binary sha256 | `670f5be0715156c2491d0e6404f865374f4cecf6dd92d327d4ca4215daf9e366` |
| CDHash | `a97e63ae55179c9a6184906432fe15ef9dcacd08` |
| LC_UUID | `441F2FD0-4CD1-39E7-AD46-E1CBE03AD941` |
| hypervisor entitlement | present |
| `__TEXT,__dof_carrick` | present |
| scope | 2,127 suites, frozen and checked |

`RUST_TEST_THREADS=1 just ci` exited 0 on this source before the build. The host
was verified clean first — an orphaned Docker container from an earlier probe of
mine had been alive for 8 hours and was reaped before the run.

## Result

| metric | v6 | v7 | delta |
|---|---:|---:|---|
| suites MATCH | 1,993 | **2,000** | +7 |
| suites non-match | 134 | **127** | -7 |
| diverging assertion rows | 2,256 | **1,120** | **-50.4%** |
| assertion-level parity | 97.865% | **98.939%** | +1.07pp |

**Seven suites fixed, ZERO regressed.**

| suite | diverging rows recovered |
|---|---:|
| `go-go_types` | 507 |
| `cpython-importlib` | 349 |
| `go-go_internal_gcimporter` | 13 |
| `ltp-mq_notify01` | 6 |
| `ltp-msgsnd06` | 2 |
| `ltp-nice05` | 1 |
| `cpython-asyncio` | 1 |

The last four are the suites previously attributed as pre-existing intermittents
(`mq_notify01` measured 3/8 broken on the v5 source, `msgsnd06` hung 2/2 there).
They matching here is consistent with that attribution — it is NOT evidence they
were fixed, and they should be expected to flip again.

## The lease-generation fix reached further than predicted

It was written to stop a NULL-dereference crash. It also removed a large amount
of wasted work, because a stale row re-authenticating meant re-doing scrub and
fault work against an identity that had already been retired:

| suite | v6 | v7 |
|---|---|---|
| `go-go_types` | 360 s truncated, 50.29x | **152 s success, 21.27x** |
| `go-go_internal_gcimporter` | 360 s truncated, 60.76x | **81 s success, 13.69x** |
| `cpython-importlib` | crashed at 6 s | **35 s success, 13.22x** |

Note `cpython-importlib`'s v6 ratio of 2.4x was meaningless — it crashed early,
so the wall clock measured a dead run. Its real cost is 13.22x.

## What the remainder now is: fork/exec throughput

The crashes are gone from the multiprocessing trio; what is left is speed.

| suite | v6 | v7 | reading |
|---|---|---|---|
| `cpython-multiprocessing_spawn` | 95 s, **aborted** | 600 s truncated, 9.74x | no longer aborts; now runs into its budget |
| `cpython-multiprocessing_fork` | 600 s truncated, 11.81x | 420 s, 8.27x, completes with failures | |
| `cpython-multiprocessing_forkserver` | 600 s truncated | 600 s truncated, 10.32x | unchanged |

These are the three most fork/exec-intensive suites on the surface, and they are
now the top of the remaining ledger. That is a throughput problem in the
primitive, not a semantic one.

**Directly measured, and the reason this matters more than the suite ratios
suggest** (`docs/perf-results/2026-08-18-futex-requeue-admission/reducers/`):

| live children | carrick per fork | Docker per fork |
|---:|---:|---:|
| 32 | 7.93 ms | 0.12 ms |
| 64 | 9.87 ms | 0.12 ms |
| 128 | 14.97 ms | 0.11 ms |
| 256 | **25.29 ms** | 0.13 ms |

66x at the low end, 200x at 256 — and **super-linear**, while Docker is flat. A
growing-vs-flat curve is an algorithmic defect, not a constant-factor tax. It
also sits against `f1fc82c04`'s recorded claim that fork was de-quadraticized to
1.7 ms at 1000 live; either that regressed, or it was fixed for a fixture whose
children exit while these stay parked and live.

Under HVPatch there is no host `fork` at all: a guest fork should be a
kernel-graph task plus a stage-1/stage-2 mapping transaction, with no
address-space copy and no host process creation. The phases are already
instrumented (`hvpatch-fork-runtime-stage`: Quiesce, ProcessAllocate,
PidfdParent, ProcessSpec, DispatcherClone, RuntimeState, ThreadSpawn,
ChildReady) and read by `scripts/dtrace/hvpatch-phase4-fork-runtime-stages.d`,
so the next step is to run the ladder at n=32 and n=256 under those probes and
find the phase that grows with population.

## Budgets are hang detectors, not performance gates

Worth stating because it is easy to misread a MATCH: the declared budgets are
far looser than the 2x bar — `multiprocessing_*` allow 600 s against a ~50-60 s
oracle, i.e. ~10x, and `go-go_types` allows 360 s against 7 s, i.e. 50x. A suite
can therefore be a clean MATCH while sitting at 9x. Suite verdicts alone can
never establish the performance gate; only the ratio column on valid completing
rows can.

## Remaining top of ledger

`cpython-multiprocessing_spawn` (228), `forkserver` (200),
`ltp-futex_cmp_requeue01` (122 — 7/7 standalone, still degrading under
eight-worker gate load), `cpython-socket` (41), `ltp-process_vm_readv03` (33,
deliberately EFAULT until the foreign-mm transfer exists), `cpython-builtin`
(30), `ltp-ioctl_pidfd01` (25), then a long LTP tail of individually attributed
gaps.
