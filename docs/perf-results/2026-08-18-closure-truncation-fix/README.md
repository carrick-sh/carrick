# Closure checkpoint — post truncation fix

**Date:** 2026-08-18
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest

First closure whose accounting is trustworthy: the harness no longer discards a
timed-out run's transcript (`6e48c1479`), and the 10x `go-net_http`/`go-syscall`
regression from `af86c4ce4` is fixed (`10c62b8cb`).

## Artifact

| | |
|---|---|
| HEAD | `6e48c1479d366eef37fc2657b36d6f20171a1c6c` |
| binary sha256 | `cff33c6c5f06d7ef0b9f1967fc9c9bfb038f895ac7d379bf29b0f5e5788fe6d1` |
| CDHash | `f5f2c28332d54099f5e7dcd00fd57c18a0a26c70` |
| hypervisor entitlement | present |
| `__TEXT,__dof_carrick` | present |

Two orphaned guests from earlier interactive runs (`nh-cur`, `nh-fix`) were
reaped by run-id before the run started. That is the second time `timeout`
orphans have nearly contaminated a measurement; reap-by-run-id after any
deadline hit is now standing procedure.

## Result (identical tally rules as the two prior checkpoints)

| metric | post-libuv | this run | delta |
|---|---:|---:|---:|
| suites MATCH | 1,201 | **1,204** | +3 |
| assertion rows agreeing | 101,533 | **103,163** | **+1,630** |
| semantic gaps | 146 | 151 | +5 |
| unexercised | 5,598 | **2,572** | **−3,026** |

**Zero verdict regressions** — no suite went match → incomplete. Newly MATCH:
`ltp-mremap01`, `ltp-shmget03`, `ltp-tgkill01` (previously a 66x outlier).
`ltp-exit_group01` and `ltp-pidfd_open04`, which flipped in the discarded
intermediate run, are both MATCH here — consistent with the flakiness the
re-sampling found.

The −3,026 decomposes into the real fixes (mremap ~1,313, multiprocessing_spawn
282, go_types 574) plus the truncation fix keeping rows that timeouts used to
discard, net of the regression rows restored by `10c62b8cb`.

Confirmed in-closure: `go-net_http` success 1,316/1,316 rows at 51.4 s;
`go-go_types` success 571/571 (the OutOfTables hypothesis for its earlier
574-row wipeout is now measured, not assumed);
`cpython-multiprocessing_spawn` emits all 323 rows at 2.35x (down from a hang).

## New fact: `go-syscall` is LOAD-SENSITIVE

Standalone on this artifact it completes in 19 s. Under the closure's 8-worker
load it hit its 180 s budget (`truncated`, 6 rows kept, 47 charged). Post-libuv
it completed in 43 s under the same worker count, so the sensitivity is either
new or newly marginal. Load-coupled verdicts are a first-class failure class,
not noise — this needs a controlled two-point comparison (standalone vs
contended, ≥2 samples each) before the next re-bless.

## Remaining top clusters (from `per-suite-ledger.jsonl`)

| suite | unexercised | semantic |
|---|---:|---:|
| `cpython-multiprocessing_forkserver` | 366 | 1 |
| `cpython-importlib` | 349 | 0 |
| `cpython-multiprocessing_fork` | 227 | 0 |
| `cpython-concurrent_futures` | 178 | 1 |
| `cpython-posix` | 147 | 3 |
| `ltp-setpriority01` | 121 | 0 |
| `ltp-splice07` + `ltp-ioctl_ficlone04` | 194 | 0 |
| `ltp-futex_cmp_requeue01` | 95 | 0 |

`go-os` semantic 0→15: its oracle repair exposed 14-15 real gaps that were
previously invisible — forward progress that reads as a regression in this
column.
