# Closure checkpoint — post futex wake-durability (SUPERSEDED by `closure-v9`)

**Date:** 2026-08-19
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest

## Artifact

| | |
|---|---|
| HEAD | `8c7731a20` |
| binary sha256 | `96ef9311074c7e23c3d50dd4b7276ded10ce8ea8efb64b6d5e21ea4817efad1d` |
| CDHash | `ccd1a9d4250caed18757b2d0475aa5af122fffc4` |
| hypervisor entitlement | present |
| `__TEXT,__dof_carrick` | present |
| scope | 2,127 suites, re-frozen and checked |

`just ci` exited 0 (3,912 tests) and the probe gate was GREEN (0 failures) on this
source before the run.

## Result — a REGRESSION the probe gate could not see

| metric | v7 | v8 |
|---|---:|---:|
| suites MATCH | 2,000 | **1,999** |
| suites non-match | 127 | **128** |

| direction | suite | v7 rows |
|---|---|---:|
| **fixed** | `cpython-multiprocessing_spawn` | 228 |
| **fixed** | `ltp-msgrcv06` | 2 |
| regressed | `cpython-asyncio` | — |
| regressed | `cpython-concurrent_futures` | — |
| regressed | `ltp-nice05` | 1 (a known flapper; it was a v7 "fix") |

And the headline number, which the suite tally hides:

    ltp-futex_cmp_requeue01   122 diverging rows  ->  1,557
                              1,550 assertions, ALL FAILED, passed=0

## What it caught, and why only a full run could

The wake-durability work made the destination of a `FUTEX_CMP_REQUEUE` durable by
MARKING each moved waiter and then relinking it. The relink does not wake anyone,
so the mark stayed unclaimed until something unparked the waiter — and that
something is normally the very `FUTEX_WAKE` on uaddr2 it was waiting for. The
waiter consumed the mark, re-parked, and never returned. **The bookkeeping meant
to make the move durable was eating the wake it existed to deliver.**

`futexforkrequeue`, the probe that drove the whole fix, passed throughout — before
and after — and so did the entire probe gate. The three regressed cpython/LTP
suites and the 1,550-assertion blow-up were visible ONLY on the full surface.

That is the lesson worth keeping: a green probe gate is not evidence that a core
primitive is correct. The probe exercises one shape; `futex_cmp_requeue01` waits,
requeues and then wakes THROUGH the destination, which is the shape that fails.

Fixed in `dddc9c01b`: a requeue tells a waiter WHERE it is queued; it is not a
wake and must not consume one. The mark is applied and then the token is honoured.

Verified after the fix, before `closure-v9` was started:

- `ltp-futex_cmp_requeue01` 7/7 passed, 0 failed, two runs (`futex_cmp_requeue()
  returned 800`, futex1 woken 500, spurious wakeups 0) — matching the oracle's 7/7.
- `cpython-concurrent_futures` SUCCESS, 255 tests.
- `cpython-asyncio` SUCCESS, 2,572 tests.
- `futexforkrequeue` still exact (800 / 500 / 200, zero timeouts), probe gate
  green, `just ci` green.

## Tooling gaps this run exposed

`closure-report.py` could not render this run at all:

1. It kept a four-value result vocabulary (`success`/`failure`/`none`/`empty`)
   after the harness gained `SuiteOutcome::Truncated`. Two implementations of one
   vocabulary drifted.
2. A truncated suite can have all-matching assertion pairs and still be a
   non-match — `ltp-shmctl05` emitted one assertion, it matched, and the suite
   still hit its deadline. That tripped "non-match without an attributable
   assertion" when the attributable reason is that it TIMED OUT.

Both fixed in `7f3c8a200`; `truncated` is now classified as infrastructure, so it
is counted as a failure and never read as a pass. A third requirement stands: the
report wants a CLOSURE-MODE probe log (`CARRICK_PROBE_MODE=closure`), not the
ordinary probe-gate log.
