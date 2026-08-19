# Did the futex work regress the gate? No — controlled A/B says it is net-positive

**Date:** 2026-08-19

`closure-v9` and `closure-v10` both looked WORSE than `closure-v7` on the same
frozen surface: 1,400 / 1,398 diverging rows against v7's 1,120, with
`cpython-multiprocessing_fork` going from a 420 s completion to a 600 s timeout
and `ltp-futex_cmp_requeue01` from 122 diverging rows to 208 then 227. Two
post-change samples against one pre-change sample all pointed one way, and I was
ready to start removing pieces of the fix.

**That attribution was wrong.** A controlled A/B refutes it.

## Method

Both arms through the REAL harness, identical in everything but the binary:
24 heavy suites (the longest-running rows of `closure-v10`), `--workers 8`,
all oracles cached so the run is carrick-only, `--carrick-bin` swapping the
binary. Arms run SEQUENTIALLY, never concurrently.

| arm | binary |
|---|---|
| prefutex | `7d87ad413e97b4f6…` (parent of `f730625fb`, before any futex work) |
| current | `c0473635ec816905…` (all four futex commits) |

## Result

| suite | prefutex | current |
|---|---|---|
| `ltp-futex_cmp_requeue01` | match / 0 rows / 16.4 s | **match / 0 rows / 15.7 s** |
| `go-net_http` | **timeout / 540 s** | **match / 53.8 s** |
| `go-go_internal_gcimporter` | **timeout / 360 s** | **match / 103 s** |
| `cpython-multiprocessing_fork` | regression / 2 rows / 409.7 s | regression / 3 rows / **280.2 s** |
| `cpython-multiprocessing_spawn` | match / 0 / 99.8 s | match / 0 / 100.3 s |
| **totals** | **13 match, 49 rows** | **15 match, 50 rows** |

Only three suites differ, and all three favour the current binary: two suites
that TIMED OUT before now match (`net_http` 10x faster, `gcimporter` 3.5x), and
the fork-heavy suite is 1.46x faster. The one suite the whole investigation was
about — `futex_cmp_requeue01` — is IDENTICAL on both arms.

The speedups are consistent with what the fix did: removing a carrier-wide mutex
from the wake path, and eliminating lost wakes that previously stalled a waiter
until its timeout.

## What actually went wrong in the attribution

`closure-v7`, `-v9` and `-v10` are single samples of a load-probabilistic
surface, and the suites I compared sit near their timeout budget. Watching one
suite across the three runs shows the noise directly:

| suite | v7 | v9 | v10 |
|---|---|---|---|
| `cpython-multiprocessing_spawn` | 600 s truncated | 600 s truncated | 107 s success |
| `cpython-importlib` | 35 s | 34 s | 300 s truncated |
| `cpython-concurrent_futures` | ok | ok | fail (same wall time) |

A suite that flips between 107 s and a 600 s timeout across runs of the same
scope cannot support a 280-row conclusion drawn from one sample per side. This is
exactly the trap `AGENTS.md` names — "a load-probabilistic verdict will make a
one-run-per-point bisect converge on the WRONG commit" — and it caught me even
though I had two samples on one side, because I had only ONE on the other.

The rule that would have saved the cycle: **before believing a regression, take
the pre-change measurement yourself, under matched conditions.** A number
inherited from an earlier run is not a control.

## Two wasted experiments, and why

Before this A/B I built two synthetic-load harnesses and got nothing from either:

1. The first captured guest output through a command substitution. `timeout`
   killed the parent `carrick`, an orphaned guest child kept the pipe open, and
   the read blocked forever. Same pipe-read hang that had already stranded a
   Docker container earlier the same day.
2. The second used five continuously-looping fork-heavy guests. That pushed the
   PREFUTEX binary into a hang on a suite it finishes in 18 s at gate load — a
   regime the gate never enters, so it could not discriminate. A load that
   saturates both arms produces a confident-looking null result that means
   nothing.

Both were avoidable: the harness already takes `--suite`, `--workers` and
`--carrick-bin`, which IS a per-binary A/B at gate parallelism. Reach for the
in-tree instrument before building a load generator.

## Standing conclusion

The four futex commits (`f730625fb`, `dddc9c01b`, `6ba748fac`, plus the
`70837dda6` gettid fix alongside) are net-positive and stay. The remaining
`closure-v10` gap against v7 is measurement noise on a load-probabilistic
surface, not a code regression.

**The measurement instability is itself now a blocker.** The goal forbids
retry-recovered acceptance, and a gate whose suites flip between match and a
600 s timeout across identical runs cannot certify 100% parity. Suites sitting on
their timeout budget have to be made fast enough to stop flipping — which is the
same work as the >=10x correctness-blocker rule, and the same work as the
fork/exec pathology.
