# Closure checkpoint — post memory/inventory cluster

**Date:** 2026-08-17
**Lane:** canonical macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest

Full-surface closure on the artifact that closed `ltp-mremap01` and the
HVPatch alias-retirement/`OutOfTables` crash cluster.

## Artifact

| | |
|---|---|
| HEAD | `af86c4ce4143a76d0804ec98bf68a243fd72e667` |
| binary sha256 | `195e11b8759a3514aa69033a72992a0dc4adea362064596a91e3c0e1ad8a9dab` |
| CDHash | `1a5a5840f243cd288638e564eb1dc6580a3d317c` |
| hypervisor entitlement | present |
| `__TEXT,__dof_carrick` | present |
| scope | 2,127 suites |

Built from a clean tree at that exact HEAD with nothing newer than the binary.

## The first run of this artifact was DISCARDED

Two guests orphaned by an earlier `timeout` (a `test_multiprocessing_forkserver`
at 36 minutes and a `test_concurrent_futures` at 23 minutes) were still alive and
burning CPU when the run started, and they covered its whole first phase —
roughly 1,600 suites, nearly all of LTP. Since this artifact changes page-table
and memory code, a load-probabilistic flip in LTP would either invent a
regression or hide one, so the run was killed, the orphans reaped with the
scoped `scripts/sudo/kill.sh <run-id>`, and the measurement restarted.

`timeout` kills the wrapper, NOT the guest. Reap by run-id after any run that
hits its deadline; do not assume `timeout` cleaned up.

A second contaminant was found and removed before the restart:
`spotlightknowledged.updater` had been pinned at 100% CPU for over two days.
It was NOT carrick-related — every file it held open was Apple Mail semantic
indexing (`cs_mail`, `com.apple.mail`) — and carrick's own volumes
(`/Volumes/CaseSensitive`, `/Volumes/carrick`) already have Spotlight indexing
disabled. `~/.carrick` (34 GB) did sit on the one indexed volume, so it now
carries a `.metadata_never_index` marker as a precaution.

## Result

Both runs re-tallied from their raw `pairs` with IDENTICAL rules, because the
numbers quoted in the previous checkpoint's README used a different definition
and are not comparable to these.

| metric | post-libuv | this run | delta |
|---|---:|---:|---:|
| suites MATCH | 1,201 | **1,202** | +1 |
| suites INCOMPLETE | 926 | **925** | −1 |
| assertion rows agreeing | 101,533 | **101,637** | +104 |
| semantic gaps (both sides emitted, verdicts differ) | 146 | **151** | +5 |
| unexercised (one side absent) | 5,598 | **4,056** | **−1,542** |

Rules: a pair is `unexercised` if either side is `absent`, `agree` if both sides
emitted the same verdict, and a `semantic gap` if both emitted and they differ.

**Read the suite headline with care.** A suite is INCOMPLETE if even ONE
assertion diverges, so +1 MATCH badly understates the change; the assertion
counts are where the work shows. The −1,542 unexercised rows are rows carrick
previously never produced at all — it crashed or refused before reaching them.

## Where the movement came from

| suite | Δ unexercised | why |
|---|---:|---|
| `ltp-mremap01` | **−1,313** | `mremap` shared-mapping growth; suite is now MATCH |
| `go-os` | −634 | oracle `-t` repair; exposes 14 real gaps (see semantic +14) |
| `go-go_types` | **−574** | not touched directly — see below |
| `cpython-multiprocessing_spawn` | −282 | alias-retirement / stage-1 reclaim fix |
| `go-net` | −246 | oracle `-t` repair |
| `ltp-futex_cmp_requeue01` | −51 | |
| `ltp-setpriority01` | −37 | oracle `CAP_SYS_NICE` repair |

`go-go_types` went from 574 unexercised rows to zero without being worked on
directly, which is consistent with it having been dying on the same
`OutOfTables` stage-1 pool exhaustion that `af86c4ce4` fixed. Worth confirming
rather than assuming.

The `+5` semantic gaps are not a regression in the usual sense: rows that were
previously `absent` are now emitted and compared, and a few of them disagree.
Going from "never ran" to "ran and disagrees" is forward progress that shows up
as a small increase in this column.

## Verdict flips, and what they turned out to be

Newly MATCH: `ltp-mremap01`, `ltp-shmget03`, `ltp-waitid08`.

Regressed MATCH -> INCOMPLETE: `ltp-exit_group01`, `ltp-pidfd_open04`. Both were
re-sampled immediately rather than filed as regressions:

- `ltp-pidfd_open04` — clean 3/3 on re-run. The closure flip was noise.
- `ltp-exit_group01` — fails intermittently, roughly 1 run in 3, with
  `exit_group01.c:96: TFAIL: Expect: exit_group() succeeded` followed by
  `Threads counters value didn't change`. So `exit_group()` occasionally fails to
  report success when threads are live. That is a REAL race, but an intermittent
  one; single-run closure verdicts cannot distinguish it from a regression, which
  is why it was sampled. **Attribution against the pre-change binary is still
  outstanding** — this artifact changes page-table teardown, so carrick cannot be
  ruled out as the cause until the base revision is sampled the same way.

## CORRECTION — two of the outliers were a regression in THIS artifact

The paragraph originally here dismissed the `>= 10x` outlier list as
pre-existing hangs and moved on. That was wrong, and it is the most important
thing on this page.

`go-net_http` and `go-syscall` did not "not complete". They completed fine on
the previous artifact and were broken BY `af86c4ce4`:

| suite | post-libuv | this run |
|---|---|---|
| `go-net_http` | success, 1,316 rows, **56.8 s** | **timeout, 0 rows, 540.5 s** |
| `go-syscall` | 38 rows, **43.4 s** | **timeout, 0 rows, 180.8 s** |

Bisected, two samples per point: `c08221355` 50 s, `a6fd9e6fb` 51 s,
`af86c4ce4` does not finish in 250 s. Cause and fix are in `10c62b8cb` —
exclusivity was allowed to re-enable EAGER table reclamation, whose
512-descriptor scans run on every `apply`. Fixed by moving reclamation to the
paths that would otherwise return `OutOfTables`.

**So the 1,388 `go-net_http` rows and 58 `go-syscall` rows counted as
`unexercised` in the table above are this regression, not a pre-existing gap.**
The −1,542 headline is therefore an UNDERSTATEMENT: it nets a real ~−1,542
improvement against ~+1,446 rows of self-inflicted loss. The next closure on a
post-`10c62b8cb` artifact is the one to quote.

The general lesson is the one AGENTS.md already states and this page failed to
apply: a suite sitting on its timeout reports as spectacularly slow, so a ratio
is never evidence on its own — but "it's a known hang" is not a free pass
either. Diff the outlier list against the previous run before explaining it
away.

## Performance — not yet the phase

Remaining `>= 10x` rows still should not be read as performance numbers while
the suite does not complete.

`per-suite-ledger.jsonl` in this directory carries name, ecosystem, verdict,
agree/semantic/unexercised counts and the perf ratio for all 2,127 suites, so the
next checkpoint can be diffed against this one with identical rules instead of
re-deriving them.
