# closure-v5 — performance baseline, and how to read it

**Date:** 2026-08-18
**Artifact:** source `575c9288d`, binary
`c6e35353d915389714cdc5c5a60827eab822bdbfea444b79a67b83b205b9fb01`.

## Read this caveat first

These ratios come from the `closure-v5` correctness run, which uses **8 workers
on a 10-core host**. Every number below is therefore **contention-inflated and
is a hypothesis, not a controlled measurement** — AGENTS.md is explicit that a
concurrency sweep is never a clean variable on Apple Silicon, where the cores
are not homogeneous (4 P + 6 E). The final `<= 2.0x` gate needs paired serial
measurements, not this.

Rows whose carrick side `truncated` or produced no result are **excluded**: a
timed-out suite sits on its deadline, so quoting its ratio as performance is
simply wrong. Only valid completing rows are counted.

## Aggregates over valid completing rows

| ecosystem | rows | median | mean | share `<= 2.0x` | rows `>= 10x` |
|---|---:|---:|---:|---:|---:|
| LTP | 1,474 | **1.24x** | 1.58x | 81.5% | 7 |
| Go | 191 | **1.67x** | 2.24x | 91.1% | 6 |
| CPython | 435 | **1.94x** | 2.24x | 57.2% | 3 |
| Node | 3 | **1.95x** | 2.07x | 66.7% | 0 |

**Every ecosystem's MEDIAN is already at or under the 2.0x bar, even contended.**
The means are dragged up by a thin tail, so the remaining performance work is
tail work, not a broad regression — which is a materially different problem from
the one the raw outlier list suggests.

The cold `go-build` row (`go-build`, the real build workload rather than the
`go_build` package test) sits at **4.61x** and is measured separately; it is the
figure the campaign's 2x bar was originally written against.

## Valid completing rows at `>= 10x`

The goal treats each of these as a correctness blocker.

| ratio | suite | verdict |
|---:|---|---|
| 51.03x | `ltp-msgrcv06` | incomplete |
| 50.09x | `cpython-tarfile` | incomplete |
| 32.87x | `go-crypto` | match |
| 29.73x | `go-go_internal_srcimporter` | match |
| 28.32x | `go-go_build` | match |
| 27.50x | `ltp-timerfd_settime02` | match |
| 20.56x | `ltp-openat03` | match |
| 17.20x | `go-crypto_internal_fips140deps` | match |
| 15.49x | `go-go_doc_comment` | match |
| 13.38x | `ltp-fcntl31_64` | incomplete |
| 13.02x | `ltp-fcntl31` | incomplete |
| 11.32x | `cpython-os` | incomplete |
| 10.83x | `cpython-pathlib` | incomplete |
| 10.71x | `ltp-request_key03` | incomplete |
| 10.33x | `ltp-fork09` | match |
| 10.30x | `go-net_http` | match |

## One attribution already made

`ltp-timerfd_settime02` (27.5x) is **not** a timerfd defect. Its transcript is
`tst_fuzzy_sync` — a raw-syscall race harness that runs 1024-iteration batches
and reports nanosecond-scale deviation ratios. It is the same family as
`inotify09`, `msgrcv06` and `shmctl05`, and the project already records that
family as roughly 30x under carrick. The cost is per-syscall round-trip inside a
tight loop, so it belongs to the general overhead workstream and not to a hidden
correctness bug in timers. `ltp-fcntl31`/`_64` are a different story — their
13x is a `sigtimedwait()` that times out because SIGIO is never delivered on an
`O_ASYNC` fd, i.e. a real gap whose ratio is an artifact of the timeout.

The two `incomplete` rows above 50x are truncations in all but name and should
be re-read once their correctness gap closes.
