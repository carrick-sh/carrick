# LTP full-suite conformance baseline

The denominator + headline metric for the LTP-conformance campaign (drive
carrick's verified-MATCH across the ENTIRE LTP syscalls testsuite). This is
the honest, reproducible accounting that replaces "LTP MATCH count" — see
`docs/conformance-coverage.md` for the probe gate that locks each gain.

## How to (re)generate

```sh
# Resumable full sweep (Docker oracle vs carrick, per test). Hours for ~1436
# tests; appends docs/ltp-baseline/results.jsonl, skips already-recorded tests.
python3 scripts/ltp-baseline.py            # all areas
python3 scripts/ltp-baseline.py --area fs  # one area
python3 scripts/ltp-baseline.py --tally    # re-emit the per-area table below
```

Inventory: `docs/ltp-baseline/inventory.json` — **1436** syscall tests from the
image's `runtest/syscalls` manifest, grouped into 11 areas:

| area | tests |  | area | tests |
|---|---|---|---|---|
| fs | 442 | | net | 53 |
| process | 392 | | signals | 51 |
| mm | 117 | | ipc | 47 |
| sched | 67 | | xattr | 29 |
| epoll_poll | 62 | | other | 121 |
| timers | 55 | | **total** | **1436** |

## Classification (honest accounting)

A test is a valid differential signal **only when Docker (the oracle) cleanly
passes it** (passed>0, no fail/break). Otherwise it's `NO_ORACLE` and excluded
from the denominator — Docker's own seccomp/caps fail many privileged tests
(`acct`, `add_key`, `bpf`, the `*_16` 16-bit-uid compat variants), so they
can't tell us anything about carrick.

| class | meaning |
|---|---|
| `MATCH` | carrick's verdict == Docker's clean pass (same counts). The headline number. |
| `MATCH_PARTIAL` | carrick passed with no failures but fewer subtests ran than Docker. |
| `DIFF` | real divergence — carrick failed, produced nothing, or diverged. The work queue. |
| `TBROK` | carrick's framework setup broke (broken>0) where Docker's didn't — a hidden test. Clear the blocker (Milestone 2). |
| `TIMEOUT` | carrick hung (rc 124) — worst class. |
| `NO_ORACLE` | Docker didn't cleanly pass → not a usable differential test; excluded from the denominator. |

**Headline metric** = `MATCH / (oracle-valid)` per area and overall, where
oracle-valid = everything except `NO_ORACLE`. Paired with the owning-probe
count in `docs/conformance-coverage.md` — a MATCH without a probe is not "done."

## Per-area tally

**Complete sweep: 1436 / 1436.** Re-run `python3 scripts/ltp-baseline.py
--tally` for the live table. Includes the fcntl-record-lock, writev-iovec,
SysV-semaphore, and SysV-msg-queue fixes landed against it.

| area | MATCH | PARTIAL | DIFF | TBROK | TIMEOUT | NO_ORACLE | total | verified-MATCH (of oracle-valid) |
|---|---|---|---|---|---|---|---|---|
| timers     | 26 | 0 | 2   | 7  | 0 | 20  | 55  | **74%** |
| signals    | 36 | 0 | 3   | 7  | 3 | 2   | 51  | **73%** |
| epoll_poll | 31 | 3 | 6   | 12 | 0 | 10  | 62  | **60%** |
| sched      | 32 | 0 | 12  | 5  | 0 | 18  | 67  | **65%** |
| other      | 47 | 2 | 17  | 2  | 0 | 53  | 121 | **69%** |
| fs         | 171| 0 | 91  | 39 | 0 | 141 | 442 | **57%** |
| process    | 113| 1 | 30  | 41 | 1 | 206 | 392 | **61%** |
| ipc        | 14 | 0 | 14  | 12 | 0 | 7   | 47  | **35%** (sem + msg queues functional) |
| net        | 13 | 0 | 15  | 9  | 0 | 16  | 53  | **35%** |
| mm         | 18 | 1 | 32  | 22 | 1 | 43  | 117 | **24%** |
| xattr      | 3  | 0 | 1   | 1  | 0 | 24  | 29  | **60%** |
| **TOTAL**  | **504** | **7** | **223** | **157** | **5** | **540** | **1436** | **504/896 = 56%** |

_Refreshed 2026-05-29 against HEAD after 11 M4 fix clusters (roadmap #10 errno +
fsync, #4 signalfd4, #13 sched/priority errno, #17 flock+removexattr, #11 chmod
setgid+fchmodat2, #22 fcntl leases, #8 pread/readv special-fd errno, #5 openat2
validation). +79 MATCH vs the committed 425; **zero area regressed**. Each fix
probe-gated; conformance gate green at 92 probes. fs jumped 142→171._

### The target (DoD #2)

Live: **56% verified-MATCH** of oracle-valid tests (504/896; full sweep, HEAD;
57% incl. partial). Committed baseline was 47% (425/898). The curated four are
gated mostly by TBROK framework blockers, not errno DIFFs: signals 73% (DIFF 3 /
TBROK 7 / TIMEOUT 3), timers 74% (DIFF 2 / TBROK 7), sched 65% (DIFF 12 / TBROK
5), epoll 60% (DIFF 6 / TBROK 12) — clearing the tst_test framework blocker
(+ the mkfifo-setup / functional-FIFO class) is the highest-leverage path to the
90% curated target. (Docker-oracle cache added to the sweep harness: re-sweeps
are now carrick-only, ~halved cycle time.)
The climbing gate:
- **Phase 1 — 60%**: clear the biggest TBROK framework-blocker classes (ipc
  msg-queues, the `mount(tmpfs)` setup, the tst_test variant-switching hang)
  and the concentrated DIFF clusters (each → an owning probe).
- **Phase 2 — 75%**: bring every worked area to ≥75%; the curated four
  (signals/epoll/timers/sched) to ≥90%.
- The whole-suite floor rises with each area; `process`/privileged tests that
  Docker itself can't run stay NO_ORACLE (excluded, not counted against us).

### Landed against this baseline (each probe-gated)
- fcntl record locks (host forwarding) → `fcntllock`
- writev/readv iovec validation → `iovecedge`
- SysV semaphores (host forwarding) → `sysvsem`
- SysV message queues (host forwarding) → `sysvmsg`

<!-- prior early-sample note retained below for history -->
_(early fs sample was: 47 MATCH / 12 DIFF / 3 TBROK
/ 29 NO_ORACLE = 76% verified-MATCH of oracle-valid, notably above the curated
areas' 54%, confirming substantial uncurated conformance was simply
unmeasured.)_
