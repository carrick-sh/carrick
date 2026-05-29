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
| signals    | 33 | 0 | 7   | 6  | 3 | 2   | 51  | **67%** |
| epoll_poll | 30 | 3 | 7   | 12 | 0 | 10  | 62  | **58%** |
| sched      | 28 | 0 | 16  | 5  | 0 | 18  | 67  | **57%** |
| other      | 41 | 2 | 23  | 2  | 0 | 53  | 121 | **60%** |
| fs         | 147| 0 | 113 | 41 | 0 | 141 | 442 | **49%** |
| process    | 111| 1 | 31  | 41 | 2 | 206 | 392 | **60%** |
| ipc        | 14 | 0 | 14  | 12 | 0 | 7   | 47  | **35%** (sem + msg queues functional) |
| net        | 13 | 0 | 15  | 9  | 0 | 16  | 53  | **35%** |
| mm         | 18 | 1 | 32  | 22 | 1 | 43  | 117 | **24%** |
| xattr      | 1  | 0 | 3   | 1  | 0 | 24  | 29  | **20%** (ENOATTR→ENODATA) |
| **TOTAL**  | **462** | **7** | **263** | **158** | **6** | **540** | **1436** | **462/896 = 52%** |

_Refreshed 2026-05-28 against HEAD (re-swept the 473 non-MATCH oracle-valid
tests after the post-14:25 fixes: set\*id cred model, ENAMETOOLONG/ENOTDIR,
ioprio/vhangup, getrandom, capget, ENOATTR→ENODATA). +37 MATCH vs the committed
425; `process` jumped 87→111 from the set\*id keystone. NO_ORACLE 538→540 = 2
Docker-side jitter tests (re-confirm not masking a regression)._

### The target (DoD #2)

Live: **52% verified-MATCH** of oracle-valid tests (462/896; full sweep, HEAD).
Committed baseline was 47% (425/898).
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
