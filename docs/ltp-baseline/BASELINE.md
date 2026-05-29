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
| epoll_poll | 34 | 3 | 6   | 9  | 0 | 10  | 62  | **65%** |
| sched      | 33 | 0 | 11  | 5  | 0 | 18  | 67  | **67%** |
| other      | 48 | 2 | 16  | 2  | 0 | 53  | 121 | **71%** |
| fs         | 189| 0 | 74  | 32 | 6 | 141 | 442 | **63%** |
| process    | 114| 1 | 29  | 41 | 1 | 206 | 392 | **61%** |
| ipc        | 14 | 0 | 14  | 12 | 0 | 7   | 47  | **35%** (sem + msg queues functional) |
| net        | 13 | 0 | 15  | 9  | 0 | 16  | 53  | **35%** |
| mm         | 25 | 1 | 28  | 19 | 1 | 43  | 117 | **34%** |
| xattr      | 3  | 0 | 1   | 1  | 0 | 24  | 29  | **60%** |
| **TOTAL**  | **535** | **7** | **199** | **144** | **11** | **540** | **1436** | **535/896 = 60%** |

_Last refresh (2026-05-28): the functional-FIFO cluster (commit `31f2a7c`) added
+6 verified-MATCH — `select01` flipped to MATCH (16/16) via the FIFO O_RDWR leg +
the select multi-set return-count fix; `mknod02–05/09`, `mknodat01` now MATCH
(real `mkfifoat` FIFOs). fs 171→176, epoll_poll 31→32; DIFF 223→219, TBROK
157→154. Residual in this cluster is non-FIFO: `mknod01` device-node creation
(macOS can't `mknod` char/block devices — inherent), `mknod06` tst_test re-exec
hang, `select03`/`pselect02` select error-edge TBROK, `mknod08` DAC EACCES._

_Last refresh (2026-05-29, mm): the mmap/munmap correctness fixes (commit
`4878690`) re-swept the mmap*/munmap* family — `mmap08` (bad-fd-before-length →
EBADF), `munmap01`/`munmap02` (unmap a MAP_SHARED/MAP_PRIVATE file region), and
`munmap03` (page-alignment + out-of-range EINVAL edges) all → MATCH. The
re-sweep also caught up stale mm records from earlier M4 commits: mm MATCH
19→25, DIFF 30→28, TBROK 23→19 (no test regressed). Probe `mmapmunmap`. Total
verified-MATCH 529→535/896 (60%); mm 26%→34%._

_Earlier 2026-05-29: the mkdir setgid-directory-inheritance fix (commit
`f6280ba`) flipped `mkdir02` → MATCH (+1) — a dir created inside an S_ISGID
parent now inherits the parent's GID + gets S_ISGID. fs 188→189; DIFF 202→201.
Probe `mkdirsetgid`. `mkdir04` stays DIFF (mkdir-in-non-writable-parent →
EACCES, the deferred DAC/guest-root class shared with rmdir03/statfs03/mknod08)._

_Refreshed 2026-05-29 against HEAD after 11 M4 fix clusters (roadmap #10 errno +
fsync, #4 signalfd4, #13 sched/priority errno, #17 flock+removexattr, #11 chmod
setgid+fchmodat2, #22 fcntl leases, #8 pread/readv special-fd errno, #5 openat2
validation). +79 MATCH vs the committed 425; **zero area regressed**. Each fix
probe-gated; conformance gate green at 92 probes. fs jumped 142→171._

### The target (DoD #2)

Live: **59% verified-MATCH** of oracle-valid tests (528/896; full sweep, HEAD;
60% incl. partial). NOTE: re-measuring the fcntl family surfaced fcntl07/14
(+_64) as TIMEOUT (F_SETLKW cross-process blocking locks — a separate
blocking-lock/framework-lifecycle cluster, NOT the F_GETLK path this batch
fixed; the change is dead-code for F_SETLKW and fcntl05 MATCHes). Committed baseline was 47% (425/898). The curated four are
gated mostly by TBROK framework blockers, not errno DIFFs: signals 73% (DIFF 3 /
TBROK 7 / TIMEOUT 3), timers 74% (DIFF 2 / TBROK 7), sched 67% (DIFF 11 / TBROK
5), epoll 65% (DIFF 6 / TBROK 9) — clearing the tst_test framework blocker
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
