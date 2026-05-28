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

> **Status: sweep in progress.** Run `python3 scripts/ltp-baseline.py --tally`
> for the live table. The committed snapshot below is updated as areas
> complete. The 4 curated areas (signals/epoll/timers/sched) were ~54%
> MATCH under the old count-based verdict; this baseline re-measures them
> under the honest-oracle classifier alongside the ~1370 previously-unmeasured
> tests.

_(snapshot pending full sweep — early fs sample: 47 MATCH / 12 DIFF / 3 TBROK
/ 29 NO_ORACLE = 76% verified-MATCH of oracle-valid, notably above the curated
areas' 54%, confirming substantial uncurated conformance was simply
unmeasured.)_
