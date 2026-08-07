# Build-lane amplification ledger — Darwin kernel cost per guest operation

**Date:** 2026-08-06
**Scope:** Move-3 Task 4 / E0 — the first arming of the `AMP1` instrument
(`carrick trace --profile native-amplification`), on the canonical cold
`go build` fixture, at HEAD. This is the capture the Move-3 plan ranks every
entry against
([`2026-08-06-move3-amplification-ledger.md`](../superpowers/plans/2026-08-06-move3-amplification-ledger.md)
§3 Task 4), and it carries the **fault-ownership verdict at HEAD** (§7) and the
**re-ranking of E1–E7** (§11).
**Lane:** shipped default — Darwin/AArch64 native DSR (`--exec-backend native`).

The per-op table format is the fs entry's
([`2026-08-05-fswalk-amplification-ledger.md`](2026-08-05-fswalk-amplification-ledger.md)),
extended with the two currencies that entry could not supply: host **CPU-ns**
per guest op (`vtimestamp`) and the mach-trap and `vminfo::` fault joins.

## 1. Authority

- source commit: `623ea52bb2b07690770b1a34d233668d730f957b`. Tracked tree
  clean; two **untracked** planning files (`proposed-plan.md`,
  `proposed-plan-review.md`) sat at the repo root, which is why the ledgers'
  `provenance.git_dirty` records `true` — no tracked source differed from HEAD
  and nothing untracked enters the build.
- executable (AMP1 + native-fault arms): `target/release/carrick`, SHA-256
  `2913209a0effb34a521f64a1425cbc0ad9def4fd98338320d4644f8a7ef4e6a5`, built and
  codesigned through `just build` (default features); `__DATA,__dof_carrick`
  present. The alloc-owner arm (§9) used a separate
  `just build --features alloc-owner-census` binary, digest recorded there —
  the census is a non-default diagnostics feature and its arm contributes
  **counts only**.
- image, digest-pinned as the AMP1 launch now requires:
  `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
  (`arm64`) — byte-identical to the fs entry's image and to the one behind the
  2026-08-03 fault-ownership pair.
- fixture (the committed capture driver's default `GUEST`, argv digest bound
  into every header as `target_argv_sha256`
  `68af39c0479c95f205d1c398fbb4f68f9da70e93e7a737e0b356eb29a35c1e25`):

  ```sh
  set -eu; cd /tmp; rm -rf gc-w; printf "package main\nfunc main(){println(\"ok\")}\n" > h.go;
  GOCACHE=/tmp/gc-w /usr/local/go/bin/go build -o h ./h.go; ./h; echo BUILD_OK
  ```

  — the same cold one-line-`main` build as `workload-spread.sh`'s `build-cold`
  and the 36x round's `series-b` (those two differ from each other in scratch
  names and `WORKLOAD_NS` brackets; this is the driver's committed spelling).
- instrument: bundled `scripts/dtrace/native-amplification.d`,
  `program_sha256`
  `3c27037db4a89f1516eeee467750a5c1e7f0d77de2fee10e52e2030e6badf6bf`;
  launch qualification `birth=ba192e68fd8a4aed0bdfc6c8839ad3cc758b9ae29600e25c1f6561b6760ca210`,
  `terminal=919ee0f898c0402916b6e0fd58bf7e5e3482f2f25dd8bbb7d6b5a05763f24fbc`;
  `joins=syscall,mach,fault`, buffers `aggsize=64m dynvarsize=256m bufsize=32m`.
- capture driver: `scripts/perf/amplification-capture.sh` (one arm per
  invocation, `--preflight-quiet-host`, `CARRICK_RUN_ID` stamped,
  `scripts/sudo/kill.sh` reap). Run ids `amp1base-a79197` /
  `amp1base-b79495` / `amp1base-c79705`; preflight settled in 0 s at
  one-minute load 2.356 / 2.339 / 2.431. Zero run-id-scoped survivors after
  every arm.
- receipts (`target/perf/task4-e0/`):

  | file | SHA-256 |
  |---|---|
  | `base-a.raw` | `9d7644e55edbf56c555866b57cecc5f8c952c94bed43f1ed1ed37a8483daf4d3` |
  | `base-b.raw` | `07cb8cd80f2b8b415343fa0aa6e18d83c27b780b8392411accdce07caab9439f` |
  | `base-c.raw` | `1b8301f37d495086ada0ee40a6aa376526bb2d67bb032631c604c759086463dd` |
  | `base-a.ledger.json` | `7b8c832f4b14bbd18082e260b0ca3590b6aab284bd1dfc98b191ee8d0762024b` |
  | `base-b.ledger.json` | `69735bece05e673d7f4d79980444330ff7f20073bea8f9db878206ab6278b259` |
  | `base-c.ledger.json` | `50071332c2c45f16ca0bbe3249c7f191f167dcbe3dcf38ff34a0f5030d4dc6e0` |

- host: macOS 27.0 build `26A5388g`, Apple M4 (4 P + 6 E), 11-day uptime — the
  same host state the 2026-08-06 denominator refresh flagged; counts are the
  claim here, not wall.
- Docker held only the `registry:2` container serving `localhost:5005`; no
  Docker workload ran in any capture window (two-phase rule).

**Perturbation, measured at first arming:** an untraced run of the identical
fixture and binary completed in **8.452 s** full-run wall (`anchor.out`,
`BUILD_OK`); the three traced completion records report 22.93 / 21.29 /
21.56 s — **2.52–2.71x**, inside the D header's declared 2–4x band. Wall from
the traced runs is never citable; it is reported here only to qualify the
header's own estimate.

## 2. Completeness — the Task-4 gate, item by item

Every item below held for **all three** arms; any one failing refuses the arm.

- capture command exit **0** (the in-band record defends against accidental
  reuse of a dropped raw, not forgery — the exit status is the gate);
- in-band `AMP1|consumer-drops|principal=0|aggregation=0|dynamic=0|dynamic_rinse=0|dynamic_dirty=0|other=0|interrupted=0`;
- program-owned drops all zero: `dtrace-error=0`, `service-window-reentry=0`,
  `service-end-unmatched=0`;
- no `section=truncated` marker — every census ended on the target's own exit;
- **every declared join armed and non-zero** (guest window, host syscall
  count + CPU, mach count + CPU, all three fault kinds — the reader refuses a
  seeded zero, and none fired);
- closure exact over all ten currencies (analyzer-asserted; both sides
  published in each ledger's `closure` block);
- `BUILD_OK` exactly once per arm; zero run-id survivors after reap;
- `carrick-only` decomposed with the instrument sub-bucket named (§5).

**Sampling rule applied:** counts are quoted from a single arm (arm A) —
deterministic-op guest counts reproduce across the three arms to within 0.3%
(`openat` 3,265/3,272/3,272; `newfstatat` 3,960/3,961/3,961; `mkdirat` 282
exactly) — while **CPU-ns is quoted as mean ± sd over n = 3**, per the plan's
counts-vs-CPU-ns rule. Scheduling-sensitive ops (`nanosleep`, `futex`,
`madvise`) vary up to ~5% in count between arms and are marked where quoted.

## 3. Whole-fixture totals (n = 3, mean ± sd)

| quantity | mean ± sd | arms (a / b / c) |
|---|---:|---|
| guest Linux syscalls | 94,409 ± 356 | 94,782 / 94,074 / 94,370 |
| host macOS syscalls | 1,010,665 ± 16,481 | 1,007,670 / 1,028,438 / 995,887 |
| **host syscalls per guest syscall** | **10.71** | 10.63 / 10.93 / 10.55 |
| host syscall CPU-ns | 2.716 s ± 0.052 | 2.776 / 2.683 / 2.688 |
| mach traps | 497,301 ± 7,870 | 489,704 / 496,780 / 505,418 |
| mach trap CPU-ns | 51.9 ms ± 1.7 | 50.3 / 51.8 / 53.7 |
| `as_fault` | 1,943,665 ± 9,318 | — |
| `zfod` | 1,544,810 ± 6,859 | — |
| `cow_fault` | 83,982 ± 617 | — |

The kernel-CPU decomposition the instrument newly supplies (traced,
same-instrument shares — do not cross with the untraced sampling profiles):

| bucket | mean ± sd | share of measured kernel CPU |
|---|---:|---:|
| measured kernel CPU (syscall + mach `vtimestamp`) | 2.767 s ± 0.051 | 100% |
| guest-attributed | 1.590 s ± 0.010 | **57.5%** |
| `carrick-only` | 1.169 s ± 0.061 | **42.2%** |
| probable instrument (`kdebug_trace*`) | 8.3 ms ± 0.1 | 0.3% |

Two readings of that split, stated against the plan's §4 invalidation
conditions: `carrick-only` is **large but does not dominate** (42.2%, of which
~0.22 s is the in-process libdtrace consumer's `ioctl` traffic — see §5 — and
~0.31 s is container-create `clonefileat`), so Move 3 remains a per-guest-op
amplification program with `carrick-only` as first-class rows, not a re-scope.
And the kernel CPU is **not** concentrated in one host call — the top rows
spread across `openat`, `fork`, `read`, `kevent`, `psynch_cvwait`,
`clonefileat` — so the "drive each toward 1" framing stands.

For context only (different workloads, both this instrument's definition): the
fs-walk entry measured 2.05x whole-fixture host-per-guest; the build lane is
**10.7x**.

## 4. The ledger

Per-op, arm A counts, CPU-ns/op as mean ± sd across the three arms. "zfod
in-window" counts `vminfo:::zfod` events that fired while that guest op's
service window was open on the faulting thread. **The two "dominant" columns
answer different questions:** "by CPU" is the analyzer's `dominant_host_call`
(ranked by CPU-ns — where the kernel time went); "by count" is the largest
host-call count in the window (recomputed from the raw's
`section=host-syscalls`) — where the calls went. They frequently disagree, and
both rankings matter (the budget is CPU-denominated; count levers are how
amplification reaches 1).

| guest op | guest count | host calls | amplification | host CPU-ns/op (n=3) | mach traps | zfod in-window | dominant by CPU | dominant by count |
|---|---:|---:|---:|---:|---:|---:|---|---|
| `clone` | 364 | 9,958 | 27.36x | 1,126,549 ± 30,710 | 2,928 | 332 | `fork` (68) | `fcntl` (3,531) |
| `openat` | 3,265 | 90,239 | 27.64x | 105,542 ± 1,161 | 28 | 539 | `openat` (28,378) | `openat` (28,378) |
| `execve` | 67 | 85,038 | 1,269.22x | 3,627,767 ± 18,051 | 2,041 | 83,487 | `read` (471) | **`close` (74,253)** |
| `newfstatat` | 3,960 | 48,034 | 12.13x | 39,665 ± 187 | 20 | 101 | `openat` (16,470) | `openat` (16,470) |
| `mkdirat` | 282 | 21,987 | 77.97x | 284,410 ± 2,051 | 7 | 0 | `openat` (7,607) | `openat` (7,607) |
| `epoll_pwait` | 1,882 | 14,155 | 7.52x | 34,847 ± 271 | 182 | 142 | `poll` (5,054) | `poll` (5,054) |
| `mmap` | 6,110 | 5,653 | 0.93x | 7,537 ± 142 | 878 | **553,526** | `mprotect` (4,417) | `mprotect` (4,417) |
| `unlinkat` | 156 | 9,888 | 63.38x | 241,213 ± 9,754 | 1 | 789 | `openat` (2,794) | `openat` (2,794) |
| `nanosleep` | 16,277 | 34,434 | 2.12x | 2,100 ± 15 | 428 | 82 | `kevent` (16,212) | `waitid` (16,826) |
| `write` | 4,785 | 4,815 | 1.01x | 6,679 ± 127 | 12 | 480 | `write` (4,761) | `write` (4,761) |
| `futex` | 7,546 | 16,093 | 2.13x | 3,722 ± 117 | 125 | 183 | `psynch_cvwait` (5,703) | `psynch_cvwait` (5,703) |
| `waitid` | 72 | 99,779 | 1,385.82x | 229,260 ± 17,024 | 198 | 58 | `kevent` (24,541) | `waitid` (73,900) |
| `read` | 6,110 | 6,539 | 1.07x | 2,524 ± 61 | 67 | 131 | `read` (6,116) | `read` (6,116) |
| `wait4` | 71 | 7,541 | 106.21x | 203,511 ± 3,680 | 0 | 13 | `sysctl` (822) | `proc_info` (4,482) |
| `close` | 3,050 | 7,554 | 2.48x | 3,613 ± 85 | 74 | 68 | `close` (5,165) | `close` (5,165) |
| `fstat` | 331 | 1,324 | 4.00x | 28,584 ± 168 | 0 | 63 | `fgetxattr` (993) | `fgetxattr` (993) |
| `utimensat` | 162 | 2,595 | 16.02x | 55,246 ± 762 | 0 | 1 | `openat` (487) | `fcntl` (649) |
| `tgkill` | 2,033 | 3,885 | 1.91x | 2,999 ± 83 | 38 | 65 | `__pthread_kill` (1,894) | `write` (1,902) |
| `rt_sigaction` | 11,115 | 102,320 | 9.21x | 547 ± 8 | 0 | 36 | `sigaction` (57,860) | `sigaction` (57,860) |
| `chdir` | 58 | 682 | 11.76x | 62,369 ± 595 | 0 | 1 | `openat` (150) | `close` (150) |
| other guest ops — 47 of them | 27,086 | 8,746 | — | — | — | — | — | — |
| — `carrick-only`, workload excl. instrument (never a ratio) | — | 319,814 | n/a | — | 480,596 mach¹ | 896,271¹ | `clonefileat` (21) | `psynch_cvwait` (129,178) |
| — `carrick-only`, probable instrument | — | 106,597 | n/a | — | —¹ | —¹ | `kdebug_trace_string` | `kdebug_trace64` (53,801) |

¹ The instrument sub-bucket decomposes host calls and CPU only; the mach and
fault columns on the workload row are the **whole** `carrick-only` bucket
(the ledger's `carrick_only.host_calls` = 426,411 is the containing bucket:
319,814 workload + 106,597 instrument).

Closure receipt: the guest column sums to 94,782 and the host column —
581,259 guest-attributed + 319,814 + 106,597 — to 1,007,670, both equal to
the independently aggregated totals (all ten currency pairs equal; asserted
by the analyzer, republished in `closure`).

**The largest single count lever in the ledger (unexplained as captured;
root-caused and fixed the next day — see the box below): ~1,108 host
`close` per guest `execve`.** 74,253 of `execve`'s 85,038 in-window host
calls (87.3%) are `close` — **7.4% of every host syscall in the run** — and
the per-exec constant is stable to a tenth of a call across arms
(1,108.3 / 1,109.1 / 1,109.2 per 67/68/68 execs). Host `execve` itself is
1:1 with guest `execve` in every arm, so the window is genuine exec service,
not supervision bleed. Nothing in the entry roster currently points at this;
it is the named open question for Task 5/6 (deliberately not investigated in
this entry — E0 measures, it does not attribute causes).

> **RESOLVED 2026-08-07** — the `--fs host` stat cache allocated one host
> parent dirfd per cached LEAF, so a cold build held **1,138 open dirfds over
> 44 distinct directories** (759 of them the same `go/src/runtime`); the
> cache's clear-on-fork (`fs_backend.rs:2479`) then closed all of them one at a
> time in every fork child, and a `go build` fork child's first stat is the
> `check_exec_target` of the `execve` it was forked to perform, which is why
> the whole sweep landed in this window. Anchors are now interned per
> directory (weakly, so lifetimes are unchanged): **1,108.3 → 80.7 closes per
> exec** on the same fixture and instrument (74,253 → 5,404), and the resident
> dirfd population 1,138 → 49. Diagnosis, receipts and classification:
> [`task-close-diagnosis-report.md`](../superpowers/sdd/2026-08-06-move3-amplification-ledger/task-close-diagnosis-report.md).
> The measured columns above are the pre-fix reading and are left as captured.

Three rows are ratios over tiny denominators and must not be read as
per-call price: `execve` (67 — the loader/exec chain), `waitid`/`wait4`
(72/71 — child supervision, whose `kevent` parks land inside the wait window),
and `clone` (364 — of which 68 are full host `fork`s at ~5.6 ms of kernel CPU
each, the dominant single-call cost in the whole ledger).

`rt_sigaction` is the count-amplification outlier: 102,320 host calls — 10.2%
of every host syscall in the run — from 11,115 guest calls, at only ~547 ns
each (6 ms total). A count problem, not a CPU problem.

## 5. `carrick-only`, decomposed

Mean CPU-ms over the three arms (counts from arm A):

| host call | count | CPU-ms (n=3) | what it is |
|---|---:|---:|---|
| `clonefileat` | 21 | 311.7 ± 9.1 | per-run rootfs COW seed (container create) |
| `psynch_cvwait` | 129,178 | 277.2 ± 9.6 | park/wake |
| `ioctl` | 469 | 220.9 ± 5.6 | **the in-process libdtrace consumer's own dtrace-device traffic** — instrument-adjacent, kept in `carrick-only` per the analyzer's stated upper-bound hedge |
| `psynch_cvsignal` | 128,881 | 98.5 ± 3.2 | park/wake |
| `close` | 3,578 | 77.7 ± 0.5 | teardown |
| `fstatat64` | 9,041 | 29.4 ± 27.5 | see below |
| `open` | 834 | 14.05 ± 0.24 | setup |
| `mmap` | 2,073 | 11.27 ± 0.35 | host allocator/setup |
| `stat64` | 2,092 | 7.07 ± 5.81 | image/setup stats — same CPU instability as `fstatat64` (13.78/3.68/3.75 across arms; count stable) |
| mach `swtch_pri` | 461,714 | 21.5 | **yield storm** — 95% of all mach traps in the run |

Park/wake (`psynch_cvwait` + `psynch_cvsignal` ≈ 258k calls, **~0.38 s**) is
13–14% of measured kernel CPU — the E6 row, now with a same-instrument CPU
figure. The `swtch_pri` count (462–505k per run, cheap per call) is a
concurrency-structure smell recorded for E4/E6, not a CPU bucket.

`carrick-only` `fstatat64` is 9,041 on this lane (its CPU split 61.1 / 13.5 /
13.5 ms across arms — the count is stable, the CPU is not). The fs-walk entry's
open regression chip (`carrick-only` `fstatat64` 32 → 5,802 on fs-walk between
2026-08-02 and 2026-08-05) therefore has a build-lane counterpart; the bisect
chip already filed for it stays ranked ahead of new fs levers.

The instrument's own footprint: `kdebug_trace64`/`kdebug_trace_string`
106,597 calls / 8.3 ms, subtracted into `probable_instrument` by the analyzer;
plus the ~0.22 s of consumer `ioctl` named above, which stays in
`carrick-only` (so that bucket is an **upper bound** on carrick's supervision
cost). No instrument call was observed inside any guest service window (that
is a named refusal, and it did not fire).

## 6. The open lane at HEAD — the 19.68 successor figure

AGENTS.md's 19.68 host-opens-per-guest-open was a 2026-07-28 service-window
figure **on this same lane and window definition** (`564dd281`, cold go-build).
This capture re-measures it at HEAD:

| reading | 2026-07-28 (`564dd281`) | HEAD (this capture) |
|---|---:|---:|
| host `openat` inside guest `openat` windows ÷ guest `openat` | **19.6754** | **8.6916** (28,378/3,265; identical to 4 decimal places in all three arms) |

The 2026-08-02 trusted-dirfd lanes landed in between; this is the first
like-for-like restatement since. The guest `openat`'s **total** host-call
amplification is 27.64x (90,239 host calls: the 28.4k host `openat` plus the
resolution/mode tail — `close`, `fstatat64`, `fcntl`, `fgetxattr` — around
it), costing ~105 µs of host kernel CPU per guest open, 0.34 s per build.

The whole fs family (`openat` + `newfstatat` + `mkdirat` + `unlinkat` +
`utimensat` + `chdir` + `fstat`) is **174,749 host calls ≈ 0.64 s traced
kernel CPU ≈ 40% of all guest-attributed kernel CPU** — the largest
guest-attributed family on the build lane (§11, E5 promoted).

**Denominator shift, recorded so the 19.68 → 8.69 pair is read correctly:**
the guest `openat` count moved 2,363 (2026-07-28 capture) → 3,265 here
(+38%). Same definition, same lane, but the guest-side open population
itself changed across five weeks of drift, so the pair is a temporal
before/after of the lane, not a causal measurement of the trusted-dirfd
change alone.

## 7. Fault placement and the fault-ownership verdict at HEAD

**Temporal placement** (AMP1, per-service-window; arm A, shares stable within
0.4 pp across arms):

| where `zfod` fired | count | share |
|---|---:|---:|
| inside guest `mmap` windows | 553,526 | **36.0%** |
| inside guest `execve` windows | 83,487 | 5.4% |
| `carrick-only` (no guest window open) | 896,271 | **58.3%** |
| all other guest windows combined | 3,624 | 0.2% |

The `mmap` row is E1's predicted signature, now measured: 6,110 guest `mmap`s
issue almost no host syscalls (0.93x, the arena bump path) yet **36% of every
zero-fill fault in the build fires inside their service windows** — the eager
`vec![0; length]` + `pread` + copy materialization
(`dispatch/mem.rs:734-902,2508`).

**Ownership at HEAD** (`--profile native-fault`, birth-keyed page census, two
source-identical captures, run ids `amp1nfaultA81291`/`amp1nfaultB81560`, both
rc 0, natural completion, zero drop/violation counters, every sampled page
joined; receipts `nfault-{a,b}.raw` + `.summary.jsonl` in
`target/perf/task4-e0/`):

| metric | 08-03 A | 08-03 B | **HEAD a** | **HEAD b** |
|---|---:|---:|---:|---:|
| exact `as_fault` | 1,930,155 | 1,943,036 | 1,934,954 | 1,934,440 |
| exact `zfod` | 1,532,367 | 1,540,269 | 1,534,205 | 1,533,476 |
| host-other share of sampled `zfod` | 63.2115% | 62.7395% | **63.2559%** | **63.2966%** |
| host-other `zfod` repeat factor | 1.00638 | 1.00146 | 1.00159 | 1.00331 |

**Verdict: CONFIRMED.** The 2026-08-01 + 2026-08-03 record — ordinary Carrick
host allocations, not guest-owned mappings, dominate current-default
zero-fill faults — reproduces at HEAD to within 0.09 pp of the 08-03 A arm,
across ~40 commits of post-arena drift. The fault population itself is
unchanged (exact totals within 0.25% of the 08-03 pair). There is no
regression to name; AGENTS.md's guest-dominates bullet (traced to the oldest,
2026-07-29 reading) is corrected in the same change that lands this document,
per E0 Deliverable 2.

The two cuts compose rather than conflict: the ownership census says **whose
pages** fault (63.3% host-other — carrick's own allocations); the AMP1 join
says **when** they fault (58.3% outside any guest window, 36.0% inside guest
`mmap` service — where the eager-materialization `Vec` (host-owned) and the
destination arena pages (guest-owned) are both touched). Joining
ownership × window needs a probe neither instrument has; the scaled guest-owned
zfod estimate (~563k) and the in-`mmap`-window count (~554k) are close enough
to make "the guest-owned fault mass is mostly E1's destination-copy touches"
the working hypothesis for Task 5, stated as a hypothesis, not a measurement.

## 8. The syscall-only comparison arm — REFUSED, and the refusal is the finding

The plan asked for a syscall-only capture to set beside the fs entry. The
shipped AMP1 instrument fixes `joins=syscall,mach,fault` in its header (a
joins subset is a different instrument the comparator refuses to cross), so
the arm was taken with the fs entry's own instrument —
`carrick trace -s scripts/dtrace/native-fs-amplification.d` — on this fixture
(run id `amp1fsbuild80106`, receipt `fsamp-build.raw`).

It **truncated at its 300 s tick bound with the guest ~63% complete** (59,523
guest syscalls captured vs ~94.4k for a completed run; untraced anchor
8.452 s). Perturbation ≥ 35x, versus AMP1's 2.5–2.7x on the same lane in the
same hour — and a live `ps` during the run showed a forked `go` child at
**0.00 s CPU after 4+ minutes** while the parent crawled at ~17% duty. Two
mechanical observations, one conclusion:

- the legacy census keeps two **string** thread-locals and a string-keyed
  aggregation pair per host syscall (`self->fs_host = probefunc`), plus one
  `copyinstr` per guest syscall — exactly the per-event cost AMP1's
  zero-copyin, integer-slot design was built to remove;
- `carrick trace -s` exited **rc 0** despite the in-band truncation marker —
  the `-s` diagnostic path does not gate on the D program's exit, which is
  precisely why the ledger only accepts `--profile` captures.

Consequence: the fs census is **not usable on the build lane**, and no count
from that arm is cited. The cross-workload comparison in §3 (2.05x fs-walk vs
10.7x build) uses AMP1's own definitions on both sides of the ledger boundary
where possible, and is labeled context, not a lever. Single observation; not
retried — the mechanism is architectural, and re-running a known-pathological
instrument on the exclusive box buys nothing.

## 9. The allocation-owner join

Counts only. The census is the non-default `alloc-owner-census` feature, so
this arm ran on its own `just build --features alloc-owner-census` binary
(SHA-256 `0079f0a74f7274a652eede2beb084302556375111264d35b49e5a6dbe1ea5b77`),
untraced, `CARRICK_DSR_PROFILE=1` +
`CARRICK_ALLOC_OWNER_CENSUS_DIR`, run id `amp1owners282976`, rc 0, `BUILD_OK`,
zero survivors. **First-arming footnote:** the first attempt ran the census
env against the default-featured binary and silently produced an empty
directory with rc 0 — a set `CARRICK_ALLOC_OWNER_CENSUS_DIR` on a
non-featured binary no-ops with no diagnostic. Filed as a concern, not fixed
here.

The strict join closed completely: 136/136 independently parsed NATIVEPERF
process epochs, 69/69 pids, 136/136 fragments parsed, `valid: true`, zero
errors, `other` bucket 8.67% < the 10% fail-closed ceiling
(`alloc-owner-report.json`, SHA-256
`74065d89b49c64617bcf7a0798edf56a576fb660b057ad6994dd2cf82651f1a7`;
NATIVEPERF export SHA-256
`07f2d2a78192b3e225053e2f137eafc256430e597a206e3f07926076f2c66d82`).

Owner portfolio, 30.19 GB total requested bytes (allocation-size sums —
coverage evidence, not faulted-page or CPU claims):

| owner | requested bytes | share |
|---|---:|---:|
| `publication-recovery` | 15,738,161,472 | **52.13%** |
| `publication-map` | 4,243,613,376 | **14.06%** |
| `block-assembler-transient` | 3,204,382,884 | **10.61%** |
| `other` | 2,617,093,329 | 8.67% |
| `decode-read-buffers` | 1,319,136,618 | 4.37% |
| `translation-source-preparation` | 1,005,554,752 | 3.33% |
| `publication-indexes` | 832,065,160 | 2.76% |
| `indirect-target-cache` | 782,237,696 | 2.59% |
| `translation-orchestration` | 381,901,564 | 1.26% |
| `shared-translation-support` | 67,627,678 | 0.22% |

Publication metadata (recovery + map = 66.2%) is still the dominant owner at
HEAD, matching the 08-03 source binding (recovery ≈ 77% of initialized owned
metadata there; the recovery:map byte ratio here is 3.7:1). Task 6's owner
ranking starts from `publication-recovery`, with `block-assembler-transient`
the first newly-named owner above the 10% line.

**The three-instrument join closes the fault story coherently.** The
ownership census's guest-owned zfod scaled estimate (~563k) matches the AMP1
in-`mmap`-window count (~554k) and the 08-01 audit's `zero_backing` bucket
(561k): the guest-owned fault mass IS the E1 destination-arena first touch,
made by carrick's own copy loop inside the `mmap` service window. The
host-other 63.3% is the allocation churn portfolio above. **The pairing that
makes the two cuts agree is explicit:** host-other ↔ `carrick-only` **plus
the `execve` windows** (the loader materializes images into carrick-owned
buffers), 58.3% + 5.4% = 63.7% temporal vs 63.3% ownership; guest-owned ↔
the `mmap` windows plus the guest-op residue, 36.3% vs 36.7%. The naive
pairing (host-other ↔ `carrick-only` alone) misses by 5 pp; pooled, both
sides agree to ~0.4 pp.

## 10. Qualify-at-first-arming — the Task-1 §6 list, answered

1. **`vtimestamp` advances across `mach_trap:::entry`/`return`: YES.** Mach
   CPU totals 50.3/51.8/53.7 ms, nonzero in every arm; the join is live.
2. **The fault→service-window join reproduces `native-fault`'s independent
   totals: YES.** AMP1 exact fault totals (1.933–1.950 M `as_fault`) bracket
   the same-day native-fault pair (1.9349/1.9344 M) and the 08-03 pair.
3. **Drop counters at the declared buffer sizes: all zero in all three arms.**
   The argued 64m/256m/32m headroom holds on the ~2.5 M-event build capture.
4. **Real perturbation multiple: 2.52–2.71x** (§1) — inside the declared 2–4x.
5. **Entries without returns outside the qualified terminal roster:** present
   but explained and small on the syscall side (`kevent` 92, `psynch_cvwait`
   226, `poll` 1 — in-flight at target exit; the two terminal-roster calls
   have zero returns as qualified). The mach side is structural:
   **`swtch_pri` shows 465,792 entries / 294,101 returns** — a yield that
   parks does not return while the census is exiting — and `semaphore_wait_trap`
   never returned (296/0). Recorded as expected shape for yield-class traps;
   the analyzer reports (never refuses) these.
6. **`inherited-end` tracks the guest's clone+fork count: YES, exactly.**
   364/361/368 inherited ends vs 364/361/368 guest `clone` calls per arm.
7. **Fork-child `-end` before `proc:::create` admission:** not distinguishable
   in-band this round; the exact inherited-end match in (6) leaves no
   unexplained residue, so no evidence of silent pre-admission drops.
8. **`tid` across `execve`:** no stranded-slot symptom (zero
   `service-window-reentry` in all arms); the exec-retirement clause is doing
   its job either way.
9. **Task-1's residual** (corrupted-first-end vs inherited-end
   indistinguishable at slot==0): the exact per-arm equality in (6) is the
   strongest available in-band evidence that the inherited-end class is pure —
   a corrupted first end would have to displace a real inherited end
   one-for-one in all three arms to hide. Not proof; noted as adequately
   bounded for a counts instrument.

## 11. The re-ranking of E1–E7

Measured basis: same-instrument traced kernel-CPU shares and fault counts
above. The plan's *estimated* pre-drift CPU-s bands are deliberately not
restated; ranks are by what this capture can defend. E1/E2 remain overlapping
(the Vec side of E1 **is** E2 mass); their partition is Task 5/6's job.

| new rank | entry | measured basis (this capture) | movement |
|---|---|---|---|
| 1 | **E1** guest `mmap(MAP_PRIVATE, fd)` eager materialization | 553,526 zfod (36.0% of all) inside 6,110 guest-`mmap` windows; mmap syscall CPU itself trivial (47 ms) | confirmed #1 |
| 2 | **E2** carrick ≥128 KiB allocation churn | host-other zfod **63.26/63.30%** at HEAD (§7); carrick-only zfod 896k (58.3%) | confirmed #2; STOP re-open stands on live numbers |
| 3 | **E5 promoted** — the build-lane fs family | 174,749 host calls, ~0.64 s ≈ **40% of guest-attributed kernel CPU**; open lane 19.68 → **8.69**; `mkdirat` 78x, `unlinkat` 63x; `carrick-only` `fstatat64` 9,041 echoes the open fs-walk regression chip | **up from 5th**; was "unmeasured", now the largest guest-attributed family |
| 4 | **process/container lifecycle** (absorbs E7 + the fork cost + the seed) | `clone` 1.13 ms/op (68 host `fork`s ≈ 5.6 ms each = 0.38 s); `execve` 3.63 ms/op in-window and **~1,108 host `close` per exec** (§4 — the ledger's largest count lever; **root-caused and fixed 2026-08-07**, now 80.7/exec); `waitid`/`wait4` 107k host calls; `carrick-only` `clonefileat` 21 calls ≈ **0.31 s** | new named family; E7's "record, don't campaign" holds for the exec chain's fixed wall, but the fork row, the per-exec close storm and the per-run `clonefileat` seed are campaignable |
| 5 | **E6** `carrick-only` park/wake | `psynch_*` ≈ 258k calls, **~0.38 s = 13–14%** of measured kernel CPU; `swtch_pri` 462–505k | up slightly; bigger same-instrument share than the sampling estimate suggested |
| 6 | **E4** alias-gate / dispatch-guard scope | not measurable by this instrument; `swtch_pri` storm is consistent with contention but attributes nothing | unchanged: re-derive (Task 8) |
| 7 | **E3** decommit intent → `MADV_FREE_REUSABLE` | guest `madvise` count is **415–528 per build**, in-window host CPU ≈ 0.1–0.2 ms — noise. The kernel-side case for E3 on this lane is refuted; only the userspace memset share (invisible to AMP1) could still argue for it | **demoted from 3rd**; plan's "should be non-trivial" is falsified by measurement |

Neither §4 invalidation condition fired: `carrick-only` does not dominate
(42.2%, with named instrument-adjacent and one-off-seed components inside it),
and no single host call concentrates the kernel CPU.

**What this ledger cannot see, so nobody banks it silently:** userspace CPU
(memset/memcpy/malloc — E1's copy cost and E3's memset live there), fault
**CPU** (the fault join is counts; the kernel non-syscall bucket is priced
only by the audit's 1.81–3.84 µs/fault range), and blocked time (by design —
`vtimestamp`).

## 12. Wall context (cited, not re-measured)

Official shipped-default ratio: **10.8586x**
(`2026-08-06-post-arena-default-refresh.md`, median carrick CPU 21.391 s).
Nothing in this entry re-measures it; the untraced anchor above is a
single-run sanity wall, not a ratio input.
