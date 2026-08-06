# fs-walk amplification ledger — host syscalls per guest operation

**Date:** 2026-08-05
**Scope:** first Move-3 amplification-ledger entry of the category-collapse
strategy. Measures host-ops-per-guest-op on the fs-walk fixture at HEAD, and
corrects two figures that were being quoted without their denominators:
AGENTS.md's "19.68 host opens per guest open" (a *go-build* service-window
number, not an fs-walk one — see below) and the 45,005-host-call attribution
pointer in `container-lifecycle-split.jsonl` (fs-class-filtered, so not
comparable to an unfiltered total).
**Lane:** shipped default — Darwin/AArch64 native DSR (`--exec-backend native`).

The table below is the format every subsequent ledger entry reuses:
`guest op | guest count | host calls attributed | amplification | dominant host call`.

## Authority

- source commit: `fad9ae0d9c6cc7f5c4aaa11d791b6bbb0cbb50f3`;
- executable: `target/release/carrick`, SHA-256
  `47f50141f5645006eaa9dcc2da511b725648e95ac38037358869408d2db913f2`, built and
  codesigned through `just build`; `__TEXT,__dof_carrick` present (USDT probes
  register);
- image:
  `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
  (`arm64`) — byte-identical to the image behind the 18.9286x wall figure in
  `2026-08-03-current-default-workload-spread.md`;
- fixture, byte-identical to `scripts/perf/workload-spread.sh:45`:
  `find /usr/local/go -type f | wc -l >/dev/null`;
- run id `fswalk-ledger-1`;
- instrument: `scripts/dtrace/native-fs-amplification.d`, SHA-256
  `513280dd40b9b46f1b68d34c2dda2586adcc49ec10de550b66589b8dc3a9a613` — the
  unfiltered-denominator version landed in `1a96548a`, one commit after the
  source commit above. The script is read at runtime via `--script` and is not
  compiled into the binary, so the executable digest still corresponds to
  `fad9ae0d`;
- receipts: `target/perf/fswalk-ledger/fswalk-ledger-trace.raw`, SHA-256
  `235228deb8cde6236347a1a45ef2fa089c9fd6323a72b7387d8045bd8b03bd6b`
  (549 lines, `FSAMP1` protocol), plus `trace-driver.log`,
  `sanity-filecount.log`, `sanity-warm-wall.log` in the same directory.

Capture command (the `carrick-trace` skill governs the flags; `carrick trace`
auto-sudos, so no `sudo` prefix):

```bash
target/release/carrick trace \
  -s scripts/dtrace/native-fs-amplification.d \
  -o target/perf/fswalk-ledger/fswalk-ledger-trace.raw \
  -- run --exec-backend native -e CARRICK_RUN_ID=fswalk-ledger-1 -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 \
  /bin/sh -c 'find /usr/local/go -type f | wc -l >/dev/null'
```

**Host state.** Docker held only the local `registry:2` container that serves
`localhost:5005` (image source); no Docker workload ran in the window, and no
carrick guest was live at start. macOS reported no thermal, performance, or
CPU-power warning. Power was battery at 95%; this entry's citable quantities are
syscall **counts**, which power state does not move.

## Completeness and honesty of attribution

- The capture is complete, not truncated: the script's tick bound emits an
  explicit `section=truncated` marker and exits non-zero if it fires, and no
  such marker is present. The census ended on the target's own `proc:::exit`.
- Arithmetic closes exactly: the per-guest-op host totals sum to 52,805 (the
  independently aggregated host total) and the per-op guest counts sum to
  24,201 (the independently aggregated guest total).
- The fixture visited **14,179 files**, confirmed by a separate untraced run
  (`sanity-filecount.log`) — the same count the 2026-08-02 fs-walk endgame
  design records, so the workload is the one this ledger claims to measure.
- Guest-op counts are within 2 calls of the 2026-08-02 census
  (`target/perf/fswalk-amp7.raw`: 1,670/3,123/4,769/6,326/7,799 vs
  1,671/3,123/4,769/6,328/7,801 here), and the fs-class host joins are
  unchanged (host `fstatat64` per guest `newfstatat` = 4,841 in both). The
  guest-side shape of this workload has not moved at HEAD.
- **Scoping.** The instrument scopes on a `tracked[]` table seeded from
  `$target` and grown through `proc:::create`, *not* on `execname == "carrick"`.
  That matters: `carrick trace` runs libdtrace in-process inside a `carrick`
  binary, so an execname filter would count the tracer's own syscalls as the
  guest's — the trap AGENTS.md records as having made 54% of an earlier profile
  the profiler.
- **What the census cannot see.** Guest operations served without a runtime
  exit (anything satisfied inside the JIT/gateway) never open a service span and
  are invisible to both columns by construction. For this fixture that is not a
  material gap — no such op appears in the guest census.
- **Perturbation.** Two probes fire on every host syscall the tracked tree
  issues. Wall time from this run is therefore **not** a performance number and
  none is quoted from it; only same-instrument counts and ratios are citable.
  Separately, 3,182 host calls in the capture are probably the instrument's
  own — see "Where the 45k went".
- **Single capture; no variance is reported and none should be quoted from
  this entry.** These are syscall counts on a deterministic fixture, and they
  reproduce the 2026-08-02 census to within 2 guest calls, which is why one run
  is treated as sufficient for the count columns. Any claim that needs a
  distribution — in particular any before/after comparison of a lever — needs
  its own repeated sampling.

## Whole-fixture ratios

3,182 of the captured host syscalls (1,606 `kdebug_trace64` + 1,576
`kdebug_trace_string`) are probable instrumentation, not workload — see the
caveat under "Where the 45k went". They are all `carrick-only`. The primary
figures below therefore **exclude** them; the with-tracer variant is kept only
so the raw receipt reconciles.

| quantity | primary (tracer-free) | with-tracer variant |
|---|---:|---:|
| guest Linux syscalls | 24,201 | 24,201 |
| host macOS syscalls | 49,623 | 52,805 |
| **host syscalls per guest syscall (whole fixture)** | **2.0505x** | 2.1819x |
| host syscalls issued while servicing a guest syscall | 41,314 | 41,314 |
| host syscalls per guest syscall (service windows only) | **1.7071x** | 1.7071x |
| host syscalls outside any guest service window (`carrick-only`) | 8,309 (16.7%) | 11,491 (21.8%) |

The two service-window rows are identical because every `kdebug_trace*` call
landed in `carrick-only`: no per-op amplification cell in this document is
affected by the exclusion.

`carrick-only` is real cost but it is not amplification of any guest op, so it
is never folded into a per-op ratio.

## The ledger

Every cell below is **per-op**, not whole-fixture: the host column counts the
host syscalls issued on the same thread inside that guest op's service window.
"Dominant host call" gives the largest single host syscall in that window with
its count.

| guest op | guest count | host calls attributed | amplification | dominant host call |
|---|---:|---:|---:|---|
| `newfstatat` | 4,769 | 13,652 | **2.8627x** | `fstatat64` (4,841) |
| `getdents64` | 3,123 | 12,513 | **4.0067x** | `getdirentries64` (3,150) |
| `openat` | 1,671 | 9,876 | **5.9102x** | `openat` (3,955) |
| `close` | 6,328 | 1,708 | **0.2699x** | `close` (1,673) |
| `fcntl` | 7,801 | 7 | **0.0009x** | — (served in-process) |
| `read` | 163 | 608 | 3.7301x | `read` (310) |
| `write` | 185 | 185 | 1.0000x | `write` (185) |
| `mmap` | 51 | 198 | 3.8824x | `mprotect` (142) |
| `exit_group` | 3 | 1,622 | 540.67x | `close` (1,585) |
| `execve` | 2 | 357 | 178.50x | `openat`/`fcntl` (64 each) |
| other guest ops — 28 of them, 11 with any host call | 105 | 588 | 5.6000x | `openat` (87) |
| — `carrick-only`, workload (not amplification) | — | 8,309 | n/a | `fstatat64` (5,802) |
| — `carrick-only`, probable tracer (`kdebug_trace*`) | — | 3,182 | n/a | `kdebug_trace64` (1,606) |

The table is complete: the guest column sums to 24,201 and the host column to
52,805, both matching the independently aggregated totals.

Two rows are **ratios over a tiny denominator** and must not be read as
per-call cost: `exit_group` (3 calls) is process teardown closing 1,585 host
fds in one go, and `execve` (2 calls) is the loader. They are listed because
their absolute host-call counts are material (3.3% and 0.7% of the tracer-free
run), not because 540x is a meaningful per-op figure.

The `mmap` row is small in absolute terms (198 host calls) but its dominant
host call is worth recording: 51 guest `mmap`s produce **142 host `mprotect`s**.
That is the exact idiom AGENTS.md's Go dual-port-oracle note warns about — Go's
Darwin port manages its heap with *zero* `mprotect`, using
`mmap(…|MAP_FIXED)` and the `MADV_FREE_REUSABLE`/`REUSE` pair instead, because
on Darwin `mprotect` is the expensive primitive. This lane is re-issuing a
Linux mechanism rather than lowering the guest's intent.

### The open lane, and what 19.68 actually was

AGENTS.md's 19.68 has a precise provenance, and it is not this workload.
`docs/perf-results/native-fs-amplification.jsonl` record 8
(`contained-metadata-retention`, `git_sha 564dd281`, run id
`native-fs-contained-metadata-a-20260728`) and
`native-wall-time-campaign.md:113,831` record it as
`host_openat_from_guest_openat 46,493 ÷ guest_openat 2,363 = 19.6754` — a
**service-window (contained)** figure, captured on the **cold-`GOCACHE`
go-build** (candidate median wall 19,163 ms), not on fs-walk. That same run's
whole-run analog was `host_openat_total 83,290 ÷ 2,363 = 35.25`.

So the definitions pair like this, and the *workloads do not*:

| reading | old (2026-07-28, cold go-build) | new (2026-08-05, fs-walk) |
|---|---:|---:|
| service-window: host `openat` inside guest `openat` windows ÷ guest `openat` | **19.6754** | **2.3668** |
| whole-run: all host `openat` ÷ guest `openat` | 35.25 | 4.6050 |

**No improvement multiple is claimed from this pair.** The service-window row
is the like-for-like comparison of *definitions*, but the two cells describe
different workloads — a Go build's loader- and cache-heavy open pattern versus
a directory walk — so their ratio measures the workload difference at least as
much as any change in carrick. The honest statement is the absolute one: **on
the fs-walk fixture at HEAD a guest `openat` costs 2.37 host `openat` inside
its own service window, and 4.61 counting every host `openat` in the run.**
Restating 19.68 for the go-build at HEAD is a separate measurement this entry
did not make.

### The finding this capture adds

The 2026-08-02 census filtered host syscalls to an fs allow-list, so it could
not see this: **guest `getdents64` pays a six-call directory-stream preamble,
once per directory.** Exactly 1,560 each of `dup`, `fcntl_nocancel`, `fstat64`,
`fstatfs64`, `lseek`, and `close_nocancel` are attributed to `getdents64`. The
walk issues 3,123 guest `getdents64`, i.e. **just over two per directory** —
`find` reads a directory then reads again to see EOF, and 3,123 ÷ 1,560 =
2.0019, the three extra calls being directories whose entries did not fit in
one buffer. The preamble fires once per *directory*, not once per call. That is
**9,360 host syscalls, 18.9% of the tracer-free run (17.7% with the tracer
calls included)**, spent on stream setup and teardown rather than on
enumeration; the enumeration itself is only 3,150 `getdirentries64`.

The signature is the macOS `fdopendir(3)`/`closedir(3)` sequence that cap-std's
`Dir::read_dir` compiles to, and `read_dir` is on the enumeration path
(`crates/carrick-runtime/src/fs_backend.rs:4342`, `child_names`). Naming the
exact Rust frame is left to a follow-up rather than asserted here: the census
attributes host calls to guest ops, not to call sites, and `ustack` is
unreliable on this workload because ~70 self-re-exec'd guest processes carry
independent ASLR slides. What is measured, and firm, is the *shape*: one
directory-stream open/close per directory, on top of the reads.

Enumerating from the already-open dirfd — `getdirentries64(2)` directly, or
`getattrlistbulk(2)` per fs endgame Lever A — removes six host calls per
directory without changing any guest-visible result.

### Where the 45k went — and a movement that looks like a regression

**Compare filtered to filtered.** The 45,005 figure is the *fs-class-filtered*
`carrick-only` bucket from `fswalk-amp6.raw`; this run's 11,491 is
*unfiltered*, so the two are not comparable. Reading the same filtered
`section=host-by-guest` join out of all three receipts:

| receipt | date | `carrick-only`, fs-class filtered |
|---|---|---:|
| `target/perf/fswalk-amp6.raw` | pre-trusted-lane | 45,005 |
| `target/perf/fswalk-amp7.raw` | 2026-08-02 | 561 |
| this capture | 2026-08-05 | **6,467** |

The deferred-teardown work holds: `unlinkat` dominated amp6 at 38,225 and is
*absent* at HEAD (8 host `unlink` in the whole run, 4 of them `carrick-only`).
Separately, unfiltered `carrick-only` at HEAD is 11,491, or **8,309 excluding
the probable-tracer `kdebug_trace*` calls**.

**But 561 → 6,467 is a movement to explain, not a standing block.** Both
figures are the same filtered join, on the same fixture, three days apart, and
essentially the entire delta is one host call:

| filtered join | amp7 (2026-08-02) | HEAD (2026-08-05) |
|---|---:|---:|
| `carrick-only` → `fstatat64` | **32** | **5,802** |
| `carrick-only` → `getdirentries64` | 1 | 74 |
| joined to guest `newfstatat` | 13,495 | 13,495 |
| joined to guest `getdents64` | 3,153 | 3,153 |
| joined to guest `openat` | 7,376 | 7,396 |
| joined to guest `close` | 1,672 | 1,673 |

Every column attributed to a guest op is stable to within 0.3%, while
`carrick-only` `fstatat64` moved by +5,770 — 11.6% of the tracer-free run
(11.0% with-tracer) appearing outside any guest service window where three days
ago there were 32. That shape (one bucket moving, all others frozen) reads as a **regression
introduced since 2026-08-02**, not as a long-standing unattributed block, and
it should be treated as one until shown otherwise.

**Recommended next action: bisect this movement first**, over the commits
between `fswalk-amp7.raw`'s capture and `fad9ae0d`, using the same instrument
and fixture so the filtered `carrick-only` → `fstatat64` cell is the bisect
signal. That is deliberately out of this entry's scope — this entry measures,
it does not attribute a cause — but it outranks any new amplification work,
because 5,770 host stats is larger than every per-op lever named below.

One caveat on the same bucket, stated rather than buried: 1,606
`kdebug_trace64` + 1,576 `kdebug_trace_string` (3,182 calls, 6.4% of the
tracer-free run) also land in `carrick-only`. carrick makes no direct
`kdebug`/`os_signpost` calls, and `kdebug_typefilter` appears alongside them,
so these are most likely instrumentation-induced rather than workload cost.
They are excluded from the primary whole-fixture ratios and from every
amplification cell, and they should not be banked as a lever until re-measured
with an instrument that does not enable kdebug. They are *not* the explanation
for the `fstatat64` movement above — that is a different host call, and the
old instrument counted `fstatat64` too.

## Wall context (cited, not re-measured)

From `docs/perf-results/2026-08-03-current-default-workload-spread.md`, same
image and same fixture: in-guest fs-walk medians **265 ms carrick / 14 ms
Docker = 18.9286x**. That denominator is in-guest only — it excludes container
create and teardown by construction. No wall number is taken from the traced
run above.

Reconciling the two: at **2.05** host syscalls per guest syscall (1.71 inside
service windows) this workload is not gross-amplification-bound. The in-guest
gap is dominated by the per-host-syscall cost on APFS plus the residual per-op
multiples above (`openat` 5.91x, `getdents64` 4.01x, `newfstatat` 2.86x) — and
by the unexplained 5,770-call `carrick-only` `fstatat64` movement, which alone
is 11.6% of the tracer-free run. Note this says nothing about the go-build lane,
where the 19.68 figure was taken; that lane's open amplification at HEAD is
unmeasured.

Note also that AGENTS.md's claim of "roughly one host call per guest stat"
is precise only about `fstatat64` (1.015 host stats per guest stat). A guest
stat costs **2.86 host calls** in total, the remainder being `openat` (3,497),
`close` (1,853), `fcntl` (1,624) and `flistxattr` (1,564) — the resolution and
mode-xattr work around the stat, which is where the remaining stat-lane lever
is.

## Next lever

**Ahead of any lever: bisect the `carrick-only` `fstatat64` movement**
(32 → 5,802 between 2026-08-02 and `fad9ae0d`, same fixture, same filtered
join). It is larger than every lever below and is probably a regression, so
fixing it may be free where the levers are not. Procedure and receipts are in
"Where the 45k went" above.

The standing lever, once that is settled:

**fs endgame Lever B — serve reads from the shared read-only cache tree and
copy up on write** (`docs/superpowers/specs/2026-08-02-fs-walk-endgame-design.md`
§4). It is the lever that reaches the 2x bar on total wall, worth the whole
~333 ms per-run `clonefileat` create term (total wall 620 ms → ~290 ms,
3.8x → ~1.8x).

Its expected effect on the dominant rows of this ledger, stated so the next
entry can falsify it:

- **`carrick-only` should fall**, and it is the only bucket Lever B directly
  attacks: the 21 `clonefileat` + 21 `mkdirat` of per-run seeding disappear,
  and the create-side `fstatat64`/`stat64` traffic that walks the scratch tree
  should shrink with them.
- **`openat`, `newfstatat` and `getdents64` amplification should NOT improve,
  and may worsen by up to one `fstatat64` per component** on directories with
  an overlay entry — the design's two-dirfd lookup costs one extra probe only
  for directories that have been written to. A ledger entry after Lever B that
  shows those three rows flat is the expected result, not a regression.
- Lever A (`getattrlistbulk`) and the directory-stream preamble above are what
  move the `getdents64` and `newfstatat` rows; they are independent of Lever B
  and should be measured separately so the two are never conflated.
