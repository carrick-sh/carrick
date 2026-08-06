# fs-walk amplification ledger — host syscalls per guest operation

**Date:** 2026-08-05
**Scope:** first Move-3 amplification-ledger entry of the category-collapse
strategy. Re-measures host-ops-per-guest-op on the fs-walk fixture at HEAD and
retires the stale pre-trusted-lane figures (AGENTS.md's "19.68 host opens per
guest open"; the 45,005-host-call attribution pointer in
`container-lifecycle-split.jsonl`).
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

## Whole-fixture ratios

| quantity | value |
|---|---:|
| guest Linux syscalls | 24,201 |
| host macOS syscalls | 52,805 |
| **host syscalls per guest syscall (whole fixture)** | **2.1819x** |
| host syscalls issued while servicing a guest syscall | 41,314 |
| host syscalls per guest syscall (service windows only) | 1.7071x |
| host syscalls outside any guest service window (`carrick-only`) | 11,491 (21.8%) |

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
| — `carrick-only` (not amplification) | — | 11,491 | n/a | `fstatat64` (5,802) |

Two rows are **ratios over a tiny denominator** and must not be read as
per-call cost: `exit_group` (3 calls) is process teardown closing 1,585 host
fds in one go, and `execve` (2 calls) is the loader. They are listed because
their absolute host-call counts are material (3.1% and 0.7% of the run), not
because 540x is a meaningful per-op figure.

The `mmap` row is small in absolute terms (198 host calls) but its dominant
host call is worth recording: 51 guest `mmap`s produce **142 host `mprotect`s**.
That is the exact idiom AGENTS.md's Go dual-port-oracle note warns about — Go's
Darwin port manages its heap with *zero* `mprotect`, using
`mmap(…|MAP_FIXED)` and the `MADV_FREE_REUSABLE`/`REUSE` pair instead, because
on Darwin `mprotect` is the expensive primitive. This lane is re-issuing a
Linux mechanism rather than lowering the guest's intent.

### The direct replacement for "19.68 host opens per guest open"

| reading | value |
|---|---:|
| host `openat` issued inside guest `openat` service windows ÷ guest `openat` | **2.3668** |
| all host `openat` in the run (7,695) ÷ guest `openat` (1,671) | **4.6050** |

The second is the like-for-like successor to the 19.68 figure, which was itself
a whole-run joined-opens-over-guest-opens number. Either way the open lane has
collapsed by roughly 4-8x since that figure was recorded.

### The finding this capture adds

The 2026-08-02 census filtered host syscalls to an fs allow-list, so it could
not see this: **guest `getdents64` pays a six-call directory-stream preamble,
once per directory.** Exactly 1,560 each of `dup`, `fcntl_nocancel`, `fstat64`,
`fstatfs64`, `lseek`, and `close_nocancel` are attributed to `getdents64` —
1,560 being the directory count (3,123 guest `getdents64` ÷ 2 calls per
directory: one data, one EOF). That is **9,360 host syscalls, 17.7% of every
host syscall in the run**, spent on stream setup and teardown rather than on
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

### Where the 45k went

`fswalk-amp6.raw` (pre-trusted-lane) attributed **45,005 host calls to
`carrick-only`**, dominated by 38,225 `unlinkat` of scratch teardown. At HEAD
that bucket is **11,491** and `unlinkat` is *absent* (4 `unlink` total): the
deferred-teardown work holds. The largest remaining `carrick-only` item is
5,802 `fstatat64` (11.0% of all host syscalls) issued outside any guest service
window — the biggest single unattributed block in the run, and the natural
subject of the next ledger entry.

One caveat on that bucket, stated rather than buried: 1,606 `kdebug_trace64` +
1,576 `kdebug_trace_string` (3,182 calls, 6.0% of the run) also land in
`carrick-only`. carrick makes no direct `kdebug`/`os_signpost` calls, and
`kdebug_typefilter` appears alongside them, so these are most likely
instrumentation-induced rather than workload cost. They are excluded from every
amplification cell by construction (they are `carrick-only`), and they should
not be banked as a lever until re-measured with an instrument that does not
enable kdebug.

## Wall context (cited, not re-measured)

From `docs/perf-results/2026-08-03-current-default-workload-spread.md`, same
image and same fixture: in-guest fs-walk medians **265 ms carrick / 14 ms
Docker = 18.9286x**. That denominator is in-guest only — it excludes container
create and teardown by construction. No wall number is taken from the traced
run above.

Reconciling the two: at 2.18 host syscalls per guest syscall the fs lane is no
longer *amplification*-bound in the way the 19.68 figure implied. The in-guest
gap is now dominated by the per-host-syscall cost on APFS plus the residual
per-op multiples above (`openat` 5.91x, `getdents64` 4.01x, `newfstatat`
2.86x), not by carrick issuing an order of magnitude more calls than it needs.

Note also that AGENTS.md's claim of "roughly one host call per guest stat"
is precise only about `fstatat64` (1.015 host stats per guest stat). A guest
stat costs **2.86 host calls** in total, the remainder being `openat` (3,497),
`close` (1,853), `fcntl` (1,624) and `flistxattr` (1,564) — the resolution and
mode-xattr work around the stat, which is where the remaining stat-lane lever
is.

## Next lever

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
