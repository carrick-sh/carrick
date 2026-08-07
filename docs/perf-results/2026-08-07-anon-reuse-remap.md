# Kernel-side anonymous-reuse replacement — the fault partition's successor, landed

**Date:** 2026-08-07
**Scope:** Move-3 Task 7, the successor the fault partition authorized
([`2026-08-07-build-lane-fault-partition.md`](2026-08-07-build-lane-fault-partition.md)
§7 design, §7.4 gate ladder). Production change: `52342762`
(`feat(dsr): replace the anon-reuse memset with a kernel-side remap`).
**Lane:** shipped default — Darwin/AArch64 native DSR
(`--exec-backend native`), cold `go build` canonical fixture, digest-pinned
image `localhost:5005/carrick-go-conformance@sha256:357a0879…`.
**Verdict: RETAINED on an ABBA win** (−0.660 CPU-s, 95% CI
[−0.750, −0.570], −3.24%). Default ON; `CARRICK_DSR_ZERO_REMAP=0` is the
exact escape hatch.

## 1. What shipped

`NativeMappedMemory::zero_anonymous_reuse`
(`crates/carrick-dsr-aarch64/src/mapped_memory.rs`) now replaces an eligible
reused PRIVATE anonymous range with one fresh host
`mmap(MAP_FIXED|MAP_ANON|MAP_PRIVATE)` at the biased VA — the x86 identity
backend's shipped template (`carrick-dsr/src/identity_memory.rs`
`zero_anonymous_reuse`) brought to this lane — instead of memsetting the old
backing end to end. The kernel delivers zero pages on the fresh mapping, so
the **immovable zeroed-anon guarantee is preserved by construction** with
zero touches and zero zfod at scrub time. After replacement the override
re-applies every recorded non-RW host protection (the fresh mapping comes
back RW; a stage-1-invalidated reclaimed range must not become readable —
the partition doc's §7.2 correctness edge) and performs the write path's
exclusive-monitor invalidation.

Every ineligible shape keeps the always-correct memset, each with a named
refusal (`replace_anonymous_reuse`'s doc): `MappingSharing::Shared` (the
shared-aperture arm's boot-mapped `MAP_SHARED` object stays write-through —
a fresh anon object would sever forked peers, §7.3), any overlapping
`shared_futex`/file-key region or permission-independent
`mutable_shared_backing` claim (a munmapped-then-reused shared alias),
linux4k subpages, host-page misalignment, multi-region ranges, may-execute
ranges and lifted write-exec pages, active host-access lifts, and any host
mmap failure (`MAP_FIXED` failure leaves the prior mapping intact, so the
fallback proceeds as if the path had never run). The `madvise-dontneed` and
brk scrubs route through `zero_backing` directly and are unchanged (2–33
in-window events per build).

## 2. Red-first receipts

The four `anonymous_reuse_replacement_*` tests in `mapped_memory.rs` were
written first and failed at the pre-change tree for the right reason
(E0599 — the mechanism absent; `target/perf/task7-anonzero/red-receipt.log`),
then green with the change:

- **guarantee** — a dirtied reused range reads back zero; recorded
  `PROT_NONE` survives replacement; armed exclusive reservations are
  invalidated;
- **mechanism** — exactly one whole-range `MAP_FIXED` map plus only the
  coalesced non-RW restore runs, via the injectable spy seam (no per-chunk
  lift/restore pairs);
- **severing rule** — every shared/aliased/exec/lifted shape refused
  without touching the mapping; the trait entry falls back to the memset,
  which still zeroes;
- **failure atomicity** — a forced map failure leaves bytes and recorded
  protections exactly as the memset path finds them, zero restore calls
  (the `2026-08-07-e1-atomicity-scope-correction.md` discipline).

## 3. Gates, in the ladder's order (receipts under `target/perf/task7-anonzero/`)

1. **`just ci`** exit 0 at the implementation commit (`just-ci-1.log`,
   43 `test result: ok`, zero FAILED).
2. **`conformance-probes` one-worker delta** (candidate 802.59 s run,
   `probes-candidate-oneworker-2.log`, `CARRICK_PROBE_WORKERS=1`): gating
   arm64:musl failure set = {accounting, aliassize, clone3args,
   execfromthread, mmapcluster, recursionguard} — a strict subset of the
   pinned baseline set; **nothing entered**. `execpermitchurn` is absent
   this sample; it is the documented 1–2/8 load-probabilistic fork-churn
   wedge (pre-existing, chip filed by Task 5) and its absence is flake
   variance, not a claim this change fixed it.
3. **`just conformance-quick`**: `OK: no regressions`
   (`conformance-quick.log`; VMM lane per the recipe's note).
4. **Mechanism proof** (§4) and **ABBA** (§5) below.

## 4. The mechanism proof: the (b) slice collapses

Three `carrick trace --profile native-fault` arms on the candidate binary
`914b6881…` (all rc 0, `BUILD_OK`, zero run-id survivors after
`scripts/sudo/kill.sh`; `capture.log`), re-analyzed offline with
`carrick debug native-fault-partition` — the partition instrument built for
exactly this gate. Offline analysis sections are byte-equal to the
capture-time summaries (only the offline command's own `provenance` block
differs, by design).

| quantity | off (`CARRICK_DSR_ZERO_REMAP=0`) | on (arm a) | on (arm b) |
|---|---:|---:|---:|
| `mmap-anon-reserve / own-biased-backing` | **544,009** | **0** | **0** |
| `mmap-anon-fixed-commit / own-biased-backing` | 5,774 | 0 | 0 |
| `mmap-anon-plain / own-biased-backing` | 314 | 0 | 0 |
| `madvise-dontneed / own-biased-backing` (kept memset) | 3 | 33 | 24 |
| **(b) slice total (own-biased-backing)** | **550,100** | **33** | **24** |
| total in-op zfod (closure-asserted) | 553,335 | **723** | **724** |
| whole-build exact zfod | 1,534,033 | 1,016,589 | 1,015,886 |

- The OFF arm reproduces the pre-change partition to 0.01% (E0/HEAD arms:
  543,802–544,014 on the reserve row) — the hatch is live-verified, and
  the two arms of the screen come from ONE binary.
- The (b) slice — 99.4% of the in-window mass at HEAD — is gone; what
  remains own-biased is exactly the `madvise` scrub the change deliberately
  did not touch.
- **~518k total zfod removed per build** (1,534k → 1,016k), inside the
  partition doc's 365k–543k net band near its top; the difference from the
  gross 550k is the resurfaced guest natural first touch, as the ceiling
  predicted.
- AMP1 corroboration (second instrument, `amplification-capture.sh` arms
  `ampoff`/`ampon`, both rc 0; `compare-ampoff-ampon.json`): total zfods
  −532,484; the guest-`mmap` ledger row's in-window zfods −561,011 and its
  **host CPU-ns 47,127,305 → 7,855,810** (7,581 → 1,288 ns per guest mmap,
  −6x); `as_faults` −755,717.

## 5. The ABBA (retention gate)

Two-binary, per-sample pinned, interleave a1 b1 b2 a2 b3 a3 a4 b4 (n=4 per
arm), untraced, quiet host, clean worktree enforced by the harness
(`native_go_build.py --samples 1 --variant default` per sample, t5arm.sh
pattern; `t7abba-arm.sh`). Control `carrick-control` = `aa33e7df…` built
from the pre-change tree at `8dbdcd74` — **bit-identical to Task 6's
re-parse binary**, a determinism cross-check — with the
`CARRICK_DSR_ZERO_REMAP` marker absent; candidate `carrick-candidate` =
`914b6881…` (rebuild reproduced it bit-identically), marker present.

| metric | control (memset) | candidate (remap) | delta | 95% CI |
|---|---:|---:|---:|---|
| cpu_s | 20.350 (sd 0.055) | 19.690 (sd 0.049) | **−0.660 (−3.24%)** | [−0.750, −0.570] |
| cpu_sys_s | 4.919 | 4.433 | −0.485 | — |
| cpu_user_s | 15.432 | 15.257 | −0.175 | — |
| elapsed_ms | 9,212 | 8,850 | −363 (−3.94%) | [−681, −44] |

Every candidate sample beats every control sample (max candidate 19.760 <
min control 20.285). The win is at the **bottom edge of the partition
doc's 0.66–2.09 CPU-s ceiling band** — consistent with the audit's lower
per-fault figure holding on a quiet host — and the sys-CPU term carries
73% of it, as a fault-mass removal should. **Retention condition met; no
§6 stop condition** (mechanism and ABBA agree).

## 6. Honest notes

- Fault-arm captures record `git_dirty: true` — the dirt was two stray
  untracked scratch files at the repo root (another session's
  `proposed-plan*.md`, moved aside for the ABBA's clean-tree preflight and
  restored after) plus untracked receipts; no tracked source differed from
  `52342762`.
- Counts rest on n=2 ON arms + 1 OFF arm on the deterministic fixture per
  the plan's sampling rule; the traced arms' perturbation is VERY HIGH and
  no wall from them is citable. CPU claims come only from the untraced
  ABBA (n=4/arm).
- The −0.66 CPU-s moves the ~19.7–20.4 s build ~3.2%; it does not close
  Move 3's 7.555 CPU-s gap. The out-of-window ~63% host-other mass
  (E2-proper: `publication-recovery` et al.) remains the larger, separate
  territory, unchanged by this entry.
- `conformance-quick` gates the VMM lane (the recipe's own note); native
  runtime validation here is the three traced full builds, the AMP1 arms,
  and the 16 untraced ABBA builds, all `BUILD_OK`.

## 7. Record corrections landed with this entry

- AGENTS.md's fault bullet: the scrub attribution now records the landed
  replacement and its measured result; the "levers" sentence drops the
  designed-but-unbuilt replacement and keeps the allocation-side term.

## Receipt SHA-256s

| file | SHA-256 |
|---|---|
| `nfault-a.raw` | `d358ab6da3f9db0c79079236e746a3bdf675672c055bbd7e701f233ac056c073` |
| `nfault-b.raw` | `7dea83481f94cd0e18cfbf402acbbde6a6156a52461444f7f5e613072f9fd3cb` |
| `nfault-off.raw` | `3b6ce55e2e6c11e69a9db7019894c91031a83c6f2b68642b0b767befad8d1613` |
| `nfault-a.reparse.summary.jsonl` | `db8785bd867e813b1c968f098169661540df89a054b1689a03d544987c056a39` |
| `nfault-b.reparse.summary.jsonl` | `7df07ebbcb9165e1149f88df77f3f0351144c03bf893cd671d849a5353563cd7` |
| `nfault-off.reparse.summary.jsonl` | `bc86a9cad743fd332cacf36fb3d798d7f9249b0ec9931c831d21fb8b1a233a4d` |
| `carrick-control` | `aa33e7df3aa6da5c01ced3fbf5ba2deffa47ed5c5f2ccc023aed470e9996e681` |
| `carrick-candidate` | `914b6881f759b89f40af99fff70b16c4223736f078c22f153fbf4b1b1996c17c` |
