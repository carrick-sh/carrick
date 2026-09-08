# The ordered mapping index measured SLOWER than the vector it replaced

**Recorded 2026-09-08.** Fix binary `de24f502c2a9393e` at `3bda9ef9b`
(branch `agy/attr-compile2-sep07`); base binary `211df9969462560d` at
`78155cb5e`. Both built through `just build` (hypervisor entitlement present,
`__dof_carrick` present).

## The measurement

The reducer from
[`2026-09-07-cpython-compile-attribution.md`](2026-09-07-cpython-compile-attribution.md)
(`compile('a' + '()' * DEPTH, '<test>', 'single')`) at depth 400,000, run
INTERLEAVED base/fix on one host so both sides see the same load. Guest-measured
seconds, `target/conformance/eco-load/compile-reducer.sh`:

| pair | base (78155cb5e) | fix (3bda9ef9b) | host load |
|---:|---:|---:|---|
| 1 | 4.451 s | 6.227 s | 14.8 |
| 2 | 4.220 s | 5.277 s | 14.8 |
| 3 | 3.257 s | 5.019 s | 14.0 |
| **mean** | **3.976 s** | **5.508 s** | |

**The fix is 1.39x slower, and it is slower in every one of the three pairs.**
Load was 14.0-14.8 across all six runs, so the ordering is not a load artefact,
though the absolute numbers are not citable as ratios (the bar is load < 5).

The `cpython-compile` conformance row on the fix binary hit its 300 s budget
(`carrick_ms = 300435`, verdict `timeout`, 65/65 cases passed before the cut).
A row sitting exactly on its budget is a refusal, not a ratio, so the `112.23x`
the harness printed means nothing except "did not finish".

## Why

The migration converted four of the per-fault scans the attribution named into
ordered queries -- `mapping_for_range`, the two `next_local` neighbour bounds and
`lower_has_local`. It did NOT convert the IPA-domain lookup:
`HvfVmState::mapping_for_ipa_range`, reached from `GuestVmBackend::host_ptr`,
which `Aarch64EngineCore::diagnostic_fault_page_tables` calls on every fault to
resolve the TTBR0 root before walking the live descriptors.

That lookup still walks the whole table, and the row it wants -- the page-table
root -- is published early and sits at a LOW guest VA, so both the old
`Vec::iter().rev()` and the new `BTreeMap::values().rev()` reach it LAST. The
scan length did not change; the cost per element did. Reverse iteration over a
`BTreeMap` chases pointers where the vector streamed contiguous memory, so the
one surviving O(N) scan got several times more expensive per row, and that
outweighs the four scans that became O(log N).

## The other correction the measurement forces

Coalescing cannot collapse a first-touch storm. Every sparse extent registers
its own global-frame host owner
(`sparse_materialization::prepare` -> `register_global_frame_host_owner_in` ->
`custody.allocate_logical_owner()`), so consecutive extents inside ONE VMA carry
DIFFERENT `owner_generation`s. `owner_generation` is the value
`global_frame_region_owner_matches_in` authenticates against, so two rows that
disagree on it are two different frame incarnations and must not merge. The
coalescing path is correct and it fires where generations do agree (extension
arena rows publish with generation 0), but the row count on the cpython-compile
path stays O(#extents), not O(#VMAs). The unit test that proves 10k contiguous
extents collapse to one row proves the mechanism, not that the mechanism fires
on this workload.

## What this means

The representation change is not landable in this state, and "sorted by
construction" is not by itself the fix the attribution predicted. The
attribution's own arithmetic assumed all eight scans go away; converting five of
six real ones while making the sixth more expensive is a net loss. Two things
have to be true together:

1. **No full-table walk may remain on the fault path.** `mapping_for_ipa_range`
   and `shared_futex_mapping_for_ipa_in` need an IPA-ordered query, not a
   reverse walk of a VA-ordered map.
2. Only then does the ordered representation pay, because only then is the
   B-tree's higher per-element cost paid O(log N) times instead of O(N).

## Verified

- 3 interleaved base/fix pairs at depth 400,000 (table above), plus a fix-side
  100,000-depth run at 0.439 s (load 48) and 400,000 at 11.281 s (load 51.5),
  which show how strongly this reducer inflates under load and why only the
  interleaved pairs are read.
- Conformance rows on the fix binary, `--tier full --workers 1
  --carrick-timeout-cap-s 0 --require-cached-oracle`: `ltp-mmap18` MATCH (4/4),
  `ltp-munmap01` MATCH (2/2), `go-go_types` MATCH (571/571), `cpython-mmap`
  MATCH (38/38), `cpython-compile` TIMEOUT at its 300 s budget. Correctness is
  intact on every row that finished; the failure is cost, not behaviour.

---

# Follow-up: closing the IPA gap turns the 1.39x regression into a 2.4-5.9x win

**Recorded 2026-09-08**, same branch. Fix binary `5c2e165d6166e7c8` at
`19b2fce37` (the measurements below), final artifact `59202e8d66aa6f24` at
`d821734b6` (which adds only a clippy `#[allow]` attribute and JSON position
moves, and reproduces the result). Base binary unchanged: `211df9969462560d`
at `78155cb5e`.

## What changed

`TaskMappingIndex` gained a second ordered view of the same rows keyed by
stage-2 IPA (`by_ipa: BTreeSet<(row.ipa, row.start)>`), plus an exact multiset
of live row sizes that bounds how far below a queried IPA a covering row can
begin. `mapping_for_ipa_range` and `shared_futex_mapping_for_ipa_in` resolve
through it, so no full-table walk remains on the fault path.

## Reducer, interleaved base/fix

Depth 400,000, load 12.1-14.4:

| pair | base | fix | speedup |
|---:|---:|---:|---:|
| 1 | 3.473 s | 1.569 s | 2.21x |
| 2 | 3.246 s | 1.269 s | 2.56x |
| 3 | 3.049 s | 1.257 s | 2.42x |
| **mean** | **3.256 s** | **1.365 s** | **2.39x** |

Depth 1,000,000, load 17.1-21.6:

| pair | base | fix | speedup |
|---:|---:|---:|---:|
| 1 | 49.559 s | 9.426 s | 5.26x |
| 2 | 42.102 s | 6.087 s | 6.92x |
| **mean** | **45.831 s** | **7.757 s** | **5.91x** |

The speedup GROWS with depth (2.4x at 400k, 5.9x at 1M), which is what removing
one of two super-linear terms looks like.

Repeated on the final artifact `59202e8d66aa6f24` at depth 400,000, load
20.4-21.7: base 5.077 s / 2.854 s against fix 2.091 s / 0.906 s (2.43x, 3.15x).

## Scaling is much flatter but NOT yet linear

Fix-side depth sweep, load 15.4-17.1:

| depth | fix | vs 100k | linear would be | the base's own sweep |
|---:|---:|---:|---:|---:|
| 100,000 | 0.192 s | 1.0x | 1.0x | 1.0x |
| 200,000 | 0.409 s | 2.1x | 2.0x | 2.3x |
| 400,000 | 1.173 s | 6.1x | 4.0x | 12.7x |
| 800,000 | 4.441 s | 23.1x | 8.0x | 160.8x |

At 8x the depth the fix costs 23x, where the base cost 161x. The exponent came
down a long way; it is not 1. Something super-linear remains on this path and
this change does not identify it.

## Conformance rows on the fix binary

`--tier full --workers 1 --carrick-timeout-cap-s 0 --require-cached-oracle`:

| row | verdict | carrick | oracle | ratio |
|---|---|---:|---:|---:|
| `cpython-compile` | **MATCH** 150/150 | 26.8 s | 2.677 s | 10.01x |
| `cpython-mmap` | MATCH 38/38 | 0.882 s | 0.411 s | 2.15x |
| `ltp-mmap18` | MATCH 4/4 | 0.272 s | 0.612 s | 0.44x |
| `ltp-munmap01` | MATCH 2/2 | 0.268 s | 1.010 s | 0.27x |
| `go-go_types` | MATCH 571/571 | 23.9 s / 24.6 s | 6.182 s | ~3.9x |

`cpython-compile` was a 300 s TIMEOUT before the IPA view and MATCHes at 26.8 s
after; the attribution recorded the base at 62.3 s / 23.3x. Host load was 8-14,
so these are not citable as ratios against the 2x bar, but the verdicts are
verdicts.

One `go-go_types` run at load 13.8 came back `carrick_crash` after 558/571 with
`scheduler generation observer lost exact transition ... run queue publication
authority does not match the submitted generation`. That abort is in
`carrick_runtime::kernel::scheduler`, which this change does not touch, and it
reproduces on the BASE binary (see below). Two subsequent runs on each binary at
load ~7 MATCHed 571/571.

## go-build reducer (the window-corruption check)

`gobuild-loop.sh <label> 65536 8`:

| binary | load | builds | SIGSEGV / fatal | scheduler abort |
|---|---:|---:|---:|---:|
| fix | 13.0 | 8/8 | 0 | no |
| fix | 29.7 | 8/8 | 0 | no |
| fix | 19.1 | aborted | 0 | yes |
| fix | 35.3 | aborted | 0 | yes |
| fix | 38.7 | aborted | 0 | yes |
| base | 18.5 | 8/8 | 0 | no |
| base | 21.2 | aborted | 0 | yes |

**Zero SIGSEGV and zero `fatal error` in every run on both binaries**, which is
the window-corruption criterion. The runs that did not reach 8/8 died on the
same `lost exact transition` scheduler abort, which `gobuild-loop.sh` already
greps for by name, and which the base binary hits too. It is load-correlated
(no abort below load 19 on either binary) and out of this change's fence.

## Still open

1. **The residual super-linearity above.** 23x at 8x depth is not linear and is
   not explained here.
2. **Coalescing still cannot fire on this workload** (distinct owner generations
   per extent, see above). The row count on the cpython-compile path is still
   O(#extents); the win came entirely from making the lookups ordered.
3. **The per-fault scan COUNT was never instrumented.** No probe reports it, and
   `crates/carrick-observability/src/probes.rs` is outside the fence, so the
   evidence here is wall time and verdicts, not scan counts.
