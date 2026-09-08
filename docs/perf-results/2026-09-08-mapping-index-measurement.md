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
