# Store v5: lazy per-block replay + hot/cold offset-indexed wire — the micro flips from +14% to −26%

**Date:** 2026-08-03 (lane J2). **Tree:** `acd63f06` (lazy attach `f5653bfa`
+ v5 wire `acd63f06` on base `3dfae5b2`), signed rebuilt binary, marker
proven (`strings -a`: `metadata-v5` 1, `metadata-v4` 0, XLATCENSUS4 1/V3 0).
**Box:** NOT quiet — a sibling lane compiled and ran guests throughout, so
every wall number here is **"suggests"**. Counters (NATIVEPERF, census,
manifest census) are load-independent. Raw artifacts:
`target/perf-lanej/j2-abba-lazy-micro.log`, `j2-abba-v5-micro.log`,
`j2-abba-v5-build.log`, `j2-ce-*.stderr`, `j2-v5-warm.stderr`, harness
`target/perf-lanej/j2-abba.sh` (host-env knobs, hermetic
`CARRICK_DSR_STORE_DIR`, counterbalanced ABBA/BAAB blocks, stamped
`CARRICK_RUN_ID`).

## Why lazy replay alone could not win (measured, then designed around)

Wave-3's re-flip condition assumed an exec touches a fraction of a unit.
The census refutes that for the 20-exec `compile -V` micro: the compile
unit carries **8,253 blocks and a warm exec replays ~8,170 of them
(~99%)**. Lazy-only (commit `f5653bfa`) therefore measured **ON ~2190 ms
vs OFF ~1852 ms (+18%, n=8)** — no better than eager, because the binding
cost was never the replays skipped; it was the per-exec whole-manifest
load: `load_ns ~13.8 ms/exec` (3.5 MB serial read + varint decode of
~1.79M records + validate, `validation_ns ~11.6 ms`), where translation
avoided is only ~43 ms and replay itself cost ~42 ms.

The record census names the fix: **~98% of a unit's records are pc map
(1.01M) + recovery (0.74M)** — fault-reconstruction metadata that replay
never consumes. So the v5 wire splits each block into a HOT blob
(relocations, trusted entry, direct links — decoded on first lookup) and
a COLD blob (pc map, recovery — left undecoded in the mmap'd metadata;
`guest_pc_for_cache` decodes it only when a fault interrogates the block,
rebinding with the stored replay bindings). Attach parses only a
fixed-width index; `TRANSLATOR_ABI_CURRENT` 7→8 so old stores re-record.

## Counter evidence (same workload, warm store, per compile exec)

| counter | v4 eager/lazy | v5 hot/cold |
|---|---|---|
| metadata bytes | 3,496,336 read | 3,613,061 **mapped** (read=0) |
| `shared_metadata_validation_ns` | ~11.6 ms | **~0.43 ms** |
| census `load_ns` | ~13.8 ms | (index-only decode) |
| `phase_translate_ns` (warm ON) | ~56 ms | **~17–18 ms** |
| `phase_translate_ns` (store OFF) | ~50 ms | ~50 ms (unchanged) |
| blocks replayed / attached | 8,167 / 8,253 | 8,170 / 8,282 |

Replay + attach dropped from ~5.1 µs/block (v4 replay cloned each
block's ~217-record template) to **~2.2 µs/block** vs ~6.0 µs/block
translation — the cold clone elimination, not just the decode move, is
most of the win. The go-build-primed unit (20,148 blocks, 8.8 MB
metadata) splits 6.56 MB cold / 1.68 MB hot / 0.56 MB index+header
(`native_manifest_census`, now reading the real wire again);
`sensitive_block_count` is 7, so the replay-time sensitive re-plan is a
non-factor.

## ABBA (suggests — sibling lane active; alternating counterbalanced n=8)

**Warm 20-exec `compile -V` micro** (in-guest window,
`localhost:5005/carrick-go-conformance:1.24`):

| arm | median | mean | range |
|---|---|---|---|
| store=1 (warm v5) | **1369.5 ms** | 1367.1 | 1321–1386 |
| unset | 1842 ms | 1839.2 | 1821–1859 |

**Store=1 is ~26% faster than unset; the arms do not overlap.** Wave-3
measured +14% for the same gate (2048 vs 1798).

**Cold hello `go build`** (GOCACHE empty per run, warm store):

| arm | median | mean | range |
|---|---|---|---|
| store=1 (warm v5) | **8660 ms** | 8666.1 | 8510–8746 |
| unset | 9526.5 ms | 9750.4 | 9358–11543 |

**Store=1 is ~9% faster than unset on the cold build** (gate asked only
for ≤); the arms do not overlap (the 11543 OFF sample is a load spike —
counterbalancing absorbs it; the OFF median band matches wave-3's
9375–9647). Store priming for this shape: publisher run 10.88 s, second
run 8.60 s, 10 units published.

## What did NOT change

Fail-closed posture: replay validation (opcode/trusted-entry checks)
still refuses corrupt bytes per block and detaches the unit
(`a_corrupt_code_image_fails_closed_to_translation`); publication
preflight now `validate_deep`s every blob and names the defect; the
`.code` digest check at load is untouched; election, fork-claim
clearing, and crash-safe rename publishing are untouched. A replayed
block still answers faults bit-identically to a native translation —
pinned by `a_fault_on_a_replayed_block_decodes_unit_cold_metadata`
(mutation-checked).

## Flip caveat for the coordinator

The default stays opt-in here — flipping is the coordinator's central
call. What this lane's evidence supports: the wave-3 re-flip condition
("install cheaper than retranslation on the serial micro AND
non-regressing on the build") is now MET on this box, but under sibling
load; the central quiet-box ABBA should re-run both shapes (and the
awk-8M compute parity check) before flipping
`persistent_store_runtime_enabled`.
