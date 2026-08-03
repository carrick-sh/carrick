# Persistent-store template regression: the mechanism is the block-entry shape, not fusion

**Date:** 2026-08-03 (lane G). **Tree:** base `9f8a18f8`. **Binary:** built
signed from `9f8a18f8` (pre-fix — the right arm for a mechanism proof; knob
presence verified with `strings -a`). The emission-parity fix `f7d5c3c8`
does not alter the unit lane, so these numbers describe the shipped opt-in
store before AND after it. A sibling lane ran concurrently, so every wall
number below is "suggests"; the
instruction-level and counter evidence is load-independent. Raw artifacts:
`target/laneg-abba-20260803.log`, `target/laneg-nativeperf-{off,on}-20260803.log`,
`target/laneg-disas-store-{off,on}-20260803.txt` (lldb windows of the live
JIT), harness `target/laneg-abba.sh`.

## Reproduction (hermetic store, host env knobs)

busybox `awk 'BEGIN{for(i=0;i<8000000;i++)s+=i}'` in
`localhost:5005/carrick-go-conformance:1.24`, in-guest clock window, fresh
`CARRICK_DSR_STORE_DIR` tempdir:

| arm | samples (ms) |
|---|---|
| store unset | 356, 351, 356, 358 |
| store=1, run 1 (publisher, records) | 442 |
| store=1, warm (units attach) | 596, 635, 610, 627 |

Attach-arm regression +72-78% vs unset, all pairs non-overlapping —
reproduces the scoreboard's +65%.

## What it is NOT (counter evidence, NATIVEPERF)

Same-workload profile frames for the awk exec (`exec_epoch=1`), store OFF
(pid 75328) vs warm ON (pid 75339):

- `fusion-sites-a/b` and `fusion-exec-a/b` are IDENTICAL across arms
  (3/6 `fused_direct` sites, 0 fused executions). Exclusive-region fusion
  is not the mechanism, and superblocks are in scope for units (recorded
  candidates include extensions), so "superblock-fusion loss" — the
  suspect previously on record — is refuted.
- `gateway_entries` goes DOWN in the slow arm (2814 → 1966), and
  `exit_resolve_direct` 1505 → 651: attached units arrive pre-linked, so
  the loop stays inside emitted code in BOTH arms. The regression is not
  gateway traffic; it is the emitted code itself
  (`thread_cpu_ns` 306 ms → 555 ms on the same guest work).

## What it IS (instruction evidence, same hot block both arms)

lldb attached to the live guest mid-loop, disassembling around the sampled
PC. Store OFF — the hot back-edge is a patched direct branch landing at the
TRUSTED ENTRY, three instructions past the generation guard:

```
b      0x10aabd2fc         ; loop back-edge, patched direct link
0x10aabd2fc: mov  x17, #0x0            ; trusted entry: narrow expected
0x10aabd300: str  x17, [x28, #0x478]   ; publish generation
0x10aabd304: ldr  x17, [x28, #0x468]   ; reload guest x17
<guest body>
```

Store ON (warm) — the same guest code runs from an attached unit block,
`GenerationGuard::BindingIndex`, NO trusted entry, so every entry (the
loop back-edge included, plus a binding-table install trampoline on
cross-block patches) runs the full guard:

```
0x1065425d0: ldr  x19, [x28, #0x4f0]   ; CTX_GENERATION_BINDINGS
0x1065425d4: mov  x17, #0x163          ; binding index, FIXED 4-word
0x1065425d8: movk x17, #0x0, lsl #16
0x1065425dc: movk x17, #0x0, lsl #32
0x1065425e0: movk x17, #0x0, lsl #48
0x1065425e4: add  x19, x19, x17, lsl #4
0x1065425e8: ldp  x19, x17, [x19]
0x1065425ec: ldar x19, [x19]           ; ACQUIRE, 4-deep dependent chain
0x1065425f0: eor  x19, x19, x17
0x1065425f4: cbnz x19, stale
0x1065425f8: str  x17, [x28, #0x478]
0x1065425fc: ldr  x17, [x28, #0x468]
<guest body>
```

3 instructions per hot entry vs 12 with a serialized `ldar` — on an
interpreter loop of small blocks that is the whole +65-78%.

## Root cause in the code

Two recording-path divergences from native emission
(`crates/carrick-dsr-aarch64/src/`):

1. `emit.rs` suppressed the trusted entry whenever a recording was
   attached (`recording.is_none()` gate) — fixed in `f7d5c3c8`; recording
   is now a pure tap, pinned by
   `emit::tests::recorded_emission_is_word_identical_to_native_emission`
   (plain AND fused plans, word-identical including rematerialization).
2. `record_portable_block_artifact` is a SECOND emission mode: it
   re-assembles candidates with `DirectExitEmissionPolicy::
   PortableUnitAuthority` and `GenerationGuard::binding(...)` instead of
   tapping the native emission, and the install path registers the copied
   blocks behind binding tables and edge trampolines
   (`patch_shared_edge_via_binding_trampoline`). The premise that forced
   the indirection — "immutable translation units cannot patch their
   branch words after dyld maps them" (`emit.rs`, cached-exit comment) —
   no longer holds: the transport COPIES units into the private cache at
   install, so per-process patching is possible.

## The remaining fix (re-flip condition, sized)

Units must carry the native recording and the install must replay it:

- candidates: take the `ArtifactRecord` from the ONE native emission
  (`emit_block_recording_artifact_optional`) — delete
  `record_portable_block_artifact` and the authority emission policy;
- store payload: per block, relocations + trusted entry + direct links
  next to the existing `.code`/`.metadata-v3` pair (the `ArtifactTemplate`
  serde and `TrustedEntryTemplate` landed in `f7d5c3c8` carry exactly
  this); schema-bump so pre-change stores refuse and re-record;
- install: per block, slice the code image, `apply_replay_relocations`
  with `ArtifactBindings::for_replay(observation.current_atomic(),
  INITIAL, mode)`, publish through `publish_emitted` — which already
  handles trusted entries, pending-link patching, incoming-link severing
  registration, and page dependencies — instead of
  `prepare_shared_install`'s binding tables, `TargetCacheAuthority`, and
  trampolines; sensitive blocks keep the re-plan harvest;
- then delete the unreachable machinery: `GenerationGuard::BindingIndex`,
  `PortableUnitAuthority`/`emit_cached_direct_exit`, the trampoline
  patcher, and the cell sidecar packing (`DirectBindingLayout::SidecarV1`
  demotes to `Disabled` everywhere once units stop emitting cells).

The blocking cost is the install/test surface: the legacy install path is
load-bearing for a large fixture-driven test surface
(`carrick-runtime/src/native_darwin/dsr/oracle.rs`, `aot_cache.rs`), which
is why this did not land in the same day as the emission-parity half. Until
the unit pipeline records the native tap, the store stays opt-in and the
gate doc comment on `persistent_store_runtime_enabled` names this exact
condition.

## LANDED (2026-08-03, lane G2)

The re-flip condition above is implemented: units carry the native
recording tap (`ArtifactTemplate` per block over unbaked `.code` words,
`{stem}.metadata-v4`, `TRANSLATOR_ABI_CURRENT = 7`) and
`ProcessState::install_shared_unit` replays each block through
`publish_emitted`. The `BindingIndex` guard, `PortableUnitAuthority`
emission, edge trampolines, direct-binding cell sidecar, and the V2/V3
metadata split are deleted.

Evidence (same binary, warm hermetic store, alternating arms, host-env
knobs; a sibling lane ran concurrently so wall numbers are "suggests"; raw
artifacts `target/laneg-g2-abba-20260803.log`,
`target/laneg-g2-disas-samples-20260803.txt`, harnesses
`target/laneg-g2-abba.sh` / `target/laneg-g2-disas2.sh`):

- awk-8M compute (the shape that forced opt-in, image awk = mawk): store
  OFF mean 361.5 ms / median 361.0; store ON (warm attach) mean 362.4 /
  median 355.1, n=8 per arm counterbalanced — **parity** (+0.2% mean,
  -1.6% median) against the pre-fix +65-78%.
- lldb on the live warm guest: attached blocks show the lean Absolute
  guard (`eor`/`cbnz`) followed by the 3-instruction trusted entry
  (`mov x17,#0x0; str x17,[x28,#0x478]; ldr x17,[x28,#0x468]`), and
  patched direct branches land EXACTLY at trusted entries
  (`b 0x107058a9c` -> entry at `0x107058a9c`). Six sampled 320-insn
  windows contain ZERO `CTX_GENERATION_BINDINGS` loads (the only
  `#0x4f0` references are the retained private indirect-authority
  STORES). Word identity and trusted-entry registration are pinned
  hermetically by `translator::tests::native_tap_unit_install`.
- Attach counters: warm run `shared_unit_hits=2`,
  `shared_blocks_mapped=1255`, `shared_metadata_bytes_read=436259`,
  validation 1.16 ms — the serialized-manifest read path replaces the V3
  mmap.
- CAVEAT for the flip: the coarse cold-build single-run check
  (`target/laneg-g2-build-20260803.log`, hello-world `go build`, A B B A)
  suggests store ON ~+4.5% (9.63/9.84 s vs 9.31/9.33 s) — the per-exec
  serialized-metadata decode + per-block replay replaced the mmap'd V3
  install, so the old ~3% cold-build win is NOT confirmed to survive.
  Candidate follow-ups if a quiet-box ABBA confirms it: lazy per-block
  install on first lookup, or a zero-copy record layout for the v4 wire.
  The default therefore stays opt-in until the coordinator's central
  quiet-box ABBA covers BOTH the compute shape and the build lane.
