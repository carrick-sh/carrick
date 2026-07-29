# H008: compact biased addressing and trusted-entry chaining

**Status:** design, first spike in progress.
**Lane:** Darwin/AArch64 native DSR only.
**Evidence base:** `docs/perf-results/native-dsr-shape-census.jsonl` — DSR-inserted
words are 81.3% of JIT-code CPU residency (~56% of all user CPU on the
18,321 ms `W0` workload window); the hottest guest loop (memclr-style
`stp xzr,xzr,[x17],#16; cmp; b.le`) runs as ~22 emitted words per iteration.

## 1. Where the ~22 words per iteration actually come from

Reading `emit_biased_memory` and the entry-guard emitter end-to-end (do not
skip this; the census classes alone mislead):

**Per block entry — every loop iteration via the back edge (~9-10 words):**
the generation guard's `cmp` clobbers NZCV and its sequence needs x16/x17,
so every entry pays: spill guest x16/x17 to slots 1120/1128, `mrs`+`str`
NZCV to slot 936, materialize the expected generation, `ldar`+`cmp`+`b.ne`,
then `ldr`+`msr` NZCV restore and guest x16/x17 reloads. The census's
`guard-ldar 0.1%` is just the one `ldar` word; the guard's *support* words
were counted in the ctx-store/ctx-load/x17-materialize classes.

**Per guest memory access (~13-15 words for a plain store-pair):**
2-4 scratch spills (`str xS,[x28,#{1120,1128,1144,...}]`), optional virtual
x18/x28 reloads (slots 144/224), base load, effective-address computation,
`lsr x18,eff,#41` + `cbz` window check, slow-path FAR publish to slot 1200,
base reload, **host bias load from slot 1192**, `add`, second `cbz` +
`orr #1<<47` invalid tag, the rewritten access, writeback un-bias
(`sub`+commit) when the form writes back, scratch restores.

Two structural causes:
1. The bias is treated as an arbitrary runtime value (loaded per access),
   and `biased_scratch_registers` borrows per-op scratches (preferring
   x17, x16, x15 — exactly the registers Go's runtime assembly uses),
   forcing per-op spill/restore.
2. Every entry runs the flags-clobbering guard even when reached through a
   direct link that was only installed under the same generation the guard
   re-checks.

## 2. Spike 1 — aperture-disjoint ORR bias (compact addressing)

### Key fact

`BIAS_CANDIDATES` are 512 GiB/768 GiB/1 TiB/1.25 TiB — all **below** the
guest aperture end `BIASED_GUEST_APERTURE_END = 0x200_0000_0000` (2 TiB,
sized for Go's arena probe at `0x140_0000_0000`). A guest address can
therefore carry any candidate's bits, and the bias must be *added*.

A bias of exactly **`0x200_0000_0000` (1<<41)** is:
- disjoint from every in-aperture guest address by construction
  (`guest & bias == 0` for all guest < 2^41), so `orr == add`;
- an encodable AArch64 logical immediate (single bit);
- mappable: probed live on this host — `mmap(MAP_FIXED)` at 0x200_0000_0000,
  0x3FF_0000_0000, 0x400_0000_0000 and 0x7FF_0000_0000 all map and write
  (scratch probe, 2026-07-28).

### Lowering (immediate/unsigned-offset and writeback forms)

With an aperture-disjoint encodable bias, a memory access whose effective
address is `base + bounded_imm` lowers to:

```text
str  xS,  [x28, #spill]      ; ONE scratch (per-op v1; block-resident later)
lsr  x18, xBASE, #41         ; base-only window check (x18 is DSR-owned)
cbnz x18, slow               ; out-of-window → general tagged path
orr  xS,  xBASE, #(1<<41)    ; host address, no bias load, no add
<rewritten access, base=xS>  ; original imm offset / writeback form intact
[and xGUESTBASE, xS, #~(1<<41)]  ; writeback commit un-bias, one word
ldr  xS,  [x28, #spill]
```

~6 words for plain forms, ~7-8 with writeback, versus ~13-15 today. No
NZCV interaction (lsr/cbnz/orr/and set no flags), one scratch instead of
2-4, zero context loads.

### Soundness argument

- **Base-only check + displacement overhang:** `select()` already reserves
  `[aperture_end, aperture_end + 1 MiB + page)` as a guard window
  (`BIASED_GUEST_LITERAL_DISPLACEMENT_WINDOW`, address.rs). An in-window
  base with a positive scaled immediate (≤ 32,760 + 16-byte tail) can
  overhang at most into that reserved window → clean fault, recovery
  derives the guest address from FAR − bias. A negative immediate
  underflow wraps far above the Darwin user ceiling → clean fault.
- **Out-of-window bases** take the existing general path (tagged with
  `INVALID_BIASED_HOST_ADDRESS_BIT`), unchanged.
- **Register-offset forms** (`[xN, xM]`) have unbounded effective
  addresses; they stay on the general path in v1.
- **Recovery:** every word carries `BiasedMemoryRecovery` exactly as
  today; the compact shape has strictly fewer live states (one scratch,
  guest-coordinate base throughout except between `orr` and writeback
  commit). The writeback `and` un-bias replaces the `sub` and needs the
  same `base_coordinate: Host → Guest` transition bookkeeping.
- **Portability/cache identity:** the bias is already part of
  `AddressModeIdentity::Biased { host_bias }` and the translation-unit
  key; a process with a non-encodable bias simply emits the general form.
  Emitted bytes never depend on which process loads them.

### Selection change (LANDED)

`0x200_0000_0000` is prepended to `BIAS_CANDIDATES`, and the biased
reservation now extends one `BIASED_GUEST_UNDERFLOW_WINDOW` (1 MiB) below
guest zero so base-only checks stay sound for bounded negative immediates.
`NativeHostBias::aperture_disjoint_orr_immediate()` returns the
`(immr, imms)` ORR fields (N=1) exactly when the compact lowering is
permitted. `select()` keeps probe-and-fall-back, so hosts or layouts that
cannot reserve [2 TiB − 1 MiB, 4 TiB + 1 MiB) degrade to the historical
candidates and today's emission.

Fixture lesson: candidate spans are aperture-wide (2 TiB) but only
0.5-1.25 TiB apart, so they overlap — a collision at one candidate's base
blocks every candidate. Tests that force fallback must occupy
span-1-exclusive addresses (e.g. `0x390_0000_0000`).

## 3. Spike 2 — trusted-entry direct chaining (deferred until Spike 1 lands)

Direct links are only installed between blocks of the same generation, and
invalidation already severs them; a chained transition therefore re-proves
what the link's existence already witnesses. Emitting a second entry point
past the guard preamble (guard + its x16/x17 spills + NZCV round-trip) and
pointing direct links at it removes ~9-10 words per chained transition —
the whole per-iteration entry tax of hot loops.

Soundness obligations to verify in code before building (NOT yet done):
1. every invalidation path (page write, munmap, generation bump) unlinks or
   repatches incoming direct links before the old code can be re-entered;
2. the kick/fault recovery map remains valid for entries that skipped the
   preamble (recovery entries between the two entry points must not assume
   the preamble ran);
3. fork/exec link-reset paths (`fork_child`, `reset_for_exec`) already
   clear links — confirm the trusted entry cannot survive into a child
   with a stale generation table.

## 4. Gates

- **Mechanism gate:** re-run the shape census
  (`scripts/dtrace/native-shape-census.d` + `shape_classify.py`); the
  ctx-slot store+load share (63.6% of matched JIT samples at `W0`) must
  drop materially and proportionally to the emitted-shape change; the
  disassembled hot loop must show the compact form.
- **Wall gate:** paired alternating candidate/control screens per Decision
  14, then a clean committed five-sample campaign against `W0=18,321 ms`.
- **Correctness gates:** red-first emit tests (`bad64::decode` asserted
  sequences, shown red on revert), the biased-memory recovery oracle and
  jitter/async-kick suites, `just ci`, and
  `just conformance-native smoke --workers 4` (go-sync and
  cpython-threading break first on addressing bugs).

## 5. Rejected shapes

- **Plain `orr` with any current sub-aperture bias** — wrong for guest
  addresses above 512 GiB (Go's arena), which is why the bias is added
  today.
- **Dropping the window check entirely under the 2 TiB bias** — a wild
  guest pointer ≥ 2^41 would alias real host mappings inside
  [2 TiB, 4 TiB); the two-word flag-free check stays.
- **Per-op scratch selection by block liveness alone** (without the
  compact form) — it moves the spill traffic to different registers but
  keeps the per-op spill/restore and bias load; measured ceiling too low
  relative to the compact form's.
