# Steady-state emitted code: removing the block-boundary and virtualization tax

**Status:** design, Phase 1 starting.
**Lane:** Darwin/AArch64 native DSR only.
**Goal served:** close the ~12x steady-state execution penalty (`handoff.md`).
**Evidence base:** the first executed-shape census on the *compute* workload
(2026-08-01, this doc's §1), which the handoff named as the blocking step.

## 1. The census, and what it settles

`scripts/dtrace/native-shape-census.d` attached to an 80M-iteration awk loop
(`localhost:5005/carrick-go-conformance:1.24`, `--exec-backend native`),
joined against `CARRICK_DSR_CODE_SNAPSHOT_DIR` retirement snapshots by
`shape_classify.py`, then block-attributed and disassembled with
`scripts/perf/hot_blocks.py`. 11,192 matched samples, 2 guest processes;
record appended to `docs/perf-results/native-dsr-shape-census.jsonl`
(raw sha256 `ea0cb219ecf9…`).

Headline: **the compute workload runs in Direct (identity) address mode —
zero window-check or bias samples — and DSR-inserted words are still 68.0%
of JIT-resident CPU.** The biased-memory lowering that dominated the build
census is not present here at all. The tax is at block boundaries and around
the three virtualized registers:

| class | share of matched |
|---|---|
| `dsr:ctx-load64` | 33.9% |
| `guest:ldst-imm` (guest's own work) | 24.5% |
| `dsr:x17-materialize` | 18.6% |
| `dsr:ctx-store64` | 13.4% |
| everything else guest | ~7% |
| `dsr:br-x17` + guard + nzcv | ~2.2% |

Block attribution: the top 8 blocks carry 86% of samples; all are mawk's
bytecode-dispatch loop (`guest 0x400009xxx`). Reading the hottest block
(40.3% of all samples, 101 emitted words for ~6 native instructions) gives
the mechanism split:

- **Indirect-branch exit machinery ≈ 30%** of samples: 4 register spills,
  NZCV `mrs`+`str` … `ldr`+`msr` round-trip, target staging store, 2-way
  cache probe, authority re-validation (3 more context stores), restores,
  `cbz` + `br x17` — ~40 executed words per dispatch.
- **Virtualized-register dances ≈ 20%**: mawk keeps its VM program counter
  in guest **x28** and its jump table in guest **x19** — exactly the two
  stolen registers. Each touch pays the 8-word `emit_virtualized_register`
  template (§2).
- **Entry guard ≈ 13%**: 11 words on 100% of entries — including entries
  through already-patched same-generation direct links — with a 4-word
  materialization of expected generation **zero** (`movz x17,#0` +
  3× `movk #0`) sitting right after the `ldar` (the 476-sample spike on
  `movz x17,#0` is the acquire-load stall with sampling skid).
- **Guest's own computation ≈ 30%.**

Removing the inserted words entirely would take JIT-resident CPU to ~1/3 —
compute ratio from 10.9x toward ~3.5-4x — before any second-order wins
(I-cache, store-buffer pressure, the 33%→0 D-cache slot traffic).

Register-use census (sample-weighted, guest-classified words only): the hot
guest code uses x0-x2, x15-x17, x19-x30; **x3-x14 are completely unused**.
The stolen/borrowed set — x28+x19 stolen, x17 semi-stolen, x15/x16 borrowed
per-op — collides with the hot registers of *both* measured ecosystems (Go
assembly leans on x15-x17; AAPCS64 C leans on x19/x28, the first and last
callee-saved registers). x19 was chosen as `RESERVED_SCRATCH` from a
Go-build census in which it had zero weight; that generalized exactly as
well as the build workload itself.

## 2. Why the templates cost what they cost

`emit_virtualized_register` (emit.rs) emits, for ONE guest instruction that
mentions one virtualized register (e.g. `ldrh w0,[x19,w23,uxtw #1]`):

```text
str  xS, [x28,#1120]   ; spill borrowed scratch
str  xC, [x28,#1128]   ; spill borrowed context scratch
mov  xC, x28           ; mirror the context pointer
ldr  xS, [xC,#slot]    ; load the virtual register
<rewritten word>       ; base/mention rewritten to S
str  xS, [xC,#slot]    ; store back — even when nothing changed
ldr  xS, [xC,#1120]    ; restore scratch
ldr  xC, [x28,#1128]   ; restore context scratch
```

Three of these eight words do nothing an invariant doesn't already
guarantee: x28 *is* the context pointer for the whole of translated
execution, so the mirror is addressable as `[x28,#slot]` directly, and the
single-virtual rewritten word cannot mention x28 (an x28 mention is the
dual-virtual case); the store-back is dead for every non-writeback,
non-destination use. `emit_dual_virtual` has the same shape at 10+ words.

The lean entry guard (13 words) re-proves on every entry what a patched
direct link already witnesses — links are only installed between blocks of
the same generation, and nothing in the tree severs links on invalidation,
so the guard must run everywhere (1,880,869/1,880,869 entries in the H008
grounding record). The indirect exit re-validates target authority and
round-trips NZCV because its probe uses flag-setting compares.

## 3. Approaches considered

**A. Staged emission repair (recommended, chosen).** Keep the translator's
architecture — per-thread code cache, direct links, inline indirect cache,
per-word recovery — and remove the taxes in place, each stage gated by the
compute census (mechanism) and the workload-spread ratio (wall). This is
the DynamoRIO/Pin shape: same-ISA code runs verbatim, boundary machinery is
hand-tightened, invalidation pays instead of steady state.

**B. Liveness-driven per-block register allocation.** A real regalloc pass
(guest registers renamed into a per-block allocation, ctx traffic only at
boundaries) has a higher ceiling, but it rewrites the recovery contract —
every word's guest-state reconstruction — wholesale, for a win the census
does not require: the guest's registers are *already* host-resident; only
3 registers and the boundaries are taxed. Adopt its cheapest core only if
Phases 1-3 leave virtualization hot: per-block scratch residency (spill a
block-dead register once per block, restore at exits).

**C. More caching/AOT.** Refuted by measurement (handoff: translation is
noise on compute; caching leaves ~10-11.5x untouched). Not pursued.

## 4. Phases

Each phase lands default-ON with a `=0` escape hatch, red-first emit tests,
and the gates in §5. Later phases build on earlier ones but do not require
them.

**Phase 1 — virtualization template repair (emission-local).**
Single-virtual: address slots via x28 directly (drop mirror + context
scratch entirely), elide the load for write-only destinations, elide the
store-back for read-only uses → 8 words to 4 (read-only borrowed-scratch
case), 2 if the scratch question dissolves with the store/load elisions.
Dual-virtual: same treatment → 10+ words to ~5. Every removed word removes
its recovery entry; remaining entries keep today's actions (the states are
a strict subset). Expected on compute: a large cut of the 47.3%
ctx-load+store share; wall from 10.9x toward ~8x.

**Phase 2 — trusted-entry chaining.** Second entry point past the guard;
patched PRIVATE direct links target it. The 2026-08-01 audit (see the
`phase2-audit` notes below) corrected three assumptions, and the H008 doc's
"invalidation already severs them" line, before code was written:

- **The trusted entry is 2 words, not 0.** Ctx slot 1144
  (`DsrContext.generation`) is consumed by sensitive-exit dispatch
  (`state.sensitive` is keyed `(GuestVa, CodeGeneration)` and never pruned),
  and every gateway wrapper seeds it with a stale INITIAL — skipping the
  publish silently resolves a *previous* generation's metadata. The trusted
  entry publishes its block's generation (materialize + `str`), then falls
  into the body. Honest saving: ~11 of the 13 guard words.
- **Links are not same-generation and nothing severs them today.** The
  guard at every entry IS the invalidation mechanism; `DirectLink` metadata
  is dropped at publication (`translator.rs:3917`), so the reverse index is
  net-new state, modeled on `DirectBindingTable::incoming`. Severing must be
  EAGER at generation-bump time (a code-write observer from
  `mapped_memory`'s bump path into the process translator), not part of the
  lazy reap in `translate()` — a hot loop through a trusted entry would
  otherwise run stale forever. Sever = repatch the slot to the `b +1`
  fall-into-stub form; the next traversal resolves through the gateway and
  retranslates.
- **The stale window stays one block body, no kick needed.** A loop's back
  edge is itself an incoming link taken every iteration, so eager severing
  of every link into a bumped page bounds any thread's stale execution to
  the remainder of its current block plus at most one non-stale block —
  the same order as today's guard-at-entry window, which already tolerates
  mid-block staleness (blocks are single-page by construction).
- **Shared units are out.** Intra-unit links are baked into immutable
  dyld-mapped code with no repatch path; `BindingIndex`-guarded blocks keep
  their guards, and the private→shared trampoline keeps targeting the
  guarded entry. Only the two private patch sites move to the trusted
  entry.
- **Fork/exec are already clean** (fork agrees at the instant and inherits
  COW state; exec discards blocks, links, and the cache cursor), and at
  every patched slot guest x17 is already committed to slots 136/1128, so
  recovery entries in the skipped preamble are simply never reached.
- **Phase 3 may NOT point indirect-cache hits at the trusted entry** until
  `IndirectTargetCacheEntry` carries and checks a generation — the JIT
  cache discards it today and relies on the target's guard.

**Phase 3 — indirect-branch lookup slimming.** Flag-free probe
(`eor`+`cbnz` / `sub`+`cbz` instead of `cmp`+`b.eq`) so the NZCV
`mrs`/`msr` round-trip disappears; skip the authority switch when the hit
entry's authority is the current cache (the steady-state case — install
authority data into the entry once, at fill time); spill only what the
shape uses (`x30` staging only for `blr`); point hits at the Phase 2
trusted entry. Target: ~40 executed words per dispatch to ~15, on the ~30%
share.

**Phase 4 — evaluate, then only if the census still shows it: un-steal
x19.** Replace `RESERVED_SCRATCH` with per-block scratch residency chosen
from the block's dead registers (census: x3-x14 free in every hot block),
restoring at exits. This is the Approach-B core, adopted narrowly.

## 5. Gates

- **Mechanism gate per phase:** re-run the compute shape census; the class
  the phase targets must drop proportionally to the emitted-shape change,
  and `hot_blocks.py` must show the new sequence in the dispatch block.
- **Wall gate:** `scripts/perf/workload-spread.sh` compute ratio, N≥3,
  strictly serial phases; the build and fs-walk rows must not regress.
- **Correctness:** red-first emit tests per changed template
  (`bad64`-asserted sequences), the recovery oracle and jitter/async-kick
  suites, `just ci`, and the native conformance smoke (go-sync and
  cpython-threading break first on addressing bugs).

## 6. Out of scope

fs-walk's 128x (cap-std amplification, separately ranked in the handoff),
the biased-mode memory lowering (not exercised by compute; revisit against
a non-PIE workload after Phase 1 lands the shared template repairs), and
any weakening of guest-visible ABI guarantees.


## 7. Soundness argument: the generation `ldar` can be a plain `ldr`

*(Written before any code, per the campaign rule; the change this licenses is
the Phase-4 follow-on that relaxes the acquire in the entry guard and the
IBL's flavor-1 generation check, default-relaxed with `CARRICK_DSR_ACQUIRE_GEN=1`
restoring the acquire for bisection.)*

**Claim.** Replacing `ldar` with `ldr` at both generation-check sites preserves
every invariant the system actually relies on. The acquire is a vestige of
treating the check as a lock acquisition; it is a *versioned re-resolution
hint*, and hints need bounded staleness, not ordering.

**The writer's own ordering already forfeits what acquire would buy.** The
code-write path bumps the page generation (Release store,
`PageGenerationTable::note_guest_code_write`) *before* touching guest RAM
(`invalidate_and_note_dsr_write`, mapped_memory.rs — "before touching guest
RAM" is its documented contract). So even with acquire semantics, observing
the bumped value has never implied observing the new code bytes; the pairing
"acquire the version, then rely on what release published before it" does not
describe this protocol. What actually re-synchronizes a stale reader is the
MISS path: a mismatched check exits to the resolver, which retranslates from
current guest memory under the translator's locks.

**Coherence, not ordering, bounds staleness — and it already had to.** A plain
load may be *reordered* relative to the reader's other accesses, but it cannot
read an older value of the atomic than coherence delivers; propagation latency
is identical for `ldr` and `ldar`. The system's accepted staleness window is
already far larger than coherence latency: the guard checks only at block
entry (mid-block staleness is tolerated for a full block body), Phase 2a's
severing leaves a not-yet-severed-link window of one block body, and the
guest's own architectural SMC contract (`IC IVAU`/`ISB`, or kernel
membarrier/IPIs — without which stale execution is architecturally permitted
indefinitely on real hardware) dominates all of these. A nanoseconds-scale
reorder window on the version read adds nothing observable.

**No cross-thread payload is consumed under the check.** The IBL entry
(tag/expected/gen-pointer/code) is THREAD-PRIVATE, published by the same
thread's resolver; the guard compares against an immediate baked at
translation time. The only datum reached through a loaded pointer is the
generation value itself, and an address-dependent load is ordered after the
load of its address on AArch64 regardless of acquire. The branch target on a
hit is JIT code whose publication was separately synchronized at install time
(store + `sys_icache_invalidate`, and instruction fetch is not ordered by
`ldar` anyway — the acquire never protected I-fetch).

**The torn-bytes race is the guest's, and is unchanged.** A reader that misses
while the writer is mid-copy can retranslate from partially written bytes —
with or without acquire, today and after this change. On hardware,
concurrently executing code being modified without the architectural
synchronization sequence is the guest's own data race; guests that JIT
correctly serialize against execution. Not a new risk and not a widened one.

**Precedent.** QEMU's TCG reads its translation-block version state with plain
loads and synchronizes invalidation through quiescence; DynamoRIO likewise
does not pay an acquire per dispatch. The acquire-per-block-entry design is
the outlier, not the norm.

**Gates for the change.** The jitter/async-kick oracle suites and the 2a/2b/3
live invalidation tests (sever, stale-entry re-resolve) must stay green; a
census must show the `ldar` stall (the post-4d dominant single stall) convert
into wall time; conformance smoke must report no regressions. The escape
hatch restores `ldar` at both sites from one switch so any field report can
bisect the relaxation in isolation.
