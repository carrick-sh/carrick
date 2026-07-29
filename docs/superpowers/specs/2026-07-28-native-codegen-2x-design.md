# A codegen path within 2x of native guest execution

**Status:** approved design (user-approved 2026-07-28).
**Lane:** Darwin/AArch64 native DSR only.
**Goal:** translated execution costs no more than **2x the guest's own work**.
**Measured start:** translated execution is **16.1 CPU-s** where the guest's
own instructions account for **3.0 CPU-s** — **5.4x**. Target ≤ 6.0 CPU-s.

This supersedes H008 Spike 1 (compact biased addressing), which was
implemented, measured 3.76% SLOWER, and disabled in `c4a5504c`.

## 1. Where the 13.1 CPU-s of inserted code actually goes

Sampled PCs joined against per-process JIT snapshots, then bucketed by the
exact `DsrContext` slot each access targets. Share of matched JIT-code
samples (21,935 samples, 87.6% of them DSR-inserted):

| category | share | slots / shape |
|---|---:|---|
| **per-access scratch spill** | **33.5%** | `rewrite_scratch` 1120 (17.4%), `rewrite_context_scratch` 1128 (15.2%), 1160/1168 |
| **per-block-transition bookkeeping** | **~20%** | `entry_in_progress` 1152 (12.0%), `exit_target` 1080 (3.7%), `entry` 1072 (2.2%), `generation` 1144, guest x17 restore 136 |
| **generation-guard materialization** | **13.9%** | `movz`/`movk` into x17. CORRECTED 2026-07-29: this is the GUARD's expected value, NOT exit targets — direct exits are patched and that stub is dead code (re-derived: 15.69% guard vs 0.01% exit_target) |
| NZCV save/restore | 5.8% | slot 936, forced by the guard's `cmp` |
| host bias load | 2.6% | slot 1192 |
| aperture window check | ~3% | `lsr`/`cbz` |
| guest x18/x28 virtualization | ~1.9% | slots 144 / 224 |

Two structural facts follow, and they are the whole design:

**(a) There is no free host register.** Guest registers map 1:1 onto host
registers so that ordinary instructions emit verbatim (`InstAction::Copy`).
That makes translation fast and code small, but leaves the memory lowering
with nothing to compute an address into — so it borrows a guest register,
spills it to the context, and restores it, **on every access**.

**(b) Blocks are tiny, so per-transition cost is paid constantly.** A hot
loop is often one block; its self-link re-enters the block every iteration,
paying entry bookkeeping, the guest-x17 restore, the generation guard (and
its NZCV round-trip), and an exit-target materialization each time.

Guest x28 virtualization was the leading hypothesis before measurement and
is **refuted**: Go's goroutine register collides with carrick's context
register, but it costs only 0.9%. Do not spend effort there.

## 2. Ceiling arithmetic — what each fix is worth

Guest work is 12.4% of translated-execution samples. To reach 2x, inserted
code must fall to ≤50% of translated execution, i.e. **~86% of today's
inserted code must go**. Eliminating the per-access spill and all
per-transition bookkeeping together removes ~67% of inserted code and lands
near **3.3x** — real, but short. The remainder must come from exit
materialization, the window check, and the bias load. This design therefore
sequences every one of them, and states plainly that no single phase reaches
the goal.

## 3. Architecture

Three changes, each independently measurable, in descending measured value.

### Phase A — a permanently reserved address scratch (removes ~33.5%)

Reserve one GPR for the memory lowering, exactly as x18 and x28 are already
reserved, so an access computes its host address into that register with no
spill and no restore. Guest instructions naming the reserved register are
virtualized through a context slot, which is the mechanism already shipped
for x18/x28 — proven code, not new machinery.

The register choice is empirical, not a guess: instrument the emitter to
count guest register usage across the workload and reserve the least-used
GPR. The trade is `(memory accesses × ~10 words saved)` against
`(uses of the reserved register × ~3 words added)`; the counter tells us the
sign before we write the lowering. Measured x18/x28 virtualization at ~1.9%
suggests a well-chosen third register costs little.

### Phase B — amortize block transitions (removes ~20% + 13.9%)

Two independent levers, cheapest first:

1. **Trusted-entry chaining.** A direct link is only installed between
   blocks of the same generation and is severed on invalidation, so the
   guard it jumps to re-proves what the link's existence already witnesses.
   Emit a second entry point past the guard prologue and point verified
   direct links at it. Removes the guard, its NZCV round-trip and the
   x17 restore from every chained transition. **Requires** an audit of every
   invalidation path (page write, munmap, generation bump, fork, exec)
   proving links are severed before stale code can be re-entered.
2. **Superblock formation.** Extend translation past a direct branch into
   its target when the target has a single predecessor, so a hot loop body
   becomes one unit. This amortizes entry bookkeeping and exit
   materialization over many guest instructions and is what makes Phase A's
   reserved register pay off across a whole loop rather than one access.

### Phase C — flags-free guard and cheaper exits (removes ~5.8% + part of 13.9%)

The NZCV round-trip exists only because the guard compares with `cmp`. A
comparison that does not write flags (e.g. `eor`/`cbnz`) removes the save and
restore entirely. Exit-target materialization shrinks by loading the target
from the context or a literal pool instead of a four-word `movz`/`movk`
chain — the same move already made for gateway addresses in `26de3c07`.

## 4. Correctness contract (unchanged and non-negotiable)

Every phase preserves the existing recovery model: at every interruptible
emitted word, a fault or asynchronous kick must reconstruct exact guest
register, SP, PC and memory state. Concretely, each phase ships with:

- red-first `bad64`-asserted sequence tests, shown red on revert;
- a fault injected at **every** recovery point via the existing
  `recovery_points_for_test` / `patch_recovery_word_for_test` matrix,
  asserting exact register/SP/PC equality against an uninterrupted run;
- the live jittered-SIGPIPE sweep for asynchronous coverage;
- `just conformance-native smoke` (go-sync and cpython-threading break first
  on register-allocation errors) and `just ci`.

Spike 1 is the cautionary precedent: it passed every structural gate and was
still both a regression and a source of an intermittent host-address leak.
Structural green is necessary, never sufficient.

## 5. Gates

- **Mechanism gate, per phase:** re-run the shape census; the targeted
  category's share of JIT samples must fall by the predicted amount. A phase
  that does not move its own category is rejected regardless of wall time.
- **Wall gate, per phase:** paired alternating candidate/control screens on
  the workload window (Decision 14), with the phase behind a switch so both
  arms come from one binary — the method that produced the clean Spike 1
  rejection.
- **Goal gate:** translated execution ≤ 2x guest work, measured by the
  census's guest-vs-inserted split, with the workload-window ratio reported
  alongside.

## 6. Rejected

- **Direct (identity) addressing**, which would remove address translation
  entirely: blocked because Darwin's 4 GiB hard `__PAGEZERO` makes low guest
  images unmappable, and Go toolchain binaries are non-PIE at low addresses.
- **Moving carrick's context register off x28** to free Go's `g`: measured
  at 0.9%, not worth its churn.
- **Per-block liveness-only scratch selection** without Phase B: a hot loop
  whose body is one block still pays the spill every iteration, because the
  block boundary is the loop boundary.
