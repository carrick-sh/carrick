# Stolen-register traffic: the largest remaining term in emitted code

**Status:** design, evidence committed. **Lane:** native/DSR, macOS arm64 (the
shipped default). **Goal served:** close the steady-state emitted-code penalty.

## 1. What the measurement says

Sampling a `go build` with the tracer's own pid excluded
(`scripts/dtrace/native-cpu-attribution.d`, fixed in `94c260e8`):

| bucket | share of ALL build CPU |
|---|---|
| emitted code executing (JIT cache) | **~45%** |
| carrick's own Rust | 9.0% |
| memcpy/memset | 5.9% |
| malloc | 5.2% |
| kernel | 32.4% |

Within emitted code (`scripts/perf/shape_classify.py`, record appended to
`docs/perf-results/native-dsr-shape-census.jsonl`), the DSR overhead floor is
**52.4% of executed instructions**, down from the 81.3% AGENTS.md carried. The
residue is concentrated in context traffic — `ctx-load64` 25.0% plus
`ctx-store64` 8.7% = **33.7% of executed emitted instructions ≈ 15% of total
build CPU**.

Histogrammed by `(slot, transfer register)`, that traffic is **not** general
guest-register spilling. Carrick keeps guest registers in host registers. It is
the cost of the physical registers carrick *borrows*:

| slot | reg | share of emitted |
|---|---|---|
| 1128 | x17 | 15.11% |
| 1192 | x19 | 8.97% |
| 1120 | x17 | 3.68% |
| 1272 | x15 | 1.87% |
| 224 | x17 | 1.68% |
| 1160 | x15 | 1.41% |

By register: **x17 ~21%, x19 ~9%, x15 ~3.3%, x16 ~0.2%.**

## 2. Why it happens

`virtual_snapshot_offset` (`emit.rs:672`) virtualizes exactly three guest
registers — x18 → 144, x28 → 224, `RESERVED_SCRATCH` (x19) → 1192. Everything
else, **including x17, is resident in its physical register**. Two consequences:

- Guest reads of x18/x19/x28 are context loads by construction. Slot 1192 at
  8.97% is guest x19 traffic, and it is irreducible without un-reserving x19.
- Physical x17 holds a live guest value, so every time the emitter borrows x17
  it must save and restore it. That is the 21%.

The hottest borrow site is `emit_internal_fallthrough_edge` (`emit.rs:2193`).
For a conditional edge whose operand is a *virtualized* register it emits:

```
str x17, [x28, #1128]        ; save guest x17
ldr x17, [x28, #<operand>]   ; borrow x17 to hold the condition
<conditional branch on x17>
b fallthrough / b stub
ldr x17, [x28, #1128]        ; restore guest x17
```

The save/restore is gated on **the operand being virtual**, never on whether
guest x17 is live. The comment there rules out physical x18 for a real reason:
Darwin may clear the platform register between the load and the branch.

## 3. Two candidate fixes, cheapest first

**A. Borrow a register carrick already owns.** `RESERVED_SCRATCH` (x19) is
documented as host-owned for the whole of translated execution — the guest's x19
lives in slot 1192 and is never loaded into the physical register. If x19 is
genuinely free at this point, borrowing it instead of x17 removes both the save
and the restore outright, with no liveness analysis. **The open question that
must be answered first:** the reserved-resident work can make physical x19 hold
a guest address base, so x19 is only free when that plan is inactive. The edge
emitter must be able to ask. If it can, this is a small, local change worth most
of the 15.1% slot-1128 term.

**B. Gate the borrow on guest x17 liveness.** Go's register allocator never
allocates R17 — it is linker veneer scratch — so for Go guests the saved value
is usually dead. Skipping save/restore when the block provably neither reads nor
writes x17 targets the same term but needs a liveness pass and a careful story
about values live *across* block boundaries, since slot 1128 is the authority
and physical x17 is loaded on demand.

Prefer A. Fall back to B only if x19 turns out not to be free.

## 4. Correctness constraints that must not be traded

- **The recovery contract is per-word.** Each of these words carries a
  `RecoveryEntry` (`RestoreGuestX17` and friends). Removing or moving a word
  changes which action a fault at that offset resolves to; the entries must move
  with the words, and absence of an entry is only valid for idempotent words.
- **Direct links rewrite the slot at runtime.** Any sequence change must keep the
  slot at a stable offset relative to the stub branch.
- **Darwin may clear x18 between two instructions.** That hazard is why x18 is
  not the answer here; do not "simplify" by reusing it.

## 5. Gates

Red-first: a translation test asserting the emitted word sequence for a
conditional edge with a virtual operand, before and after. Then the shape census
re-run (`native-shape-census.d` + `shape_classify.py`) showing the slot-1128
share fall, a paired build wall A/B, `just ci`, and
`just conformance-native smoke` — the smoke is non-negotiable for emitter
changes, since fault recovery is exactly what unit tests do not cover.

## 6. The honest ceiling

Even if every emitted word were guest-shaped, emitted CPU falls from ~45% to
~21% and the build lands near **5x** Docker, not 2x. The kernel term (32.4%) and
carrick's own userspace have to come down as well. This work is the largest
single item, not a sufficient one.
