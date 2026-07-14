# Native Exclusive-Region Fusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop routing every guest AArch64 exclusive access through a gateway
round-trip: fuse `LDXR..STXR` regions into a single translated block that
executes the exclusive instructions natively, removing ~33 percent of all
gateway exits and improving AArch64 atomic fidelity at the same time.

**Architecture:** The DSR currently converts every `MemoryClass::Exclusive`
into `SensitiveKind::Exclusive` at decode time, which terminates the block plan
and forces a trap on every execution — the block covering an exclusive site
carries zero guest instructions. This plan teaches the block planner to
recognise an exclusive region, keep its instructions inside one block, emit
them verbatim in the unbiased (`native16k` Direct) path, and exit the region
through a `CLREX` stub. The existing trap path stays as the fallback for every
case fusion cannot prove safe.

**Tech Stack:** Rust (carrick-runtime `native_darwin/dsr`: decode, block, emit,
cache), AArch64, the NATIVEPERF profiler, the frozen W1/W2 measurement harness.

## Global Constraints

- Never weaken AArch64 exclusive or signal semantics. Replacing Linux atomics
  with a coarse lock is explicitly forbidden by the performance design.
- Never raise `max_traps`, timeouts, or weaken the 2 percent additive gate or
  the 10 percent ABBA tax gate.
- Fusion applies only where it can be proven safe; every unproven case keeps
  the existing trap-and-emulate path. Correctness beats coverage.
- Profile-off builds keep the specialized no-timer path; no new work on the
  untraced hot path beyond the translation itself.
- Untraced signed runs are the only absolute wall/CPU authority. Rebuild and
  sign with `just build` before every guest run; measured runs need a clean
  tree; stamp `CARRICK_RUN_ID` and reap with `sudo -n scripts/sudo/kill.sh`.
- Never overlap Carrick and Docker phases.

## Measured basis (diagnosis, `.superpowers/sdd/exclusive-diagnosis.md`)

- Exclusive traps are 134,610 of 403,888 gateway exits per W2 run (33.3 percent
  run-wide; 43 percent in the hot `go build` process).
- The block covering an exclusive site contains ZERO guest instructions: pure
  prologue, generation guard, exit stub. Every execution traps, forever.
- Each round-trip serializes on the process-wide memory mutex three times
  (`native_darwin.rs:1588`, `:1750`, `:1787`) plus an exclusive `pages.write()`
  RwLock per prepare (`cache.rs:127-144`).
- No correctness blocker: `emit.rs:1442` is a defensive tripwire in the
  BIASED-only path. The current emulation (`native_darwin.rs:7919-8048`) is a
  value-compare CAS plus a software sequence counter, which is **ABA-unsound**
  relative to real LDXR/STXR — native exclusives are strictly MORE faithful.
- Upside (lower bound): 502 ms of 2.343 s guest CPU run-wide (21.4 percent),
  615 ms of 1,361 ms (45 percent) in the hot process. W2 3.89 s → 3.39-3.64 s,
  i.e. **14.28x → ~12.4-13.4x** Docker.
- **10x is NOT reachable by this fix alone.** The translation term (34.1
  percent) is genuine cold translation of 134,436 DISTINCT blocks, with 22 of
  23 processes translating from scratch. That is a separate, later slice (a
  shared/AOT translation cache), and this plan does not attempt it.

## Hazards the design must respect

1. **The pair must be fused into ONE block.** If the block prologue's context
   stores land between `LDXR` and `STXR`, they can clear the exclusive monitor
   and livelock the guest's retry loop.
2. **`CLREX` on every region exit edge.** Any path that leaves a fused region
   without completing the `STXR` must clear the monitor, or a stale reservation
   can make a later unrelated `STXR` succeed.
3. **Bias mode.** The fused instructions must be emitted verbatim, which is
   only sound where memory ops are already emitted verbatim (`native16k` Direct
   path). Biased mode, `x18`/`x28`-based addressing, and any rewrite that would
   insert instructions inside the region keep the trap path.
4. **Unmatched or exotic regions** (no `STXR` within the scan window, a syscall
   or another sensitive op inside the region, a branch out of the region that
   is not the retry edge) keep the trap path.

---

### Task 1: Recognise the exclusive region in the block planner

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/decode.rs` (~:780-790,
  where `MemoryClass::Exclusive` becomes `SensitiveKind::Exclusive`)
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/block.rs` (~:157, where
  `InstAction::Sensitive` terminates the plan)
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/types.rs` (new typed
  action/plan variants)
- Test: unit tests alongside `block.rs`/`decode.rs`

**Interfaces:**
- Produces, for Task 2: a typed `InstAction::ExclusiveRegion { start, end,
  instructions, retry_edge, load_word, store_word }` (exact field names) that
  the planner emits INSTEAD of `InstAction::Sensitive(SensitiveKind::Exclusive)`
  when, and only when, fusion is provably safe; every other exclusive keeps
  emitting `InstAction::Sensitive` exactly as today.
- Consumes: the existing `classify_memory` / `MemoryClass::Exclusive`
  classification.

- [ ] **Step 1: Red-first planner tests.** A `ldaxr/cmp/b.ne/stlxr/cbnz` CAS
  loop plans as ONE block whose instruction list contains the load, the compare,
  the branch, and the store (not a zero-instruction sensitive exit). Negative
  cases each still plan as a `Sensitive` exit: no `STXR` within the scan window;
  a syscall inside the region; another sensitive op inside the region; a branch
  out of the region that is not the retry edge; an `x18`/`x28`-based address.
  Watch each fail.
- [ ] **Step 2: Implement the recogniser** with a bounded forward scan from the
  `LDXR` (cap the window — an unbounded scan is a decode-time DoS surface; pick
  a small constant and state it in the code with a comment). Reject and fall
  back to `Sensitive` on anything the tests above pin.
- [ ] **Step 3: Green + `just fmt-check` + commit** (`feat(native): plan fused
  exclusive regions`).

### Task 2: Emit the fused region verbatim with CLREX exit edges

**Files:**
- Modify: `crates/carrick-runtime/src/native_darwin/dsr/emit.rs` (the memory
  emission path; note the `:1442` tripwire — it must stay for the biased path)
- Test: emitted-code unit tests alongside `emit.rs`

**Interfaces:**
- Consumes: Task 1's `InstAction::ExclusiveRegion`.
- Produces: a translated block that executes the region's instructions
  verbatim, with a `CLREX` emitted on every edge that leaves the region without
  completing the `STXR`.

- [ ] **Step 1: Red-first emit tests.** The fused block's emitted code contains
  the original `LDXR`/`STXR` encodings verbatim and NO instructions between them
  (assert on the emitted word sequence). Every non-completing exit edge emits
  `CLREX`. The biased path still refuses (the `:1442` tripwire fires) — pin that
  it is unreachable from the fused path but intact for its own.
- [ ] **Step 2: Implement.** Emit verbatim in the unbiased Direct path only.
- [ ] **Step 3: DSR oracle/emitted-code tests for the exclusive class** (the
  repo already has DSR emission tests — extend them for this class) + commit
  (`feat(native): emit fused exclusive regions natively`).

### Task 3: Prove correctness on real guests, then measure

**Files:**
- Verify: the native probe gate; the exact reducers; `just ci`
- Create: `docs/perf-results/native-compiler-budget-v4.jsonl`
- Modify: `docs/native-default-conformance-campaign.md`

- [ ] **Step 1: Correctness before speed.** Run the complete native probe gate
  and the exact prepared-image reducers. Any regression stops the plan. Pay
  particular attention to multithreaded futex/atomic probes — a livelock or a
  lost wakeup here is exactly the hazard the fusion rules exist to prevent. Run
  the multithreaded probes repeatedly (at least 10x) to shake out livelock.
- [ ] **Step 2: Guest atomic stress.** Run a real multithreaded atomic workload
  (the Go or CPython threading reducers already in the ecosystem lanes) and
  require identical output/status to Docker.
- [ ] **Step 3: Measure.** `just build`, then the frozen campaign procedure
  exactly as recorded for v3 (Plane A baseline, ABBA Plane B, one-thread
  control, Plane C), writing `native-compiler-budget-v4.jsonl`. REQUIRE: the
  exclusive share of gateway exits collapses; the untraced W2 ratio improves
  measurably from 14.28x; every gate (2 percent additive, 10 percent tax,
  plausibility guard) still passes; `analyze --check` green.
- [ ] **Step 4: Record honestly.** Append the measured before/after to the
  campaign ledger. If the ratio does NOT improve, say so and keep the code only
  if the atomic-fidelity improvement justifies it on its own; do not claim a win
  the untraced numbers do not show.
- [ ] **Step 5: Commit** (`perf(native): execute guest exclusives natively`).

## Self-Review Results

- Spec coverage: the design's rung-1 prescription ("faithful translated
  exclusive regions or typed atomic lowering; do not replace Linux atomics with
  a coarse lock") maps to Tasks 1-2; its promotion gates (probe gate, exact
  reducers, `just ci`, untraced authority) map to Task 3. The plan explicitly
  does NOT attempt the cold-translation/AOT slice, which the diagnosis shows is
  a separate 34 percent term.
- Placeholder scan: none. The scan-window constant is deliberately left to the
  implementer with a stated requirement to bound it and comment it.
- Type consistency: `InstAction::ExclusiveRegion` and its field names are used
  identically in Tasks 1 and 2.
- Honesty: the expected outcome (~12.4-13.4x, NOT 10x) is stated up front so
  Task 3 cannot be spun as a bigger win than the measurement supports.
