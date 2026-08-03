# Getting carrick correct and fast: the plan

**Status:** roadmap. Supersedes ad-hoc ranking with a phased plan whose every
number is measured, not estimated — except where explicitly marked.

## 0. Where we actually are

Measured 2026-08-02, all in-guest wall with container lifecycle excluded,
carrick and Docker phases run serially:

| workload shape | carrick | docker | ratio |
|---|---|---|---|
| 20 execs of `compile -V` (no real work) | 2570 ms | 21 ms | **123x** |
| cold `go build` (~61 execs + work) | 19.4 s | 1.46 s | 13.3x |
| warm `go build` (~1-2 execs) | 785 ms | 39 ms | 19.4x |
| one exec + ~1 s real compute | 1163 ms | 163 ms | 7.3x |
| one exec + ~4x that work | 3669 ms | 735 ms | **5.0x** |

The spread is the whole story: **overhead is a function of workload SHAPE.**
Long-running processes are ~5x and falling as startup amortizes; process-churn
workloads are 13-123x. Quoting one number for "carrick's overhead" is
misleading, and the 2x bar has to be read per shape.

Two independent cost centres, each with its own fix:

**Per-exec cost** — 76% of a cold build, decomposed into three separable terms:
fork 4.25 ms, a fixed ~18 ms that exec adds regardless of guest size (carrick
self-re-execing its own ~30 MB signed binary and rebuilding dispatcher state),
and ~2.6 ms/MB of image materialization (52 ms of `compile`'s 125 ms).

**Steady-state execution** — emitted code is ~45% of build CPU, and 52.4% of
executed emitted instructions are the translator's own glue.

And one important negative result: **translation is not the bottleneck.**
Turning on shared translation removes 87% of translations (170,727 -> 22,895)
and buys 3.3% of wall, because its own load costs 14.8 ms per process. The
codegen campaign was ranking against the wrong term.

## 1. The two tracks, and why both are needed

**Track D — direct execution (tier D).** Same-ISA guests do not need
translating: only `svc`, x18 and `tpidr_el0` cannot execute on Darwin, and they
are 0.048% of a real binary's instructions. Tier D patches those and runs
everything else unmodified. Its measured cost model:

| | cost |
|---|---|
| unpatched guest instruction | native, by construction |
| `tpidr_el0` veneer | +0.28 ns per use |
| x18 veneer | +1.25 ns per use |
| syscall island | 7 ns |

This attacks the steady-state term, i.e. long-running workloads.

**Track E — exec cost.** Zygote, file-backed image mapping, cheap shared-unit
loading. This attacks the per-exec term, i.e. build and CI workloads.

They are not alternatives. A server execs once and runs for hours; a build
execs 61 times and computes little. Neither track helps the other's shape.

## 2. Phases

### Phase 1 — tier D generalization (correctness; unlocks everything)

Nothing real runs on tier D yet. In order:

1. **Exit path.** `GuestContext::pc` is informational because the island's
   return leg is a CONSTANT branch — which is exactly what makes it
   register-free. Signal delivery and `execve` need a real exit: a gateway like
   the DSR one, or islands that branch indirectly through a scratch slot.
   Until this exists a guest can only leave by calling `exit`.
2. **Guest-leave contract.** The fixture bug that blocked the bridge for a full
   session (a guest returning to Rust with SP unbalanced) was a symptom of
   there being no stated contract. Write it down: a tier-D guest leaves through
   the handler, never by returning.
3. **Dynamic linking.** `ld.so` is more PIE mappings through the same loader,
   plus TLS initialisation now that `tpidr_el0` is veneered.
4. **Threads.** `guest_tls`/`guest_x18` are per-image today; they must be
   per-thread.
5. **fork/exec, signals, guest-created executable pages** (scan+patch at the
   intercepted `mmap`/`mprotect` PROT_EXEC boundary; RWX-without-flip falls
   back to tier T).

**Gate:** `/bin/dash -c 'echo hi'` end to end, then `python3 -c`, then the full
native conformance smoke green with tier D forced on for eligible images.
**Worth:** zero directly. Everything in Phase 2 depends on it.

### Phase 2 — tier D default-on (the compute win)

Flip eligible images to tier D with an exact `=0` hatch, per the
opt-out-not-opt-in rule.

**Gate:** conformance smoke, plus the outlier ratios the smoke already prints —
node 22-23x and cpython 14-17x today, both PIE and both dominated by emitted
code.
**Worth, ESTIMATED not measured:** the ~45% emitted-code CPU share collapses
toward guest-native. On the long-running shape that should move 5.0x to roughly
**3.3x**. This is the number to verify first, because the whole architecture
argument rests on it.

### Phase 3 — exec cost (the build win)

Three sized items, largest first:

| item | worth |
|---|---|
| file-backed image mapping (kill ~2.6 ms/MB materialization) | ~1.5-2 s |
| zygote / no self-re-exec (kill the fixed ~18 ms) | ~1.1 s |
| cheap shared-unit load (MAP_JIT copy instead of signed dylib + `dlopen`; publishing currently shells out to `codesign` twice) | ~0.8 s |

**Gate:** paired A/B on the cold `go build` with arms alternating, plus the
20-exec microbenchmark. Both, because they have disagreed before.
**Worth:** ~3.5 s of a 10.4 s build, i.e. build ~6.9 s ≈ **3.4x** Docker.

### Phase 4 — the kernel and memory residual

After Phases 2-3 the remaining excess is kernel time (32.4% of build CPU) and
carrick's host userspace. Known levers, already scoped elsewhere:

- fs endgame Lever B (serve reads from the shared cache tree, copy up on write):
  fs-walk total wall 3.8x -> ~1.8x;
- per-guest-page cost on Darwin — translate the guest's INTENT, using Go's
  dual-port allocator as the oracle (`MADV_FREE_REUSABLE`/`REUSE` rather than
  re-issuing Linux's `mprotect` idiom);
- the syscall floor (0.29 µs measured) against Docker's.

**Gate:** re-measure the workload-shape table in section 0. That table is the
scoreboard.

## 3. What would invalidate this plan

- **Phase 2 comes in well under its estimate.** If removing the emitted-code
  penalty does not move the long-running shape close to 3.3x, then steady-state
  cost is dominated by something else (most likely kernel/memory), and Phase 4
  should be promoted ahead of Phase 3.
- **Tier D cannot hold a real workload.** RWX self-modifying guests and
  thread-heavy TLS are the two shapes most likely to force tier T; if cpython
  or node ends up on tier T, Phase 2's value evaporates and Track E becomes the
  whole plan.
- **The undecodable tail bites.** 81 words in 5.2M are undecodable today, but a
  different binary corpus (musl, Rust static binaries, JITs) may have more, and
  the scan fails closed.

## 4. The honest ceiling

Even with every phase landed, the 2x bar is per-shape, not global. Long-running
PIE workloads are the ones that can plausibly reach it: compute goes to roughly
native and the residual is syscalls plus memory management. Build- and
CI-shaped workloads carry an irreducible per-process cost that Docker pays once
at container start and carrick pays per exec — Phase 3 shrinks it, and a zygote
shrinks it further, but 61 process creations will not be free.

State the shape with the number, always.
