# Wave-3 scoreboard: parity won, install cost now binds; build at 11.9x

**Date:** 2026-08-03. **Tree:** `8dbcc709`, full `just ci` green, signed
rebuilt binary with the v4 wire marker proven (`strings` 0→1). Quiet box,
serial phases, host-env knobs, counterbalanced ABBA n=8/shape. Raw:
`target/perf-wave3-20260803.log`.

## Scoreboard (defaults: persistent store opt-in/off)

| workload | carrick | docker | ratio | session start (08-02) |
|---|---|---|---|---|
| startup (2 execs) | 37 ms | ~0 | — | 42 ms |
| compute | 365 ms | 111 ms | **3.3x** | 3.8x band |
| fs-walk | 252 ms | 13 ms | 19.4x | 18-20x |
| build-cold | 9613 ms | 805 ms | **11.9x** | 13.3x |

The baseline improved ~5% this wave with the store OFF — Lane I's interval
protection bookkeeping and the wave-3 merges are in the default path. The
micro's store-off arm dropped from ~2060 ms (wave 2) to ~1798 ms.

## Store ABBAs (v4 native-tap format, warm store)

| shape | store=1 | unset | verdict |
|---|---|---|---|
| awk compute | ~373 ms | ~366 ms | **parity** (was +65-78%) |
| cold build | ~9647 ms | ~9375 ms | +2.9% — attach cost |
| 20-exec micro | ~2048 ms | ~1798 ms | **+14% — attach cost** |

Template parity is WON — Lane G2's disassembly shows attached blocks
word-shaped like native emission, and the compute shape proves it. What
binds now is exactly the risk G2 flagged: the v4 install path (serialized
manifest decode + EAGER per-block replay) costs more than the V3 mmap
install it replaced, and at 61 execs it cancels the retranslation savings.
The V3-era micro win (~11%) inverted to a 14% loss against the faster
baseline.

**Decision: the store stays opt-in.** The re-flip condition moves from
"template parity" (achieved) to "install cheaper than retranslation on the
serial micro AND non-regressing on the build" — the scoped follow-up is
lazy per-block install (replay a block on first lookup, not all blocks at
attach) and/or a zero-copy v4 record layout.

## Where the campaign stands against 2-3x

13.3x → 11.9x in one day, with the structure to go further now built and
proven correct: the exec pipeline is lean (~20 ms chain), tier D runs real
dash/CPython including threads, template emission is parity-quality, and
the build's remaining excess is measured: retranslation CPU (14.6 s, needs
the cheap-install store), gateway round-trips (7.1 s, mostly killed by a
warm cache), emitted-code overhead (tier D Phase 2: driver wiring +
fork/execve/signals), and the smaller sized levers. The 2-3x path is
unchanged; two of its three big rocks now have their correctness halves
done and only their cost halves open.

State the shape with the number, always.
