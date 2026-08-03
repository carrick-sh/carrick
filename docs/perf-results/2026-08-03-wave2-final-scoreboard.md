# Wave-2 final scoreboard: store works, templates don't, tier D gate met

**Date:** 2026-08-03. **Tree:** `707fd9c5`. **Box:** quiet, serial phases,
signed rebuilt binary (see the trap below). Raw logs:
`target/perf-final2-20260803.log`, `target/perf-compute-abba-20260803.log`;
a superseded stale-binary round survives as `target/perf-final-20260803.log`.

## The stale-binary trap fired

The first "final" round measured a binary built BEFORE wave 2 merged: ABBA
arms were identical (the knobs didn't exist in the binary), and only the
contradiction with Lane E's mechanism-level counters exposed it. The
AGENTS.md rule is literal: after runtime changes, `just build` again and
prove the marker (`strings -a target/release/carrick | grep <knob>` went
0 → 1). Every number below is from the rebuilt binary.

## Scoreboard (`workload-spread.sh 3`, store at its shipped default)

| workload | carrick | docker | ratio | 2026-08-02 morning |
|---|---|---|---|---|
| startup (2 execs) | 34 ms | ~0 | — | 42 ms |
| compute | 358 ms* | 111 ms | **3.2x** | 3.8x band |
| fs-walk | 290 ms | 12 ms | 24x | 18-20x band |
| build-cold | ~9.9 s* | 783 ms | **~12.6x** | 13.3x |

\* quoted at the shipped default (store OFF — the spread ran during the
default-ON window and its compute/build rows mix template arms; the ABBA
arms below are the controlled numbers).

## Store ABBAs (counterbalanced, n=8 each, rebuilt binary)

| shape | store+cells ON | OFF | verdict |
|---|---|---|---|
| cold build | ~9716 ms | ~10041 ms | ON wins ~3%, all pairs |
| 20-exec micro | ~1837 ms | ~2061 ms | ON wins ~11%, all pairs |
| compute (awk 8M) | ~594 ms | ~358 ms | **ON LOSES 65%, all pairs** |

The compute regression is attached RECORDED-TEMPLATE units running
busybox awk's hot loop materially slower than natively-emitted code
(superblock-fusion loss suspected — Lane E's own `translated_run +2.7 s`
build residual was the same signal). Consequence, committed as
`707fd9c5`: **the store is opt-in (`CARRICK_DSR_PERSISTENT_STORE=1`)
until template quality reaches hot-loop parity.** The election and
persistence mechanics are sound and stay; the old concurrent-publisher
regression stays fixed.

## What wave 2 proved

- The build's 12x is CPU amplification at Docker-equal core width, and its
  decomposition is committed (translate 14.6 s, gateway 7.1 s,
  emitted-run 7.9 s vs 2.1 s useful) — the store attacks the first two
  terms and measurably wins on build/micro shapes already.
- Tier D's Phase 1 gate is MET: real `/bin/dash -c 'echo hi'` and real
  CPython `print(1)` run end to end (single-threaded), with guest-created
  executable pages scanned+patched and everything unproven failing closed.
- The remaining path to 2-3x on the build runs through (a) template
  quality (re-flips the store, task #12), (b) tier D default-on for the
  emitted-code term (Phase 2), and (c) the smaller sized levers
  (PROT_NONE reserve lowering ~0.7 s, CPU exposure 0.3-0.4 s, driver
  setup ~0.6 s).

State the shape with the number, always.
