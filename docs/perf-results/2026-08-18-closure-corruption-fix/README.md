# Closure checkpoint — post corruption fix

**Date:** 2026-08-18
**Artifact:** HEAD `108c3516d`, binary sha256 `46acf418d9bdec478cba63bb0f3d651ce40b84b3cc1085088b2078e9245fb987`, entitlement + `__dof_carrick` present.

Closure on the exclusive-claim corruption fix (`1e970696e`), BEFORE the two
follow-up regressions fixes it triggered (`b73672357`, `41e49f7ed`) — read the
caveats below before quoting anything.

## Result (identical tally rules; post-libuv baseline)

| metric | post-libuv | truncation-fix run | this run |
|---|---:|---:|---:|
| suites MATCH | 1,201 | 1,204 | 1,202 |
| rows agreeing | 101,533 | 103,163 | 103,154 |
| semantic gaps | 146 | 151 | 162 |
| unexercised | 5,598 | 2,572 | **2,419** |

## The important reading: budgets now bind where crashes used to

The corruption fix converts the multiprocessing family from CRASHES into
slow-but-correct. Standalone on this artifact the suites fully pass
(forkserver 4/4, spawn 4/4, concurrent_futures 8/8); under the closure's
8-worker load they blow their 300 s budgets, so the ledger shows partial
truncation instead of full conversion (forkserver 366 -> 199 unexercised —
the truncation fix keeping the rows it reached; fork unchanged at 227).
`multiprocessing_spawn` is at sem=0/unex=0 yet still INCOMPLETE — a totals
mismatch (skip-count asymmetry) to chase separately. `go-go_types` re-truncated
at its documented ~10% budget margin (+352 back).

So the next levers are BUDGETS (fork/forkserver/concurrent_futures need
~600 s under load; go_types/gcimporter margins) — with each raw ratio then
falling under the goal's >=10x-completing-row rule for the perf phase — and
the spawn totals mismatch.

## Verdict flips, all attributed before filing

- `ltp-setpriority01` newly MATCH (the 121-row fix, confirmed in-closure).
- `ltp-brk02`, `ltp-tgkill01`, `node-app-smoke` flipped match->incomplete:
  - brk02: REAL regression from `1e970696e` (two stacked causes: the
    exclusive-claim rule firing for boot/identity regions, and live VAs with
    stale retained outputs routed into the retired-reuse materializer).
    Fixed in `b73672357` + `41e49f7ed`, re-verified 2 TPASS x3.
  - tgkill01: pre-existing checkpoint-futex flakiness — 0/6 on the
    PRE-corruption-fix binary too; its earlier MATCH was the lucky sample.
  - node-app-smoke: 1 semantic row; not yet attributed.

`per-suite-ledger.jsonl` beside this file, same schema as prior checkpoints.
