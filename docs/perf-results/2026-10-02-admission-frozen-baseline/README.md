# Frozen admission baseline (2026-10-02)

Evidence for the N1/N2 red witnesses. The EL1 anonymous-memory admission
branch `work/s3-t3b` was frozen unlanded at `1cf7568e1` and became N1's base
(see [the native-ownership plan](../../superpowers/plans/2026-10-02-el1-native-ownership.md)).

- [narrow-report.md](narrow-report.md): the final signed generic/case probe
  batch on `1cf7568e1` (13 musl DIFFs plus the `epollstopcont` deadline vs
  main), grouped by suspected shared cause. These rows are the frozen
  denominator N1 and N2 must clear.
- [sol3-handoff.md](sol3-handoff.md), [sol2-handoff.md](sol2-handoff.md):
  the admission workers' handoff notes, with receipt paths that were local to
  that machine's `/tmp` (kept for provenance; not reproducible artifacts).

Copied from the director's scratchpad so the evidence survives `/tmp`
cleanup. Causes in the grouped table are hypotheses until each probe is
re-run signed on the branch that claims to fix it.
