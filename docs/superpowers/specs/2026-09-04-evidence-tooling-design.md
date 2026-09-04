# Evidence Tooling Design

## Goal

Make short ABBA investigations honest and usable, and make Carrick's scoped
HVF cleanup reliable from any Git worktree without weakening run isolation.

## ABBA evidence classes

The implicit-embed ABBA harness has two evidence classes:

- `official`: 8 through 127 quads, with the existing fail-closed
  pass/fail/unresolved decision and acceptance rules.
- `directional-pilot`: 1 through 7 quads, selected explicitly with `--pilot`.
  A completed pilot exits successfully as a measurement, but its artifact is
  never eligible or accepted and its decision status is `directional`.

Pilot and official runs use the same artifact authentication, preflight,
serialization, sample schedule, and scoped cleanup. The evidence class is a
top-level artifact field and an eligibility input, so a pilot cannot be
reinterpreted as an official campaign by looking only at its ratios.

## Worktree-safe scoped cleanup

The conformance runner resolves the HVF cleanup helper from the absolute
`CARRICK_SCOPED_CLEANUP_HELPER` path when set, otherwise from the compile-time
repository root rather than the process current directory. An override must be
an absolute, executable regular file and must not be a symlink.

Cleanup tries the helper directly first, which is sufficient for ordinary
same-user Carrick processes and public runners. If that does not establish an
exact `remaining carrick procs (...) = 0` receipt, it retries through
`sudo -n` for hosts with a path-specific non-interactive sudo rule. The final
cleanup attempt is authoritative: malformed output, a nonzero count, or an
unusable helper fails the suite run instead of merely warning and leaking
processes. The direct child process group is still killed before helper-based
cleanup, and all matching remains scoped to the exact run id.

## Non-goals

- Lowering the official eight-quad evidence floor.
- Treating pilot statistics as release or regression-gate authority.
- Adding global process cleanup or broad `pkill` behavior.
- Redesigning non-HVF remote/local backend cleanup in this change.
