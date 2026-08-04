# Task 7 report: revert and stopped-hypothesis closeout

## Verdict

The losing optimistic decode-outside-writer implementation has been reverted
exactly as authorized, and the restored diagnostics-only tree passed every
focused, repository, signed-build, and shipped-default smoke gate. The durable
evidence record and handoff now describe the candidate as stopped, keep the
official 10.1776x scoreboard unchanged, and leave eager whole-image translation
deferred.

No source fix, ABBA rerun, push, local-main movement, worktree deletion, or new
performance hypothesis was performed.

## Revert boundary

Starting state was exact clean HEAD
`9a2788d6eb8f4c29f4ea5df23b2fc38866d2d39d`; the Task 6 artifact SHA-256 was
reconfirmed as
`5e88d50dc10308b56d76984146391fe77e1e8dda790303cd6ae37330ea2c1f05`.
Both losing commits were inspected before the clean dependency-reverse reverts:

- `99ce4d0c` — reverts `9e0b0817`
- `89e82b84` — reverts `3733eeef`

The three implementation files at `89e82b84` compare byte-for-byte equal to
diagnostics-only `d4c84088`. Typed optimistic-discard fields remain structurally
present, initialize to zero, and have no production increment on the restored
serialized path. Parser/test commit `9a2788d6`, diagnostics commit `d4c84088`,
the design/plan, detached control, and all target-only receipts were preserved.

## Fresh verification

Focused gates at restored HEAD `89e82b84`:

| Gate | Result |
|---|---|
| `carrick-dsr` profile tests | 16 passed, 0 failed |
| AArch64 translator tests | 38 passed, 0 failed |
| serialized runtime native-DSR filter | 153 passed, 5 intentional opt-in ignores |
| Python mechanism suites | 165 passed, 0 failed |
| focused Clippy `-D warnings` | pass |
| format check | pass |

Repository and runtime gates:

- `RUST_TEST_THREADS=1 just ci`: exit 0. The observed major totals included
  runtime 1,164 passed/5 intentional ignores, runtime integration 296/296, and
  process-syscall integration 17/17.
- `just build`: exit 0. Restored release binary SHA-256
  `82572dd3f7da5f2a4252782038f2c52bec8b30f6cdd7f1fc3a121f13ccceae51`;
  strict codesign verification passed, the hypervisor entitlement was present,
  and `__TEXT,__dof_carrick` was loadable/present.
- `just conformance-native smoke`: exit 0, 23/23 MATCH, 23 cached oracle
  results, zero live Docker oracle runs, no regressions.

## Documentation

`docs/perf-results/2026-08-04-native-optimistic-decode.md` binds the candidate,
control, signed binaries, NATIVEPERF captures, typed DTrace captures, paired
attribution, ABBA artifact, statistical decision, exact reverts, and restored-
tree gates. `handoff.md` now records 99% confidence in the regression/no-retain
decision, high confidence in the preserved diagnostics, the unchanged official
10.1776x result, the sequential at-least-10% policy, and the requirement to
attribute a new current-retained-tree bucket before proposing another patch.

## Remaining concern and next attribution question

The exact source of the candidate's extra CPU remains unproven: duplicate
decode, increased runnable concurrency, and induced kernel work are plausible,
but no one is promoted to fact. This does not weaken the no-retain decision.

The next evidence-backed question is: on the fully restored serialized tree,
which source-distinct user or Darwin-kernel mechanism accounts for at least 10%
of end-to-end cold-build CPU or wall after excluding the already-stopped
memory, exec/exit, context-traffic, allocation, route-copy, warm-reader-lock,
and optimistic-writer lines? Attribution must precede implementation.
