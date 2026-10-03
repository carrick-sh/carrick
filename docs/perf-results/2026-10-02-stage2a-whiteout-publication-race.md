# Stage 2a whiteout cache publication race correction

Contract: `kernel.vfs.host-namespace-mutation-work`. Rebased onto
`b0d8743ee`, which adds `just accept`. This is a host / VM-free correction;
existing signed census receipts still identify their original artifact.

The landing failure at `9398c9c40` was a real cache race. Each matrix actor
orders its rename/unlink before its ENOENT open and uses distinct leaf names.
Changing task scheduling therefore cannot legitimately change that answer.
The retained failing physical tree contained the completed whiteout with
its correct leaf contents, while the immutable lower file remained intact.
The failing open was specifically `openat-after-unlink-whiteout`.

The correction keeps namespace operations concurrent and changes cache
publication, not Linux expectations or physical namespace operations:

- Lower bindings carry the generation that proved upper absence. Both the
  component cache and full-path lookup cache reject an expired lower proof;
  the unchanged immutable lower inode cannot validate a later upper view.
- Refills sample the generation before host probes and check it under the
  entry publication lock. A refill that overlaps invalidation cannot install
  its earlier observation after that invalidation.
- Cache mutation publication commits after name/inode invalidation, through
  an owned scope guard. An overlapping reader's fast-path publication is
  invalidated before the mutation returns.
- A missing upper directory is stamped with its pre-probe generation, not
  the generation when a delayed directory refill publishes.
- Exchange takes directory objects before path bindings, matching reset.
  Three other path-index reads release their guard before taking directory
  locks. No lock ownership or cache ownership moves were introduced.

Red-first deterministic evidence:

| Forced case | Red | Green behavior |
| --- | --- | --- |
| Two live Linux tasks: reader pauses after lower leaf stat; writer copy-ups and renames/whiteouts; reader publishes late, then opens again | expected errno 2, returned fd 3 | the distinct non-overlapping open sees ENOENT |
| Reader overlaps a paused cache-removal hook after physical whiteout | completed whiteout left a lower fast-path result | hook-end publication clears overlapping cache results |
| Delayed lower-directory refill plus eviction of the leaf negative | cold leaf opened the hidden lower file | expired upper-absence proof causes fresh upper probing |

The test checkpoints use the existing five-second wait bound. The overlapping
open may retain its earlier file; the following open must see ENOENT. The
original matrix expectations and concurrency remain intact. Matrix labels
now distinguish rename and unlink whiteouts, and child expectations take
precedence over a consequent parent read/wait timeout in the example harness.

The loaded investigation also exposed an exchange/reset ABBA. The captured
host stack is `target/el1-host-namespace/race-correction/stage2a-refill-loaded-stall.sample`.
Failed intermediate loops remain failure evidence; none were retried into
acceptance or counted toward the final proof.

Final loaded proof: **50 consecutive complete iterations**, four parallel
owned `yes` CPU workers, all three namespace tests running with the harness's
normal test concurrency. Each iteration contains both full 16-cell matrices
(n 1/8/32/128, population 0/128, same/unrelated parents), plus the forced
refill case: **150 test passes, 1,600 matrix cells**. The loop stopped on any
failure and had no retry logic. Load PIDs 28159/28160/28161/28162 were killed,
waited, and confirmed absent. Log and invocation are retained as
`target/el1-host-namespace/race-correction/loaded-50.{log,sh}`.

The retained loaded executable is
`target/el1-host-namespace/race-correction/namespace-two-process-loaded`, SHA-256
`c35bb871f524fe3467f6f95c33d63f86b7459da277c8b506b095620fcd23f0a0`.
Deterministic red logs are retained alongside it. The original lower-layer
failure's physical evidence paths are in `stage2a-refill-physical-build.log`.

The authoritative clean-commit host acceptance receipt is written to
`target/el1-host-namespace/race-correction/host-receipt.json` by
`CARGO_BUILD_JOBS=3 RUSTC_WRAPPER= just accept --phase host --receipt
 target/el1-host-namespace/race-correction/host-receipt.json`.
Its recorded HEAD, per-step logs, exit codes and verdict govern host closure.
No earlier signed artifact is claimed to verify this new correction; signed
landing and Docker/ecosystem acceptance remain director-owned.
