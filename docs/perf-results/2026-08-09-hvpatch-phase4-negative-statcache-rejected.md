# HvPatch Phase 4 contained-parent stat-cache experiment

Date: 2026-08-09

Status: **REJECTED; resolver operations fell 39.7%, but the untraced cold-build
gain was only 3.74% CPU and 2.47% wall. Phase 4 remains RED.** The candidate
cached positive and authoritative-negative leaves under already-contained
parent fds, revalidating every hit with one `fstatat`. It also reused that
answer for the overlay `lookup_kind` preflight. The implementation was removed
because neither ABBA block approached this campaign's at-least-10% retention
threshold.

## Hypothesis and semantic boundary

The typed resolver-path capture in
`2026-08-09-hvpatch-phase4-resolver-paths.md` found at least 4,183 repeated
Darwin `openat` ENOENT results and 5,882 repeated `fstatat64` ENOENT results
after the first occurrence of the same key. The candidate asked whether one
contained parent-fd cache could collapse the shared resolution chain used by
Linux `openat`, `newfstatat`, `statx`, and root-credential `F_OK` checks.

The fail-closed boundary was:

- cache only a single leaf below a parent fd already proven beneath the guest
  root;
- cache a negative only when `fstatat(parent_fd, leaf,
  AT_SYMLINK_NOFOLLOW)` returned exactly `ENOENT`;
- re-run that one `fstatat` on every positive or negative hit, so an external
  host-side creator is visible immediately without a Carrick generation bump;
- retain the complete resolver for symlinks, devices, escapes, Unicode aliases,
  cross-mount cases, and all uncertain/error results;
- clear on existing fork/rename invalidation paths and retain the 4,096-entry
  bound;
- gate the whole experiment with host environment hatch
  `CARRICK_FS_NEGATIVE_STATCACHE=0` for same-binary ABBA.

This changed no guest process topology, ASID, or VM lifecycle behavior.

## Provenance

- Host: macOS 27.0 build `26A5388g`, arm64.
- Branch: `codex/hvpatch`; committed parent `0c324210`.
- Candidate: uncommitted source diff, absent after this evidence checkpoint.
- Candidate signed binary SHA-256:
  `8f245926a0dc97446798d39a8fd021e06136dcef4103158500581859d56db51e`.
- Backend: `--exec-backend hvpatch`; filesystem: `--fs host`.
- Workload: `scripts/perf/fixtures/hvpatch-cold-go-build.sh` in
  `localhost:5005/carrick-go-conformance:1.24`, `--pull never`.
- Each arm used a unique scoped `CARRICK_RUN_ID`; Carrick and Docker were not
  run concurrently.
- Every arm printed exact `ok` and `BUILD_OK` and exited zero.

Retained raw evidence:

- typed mechanism baseline with hatch off:
  `target/perf/hvpatch-phase4/negative-statcache-lookup-off-1.raw`, SHA-256
  `e051964384d91ee8df8771f9358b81159f3927d68f88c5d6916abd45392dfb83`;
- typed mechanism candidate with hatch on:
  `target/perf/hvpatch-phase4/negative-statcache-lookup-on-1.raw`, SHA-256
  `82fa3607efa37122861b8ac6438ce7098c259fbaaa3ef8d3e8ae64f6a46c8422`;
- untraced ABBA:
  `target/perf/hvpatch-phase4/negative-statcache-lookup-abba-1.raw`, SHA-256
  `37928f1d225fafe5f585c7175a2fbde819018612e3261b1b8e563b24c2bc5187`.

## Correctness and red-first proof

The new negative-cache test first failed to compile because the tri-state
`StatCacheLookup` contract did not exist. The completed candidate then proved
that a missing leaf returned `Missing`, a second lookup revalidated the miss,
and an external host-side creation with no generation bump was observed as a
positive hit. A separate test proved the `=0` hatch retained the historical
positive-only fallback.

Verification on the candidate:

- four focused stat-cache tests passed;
- `cargo test -p carrick-runtime --test integration`: 296 passed;
- `cargo check -p carrick-runtime`: passed;
- `cargo fmt` and `git diff --check`: passed;
- signed `just build`: passed and the binary retained the Hypervisor.framework
  entitlement.

These prove the scoped behavior exercised, not full conformance. Because the
performance authority rejected the candidate, full conformance and `just ci`
on the candidate were not run.

## Typed mechanism result

Both same-instrument captures had balanced 3,266 Linux `openat` and 3,962 Linux
`newfstatat` service windows, exact workload output, and no DTrace/join errors.

| Linux window | Darwin operation | Hatch off | Candidate on | Change |
|---|---|---:|---:|---:|
| `openat` | `openat` | 34,466 | 22,628 | -34.3% |
| | `fcntl` | 20,970 | 16,171 | -22.9% |
| | `fstatat64` | 3,256 | 8,978 | +175.7% |
| `newfstatat` | `openat` | 18,150 | 1,848 | -89.8% |
| | `fcntl` | 4,092 | 163 | -96.0% |
| | `fstatat64` | 9,046 | 4,500 | -50.3% |

Across these selected three-operation populations, the total fell from 89,980
to 54,288 (-39.7%). The increased `fstatat64` population inside Linux `openat`
is expected: the cache substitutes one dirfd-anchored stat for a longer
open/F_GETPATH resolver chain. This is mechanism evidence only because DTrace
perturbs the workload.

## Untraced ABBA authority

Pattern: `off on on off / off on on off`, using the same signed binary. CPU is
`/usr/bin/time -lp` user plus system.

| Block | Arm | Wall-s | User-s | System-s | CPU-s |
|---|---|---:|---:|---:|---:|
| b1 | hatch off | 2.44 | 2.18 | 1.65 | 3.83 |
| b1 | candidate on | 2.65 | 2.28 | 1.76 | 4.04 |
| b1 | candidate on | 2.64 | 2.24 | 1.80 | 4.04 |
| b1 | hatch off | 2.86 | 2.27 | 2.07 | 4.34 |
| b2 | hatch off | 2.77 | 2.27 | 2.09 | 4.36 |
| b2 | candidate on | 2.69 | 2.29 | 1.81 | 4.10 |
| b2 | candidate on | 2.67 | 2.27 | 1.77 | 4.04 |
| b2 | hatch off | 2.85 | 2.27 | 2.05 | 4.32 |

| Arm | n | Mean wall-s | Mean CPU-s |
|---|---:|---:|---:|
| hatch off | 4 | 2.7300 | 4.2125 |
| candidate on | 4 | 2.6625 | 4.0550 |

Candidate/off is 0.962611 CPU (-3.74%) and 0.975275 wall (-2.47%). Block 1
measured -1.10% CPU / -0.19% wall; block 2 measured -6.22% CPU / -4.63% wall.
The direction is consistent, but the entire observed opportunity is below 10%
and the candidate remains above Phase 4's `<3.5` CPU-second gate.

## Decision and next interface lever

Remove the behavior diff and retain the typed CTF boundary, durable resolver
D script, raw captures, and this rejection. The result also sharpens the next
question: scalar cache surgery cannot supply the missing Phase 4 opportunity.
The next candidate should test Darwin's bulk metadata interfaces at the
lowering boundary—`getattrlistbulk` for directory enumeration plus child
metadata, and a fail-closed `getattrlistat` scout for scalar metadata—while
retaining Carrick's private xattr semantics and exact containment rules.

That work requires typed guest PID/TID/ASID attribution and field-for-field
parity tests before any performance claim. It also belongs in the durable
`carrick trace`/DTrace tool surface so zero events, ABI drift, and identity
mismatches fail closed.
