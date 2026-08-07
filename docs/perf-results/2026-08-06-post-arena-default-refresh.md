# Post-arena shipped-default cold-build wall refresh

**Date:** 2026-08-06 (run window 2026-08-07T00:52:52Z → 00:53:56Z)
**Scope:** Darwin/AArch64 shipped-default native cold `go build`
**Decision:** **accept as the current official scoreboard: 10.8586x
native-arm64 Docker** (workload wall medians 8,676 ms Carrick / 799 ms
Docker). Process elapsed medians are 9,448 ms / 964 ms = **9.8008x**.

This is the Task-10 failure-arm reprofile required by
`docs/superpowers/plans/2026-08-05-native-live-translation-arena.md`
("Reprofile the shipped-default lane before choosing another redesign"),
measured at the exact tip that deleted the live translation arena
(`1cb06de6` + the knob refusal `7318f583`). It supersedes the 2026-08-04
official 8,254 ms / 811 ms = 10.1776x result.

## Delta vs the prior official, stated honestly

Carrick workload wall is +422 ms (+5.11%), Docker −12 ms (−1.48%), so the
ratio moves +6.69% (10.1776x → 10.8586x). Median Carrick CPU is
21.391 s vs 20.168 s (+6.06%).

The delete itself is NOT the cause of the drift in any attributable sense:
the 3-arm smoke in the task-10 gate run proved the pre-delete signed tip
(`2828808d…`) and the post-delete binary produce **byte-identical guest
output on the default arm** (3 paired runs, single stdout md5), and the
arena was default-off in both. What differs from the 2026-08-04
measurement is (a) ~40 commits of tip drift — the campaign's keepers,
including the alias-install-under-guard deadlock fix (`8d5b3a19`) and the
6E catalog publication, are in this binary and were not in `64bebc26` —
and (b) host state (11-day uptime, ambient load ≈2.2 with a concurrent
text-only documentation agent). Per the single-variable rule this run
cannot decompose those terms; the serialized scoreboard is the timing
authority for the current ratio, not a causal estimate of any one change.
If the +5% Carrick wall persists on a quieter box it deserves its own
controlled attribution before any redesign is priced against it.

## Bars at the current Docker denominator (799 ms)

| bar | target wall | removal required from 8,676 ms |
|---|---:|---:|
| 8x | 6,392 ms | 26.33% |
| 5x | 3,995 ms | 53.95% |
| 3x | 2,397 ms | 72.37% (3.62x reduction) |
| 2x (product bar) | 1,598 ms | 81.58% (5.43x reduction) |

## Authority

Artifact: `target/perf/task10-delete/native-go-build-post-arena.json`,
SHA-256
`b2b77a161a42913354d471b4af5d426940148646a31c2bd6ed1107f736569eb1`.

- clean source: `7318f58325441430826e453f9cf3bc5a4a6d25c2` (`git_dirty:
  false`; docs edits in flight were stashed for the run so the measured
  tree is exactly the committed tip);
- signed binary SHA-256:
  `bbc63c51868e75740aacb79ab1c56e1ebcfcf4a03669eba13e32e3b41e5b3d9c`
  (`__dof_carrick` present, hypervisor entitlement present);
- image: `localhost:5005/carrick-go-conformance:1.24`, digest
  `sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
  (identical to the 2026-08-04 run);
- Docker platform: `linux/arm64` (native arm64, no Rosetta);
- performance overlay: shipped default, every control key unset
  (`CARRICK_DSR_LIVE_ARENA` no longer exists; setting it hard-errors);
- harness preflight: passed without `--allow-busy`;
- result: 5/5 `BUILD_OK` in each phase, zero nonzero exits, timeouts,
  capture errors, or cleanup failures; the two phases ran serialized,
  every Carrick sample before any Docker sample, never overlapping.

## Samples

| engine | workload wall, ms | process elapsed, ms | total CPU, s |
|---|---:|---:|---:|
| Carrick 1 | 8,573 | 16,674 | — |
| Carrick 2 | 8,710 | 9,398 | — |
| Carrick 3 | 8,762 | 9,457 | — |
| Carrick 4 | 8,676 | 9,392 | — |
| Carrick 5 | 8,649 | 9,448 | — |
| Docker 1 | 909 | 1,080 | host wrapper only |
| Docker 2 | 832 | 1,000 | host wrapper only |
| Docker 3 | 799 | 964 | host wrapper only |
| Docker 4 | 787 | 942 | host wrapper only |
| Docker 5 | 788 | 958 | host wrapper only |

Carrick CPU median (RUSAGE) is 21.391 s; per-sample CPU lives in the JSON
artifact. Carrick sample 1's process elapsed (16,674 ms) is a first-sample
container-assembly outlier; its in-container workload window (8,573 ms) is
normal, and workload wall — the identical in-container clock window on both
engines — is the official metric. Docker's recorded `RUSAGE_CHILDREN` is
the host `docker` wrapper and is intentionally not compared to Carrick CPU.

## Interpretation

The arena delete leaves the shipped default where it was: roughly 8.7 s
absolute and roughly 10.9x native-arm64 Docker on this host today. No
performance was claimed for the campaign and none was lost by its removal;
the next levers are the ones the category-collapse spec now sequences
(Move 3 kernel amplification ledger first, Move 2 re-costed against the
persistent unit store).
