# Current-default cold-build wall refresh

**Date:** 2026-08-04  
**Scope:** Darwin/AArch64 shipped-default native cold `go build`  
**Decision:** **accept as the current official scoreboard: 10.1776x
native-arm64 Docker**

The current clean, signed shipped-default binary was measured in two serialized
five-sample phases: every Carrick execution first, then every native-arm64
Docker execution. The current workload-wall medians are **8,254 ms Carrick**
and **811 ms Docker**, a ratio of **10.1775586x**. Process elapsed medians are
8,991 ms / 995 ms = **9.0361809x**.

This supersedes the 2026-08-03 official 8,575 ms / 821 ms = 10.4446x result.
Carrick workload wall is 321 ms (3.74%) lower while the Docker median is 10 ms
(1.22%) lower, so the ratio improves by 2.56%. The current median Carrick CPU
is 20.167694 s, 9.63% below the prior official run's 22.316068 s and consistent
in direction and scale with the separately controlled published-block-lock
ABBA CPU result. The serialized scoreboard is timing authority for the current
ratio, but it is not a counterbalanced causal estimate of the lock split; the
ABBA remains authority for that mechanism.

At the current Docker denominator, 3x is 2,433 ms. Reaching it requires removing
another 5,821 ms, or **70.52%**, from current Carrick workload wall (a 3.3925x
reduction). The 2x product bar is 1,622 ms and requires removing **80.35%**
(5.0888x).

## Authority

Artifact:
`target/perf/current-wall-refresh/native-go-build-v1.json`, SHA-256
`b55ad2d5ab23476535c26f2fb31085e78246fed1fee5412724a42d0e1b2d9a3d`.

- clean source: `08be3b7f006300427edd49ba3265f4b2ff8cf8b8`;
- measured runtime code authority:
  `64bebc26b72ffd1f7a9ba581fded0f91fca21f63`;
- signed binary SHA-256:
  `aa423abce65be7408a4e565bec04383c7eb0dfeec8a3e72f56fb1cc8f96fd5df`;
- image digest:
  `sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`;
- Docker platform: `linux/arm64`;
- performance overlay: shipped default, with every control key unset;
- host preflight: no busy-host reasons and no override;
- result: 5/5 `BUILD_OK` and zero nonzero exits, timeouts, capture errors, or
  cleanup failures in each phase.

The run began at `2026-08-04T12:58:50.401075Z` and ended at
`2026-08-04T12:59:44.270815Z`. Carrick and Docker never overlapped.

## Samples

| engine | workload wall, ms | process elapsed, ms | total CPU, s |
|---|---:|---:|---:|
| Carrick 1 | 8,240 | 9,367 | 19.968043 |
| Carrick 2 | 8,206 | 8,915 | 20.124471 |
| Carrick 3 | 8,254 | 8,970 | 20.201404 |
| Carrick 4 | 8,278 | 9,000 | 20.259955 |
| Carrick 5 | 8,264 | 8,991 | 20.167694 |
| Docker 1 | 931 | 1,119 | host wrapper only |
| Docker 2 | 809 | 984 | host wrapper only |
| Docker 3 | 811 | 995 | host wrapper only |
| Docker 4 | 823 | 1,022 | host wrapper only |
| Docker 5 | 793 | 963 | host wrapper only |

Docker's recorded `RUSAGE_CHILDREN` is the host `docker` wrapper rather than
container CPU and is intentionally not compared to Carrick CPU. Workload wall
comes from the identical in-container clock window on both engines.

## Interpretation

The fresh run confirms that the absolute shipped-default wall remains roughly
8.25 seconds and the overhead remains roughly 10.18x, not that the controlled
lock split alone produced a statistically resolved wall win. Its eight-quad
ABBA workload-wall interval crossed parity, while total CPU improved 8.50% and
system CPU improved 23.46%. The next performance experiment therefore remains
the exclusive translation writer identified by the paired DTrace stacks.
