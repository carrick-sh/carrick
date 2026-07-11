# Native Backend Fork Benchmark (2026-07-10)

First fork-cost measurement of the native16k Darwin backend, against the three
reference lanes required by the approved design. All three acceptance gates
pass.

## Verdict

| Gate | Requirement | Measured | Result |
| --- | --- | --- | --- |
| 1 | native `perf_fork` p50 <= 2x host Darwin p50 | 626.5 us vs 408.3 us = **1.53x** | PASS |
| 2 | native `perf_fork` p95 <= 3x host Darwin p95 | 728.6 us vs 537.1 us = **1.36x** | PASS |
| 3 | native `perf_fork_exec` materially beats warmed HVF | 2576.1 us vs 6786.2 us = **2.63x faster** (saves 4.21 ms/spawn) | PASS |

## Environment

- Host: Mac16,12, macOS 27.0 (26A5378j), 10 hardware threads.
- Git SHA: `cf9dfd1c` for the four main lanes; `bc6c680b` (argv-knob probe
  change only, timed loop untouched) for the scale matrix.
- Linux probe binaries: native-PIE aarch64 musl from
  `scripts/build-probes.sh --native-pie`; byte-identical binary used by the
  native16k, HVF, and Docker lanes.
  - `perf_fork` sha256 `2bab38a9ce147d146c94bc5af8d275ae3ecdd46178dea6e79b9ac72e007d8adb`
  - `perf_fork_exec` sha256 `d68eb0e9feaa23358a682720b3886f8500f3b2ce0cc49ff3f79d0583f6baed0f`
- Host lane binaries: `bench-native` release build of the exact same sources
  (`perf_fork` sha256 `98285e4d...`, `perf_fork_exec` sha256 `183c4999...`).
- Raw logs, hashes, and full metadata: `/tmp/carrick-fork-bench-20260710/`
  (`env.txt`, one log per lane/probe/rep).
- Lanes ran strictly serially; no Carrick lane overlapped Docker work. The
  only Docker-side residents during Carrick lanes were the idle Docker Desktop
  VM and the idle `carrick-registry-5050` container (0.01% CPU), matching
  prior baselines. Process residue audited clean after every lane.
- Run-ID scheme: `native-fork-<probe>-<rep>`, `hvf-fork-<probe>-<rep>`,
  `native-scale2-<t>-<m>`, `hvf-scale2-<t>-<m>`.

## Main lanes

Each lane: 1 discarded warm-up + 5 recorded repetitions. Probes self-time
in-guest (300 fork iterations or 200 fork+exec iterations per repetition after
internal warm-up). Values below are the median across the 5 repetitions;
`min` is the lane minimum.

### `perf_fork` (fork + immediate `_exit` + reap)

| Lane | p50 (us) | p95 (us) | min (us) |
| --- | ---: | ---: | ---: |
| native16k | 626.5 | 728.6 | 578.5 |
| HVF | 2146.2 | 2470.3 | 1898.4 |
| Docker (arm64 Linux) | 63.0 | 158.8 | 31.5 |
| host Darwin | 408.3 | 537.1 | 283.5 |

Per-rep native p50 spread was 622.1-629.1 us (1.1%); HVF 2087.0-2187.4 us.

### `perf_fork_exec` (fork + execve + child start + reap)

| Lane | p50 (us) | p95 (us) | min (us) |
| --- | ---: | ---: | ---: |
| native16k | 2576.1 | 2900.3 | 2425.2 |
| HVF | 6786.2 | 7278.8 | 6247.5 |
| Docker (arm64 Linux) | 97.0 | 207.2 | 61.3 |
| host Darwin | 1639.7 | 1894.6 | 1428.1 |

### Ratios (p50)

| Comparison | `perf_fork` | `perf_fork_exec` |
| --- | ---: | ---: |
| native / host Darwin | 1.53x | 1.57x |
| native / HVF | 0.29x (3.43x faster) | 0.38x (2.63x faster) |
| native / Docker Linux | 9.9x slower | 26.6x slower |

HVF's lane numbers reproduce its historical baseline (fork p50 ~2.06-2.14 ms;
fork_exec p50 ~7.2-8.0 ms), so the comparison is against a healthy warmed HVF,
not a degraded one. The Docker gap is a Linux in-kernel COW clone versus any
Darwin-process-per-guest-process design; it is the known structural reference
point, not a regression.

## `perf_fork_scale` diagnostic matrix

Run at `bc6c680b` after adding an argv fallback for the two knobs
(`perf_fork_scale [threads [mem_mb]]`, env wins), because `run-elf` gives the
guest a fixed env allowlist and silently delivered `threads=0 mem_mb=0` on the
first attempt; the probe's knob echo caught it, and the invalid first-run logs
are retained (`scale-*.log`) alongside the valid ones (`scale2-*.log`).
100 iterations per point; knob echo verified in every log.

| Point | native16k p50 (us) | HVF p50 (us) | host p50 (us) |
| --- | ---: | ---: | ---: |
| threads=0 mem=0 | 766.8 | 2503.6 | 382.2 |
| threads=0 mem=256 | 951.3 (+24%) | 5541.9 (+121%) | 468.5 (+23%) |
| threads=4 mem=0 | rejected (rc=125) | 2737.6 (+9%) | 410.9 (+8%) |

- **Memory scaling is the structural story**: with 256 MiB resident, native
  fork grows +24%, tracking host Darwin's +23%, because private pages inherit
  through host COW. HVF more than doubles (+121%) because its ForkRebuild cost
  scales with the mapped guest footprint.
- **Threaded-lane rejection is expected evidence, not noise**: native16k fails
  fast with `native Darwin fork with 5 live guest threads is not yet
  supported`. This is the documented multithreaded-fork lifecycle boundary
  (same family as the `execthreads`/`forkfpreclaim` probe gaps).
- `perf_fork_scale` uses 100 iterations versus `perf_fork`'s 300, so its
  (0,0) points sit slightly above the main-lane p50s; comparisons within the
  matrix are like-for-like.

## Caveats

- Docker lane transport is the established base64 injection into
  `ubuntu:24.04` (`scripts/probe-docker.sh` idiom); injection completes before
  the probe's internal measurement loop.
- Guest lanes report `nproc=4` (carrick exposes 4 CPUs) versus 10 on host;
  the probes are single-threaded timing loops, so this does not affect the
  measured fork path.
- The first scale-matrix attempt measured (0,0) for every carrick point
  because host env does not propagate through `run-elf`; treat any future
  env-knob probe run under `run-elf` as suspect unless the probe echoes its
  knobs.
