# Post-Move-3 shipped-default cold-build wall refresh

**Date:** 2026-08-07 (run window 2026-08-07T14:20:19Z → 14:21:12Z)
**Scope:** Darwin/AArch64 shipped-default native cold `go build`
**Decision:** **accept as the current official scoreboard: 10.1806x
native-arm64 Docker** (workload wall medians 8,175 ms Carrick / 803 ms
Docker). Process elapsed medians are 8,887 ms / 965 ms = **9.2093x**.

Measured by the standing procedure
([`2026-08-04-current-default-wall-refresh.md`](2026-08-04-current-default-wall-refresh.md)):
two serialized five-sample phases, every Carrick execution first, then
every native-arm64 Docker execution, never overlapping; digest-pinned
image; shipped default with every control key unset; harness preflight
passed without `--allow-busy`. It supersedes the 2026-08-06 official
8,676 ms / 799 ms = 10.8586x
([`2026-08-06-post-arena-default-refresh.md`](2026-08-06-post-arena-default-refresh.md)).

## What this run folds in

The prior official was measured at `7318f583` (binary `bbc63c51…`),
BEFORE the Move-3 execution wave. This tip (`e4ee4a7e`) adds, wall-relevant:

- **the kernel-side anonymous-reuse replacement** (`52342762`, evidence
  [`2026-08-07-anon-reuse-remap.md`](2026-08-07-anon-reuse-remap.md)):
  ~518k faults/build removed, ABBA-attributed −0.660 CPU-s
  [−0.750, −0.570] and −363 ms wall on its own controlled screen;
- **the stat-cache dirfd interning** (`dce3266a`, plus its
  rename-unpublish correctness fix `85ec0f4c`): the amplification ledger
  credits it with 68,849 host syscalls removed per build; it had never
  been wall-measured until this refresh;
- **E1's host file-backed private file mmaps** (`f2a42bc3`, atomicity
  correction `ca96024a`): mechanism-verified earlier; its own AMP/ABBA
  showed no resolved wall movement (population 3.8 MiB/build).

The rest of the window is instruments and docs (the AMP1/NFAULT2 ledger
and partition tooling, this campaign's evidence entries).

## Delta vs the prior official, stated honestly

Carrick workload wall −501 ms (−5.77%), Docker +4 ms (+0.50%), ratio
−6.27% (10.8586x → 10.1806x). Median Carrick CPU is **19.795 s vs
21.391 s (−7.46%)**, and 1.85% BELOW the 2026-08-04 official's 20.168 s.

**The drift question, updated.** The 2026-08-06 entry carried a +6.06%
CPU / +5.11% wall drift over 2026-08-04 that it could not decompose (tip
drift vs host state under ambient load ≈2.2 with a concurrent agent).
Today's run un-does that drift and more. Two same-box anchors from this
task's ABBA (yesterday, quiet host) bracket it: the ABBA **control**
(pre-remap code at the Move-3 tip) ran 20.350 s CPU — within 0.9% of the
2026-08-04 official's 20.168 s — and the ABBA **candidate** ran
19.690 s — within 0.6% of today's official 19.795 s. This SUGGESTS
(same-box consistency, not a controlled decomposition) that the
2026-08-06 +6% was predominantly host-state of that run window, not
code, and that today's official is the 2026-08-04 baseline plus the
remap's controlled −0.66 CPU-s. The stat-cache interning's syscall
removal is folded in but not separately resolved at this scale; no
further unattributed drift remains open against this scoreboard.

## Bars at the current Docker denominator (803 ms)

| bar | target wall | removal required from 8,175 ms |
|---|---:|---:|
| 8x | 6,424 ms | 21.42% |
| 5x | 4,015 ms | 50.89% |
| 3x | 2,409 ms | 70.53% (3.39x reduction) |
| 2x (product bar) | 1,606 ms | 80.36% (5.09x reduction) |

## Authority

Artifact: `target/perf/task7-anonzero/native-go-build-post-move3.json`,
SHA-256
`5973ee9c65384033dd324b76f1b2a560a65be6750050b0a319487e3cb8cbd401`.

- clean source: `e4ee4a7e7de96a92853674ceaa0e8ab5aedd3038` (`git_dirty:
  false`; two stray untracked scratch files from another session were
  moved aside for the run and restored after);
- signed binary SHA-256:
  `61f0bbb3c93f4009c2a64ba915cf0e84b5e049e0adb19e47bde8a82daf74855f`
  (built at this exact tip, `__dof_carrick` present,
  `CARRICK_DSR_ZERO_REMAP` marker present);
- image: `localhost:5005/carrick-go-conformance:1.24`, digest
  `sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b`
  (identical to the 2026-08-04 and 2026-08-06 runs);
- Docker platform: `linux/arm64` (native arm64, no Rosetta);
- performance overlay: shipped default, every control key unset;
- harness preflight: passed without `--allow-busy` (no named busy
  reasons); the recorded 1-minute load average at start (5.51) is the
  tail of the signed rebuild finishing moments earlier — Carrick sample 4
  (8,767 ms workload, 21.873 s CPU) is the visible casualty and the
  medians are robust to it;
- result: 5/5 `BUILD_OK` in each phase, zero nonzero exits, timeouts,
  capture errors, or cleanup failures; the two phases ran serialized,
  every Carrick sample before any Docker sample, never overlapping.

## Samples

| engine | workload wall, ms | process elapsed, ms | total CPU, s |
|---|---:|---:|---:|
| Carrick 1 | 8,046 | 8,887 | 19.621 |
| Carrick 2 | 8,042 | 8,754 | 19.790 |
| Carrick 3 | 8,186 | 8,874 | 19.795 |
| Carrick 4 | 8,767 | 9,522 | 21.873 |
| Carrick 5 | 8,175 | 8,907 | 20.334 |
| Docker 1 | 991 | 1,171 | host wrapper only |
| Docker 2 | 803 | 946 | host wrapper only |
| Docker 3 | 795 | 949 | host wrapper only |
| Docker 4 | 890 | 1,035 | host wrapper only |
| Docker 5 | 803 | 965 | host wrapper only |

Docker's recorded `RUSAGE_CHILDREN` is the host `docker` wrapper rather
than container CPU and is intentionally not compared to Carrick CPU.
Workload wall comes from the identical in-container clock window on both
engines.

## Interpretation

The shipped default is back under the 2026-08-04 line: roughly 8.2 s
absolute and **10.18x** native-arm64 Docker on this host today, with the
remap's controlled −0.66 CPU-s now visible in the official scoreboard
and the 2026-08-06 drift closed as host-state. The 2x product bar still
requires removing 80.36% of current Carrick wall; the next territory
remains the out-of-window ~63% host-other allocation churn (E2-proper)
that Move 3's ledger sequenced.
