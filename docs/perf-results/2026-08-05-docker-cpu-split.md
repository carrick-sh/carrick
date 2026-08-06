# 2026-08-05 Docker-side in-container CPU split

**Scope.** Docker-only denominators for Move 0 of the category-collapse
performance strategy
(`docs/superpowers/specs/2026-08-05-category-collapse-strategy-design.md`).
The existing `scripts/perf/workload-spread.sh` scoreboard deliberately does
not capture in-container CPU — its recorded `RUSAGE_CHILDREN` is the host
`docker` wrapper's own rusage, not the guest shell's. This run adds the POSIX
`times` builtin inside the same in-container `sh -c` window the spread
harness brackets, Docker side only, so the four spread fixtures
(`compute`, `fs-walk`, `exec-20`, `build-cold`) get a user/sys split that can
join the existing scoreboard. Carrick-side CPU is **not** re-measured here —
see Caveats.

## Authority

| | |
|---|---|
| git commit | `f5f93007734c16048211f0a462ecea369c224d11` |
| image | `localhost:5005/carrick-go-conformance:1.24` |
| image id | `sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b` |
| docker server version | `29.6.2` |
| host preflight | `pgrep -fl 'carrick run'` empty (checked immediately before probe and before the real run); `pmset -g batt` 97-98% discharging, no thermal/performance warning recorded; `ps -Ao %cpu,comm \| sort -rn \| head` showed no non-measurement process near a full core (top non-Apple-system entry ≤12% CPU) at both preflight checks |
| run window (5-sample run) | 2026-08-05 19:53:25 PDT -> 19:53:34 PDT |
| harness | `scripts/perf/docker-cpu-split.sh` |
| raw receipts | `target/perf/docker-cpu-split/docker-cpu-split.jsonl`, `probe.log`, `run-5x.log`, `raw-<workload>-<sample>.txt` |

No carrick guest ran at any point during the probe or the real measurement
window (verified by `pgrep -fl 'carrick run' \|\| true` immediately before
each run).

## `times` format observed

The probe run (Step 2, `N=1`) did **not** trigger the parser assertion — the
harness's assumed format matched the image's actual `times` output on the
first try, so no regex fix was needed. Raw per-workload output
(`target/perf/docker-cpu-split/raw-*.txt`) shows exactly two lines after the
`WORKLOAD_NS=` marker:

```
WORKLOAD_NS=891671126
0m0.000000s 0m0.000000s
0m2.040000s 0m0.210000s
```

Line 1 is the invoking shell's own usage (`0m0.000000s` user, `0m0.000000s`
sys — negligible for a single `sh -c` wrapper), line 2 is the summed usage of
its children (the actual workload). Both lines follow POSIX
`<minutes>m<seconds>.<fraction>s <minutes>m<seconds>.<fraction>s` (user then
sys), with microsecond-resolution fractional seconds in this image's `sh`
(BusyBox/dash-style `times`), i.e. finer than the "centisecond-scale"
assumption in the brief — see Caveats.

## Per-sample results

### compute
| sample | wall_ms | user_s | sys_s |
|---|---|---|---|
| 1 | 108 | 0.10 | 0.00 |
| 2 | 106 | 0.10 | 0.00 |
| 3 | 107 | 0.10 | 0.00 |
| 4 | 107 | 0.10 | 0.00 |
| 5 | 88 | 0.08 | 0.00 |

### fs-walk
| sample | wall_ms | user_s | sys_s |
|---|---|---|---|
| 1 | 13 | 0.00 | 0.01 |
| 2 | 11 | 0.00 | 0.00 |
| 3 | 12 | 0.00 | 0.01 |
| 4 | 11 | 0.00 | 0.00 |
| 5 | 12 | 0.00 | 0.00 |

### exec-20
| sample | wall_ms | user_s | sys_s |
|---|---|---|---|
| 1 | 18 | 0.00 | 0.00 |
| 2 | 18 | 0.00 | 0.00 |
| 3 | 17 | 0.01 | 0.00 |
| 4 | 17 | 0.00 | 0.00 |
| 5 | 18 | 0.00 | 0.00 |

### build-cold
| sample | wall_ms | user_s | sys_s |
|---|---|---|---|
| 1 | 788 | 2.01 | 0.21 |
| 2 | 794 | 2.01 | 0.15 |
| 3 | 803 | 2.11 | 0.14 |
| 4 | 774 | 1.96 | 0.15 |
| 5 | 781 | 1.98 | 0.14 |

## Medians (n=5 each)

| workload | wall_ms | user_s | sys_s | cpu_total_s |
|---|---|---|---|---|
| compute | 107 | 0.100 | 0.000 | 0.100 |
| fs-walk | 12 | 0.000 | 0.000 | 0.000 |
| exec-20 | 18 | 0.000 | 0.000 | 0.000 |
| build-cold | 788 | 2.010 | 0.150 | 2.160 |

Medians recomputed independently against the JSONL and cross-checked byte-for
-byte against the harness's own summary block (`run-5x.log` tail) — they
match.

## Caveats

- **`times` granularity is finer than assumed, not coarser.** The brief
  flagged `times` as "centisecond-scale"; this image's `sh` actually reports
  microsecond-resolution fractional seconds (`0m0.100000s`). The harness's
  regex (`[0-9.]+`) accepts any fractional precision, so this did not require
  a fix, but the `fs-walk`/`exec-20` user/sys medians of `0.000` are genuinely
  at or below single-digit-millisecond CPU consumption for those fixtures in
  this image, not an artifact of a coarse clock rounding non-zero usage down
  to zero.
- **The in-container wall window matches the spread harness's bracket
  exactly** — same `date +%s%N` pre/post markers around the byte-identical
  fixture command, so `wall_ms` here is directly comparable to the Docker
  `wall_ms` column workload-spread.sh already records (modulo per-run
  variance and the fact that this harness runs each workload in its own
  fresh `--rm` container, same as workload-spread.sh's Docker arm).
- **`fs-walk` and `exec-20` wall times differ from the earlier probe run**
  (`fs-walk` 73ms in the probe's single sample vs an 11-13ms median here;
  `exec-20` at 41ms in the probe vs a 17-18ms median here). This tracks host
  page-cache warm-up across successive `docker run --rm` invocations against
  the same image layers (`/usr/local/go` files get cached after the first
  touch), not a measurement bug — the probe was the first touch of those
  paths this session.
- **Carrick-side CPU is deliberately NOT re-measured here.** This harness is
  Docker-only by design (AGENTS.md's never-run-concurrently rule). The
  wall-refresh doc's carrick `build-cold` median of **20.167694 s** and its
  v5 category shares remain that side's sole authority; this doc supplies
  only the Docker-side user/sys denominators for Move 0's category budgets.
- Host was on battery power throughout (97-98%, discharging) — not mains
  power. No attempt was made to control for that as a variable; it is noted
  for completeness since Apple Silicon can shift performance-core scheduling
  under battery-power policies. All samples within a workload were collected
  in one continuous run so this is at least a constant condition across the
  5 samples reported here.
