# The cold go build attributed: nothing serializes it — every second is amplified ~12x

**Date:** 2026-08-03. **Tree:** `032593e1`, signed release binary (built at
`ed1bb372`'s code; later commits are docs/D-scripts only), native backend.
**Fixture:** the composed-lanes scoreboard's build-cold workload (hello-world
`go build`, `GOCACHE` empty, `localhost:5005/carrick-go-conformance:1.24`),
in-guest wall bracketed. **Box:** quiet — `ps` verified before each batch; no
stale consumers; every run stamped `CARRICK_RUN_ID` and reaped with
`scripts/sudo/kill.sh`. All carrick and Docker phases strictly serial.

**Instruments** (all untraced — no DTrace consumer touched any number here):
`/usr/bin/time -l` over the supervisor (rusage aggregates the whole reaped
tree); `CARRICK_DSR_PROFILE=1` NATIVEPERF thread frames (415 records, 69
processes) + supervisor rusage record; `CARRICK_EXEC_STAMPS` lifecycle stamps
(983 lines); a 60–100 ms `ps` sampler for pid→argv and live width; **Go's own
`-debug-trace` action timeline run under BOTH engines** (cmd/go's JSON gauge —
same instrument both arms); Docker cgroup `cpu.stat` for the oracle's CPU.
Instrumented walls sit inside the clean-run band, so gauge overhead is below
run variance. Raw evidence: `target/perf-bsattr-20260803/`.

## 1. First split: CPU vs wall — the verdict is AMPLIFIED, not serialized

Clean runs, `/usr/bin/time -l` (user+sys is the whole process tree):

| engine | wall (guest window) | total CPU | avg cores busy |
|---|---|---|---|
| carrick (n=4: 9.79, 9.89, 9.94†, 10.88† s) | ~9.9 s | 25.3–26.6 s | **2.5** |
| docker (n=2: 0.796, 0.765 s) | ~0.78 s | 2.20, 2.09 s | **2.8** |

† later batch, monotone thermal drift band; ABBA interleaving used for all
comparisons.

**Utilization is the SAME on both engines (~2.5 vs ~2.8 cores).** The 12.7x
wall ratio is a ~12x **CPU amplification** at unchanged parallelism — there is
no carrick-side serializer stealing width. The build has limited intrinsic
parallelism on both engines: Docker also spends 82% of its wall (646 of
787 ms) inside the single serial `build runtime` action.

Environment checks that could have faked a serializer, both refuted:

- **Guest sees 4 CPUs** (`nproc`=4, `/proc/cpuinfo`=4 ⇒ `GOMAXPROCS`=4,
  `go build -p 4`) vs Docker's 10: `select_exposed_cpu_count`
  (`crates/carrick-host/src/host_facts.rs:147`) deliberately exposes
  `hw.perflevel0.logicalcpu` (4 P-cores). Measured lever, ABBA
  (`CARRICK_EXPOSED_CPUS=10` host env): 10.44/9.65 s vs 10.88/9.94 s —
  **only ~0.3–0.4 s**. Width is not the story (E-core confound noted: the
  extra 6 CPUs are E-cores, exactly what Docker gets).
- **The agent launch shell runs at nice 5** (guest tree inherits it; Docker's
  VM is nice 0). Root-renice-to-0 arm: 10.35 s / 25.8 s CPU vs default
  10.25 s / 25.7 s — **no effect** on the quiet box (no QoS clamp present,
  `taskinfo` verified). The recorded 13x is not a priority artifact.

## 2. Wall decomposition along the build's own action timeline

`go build -debug-trace` under both engines (identical instrument), carrick
run `cbID1` (guest window 10.28 s), corroborated by an independent stamps-only
run (`cbP1`: same 3.4 s solo-compile + serial ~100 ms tail-train shape):

| segment (go action timeline) | docker | carrick | excess |
|---|---|---|---|
| driver setup → first action (`load.PackagesAndErrors` …) | 26 ms | 467 ms | +0.44 s |
| deps wave → `build runtime` starts (26 internal/* actions, width ~3.6 of 4) | 87 ms | 3 775 ms | +3.69 s |
| `build runtime` action (serial critical path) | 646 ms | 5 067 ms | +4.42 s |
| `build main` + link + buildid tail | 28 ms | ~890 ms | +0.86 s |
| outside the build command (sh/date/rm edges) | ~9 ms | ~310 ms | +0.30 s |
| **guest window** | **796 ms** | **~10 280 ms** | **+9.5 s** |

Inside the +4.42 s `build runtime` action (stamps + sampler pid→argv):
`compile` of package runtime runs **3.44 s alone** (8 threads, 6.9 s CPU,
~2 cores — translate 1.13 s + 5.53 s emitted-code execution), then cmd/go's
per-package build action serially execs **~10 `asm` (one per .s file), pack,
buildid — each a ~100 ms carrick process for ~5 ms of real work**
(~1.4 s of pure serial exec train; each is ~8 ms under Docker).

## 3. CPU decomposition by mechanism — and it sums

NATIVEPERF, all 69 guest processes of run `cbID1` (thread_cpu 26.3 s; closes
against `/usr/bin/time` 27.2 s − supervisor 0.32 s − sh; the second sample
`cbP1` gives the same split: 13.7/7.4/2.5 s):

| mechanism | wall-in-phase | ≈CPU (scaled ×0.82‡) | share |
|---|---|---|---|
| **translate** (1.74 M blocks @ 8.4 µs — every process re-translates its image from scratch) | 14.6 s | ~12.0 s | 46% |
| **translated_run** (emitted guest code; useful work ≈ Docker's 2.1 s lives here) | 7.9 s | ~6.5 s | 25% |
| **gateway prepare+finish** (3.65 M entries @ 1.94 µs; 1.73 M exits are cold-cache branch-resolves) | 7.1 s | ~5.8 s | 22% |
| **syscall dispatch** (88.7 k @ 29.5 µs; mmap-dominated per 2026-08-03 exec-window shape) | 2.6 s | ~2.1 s | 8% |

‡ phases are per-thread wall clocks and sum to 32.1 s > 26.3 s CPU under
4-core contention; scaled proportionally — the honest residue of this table.

Closure: excess CPU = 26.3 − 2.1 (Docker-equivalent useful) = 24.2 s
≈ 12.0 (translate) + 5.8 (gateway) + 4.4 (emitted-code overhead:
6.5 − 2.1) + 2.1 (dispatch). Excess wall = 24.2 s ÷ 2.56 avg cores = 9.5 s =
the measured excess. **The model closes on both axes.**

Sys side: carrick 7.5–8.9 s vs Docker 0.21 s (36x) — the kernel share of
translate (JIT cache mmap/mprotect/icache), dispatch (mmap reserves), and the
exec chain; it is inside the buckets above, not additive.

## 4. Per-process-class inflation (why short processes hurt most)

Stamps × NATIVEPERF × sampler join, per exec:

| class | n | carrick life | of which: chain / translate / real work | docker | ratio |
|---|---|---|---|---|---|
| `asm` | 33 | ~108 ms | 13.5 / **68** / 4.9 ms | ~8 ms | ~13x |
| `buildid`, `pack` | 32 | ~45 ms | 10 / 22 / 1.2 ms | ~2 ms | ~18x |
| `compile` (small pkg) | ~18 | 120–480 ms | ~20 / 75–615 / 5–70 ms | 4–43 ms | 10–30x |
| `compile` (runtime) | 1 | 3 440 ms | 16 / 1 130 / 5 530(CPU) ms | ~550 ms | 6.3x |
| `link` | 1 | ~360 ms | — | 24 ms | 15x |
| go driver | 1 | whole run | dispatch 0.78 s CPU; translate 0.20 s | — | setup 18x |

The floor term is startup retranslation (the Go runtime boot path, ~68 ms)
plus the ~13.5 ms exec chain plus ~21 ms of mmap-reserve dispatch — the
2026-08-03 exec-window attribution, confirmed in situ on the real build.

## 5. Suspect verdicts

1. **`HostAliasTransactions` exclusive gate — NOT the term.** Total syscall
   dispatch is 2.6 s of 26.3 s CPU; `phase_blocked_cpu_ns` 0.19 s;
   compile-runtime (the many-threads-one-process worst case) spends 102 ms
   in dispatch over 3.44 s of wall.
2. **fs amplification — only the driver setup term (~0.44 s).** The build is
   not stat-bound; go driver dispatch is 0.78 s CPU total.
3. **futex/scheduler lowering — non-issue** (1.6 ms/run, prior traced
   ranking; blocked time is parked idle Go workers, not contention).
4. **Process-shared lock collapse — refuted by the first split**: utilization
   equals Docker's.

## 6. Ranked levers, sized in wall seconds on THIS build

| rank | lever | size | evidence |
|---|---|---|---|
| 1 | **Kill per-exec retranslation** (persistent per-image translation store with cheap attach). Ceiling ≈ translate's wall share ~4.7 s, plus most of the gateway term (resolve exits are cold-cache artifacts) → **~5–6 s**. The existing `CARRICK_DSR_SHARED_TRANSLATION=1` is measured **30% WORSE** on this build (concurrent publishers, scoreboard correction) — the lever is a transport redesign, not the flag. | ~5–6 s | §3 translate 14.6 s / 1.74 M blocks; §4 per-class; scoreboard-correction A/B |
| 2 | **Emitted-code overhead** (DSR floor ~52% of executed emitted instructions; stolen-register ctx traffic) — mostly the compile-runtime critical path (5.5 s emitted CPU at ~2 cores) | ~1.7–2.5 s | §3 translated_run 7.9 s vs 2.1 s useful; shape census 2026-08-02 |
| 3 | **Gateway round-trip cost** (3.65 M entries @ ~2 µs bookkeeping + resolve work) — largely subsumed by lever 1; independently attackable by cheaper entry/exit | ~2.3 s (overlaps 1) | §3 gateway counters |
| 4 | **mmap dispatch compute** (Go `PROT_NONE` arena reserves → O(1) Darwin lowering) | ~0.7 s | §3 dispatch 2.6 s; exec-window shape (mmap 85% of syscall time) |
| 5 | Exec chain (13.5 ms × 89 execs; ~0.25 s of it strictly serial in the runtime action's asm train) | ~0.5 s | §4 chain column; stamps |
| 6 | Expose 10 CPUs (`CARRICK_EXPOSED_CPUS` default) | **0.3–0.4 s measured** | §1 ABBA |
| 7 | Driver setup fs (18x) + rootfs clonefile seed (0.35 s supervisor CPU) | ~0.6 s | §2 row 1; exec-window §5 |

Levers 1+2+4+5+6+7 ≈ 8.7–10 s against the 9.1–9.5 s excess (lever 3 overlaps
1) — the ledger is complete; the residue is the ×0.82 phase-scaling
approximation in §3. Even at the full lever-1+2 ceiling the build lands near
Docker's shape only if the serial `compile runtime` process also gets its
emitted-code and startup terms — the critical path is that one process plus
its serial asm train, on both engines.

## 7. Reproduction

- Clean: `/usr/bin/time -l target/release/carrick run --exec-backend native -e CARRICK_RUN_ID=<id> -w /tmp localhost:5005/carrick-go-conformance:1.24 /bin/sh -c '<build-cold script from scripts/perf/workload-spread.sh>'`
- Attribution: same + host env `CARRICK_DSR_PROFILE=1 CARRICK_EXEC_STAMPS=<abs path>`; in-guest `go build -x -debug-trace=/tmp/gotrace.json`.
- Docker (serial phase): same script + `-debug-trace` + `cat /sys/fs/cgroup/cpu.stat`.
- Width arm: host `CARRICK_EXPOSED_CPUS=10`. Renice arm: `target/perf-bsattr-20260803/renice0-loop.sh` (root, run-id-scoped).
