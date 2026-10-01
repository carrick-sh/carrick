# What bounds the Node shard's wall time?

**Status (2026-10-01):** diagnosis only, Carrick side. The host was shared
with other workers throughout (load average 9–30 on 10 CPUs), so every
absolute time below suggests and none confirms. The Docker column is
deliberately empty: the same capture must be run under Docker in a quiet
window (commands in [Docker side](#docker-side-to-be-run-by-the-director)).
Shares of the gap are estimates until then, and are labelled as estimates.

Workload: `node-core-worker-message-port`, i.e. `python3 tools/test.py
--shell node24 --progress tap 'parallel/test-worker-message-port*'` in
`localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0`, 26 tests.
Quiet-host walls: Carrick about 2.1 s, Docker 0.97 s (`el1ab-node2-*`).
The two latency fixes so far (host `clock_gettime` 48k → 0, busy-slot claim
1.5 ms → 0.1 ms) left the Carrick wall unchanged.

## Answer in one paragraph

The wall time is one serial chain, and one test dominates it. First the
runner starts and probes node six times in a row. Then
`test-worker-message-port-message-before-close` runs: it is about the tenth
test to start at `-j4`, and its body is 10,000 strictly serial cross-thread
round trips. On Carrick that one test runs 1.2 s of the 2.1 s wall (tap
`duration_ms` 1170 on the quietest runs), at about 117 µs per round trip.
Linux needs well under 40 µs per round trip for this ping-pong (an
estimate, to be checked with the Docker run of the included microbench).
**The gap is mostly blocked-wait round-trip latency on that critical path
(est. ~70%).** Next come the serial per-process fixed costs of the runner
preamble (python `test.py` import, six node config probes; est. ~30%).
Lower test parallelism (Carrick's guest sees 4 CPUs, so `test.py` runs
`-j4`) adds est. ~10–15%. Carrick's faster container start
(63 ms against `docker run`'s few hundred ms) pays back about 20–25% of the
gap. Worker thread creation and process reaping are each a few percent at
most.

## Method

- **Timeline capture** ([`node-critical-path/timeline.sh`](node-critical-path/timeline.sh)),
  run inside the image with the directory mounted at `/ncp`. It runs the
  shard exactly as `nodejs-conformance` does, but with
  `--shell /tmp/nodewrap`. The wrapper records spawn and exit times for
  every node process with bash's fork-free `$EPOCHREALTIME`, and preloads
  [`timing.js`](node-critical-path/timing.js) (`-r`). In each main thread,
  `timing.js` writes `performance.timeOrigin`, the `nodeTiming` bootstrap
  milestones and the worker new/online/exit times, plus the JS exit time.
  After the shard it runs three microbenchmarks:
  - `node -e 0` 20 times (fixed per-process cost);
  - 50 worker create+join (per-worker cost);
  - 2000 `message-before-close` round trips (per-wake cost).
- **Analyzer** ([`analyze.py`](node-critical-path/analyze.py)): it prints
  per-test start, lifetime, exec (spawn → `timeOrigin`), bootstrap (to
  `bootstrapComplete`), first worker new and online, JS end and reap
  (JS exit → wrapper sees exit), plus runner phases.
- **Perturbation:** one extra bash per node process. Carrick: traced
  `-j4` walls of 2.8 s, against 2.05 s untraced on a quieter host. Use the
  structure and the microbench ratios, not the absolute walls.
- **Run ids:**
  - `ncp-tl-1..8`: timelines (`-j` default, so 4, or `-j10`).
  - `ncp-u4-*`, `ncp-u10-*`: untraced `-j4` against `-j10`.
  - `ncp-true-*` and `ncp-py-*`: container and runner fixed costs.
  - All on the `work/sched-diag` binary without zone-wake (b58ece6f);
    lane off. Every run was reaped with `scripts/sudo/kill.sh`.
  - Captures are in [`node-critical-path/runs/`](node-critical-path/runs/).

## Per-test timeline (Carrick, `ncp-tl-7`, `-j4`, load ~14)

All times are ms. `start` is from the runner start; `life` is spawn to
wrapper exit. `exec` is spawn to `timeOrigin`; `boot` is `timeOrigin` to
`bootstrapComplete`. `w_up` is worker `new` to `online`; `reap` is JS exit
to wrapper exit.

| phase | start | duration |
|---|---|---|
| runner: python start + `tools/test.py` import + test discovery | 0 | 248 |
| 6 serial node config probes (`-p process.arch`, `process.versions.openssl`, ...) | 248 | 456 (first 127, then ~40 each, plus ~20 ms python between) |
| 26 tests at `-j4` | 723 | until 2672 |
| ↳ `message-before-close` | 1036 | **1636** (exec 11, boot 74, worker new 24 → online 53, JS ~1.5 s, reap 12) |
| last exit → runner exit | 2672 | 150 |

Typical tests are short: median life 94 ms, exec 9 ms, boot 38 ms, reap
13 ms. The long ones are `message-before-close` (1.2–1.9 s across runs),
`terminate-transfer-list` (0.45–0.9 s, a `setTimeout(100)` plus
terminating a worker spinning in JS), `drain` (0.26–0.44 s),
`transfer-terminate` (~0.35 s) and `wasm-module`/`wasm-threads`
(~0.3 s each). Every test except `message-before-close` finishes before it
does: it is the whole tail.

Microbenchmarks, Carrick, `ncp-tl-5..8`:

- `node -e 0`: 28–46 ms.
- Worker create+join: 19–30 ms.
- `message-before-close` round trip: 61–115 µs. The test itself averages
  117–165 µs per iteration, because it also pays for `assert.deepStrictEqual`
  and runs alongside the other tests.
- Container start (`carrick run ... /bin/sh -c 'echo hi'`): 61–63 ms.
- Python start: 25 ms. `tools/test.py --help` (import): 176–180 ms.
- `node -p process.arch` alone: 85 ms.

## Classifying the 1.13 s gap (estimates until the Docker capture)

| class | Carrick evidence | est. share of gap |
|---|---|---|
| **Serial cross-thread round trips** (`message-before-close`: 10,000 × post → worker wakes from `epoll_pwait` → two replies → main wakes) | 1.17 s untraced; microbench 61–115 µs per round trip; about two blocked-wait wakes per round trip. sched-diag measured epoll wake-to-run p50 20–35 µs and claim-to-run 6–15 µs, plus the forwarded `write`/`epoll_pwait` service around each wake | **~0.8 s (~70%)** if Linux runs ~35 µs per round trip |
| **Serial per-process fixed cost in the runner preamble** (python import, 6 node probes, each a fresh exec + node bootstrap) | ~0.25 s runner + ~0.46 s probes = ~0.7 s. `node -e 0` 28–46 ms; python import of `test.py` 176 ms (syscall-heavy: many opens, stats and mmaps) | **~0.35 s (~30%)** if Docker's preamble is ~0.3 s |
| **Test parallelism** | Carrick's guest reports `nproc` 4, so `test.py` defaults to `-j4`; `message-before-close` starts ~300 ms after the first test. At `-j10` it starts ~100–250 ms earlier (`ncp-tl-6`, `ncp-tl-8`; traced walls 2.35–2.5 s against 2.8 s at `-j4`). Docker's `-j` is the Docker VM's `nproc` (unknown here) | **~0.1–0.2 s (~10–15%)** |
| **Per-worker-thread cost** | `message-before-close` creates one worker: new → online 53–127 ms traced; microbench create+join 19–30 ms | ~0.03–0.05 s (≤5%) |
| **Reap / pipe-EOF to the runner** | JS exit → wrapper exit 8–15 ms per test; once on the critical path, plus the 150 ms runner tail | ~0.05 s (≤5%) |
| **Container start** (in the wall for both runtimes) | Carrick 63 ms against `docker run`'s create/start/attach/remove, typically a few hundred ms | **−0.25 s (Carrick ahead)** |

The estimates sum to about 1.1 s, consistent with the measured gap. Two
points are firm without Docker:

1. **The critical path is one ping-pong test.** Making every other test
   free would change the wall by roughly the 0.3 s it takes
   `message-before-close` to get a `-j4` slot.
2. **That test is extremely load-sensitive on Carrick.** Untraced runs at
   load 9–22 gave `message-before-close` 2.6–12.9 s
   (`ncp-u4-1..3`, `ncp-u10-1..3`). Each of its ~20,000 blocking waits
   needs a host thread scheduled to wake it. Quiet-host A/B is mandatory
   for this row; a loaded host measures host scheduling, not Carrick.

## Runner parallelism (`-j`)

`tools/test.py` uses `-j 0` by default, which means
`multiprocessing.cpu_count()` (or `$JOBS`). Inside Carrick that is 4: the
carrier exposes 4 guest CPUs on this 10-CPU host. Under Docker it is the
Linux VM's CPU count (Docker Desktop's setting, often every host CPU). If
Docker runs `-j8` or higher, its tests run in more parallel lanes and the
long test starts almost at once. That is a scheduling-policy difference,
not Carrick slowness. Carrick's executor saturation ("all executors on the
host" for about 10% of placements, zone-wake note) does not serialize the
lanes here: the timeline shows 2–4 node processes running concurrently
throughout the test phase (mean concurrency about 2). It does inflate
every per-process cost while 4 tests run, as shown by the `-j10` boot times
(boot median 104–111 ms at `-j10`, against 38–41 ms at `-j4`).

## Ranked levers (none implemented here)

1. **Blocked-wait round-trip latency for in-zone producers**
   (`eventfd`/pipe write by one guest thread waking another's
   `epoll_pwait`). This is the critical path. Every wake currently goes
   from the guest syscall, through the host wait service, to scheduler
   wake, to zone placement, to an executor claim and resume. Measure
   post-to-run per round trip with the included microbench on both
   runtimes, then attack the largest stage. The obvious structural
   candidate: the waker and wakee are both guest threads, so a wake that
   stays in EL1 (the in-guest futex zone already does this for futexes)
   would skip the host wait service entirely. That puts
   epoll/eventfd/pipe readiness for carrick-owned objects into the zone,
   which is the "zone the workloads" direction.
2. **Per-process fixed cost** (exec + node bootstrap 28–46 ms, python
   import 176 ms). It is serial in the runner preamble (~0.7 s on Carrick).
   Decompose `node -e 0` and `python3 -c 'import multiprocessing, …'` by
   host exits (page faults on the ~100 MB node binary, file syscalls)
   against Docker.
3. **Guest CPU count presented to the runner.** If Docker runs more
   lanes, presenting the carrier's real usable CPU count, or reporting the
   `-j` difference in the A/B, removes about 0.1–0.2 s of apparent gap.
   This is a policy question for the director, not a bug.
4. **Worker thread lifecycle** (born-in-zone L-series, on hold): small
   (≤5%) for this shard.
5. **Reap / pipe-EOF latency to the runner:** small (≤5%).

## Docker side (to be run by the director)

Mount this directory at `/ncp` in both runtimes, and run each command in
its own phase (never Carrick and Docker together). `0` means the runtime's
default `-j` (= `nproc`); `4` forces equal parallelism.

```sh
D=$PWD/docs/perf-results/2026-10-01-el1-real-workload-ab/node-critical-path
IMG=localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0

# Docker (quiet window, no Carrick alive), default -j and -j4:
docker run --rm --platform linux/arm64 -v "$D":/ncp --entrypoint /bin/bash "$IMG" /ncp/timeline.sh 0 /ncp/runs/docker-j0-1
docker run --rm --platform linux/arm64 -v "$D":/ncp --entrypoint /bin/bash "$IMG" /ncp/timeline.sh 4 /ncp/runs/docker-j4-1

# Carrick (quiet window, no Docker alive), same image and script:
CARRICK_RUN_ID=ncp-q-1 CARRICK_EL1_DESCRIPTOR_LANE=0 target/release/carrick run --name ncp-q-1 \
  --max-traps 18446744073709551615 --fs host -v "$D":/ncp --entrypoint /bin/bash "$IMG" \
  /ncp/timeline.sh 0 /ncp/runs/carrick-j0-1
scripts/sudo/kill.sh ncp-q-1

# Both:
python3 "$D/analyze.py" "$D/runs/docker-j0-1"
python3 "$D/analyze.py" "$D/runs/carrick-j0-1"
```

`total.txt` records `nproc` and `-j`. `micro.txt` gives the three
microbenchmarks, which split the gap without the runner: per-process
(`node_e0_ms`), per-worker (`worker_create_join_ms`) and per-wake
(`roundtrip_us`). If `test.py` per-test times alone are enough, the tap
stream already carries `duration_ms` per test (`tap.txt`), and
`tools/test.py --time` prints a sorted per-test timing table at the end.
