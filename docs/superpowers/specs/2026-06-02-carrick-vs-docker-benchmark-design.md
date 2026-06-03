# Carrick vs Docker Benchmark — Strategy & Design

**Date:** 2026-06-02
**Status:** Phase 0 implemented (branch `bench/carrick-vs-docker`) — reusable harness + first marquee result (loopback TCP_RR). This doc is the strategy for all 4 dimensions / 5 phases; see the running results log at the end.
**Author:** brainstorming session (Timothy J Fontaine + Claude)

---

## 1. Purpose & thesis

Carrick runs unmodified aarch64 Linux ELFs as **native macOS processes** via Hypervisor.framework — no guest kernel — translating syscalls directly to Darwin primitives. Docker on this host is a full LinuxKit Linux VM.

**Thesis to prove or diagnose:**

> Carrick has **no extra bridge / vhost / virtiofs abstraction** — it uses native Darwin sockets and native host file descriptors directly, while Docker pays VM-boundary translation (virtio-net + bridge/NAT for network, virtiofs/9p for host bind mounts, overlayfs for the rootfs). Therefore on **IO (disk + network) carrick *should* win.** Where it does, prove it; where it doesn't, **diagnose the cause** and attribute it to *architecture* (unavoidable HVF/no-guest-kernel cost) vs *implementation* (fixable overhead with a named call-site).

This is **advocacy, but intellectually honest.** Disk + network are the thesis core. Forks + threads are honest characterization where carrick carries real, expected HVF costs that are **never** counted against the IO thesis.

### Locked decisions (from brainstorming)

| # | Decision | Choice |
|---|---|---|
| 1 | Purpose | Competitive advocacy, intellectually honest — prove the IO-wins thesis or diagnose precisely why it fails. |
| 2 | Boot tax | Report **cold-vs-daemon honestly** (carrick per-run 265 ms vs Docker warm daemon) AND break out boot-subtracted per-op cost AND a warm carrick lane. |
| 3 | Normalization | **Strict apples-to-apples.** Both engines pinned to 4 cores; arm64-vs-arm64; one canonical fs mode per disk comparison. |
| 4 | Corpus | **Both** micro-benchmarks (isolate mechanism) and macro (re-time existing oracles for realism). |
| 5 | Run discipline | Stamp `CARRICK_RUN_ID`, reap with `scoped_kill_guests` (`sudo kill.sh <run_id>`) between blocks, exactly like `conformance.rs`. |
| 6 | Reusability | A durable, **reusable benchmark framework** — not a one-off script. Declarative registry, versioned provenance-stamped store, single entry point, regression mode. |
| 7 | Docker network mode | **`--network host`** for the cross-boundary network tests (fair engine compare; not penalized by NAT). |
| 8 | Run budget | **Quick profile is the default** (`just bench`); full run behind `--full`. |
| 9 | Disk target | Scratch dir on the internal-SSD case-sensitive APFS volume. |
| 10 | CI | **On-demand only**; track dated baselines, no blocking gate. |

### Host of record

Apple **M4 (Mac16,12)**, **4 performance + 6 efficiency cores** (10 total), **32 GB** RAM, **macOS 26.6**. Docker engine **29.5.2**, native **linux/arm64** (LinuxKit kernel ~6.12, glibc 2.41). Carrick exposes **perf-cores only** (`hw.perflevel0.logicalcpu = 4`). Disk target volume `/Volumes/CaseSensitive` verified **Internal / Solid State / Apple Fabric (NVMe) / case-sensitive APFS / 2.0 TB**.

---

## 2. The hard constraint

**Carrick (HVF) and Docker (LinuxKit VM) must never run concurrently during a timed sample.** They contend for the same physical perf-cores and skew timing-sensitive measurements. This is already enforced for correctness as a three-phase gate in `crates/carrick-cli/tests/conformance.rs:1205-1210` (all-carrick → all-docker → classify). **The perf runner inherits and tightens this:** all timed samples are serial (`n_workers=1`), carrick and docker disjoint in wall-clock by construction — never a fan-out, never interleaved.

---

## 3. Harness architecture — extend the proven machinery

All three independent design lenses (measurement-science, systems-attribution, pragmatic-MVP) chose to **extend `conformance.rs`** rather than build a parallel harness. Settled.

New test entry point: **`crates/carrick-cli/tests/perf_runner.rs`** plus a **`crates/carrick-cli/tests/perf_support/`** module tree (`cases`, `stats`, `metric`, `provenance`, `invoke`), reusing the proven `conformance.rs` patterns:

- a per-binary serialization lock — *as built*, its own `PERF_LOCK` rather than `CONFORMANCE_LOCK` (the two suites are separate test binaries, so they cannot share an in-process mutex; the cross-process `fd-lock` shared with conformance is the deferred hardening in §9),
- a per-sample run id `cr-perf-{pid}-{seq}` (monotonic, never reused) stamped into `CARRICK_RUN_ID`,
- `scoped_kill_guests(run_id)` via `scripts/sudo/kill.sh` (matches `carrick:<run_id>` proctitle),
- the `CASE_DEADLINE` watchdog (pgid kill on timeout),
- `scripts/build-probes.sh` (static-musl probe build),
- the macro oracles `scripts/cpython-parity.py` / `ltp-baseline.py`.

**The one deliberate departure:** timed samples run **serial adjacent-pair**, not the gate's fan-out. For each `(workload, rep)`: run carrick-sample → cooldown → docker-sample → cooldown. `fan_out_indexed` is reused **only** for the untimed warmup/correctness dry-run. Rationale: the two numbers divided into the thesis ratio (`carrick/docker`) must share a thermal state; adjacency cancels drift, and serial execution makes the hard constraint structurally true at single-comparison granularity — while letting the right DTrace script attach to exactly one carrick invocation.

### Reusable-framework layer (decision 6)

- **Declarative case registry** — in `perf_support/cases.rs`. *Phase 0 ships a single `PerfCase` struct* (`probe`, `dimension`, `workload`, `metric_key`, `unit`); later phases may add per-dimension fields/structs as the disk/fork/thread workloads need them. A workload = data (probe binary, metric key, labels). Adding a workload or dimension is a data edit, not a harness rewrite.
- **Append-only JSONL store with provenance** — `docs/perf-results/<date>-<dim>.jsonl`, one row per `(workload, engine, lane, rep-set)`, stamping: carrick git SHA, image **OCI digest** (pinned; run aborts on drift), host facts, fs mode, CPU pin, `nproc`-validated flag, thermal label, `run_quality`, and `run_id`. Same shape/spirit as the existing `docker-oracle.jsonl`. **Committed** (not gitignored) so baselines are durable and cross-machine comparable.
- **Single entry point** — `just bench` → `scripts/measure-perf.sh` → `cargo test -p carrick-cli --test perf_runner`. Self-skips when Docker / HVF / signed binary absent (like `just conformance`). Supports `--quick` / `--full` / `--dimension <d>` / `--filter <glob>`.
- **Regression mode** — `scripts/measure-perf.sh --baseline <file>` diffs a fresh run against a stored baseline row and flags deltas, reading the same store the advocacy report renders from.
- **`.bench-scratch/`** (gitignored) holds the disk bind-mount target; `docs/perf-results/` stays committed.

---

## 4. Measurement protocol

| Knob | Decision |
|---|---|
| **Ordering** | Serial **adjacent-pair** A/B: carrick-sample then docker-sample for the *same* workload, temporally adjacent. Fixed workload order (variance attributable to contention, not sequencing). This is the gate's `run_one_probe` serial-tail pattern (`conformance.rs:1047-1062`) scaled to N reps. |
| **Reps** | Tiered by jitter: **micro N=10** (drop 2 warmup → stats over 8), **macro N=5** (drop 1 → stats over 4). **Adaptive:** if post-warmup `stddev/median > 10%`, auto-extend to 15 / 8 and flag the row `NOISY`. |
| **Warmup** | One **untimed** correctness+cache-priming dry-run per workload (validates carrick and docker produce equivalent output AND warms L3 + APFS buffer cache + ARP), then discarded. `fan_out_indexed` parallelism is permitted **only here**. |
| **Statistics** | Report **p50 + p95 + min**, never mean (thermal spikes skew it). **IQR** = Q3−Q1 as the quality marker. Parity band = ratio ∈ **[0.8, 1.25]**. |
| **What's timed (3 columns, never collapsed)** | **(a) WALL cold** = `Instant::now()` spawn-to-exit, includes the ~265 ms boot+teardown — the honest `carrick run X` cost. **(b) GUEST-ONLY** = USDT lifecycle `phase4 FIRST_VCPU_RUN` .. `phase5 VM_DESTROY_BEGIN` delta — boot-subtracted per-op cost (the thesis number). **(c) WARM** = `run -d` once + N× `exec` — daemon-amortized, the fair head-to-head vs Docker's warm daemon. Micro primary metric is the tool's own **in-guest JSON** (`fio -j`, `iperf3 -J`, ping-pong probe self-timer); WALL is only a sanity cross-check. Docker reports one WALL number (boot tax ≈ 0). |
| **CPU normalization (hard fail-fast gate)** | `CARRICK_EXPOSED_CPUS=4` (forwarded via `--forward-env`), `docker --cpus=4`. **Before each pair, assert `nproc==4` inside *both* guests** (`host_facts.rs:133/158` confirm the override is real) or the rep is `INVALID` and excluded. The vCPU cap (~64) is reported as a **separate axis** for fork/thread, not normalized away. |
| **Thermal** | `pmset -g thermlog` sampled before+after each pair, logged as a metadata column. 30 s idle baseline; 15 s cooldown between samples, 30 s between workloads. **Discard + resample** any pair whose two halves throttle differently. Per-row label: `STABLE` / `THROTTLE_FLAG`. No active fan control (realistic). Time-of-day is **not** pinned — the per-pair thermal-discard rule is relied on instead. |

> **Tooling traps to honor:** `carrick trace --trace-out` is broken (`sweep-perf.md:70`) — read lifecycle deltas from the DTrace script *stdout* (`trace-bootfork.d` / `trace-lifecycle.d`), not `--trace-out`. The signed binary must be built via `just build` (plain `cargo build` strips the hypervisor entitlement → `HV_DENIED`). `ld64` only (not `lld`) so USDT probes fire.

---

## 5. Per-dimension plan

DISK + NETWORK are thesis-core; FORK + THREAD are characterization.

### 5.1 Disk — split into two axes (the in-repo data forbids a blanket "disk win")

**5.1a Bulk seq/IOPS (thesis-favorable).** `fio` sequential read (256 MiB) and 4 KiB random-read IOPS over the `--fs host` bind-mount on `.bench-scratch`. Use a **portable ioengine (`psync`/`libaio`)** for the parity number; treat **io_uring as a separate async-architecture axis** (carrick may not implement it — that's an honest architectural gap, not a thesis falsification). Plus `dd` buffered cross-check.
- *Prediction:* parity-or-win on seq (native host FD + shared APFS buffer cache vs Docker virtiofs); may lose rand-IOPS to Docker's in-kernel async.
- *Diagnosis if it loses:* `trace-read-buffers.d` host-pread/guest-read ratio (>1.1 = bounce-buffer amplification ⇒ IMPLEMENTATION); io_uring-absence confirmed via `carrick trace` ⇒ ARCHITECTURE (actionable: io_uring bindings / batched pread).

**5.1b Metadata (the honest exception).** stat ×10k, readdir ×1k, `glob('/usr/lib/**', recursive=True)` deep-tree — run with **`CARRICK_FAST_FS` 1 vs 0 A/B** to isolate the fast-path contribution.
- *Prediction:* loses (documented ~162× stat, ~84× readdir, ~440× glob; ~16× with fast-fs). Mechanism: cap-std ~291 host `open()` per guest `open()` (no `openat2`/`RESOLVE_BENEATH` on macOS).
- *Diagnosis — prove the mechanism, don't just report the loss:* `glob-openat-drill.d` gives the host-open/guest-open ratio. fast-fs ON still >100× ⇒ fast path not engaging = IMPLEMENTATION bug (named call-site in `fs_backend.rs`). ~291× OFF dropping with ON ⇒ mechanism confirmed as designed. **Kill:** glob >80 s with fast-fs ON + `--fs host` ⇒ fast-fs broken, escalate before trusting any disk number.

**Macro:** `python3 -m compileall /usr/lib/python3`, `du -sh /usr`, `tar xzf` (bulk-dominated), LTP fileio subset, cpython `test_glob` re-timed via `cpython-parity.py`.

### 5.2 Network — the strongest thesis-core proof, two topologies

**Topology A — in-guest loopback** (server + client in one guest over `127.0.0.1`): isolates the loopback *syscall-translation* path. Network mode is moot here. carrick folds `127/8` to host loopback; Docker uses the container's in-VM loopback.

**Topology B — cross-boundary** (a macOS-host-side client → server in the guest): the true **no-bridge thesis** test — carrick binds a real host socket (zero VM hop); Docker crosses virtio-net. Docker runs `--network host` (decision 7) so the comparison isolates VM-boundary cost from NAT cost. *Threat to verify in implementation:* Docker Desktop for Mac host-networking routes through the VM — confirm the topology actually exercises the boundary as intended.

**Micro:**
- `iperf3 -c 127.0.0.1 -t 10 -P 1 -J` — **TCP_STREAM** loopback (Topology A) → Mbps. Expect carrick wins/ties.
- **TCP_RR** 1-byte request/reply latency p50/p95/p99 — the **marquee number**. Tool: an in-repo ping-pong probe (matches the `conformance-probes` pattern, no `netperf` packaging dependency, and works host↔guest for Topology B); `netperf TCP_RR` as an alternative where available. carrick's syscall-trap round-trip vs Docker's hypervisor-per-syscall round-trip.
- 100-fd echo server, ~10k msg/s — **epoll fan-out**, exposes carrick's O(n) per-`epoll_wait` re-poll (`net.rs` `poll(fd,1,0)` per ready fd).

**Macro:** `wrk`/`ab` vs busybox httpd; `iperf3 -P 4`; Go-net + Node async-IO conformance images (reuse `docker/go-conformance`, `docker/nodejs-conformance`).

- *Diagnosis:* TCP_RR carrick slower → `trace-go-net.d` + count `poll(fd,1,0)` per `epoll_wait` (O(n) re-poll confirmed ⇒ ARCHITECTURE, actionable: single `kevent`; `epoll-kqueue-plan.md` exists). TCP_STREAM low → host-`sendto`/guest-`sendto` ratio >1.1 = bounce-buffer ⇒ IMPLEMENTATION (`sendmmsg`/iov batching). **Kill:** carrick loses loopback TCP_STREAM with *no* sendto amplification ⇒ the no-bridge advantage isn't materializing, investigate before claiming a network win.

### 5.3 Forks (characterization)

`perf_fork_storm`: fork+exec `/bin/true` loop on the **docker-compatible run path** (not `run-elf`). Report forks/sec and ms/fork for **cold** (incl. 265 ms boot+teardown) vs **warm** (`run -d` + `exec`, per-exec ~5.7 ms fork).
- *Prediction:* loses cold (boot dominates, ~1.5–4 runs/s); warm collapses boot to one-time → per-exec competitive. Real HVF cost (`trap.rs:3955-4016` `mincore`+memcpy, MAP_SHARED not COW).
- *Diagnosis:* `trace-bootfork.d` decomposes boot / fork / teardown. Exclude the known MT-fork wedge probes (`GATE_SKIP`, `conformance.rs:69`). Not a thesis kill (5–10× expected).

### 5.4 Threads (characterization)

`perf_thread_scale`: spawn N = 1,2,4,8,16,32,48,64,96,128 threads each doing a futex-counter loop; plot wall vs N and futex-wake latency vs N.
- *Prediction:* matches Docker at N≤4 (both pinned to 4); super-linear above 4 (64-shard `FutexTable` vs kernel load-balance); **cliff at N>64** (HVF vCPU cap; `spawn_clone_thread` blocks).
- *Diagnosis:* cliff at N<64 → verify `nproc==4`/`sched_getaffinity` honored; `trace-futex.d` for shard-hold time. Not a thesis kill.

---

## 6. Verdict schema — "prove or diagnose"

Each row in the final table states:

- **engine ratio** = `carrick_guest_only_p50 / docker_p50` (the thesis number),
- **cold WALL ratio** (boot tax shown separately, honestly),
- **verdict** ∈ { THESIS-WIN | PARITY | DIAGNOSED-LOSS },
- **mechanism** ∈ { ARCHITECTURE (unavoidable) | IMPLEMENTATION (fixable, named call-site) },
- **kill-flag** if a gate tripped.

**Thesis is PROVEN** iff: disk-seq ratio in parity band or better, AND network TCP_STREAM ratio ≤ 1.0 (carrick wins/ties loopback), AND TCP_RR competitive *or* its loss diagnosed to the named O(n) epoll re-poll. The two acknowledged thesis-core losses (disk metadata, rand-IOPS) **do not falsify** the thesis *iff* each is diagnosed to a named, mechanism-confirmed call-site and labelled ARCHITECTURE-or-IMPLEMENTATION.

**A loss is thesis-FALSIFYING only if** it is unexplained (no mechanism), or flips sign vs a where-carrick-should-win prediction with no diagnosis.

**Kill-criteria (operational):** (1) `nproc≠4` either engine → rep INVALID. (2) thermal level steps mid-pair → pair discarded+resampled. (3) image OCI digest drift → run ABORTED. (4) glob >80 s with fast-fs ON + `--fs host` → disk numbers UNTRUSTED. (5) post-warmup `stddev/median >10%` after adaptive-N → row `NOISY`, ratio reported with IQR band not a point claim. (6) MT-fork wedge / manythreads SEGV → that workload `GATE_SKIP`, noted, never silently averaged. **Aggregate kill:** >2 thesis-core dims showing unexplained >2× carrick loss ⇒ benchmark INVALID, debug before claiming anything — advocacy never overrides an unexplained contradiction.

---

## 7. Phasing (smallest credible result first)

0. **~1 day** — shared pinned image + serial A/B driver (reusing `CONFORMANCE_LOCK`/`case_run_id`/`scoped_kill_guests`) + **NETWORK TCP_RR** end-to-end. One row: carrick vs docker RR latency p50/p95 with the CPU-normalization assertion. Proves the harness *and* the most quotable thesis claim.
1. **Thesis-core completion** — disk seq + metadata-storm (fast-fs A/B + `glob-openat-drill.d`) + TCP_STREAM + epoll-fanout. Minimum set that stands as the advocacy-but-honest result.
2. **Rigor hardening** — adaptive-N, thermal discard/resample, guest-only boot-subtraction (`trace-bootfork.d`), WARM carrick lane (`run -d` + `exec`).
3. **Characterization** — fork storm + thread scaling sweep (excluding `GATE_SKIP` wedge probes).
4. **Macro realism + reporting** — re-time cpython/LTP/Go/Node oracles; `measure-perf.sh` CSV + markdown verdict table.

---

## 8. Deliverables

- `crates/carrick-cli/tests/perf_runner.rs` — `perf_gate()`: serial A/B driver, reuses lock/run-id/cleanup/deadline, p50/p95/IQR collector, adaptive-N, CPU-norm fail-fast validator, `pmset` thermal sampler + discard/resample.
- `crates/carrick-cli/tests/perf_cases.rs` — case structs; `measure_carrick_cold` / `measure_carrick_warm` (`run -d`+`exec`) / `measure_docker`; lifecycle-USDT boot subtraction; JSON emitter with `run_quality` + image digest.
- `conformance-probes/src/bin/{perf_disk_seq,perf_disk_rand_iops,perf_disk_small_create,perf_disk_meta_storm,perf_net_tcp_stream,perf_net_tcp_rr,perf_net_epoll_fanout,perf_fork_storm,perf_thread_scale}.rs` — static-musl, in-guest JSON self-timing, built via `scripts/build-probes.sh`.
- `docker/perf-benchmark/Dockerfile` — single shared arm64 `ubuntu:24.04` + `fio`/`iperf3`/`stress-ng`/`findutils`/`coreutils`/`python3` (+ ping-pong probe), OCI-digest pinned.
- `scripts/measure-perf.sh` — orchestrator; attaches per-dimension DTrace for the diagnosis lane; emits CSV + markdown verdict table (cold WALL / warm / guest-only / docker columns, ratio, ARCHITECTURE-vs-IMPLEMENTATION, kill-flags); `--baseline` regression-diff mode.
- `just bench` recipe (quick default, `--full`/`--dimension`/`--filter`).
- `docs/perf-strategy.md` — the shipped strategy doc (this design, trimmed to an in-tree reference).
- `docs/perf-results/` — dated, provenance-stamped baseline JSONL rows (committed).
- `.gitignore` += `/.bench-scratch/`.

---

## Results (running log)

| Dimension / workload | Metric (direction) | carrick | docker | Winner | n | Verdict |
|---|---|---|---|---|---|---|
| network / tcp_rr (loopback) | p50 latency µs (lower=better) | 19.2–20.9 | 23.4–23.7 | **carrick ~1.2×** | 4–8 | THESIS-WIN |
| network / tcp_stream (loopback bulk) | throughput MB/s (higher=better) | 4,338 | 22,156 | **docker ~5.1×** | 4 | DIAGNOSED-LOSS (bounce buffer) |
| disk / stat_storm (8-deep path) | p50 stat µs (lower=better) | 1,188 | 0.46 | **docker ~2,589×** | 4 | DIAGNOSED-LOSS (cap-std re-walk) |

Host: Mac16,12 (M4, 4P+6E), macOS 26.6, Docker 29.5.2, linux/arm64, `nproc=4` enforced both engines, image digest pinned. All ratios are carrick/docker; "Winner" is the fold-difference of the better engine.

**What this says about the thesis.** carrick's "no extra bridge/vhost" advantage is real and shows up exactly where the cost is *per-operation latency*: it **wins loopback TCP_RR by ~18–14%** (and with a tighter, lower-tail distribution) because it folds 127/8 to host loopback and issues Darwin `sendto`/`recvfrom` directly, while docker's loopback crosses the LinuxKit guest-kernel net stack with a hypervisor round-trip per syscall. But the advantage is **offset by two carrick *implementation* costs** wherever volume dominates — both predicted, both now *diagnosed to a named call-site* rather than left as mysteries:
- **Bulk throughput — docker ~5.1×** (carrick 4.3 GB/s vs 22 GB/s). Mechanism: carrick coalesces guest iovecs and **memcpy's through a bounce buffer on every send/recv** (`net.rs`); docker's in-kernel loopback is zero-copy. This is *implementation*, not the architecture — the fix is `sendmmsg`/iovec batching to remove the per-call copy.
- **Metadata — docker ~2,589×** (carrick 1.19 ms vs 0.46 µs to `stat` an 8-deep path). Mechanism: carrick's **cap-std per-component `openat` re-walk** (no `openat2`/`RESOLVE_BENEATH` on macOS) amplifies with depth; docker does one in-kernel VFS walk. This is the thesis's honest exception, now quantified — and it scales with path depth, so the 8-level case is far worse than the documented ~162× single-level `stat`.

Net: the **"no-abstraction → IO wins" thesis holds for latency-bound small ops and is contradicted for bulk/metadata by carrick-side implementation overhead** — exactly the prove-or-diagnose split the benchmark was built to surface. Both losses point at concrete, fixable call-sites.

### Optimization log (diagnose → fix → re-measure)

**2026-06-02 — bulk-throughput copy (commit `1577b26`).** A `carrick trace` of `tcp_stream` (count-only D script to avoid dynvar drops; then timed `sendto`/`recvfrom`) showed the hot path is `sendto`(25,207)/`recvfrom`(36,278) at a **1:1** guest→host syscall ratio (no amplification), with `sendto` ≈ **59 µs/call**. Reading the copy primitive revealed `read_guest_bytes`/`write_guest_bytes` used a **byte-at-a-time `read_volatile` loop** (`trap.rs:1508/1521`) — ~33 µs of that 59 µs — because the volatile byte loop can't vectorize (the volatility is required: guest RAM is `MAP_SHARED`, a non-volatile read racing a guest write is language-level UB). Fix: widen the volatile unit to `usize` words on the guest side (aligned word-volatile + byte head/tail), plain unaligned ops on the private host buffer — preserves the UB guarantee at ~8× fewer guest accesses. **Result: `tcp_stream` carrick 4.3 → 8.9 GB/s (+106%), gap to Docker 5.1× → 2.4×.** Control: `stat_storm` unchanged (+0.9%, it's path-walk-bound), confirming the fix is targeted at the copy. Residual gap is HVF trap-per-syscall + the kernel's own loopback copy; **Fix B (zero-copy `sendto`/`recvfrom` via host iovecs into guest-mapped memory, validated writable)** would chase the rest. ⚠️ This touches a core memory primitive used on every guest↔host transfer; an exhaustive alignment/length unit test was added, but the full differential conformance suite should be run before this lands in a standalone runtime PR.

**2026-06-02 — zero-copy `sendto`/`recvfrom` (Fix B).** Removed the bounce buffer entirely on the socket hot path: a new `GuestMemory::host_ptr_for_read/write` returns the host VA of a guest buffer **iff the whole range is one contiguous mapped region** (`mapping_for_range`; for recv, `validate_guest_write_range(.., true)` so a read-only mapping falls back to the checked copy → EFAULT, not a kernel write through a raw ptr). The `sendto`/`recvfrom` handlers send straight out of / `recvfrom` straight into guest memory, falling back to the (word-fast) copy for multi-region or non-writable buffers. Safe because `blocking_io`'s op is `FnOnce` — an EAGAIN re-dispatches the whole handler, so the pointer never outlives a lock-releasing wait, and the issuing vCPU is quiesced during the op. **Result: `tcp_stream` carrick 8.9 → 16.4 GB/s; gap to Docker 2.4× → 1.32×** (full progression **4.3 → 8.9 → 16.4 GB/s, 3.8× total**, from 5.1× behind to near-parity). Controls held (`stat_storm` 1197 µs, `tcp_rr` ratio ~0.82 — both untouched). **Validated:** 6 differential socket/bulk probes MATCH, an exhaustive `volatile_copy` unit test, and the **full conformance suite green** (`4 passed; 0 failed`). Residual 1.32× is the architectural floor (HVF trap-per-syscall + the kernel's own socket-buffer copy). Harness note: `perf_*` probes are now excluded from the conformance gate (non-deterministic timing output), and the pre-existing host-saturation flake `pidnsinitreap` was quarantined to the serial lane.

---

## 9. Threats to validity

- **Docker Desktop host-networking on Mac** routes through the VM — verify Topology B actually exercises the boundary (§5.2).
- **io_uring** unsupported under carrick would make any io_uring fio engine fail or fall back — pin a portable engine for parity; measure io_uring as its own axis, not silently.
- **`--fs host` amplification** can dominate even bulk I/O if the workload touches many paths — keep bulk-I/O workloads path-shallow so the metadata axis stays separate from the throughput axis.
- **Thermal headroom varies with ambient** on a quiet M4 — the per-pair discard rule is the guard; cross-day comparisons should check the `STABLE`/`THROTTLE_FLAG` column before trusting deltas.
- **Warm-lane fidelity** — `run -d`+`exec` exists, but confirm `exec` reuses the resident guest's address space (true daemon amortization) rather than re-bootstrapping.
- **Page-cache cross-priming** — serial adjacent-pair plus per-workload cooldown mitigates, but cold-cache disk numbers need an explicit cache-drop or first-touch discard per pair.
- **Cross-test-binary engine overlap (deferred hardening).** `perf_gate` serializes via an in-process `PERF_LOCK`, and the conformance suite via its own `CONFORMANCE_LOCK` — but these are separate test *binaries*/processes, so a `cargo test -p carrick-cli`/`--workspace` run (with the signed binary + Docker + built probes all present) could run `perf_gate` and a conformance case concurrently, violating the never-co-run rule. In practice this never happens: the benchmark is invoked only as `just bench` (= `cargo test --test perf_runner perf_gate`), and conformance only as `just conformance` (= `--test conformance`); the two never co-run. The structural fix is a **cross-process advisory file lock** (`fd-lock`, already a workspace dependency) on a shared lockfile (e.g. `target/.carrick-engine-exclusive.lock`) acquired by BOTH `perf_gate` and every conformance `#[test]` entry point. Deferred from Phase 0 to avoid modifying the proven conformance gate in the harness-bring-up commit; land it as a small, separately-verified follow-up.
