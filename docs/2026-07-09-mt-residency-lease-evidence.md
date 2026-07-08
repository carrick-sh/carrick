# MT Residency-Lease + Pump-Stop Evidence

Date: 2026-07-09

This follows `docs/2026-07-08-hvf-residency-e4-evidence.md`. E4 measured the HVF
residency ceiling and proved that single-threaded blocked processes already
release their whole VM, leaving a named residual: multi-threaded blocked
processes keep the VM alive (`reclaim_park` destroys only the vCPU) and so remain
capacity-bound at the per-VM ceiling. This campaign (plan
`docs/superpowers/plans/2026-07-08-mt-residency-lease-and-pump-stop.md`, branch
`codex/architecture-evidence-gates`, base `9baacd44`, code-final HEAD
`b01e18e2`) implements the multi-threaded lease and lands the pump-stop fork
speedup, told honestly including the two iterations measurement refuted along the
way.

Every number below is verbatim from the task reports and the logs under
`target/conformance/logs/mt-lease/` and `docs/perf-results/2026-07-08-*.jsonl`.
Where a design was refuted, it is marked refuted.

## Host

Same quiet host as E4; the per-VM ceiling (127) is machine- and OS-specific and
can move on a macOS update.

| Field | Value |
|---|---|
| ProductVersion | macOS 27.0 (build 26A5378j) |
| hw.model | Mac16,12 |
| hw.memsize | 34359738368 (32 GiB) |
| CPUs | 10 |

## Verdict

1. **Pump-stop fork speedup landed.** The event-driven `SignalPump` stop
   (`eadee537`) cut phase-52 from **1305 µs → 57 µs**, taking `perf_fork` p50
   from ~3.4 ms (E4 final 3687 µs) to the **2.06–2.14 ms** band (~40% off the
   fork path). Its designated regression witness — the CPython
   `multiprocessing_forkserver` suite — is **green (397 tests)**.

2. **The multi-threaded VM lease is default-on** (`CARRICK_MT_VM_LEASE`, default
   on; `=0` reverts to vCPU-only MT parks). It reached its final shape through
   three iterations, two of which measurement refuted:
   - **(a) Eager last-unparked whole-VM release** (`557af3c9`..`09f1cc3e`) —
     correct under max-capability review, but attribution
     (`.superpowers/sdd/task-6-regression-attribution.md`) identified it as the
     single root cause of `wait_pipe_pingpong` **+867%** and the forkserver
     wedge. **Refuted as the shipping hot-path design.**
   - **(b) Slice-tick deferred upgrade** (`53b08b3c`) — restored the hot paths
     (`wait_pipe` p50 **42.333 µs**, was 354) but churned a fully-parked idle
     process ~**1 VM release+rebuild/sec**. **Refuted as the idle-fleet design.**
   - **(c) Churn damping + `VcpuParkClass` fd-backed veto** (`4a69a02c`, probe
     `e5ae5a71`/`b01e18e2`) — final: post-release slice stretch 2 s→4 s→8 s
     drops idle churn to ~**1 cycle / 8 s**; a non-empty fd-set park vetoes the
     release so fd-waiters are never stranded. All acceptance green.

3. **A latent cross-process signal bug was flushed out and fixed.** The lease's
   timing change exposed that `drain_xsignals_for_tid` published a
   process-directed ring signal **pinned to whichever tid ran the drain**. When a
   `pause()`-sibling won the drain race, the parent's SIGUSR1 stranded in that
   sibling's masked pending set and the main thread's `sigwait` re-parked forever.
   The lease only changed timing (the pre-lease `red-sigwait` stall was the same
   bug). Fix = process-directed publication (`e22b689f`) + provenance-gated
   siginfo stores (`5f1a5bea`), both mutation-test pinned.

4. **Gates green.** `procladder_mt` @160 GREEN (4.3 s, both booleans);
   `procladder` @160 stays green (<1 s); `procladder_mixed` MATCH. The
   `procladder_mixed` mutation check **refuted** the stranding prediction: with
   the veto neutered, 8/8 released VMs and the parked pipe-read fd-waiter woke
   correctly — plain fd waits provably survive release. The veto is retained on
   cluster-B grounds alone; its cost is capacity, never correctness.

5. **`MAP_SHARED` reacquire budget de-provisionalized.** `desc_count = 14 + 1`
   per guest `MAP_SHARED` mapping; replay is desc-linear and sane even at 270
   descriptors. E4's provisional caveat is now bounded.

6. **Regression battery green** except the two recorded, understood follow-ups
   (kill-switch fatal shape; the veto's `procladder_mixed`@160 capacity cost).

7. **Load sensitivity is treated as first-class** (dedicated section below), per
   the 2026-07-08 user ruling.

## Changes / Instrumentation

- **Pump-stop** (`eadee537`): event-driven `SignalPump` stop (bounded cv-wait,
  10 ms re-wake, 2 s detach) replaces the busy phase.
- **MT lease core** (`557af3c9` + `dd0b7c55` signal-wait park + `2a96e020`
  fork-path EAGAIN degradation + `09f1cc3e` mark-after-destroy review fix):
  `park_vcpu_for_blocking_wait` releases the whole VM on the last-unparked MT
  park; the first waker claims (`unpark_vcpu`) under the topology lock and
  union-replays the process-global `alias_registry`
  (`rebind_shared_wait_state_mt`). Kill switch `CARRICK_MT_VM_LEASE`.
- **Slice-tick redesign** (`53b08b3c`): the release is deferred to a
  `try_upgrade_vm_release_on_slice_tick` in the slicing wait arms (WaitOnSignals,
  WaitOnSleep) after ≥1 full parked ≥1 s slice; the first tick is always
  vCPU-only, so ping-pong-hot waits never reach an upgrade.
- **Veto + churn damping** (`4a69a02c`): `VcpuParkClass{FdBacked, ReleaseSafe}`
  in `carrick-thread`; `park_vcpu_classified`; the under-lock re-check is
  `all_other_parked_release_safe` (any parked fd-backed thread vetoes release).
  Current-tick-full-slice requirement + progressive 2 s→4 s→8 s post-release
  stretch (reset on any real wake).
- **xsig routing** (`e22b689f` + `5f1a5bea`): `drain_xsignals_for_tid` publishes
  process-directed (`mark_process_signal_pending` + `process_pending_siginfos`
  queue); provenance-gated `take_*_from` so a host-slot delivery can't steal a
  queued process-directed payload. Deterministic pinning tests + mutation check.
- **Probes**: `procladder_mt` (children spawn a second thread, then the main
  thread `sigwait`s); `procladder_mixed` (`e5ae5a71`/`b01e18e2`: a
  `nanosleep(3s)`-looping release-safe sibling + a pipe-`read()` fd-backed main);
  `FORK_SHARED_MAPS` knob on `clonebasic` (`c77e7030`); the `perf_fork`,
  `perf_fork_exec`, `perf_wait_pipe_pingpong`, `perf_epoll_pipe_loop`,
  `perf_futex_pingpong` perf probes.

## Measurements

### Pump-stop fork speedup (Task 1, `eadee537`)

| Metric | Before | After | Evidence |
|---|---:|---:|---|
| fork phase-52 | 1305 µs | **57 µs** | Task 1 report |
| `perf_fork` p50 | ~3.4 ms (E4 final 3687 µs) | **2076 µs** (Task 1) → **2059 µs** (Task 6 `2c4538e2`) → **2140.916 µs** (`53b08b3c`) → **2107.875 µs** (`4a69a02c`) | logs below |

Witness: CPython `multiprocessing_forkserver` SUCCESS (see §Battery). The
speedup is stable across the whole stack (all four `perf_fork` readings land in
2.06–2.14 ms; target ≤2.5 ms; E4 final was 3.69 ms).

### The design arc (Task 5 + Task 6 attribution)

**(a) Eager release — refuted as the hot-path design.** Attribution
(`.superpowers/sdd/task-6-regression-attribution.md`) traced every campaign
regression to the ONE branch `557af3c9` added: last-unparked MT park →
whole-VM teardown + first-waker rebuild ≈ +300 µs/iteration.

| probe | HEAD default (eager) | `CARRICK_MT_VM_LEASE=0` | BASE `9baacd44` | 07-06 baseline |
|---|---:|---:|---:|---:|
| `perf_wait_pipe_pingpong` p50 | **354.083 µs** | 41.71 µs | 41.88 µs | 36.6 µs |
| `perf_epoll_pipe_loop` p50 | 56.042 µs | 50.58 µs | 50.92 µs | 33.2 µs |
| `perf_futex_pingpong` p50 | 33.416 µs | — | — | 33.625 µs |

Kill-switch cross-check is the attribution evidence: `wait_pipe` **41.71 µs**
with the lease off = BASE **41.88 µs**; the forkserver suite ran **SUCCESS,
397 tests, 95 s** with the lease off vs a 300 s TIMEOUT with it on
(`scratchpad/fs-killswitch.log`). Pump-stop (`eadee537`) and the xsig fixes
(`e22b689f`/`5f1a5bea`) were **exonerated** — the forkserver passes with the
lease off at a HEAD that already contains them. `min=33.5 µs` at HEAD-default
proves the no-park fast path itself survived; the cost is only the whole-VM
teardown when the last unparked thread parks.

**(b) Slice-tick upgrade — refuted as the idle design** (`53b08b3c`). Hot paths
restored, but a fully-parked idle process resumed its vCPU every slice tick and
churned ~1 VM release+rebuild/sec:

```
perf_wait_pipe_pingpong  p50=42.333µs  p95=52.084µs  min=35.333µs   (was 354µs eager)
perf_futex_pingpong      p50=31.291µs  p95=37.625µs                 (flat)
perf_fork                p50=2140.916µs  p95=2224.834µs             (≤2.5ms)
procladder_mt @160 lease-ON → ladder_forked_all=true ladder_children_ok=true rc=0
cpython forkserver → SUCCESS, 4/4 files, 397 tests, 1 min 40 s, rc=0
```

**(c) Churn damping + fd-backed veto — final** (`4a69a02c` + `b01e18e2`):

```
carrick-runtime: 539 passed    carrick-thread: 29 passed (incl. the veto test)
perf_wait_pipe_pingpong  p50=41.750µs   (≤50µs)
perf_futex_pingpong      p50=31.333µs   (flat)
procladder_mt @160 lease-ON → ladder_forked_all=true ladder_children_ok=true  (4.3 s wall)
procladder_mixed → MATCH  (ladder_forked_all=true ladder_children_ok=true)
cpython forkserver → SUCCESS, 4/4 files, 397 tests, 1 min 39 s
perf_fork                p50=2107.875µs  (≤2.5ms)
```

Idle churn converges to ~1 rebuild / 8 s (2 s→4 s→8 s stretch); at a 128-VM
fleet that is ~0.5% of one core (re-review accepted).

### The latent xsig stranding bug (Task 6 debug, `e22b689f`/`5f1a5bea`)

Bisect (lease ON, `09f1cc3e`, 10-core host): GREEN through N=20; N=24
**intermittent** (stall then green on retry); N=32 stalls **~60% of attempts**;
N=160 the original red. Threshold ≈20–24 is far below the 120-permit / 127-VM
ceilings — disqualifying admission exhaustion. Kill-switch (`CARRICK_MT_VM_LEASE=0`)
at N=32 also stalled 2/3 runs → the whole-VM release is exonerated; the trigger is
the signal-wait park (`dd0b7c55`) amplifying a pre-existing delivery race. Core
statics of three stuck children: `PROC_PENDING = 0x0` (the wake was never
published process-wide). Smoking-gun trace (child 92912): the drain ran on tid
92913 (the sibling), signal blocked for the drainer; the main thread's `sigwait`
re-dispatched every second with empty own-tid and process pending sets.

Fix re-runs (fixed, signed binary): N=32 × 8 → **8/8 GREEN**; N=160 → GREEN 2 s;
`scripts/run-probe.sh procladder_mt` → MATCH; killrt/killtarget/killgroup/
killchld/forksigwalk → MATCH ×5; 539/539 tests. Mutation check: reverting the
drain hunk to drainer-pinning + restoring the ungated fallback fails both new
pinning tests at their intended assertions; real code restored, both pass.

### Gates (Task 5 / Task 6)

| Gate | Result | Evidence |
|---|---|---|
| `procladder_mt` @160 lease-ON | GREEN, both booleans, rc=0, **4.3 s** | `procladder_mt-160-green-20260708-103016.log` (2 s at `2c4538e2`) |
| `procladder_mt` @160 Docker | identical booleans (MATCH) | `procladder_mt-160-docker-20260708-103029.log` |
| `procladder` ST twin @160 | GREEN, <1 s | `procladder-160-green-20260708-103044.log` |
| `procladder_mixed` (gate N) | MATCH | `scripts/run-probe.sh procladder_mixed` |
| `procladder_mixed` @160 (RECORDED, not gated) | ~10.5 s, post-fork `HV_NO_RESOURCES` fatals | Task 5 report (veto capacity cost) |

**`procladder_mixed` mutation check — expectation refuted, recorded honestly**
(`b01e18e2`): with the veto neutered (`all_other_parked_release_safe` treating
FdBacked as ReleaseSafe; temporary, reverted before the verification runs) plus a
temporary release marker, **all 8/8 children printed a whole-VM release** inside
the parent's window — the probe genuinely drives the release attempt — but it
stayed **GREEN**: the pipe-read fd-waiter woke via **kqueue + claim + union
rebuild** even with the VM released from under it. So a plain parked pipe read is
**not** a stranded-reader detector; cluster B's wedge needs a richer shape (the
wedged manager was an epoll/AF_UNIX server). The veto is retained on cluster-B
grounds (real, un-root-caused, observed under the eager design); the probe stands
as the attempt-vs-veto mechanism gate and the future wake-correctness proof if
fd-backed releases are ever enabled. Its cost is capacity, never correctness.

### `MAP_SHARED` replay pricing (Task 3, `c77e7030`)

E4 proved `desc_count` flat at 14 for anonymous-private guest VA fragmentation
and left the `MAP_SHARED`-file reacquire budget **provisional**. The
`FORK_SHARED_MAPS` sweep de-provisionalizes it:

| `FORK_SHARED_MAPS` | desc_count | replay parent µs | replay child µs |
|---:|---:|---:|---:|
| 64  | 78  | 217 | 612 |
| 256 | 270 | 351 | 731 |

`desc_count = 14 + 1` per guest `MAP_SHARED` mapping (both parent and child).
Replay grows front-loaded ~0.5–2.3 µs/descriptor (351/731 µs at 270 descs); host
`fork(2)` stayed flat. **The lease reacquire budget is desc-linear and sane even
at 270 descriptors** — the union-replay a first-waker MT rebuild pays scales with
the process's own shared-mapping count, not pathologically.

### Regression battery (Task 6, HEAD `2c4538e2`; final numbers at `4a69a02c`)

- **LTP six-pack — 6/6 MATCH**: `ltp-clone08` 5/5, `ltp-kill10` 1/1,
  `ltp-ptrace06` 48/48, `ltp-waitpid06` 1/1, `ltp-waitpid08` 1/1,
  `ltp-waitpid10` 1/1.
- **`go-os_exec` — MATCH 86/86**.
- **CPython `multiprocessing_forkserver` — SUCCESS**, 4/4 files, 397 tests,
  1 min 39 s (was a 300 s TIMEOUT under the refuted eager design; the pump-stop
  witness).
- **`perf_futex_pingpong` FLAT**: 33.416 µs (`2c4538e2`), 31.291 µs
  (`53b08b3c`), 31.333 µs (`4a69a02c`) — the 31.3–33.4 µs band.
- **`perf_wait_pipe_pingpong` 41.750 µs** ≈ BASE 41.88 / lease-off 41.71.
- **`perf_fork` 2107.875 µs** (2.11 ms); **`perf_fork_exec` 7229.666 µs**
  (7.23 ms, below the E3/E4 final 8.464 ms).
- Tests: `carrick-runtime` 539 passed, `carrick-thread` 29 passed,
  `carrick-vmm-hvf` 82 passed; clippy no new warnings.

## Load Sensitivity

Per the 2026-07-08 user ruling (`feedback_load_sensitivity_first_class.md`),
load-coupled behavior is a first-class architectural concern — identified and
planned, never dismissed as flake. This campaign is a case study; every
load-coupled observation is classified into one of three buckets.

**(i) Real races that load exposes (highest-value fixes).**
- The **xsig process-directed stranding bug** manifested only at **N≥24** under
  scheduling pressure (~60% at N=32); a genuine permanent wake loss in the
  cross-process signal drain. Load was the bug-finder. Fixed (`e22b689f`/
  `5f1a5bea`).
- The **eager-lease forkserver wedge** was load-shaped: a forkserver-descended MT
  manager (pid 38232, orphaned ppid=1, AF_UNIX server, both threads parked in
  WaitOnFds) stopped making progress once all its threads parked and the VM was
  released. Root cause bracketed to `557af3c9`'s whole-VM release; not yet
  root-caused at the wake-gap level (Next Track (b)).

**(ii) Correctness-load-bearing time assumptions.** Slice loops, sleeps,
timeouts, and backoff cadences tuned for unloaded hosts. The lease's own churn
damping (2 s→4 s→8 s) and the first-tick-vCPU-only rule are examples of replacing
a timing assumption with an event-gated one. Inventory of constants that carry
correctness weight under load: `SIGNAL_WAIT_SLICE` 50 ms,
`SHORT_TIMED_WAIT_RECLAIM_CUTOFF` 250 ms, permit PARK 25 ms / MAX_WAIT 10 s, the
60 s admission bounds, pump-stop 2 s / 10 ms, vcpu-permit backoff 1–50 ms, and
probe `sleep(1)` guards. `skip-resume-on-idle-TimedOut` (Next Track (c)) is the
event-based endpoint for the slice-tick timing.

**(iii) Measurement contamination.** The 07-06 perf baseline (sha `0572d32f`) is
124 commits before campaign BASE `9baacd44`; comparing across it brackets a
regression to a window, not a commit. Docker control rows stayed flat (or faster)
across the campaign, so the two carrick perf deltas were **not** environmental;
BASE-worktree runs reproduced the kill-switch numbers exactly, confirming the
attribution rather than a load artifact.

**The 4 load-coupled gate flakes** — `epollforkeventfd`, `fifoforkeof`,
`ptyforkreopen`, `syscallregpreserve` — all **MATCH standalone** (one run each at
HEAD) and fail only under the full parallel 456 s probe gate. Cluster A1's
+300 µs-per-blocked-wait under gate load is the plausible amplifier (unproven;
re-run the gate after (b) lands rather than bisect a 456 s run).

**Pre-existing debt marked non-regression** (tracked separately, keeps core work
moving — user ruling): `execthreads`, `keydeny`, `mlock2`, `rlimitroundtrip` all
DIFF at BASE `9baacd44` with byte-identical diff text to HEAD, and the
`perf_epoll_pipe_loop` **p50 50.9 µs** baseline (BASE 50.92 µs = HEAD-lease-off
50.58 µs; the +69% vs the 07-06 33.2 µs happened pre-campaign in the
`0572d32f..9baacd44` epoll-ET/kqueue window). The campaign's lease adds only the
epoll **p95** tail (62→222 µs). None are campaign regressions.

**Follow-up campaign:** deliberate **load-injection test lanes** — run the gates
under synthetic host load — because load has repeatedly been the best bug-finder
here. Harness it rather than suppress it.

## Verification Commands

- `procladder_mt` @160 gate (lease on, one shot, RUN_ID-scoped):
  `base64 -i .../procladder_mt | CARRICK_RUN_ID=$RUN_ID CARRICK_HVF_ADMISSION_TRACE=1 timeout 180 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p'`
  — Result: `ladder_forked_all=true ladder_children_ok=true`, rc=0, 4.3 s.
- `scripts/run-probe.sh procladder_mt` / `procladder` / `procladder_mixed` — Result: MATCH.
- Kill-switch cross-check (attribution): prefix `CARRICK_MT_VM_LEASE=0` — Result:
  `wait_pipe` 41.71 µs (= BASE); forkserver SUCCESS 397/95 s; @160 bounded ~21 s
  trap-fatal family (recorded, the resident-VM accounting follow-up).
- `perf_fork` / `perf_fork_exec` / `perf_wait_pipe_pingpong` /
  `perf_futex_pingpong` via the perf probes under `carrick run ... --raw --fs host`
  — Result: 2.11 ms / 7.23 ms / 41.75 µs / 31.3 µs.
- LTP six-pack + `go-os_exec`:
  `target/release/carrick-conformance --workers 1 --no-image-refresh --suite ltp-clone08 --suite ltp-kill10 --suite ltp-ptrace06 --suite ltp-waitpid06 --suite ltp-waitpid08 --suite ltp-waitpid10`
  and `--suite go-os_exec` — Result: 6/6 MATCH, 86/86 MATCH.
- `FORK_SHARED_MAPS` sweep:
  `sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf .../clonebasic -- 0 0 <shared_maps>'`
  — Result: desc 78 @64 / 270 @256; replay 217/612 → 351/731 µs.
- Tests: `cargo test -p carrick-thread -p carrick-runtime -p carrick-vmm-hvf --lib`
  — Result: 539 / 29 / 82 passed.

No carrick guest/probe and Docker oracle command were run concurrently;
`scripts/run-probe.sh` sequences its carrick and Docker phases.

## Next Track

The lease is default-on and green. The remaining ledger, each with its evidence
pointer:

1. **Resident-VM accounting for the admission gate.** `fork_admission_check`
   probes the **permit** budget, but a vCPU-only park releases its permit while
   keeping its VM — so permits **under-report hard-slot residency**. TWO measured
   manifestations: (a) the **kill-switch fatal shape** — with the lease off,
   parked MT children free permits but pin the ~127-VM ceiling; the pre-fork gate
   passes trivially and the child's post-fork `hv_vm_create` fatals after 10 s
   backpressure (18–20× `trap engine failed`, rc=125;
   `.superpowers/sdd/task-6-debug-report.md` kill-switch verdict); (b) the
   **`procladder_mixed`@160 veto capacity cost** — the fd-backed veto retains VMs,
   so a flat 160-fork storm exhausts the hard ceiling (~10.5 s, post-fork
   `HV_NO_RESOURCES` fatals; `.superpowers/sdd/task-5-report.md`). Fix = make fork
   admission see resident VMs (a cross-process resident-VM counter in the permit
   region), not just live vCPUs. Not landed; the lease-on default path is green,
   so this is robustness debt, not a gate blocker.

2. **Cluster-B root cause via a richer-shape probe** (epoll/AF_UNIX manager,
   forkserver-descended). This is the **named gate for ever lifting the fd-backed
   veto** (recorded reviewer condition): `procladder_mixed` proved a plain pipe
   read survives release, so it is *not* the veto-removal evidence — the wedged
   shape was an epoll/AF_UNIX server (pid 38232 in the attribution cores,
   `cr-attr-fs.38232.core`). Root-cause the lost progress of a fully-parked
   VM-released MT process of that shape first.

3. **`skip-resume-on-idle-TimedOut`** as the zero-churn endpoint — named in code
   at `try_upgrade_vm_release_on_slice_tick`, deliberately not attempted this
   campaign (deadline/EINTR bookkeeping risk). Replaces the slice-tick timing
   with an event.

4. **xsig ring `target_tid` field** for cross-process thread-directed sends. The
   ring slot carries no target tid, so `tkill`/`tgkill` are now explicitly
   process-directed (correct for the stranding fix, but a durable thread-directed
   cross-process send wants a `target_tid` slot; `e22b689f` review minor).

5. **The epoll-ET p50 pre-existing debt window** (`0572d32f..9baacd44`, 124
   commits dense with epoll-ET/kqueue work — `348ae189` "park epoll et on kqueue
   edges" et al.). `perf_epoll_pipe_loop` p50 33.2 → 50.9 µs happened there, not
   in this campaign; separate bisect if the +17 µs matters.

## epoll-ET p50 debt window: bisect result

Bisected the `perf_epoll_pipe_loop` p50 regression (follow-up item 5 above)
across `0572d32f..9baacd44` with `scripts/perf/bisect-epoll-p50.sh`
(median of 3 one-shot runs, threshold 42 µs, quiet host, probe binary built
once at HEAD; 7 predicate evaluations, zero skips).

**Culprit: `37dd7c20` "fix(runtime): rearm epoll et across dup reads".**

| commit | p50 median |
| --- | --- |
| `0572d32f` (window good endpoint) | 31.58 µs |
| `d1276b47` (culprit~1) | 32.21 µs |
| `37dd7c20` (culprit) | 56.21 µs |
| `9baacd44` (window bad endpoint) | 54.71 µs |

Single-commit jump: 32.2 → 56.2 µs at the culprit; flat on both sides.

**Mechanism hypothesis** (from the culprit diff, `dispatch/net.rs`
`epoll_rearm_after_io` + `dispatch/mod.rs` `wake_parked`): the dup-sibling
correctness fix put the whole ET bookkeeping pass on every successful read.

1. `read_consumed = positive || zero || eagain` — before the culprit, a
   positive read took no rearm path at all (only 0/EAGAIN did). Now every
   1-byte pipe read in the loop enters the epoll interest pass under the
   epoll description write lock.
2. The pass became O(interest set) per read with heavy per-candidate work:
   for each target fd it clones the open-description `Arc`, then scans
   *every* key in the interest map calling `host_fd_for_poll` (fd-table
   lookup) and `open_file` + `Arc::ptr_eq` per candidate, collecting into a
   fresh `Vec` — even when there are no dup registrations.
3. macOS `wake_parked()` stopped being a no-op: each rearm now fires the
   shared-kqueue user wake (`trigger_user(0)`), an extra host kevent per
   read plus a spurious wake/re-park round trip for any parked waiter.

**Decision: defer — named follow-up, not a one-liner.** The commit is a
load-bearing correctness fix (Go netpoller dup-read rearm,
TestServerNoWriteTimeout); reverting any leg regresses that. The perf fix is
a fast path, not a tweak: skip the sibling scan when the interest map has a
single entry (or the target fd is its only self-match), hoist the
per-candidate fd-table lookups, and fire `wake_parked` only when a latch
actually changed. Follow-up name: **epoll-rearm-fastpath** (target: recover
p50 ≤ ~35 µs with the dup-sibling regression tests still green).
