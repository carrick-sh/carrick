# Next Track Follow-ups Evidence

Date: 2026-07-09

This follows `docs/2026-07-09-mt-residency-lease-evidence.md`. That campaign
shipped the multi-threaded VM lease default-on and left a five-item Next Track
ledger. This campaign (plan
`docs/superpowers/plans/2026-07-09-next-track-followups.md`, branch
`codex/architecture-evidence-gates`, base `0ac568a0`, code-final HEAD
`36c8b8cb`) lands those five items: (1) resident-VM accounting for the fork
admission gate, (2) the cluster-B root-cause reproducer, (3)
skip-resume-on-idle, (4) an xsig-ring `target_tid`, (5) the epoll-ET p50
pre-existing-debt bisect.

Every number below is verbatim from the task reports
(`.superpowers/sdd/task-{1,2,3,4}-report.md`,
`.superpowers/sdd/task-{5,6}-report-nt.md`,
`.superpowers/sdd/cluster-b-rootcause.md`) or from the Task-7 re-verification
battery run for this document. Where a design was refuted or a result was
negative, it is marked so. **Two Task-7 battery divergences are recorded
honestly in §Verdict and §Load Sensitivity; the campaign closes
DONE_WITH_CONCERNS, not clean.**

## Host

Same quiet Mac as the predecessor campaign. The per-VM HVF residency ceiling
(measured 127 in E4) is machine- and OS-specific and can move on a macOS
update; it is also churn-sensitive (see §Load Sensitivity).

| Field | Value |
|---|---|
| ProductVersion | macOS 27.0 (build 26A5378j) |
| hw.model | Mac16,12 |
| hw.memsize | 34359738368 (32 GiB) |
| CPUs | 10 |

## Verdict

1. **Resident-VM accounting landed** (Tasks 1+2, `6c10df75` + `06185576`). The
   fork admission gate now probes a second generation-stamped atomic slot table
   (one slot per live HVF VM) in addition to the vCPU-permit table, closing the
   permit-under-reports-residency blind spot. As landed, the two fatal shapes
   the predecessor recorded — the lease-off @160 `trap engine failed` storm
   (rc=125) and the `procladder_mixed`@160 post-fork `HV_NO_RESOURCES` fatal —
   both now degrade to guest `EAGAIN` (rc=0, no `trap engine failed`): kill-switch
   shape EAGAINed at 10.037 s / 199 parks, mixed shape at 10.010 s / 198 parks
   (Task 2 report, one-shot each).

2. **Skip-resume-on-idle landed** (Task 4, `fe895f39`). An idle parked
   `TimedOut` tick now re-arms the wait without the resume/re-park round trip.
   Measured idle churn dropped **11 → 2** `hv_vm_create` over one bounded 20 s
   two-thread idle-sleep run (external dtrace). Six load-bearing invariants
   preserved (§Measurements).

3. **xsig ring carries `target_tid`** (Task 3, `375b068c`). Cross-process
   `tkill`/`tgkill`/`rt_tgsigqueueinfo` now land thread-directed instead of
   process-directed. Ring layout change is compat-safe (same-binary fork-shared
   ring); thread-directed sends to an exited tid are discarded (Linux
   discard-at-thread-exit semantics). Known limitation retained: the ring is
   still addressed by host pid, so cross-process delivery to a NON-main thread
   is still not reachable (Next Track 2).

4. **Cluster-B: measured negative, veto NOT lifted** (Task 5, `dd4ce618` +
   `7dfbc56e` + `6b9d225b`). The `procladder_epollmgr` probe drove a
   veto-neutered whole-VM release under epoll/AF_UNIX fd-backed waiters;
   marker-instrumented, 4/4 children released their VM and both epoll fd-waiters
   woke correctly. Baseline + three escalations (EPOLLET / double-fork orphan /
   alive-pipe-EOF) all GREEN. This does **not** reproduce the cluster-B wedge,
   so the fd-backed veto stays the shipping default. The named gate for ever
   lifting it is unchanged: reproduce the real 3-process
   `wait_proc_exit_kqueue` + poll-forkserver + epoll-manager chain from the
   forkserver cores (Next Track 1).

5. **epoll-ET p50 debt bisected** (Task 6, `56af638d` + `36c8b8cb`). Culprit is
   `37dd7c20` "fix(runtime): rearm epoll et across dup reads"; decision **defer**
   with named follow-up `epoll-rearm-fastpath`. The full bisect record lives in
   the predecessor doc's §"epoll-ET p50 debt window: bisect result" — it is not
   duplicated here.

6. **DONE_WITH_CONCERNS — two Task-7 re-verification divergences.**
   - **`just ci` doc lane RED.** The `doc` recipe (rustdoc under `-D warnings`)
     fails with two `rustdoc::private_intra_doc_links` errors in
     `probe_fork_vm_admission`'s doc comment: a link to `probe_vm_slot_budget`
     (trap.rs:1915, introduced THIS campaign by Task 2 `06185576`) and a link to
     `ADMISSION_PERMIT_MAX_WAIT` (trap.rs:1895, PRE-EXISTING from the prior
     campaign `2a96e020`, present at base `0ac568a0`). `fmt`, `clippy`, `build`,
     `test`, and `cargo deny` all passed; only `doc` failed. Deterministic, not
     load-coupled. No prior task ran the doc lane, so both slipped through. Fix
     is mechanical (demote both intra-doc links to plain code spans, or scope an
     `#[allow]`); it touches no runtime behavior. **Named follow-up 6.**
   - **`procladder_mt`@160 lease-ON gate did NOT reproduce GREEN.** Three
     one-shot runs on a quiet, settled host (fresh `CARRICK_RUN_ID` each) all hit
     the 180 s `timeout` (EXIT_CODE=124) with an empty ladder and a single trace
     line `resident-vm slot budget 120 full; park #1`. The exercised code path
     (knob unset → `all_other_parked_release_safe`) is **byte-identical** to Task
     4's `fe895f39`, which recorded this gate GREEN in ~4.3 s days earlier;
     Task 2 recorded it GREEN too. Classified host-capacity / measurement-coupled
     with a real robustness sub-finding (§Load Sensitivity). **Named follow-up 7.**

7. **Functional + perf surface otherwise green** (Task-7 battery): 5-crate lib
   tests pass; four `procladder*` probes MATCH; LTP six-pack 6/6 MATCH;
   `go-os_exec` 86/86 MATCH; CPython forkserver 323/323 MATCH (the lease's
   designated witness — the closest functional analogue to the cluster-B
   forkserver shape, and GREEN); perf floors hold except one marginal jitter
   sample (§Measurements).

8. **Load sensitivity is treated as first-class** (dedicated section below), per
   the 2026-07-08 user ruling.

## Changes / Instrumentation

- **Resident-VM slot table** (Task 1, `6c10df75`):
  `crates/carrick-kernel/src/arena.rs` gains an append-only `vm_slots:
  PermitSection` in `ArenaLayout` (`ARENA_VERSION` 2 → 3, so any stale arena
  file fails closed on attach); `crates/carrick-vmm-hvf/src/trap.rs` gains
  `vm_residency_region()` over that section, `VM_RESIDENCY_LOCAL_KEY = u64::MAX`
  (one VM per process), `record_vm_resident()` / `record_vm_released()` wired at
  the single create funnel and all four `hv_vm_destroy` sites + execve rebuild,
  fork-child local reset, cooperative release, and a `DualReclaimSource` so the
  ONE vcpu-permit reaper reclaims dead owners' slots in BOTH tables.
  **Design:** occupancy is DERIVED from generation-stamped slots and
  death-reclaimed by the reaper — there is no free-running counter to drift.
  Recording is unconditional (budget = `MAX_SLOTS`); the budget is enforced only
  by the fork-admission PROBE. Flock fallback has no residency table (both
  record helpers no-op when `!atomic_permit_enabled()`).
- **Fork gate probes residency** (Task 2, `06185576`):
  `probe_fork_vm_admission` now also calls `probe_vm_slot_budget(vm_residency_region(),
  GLOBAL_VM_CEILING=120, FORK_VM_PROBE_MAX_WAIT)` when `atomic_permit_enabled()`.
  **`FORK_VM_PROBE_MAX_WAIT = 10 s` is deliberately the SAME bound as the
  post-fork `hv_vm_create` `HV_NO_RESOURCES` backpressure MAX_WAIT** — the
  pre-fork gate never waits longer than the post-fork path it replaces, so a
  pinned fleet degrades to guest `EAGAIN` in ~10 s instead of a rc=125 trap
  fatal; lease-driven releases land at the 2–8 s slice ticks, inside the bound.
  The `probe_fork_vm_admission` doc paragraph was rewritten from "KNOWN BLIND
  SPOT" to "CLOSED BLIND SPOT" (this rewrite introduced the doc-lane failure in
  §Verdict 6).
- **skip-resume-on-idle** (Task 4, `fe895f39`):
  `crates/carrick-runtime/src/vcpu_loop/mod.rs` `WaitOnSignals` and `WaitOnSleep`
  arms each gain an inner re-wait loop; an idle parked `TimedOut` tick re-arms
  the wait with the vCPU still parked (no resume/re-park round trip). The two
  "deliberately NOT attempted" doc comments were flipped to "now implemented";
  the superseded pre-wait upgrade/stretch code was deleted. New probe
  `conformance-probes/src/bin/mtidlesleep.rs` (two threads, each a 20 s
  `nanosleep`) is the churn witness (its own report is a boolean; the real
  witness is external dtrace on `hv_vm_create`).
- **xsig `target_tid`** (Task 3, `375b068c`):
  `crates/carrick-signal-core/src/xsig.rs` `XSigSlot` gains
  `target_ns_tid: AtomicI32` (0 = process-directed); `xsig_enqueue`/
  `xsig_drain_for_self` carry it. `drain_xsignals_process_directed`
  (signal.rs) routes `target_ns_tid != 0` per-thread (mirroring
  `route_thread_signal`'s publish half — per-tid siginfo + pending mark +
  waiter kick), discarding on unresolved tid. Send sites pass the tid for
  `rt_tgsigqueueinfo`/`tkill`/`tgkill` and 0 elsewhere (`rt_sigqueueinfo`,
  `pidfd_send_signal`, adopted-SIGCHLD, mq-notify). A new
  `current_registry_liveness` accessor on `carrick-thread` resolves the tid
  through the same process-global `CURRENT_REGISTRY` `/proc` synthesis already
  uses (no ctx threading). **Ring-layout compat argument:** the ring is a
  same-binary fork-shared region — parent and child run the identical binary,
  so a `#[repr(C)]` field append is always ABI-consistent across the fork
  boundary; there is no cross-version reader.
- **cluster-B knob + probe** (Task 5, `dd4ce618` + `7dfbc56e` + `6b9d225b`):
  test-only `CARRICK_MT_VM_LEASE_FDBACKED=1` (default OFF, truthy only on `"1"`)
  swaps `try_release_vm_mt`'s re-check from the shipped class-aware
  `all_other_parked_release_safe` to the class-blind `all_other_parked`
  (`all_other_vcpus_parked` promoted to `all_other_parked`; thin alias kept).
  New probe `conformance-probes/src/bin/procladder_epollmgr.rs`: N three-threaded
  children — thread A owns an epfd on an AF_UNIX `SOCK_STREAM` listener
  (fd-backed), main owns an epfd on a socketpair peer + notify pipe (fd-backed),
  thread B loops `nanosleep(3s)` (release-safe, drives the slice-tick upgrade
  attempt). The knob and the class-blind query have NO shipping caller.
- **epoll p50 bisect** (Task 6, `56af638d` + `36c8b8cb`):
  `scripts/perf/bisect-epoll-p50.sh` (median-of-3, threshold 42 µs) + the
  bisect-result section appended to the predecessor evidence doc.

## Measurements

### Resident-VM accounting (Tasks 1+2)

The two previously-fatal 160-fork storm shapes now degrade to guest `EAGAIN`
(Task 2 report, one-shot each, recorded):

| Shape | Before (predecessor) | After (this campaign) |
|---|---|---|
| lease-off @160 kill-switch | rc=125, 18–20× `trap engine failed` | `ladder_forked_all=false ladder_children_ok=true`, rc=0; EAGAIN at 10.037375542 s / 199 parks, 0 `trap engine failed` |
| `procladder_mixed`@160 veto | ~10.5 s post-fork `HV_NO_RESOURCES` fatals, report lost | `ladder_forked_all=false ladder_children_ok=true`, rc=0; EAGAIN at 10.010566291 s / 198 parks, 0 `trap engine failed` |

`perf_fork` p50 at Task 2 = **2088.625 µs** (≤ 2.5 ms; the gate adds one atomic
scan per fork). Unit tests: `carrick-vmm-hvf` 86 passed (was 82; +4 from the
resident-VM tests), `carrick-kernel` 18 passed.

### skip-resume-on-idle (Task 4)

Idle-churn witness (`mtidlesleep`, external dtrace on `hv_vm_create`, one
bounded 20 s two-thread idle-sleep run, `--fs host` per the brief's fallback):

| | `hv_vm_create` count | boolean |
|---|---:|---|
| RED (HEAD pre-change) | 11 | `slept_both=true` |
| GREEN (post-change) | 2 | `slept_both=true` |

The six preserved invariants (Task 4 report, verified against final code, one
line each): (1) `exec_replaced_thread_exit()` still returns without resuming
inside the inner loop; (2) `Interrupted`/`Ready`/`Errno` always break to the
single `resume_vcpu_after_blocking_wait`; (3) finite-deadline expiry breaks →
resume → `EAGAIN`/`Returned{0}` exactly as before; (4) `reclaim.is_none()`
(short-wait class) keeps the old per-tick re-dispatch cadence; (5) the deferred
whole-VM upgrade attempt + 2 s→4 s→8 s stretch relocated into the inner loop
with byte-identical gating; (6) `sleep_interrupt_pending` still polled every
tick, so a sleeper still drains process-directed signals.

Task 4 battery: `perf_fork` p50 2097 µs; `perf_wait_pipe_pingpong` p50
42.083 µs; `perf_futex_pingpong` re-measures 31.167 / 31.334 µs (first sample
34.125 µs classified jitter on the untouched `WaitOnSharedWord` arm); CPython
forkserver MATCH 323/323; LTP six-pack 6/6 MATCH; `carrick-runtime` 542 tests.

### xsig `target_tid` (Task 3)

`carrick-signal-core` 35 tests (incl. the new
`enqueue_carries_target_tid_through_drain`); `carrick-runtime` 542 tests, incl.
3 new pinning tests (`ring_drain_routes_thread_directed_to_target_tid_only`,
`ring_drain_target_tid_zero_stays_process_directed`,
`ring_drain_discards_thread_directed_for_exited_tid`) and the two pre-existing
stranding-fix tests UNCHANGED and green. e2e: `killrt`, `killtarget`,
`killgroup`, `killchld`, `forksigwalk`, `procladder_mt` — MATCH ×6, plus
`rtsigqueueinfoxthread` MATCH. **Discard-at-exit semantics:** a thread-directed
send whose `target_ns_tid` resolves to no live thread is dropped (not
re-published process-directed), matching Linux discarding a thread's pending
signals at thread exit. **Non-main-thread routing limitation:** routing still
addresses the ring by host pid, so cross-process delivery reaches only tids the
target's registry has live — in practice tid == pid main threads. The
delivery side is now correct (lands thread-directed in the target); the
addressing side is unchanged, hence Next Track 2.

### Cluster-B experiment (Task 5) — durable record

`.superpowers/sdd/cluster-b-rootcause.md` is gitignored; this section is its
only durable home. Summary (not a wholesale paste):

**Gate shape (veto ON, shipping default):** `scripts/run-probe.sh
procladder_epollmgr` → MATCH (`mgr_forked_all=true mgr_children_ok=true`), run
twice, stable.

**Experiment matrix (veto NEUTERED, `CARRICK_MT_VM_LEASE_FDBACKED=1`,
one-shot each, fresh `CARRICK_RUN_ID`, `timeout 120`):**

| variant | result |
|---|---|
| baseline (committed probe) | GREEN, rc=0 |
| (i) EPOLLET on all three registrations | GREEN, rc=0 |
| (ii) double-fork orphan (ppid=1) | GREEN, rc=0 |
| (iii) inherited alive-pipe dup + parent EOF read | GREEN, rc=0 (incl. `mgr_alive_pipe_eof=true`) |

**Marker evidence (vacuousness check):** a temporary (never-committed)
`eprintln!` in `try_release_vm_mt`'s `Ok(true)` arm, one knob-ON run of the
committed baseline probe (RUN_ID `cr-clb-marker-63206`), printed **4 marker
lines, 4 distinct pids** = one whole-VM release per child (N=4), and the probe
still exited green. So the negative is **MEASURED, not merely reasoned**: every
child's VM was released while its two epoll fd-backed waiters were parked, and
both waiters woke correctly. Scope caveat: only the baseline shape was
marker-instrumented; the three escalations ran without the marker and inherit
this evidence via the shared machinery, but were not each independently
marker-verified.

**Conclusion:** honest measured negative. **The veto is NOT lifted.** A flat
two-level process shape (parent + N independent children, each with its own
epoll+listener and epoll+socketpair fd-backed waits) survives a veto-neutered
release — even with edge-triggering, orphaning, or an alive-pipe-EOF
dependency added. What it does NOT rule out is the real cores'
**three-process chain**: 38134 blocked in `wait_proc_exit_kqueue(pid=38136)` (a
process-exit wait, not an fd wait) on the forkserver; 38136 the forkserver
blocked in `poll_with_signal`/`fallback_poll` on `[listener, alive_r]` (a POLL,
not epoll); 38232 the orphaned epoll/AF_UNIX MT manager (the piece this probe
isolates). The reproducer never assembled that mixed-wait-primitive nesting
under one released-VM attempt — that is the un-ruled-out shape and the named
veto-lift gate (Next Track 1).

### epoll-ET p50 bisect (Task 6)

Culprit `37dd7c20` "fix(runtime): rearm epoll et across dup reads": a clean
single-commit jump 32.21 → 56.21 µs, flat on both sides (endpoints 31.58 /
54.71 µs). Decision **defer**, named follow-up `epoll-rearm-fastpath`
(single-entry fast path + hoist per-candidate fd lookups + fire `wake_parked`
only on actual latch change; target p50 ≤ ~35 µs with the culprit's regression
tests green). Full table, per-step medians, measurement conditions, and
mechanism hypothesis are in the predecessor doc's §"epoll-ET p50 debt window:
bisect result" (Task 6 appended them there, `56af638d`/`36c8b8cb`); not
duplicated here.

### Task-7 re-verification battery (HEAD `36c8b8cb`)

One-shot each, strictly sequential, nothing concurrent.

| Gate | Result |
|---|---|
| `cargo test --lib` ×5 crates | PASS — kernel 18, runtime 542, signal-core 35, thread 30, vmm-hvf 86 (0 failed) |
| `just ci` | **RED at `doc`** (rustdoc private-intra-doc-links ×2; fmt/clippy/build/test/deny all passed) — §Verdict 6 |
| `run-probe procladder` | MATCH (`ladder_forked_all=true ladder_reaped_all=true`) |
| `run-probe procladder_mt` | MATCH (`ladder_forked_all=true ladder_children_ok=true`) |
| `run-probe procladder_mixed` | MATCH (`ladder_forked_all=true ladder_children_ok=true`) |
| `run-probe procladder_epollmgr` | MATCH (`mgr_forked_all=true mgr_children_ok=true`) |
| `procladder_mt`@160 lease-ON | **TIMEOUT ×3** (EXIT_CODE=124, empty ladder, `resident-vm slot budget 120 full; park #1`) — §Verdict 6 / §Load Sensitivity |
| LTP six-pack | 6/6 MATCH — clone08 5/5, kill10 1/1, ptrace06 48/48, waitpid06/08/10 1/1 |
| `go-os_exec` | MATCH 86/86 |
| CPython `multiprocessing_forkserver` | MATCH 323/323 |
| `perf_fork` p50 | 2144.208 µs (≤ 2.5 ms) ✓ |
| `perf_fork_exec` p50 | 7975.541 µs (recorded; elevated vs predecessor 7229.666 — churned host) |
| `perf_wait_pipe_pingpong` p50 | 42.375 µs (≤ 50 µs) ✓ |
| `perf_futex_pingpong` p50 | 34.166 µs (0.166 µs over the 31–34 band — jitter, §Load Sensitivity) |
| `perf_epoll_pipe_loop` p50 | 51.542 µs (= the pre-existing ~51 µs debt Task 6 bisected) |

The **two EAGAIN-shape tests** (Task 2 Step 6: `CARRICK_MT_VM_LEASE=0`
`procladder_mt`@160 and `procladder_mixed`@160) were **NOT run in the Task-7
battery**: each is another 160-wide HVF storm, and the plan forbids looping
unthrottled HVF storms (WindowServer/Finder crash risk) while the no-retry rule
forbids piling storms after the @160 divergence. Their as-landed results stand
in the Task 2 report (both EAGAIN rc=0, quoted in §Measurements above).

## Load Sensitivity

Per the 2026-07-08 user ruling (`feedback_load_sensitivity_first_class.md`),
every load-coupled observation is classified into one of three buckets and
never dismissed.

**(i) Real races that load exposes.** None newly surfaced this campaign. The
predecessor's two (the xsig process-directed stranding bug; the eager-lease
forkserver wedge) were already fixed / bracketed. The `procladder_mt`@160
Task-7 timeout has a candidate real-robustness sub-finding inside it (see (ii)).

**(ii) Correctness-load-bearing time assumptions.**
- **The `procladder_mt`@160 lease-ON gate divergence.** Three one-shot runs on a
  quiet, settled host (loadavg ~1.7 on 10 cores, 79% memory free, zero leftover
  carrick processes, default per-process arena confirmed fresh) all timed out at
  180 s with an empty ladder and a single trace line
  `resident-vm slot budget 120 full; park #1`. Classification evidence:
  - The exercised code path (knob unset → `all_other_parked_release_safe`) is
    **byte-identical** to Task 4's `fe895f39`, which recorded this gate GREEN in
    ~4.3 s; Task 2's `06185576` recorded it GREEN too. The only diff `fe895f39
    → 36c8b8cb` in the lease hot path is Task 5's default-OFF knob and the
    `all_other_parked` rename (pure refactor, thin alias). A code regression is
    therefore essentially ruled out.
  - The most likely trigger is **host-capacity contamination**: this session
    ran multiple full workspace builds, four back-to-back docker probe cycles,
    and three SIGKILLed ~120-VM storms, and macOS reclaims HVF VMs from a killed
    process lazily — so the residency budget of 120 legitimately reads "full"
    against a host whose effective concurrent-VM capacity had degraded below it.
    The gate's correctness depends on the host clearing VMs fast enough for the
    lease's 2–8 s slice ticks to free residency slots, a host-capacity time
    assumption this contaminated host violated. This is the same
    class of first-class load sensitivity the predecessor's Load Sensitivity
    section flagged (HVF churn-sensitivity, per-VM ceiling that "can move").
  - **Real robustness sub-finding (bucket i candidate):** the trace shows only
    `park #1`, never Task 2's clean cadence of ~198 parks culminating in a 10 s
    `EAGAIN` bound-out. When the host genuinely cannot clear the residency
    budget, the fork gate did NOT visibly degrade to `EAGAIN` — the guest wedged
    instead. This may be the guest blocked waiting on host VM scheduling that
    never arrives rather than the gate's own bound-out failing, but it is
    unresolved and is recorded as Next Track 7. Deliberately NOT re-stormed to
    root-cause (safety + no-retry).
  - Countervailing evidence that the lease default path is healthy: the small-N
    `procladder_mt` MATCHed via `run-probe` in the same battery, and the CPython
    forkserver (the lease's designated witness, the closest functional analogue
    to the cluster-B forkserver shape) MATCHed 323/323.
- **`perf_futex_pingpong` p50 34.166 µs** — 0.166 µs over the 31–34 band. The
  `WaitOnSharedWord` (futex) arm is untouched by this campaign, so no regression
  is possible there; this is a jitter sample on a churned host (Task 4 saw the
  identical shape: a 34.125 µs first sample that re-measured to 31.167 /
  31.334 µs). Classified measurement.
- **`perf_fork_exec` p50 7975.541 µs** (vs predecessor 7229.666 µs) and
  **`perf_fork` 2144.208 µs** (vs Task 2/4 2088/2097 µs) — both elevated but
  `perf_fork` holds its ≤ 2.5 ms floor; the uplift tracks the churned host, not
  a code change. Classified measurement.

**(iii) Measurement contamination.** `perf_epoll_pipe_loop` p50 51.542 µs is
the pre-existing `37dd7c20` debt (predecessor baseline 50.9 µs), not a campaign
regression — Task 6 bisected it. The Task-7 perf numbers were taken after three
SIGKILLed HVF storms on the same host; the elevations above are read as host
contamination, not regressions, because the code paths they measure are
unchanged this campaign.

**Follow-up campaign (carried):** the deliberate **load-injection test lanes**
from the predecessor doc stay on the ledger (Next Track 5) — this campaign's
own @160 timeout is a fresh argument for harnessing host load rather than
hoping for a quiet host.

## Verification Commands

- Fork EAGAIN degradation (Task 2, as landed):
  `base64 -i .../procladder_mt | CARRICK_MT_VM_LEASE=0 CARRICK_RUN_ID=$RUN_ID timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p'`
  and the `procladder_mixed` variant — Result: `ladder_forked_all=false
  ladder_children_ok=true`, rc=0, EAGAIN ~10 s, 0 `trap engine failed`.
- Idle churn (Task 4):
  `sudo -n /usr/sbin/dtrace -q -n 'pid$target:Hypervisor:hv_vm_create:entry { @creates = count(); }' -c "target/release/carrick run-elf --raw --fs host .../mtidlesleep"`
  — Result: 11 (pre) → 2 (post).
- `scripts/run-probe.sh procladder` / `procladder_mt` / `procladder_mixed` /
  `procladder_epollmgr` — Result: MATCH ×4.
- `procladder_mt`@160 lease-ON (one shot, RUN_ID-scoped): as the predecessor's
  command — Result THIS BATTERY: TIMEOUT ×3 (EXIT_CODE=124), see §Load
  Sensitivity.
- Cluster-B experiment: prefix `CARRICK_MT_VM_LEASE_FDBACKED=1` on the base64
  `procladder_epollmgr` run — Result: GREEN (baseline + 3 escalations); 4/4
  marker-verified releases on the baseline.
- LTP six-pack + `go-os_exec` + forkserver:
  `target/release/carrick-conformance --workers 1 --no-image-refresh --suite ltp-clone08 --suite ltp-kill10 --suite ltp-ptrace06 --suite ltp-waitpid06 --suite ltp-waitpid08 --suite ltp-waitpid10`,
  `--suite go-os_exec`, `--suite cpython-multiprocessing_forkserver` — Result:
  6/6, 86/86, 323/323 MATCH.
- Perf: the five `perf_*` probes under `carrick run … --raw --fs host` — Results
  in §Measurements.
- Tests: `cargo test -p carrick-thread -p carrick-runtime -p carrick-vmm-hvf -p carrick-kernel -p carrick-signal-core --lib`
  — Result: 30 / 542 / 86 / 18 / 35 passed.
- Full gate: `just ci` — Result: RED at `doc` (§Verdict 6).

No carrick guest/probe and Docker oracle command ran concurrently;
`scripts/run-probe.sh` and `carrick-conformance` sequence their phases.

## Next Track

The five predecessor items landed (with the two DONE_WITH_CONCERNS divergences
above). The new ledger, each with its evidence pointer:

1. **Veto-lift decision, gated on a 3-process-chain reproducer.** Building the
   `wait_proc_exit_kqueue` (process-exit wait on another guest process) +
   poll-based forkserver + epoll/AF_UNIX manager chain from the real forkserver
   cores (`cr-attr-fs.38232` et al.), under one released-VM attempt. This — not
   `procladder_epollmgr`'s flat shape — is the recorded reviewer condition for
   ever treating fd-backed parks as release-safe. Evidence: §Measurements
   cluster-B; `.superpowers/sdd/cluster-b-rootcause.md`.

2. **xsig `target_tid` routing for NON-main-thread cross-process targets.** The
   delivery side lands thread-directed now; the ring is still addressed by host
   pid, so a cross-process send to a non-main thread is unreachable. Fix = a
   ring addressing scheme that carries the target thread's routing key.
   Evidence: §Measurements xsig; Task 3 report.

3. **flock-fallback path has no residency table.** `record_vm_resident` /
   `record_vm_released` no-op when `!atomic_permit_enabled()`
   (`CARRICK_HVF_ATOMIC_PERMIT=0`), and the fork gate skips the VM probe there
   — it keeps the historical permit-only gate. Out of scope this campaign;
   named so the gap is durable. Evidence: Task 1/Task 2 reports.

4. **`epoll-rearm-fastpath`** (Task 6 defer). Recover `perf_epoll_pipe_loop`
   p50 to ≤ ~35 µs: single-entry/self-match fast path skipping the sibling
   scan, hoist the per-candidate fd-table lookups, fire `wake_parked` only on
   an actual latch change — with `37dd7c20`'s dup-read regression tests still
   green. Evidence: predecessor doc §"epoll-ET p50 debt window: bisect result".

5. **Load-injection test lanes** (carried from the predecessor). Run the gates
   under synthetic host load, because load — including this campaign's own @160
   timeout — has repeatedly been the best bug-finder. Harness it rather than
   depend on a quiet host. Evidence: §Load Sensitivity.

6. **Fix the `just ci` doc lane.** Demote the two `probe_fork_vm_admission`
   intra-doc links (`probe_vm_slot_budget`, trap.rs:1915, THIS campaign;
   `ADMISSION_PERMIT_MAX_WAIT`, trap.rs:1895, pre-existing) to plain code spans
   or scope an `#[allow(rustdoc::private_intra_doc_links)]`. Mechanical, no
   runtime impact; blocks a clean `just ci`. Evidence: §Verdict 6. (A doc-lane
   check belongs in the per-task battery so this class stops slipping through.)

7. **Root-cause the `procladder_mt`@160 wedge under a genuinely-full host.** On
   a freshly-quiet host, confirm the gate returns to its Task-2/Task-4 GREEN
   (~4.3 s); if it does, the Task-7 timeout is confirmed host-contamination and
   this closes. If it reproduces green-fresh but the guest still wedges (only
   `park #1`, no `EAGAIN`) when residency is genuinely unclearable, that
   fork-gate-does-not-degrade-to-EAGAIN behavior is a real robustness bug to
   fix. Evidence: §Load Sensitivity (ii).
