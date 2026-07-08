# HVF Residency-Ceiling E4 Evidence

Date: 2026-07-08

This follows `docs/2026-07-08-hvf-fork-e3-evidence.md`. E4 characterizes the
HVF VM residency ceiling and its scaling behavior so the `WakeFromBlockingSyscall`
residency-lease design (Track 3, separate plan) can be written against measured
constraints rather than the strategy memo's predictions.

## Host

All E4 measurements are from one quiet host. The ceiling is machine- and
OS-specific, undocumented by Apple, and can move on a macOS update — re-running
Task 2's matrix after any OS bump is cheap insurance and the numbers below are
only valid for this configuration.

| Field | Value | Evidence |
|---|---|---|
| ProductName | macOS | `target/conformance/logs/hvf-residency-e4/host-info-20260707-213815.log` |
| ProductVersion | 27.0 | same |
| BuildVersion | 26A5378j | same |
| hw.model | Mac16,12 | same |
| hw.memsize | 34359738368 (32 GiB) | same |
| CPUs | 10 | same |

## Verdict

E4 answers the brief's five questions and **refutes the strategy memo's core
prediction** that blocked processes hold residency and stall workloads past the
soft budget. That prediction is false for single-threaded blocked processes:
carrick already releases the whole VM for them.

1. **Is the ceiling per-VM, per-vCPU, or memory-coupled? — PER-VM.**
   Exactly **127** VMs materialize in all five quiet-host configurations before
   `HV_NO_RESOURCES(0xfae94005)`, while `total_vcpus` scales 127 → 254 → 508
   (`vcpus_per_vm` 1/2/4) and `map_mib` scales 0 → 16 → 64. The ceiling never
   moves. It is a per-VM slot budget, not a system-wide vCPU budget and not
   memory-coupled. This **refutes the `trap.rs:761-775` comment** that calls it a
   "~126 system-wide vCPU budget": the earlier "~126" reading is superseded by
   five exact-127 quiet-host runs; why it read lower before is undetermined —
   plausibly a 128-slot machine-wide table with one slot consumed elsewhere,
   or the earlier measurement running with other live VM consumers (stray
   guests) on the host. The per-VM verdict is unaffected either way: it is
   per-VM at 127 on this host/OS, not per-vCPU nor system-wide-in-vCPUs.
   Multi-vCPU (multithreaded) processes do **not**
   consume extra ceiling budget; mapped memory is free with respect to the
   ceiling up to at least 64 MiB/VM (~8 GiB aggregate across 127 VMs).

2. **Sustained sequential create/destroy cost, and does it degrade over 200
   cycles? — CHEAP AND FLAT (slightly improving).** Create settles at ~32 µs
   median (25 µs min, one 859 µs cold-start outlier at iter 0), destroy at
   ~21 µs median (17 µs min, 48 µs max). Over 200 cycles the trend is a
   ~10-13% *improvement* first-50 vs last-50, i.e. no leak, no bloat. A
   lease reacquire pays tens of microseconds for the HVF create/destroy itself.

3. **Does guest VA fragmentation multiply stage-2 descriptors / replay cost? —
   NO, REPLAY-BOUNDED for anonymous-private fragmentation.** `desc_count` is
   flat at **14** across `FORK_MAPS` 0/256/1024 (up to ~2048 distinct guest
   region/protection boundaries), both parent and child, at every phase. Local
   replay stayed in the ~200-670 µs band (parent 209/210/324 µs; child
   599/611/671 µs), the small child drift tracking host `fork(2)` cost rising,
   not descriptor growth. carrick's host stage-2 descriptor set is a function
   of *its own* coarse region layout (code, rw-arena, guard, stacks, page
   tables), not of how the guest carves up its anonymous-private mmap arena. A
   lease reacquire needs no eviction bias against anonymous-private
   fragmented/mapping-heavy processes.

   This flat-14 result is proven only for anonymous-private guest VA
   fragmentation, which lives entirely inside carrick's arena and never adds
   host stage-2 descriptors. Guest `MAP_SHARED` FILE mappings are different:
   they DO grow the per-process mapping list (pushes at
   `crates/carrick-vmm-hvf/src/trap.rs:2995`, `:4233`, `:4319`, `:4524` — the
   dynamic MAP_SHARED-file alias registry at `trap.rs:415`), and shared-wait
   resume replays every entry in that list. A `MAP_SHARED`-file variant of the
   `FORK_MAPS` sweep is required follow-up before the lease plan fixes its
   reacquire budget; until then the reacquire budget below is **provisional**
   for shared-file-mapping-heavy processes.

4. **What happens when a workload exceeds the soft budget with blocked
   (non-exiting) children? — NO STALL. PREDICTION REFUTED.** At
   `PROC_LADDER_N=160` — 160 children all simultaneously alive (proven by
   `ladder_forked_all=true`) and blocked in `pause(2)`, i.e. 33 over the 127
   hard ceiling and 40 over the 120 soft budget — the probe **passes under
   carrick in under 2 seconds, rc=0**, matching the Docker oracle byte-for-byte;
   that is the pass evidence. With `CARRICK_HVF_ADMISSION_TRACE=1` set, the run
   also emitted **no** `HV_NO_RESOURCES` and **no** admission-trace lines,
   supporting but not load-bearing for the verdict. There is no plateau, no
   timeout, no permit-wait stall. The reason (verified in source,
   see below): a single-threaded process that blocks releases its **entire VM**.
   So the anticipated "fork #121 stalls in the unbounded permit wait" scenario
   **does not exist for single-threaded blocked processes**. `procladder@160` is
   therefore a **regression test** guarding existing behavior, not a red gate.

5. **Therefore, the residency-lease design constraints.** The lease already
   exists for the single-threaded case; the remaining design work is to extend
   it to the multi-threaded case (see Next Track). Measured parameters for that
   design:
   - **Eviction unit: whole VM** (question 1 — the ceiling is per-VM, so
     releasing a vCPU alone does not free a slot; the existing single-threaded
     path already destroys the VM, which is why it works).
   - **Reacquire budget: tens of µs of HVF create + ~200-670 µs stage-2 replay**
     (questions 2+3), bounded at 14 descriptors independent of guest VA
     fragmentation.
   - **Churn bound: flat / non-degrading over 200 cycles** (question 2) — a
     lease can release and reacquire repeatedly without accumulating cost.
   - **Acceptance test: `PROC_LADDER_N=160 procladder` MATCH** stays green as the
     regression guard; the red-first gate for the *new* multi-threaded scope is a
     `procladder-mt` variant (children spawn a second thread, then block) that
     must currently fail and pass after the lease extension.

## Instrumentation Added

- **Concurrent-ceiling matrix knobs** (commit `dbacff30`): the
  `hvf_fork_probe concurrent-ceiling <max> <hold_secs> <vcpus_per_vm> <map_mib>`
  probe gained the `vcpus_per_vm` and `map_mib` arguments so the ceiling can be
  swept against total-vCPU and mapped-memory pressure independently. Emits a
  single `=== CEILING ... ===` summary line plus `torn_down=<n>` on teardown.
- **`clonebasic` `FORK_MAPS` knob** (commit `c39c763f`): `argv[2]` / `FORK_MAPS`
  env creates N disjoint 64 KiB anonymous mappings (each carved from a 128 KiB
  span with the neighbor `munmap`'d so they cannot coalesce, alternating
  `PROT_READ`), touched one byte per page, to fragment the guest VA space
  without changing probe stdout. Read by `scripts/dtrace/fork-phases.d`'s
  existing `fork-rebuild` `desc`/`maps` fields.
- **`procladder` probe** (commits `41409fe7`, `77b593c3`): parent forks N
  children (`PROC_LADDER_N`, default 8, clamped 1..=1024), each parks in
  `pause(2)`; parent SIGKILLs and reaps all. Reports `ladder_forked_all` /
  `ladder_reaped_all`. Commit `77b593c3` rewrote the module doc comment from the
  now-refuted stall prediction to the measured residency-release framing.

## Measurements

### Ceiling matrix (Task 2)

STAMP `20260707-213815`. Sequential, `sleep 10` between runs, each under
`timeout 300`; every teardown reported `torn_down=127 children`; no stray
children between runs; the only error lines were the expected ceiling hits.

| Run | vcpus_per_vm | map_mib | total_vcpus | ceiling | first_create_us | last_create_us | failure | Evidence |
|---|---:|---:|---:|---:|---:|---:|---|---|
| 1 | 1 | 0 | 127 | **127** | 1242 | 230 | HV_NO_RESOURCES | `ceiling-v1-m0-20260707-213815.log` |
| 2 | 2 | 0 | 254 | **127** | 1401 | 329 | HV_NO_RESOURCES | `ceiling-v2-m0-20260707-213815.log` |
| 3 | 4 | 0 | 508 | **127** | 1524 | 375 | HV_NO_RESOURCES | `ceiling-v4-m0-20260707-213815.log` |
| 4 | 1 | 16 | 127 | **127** | 3044 | 1102 | HV_NO_RESOURCES | `ceiling-v1-m16-20260707-213815.log` |
| 5 | 1 | 64 | 127 | **127** | 7403 | 3779 | HV_NO_RESOURCES | `ceiling-v1-m64-20260707-213815.log` |

Reading: ceiling is per-VM (127 flat while total_vcpus 127→254→508). Memory does
not consume the ceiling but raises per-VM create latency ~3-4x at 16 MiB and
~10-15x at 64 MiB. Caveat: the probe's `create_us` window includes the `mmap`
call plus a one-store-per-16-KiB resident-touch loop over the mapped region
(thousands of zero-fill page faults at 64 MiB), so first-touch fault cost
dominates the m16/m64 numbers; this overstates what a lease reacquire would
pay, since reacquired memory is already host-resident and would not re-fault.
All logs under `target/conformance/logs/hvf-residency-e4/`.

### Sequential churn (Task 3)

`hvf_fork_probe recreate-loop 200 0`, exit 0, no stray processes.

| Metric | min µs | median µs | max µs | first-50 vs last-50 | Evidence |
|---|---:|---:|---:|---|---|
| create | 25 | 32.0 | 859 | −10.3% (improved) | `recreate-loop-200-20260707-214316.log` |
| destroy | 17 | 21.0 | 48 | −13.0% (improved) | same |

The 859 µs create max is the iter-0 cold start; steady state is 25-65 µs.

### Stage-2 replay vs guest VA fragmentation (Task 4)

`clonebasic` under `scripts/dtrace/fork-phases.d`, one carrick+dtrace run per
`FORK_MAPS` value, each under `timeout 240`, all rc 0; probe stdout
byte-identical to the gate at every knob. Guest-side fragmented-arena resident
bytes did scale (16384 → 16,793,600 → 67,125,248 for maps 0/256/1024, confirming
the workload ran) but that scaling did **not** propagate into `desc_count`.

| FORK_MAPS | side | desc_count (phase 3) | map_count (phase 3) | local replay µs (phase 3) | host fork(2) µs | Evidence |
|---:|---|---:|---:|---:|---:|---|
| 0    | parent | 14 | 14 | 209 | 2900 | `fork-phases-maps0-20260707-214600.log` |
| 0    | child  | 14 | 14 | 599 | 2922 | same |
| 256  | parent | 14 | 14 | 210 | 2841 | `fork-phases-maps256-20260707-214600.log` |
| 256  | child  | 14 | 14 | 611 | 2937 | same |
| 1024 | parent | 14 | 14 | 324 | 3517 | `fork-phases-maps1024-20260707-214600.log` |
| 1024 | child  | 14 | 14 | 671 | 3577 | same |

Verdict: **replay-bounded**. desc_count flat at 14 across 0→1024 guest maps.

### Over-ceiling workload (Task 5)

`procladder` gate at N=8 MATCH; N=160 under carrick.

| N | ladder_forked_all | ladder_reaped_all | rc | wall | peak live guests sampled | HV_NO_RESOURCES lines | Evidence |
|---:|---|---|---:|---|---:|---|---|
| 8 (gate) | true | true | 0 (MATCH) | — | — | 0 | Task 5 report `scripts/run-probe.sh procladder` |
| 160 | true | true | 0 | <2 s | 0 (run finished before 2s tick) | 0 | `procladder-160-20260708-054723.log` |
| 160 (first) | true | true | 0 | <45 s | — | 0 | `procladder-160-20260707-215138.log` |

Docker oracle at N=160 was byte-identical (`ladder_forked_all=true` /
`ladder_reaped_all=true`). No stall; 160 simultaneously-alive blocked children
exceed the 127 ceiling yet the run passes — direct proof of residency release.

## The residency release that refutes the prediction

Verified in source (controller trace, cited paths):

- `park_vcpu_for_blocking_wait` (`crates/carrick-runtime/src/vcpu_loop/mod.rs:613`)
  branches on `registry.live_count() == 1`. A **single-threaded** process that
  blocks takes `engine.save_shared_wait_state()`.
- For HVF that is `shared_wait_park` (`crates/carrick-vmm-hvf/src/trap.rs:3729`):
  it `hv_vcpu_destroy`s the vCPU **and** `hv_vm_destroy`s the whole VM while the
  process is parked, then rebuilds on wake via
  `create_vm_with_admission(VmCreateAdmission::SharedWaitResume)` and re-maps
  `self.mappings` — bounded at 14 descriptors (Task 4).
- So a child blocked in `pause(2)` holds **no** materialized VM/vCPU residency.
  That is why 160 simultaneously-alive paused children pass despite the 127
  ceiling. The strategy memo's predicted fork-#121 permit-wait stall does not
  exist for this workload shape.

**Residual exposure (the real remaining gap):** a **multi-threaded** process that
blocks takes the *other* branch — `engine.save_guest_state()` → HVF
`reclaim_park`, a **vCPU-only** destroy that keeps the VM alive. So more than 127
simultaneously-blocked multi-threaded processes (Node/Java-shaped fleets) remain
capacity-bound. This is the promoted Track 3 work item.

## Comment fixes flagged (no behavior change this campaign)

E4's measurements refute two stale source comments — flag as follow-ups:

- `crates/carrick-vmm-hvf/src/trap.rs:761-775` calls the ceiling a "~126
  system-wide vCPU budget". It is a per-VM slot budget of 127 on this host/OS;
  both the "~126" and "system-wide vCPU" framings are wrong.
- `crates/carrick-vmm-hvf/src/trap.rs:3665` and `trap.rs:3702` mark
  `reclaim_park`/`reclaim_resume` as "NOT YET WIRED"; they **are** wired via
  `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs:536` and `:558`.

## Verification Commands

- Ceiling matrix (Task 2), per config:
  `timeout 300 target/release/hvf_fork_probe concurrent-ceiling 150 120 <vcpus> <map_mib> | tee target/conformance/logs/hvf-residency-e4/ceiling-...log`
  — Result: `max_concurrent_vms=127` in all 5 configs, `failure=HV_NO_RESOURCES(0xfae94005)`, `torn_down=127 children`.
- Sequential churn (Task 3):
  `timeout 300 target/release/hvf_fork_probe recreate-loop 200 0 | tee target/conformance/logs/hvf-residency-e4/recreate-loop-200-...log`
  — Result: rc 0; create median 32 µs, destroy median 21 µs; −10-13% first-50 vs last-50.
- Fragmentation replay (Task 4), per FORK_MAPS value:
  `timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic -- 0 <maps>'`
  — Result: rc 0; desc_count flat at 14 across maps 0/256/1024.
- `scripts/run-probe.sh clonebasic` — Result: `MATCH clonebasic`, rc 0.
- `scripts/run-probe.sh procladder` — Result: `MATCH procladder`, rc 0 (N=8 gate).
- Over-ceiling (Task 5):
  `base64 -i "$PROBE" | CARRICK_RUN_ID=$RUN_ID CARRICK_HVF_ADMISSION_TRACE=1 timeout 90 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p'`
  — Result: `ladder_forked_all=true`, `ladder_reaped_all=true`, rc 0 in under 2 s,
  matching the Docker oracle byte-for-byte — that is the pass evidence. With
  `CARRICK_HVF_ADMISSION_TRACE=1` set, the log also showed no `HV_NO_RESOURCES`
  lines and no admission-trace lines, supporting but not load-bearing detail.

No carrick guest/probe and Docker oracle command were run concurrently in any
task; `scripts/run-probe.sh` sequences its carrick and Docker phases.

## Next Track

E4 closes the residency-ceiling characterization. The `WakeFromBlockingSyscall`
lease work is now scoped by measured reality, not the memo's prediction:

1. **Promoted work item — multi-threaded residency lease.** Extend the whole-VM
   release that single-threaded blocked processes already get
   (`shared_wait_park`) to multi-threaded blocked processes, which today keep the
   VM alive via `reclaim_park` and so remain capacity-bound at 127. Eviction unit
   is the whole VM (per-VM ceiling); reacquire budget is tens of µs create +
   ~200-670 µs replay bounded at 14 descriptors; churn is flat/non-degrading.
   - **Red-first gate:** a `procladder-mt` variant whose children spawn a second
     thread and *then* block — this must currently fail (>127 multithreaded
     blocked processes hit `HV_NO_RESOURCES`) and pass after the lease extension.
   - **Regression guard:** `PROC_LADDER_N=160 procladder` stays green throughout.
   - **Regression guard for the lease mechanics themselves:** `perf_fork` and
     `perf_fork_exec` (E3 baselines: `perf_fork` p50 3687 µs / 5042 µs at 0/256
     MiB; `perf_fork_exec` p50 8464 µs / 10957 µs) must not regress under any
     lease-path change.
2. **Comment fixes** (no behavior change): `trap.rs:761-775` "~126 system-wide
   vCPU budget" and `trap.rs:3665`/`:3702` "NOT YET WIRED" per the section above.
3. **Cross-host re-measurement.** Re-run Task 2's ceiling matrix after any macOS
   update; the 127 figure is host/OS-specific and undocumented by Apple.
