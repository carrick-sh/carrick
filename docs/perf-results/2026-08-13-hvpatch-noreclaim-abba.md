# No-reclaim vs reclaim: the threading model priced by ABBA

**Recorded 2026-08-13.** The M:N executor design's central claim is that a
guest thread should never surrender its vCPU. `CARRICK_HVF_VCPU_RECLAIM=0`
(`hvf_aarch64_engine.rs:59-64`) already implements exactly that end state —
one VM, one live HVF vCPU per guest thread, no destroy/recreate, no slot
contention. So the model can be priced today, without writing it.

## Method

Cold `go build`, signed binary, ABBA alternating, three pairs, Docker not
running. Arm A is the shipped default (reclaim on); arm B sets
`CARRICK_HVF_VCPU_RECLAIM=0`.

## Measured

| | CPU-s mean | sd | spread | wall mean | CPU/wall |
| --- | ---: | ---: | ---: | ---: | ---: |
| A — reclaim ON (shipped) | 4.610 | 0.372 | **0.910** | 2.827 s | 1.63 |
| B — reclaim OFF | 4.527 | 0.031 | **0.070** | 2.833 s | 1.60 |

Delta: CPU **−0.083 s (−1.8%)**, wall **+0.007 s (+0.2%)**. Arm A performed
1,448-1,571 reclaims per build; arm B performed **zero**.

## Three results, one of them negative and important

**1. The no-reclaim model WORKS.** Three of three builds complete with one
live vCPU per guest thread. The HVF vCPU count is not a binding constraint for
this workload, which retires the main feasibility objection to the executor
design. It also confirms the panel's reading that the ten-slot budget's
binding term is `physical_cpu_count` (`trap.rs:2534`) — a **self-imposed** cap,
not an HVF one.

**2. It buys neither CPU nor wall.** −1.8% CPU is within noise and wall is
flat. This is a negative result and it must be stated plainly: **the ~600-750
ms of "resume" time measured in the reclaim census is not on the critical
path.** It is blocked time that overlaps other work, so removing it does not
speed the build up. Any argument for the executor model that leans on that
figure is wrong, including the one I was about to make.

**3. It is 13x more consistent.** Arm A's CPU spread is 0.910 s against arm
B's 0.070 s (sd 0.372 vs 0.031). The reclaim path is the dominant source of
run-to-run variance on this workload. That matters beyond aesthetics: every
future A/B on this lane has to resolve differences against that noise floor,
and a 0.9 s spread makes anything below ~20% unmeasurable. Removing reclaim
makes the whole lane a usable measuring instrument.

## What this decides

The M:N executor design stands, but its justification is now precisely three
things, none of them throughput:

- **Correctness/liveness** — slot starvation has already produced one real
  deadlock, and two further slot-pinning sites are known. A blocked thread
  holding nothing removes the class by construction.
- **Determinism** — 13x tighter CPU spread, which is a precondition for
  measuring everything else.
- **Architecture** — a kernel owns its scheduler; `hybrid.md` forbids baking
  in one host thread per Linux thread.

It is NOT justified as a route to 2.3 CPU-s, and this document is the evidence
for that. The CPU bar must be met in the syscall path, exec, and fault
handling.

## Immediate opportunity

Two defects the panel found, now confirmed against this measurement:

- `VcpuScheduler::has_waiters` / `has_spare_capacity`
  (`carrick-hal/src/vcpu_sched.rs:82,92`) have **zero callers anywhere**. The
  documented design — "with spare slots a blocking thread KEEPS its vCPU" —
  was never wired, so every futex block pays a full destroy/recreate even with
  nine of ten slots free.
- The topology lock is taken on every rebind (~2,779 per build per the
  2026-08-09 capture), and its stated justification — stopping
  `hv_vcpu_create` racing a fork's `hv_vm_destroy` — **does not apply to
  HVPatch**, whose VM is persistent and is never destroyed on a park.

Both point the same way as arm B, and arm B shows the end state is already
reachable and correct.
