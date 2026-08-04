# Current-default broad CPU attribution

**Date:** 2026-08-04  
**Workload:** Darwin/AArch64 native cold `go build`  
**Decision:** **measurement accepted; carry anonymous-memory intent attribution,
not a production patch**

Two independent, naturally completed `native-wall` captures agree that Darwin
kernel execution is the current dominant sampled CPU category at **50.6261% /
50.8335%**. The kernel population separates into two independently stable
coarse classes: named-syscall work at **28.7315% / 28.7129%** of all sampled
CPU and non-syscall work at **21.8945% / 22.1207%**.

The prior exact fault census independently measured 1,531,118 / 1,531,742
zero-fill faults. Charging the deliberately favorable 3,840 ns cost to all of
them projects to **25.3299% / 24.4248%** of ordinary CPU; even the already
isolated host-other subset projects to **15.9822% / 15.4279%**. Anonymous
zero-fill service therefore clears the campaign's 10% opportunity screen twice.

This does **not** authorize a memory change. The 3,840 ns input is a favorable
all-system-CPU ceiling rather than a measured current per-fault cost, and the
completed allocation-owner census proved that no individual Carrick allocation
owner clears 10%. The next step is a lifecycle-complete census of guest memory
intent (`mmap`, `madvise`, `mprotect`, `munmap`) bound to zero-fill faults. Only
an exact semantic sequence that clears 10% twice may become a Darwin-lowering
experiment.

This is mechanism evidence, not timing authority. DTrace materially perturbs
the workload, so the 27.94-28.58 s traced elapsed values are discarded. The
official shipped-default cold-build result remains **10.4446x** native-arm64
Docker.

## Bound inputs

Both accepted captures ran the same signed ordinary binary from clean runtime
source `daebb0203c854b507b2441eee98fa341f353dd20`:

- executable SHA-256
  `d43c38bc2eec4d99170f869100fc901580c8781a95c4a77eccb4106821f3f037`;
- native-wall D program SHA-256
  `bcfe47c2f762e5af4f7fa74b5818898101f8ce0902b40ccb24e840c0229c577e`;
- terminal qualification SHA-256
  `919ee0f898c0402916b6e0fd58bf7e5e3482f2f25dd8bbb7d6b5a05763f24fbc`;
- macOS 27.0 build 26A5388g on arm64; and
- the same locked 61-file persistent store, whose pre/mid/post normalized
  digest remained
  `432a3ab42a5834fd29f81723333584274ac75e2b1b3a532a43bdf81ac5125cc6`.

The analyzer at `900e6d57` reports the kernel class split and checks its
between-run stability. `0f24eb54` coalesces byte-identical per-exec host image
catalogs without weakening address coverage. Those are offline evidence
consumer changes; the measured runtime binary remains exactly source-bound to
`daebb020` in both profiles.

| input | A | B |
|---|---|---|
| run id | `dsr-20260804T092759.961Z-49650` | `dsr-20260804T093221.530Z-50365` |
| raw trace | `target/perf/current-default-broad-attribution/accepted-A-v5/raw.trace` | `target/perf/current-default-broad-attribution/accepted-B/raw.trace` |
| raw lines | 808,997 | 857,599 |
| raw SHA-256 | `c01d6fa0…ba07` | `7a7304a0…c5c` |
| profile | `target/perf/current-default-broad-attribution/accepted-A-v5/profile.jsonl` | `target/perf/current-default-broad-attribution/accepted-B/profile.jsonl` |
| profile lines | 108,202 | 112,582 |
| profile SHA-256 | `8ba44cd8…a2da` | `1ecd47a0…52a9` |
| target completion | natural, reason 1 | natural, reason 1 |
| elapsed, perturbation only | 28.576506 s | 27.936572 s |

Every capture completeness, target-lifecycle, overflow, incomplete-pair, live
process, and DTrace principal/aggregation/dynamic/rinse/dirty/other/interrupted
counter is zero. The analyzer accepted 100% wall-timer coverage and
99.9424% / 99.9447% resolved CPU coverage. The final derived artifact is
`target/perf/current-default-broad-attribution/attribution.json`, SHA-256
`58b709a3f44bac99a2eed20df99052fd9c982367b78903473dcc02df71e50544`.

## Broad result

Percentages use all CPU samples as the denominator and remain separate from
wall-state occupancy and exact off-CPU durations.

| CPU category | A samples | A share | B samples | B share | absolute drift |
|---|---:|---:|---:|---:|---:|
| Darwin kernel | 21,955 | **50.6261%** | 22,077 | **50.8335%** | 0.2075 pp |
| translated guest | 9,899 | **22.8261%** | 9,867 | **22.7193%** | 0.1068 pp |
| Darwin userspace | 4,441 | **10.2405%** | 4,484 | **10.3247%** | 0.0842 pp |
| other Carrick | 3,414 | 7.8723% | 3,863 | 8.8948% | 1.0224 pp |
| translation | 3,117 | 7.1875% | 2,594 | 5.9728% | 1.2147 pp |
| process setup | 383 | 0.8832% | 393 | 0.9049% | 0.0217 pp |
| gateway | 95 | 0.2191% | 78 | 0.1796% | 0.0395 pp |
| dispatch | 38 | 0.0876% | 50 | 0.1151% | 0.0275 pp |
| unresolved | 25 | 0.0576% | 24 | 0.0553% | 0.0024 pp |

The dominant Darwin-userspace images are also stable: `libsystem_platform` is
4.2429% / 4.2528%, `libsystem_malloc` is 3.3551% / 3.5482%, and
`libsystem_kernel` is 2.1399% / 2.0907% of all CPU samples. No individual
userspace image clears 10%.

## Kernel split

`native-wall` assigns every sampled kernel PC to exactly one of the two classes
below. The analyzer now fails closed on an unknown class and applies the same
five-percentage-point stability gate used for broad categories.

| kernel class | A samples | A share of all CPU | B samples | B share of all CPU | absolute drift |
|---|---:|---:|---:|---:|---:|
| named syscall | 12,460 | **28.7315%** | 12,470 | **28.7129%** | 0.0187 pp |
| non-syscall | 9,495 | **21.8945%** | 9,607 | **22.1207%** | 0.2261 pp |

These are selectable populations, not causal leaf functions. Prior KDK/LLDB
work proved that a sampled interrupt-return PC can accumulate the cost of the
preceding interrupt-disabled interval, so raw kernel leaf ranking remains
insufficient to authorize a patch.

## Exact fault binding

The source-identical ordinary-runtime N1/N2 fault captures and C1/C2 untraced
CPU denominators were already accepted in
[`2026-08-03-native-allocation-owner-census.md`](2026-08-03-native-allocation-owner-census.md).
The calculation below deliberately distinguishes measured values from the
favorable cost projection.

```text
all_zfod_opportunity = exact_zfod * 3840 / ordinary_supervisor_total_cpu_ns
```

| binding | exact zfod, measured | ordinary CPU, measured | all-zfod projection | host-other projection |
|---|---:|---:|---:|---:|
| N1/C1 | 1,531,118 | 23.211641 s | **25.3299%** | **15.9822%** |
| N2/C2 | 1,531,742 | 24.081648 s | **24.4248%** | **15.4279%** |

The all-zfod values are an opportunity ceiling, not additive to the kernel
sample share. The host-other projections are a subset of the same ceiling.
Their agreement with the refreshed 21.89-22.12% non-syscall kernel population
is corroboration of scale, not proof that every non-syscall sample is a fault.

## What the current lowering already does

The source audit prevents the next step from beginning with a guessed patch:

- writable private/anonymous Linux `MADV_DONTNEED` reaches
  `GuestMemory::zero_backing`;
- Darwin identity backing implements that operation as one fresh anonymous
  `MAP_FIXED|MAP_PRIVATE` replacement, preserving Linux zero-on-next-access
  semantics; and
- private/anonymous Linux `MADV_FREE` currently returns success without a host
  reclamation call.

Go's native Darwin runtime uses `MADV_FREE_REUSABLE` / `MADV_FREE_REUSE` for
its unused/used heap transition, while its Linux runtime normally uses
`MADV_FREE` with `MADV_DONTNEED` fallback. That dual-port comparison supplies a
candidate vocabulary, not evidence that Carrick should substitute it: Carrick
must first measure which advice/protection/mapping sequences actually precede
the accepted fault population and preserve Linux's observable semantics.

## Failed-closed capture trail

Invalid captures remain under
`target/perf/current-default-broad-attribution/`; none contributed samples to
the accepted result.

1. `A` exposed stale native-wall metadata and only 75.942% resolved CPU.
2. `qualified-A` exposed unsorted/non-overlapping host catalogs; the producer
   now canonicalizes them.
3. `accepted-A` exhausted the 128 MiB DTrace dynamic pool.
4. `accepted-A-v2` hit the old 60 s observer watchdog.
5. `accepted-A-v3/v4` proved one `DTRACEFLT_BADADDR` per failed repeated
   `copyinstr` of the same image catalog. The final profile copies that
   immutable catalog into DTrace kernel storage once and replays it with an
   explicit source PID.

The retained control-plane fixes are commits `61bb1f1b` through `daebb020`.
They convert plausible-looking incomplete evidence into named failures and
make the two accepted captures possible; they do not change ordinary guest
semantics.

## Decision and next gate

Carry one measurement, not one assumed solution:

1. Add an export-only, lifecycle-complete memory-intent census for guest
   `mmap`, `madvise`, `mprotect`, and `munmap`, grouped by semantic sequence,
   mapping provenance, bytes, and subsequent exact zero-fill pages.
2. Require every process-image epoch, byte total, and fault join to reconcile;
   retain core-readable/event-ring recovery for crashes where practical.
3. Select a Darwin lowering only if the same non-overlapping sequence projects
   to at least 10% of ordinary CPU in two independent bindings.
4. Validate one variable with ordinary-binary ABBA CPU seconds and workload
   wall, then rerun the real Carrick/Docker lane only for a retained candidate.
5. If no memory sequence clears 10%, stop the line and source-distinctly split
   the stable 28.72% named-syscall population next.

Eager whole-image translation remains explicitly deferred. It may eventually
amortize a complete eligible image, but incremental augmentation is still
required for JIT-on-JIT and dynamically generated code.
