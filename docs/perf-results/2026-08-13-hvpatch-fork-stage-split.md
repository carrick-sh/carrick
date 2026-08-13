# HVPatch fork stage split — measured, and it re-aims K2

**Recorded 2026-08-13.** The K2 scoping document said to measure before
ranking levers. This is that measurement, and it changes the ranking.

## Method

One cold `go build` under `--exec-backend hvpatch` on the signed binary, with
a D script summing the existing `carrick*:::hvpatch-fork-process-spec-stage`
probe's elapsed-ns argument per phase across all 68 forks. No new
instrumentation. Every phase reports exactly 68 samples, so the capture is
complete.

**Perturbation is severe and must not be ignored.** The traced run took over
ten minutes against ~3 s untraced. These numbers are usable as a RELATIVE
split between stages measured by one instrument; the absolute milliseconds
and any ratio against the untraced 4.410 CPU-s budget are not trustworthy.

## The split (68 forks, summed)

| Phase | ms | share of fork |
| --- | ---: | ---: |
| **PrivateSnapshot (5)** | **77.37** | **70.6%** |
| TablePublish (7) | 14.77 | 13.5% |
| BackendSpecFinalize (9) | 5.73 | 5.2% |
| ParentPageTablesClone (2) | 4.88 | 4.4% |
| PageTablesRebase (3) | 1.40 | 1.3% |
| AliasUnion (4) | 0.21 | 0.2% |
| VcpuSnapshot (1) | 0.11 | 0.1% |
| BackendProtections (8) | 0.03 | 0.0% |
| Validation (6) | 0.02 | 0.0% |
| WrapperProtections (10) | 0.02 | 0.0% |
| ParentPageTablesLoad (0) | 0.01 | 0.0% |
| **Total (11)** | **109.61** | 1.612 ms per fork |

## What this changes

**Within fork, `PrivateSnapshot` is the whole story at 70.6%.** That is the
per-private-mapping `mach_vm_remap(copy=TRUE)` whose `size` argument names
the mapping's full virtual span — the 32 GiB arena in one call
(`trap.rs:6264-6265`). K2's structural target is confirmed by measurement,
not just by reading.

**Two levers the scoping doc flagged are now quantified as small.**
`PageTablesRebase` — the 16,384 L2 block-descriptor rebuild that looked
alarming in the code — is **1.3%** of fork. `ParentPageTablesClone` is 4.4%,
consistent with the already-disproved clone removal (`ba26307a5`) having
changed nothing measurable. Do not spend K2 on either.

**The bigger question this raises: fork may not be where the CPU is.** Total
fork process-spec work is 109.61 ms. Even allowing generously for
perturbation inflating rather than deflating it, that is a small fraction of
a 4.410 CPU-s build. If that holds untraced, then replacing the fork memory
model — K2's entire remit — cannot by itself move the number to the 2.3 CPU-s
bar, and the remaining CPU is in the syscall path, exec, or guest execution.

**Do not act on that comparison yet.** It divides a traced number by an
untraced one, which this tree's own rules forbid as an authority for
retention. The next measurement must be an untraced attribution of where the
4.410 CPU-s actually goes — CPU sampling with the profiler's own pid excluded
(the 2026-08-02 lesson, where 54% of a profile turned out to be the profiler),
or the amplification ledger. Only then can K2's scope be judged against the
goal.

What is safe to conclude today: **inside the fork path, attack
`PrivateSnapshot`, and nothing else.**

## Follow-up: whole-run CPU attribution (same day)

A `profile-997` sample over the same fixture, screened on the target and its
progeny and **excluding the profiler's own pid** (the 2026-08-02 lesson), with
kernel and user PCs counted separately:

| | samples | share |
| --- | ---: | ---: |
| kernel PC | 3,590 | 88.7% |
| user PC | 456 | 11.3% |

User time by module (top): `carrick` 228, `libsystem_malloc` 70,
`libsystem_platform` 66, `libsystem_kernel` 33, `Hypervisor` 28.

**Read this carefully — 88.7% "kernel" is NOT 88.7% overhead.** Under HVF the
guest executes inside `hv_vcpu_run`, which is a kernel call, so guest
execution is sampled as kernel PC. This bucket therefore mixes the guest's own
useful work with carrick's host-side syscall service and fault handling, and
the two cannot be separated by this instrument.

Note also that it does not agree with the `/usr/bin/time` split of 54% user /
46% sys on the untraced run, which is expected for the same reason: `time`
attributes hypervisor-entered guest execution differently from a PC sampler.
Neither is wrong; they answer different questions. Do not quote 88.7% as an
overhead figure.

The measurement that would actually separate them is a sampler that
distinguishes samples taken inside `hv_vcpu_run` from those outside it — i.e.
guest execution versus host service. That is the next instrument to build, and
it is the precondition for judging whether K2's fork-path remit can reach the
2.3 CPU-s bar or whether the remaining CPU is in the syscall path and exec.

What survives from user-side attribution: carrick's own text is about half of
user time and malloc about 15%, so host-side allocation is a real but
second-order bucket.
