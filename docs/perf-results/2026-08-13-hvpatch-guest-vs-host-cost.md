# Separating guest work from carrick overhead — and what the 2.3 CPU-s bar means

**Recorded 2026-08-13.** The fork-stage measurement left one question
blocking every K2 decision: how much of the 4.410 CPU-s is the guest's own
work versus carrick's overhead? A PC sampler cannot answer it, because under
HVF the guest runs inside `hv_vcpu_run` and is sampled as kernel time.

## Method

Ask the guest. The same fixture on both engines, with the shell's `times`
builtin run inside the guest after the build, plus `/usr/bin/time` on the
host process. Two runs per engine, never concurrent.

## Measured

| | guest-perceived CPU | host CPU |
| --- | ---: | ---: |
| carrick hvpatch | 5.77 s, 6.19 s (mean **5.98**) | 4.07 s, 4.50 s (mean 4.29) |
| Docker arm64 | 2.52 s, 2.12 s (mean **2.32**) | ~0 (work is in the LinuxKit VM) |

Guest-perceived ratio: **2.58x**, which independently reproduces the
workload-window ratio of 2.574x from a completely different instrument. Two
unrelated measurements agreeing on 2.57-2.58x is the strongest evidence yet
that the overhead figure is real.

## Finding 1 — the 2.3 CPU-s bar is essentially "zero overhead"

Docker needs **2.32 CPU-s of guest work** to perform this build. The goal's
bar is **below 2.3 CPU-s** on the same workload.

So the bar is approximately **1.01x the workload's own intrinsic cost.**
Reaching it does not mean "reduce overhead substantially" — it means carrick's
total host cost must come down to roughly what the guest's own computation
costs, i.e. overhead must approach zero.

Carrick's host CPU is currently 4.29 s against that 2.32 s of intrinsic work:
**1.85x**, or about 1.97 CPU-s of overhead to remove.

This is worth stating plainly because it reframes the remaining phases. K2's
fork-path remit was measured at 109.61 ms of fork process-spec work. Even
eliminating fork's memory cost entirely cannot remove 1.97 CPU-s. The bar is
reachable only if the syscall path, exec, and fault handling are all driven
close to native — which is what K5's "smallest correct modern Darwin
primitive set" is for.

## Finding 2 — carrick over-reports guest CPU by ~40%

The guest believes it consumed **5.98 CPU-s** while carrick's entire host
process tree consumed **4.29 CPU-s**. A guest cannot legitimately use more
CPU than its host, so carrick's `times`/`getrusage` accounting for the guest
is wrong by roughly 40%.

There is a second, sharper symptom in the same capture. Under Docker the
`times` output attributes the build to CHILDREN (`0m2.28s 0m0.24s` on the
children line, zero on the shell line). Under carrick it is attributed to the
SHELL ITSELF (`0m4.34s 0m1.43s` on the shell line, zero on the children
line). Linux puts a reaped child's CPU on the children line; carrick puts it
on `RUSAGE_SELF`.

That is a guest-visible Linux divergence, independent of performance: any
guest that uses `times(2)` or `getrusage(RUSAGE_CHILDREN)` to attribute work —
`make`, `time`, benchmark harnesses, CI tooling — reads the wrong answer.
It is not a K2 item; it belongs with the syscall-correctness work, and it
needs its own differential probe against the Docker oracle.

## What to do next

1. Fix the `times`/`getrusage` self-versus-children attribution. It is a
   correctness bug with a trivial oracle, and it currently makes every
   guest-side CPU measurement untrustworthy — including any future
   before/after for K2 itself.
2. Only then use guest-side CPU as an instrument.
3. Re-scope K2 honestly against Finding 1: it is necessary structural work
   for the fork/COW model the later phases build on, but it is not, on this
   evidence, the phase that reaches 2.3 CPU-s.
