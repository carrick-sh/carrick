# The native exec "fixed ~18 ms" decomposed: mostly Darwin's exec floor, plus a per-MB digest that was hiding in it

**Date:** 2026-08-03. **Lane:** exec-cost (roadmap Phase 3, item 2).
**Instrument:** `CARRICK_EXEC_STAMPS` (`carrick-runtime/src/exec_stamps.rs`) —
untraced `CLOCK_MONOTONIC_RAW` stamps at eight fixed points of a fork-child
guest `execve`, appended line-atomically to a file. All medians below are from
120 exec chains of `/bin/sh -c` loops over `ubuntu:24.04`, native backend,
quiet box unless marked loaded.

## 1. Why the existing USDT numbers could not answer this

The `dsr-fork` profile brackets every reexec phase, but the window under study
contains **dyld re-registering the binary's DOF section with the kernel on
every exec**, and an attached DTrace consumer makes that rendezvous radically
more expensive: traced, the exec→probes-ready window measured 9.4 ms with 95%
of profile samples inside `dyld` `__ioctl`; untraced (stamps), the same
carrick-side registration work is **0.10 ms**. Any traced measurement of this
window overstates the USDT-registration term several-fold. That is the reason
the stamps instrument exists.

## 2. The untraced decomposition (per fork-child guest execve, `/bin/echo`)

| segment | median | what it is |
|---|---|---|
| execve-dispatch → capsule-prepare | 0.58 ms | resolve + load target ELF (old image) |
| capsule-prepare → pre-exec | 0.48 ms | fd/process snapshot, prepared-artifact build, capsule write |
| **pre-exec → main-entry** | **5.31 ms** | kernel execve + dyld + static init |
| main-entry → probes-ready | 0.10 ms | env config, proctitle, USDT registration |
| probes-ready → resume-entry | 0.26 ms | clap parse + CLI dispatch |
| resume-entry → dispatcher-ready | 0.66 ms | capsule read, arena/ulock/fs attach, fd table |
| dispatcher-ready → image-mapped | 1.25 ms | artifact validate + map + execve resets |
| image-mapped → runtime-ready | 0.13 ms | shared-translation store, signal plumbing, thread runtime |
| **TOTAL fixed chain** | **8.5-9.0 ms** | |

The roadmap's "fixed ~18 ms" is therefore stale: deferred exec digests and the
prepared-image transport had already harvested roughly half of it before this
lane started.

## 3. The 5.3 ms exec+dyld term is floor-bound

Controlled `execve→main` floors (interleaved rounds, t0 taken in the child
immediately before `execve`):

| image | execve→main |
|---|---|
| tiny C binary (libSystem only) | **1.83 ms** |
| tiny C + CoreFoundation/Hypervisor/libdtrace/libiconv | 2.75 ms |
| carrick (24 MB, same dylibs) | 3.55 ms |
| carrick, in-guest (exec FROM a live guest process) | 5.2-5.5 ms |

So the 5.3 ms is: **~1.8 ms Darwin per-exec floor** (any binary) + **~0.9 ms
dylib initializer set** (CF dominates; HVF and libdtrace mostly ride on it) +
**~0.8 ms carrick-binary premium** (24 MB mapping + fixups + Rust pre-main) +
**~1.6 ms old-address-space teardown** (scales with the dying image's resident
pages: a clean child pays 1.9 ms, the same child with 4000 touched 64 KiB
mappings pays 5.2 ms). While the libdispatch constraint stands (a forked child
MUST exec before the new image may create threads — Node/Go/CPython trap in
`_dispatch_sema4_wait` otherwise, see the 2026-07-13 self-reexec design), and
PID preservation pins the successor to being the exec'd image of the same
process (no zygote pool can donate a pid), **at most ~1.7 ms of this term is
recoverable, via heroics** (slim resume binary, CF/HVF/dtrace dlopen surgery).

**Negative result — chained fixups:** relinking with `-Wl,-fixup_chains`
(LC_DYLD_CHAINED_FIXUPS instead of 40,643 eager opcode fixups) moved
pre-exec→main-entry by ~0.1 ms. Not landed. Removing the `__dof_carrick`
section or stripping symbols: no measurable change either.

## 4. What was NOT fixed in the "fixed" cost: the artifact payload digest

The chain scales at ~2 ms/MB of guest binary (echo 8.5 ms → perl (~4 MB)
13.5 ms), and the slope was the prepared-artifact pipeline hashing every
initialized payload byte **twice per exec** — once while writing (producer),
once re-reading before mapping (consumer). `perf(dsr)` made the digest
metadata-only by default (`ArtifactDigestCoverage`, hatch
`CARRICK_EXEC_FAST=0`). Paired A/B on a loaded box (alternating arms, so
within-round comparison only) **suggests**:

| guest | arm | capsule-prepare→pre-exec | dispatcher-ready→image-mapped |
|---|---|---|---|
| perl ~4 MB | default (metadata) | 1.6 / 2.0 ms | 2.2 / 2.6 ms |
| perl ~4 MB | `CARRICK_EXEC_FAST=0` | 4.6 / 5.4 ms | 4.8 / 6.3 ms |
| echo | both arms | no difference | no difference |

i.e. **~1.5-2 ms/MB removed per exec** (~6-8 ms on a 4 MB guest, ~0 on echo).
For a cold `go build` execing ~15-25 MB toolchain binaries ~61 times this
suggests on the order of **1-2 s** — larger than the roadmap's ~1.1 s estimate
for the whole item, because the digest term was per-MB, not fixed. Re-measure
with the paired cold-build A/B on a quiet box before quoting a build-level
number.

## 5. Where the remaining per-exec money actually is

Untraced per-`fork+exec+/bin/echo` wall is ~31 ms: ~2.8 ms fork + ~8.5 ms
fixed chain + **~20 ms after runtime-ready** — the guest's own `ld.so`+libc
loading, per-process translation, and execution. That last term belongs to the
file-backed-mapping and tier-D lanes, not to exec-architecture work; it is the
reason killing the entire fixed chain would still only be worth ~0.5 s of the
build.

## 6. Reproduction

- stamps: `CARRICK_EXEC_STAMPS=/tmp/stamps.txt carrick run ubuntu:24.04 /bin/sh -c 'i=0; while [ $i -lt 120 ]; do /bin/echo hi >/dev/null; i=$((i+1)); done'`
- traced per-phase brackets (knowing the DOF caveat): `carrick trace --profile dsr-fork …`
- A/B arms: default vs `CARRICK_EXEC_FAST=0`, alternating, paired rounds.
