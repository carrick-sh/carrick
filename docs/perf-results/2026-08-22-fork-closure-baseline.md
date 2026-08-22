# Fork-closure phase-0 baseline

**Date:** 2026-08-22
**Lane:** macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest
**Plan:** `docs/superpowers/plans/2026-08-22-hvpatch-fork-lifecycle-closure.md`
**Spec:** `docs/superpowers/specs/2026-08-22-hvpatch-fork-lifecycle-closure-design.md`

This is the frozen "before" for the fork lifecycle closure goal. Phase 1
(deletion) must not change any SHAPE recorded here; Phase 3 must change all of
them.

## Exact signed artifact

- source HEAD: `97449917fcb7b717e43b0b3df430597c2f83d0f4`
- tracked tree: clean (0 modified paths)
- binary SHA-256: `b9b4196f46423dfe68bb11da8f3a4a89c312a38e25ba8d2b71ef03e091b0d301`
- codesign identifier: `carrick.tmp.49125`
- CDHash: `3640ce0a74eca729b66861e8026d0c1c67ef16d2`
- LC_UUID: `5520EE17-0726-3E47-B483-3F522EE17F82`
- `com.apple.security.hypervisor`: present
- `__TEXT,__dof_carrick`: present

## Headline: the conformance probe gate

`cargo test -p carrick-cli --test conformance conformance_probes`, run from the
repo root, 3,519.92 s wall:

| | count |
|---|---:|
| MATCH | **0** |
| DIFF | **813** |
| SKIP | 1 |

**Zero probes match the Docker oracle.** This is not confined to the forking
probes — it is systemic, and the mechanism is that carrick's teardown failure
text lands in the compared output stream, so a probe whose guest logic ran
correctly still DIFFs on the trailing error.

Carrick-side failure signatures across the diffs (a probe may show more than
one):

| count | signature |
|---:|---|
| 409 | `HVPatch inventory retirement is duplicate or not active` |
| 188 | `<TIMEOUT after 45s>` |
| 140 | `cancel dormant binding … exact thread generation is not live` |
| 119 | `aarch64 destination executor invariant mismatch` (e.g. `sctlr=0x3400d185/0x400d005`) |
| 54 | `EL0Fault during scoped EL1 ASID maintenance` |
| 36 | `ASID retirement executor ExecutorId(N) command channel closed` |
| 32 | `drop HVPatch MM authority (phase=active …)` |

Two of these are new to this measurement and were not seen in the single-probe
reducers: the **executor invariant mismatch** (119) shows an SCTLR divergence
between source and destination executor on task migration
(`0x3400d185` vs `0x400d005`), and **`inventory retirement is duplicate or not
active`** (409) is the most common failure overall — it is the same authority
state machine as the open defect 4, reached by a different route.

Read together with the shape table below, this says the teardown/executor layer
is the universal blocker: fixing it is expected to unblock most of the 813,
which makes Phase 3 Tasks 9-10 the highest-leverage work in the plan.

## Fork battery shapes (`run-elf --raw`, must be unchanged by Phase 1)

| probe | exit | stdout lines | first carrick signature |
|---|---:|---:|---|
| clonebasic | 134 | 0 | drop HVPatch MM authority |
| forkcow | 134 | 0 | drop HVPatch MM authority |
| forkfiletable | 134 | 0 | drop HVPatch MM authority |
| forkshared | 134 | 0 | drop HVPatch MM authority |
| waitexitstorm | 134 | 0 | drop HVPatch MM authority |
| waitidsiuid | 134 | 0 | drop HVPatch MM authority |
| mqnotifycrossproc | 134 | 0 | drop HVPatch MM authority |
| futexpingpong | 134 | 0 | drop HVPatch MM authority |
| cloneexitsig | 134 | 0 | drop HVPatch MM authority |
| sigchld | 134 | 0 | drop HVPatch MM authority |
| xsignal | 134 | 0 | drop HVPatch MM authority |
| forkexecpthread | 134 | 0 | drop HVPatch MM authority |
| execpipe | 134 | 1 | drop HVPatch MM authority |
| clone3args | 134 | 0 | drop HVPatch MM authority |
| cloneexithandled | 134 | 0 | drop HVPatch MM authority |
| threadspawn | 0 | 1 | — |
| manythreads | 0 | 3 | — |
| epollinmemwake | 0 | 1 | — |
| epolloutrearm | 0 | 1 | — |
| rtsigqueueinfo | 0 | 5 | — |
| vforkpid | 0 | 6 | — |
| vforkvmshare | 0 | 2 | — |

15 forking probes abort identically; 7 non-forking probes pass. The split is the
diagnostic: process fork is broken, thread clone is not.

## Reducers

| reducer | exit | stdout | note |
|---|---:|---|---|
| `carrick run ubuntu:24.04 --raw --fs host /bin/sh -c '/bin/echo hi'` | 125 | `hi` | dash vforks; guest output correct, shutdown fails |
| `carrick run ubuntu:24.04 --raw --fs host /bin/bash -c '/bin/echo hi'` | 0 | `hi` | bash forks; the control that isolates the shared-mm path |

Shutdown failure alternates between two timing-dependent shapes: a stale dormant
binding (4/6 observed) and `EL0Fault during scoped EL1 ASID maintenance` (2/6).

## Gate baseline

`RUST_TEST_THREADS=1 just ci`, status read from a file: **exit 101**, stopping at
`lint-domains`. clippy passes workspace-wide for the first time as of
`4acd8cc9f`. The census reports 4 genuinely unreviewed host-thread uses added by
the persistent-executor campaign and 8 rows retired; every other differing row is
position-only. Reproduced on unmodified HEAD `50bf9ddd8`, so it is pre-existing.

## Probe surface

Both arm64 lanes now carry all 461 declared binaries. `waitidsiuid` and
`mqnotifycrossproc` (added in `301ac30a9`) had no binaries in either lane until
2026-08-22 and were being silently skipped, because the ordinary probe gate
treats a missing binary as `SKIP` and still returns green. Only closure mode
rejects skips — which is why the goal names
`just conformance-probes-closure` as the closing gate.
